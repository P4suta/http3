import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import http/body
import http/client
import http/context
import http/error
import http/internal/http2/connection
import http/internal/http2/control
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/peer_settings
import http/internal/http2/priority
import http/internal/http2/settings
import http/internal/http2/wire
import http/internal/transport
import http/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

type IsolationTerminal {
  IsolationDeadline
  IsolationReadFailure
  IsolationReadEnd
  IsolationWireFailure
}

type IsolationTrace {
  IsolationTrace(
    reset_seen: Bool,
    fast_seen: Bool,
    response_statuses: List(#(Int, Int)),
    stream_resets: List(#(Int, Int)),
    peer_goaways: List(#(Int, Int)),
    terminal: IsolationTerminal,
  )
}

type PriorityBarrierFailure {
  PriorityBarrierFailure(
    stage: String,
    first_bytes: Int,
    second_bytes: Int,
    remaining_reads: Int,
  )
}

type GoAwayTerminal {
  GoAwayObserved
  GoAwayReadDeadline
  GoAwayReadEnd
  GoAwayReadFailure(transport.Error)
  GoAwayWireFailure(wire.Error)
  GoAwayAutomaticWriteFailure(wire.Error)
  GoAwayAutomaticSendFailure(transport.Error)
  GoAwayReadLimit
}

type GoAwayTrace {
  GoAwayTrace(
    read_attempts: Int,
    read_bytes: Int,
    peer_goaways: List(#(Int, Int)),
    terminal: GoAwayTerminal,
  )
}

pub fn concurrent_streams_complete_without_head_of_line_handler_blocking_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/slow" -> process.sleep(100)
      _ -> Nil
    }
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(initial_listener_snapshot) =
    server.http2_listener_snapshot(listener)
  assert initial_listener_snapshot.consistent
  assert initial_listener_snapshot.state == server.Running
  assert initial_listener_snapshot.accepted_connections == 0
  assert initial_listener_snapshot.goaways_sent == 0
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, slow)) =
    wire.send_request_headers(
      state,
      get_request(port, "/slow"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, fast)) =
    wire.send_request_headers(
      state,
      get_request(port, "/fast"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, slow)
  let assert Ok(Nil) = send_frames(socket, fast)

  let assert Ok(#(socket, _, responses)) =
    collect_responses(socket, state, [], 2)
  assert responses == [#(3, 204), #(1, 204)]

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn rfc9218_default_nonincremental_responses_serialize_by_stream_id_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let payload = string.repeat("x", times: 120_000) |> bit_array.from_string
  let handlers_started = process.new_subject()
  let handler = fn(_, _) {
    let release_handler = process.new_subject()
    process.send(handlers_started, release_handler)
    let assert Ok(Nil) = process.receive(release_handler, within: 1000)
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_bytes(payload),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) =
    wire.initial_bytes(state, [settings.InitialWindowSize(0)])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, first_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/first"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, second_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/second"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, first_request)
  let assert Ok(Nil) = send_frames(socket, second_request)
  let assert Ok(first_handler) = process.receive(handlers_started, within: 1000)
  let assert Ok(second_handler) =
    process.receive(handlers_started, within: 1000)
  process.send(first_handler, Nil)
  process.send(second_handler, Nil)

  let assert Ok(#(socket, state)) =
    open_priority_measurement_window(socket, state)

  let assert Ok(#(socket, _, first_bytes, second_bytes)) =
    collect_initial_data(socket, state, 0, 0, 64)
  assert first_bytes + second_bytes == 65_535
  assert first_bytes == 65_535
  assert second_bytes == 0

  let _closed = transport.close(socket)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn rfc9218_incremental_priority_header_round_robins_live_responses_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let payload = string.repeat("x", times: 120_000) |> bit_array.from_string
  let handlers_started = process.new_subject()
  let handler = fn(_, _) {
    let release_handler = process.new_subject()
    process.send(handlers_started, release_handler)
    let assert Ok(Nil) = process.receive(release_handler, within: 1000)
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_bytes(payload),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) =
    wire.initial_bytes(state, [settings.InitialWindowSize(0)])
  let assert Ok(Nil) = transport.send(socket, initial)
  let first =
    get_request(port, "/first")
    |> request.set_header("priority", "i")
  let second =
    get_request(port, "/second")
    |> request.set_header("priority", "i")
  let assert Ok(wire.HeadersWritten(state, 1, first_request)) =
    wire.send_request_headers(state, first, end_stream: True)
  let assert Ok(wire.HeadersWritten(state, 3, second_request)) =
    wire.send_request_headers(state, second, end_stream: True)
  let assert Ok(Nil) = send_frames(socket, first_request)
  let assert Ok(Nil) = send_frames(socket, second_request)
  let assert Ok(first_handler) = process.receive(handlers_started, within: 1000)
  let assert Ok(second_handler) =
    process.receive(handlers_started, within: 1000)
  process.send(first_handler, Nil)
  process.send(second_handler, Nil)

  let assert Ok(#(socket, state)) =
    open_priority_measurement_window(socket, state)

  let assert Ok(#(socket, _, first_bytes, second_bytes)) =
    collect_initial_data(socket, state, 0, 0, 64)
  assert first_bytes + second_bytes == 65_535
  assert first_bytes > 0
  assert second_bytes > 0
  assert int.absolute_value(first_bytes - second_bytes) <= 1

  let _closed = transport.close(socket)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn rfc9218_registered_priority_updates_reorder_live_responses_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let payload = string.repeat("x", times: 120_000) |> bit_array.from_string
  let handlers_started = process.new_subject()
  let handler = fn(_, _) {
    let release_handler = process.new_subject()
    process.send(handlers_started, release_handler)
    let assert Ok(Nil) = process.receive(release_handler, within: 1000)
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_bytes(payload),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) =
    wire.initial_bytes(state, [settings.InitialWindowSize(0)])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, first_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/first"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, second_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/second"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, first_request)
  let assert Ok(Nil) = send_frames(socket, second_request)
  let assert Ok(first_handler) = process.receive(handlers_started, within: 1000)
  let assert Ok(second_handler) =
    process.receive(handlers_started, within: 1000)

  let assert Ok(first_update) =
    priority.encode_update(
      priority.Update(1, priority.Priority(7, False)),
      maximum_frame_bytes: 16_384,
    )
  let assert Ok(second_update) =
    priority.encode_update(
      priority.Update(3, priority.Priority(0, False)),
      maximum_frame_bytes: 16_384,
    )
  let acknowledgement = <<"priority":utf8>>
  let assert Ok(ping) = frame.encode(frame.Ping, 0, 0, acknowledgement, 16_384)
  let assert Ok(Nil) = transport.send(socket, first_update)
  let assert Ok(Nil) = transport.send(socket, second_update)
  let assert Ok(Nil) = transport.send(socket, ping)
  let assert Ok(#(socket, state)) =
    receive_ping_acknowledgement(socket, state, acknowledgement, 16)

  process.send(first_handler, Nil)
  process.send(second_handler, Nil)
  let assert Ok(#(socket, state)) =
    open_priority_measurement_window(socket, state)
  let assert Ok(#(socket, _, first_bytes, second_bytes)) =
    collect_initial_data(socket, state, 0, 0, 64)
  assert first_bytes + second_bytes == 65_535
  assert first_bytes == 0
  assert second_bytes == 65_535

  let _closed = transport.close(socket)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn http2_listener_configuration_rejects_unbounded_values_test() -> Nil {
  let defaults = server.http2_defaults()
  let assert Error(timeout) =
    server.with_http2_timeouts(defaults, 0, 1000, 1000, 1000, 1000)
  assert error.kind(timeout) == error.Policy(error.SecurityPolicy)
  let assert Error(connections) =
    server.with_http2_connection_limits(defaults, 0, 1)
  assert error.kind(connections) == error.Policy(error.SecurityPolicy)
  let assert Error(headers) =
    server.with_http2_header_limits(defaults, 0, 4096, 4096)
  assert error.kind(headers) == error.Policy(error.SecurityPolicy)
  let assert Error(bodies) = server.with_http2_body_limits(defaults, 0, 4096)
  assert error.kind(bodies) == error.Policy(error.SecurityPolicy)

  let assert Ok(configured) =
    server.with_http2_timeouts(defaults, 1000, 1000, 1000, 1000, 1000)
  let assert Ok(configured) =
    server.with_http2_connection_limits(configured, 8, 32)
  let assert Ok(configured) =
    server.with_http2_header_limits(configured, 8192, 16_384, 4096)
  let assert Ok(_) = server.with_http2_body_limits(configured, 1_000_000, 8192)
  Nil
}

pub fn cleartext_http2_requires_explicit_prior_knowledge_opt_in_test() -> Nil {
  let handler = fn(_, _) {
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Error(denied) =
    server.listen_http2_cleartext(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
    )
  assert error.kind(denied) == error.Policy(error.SecurityPolicy)

  let configuration =
    server.http2_defaults() |> server.allow_http2_cleartext_prior_knowledge
  let assert Ok(listener) =
    server.listen_http2_cleartext(executor, <<127, 0, 0, 1>>, 0, configuration)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, request_frames)) =
    wire.send_request_headers(
      state,
      get_request(port, "/h2c"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, request_frames)
  let assert Ok(#(socket, _, [#(1, 204)])) =
    collect_responses(socket, state, [], 1)

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn extended_connect_is_advertised_and_accepted_only_after_opt_in_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let accepted = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), metadata) {
    case incoming.method {
      gleam_http.Connect ->
        process.send(accepted, context.extended_connect_protocol(metadata))
      _ -> Nil
    }
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let configuration =
    server.http2_defaults() |> server.enable_http2_extended_connect
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      configuration,
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(#(socket, state)) =
    receive_extended_connect_setting(socket, state, 8)
  let assert Ok(wire.HeadersWritten(state, 1, request_frames)) =
    wire.send_extended_connect_headers(
      state,
      connect_request(port),
      protocol: "websocket",
    )
  let assert Ok(Nil) = send_frames(socket, request_frames)
  assert process.receive(accepted, within: 1000) == Ok(Some("websocket"))
  let assert Ok(#(socket, _, [#(1, 204)])) =
    collect_responses(socket, state, [], 1)

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn streaming_request_and_response_resume_through_flow_control_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let payload = string.repeat("flow", times: 20_000) |> bit_array.from_string
  let handler = fn(incoming: request.Request(body.Body), _) {
    use #(bytes, trailers) <- result.try(body.read_all(incoming.body, 100_000))
    assert trailers == []
    Ok(response.Response(status: 200, headers: [], body: body.from_bytes(bytes)))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(owner) =
    client.start(
      client.defaults()
      |> client.with_ca_certificates(ca_certificates: [ca_certificate]),
    )
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [],
      body: body.from_bytes(payload),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/flow",
      query: None,
    )
  let assert Ok(exchange) = client.exchange(client: owner, outgoing:)
  assert client.selected_protocol(exchange) == client.Http2
  let assert Ok(#(received, [])) =
    body.read_all(client.response(exchange).body, 100_000)
  assert received == payload

  let assert Ok(Nil) = client.close(owner)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn response_source_stops_at_the_peer_window_until_the_client_pulls_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let pulled = process.new_subject()
  let chunk = string.repeat("x", times: 60_000) |> bit_array.from_string
  let assert Ok(response_body) =
    body.from_pull(
      counted_response_source(pulled, [chunk, chunk]),
      None,
      None,
      fn() { Nil },
    )
  let handler = fn(_: request.Request(body.Body), _) {
    Ok(response.Response(status: 200, headers: [], body: response_body))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(owner) =
    client.start(
      client.defaults()
      |> client.with_ca_certificates(ca_certificates: [ca_certificate]),
    )
  let assert Ok(exchange) =
    client.exchange(client: owner, outgoing: get_request(port, "/bounded"))

  assert process.receive(pulled, within: 1000) == Ok(2)
  assert process.receive(pulled, within: 1000) == Ok(1)
  assert process.receive(pulled, within: 0) == Error(Nil)
  let assert Ok(#(received, [])) =
    body.read_all(client.response(exchange).body, 130_000)
  assert bit_array.byte_size(received) == 120_000
  assert process.receive(pulled, within: 1000) == Ok(0)

  let assert Ok(Nil) = client.close(owner)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn stalled_response_source_resets_only_its_stream_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let stalled = process.new_subject()
  let cancelled = process.new_subject()
  let source =
    body.pull(fn(_) {
      process.send(stalled, Nil)
      process.sleep(1000)
      Ok(body.PullEnd([]))
    })
  let assert Ok(stalled_body) =
    body.from_pull(source, None, None, fn() { process.send(cancelled, Nil) })
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/stall" ->
        Ok(response.Response(status: 200, headers: [], body: stalled_body))
      _ -> Ok(response.Response(status: 204, headers: [], body: body.empty()))
    }
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(configuration) =
    server.with_http2_timeouts(
      server.http2_defaults(),
      2000,
      100,
      1000,
      1000,
      1000,
    )
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      configuration,
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, stalled_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/stall"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, fast_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/fast"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, stalled_request)
  let assert Ok(Nil) = send_frames(socket, fast_request)

  assert process.receive(stalled, within: 1000) == Ok(Nil)
  let assert Ok(#(socket, _, True, True)) =
    collect_reset_and_fast_response(socket, state, False, False, 5000)
  assert process.receive(cancelled, within: 1000) == Ok(Nil)

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn stalled_handler_resets_only_its_stream_test() -> Nil {
  repeat_stalled_handler_isolation(20)
}

pub fn externally_cancelled_context_resets_only_its_http2_stream_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let captured_context = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    case incoming.path {
      "/cancel" -> {
        process.send(captured_context, request_context)
        process.sleep(1000)
      }
      _ -> Nil
    }
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(configuration) =
    server.with_http2_timeouts(
      server.http2_defaults(),
      2000,
      1500,
      1000,
      1000,
      1000,
    )
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      configuration,
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, cancelled_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/cancel"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, fast_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/fast"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, cancelled_request)
  let assert Ok(Nil) = send_frames(socket, fast_request)

  let assert Ok(request_context) =
    process.receive(captured_context, within: 1000)
  assert context.protocol(request_context) == context.Http2
  context.cancel(request_context)
  let assert Ok(#(socket, state, True, True)) =
    collect_reset_and_fast_response(socket, state, False, False, 5000)

  // A stream-local cancellation must not poison later streams on the same
  // authenticated connection.
  let assert Ok(wire.HeadersWritten(state, 5, healthy_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/healthy"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, healthy_request)
  let assert Ok(#(socket, _, [#(5, 204)])) =
    collect_responses(socket, state, [], 1)

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

fn repeat_stalled_handler_isolation(remaining: Int) -> Nil {
  case remaining > 0 {
    False -> Nil
    True -> {
      assert_stalled_handler_isolation()
      repeat_stalled_handler_isolation(remaining - 1)
    }
  }
}

fn assert_stalled_handler_isolation() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let stalled = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/stall" -> {
        process.send(stalled, Nil)
        process.sleep(1000)
      }
      _ -> Nil
    }
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(configuration) =
    server.with_http2_timeouts(
      server.http2_defaults(),
      2000,
      100,
      1000,
      1000,
      1000,
    )
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      configuration,
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, stalled_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/stall"),
      end_stream: True,
    )
  let assert Ok(wire.HeadersWritten(state, 3, fast_request)) =
    wire.send_request_headers(
      state,
      get_request(port, "/fast"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, stalled_request)
  let assert Ok(Nil) = send_frames(socket, fast_request)

  assert process.receive(stalled, within: 1000) == Ok(Nil)
  let assert Ok(#(socket, _, True, True)) =
    collect_reset_and_fast_response(socket, state, False, False, 5000)

  let assert Ok(Nil) = transport.close(socket)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn drain_sends_goaway_before_waiting_for_inflight_streams_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let released = process.new_subject()
  let source =
    body.pull(fn(_) {
      let release = process.new_subject()
      process.send(started, release)
      let release_outcome = process.receive(release, within: 30_000)
      process.send(released, release_outcome)
      Ok(body.PullEnd([]))
    })
  let assert Ok(response_body) =
    body.from_pull(source, None, None, fn() { Nil })
  let handler = fn(_, _) {
    Ok(response.Response(status: 200, headers: [], body: response_body))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, request_frames)) =
    wire.send_request_headers(
      state,
      get_request(port, "/drain"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, request_frames)
  let assert Ok(release) = process.receive(started, within: 1000)
  let assert Ok(admitted_snapshot) = server.http2_listener_snapshot(listener)
  assert admitted_snapshot.consistent
  assert admitted_snapshot.accepted_connections == 1
  assert admitted_snapshot.connection_start_attempts == 1
  assert admitted_snapshot.started_connections == 1
  assert admitted_snapshot.active_connections == 1

  let drained = process.new_subject()
  let _drainer =
    process.spawn_unlinked(fn() {
      process.send(drained, server.drain_listener(listener))
    })
  let assert Ok(drain_snapshot) =
    await_http2_goaway_sent(listener, within_milliseconds: 10_000)
  let #(socket, _, goaway_trace) =
    collect_goaway(socket, state, 8, within_milliseconds: 10_000)
  let drain_before_release = process.receive(drained, within: 0)
  process.send(release, Nil)
  let body_release = process.receive(released, within: 10_000)
  let drain_after_release = process.receive(drained, within: 10_000)
  let assert Ok(completed_snapshot) = server.http2_listener_snapshot(listener)

  let socket_close = transport.close(socket)
  let listener_stop = server.stop_listener(listener)
  let executor_stop = server.stop(executor)

  assert #(
      goaway_trace.terminal,
      goaway_trace.peer_goaways,
      drain_snapshot.state,
      drain_snapshot.drain_requests,
      drain_snapshot.connection_drain_commands,
      drain_snapshot.connection_drain_receipts,
      drain_snapshot.goaway_attempts,
      drain_snapshot.goaways_sent,
      drain_snapshot.goaway_failures,
      drain_snapshot.drain_completions,
      drain_before_release,
      body_release,
      drain_after_release,
    )
    == #(
      GoAwayObserved,
      [#(1, 0)],
      server.Draining,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      Error(Nil),
      Ok(Ok(Nil)),
      Ok(Ok(Nil)),
    )
  assert goaway_trace.read_attempts > 0
  assert goaway_trace.read_bytes > 0
  assert completed_snapshot.consistent
  assert completed_snapshot.state == server.Draining
  assert completed_snapshot.active_connections == 0
  assert completed_snapshot.exited_connections == 1
  assert completed_snapshot.drain_completions == 1
  assert socket_close == Ok(Nil)
  assert listener_stop == Ok(Nil)
  assert executor_stop == Ok(Nil)
  Nil
}

pub fn http2_listener_phase_snapshot_is_atomic_under_race_test() -> Nil {
  let #(
    violations,
    accepted,
    accept_failures,
    start_attempts,
    started,
    start_failures,
    active,
    exited,
    drain_requests,
    drain_commands,
    drain_receipts,
    goaway_attempts,
    goaways_sent,
    goaway_failures,
    drain_completions,
    connection_failures,
    maximum_start_milliseconds,
    maximum_goaway_milliseconds,
  ) = http_test_support.http2_listener_snapshot_race(20_000)
  assert violations == 0
  assert accepted == 40_000
  assert accept_failures == 20_000
  assert start_attempts == 40_000
  assert started == 20_000
  assert start_failures == 20_000
  assert active == 0
  assert exited == 20_000
  assert drain_requests == 20_000
  assert drain_commands == 40_000
  assert drain_receipts == 40_000
  assert goaway_attempts == 40_000
  assert goaways_sent == 20_000
  assert goaway_failures == 20_000
  assert drain_completions == 20_000
  assert connection_failures == 20_000
  assert maximum_start_milliseconds == 19_999
  assert maximum_goaway_milliseconds == 19_999
}

pub fn http2_listener_orphaned_writer_is_finite_and_observable_test() -> Nil {
  let #(snapshot_finished, writer_finished, explicitly_inconsistent) =
    http_test_support.http2_listener_orphaned_writer_trace()
  assert snapshot_finished
  assert writer_finished
  assert explicitly_inconsistent
}

pub fn http2_listener_snapshot_rejects_other_protocols_without_handles_test() -> Nil {
  let handler = fn(_, _) {
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let config = server.http1_defaults() |> server.allow_http1_cleartext
  let assert Ok(listener) =
    server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
  let assert Error(failure) = server.http2_listener_snapshot(listener)
  assert error.kind(failure) == error.Protocol(error.Http2)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

fn counted_response_source(
  pulled: process.Subject(Int),
  chunks: List(BitArray),
) -> body.Pull {
  body.pull(fn(_) {
    process.send(pulled, list.length(chunks))
    case chunks {
      [] -> Ok(body.PullEnd([]))
      [chunk, ..rest] ->
        Ok(body.PullData(chunk, counted_response_source(pulled, rest)))
    }
  })
}

fn open_priority_measurement_window(
  socket: transport.Socket,
  state: wire.State,
) -> Result(#(transport.Socket, wire.State), PriorityBarrierFailure) {
  use collected <- result.try(
    collect_responses(socket, state, [], 2)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure("response-heads", 0, 0, 0)
    }),
  )
  let #(socket, state, responses) = collected
  use _ <- result.try(
    case
      list.contains(responses, #(1, 200)) && list.contains(responses, #(3, 200))
    {
      True -> Ok(Nil)
      False -> Error(PriorityBarrierFailure("response-head-values", 0, 0, 0))
    },
  )

  use first_probe_credit <- result.try(
    control.encode(control.WindowUpdateFrame(1), 1, 16_384)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure("encode-first-probe-credit", 0, 0, 0)
    }),
  )
  use second_probe_credit <- result.try(
    control.encode(control.WindowUpdateFrame(1), 3, 16_384)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure("encode-second-probe-credit", 0, 0, 0)
    }),
  )
  use _ <- result.try(
    transport.send(
      socket,
      bit_array.concat([first_probe_credit, second_probe_credit]),
    )
    |> result.map_error(fn(_) {
      PriorityBarrierFailure("send-probe-credit", 0, 0, 64)
    }),
  )
  use probed <- result.try(collect_priority_probe(socket, state, 0, 0, 64))
  let #(socket, state, first_bytes, second_bytes) = probed

  use first_released <- result.try(
    wire.release_receive_credit(state, stream_id: 1, octets: first_bytes)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "release-first-probe-credit",
        first_bytes,
        second_bytes,
        64,
      )
    }),
  )
  let wire.ReceiveCreditReleased(state, first_release_frames) = first_released
  use second_released <- result.try(
    wire.release_receive_credit(state, stream_id: 3, octets: second_bytes)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "release-second-probe-credit",
        first_bytes,
        second_bytes,
        64,
      )
    }),
  )
  let wire.ReceiveCreditReleased(state, second_release_frames) = second_released

  let additional_credit = 65_535 - first_bytes
  use first_measurement_credit <- result.try(
    control.encode(control.WindowUpdateFrame(additional_credit), 1, 16_384)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "encode-first-measurement-credit",
        first_bytes,
        second_bytes,
        64,
      )
    }),
  )
  use second_measurement_credit <- result.try(
    control.encode(control.WindowUpdateFrame(65_535 - second_bytes), 3, 16_384)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "encode-second-measurement-credit",
        first_bytes,
        second_bytes,
        64,
      )
    }),
  )
  let measurement_credit =
    list.append(first_release_frames, second_release_frames)
    |> list.append([first_measurement_credit, second_measurement_credit])
    |> bit_array.concat
  use _ <- result.try(
    transport.send(socket, measurement_credit)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "send-measurement-credit",
        first_bytes,
        second_bytes,
        64,
      )
    }),
  )
  Ok(#(socket, state))
}

fn collect_priority_probe(
  socket: transport.Socket,
  state: wire.State,
  first_bytes: Int,
  second_bytes: Int,
  remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State, Int, Int), PriorityBarrierFailure) {
  case first_bytes >= 1 && second_bytes >= 1, remaining_reads > 0 {
    True, _ -> Ok(#(socket, state, first_bytes, second_bytes))
    False, False ->
      Error(PriorityBarrierFailure(
        "probe-exhausted",
        first_bytes,
        second_bytes,
        remaining_reads,
      ))
    False, True -> {
      use read <- result.try(
        transport.read(socket, 65_536, 1000)
        |> result.map_error(fn(_) {
          PriorityBarrierFailure(
            "probe-read",
            first_bytes,
            second_bytes,
            remaining_reads,
          )
        }),
      )
      case read {
        transport.ReadEnd(_) ->
          Error(PriorityBarrierFailure(
            "probe-read-end",
            first_bytes,
            second_bytes,
            remaining_reads,
          ))
        transport.ReadData(bytes, socket) ->
          continue_priority_probe(
            socket,
            state,
            bytes,
            first_bytes,
            second_bytes,
            remaining_reads,
          )
      }
    }
  }
}

fn continue_priority_probe(
  socket: transport.Socket,
  state: wire.State,
  bytes: BitArray,
  first_bytes: Int,
  second_bytes: Int,
  remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State, Int, Int), PriorityBarrierFailure) {
  use fed <- result.try(
    wire.feed(state, bytes)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "probe-wire-feed",
        first_bytes,
        second_bytes,
        remaining_reads,
      )
    }),
  )
  let wire.Fed(state, actions) = fed
  use automatic <- result.try(
    wire.automatic_writes(actions, 16_384)
    |> result.map_error(fn(_) {
      PriorityBarrierFailure(
        "probe-automatic-writes",
        first_bytes,
        second_bytes,
        remaining_reads,
      )
    }),
  )
  use _ <- result.try(send_priority_frames(
    socket,
    automatic,
    "probe-send-automatic",
    first_bytes,
    second_bytes,
    remaining_reads,
  ))
  let #(first_bytes, second_bytes) =
    count_stream_data(actions, first_bytes, second_bytes)
  collect_priority_probe(
    socket,
    state,
    first_bytes,
    second_bytes,
    remaining_reads - 1,
  )
}

fn send_priority_frames(
  socket: transport.Socket,
  frames: List(BitArray),
  stage: String,
  first_bytes: Int,
  second_bytes: Int,
  remaining_reads: Int,
) -> Result(Nil, PriorityBarrierFailure) {
  case frames {
    [] -> Ok(Nil)
    [frame, ..rest] -> {
      use _ <- result.try(
        transport.send(socket, frame)
        |> result.map_error(fn(_) {
          PriorityBarrierFailure(
            stage,
            first_bytes,
            second_bytes,
            remaining_reads,
          )
        }),
      )
      send_priority_frames(
        socket,
        rest,
        stage,
        first_bytes,
        second_bytes,
        remaining_reads,
      )
    }
  }
}

fn collect_initial_data(
  socket: transport.Socket,
  state: wire.State,
  first_bytes: Int,
  second_bytes: Int,
  remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State, Int, Int), #(Int, Int, Int)) {
  case first_bytes + second_bytes >= 65_535, remaining_reads > 0 {
    True, _ -> Ok(#(socket, state, first_bytes, second_bytes))
    False, False -> Error(#(first_bytes, second_bytes, remaining_reads))
    False, True -> {
      use read <- result.try(
        transport.read(socket, 65_536, 1000)
        |> result.map_error(fn(_) {
          #(first_bytes, second_bytes, remaining_reads)
        }),
      )
      let assert transport.ReadData(bytes, socket) = read
      use fed <- result.try(
        wire.feed(state, bytes)
        |> result.map_error(fn(_) {
          #(first_bytes, second_bytes, remaining_reads)
        }),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(fn(_) {
          #(first_bytes, second_bytes, remaining_reads)
        }),
      )
      use _ <- result.try(
        send_frames(socket, automatic)
        |> result.map_error(fn(_) {
          #(first_bytes, second_bytes, remaining_reads)
        }),
      )
      let #(first_bytes, second_bytes) =
        count_stream_data(actions, first_bytes, second_bytes)
      collect_initial_data(
        socket,
        state,
        first_bytes,
        second_bytes,
        remaining_reads - 1,
      )
    }
  }
}

fn count_stream_data(
  actions: List(connection.Action),
  first_bytes: Int,
  second_bytes: Int,
) -> #(Int, Int) {
  case actions {
    [] -> #(first_bytes, second_bytes)
    [connection.DataReceived(1, bytes, _, _), ..rest] ->
      count_stream_data(
        rest,
        first_bytes + bit_array.byte_size(bytes),
        second_bytes,
      )
    [connection.DataReceived(3, bytes, _, _), ..rest] ->
      count_stream_data(
        rest,
        first_bytes,
        second_bytes + bit_array.byte_size(bytes),
      )
    [_, ..rest] -> count_stream_data(rest, first_bytes, second_bytes)
  }
}

fn collect_reset_and_fast_response(
  socket: transport.Socket,
  state: wire.State,
  reset_seen: Bool,
  fast_seen: Bool,
  within_milliseconds: Int,
) -> Result(#(transport.Socket, wire.State, Bool, Bool), IsolationTrace) {
  collect_reset_and_fast_response_until(
    socket,
    state,
    reset_seen,
    fast_seen,
    [],
    [],
    [],
    transport.monotonic_millisecond() + within_milliseconds,
  )
}

fn collect_reset_and_fast_response_until(
  socket: transport.Socket,
  state: wire.State,
  reset_seen: Bool,
  fast_seen: Bool,
  response_statuses: List(#(Int, Int)),
  stream_resets: List(#(Int, Int)),
  peer_goaways: List(#(Int, Int)),
  deadline: Int,
) -> Result(#(transport.Socket, wire.State, Bool, Bool), IsolationTrace) {
  let remaining = deadline - transport.monotonic_millisecond()
  case reset_seen && fast_seen, remaining > 0 {
    True, _ -> Ok(#(socket, state, reset_seen, fast_seen))
    False, False ->
      Error(isolation_trace(
        reset_seen,
        fast_seen,
        response_statuses,
        stream_resets,
        peer_goaways,
        IsolationDeadline,
      ))
    False, True -> {
      case transport.read(socket, 65_536, int.max(remaining, 1)) {
        Error(_) ->
          Error(isolation_trace(
            reset_seen,
            fast_seen,
            response_statuses,
            stream_resets,
            peer_goaways,
            IsolationReadFailure,
          ))
        Ok(transport.ReadEnd(_)) ->
          Error(isolation_trace(
            reset_seen,
            fast_seen,
            response_statuses,
            stream_resets,
            peer_goaways,
            IsolationReadEnd,
          ))
        Ok(transport.ReadData(bytes, socket)) -> {
          let wire_failure =
            isolation_trace(
              reset_seen,
              fast_seen,
              response_statuses,
              stream_resets,
              peer_goaways,
              IsolationWireFailure,
            )
          use fed <- result.try(
            wire.feed(state, bytes)
            |> result.replace_error(wire_failure),
          )
          let wire.Fed(state, actions) = fed
          use automatic <- result.try(
            wire.automatic_writes(actions, 16_384)
            |> result.replace_error(wire_failure),
          )
          use _ <- result.try(
            send_frames(socket, automatic)
            |> result.replace_error(wire_failure),
          )
          let #(
            reset_seen,
            fast_seen,
            response_statuses,
            stream_resets,
            peer_goaways,
          ) =
            observe_isolation_actions(
              actions,
              reset_seen,
              fast_seen,
              response_statuses,
              stream_resets,
              peer_goaways,
            )
          collect_reset_and_fast_response_until(
            socket,
            state,
            reset_seen,
            fast_seen,
            response_statuses,
            stream_resets,
            peer_goaways,
            deadline,
          )
        }
      }
    }
  }
}

fn isolation_trace(
  reset_seen: Bool,
  fast_seen: Bool,
  response_statuses: List(#(Int, Int)),
  stream_resets: List(#(Int, Int)),
  peer_goaways: List(#(Int, Int)),
  terminal: IsolationTerminal,
) -> IsolationTrace {
  IsolationTrace(
    reset_seen:,
    fast_seen:,
    response_statuses: list.reverse(response_statuses),
    stream_resets: list.reverse(stream_resets),
    peer_goaways: list.reverse(peer_goaways),
    terminal:,
  )
}

fn collect_goaway(
  socket: transport.Socket,
  state: wire.State,
  remaining_reads: Int,
  within_milliseconds within_milliseconds: Int,
) -> #(transport.Socket, wire.State, GoAwayTrace) {
  collect_goaway_until(
    socket,
    state,
    remaining_reads,
    transport.monotonic_millisecond() + within_milliseconds,
    0,
    0,
    [],
  )
}

fn collect_goaway_until(
  socket: transport.Socket,
  state: wire.State,
  remaining_reads: Int,
  deadline: Int,
  read_attempts: Int,
  read_bytes: Int,
  peer_goaways: List(#(Int, Int)),
) -> #(transport.Socket, wire.State, GoAwayTrace) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining_reads > 0, remaining > 0 {
    False, _ -> #(
      socket,
      state,
      goaway_trace(read_attempts, read_bytes, peer_goaways, GoAwayReadLimit),
    )
    _, False -> #(
      socket,
      state,
      goaway_trace(read_attempts, read_bytes, peer_goaways, GoAwayReadDeadline),
    )
    True, True ->
      case transport.read(socket, 65_536, int.max(remaining, 1)) {
        Error(transport.Timeout) -> #(
          socket,
          state,
          goaway_trace(
            read_attempts + 1,
            read_bytes,
            peer_goaways,
            GoAwayReadDeadline,
          ),
        )
        Error(failure) -> #(
          socket,
          state,
          goaway_trace(
            read_attempts + 1,
            read_bytes,
            peer_goaways,
            GoAwayReadFailure(failure),
          ),
        )
        Ok(transport.ReadEnd(socket)) -> #(
          socket,
          state,
          goaway_trace(
            read_attempts + 1,
            read_bytes,
            peer_goaways,
            GoAwayReadEnd,
          ),
        )
        Ok(transport.ReadData(bytes, socket)) -> {
          let next_attempts = read_attempts + 1
          let next_bytes = read_bytes + bit_array.byte_size(bytes)
          collect_goaway_bytes(
            socket,
            state,
            bytes,
            remaining_reads,
            deadline,
            next_attempts,
            next_bytes,
            peer_goaways,
          )
        }
      }
  }
}

fn collect_goaway_bytes(
  socket: transport.Socket,
  state: wire.State,
  bytes: BitArray,
  remaining_reads: Int,
  deadline: Int,
  read_attempts: Int,
  read_bytes: Int,
  peer_goaways: List(#(Int, Int)),
) -> #(transport.Socket, wire.State, GoAwayTrace) {
  case wire.feed(state, bytes) {
    Error(failure) -> #(
      socket,
      state,
      goaway_trace(
        read_attempts,
        read_bytes,
        peer_goaways,
        GoAwayWireFailure(failure),
      ),
    )
    Ok(wire.Fed(state, actions)) ->
      collect_goaway_actions(
        socket,
        state,
        actions,
        remaining_reads,
        deadline,
        read_attempts,
        read_bytes,
        peer_goaways,
      )
  }
}

fn collect_goaway_actions(
  socket: transport.Socket,
  state: wire.State,
  actions: List(connection.Action),
  remaining_reads: Int,
  deadline: Int,
  read_attempts: Int,
  read_bytes: Int,
  peer_goaways: List(#(Int, Int)),
) -> #(transport.Socket, wire.State, GoAwayTrace) {
  let peer_goaways = collect_peer_goaways(actions, peer_goaways)
  case wire.automatic_writes(actions, 16_384) {
    Error(failure) -> #(
      socket,
      state,
      goaway_trace(
        read_attempts,
        read_bytes,
        peer_goaways,
        GoAwayAutomaticWriteFailure(failure),
      ),
    )
    Ok(automatic) ->
      collect_goaway_after_automatic_writes(
        socket,
        state,
        automatic,
        remaining_reads,
        deadline,
        read_attempts,
        read_bytes,
        peer_goaways,
      )
  }
}

fn collect_goaway_after_automatic_writes(
  socket: transport.Socket,
  state: wire.State,
  automatic: List(BitArray),
  remaining_reads: Int,
  deadline: Int,
  read_attempts: Int,
  read_bytes: Int,
  peer_goaways: List(#(Int, Int)),
) -> #(transport.Socket, wire.State, GoAwayTrace) {
  case send_frames_traced(socket, automatic) {
    Error(failure) -> #(
      socket,
      state,
      goaway_trace(
        read_attempts,
        read_bytes,
        peer_goaways,
        GoAwayAutomaticSendFailure(failure),
      ),
    )
    Ok(Nil) ->
      case list.contains(peer_goaways, #(1, 0)) {
        True -> #(
          socket,
          state,
          goaway_trace(read_attempts, read_bytes, peer_goaways, GoAwayObserved),
        )
        False ->
          collect_goaway_until(
            socket,
            state,
            remaining_reads - 1,
            deadline,
            read_attempts,
            read_bytes,
            peer_goaways,
          )
      }
  }
}

fn goaway_trace(
  read_attempts: Int,
  read_bytes: Int,
  peer_goaways: List(#(Int, Int)),
  terminal: GoAwayTerminal,
) -> GoAwayTrace {
  GoAwayTrace(
    read_attempts:,
    read_bytes:,
    peer_goaways: list.reverse(peer_goaways),
    terminal:,
  )
}

fn collect_peer_goaways(
  actions: List(connection.Action),
  peer_goaways: List(#(Int, Int)),
) -> List(#(Int, Int)) {
  case actions {
    [] -> peer_goaways
    [connection.PeerGoAway(last_stream_id, error_code, _), ..rest] ->
      collect_peer_goaways(rest, [#(last_stream_id, error_code), ..peer_goaways])
    [_, ..rest] -> collect_peer_goaways(rest, peer_goaways)
  }
}

fn await_http2_goaway_sent(
  listener: server.Listener,
  within_milliseconds within_milliseconds: Int,
) -> Result(server.Http2ListenerSnapshot, server.Http2ListenerSnapshot) {
  let deadline = transport.monotonic_millisecond() + within_milliseconds
  await_http2_goaway_sent_until(listener, deadline)
}

fn await_http2_goaway_sent_until(
  listener: server.Listener,
  deadline: Int,
) -> Result(server.Http2ListenerSnapshot, server.Http2ListenerSnapshot) {
  let assert Ok(snapshot) = server.http2_listener_snapshot(listener)
  case snapshot.goaways_sent > 0, transport.monotonic_millisecond() < deadline {
    True, _ -> Ok(snapshot)
    False, True -> {
      process.sleep(1)
      await_http2_goaway_sent_until(listener, deadline)
    }
    False, False -> Error(snapshot)
  }
}

fn receive_extended_connect_setting(
  socket: transport.Socket,
  state: wire.State,
  remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State), Nil) {
  case
    peer_settings.extended_connect_enabled(
      connection.peer_settings(wire.connection_state(state)),
    ),
    remaining_reads > 0
  {
    True, _ -> Ok(#(socket, state))
    False, False -> Error(Nil)
    False, True -> {
      use read <- result.try(
        transport.read(socket, 65_536, 500) |> result.map_error(fn(_) { Nil }),
      )
      let assert transport.ReadData(bytes, socket) = read
      use fed <- result.try(
        wire.feed(state, bytes) |> result.map_error(fn(_) { Nil }),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(fn(_) { Nil }),
      )
      use _ <- result.try(send_frames(socket, automatic))
      receive_extended_connect_setting(socket, state, remaining_reads - 1)
    }
  }
}

fn receive_ping_acknowledgement(
  socket: transport.Socket,
  state: wire.State,
  expected: BitArray,
  remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State), Nil) {
  case remaining_reads > 0 {
    False -> Error(Nil)
    True -> {
      use read <- result.try(
        transport.read(socket, 65_536, 500) |> result.map_error(fn(_) { Nil }),
      )
      let assert transport.ReadData(bytes, socket) = read
      use fed <- result.try(
        wire.feed(state, bytes) |> result.map_error(fn(_) { Nil }),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(fn(_) { Nil }),
      )
      use _ <- result.try(send_frames(socket, automatic))
      case has_ping_acknowledgement(actions, expected) {
        True -> Ok(#(socket, state))
        False ->
          receive_ping_acknowledgement(
            socket,
            state,
            expected,
            remaining_reads - 1,
          )
      }
    }
  }
}

fn has_ping_acknowledgement(
  actions: List(connection.Action),
  expected: BitArray,
) -> Bool {
  case actions {
    [] -> False
    [connection.PingAcknowledged(payload), ..] -> payload == expected
    [_, ..rest] -> has_ping_acknowledgement(rest, expected)
  }
}

fn observe_isolation_actions(
  actions: List(connection.Action),
  reset_seen: Bool,
  fast_seen: Bool,
  response_statuses: List(#(Int, Int)),
  stream_resets: List(#(Int, Int)),
  peer_goaways: List(#(Int, Int)),
) -> #(Bool, Bool, List(#(Int, Int)), List(#(Int, Int)), List(#(Int, Int))) {
  case actions {
    [] -> #(
      reset_seen,
      fast_seen,
      response_statuses,
      stream_resets,
      peer_goaways,
    )
    [connection.StreamReset(stream_id, error_code), ..rest] ->
      observe_isolation_actions(
        rest,
        reset_seen || { stream_id == 1 && error_code == 0x2 },
        fast_seen,
        response_statuses,
        [#(stream_id, error_code), ..stream_resets],
        peer_goaways,
      )
    [
      connection.HeadersReceived(header_codec.HeaderSection(
        stream_id,
        _,
        header_semantics.Validated(
          header_semantics.ResponseControlData(status),
          _,
          _,
        ),
        _,
      )),
      ..rest
    ] ->
      observe_isolation_actions(
        rest,
        reset_seen,
        fast_seen || { stream_id == 3 && status == 204 },
        [#(stream_id, status), ..response_statuses],
        stream_resets,
        peer_goaways,
      )
    [connection.PeerGoAway(last_stream_id, error_code, _), ..rest] ->
      observe_isolation_actions(
        rest,
        reset_seen,
        fast_seen,
        response_statuses,
        stream_resets,
        [#(last_stream_id, error_code), ..peer_goaways],
      )
    [_, ..rest] ->
      observe_isolation_actions(
        rest,
        reset_seen,
        fast_seen,
        response_statuses,
        stream_resets,
        peer_goaways,
      )
  }
}

fn get_request(port: Int, path: String) -> request.Request(body.Body) {
  request.Request(
    method: gleam_http.Get,
    headers: [],
    body: body.empty(),
    scheme: gleam_http.Https,
    host: "localhost",
    port: Some(port),
    path:,
    query: None,
  )
}

fn connect_request(port: Int) -> request.Request(body.Body) {
  request.Request(
    method: gleam_http.Connect,
    headers: [],
    body: body.empty(),
    scheme: gleam_http.Https,
    host: "localhost",
    port: Some(port),
    path: "/chat",
    query: None,
  )
}

fn collect_responses(
  socket: transport.Socket,
  state: wire.State,
  reversed: List(#(Int, Int)),
  expected: Int,
) -> Result(#(transport.Socket, wire.State, List(#(Int, Int))), Nil) {
  case list.length(reversed) >= expected {
    True -> Ok(#(socket, state, list.reverse(reversed)))
    False -> {
      use read <- result.try(
        transport.read(socket, 65_536, 1000) |> result.map_error(fn(_) { Nil }),
      )
      let assert transport.ReadData(bytes, socket) = read
      use fed <- result.try(
        wire.feed(state, bytes) |> result.map_error(fn(_) { Nil }),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(fn(_) { Nil }),
      )
      use _ <- result.try(send_frames(socket, automatic))
      collect_responses(
        socket,
        state,
        response_actions(actions, reversed),
        expected,
      )
    }
  }
}

fn response_actions(
  actions: List(connection.Action),
  reversed: List(#(Int, Int)),
) -> List(#(Int, Int)) {
  case actions {
    [] -> reversed
    [
      connection.HeadersReceived(header_codec.HeaderSection(
        stream_id,
        _,
        header_semantics.Validated(
          header_semantics.ResponseControlData(status),
          _,
          _,
        ),
        _,
      )),
      ..rest
    ] -> response_actions(rest, [#(stream_id, status), ..reversed])
    [_, ..rest] -> response_actions(rest, reversed)
  }
}

fn send_frames(
  socket: transport.Socket,
  frames: List(BitArray),
) -> Result(Nil, Nil) {
  send_frames_traced(socket, frames) |> result.map_error(fn(_) { Nil })
}

fn send_frames_traced(
  socket: transport.Socket,
  frames: List(BitArray),
) -> Result(Nil, transport.Error) {
  case frames {
    [] -> Ok(Nil)
    [frame, ..rest] -> {
      use _ <- result.try(transport.send(socket, frame))
      send_frames_traced(socket, rest)
    }
  }
}

fn connection_limits() -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 64,
    maximum_active_streams: 16,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 4096,
      maximum_header_list_bytes: 8192,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: 16,
    ),
  )
}

fn wire_limits() -> wire.Limits {
  wire.Limits(
    maximum_frame_bytes: 16_384,
    maximum_feed_bytes: 65_536,
    maximum_frames_per_feed: 32,
  )
}
