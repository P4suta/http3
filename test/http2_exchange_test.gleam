import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int as gleam_int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/client_trace
import http/internal/http2/connection
import http/internal/http2/exchange
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/message
import http/internal/http2/preface
import http/internal/http2/wire
import http/internal/transport
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
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

fn get_request(port: Int) -> request.Request(body.Body) {
  request.Request(
    method: gleam_http.Get,
    headers: [#("x-client", "h2")],
    body: body.empty(),
    scheme: gleam_http.Https,
    host: "localhost",
    port: Some(port),
    path: "/h2",
    query: None,
  )
}

pub fn authenticated_h2_round_trip_uses_incremental_wire_state_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(state) =
        wire.new(connection.Server, connection_limits(), wire_limits())
      let assert Ok(wire.Started(state, initial)) =
        wire.initial_bytes(state, [])
      let assert Ok(Nil) = transport.send(socket, initial)
      let #(socket, state, incoming) = await_request(socket, state)
      let outgoing =
        response.Response(
          status: 200,
          headers: [#("x-server", "h2")],
          body: Nil,
        )
      let assert Ok(wire.HeadersWritten(state, 1, headers)) =
        wire.send_response_headers(state, 1, outgoing, end_stream: False)
      send_all(socket, headers)
      let assert Ok(wire.DataWritten(_, data, <<>>, True)) =
        wire.send_data(
          state,
          stream_id: 1,
          bytes: <<"hello">>,
          end_stream: True,
        )
      send_all(socket, data)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      incoming
    })
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])

  let outcome = exchange.run(get_request(port), config)
  let assert Ok(exchange.Http2Response(incoming)) = outcome

  assert incoming.status == 200
  assert response.get_header(incoming, "x-server") == Ok("h2")
  let assert Ok(#(<<"hello">>, [])) = body.read_all(incoming.body, 16)
  let received = http_test_support.await_task(server_task)
  assert received.method == gleam_http.Get
  assert received.path == "/h2"
  assert received.headers == [#("x-client", "h2")]
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn authenticated_reset_before_response_keeps_http2_diagnostic_protocol_test() -> Nil {
  let #(certificate, private_key, ca) = http_test_support.server_credentials()
  let finished = process.new_subject()
  let released = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(32, 1000, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptFinished(_, protocol, outcome),
        ) -> process.send(finished, #(protocol, result.is_error(outcome)))
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptReleased(_, protocol, _),
        ) -> process.send(released, protocol)
        _ -> Nil
      }
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  let assert Ok(listener) =
    transport.listen(<<127, 0, 0, 1>>, 0, 8, 2000) |> result.replace_error(Nil)
  let assert Ok(endpoint) =
    transport.local_endpoint(listener) |> result.replace_error(Nil)
  let #(_, port) = endpoint
  let peer =
    http_test_support.start_task(fn() {
      let assert Ok(socket) =
        transport.accept(listener, 2000) |> result.replace_error(Nil)
      let assert Ok(ready) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          2000,
        )
        |> result.replace_error(Nil)
      let transport.TlsReady(socket, selected, _) = ready
      let assert Ok(state) =
        wire.new(connection.Server, connection_limits(), wire_limits())
        |> result.replace_error(Nil)
      let assert Ok(started) =
        wire.initial_bytes(state, []) |> result.replace_error(Nil)
      let wire.Started(state, initial) = started
      assert result.is_ok(transport.send(socket, initial))
      let #(socket, state, _) = await_request(socket, state)
      let assert Ok(written) =
        wire.send_response_headers(state, 1, response.new(200), False)
        |> result.replace_error(Nil)
      let wire.HeadersWritten(state, _, headers) = written
      let assert Ok(reset) =
        wire.reset_stream(state, 1, 2) |> result.replace_error(Nil)
      let wire.ControlWritten(_, frames) = reset
      // One TLS write keeps the final header and failure in one input batch.
      let sent =
        transport.send(socket, bit_array.concat(list.append(headers, frames)))
      let peer_closed = case await_socket_end(socket) {
        Ok(_) | Error(transport.Closed) -> True
        _ -> False
      }
      let _closed = transport.close(socket)
      selected == <<"h2">> && result.is_ok(sent) && peer_closed
    })
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca])
    |> exchange.with_trace(trace)
  let outcome = exchange.run(get_request(port), config)
  let peer_closed = http_test_support.await_task(peer)
  let _stopped = transport.stop(listener)
  let finished_event = process.receive(finished, within: 1000)
  let released_event = process.receive(released, within: 1000)
  let reporter_stopped = diagnostics.stop(reporter)
  assert result.is_error(outcome)
  assert peer_closed
  assert finished_event == Ok(#(Some(context.Http2), True))
  assert released_event == Ok(Some(context.Http2))
  assert process.receive(finished, within: 0) == Error(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert reporter_stopped == Ok(Nil)
}

pub fn complete_early_response_and_no_error_reset_preserve_body_and_cleanup_test() -> Nil {
  let #(certificate, private_key, ca) = http_test_support.server_credentials()
  let disposed = process.new_subject()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 2000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let peer =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 2000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          2000,
        )
      let assert Ok(state) =
        wire.new(connection.Server, connection_limits(), wire_limits())
      let assert Ok(wire.Started(state, initial)) =
        wire.initial_bytes(state, [])
      let assert Ok(Nil) = transport.send(socket, initial)
      let #(socket, state, _) = await_request(socket, state)
      let assert Ok(wire.HeadersWritten(state, 1, headers)) =
        wire.send_response_headers(
          state,
          1,
          response.new(201),
          end_stream: False,
        )
      let assert Ok(wire.DataWritten(state, data, <<>>, True)) =
        wire.send_data(
          state,
          stream_id: 1,
          bytes: <<"complete">>,
          end_stream: True,
        )
      let assert Ok(wire.ControlWritten(_, reset)) =
        wire.reset_stream(state, stream_id: 1, error_code: 0)
      let assert Ok(duplicate) =
        frame.encode(frame.RstStream, 0, 1, <<5:size(32)>>, 16_384)
      let bytes =
        list.append(headers, list.append(data, list.append(reset, [duplicate])))
        |> bit_array.concat
      let assert Ok(Nil) = transport.send(socket, bytes)
      let closed = case await_socket_end(socket) {
        Ok(_) | Error(transport.Closed) -> True
        _ -> False
      }
      let _closed = transport.close(socket)
      closed
    })
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        let _never = process.receive(process.new_subject(), within: 5000)
        Ok(body.PullEnd([]))
      }),
      Some(0),
      None,
      fn() { process.send(disposed, Nil) },
    )
  let outgoing = get_request(port) |> request.set_body(source)
  let config = exchange.defaults() |> exchange.with_ca_certificates([ca])
  let outcome = case exchange.run(outgoing, config) {
    Ok(exchange.Http2Response(incoming)) -> {
      let collected = body.read_all(incoming.body, 8)
      incoming.status == 201 && collected == Ok(#(<<"complete">>, []))
    }
    _ -> False
  }
  let peer_closed = http_test_support.await_task(peer)
  let _stopped = transport.stop(listener)
  body.cancel(source)
  assert outcome
  assert peer_closed
  assert process.receive(disposed, within: 1000) == Ok(Nil)
  assert process.receive(disposed, within: 0) == Error(Nil)
}

pub fn cancelling_streaming_response_after_headers_closes_h2_socket_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(state) =
        wire.new(connection.Server, connection_limits(), wire_limits())
      let assert Ok(wire.Started(state, initial)) =
        wire.initial_bytes(state, [])
      let assert Ok(Nil) = transport.send(socket, initial)
      let #(socket, state, _) = await_request(socket, state)
      let outgoing =
        response.Response(
          status: 200,
          headers: [
            #("content-length", "5"),
          ],
          body: Nil,
        )
      let assert Ok(wire.HeadersWritten(_, 1, headers)) =
        wire.send_response_headers(state, 1, outgoing, end_stream: False)
      send_all(socket, headers)
      let assert Ok(socket) = await_socket_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])

  let assert Ok(exchange.Http2Response(incoming)) =
    exchange.run(get_request(port), config)
  body.cancel(incoming.body)
  let assert Error(failure) = body.read(incoming.body, 1)
  assert error.kind(failure) == error.Cancelled
  assert http_test_support.await_task(server_task) == Nil
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn negotiated_http1_returns_before_sending_any_application_bytes_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"http/1.1">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"http/1.1">>],
          1000,
        )
      let assert Ok(transport.ReadEnd(socket)) = transport.read(socket, 1, 1000)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])

  assert exchange.run(get_request(port), config) == Ok(exchange.Http1Required)
  assert http_test_support.await_task(server_task) == Nil
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn pooled_http1_contender_is_authenticated_before_single_use_selection_test() -> Nil {
  let #(certificate, key, ca) = http_test_support.server_credentials()
  let events = process.new_subject()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 10_000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let peer =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 10_000)
      let assert Ok(ready) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          key,
          [<<"http/1.1">>],
          10_000,
        )
      let transport.TlsReady(socket, _, _) = ready
      let no_application_bytes = case transport.read(socket, 1, 10_000) {
        Ok(transport.ReadEnd(_)) | Error(transport.Closed) -> True
        _ -> False
      }
      let _closed = transport.close(socket)
      no_application_bytes
    })
  let assert Ok(socket) = transport.connect("127.0.0.1", port, 10_000, 10_000)
  let assert Ok(secured) =
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca],
      [<<"http/1.1">>],
      10_000,
    )
  let transport.TlsReady(socket, selected, _) = secured
  let authenticated_http1 = selected == <<"http/1.1">>
  assert authenticated_http1
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(events, 7)
        Ok(body.PullEnd([]))
      }),
      Some(0),
      None,
      fn() { process.send(events, 8) },
    )
  let outgoing = get_request(port) |> request.set_body(source)
  let config =
    exchange.defaults()
    |> exchange.with_pool(
      fn(_) {
        process.send(events, 1)
        Ok(None)
      },
      fn(_, _, _, _) { False },
    )
    |> exchange.with_http1_pool(fn(origin) {
      let correct_origin =
        origin == "https://localhost:" <> gleam_int.to_string(port)
      assert correct_origin
      process.send(events, 2)
      Ok(Some(socket))
    })
    |> exchange.with_http1_fallback(fn(_, _, _, _) {
      process.send(events, 5)
      Error(error.new(error.Service))
    })
    |> exchange.with_lifecycle(
      fn(_, _) {
        process.send(events, 3)
        Ok(fn() { process.send(events, 4) })
      },
      fn() { False },
    )
    |> exchange.with_admission(
      fn(_) {
        process.send(events, 6)
        Error(error.new(error.Resource(error.Connections)))
      },
      fn(_, _) { Ok(Nil) },
    )
  let assert Ok(ready) = exchange.prepare_connection(outgoing, config)
  assert process.receive(events, within: 0) == Ok(1)
  assert process.receive(events, within: 0) == Ok(2)
  assert process.receive(events, within: 0) == Ok(3)
  assert process.receive(events, within: 0) == Error(Nil)
  exchange.discard_ready(ready)
  exchange.discard_ready(ready)
  let rejected = case exchange.run_ready(ready) {
    Error(failure) -> error.kind(failure) == error.Cancelled
    Ok(_) -> False
  }
  let peer_closed_without_request = http_test_support.await_task(peer)
  let _stopped = transport.stop(listener)
  assert rejected
  assert peer_closed_without_request
  assert process.receive(events, within: 0) == Ok(4)
  assert process.receive(events, within: 0) == Error(Nil)
  body.cancel(source)
  assert process.receive(events, within: 0) == Ok(8)
}

pub fn request_body_and_trailers_resume_after_peer_flow_control_credit_test() -> Nil {
  let pull_budgets = process.new_subject()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let payload = string.repeat("x", times: 70_000) |> bit_array.from_string
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(
        transport.accept(listener, 1000)
        |> result.map_error(fn(_) { Nil }),
      )
      use ready <- result.try(
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
        |> result.map_error(fn(_) { Nil }),
      )
      let transport.TlsReady(socket, _, _) = ready
      use state <- result.try(
        wire.new(connection.Server, connection_limits(), wire_limits())
        |> result.map_error(fn(_) { Nil }),
      )
      use started <- result.try(
        wire.initial_bytes(state, []) |> result.map_error(fn(_) { Nil }),
      )
      let wire.Started(state, initial) = started
      use _ <- result.try(
        transport.send(socket, initial) |> result.map_error(fn(_) { Nil }),
      )
      use received <- result.try(
        receive_complete_request(socket, state, None, [], []),
      )
      let #(socket, state, incoming, request_body, trailers) = received
      let outgoing = response.Response(status: 204, headers: [], body: Nil)
      use written <- result.try(
        wire.send_response_headers(state, 1, outgoing, end_stream: True)
        |> result.map_error(fn(_) { Nil }),
      )
      let wire.HeadersWritten(_, _, frames) = written
      use _ <- result.try(send_all_result(socket, frames))
      let socket = drain_until_end(socket)
      let _close_result = transport.close(socket)
      Ok(#(incoming, request_body, trailers))
    })
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [],
      body: streamed_upload(70_000, pull_budgets),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/upload",
      query: None,
    )
  let assert Ok(config) =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])
    |> exchange.with_body_limits(100_000, 8192)

  let outcome = exchange.run(outgoing, config)
  let server_outcome = http_test_support.await_task(server_task)
  let assert Ok(exchange.Http2Response(incoming)) = outcome
  assert incoming.status == 204
  let assert Ok(#(received, request_body, trailers)) = server_outcome
  assert received.method == gleam_http.Post
  assert request_body == payload
  assert trailers == [#("checksum", "yes")]
  assert collect_pull_budgets(pull_budgets, []) == list.repeat(8192, 10)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

fn streamed_upload(remaining: Int, budgets: process.Subject(Int)) -> body.Body {
  let assert Ok(source) =
    body.from_pull(upload_pull(remaining, budgets), None, None, fn() { Nil })
  source
}

fn upload_pull(remaining: Int, budgets: process.Subject(Int)) -> body.Pull {
  body.pull(fn(maximum) {
    process.send(budgets, maximum)
    case remaining {
      0 -> Ok(body.PullEnd([#("checksum", "yes")]))
      _ -> {
        let count = case remaining < maximum {
          True -> remaining
          False -> maximum
        }
        Ok(body.PullData(
          string.repeat("x", count) |> bit_array.from_string,
          upload_pull(remaining - count, budgets),
        ))
      }
    }
  })
}

fn collect_pull_budgets(
  budgets: process.Subject(Int),
  reversed: List(Int),
) -> List(Int) {
  case process.receive(budgets, within: 0) {
    Ok(budget) -> collect_pull_budgets(budgets, [budget, ..reversed])
    Error(Nil) -> list.reverse(reversed)
  }
}

pub fn operation_deadline_bounds_a_stalled_h2_response_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, _, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
      let assert Ok(Nil) = transport.send(socket, initial)
      let assert Ok(transport.ReadData(_, socket)) =
        transport.read(socket, 65_536, 1000)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let assert Ok(config) =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])
    |> exchange.with_timeouts(500, 500, 500, 50, 500, 1000)

  let outcome = exchange.run(get_request(port), config)
  assert http_test_support.await_task(server_task) == Nil
  let assert Ok(Nil) = transport.stop(listener)

  let assert Error(failure) = outcome
  assert error.kind(failure) == error.Timeout(error.Operation)
}

pub fn conflicting_declared_request_length_is_rejected_before_tls_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [#("content-length", "4")],
      body: body.from_bytes(<<"abc":utf8>>),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/upload",
      query: None,
    )
  let assert Ok(config) =
    exchange.defaults()
    |> exchange.with_timeouts(100, 100, 100, 100, 100, 200)

  let outcome = exchange.run(outgoing, config)
  let assert Ok(Nil) = transport.stop(listener)

  let assert Error(failure) = outcome
  assert error.kind(failure) == error.Body(error.LengthMismatch(4, 3))
}

fn await_request(
  socket: transport.Socket,
  state: wire.State,
) -> #(transport.Socket, wire.State, request.Request(Nil)) {
  let assert Ok(transport.ReadData(bytes, socket)) =
    transport.read(socket, 65_536, 1000)
  let assert Ok(wire.Fed(state, actions)) = wire.feed(state, bytes)
  let assert Ok(automatic) = wire.automatic_writes(actions, 16_384)
  send_all(socket, automatic)
  case find_request(actions) {
    Some(incoming) -> #(socket, state, incoming)
    None -> await_request(socket, state)
  }
}

fn find_request(
  actions: List(connection.Action),
) -> option.Option(request.Request(Nil)) {
  case actions {
    [] -> None
    [
      connection.HeadersReceived(header_codec.HeaderSection(_, _, validated, _)),
      ..
    ] -> {
      let assert Ok(incoming) =
        message.request_from_validated(validated, Nil, gleam_http.Https)
      Some(incoming)
    }
    [_, ..rest] -> find_request(rest)
  }
}

fn send_all(socket: transport.Socket, frames: List(BitArray)) -> Nil {
  case frames {
    [] -> Nil
    [bytes, ..rest] -> {
      let assert Ok(Nil) = transport.send(socket, bytes)
      send_all(socket, rest)
    }
  }
}

fn receive_complete_request(
  socket: transport.Socket,
  state: wire.State,
  incoming: option.Option(request.Request(Nil)),
  reversed_body: List(BitArray),
  trailers: body.Headers,
) -> Result(
  #(transport.Socket, wire.State, request.Request(Nil), BitArray, body.Headers),
  Nil,
) {
  use read <- result.try(
    transport.read(socket, 65_536, 2000)
    |> result.map_error(fn(_) { Nil }),
  )
  case read {
    transport.ReadEnd(_) -> Error(Nil)
    transport.ReadData(bytes, socket) -> {
      use fed <- result.try(
        wire.feed(state, bytes) |> result.map_error(fn(_) { Nil }),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(fn(_) { Nil }),
      )
      use _ <- result.try(send_all_result(socket, automatic))
      use handled <- result.try(handle_request_actions(
        socket,
        state,
        actions,
        incoming,
        reversed_body,
        trailers,
        False,
      ))
      let #(state, incoming, reversed_body, trailers, complete) = handled
      case complete, incoming {
        True, Some(incoming) ->
          Ok(#(
            socket,
            state,
            incoming,
            reversed_body |> list.reverse |> bit_array.concat,
            trailers,
          ))
        _, _ ->
          receive_complete_request(
            socket,
            state,
            incoming,
            reversed_body,
            trailers,
          )
      }
    }
  }
}

fn handle_request_actions(
  socket: transport.Socket,
  state: wire.State,
  actions: List(connection.Action),
  incoming: option.Option(request.Request(Nil)),
  reversed_body: List(BitArray),
  trailers: body.Headers,
  complete: Bool,
) -> Result(
  #(
    wire.State,
    option.Option(request.Request(Nil)),
    List(BitArray),
    body.Headers,
    Bool,
  ),
  Nil,
) {
  case actions {
    [] -> Ok(#(state, incoming, reversed_body, trailers, complete))
    [
      connection.HeadersReceived(header_codec.HeaderSection(
        _,
        end_stream,
        validated,
        _,
      )),
      ..rest
    ] ->
      case incoming {
        None -> {
          use incoming <- result.try(
            message.request_from_validated(validated, Nil, gleam_http.Https)
            |> result.map(Some)
            |> result.map_error(fn(_) { Nil }),
          )
          handle_request_actions(
            socket,
            state,
            rest,
            incoming,
            reversed_body,
            trailers,
            complete || end_stream,
          )
        }
        Some(_) -> {
          use trailers <- result.try(
            message.trailers_from_validated(validated)
            |> result.map_error(fn(_) { Nil }),
          )
          handle_request_actions(
            socket,
            state,
            rest,
            incoming,
            reversed_body,
            trailers,
            complete || end_stream,
          )
        }
      }
    [connection.DataReceived(stream_id, bytes, end_stream, controlled), ..rest] -> {
      use state <- result.try(release_test_credit(
        socket,
        state,
        stream_id,
        controlled,
      ))
      handle_request_actions(
        socket,
        state,
        rest,
        incoming,
        [bytes, ..reversed_body],
        trailers,
        complete || end_stream,
      )
    }
    [_, ..rest] ->
      handle_request_actions(
        socket,
        state,
        rest,
        incoming,
        reversed_body,
        trailers,
        complete,
      )
  }
}

fn release_test_credit(
  socket: transport.Socket,
  state: wire.State,
  stream_id: Int,
  controlled: Int,
) -> Result(wire.State, Nil) {
  case controlled > 0 {
    False -> Ok(state)
    True -> {
      use released <- result.try(
        wire.release_receive_credit(
          state,
          stream_id: stream_id,
          octets: controlled,
        )
        |> result.map_error(fn(_) { Nil }),
      )
      let wire.ReceiveCreditReleased(state, frames) = released
      use _ <- result.try(send_all_result(socket, frames))
      Ok(state)
    }
  }
}

fn send_all_result(
  socket: transport.Socket,
  frames: List(BitArray),
) -> Result(Nil, Nil) {
  case frames {
    [] -> Ok(Nil)
    [bytes, ..rest] -> {
      use _ <- result.try(
        transport.send(socket, bytes) |> result.map_error(fn(_) { Nil }),
      )
      send_all_result(socket, rest)
    }
  }
}

fn drain_until_end(socket: transport.Socket) -> transport.Socket {
  case transport.read(socket, 65_536, 2000) {
    Ok(transport.ReadData(_, socket)) -> drain_until_end(socket)
    Ok(transport.ReadEnd(socket)) -> socket
    Error(_) -> socket
  }
}

fn await_socket_end(
  socket: transport.Socket,
) -> Result(transport.Socket, transport.Error) {
  case transport.read(socket, 65_536, 1000) {
    Ok(transport.ReadData(_, socket)) -> await_socket_end(socket)
    Ok(transport.ReadEnd(socket)) -> Ok(socket)
    Error(failure) -> Error(failure)
  }
}
