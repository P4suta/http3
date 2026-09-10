import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import http/body
import http/error
import http/internal/http2/connection
import http/internal/http2/exchange
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

pub fn request_body_and_trailers_resume_after_peer_flow_control_credit_test() -> Nil {
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
      body: body.from_bytes_with_trailers(payload, [#("checksum", "yes")]),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/upload",
      query: None,
    )
  let config =
    exchange.defaults()
    |> exchange.with_ca_certificates([ca_certificate])

  let outcome = exchange.run(outgoing, config)
  let server_outcome = http_test_support.await_task(server_task)
  let assert Ok(exchange.Http2Response(incoming)) = outcome
  assert incoming.status == 204
  let assert Ok(#(received, request_body, trailers)) = server_outcome
  assert received.method == gleam_http.Post
  assert request_body == payload
  assert trailers == [#("checksum", "yes")]
  let assert Ok(Nil) = transport.stop(listener)
  Nil
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
