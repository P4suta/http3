import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleeunit/should
import http3/client
import http3/server
import http3_test_support

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounded_server_round_trip_over_real_udp_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let request =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/bounded")
        |> request.set_query([#("name", "gleam")])
        |> request.set_method(http.Post)
        |> request.set_header("x-test", "server")
        |> request.set_body(<<"request body":utf8>>)
      client.send(client_configuration(ca_certificate), request)
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert server.method(incoming) == http.Post
  assert server.path(incoming) == "/bounded?name=gleam"
  assert list.key_find(server.headers(incoming), "x-test") == Ok("server")
  assert server.read_body(incoming) |> should.be_ok == <<"request body":utf8>>
  server.respond(
    incoming,
    201,
    [#("content-type", "text/plain"), #("x-server", "http3")],
    <<"response body":utf8>>,
  )
  |> should.be_ok

  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.status == 201
  assert response.get_header(reply, "x-server") == Ok("http3")
  assert reply.body == <<"response body":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
  assert server.stop(listener) == Ok(server.AlreadyStopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_server_round_trip_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let configuration = client_configuration(ca_certificate)
      let connection =
        client.connect(configuration, "localhost", port) |> should.be_ok
      let request =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/stream")
        |> request.set_method(http.Post)
        |> request.set_body(Nil)
      let stream = client.open_stream(connection, request) |> should.be_ok
      client.send_chunk(stream, <<"one-":utf8>>) |> should.be_ok
      client.send_chunk(stream, <<"two":utf8>>) |> should.be_ok
      client.finish(stream) |> should.be_ok
      let events = receive_client_response(stream, [])
      let _close = client.close(connection)
      events
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert receive_server_body(incoming, <<>>) == <<"one-two":utf8>>
  server.send_response(incoming, 200, [#("x-mode", "streaming")])
  |> should.be_ok
  server.send_chunk(incoming, <<"alpha-":utf8>>) |> should.be_ok
  server.send_chunk(incoming, <<"beta":utf8>>) |> should.be_ok
  server.finish_response(incoming) |> should.be_ok

  let #(status, headers, body) = http3_test_support.await_task(client_task)
  assert status == 200
  assert list.key_find(headers, "x-mode") == Ok("streaming")
  assert body == <<"alpha-beta":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn informational_and_bidirectional_trailers_round_trip_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let connection =
        client.connect(client_configuration(ca_certificate), "localhost", port)
        |> should.be_ok
      let request =
        streaming_request(port, "/trailers")
        |> request.set_method(http.Post)
      let stream = client.open_stream(connection, request) |> should.be_ok
      client.send_chunk(stream, <<"request":utf8>>) |> should.be_ok
      client.send_trailers(stream, [#("digest", "request-digest")])
      |> should.be_ok
      assert client.finish(stream) == Error(client.RequestAlreadyFinished)
      let events = collect_response_events(stream, [])
      let _closed = client.close(connection)
      events
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert server.next_event(incoming) == Ok(server.Data(<<"request":utf8>>))
  assert server.next_event(incoming)
    == Ok(server.Trailers([#("digest", "request-digest")]))
  assert server.next_event(incoming) == Ok(server.End)
  server.send_informational(incoming, 103, [#("link", "</style.css>")])
  |> should.be_ok
  server.send_response(incoming, 200, [#("x-final", "yes")])
  |> should.be_ok
  assert server.send_informational(incoming, 103, [])
    == Error(server.ResponseAlreadyStarted)
  server.send_chunk(incoming, <<"response":utf8>>) |> should.be_ok
  server.send_trailers(incoming, [#("digest", "response-digest")])
  |> should.be_ok
  assert server.finish_response(incoming)
    == Error(server.ResponseAlreadyFinished)

  assert http3_test_support.await_task(client_task)
    == [
      client.InformationalResponse(103, [#("link", "</style.css>")]),
      client.Response(200, [#("x-final", "yes")]),
      client.Data(<<"response":utf8>>),
      client.Trailers([#("digest", "response-digest")]),
      client.End,
    ]
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_multiplexes_concurrent_requests_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let first = start_bounded_client(port, ca_certificate, "/first")
  let second = start_bounded_client(port, ca_certificate, "/second")

  let request_a = server.accept(listener) |> should.be_ok
  let request_b = server.accept(listener) |> should.be_ok
  server.respond(
    request_b,
    200,
    [],
    bit_array.from_string(server.path(request_b)),
  )
  |> should.be_ok
  server.respond(
    request_a,
    200,
    [],
    bit_array.from_string(server.path(request_a)),
  )
  |> should.be_ok

  let first_reply = http3_test_support.await_task(first) |> should.be_ok
  let second_reply = http3_test_support.await_task(second) |> should.be_ok
  assert first_reply.body == <<"/first":utf8>>
  assert second_reply.body == <<"/second":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_enforces_request_body_limit_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration =
    server.with_request_body_limit(configuration, 4) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_task =
    start_bounded_client_with_body(port, ca_certificate, <<"too large":utf8>>)

  let incoming = server.accept(listener) |> should.be_ok
  assert server.read_body(incoming) == Error(server.RequestBodyTooLarge(4))
  let _client_result = http3_test_support.await_task(client_task)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_stop_releases_blocked_accept_test() -> Nil {
  let #(listener, _, _) = start_server()
  let accept_task =
    http3_test_support.start_task(fn() { server.accept(listener) })

  assert server.stop(listener) == Ok(server.Stopped)
  assert http3_test_support.await_task(accept_task)
    == Error(server.ListenerClosed)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_rejects_invalid_credentials_test() -> Nil {
  assert server.new(<<"invalid":utf8>>, <<"invalid":utf8>>)
    == Error(server.InvalidCertificate)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_multiplexes_streams_on_one_connection_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let connection =
        client.connect(client_configuration(ca_certificate), "localhost", port)
        |> should.be_ok
      let first =
        streaming_request(port, "/stream-one")
        |> client.open_stream(connection, _)
        |> should.be_ok
      let second =
        streaming_request(port, "/stream-two")
        |> client.open_stream(connection, _)
        |> should.be_ok
      client.finish(first) |> should.be_ok
      client.finish(second) |> should.be_ok
      let first_response = receive_client_response(first, [])
      let second_response = receive_client_response(second, [])
      let _close = client.close(connection)
      #(first_response, second_response)
    })

  let first = server.accept(listener) |> should.be_ok
  let second = server.accept(listener) |> should.be_ok
  server.respond(second, 200, [], bit_array.from_string(server.path(second)))
  |> should.be_ok
  server.respond(first, 200, [], bit_array.from_string(server.path(first)))
  |> should.be_ok

  let #(#(_, _, first_body), #(_, _, second_body)) =
    http3_test_support.await_task(client_task)
  assert first_body == <<"/stream-one":utf8>>
  assert second_body == <<"/stream-two":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_reports_abrupt_peer_termination_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let signal = http3_test_support.new_signal()
  let client_task =
    http3_test_support.start_task(fn() {
      let connection =
        client.connect(client_configuration(ca_certificate), "localhost", port)
        |> should.be_ok
      let _stream =
        streaming_request(port, "/peer-close")
        |> client.open_stream(connection, _)
        |> should.be_ok
      http3_test_support.checkpoint(signal)
      client.close(connection)
    })

  let incoming = server.accept(listener) |> should.be_ok
  let receive_task =
    http3_test_support.start_task(fn() { server.next_event(incoming) })
  http3_test_support.release_signal(signal)
  let _client_close = http3_test_support.await_task(client_task)
  assert http3_test_support.await_task(receive_task)
    == Error(server.ConnectionClosed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_rejects_concurrent_accepts_test() -> Nil {
  let #(listener, _, _) = start_server()
  let results = http3_test_support.concurrent_accepts(listener)
  assert list.contains(results, Error(server.ConcurrentAccept))
  assert list.contains(results, Error(server.ListenerClosed))
  assert server.stop(listener) == Ok(server.AlreadyStopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_listener_stops_with_its_owner_test() -> Nil {
  let #(certificate, private_key, _) = http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  assert http3_test_support.server_owner_cleanup(configuration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_enforces_response_body_limit_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration =
    server.with_response_body_limit(configuration, 4) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_task =
    start_bounded_client(port, ca_certificate, "/response-limit")
  let incoming = server.accept(listener) |> should.be_ok

  assert server.respond(incoming, 200, [], <<"large":utf8>>)
    == Error(server.ResponseBodyTooLarge(4))
  server.respond(incoming, 200, [], <<"four":utf8>>) |> should.be_ok
  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.body == <<"four":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_server_enforces_declared_content_length_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    start_bounded_client(port, ca_certificate, "/declared-response")
  let incoming = server.accept(listener) |> should.be_ok

  assert server.finish_response(incoming) == Error(server.ResponseNotStarted)
  server.send_response(incoming, 200, [#("content-length", "5")])
  |> should.be_ok
  server.send_chunk(incoming, <<"four":utf8>>) |> should.be_ok
  assert server.finish_response(incoming) == Error(server.InvalidContentLength)
  server.send_chunk(incoming, <<"!":utf8>>) |> should.be_ok
  server.finish_response(incoming) |> should.be_ok

  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.body == <<"four!":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

fn start_server() -> #(server.Listener, Int, BitArray) {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let configuration =
    server.with_stream_buffer_limit(configuration, 65_536) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  #(listener, port, ca_certificate)
}

fn client_configuration(ca_certificate: BitArray) -> client.Client {
  let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
  client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
}

// nolint: label_possible -- positional test-helper arguments remain concise.
fn start_bounded_client(
  port: Int,
  ca_certificate: BitArray,
  path: String,
) -> http3_test_support.Task(Result(response.Response(BitArray), client.Error)) {
  start_bounded_client_with_path_and_body(port, ca_certificate, path, <<>>)
}

// nolint: label_possible -- positional test-helper arguments remain concise.
fn start_bounded_client_with_body(
  port: Int,
  ca_certificate: BitArray,
  body: BitArray,
) -> http3_test_support.Task(Result(response.Response(BitArray), client.Error)) {
  start_bounded_client_with_path_and_body(port, ca_certificate, "/limit", body)
}

// nolint: label_possible -- positional test-helper arguments remain concise.
fn start_bounded_client_with_path_and_body(
  port: Int,
  ca_certificate: BitArray,
  path: String,
  body: BitArray,
) -> http3_test_support.Task(Result(response.Response(BitArray), client.Error)) {
  http3_test_support.start_task(fn() {
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path(path)
      |> request.set_method(http.Post)
      |> request.set_body(body)
    client.send(client_configuration(ca_certificate), request)
  })
}

fn streaming_request(port: Int, path: String) -> request.Request(Nil) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(Nil)
}

fn receive_server_body(incoming: server.Request, body: BitArray) -> BitArray {
  case server.next_event(incoming) |> should.be_ok {
    server.Data(chunk) ->
      receive_server_body(incoming, bit_array.append(body, chunk))
    server.Trailers(_) -> receive_server_body(incoming, body)
    server.End -> body
  }
}

fn receive_client_response(
  stream: client.Stream,
  chunks: List(BitArray),
) -> #(Int, List(#(String, String)), BitArray) {
  case client.next_event(stream) |> should.be_ok {
    client.InformationalResponse(_, _) ->
      receive_client_response(stream, chunks)
    client.Response(status, headers) ->
      receive_client_body(stream, status, headers, chunks)
    _ -> receive_client_response(stream, chunks)
  }
}

fn collect_response_events(
  stream: client.Stream,
  events: List(client.ResponseEvent),
) -> List(client.ResponseEvent) {
  let event = client.next_event(stream) |> should.be_ok
  case event {
    client.End -> list.reverse([event, ..events])
    _ -> collect_response_events(stream, [event, ..events])
  }
}

// nolint: label_possible -- recursive accumulator arguments are conventional.
fn receive_client_body(
  stream: client.Stream,
  status: Int,
  headers: List(#(String, String)),
  chunks: List(BitArray),
) -> #(Int, List(#(String, String)), BitArray) {
  case client.next_event(stream) |> should.be_ok {
    client.Data(chunk) ->
      receive_client_body(stream, status, headers, [chunk, ..chunks])
    client.Trailers(_) -> receive_client_body(stream, status, headers, chunks)
    client.End -> #(status, headers, bit_array.concat(list.reverse(chunks)))
    _ -> receive_client_body(stream, status, headers, chunks)
  }
}
