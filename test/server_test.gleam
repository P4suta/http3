import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/result
import gleeunit/should
import http3/address
import http3/client
import http3/config
import http3/failure
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
pub fn bounded_client_request_crosses_initial_connection_window_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_timeout(configuration, 10_000) |> should.be_ok
  let configuration =
    server.with_stream_buffer_limit(configuration, 262_144) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let body = http3_test_support.repeated_bytes(1_048_577)
  let client_task =
    http3_test_support.start_task(fn() {
      let configuration =
        client.with_timeout(client.new(), 10_000) |> should.be_ok
      let configuration =
        client.with_ca_certificate(configuration, ca_certificate)
        |> should.be_ok
      let outbound =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/large-request")
        |> request.set_method(http.Post)
        |> request.set_body(body)
      client.send(configuration, outbound)
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert receive_request_bytes(incoming, 0) == Ok(1_048_577)
  server.respond(incoming, 204, [], <<>>) |> should.be_ok
  let reply = http3_test_support.await_task(client_task)
  assert result.map(reply, fn(response) { response.status }) == Ok(204)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounded_head_response_keeps_representation_length_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let outbound =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/head")
        |> request.set_method(http.Head)
        |> request.set_body(<<>>)
      client.send(client_configuration(ca_certificate), outbound)
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert server.method(incoming) == http.Head
  server.respond(incoming, 200, [#("content-length", "1048577")], <<>>)
  |> should.be_ok
  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.status == 200
  assert reply.body == <<>>
  assert response.get_header(reply, "content-length") == Ok("1048577")
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ipv6_server_round_trip_over_real_udp_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let listener =
    configuration
    |> server.with_address_family(config.Ipv6)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let server_task =
    http3_test_support.start_task(fn() {
      let incoming = server.accept(listener) |> should.be_ok
      assert server.path(incoming) == "/ipv6"
      assert server.read_body(incoming) |> should.be_ok == <<>>
      server.respond(incoming, 200, [], <<"ipv6":utf8>>) |> should.be_ok
    })
  let request =
    request.new()
    |> request.set_host("::1")
    |> request.set_port(port)
    |> request.set_path("/ipv6")
    |> request.set_body(<<>>)
  let reply =
    client.send(client_configuration(ca_certificate), request) |> should.be_ok
  let _served = http3_test_support.await_task(server_task)
  assert reply.status == 200
  assert reply.body == <<"ipv6":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exact_bind_and_validated_request_context_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let bind_address = address.parse("127.0.0.1") |> should.be_ok
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration = server.with_bind_address(configuration, bind_address)
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_task = start_bounded_client(port, ca_certificate, "/context")
  let incoming = server.accept(listener) |> should.be_ok

  assert server.scheme(incoming) == "https"
  assert server.authority(incoming) == "localhost:" <> int.to_string(port)
  let peer = server.peer_endpoint(incoming) |> should.be_ok
  assert address.to_string(address.endpoint_address(peer)) == "127.0.0.1"
  assert address.port(peer) > 0

  server.respond(incoming, 200, [], <<>>) |> should.be_ok
  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.status == 200
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_keepalive_interval_is_bounded_test() -> Nil {
  let #(certificate, private_key, _) = http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  assert server.with_keepalive(configuration, 999)
    == Error(server.InvalidKeepalive)
  assert server.with_keepalive(configuration, 29_001)
    == Error(server.InvalidKeepalive)
  let _configured = server.with_keepalive(configuration, 1000) |> should.be_ok
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_selects_certificate_by_sni_over_real_udp_test() -> Nil {
  let #(
    fallback_certificate,
    fallback_private_key,
    localhost_certificate,
    localhost_private_key,
    ca_certificate,
  ) = http3_test_support.server_certificate_selection_credentials()
  let configuration =
    server.new(fallback_certificate, fallback_private_key) |> should.be_ok
  assert server.with_certificate(
      configuration,
      "127.0.0.1",
      localhost_certificate,
      localhost_private_key,
    )
    == Error(server.InvalidServerName)
  let configuration =
    server.with_certificate(
      configuration,
      "localhost",
      localhost_certificate,
      localhost_private_key,
    )
    |> should.be_ok
  assert server.with_certificate(
      configuration,
      "LOCALHOST",
      localhost_certificate,
      localhost_private_key,
    )
    == Error(server.DuplicateServerName)
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_task =
    http3_test_support.start_task(fn() {
      let request =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/sni")
        |> request.set_body(<<>>)
      client.send(client_configuration(ca_certificate), request)
    })
  let incoming = server.accept(listener) |> should.be_ok
  server.respond(incoming, 200, [], <<"selected":utf8>>) |> should.be_ok
  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.body == <<"selected":utf8>>
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn certificate_reload_is_atomic_and_preserves_existing_connections_test() -> Nil {
  let #(
    fallback_certificate,
    fallback_private_key,
    localhost_certificate,
    localhost_private_key,
    ca_certificate,
  ) = http3_test_support.server_certificate_selection_credentials()
  let valid =
    server.new(localhost_certificate, localhost_private_key) |> should.be_ok
  // Certificate replacement is the subject of this test. Keep address-family
  // racing in its dedicated transport coverage so a rejected TLS handshake
  // cannot be hidden behind a slower Happy Eyeballs candidate on CI.
  let valid = server.with_address_family(valid, config.Ipv4)
  let listener = server.start(valid) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let ipv4_client =
    client_configuration(ca_certificate)
    |> client.with_address_family(config.Ipv4)
  let existing = client.connect(ipv4_client, "localhost", port) |> should.be_ok

  // The replacement is fully decoded before the actor swaps one value.
  let untrusted =
    server.new(fallback_certificate, fallback_private_key) |> should.be_ok
  let untrusted = server.with_address_family(untrusted, config.Ipv4)
  server.reload_certificates(listener, untrusted) |> should.be_ok

  // Existing authenticated connections retain their original TLS state.
  let existing_stream =
    client.open_stream(existing, streaming_request(port, "/existing"))
    |> should.be_ok
  client.finish(existing_stream) |> should.be_ok
  let existing_request = server.accept(listener) |> should.be_ok
  assert server.path(existing_request) == "/existing"
  assert server.read_body(existing_request) |> should.be_ok == <<>>
  server.respond(existing_request, 200, [], <<"still-open":utf8>>)
  |> should.be_ok
  let #(existing_status, _, existing_body) =
    receive_client_response(existing_stream, [])
  assert existing_status == 200
  assert existing_body == <<"still-open":utf8>>

  // A new handshake observes the newly installed, deliberately untrusted set.
  assert client.connect(ipv4_client, "localhost", port)
    == Error(client.Failure(failure.Tls(failure.Peer)))

  server.reload_certificates(listener, valid) |> should.be_ok
  let replacement =
    client.connect(ipv4_client, "localhost", port) |> should.be_ok
  let replacement_stream =
    client.open_stream(replacement, streaming_request(port, "/replacement"))
    |> should.be_ok
  client.finish(replacement_stream) |> should.be_ok
  let replacement_request = server.accept(listener) |> should.be_ok
  assert server.path(replacement_request) == "/replacement"
  assert server.read_body(replacement_request) |> should.be_ok == <<>>
  server.respond(replacement_request, 204, [], <<>>) |> should.be_ok
  let #(replacement_status, _, replacement_body) =
    receive_client_response(replacement_stream, [])
  assert replacement_status == 204
  assert replacement_body == <<>>

  assert client.close(existing) == Ok(client.Closed)
  assert client.close(replacement) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn configured_queue_limit_bounds_peer_event_count_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let limits =
    config.default_limits()
    |> config.with_limit(failure.Queue, 4)
    |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_limits(limits)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/empty-flood"))
    |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok

  send_small_chunks(stream, 5)
  http3_test_support.pause_milliseconds(50)
  assert server.next_event(incoming) == Ok(server.Data(<<1>>))
  assert server.next_event(incoming) == Ok(server.Data(<<1>>))
  assert server.next_event(incoming) == Ok(server.Data(<<1>>))
  assert server.next_event(incoming) == Ok(server.Data(<<1>>))
  assert server.next_event(incoming)
    == Error(server.Failure(failure.Limit(failure.Queue, 4)))

  let _close_result = client.close(connection)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_queue_limit_bounds_small_response_frames_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let limits =
    config.default_limits()
    |> config.with_limit(failure.Queue, 4)
    |> should.be_ok
  let configuration =
    client_configuration(ca_certificate) |> client.with_limits(limits)
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/response-flood"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok

  server.send_response(incoming, 200, []) |> should.be_ok
  send_small_response_chunks(incoming, 5)
  http3_test_support.pause_milliseconds(50)

  assert client.next_event(stream) == Ok(client.Response(200, []))
  assert client.next_event(stream) == Ok(client.Data(<<1>>))
  assert client.next_event(stream) == Ok(client.Data(<<1>>))
  assert client.next_event(stream) == Ok(client.Data(<<1>>))
  assert client.next_event(stream)
    == Error(client.Failure(failure.Limit(failure.Queue, 4)))

  let _close_result = client.close(connection)
  assert server.stop(listener) == Ok(server.Stopped)
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
pub fn graceful_stop_drains_active_request_and_rejects_accept_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let client_task =
    http3_test_support.start_task(fn() {
      let connection =
        client.connect(client_configuration(ca_certificate), "localhost", port)
        |> should.be_ok
      let stream =
        streaming_request(port, "/drain")
        |> client.open_stream(connection, _)
        |> should.be_ok
      client.finish(stream) |> should.be_ok
      let events = collect_response_events(stream, [])
      let _closed = client.close(connection)
      events
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert server.next_event(incoming) == Ok(server.End)
  let drain_task =
    http3_test_support.start_task(fn() { server.graceful_stop(listener) })
  assert server.accept(listener)
    == Error(server.Failure(failure.Closed(failure.Local, None)))
  server.respond(incoming, 200, [], <<"drained":utf8>>) |> should.be_ok

  assert http3_test_support.await_task(client_task)
    == [
      client.Response(200, []),
      client.Data(<<"drained":utf8>>),
      client.End,
    ]
  assert http3_test_support.await_task(drain_task) == Ok(server.Drained)
  assert server.graceful_stop(listener) == Ok(server.AlreadyDrained)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn graceful_stop_types_rejected_and_new_client_work_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server()
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let active =
    client.open_stream(connection, streaming_request(port, "/active-drain"))
    |> should.be_ok
  client.finish(active) |> should.be_ok
  let rejected =
    client.open_stream(connection, streaming_request(port, "/queued-drain"))
    |> should.be_ok
  client.finish(rejected) |> should.be_ok

  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == "/active-drain"
  assert server.next_event(incoming) == Ok(server.End)
  let drain_task =
    http3_test_support.start_task(fn() { server.graceful_stop(listener) })
  await_connection_draining(connection: connection, port: port, attempts: 100)
  assert server.accept(listener)
    == Error(server.Failure(failure.Closed(failure.Local, None)))
  assert client.next_event(rejected) == Error(client.RequestRejected)

  server.respond(incoming, 200, [], <<"active-complete":utf8>>)
  |> should.be_ok
  assert collect_response_events(active, [])
    == [
      client.Response(200, []),
      client.Data(<<"active-complete":utf8>>),
      client.End,
    ]
  assert http3_test_support.await_task(drain_task) == Ok(server.Drained)
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
    == Error(server.Failure(failure.Closed(failure.Local, None)))
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
    == Error(server.Failure(failure.Closed(failure.Peer, None)))
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_rejects_concurrent_accepts_test() -> Nil {
  let #(listener, _, _) = start_server()
  let results = http3_test_support.concurrent_accepts(listener)
  assert list.contains(results, Error(server.ConcurrentAccept))
  assert list.contains(
    results,
    Error(server.Failure(failure.Closed(failure.Local, None))),
  )
  assert server.stop(listener) == Ok(server.AlreadyStopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn configured_accept_waiter_capacity_allows_two_callers_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let limits =
    config.default_limits()
    |> config.with_limit(failure.AcceptWaiters, 2)
    |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_limits(limits)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let first_accept =
    http3_test_support.start_task(fn() { server.accept(listener) })
  let second_accept =
    http3_test_support.start_task(fn() { server.accept(listener) })
  http3_test_support.pause_milliseconds(50)

  let first_client = start_bounded_client(port, ca_certificate, "/waiter-one")
  let second_client = start_bounded_client(port, ca_certificate, "/waiter-two")
  let first_request =
    http3_test_support.await_task(first_accept) |> should.be_ok
  let second_request =
    http3_test_support.await_task(second_accept) |> should.be_ok
  server.respond(
    first_request,
    200,
    [],
    bit_array.from_string(server.path(first_request)),
  )
  |> should.be_ok
  server.respond(
    second_request,
    200,
    [],
    bit_array.from_string(server.path(second_request)),
  )
  |> should.be_ok

  let first_response =
    http3_test_support.await_task(first_client) |> should.be_ok
  let second_response =
    http3_test_support.await_task(second_client) |> should.be_ok
  assert list.contains([first_response.body, second_response.body], <<
    "/waiter-one":utf8,
  >>)
  assert list.contains([first_response.body, second_response.body], <<
    "/waiter-two":utf8,
  >>)
  assert server.stop(listener) == Ok(server.Stopped)
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_server_has_no_lifetime_body_ceiling_without_length_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration =
    server.with_response_body_limit(configuration, 4) |> should.be_ok
  let configuration = server.with_timeout(configuration, 3000) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_task =
    start_bounded_client(port, ca_certificate, "/unbounded-stream")
  let incoming = server.accept(listener) |> should.be_ok

  server.send_response(incoming, 200, []) |> should.be_ok
  server.send_chunk(incoming, <<1, 2, 3, 4>>) |> should.be_ok
  server.send_chunk(incoming, <<5, 6, 7, 8>>) |> should.be_ok
  server.finish_response(incoming) |> should.be_ok

  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.body == <<1, 2, 3, 4, 5, 6, 7, 8>>
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

fn send_small_chunks(stream: client.Stream, remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      client.send_chunk(stream, <<1>>) |> should.be_ok
      send_small_chunks(stream, remaining - 1)
    }
  }
}

fn send_small_response_chunks(request: server.Request, remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      let _send_result = server.send_chunk(request, <<1>>)
      send_small_response_chunks(request, remaining - 1)
    }
  }
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

fn receive_request_bytes(
  incoming: server.Request,
  received: Int,
) -> Result(Int, #(Int, server.Error)) {
  case server.next_event(incoming) {
    Ok(server.Data(chunk)) ->
      receive_request_bytes(incoming, received + bit_array.byte_size(chunk))
    Ok(server.Trailers(_)) -> receive_request_bytes(incoming, received)
    Ok(server.End) -> Ok(received)
    Error(error) -> Error(#(received, error))
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

fn await_connection_draining(
  connection connection: client.Connection,
  port port: Int,
  attempts attempts: Int,
) -> Nil {
  assert attempts > 0
  case
    client.open_stream(connection, streaming_request(port, "/after-goaway"))
  {
    Error(client.ConnectionDraining) -> Nil
    Ok(stream) -> {
      client.finish(stream) |> should.be_ok
      assert client.next_event(stream) == Error(client.RequestRejected)
      await_connection_draining(
        connection: connection,
        port: port,
        attempts: attempts - 1,
      )
    }
    Error(error) -> {
      assert error == client.ConnectionDraining
      Nil
    }
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

// The listener flushes at most `maximum_packets_per_connection_flush` (16)
// datagrams of at most `maximum_frame_data_bytes` (1000) payload bytes per
// connection per turn, so a 64 KiB response body needs the flush to be
// resumed several times after the request datagram has been consumed.
const capped_flush_body_bytes = 65_536

const capped_flush_bound_milliseconds = 2000

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn capped_flush_drains_response_backlog_within_bound_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key) |> should.be_ok
  let configuration =
    server.with_timeout(configuration, capped_flush_bound_milliseconds)
    |> should.be_ok
  let configuration =
    server.with_stream_buffer_limit(configuration, 131_072) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let body = http3_test_support.repeated_bytes(capped_flush_body_bytes)

  // The client sends its request and then nothing else, so the backlogged
  // response has to be driven by the listener within the bound.
  let client_task =
    http3_test_support.start_task(fn() {
      let outbound =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/backlog")
        |> request.set_method(http.Get)
        |> request.set_body(<<>>)
      let configuration =
        client.new()
        |> client.with_timeout(capped_flush_bound_milliseconds)
        |> should.be_ok
        |> client.with_ca_certificate(ca_certificate)
        |> should.be_ok
        |> client.with_stream_buffer_limit(131_072)
        |> should.be_ok
      client.send(configuration, outbound)
    })

  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == "/backlog"
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(
    incoming,
    200,
    [#("content-type", "application/octet-stream")],
    body,
  )
  |> should.be_ok

  let reply = http3_test_support.await_task(client_task) |> should.be_ok
  assert reply.status == 200
  assert list.key_find(reply.headers, "content-type")
    == Ok("application/octet-stream")
  assert bit_array.byte_size(reply.body) == capped_flush_body_bytes
  assert reply.body == body
  assert server.stop(listener) == Ok(server.Stopped)
}
