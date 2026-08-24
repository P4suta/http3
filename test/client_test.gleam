import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/string
import gleam_quic/internal/tls/authentication
import gleeunit/should
import http3/client
import http3/transport
import http3_test_support

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ipv6_literal_certificate_identity_is_verified_test() -> Nil {
  let #(certificate, _, ca_certificate) =
    http3_test_support.server_credentials()
  let chain =
    authentication.certificate_chain_from_pem(certificate) |> should.be_ok
  let trust_store =
    authentication.trust_store_from_der([ca_certificate]) |> should.be_ok
  let _peer =
    authentication.validate_server_certificate(chain, trust_store, "::1")
    |> should.be_ok
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_https_request_test() -> Nil {
  let request =
    request.new()
    |> request.set_scheme(http.Http)
    |> request.set_body(<<>>)

  assert client.send(client.new(), request) == Error(client.InvalidScheme)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_empty_host_test() -> Nil {
  let request =
    request.new()
    |> request.set_host("")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request) == Error(client.InvalidHost)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_invalid_port_test() -> Nil {
  let request =
    request.new()
    |> request.set_port(0)
    |> request.set_body(<<>>)

  assert client.send(client.new(), request) == Error(client.InvalidPort(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_byte_aligned_body_test() -> Nil {
  let request = request.new() |> request.set_body(<<1:size(1)>>)

  assert client.send(client.new(), request) == Error(client.InvalidBody)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_connect_method_test() -> Nil {
  let request =
    request.new()
    |> request.set_method(http.Connect)
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.UnsupportedMethod("CONNECT"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_relative_path_test() -> Nil {
  let request =
    request.new()
    |> request.set_path("relative")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidPath("relative"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_http3_forbidden_header_test() -> Nil {
  let request =
    request.new()
    |> request.set_header("connection", "close")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidHeader("connection"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_token_header_name_test() -> Nil {
  let request =
    request.new()
    |> request.set_header("bad name", "value")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidHeader("bad name"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_control_character_in_header_value_test() -> Nil {
  let request =
    request.new()
    |> request.set_header("x-test", "bad\u{0000}value")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidHeader("x-test"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_duplicate_content_length_test() -> Nil {
  let request =
    request.new()
    |> request.set_header("content-length", "1")
    |> request.prepend_header("content-length", "1")
    |> request.set_body(<<"a":utf8>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidContentLength)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_invalid_custom_method_test() -> Nil {
  let request =
    request.new()
    |> request.set_method(http.Other("BAD METHOD"))
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.UnsupportedMethod("BAD METHOD"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_whitespace_in_host_test() -> Nil {
  let request =
    request.new()
    |> request.set_host("local host")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request) == Error(client.InvalidHost)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_whitespace_in_path_test() -> Nil {
  let request =
    request.new()
    |> request.set_path("/bad path")
    |> request.set_body(<<>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidPath("/bad path"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_mismatched_content_length_test() -> Nil {
  let request =
    request.new()
    |> request.set_header("content-length", "2")
    |> request.set_body(<<"a":utf8>>)

  assert client.send(client.new(), request)
    == Error(client.InvalidContentLength)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_enforces_request_body_limit_before_connecting_test() -> Nil {
  let configuration =
    client.with_request_body_limit(client.new(), 3) |> should.be_ok
  let request = request.new() |> request.set_body(<<"four":utf8>>)

  assert client.send(configuration, request)
    == Error(client.RequestBodyTooLarge(3))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_push_limit_is_bounded_and_can_be_disabled_test() -> Nil {
  assert client.with_push_limit(client.new(), -1)
    == Error(client.InvalidPushLimit)
  assert client.with_push_limit(client.new(), 1025)
    == Error(client.InvalidPushLimit)
  let _disabled = client.with_push_limit(client.new(), 0) |> should.be_ok
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounded_client_round_trip_over_real_udp_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_response_body_limit(configuration, 1024) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_query([#("name", "gleam")])
      |> request.set_method(http.Post)
      |> request.set_header("x-test", "loopback")
      |> request.set_body(<<"hello over h3":utf8>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert response.get_header(reply, "content-type")
      == Ok("application/octet-stream")
    assert response.get_header(reply, "x-request-method") == Ok("POST")
    assert response.get_header(reply, "x-request-path")
      == Ok("/echo?name=gleam")
    assert response.get_header(reply, "x-received-test") == Ok("loopback")
    assert response.get_header(reply, ":status") == Error(Nil)
    assert reply.body == <<"hello over h3":utf8>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounded_client_round_trip_over_quic_v2_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration =
      client.new()
      |> client.with_quic_version(transport.QuicV2)
      |> client.with_timeout(3000)
      |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_body(<<"v2":utf8>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert response.get_header(reply, "x-request-path") == Ok("/echo")
    assert reply.body == <<"v2":utf8>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_cancels_response_that_exceeds_body_limit_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_response_body_limit(configuration, 16) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    assert client.send(configuration, request)
      == Error(client.ResponseBodyTooLarge(16))
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_times_out_incomplete_response_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 1000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/timeout")
      |> request.set_body(<<>>)

    assert client.send(configuration, request) == Error(client.Timeout)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_verifies_server_certificate_by_default_test() -> Nil {
  http3_test_support.with_server(fn(port, _ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    let _reason = client.send(configuration, request) |> should.be_error
    Nil
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_keeps_hostname_verification_with_custom_ca_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("127.0.0.1")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    let _reason = client.send(configuration, request) |> should.be_error
    Nil
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_completes_headers_only_response_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/empty")
      |> request.set_body(<<>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 204
    assert reply.body == <<>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_collects_multiple_response_data_frames_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/chunks")
      |> request.set_body(<<>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert reply.body == <<"one-two":utf8>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_recovers_from_initial_packet_loss_test() -> Nil {
  http3_test_support.with_lossy_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 5000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert bit_array.byte_size(reply.body) == 64
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_recovers_from_reordered_datagrams_test() -> Nil {
  http3_test_support.with_reordering_proxy(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 5000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert bit_array.byte_size(reply.body) == 64
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_reports_peer_termination_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/close")
      |> request.set_body(<<>>)

    assert client.send(configuration, request) == Error(client.ConnectionClosed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_round_trip_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_method(http.Post)
      |> request.set_header("x-test", "streaming")
      |> request.set_body(Nil)
    let stream = client.open_stream(connection, request) |> should.be_ok

    client.send_chunk(stream, <<"hello ":utf8>>) |> should.be_ok
    client.send_chunk(stream, <<"stream":utf8>>) |> should.be_ok
    client.finish(stream) |> should.be_ok

    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, headers) =
      client.next_event(stream) |> should.be_ok
    assert list.key_find(headers, "x-request-method") == Ok("POST")
    assert receive_stream_body(stream, <<>>) == <<"hello stream":utf8>>
    assert client.close(connection) == Ok(client.Closed)
    assert client.close(connection) == Ok(client.AlreadyClosed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_multiplexes_requests_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let large =
      streaming_request(port, "/large")
      |> client.open_stream(connection, _)
      |> should.be_ok
    let empty =
      streaming_request(port, "/empty")
      |> client.open_stream(connection, _)
      |> should.be_ok

    client.finish(large) |> should.be_ok
    client.finish(empty) |> should.be_ok

    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, _) =
      client.next_event(large) |> should.be_ok
    assert bit_array.byte_size(receive_stream_body(large, <<>>)) == 64
    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(204, _) =
      client.next_event(empty) |> should.be_ok
    assert receive_stream_body(empty, <<>>) == <<>>
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_observes_early_response_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/large")
      |> client.open_stream(connection, _)
      |> should.be_ok

    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, _) =
      client.next_event(stream) |> should.be_ok
    assert bit_array.byte_size(receive_stream_body(stream, <<>>)) == 64
    assert client.cancel(stream) == Ok(client.AlreadyCompleted)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_cancellation_is_idempotent_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/timeout")
      |> client.open_stream(connection, _)
      |> should.be_ok

    assert client.cancel(stream) == Ok(client.Cancelled)
    assert client.cancel(stream) == Ok(client.AlreadyCancelled)
    assert client.next_event(stream) == Error(client.StreamCancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_enforces_declared_content_length_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let request =
      streaming_request(port, "/echo")
      |> request.set_method(http.Post)
      |> request.set_header("content-length", "5")
    let stream = client.open_stream(connection, request) |> should.be_ok

    client.send_chunk(stream, <<"four":utf8>>) |> should.be_ok
    assert client.finish(stream) == Error(client.InvalidContentLength)
    assert client.cancel(stream) == Ok(client.Cancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_rejects_origin_mismatch_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let request =
      request.new()
      |> request.set_host("example.com")
      |> request.set_port(port)
      |> request.set_body(Nil)

    assert client.open_stream(connection, request)
      == Error(client.OriginMismatch)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_bounds_slow_consumers_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_stream_buffer_limit(configuration, 8) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let connection =
      client.connect(configuration, "localhost", port) |> should.be_ok
    let stream =
      streaming_request(port, "/large")
      |> client.open_stream(connection, _)
      |> should.be_ok

    client.finish(stream) |> should.be_ok
    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, _) =
      client.next_event(stream) |> should.be_ok
    assert client.next_event(stream) == Error(client.ConsumerTooSlow(8))
    assert client.cancel(stream) == Ok(client.AlreadyCancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_rejects_request_data_after_finish_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/empty")
      |> client.open_stream(connection, _)
      |> should.be_ok

    client.finish(stream) |> should.be_ok
    assert client.send_chunk(stream, <<>>)
      == Error(client.RequestAlreadyFinished)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_rejects_non_byte_aligned_chunk_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/timeout")
      |> client.open_stream(connection, _)
      |> should.be_ok

    assert client.send_chunk(stream, <<1:size(1)>>) == Error(client.InvalidBody)
    assert client.cancel(stream) == Ok(client.Cancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_rejects_concurrent_receivers_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/timeout")
      |> client.open_stream(connection, _)
      |> should.be_ok
    client.finish(stream) |> should.be_ok

    let results = http3_test_support.concurrent_next_events(stream)
    assert list.contains(results, Error(client.ConcurrentReceive))
    assert list.contains(results, Error(client.StreamCancelled))
    assert client.cancel(stream) == Ok(client.AlreadyCancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_cancellation_race_is_safe_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/timeout")
      |> client.open_stream(connection, _)
      |> should.be_ok

    let results = http3_test_support.concurrent_cancellations(stream)
    assert list.contains(results, Ok(client.Cancelled))
    assert list.contains(results, Ok(client.AlreadyCancelled))
    assert client.next_event(stream) == Error(client.StreamCancelled)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_connection_stops_with_its_owner_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok

    assert http3_test_support.connection_owner_cleanup(
      configuration,
      "localhost",
      port,
    )
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_reports_peer_termination_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection = streaming_connection(port, ca_certificate)
    let stream =
      streaming_request(port, "/stream-close")
      |> client.open_stream(connection, _)
      |> should.be_ok
    client.finish(stream) |> should.be_ok

    assert client.next_event(stream) == Error(client.ConnectionClosed)
    let _close_result = client.close(connection)
    Nil
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_times_out_incomplete_response_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 1000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let connection =
      client.connect(configuration, "localhost", port) |> should.be_ok
    let stream =
      streaming_request(port, "/timeout")
      |> client.open_stream(connection, _)
      |> should.be_ok
    client.finish(stream) |> should.be_ok

    assert client.next_event(stream) == Error(client.Timeout)
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_applies_send_backpressure_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 5000) |> should.be_ok
    let configuration =
      client.with_stream_buffer_limit(configuration, 524_288) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let connection =
      client.connect(configuration, "localhost", port) |> should.be_ok
    let request =
      streaming_request(port, "/echo")
      |> request.set_method(http.Post)
    let stream = client.open_stream(connection, request) |> should.be_ok
    let chunk = string.repeat("x", times: 16_384) |> bit_array.from_string

    send_chunks(stream: stream, chunk: chunk, remaining: 16)
    client.finish(stream) |> should.be_ok
    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, _) =
      client.next_event(stream) |> should.be_ok
    assert bit_array.byte_size(receive_stream_body(stream, <<>>)) == 262_144
    assert client.close(connection) == Ok(client.Closed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_client_recovers_from_packet_loss_test() -> Nil {
  http3_test_support.with_lossy_server(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 5000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let connection =
      client.connect(configuration, "localhost", port) |> should.be_ok
    let stream =
      streaming_request(port, "/large")
      |> client.open_stream(connection, _)
      |> should.be_ok
    client.finish(stream) |> should.be_ok

    // nolint: assert_ok_pattern -- the response shape is the test assertion.
    let assert client.Response(200, _) =
      client.next_event(stream) |> should.be_ok
    assert bit_array.byte_size(receive_stream_body(stream, <<>>)) == 64
    assert client.close(connection) == Ok(client.Closed)
  })
}

fn streaming_connection(
  port: Int,
  ca_certificate: BitArray,
) -> client.Connection {
  let configuration = client.with_timeout(client.new(), 3000) |> should.be_ok
  let configuration =
    client.with_stream_buffer_limit(configuration, 1024) |> should.be_ok
  let configuration =
    client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
  client.connect(configuration, "localhost", port) |> should.be_ok
}

fn streaming_request(port: Int, path: String) -> request.Request(Nil) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(Nil)
}

fn receive_stream_body(stream: client.Stream, body: BitArray) -> BitArray {
  case client.next_event(stream) |> should.be_ok {
    client.InformationalResponse(_, _) -> receive_stream_body(stream, body)
    client.Response(_, _) -> receive_stream_body(stream, body)
    client.Data(chunk) ->
      receive_stream_body(stream, bit_array.append(body, chunk))
    client.Trailers(_) -> receive_stream_body(stream, body)
    client.End -> body
  }
}

fn send_chunks(
  stream stream: client.Stream,
  chunk chunk: BitArray,
  remaining remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      client.send_chunk(stream, chunk) |> should.be_ok
      send_chunks(stream: stream, chunk: chunk, remaining: remaining - 1)
    }
  }
}
