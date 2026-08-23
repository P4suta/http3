import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/http/response
import gleeunit/should
import http3/client
import http3_test_support

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
