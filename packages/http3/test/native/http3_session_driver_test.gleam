//// Black-box replacements for the former private-driver session fixture.
////
//// These tests intentionally import only the stable HTTP/3 surface. The
//// transport, TLS, UDP, and connection actors are exercised through the
//// public `quic_core` adapter used by the product runtime.

import gleam/http/request
import gleam/http/response
import gleeunit/should
import http3/client
import http3/transport
import http3_test_support

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_core_v1_request_response_loopback_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration = client_configuration(ca_certificate)
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_header("x-boundary", "public-core")
      |> request.set_body(<<"public v1":utf8>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert response.get_header(reply, "x-request-path") == Ok("/echo")
    assert reply.body == <<"public v1":utf8>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_core_v2_request_response_loopback_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let configuration =
      client_configuration(ca_certificate)
      |> client.with_quic_version(transport.QuicV2)
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_body(<<"public v2":utf8>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert reply.body == <<"public v2":utf8>>
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_core_connection_controls_loopback_test() -> Nil {
  http3_test_support.with_server(fn(port, ca_certificate) {
    let connection =
      client.connect(client_configuration(ca_certificate), "localhost", port)
      |> should.be_ok
    let controls = client.connection_transport(connection)

    transport.ping(controls) |> should.be_ok
    assert transport.maximum_transmission_unit(controls) |> should.be_ok >= 1200
    assert client.close(connection) == Ok(client.Closed)
  })
}

fn client_configuration(ca_certificate: BitArray) -> client.Client {
  client.new()
  |> client.with_timeout(3000)
  |> should.be_ok
  |> client.with_ca_certificate(ca_certificate)
  |> should.be_ok
}
