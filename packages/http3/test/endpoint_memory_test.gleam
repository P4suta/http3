//// HTTP/3 propagation of the public core endpoint-memory admission policy.

import gleam/option.{Some}
import gleam/result
import gleeunit/should
import http3/client
import http3/config
import http3/failure
import http3/server
import http3_test_support

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn insufficient_client_endpoint_memory_is_typed_test() -> Nil {
  let #(listener, port, ca_certificate) = start_server(config.default_limits())
  let limits =
    config.default_limits()
    |> config.with_limit(failure.EndpointMemory, 1)
    |> should.be_ok
  let configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
    |> client.with_limits(limits)
  let outcome = client.connect(configuration, "localhost", port)
  let _cleanup = result.map(outcome, client.close)
  let stopped = server.stop(listener)

  assert outcome
    == Error(client.Failure(failure.Limit(failure.EndpointMemory, 1)))
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_endpoint_memory_refuses_live_connection_admission_test() -> Nil {
  let limits =
    config.default_limits()
    |> config.with_limit(failure.EndpointMemory, 1)
    |> should.be_ok
  let #(listener, port, ca_certificate) = start_server(limits)
  let configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
  let outcome = client.connect(configuration, "localhost", port)
  let _cleanup = result.map(outcome, client.close)
  let stopped = server.stop(listener)

  assert peer_refused_connection(outcome)
  assert stopped == Ok(server.Stopped)
}

fn start_server(limits: config.Limits) -> #(server.Listener, Int, BitArray) {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_limits(limits)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  #(listener, port, ca_certificate)
}

fn peer_refused_connection(
  outcome: Result(client.Connection, client.Error),
) -> Bool {
  case outcome {
    Error(client.Failure(failure.Closed(failure.Peer, Some(2)))) -> True
    Error(client.Failure(failure.Quic(failure.Peer, Some(2)))) -> True
    _ -> False
  }
}
