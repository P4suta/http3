//// Client-side `EndpointMemory` admission over the public API.

import gleam/result
import gleeunit/should
import quic_core
import quic_core/client
import quic_core/config
import quic_core/failure
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn insufficient_client_endpoint_memory_fails_before_admission_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let limits =
    config.default_limits()
    |> config.with_limit(failure.EndpointMemory, 1)
    |> should.be_ok
  let outcome =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.with_limits(limits)
    |> client.connect

  let _cleanup = result.map(outcome, client.close)
  let stopped = server.stop(listener)

  assert outcome
    == Error(client.Failure(failure.Limit(failure.EndpointMemory, 1)))
  assert stopped == Ok(server.Stopped)
}
