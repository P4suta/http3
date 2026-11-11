//// The public H3 paths must fund diagnostic work before connecting, including the buffered path which used to open its own writer after the core dial.

import gleam/http/request
import gleeunit/should
import http3/client
import http3/config
import http3/failure
import http3/internal/qlog_admission
import http3/transport
import http3_test_support

// nolint: unused_exports -- gleeunit discovers ordinary public test functions.
pub fn diagnostic_public_slice_uses_the_shared_core_ledger_test() -> Nil {
  let identity = qlog_admission.new()
  let limits =
    config.default_limits()
    |> config.with_limit(failure.EndpointMemory, 81_920)
    |> should.be_ok
  let reservation =
    qlog_admission.reserve(identity, "unused-config-only", limits)
    |> should.be_ok
  assert qlog_admission.snapshot(identity) == #(16_384, 0)
  assert qlog_admission.begin_open(reservation) == Ok(Nil)
  qlog_admission.release_unused(reservation)
  assert qlog_admission.snapshot(identity) == #(16_384, 0)
  qlog_admission.release_confirmed(reservation)
  qlog_admission.release_confirmed(reservation)
  assert qlog_admission.snapshot(identity) == #(0, 0)
}

// nolint: unused_exports -- gleeunit discovers ordinary public test functions.
pub fn buffered_qlog_requires_diagnostic_admission_test() -> Nil {
  let #(_, files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      http3_test_support.with_ipv4_server_timeout(3000, fn(port, ca) {
        let configured = configured_client(directory, ca)
        let outbound =
          request.new()
          |> request.set_host("localhost")
          |> request.set_port(port)
          |> request.set_path("/echo")
          |> request.set_body(<<>>)
        assert client.send(configured, outbound)
          == Error(
            client.Failure(failure.Limit(failure.EndpointMemory, 65_536)),
          )
      })
    })
  assert files == 0
}

// nolint: unused_exports -- gleeunit discovers ordinary public test functions.
pub fn reusable_qlog_requires_diagnostic_admission_test() -> Nil {
  let #(_, files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      http3_test_support.with_ipv4_server_timeout(3000, fn(port, ca) {
        let configured = configured_client(directory, ca)
        let refused = case client.connect(configured, "localhost", port) {
          Error(error) ->
            error
            == client.Failure(failure.Limit(failure.EndpointMemory, 65_536))
          Ok(connection) -> {
            assert client.close(connection) == Ok(client.Closed)
            False
          }
        }
        assert refused
      })
    })
  assert files == 0
}

fn configured_client(directory: String, ca: BitArray) -> client.Client {
  let limits =
    config.default_limits()
    |> config.with_limit(failure.EndpointMemory, 65_536)
    |> should.be_ok
  let trace = transport.qlog(directory) |> should.be_ok
  client.new()
  |> client.with_ca_certificate(ca)
  |> should.be_ok
  |> client.with_address_family(config.Ipv4)
  |> client.with_limits(limits)
  |> client.with_qlog(trace)
  |> client.with_timeout(3000)
  |> should.be_ok
}
