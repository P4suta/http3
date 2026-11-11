//// HTTP/3 needs three local unidirectional streams before requests can run.
//// The fault below is local to one call and reaches the same core-close and qlog-release path as a real critical-stream bootstrap failure.

import gleam/option.{type Option, None, Some}
import gleam/result
import http3/config
import http3/failure
import http3/internal/native/client as native_client
import http3/internal/native/client_connection
import http3/internal/native/protocol
import http3/internal/native/server as native_server
import http3/internal/qlog_admission
import http3_test_support
import quic_core

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn three_unidirectional_streams_are_the_minimum_http3_capacity_test() -> Nil {
  let limits = config.default_limits()
  assert config.with_limit(limits, failure.UnidirectionalStreams, 1)
    == Error(config.InvalidLimit(failure.UnidirectionalStreams, 1))
  assert config.with_limit(limits, failure.UnidirectionalStreams, 2)
    == Error(config.InvalidLimit(failure.UnidirectionalStreams, 2))
  let assert Ok(limits) =
    config.with_limit(limits, failure.UnidirectionalStreams, 3)
  assert config.limit(limits, failure.UnidirectionalStreams) == 3
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn native_client_and_server_reject_capacity_below_critical_streams_test() -> Nil {
  let assert Ok(client) = native_client.new("localhost", 443)
  assert native_client.with_unidirectional_stream_limit(client, 1)
    == Error(native_client.InvalidUnidirectionalStreamLimit)
  assert native_client.with_unidirectional_stream_limit(client, 2)
    == Error(native_client.InvalidUnidirectionalStreamLimit)
  let assert Ok(_) = native_client.with_unidirectional_stream_limit(client, 3)

  let #(certificate, private_key, _) = http3_test_support.server_credentials()
  let assert Ok(server) = native_server.new(certificate, private_key)
  assert native_server.with_unidirectional_stream_limit(server, 1)
    == Error(native_server.InvalidUnidirectionalStreamLimit)
  assert native_server.with_unidirectional_stream_limit(server, 2)
    == Error(native_server.InvalidUnidirectionalStreamLimit)
  let assert Ok(_) = native_server.with_unidirectional_stream_limit(server, 3)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn critical_stream_bootstrap_failure_closes_core_and_returns_qlog_budget_test() -> Nil {
  let #(_, qlog_files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      http3_test_support.with_ipv4_server_timeout(3000, fn(port, ca) {
        let identity = qlog_admission.new()
        let first = failed_bootstrap(identity, directory, port, ca)
        assert first
          == client_connection.Http3OperationFailed(
            "start",
            protocol.ResourceFailure(protocol.InvalidResourceOperation),
          )
        assert qlog_admission.snapshot(identity) == #(0, 0)

        // A second fully admitted connection reaches the same injected fault.
        // If the first core owner or HTTP/3 slice leaked, reservation would be refused as Connections/EndpointMemory before this point.
        let second = failed_bootstrap(identity, directory, port, ca)
        assert second == first
        assert qlog_admission.snapshot(identity) == #(0, 0)
      })
    })
  assert qlog_files == 2
}

fn failed_bootstrap(
  identity: qlog_admission.Identity,
  directory: String,
  port: Int,
  ca: BitArray,
) -> client_connection.Error {
  let reservation =
    qlog_admission.reserve(identity, directory, diagnostic_limits())
    |> result_or_fail("diagnostic_reservation_refused")
  let outcome =
    client_connection.connect_with_third_critical_stream_failure(
      connection_config(port, ca, directory, reservation),
    )
  qlog_admission.release_unused(reservation)
  case outcome {
    Error(error) -> error
    Ok(state) -> {
      let _closed = client_connection.close_result(state, 0x100)
      http3_test_support.fail("unexpected_bootstrap_success")
    }
  }
}

fn diagnostic_limits() -> config.Limits {
  let assert Ok(limits) =
    config.with_limit(
      config.default_limits(),
      failure.EndpointMemory,
      8_388_608,
    )
  let assert Ok(limits) = config.with_limit(limits, failure.Connections, 1)
  limits
}

fn connection_config(
  port: Int,
  ca: BitArray,
  directory: String,
  reservation: Option(qlog_admission.Reservation),
) -> client_connection.Config {
  client_connection.Config(
    hostname: "localhost",
    port: port,
    address_family: quic_core.Ipv4,
    connect_address: None,
    dns_timeout_milliseconds: 3000,
    connect_timeout_milliseconds: 3000,
    handshake_timeout_milliseconds: 3000,
    timeout_milliseconds: 3000,
    idle_timeout_milliseconds: 3000,
    ca_certificates: Some([ca]),
    http_datagrams: False,
    resumption_ticket: None,
    address_token: <<>>,
    maximum_pushes: 0,
    quic_version: quic_core.QuicV1,
    stream_buffer_limit: 262_144,
    endpoint_memory_limit: 8_388_608,
    bidirectional_stream_limit: 100,
    unidirectional_stream_limit: 3,
    frame_limit: 65_536,
    datagram_limit: 65_527,
    qpack_table_limit: 4096,
    qpack_blocked_stream_limit: 16,
    telemetry_limit: 1024,
    qlog_directory: directory,
    connect_port: port,
    connect_trace: None,
    qlog_reservation: reservation,
  )
}

fn result_or_fail(outcome: Result(value, error), safe_reason: String) -> value {
  result.lazy_unwrap(outcome, fn() { http3_test_support.fail(safe_reason) })
}
