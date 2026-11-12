import gleam/list
import gleam/option.{Some}
import quic_core
import quic_core/client
import quic_core/diagnostics
import quic_core/internal/runtime/connect_trace
import quic_core/internal/runtime/happy_eyeballs
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

pub type ContractTests

// nolint: unused_exports, trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "quic_connect_trace_test", "contracts")
pub fn bounded_connect_trace_contracts_test_() -> ContractTests

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owner_deadline_finishes_pending_candidate_phases_test() -> Nil {
  let trace = diagnostics.new_connect_trace()
  let attempt = connect_trace.begin(Some(trace))
  let candidate = connect_trace.candidate(attempt, 2)
  connect_trace.record(candidate, 2, 1)
  connect_trace.record(candidate, 2, 2)
  connect_trace.record(candidate, 3, 1)
  connect_trace.abandon(attempt)
  let outcomes =
    diagnostics.connect_snapshot(trace).events
    |> list.map(fn(event) { #(event.candidate, event.phase, event.outcome) })
  assert outcomes
    == [
      #(2, diagnostics.UdpOpen, diagnostics.Started),
      #(2, diagnostics.UdpOpen, diagnostics.Succeeded),
      #(2, diagnostics.TlsHandshake, diagnostics.Started),
      #(2, diagnostics.TlsHandshake, diagnostics.Abandoned),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connect_trace_retains_verified_native_phases_after_close_test() -> Nil {
  let assert Ok(certificate) = fixture("server.pem")
  let assert Ok(key) = fixture("server-key.pem")
  let assert Ok(configured) = server.new(certificate, key, "trace")
  let assert Ok(listener) =
    configured |> server.with_address_family(quic_core.Ipv4) |> server.start
  let assert Ok(port) = server.port(listener)
  let trace = diagnostics.new_connect_trace()
  let assert Ok(configured) = client.new("localhost", port, "trace")
  let assert Ok(configured) =
    client.with_ca_certificates(configured, certificate)
  let assert Ok(connection) =
    configured
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_connect_trace(trace)
    |> client.connect
  let assert Ok(peer) = server.accept(listener)
  let _client_closed = client.close(connection)
  let _server_closed = server.close(peer)
  let _stopped = server.stop(listener)
  let snapshot = diagnostics.connect_snapshot(trace)
  assert snapshot.consistent
  assert snapshot.dropped == 0
  let resolution = connect_trace.resolution_snapshot(trace)
  assert resolution.consistent
  assert resolution.dropped == 0
  assert list.map(resolution.events, fn(event) {
      #(event.family, event.outcome)
    })
    == [
      #(happy_eyeballs.Ipv4, happy_eyeballs.ResolutionStarted),
      #(happy_eyeballs.Ipv4, happy_eyeballs.ResolutionUsable),
    ]
  [
    diagnostics.NameResolution,
    diagnostics.UdpOpen,
    diagnostics.TlsHandshake,
    diagnostics.OwnershipPublication,
  ]
  |> list.each(fn(phase) {
    let completed =
      list.any(snapshot.events, fn(event) {
        event.phase == phase && event.outcome == diagnostics.Succeeded
      })
    assert completed
  })
}
