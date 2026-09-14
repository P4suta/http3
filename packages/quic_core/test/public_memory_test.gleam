//// Listener-wide `EndpointMemory` enforcement over real UDP.
////
//// PRE-004 requires the listener to own one aggregate byte budget for every
//// connection it admits. A connection is charged a working set when it is
//// admitted, and after that it asks the listener for room -- in whole quanta,
//// before it uses any of it -- for the memory it may come to hold: receive
//// reassembly, delivered-but-unread stream data, unsent and retransmittable
//// send buffers, sent-packet histories, crypto reassembly, and its own
//// Datagram backlog.
////
//// These tests pin the observable consequences over real UDP. Every budget
//// here is stated as the endpoint's own arithmetic over the connections its
//// test admits -- so many connections resting on a growth step, plus a stated
//// remainder -- rather than as a figure chosen to come out right, and each
//// test says which of the two shapes it wants: a budget its connections spend
//// between them, so a further connection cannot be admitted at all, or a
//// budget that admits every connection and then has no second growth step for
//// any of them.
////
////   * Aggregate pressure: with the budget spent by the connections holding
////     it, a further connection is refused rather than admitted into memory
////     the listener does not have, and the refusal reaches the client as a
////     typed failure rather than as a handshake that simply times out.
////   * Recovery: closing one of those connections returns its whole
////     reservation, so the next connection is admitted again.
////   * Backpressure, not truncation: a connection pressed up against its grant
////     stops being granted room to grow, so a server send parks and ends on
////     its own deadline as `Overload(EndpointMemory)` -- while the connection
////     itself stays live, data already inside an advertised window is still
////     delivered whole, and an unrelated connection completes an exchange
////     untouched.
////   * A refused connection is throttled, never destroyed: a Datagram frame
////     that would take it past its grant is dropped, which RFC 9221 permits,
////     and counted where every other inbound drop for that connection is
////     counted, while the connection itself stays live and responsive.
////   * Recovery from a refusal: when its neighbours release memory, a refused
////     connection is granted again and goes back to accepting the Datagrams it
////     had been dropping. That the grant needs no traffic of the connection's
////     own to arrive is the ledger's own property, and `budget_test` is where
////     it is pinned; what this suite shows is the recovery itself.
////   * Grant-before-growth on the send side: a connection whose grant was met
////     in full, with nothing refused it, still admits an application's write
////     only as far as that grant reaches. The per-stream `Buffer` ceiling the
////     application chose is not what bounds the write, and the bound does not
////     wait for a refusal to land.
////   * One grant, not one per stream: many streams writing at once share the
////     one grant their connection holds, so what the connection holds never
////     runs past what it was granted however many streams are pushing at it.
////     This is the send-side bound stated as the standing invariant rather
////     than as one write's outcome, because a single parked write cannot tell
////     a grant that bounded it from a refusal that arrived while it waited.
////   * Crash release: a connection actor that is killed rather than closed
////     returns its reservation just the same, and the next connection is
////     admitted.

import gleam/bit_array
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleeunit/should
import quic_core
import quic_core/client
import quic_core/config
import quic_core/diagnostics
import quic_core/failure
import quic_core/internal/connection_state
import quic_core/internal/runtime/client_worker
import quic_core/internal/runtime/connection_worker
import quic_core/internal/udp
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

/// The process behind one opaque public handle, found by its fixed role label.
@external(erlang, "quic_core_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

/// The connection actor handle inside one opaque public connection, so this
/// suite can read the send-buffer-against-grant seam no public API publishes.
@external(erlang, "quic_core_test_ffi", "connection_handle")
fn connection_handle(
  connection: server.Connection,
) -> Result(connection_worker.Connection, Nil)

/// The client actor handle inside one opaque public connection. The Erlang
/// seam only unwraps the public one-field wrapper and validates its shape.
@external(erlang, "quic_core_test_ffi", "connection_handle")
fn client_connection_handle(
  connection: client.Connection,
) -> Result(client_worker.Connection, Nil)

/// Which live actor executed one traced transport boundary.
pub type TraceEndpoint {
  ClientEndpoint
  ServerEndpoint
}

/// Payload-free STREAM/ACK progress captured while one bounded action waits.
pub type FrameProgressTrace {
  StreamCommitted(
    endpoint: TraceEndpoint,
    packet_number: Int,
    stream_id: Int,
    offset: Int,
    bytes: Int,
    finished: Bool,
    at_milliseconds: Int,
  )
  StreamReceived(
    endpoint: TraceEndpoint,
    packet_number: Int,
    stream_id: Int,
    offset: Int,
    bytes: Int,
    finished: Bool,
    at_milliseconds: Int,
  )
  AckCommitted(
    endpoint: TraceEndpoint,
    packet_number: Int,
    at_milliseconds: Int,
  )
  AckReceived(endpoint: TraceEndpoint, packet_number: Int, at_milliseconds: Int)
  ConnectionTicked(endpoint: TraceEndpoint, at_milliseconds: Int)
}

/// Exact API-boundary timing for one failed four-byte exchange.
type RoundTripTiming {
  RoundTripTiming(
    opened_at_milliseconds: Int,
    request_started_at_milliseconds: Int,
    request_finished_at_milliseconds: Int,
    accept_started_at_milliseconds: Int,
    accept_finished_at_milliseconds: Int,
  )
}

@external(erlang, "quic_core_test_ffi", "trace_frame_progress")
fn trace_frame_progress(
  client_actor: Pid,
  server_actor: Pid,
  action: fn() -> value,
) -> #(value, List(FrameProgressTrace))

/// The fixed diagnostic label every per-connection actor must carry.
const connection_label = "quic_core.connection"

const client_label = "quic_core.client"

/// The accounting quantum: the ledger's own step, and the working set the
/// listener charges to admit one connection.
const quantum_bytes = 16_384

/// One connection's stream buffer, thirty-two quanta. Its owner never drains
/// it in these tests, so what is offered to it stays where it was put: in the
/// sending endpoint's buffer once the receiving peer's own credit runs out.
///
/// It is deliberately twice the growth step a pressed connection rests on, so
/// that what ends a press is the endpoint budget and not one stream's own
/// reassembly bound. A `Buffer` narrower than the grant would make the
/// per-stream ceiling the first thing a flood meets, which is a different
/// bound from the one these tests exist to pin.
const connection_buffer_bytes = 524_288

/// The whole quanta one admitted connection settles at.
///
/// A connection is charged its admission on its first Initial packet and then
/// asks its endpoint, on its actor's very first turn, for one growth step of
/// headroom to advertise receive credit into. That step is what it rests on,
/// so a listener's budget is spent by the connections it holds rather than by
/// what any one of them happens to be carrying.
const resting_quanta = 16

/// What a budget leaves over its connections' resting grants when the point is
/// that a further connection cannot be admitted: less than one admission
/// charge, which is three quanta.
const admission_remainder_quanta = 2

/// What a budget leaves over when the point is that its connections are all
/// admitted and none of them can be granted a second step.
///
/// Exactly one admission charge. It has to be at least that, or the last
/// connection would be refused admission rather than refused room to grow, and
/// it is kept to exactly that so a connection refused its second step is left
/// with a grant it is already nearly filling.
const growth_remainder_quanta = 3

/// How many connections are admitted before the budget is spent.
const loaded_connections = 3

const flood_chunk_bytes = 16_384

/// Eight times one connection's stream buffer, so every flood is held by its
/// peer's window rather than by running out of data to send.
const flood_chunks = 128

/// What a press offers one connection: one MiB, wider than the roughly 290 KiB
/// receive credit this grant can expose plus the client's 512 KiB stream send
/// buffer. The press therefore ends on a typed stop even when a promptly
/// flushed credit update lets the peer fill every funded byte.
const press_chunks = 64

/// Prefix a pressure probe reads before deliberately stopping.
///
/// Reading one accounting quantum opens fresh receive credit, then stopping
/// leaves the peer to fill that credit and the previously funded remainder.
/// The next grant request is `held + growth_step`, so this is sufficient to
/// make a full endpoint answer without draining the pressure away. The exact
/// prefix is retained in `PressureEvidence`; the subsequent refusal barrier or
/// Datagram drop is what proves endpoint pressure.
const window_probe_bytes = quantum_bytes

/// What the server offers a peer whose endpoint has no room for it, one
/// quantum at a time. The run ends at the first offer the endpoint will not
/// fund, so this only has to outlast what the peer's own receive credit and
/// the last of the endpoint's room will still take.
const blocked_send_quanta = 24

/// A send-buffer ceiling far wider than any grant this listener hands out, so
/// a write admitted to the ceiling is a write the grant never bounded.
///
/// It exists to tell the two bounds apart. A connection rests on a 256 KiB
/// grant; give its streams a 1 MiB buffer and the only thing that can hold a
/// write back is grant-before-growth itself.
const wide_send_buffer_bytes = 1_048_576

/// One write far wider than the grant plus everything a peer that never reads
/// can absorb, and far inside the send buffer's own ceiling.
///
/// A peer that never reads absorbs one stream receive window, 256 KiB, and the
/// grant behind the sending connection is another 256 KiB or so. Three quarters
/// of a megabyte is comfortably past both together and comfortably inside the
/// one-megabyte ceiling, so a write that completes completed because the
/// ceiling was the only bound.
const send_beyond_grant_bytes = 786_432

/// How many streams push at one connection's single grant at once.
///
/// One turn of a connection actor advances every parked stream it owns, so a
/// send side that bounded each stream separately would admit a whole allowance
/// per stream in that one turn. Sixteen is enough that the two readings are
/// nowhere near each other: sixteen per-stream ceilings is sixteen megabytes,
/// and one grant is a quarter of one.
const parallel_streams = 16

/// What each of those streams is offered: a quarter of the per-stream `Buffer`
/// ceiling, so no stream is ever held by its own ceiling, and sixteen of them
/// together are far more than any grant this listener hands out.
const parallel_write_bytes = 262_144

/// How long sixteen parallel writes have to settle. Each of them ends either
/// by completing or on its own operation deadline, so this only has to outlast
/// the last of those deadlines.
const parallel_bound_milliseconds = 10_000

/// Every wait in this module is bounded; exceeding a bound is a failure.
const operation_bound_milliseconds = 5000

/// Endpoint-memory pressure, not an unrelated idle timer, decides these
/// multi-connection tests. The bound stays finite but outlasts every bounded
/// flood and drain even when pure BEAM crypto shares a 1200-byte path.
const memory_test_idle_milliseconds = 120_000

/// A flood ends when its own sends stop being accepted, one operation
/// deadline after the peer's window shuts; this bound covers every flooder.
const flood_bound_milliseconds = 20_000

const drain_bound_milliseconds = 10_000

const drain_chunk_bytes = 65_536

/// How long a released reservation may take to reach the listener.
const release_bound_milliseconds = 2000

/// One RFC 9221 Datagram frame's payload, comfortably inside the smallest
/// path every QUIC connection carries.
const datagram_bytes = 1024

/// How many Datagrams one batch offers a refused connection: a fraction of the
/// 192-datagram delivery window in front of it, so nothing here is lost to that
/// window instead of to the budget. Batches are repeated until a drop is
/// counted, so this is a pacing figure rather than a total.
const datagram_offers = 32

/// A per-connection Datagram backlog far wider than the run above, so the
/// standing `Datagram` ceiling cannot be what discards one of these. That
/// ceiling is the application's own choice and is fatal when it is exceeded;
/// what these tests are about is the endpoint budget, which drops rather than
/// kills. The two must not be able to stand in for each other.
const datagram_budget_bytes = 1_048_576

/// How long a dropped Datagram may take to reach the connection's counter,
/// and how long a grant released by a neighbour may take to reach the
/// connection that was refused.
const grant_bound_milliseconds = 10_000

/// How often a bounded poll re-reads a counter it is waiting on.
const poll_milliseconds = 10

/// The step of a bounded exchange that failed, if any did.
type Step {
  ClientOpen(error: client.Error)
  ClientRequest(error: client.Error)
  ServerAcceptStream(
    error: server.Error,
    stream_id: quic_core.StreamId,
    timing: RoundTripTiming,
    client_progress: Result(client_worker.DevelopmentSnapshot, Nil),
    frame_trace: List(FrameProgressTrace),
    memory: Result(connection_worker.MemoryGrantSnapshot, Nil),
    client_traffic: Result(diagnostics.ConnectionStats, client.Error),
    server_traffic: Result(diagnostics.ConnectionStats, server.Error),
    server_dropped_datagrams: Result(Int, server.Error),
    client_path: Result(diagnostics.PathStats, client.Error),
    server_path: Result(diagnostics.PathStats, server.Error),
  )
  ServerRead(
    observed: Result(server.Read, server.Error),
    memory: Result(connection_worker.MemoryGrantSnapshot, Nil),
  )
  ServerReply(
    error: server.Error,
    memory: Result(connection_worker.MemoryGrantSnapshot, Nil),
  )
  ClientResponse(observed: Result(client.Read, client.Error))
}

/// Why the test-only endpoint-pressure barrier could not observe a refusal.
///
/// A timeout retains the complete last accounting snapshot. This turns a
/// scheduling-sensitive failure into evidence about which side of the grant
/// protocol had not advanced, without retaining application payload.
type PressureBarrierError {
  PressureStateUnavailable
  RefusalDeadlineExceeded(last: connection_worker.MemoryGrantSnapshot)
}

/// Whether a bounded flood exhausted its deliberately excessive input or was
/// actually stopped by the peer, retaining the typed terminal send error.
type FloodOutcome {
  FloodStopped(error: client.Error)
  FloodExhausted
}

/// Exact result of opening the receive window that drives one connection into
/// endpoint pressure. An accept failure and a short read are distinct evidence.
type WindowEvidence {
  WindowEvidence(accept_error: Option(server.Error), bytes_read: Int)
}

/// Payload-free evidence for the whole pressure precondition.
type PressureEvidence {
  PressureEvidence(
    window: WindowEvidence,
    flood: Result(FloodOutcome, Nil),
    memory: Result(connection_worker.MemoryGrantSnapshot, Nil),
    client_traffic: Result(diagnostics.ConnectionStats, client.Error),
    server_traffic: Result(diagnostics.ConnectionStats, server.Error),
  )
}

/// One admitted connection and the peer handle its listener owns.
type Pair {
  Pair(connection: client.Connection, peer: server.Connection)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn live_client_development_snapshot_explains_its_last_park_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = refusing_limits(1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok
  let pair = admitted(listener, port, ca_certificate, deadlines, limits)

  let snapshot = client_development_snapshot(pair.connection) |> should.be_ok
  let assert client_worker.DevelopmentSnapshot(
    observed_at_milliseconds: observed_at,
    next_wake_milliseconds: next_wake,
    previous_park: Some(previous_park),
    next_pmtu_probe_milliseconds: next_probe,
    path_mtu: path_mtu,
    pacing: pacing,
    longest_wait: Some(longest_wait),
    transport: transport,
    streams: streams,
    actor_pending_sends: pending_sends,
    actor_streams: actor_streams,
    incoming_streams: incoming_streams,
    maximum_pto_backoff: maximum_pto_backoff,
  ) = snapshot
  let client_worker.ParkProgress(
    observed_at_milliseconds: parked_at,
    selected_deadline: parked_deadline,
    path_mtu: parked_path_mtu,
    pacing: parked_pacing,
    transport: parked_transport,
    ..,
  ) = previous_park
  let client_worker.WaitProgress(
    park: client_worker.ParkProgress(
      observed_at_milliseconds: wait_started_at,
      ..,
    ),
    resumed_at_milliseconds: wait_resumed_at,
    wake: wake,
  ) = longest_wait
  let connection_state.SendProgress(
    pto_backoff_count: current_pto_backoff,
    active_streams: active_streams,
    ..,
  ) = transport

  assert observed_at >= parked_at
  assert wait_resumed_at >= wait_started_at
  assert wait_wake_is_typed(wake)
  assert next_probe > 0
  assert path_mtu >= 1200
  assert parked_path_mtu == path_mtu
  assert pacing_metadata_matches_path(pacing, path_mtu)
  assert pacing_metadata_matches_path(parked_pacing, path_mtu)
  assert parked_transport == transport
  assert maximum_pto_backoff >= current_pto_backoff
  assert streams == []
  assert pending_sends == []
  assert active_streams == []
  assert actor_streams == 0
  assert incoming_streams == 0
  assert deadline_is_bounded(next_wake, observed_at)
  assert deadline_is_bounded(parked_deadline, parked_at)

  close_pairs([pair])
  assert server.stop(listener) == Ok(server.Stopped)
}

fn wait_wake_is_typed(wake: client_worker.WaitWake) -> Bool {
  case wake {
    client_worker.CommandWake
    | client_worker.NetworkWake
    | client_worker.TimerWake -> True
  }
}

fn deadline_is_bounded(deadline: Option(Int), observed_at: Int) -> Bool {
  case deadline {
    None -> True
    Some(value) -> value >= observed_at
  }
}

fn pacing_metadata_matches_path(
  progress: connection_state.PacingWakeProgress,
  expected_path_mtu: Int,
) -> Bool {
  case progress {
    connection_state.NoPacingOutput -> True
    connection_state.PacingReady(candidate, path, window, flight, rtt) ->
      pacing_inputs_are_bounded(
        candidate,
        path,
        window,
        flight,
        rtt,
        expected_path_mtu,
      )
    connection_state.PacingWaiting(
      candidate,
      deadline,
      path,
      window,
      flight,
      rtt,
    ) ->
      deadline > 0
      && pacing_inputs_are_bounded(
        candidate,
        path,
        window,
        flight,
        rtt,
        expected_path_mtu,
      )
    connection_state.PacingDecisionInvalid(candidate, path, window, flight, rtt) ->
      pacing_inputs_are_bounded(
        candidate,
        path,
        window,
        flight,
        rtt,
        expected_path_mtu,
      )
  }
}

fn pacing_inputs_are_bounded(
  candidate: Int,
  path: Int,
  window: Int,
  flight: Int,
  rtt: Int,
  expected_path_mtu: Int,
) -> Bool {
  candidate > 0
  && candidate <= path
  && path == expected_path_mtu
  && window >= path
  && flight >= 0
  && rtt >= 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn aggregate_memory_pressure_refuses_a_further_connection_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = refusing_limits(loaded_connections)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // Every connection is admitted while the budget is still empty, so none of
  // them is refused for a reason this test is not about.
  let pairs =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  // Each peer then fills the receive buffer its owner never reads, so the
  // listener is holding every byte the budget has.
  let filled = flood_pairs(pairs)

  // The next connection arrives with the endpoint at its budget. It has to be
  // refused, and the refusal has to reach the client as a typed failure.
  let refused = connect(port, ca_certificate, deadlines, limits)

  // The admitted connections are healthy throughout: once their owners read,
  // every one of them still completes an exchange.
  let drained = list.map(pairs, drain_backlog)
  let exchanged = list.map(pairs, round_trip)

  // Bounded teardown before any bound is asserted.
  close_attempt(refused)
  close_pairs(pairs)
  let stopped = server.stop(listener)

  assert filled == True
  // Red until the listener owns an aggregate budget: today a fourth
  // connection is admitted into memory the endpoint has already spent.
  assert refusal(refused) == True
  assert drained == list.repeat(True, loaded_connections)
  assert exchanged == list.repeat(Ok(Nil), loaded_connections)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn draining_backlog_flushes_credit_before_an_unrelated_wake_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = refusing_limits(1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok
  let pair = admitted(listener, port, ca_certificate, deadlines, limits)

  // This one-connection shape isolates the credit-update edge hidden inside
  // the aggregate test: the endpoint has refused further growth, the peer has
  // filled the advertised window, and the application releases one quantum.
  let filled = flood_pairs([pair])
  let drained = drain_backlog(pair)
  let exchanged = round_trip(pair)

  // No packet, timer, or second API call is inserted between the read and the
  // exchange. The read command itself must flush MAX_DATA/MAX_STREAM_DATA.
  close_pairs([pair])
  let stopped = server.stop(listener)
  assert filled == True
  assert drained == True
  assert exchanged == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn releasing_a_loaded_connection_admits_a_new_one_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = refusing_limits(loaded_connections)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let pairs =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let released = list.take(pairs, 1)
  let kept = list.drop(pairs, 1)
  // Only the connection being released is loaded. The other connections'
  // resting grants still spend the listener budget, but they hold no
  // legitimate withheld growth requests that could consume the returned room
  // ahead of a new admission; FIFO regrant has its own pure and live tests.
  let filled = flood_pairs(released)
  let refused = connect(port, ca_certificate, deadlines, limits)

  // One loaded connection is closed in an orderly way, which returns its
  // whole reservation -- its receive backlog and its working set alike.
  close_pairs(released)
  let vacated = await_release(released)

  // The room that came back has to admit a new connection.
  let readmitted = connect(port, ca_certificate, deadlines, limits)
  let readmitted_peer = server.accept(listener)

  // Bounded teardown before any bound is asserted.
  close_attempt(refused)
  close_attempt(readmitted)
  close_peer_attempt(readmitted_peer)
  close_pairs(kept)
  let stopped = server.stop(listener)

  assert filled == True
  assert vacated == True
  // Red until the budget exists: the refusal below never happens today, so
  // the readmission it recovers from is not a recovery at all.
  assert refusal(refused) == True
  let assert Ok(_) = readmitted
  let assert Ok(_) = readmitted_peer
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn endpoint_memory_backpressures_instead_of_truncating_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = pressing_limits(loaded_connections + 2)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // Enough connections to spend the budget, one connection whose peer stops
  // reading, and one connection left alone to prove the budget bites where the
  // pressure is rather than everywhere. Every one of them is admitted before
  // any of them is pressed, so nothing here is refused admission.
  let loaded =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let stalled = admitted(listener, port, ca_certificate, deadlines, limits)
  let healthy = admitted(listener, port, ca_certificate, deadlines, limits)
  let stalled_actor = labelled_pid(stalled.peer, connection_label)

  // One quantum offered to the stalled peer, inside the window this endpoint
  // advertised and inside the room it was granted, so it has to arrive whole
  // however tight the budget becomes afterwards.
  let outgoing = server.open_bidirectional(stalled.peer) |> should.be_ok
  let inside_window = server.send(outgoing, repeated_bytes(quantum_bytes))

  // The budget is then spent by the connections whose owners never read, and
  // the stalled connection is pressed up against the room it was granted.
  let filled = flood_pairs(loaded)
  let pressed = press(stalled)

  // `press` ending says the remote sender stopped; it does not by itself say
  // that the listener's refusal has already reached this connection actor.
  // Establish that causal precondition explicitly before testing the send
  // side. The bounded barrier also retains the complete final accounting
  // state when a loaded run misses it.
  let pressure =
    await_memory_refused(
      stalled.peer,
      udp.monotonic_millisecond() + release_bound_milliseconds,
    )

  // Anything further the server offers that peer has to be held in memory the
  // endpoint has refused to fund. The funded prefix is sent first and the
  // remainder parks, so that partial progress must retain the grant as its
  // binding cause and end on its own deadline as a transient overload rather
  // than as a bare operation timeout.
  let before_blocked = send_buffer_grant_snapshot(stalled.peer)
  let blocked = send_until_refused(outgoing, blocked_send_quanta)
  let after_blocked = send_buffer_grant_snapshot(stalled.peer)

  // Backpressure, not truncation: the connection that could not be funded is
  // still there -- a write was held back, not a connection destroyed -- what
  // was already offered still arrives whole, the pressed connection's own
  // backlog is still there for its owner to read, and an unrelated connection
  // is untouched by any of it.
  let alive = result.map(stalled_actor, process.is_alive) == Ok(True)
  let delivered = read_prefix(stalled.connection)
  let retained = drain_backlog(list.first(loaded) |> should.be_ok)
  let exchanged = round_trip(healthy)

  // Bounded teardown before any bound is asserted.
  close_pairs([stalled, healthy, ..loaded])
  let stopped = server.stop(listener)

  assert inside_window == Ok(Nil)
  assert filled == True
  assert #(pressure_reached(pressed), pressed) == #(True, pressed)
  assert #(pressure, result.is_ok(pressure)) == #(pressure, True)
  // Red until the budget exists: today the server keeps growing its send
  // buffer for a peer that never reads until the exchange fails outright.
  // Keep the live grant snapshots in the assertion value so a failure says
  // whether the pressure precondition was missing or funded bytes overran.
  assert #(blocked, before_blocked, after_blocked)
    == #(
      Error(server.Failure(failure.Overload(failure.EndpointMemory))),
      before_blocked,
      after_blocked,
    )
  assert alive == True
  assert delivered >= quantum_bytes
  assert retained == True
  assert exchanged == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_refused_connection_drops_a_datagram_and_stays_alive_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = pressing_limits(loaded_connections + 1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // Every connection is admitted while the budget is still empty, and only
  // then is it spent, so what follows is a refusal to grow rather than a
  // refusal to admit.
  let pairs =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let subject = admitted(listener, port, ca_certificate, deadlines, limits)
  let filled = flood_pairs(pairs)
  let pressed = press(subject)

  // A Datagram frame is droppable by RFC 9221, so one that would take this
  // connection past a grant the endpoint has refused to widen is dropped and
  // counted where every other inbound loss for this connection is counted --
  // never queued, and never fatal.
  let before = settled_drops(subject.peer)
  let counted = offer_until_dropped(subject, before)
  let actor = labelled_pid(subject.peer, connection_label) |> should.be_ok
  let alive = process.is_alive(actor)

  // Bounded teardown before any bound is asserted.
  close_pairs([subject, ..pairs])
  let stopped = server.stop(listener)

  assert filled == True
  assert #(pressure_reached(pressed), pressed) == #(True, pressed)
  assert counted == True
  // The peer used credit this endpoint advertised, so the connection it used
  // it on is still there: a droppable frame was dropped, and nothing else.
  assert alive == True
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn releasing_memory_grants_a_refused_connection_again_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = pressing_limits(loaded_connections + 1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let pairs =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let subject = admitted(listener, port, ca_certificate, deadlines, limits)
  let filled = flood_pairs(pairs)
  let pressed = press(subject)

  // The refusal is established rather than assumed: a Datagram offered to this
  // connection is dropped for want of room.
  let before = settled_drops(subject.peer)
  let counted = offer_until_dropped(subject, before)

  // Its neighbours go away. Nothing happens on this connection to prompt a
  // retry -- and a refused connection does not ask again, because it would
  // only be refused again -- so the listener owes it the retry. A refusal
  // only lifted by traffic is a refusal that never lifts on a steady
  // connection.
  close_pairs(pairs)
  let vacated = await_release(pairs)

  // A Datagram now arrives instead of being dropped, which it can only do
  // inside a grant this connection was given rather than one it asked for. It
  // carries a payload none of the offers above did, so what proves the point is
  // a Datagram sent after the release rather than one queued before it.
  let resumed = await_datagram(subject, marked_bytes(datagram_bytes))

  // Bounded teardown before any bound is asserted.
  close_pairs([subject])
  let stopped = server.stop(listener)

  assert filled == True
  assert #(pressure_reached(pressed), pressed) == #(True, pressed)
  assert counted == True
  assert vacated == True
  assert resumed == True
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_crashed_connection_returns_its_whole_reservation_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = refusing_limits(loaded_connections)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let pairs =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  // One connection actor is killed outright rather than closed. The listener
  // learns of it only through the monitor it holds, and that release has to
  // return the whole reservation the dead actor was charged for.
  let crashed = list.first(pairs) |> should.be_ok
  let kept = list.drop(pairs, 1)
  // Keep the other connections at their resting grants so their independent
  // FIFO growth retries cannot consume the reservation this test expects to
  // observe as a new admission.
  let filled = flood_pairs([crashed])
  let refused = connect(port, ca_certificate, deadlines, limits)
  let actor = labelled_pid(crashed.peer, connection_label) |> should.be_ok
  process.kill(actor)
  let vacated = settled_exit(actor, release_bound_milliseconds)

  let readmitted = connect(port, ca_certificate, deadlines, limits)
  let readmitted_peer = server.accept(listener)

  // Bounded teardown before any bound is asserted.
  close_attempt(refused)
  close_attempt(readmitted)
  close_peer_attempt(readmitted_peer)
  close_pairs([crashed, ..kept])
  let stopped = server.stop(listener)

  assert filled == True
  assert vacated == True
  // Red until the budget exists: nothing is charged today, so nothing is
  // refused before the crash and nothing is returned by it.
  assert refusal(refused) == True
  let assert Ok(_) = readmitted
  let assert Ok(_) = readmitted_peer
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_met_grant_bounds_a_send_before_any_refusal_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = wide_buffer_limits(loaded_connections + 1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // Enough connections to spend the budget, and one more that is left alone.
  let loaded =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let target = admitted(listener, port, ca_certificate, deadlines, limits)

  // The budget is spent by the connections whose owners never read. The target
  // sends and receives nothing while that happens, so it never comes back for
  // a second step and nothing is ever refused it: the grant it holds is the
  // one it asked for on its first turn, met in full.
  let filled = flood_pairs(loaded)

  // One write far wider than that grant and far inside the per-stream `Buffer`
  // ceiling its application chose. Which of the two bounds it is the whole
  // question: charging for the growth after taking it would admit the write to
  // the ceiling, because no refusal has landed yet, and the write would
  // succeed. Funding it first admits only what the grant reaches past what the
  // connection holds, and parks the rest. What the deadline then reports is the
  // grant that had no room for it rather than any refusal: a send the grant
  // holds is endpoint memory whether or not the endpoint has said no yet.
  let outgoing = server.open_bidirectional(target.peer) |> should.be_ok
  let blocked = server.send(outgoing, repeated_bytes(send_beyond_grant_bytes))

  // And the write was held back, not the connection destroyed.
  let actor = labelled_pid(target.peer, connection_label) |> should.be_ok
  let alive = process.is_alive(actor)

  // Bounded teardown before any bound is asserted.
  close_pairs([target, ..loaded])
  let stopped = server.stop(listener)

  assert filled == True
  assert blocked
    == Error(server.Failure(failure.Overload(failure.EndpointMemory)))
  assert alive == True
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn one_grant_bounds_every_parallel_write_together_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines()
  let limits = wide_buffer_limits(loaded_connections + 1)
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // Enough connections to spend the budget, and one more that is left alone
  // until it is written to, so the grant it holds is the one it asked for on
  // its first turn and met in full.
  let loaded =
    admit(listener, port, ca_certificate, deadlines, limits, loaded_connections)
  let target = admitted(listener, port, ca_certificate, deadlines, limits)
  let filled = flood_pairs(loaded)

  // Sixteen streams are offered a quarter of the per-stream `Buffer` ceiling
  // each, all at once, and the connection is asked what it holds throughout.
  // A send side that admitted a write against the stream it is on would take
  // sixteen of those quarters -- four megabytes against a 256 KiB grant -- in
  // the single turn that advances every parked stream. One grant shared
  // between them admits one grant.
  let #(written, overrun) = parallel_writes(target.peer, parallel_streams)

  // The writes were held back, not the connection destroyed.
  let alive = still_alive(target.peer)

  // Bounded teardown before any bound is asserted.
  close_pairs([target, ..loaded])
  let stopped = server.stop(listener)

  assert filled == True
  // The standing bound: the bytes these writes took into this connection's
  // send buffers never ran past the endpoint memory that funded them, at any
  // point while sixteen streams were pushing at it.
  assert overrun == 0
  // And what the grant would not fund parked and named the endpoint rather
  // than merely running late.
  assert list.contains(
      written,
      Error(server.Failure(failure.Overload(failure.EndpointMemory))),
    )
    == True
  assert alive == True
  assert stopped == Ok(server.Stopped)
}

/// Deadlines short enough that every parked operation, handshake, and connect
/// attempt in this module ends well inside its own bound.
fn bounded_deadlines() -> config.Deadlines {
  config.default_deadlines()
  |> config.with_deadline(failure.Connect, operation_bound_milliseconds)
  |> should.be_ok
  |> config.with_deadline(failure.Handshake, operation_bound_milliseconds)
  |> should.be_ok
  |> config.with_deadline(failure.Operation, operation_bound_milliseconds)
  |> should.be_ok
  |> config.with_deadline(failure.Idle, memory_test_idle_milliseconds)
  |> should.be_ok
}

/// A listener budget that the connections a test admits spend between them,
/// leaving too little for one more connection to be admitted at all.
fn refusing_limits(connections: Int) -> config.Limits {
  budgeted_limits(connections * resting_quanta + admission_remainder_quanta)
}

/// A listener budget that admits every connection a test asks for and then has
/// no second growth step left for any of them.
///
/// The remainder is what makes both halves of that hold whatever order the
/// grants arrive in. It is exactly one admission charge -- the least it can be
/// and still admit the last connection after every earlier one has taken its
/// resting step -- and an admission charge is far short of a growth step, so no
/// connection that comes back for a second step can be given one. Neither half
/// depends on timing.
fn pressing_limits(connections: Int) -> config.Limits {
  budgeted_limits(connections * resting_quanta + growth_remainder_quanta)
}

/// A listener budget shaped like `pressing_limits`, with a per-stream buffer
/// far wider than the grant its connections rest on, so the only thing that can
/// hold a write back is the grant.
fn wide_buffer_limits(connections: Int) -> config.Limits {
  config.with_limit(
    pressing_limits(connections),
    failure.Buffer,
    wide_send_buffer_bytes,
  )
  |> should.be_ok
}

fn budgeted_limits(quanta: Int) -> config.Limits {
  config.default_limits()
  |> config.with_limit(failure.Buffer, connection_buffer_bytes)
  |> should.be_ok
  |> config.with_limit(failure.Datagram, datagram_budget_bytes)
  |> should.be_ok
  |> config.with_limit(failure.EndpointMemory, quanta * quantum_bytes)
  |> should.be_ok
}

fn start_listener(
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> server.Listener {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  server.new(certificate, private_key, "sample")
  |> should.be_ok
  |> server.with_address_family(quic_core.Ipv4)
  |> server.with_deadlines(deadlines)
  |> server.with_limits(limits)
  |> server.start
  |> should.be_ok
}

fn connect(
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> Result(client.Connection, client.Error) {
  client.new("localhost", port, "sample")
  |> should.be_ok
  |> client.with_address_family(quic_core.Ipv4)
  |> client.with_ca_certificates(ca_certificate)
  |> should.be_ok
  |> client.with_deadlines(deadlines)
  |> client.with_limits(limits)
  |> client.connect
}

/// One connection admitted and accepted, which every test needs before the
/// budget is spent.
fn admitted(
  listener: server.Listener,
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> Pair {
  let connection =
    connect(port, ca_certificate, deadlines, limits) |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  Pair(connection, peer)
}

fn admit(
  listener: server.Listener,
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
  count: Int,
) -> List(Pair) {
  case count <= 0 {
    True -> []
    False -> [
      admitted(listener, port, ca_certificate, deadlines, limits),
      ..admit(listener, port, ca_certificate, deadlines, limits, count - 1)
    ]
  }
}

/// Fill every listed connection's receive buffer with data its owner never
/// reads, and report whether every flood ended inside its bound.
fn flood_pairs(pairs: List(Pair)) -> Bool {
  let filled = process.new_subject()
  list.each(pairs, fn(pair) { start_flood(pair, filled, flood_chunks) })
  await_floods(filled, list.length(pairs))
}

/// Press one connection up against the room its endpoint granted it, and stop
/// when the endpoint has stopped funding it.
///
/// A peer floods, and this connection's owner reads one accounting quantum,
/// which advertises fresh credit, then stops. Stopping leaves the funded window
/// filled with data nobody is coming to take. A later refusal barrier or
/// Datagram drop proves the pressure itself.
fn press(pair: Pair) -> PressureEvidence {
  let filled = process.new_subject()
  let stream = client.open_bidirectional(pair.connection) |> should.be_ok
  let _flooder =
    process.spawn_unlinked(fn() {
      process.send(
        filled,
        flood(stream, repeated_bytes(flood_chunk_bytes), press_chunks),
      )
    })
  let window = open_window(pair.peer)
  let flood = process.receive(filled, within: flood_bound_milliseconds)
  PressureEvidence(
    window,
    flood,
    memory_grant_snapshot(pair.peer),
    client.connection_stats(pair.connection),
    server.connection_stats(pair.peer),
  )
}

/// Read one growth step of what a press is delivering, inside a fixed bound.
fn open_window(peer: server.Connection) -> WindowEvidence {
  case server.accept_stream(peer) {
    Error(reason) -> WindowEvidence(Some(reason), 0)
    Ok(server.IncomingStream(stream, _kind)) ->
      WindowEvidence(
        None,
        drain_stream_bytes(
          stream,
          udp.monotonic_millisecond() + drain_bound_milliseconds,
          0,
          window_probe_bytes,
        ),
      )
  }
}

fn pressure_reached(evidence: PressureEvidence) -> Bool {
  let PressureEvidence(window:, flood:, ..) = evidence
  let WindowEvidence(accept_error:, bytes_read:) = window
  accept_error == None
  && bytes_read >= window_probe_bytes
  && case flood {
    Ok(FloodStopped(_)) -> True
    Ok(FloodExhausted) | Error(Nil) -> False
  }
}

/// One unlinked flooder per connection, so a flood parked behind a shut window
/// ends with its own send rather than holding this test process.
fn start_flood(pair: Pair, filled: Subject(Nil), chunks: Int) -> Pid {
  let stream = client.open_bidirectional(pair.connection) |> should.be_ok
  process.spawn_unlinked(fn() {
    let _outcome = flood(stream, repeated_bytes(flood_chunk_bytes), chunks)
    process.send(filled, Nil)
  })
}

fn flood(
  stream: client.Stream,
  chunk: BitArray,
  remaining: Int,
) -> FloodOutcome {
  case remaining <= 0 {
    True -> FloodExhausted
    False ->
      case client.send(stream, chunk) {
        Error(reason) -> FloodStopped(reason)
        Ok(Nil) -> flood(stream, chunk, remaining - 1)
      }
  }
}

fn await_floods(filled: Subject(Nil), remaining: Int) -> Bool {
  case remaining <= 0 {
    True -> True
    False ->
      case process.receive(filled, within: flood_bound_milliseconds) {
        Error(Nil) -> False
        Ok(Nil) -> await_floods(filled, remaining - 1)
      }
  }
}

/// Whether a connect attempt was refused for the endpoint's memory budget:
/// the typed limit itself, or the CONNECTION_REFUSED close (transport code
/// 0x02) a refused handshake carries.
fn refusal(outcome: Result(client.Connection, client.Error)) -> Bool {
  case outcome {
    Error(client.Failure(failure.Limit(failure.EndpointMemory, _maximum))) ->
      True
    Error(client.Failure(failure.Closed(failure.Peer, Some(2)))) -> True
    Error(client.Failure(failure.Quic(failure.Peer, Some(2)))) -> True
    _other -> False
  }
}

/// Read back a quantum of one connection's unread backlog, which is what its
/// owner reading means here, inside a fixed bound.
fn drain_backlog(pair: Pair) -> Bool {
  case server.accept_stream(pair.peer) {
    // nolint: thrown_away_error -- a connection with no backlog fails here.
    Error(_reason) -> False
    Ok(server.IncomingStream(stream, _kind)) ->
      drain_stream(
        stream,
        udp.monotonic_millisecond() + drain_bound_milliseconds,
        0,
        quantum_bytes,
      )
  }
}

fn drain_stream(
  stream: server.Stream,
  deadline: Int,
  seen: Int,
  wanted: Int,
) -> Bool {
  drain_stream_bytes(stream, deadline, seen, wanted) >= wanted
}

fn drain_stream_bytes(
  stream: server.Stream,
  deadline: Int,
  seen: Int,
  wanted: Int,
) -> Int {
  case seen >= wanted {
    True -> seen
    False ->
      case udp.monotonic_millisecond() >= deadline {
        True -> seen
        False ->
          case server.receive(stream, drain_chunk_bytes) {
            Ok(server.Data(bytes, _finished)) ->
              drain_stream_bytes(
                stream,
                deadline,
                seen + bit_array.byte_size(bytes),
                wanted,
              )
            Ok(server.Finished) | Ok(server.Reset(_)) -> seen
            // nolint: thrown_away_error -- A short count is failure evidence.
            Error(_) -> seen
          }
      }
  }
}

/// Offer a peer that never reads one quantum at a time until an offer is
/// refused, and report the refusal. A run that is never refused reports the
/// success it should not have had.
fn send_until_refused(
  stream: server.Stream,
  remaining: Int,
) -> Result(Nil, server.Error) {
  case remaining <= 0 {
    True -> Ok(Nil)
    False ->
      case server.send(stream, repeated_bytes(quantum_bytes)) {
        Error(reason) -> Error(reason)
        Ok(Nil) -> send_until_refused(stream, remaining - 1)
      }
  }
}

/// Whether the actor behind one accepted connection is still running.
fn still_alive(peer: server.Connection) -> Bool {
  case labelled_pid(peer, connection_label) {
    Error(Nil) -> False
    Ok(actor) -> process.is_alive(actor)
  }
}

/// Offer `count` streams `parallel_write_bytes` each at the same time, and
/// report how every write ended together with the widest margin by which what
/// the connection held ever ran past what it was granted.
///
/// The margin is sampled while the writes are in flight as well as after they
/// have settled, because an overrun is admitted in the turn that advances the
/// parked streams and a connection that has already been refused more room
/// looks the same afterwards either way.
fn parallel_writes(
  peer: server.Connection,
  count: Int,
) -> #(List(Result(Nil, server.Error)), Int) {
  let written = process.new_subject()
  let payload = repeated_bytes(parallel_write_bytes)
  list.each(open_streams(peer, count), fn(stream) {
    process.spawn_unlinked(fn() {
      process.send(written, server.send(stream, payload))
    })
  })
  collect_parallel_writes(
    peer,
    written,
    count,
    udp.monotonic_millisecond() + parallel_bound_milliseconds,
    [],
    grant_overrun(peer),
  )
}

fn open_streams(peer: server.Connection, count: Int) -> List(server.Stream) {
  case count <= 0 {
    True -> []
    False -> [
      server.open_bidirectional(peer) |> should.be_ok,
      ..open_streams(peer, count - 1)
    ]
  }
}

fn collect_parallel_writes(
  peer: server.Connection,
  written: Subject(Result(Nil, server.Error)),
  remaining: Int,
  deadline: Int,
  results: List(Result(Nil, server.Error)),
  overrun: Int,
) -> #(List(Result(Nil, server.Error)), Int) {
  case remaining <= 0 || udp.monotonic_millisecond() >= deadline {
    True -> #(results, int.max(overrun, grant_overrun(peer)))
    False -> {
      let #(remaining, results) = case
        process.receive(written, within: poll_milliseconds)
      {
        Error(Nil) -> #(remaining, results)
        Ok(result) -> #(remaining - 1, [result, ..results])
      }
      collect_parallel_writes(
        peer,
        written,
        remaining,
        deadline,
        results,
        int.max(overrun, grant_overrun(peer)),
      )
    }
  }
}

/// How far the bytes one connection has taken into its send buffers have run
/// past the endpoint memory that funded them, which grant-before-growth on the
/// send side keeps at zero. A connection whose actor has already gone has
/// nothing to answer for.
fn grant_overrun(peer: server.Connection) -> Int {
  case send_buffer_grant_snapshot(peer) {
    Error(Nil) -> 0
    Ok(#(buffered, granted)) -> int.max(0, buffered - granted)
  }
}

/// Snapshot one connection's send buffers against the endpoint grant that
/// funds them, without exposing that test-only actor seam to production API.
fn send_buffer_grant_snapshot(
  peer: server.Connection,
) -> Result(#(Int, Int), Nil) {
  use handle <- result.try(connection_handle(peer))
  connection_worker.send_buffer_grant(handle)
  |> result.replace_error(Nil)
}

/// Wait until the endpoint's refusal response has reached one connection.
///
/// This is a synchronization barrier, not a timing allowance: a remote flood
/// ending and the listener's reply becoming actor state are separate message
/// deliveries. Both paths are bounded, and a deadline reports every finite
/// accounting counter from the last state observed.
fn await_memory_refused(
  peer: server.Connection,
  deadline: Int,
) -> Result(connection_worker.MemoryGrantSnapshot, PressureBarrierError) {
  case memory_grant_snapshot(peer) {
    Error(Nil) -> Error(PressureStateUnavailable)
    Ok(snapshot) ->
      case snapshot.refused {
        True -> Ok(snapshot)
        False ->
          case udp.monotonic_millisecond() >= deadline {
            True -> Error(RefusalDeadlineExceeded(snapshot))
            False -> {
              process.sleep(poll_milliseconds)
              await_memory_refused(peer, deadline)
            }
          }
      }
  }
}

/// Read the complete internal grant state without widening the package API.
fn memory_grant_snapshot(
  peer: server.Connection,
) -> Result(connection_worker.MemoryGrantSnapshot, Nil) {
  use handle <- result.try(connection_handle(peer))
  connection_worker.memory_grant_snapshot(handle)
  |> result.replace_error(Nil)
}

/// How many bytes of one server-initiated stream a client that stopped reading
/// can still read back, which is what "never discard data already inside the
/// advertised window" means from the peer's side.
fn read_prefix(connection: client.Connection) -> Int {
  case client.accept_stream(connection) {
    // nolint: thrown_away_error -- nothing offered means nothing delivered.
    Error(_reason) -> 0
    Ok(client.IncomingStream(stream, _kind)) ->
      read_stream(
        stream,
        udp.monotonic_millisecond() + drain_bound_milliseconds,
        quantum_bytes,
        0,
      )
  }
}

/// Read up to `wanted` bytes inside a fixed bound of this function's own, the
/// same bound `drain_stream` keeps: a read that never fills is a failed test,
/// not a function that runs until some other deadline rescues it.
fn read_stream(
  stream: client.Stream,
  deadline: Int,
  wanted: Int,
  seen: Int,
) -> Int {
  case seen >= wanted || udp.monotonic_millisecond() >= deadline {
    True -> seen
    False ->
      case client.receive(stream, drain_chunk_bytes) {
        Ok(client.Data(bytes, _finished)) ->
          read_stream(
            stream,
            deadline,
            wanted,
            seen + bit_array.byte_size(bytes),
          )
        _other -> seen
      }
  }
}

/// One bounded request and response, naming the step that failed.
fn round_trip(pair: Pair) -> Result(Nil, Step) {
  let opened_at = udp.monotonic_millisecond()
  case client.open_bidirectional(pair.connection) {
    Error(reason) -> Error(ClientOpen(reason))
    Ok(stream) ->
      round_trip_request(stream, pair.connection, pair.peer, opened_at)
  }
}

fn round_trip_request(
  stream: client.Stream,
  connection: client.Connection,
  peer: server.Connection,
  opened_at: Int,
) -> Result(Nil, Step) {
  let request_started_at = udp.monotonic_millisecond()
  case client.send_and_finish(stream, <<"ping":utf8>>) {
    Error(reason) -> Error(ClientRequest(reason))
    Ok(Nil) -> {
      let request_finished_at = udp.monotonic_millisecond()
      round_trip_accept(
        stream,
        connection,
        peer,
        opened_at,
        request_started_at,
        request_finished_at,
      )
    }
  }
}

fn round_trip_accept(
  stream: client.Stream,
  connection: client.Connection,
  peer: server.Connection,
  opened_at: Int,
  request_started_at: Int,
  request_finished_at: Int,
) -> Result(Nil, Step) {
  let accept_started_at = udp.monotonic_millisecond()
  let #(accepted, frame_trace) = traced_accept(connection, peer)
  let accept_finished_at = udp.monotonic_millisecond()
  case accepted {
    Error(reason) -> {
      // Development snapshots come first: every ordinary actor call is also a
      // bounded drive trigger, so taking counters first would perturb the
      // stalled state this failure exists to explain.
      let client_progress = client_development_snapshot(connection)
      let memory = memory_grant_snapshot(peer)
      Error(ServerAcceptStream(
        reason,
        client.stream_id(stream),
        RoundTripTiming(
          opened_at,
          request_started_at,
          request_finished_at,
          accept_started_at,
          accept_finished_at,
        ),
        client_progress,
        frame_trace,
        memory,
        client.connection_stats(connection),
        server.connection_stats(peer),
        server.dropped_datagrams(peer),
        client.path_stats(connection),
        server.path_stats(peer),
      ))
    }
    Ok(server.IncomingStream(peer_stream, _kind)) ->
      round_trip_read(stream, peer_stream, peer)
  }
}

fn traced_accept(
  connection: client.Connection,
  peer: server.Connection,
) -> #(Result(server.IncomingStream, server.Error), List(FrameProgressTrace)) {
  case
    labelled_pid(connection, client_label),
    labelled_pid(peer, connection_label)
  {
    Ok(client_actor), Ok(server_actor) ->
      trace_frame_progress(client_actor, server_actor, fn() {
        server.accept_stream(peer)
      })
    _, _ -> #(server.accept_stream(peer), [])
  }
}

fn client_development_snapshot(
  connection: client.Connection,
) -> Result(client_worker.DevelopmentSnapshot, Nil) {
  use handle <- result.try(client_connection_handle(connection))
  client_worker.development_snapshot(handle)
  |> result.replace_error(Nil)
}

fn round_trip_read(
  stream: client.Stream,
  peer_stream: server.Stream,
  peer: server.Connection,
) -> Result(Nil, Step) {
  case server.receive(peer_stream, drain_chunk_bytes) {
    Ok(server.Data(<<"ping":utf8>>, True)) ->
      round_trip_reply(stream, peer_stream, peer)
    observed -> Error(ServerRead(observed, memory_grant_snapshot(peer)))
  }
}

fn round_trip_reply(
  stream: client.Stream,
  peer_stream: server.Stream,
  peer: server.Connection,
) -> Result(Nil, Step) {
  case server.send_and_finish(peer_stream, <<"pong":utf8>>) {
    Error(reason) -> Error(ServerReply(reason, memory_grant_snapshot(peer)))
    Ok(Nil) -> round_trip_response(stream)
  }
}

fn round_trip_response(stream: client.Stream) -> Result(Nil, Step) {
  case client.receive(stream, drain_chunk_bytes) {
    Ok(client.Data(<<"pong":utf8>>, True)) -> Ok(Nil)
    observed -> Error(ClientResponse(observed))
  }
}

/// Wait, bounded, for every closed connection's actor to exit. The internal
/// release acknowledgement makes that exit a listener-ledger barrier rather
/// than merely proof that the actor sent its release notice.
fn await_release(pairs: List(Pair)) -> Bool {
  list.all(pairs, fn(pair) {
    case labelled_pid(pair.peer, connection_label) {
      // The actor is already gone, which is the release itself.
      Error(Nil) -> True
      Ok(actor) -> settled_exit(actor, release_bound_milliseconds)
    }
  })
}

fn settled_exit(actor: Pid, bound: Int) -> Bool {
  settled_exit_loop(actor, udp.monotonic_millisecond() + bound)
}

fn settled_exit_loop(actor: Pid, deadline: Int) -> Bool {
  case process.is_alive(actor) {
    False -> True
    True ->
      case udp.monotonic_millisecond() >= deadline {
        True -> False
        False -> {
          process.sleep(10)
          settled_exit_loop(actor, deadline)
        }
      }
  }
}

fn close_pairs(pairs: List(Pair)) -> Nil {
  list.each(pairs, fn(pair) {
    let _closed = client.close(pair.connection)
    let _peer_closed = server.close(pair.peer)
    Nil
  })
}

fn close_attempt(outcome: Result(client.Connection, client.Error)) -> Nil {
  case outcome {
    // nolint: thrown_away_error -- a refused connection has nothing to close.
    Error(_reason) -> Nil
    Ok(connection) -> {
      let _closed = client.close(connection)
      Nil
    }
  }
}

fn close_peer_attempt(outcome: Result(server.Connection, server.Error)) -> Nil {
  case outcome {
    // nolint: thrown_away_error -- an unaccepted peer has nothing to close.
    Error(_reason) -> Nil
    Ok(peer) -> {
      let _closed = server.close(peer)
      Nil
    }
  }
}

fn repeated_bytes(size: Int) -> BitArray {
  grow_bytes(<<0>>, size)
}

/// Bytes of the same length as `repeated_bytes` and none of its content, so a
/// delivery can be told apart from anything offered before it.
fn marked_bytes(size: Int) -> BitArray {
  grow_bytes(<<1>>, size)
}

fn grow_bytes(seed: BitArray, size: Int) -> BitArray {
  case bit_array.byte_size(seed) >= size {
    True -> bit_array.slice(seed, 0, size) |> result.unwrap(seed)
    False -> grow_bytes(bit_array.append(seed, seed), size)
  }
}

/// Offer a run of Datagrams to one connection, reporting whether every one of
/// them was accepted for sending. What the endpoint does with them on the far
/// side is what the test is about; refusing to send them here is not.
fn offer_datagrams(connection: client.Connection, remaining: Int) -> Bool {
  case remaining <= 0 {
    True -> True
    False ->
      case client.send_datagram(connection, repeated_bytes(datagram_bytes)) {
        // nolint: thrown_away_error -- an unsent offer fails this outright.
        Error(_reason) -> False
        Ok(Nil) -> offer_datagrams(connection, remaining - 1)
      }
  }
}

/// Read one connection's inbound drop counter once it has stopped moving, so
/// the drops the test then causes are the only ones it measures.
fn settled_drops(peer: server.Connection) -> Int {
  settled_drops_loop(
    peer,
    -1,
    udp.monotonic_millisecond() + grant_bound_milliseconds,
  )
}

fn settled_drops_loop(
  peer: server.Connection,
  seen: Int,
  deadline: Int,
) -> Int {
  case server.dropped_datagrams(peer) {
    // nolint: thrown_away_error -- a counter that cannot be read is settled.
    Error(_reason) -> seen
    Ok(dropped) ->
      case dropped == seen || udp.monotonic_millisecond() >= deadline {
        True -> dropped
        False -> {
          process.sleep(poll_milliseconds)
          settled_drops_loop(peer, dropped, deadline)
        }
      }
  }
}

/// Offer Datagrams to one connection, batch by batch, until one of them is
/// dropped for want of room, inside a fixed bound.
///
/// The pacing is what keeps this honest. A batch is a fraction of the
/// listener's delivery window and the poll between batches lets that window
/// refill, so a drop counted here is one the endpoint budget caused rather than
/// one the window did. How much has to be offered before the first drop is the
/// room the endpoint happened to have left over, which is why this offers until
/// it sees one rather than offering a figure guessed in advance.
fn offer_until_dropped(pair: Pair, before: Int) -> Bool {
  offer_until_dropped_loop(
    pair,
    before,
    udp.monotonic_millisecond() + grant_bound_milliseconds,
  )
}

fn offer_until_dropped_loop(pair: Pair, before: Int, deadline: Int) -> Bool {
  case server.dropped_datagrams(pair.peer) {
    Ok(dropped) if dropped > before -> True
    _other ->
      case udp.monotonic_millisecond() >= deadline {
        True -> False
        False -> {
          let offered = offer_datagrams(pair.connection, datagram_offers)
          process.sleep(poll_milliseconds)
          offered && offer_until_dropped_loop(pair, before, deadline)
        }
      }
  }
}

/// Offer one Datagram at a time until one is delivered whole, inside a fixed
/// bound. Each offer is droppable while the endpoint still refuses this
/// connection room, so a delivery is the grant having landed.
fn await_datagram(pair: Pair, payload: BitArray) -> Bool {
  await_datagram_loop(
    pair,
    payload,
    udp.monotonic_millisecond() + grant_bound_milliseconds,
  )
}

fn await_datagram_loop(pair: Pair, payload: BitArray, deadline: Int) -> Bool {
  // An offer this connection cannot make yet is simply offered again below.
  let _offered = client.send_datagram(pair.connection, payload)
  case server.receive_datagram(pair.peer) {
    Ok(delivered) if delivered == payload -> True
    _other ->
      case udp.monotonic_millisecond() >= deadline {
        True -> False
        False -> await_datagram_loop(pair, payload, deadline)
      }
  }
}
