//// Credit-bounded router-to-connection delivery over real UDP.
////
//// The listener routes every inbound datagram to the connection actor that
//// owns the destination connection ID. That hand-off is credit bounded: the
//// listener sends one connection at most one message per relay batch, that
//// message carries only what the connection's remaining window admits --
//// `datagram_credit` datagrams and `byte_credit` bytes -- whatever exceeds
//// the window is dropped and counted for that connection alone, and the
//// actor's acknowledgement of what it consumed refills the window.
////
//// These tests pin the observable consequences over real UDP. A peer that
//// floods one connection's ID leaves that actor's mailbox inside the window
//// in both units, and leaves one whole batch's admitted share in a single
//// message rather than one message per datagram. A flood of datagrams too
//// large for the datagram half to bind first is held under the byte half. The
//// flooded connection's dropped-datagram counter rises while an unrelated
//// connection's stays at zero. And because QUIC is loss tolerant, the
//// connection whose window the drops shut still completes a bounded exchange
//// once its owner reads again.
////
//// The window is bounded from below as well. The relay hands the listener a
//// whole batch of up to `relay_batch` datagrams in one message, and the
//// listener routes that batch -- and may route the next one -- before any
//// `Consumed` acknowledgement refills a window mid-batch. A window narrower
//// than two full batches therefore sheds part of a burst that a perfectly
//// healthy connection is keeping up with: throughput lost for loss recovery
//// to repair, rather than a peer held to its share. A connection whose owner
//// reads the burst as it arrives must lose nothing.
////
//// Two tests carry that lower bound, and it is worth being exact about what
//// each one pins. One reads the shipped window straight out of the listener
//// and the batch size straight out of the relay, so the `at least two whole
//// batches` requirement binds the numbers production actually uses. The
//// other is behavioural: a connection whose owner keeps reading takes the two
//// whole relay batches that floor demands, sent back to back with no flow
//// control in the way, without its drop counter ever leaving zero.

import gleam/bit_array
import gleam/erlang/process.{type Pid}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic
import gleam_quic/client
import gleam_quic/config
import gleam_quic/failure
import gleam_quic/internal/ecn
import gleam_quic/internal/runtime/server_worker
import gleam_quic/internal/udp
import gleam_quic/server
import gleeunit/should

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

/// The process behind one opaque public handle, found by its fixed role label.
@external(erlang, "gleam_quic_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

/// The number of messages waiting in one connection actor's mailbox -- the
/// backlog the router's per-connection credit window must bound.
@external(erlang, "gleam_quic_test_ffi", "mailbox_length")
fn mailbox_length(actor: Pid) -> Result(Int, Nil)

/// One actor's mailbox as the delivery window sees it: the number of messages
/// waiting, and for every message carrying routed datagrams, how many
/// datagrams it carries and how many bytes they total. Both are read in one
/// call, so the message view and the datagram view cannot drift apart.
@external(erlang, "gleam_quic_test_ffi", "mailbox_deliveries")
fn mailbox_deliveries(actor: Pid) -> Result(#(Int, List(#(Int, Int))), Nil)

/// The destination connection ID of one datagram the listener already routed
/// to this actor, read straight off the wire bytes waiting in its mailbox.
@external(erlang, "gleam_quic_test_ffi", "routed_connection_id")
fn routed_connection_id(actor: Pid) -> Result(BitArray, Nil)

/// The relay's own maximum batch size, read straight from the transport FFI.
@external(erlang, "gleam_quic_test_ffi", "maximum_relay_batch")
fn maximum_relay_batch() -> Int

/// The connection ID the listener routes to one actor, taken from a bounded
/// trace of what that actor receives. A connection whose owner keeps reading
/// never leaves a routed datagram waiting in its mailbox, so the trace -- not
/// a mailbox poll -- is what makes the read an observation rather than a race.
@external(erlang, "gleam_quic_test_ffi", "traced_routed_connection_id")
fn traced_routed_connection_id(actor: Pid, bound: Int) -> Result(BitArray, Nil)

/// The fixed diagnostic label every per-connection actor must carry.
const connection_label = "gleam_quic.connection"

/// The datagram half of the router's per-connection delivery window, read
/// from the listener that ships it rather than copied here, so every bound in
/// this module binds the value production actually uses.
fn datagram_credit() -> Int {
  server_worker.delivery_window().0
}

/// The byte half of that same shipped window.
fn byte_credit() -> Int {
  server_worker.delivery_window().1
}

/// The relay's maximum batch: the most datagrams the socket relay hands the
/// listener in one message, mirrored from `MAXIMUM_RELAY_BATCH` in
/// gleam_quic_udp_ffi.erl and pinned below against the value the relay itself
/// reports. The listener routes a whole batch in one step and cannot refill a
/// window part way through it.
const relay_batch = 64

/// How many whole relay batches the delivery window has to span. This is the
/// requirement the shipped window is held to, not a copy of it: the listener
/// can route a second batch before the first batch's `Consumed` is handled,
/// so a window narrower than this many batches sheds part of a burst that its
/// connection is keeping up with.
const delivery_window_batches = 2

/// The healthy connection's receive buffer, which is what bounds the peer's
/// in-flight stream bytes below the delivery window: 64 KiB is roughly 54
/// datagrams, under one relay batch. That is deliberate, and it is also the
/// reason the transfer phase of the healthy regression is a sanity check on
/// real traffic rather than the pin on the window. A connection allowed more
/// bytes in flight than the window admits is by construction outrunning the
/// delivery window, so raising this buffer above `byte_credit` would make
/// drops legitimate rather than exercise the window's lower bound. The pin on
/// that lower bound is the spoofed burst below, which puts two full relay
/// batches on the wire at once with no flow control in the way.
const healthy_buffer_bytes = 65_536

/// How wide the healthy transfer is, in stream chunks: many relay batches'
/// worth of datagrams in total, though flow control keeps under one batch of
/// them in flight at a time, and few enough that the whole transfer passes
/// the owner inside a fixed bound.
const burst_chunks = 32

const burst_drain_bound_milliseconds = 10_000

/// The outer bound on the whole flow-controlled transfer, one settle longer
/// than the deadline its reader runs under, so a stalled transfer is reported
/// by that reader's deadline rather than by this wait.
const transfer_bound_milliseconds = 12_000

/// The mailbox bound, in messages. The router sends one message per
/// connection per relay batch and only while that connection's window is
/// open, and every such message costs the window at least one datagram, so no
/// more than one window of datagrams' worth of credited messages can ever be
/// outstanding at once.
/// One further message may carry a drop report for a window that was shut,
/// and the connection's owner may have a command of its own in flight.
const drop_report_messages = 1

const owner_command_allowance = 2

/// Every wait in this module is bounded; exceeding a bound is a failure.
const settle_bound_milliseconds = 2000

const operation_bound_milliseconds = 2000

/// How long a flooded actor's mailbox is sampled.
const flood_window_milliseconds = 400

const mailbox_poll_milliseconds = 2

/// The stalled connection's server-side receive buffer, which its owner never
/// drains, so the sender that exposes the routed connection ID stays inside
/// flow control.
const stall_buffer_bytes = 4_194_304

const cid_chunk_bytes = 16_384

const cid_chunks = 512

/// One spoofed short-header datagram: a short-header first byte, the routed
/// destination connection ID, then filler. It resolves to the connection's
/// actor without ever authenticating.
const junk_first_byte = 0x40

const junk_filler_bytes = 1191

/// An oversized spoofed datagram: 8 KiB on the wire, which loopback carries
/// whole and the listener sockets accept without any packet-size cap. Exactly
/// thirty-two of them fill the byte half of the window, so the byte half --
/// not the datagram half, which would admit 192 of them, six windows' worth
/// of bytes -- is what bounds a flood of these.
const oversized_junk_filler_bytes = 8183

/// A legitimate flood that fits inside the stalled receive buffer, so it ends
/// on its own without its owner ever reading and the spoofed flood that
/// follows is the only traffic being measured.
const quiet_flood_chunks = 128

/// A bounded overflow burst: far more datagrams than one credit window admits,
/// yet few enough that the actor drains them inside a fixed bound.
const overflow_burst = 4000

/// A mailbox small enough that a statistics command is serviced at once.
const drained_mailbox = 4

const drain_settle_bound_milliseconds = 10_000

/// A recovered connection answers a request promptly; EUnit's own five-second
/// test bound is the outer limit either way.
const recovery_round_trip_bound_milliseconds = 2000

/// Draining the 2 MiB recovery flood can take longer than one operation bound
/// on a path that correctly stays at QUIC's 1200-byte floor (for example when
/// the host cannot enable Don't-Fragment for DPLPMTUD). Keep the test finite,
/// while giving that portable path enough time to deliver the complete stream.
const recovery_drain_bound_milliseconds = 10_000

const drain_chunk_bytes = 65_536

/// The step of a recovery exchange that failed, if any did.
type Step {
  DrainFailed
  DrainReset
  DrainTimeout
  ClientOpen
  ClientRequest
  ServerAcceptStream
  ServerRead
  ServerReply
  ClientResponse
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn delivery_window_admits_two_full_relay_batches_test() -> Nil {
  // The relay delivers up to `relay_batch` datagrams in one message, the
  // listener routes that whole batch in a single step, and the next batch can
  // be routed before the `Consumed` for the previous one is handled. A window
  // narrower than two full batches therefore drops part of a burst its
  // connection is keeping up with, so the window must span two of them.
  assert relay_batch == maximum_relay_batch()
  assert datagram_credit() >= delivery_window_batches * maximum_relay_batch()
  // A datagram of the 1200-byte floor every QUIC path carries (RFC 9000
  // section 14) is the smallest a burst can be made of, so the byte half has
  // to hold two full batches of them as well, or it shuts before the datagram
  // half does and sheds the same healthy burst.
  assert byte_credit() >= delivery_window_batches * maximum_relay_batch() * 1200
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn healthy_connection_never_drops_a_full_batch_burst_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  // A long operation deadline covers the whole burst and the statistics query
  // that follows it, so no reply ever outlives its call.
  let deadlines = config.default_deadlines()
  let limits = healthy_limits()
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let healthy = tuned_connect(port, ca_certificate, deadlines, limits)
  let healthy_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(healthy_peer, connection_label) |> should.be_ok

  // A peer sends a flow-controlled transfer while its owner reads it as it
  // arrives. Flow control holds it under one relay batch in flight, so this
  // phase exercises the routed path rather than the window itself; what it
  // has to produce is a connection that is caught up and the identifier the
  // listener routes to it. A watcher traces the routed datagrams the actor
  // receives, so that identifier is readable without the owner ever having to
  // stop reading.
  let found = process.new_subject()
  let _watcher =
    spawn_identifier_watcher(actor, burst_drain_bound_milliseconds, found)
  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stream = client.open_bidirectional(healthy) |> should.be_ok
  let _flooder = spawn_flooder(stream, flooding, flooded, burst_chunks, True)
  let started = process.receive(flooding, within: settle_bound_milliseconds)
  let received =
    read_incoming_stream(
      healthy_peer,
      udp.monotonic_millisecond() + burst_drain_bound_milliseconds,
    )
  let sent = process.receive(flooded, within: transfer_bound_milliseconds)
  let identifier =
    process.receive(found, within: transfer_bound_milliseconds)
    |> result.flatten
  let quiet =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )
  let transferred_dropped = dropped_count(healthy_peer)

  // The connection is now idle and its actor is keeping up, so nothing but the
  // window itself can lose a datagram. Two whole relay batches then arrive
  // back to back, faster than any acknowledgement can refill a window
  // mid-burst: exactly the floor the window has to hold outright. The shipped
  // window is wider than that floor, which is the margin that keeps a stray
  // datagram of the peer's own -- an acknowledgement, a probe -- from tipping
  // the assertion below.
  let junked = process.new_subject()
  let _junker =
    spawn_burst_junker(
      port,
      result.unwrap(identifier, <<0:64>>),
      delivery_window_batches * relay_batch,
      junked,
    )
  let junk_done = process.receive(junked, within: 3 * settle_bound_milliseconds)
  let settled =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )
  let dropped = dropped_count(healthy_peer)

  // Bounded teardown before any bound is asserted.
  let _healthy_closed = client.close(healthy)
  let _healthy_peer_closed = server.close(healthy_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert sent == Ok(Nil)
  assert result.is_ok(identifier)
  assert quiet == Ok(Nil)
  assert junk_done == Ok(Nil)
  assert settled == Ok(Nil)
  // Every byte of the transfer arrived.
  assert received == Ok(burst_chunks * cid_chunk_bytes)
  // And a connection that kept up with all of it lost nothing. The two counts
  // are read separately so a regression names the phase that shed a datagram.
  // The transfer is flow controlled below one relay batch in flight, so its
  // count is a sanity check that real traffic under a reading owner loses
  // nothing; the burst that follows is what pins the window's lower bound,
  // because it puts three whole batches on the wire at once.
  assert transferred_dropped == Ok(0)
  assert dropped == Ok(0)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn flooded_connection_actor_mailbox_stays_within_credit_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines =
    config.uniform_deadlines(operation_bound_milliseconds) |> should.be_ok
  let limits = stalled_limits()
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  // One connection whose owner never reads a single byte.
  let stalled = tuned_connect(port, ca_certificate, deadlines, limits)
  let stalled_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(stalled_peer, connection_label) |> should.be_ok

  // A sender keeps routed datagrams flowing so the routed connection ID can be
  // read off the actor's mailbox.
  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stream = client.open_bidirectional(stalled) |> should.be_ok
  let _flooder = spawn_flooder(stream, flooding, flooded, cid_chunks, False)
  let started = process.receive(flooding, within: settle_bound_milliseconds)
  let identifier =
    await_routed_identifier(
      actor,
      udp.monotonic_millisecond() + settle_bound_milliseconds,
    )

  // A peer floods that connection ID with spoofed short-header datagrams for a
  // fixed window; the router must never grow the actor's mailbox without bound.
  let deadline = udp.monotonic_millisecond() + flood_window_milliseconds
  let junking = process.new_subject()
  let junked = process.new_subject()
  let _junker =
    spawn_windowed_junker(
      port,
      result.unwrap(identifier, <<0:64>>),
      junk_filler_bytes,
      deadline,
      junking,
      junked,
    )
  let junk_started = process.receive(junking, within: settle_bound_milliseconds)
  let peak = peak_backlog(actor, deadline, empty_backlog())

  // Bounded teardown before any bound is asserted.
  let junk_done = process.receive(junked, within: 3 * settle_bound_milliseconds)
  let _stalled_closed = client.close(stalled)
  let drained =
    process.receive(flooded, within: 3 * operation_bound_milliseconds)
  let _stalled_peer_closed = server.close(stalled_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert junk_started == Ok(Nil)
  assert junk_done == Ok(Nil)
  assert drained == Ok(Nil)
  assert result.is_ok(identifier)
  // The flood was observed while it was actually in the actor's mailbox.
  assert peak.deliveries > 0
  // Both halves of the window bound the whole mailbox, in their own units.
  assert peak.datagrams <= datagram_credit()
  assert peak.bytes <= byte_credit()
  // The message-count bound, in messages: every credited message costs the
  // window at least one datagram, so no more than `datagram_credit` of them
  // can be outstanding, plus one drop report and the owner's own commands.
  assert peak.messages
    <= datagram_credit() + drop_report_messages + owner_command_allowance
  // One message per connection per batch: a single message carries a whole
  // batch's admitted share, not one message for each routed datagram.
  assert peak.largest > 1
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn oversized_datagram_flood_is_bounded_by_the_byte_window_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  // A long operation deadline lets the statistics query drain the flooded
  // actor and consume its own reply, so a slow answer never outlives the call.
  let deadlines = config.default_deadlines()
  let limits = stalled_limits()
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let stalled = tuned_connect(port, ca_certificate, deadlines, limits)
  let stalled_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(stalled_peer, connection_label) |> should.be_ok

  // A legitimate flood exposes the routed connection ID and then ends inside
  // the stalled receive buffer, so the spoofed flood below is measured alone.
  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stream = client.open_bidirectional(stalled) |> should.be_ok
  let _flooder =
    spawn_flooder(stream, flooding, flooded, quiet_flood_chunks, True)
  let started = process.receive(flooding, within: settle_bound_milliseconds)
  let identifier =
    await_routed_identifier(
      actor,
      udp.monotonic_millisecond() + settle_bound_milliseconds,
    )
  let drained = process.receive(flooded, within: 3 * settle_bound_milliseconds)
  let quiet =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )

  // Every spoofed datagram is 8 KiB, so the datagram half of the window can
  // never bind first: 192 of them would be 1.5 MiB in one mailbox.
  let deadline = udp.monotonic_millisecond() + flood_window_milliseconds
  let junking = process.new_subject()
  let junked = process.new_subject()
  let _junker =
    spawn_windowed_junker(
      port,
      result.unwrap(identifier, <<0:64>>),
      oversized_junk_filler_bytes,
      deadline,
      junking,
      junked,
    )
  let junk_started = process.receive(junking, within: settle_bound_milliseconds)
  let peak = peak_backlog(actor, deadline, empty_backlog())

  // Bounded teardown before any bound is asserted.
  let junk_done = process.receive(junked, within: 3 * settle_bound_milliseconds)
  let settled =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )
  let dropped = dropped_count(stalled_peer)
  let _stalled_closed = client.close(stalled)
  let _stalled_peer_closed = server.close(stalled_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert drained == Ok(Nil)
  assert quiet == Ok(Nil)
  assert junk_started == Ok(Nil)
  assert junk_done == Ok(Nil)
  assert settled == Ok(Nil)
  assert result.is_ok(identifier)
  // The flood was observed while it was actually in the actor's mailbox.
  assert peak.deliveries > 0
  // The byte half is what holds this flood. The whole mailbox never carried
  // more than one window of bytes, which thirty-two oversized datagrams
  // already fill, so a single message was admitted far fewer datagrams than
  // the datagram half on its own would have let through: 192 of these would
  // have put 1.5 MiB in one mailbox.
  assert peak.bytes <= byte_credit()
  assert peak.largest < datagram_credit()
  assert peak.datagrams <= datagram_credit()
  assert result.map(dropped, fn(count) { count > 0 }) == Ok(True)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn overflow_datagrams_are_dropped_and_counted_per_connection_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  // A long operation deadline lets the statistics query drain the flooded
  // actor and consume its own reply, so a slow answer never outlives the call.
  let deadlines = config.default_deadlines()
  let limits = stalled_limits()
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let stalled = tuned_connect(port, ca_certificate, deadlines, limits)
  let stalled_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(stalled_peer, connection_label) |> should.be_ok
  // An unrelated connection on the same listener, which nobody floods.
  let healthy = tuned_connect(port, ca_certificate, deadlines, limits)
  let healthy_peer = server.accept(listener) |> should.be_ok

  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stream = client.open_bidirectional(stalled) |> should.be_ok
  let _flooder = spawn_flooder(stream, flooding, flooded, cid_chunks, False)
  let started = process.receive(flooding, within: settle_bound_milliseconds)
  let identifier =
    await_routed_identifier(
      actor,
      udp.monotonic_millisecond() + settle_bound_milliseconds,
    )

  // A bounded burst of spoofed datagrams overruns the connection's window.
  let junked = process.new_subject()
  let _junker =
    spawn_burst_junker(
      port,
      result.unwrap(identifier, <<0:64>>),
      overflow_burst,
      junked,
    )
  let junk_done = process.receive(junked, within: 3 * settle_bound_milliseconds)
  // Let the flooded actor drain so its statistics query answers promptly.
  let settled =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )

  // Overflow is dropped for the flooded connection only.
  let stalled_dropped = dropped_count(stalled_peer)
  let healthy_dropped = dropped_count(healthy_peer)

  let _stalled_closed = client.close(stalled)
  let drained = process.receive(flooded, within: 3 * settle_bound_milliseconds)
  let _healthy_closed = client.close(healthy)
  let _stalled_peer_closed = server.close(stalled_peer)
  let _healthy_peer_closed = server.close(healthy_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert junk_done == Ok(Nil)
  assert settled == Ok(Nil)
  assert drained == Ok(Nil)
  assert result.is_ok(identifier)
  assert result.map(stalled_dropped, fn(count) { count > 0 }) == Ok(True)
  assert healthy_dropped == Ok(0)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn flooded_connection_recovers_once_its_owner_reads_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  // A long operation deadline lets the statistics query drain the flooded
  // actor and consume its own reply, so a slow answer never outlives the call.
  let deadlines = config.default_deadlines()
  let limits = stalled_limits()
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let stalled = tuned_connect(port, ca_certificate, deadlines, limits)
  let stalled_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(stalled_peer, connection_label) |> should.be_ok

  // A legitimate flood its owner has not read yet, which also exposes the
  // routed connection ID a spoofing peer needs to shut the window. It ends
  // inside the stalled receive buffer, so nothing of it is still in flight
  // when the window shuts and the recovery below measures the window alone.
  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stream = client.open_bidirectional(stalled) |> should.be_ok
  let _flooder =
    spawn_flooder(stream, flooding, flooded, quiet_flood_chunks, True)
  let started = process.receive(flooding, within: settle_bound_milliseconds)
  let identifier =
    await_routed_identifier(
      actor,
      udp.monotonic_millisecond() + settle_bound_milliseconds,
    )
  let delivered =
    process.receive(flooded, within: 3 * settle_bound_milliseconds)
  let quiet =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )

  // A burst many windows wide shuts this connection's delivery window, so the
  // router must drop part of it and count the drops against this connection.
  let junked = process.new_subject()
  let _junker =
    spawn_burst_junker(
      port,
      result.unwrap(identifier, <<0:64>>),
      overflow_burst,
      junked,
    )
  let junk_done = process.receive(junked, within: 3 * settle_bound_milliseconds)
  let settled =
    await_drained(
      actor,
      udp.monotonic_millisecond() + drain_settle_bound_milliseconds,
    )
  let dropped = dropped_count(stalled_peer)

  // The owner then reads what the flood left buffered, and the connection
  // whose window those drops shut completes a bounded round trip: the window
  // reopened, and QUIC recovered whatever it dropped.
  let drained = drain_flooded_stream(stalled_peer)
  let round_trip_started = udp.monotonic_millisecond()
  let round_trip = round_trip(stalled, stalled_peer)
  let round_trip_milliseconds = udp.monotonic_millisecond() - round_trip_started

  let _stalled_closed = client.close(stalled)
  let _stalled_peer_closed = server.close(stalled_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert result.is_ok(identifier)
  assert delivered == Ok(Nil)
  assert quiet == Ok(Nil)
  assert junk_done == Ok(Nil)
  assert settled == Ok(Nil)
  // The window really did shut on this connection before the recovery.
  assert result.map(dropped, fn(count) { count > 0 }) == Ok(True)
  assert drained == Ok(Nil)
  assert round_trip == Ok(Nil)
  assert round_trip_milliseconds < recovery_round_trip_bound_milliseconds
  assert stopped == Ok(server.Stopped)
}

fn stalled_limits() -> config.Limits {
  config.with_limit(config.default_limits(), failure.Buffer, stall_buffer_bytes)
  |> should.be_ok
}

/// Limits for a connection whose owner keeps reading: a receive buffer small
/// enough that flow control paces the peer to what the owner consumes.
fn healthy_limits() -> config.Limits {
  config.with_limit(
    config.default_limits(),
    failure.Buffer,
    healthy_buffer_bytes,
  )
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
  |> server.with_address_family(gleam_quic.Ipv4)
  |> server.with_deadlines(deadlines)
  |> server.with_limits(limits)
  |> server.start
  |> should.be_ok
}

fn tuned_connect(
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> client.Connection {
  client.new("localhost", port, "sample")
  |> should.be_ok
  |> client.with_address_family(gleam_quic.Ipv4)
  |> client.with_ca_certificates(ca_certificate)
  |> should.be_ok
  |> client.with_deadlines(deadlines)
  |> client.with_limits(limits)
  |> client.connect
  |> should.be_ok
}

fn spawn_flooder(
  stream: client.Stream,
  flooding: process.Subject(Nil),
  flooded: process.Subject(Nil),
  chunks: Int,
  finish: Bool,
) -> Pid {
  process.spawn_unlinked(fn() {
    let chunk = repeated_bytes(cid_chunk_bytes)
    case client.send(stream, chunk) {
      // nolint: thrown_away_error -- a stalled peer stops on any send error.
      Error(_reason) -> Nil
      Ok(Nil) -> {
        process.send(flooding, Nil)
        flood(stream, chunk, chunks - 1)
        finish_flood(stream, finish)
      }
    }
    process.send(flooded, Nil)
  })
}

/// End the flooding stream when the caller asked for one that finishes, so a
/// recovery flood the server drains reaches a real end of stream.
fn finish_flood(stream: client.Stream, finish: Bool) -> Nil {
  case finish {
    False -> Nil
    True -> {
      let _finished = client.finish(stream)
      Nil
    }
  }
}

fn flood(stream: client.Stream, chunk: BitArray, remaining: Int) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False ->
      case client.send(stream, chunk) {
        // nolint: thrown_away_error -- a stalled peer stops on any send error.
        Error(_reason) -> Nil
        Ok(Nil) -> flood(stream, chunk, remaining - 1)
      }
  }
}

/// Flood the listener's port from a socket the child process owns for a fixed
/// window, so every stray ICMP or reply lands in that child's mailbox and dies
/// with it rather than polluting the shared test process.
fn spawn_windowed_junker(
  port: Int,
  identifier: BitArray,
  filler_bytes: Int,
  deadline: Int,
  junking: process.Subject(Nil),
  junked: process.Subject(Nil),
) -> Pid {
  spawn_junker(
    port,
    identifier,
    filler_bytes,
    Some(junking),
    junked,
    fn(socket, target, payload) {
      junk_window(socket, target, payload, deadline)
    },
  )
}

/// Send one bounded burst of spoofed datagrams, then stop.
fn spawn_burst_junker(
  port: Int,
  identifier: BitArray,
  count: Int,
  junked: process.Subject(Nil),
) -> Pid {
  spawn_junker(
    port,
    identifier,
    junk_filler_bytes,
    None,
    junked,
    fn(socket, target, payload) { junk_burst(socket, target, payload, count) },
  )
}

fn spawn_junker(
  port: Int,
  identifier: BitArray,
  filler_bytes: Int,
  junking: Option(process.Subject(Nil)),
  junked: process.Subject(Nil),
  send: fn(udp.Socket, udp.Endpoint, BitArray) -> Nil,
) -> Pid {
  process.spawn_unlinked(fn() {
    let wildcard = udp.ipv4(0, 0, 0, 0) |> should.be_ok
    let local = udp.endpoint(wildcard, 0) |> should.be_ok
    let socket = udp.open(local) |> should.be_ok
    let loopback = udp.ipv4(127, 0, 0, 1) |> should.be_ok
    let target = udp.endpoint(loopback, port) |> should.be_ok
    let payload = spoofed_datagram(identifier, filler_bytes)
    case junking {
      Some(subject) -> process.send(subject, Nil)
      None -> Nil
    }
    send(socket, target, payload)
    let _closed = udp.close(socket)
    process.send(junked, Nil)
  })
}

fn spoofed_datagram(identifier: BitArray, filler_bytes: Int) -> BitArray {
  <<junk_first_byte, identifier:bits, repeated_bytes(filler_bytes):bits>>
}

fn junk_window(
  socket: udp.Socket,
  target: udp.Endpoint,
  payload: BitArray,
  deadline: Int,
) -> Nil {
  case udp.monotonic_millisecond() >= deadline {
    True -> Nil
    False ->
      case udp.send(socket, target, payload, ecn.NotEct) {
        // nolint: thrown_away_error -- a junk flood stops on any send error.
        Error(_reason) -> Nil
        Ok(Nil) -> junk_window(socket, target, payload, deadline)
      }
  }
}

fn junk_burst(
  socket: udp.Socket,
  target: udp.Endpoint,
  payload: BitArray,
  remaining: Int,
) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False ->
      case udp.send(socket, target, payload, ecn.NotEct) {
        // nolint: thrown_away_error -- a junk burst stops on any send error.
        Error(_reason) -> Nil
        Ok(Nil) -> junk_burst(socket, target, payload, remaining - 1)
      }
  }
}

/// Trace one actor's routed datagrams from a process of its own until the
/// connection ID the listener routes to it is known, so a healthy connection
/// exposes that identifier without its owner ever having to stall. The trace
/// dies with the watcher, and the watcher gives up at its own bound.
fn spawn_identifier_watcher(
  actor: Pid,
  bound: Int,
  found: process.Subject(Result(BitArray, Nil)),
) -> Pid {
  process.spawn_unlinked(fn() {
    process.send(found, traced_routed_connection_id(actor, bound))
  })
}

/// Poll one actor's mailbox until it reveals the connection ID the listener
/// routes to it, or the bound elapses.
fn await_routed_identifier(actor: Pid, deadline: Int) -> Result(BitArray, Nil) {
  case routed_connection_id(actor) {
    Ok(identifier) -> Ok(identifier)
    Error(Nil) ->
      case udp.monotonic_millisecond() >= deadline {
        True -> Error(Nil)
        False -> {
          process.sleep(1)
          await_routed_identifier(actor, deadline)
        }
      }
  }
}

/// The worst backlog seen in one connection actor's mailbox: the most
/// messages, the most routed datagrams and bytes waiting across all of them,
/// the most datagrams any single message carried, and how many messages
/// carrying routed datagrams were seen at all.
type Backlog {
  Backlog(
    messages: Int,
    datagrams: Int,
    bytes: Int,
    largest: Int,
    deliveries: Int,
  )
}

fn empty_backlog() -> Backlog {
  Backlog(0, 0, 0, 0, 0)
}

/// The worst backlog observed at any poll before the deadline.
fn peak_backlog(actor: Pid, deadline: Int, peak: Backlog) -> Backlog {
  let peak = case mailbox_deliveries(actor) {
    Error(Nil) -> peak
    Ok(#(messages, sizes)) -> merge_backlog(peak, messages, sizes)
  }
  case udp.monotonic_millisecond() >= deadline {
    True -> peak
    False -> {
      process.sleep(mailbox_poll_milliseconds)
      peak_backlog(actor, deadline, peak)
    }
  }
}

fn merge_backlog(
  peak: Backlog,
  messages: Int,
  sizes: List(#(Int, Int)),
) -> Backlog {
  let sample = sample_backlog(sizes, Backlog(messages, 0, 0, 0, 0))
  Backlog(
    messages: int.max(peak.messages, sample.messages),
    datagrams: int.max(peak.datagrams, sample.datagrams),
    bytes: int.max(peak.bytes, sample.bytes),
    largest: int.max(peak.largest, sample.largest),
    deliveries: int.max(peak.deliveries, sample.deliveries),
  )
}

fn sample_backlog(sizes: List(#(Int, Int)), sample: Backlog) -> Backlog {
  case sizes {
    [] -> sample
    [#(datagrams, bytes), ..rest] ->
      sample_backlog(
        rest,
        Backlog(
          ..sample,
          datagrams: sample.datagrams + datagrams,
          bytes: sample.bytes + bytes,
          largest: int.max(sample.largest, datagrams),
          deliveries: sample.deliveries + 1,
        ),
      )
  }
}

/// Wait until the flooded actor has drained its backlog, so a statistics query
/// is serviced at once and its reply never outlives the call.
fn await_drained(actor: Pid, deadline: Int) -> Result(Nil, Nil) {
  case mailbox_length(actor) {
    Ok(count) if count <= drained_mailbox -> Ok(Nil)
    _other ->
      case udp.monotonic_millisecond() >= deadline {
        True -> Error(Nil)
        False -> {
          process.sleep(20)
          await_drained(actor, deadline)
        }
      }
  }
}

/// The per-connection dropped-datagram counter the router publishes through
/// the connection diagnostics path.
fn dropped_count(peer: server.Connection) -> Result(Int, Nil) {
  case server.dropped_datagrams(peer) {
    Error(_reason) -> Error(Nil)
    Ok(count) -> Ok(count)
  }
}

/// Read one whole incoming stream inside a fixed bound, reporting how many
/// bytes arrived, so a caller can check a healthy transfer for completeness as
/// well as simply drain a flood.
fn read_incoming_stream(
  peer: server.Connection,
  deadline: Int,
) -> Result(Int, Step) {
  case server.accept_stream(peer) {
    Error(_reason) -> Error(ServerAcceptStream)
    Ok(server.IncomingStream(stream, _kind)) -> read_stream(stream, deadline, 0)
  }
}

fn read_stream(
  stream: server.Stream,
  deadline: Int,
  seen: Int,
) -> Result(Int, Step) {
  case udp.monotonic_millisecond() >= deadline {
    True -> Error(DrainTimeout)
    False ->
      case server.receive(stream, drain_chunk_bytes) {
        Ok(server.Data(bytes, True)) -> Ok(seen + bit_array.byte_size(bytes))
        Ok(server.Finished) -> Ok(seen)
        Ok(server.Data(bytes, False)) ->
          read_stream(stream, deadline, seen + bit_array.byte_size(bytes))
        Ok(server.Reset(_code)) -> Error(DrainReset)
        Error(_reason) -> Error(DrainFailed)
      }
  }
}

/// Drain the flood a recovering connection still owes, discarding the byte
/// count that only the healthy-burst test has a use for.
fn drain_flooded_stream(peer: server.Connection) -> Result(Nil, Step) {
  read_incoming_stream(
    peer,
    udp.monotonic_millisecond() + recovery_drain_bound_milliseconds,
  )
  |> result.replace(Nil)
}

/// One bounded request/response exchange, naming the step that failed.
fn round_trip(
  connection: client.Connection,
  peer: server.Connection,
) -> Result(Nil, Step) {
  case client.open_bidirectional(connection) {
    Error(_reason) -> Error(ClientOpen)
    Ok(stream) -> round_trip_request(stream, peer)
  }
}

fn round_trip_request(
  stream: client.Stream,
  peer: server.Connection,
) -> Result(Nil, Step) {
  case client.send_and_finish(stream, <<"ping":utf8>>) {
    Error(_reason) -> Error(ClientRequest)
    Ok(Nil) -> round_trip_accept(stream, peer)
  }
}

fn round_trip_accept(
  stream: client.Stream,
  peer: server.Connection,
) -> Result(Nil, Step) {
  case server.accept_stream(peer) {
    Error(_reason) -> Error(ServerAcceptStream)
    Ok(server.IncomingStream(peer_stream, _kind)) ->
      round_trip_read(stream, peer_stream)
  }
}

fn round_trip_read(
  stream: client.Stream,
  peer_stream: server.Stream,
) -> Result(Nil, Step) {
  case server.receive(peer_stream, 1024) {
    Ok(server.Data(<<"ping":utf8>>, True)) ->
      round_trip_reply(stream, peer_stream)
    _other -> Error(ServerRead)
  }
}

fn round_trip_reply(
  stream: client.Stream,
  peer_stream: server.Stream,
) -> Result(Nil, Step) {
  case server.send_and_finish(peer_stream, <<"pong":utf8>>) {
    Error(_reason) -> Error(ServerReply)
    Ok(Nil) -> round_trip_response(stream)
  }
}

fn round_trip_response(stream: client.Stream) -> Result(Nil, Step) {
  case client.receive(stream, 1024) {
    Ok(client.Data(<<"pong":utf8>>, True)) -> Ok(Nil)
    _other -> Error(ClientResponse)
  }
}

fn repeated_bytes(size: Int) -> BitArray {
  grow_bytes(<<0>>, size)
}

fn grow_bytes(seed: BitArray, size: Int) -> BitArray {
  case bit_array.byte_size(seed) >= size {
    True -> bit_array.slice(seed, 0, size) |> result.unwrap(seed)
    False -> grow_bytes(bit_array.append(seed, seed), size)
  }
}
