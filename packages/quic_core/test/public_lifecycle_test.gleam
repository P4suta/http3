//// Connection-actor lifecycle over real UDP.
////
//// A connection actor owns connection IDs, an admission slot, a qlog writer,
//// and the waiters its owner is parked in. Its life ends with its transport:
//// once the phase reaches `Closed` -- after a local close has drained, or
//// after the idle timeout expired because the peer vanished -- the actor has
//// to fail every remaining waiter with the typed closed error, hand its
//// identifiers and its admission slot back to the listener, and exit, while
//// the listener itself stays up and serving.
////
//// The typed error is what separates an orderly release from a connection
//// that merely fell over: a connection whose transport ended is a closed
//// connection, so its waiters see `failure.Closed`, never `failure.Quic`.

import gleam/erlang/process.{type Pid, type Subject}
import gleam/option.{None}
import gleam/result
import gleeunit/should
import quic_core
import quic_core/client
import quic_core/config
import quic_core/failure
import quic_core/internal/udp
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

/// The process behind one opaque public handle, found by its fixed role label.
@external(erlang, "quic_core_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

/// The fixed diagnostic label every per-connection actor carries.
const connection_label = "quic_core.connection"

/// The fixed diagnostic label every client connection actor carries.
const client_label = "quic_core.client"

/// A local close drains for the fixed 3000 ms draining timeout before the
/// transport reaches `Closed`, so every bound spanning one has to clear it.
const close_bound_milliseconds = 6000

/// The bound an idle-timed-out connection actor must exit within.
const idle_bound_milliseconds = 4000

/// A deliberately short server idle timeout, so a vanished peer is noticed
/// well inside `idle_bound_milliseconds`.
const idle_timeout_milliseconds = 500

const operation_bound_milliseconds = 2000

/// The parked read's own deadline, which must outlast both the idle timeout
/// and the draining timeout, so the connection ending -- not the read
/// expiring -- is what fails the waiter.
const waiter_bound_milliseconds = 8000

const poll_interval_milliseconds = 20

const read_bytes = 1024

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn accept_next_is_released_when_listener_stops_test() -> Nil {
  let listener =
    start_listener(
      bounded_deadlines(operation_bound_milliseconds),
      config.default_limits(),
    )
  let ready = process.new_subject()
  let outcome = process.new_subject()
  let waiter =
    process.spawn_unlinked(fn() {
      // Tell the owner before entering the unbounded public wait. The short
      // settle below gives the listener one scheduling turn to enqueue it;
      // either ordering is safe, but the normal path exercises shutdown's
      // waiter release instead of only call_forever's process monitor.
      process.send(ready, Nil)
      process.send(outcome, server.accept_next(listener))
    })

  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  process.sleep(poll_interval_milliseconds)
  assert process.is_alive(waiter)

  assert server.stop(listener) == Ok(server.Stopped)
  assert process.receive(outcome, within: operation_bound_milliseconds)
    == Ok(Error(server.Failure(failure.Closed(failure.Local, None))))
  assert settled_exit(waiter, operation_bound_milliseconds)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn supervised_server_waits_are_released_when_listener_stops_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines(waiter_bound_milliseconds)
  let listener = start_listener(deadlines, config.default_limits())
  let port = server.port(listener) |> should.be_ok
  let connection = connect(port, ca_certificate, deadlines) |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let #(_stream, peer_stream) = opened_stream(connection, peer)

  let ready = process.new_subject()
  let accepted = process.new_subject()
  let accept_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(accepted, server.accept_stream_next(peer))
    })
  let received = process.new_subject()
  let read_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(received, server.receive_next(peer_stream, read_bytes))
    })
  let datagram = process.new_subject()
  let datagram_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(datagram, server.receive_datagram_next(peer))
    })

  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  process.sleep(poll_interval_milliseconds)
  assert process.is_alive(accept_waiter)
  assert process.is_alive(read_waiter)
  assert process.is_alive(datagram_waiter)

  assert server.stop(listener) == Ok(server.Stopped)
  assert process.receive(accepted, within: operation_bound_milliseconds)
    == Ok(Error(server.Failure(failure.Closed(failure.Peer, None))))
  assert process.receive(received, within: operation_bound_milliseconds)
    == Ok(Error(server.Failure(failure.Closed(failure.Peer, None))))
  assert process.receive(datagram, within: operation_bound_milliseconds)
    == Ok(Error(server.Failure(failure.Closed(failure.Peer, None))))
  assert settled_exit(accept_waiter, operation_bound_milliseconds)
  assert settled_exit(read_waiter, operation_bound_milliseconds)
  assert settled_exit(datagram_waiter, operation_bound_milliseconds)
  let _closed = client.close(connection)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn supervised_client_waits_are_released_when_connection_closes_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = bounded_deadlines(waiter_bound_milliseconds)
  let listener = start_listener(deadlines, config.default_limits())
  let port = server.port(listener) |> should.be_ok
  let connection = connect(port, ca_certificate, deadlines) |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let peer_stream = server.open_bidirectional(peer) |> should.be_ok
  server.send(peer_stream, <<"ping":utf8>>) |> should.be_ok
  let assert client.IncomingStream(stream, client.Bidirectional) =
    client.accept_stream(connection) |> should.be_ok
  assert client.receive(stream, read_bytes)
    == Ok(client.Data(<<"ping":utf8>>, False))

  let ready = process.new_subject()
  let accepted = process.new_subject()
  let accept_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(accepted, client.accept_stream_next(connection))
    })
  let received = process.new_subject()
  let read_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(received, client.receive_next(stream, read_bytes))
    })
  let datagram = process.new_subject()
  let datagram_waiter =
    process.spawn_unlinked(fn() {
      process.send(ready, Nil)
      process.send(datagram, client.receive_datagram_next(connection))
    })

  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  assert process.receive(ready, within: operation_bound_milliseconds) == Ok(Nil)
  process.sleep(poll_interval_milliseconds)
  assert process.is_alive(accept_waiter)
  assert process.is_alive(read_waiter)
  assert process.is_alive(datagram_waiter)

  assert client.close(connection) == Ok(client.Closed)
  assert process.receive(accepted, within: operation_bound_milliseconds)
    == Ok(Error(client.Failure(failure.Closed(failure.Peer, None))))
  assert process.receive(received, within: operation_bound_milliseconds)
    == Ok(Error(client.Failure(failure.Closed(failure.Peer, None))))
  assert process.receive(datagram, within: operation_bound_milliseconds)
    == Ok(Error(client.Failure(failure.Closed(failure.Peer, None))))
  assert settled_exit(accept_waiter, operation_bound_milliseconds)
  assert settled_exit(read_waiter, operation_bound_milliseconds)
  assert settled_exit(datagram_waiter, operation_bound_milliseconds)
  let _peer_closed = server.close(peer)
  assert server.stop(listener) == Ok(server.Stopped)
}

// A successful local close acknowledges the API call, not destruction of the
// QUIC closing state. The actor must retain its socket after its owner exits so
// it can acknowledge or answer a peer retransmission during the fixed closing
// period. Otherwise loss of the first CONNECTION_CLOSE can leave the peer
// waiting for already-consumed response bytes until its much longer
// application drain deadline.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn locally_closed_client_outlives_its_owner_until_transport_close_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = draining_deadlines()
  let listener = start_listener(deadlines, config.default_limits())
  let port = server.port(listener) |> should.be_ok
  let ready = process.new_subject()
  let closed = process.new_subject()

  let _owner =
    process.spawn_unlinked(fn() {
      let connection = connect(port, ca_certificate, deadlines) |> should.be_ok
      let actor = labelled_pid(connection, client_label) |> should.be_ok
      let close_now = process.new_subject()
      process.send(ready, #(connection, actor, close_now))
      let assert Ok(Nil) =
        process.receive(close_now, within: operation_bound_milliseconds)
      process.send(closed, client.close(connection))
    })

  let assert Ok(#(connection, actor, close_now)) =
    process.receive(ready, within: waiter_bound_milliseconds)
  let peer = server.accept(listener) |> should.be_ok
  process.send(close_now, Nil)
  assert process.receive(closed, within: waiter_bound_milliseconds)
    == Ok(Ok(client.Closed))

  // Give the owner time to exit.  The connection actor is nevertheless a
  // finite closing tombstone with live wire input, not an owner-bound leak.
  process.sleep(100)
  let retained_during_close = process.is_alive(actor)
  let duplicate_close = client.close(connection)
  let exited = settled_exit(actor, close_bound_milliseconds)

  let _peer_closed = server.close(peer)
  let stopped = server.stop(listener)

  assert retained_during_close == True
  assert duplicate_close == Ok(client.AlreadyClosed)
  assert exited == True
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn released_connection_fails_its_waiters_as_closed_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = idle_deadlines()
  let listener = start_listener(deadlines, config.default_limits())
  let port = server.port(listener) |> should.be_ok

  let connection = connect(port, ca_certificate, deadlines) |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(peer, connection_label) |> should.be_ok
  let #(_stream, peer_stream) = opened_stream(connection, peer)

  // The peer vanishes while this owner is parked in a read, so the connection
  // ends on the idle timeout with a waiter still on it.
  vanish(connection)
  let blocked = server.receive(peer_stream, read_bytes)
  let exited = settled_exit(actor, idle_bound_milliseconds)

  let live_port = server.port(listener)
  let stopped = server.stop(listener)

  // A connection that ended is a closed connection, not a protocol failure.
  assert blocked == Error(server.Failure(failure.Closed(failure.Peer, None)))
  assert exited == True
  assert live_port == Ok(port)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn closed_connection_releases_its_actor_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = draining_deadlines()
  let listener = start_listener(deadlines, config.default_limits())
  let port = server.port(listener) |> should.be_ok

  let connection = connect(port, ca_certificate, deadlines) |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(peer, connection_label) |> should.be_ok
  let #(_stream, peer_stream) = opened_stream(connection, peer)

  // A second process parks in a read, so the owner is free to close the
  // connection underneath it and the draining timeout is what ends it.
  let parked = park_reader(peer_stream)
  let peer_closed = server.close(peer)
  let blocked = process.receive(parked, within: waiter_bound_milliseconds)
  let exited = settled_exit(actor, close_bound_milliseconds)

  let _closed = client.close(connection)
  let live_port = server.port(listener)
  let stopped = server.stop(listener)

  assert peer_closed == Ok(server.Closed)
  assert blocked
    == Ok(Error(server.Failure(failure.Closed(failure.Peer, None))))
  assert exited == True
  assert live_port == Ok(port)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn released_connection_frees_its_admission_slot_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = idle_deadlines()
  let limits =
    config.with_limit(config.default_limits(), failure.Connections, 1)
    |> should.be_ok
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let first = connect(port, ca_certificate, deadlines) |> should.be_ok
  let first_peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(first_peer, connection_label) |> should.be_ok
  let #(_stream, first_stream) = opened_stream(first, first_peer)

  vanish(first)
  let blocked = server.receive(first_stream, read_bytes)
  let exited = settled_exit(actor, idle_bound_milliseconds)

  // The single admission slot the released connection held must be reusable.
  let second = connect(port, ca_certificate, deadlines)
  let second_peer = server.accept(listener)

  close_client(second)
  close_peer(second_peer)
  let stopped = server.stop(listener)

  // The slot came back through an orderly release, not a failed connection.
  assert blocked == Error(server.Failure(failure.Closed(failure.Peer, None)))
  assert exited == True
  assert result.is_ok(second)
  assert result.is_ok(second_peer)
  assert stopped == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn releasing_one_connection_keeps_its_neighbour_routed_test() -> Nil {
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = idle_deadlines()
  let limits =
    config.with_limit(config.default_limits(), failure.Connections, 2)
    |> should.be_ok
  let listener = start_listener(deadlines, limits)
  let port = server.port(listener) |> should.be_ok

  let first = connect(port, ca_certificate, deadlines) |> should.be_ok
  let first_peer = server.accept(listener) |> should.be_ok
  let first_actor = labelled_pid(first_peer, connection_label) |> should.be_ok
  let second = connect(port, ca_certificate, deadlines) |> should.be_ok
  let second_peer = server.accept(listener) |> should.be_ok

  // Releasing one connection must free exactly its own identifiers and its
  // own admission slot: the neighbour keeps routing, and exactly one slot
  // comes back. The listener deliberately gives every connection the same
  // short idle timeout, so exercise the neighbour while waiting instead of
  // letting that unrelated timeout decide the test on a slower scheduler.
  vanish(first)
  let exited =
    settled_exit_while(first_actor, idle_bound_milliseconds, fn() {
      client.ping(second)
    })
  let #(neighbour, neighbour_stream) = opened_stream(second, second_peer)
  client.send(neighbour, <<"pong":utf8>>) |> should.be_ok
  let neighbour_read = server.receive(neighbour_stream, read_bytes)
  let third = connect(port, ca_certificate, deadlines)
  let third_peer = server.accept(listener)

  let _second_closed = client.close(second)
  close_client(third)
  close_peer(third_peer)
  let stopped = server.stop(listener)

  assert exited == True
  assert neighbour_read == Ok(server.Data(<<"pong":utf8>>, False))
  assert result.is_ok(third)
  assert result.is_ok(third_peer)
  assert stopped == Ok(server.Stopped)
}

fn bounded_deadlines(operation: Int) -> config.Deadlines {
  config.default_deadlines()
  |> config.with_deadline(failure.Connect, operation_bound_milliseconds)
  |> should.be_ok
  |> config.with_deadline(failure.Handshake, operation_bound_milliseconds)
  |> should.be_ok
  |> config.with_deadline(failure.Operation, operation)
  |> should.be_ok
}

/// Deadlines whose idle timeout expires well inside the exit bound, and whose
/// operations outlast that idle timeout.
fn idle_deadlines() -> config.Deadlines {
  bounded_deadlines(waiter_bound_milliseconds)
  |> config.with_deadline(failure.Idle, idle_timeout_milliseconds)
  |> should.be_ok
}

/// Deadlines whose operations outlast the fixed draining timeout, so a read
/// parked across a local close is ended by the close, not by its own bound.
fn draining_deadlines() -> config.Deadlines {
  bounded_deadlines(waiter_bound_milliseconds)
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
) -> Result(client.Connection, client.Error) {
  client.new("localhost", port, "sample")
  |> should.be_ok
  |> client.with_address_family(quic_core.Ipv4)
  |> client.with_ca_certificates(ca_certificate)
  |> should.be_ok
  |> client.with_deadlines(deadlines)
  |> client.connect
}

/// Open one client stream, carry a byte across it, and drain that byte, so a
/// later read on the returned server-side stream parks on real accepted
/// stream state instead of returning what is already buffered.
fn opened_stream(
  connection: client.Connection,
  peer: server.Connection,
) -> #(client.Stream, server.Stream) {
  let stream = client.open_bidirectional(connection) |> should.be_ok
  client.send(stream, <<"ping":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  let assert Ok(server.Data(<<"ping":utf8>>, False)) =
    server.receive(peer_stream, read_bytes)
  #(stream, peer_stream)
}

/// Park a second process in a stream read and report whatever ends it, so the
/// test process stays free to close the connection underneath that waiter.
fn park_reader(
  stream: server.Stream,
) -> Subject(Result(server.Read, server.Error)) {
  let outcome = process.new_subject()
  let _reader =
    process.spawn_unlinked(fn() {
      process.send(outcome, server.receive(stream, read_bytes))
    })
  outcome
}

/// Make one peer disappear without a close, exactly like a lost host: its
/// actor is killed, so no CONNECTION_CLOSE ever reaches the server.
fn vanish(connection: client.Connection) -> Nil {
  process.kill(labelled_pid(connection, client_label) |> should.be_ok)
}

fn close_client(connection: Result(client.Connection, client.Error)) -> Nil {
  case connection {
    Ok(value) -> {
      let _closed = client.close(value)
      Nil
    }
    // nolint: thrown_away_error -- teardown closes whatever was connected.
    Error(_reason) -> Nil
  }
}

fn close_peer(peer: Result(server.Connection, server.Error)) -> Nil {
  case peer {
    Ok(value) -> {
      let _closed = server.close(value)
      Nil
    }
    // nolint: thrown_away_error -- teardown closes whatever was accepted.
    Error(_reason) -> Nil
  }
}

/// Whether one actor has exited within a fixed bound.
fn settled_exit(actor: Pid, bound_milliseconds: Int) -> Bool {
  poll_exit(actor, udp.monotonic_millisecond() + bound_milliseconds)
}

/// Whether one actor exits while a live neighbour performs bounded work.
fn settled_exit_while(
  actor: Pid,
  bound_milliseconds: Int,
  keep_alive: fn() -> Result(Nil, client.Error),
) -> Bool {
  poll_exit_while(
    actor,
    udp.monotonic_millisecond() + bound_milliseconds,
    keep_alive,
  )
}

fn poll_exit_while(
  actor: Pid,
  deadline: Int,
  keep_alive: fn() -> Result(Nil, client.Error),
) -> Bool {
  case process.is_alive(actor) {
    False -> True
    True ->
      case udp.monotonic_millisecond() >= deadline {
        True -> False
        False -> {
          let _kept_alive = keep_alive()
          process.sleep(poll_interval_milliseconds)
          poll_exit_while(actor, deadline, keep_alive)
        }
      }
  }
}

fn poll_exit(actor: Pid, deadline: Int) -> Bool {
  case process.is_alive(actor) {
    False -> True
    True ->
      case udp.monotonic_millisecond() >= deadline {
        True -> False
        False -> {
          process.sleep(poll_interval_milliseconds)
          poll_exit(actor, deadline)
        }
      }
  }
}
