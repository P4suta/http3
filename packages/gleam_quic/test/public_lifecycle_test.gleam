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
import gleam_quic
import gleam_quic/client
import gleam_quic/config
import gleam_quic/failure
import gleam_quic/internal/udp
import gleam_quic/server
import gleeunit/should

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

/// The process behind one opaque public handle, found by its fixed role label.
@external(erlang, "gleam_quic_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

/// The fixed diagnostic label every per-connection actor carries.
const connection_label = "gleam_quic.connection"

/// The fixed diagnostic label every client connection actor carries.
const client_label = "gleam_quic.client"

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
  |> server.with_address_family(gleam_quic.Ipv4)
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
  |> client.with_address_family(gleam_quic.Ipv4)
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
