//// Per-connection actor topology and cross-connection isolation over real UDP.
////
//// PRE-003 requires one supervised actor per accepted connection so that a
//// stalled connection cannot delay unrelated connections on the same listener.

import gleam/bit_array
import gleam/erlang/process
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

@external(erlang, "gleam_quic_test_ffi", "processes_labelled")
fn processes_labelled(label: String) -> Int

/// The fixed diagnostic label every per-connection actor must carry.
const connection_label = "gleam_quic.connection"

/// Every wait in this module is bounded; exceeding a bound is a failure.
const settle_bound_milliseconds = 2000

/// The bound an unrelated connection must meet while a stalled peer floods.
const isolation_bound_milliseconds = 500

const operation_bound_milliseconds = 2000

/// A's server-side receive buffer, which its owner never drains.
const stall_buffer_bytes = 4_194_304

const flood_chunk_bytes = 16_384

const flood_chunks = 512

/// The step of the isolation exchange that failed, if any did.
type Step {
  ClientOpen
  ClientRequest
  ServerAcceptStream
  ServerRead
  ServerReply
  ClientResponse
  JoinerConnect
  JoinerSilent
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn listener_owns_one_labelled_actor_per_accepted_connection_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok

  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  let first = connect(port, ca_certificate)
  let first_peer = server.accept(listener) |> should.be_ok
  let second = connect(port, ca_certificate)
  let second_peer = server.accept(listener) |> should.be_ok
  let third = connect(port, ca_certificate)
  let third_peer = server.accept(listener) |> should.be_ok

  // One supervised actor per accepted connection, and nothing else.
  let accepted = settled_label_count(3, settle_bound_milliseconds)

  let _first_closed = client.close(first)
  let _second_closed = client.close(second)
  let _third_closed = client.close(third)
  let _first_peer_closed = server.close(first_peer)
  let _second_peer_closed = server.close(second_peer)
  let _third_peer_closed = server.close(third_peer)
  let stopped = server.stop(listener)

  // Stopping the listener terminates every connection actor it owned.
  let drained = settled_label_count(0, settle_bound_milliseconds)

  assert accepted == 3
  assert stopped == Ok(server.Stopped)
  assert drained == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn stalled_connection_does_not_delay_unrelated_connections_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines =
    config.uniform_deadlines(operation_bound_milliseconds) |> should.be_ok
  let limits =
    config.with_limit(
      config.default_limits(),
      failure.Buffer,
      stall_buffer_bytes,
    )
    |> should.be_ok

  let listener =
    server.new(certificate, private_key, "sample")
    |> should.be_ok
    |> server.with_address_family(gleam_quic.Ipv4)
    |> server.with_deadlines(deadlines)
    |> server.with_limits(limits)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  // Connection A: its owner never reads a single byte.
  let stalled = tuned_connect(port, ca_certificate, deadlines, limits)
  let stalled_peer = server.accept(listener) |> should.be_ok
  // Connection B: an unrelated healthy connection on the same listener.
  let healthy = tuned_connect(port, ca_certificate, deadlines, limits)
  let healthy_peer = server.accept(listener) |> should.be_ok

  let flooding = process.new_subject()
  let flooded = process.new_subject()
  let stalled_stream = client.open_bidirectional(stalled) |> should.be_ok
  let _flooder =
    process.spawn_unlinked(fn() {
      let chunk = repeated_bytes(flood_chunk_bytes)
      case client.send(stalled_stream, chunk) {
        // nolint: thrown_away_error -- a stalled peer stops on any send error.
        Error(_reason) -> Nil
        Ok(Nil) -> {
          process.send(flooding, Nil)
          flood(stalled_stream, chunk, flood_chunks - 1)
        }
      }
      process.send(flooded, Nil)
    })
  let started = process.receive(flooding, within: settle_bound_milliseconds)

  // B completes a bounded request/response round trip while A is stalled.
  let round_trip_started = udp.monotonic_millisecond()
  let round_trip = healthy_round_trip(healthy, healthy_peer)
  let round_trip_milliseconds = udp.monotonic_millisecond() - round_trip_started

  // The listener still serves a fresh accept waiter within the same bound.
  let joining = process.new_subject()
  let accept_started = udp.monotonic_millisecond()
  let _joiner =
    process.spawn_unlinked(fn() {
      process.send(
        joining,
        tuned_connect_result(port, ca_certificate, deadlines, limits),
      )
    })
  let joined_peer = server.accept(listener)
  let accept_milliseconds = udp.monotonic_millisecond() - accept_started
  let joined = process.receive(joining, within: settle_bound_milliseconds)

  // Bounded teardown before any bound is asserted.
  let _stalled_closed = client.close(stalled)
  let drained =
    process.receive(flooded, within: 3 * operation_bound_milliseconds)
  let _healthy_closed = client.close(healthy)
  let _joined_closed = close_joined(joined)
  let _stalled_peer_closed = server.close(stalled_peer)
  let _healthy_peer_closed = server.close(healthy_peer)
  let _joined_peer_closed = close_peer(joined_peer)
  let stopped = server.stop(listener)

  assert started == Ok(Nil)
  assert drained == Ok(Nil)
  assert round_trip == Ok(Nil)
  assert round_trip_milliseconds < isolation_bound_milliseconds
  assert joined_connect_outcome(joined) == Ok(Nil)
  assert result.is_ok(joined_peer)
  assert accept_milliseconds < isolation_bound_milliseconds
  assert stopped == Ok(server.Stopped)
}

fn connect(port: Int, ca_certificate: BitArray) -> client.Connection {
  client.new("localhost", port, "sample")
  |> should.be_ok
  |> client.with_address_family(gleam_quic.Ipv4)
  |> client.with_ca_certificates(ca_certificate)
  |> should.be_ok
  |> client.connect
  |> should.be_ok
}

fn tuned_connect(
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> client.Connection {
  tuned_connect_result(port, ca_certificate, deadlines, limits)
  |> should.be_ok
}

fn tuned_connect_result(
  port: Int,
  ca_certificate: BitArray,
  deadlines: config.Deadlines,
  limits: config.Limits,
) -> Result(client.Connection, client.Error) {
  client.new("localhost", port, "sample")
  |> should.be_ok
  |> client.with_address_family(gleam_quic.Ipv4)
  |> client.with_ca_certificates(ca_certificate)
  |> should.be_ok
  |> client.with_deadlines(deadlines)
  |> client.with_limits(limits)
  |> client.connect
}

fn joined_connect_outcome(
  joined: Result(Result(client.Connection, client.Error), Nil),
) -> Result(Nil, Step) {
  case joined {
    Ok(Ok(_connection)) -> Ok(Nil)
    Ok(Error(_reason)) -> Error(JoinerConnect)
    Error(Nil) -> Error(JoinerSilent)
  }
}

fn close_joined(
  joined: Result(Result(client.Connection, client.Error), Nil),
) -> Nil {
  case joined {
    Ok(Ok(connection)) -> {
      let _closed = client.close(connection)
      Nil
    }
    _other -> Nil
  }
}

fn close_peer(peer: Result(server.Connection, server.Error)) -> Nil {
  case peer {
    Ok(connection) -> {
      let _closed = server.close(connection)
      Nil
    }
    // nolint: thrown_away_error -- teardown closes whatever was accepted.
    Error(_reason) -> Nil
  }
}

/// One bounded request/response exchange, naming the step that failed.
fn healthy_round_trip(
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

fn settled_label_count(expected: Int, bound_milliseconds: Int) -> Int {
  poll_label_count(expected, udp.monotonic_millisecond() + bound_milliseconds)
}

fn poll_label_count(expected: Int, deadline: Int) -> Int {
  let count = processes_labelled(connection_label)
  case count == expected || udp.monotonic_millisecond() >= deadline {
    True -> count
    False -> {
      process.sleep(20)
      poll_label_count(expected, deadline)
    }
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
