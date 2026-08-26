//// Bounded listener flush progress for backlogged connections over real UDP.

import gleam/bit_array
import gleam/result
import gleam_quic
import gleam_quic/client
import gleam_quic/config
import gleam_quic/failure
import gleam_quic/server
import gleeunit/should

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// The listener flushes at most `maximum_packets_per_flush` (64) datagrams of
// at most `maximum_frame_data_bytes` (1000) payload bytes per connection per
// turn, so a 256 KiB stream needs the flush to be resumed several times.
const backlog_bytes = 262_144

const bound_milliseconds = 2000

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn capped_flush_drains_stream_backlog_within_bound_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca_certificate = fixture("ca.pem") |> should.be_ok
  let deadlines = config.uniform_deadlines(bound_milliseconds) |> should.be_ok
  let limits =
    config.with_limit(config.default_limits(), failure.Buffer, 1_048_576)
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
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_address_family(gleam_quic.Ipv4)
    |> client.with_ca_certificates(ca_certificate)
    |> should.be_ok
    |> client.with_deadlines(deadlines)
    |> client.with_limits(limits)
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok

  let stream = client.open_bidirectional(connection) |> should.be_ok
  client.send_and_finish(stream, <<"backlog":utf8>>) |> should.be_ok
  let assert server.IncomingStream(peer_stream, server.Bidirectional) =
    server.accept_stream(peer) |> should.be_ok
  assert server.receive(peer_stream, 1024)
    == Ok(server.Data(<<"backlog":utf8>>, True))

  let payload = repeated_bytes(backlog_bytes)
  server.send_and_finish(peer_stream, payload) |> should.be_ok

  // The client sends nothing further, so the queued backlog has to be driven
  // by the listener itself within the configured operation deadline.
  let received = drain(stream, <<>>)
  assert bit_array.byte_size(received) == backlog_bytes
  assert received == payload

  let _closed = client.close(connection)
  let _peer_closed = server.close(peer)
  assert server.stop(listener) == Ok(server.Stopped)
}

fn drain(stream: client.Stream, collected: BitArray) -> BitArray {
  case client.receive(stream, 65_536) |> should.be_ok {
    client.Reset(_) -> collected
    client.Finished -> collected
    client.Data(bytes, True) -> bit_array.append(collected, bytes)
    client.Data(bytes, False) ->
      drain(stream, bit_array.append(collected, bytes))
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
