//// What a runtime flush does when the local stack refuses a datagram the
//// connection believed the path carried.
////
//// The socket sets Don't-Fragment, so the kernel answers a datagram larger
//// than the outgoing device with EMSGSIZE - `udp.MessageTooLarge` - instead
//// of splitting it. Both core flush paths, `client_transport.send_prepared`
//// and `server_worker.flush_connection`, treat that as a path measurement
//// rather than a broken socket: the prepared datagram is dropped uncommitted,
//// so its frames stay owed, the path returns to the 1200-byte floor, and the
//// connection keeps running. These tests model exactly that step over the two
//// runtime states those flushes hold.

import gleam/bit_array
import gleam/option.{type Option, None, Some}
import gleam_quic/internal/connection_state
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/runtime/connection
import gleam_quic/internal/runtime/server_transport
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/version

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const original_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

const client_connection_id = <<9, 10, 11, 12, 13, 14, 15, 16>>

const server_connection_id = <<17, 18, 19, 20, 21, 22, 23, 24>>

/// RFC 9000 section 14.1: the datagram size every path carries, and the size
/// DPLPMTUD falls back to when a larger one turns out not to be sendable.
const minimum_datagram_bytes = 1200

/// More stream data than the floor carries, so the flush after the refusal has
/// to keep sending rather than fitting everything into one datagram.
const payload_bytes = 4000

/// A bound on every delivery loop, so a stalled connection fails the test
/// instead of running forever.
const maximum_delivery_rounds = 32

type Pair {
  Pair(
    client: connection.State,
    server: server_transport.State,
    policy: resumption.ServerPolicy,
    now: Int,
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn core_client_keeps_the_connection_after_a_refused_datagram_test() -> Nil {
  let pair = confirms_a_wider_client_path(established_pair())
  assert connection.path_mtu(pair.client) > minimum_datagram_bytes

  let assert Ok(#(client, stream)) =
    connection.open_stream(pair.client, stream_id.Bidirectional)
  let assert Ok(client) =
    connection.send(client, stream, <<0:size(payload_bytes)-unit(8)>>, True)

  // The flush builds a datagram for the path it has been told to trust.
  let assert Ok(Some(prepared)) =
    connection.prepare_datagram(client, 1000, pair.now)
  assert bit_array.byte_size(connection.prepared_bytes(prepared))
    > minimum_datagram_bytes

  // The socket refuses it. The refusal is classified the way the flush
  // classifies it, so this models the whole step and not just its second half:
  // `send_prepared` never commits the prepared datagram, so `client` is still
  // the state that owes those frames.
  let assert Ok(client) = client_after_refused_send(client)

  assert connection.phase(client) == connection_state.Established
  assert connection.path_mtu(client) == minimum_datagram_bytes
  assert connection.buffered_send_bytes(client, stream) == Ok(payload_bytes)

  // Every later datagram fits the floor, and the frames the refused one
  // carried are still delivered.
  let assert Ok(pair) =
    deliver_from_client(
      Pair(..pair, client: client),
      maximum_delivery_rounds,
      0,
    )
  assert connection.path_mtu(pair.client) == minimum_datagram_bytes
  assert server_read_bytes(pair.server, stream, 0) == payload_bytes
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn core_server_keeps_the_connection_after_a_refused_datagram_test() -> Nil {
  let pair = confirms_a_wider_server_path(established_pair())
  assert server_transport.path_mtu(pair.server) > minimum_datagram_bytes

  let assert Ok(#(server, stream)) =
    server_transport.open_stream(pair.server, stream_id.Unidirectional)
  let assert Ok(server) =
    server_transport.send(
      server,
      stream,
      <<0:size(payload_bytes)-unit(8)>>,
      False,
    )

  let assert Ok(Some(prepared)) =
    server_transport.prepare_datagram(server, 1000, pair.now)
  assert bit_array.byte_size(server_transport.prepared_bytes(prepared))
    > minimum_datagram_bytes

  // `flush_connection` classifies the refusal, drops the refused datagram, and
  // keeps the peer.
  let assert Ok(server) = server_after_refused_send(server)

  assert server_transport.phase(server) == connection_state.Established
  assert server_transport.path_mtu(server) == minimum_datagram_bytes
  assert server_transport.buffered_send_bytes(server, stream)
    == Ok(payload_bytes)

  let assert Ok(pair) =
    deliver_from_server(
      Pair(..pair, server: server),
      maximum_delivery_rounds,
      0,
    )
  assert server_transport.path_mtu(pair.server) == minimum_datagram_bytes
  assert client_read_bytes(pair.client, stream, 0) == payload_bytes
}

/// The step `client_transport.send_prepared` takes for one refused send.
///
/// The classification is the part under test: only `udp.PathTooSmall` keeps
/// the connection. Were EMSGSIZE folded back into a socket failure, the flush
/// would return `SocketUnavailable` and this returns `Error(Nil)` in its place,
/// so the test fails instead of quietly asserting an unreachable state.
fn client_after_refused_send(
  state: connection.State,
) -> Result(connection.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(connection.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// The same step for `server_worker.flush_connection`.
fn server_after_refused_send(
  state: server_transport.State,
) -> Result(server_transport.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(server_transport.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// One established client and server exchanging datagrams in memory.
fn established_pair() -> Pair {
  let assert Ok(client_tls) = engine.start_client(client_tls_config())
  let assert Ok(quic) =
    driver.start_client(
      client_transport_config(),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let client = connection.new(peer_endpoint(), quic)
  let assert Ok(Some(prepared)) = connection.prepare_datagram(client, 1000, 1)
  let initial = connection.prepared_bytes(prepared)
  let assert Ok(client) = connection.commit_datagram(prepared, ecn.NotEct, 1)
  let assert Ok(cache) = anti_replay.new(10_000, 16)
  let assert Ok(policy) = resumption.server_policy(<<0:256>>, 1, 1000, cache)
  let assert Ok(server) =
    server_transport.accept_initial(
      config: server_config(),
      protocol_version: version.Version1,
      original_destination_connection_id: original_destination_connection_id,
      local_connection_id: server_connection_id,
      peer_connection_id: client_connection_id,
      retry_source_connection_id: None,
      peer: peer_endpoint(),
      datagram: initial,
      marking: packet_space.NotEct,
      now: 1,
      resumption_policy: policy,
    )
  let assert Ok(pair) =
    handshake(Pair(client, server, policy, 2), maximum_delivery_rounds)
  pair
}

fn handshake(pair: Pair, rounds: Int) -> Result(Pair, Nil) {
  let complete =
    connection.established(pair.client)
    && server_transport.established(pair.server)
  case complete, rounds {
    True, _ -> Ok(pair)
    False, 0 -> Error(Nil)
    False, remaining -> handshake(exchange(pair), remaining - 1)
  }
}

/// One client datagram and one server datagram, either of which may be absent.
fn exchange(pair: Pair) -> Pair {
  let pair = case client_datagram(pair) {
    None -> pair
    Some(#(pair, bytes)) -> receive_on_server(pair, bytes)
  }
  case server_datagram(pair) {
    None -> Pair(..pair, now: pair.now + 10)
    Some(#(pair, bytes)) ->
      Pair(..receive_on_client(pair, bytes), now: pair.now + 10)
  }
}

fn client_datagram(pair: Pair) -> Option(#(Pair, BitArray)) {
  let assert Ok(client) = connection.tick(pair.client, pair.now)
  let assert Ok(prepared) = connection.prepare_datagram(client, 1000, pair.now)
  case prepared {
    None -> None
    Some(prepared) -> {
      let bytes = connection.prepared_bytes(prepared)
      let assert Ok(client) =
        connection.commit_datagram(prepared, ecn.NotEct, pair.now)
      Some(#(Pair(..pair, client: client), bytes))
    }
  }
}

fn server_datagram(pair: Pair) -> Option(#(Pair, BitArray)) {
  let assert Ok(server) = server_transport.tick(pair.server, pair.now)
  let assert Ok(prepared) =
    server_transport.prepare_datagram(server, 1000, pair.now)
  case prepared {
    None -> None
    Some(prepared) -> {
      let bytes = server_transport.prepared_bytes(prepared)
      let assert Ok(server) =
        server_transport.commit_datagram(prepared, ecn.NotEct, pair.now)
      Some(#(Pair(..pair, server: server), bytes))
    }
  }
}

fn receive_on_server(pair: Pair, bytes: BitArray) -> Pair {
  let assert Ok(server) =
    server_transport.receive_datagram(
      pair.server,
      bytes,
      packet_space.NotEct,
      pair.now,
      pair.policy,
    )
  Pair(..pair, server: server)
}

fn receive_on_client(pair: Pair, bytes: BitArray) -> Pair {
  let assert Ok(client) =
    connection.receive_datagram(
      pair.client,
      bytes,
      packet_space.NotEct,
      pair.now,
    )
  Pair(..pair, client: client)
}

/// Send one exact-size DPLPMTUD probe from the client and have the server
/// acknowledge it, so the client's path is wider than the floor.
fn confirms_a_wider_client_path(pair: Pair) -> Pair {
  let assert Ok(Some(prepared)) =
    connection.prepare_pmtu_probe(pair.client, pair.now)
  let bytes = connection.prepared_bytes(prepared)
  assert bit_array.byte_size(bytes) > minimum_datagram_bytes
  let assert Ok(client) =
    connection.commit_datagram(prepared, ecn.NotEct, pair.now)
  let pair = receive_on_server(Pair(..pair, client: client), bytes)
  acknowledges(Pair(..pair, now: pair.now + 50), maximum_delivery_rounds)
}

/// Send one exact-size DPLPMTUD probe from the server and have the client
/// acknowledge it.
fn confirms_a_wider_server_path(pair: Pair) -> Pair {
  let assert Ok(Some(prepared)) =
    server_transport.prepare_pmtu_probe(pair.server, pair.now)
  let bytes = server_transport.prepared_bytes(prepared)
  assert bit_array.byte_size(bytes) > minimum_datagram_bytes
  let assert Ok(server) =
    server_transport.commit_datagram(prepared, ecn.NotEct, pair.now)
  let pair = receive_on_client(Pair(..pair, server: server), bytes)
  acknowledges(Pair(..pair, now: pair.now + 50), maximum_delivery_rounds)
}

/// Exchange datagrams until both paths have absorbed every acknowledgement.
fn acknowledges(pair: Pair, rounds: Int) -> Pair {
  case rounds {
    0 -> pair
    remaining -> acknowledges(exchange(pair), remaining - 1)
  }
}

/// Deliver every datagram the client still owes, failing if the flush stalls
/// or hands the socket a datagram the floor cannot carry.
fn deliver_from_client(
  pair: Pair,
  rounds: Int,
  sent: Int,
) -> Result(Pair, Nil) {
  case rounds, client_datagram(pair) {
    0, _ -> Error(Nil)
    _, None ->
      case sent {
        0 -> Error(Nil)
        _ -> Ok(pair)
      }
    remaining, Some(#(pair, bytes)) ->
      case bit_array.byte_size(bytes) <= minimum_datagram_bytes {
        False -> Error(Nil)
        True -> {
          let pair = receive_on_server(pair, bytes)
          let pair = case server_datagram(pair) {
            None -> pair
            Some(#(pair, response)) -> receive_on_client(pair, response)
          }
          deliver_from_client(
            Pair(..pair, now: pair.now + 10),
            remaining - 1,
            sent + 1,
          )
        }
      }
  }
}

/// Deliver every datagram the server still owes.
fn deliver_from_server(
  pair: Pair,
  rounds: Int,
  sent: Int,
) -> Result(Pair, Nil) {
  case rounds, server_datagram(pair) {
    0, _ -> Error(Nil)
    _, None ->
      case sent {
        0 -> Error(Nil)
        _ -> Ok(pair)
      }
    remaining, Some(#(pair, bytes)) ->
      case bit_array.byte_size(bytes) <= minimum_datagram_bytes {
        False -> Error(Nil)
        True -> {
          let pair = receive_on_client(pair, bytes)
          let pair = case client_datagram(pair) {
            None -> pair
            Some(#(pair, response)) -> receive_on_server(pair, response)
          }
          deliver_from_server(
            Pair(..pair, now: pair.now + 10),
            remaining - 1,
            sent + 1,
          )
        }
      }
  }
}

/// Total stream bytes the server has read.
fn server_read_bytes(
  server: server_transport.State,
  stream: Int,
  total: Int,
) -> Int {
  let assert Ok(#(server, read)) =
    server_transport.read(server, stream, payload_bytes)
  case read {
    connection.Data(bytes, _) ->
      server_read_bytes(server, stream, total + bit_array.byte_size(bytes))
    _ -> total
  }
}

/// Total stream bytes the client has read.
fn client_read_bytes(client: connection.State, stream: Int, total: Int) -> Int {
  let assert Ok(#(client, read)) =
    connection.read(client, stream, payload_bytes)
  case read {
    connection.Data(bytes, _) ->
      client_read_bytes(client, stream, total + bit_array.byte_size(bytes))
    _ -> total
  }
}

fn peer_endpoint() -> udp.Endpoint {
  let assert Ok(address) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(endpoint) = udp.endpoint(address, 443)
  endpoint
}

/// A client on a socket that carries the Don't-Fragment option, so DPLPMTUD
/// is allowed to search above the floor.
fn client_transport_config() -> connection_state.Config {
  connection_state.Config(
    ..connection_state.default_config(connection_state.Client),
    path_dont_fragment: True,
  )
}

fn client_tls_config() -> engine.ClientConfig {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  engine.ClientConfig(
    version: version.Version1,
    hostname: "localhost",
    application_protocols: [<<"h3">>],
    transport_parameters: [
      transport_parameter.InitialSourceConnectionId(client_connection_id),
      transport_parameter.GreaseQuicBit,
      transport_parameter.VersionInformation(version.Version1, [
        version.Version1,
      ]),
      transport_parameter.InitialMaxData(1_048_576),
      transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
      transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
      transport_parameter.InitialMaxStreamDataUni(262_144),
      transport_parameter.InitialMaxStreamsBidi(100),
      transport_parameter.InitialMaxStreamsUni(100),
      transport_parameter.MaxUdpPayloadSize(65_527),
      transport_parameter.MaxDatagramFrameSize(65_535),
    ],
    trust_store: trust_store,
    client_credential: None,
    retried: False,
    version_negotiated: False,
  )
}

fn server_config() -> server_transport.Config {
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  server_transport.Config(
    certificate_chain: chain,
    signing_key: signing_key,
    signature_scheme: extension_value.Ed25519,
    alternative_credentials: [],
    client_authentication: engine.ClientAuthenticationDisabled,
    application_protocols: [<<"h3">>],
    ticket_key: <<0:256>>,
    stateless_reset_key: <<1:256>>,
    allow_zero_rtt: False,
    idle_timeout_milliseconds: 30_000,
    congestion_control: connection_state.NewReno,
    bidirectional_stream_limit: 100,
    unidirectional_stream_limit: 100,
    stream_buffer_limit: 262_144,
    datagram_limit: 65_535,
    path_dont_fragment: True,
  )
}
