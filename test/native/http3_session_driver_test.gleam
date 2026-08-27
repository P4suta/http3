//// HTTP/3 sessions carried over the native QUIC driver.
////
//// These three tests stay in the root package because `session` still takes
//// and returns core types - `driver.State`, `ecn.Marking`, a `packet_space`
//// marking, `connection_state.Phase` - so they cannot move into
//// `gleam_quic`'s own suite the way the driver-only tests did. The handshake
//// fixtures below are therefore duplicated from
//// `packages/gleam_quic/test/driver_test.gleam`; the Phase 3 runtime
//// migration removes that coupling and this duplication with it.

import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam_quic/internal/connection_state
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/udp
import gleam_quic/transport_parameter
import gleam_quic/version
import http3/internal/native/connection_state as http3_state
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/session
import http3/internal/qpack/header.{type Header, Header}

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

const original_destination_connection_id = <<1, 2, 3, 4, 5, 6, 7, 8>>

const client_connection_id = <<9, 10, 11, 12, 13, 14, 15, 16>>

const maximum_handshake_rounds = 64

/// RFC 9000 section 14.1: the datagram size every path carries, and the size
/// DPLPMTUD falls back to when a larger one turns out not to be sendable.
const minimum_datagram_bytes = 1200

type Peers {
  Peers(client: driver.State, server: driver.State, now_ms: Int)
}

type SessionPeers {
  SessionPeers(client: session.State, server: session.State, now_ms: Int)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn carries_http3_request_response_over_protected_streams_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let assert Ok(client) =
    session.start(client, http3_state.default_config(http3_state.Client), False)
  let assert Ok(server) =
    session.start(server, http3_state.default_config(http3_state.Server), False)
  assert session.phase(client) == connection_state.Established
  assert session.phase(server) == connection_state.Established

  let assert Ok(#(client, request_id)) =
    session.open_request(client, streaming_request_headers(), False)
  assert request_id == 0
  let assert Ok(client) = session.send_data(client, request_id, <<"hello ">>)
  let assert Ok(client) = session.send_data(client, request_id, <<"stream">>)
  let assert Ok(client) = session.finish_stream(client, request_id)
  let assert Ok(SessionPeers(client, server, now_ms)) =
    drive_sessions(SessionPeers(client, server, now_ms), 64)
  let #(server, server_events) = session.take_events(server)
  assert has_request_headers(server_events, request_id)
  assert has_data(server_events, request_id, <<"hello ">>)
  assert has_data(server_events, request_id, <<"stream">>)
  assert has_stream_finished(server_events, request_id)

  let assert Ok(server) =
    session.send_response_headers(server, request_id, response_headers(), False)
  let assert Ok(server) = session.send_data(server, request_id, <<"abc">>)
  let assert Ok(server) =
    session.send_trailers(
      server,
      request_id,
      [Header(<<"x-checksum">>, <<"ok">>, False)],
      False,
    )
  let assert Ok(server) = session.finish_stream(server, request_id)
  let assert Ok(SessionPeers(client, server, _)) =
    drive_sessions(SessionPeers(client, server, now_ms), 64)
  let #(client, client_events) = session.take_events(client)
  assert has_response_headers(client_events, request_id)
  assert has_data(client_events, request_id, <<"abc">>)
  assert has_trailers(client_events, request_id)
  assert has_stream_finished(client_events, request_id)
  assert session.phase(client) == connection_state.Established
  assert session.phase(server) == connection_state.Established
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn configured_http3_frame_limit_rejects_oversized_peer_settings_test() -> Nil {
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      connection_state.default_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      connection_state.default_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let client_config = http3_state.default_config(http3_state.Client)
  let server_defaults = http3_state.default_config(http3_state.Server)
  let server_config =
    http3_state.Config(
      ..server_defaults,
      settings: http3_state.Settings(
        ..server_defaults.settings,
        maximum_field_section_size: 8,
      ),
      maximum_frame_payload_bytes: 8,
    )
  let assert Ok(client) = session.start(client, client_config, False)
  let assert Ok(server) = session.start(server, server_config, False)

  assert drive_sessions(SessionPeers(client, server, now_ms), 8)
    == Error(
      session.FrameParserFailure(
        frame_parser.FrameFailure(frame.PayloadLimitExceeded(8)),
      ),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn keeps_request_data_when_the_socket_refuses_a_datagram_test() -> Nil {
  // The same step over the state `client_connection.flush` holds once the
  // connection is established and DPLPMTUD has confirmed a wider path.
  let #(client_tls_config, server_tls_config) = tls_configs()
  let assert Ok(client_tls) = engine.start_client(client_tls_config)
  let assert Ok(server_tls) = engine.start_server(server_tls_config)
  let assert Ok(client) =
    driver.start_client(
      dont_fragment_config(connection_state.Client),
      client_tls,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(server) =
    driver.start_server(
      dont_fragment_config(connection_state.Server),
      server_tls,
      original_destination_connection_id,
      original_destination_connection_id,
      client_connection_id,
      0,
    )
  let assert Ok(Peers(client, server, now_ms)) =
    drive_handshake(Peers(client, server, 1), maximum_handshake_rounds)
  let assert Ok(client) =
    session.start(client, http3_state.default_config(http3_state.Client), False)
  let assert Ok(server) =
    session.start(server, http3_state.default_config(http3_state.Server), False)

  // Confirm a path wider than the floor, the way a live connection does.
  let assert Ok(Some(probe)) = session.prepare_pmtu_probe(client, now_ms)
  let probe_bytes = session.prepared_bytes(probe)
  assert bit_array.byte_size(probe_bytes) > minimum_datagram_bytes
  let assert Ok(client) = session.commit_datagram(probe, ecn.NotEct, now_ms)
  let assert Ok(server) =
    session.receive_datagram(
      server,
      probe_bytes,
      packet_space.NotEct,
      now_ms + 1,
    )
  let assert Ok(SessionPeers(client, server, now_ms)) =
    drive_sessions(SessionPeers(client, server, now_ms + 30), 4)
  assert session.path_mtu(client) > minimum_datagram_bytes

  let assert Ok(#(client, request_id)) =
    session.open_request(client, large_request_headers(), False)
  let assert Ok(client) =
    session.send_data(client, request_id, <<0:size(3000)-unit(8)>>)

  // The flush builds a datagram for the confirmed path and the socket refuses
  // it. The prepared datagram is dropped uncommitted.
  let assert Ok(Some(refused)) = session.prepare_datagram(client, 1000, now_ms)
  assert bit_array.byte_size(session.prepared_bytes(refused))
    > minimum_datagram_bytes
  let assert Ok(client) = session_after_refused_send(client)

  assert session.phase(client) == connection_state.Established
  assert session.path_mtu(client) == minimum_datagram_bytes

  // The request body is still owed and still arrives, inside the floor.
  let assert Ok(SessionPeers(client, server, _)) =
    drive_sessions(SessionPeers(client, server, now_ms), 32)
  let #(_, server_events) = session.take_events(server)
  assert has_request_headers(server_events, request_id)
  assert received_data_bytes(server_events, request_id) == 3000
  assert session.phase(client) == connection_state.Established
  assert session.path_mtu(client) == minimum_datagram_bytes
}

/// Request headers for a body larger than one floor-sized datagram carries.
fn large_request_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"POST">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/native">>, False),
    Header(<<"content-length">>, <<"3000">>, False),
  ]
}

/// Total DATA payload bytes one stream delivered.
fn received_data_bytes(events: List(session.Event), stream_id: Int) -> Int {
  list.fold(events, 0, fn(total, event) {
    case event {
      session.Http3Event(http3_state.Data(identifier, bytes))
        if identifier == stream_id
      -> total + bit_array.byte_size(bytes)
      _ -> total
    }
  })
}

/// The same step for `client_connection.send_prepared`, which flushes the
/// established HTTP/3 session rather than the handshake.
fn session_after_refused_send(
  state: session.State,
) -> Result(session.State, Nil) {
  case udp.classify_send(Error(udp.MessageTooLarge)) {
    udp.PathTooSmall -> Ok(session.report_pmtu_black_hole(state))
    udp.Delivered | udp.SocketLost -> Error(Nil)
  }
}

/// A configuration for a socket that carries the Don't-Fragment option, which
/// is what lets DPLPMTUD search above the 1200-byte floor.
fn dont_fragment_config(
  role: connection_state.Role,
) -> connection_state.Config {
  connection_state.Config(
    ..connection_state.default_config(role),
    path_dont_fragment: True,
  )
}

fn drive_handshake(peers: Peers, rounds: Int) -> Result(Peers, driver.Error) {
  case handshake_complete(peers), rounds {
    True, _ -> Ok(peers)
    False, 0 -> Error(driver.InvalidInput)
    False, remaining -> {
      use peers <- result.try(send_client_datagram(peers))
      use peers <- result.try(send_server_datagram(peers))
      drive_handshake(peers, remaining - 1)
    }
  }
}

fn handshake_complete(peers: Peers) -> Bool {
  driver.phase(peers.client) == connection_state.Established
  && driver.phase(peers.server) == connection_state.Established
  && connection_state.packet_space_discarded(
    driver.connection(peers.client),
    engine.Handshake,
  )
}

fn send_client_datagram(peers: Peers) -> Result(Peers, driver.Error) {
  use client <- result.try(driver.tick(peers.client, peers.now_ms))
  use server <- result.try(driver.tick(peers.server, peers.now_ms))
  case driver.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      use client <- result.try(driver.commit_datagram(prepared, peers.now_ms))
      use server <- result.try(driver.receive_datagram(
        server,
        driver.prepared_bytes(prepared),
        peers.now_ms,
      ))
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn send_server_datagram(peers: Peers) -> Result(Peers, driver.Error) {
  use client <- result.try(driver.tick(peers.client, peers.now_ms))
  use server <- result.try(driver.tick(peers.server, peers.now_ms))
  case driver.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(Peers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      use server <- result.try(driver.commit_datagram(prepared, peers.now_ms))
      use client <- result.try(driver.receive_datagram(
        client,
        driver.prepared_bytes(prepared),
        peers.now_ms,
      ))
      Ok(Peers(client, server, peers.now_ms + 100))
    }
  }
}

fn drive_sessions(
  peers: SessionPeers,
  rounds: Int,
) -> Result(SessionPeers, session.Error) {
  case rounds {
    0 -> Ok(peers)
    remaining -> {
      use peers <- result.try(send_client_session(peers))
      use peers <- result.try(send_server_session(peers))
      drive_sessions(peers, remaining - 1)
    }
  }
}

fn send_client_session(
  peers: SessionPeers,
) -> Result(SessionPeers, session.Error) {
  use client <- result.try(session.tick(peers.client, peers.now_ms))
  use server <- result.try(session.tick(peers.server, peers.now_ms))
  case session.prepare_datagram(client, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(SessionPeers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = session.prepared_bytes(prepared)
      use client <- result.try(session.commit_datagram(
        prepared,
        ecn.NotEct,
        peers.now_ms,
      ))
      use server <- result.try(session.receive_datagram(
        server,
        bytes,
        packet_space.NotEct,
        peers.now_ms,
      ))
      Ok(SessionPeers(client, server, peers.now_ms + 100))
    }
  }
}

fn send_server_session(
  peers: SessionPeers,
) -> Result(SessionPeers, session.Error) {
  use client <- result.try(session.tick(peers.client, peers.now_ms))
  use server <- result.try(session.tick(peers.server, peers.now_ms))
  case session.prepare_datagram(server, 1000, peers.now_ms) {
    Error(error) -> Error(error)
    Ok(None) -> Ok(SessionPeers(client, server, peers.now_ms + 100))
    Ok(Some(prepared)) -> {
      let bytes = session.prepared_bytes(prepared)
      use server <- result.try(session.commit_datagram(
        prepared,
        ecn.NotEct,
        peers.now_ms,
      ))
      use client <- result.try(session.receive_datagram(
        client,
        bytes,
        packet_space.NotEct,
        peers.now_ms,
      ))
      Ok(SessionPeers(client, server, peers.now_ms + 100))
    }
  }
}

fn streaming_request_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"POST">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/native">>, False),
    Header(<<"content-length">>, <<"12">>, False),
  ]
}

fn response_headers() -> List(Header) {
  [
    Header(<<":status">>, <<"200">>, False),
    Header(<<"content-length">>, <<"3">>, False),
  ]
}

fn has_request_headers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.RequestHeaders(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_response_headers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_data(
  events: List(session.Event),
  stream_id: Int,
  expected: BitArray,
) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.Data(identifier, bytes)) ->
        identifier == stream_id && bytes == expected
      _ -> False
    }
  })
}

fn has_trailers(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.Trailers(identifier, _)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn has_stream_finished(events: List(session.Event), stream_id: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      session.Http3Event(http3_state.StreamFinished(identifier)) ->
        identifier == stream_id
      _ -> False
    }
  })
}

fn tls_configs() -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  let shared_parameters = [
    transport_parameter.GreaseQuicBit,
    transport_parameter.VersionInformation(version.Version1, [
      version.Version2,
      version.Version1,
    ]),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.MaxUdpPayloadSize(1400),
    transport_parameter.MaxDatagramFrameSize(1400),
  ]
  #(
    engine.ClientConfig(
      version: version.Version1,
      hostname: "localhost",
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(client_connection_id),
        ..shared_parameters
      ],
      trust_store: trust_store,
      client_credential: None,
      retried: False,
      version_negotiated: False,
    ),
    engine.ServerConfig(
      version: version.Version1,
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.OriginalDestinationConnectionId(
          original_destination_connection_id,
        ),
        transport_parameter.InitialSourceConnectionId(
          original_destination_connection_id,
        ),
        ..shared_parameters
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
      alternative_credentials: [],
      client_authentication: engine.ClientAuthenticationDisabled,
    ),
  )
}
