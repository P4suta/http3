//// Pure QUIC connection orchestration over TLS, recovery, streams, and paths.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam_quic/frame
import gleam_quic/internal/aead_usage
import gleam_quic/internal/amplification
import gleam_quic/internal/connection_id
import gleam_quic/internal/cubic
import gleam_quic/internal/ecn
import gleam_quic/internal/flow_control
import gleam_quic/internal/initial_crypto
import gleam_quic/internal/key_phase
import gleam_quic/internal/new_reno
import gleam_quic/internal/pacer
import gleam_quic/internal/packet_space
import gleam_quic/internal/path_validation
import gleam_quic/internal/pmtu
import gleam_quic/internal/reassembler
import gleam_quic/internal/rtt
import gleam_quic/internal/stream_state
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/traffic_keys
import gleam_quic/internal/wire_packet
import gleam_quic/stream_id
import gleam_quic/transport_parameter
import gleam_quic/varint
import gleam_quic/version.{type Version}

// RFC 9000 section 14: every QUIC path carries a 1200-byte datagram. It is the
// floor DPLPMTUD starts from and the datagram unit congestion control and
// pacing are denominated in before any larger size has been validated.
const minimum_datagram_bytes = 1200

// RFC 9000 section 18.2: the default max_udp_payload_size, and the largest
// value an endpoint may advertise for what it is willing to receive.
const maximum_udp_payload_size = 65_527

// A conservative ceiling for DPLPMTUD's search. One IP datagram carries at
// most 65_507 bytes of UDP payload, and a datagram that size leaves the host
// no room for IP options or for the per-datagram overhead a socket adds, so
// the search stops at 60 kilobytes instead. Every size it can validate is
// then one a single UDP send is known to accept.
const maximum_sendable_udp_payload = 61_440

// The largest header a STREAM or CRYPTO frame writes ahead of its data: one
// type byte plus stream identifier, offset, and length as 8-byte varints.
const maximum_data_frame_header_bytes = 25

// RFC 9000 section 16: eight bytes is the widest variable-length integer
// encoding, and therefore the most any length or count field can cost.
const maximum_varint_bytes = 8

// What one Initial packet must be able to carry beyond its own protection: a
// CRYPTO frame header, the acknowledgement the space owes, and enough of the
// first flight for the handshake to advance on every packet. Reserving it is
// what turns "the address-validation token has to fit" into a token width.
const minimum_initial_payload_bytes = 256

// RFC 9002 section 7.7: the pacer releases this many datagrams back to back
// before spacing takes over. The burst scales with the path, never below one
// whole datagram.
const pacer_burst_datagrams = 10

const timer_granularity_milliseconds = 1

const maximum_crypto_buffer_bytes = 1_048_576

const maximum_crypto_offset = 4_194_304

// A NEW_TOKEN frame is reliable and indivisible: it cannot be split to fit a
// packet and it cannot be dropped. Bound the token so the frame always fits
// the 1200-byte floor a black hole can reset the path to.
const maximum_address_token_bytes = 1024

// The same bound for the reason phrase a caller attaches to CONNECTION_CLOSE,
// which is reliable and indivisible for the same reasons.
const maximum_close_reason_bytes = 1024

const active_connection_id_limit = 4

// A single minimum-size datagram can contain more than one hundred
// PATH_CHALLENGE frames. Keep responses bounded even when acknowledgements
// are withheld; duplicate challenges share one pending response.
const maximum_pending_path_responses = 64

/// Endpoint role fixes stream-ID ownership and amplification behavior.
pub type Role {
  Client
  Server
}

/// Congestion controller selected for the current path.
pub type CongestionAlgorithm {
  NewReno
  Cubic
}

/// Read or write packet-protection direction.
pub type KeyDirection {
  Read
  Write
}

/// Stable connection lifecycle visible to the runtime adapter.
pub type Phase {
  Handshaking
  Established
  Closing
  Draining
  Closed
}

/// Stable live path diagnostics in milliseconds and bytes.
pub type PathSnapshot {
  PathSnapshot(
    latest_rtt_milliseconds: Int,
    smoothed_rtt_milliseconds: Int,
    minimum_rtt_milliseconds: Int,
    rtt_variation_milliseconds: Int,
    congestion_window: Int,
    bytes_in_flight: Int,
    in_recovery: Bool,
    congested: Bool,
  )
}

/// Transport-owned diagnostic counters that survive HTTP/3 orchestration.
pub type ConnectionCounters {
  ConnectionCounters(
    acknowledgements_sent: Int,
    retransmissions: Int,
    packets_coalesced: Int,
  )
}

/// Resource and transport policy for one connection.
pub type Config {
  Config(
    role: Role,
    version: Version,
    congestion_algorithm: CongestionAlgorithm,
    maximum_ack_delay_milliseconds: Int,
    maximum_ack_ranges: Int,
    maximum_outstanding_packets: Int,
    initial_receive_data: Int,
    receive_data_window: Int,
    maximum_receive_data: Int,
    initial_receive_stream_data: Int,
    receive_stream_window: Int,
    maximum_receive_stream_data: Int,
    maximum_peer_streams_bidirectional: Int,
    maximum_peer_streams_unidirectional: Int,
    maximum_stream_receive_buffer: Int,
    maximum_stream_send_buffer: Int,
    maximum_stream_final_size: Int,
    maximum_total_streams: Int,
    maximum_udp_payload_size: Int,
    maximum_datagram_frame_size: Int,
    grease_quic_bit: Bool,
    idle_timeout_milliseconds: Int,
    draining_timeout_milliseconds: Int,
    path_dont_fragment: Bool,
  )
}

/// Ordered notifications consumed by HTTP/3 or the runtime owner.
pub type Event {
  PeerParametersApplied
  EarlyDataWasAccepted
  EarlyDataWasRejected
  HandshakeEstablished
  SessionTicketStored(session_ticket.ClientTicket)
  StreamOpened(Int)
  StreamReadable(Int)
  StreamWasReset(Int, application_error_code: Int)
  DatagramReceived(BitArray)
  NewTokenReceived(BitArray)
  PathValidated
  PathValidationFailed
  PeerConnectionIdAvailable(sequence: Int, value: BitArray)
  LocalConnectionIdRetirementRequested(sequence: Int)
  StatelessResetReceived
  PeerClosed(error_code: Int, reason: String)
  CryptoReceived(engine.EncryptionLevel, BitArray)
}

/// Result of polling one encryption level for packet payload frames.
pub type Preparation {
  NoPacket(State)
  PacketPrepared(
    State,
    engine.EncryptionLevel,
    packet_number: Int,
    frames: List(frame.Frame),
  )
}

/// Authenticated long-header packet metadata plus remaining coalesced bytes.
pub type LongPacketReceipt {
  LongPacketReceipt(
    state: State,
    destination_connection_id: BitArray,
    source_connection_id: BitArray,
    rest: BitArray,
  )
}

/// Authenticated short-header metadata after transport-frame processing.
pub type ShortPacketReceipt {
  ShortPacketReceipt(
    state: State,
    destination_connection_id: BitArray,
    key_phase: Bool,
    spin: Bool,
  )
}

type LevelKeys {
  LevelKeys(
    read: Option(traffic_keys.TrafficKeys),
    write: Option(traffic_keys.TrafficKeys),
  )
}

type InitialLevelKeys {
  InitialLevelKeys(
    read: Option(initial_crypto.PacketKeys),
    write: Option(initial_crypto.PacketKeys),
  )
}

type ShortDecryption {
  ShortDecryption(wire_packet.DecodedShort, key_phase.CandidateKind)
}

type CongestionState {
  RenoState(new_reno.State)
  CubicState(cubic.State)
}

type TlsEndpoint {
  NoTlsEndpoint
  ClientTlsEndpoint(engine.Client)
  ServerTlsEndpoint(engine.Server)
}

/// All live protocol state; runtime handles and socket values remain outside.
pub opaque type State {
  State(
    config: Config,
    tls_endpoint: TlsEndpoint,
    phase: Phase,
    handshake_confirmed: Bool,
    early_data_accepted: Bool,
    initial_keys: InitialLevelKeys,
    handshake_keys: LevelKeys,
    zero_rtt_keys: LevelKeys,
    one_rtt_keys: LevelKeys,
    one_rtt_key_phase: Option(key_phase.State),
    one_rtt_aead_usage: Option(aead_usage.Usage),
    initial_space: packet_space.State,
    handshake_space: packet_space.State,
    application_space: packet_space.State,
    initial_crypto_receive: reassembler.Reassembler,
    handshake_crypto_receive: reassembler.Reassembler,
    application_crypto_receive: reassembler.Reassembler,
    initial_crypto_send_offset: Int,
    handshake_crypto_send_offset: Int,
    application_crypto_send_offset: Int,
    initial_token_bytes: Int,
    initial_queue: List(frame.Frame),
    handshake_queue: List(frame.Frame),
    zero_rtt_queue: List(frame.Frame),
    application_queue: List(frame.Frame),
    streams: Dict(Int, stream_state.State),
    stream_order: List(Int),
    local_bidirectional_streams: flow_control.StreamLimit,
    local_unidirectional_streams: flow_control.StreamLimit,
    remote_bidirectional_streams: flow_control.StreamLimit,
    remote_unidirectional_streams: flow_control.StreamLimit,
    connection_receiver: flow_control.Receiver,
    connection_sender: flow_control.Sender,
    peer_stream_data_bidi_local: Int,
    peer_stream_data_bidi_remote: Int,
    peer_stream_data_uni: Int,
    peer_ack_delay_exponent: Int,
    peer_maximum_udp_payload_size: Int,
    peer_maximum_datagram_frame_size: Int,
    peer_grease_quic_bit: Bool,
    peer_disabled_active_migration: Bool,
    estimator: rtt.Estimator,
    congestion: CongestionState,
    pacer: pacer.State,
    ecn: ecn.State,
    amplification: amplification.Budget,
    pmtu: pmtu.State,
    path_validator: path_validation.Validator,
    peer_connection_ids: Option(connection_id.Registry),
    pending_peer_stateless_reset_token: Option(BitArray),
    events: List(Event),
    acknowledgements_sent: Int,
    retransmissions: Int,
    packets_coalesced: Int,
    last_activity_milliseconds: Int,
    close_deadline_milliseconds: Option(Int),
  )
}

/// Fatal configuration, peer protocol, resource, or state error.
pub type Error {
  InvalidConfiguration
  InvalidInput
  ConnectionUnavailable
  SpaceUnavailable
  MissingReadKeys(engine.EncryptionLevel)
  MissingWriteKeys(engine.EncryptionLevel)
  PacketSpaceFailure
  FlowControlFailure
  StreamFailure
  UnknownStream(Int)
  StreamLimitFailure
  ProtocolViolation
  CongestionLimited
  PacingLimited(Int)
  AmplificationLimited
  DatagramNotNegotiated
  DatagramTooLarge(Int)
  InitialKeyFailure(initial_crypto.Error)
  FrameCodecFailure(frame.Error)
  WirePacketFailure(wire_packet.Error)
  KeyUpdateFailure(key_phase.Error)
  AeadUsageFailure(aead_usage.Error)
  PathValidationFailure(path_validation.Error)
  ActiveMigrationDisabled
  ConnectionIdFailure(connection_id.Error)
  PmtuFailure(pmtu.Error)
  TlsFailure(engine.Error)
}

/// Conservative bounded defaults; authenticated transport parameters raise
/// only peer-controlled sending limits.
pub fn default_config(role: Role) -> Config {
  Config(
    role: role,
    version: version.Version1,
    congestion_algorithm: NewReno,
    maximum_ack_delay_milliseconds: 25,
    maximum_ack_ranges: 256,
    maximum_outstanding_packets: 4096,
    initial_receive_data: 1_048_576,
    receive_data_window: 1_048_576,
    maximum_receive_data: 16_777_216,
    initial_receive_stream_data: 262_144,
    receive_stream_window: 262_144,
    maximum_receive_stream_data: 4_194_304,
    maximum_peer_streams_bidirectional: 100,
    maximum_peer_streams_unidirectional: 100,
    maximum_stream_receive_buffer: 262_144,
    maximum_stream_send_buffer: 262_144,
    maximum_stream_final_size: 16_777_216,
    maximum_total_streams: 1024,
    maximum_udp_payload_size: 65_527,
    maximum_datagram_frame_size: 65_535,
    grease_quic_bit: True,
    idle_timeout_milliseconds: 30_000,
    draining_timeout_milliseconds: 3000,
    // Fail closed: a caller that has not looked at its socket gets the
    // 1200-byte floor every path carries. Every runtime construction site
    // passes `udp.dont_fragment` for the socket it actually sends on, so only
    // a connection built outside them keeps this default.
    path_dont_fragment: False,
  )
}

/// The largest datagram DPLPMTUD may ever confirm for this connection.
///
/// RFC 8899 section 3 reads an acknowledged probe as proof the path carries
/// that size only when the probe could not have been fragmented. A socket the
/// kernel refused the Don't-Fragment option to can have an oversized probe
/// fragmented locally, delivered, and acknowledged, which would raise the path
/// to a permanently fragmenting size. Without that option the ceiling is the
/// 1200-byte floor every path carries, so discovery starts complete and the
/// connection never sends a datagram it has not been told fits.
fn discovery_ceiling(config: Config) -> Int {
  case config.path_dont_fragment {
    False -> minimum_datagram_bytes
    True ->
      minimum(config.maximum_udp_payload_size, maximum_sendable_udp_payload)
  }
}

/// The widest address-validation token an Initial packet may repeat.
///
/// A client repeats its token in every Initial it sends (RFC 9000 section
/// 8.1.2), and every Initial has to fit the 1200-byte floor of RFC 9000
/// section 14.1, because that is the only size a path is known to carry before
/// DPLPMTUD has confirmed more. An Initial payload is budgeted as the path
/// minus `initial_packet_overhead`, so a token past this width would leave no
/// payload to budget and build a datagram over the floor. `driver` checks both
/// doors a token comes through - a cached one at start-up and a Retry's -
/// against this, which is what lets the send path treat that budget as a real
/// ceiling.
///
/// This is a conservative internal ceiling, not a wire limit: RFC 9000 places
/// no upper bound on a token, and the width is computed by charging every
/// header field its widest encoding - twenty-byte connection IDs and 8-byte
/// varints throughout - so a token a little past it would often still have fit
/// the real header this connection writes.
pub fn maximum_initial_token_bytes() -> Int {
  minimum_datagram_bytes
  - initial_packet_overhead(0)
  - minimum_initial_payload_bytes
}

/// The most protecting an Initial packet ever adds around its frame payload:
/// everything a 0-RTT or Handshake packet pays, plus the Token Length field at
/// its widest and the `token_bytes` of the token itself.
///
/// RFC 9000 section 17.2.2 gives only Initial a token, and a client that was
/// issued a large address-validation token carries it in every Initial it
/// sends, so a caller budgeting an Initial payload has to pay for it too.
fn initial_packet_overhead(token_bytes: Int) -> Int {
  wire_packet.maximum_long_packet_overhead()
  + maximum_varint_bytes
  + token_bytes
}

/// Initialize all independently bounded packet, stream, and path state.
pub fn new(config: Config, now_milliseconds: Int) -> Result(State, Error) {
  use _ <- result.try(validate_config(config, now_milliseconds))
  use initial_space <- result.try(create_packet_space(
    packet_space.Initial,
    config,
  ))
  use handshake_space <- result.try(create_packet_space(
    packet_space.Handshake,
    config,
  ))
  use application_space <- result.try(create_packet_space(
    packet_space.Application,
    config,
  ))
  use initial_crypto <- result.try(create_crypto_reassembler())
  use handshake_crypto <- result.try(create_crypto_reassembler())
  use application_crypto <- result.try(create_crypto_reassembler())
  use connection_receiver <- result.try(create_receiver(
    config.initial_receive_data,
    config.receive_data_window,
    config.maximum_receive_data,
  ))
  use connection_sender <- result.try(create_sender(0))
  use local_bidi <- result.try(create_stream_limit(0))
  use local_uni <- result.try(create_stream_limit(0))
  use remote_bidi <- result.try(create_stream_limit(
    config.maximum_peer_streams_bidirectional,
  ))
  use remote_uni <- result.try(create_stream_limit(
    config.maximum_peer_streams_unidirectional,
  ))
  use estimator <- result.try(create_rtt())
  use congestion <- result.try(create_congestion(config))
  use pacing <- result.try(create_pacer(config, now_milliseconds))
  use amplification <- result.try(create_amplification(config.role))
  use path_mtu <- result.try(create_pmtu(discovery_ceiling(config)))
  Ok(State(
    config: config,
    tls_endpoint: NoTlsEndpoint,
    phase: Handshaking,
    handshake_confirmed: False,
    early_data_accepted: False,
    initial_keys: empty_initial_keys(),
    handshake_keys: empty_keys(),
    zero_rtt_keys: empty_keys(),
    one_rtt_keys: empty_keys(),
    one_rtt_key_phase: None,
    one_rtt_aead_usage: None,
    initial_space: initial_space,
    handshake_space: handshake_space,
    application_space: application_space,
    initial_crypto_receive: initial_crypto,
    handshake_crypto_receive: handshake_crypto,
    application_crypto_receive: application_crypto,
    initial_crypto_send_offset: 0,
    handshake_crypto_send_offset: 0,
    application_crypto_send_offset: 0,
    initial_token_bytes: 0,
    initial_queue: [],
    handshake_queue: [],
    zero_rtt_queue: [],
    application_queue: [],
    streams: dict.new(),
    stream_order: [],
    local_bidirectional_streams: local_bidi,
    local_unidirectional_streams: local_uni,
    remote_bidirectional_streams: remote_bidi,
    remote_unidirectional_streams: remote_uni,
    connection_receiver: connection_receiver,
    connection_sender: connection_sender,
    peer_stream_data_bidi_local: 0,
    peer_stream_data_bidi_remote: 0,
    peer_stream_data_uni: 0,
    peer_ack_delay_exponent: 3,
    // RFC 9000 section 18.2: absence of max_udp_payload_size means 65527.
    peer_maximum_udp_payload_size: 65_527,
    peer_maximum_datagram_frame_size: 0,
    peer_grease_quic_bit: False,
    peer_disabled_active_migration: False,
    estimator: estimator,
    congestion: congestion,
    pacer: pacing,
    ecn: ecn.new(),
    amplification: amplification,
    pmtu: path_mtu,
    path_validator: path_validation.new(),
    peer_connection_ids: None,
    pending_peer_stateless_reset_token: None,
    events: [],
    acknowledgements_sent: 0,
    retransmissions: 0,
    packets_coalesced: 0,
    last_activity_milliseconds: now_milliseconds,
    close_deadline_milliseconds: None,
  ))
}

/// Attach a freshly started client TLS step and apply its Initial actions.
pub fn attach_client_tls(
  state: State,
  step: engine.Step(engine.Client),
) -> Result(State, Error) {
  case state.config.role, state.tls_endpoint {
    Client, NoTlsEndpoint -> {
      let engine.Step(client, actions) = step
      apply_tls_actions(
        State(..state, tls_endpoint: ClientTlsEndpoint(client)),
        actions,
      )
    }
    _, _ -> Error(InvalidConfiguration)
  }
}

/// Attach a validated server TLS state before receiving ClientHello bytes.
pub fn attach_server_tls(
  state: State,
  server: engine.Server,
) -> Result(State, Error) {
  case state.config.role, state.tls_endpoint {
    Server, NoTlsEndpoint ->
      Ok(State(..state, tls_endpoint: ServerTlsEndpoint(server)))
    _, _ -> Error(InvalidConfiguration)
  }
}

/// Derive and install role-correct QUIC Initial packet keys from the original
/// destination connection ID. TLS never supplies keys for this level.
pub fn install_initial_keys(
  state: State,
  destination_connection_id: BitArray,
) -> Result(State, Error) {
  let length = bit_array.byte_size(destination_connection_id)
  case
    state.phase == Handshaking,
    !packet_space.is_discarded(state.initial_space),
    bit_array.bit_size(destination_connection_id) % 8 == 0,
    length >= 8 && length <= 20
  {
    False, _, _, _ | _, False, _, _ -> Error(ConnectionUnavailable)
    _, _, False, _ | _, _, _, False -> Error(InvalidInput)
    True, True, True, True ->
      case
        initial_crypto.derive_initial(
          state.config.version,
          destination_connection_id,
        )
      {
        Error(error) -> Error(InitialKeyFailure(error))
        Ok(initial_crypto.InitialKeys(_, client, server)) -> {
          let #(read, write) = case state.config.role {
            Client -> #(server, client)
            Server -> #(client, server)
          }
          Ok(
            State(
              ..state,
              initial_keys: InitialLevelKeys(Some(read), Some(write)),
            ),
          )
        }
      }
  }
}

/// Tentatively switch a client's Initial and TLS key schedule to an offered
/// compatible version. Authenticated Version Information validates the choice
/// before the handshake can complete.
pub fn negotiate_compatible_version(
  state: State,
  negotiated_version: Version,
  initial_secret_connection_id: BitArray,
) -> Result(State, Error) {
  case state.config.role, state.phase, state.tls_endpoint {
    Client, Handshaking, ClientTlsEndpoint(client) -> {
      use client <- result.try(
        engine.negotiate_client_version(client, negotiated_version)
        |> map_tls_result,
      )
      let switched =
        State(
          ..state,
          config: Config(..state.config, version: negotiated_version),
          tls_endpoint: ClientTlsEndpoint(client),
        )
      install_initial_keys(switched, initial_secret_connection_id)
    }
    _, _, _ -> Error(ConnectionUnavailable)
  }
}

/// Restart Initial protection and recovery after an authenticated Retry while
/// retaining the exact TLS ClientHello and every packet-number counter.
pub fn process_retry(
  state: State,
  retry_source_connection_id: BitArray,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let length = bit_array.byte_size(retry_source_connection_id)
  case
    state.config.role == Client
    && state.phase == Handshaking
    && !packet_space.is_discarded(state.initial_space)
    && bit_array.bit_size(retry_source_connection_id) % 8 == 0
    && length >= 8
    && length <= 20
    && now_milliseconds >= state.last_activity_milliseconds
  {
    False -> Error(ConnectionUnavailable)
    True ->
      process_valid_retry(state, retry_source_connection_id, now_milliseconds)
  }
}

fn process_valid_retry(
  state: State,
  retry_source_connection_id: BitArray,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case state.tls_endpoint {
    ClientTlsEndpoint(client) -> {
      use #(client, client_hello) <- result.try(
        engine.accept_quic_retry(client) |> map_tls_result,
      )
      use state <- result.try(reject_early_data(state))
      use initial_receive <- result.try(create_crypto_reassembler())
      use estimator <- result.try(create_rtt())
      use congestion <- result.try(create_congestion(state.config))
      use pacing <- result.try(create_pacer(state.config, now_milliseconds))
      use amplification <- result.try(create_amplification(Client))
      let restarted =
        State(
          ..state,
          tls_endpoint: ClientTlsEndpoint(client),
          initial_keys: empty_initial_keys(),
          initial_space: packet_space.reset_recovery(state.initial_space),
          handshake_space: packet_space.reset_recovery(state.handshake_space),
          application_space: packet_space.reset_recovery(
            state.application_space,
          ),
          initial_crypto_receive: initial_receive,
          initial_crypto_send_offset: bit_array.byte_size(client_hello),
          initial_queue: [frame.Crypto(0, client_hello)],
          estimator: estimator,
          congestion: congestion,
          pacer: pacing,
          ecn: ecn.new(),
          amplification: amplification,
          last_activity_milliseconds: now_milliseconds,
        )
      install_initial_keys(restarted, retry_source_connection_id)
    }
    _ -> Error(ConnectionUnavailable)
  }
}

/// Initialize the peer-issued connection-ID registry once the initial ID and
/// authenticated stateless-reset token are both known.
pub fn initialize_peer_connection_id(
  state: State,
  initial_connection_id: BitArray,
  stateless_reset_token: BitArray,
) -> Result(State, Error) {
  case state.peer_connection_ids {
    Some(_) -> Error(InvalidConfiguration)
    None -> {
      use registry <- result.try(
        connection_id.new(
          active_connection_id_limit,
          initial_connection_id,
          stateless_reset_token,
        )
        |> map_connection_id_result,
      )
      Ok(
        State(
          ..state,
          peer_connection_ids: Some(registry),
          pending_peer_stateless_reset_token: None,
        ),
      )
    }
  }
}

/// Record the authenticated sequence-zero source connection ID. A client's
/// reset token can arrive in TLS transport parameters before the packet driver
/// returns the corresponding long-header source ID, so both arrival orders are
/// supported.
pub fn observe_peer_initial_connection_id(
  state: State,
  initial_connection_id: BitArray,
) -> Result(State, Error) {
  case state.peer_connection_ids {
    Some(_) -> Error(InvalidConfiguration)
    None -> {
      let registry = case state.pending_peer_stateless_reset_token {
        Some(token) ->
          connection_id.new(
            active_connection_id_limit,
            initial_connection_id,
            token,
          )
        None ->
          connection_id.new_without_reset_token(
            active_connection_id_limit,
            initial_connection_id,
          )
      }
      use registry <- result.try(registry |> map_connection_id_result)
      Ok(
        State(
          ..state,
          peer_connection_ids: Some(registry),
          pending_peer_stateless_reset_token: None,
        ),
      )
    }
  }
}

/// Return the lowest-sequence active destination connection ID.
pub fn current_peer_connection_id(state: State) -> Result(BitArray, Error) {
  case state.peer_connection_ids {
    None -> Error(ConnectionUnavailable)
    Some(registry) ->
      case connection_id.current(registry) {
        Ok(connection_id.ConnectionId(_, value, _)) -> Ok(value)
        Error(error) -> Error(ConnectionIdFailure(error))
      }
  }
}

/// Check an undecryptable short packet for a peer stateless reset and enter
/// draining without transmitting a response when its active token matches.
pub fn handle_stateless_reset_candidate(
  state: State,
  datagram: BitArray,
  now_milliseconds: Int,
) -> Result(#(State, Bool), Error) {
  case state.peer_connection_ids, now_milliseconds >= 0 {
    _, False -> Error(InvalidInput)
    None, True -> Ok(#(state, False))
    Some(registry), True -> {
      use matched <- result.try(
        connection_id.matches_stateless_reset(registry, datagram)
        |> map_connection_id_result,
      )
      case matched {
        False -> Ok(#(state, False))
        True ->
          Ok(#(
            State(
              ..state,
              phase: Draining,
              close_deadline_milliseconds: Some(
                now_milliseconds + state.config.draining_timeout_milliseconds,
              ),
            )
              |> add_event(StatelessResetReceived),
            True,
          ))
      }
    }
  }
}

/// Ask a connected server TLS engine to issue one protected session ticket.
pub fn issue_session_ticket(
  state: State,
  ticket_key: BitArray,
  now_milliseconds: Int,
  lifetime_seconds: Int,
  permit_early_data: Bool,
) -> Result(State, Error) {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) ->
      case
        engine.issue_new_session_ticket(
          server,
          ticket_key,
          now_milliseconds,
          lifetime_seconds,
          permit_early_data,
        )
      {
        Error(error) -> Error(TlsFailure(error))
        Ok(engine.Step(server, actions)) ->
          apply_tls_actions(
            State(..state, tls_endpoint: ServerTlsEndpoint(server)),
            actions,
          )
      }
    _ -> Error(ConnectionUnavailable)
  }
}

/// Report whether this connected server can bind a ticket to a DNS origin.
pub fn can_issue_session_ticket(state: State) -> Bool {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_can_issue_session_ticket(server)
    _ -> False
  }
}

/// Replace a handshaking server's resumption policy with the listener's most
/// recent bounded anti-replay snapshot.
pub fn refresh_server_resumption_policy(
  state: State,
  policy: resumption.ServerPolicy,
) -> Result(State, Error) {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) ->
      engine.refresh_server_resumption_policy(server, policy)
      |> result.map(fn(server) {
        State(..state, tls_endpoint: ServerTlsEndpoint(server))
      })
      |> result.map_error(TlsFailure)
    _ -> Error(ConnectionUnavailable)
  }
}

/// Return only the bounded replay cache from a server TLS endpoint.
pub fn server_replay_cache(state: State) -> Option(anti_replay.Cache) {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_replay_cache(server)
    _ -> None
  }
}

/// Apply ordered TLS side effects without exposing key material to callers.
pub fn apply_tls_actions(
  state: State,
  actions: List(engine.Action),
) -> Result(State, Error) {
  case actions {
    [] -> Ok(state)
    [action, ..rest] -> {
      use state <- result.try(apply_tls_action(state, action))
      apply_tls_actions(state, rest)
    }
  }
}

/// Return whether packet protection exists at an encryption level/direction.
pub fn keys_available(
  state: State,
  level: engine.EncryptionLevel,
  direction: KeyDirection,
) -> Bool {
  case level {
    engine.Initial ->
      case direction, state.initial_keys {
        Read, InitialLevelKeys(Some(_), _) -> True
        Write, InitialLevelKeys(_, Some(_)) -> True
        _, _ -> False
      }
    engine.Handshake | engine.ZeroRtt | engine.OneRtt -> {
      let keys = traffic_keys_for_level(state, level)
      case direction, keys {
        Read, LevelKeys(Some(_), _) -> True
        Write, LevelKeys(_, Some(_)) -> True
        _, _ -> False
      }
    }
  }
}

/// Return whether an Initial or Handshake packet-number space was discarded.
pub fn packet_space_discarded(
  state: State,
  level: engine.EncryptionLevel,
) -> Bool {
  case level {
    engine.Initial -> packet_space.is_discarded(state.initial_space)
    engine.Handshake -> packet_space.is_discarded(state.handshake_space)
    engine.ZeroRtt | engine.OneRtt ->
      packet_space.is_discarded(state.application_space)
  }
}

/// Pull and clear ordered connection events.
pub fn take_events(state: State) -> #(State, List(Event)) {
  #(State(..state, events: []), state.events)
}

/// Poll ACK/control/CRYPTO/STREAM work for one protected packet.
pub fn prepare_packet(
  state: State,
  level: engine.EncryptionLevel,
  maximum_frame_data_bytes: Int,
  now_milliseconds: Int,
) -> Result(Preparation, Error) {
  case connection_can_send(state), maximum_frame_data_bytes > 0 {
    False, _ -> Error(ConnectionUnavailable)
    _, False -> Error(InvalidInput)
    True, True ->
      prepare_sendable_packet(
        state,
        level,
        maximum_frame_data_bytes,
        now_milliseconds,
      )
  }
}

/// Widen a caller's pre-validation request to the frame data one datagram
/// still carries on the validated path, after everything else this packet
/// holds has been paid for: short-header and AEAD overhead, the `coalesced`
/// bytes of the ACK frame already taken for this packet, and the data frame's
/// own header.
///
/// Only 1-RTT and 0-RTT packets are widened. DPLPMTUD raises the path MTU only
/// once a probe of that size has been acknowledged, so the result is a
/// datagram size the path has been observed to carry. Initial and Handshake
/// packets keep the caller's pre-validation request, but every level is capped
/// by the path: a caller asking for more than the path carries would otherwise
/// build an oversized datagram at that level.
fn path_frame_data_bytes(
  state: State,
  level: engine.EncryptionLevel,
  requested: Int,
  coalesced: Int,
) -> Int {
  let overhead =
    packet_protection_overhead(state, level)
    + coalesced
    + maximum_data_frame_header_bytes
  let preferred = case level {
    // Prefer a datagram the congestion window can release right now: a
    // larger one is refused by `validate_send_budget` however long it
    // waits. The caller's request stays the floor, so a window narrower
    // than that behaves exactly as it did before the path grew.
    engine.OneRtt | engine.ZeroRtt ->
      maximum(
        requested,
        congestion_window(state) - bytes_in_flight(state) - overhead,
      )
    _ -> requested
  }
  // The validated path is a hard ceiling. `pmtu` never rises above the peer's
  // authenticated max_udp_payload_size, so a packet built to this budget is
  // one the peer said it will receive. Only a coalesced acknowledgement can
  // drive this below one byte, and a packet in that state gives its frame up
  // to the acknowledgement in `fill_path_sized_packet` rather than sending it.
  maximum(1, minimum(preferred, path_mtu(state) - overhead))
}

/// The encoded size of a frame already committed to the packet being built.
fn encoded_frame_bytes(value: Option(frame.Frame)) -> Result(Int, Error) {
  case value {
    None -> Ok(0)
    Some(value) ->
      frame.encode(value)
      |> map_frame_result
      |> result.map(bit_array.byte_size)
  }
}

/// The exact encoded size of one frame the send path is about to place in a
/// packet.
///
/// Frames whose payload dominates their encoding are measured from that
/// payload and the header their type writes ahead of it, so sizing a packet
/// never encodes a large frame only to throw the bytes away. STREAM and CRYPTO
/// data is split to the remaining budget, so the largest header either can
/// write is the honest bound; a DATAGRAM frame is indivisible and is measured
/// exactly. Every other frame is small enough that encoding it is the cheapest
/// answer.
fn outgoing_frame_bytes(value: frame.Frame) -> Result(Int, Error) {
  case value {
    frame.Stream(_, _, data, _) | frame.Crypto(_, data) ->
      Ok(bit_array.byte_size(data) + maximum_data_frame_header_bytes)
    frame.Datagram(data) -> {
      let length = bit_array.byte_size(data)
      use header <- result.try(
        varint.encoded_size(length) |> result.map_error(fn(_) { InvalidInput }),
      )
      Ok(1 + header + length)
    }
    _ -> encoded_frame_bytes(Some(value))
  }
}

/// Commit a successfully constructed datagram to recovery and path accounting.
pub fn commit_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  datagram_bytes: Int,
  codepoint: ecn.Codepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case connection_can_send(state) {
    False -> Error(ConnectionUnavailable)
    True ->
      commit_sendable_packet(
        state,
        level,
        packet_number,
        frames,
        datagram_bytes,
        codepoint,
        now_milliseconds,
      )
  }
}

/// Check congestion, pacing, and anti-amplification budgets before a caller
/// transmits a protected datagram. The decision is non-mutating; a successful
/// UDP send is still recorded by `commit_packet`.
pub fn validate_send_budget(
  state: State,
  frames: List(frame.Frame),
  datagram_bytes: Int,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  case datagram_bytes > 0 && now_milliseconds >= 0 {
    False -> Error(InvalidInput)
    True -> {
      let ack_eliciting = frames_ack_eliciting(frames)
      let in_flight = ack_eliciting || frames_have_padding(frames)
      use _ <- result.try(debit_amplification(
        state.amplification,
        datagram_bytes,
      ))
      use _ <- result.try(check_and_record_congestion_send(
        state.congestion,
        datagram_bytes,
        in_flight,
      ))
      use _ <- result.try(reserve_pacing(
        state,
        datagram_bytes,
        in_flight,
        now_milliseconds,
      ))
      Ok(Nil)
    }
  }
}

/// Encode and protect one Initial, 0-RTT, or Handshake packet from transport
/// frames using keys owned by this connection.
pub fn protect_long_packet(
  state: State,
  kind: wire_packet.LongKind,
  destination_connection_id: BitArray,
  source_connection_id: BitArray,
  packet_number: Int,
  frames: List(frame.Frame),
) -> Result(BitArray, Error) {
  let level = level_for_long_kind(kind)
  use keys <- result.try(packet_keys_for(state, level, Write))
  use plaintext <- result.try(frame.encode_all(frames) |> map_frame_result)
  protect_long_payload(
    state,
    kind,
    destination_connection_id,
    source_connection_id,
    packet_number,
    packet_space.largest_acknowledged(packet_space_for_level(state, level)),
    plaintext,
    keys,
  )
}

/// Initiate an explicit 1-RTT key update after handshake confirmation and
/// after the current generation has been acknowledged.
pub fn initiate_key_update(
  state: State,
  now_milliseconds: Int,
) -> Result(State, Error) {
  use key_state <- result.try(require_key_phase(state))
  use probe_timeout <- result.try(current_probe_timeout(state))
  use key_state <- result.try(
    key_phase.initiate(
      key_state,
      packet_space.next_packet_number(state.application_space),
      now_milliseconds,
      probe_timeout,
    )
    |> map_key_phase_result,
  )
  Ok(install_key_phase_state(state, key_state, reset_usage: True))
}

/// Begin validation of a candidate address. The runtime keeps address values
/// outside the protocol state and switches paths only after `PathValidated`.
pub fn begin_path_validation(
  state: State,
  challenge: BitArray,
  active_migration: Bool,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case state.phase, active_migration && state.peer_disabled_active_migration {
    Established, True -> Error(ActiveMigrationDisabled)
    Established, False -> {
      use probe_timeout <- result.try(current_probe_timeout(state))
      use validator <- result.try(
        path_validation.start(
          state.path_validator,
          challenge,
          now_milliseconds,
          3 * probe_timeout,
        )
        |> map_path_validation_result,
      )
      Ok(
        State(..state, path_validator: validator)
        |> queue_application_frame(frame.PathChallenge(challenge)),
      )
    }
    _, _ -> Error(ConnectionUnavailable)
  }
}

/// Reserve the next exact DPLPMTUD datagram size. The runtime pads a PING
/// packet to this size and commits that exact datagram through recovery.
pub fn start_pmtu_probe(state: State) -> Result(#(State, Int), Error) {
  case state.phase {
    Established ->
      case pmtu.start_probe(state.pmtu, probe_allowance(state)) {
        Ok(#(path_mtu, size)) -> Ok(#(put_path_mtu(state, path_mtu), size))
        Error(error) -> Error(PmtuFailure(error))
      }
    _ -> Error(ConnectionUnavailable)
  }
}

/// Return the currently confirmed non-fragmenting UDP payload size.
pub fn path_mtu(state: State) -> Int {
  pmtu.current(state.pmtu)
}

/// Store a new DPLPMTUD state and keep the congestion controller sized from
/// the path its datagrams are built for.
///
/// RFC 9002 section 7.2 derives the minimum congestion window - twice
/// `max_datagram_size` - and the initial window from the datagram size. A
/// controller left at the pre-validation floor would reduce to a window
/// narrower than one datagram the validated path carries, stalling both
/// path-sized output and the DPLPMTUD probes that keep the path confirmed
/// until the window regrew. Every confirmed size is a size the controllers
/// accept, so the fallback below is unreachable; it exists only to keep this
/// total.
fn put_path_mtu(state: State, path: pmtu.State) -> State {
  State(
    ..state,
    pmtu: path,
    congestion: sized_congestion(state.congestion, pmtu.current(path)),
  )
}

fn sized_congestion(
  congestion: CongestionState,
  datagram_bytes: Int,
) -> CongestionState {
  case congestion {
    RenoState(controller) ->
      new_reno.set_maximum_datagram_size(controller, datagram_bytes)
      |> result.map(RenoState)
      |> result.unwrap(congestion)
    CubicState(controller) ->
      cubic.set_maximum_datagram_size(controller, datagram_bytes)
      |> result.map(CubicState)
      |> result.unwrap(congestion)
  }
}

/// The largest datagram DPLPMTUD may probe with right now. A probe the
/// congestion window cannot release is refused by the send budget, and one
/// that claims the whole window starves ordinary data until it is acknowledged
/// or declared lost, so a probe takes at most three quarters of what the
/// window still has free and the next probe interval retries the rest.
fn probe_allowance(state: State) -> Int {
  3 * { congestion_window(state) - bytes_in_flight(state) } / 4
}

/// Return whether DPLPMTUD has reached the authenticated path ceiling.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  pmtu.discovery_complete(state.pmtu)
}

/// Record the width of the address-validation token this endpoint writes into
/// every Initial packet, so an Initial payload is budgeted with it paid for.
///
/// The caller owns keeping this equal to the token it actually writes, and
/// owns bounding it: `driver` accepts no token wide enough to push an Initial
/// packet's protection past the 1200-byte floor.
pub fn set_initial_token_bytes(state: State, bytes: Int) -> State {
  case bytes >= 0 {
    False -> state
    True -> State(..state, initial_token_bytes: bytes)
  }
}

/// Return the next application packet number for exact-size runtime probes.
pub fn next_application_packet_number(state: State) -> Int {
  next_packet_number_for_level(state, engine.OneRtt)
}

/// Return whether candidate-path validation is still in progress.
pub fn path_validation_in_progress(state: State) -> Bool {
  path_validation.phase(state.path_validator) == path_validation.Validating
}

/// Return whether the peer permits client-selected address migration.
pub fn active_migration_available(state: State) -> Bool {
  state.phase == Established && !state.peer_disabled_active_migration
}

/// Return whether both endpoints negotiated RFC 9287 QUIC Bit greasing.
pub fn grease_quic_bit_negotiated(state: State) -> Bool {
  state.config.grease_quic_bit && state.peer_grease_quic_bit
}

/// Reset the confirmed size after repeated loss of formerly working large
/// datagrams while preserving the configured discovery ceiling.
pub fn report_pmtu_black_hole(state: State) -> State {
  put_path_mtu(state, pmtu.black_hole_detected(state.pmtu))
}

/// Encode and protect one 1-RTT short-header packet. The returned connection
/// accounts for AEAD use and any automatic key update.
pub fn protect_short_packet(
  state: State,
  destination_connection_id: BitArray,
  packet_number: Int,
  spin: Bool,
  frames: List(frame.Frame),
  now_milliseconds: Int,
) -> Result(#(State, BitArray), Error) {
  use state <- result.try(ensure_aead_write_capacity(state, now_milliseconds))
  use key_state <- result.try(require_key_phase(state))
  let keys = wire_packet.TrafficPacketKeys(key_phase.write_keys(key_state))
  let phase_bit = key_phase.phase(key_state) == key_phase.PhaseOne
  use plaintext <- result.try(frame.encode_all(frames) |> map_frame_result)
  use packet <- result.try(protect_short_payload(
    state,
    destination_connection_id,
    packet_number,
    phase_bit,
    spin,
    plaintext,
    keys,
  ))
  use usage <- result.try(record_encrypted_packet(state))
  use key_state <- result.try(
    key_phase.record_sent(key_state, packet_number) |> map_key_phase_result,
  )
  Ok(#(
    State(
      ..state,
      one_rtt_key_phase: Some(key_state),
      one_rtt_aead_usage: Some(usage),
    ),
    packet,
  ))
}

/// Authenticate, decrypt, decode, and process one long-header packet. The
/// caller records the UDP datagram exactly once before walking coalesced bytes.
pub fn receive_protected_long_packet(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(LongPacketReceipt, Error) {
  use #(kind, packet_version) <- result.try(
    wire_packet.inspect_long_with_grease(datagram, state.config.grease_quic_bit)
    |> map_wire_result,
  )
  case packet_version == state.config.version {
    False -> Error(ProtocolViolation)
    True -> {
      use receipt <- result.try(receive_versioned_long_packet(
        state,
        kind,
        datagram,
        codepoint,
        now_milliseconds,
      ))
      let LongPacketReceipt(state, destination, source, rest) = receipt
      let state = case rest {
        <<>> -> state
        _ -> State(..state, packets_coalesced: state.packets_coalesced + 1)
      }
      Ok(LongPacketReceipt(state, destination, source, rest))
    }
  }
}

/// Authenticate, decrypt, decode, and process one complete 1-RTT packet.
pub fn receive_protected_short_packet(
  state: State,
  datagram: BitArray,
  destination_connection_id_length: Int,
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(ShortPacketReceipt, Error) {
  let expected = packet_space.expected_packet_number(state.application_space)
  use decryption <- result.try(decrypt_short_packet(
    state,
    datagram,
    destination_connection_id_length,
    expected,
    now_milliseconds,
  ))
  let ShortDecryption(decoded, candidate_kind) = decryption
  use state <- result.try(apply_authenticated_key_phase(
    state,
    decoded,
    candidate_kind,
    now_milliseconds,
  ))
  let wire_packet.DecodedShort(
    destination,
    packet_number,
    key_phase,
    spin,
    plaintext,
  ) = decoded
  use frames <- result.try(
    frame.decode_all(plaintext, short_packet_frame_limits(plaintext))
    |> map_frame_result,
  )
  use state <- result.try(receive_packet(
    state,
    engine.OneRtt,
    packet_number,
    frames,
    codepoint,
    now_milliseconds,
  ))
  Ok(ShortPacketReceipt(state, destination, key_phase, spin))
}

/// Credit one UDP datagram exactly once before processing its coalesced packets.
pub fn record_datagram_received(
  state: State,
  datagram_bytes: Int,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case datagram_bytes > 0 && now_milliseconds >= 0 {
    False -> Error(InvalidInput)
    True ->
      case amplification.record_received(state.amplification, datagram_bytes) {
        Error(_) -> Error(InvalidInput)
        Ok(budget) ->
          Ok(
            State(
              ..state,
              amplification: budget,
              last_activity_milliseconds: now_milliseconds,
            ),
          )
      }
  }
}

/// Process one already authenticated packet and all decoded transport frames.
pub fn receive_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case state.phase {
    Closed | Draining -> Error(ConnectionUnavailable)
    _ ->
      receive_live_packet(
        state,
        level,
        packet_number,
        frames,
        codepoint,
        now_milliseconds,
      )
  }
}

/// Open the next locally initiated stream of one directionality class.
pub fn open_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), Error) {
  case state.phase, early_streams_available(state) {
    Established, _ | Handshaking, True ->
      open_established_stream(state, direction)
    _, _ -> Error(ConnectionUnavailable)
  }
}

/// Return whether a resumed client can emit application streams in 0-RTT.
pub fn can_send_early_data(state: State) -> Bool {
  early_streams_available(state)
}

fn early_streams_available(state: State) -> Bool {
  state.config.role == Client
  && state.phase == Handshaking
  && keys_available(state, engine.ZeroRtt, Write)
}

/// Queue bounded application bytes on an existing local send direction.
pub fn queue_stream(
  state: State,
  identifier: Int,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  case dict.get(state.streams, identifier) {
    Error(_) -> Error(UnknownStream(identifier))
    Ok(stream) ->
      case stream_state.queue_send(stream, data, fin) {
        Error(_) -> Error(StreamFailure)
        Ok(updated) ->
          Ok(
            State(
              ..state,
              streams: dict.insert(state.streams, identifier, updated),
            ),
          )
      }
  }
}

/// Abort every locally usable direction of one stream.
///
/// A bidirectional request stream emits both RESET_STREAM and STOP_SENDING,
/// immediately releases locally buffered send bytes, and asks the peer to
/// stop its response direction. Callers provide the application error code.
pub fn abort_stream(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  case
    state.phase == Established
    && application_error_code >= 0
    && application_error_code <= varint.maximum
  {
    False -> Error(ConnectionUnavailable)
    True -> abort_established_stream(state, identifier, application_error_code)
  }
}

/// Return unique stream bytes retained for sending or retransmission.
pub fn stream_buffered_send_bytes(
  state: State,
  identifier: Int,
) -> Result(Int, Error) {
  case dict.get(state.streams, identifier) {
    Error(_) -> Error(UnknownStream(identifier))
    Ok(stream) -> Ok(stream_state.buffered_send_bytes(stream))
  }
}

/// Return the largest raw QUIC DATAGRAM payload fitting both the peer's frame
/// limit and the currently confirmed path MTU. HTTP/3 callers must additionally
/// subtract their quarter-stream ID.
///
/// This is a point-in-time bound, not a stable property of the connection. It
/// rises as DPLPMTUD confirms a larger path and falls when the path is reset
/// to the pre-validation floor, and it also shrinks while an acknowledgement
/// is scheduled, because a DATAGRAM frame cannot be split and has to leave
/// room for the ACK sharing its packet -- down to half the path when the
/// retained ranges are at their most fragmented. A caller that queues against
/// a remembered value can therefore be answered with `DatagramTooLarge`; the
/// correct response is to read this again and resize, not to treat the
/// earlier value as authoritative.
pub fn maximum_datagram_data_size(state: State) -> Result(Int, Error) {
  case state.peer_maximum_datagram_frame_size {
    0 -> Error(DatagramNotNegotiated)
    _ -> {
      let frame_limit = datagram_frame_limit(state)
      datagram_payload_for_frame_limit(frame_limit, frame_limit - 2)
    }
  }
}

/// The largest QUIC DATAGRAM frame this connection may queue right now.
///
/// A DATAGRAM frame cannot be split (RFC 9221 section 3), so everything else
/// the packet carrying it holds has to be paid for before the frame is built.
/// An established connection writes a short header and coalesces the
/// acknowledgement it owes ahead of the frame; an early datagram rides a 0-RTT
/// long header, which is wider and never carries an acknowledgement (RFC 9000
/// section 17.2.3).
fn datagram_frame_limit(state: State) -> Int {
  let overhead = case state.phase {
    Established ->
      wire_packet.maximum_short_packet_overhead()
      + coalesced_ack_reservation(state)
    _ -> wire_packet.maximum_long_packet_overhead()
  }
  minimum(state.peer_maximum_datagram_frame_size, path_mtu(state) - overhead)
}

/// The bytes a 1-RTT packet keeps free for the acknowledgement it is about to
/// coalesce, and zero when none is scheduled.
///
/// A heavily fragmented range set can want more of the path than the frame
/// sharing the packet would have left, so the reservation is capped at half of
/// it. Past that the two simply do not share a packet: the send path measures
/// the finished acknowledgement, gives it the packet, and the frame follows in
/// the next one.
fn coalesced_ack_reservation(state: State) -> Int {
  minimum(
    packet_space.scheduled_ack_bytes(state.application_space),
    path_mtu(state) / 2,
  )
}

/// Queue a negotiated QUIC DATAGRAM without allowing an oversized frame into
/// the connection's bounded application queues.
pub fn queue_datagram(state: State, data: BitArray) -> Result(State, Error) {
  use encoded <- result.try(
    frame.encode(frame.Datagram(data)) |> map_frame_result,
  )
  let frame_size = bit_array.byte_size(encoded)
  let frame_limit = datagram_frame_limit(state)
  case state.peer_maximum_datagram_frame_size, state.phase {
    0, _ -> Error(DatagramNotNegotiated)
    _, _ if frame_size > frame_limit -> Error(DatagramTooLarge(frame_limit))
    _, Established -> Ok(queue_application_frame(state, frame.Datagram(data)))
    _, Handshaking -> queue_early_datagram(state, data)
    _, _ -> Error(ConnectionUnavailable)
  }
}

/// Queue an ack-eliciting PING without opening an application stream.
pub fn queue_ping(state: State) -> Result(State, Error) {
  case state.phase {
    Established -> Ok(queue_application_frame(state, frame.Ping))
    _ -> Error(ConnectionUnavailable)
  }
}

/// Queue a bounded NEW_TOKEN frame from an established server endpoint.
pub fn queue_new_token(state: State, token: BitArray) -> Result(State, Error) {
  let size = bit_array.byte_size(token)
  case
    bit_array.bit_size(token) % 8 == 0,
    size > 0 && size <= maximum_address_token_bytes,
    state.config.role,
    state.phase
  {
    False, _, _, _ | _, False, _, _ -> Error(InvalidInput)
    True, True, Server, Established ->
      Ok(queue_application_frame(state, frame.NewToken(token)))
    _, _, _, _ -> Error(ConnectionUnavailable)
  }
}

/// Change the live congestion controller while preserving bytes in flight.
pub fn set_congestion_algorithm(
  state: State,
  algorithm: CongestionAlgorithm,
) -> Result(State, Error) {
  case state.phase {
    Established -> switch_congestion_algorithm(state, algorithm)
    _ -> Error(ConnectionUnavailable)
  }
}

fn queue_early_datagram(state: State, data: BitArray) -> Result(State, Error) {
  case
    state.config.role == Client && keys_available(state, engine.ZeroRtt, Write)
  {
    False -> Error(ConnectionUnavailable)
    True ->
      Ok(
        State(
          ..state,
          zero_rtt_queue: list.append(state.zero_rtt_queue, [
            frame.Datagram(data),
          ]),
        ),
      )
  }
}

fn abort_established_stream(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  use stream <- result.try(
    dict.get(state.streams, identifier)
    |> result.replace_error(UnknownStream(identifier)),
  )
  use #(stream, reset_frames) <- result.try(reset_send_direction(
    stream,
    identifier,
    local_initiator(state),
    application_error_code,
  ))
  let stop_frames = case
    stream_id.can_receive(identifier, local_initiator(state))
  {
    True -> [frame.StopSending(identifier, application_error_code)]
    False -> []
  }
  let state =
    State(..state, streams: dict.insert(state.streams, identifier, stream))
  Ok(
    queue_application_frame_list(state, list.append(reset_frames, stop_frames))
    |> cleanup_stream_if_terminal(identifier),
  )
}

fn reset_send_direction(
  stream: stream_state.State,
  identifier: Int,
  local: stream_id.Initiator,
  application_error_code: Int,
) -> Result(#(stream_state.State, List(frame.Frame)), Error) {
  case stream_id.can_send(identifier, local) {
    False -> Ok(#(stream, []))
    True ->
      case stream_state.reset_send(stream, application_error_code) {
        Ok(#(stream, reset)) -> Ok(#(stream, [reset]))
        Error(_) -> Error(StreamFailure)
      }
  }
}

fn queue_application_frame_list(
  state: State,
  frames: List(frame.Frame),
) -> State {
  case frames {
    [] -> state
    [next, ..rest] ->
      queue_application_frame_list(queue_application_frame(state, next), rest)
  }
}

fn local_initiator(state: State) -> stream_id.Initiator {
  case state.config.role {
    Client -> stream_id.Client
    Server -> stream_id.Server
  }
}

/// Pull bounded stream data and replenish stream and connection receive credit.
pub fn read_stream(
  state: State,
  identifier: Int,
  maximum_bytes: Int,
) -> Result(#(State, stream_state.ReadOutcome), Error) {
  case dict.get(state.streams, identifier) {
    Error(_) -> Error(UnknownStream(identifier))
    Ok(stream) ->
      case stream_state.read(stream, maximum_bytes) {
        Error(_) -> Error(StreamFailure)
        Ok(outcome) -> apply_stream_read(state, identifier, outcome)
      }
  }
}

/// Extract a data event without exposing the embedded stream state.
pub fn read_data(
  outcome: stream_state.ReadOutcome,
) -> Option(#(BitArray, Bool)) {
  case outcome {
    stream_state.ReadData(_, data, finished, _) -> Some(#(data, finished))
    _ -> None
  }
}

/// Enter closing and queue an application CONNECTION_CLOSE exactly once.
pub fn close(
  state: State,
  application_error_code: Int,
  reason: String,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case
    application_error_code >= 0
    && application_error_code <= varint.maximum
    && now_milliseconds >= 0
  {
    False -> Error(InvalidInput)
    True -> close_valid(state, application_error_code, reason, now_milliseconds)
  }
}

/// Advance idle, closing, and recovery timers without consulting wall time.
pub fn tick(state: State, now_milliseconds: Int) -> Result(State, Error) {
  case now_milliseconds < state.last_activity_milliseconds {
    True -> Error(InvalidInput)
    False -> {
      let state = tick_path_validation(state, now_milliseconds)
      tick_monotonic(state, now_milliseconds)
    }
  }
}

/// Return the earliest protocol deadline without introducing periodic polls.
///
/// The owner wakes only for an ACK, recovery, validation, close, idle, or
/// pacer-release deadline. Newly queued output is flushed by the command or
/// network event that produced it, and congestion-blocked output resumes on an
/// ACK or a recovery deadline.
///
/// The pacer-release deadline is computed on every call rather than cached when
/// a packet was sent. It is asked for only while the send path still has output
/// to draw -- a queued frame, or a stream whose poll would emit -- so a
/// connection holding nothing but unacknowledged bytes arms no pacing wake. It
/// is then when the pacer would release one path-sized datagram against the
/// congestion window and smoothed round trip this state holds at
/// `now_milliseconds`, so a window that shrank, or a round trip that grew,
/// since the last send pushes the wake later instead of leaving the owner
/// holding a release it has already passed.
///
/// Sizing that datagram re-derives the acknowledgement this connection owes
/// and walks the streams the send path would draw from, so one wakeup costs
/// O(open streams + retained ACK ranges). Both are bounded by limits this
/// endpoint sets and the peer cannot raise -- `maximum_total_streams` and the
/// peer stream limits it advertises, and `maximum_ack_ranges` -- so the work
/// per wakeup has a fixed ceiling and is not worth memoising against state
/// that changes on every packet.
pub fn next_deadline(
  state: State,
  now_milliseconds: Int,
) -> Result(Option(Int), Error) {
  case now_milliseconds < state.last_activity_milliseconds, state.phase {
    True, _ -> Error(InvalidInput)
    False, Closed -> Ok(None)
    False, Closing | False, Draining -> Ok(state.close_deadline_milliseconds)
    False, Handshaking | False, Established -> {
      use initial <- result.try(packet_space_deadline(
        state,
        state.initial_space,
      ))
      use handshake <- result.try(packet_space_deadline(
        state,
        state.handshake_space,
      ))
      use application <- result.try(packet_space_deadline(
        state,
        state.application_space,
      ))
      let deadline =
        Some(
          state.last_activity_milliseconds
          + state.config.idle_timeout_milliseconds,
        )
        |> earlier_deadline(path_validation.deadline(state.path_validator))
        |> earlier_deadline(initial)
        |> earlier_deadline(handshake)
        |> earlier_deadline(application)
        |> earlier_deadline(pending_pacer_release(state, now_milliseconds))
      Ok(deadline)
    }
  }
}

/// Return stable connection progress.
pub fn phase(state: State) -> Phase {
  state.phase
}

/// Return whether this established client selected an offered TLS ticket.
pub fn client_resumed(state: State) -> Bool {
  case state.tls_endpoint {
    ClientTlsEndpoint(client) -> engine.client_resumed(client)
    _ -> False
  }
}

/// Return the authenticated ALPN selection for either endpoint role.
pub fn application_protocol(state: State) -> Option(BitArray) {
  case state.tls_endpoint {
    ClientTlsEndpoint(client) -> engine.client_application_protocol(client)
    ServerTlsEndpoint(server) -> engine.server_application_protocol(server)
    NoTlsEndpoint -> None
  }
}

/// Return the authenticated TLS cipher selection without exposing keys.
pub fn cipher_suite(state: State) -> Option(hello.CipherSuite) {
  case state.tls_endpoint {
    ClientTlsEndpoint(client) -> engine.client_cipher_suite(client)
    ServerTlsEndpoint(server) -> engine.server_cipher_suite(server)
    NoTlsEndpoint -> None
  }
}

/// Return whether an established server connection selected a ticket.
pub fn server_resumed(state: State) -> Bool {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_resumed(server)
    _ -> False
  }
}

/// Return the path- and signature-verified client certificate identity.
pub fn server_client_identity(
  state: State,
) -> Option(authentication.VerifiedPeer) {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_client_identity(server)
    _ -> None
  }
}

/// Return whether replay-guarded early data was accepted by this server.
pub fn server_early_data_accepted(state: State) -> Bool {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_early_data_accepted(server)
    _ -> False
  }
}

/// Return whether this server peer offered early data.
pub fn server_early_data_attempted(state: State) -> Bool {
  case state.tls_endpoint {
    ServerTlsEndpoint(server) -> engine.server_early_data_attempted(server)
    _ -> False
  }
}

/// Return the number of transport streams still retaining live state.
pub fn active_stream_count(state: State) -> Int {
  dict.size(state.streams)
}

/// Return outstanding congestion-controlled bytes on the active path.
pub fn bytes_in_flight(state: State) -> Int {
  case state.congestion {
    RenoState(reno) -> new_reno.bytes_in_flight(reno)
    CubicState(cubic_state) -> cubic.bytes_in_flight(cubic_state)
  }
}

/// Return the active path's congestion window in bytes.
pub fn congestion_window(state: State) -> Int {
  case state.congestion {
    RenoState(reno) -> new_reno.congestion_window(reno)
    CubicState(cubic_state) -> cubic.congestion_window(cubic_state)
  }
}

/// Snapshot RTT and congestion state without exposing controller internals.
pub fn path_snapshot(state: State) -> PathSnapshot {
  let rtt.Snapshot(latest, smoothed, variation, minimum_rtt) =
    rtt.snapshot(state.estimator)
  let #(window, in_flight, recovery) = case state.congestion {
    RenoState(reno) -> {
      let new_reno.Snapshot(window, in_flight, phase) = new_reno.snapshot(reno)
      #(window, in_flight, case phase {
        new_reno.Recovery -> True
        _ -> False
      })
    }
    CubicState(cubic_state) -> {
      let cubic.Snapshot(window, in_flight, phase) = cubic.snapshot(cubic_state)
      #(window, in_flight, case phase {
        cubic.Recovery -> True
        _ -> False
      })
    }
  }
  PathSnapshot(
    latest,
    smoothed,
    minimum_rtt,
    variation,
    window,
    in_flight,
    recovery,
    in_flight >= window,
  )
}

/// Snapshot ACK, loss-retransmission, and packet-coalescing counters.
pub fn connection_counters(state: State) -> ConnectionCounters {
  ConnectionCounters(
    state.acknowledgements_sent,
    state.retransmissions,
    state.packets_coalesced,
  )
}

fn validate_config(
  config: Config,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    now_milliseconds >= 0
    && config.maximum_ack_delay_milliseconds >= 0
    && config.maximum_ack_ranges > 0
    && config.maximum_outstanding_packets > 0
    && config.maximum_stream_receive_buffer >= 0
    && config.maximum_stream_send_buffer >= 0
    && config.maximum_total_streams > 0
    && config.maximum_udp_payload_size >= minimum_datagram_bytes
    && config.maximum_udp_payload_size <= maximum_udp_payload_size
    && config.maximum_datagram_frame_size >= 0
    && config.idle_timeout_milliseconds > 0
    && config.draining_timeout_milliseconds > 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  }
}

fn create_packet_space(
  kind: packet_space.Kind,
  config: Config,
) -> Result(packet_space.State, Error) {
  case
    packet_space.new(
      kind,
      config.maximum_ack_delay_milliseconds,
      config.maximum_ack_ranges,
      config.maximum_outstanding_packets,
    )
  {
    Ok(space) -> Ok(space)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_crypto_reassembler() -> Result(reassembler.Reassembler, Error) {
  case reassembler.new(maximum_crypto_buffer_bytes, maximum_crypto_offset) {
    Ok(state) -> Ok(state)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_receiver(
  initial: Int,
  window: Int,
  maximum: Int,
) -> Result(flow_control.Receiver, Error) {
  case flow_control.new_receiver(initial, window, maximum) {
    Ok(receiver) -> Ok(receiver)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_sender(initial: Int) -> Result(flow_control.Sender, Error) {
  case flow_control.new_sender(initial) {
    Ok(sender) -> Ok(sender)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_stream_limit(limit: Int) -> Result(flow_control.StreamLimit, Error) {
  case flow_control.new_stream_limit(limit) {
    Ok(stream_limit) -> Ok(stream_limit)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_rtt() -> Result(rtt.Estimator, Error) {
  case rtt.new(333) {
    Ok(estimator) -> Ok(estimator)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_congestion(config: Config) -> Result(CongestionState, Error) {
  case config.congestion_algorithm {
    NewReno ->
      case new_reno.new(minimum_datagram_bytes) {
        Ok(state) -> Ok(RenoState(state))
        Error(_) -> Error(InvalidConfiguration)
      }
    Cubic ->
      case cubic.new(minimum_datagram_bytes) {
        Ok(state) -> Ok(CubicState(state))
        Error(_) -> Error(InvalidConfiguration)
      }
  }
}

fn create_pacer(_config: Config, now: Int) -> Result(pacer.State, Error) {
  case pacer.new(pacer_burst_datagrams * minimum_datagram_bytes, now) {
    Ok(state) -> Ok(state)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_amplification(role: Role) -> Result(amplification.Budget, Error) {
  let amplification_role = case role {
    Client -> amplification.Client
    Server -> amplification.Server
  }
  case amplification.new(amplification_role) {
    Ok(state) -> Ok(state)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn create_pmtu(maximum: Int) -> Result(pmtu.State, Error) {
  case pmtu.new(maximum) {
    Ok(state) -> Ok(state)
    Error(_) -> Error(InvalidConfiguration)
  }
}

fn level_for_long_kind(kind: wire_packet.LongKind) -> engine.EncryptionLevel {
  case kind {
    wire_packet.Initial(_) -> engine.Initial
    wire_packet.ZeroRtt -> engine.ZeroRtt
    wire_packet.Handshake -> engine.Handshake
  }
}

fn packet_keys_for(
  state: State,
  level: engine.EncryptionLevel,
  direction: KeyDirection,
) -> Result(wire_packet.PacketKeys, Error) {
  case level {
    engine.Initial -> initial_packet_keys_for(state.initial_keys, direction)
    engine.Handshake | engine.ZeroRtt | engine.OneRtt ->
      traffic_packet_keys_for(
        traffic_keys_for_level(state, level),
        level,
        direction,
      )
  }
}

fn initial_packet_keys_for(
  keys: InitialLevelKeys,
  direction: KeyDirection,
) -> Result(wire_packet.PacketKeys, Error) {
  case keys, direction {
    InitialLevelKeys(Some(keys), _), Read ->
      Ok(wire_packet.InitialPacketKeys(keys))
    InitialLevelKeys(_, Some(keys)), Write ->
      Ok(wire_packet.InitialPacketKeys(keys))
    _, Read -> Error(MissingReadKeys(engine.Initial))
    _, Write -> Error(MissingWriteKeys(engine.Initial))
  }
}

fn traffic_packet_keys_for(
  keys: LevelKeys,
  level: engine.EncryptionLevel,
  direction: KeyDirection,
) -> Result(wire_packet.PacketKeys, Error) {
  case keys, direction {
    LevelKeys(Some(keys), _), Read -> Ok(wire_packet.TrafficPacketKeys(keys))
    LevelKeys(_, Some(keys)), Write -> Ok(wire_packet.TrafficPacketKeys(keys))
    _, Read -> Error(MissingReadKeys(level))
    _, Write -> Error(MissingWriteKeys(level))
  }
}

fn require_key_phase(state: State) -> Result(key_phase.State, Error) {
  case state.one_rtt_key_phase {
    Some(key_state) -> Ok(key_state)
    None -> Error(MissingWriteKeys(engine.OneRtt))
  }
}

fn current_probe_timeout(state: State) -> Result(Int, Error) {
  case
    rtt.probe_timeout(
      state.estimator,
      state.config.maximum_ack_delay_milliseconds,
      True,
      packet_space.probe_timeout_count(state.application_space),
      timer_granularity_milliseconds,
    )
  {
    Ok(timeout) -> Ok(timeout)
    Error(_) -> Error(PacketSpaceFailure)
  }
}

fn packet_space_deadline(
  state: State,
  space: packet_space.State,
) -> Result(Option(Int), Error) {
  use recovery_deadline <- result.try(
    packet_space.timer_deadline(
      space,
      state.estimator,
      state.handshake_confirmed,
      timer_granularity_milliseconds,
    )
    |> result.map_error(fn(_) { PacketSpaceFailure }),
  )
  Ok(earlier_deadline(recovery_deadline, packet_space.ack_deadline(space)))
}

/// Report when the pacer would release this connection's next datagram.
///
/// The reservation the pacer returns is deliberately discarded: this asks a
/// question about the datagram the send path would build rather than claiming
/// budget for one. The size it asks about is an upper bound on that datagram
/// rather than the whole path: the send path commits the datagram it actually
/// built, so a wake armed for a path-sized one would sleep through the instant
/// a small write became sendable, while a wake armed for less than the send
/// path builds would fire while the pacer still refuses it. `None` means no
/// pacing wake is owed: either nothing is waiting to be sent, or the pacer
/// would release that datagram immediately.
fn pending_pacer_release(state: State, now_milliseconds: Int) -> Option(Int) {
  case has_pending_output(state) {
    False -> None
    True ->
      case ask_pacer(state, pending_datagram_bytes(state), now_milliseconds) {
        Ok(pacer.Decision(_, pacer.WaitUntil(deadline))) -> Some(deadline)
        Ok(pacer.Decision(_, pacer.SendNow)) -> None
        // The pacer declines to answer for a datagram larger than one burst,
        // which it could never release either, and for a clock behind its own
        // last reservation. Neither is a release this owner can wait for.
        Error(pacer.InvalidInput) -> None
      }
  }
}

/// An upper bound on the datagram the send path would build from the output
/// waiting right now.
///
/// One packet carries at most the acknowledgement this connection owes and one
/// frame drawn from a queue or a stream, so the bound is the largest of those
/// candidates plus what packet protection costs - and never more than the path
/// itself, which is the ceiling every datagram is built to.
fn pending_datagram_bytes(state: State) -> Int {
  let frame_bytes =
    [
      state.initial_queue,
      state.handshake_queue,
      state.zero_rtt_queue,
      state.application_queue,
    ]
    |> list.fold(pending_stream_bytes(state), fn(largest, queue) {
      maximum(largest, queue_head_bytes(queue))
    })
  minimum(
    path_mtu(state),
    frame_bytes
      + coalesced_ack_reservation(state)
      + wire_packet.maximum_short_packet_overhead(),
  )
}

/// The size of the frame at the head of one queue, which is the only frame the
/// send path draws from it. A frame whose encoding fails is charged the whole
/// pre-validation floor rather than being counted as free.
fn queue_head_bytes(queue: List(frame.Frame)) -> Int {
  case queue {
    [] -> 0
    [value, ..] ->
      outgoing_frame_bytes(value) |> result.unwrap(minimum_datagram_bytes)
  }
}

/// The most stream data one packet could draw: the bytes the widest sendable
/// stream still retains, plus the header a STREAM frame writes ahead of them.
///
/// Retained bytes include those already sent and awaiting acknowledgement, so
/// this over-states rather than under-states what the poll would emit, which
/// is the side a pacing wake has to err on.
fn pending_stream_bytes(state: State) -> Int {
  list.fold(state.stream_order, 0, fn(largest, identifier) {
    case dict.get(state.streams, identifier) {
      Error(Nil) -> largest
      Ok(stream) ->
        case stream_would_emit(stream) {
          False -> largest
          True ->
            maximum(
              largest,
              stream_state.buffered_send_bytes(stream)
                + maximum_data_frame_header_bytes,
            )
        }
    }
  })
}

/// Report whether the send path would still draw a frame from this connection.
///
/// These are the two sources it draws from: the per-level frame queues, and the
/// streams in send order. A stream counts only when the very poll the send path
/// performs would produce a frame -- a retransmission, fresh bytes, an unsent
/// FIN, or the STREAM_DATA_BLOCKED a credit-starved stream emits. Bytes already
/// sent and awaiting acknowledgment are not output, which is why this asks the
/// poll rather than reading a buffered-byte count. Acknowledgements are not
/// paced and carry their own packet-space deadlines, so they are deliberately
/// not counted here.
///
/// Walking `stream_order` rather than the stream dictionary keeps the search
/// short-circuiting and allocation-free, since it runs on every deadline query.
fn has_pending_output(state: State) -> Bool {
  state.initial_queue != []
  || state.handshake_queue != []
  || state.zero_rtt_queue != []
  || state.application_queue != []
  || list.any(state.stream_order, fn(identifier) {
    case dict.get(state.streams, identifier) {
      Ok(stream) -> stream_would_emit(stream)
      Error(Nil) -> False
    }
  })
}

/// Report whether polling this stream would yield a frame to send.
///
/// The polled stream state is discarded: this asks the send path's own question
/// without taking the bytes an answer would consume. One byte is offered
/// because the question is whether anything at all is left, not how much fits.
/// A stream the local endpoint cannot send on has nothing to contribute.
fn stream_would_emit(stream: stream_state.State) -> Bool {
  case stream_state.poll_send(stream, 1) {
    Ok(stream_state.Emit(_, _)) | Ok(stream_state.SendBlocked(_, _)) -> True
    Ok(stream_state.SendIdle(_)) -> False
    // `WrongDirection` is the only refusal a one-byte poll can raise, and a
    // stream the local endpoint cannot send on has nothing to wake for. A
    // refusal for any other reason is a fault the send path reports on its
    // next flush, so it counts as output rather than being hidden here.
    Error(reason) -> reason != stream_state.WrongDirection
  }
}

fn earlier_deadline(first: Option(Int), second: Option(Int)) -> Option(Int) {
  case first, second {
    None, deadline | deadline, None -> deadline
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn install_key_phase_state(
  state: State,
  key_state: key_phase.State,
  reset_usage reset_usage: Bool,
) -> State {
  let usage = case state.one_rtt_aead_usage, reset_usage {
    Some(usage), True -> Some(aead_usage.reset_encryption(usage))
    usage, _ -> usage
  }
  State(
    ..state,
    one_rtt_keys: LevelKeys(
      Some(key_phase.read_keys(key_state)),
      Some(key_phase.write_keys(key_state)),
    ),
    one_rtt_key_phase: Some(key_state),
    one_rtt_aead_usage: usage,
  )
}

fn ensure_aead_write_capacity(
  state: State,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case state.one_rtt_aead_usage {
    None -> Error(MissingWriteKeys(engine.OneRtt))
    Some(usage) ->
      case aead_usage.needs_key_update(usage) {
        True -> initiate_key_update(state, now_milliseconds)
        False -> Ok(state)
      }
  }
}

fn record_encrypted_packet(state: State) -> Result(aead_usage.Usage, Error) {
  case state.one_rtt_aead_usage {
    None -> Error(MissingWriteKeys(engine.OneRtt))
    Some(usage) -> aead_usage.record_encrypted(usage) |> map_aead_usage_result
  }
}

fn decrypt_short_packet(
  state: State,
  datagram: BitArray,
  destination_connection_id_length: Int,
  expected_packet_number: Int,
  now_milliseconds: Int,
) -> Result(ShortDecryption, Error) {
  use key_state <- result.try(require_key_phase(state))
  try_short_candidates(
    key_phase.decryption_candidates(key_state, now_milliseconds),
    datagram,
    destination_connection_id_length,
    expected_packet_number,
    state.config.grease_quic_bit,
    None,
  )
}

fn try_short_candidates(
  candidates: List(key_phase.ReadCandidate),
  datagram: BitArray,
  destination_connection_id_length: Int,
  expected_packet_number: Int,
  accept_greased_quic_bit: Bool,
  last_error: Option(wire_packet.Error),
) -> Result(ShortDecryption, Error) {
  case candidates {
    [] ->
      case last_error {
        Some(error) -> Error(WirePacketFailure(error))
        None -> Error(WirePacketFailure(wire_packet.AuthenticationFailed))
      }
    [candidate, ..rest] -> {
      let keys =
        wire_packet.TrafficPacketKeys(key_phase.candidate_keys(candidate))
      case
        wire_packet.unprotect_short_with_grease(
          datagram,
          destination_connection_id_length,
          expected_packet_number,
          keys,
          accept_greased_quic_bit,
        )
      {
        Ok(decoded) ->
          Ok(ShortDecryption(decoded, key_phase.candidate_kind(candidate)))
        Error(error) ->
          try_short_candidates(
            rest,
            datagram,
            destination_connection_id_length,
            expected_packet_number,
            accept_greased_quic_bit,
            Some(error),
          )
      }
    }
  }
}

fn apply_authenticated_key_phase(
  state: State,
  decoded: wire_packet.DecodedShort,
  candidate_kind: key_phase.CandidateKind,
  now_milliseconds: Int,
) -> Result(State, Error) {
  use key_state <- result.try(require_key_phase(state))
  let wire_packet.DecodedShort(_, packet_number, phase_bit, _, _) = decoded
  let observed_phase = case phase_bit {
    False -> key_phase.PhaseZero
    True -> key_phase.PhaseOne
  }
  let allowed =
    key_phase.read_candidates(
      key_state,
      observed_phase,
      packet_number,
      now_milliseconds,
    )
  case candidate_kind_is_allowed(allowed, candidate_kind) {
    False -> Error(ProtocolViolation)
    True ->
      transition_authenticated_key_phase(
        state,
        key_state,
        observed_phase,
        packet_number,
        candidate_kind,
        now_milliseconds,
      )
  }
}

fn candidate_kind_is_allowed(
  candidates: List(key_phase.ReadCandidate),
  expected: key_phase.CandidateKind,
) -> Bool {
  list.any(candidates, fn(candidate) {
    key_phase.candidate_kind(candidate) == expected
  })
}

fn transition_authenticated_key_phase(
  state: State,
  key_state: key_phase.State,
  observed_phase: key_phase.KeyPhase,
  packet_number: Int,
  candidate_kind: key_phase.CandidateKind,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case candidate_kind {
    key_phase.Current -> {
      use key_state <- result.try(
        key_phase.record_received(key_state, packet_number)
        |> map_key_phase_result,
      )
      Ok(install_key_phase_state(state, key_state, reset_usage: False))
    }
    key_phase.Previous -> Ok(state)
    key_phase.Next -> {
      use probe_timeout <- result.try(current_probe_timeout(state))
      use key_state <- result.try(
        key_phase.commit_peer_update(
          key_state,
          observed_phase,
          packet_number,
          now_milliseconds,
          probe_timeout,
        )
        |> map_key_phase_result,
      )
      Ok(install_key_phase_state(state, key_state, reset_usage: True))
    }
  }
}

fn protect_long_payload(
  state: State,
  kind: wire_packet.LongKind,
  destination_connection_id: BitArray,
  source_connection_id: BitArray,
  packet_number: Int,
  largest_acknowledged: Option(Int),
  plaintext: BitArray,
  keys: wire_packet.PacketKeys,
) -> Result(BitArray, Error) {
  let protected =
    wire_packet.protect_long_with_grease(
      kind,
      state.config.version,
      destination_connection_id,
      source_connection_id,
      packet_number,
      largest_acknowledged,
      plaintext,
      keys,
      state.peer_grease_quic_bit,
    )
  case protected {
    Error(wire_packet.InsufficientHeaderProtectionSample) ->
      wire_packet.protect_long_with_grease(
        kind,
        state.config.version,
        destination_connection_id,
        source_connection_id,
        packet_number,
        largest_acknowledged,
        <<plaintext:bits, 0, 0, 0>>,
        keys,
        state.peer_grease_quic_bit,
      )
      |> map_wire_result
    _ -> protected |> map_wire_result
  }
}

fn protect_short_payload(
  state: State,
  destination_connection_id: BitArray,
  packet_number: Int,
  key_phase: Bool,
  spin: Bool,
  plaintext: BitArray,
  keys: wire_packet.PacketKeys,
) -> Result(BitArray, Error) {
  let largest_acknowledged =
    packet_space.largest_acknowledged(state.application_space)
  let protected =
    wire_packet.protect_short_with_grease(
      destination_connection_id,
      packet_number,
      largest_acknowledged,
      key_phase,
      spin,
      plaintext,
      keys,
      state.peer_grease_quic_bit,
    )
  case protected {
    Error(wire_packet.InsufficientHeaderProtectionSample) ->
      wire_packet.protect_short_with_grease(
        destination_connection_id,
        packet_number,
        largest_acknowledged,
        key_phase,
        spin,
        <<plaintext:bits, 0, 0, 0>>,
        keys,
        state.peer_grease_quic_bit,
      )
      |> map_wire_result
    _ -> protected |> map_wire_result
  }
}

fn receive_versioned_long_packet(
  state: State,
  inspected_kind: wire_packet.LongKind,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(LongPacketReceipt, Error) {
  let level = level_for_long_kind(inspected_kind)
  use keys <- result.try(packet_keys_for(state, level, Read))
  let expected =
    packet_space.expected_packet_number(packet_space_for_level(state, level))
  use decoded <- result.try(
    wire_packet.unprotect_long_with_grease(
      datagram,
      expected,
      keys,
      state.config.grease_quic_bit,
    )
    |> map_wire_result,
  )
  finish_long_packet(
    state,
    inspected_kind,
    level,
    decoded,
    codepoint,
    now_milliseconds,
  )
}

fn finish_long_packet(
  state: State,
  inspected_kind: wire_packet.LongKind,
  level: engine.EncryptionLevel,
  decoded: wire_packet.DecodedLong,
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(LongPacketReceipt, Error) {
  let wire_packet.DecodedLong(
    decoded_kind,
    packet_version,
    destination,
    source,
    packet_number,
    plaintext,
    rest,
  ) = decoded
  case
    decoded_kind == inspected_kind && packet_version == state.config.version
  {
    False -> Error(ProtocolViolation)
    True ->
      process_long_plaintext(
        state,
        level,
        destination,
        source,
        packet_number,
        plaintext,
        rest,
        codepoint,
        now_milliseconds,
      )
  }
}

fn process_long_plaintext(
  state: State,
  level: engine.EncryptionLevel,
  destination: BitArray,
  source: BitArray,
  packet_number: Int,
  plaintext: BitArray,
  rest: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(LongPacketReceipt, Error) {
  // Long-header packets keep the fixed default budget. Initial keys are
  // derivable from a connection ID any off-path sender can observe, so this
  // decode is unauthenticated work; what this endpoint advertises as
  // max_udp_payload_size must not widen it.
  use frames <- result.try(
    frame.decode_all(plaintext, frame.default_limits()) |> map_frame_result,
  )
  use state <- result.try(receive_packet(
    state,
    level,
    packet_number,
    frames,
    codepoint,
    now_milliseconds,
  ))
  Ok(LongPacketReceipt(state, destination, source, rest))
}

fn empty_keys() -> LevelKeys {
  LevelKeys(None, None)
}

fn empty_initial_keys() -> InitialLevelKeys {
  InitialLevelKeys(None, None)
}

fn connection_can_send(state: State) -> Bool {
  state.phase != Closed && state.phase != Draining
}

fn apply_tls_action(
  state: State,
  action: engine.Action,
) -> Result(State, Error) {
  case action {
    engine.Send(level, bytes) -> queue_crypto(state, level, bytes)
    engine.InstallWriteKeys(engine.Initial, _)
    | engine.InstallReadKeys(engine.Initial, _) -> Error(InvalidConfiguration)
    engine.InstallWriteKeys(level, keys) ->
      install_traffic_keys(state, level, Write, keys)
    engine.InstallReadKeys(level, keys) ->
      install_traffic_keys(state, level, Read, keys)
    engine.DiscardKeys(level) -> Ok(discard_level(state, level))
    engine.PeerTransportParameters(parameters) ->
      apply_peer_parameters(state, parameters)
      |> result.map(add_event(_, PeerParametersApplied))
    engine.EarlyDataAccepted ->
      Ok(
        State(..state, early_data_accepted: True)
        |> add_event(EarlyDataWasAccepted),
      )
    engine.EarlyDataRejected ->
      reject_early_data(state)
      |> result.map(add_event(_, EarlyDataWasRejected))
    engine.StoreSessionTicket(ticket) ->
      Ok(add_event(state, SessionTicketStored(ticket)))
    engine.HandshakeComplete -> {
      let confirmed = case state.config.role {
        Server -> True
        Client -> state.handshake_confirmed
      }
      let budget = case state.config.role {
        Server -> amplification.validate(state.amplification)
        Client -> state.amplification
      }
      let state =
        State(
          ..state,
          phase: Established,
          handshake_confirmed: confirmed,
          amplification: budget,
        )
      let state = case state.config.role {
        Server -> queue_application_frame(state, frame.HandshakeDone)
        Client -> state
      }
      let state = case confirmed {
        True -> confirm_key_phase(state)
        False -> state
      }
      Ok(add_event(state, HandshakeEstablished))
    }
  }
}

fn reject_early_data(state: State) -> Result(State, Error) {
  let packets = packet_space.outstanding_packets(state.application_space)
  use state <- result.try(requeue_rejected_packets(state, packets))
  use state <- result.try(requeue_lost_frames(
    state,
    engine.OneRtt,
    state.zero_rtt_queue,
  ))
  use congestion <- result.try(abandon_early_congestion(
    state.congestion,
    in_flight_packet_bytes(packets, 0),
  ))
  Ok(
    State(
      ..state,
      early_data_accepted: False,
      zero_rtt_queue: [],
      zero_rtt_keys: empty_keys(),
      application_space: packet_space.reset_recovery(state.application_space),
      congestion: congestion,
    ),
  )
}

fn requeue_rejected_packets(
  state: State,
  packets: List(packet_space.SentPacket),
) -> Result(State, Error) {
  case packets {
    [] -> Ok(state)
    [packet, ..rest] -> {
      use state <- result.try(requeue_lost_frames(
        state,
        engine.OneRtt,
        packet.frames,
      ))
      requeue_rejected_packets(state, rest)
    }
  }
}

fn in_flight_packet_bytes(
  packets: List(packet_space.SentPacket),
  total: Int,
) -> Int {
  case packets {
    [] -> total
    [packet, ..rest] ->
      in_flight_packet_bytes(rest, case packet.in_flight {
        True -> total + packet.sent_bytes
        False -> total
      })
  }
}

fn abandon_early_congestion(
  congestion: CongestionState,
  bytes: Int,
) -> Result(CongestionState, Error) {
  case congestion {
    RenoState(state) ->
      new_reno.abandon_in_flight(state, bytes)
      |> result.map(RenoState)
      |> result.replace_error(InvalidInput)
    CubicState(state) ->
      cubic.abandon_in_flight(state, bytes)
      |> result.map(CubicState)
      |> result.replace_error(InvalidInput)
  }
}

fn add_event(state: State, event: Event) -> State {
  State(..state, events: list.append(state.events, [event]))
}

fn traffic_keys_for_level(
  state: State,
  level: engine.EncryptionLevel,
) -> LevelKeys {
  case level {
    engine.Initial -> empty_keys()
    engine.Handshake -> state.handshake_keys
    engine.ZeroRtt -> state.zero_rtt_keys
    engine.OneRtt -> state.one_rtt_keys
  }
}

fn put_traffic_keys(
  state: State,
  level: engine.EncryptionLevel,
  direction: KeyDirection,
  keys: Option(traffic_keys.TrafficKeys),
) -> State {
  let updated =
    update_level_keys(traffic_keys_for_level(state, level), direction, keys)
  case level {
    engine.Initial -> state
    engine.Handshake -> State(..state, handshake_keys: updated)
    engine.ZeroRtt -> State(..state, zero_rtt_keys: updated)
    engine.OneRtt -> State(..state, one_rtt_keys: updated)
  }
}

fn install_traffic_keys(
  state: State,
  level: engine.EncryptionLevel,
  direction: KeyDirection,
  keys: traffic_keys.TrafficKeys,
) -> Result(State, Error) {
  let state = put_traffic_keys(state, level, direction, Some(keys))
  case level {
    engine.OneRtt -> initialize_key_phase_if_ready(state)
    engine.Initial | engine.Handshake | engine.ZeroRtt -> Ok(state)
  }
}

fn initialize_key_phase_if_ready(state: State) -> Result(State, Error) {
  case state.one_rtt_keys {
    LevelKeys(Some(read), Some(write)) -> {
      use key_state <- result.try(
        key_phase.new(write, read) |> map_key_phase_result,
      )
      let key_state = case state.handshake_confirmed {
        True -> key_phase.confirm_handshake(key_state)
        False -> key_state
      }
      use usage <- result.try(
        aead_usage.new(write.cipher_suite) |> map_aead_usage_result,
      )
      Ok(
        State(
          ..state,
          one_rtt_key_phase: Some(key_state),
          one_rtt_aead_usage: Some(usage),
        ),
      )
    }
    _ -> Ok(state)
  }
}

fn confirm_key_phase(state: State) -> State {
  case state.one_rtt_key_phase {
    None -> state
    Some(key_state) ->
      State(
        ..state,
        one_rtt_key_phase: Some(key_phase.confirm_handshake(key_state)),
      )
  }
}

fn update_level_keys(
  current: LevelKeys,
  direction: KeyDirection,
  keys: Option(traffic_keys.TrafficKeys),
) -> LevelKeys {
  case current, direction {
    LevelKeys(_, write), Read -> LevelKeys(keys, write)
    LevelKeys(read, _), Write -> LevelKeys(read, keys)
  }
}

fn discard_level(state: State, level: engine.EncryptionLevel) -> State {
  case level {
    engine.Initial ->
      State(
        ..state,
        initial_keys: empty_initial_keys(),
        initial_space: packet_space.discard(state.initial_space),
        initial_queue: [],
      )
    engine.Handshake -> {
      let state =
        put_traffic_keys(
          put_traffic_keys(state, level, Read, None),
          level,
          Write,
          None,
        )
      State(
        ..state,
        handshake_space: packet_space.discard(state.handshake_space),
        handshake_queue: [],
      )
    }
    engine.ZeroRtt ->
      State(
        ..put_traffic_keys(
          put_traffic_keys(state, level, Read, None),
          level,
          Write,
          None,
        ),
        zero_rtt_queue: [],
      )
    engine.OneRtt -> {
      let state =
        put_traffic_keys(
          put_traffic_keys(state, level, Read, None),
          level,
          Write,
          None,
        )
      State(
        ..state,
        one_rtt_key_phase: None,
        one_rtt_aead_usage: None,
        application_space: packet_space.discard(state.application_space),
        application_queue: [],
      )
    }
  }
}

fn queue_crypto(
  state: State,
  level: engine.EncryptionLevel,
  bytes: BitArray,
) -> Result(State, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(InvalidInput)
    _ -> queue_aligned_crypto(state, level, bytes)
  }
}

fn queue_aligned_crypto(
  state: State,
  level: engine.EncryptionLevel,
  bytes: BitArray,
) -> Result(State, Error) {
  let length = bit_array.byte_size(bytes)
  case level {
    engine.Initial -> {
      let end = state.initial_crypto_send_offset + length
      case end > maximum_crypto_offset {
        True -> Error(InvalidInput)
        False ->
          Ok(
            State(
              ..state,
              initial_crypto_send_offset: end,
              initial_queue: list.append(state.initial_queue, [
                frame.Crypto(state.initial_crypto_send_offset, bytes),
              ]),
            ),
          )
      }
    }
    engine.Handshake -> {
      let end = state.handshake_crypto_send_offset + length
      case end > maximum_crypto_offset {
        True -> Error(InvalidInput)
        False ->
          Ok(
            State(
              ..state,
              handshake_crypto_send_offset: end,
              handshake_queue: list.append(state.handshake_queue, [
                frame.Crypto(state.handshake_crypto_send_offset, bytes),
              ]),
            ),
          )
      }
    }
    engine.OneRtt -> {
      let end = state.application_crypto_send_offset + length
      case end > maximum_crypto_offset {
        True -> Error(InvalidInput)
        False ->
          Ok(
            State(
              ..state,
              application_crypto_send_offset: end,
              application_queue: list.append(state.application_queue, [
                frame.Crypto(state.application_crypto_send_offset, bytes),
              ]),
            ),
          )
      }
    }
    engine.ZeroRtt -> Error(ProtocolViolation)
  }
}

fn apply_peer_parameters(
  state: State,
  parameters: List(transport_parameter.Parameter),
) -> Result(State, Error) {
  case parameters {
    [] -> Ok(state)
    [parameter, ..rest] -> {
      use state <- result.try(apply_peer_parameter(state, parameter))
      apply_peer_parameters(state, rest)
    }
  }
}

fn apply_peer_parameter(
  state: State,
  parameter: transport_parameter.Parameter,
) -> Result(State, Error) {
  case parameter {
    transport_parameter.StatelessResetToken(token) ->
      case state.peer_connection_ids {
        None ->
          Ok(State(..state, pending_peer_stateless_reset_token: Some(token)))
        Some(registry) -> {
          use registry <- result.try(
            connection_id.set_initial_reset_token(registry, token)
            |> map_connection_id_result,
          )
          Ok(
            State(
              ..state,
              peer_connection_ids: Some(registry),
              pending_peer_stateless_reset_token: None,
            ),
          )
        }
      }
    transport_parameter.InitialMaxData(limit) ->
      Ok(
        State(
          ..state,
          connection_sender: flow_control.update_sender_limit(
            state.connection_sender,
            limit,
          ),
        ),
      )
    transport_parameter.InitialMaxStreamDataBidiLocal(limit) ->
      Ok(State(..state, peer_stream_data_bidi_local: limit))
    transport_parameter.InitialMaxStreamDataBidiRemote(limit) ->
      Ok(State(..state, peer_stream_data_bidi_remote: limit))
    transport_parameter.InitialMaxStreamDataUni(limit) ->
      Ok(State(..state, peer_stream_data_uni: limit))
    transport_parameter.InitialMaxStreamsBidi(limit) ->
      Ok(
        State(
          ..state,
          local_bidirectional_streams: flow_control.update_stream_limit(
            state.local_bidirectional_streams,
            limit,
          ),
        ),
      )
    transport_parameter.InitialMaxStreamsUni(limit) ->
      Ok(
        State(
          ..state,
          local_unidirectional_streams: flow_control.update_stream_limit(
            state.local_unidirectional_streams,
            limit,
          ),
        ),
      )
    transport_parameter.AckDelayExponent(exponent) ->
      Ok(State(..state, peer_ack_delay_exponent: exponent))
    transport_parameter.MaxAckDelay(delay) ->
      case
        packet_space.update_maximum_ack_delay(state.application_space, delay)
      {
        Error(_) -> Error(ProtocolViolation)
        Ok(space) -> Ok(State(..state, application_space: space))
      }
    transport_parameter.MaxUdpPayloadSize(size) ->
      case pmtu.set_peer_maximum(state.pmtu, size) {
        Error(_) -> Error(ProtocolViolation)
        Ok(path_mtu) ->
          Ok(put_path_mtu(
            State(..state, peer_maximum_udp_payload_size: size),
            path_mtu,
          ))
      }
    transport_parameter.MaxDatagramFrameSize(size) ->
      Ok(State(..state, peer_maximum_datagram_frame_size: size))
    transport_parameter.GreaseQuicBit ->
      Ok(State(..state, peer_grease_quic_bit: True))
    transport_parameter.DisableActiveMigration ->
      Ok(State(..state, peer_disabled_active_migration: True))
    _ -> Ok(state)
  }
}

fn prepare_sendable_packet(
  state: State,
  level: engine.EncryptionLevel,
  maximum_frame_data_bytes: Int,
  now_milliseconds: Int,
) -> Result(Preparation, Error) {
  let discarded = packet_space_discarded(state, level)
  let writable = keys_available(state, level, Write)
  case discarded, writable {
    True, _ -> Error(SpaceUnavailable)
    False, False -> Error(MissingWriteKeys(level))
    False, True -> {
      use #(acked, acknowledgement) <- result.try(take_due_ack(
        state,
        level,
        now_milliseconds,
      ))
      use #(state, frames) <- result.try(fill_path_sized_packet(
        acked,
        level,
        maximum_frame_data_bytes,
        acknowledgement,
      ))
      case frames {
        [] -> Ok(NoPacket(state))
        _ ->
          Ok(PacketPrepared(
            state,
            level,
            next_packet_number_for_level(state, level),
            frames,
          ))
      }
    }
  }
}

/// Fill one packet with the acknowledgement it owes and the next frame the
/// send path draws, keeping the finished datagram inside the validated path.
///
/// STREAM and CRYPTO data is split to whatever the acknowledgement leaves, so
/// it always fits. A QUIC DATAGRAM frame is indivisible (RFC 9221 section 3)
/// and is sized at queue time with the acknowledgement already subtracted, so
/// it normally fits too - but the retained ranges can grow between those two
/// moments. When the two no longer fit together the frame yields, not the
/// acknowledgement: it stays at the head of its queue and rides the next
/// packet, while the acknowledgement goes out now. RFC 9000 section 13.2.1
/// bounds acknowledgement delay by max_ack_delay, and an application holding a
/// full queue must not be able to defer one past that.
///
/// A frame that overflows the path with no acknowledgement beside it is one
/// the path shrank underneath, since a black hole or a validated path change
/// resets DPLPMTUD to the 1200-byte floor. An unreliable DATAGRAM is dropped
/// there rather than sent past the path (RFC 9221 section 5).
///
/// Dropping the frame for the acknowledgement is safe at every level because
/// the acknowledgement was already shrunk to what this level's protection
/// leaves of the path, and protection at every level fits inside the floor:
/// the widest is an Initial's, whose token `driver` bounds precisely so that
/// it does.
fn fill_path_sized_packet(
  state: State,
  level: engine.EncryptionLevel,
  requested: Int,
  acknowledgement: Option(frame.Frame),
) -> Result(#(State, List(frame.Frame)), Error) {
  use #(acknowledgement, coalesced) <- result.try(path_sized_acknowledgement(
    state,
    level,
    acknowledgement,
  ))
  let budget = path_frame_data_bytes(state, level, requested, coalesced)
  use #(next, outgoing) <- result.try(take_outgoing_frame(state, level, budget))
  use overflows <- result.try(overflows_path(state, level, coalesced, outgoing))
  case overflows, acknowledgement {
    False, _ -> Ok(#(next, combine_optional_frames(acknowledgement, outgoing)))
    True, Some(value) -> Ok(#(state, [value]))
    True, None -> Ok(#(next, keep_deliverable_frame(outgoing)))
  }
}

/// Shrink the acknowledgement owed to what one packet on this path carries,
/// and report the bytes it encodes to.
///
/// A retained range set of a few hundred widely scattered ranges encodes past
/// the 1200-byte floor on its own, and an ACK-only packet has no other frame
/// to yield to it. RFC 9000 section 13.2.4 lets an acknowledgement carry a
/// subset of the retained ranges, so the oldest are dropped and stay retained
/// for a later packet; the largest received packet number always goes out.
///
/// An acknowledgement that already fits is returned untouched, which is every
/// acknowledgement on a healthy path: only a receive pattern scattered enough
/// to make most gaps four-byte varints reaches the second encode.
fn path_sized_acknowledgement(
  state: State,
  level: engine.EncryptionLevel,
  acknowledgement: Option(frame.Frame),
) -> Result(#(Option(frame.Frame), Int), Error) {
  use bytes <- result.try(encoded_frame_bytes(acknowledgement))
  let allowance = path_mtu(state) - packet_protection_overhead(state, level)
  case acknowledgement {
    Some(frame.Ack(value)) if bytes > allowance ->
      case ack_ranges_within(value, allowance) {
        [] -> Ok(#(None, 0))
        ranges -> {
          let shrunk = Some(frame.Ack(frame.Acknowledgement(..value, ranges:)))
          use bytes <- result.try(encoded_frame_bytes(shrunk))
          Ok(#(shrunk, bytes))
        }
      }
    _ -> Ok(#(acknowledgement, bytes))
  }
}

/// Return the leading retained ranges whose acknowledgement encodes within
/// `allowance` bytes.
///
/// RFC 9000 section 13.2.4 lets an acknowledgement carry fewer ranges than the
/// receiver retains: the ranges it omits stay retained and ride a later
/// acknowledgement. The newest ranges are the ones that matter for loss
/// detection, so the oldest are the ones dropped.
///
/// The first range is always kept: the peer learns the largest packet number
/// received from it, and at any allowance a packet can hold it fits.
fn ack_ranges_within(
  acknowledgement: frame.Acknowledgement,
  allowance: Int,
) -> List(frame.AckRange) {
  let frame.Acknowledgement(delay, ranges, counts) = acknowledgement
  case ranges {
    [] -> []
    [frame.AckRange(smallest, largest) as first, ..additional] -> {
      // The Range Count field is charged at the width the full retained set
      // encodes to. Dropping ranges can only narrow it, so a prefix chosen
      // against this bound never encodes wider than the bound allowed.
      let fixed =
        1
        + varint_bytes(largest)
        + varint_bytes(delay)
        + varint_bytes(list.length(additional))
        + varint_bytes(largest - smallest)
        + ecn_counts_bytes(counts)
      [first, ..ack_ranges_taken(additional, smallest, allowance - fixed, [])]
    }
  }
}

/// Walk the ranges beyond the first in encoder order, keeping each while its
/// gap and length varints still fit the bytes left.
fn ack_ranges_taken(
  ranges: List(frame.AckRange),
  previous_smallest: Int,
  remaining: Int,
  kept: List(frame.AckRange),
) -> List(frame.AckRange) {
  case ranges {
    [] -> list.reverse(kept)
    [frame.AckRange(smallest, largest) as range, ..rest] -> {
      let cost =
        varint_bytes(previous_smallest - largest - 2)
        + varint_bytes(largest - smallest)
      case cost <= remaining {
        False -> list.reverse(kept)
        True ->
          ack_ranges_taken(rest, smallest, remaining - cost, [range, ..kept])
      }
    }
  }
}

/// The three counts an ACK_ECN frame appends, or nothing when the space this
/// acknowledgement came from has seen no marked packet.
fn ecn_counts_bytes(counts: Option(frame.EcnCounts)) -> Int {
  case counts {
    None -> 0
    Some(frame.EcnCounts(ect0, ect1, ce)) ->
      varint_bytes(ect0) + varint_bytes(ect1) + varint_bytes(ce)
  }
}

/// The encoded width of one variable-length integer, charging the widest
/// encoding for a value no varint can hold.
fn varint_bytes(value: Int) -> Int {
  varint.encoded_size(value) |> result.unwrap(maximum_varint_bytes)
}

/// Keep a frame the shrunken path can no longer carry only when dropping it
/// would break the connection.
///
/// A DATAGRAM is unreliable by definition and RFC 9221 section 5 lets one be
/// dropped, so it is. Every other frame the send path draws is reliable and is
/// still emitted. That is safe because none of them can be oversized here: a
/// STREAM or CRYPTO frame was split to the budget, and the two frames whose
/// payload a caller supplies - NEW_TOKEN and CONNECTION_CLOSE - are bounded
/// where they enter the connection so that both fit the 1200-byte floor a
/// black hole resets the path to.
fn keep_deliverable_frame(outgoing: Option(frame.Frame)) -> List(frame.Frame) {
  case outgoing {
    None | Some(frame.Datagram(_)) -> []
    Some(value) -> [value]
  }
}

/// Whether the frames chosen for one packet would put the finished datagram
/// past the path once packet protection is paid for.
///
/// Every level is measured, and a packet carrying no drawn frame at all is
/// measured too: an acknowledgement large enough to outgrow the path on its
/// own has no other frame beside it to yield.
fn overflows_path(
  state: State,
  level: engine.EncryptionLevel,
  coalesced: Int,
  outgoing: Option(frame.Frame),
) -> Result(Bool, Error) {
  use bytes <- result.try(case outgoing {
    None -> Ok(0)
    Some(value) -> outgoing_frame_bytes(value)
  })
  let overhead = packet_protection_overhead(state, level)
  Ok(coalesced + bytes + overhead > path_mtu(state))
}

/// What protecting one packet at this level costs around its frames.
///
/// A 1-RTT packet writes a short header; 0-RTT and Handshake write a long one.
/// An Initial writes a long header plus the address-validation token this
/// endpoint sends, which is why the token width is carried on the connection.
///
/// This is always smaller than the 1200-byte floor, and therefore smaller than
/// any path: `driver` refuses a token - cached or Retry-issued - wide enough
/// to break that, so every level always has payload left to budget.
fn packet_protection_overhead(
  state: State,
  level: engine.EncryptionLevel,
) -> Int {
  case level {
    engine.OneRtt -> wire_packet.maximum_short_packet_overhead()
    engine.ZeroRtt | engine.Handshake ->
      wire_packet.maximum_long_packet_overhead()
    engine.Initial -> initial_packet_overhead(state.initial_token_bytes)
  }
}

fn take_due_ack(
  state: State,
  level: engine.EncryptionLevel,
  now_milliseconds: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case level {
    engine.ZeroRtt -> Ok(#(state, None))
    engine.Initial ->
      take_space_ack(state, state.initial_space, level, now_milliseconds)
    engine.Handshake ->
      take_space_ack(state, state.handshake_space, level, now_milliseconds)
    engine.OneRtt ->
      take_space_ack(state, state.application_space, level, now_milliseconds)
  }
}

fn take_space_ack(
  state: State,
  space: packet_space.State,
  level: engine.EncryptionLevel,
  now_milliseconds: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case
    packet_space.take_ack(
      space,
      now_milliseconds,
      local_ack_delay_exponent(state),
    )
  {
    Error(_) -> Error(PacketSpaceFailure)
    Ok(#(space, acknowledgement)) -> {
      let state = put_packet_space(state, level, space)
      Ok(#(state, option_ack_frame(acknowledgement)))
    }
  }
}

fn local_ack_delay_exponent(_state: State) -> Int {
  3
}

fn option_ack_frame(
  acknowledgement: Option(frame.Acknowledgement),
) -> Option(frame.Frame) {
  case acknowledgement {
    None -> None
    Some(ack) -> Some(frame.Ack(ack))
  }
}

fn combine_optional_frames(
  first: Option(frame.Frame),
  second: Option(frame.Frame),
) -> List(frame.Frame) {
  case first, second {
    None, None -> []
    Some(value), None | None, Some(value) -> [value]
    Some(left), Some(right) -> [left, right]
  }
}

fn take_outgoing_frame(
  state: State,
  level: engine.EncryptionLevel,
  maximum_data_bytes: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case level {
    engine.Initial ->
      take_queue_head(state, level, state.initial_queue, maximum_data_bytes)
    engine.Handshake ->
      take_queue_head(state, level, state.handshake_queue, maximum_data_bytes)
    engine.ZeroRtt ->
      case state.zero_rtt_queue {
        [] -> poll_stream_frame(state, maximum_data_bytes)
        queue -> take_queue_head(state, level, queue, maximum_data_bytes)
      }
    engine.OneRtt ->
      case state.application_queue {
        [] -> poll_stream_frame(state, maximum_data_bytes)
        queue -> take_queue_head(state, level, queue, maximum_data_bytes)
      }
  }
}

fn take_queue_head(
  state: State,
  level: engine.EncryptionLevel,
  queue: List(frame.Frame),
  maximum_data_bytes: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case queue {
    [] -> Ok(#(state, None))
    [outgoing, ..rest] -> {
      use #(emitted, remainder) <- result.try(split_data_frame(
        outgoing,
        maximum_data_bytes,
      ))
      let remaining = case remainder {
        None -> rest
        Some(value) -> [value, ..rest]
      }
      Ok(#(put_queue(state, level, remaining), Some(emitted)))
    }
  }
}

fn split_data_frame(
  outgoing: frame.Frame,
  maximum_data_bytes: Int,
) -> Result(#(frame.Frame, Option(frame.Frame)), Error) {
  case outgoing {
    frame.Crypto(offset, data) ->
      split_crypto_frame(offset, data, maximum_data_bytes)
    frame.Stream(identifier, offset, data, fin) ->
      split_stream_frame(identifier, offset, data, fin, maximum_data_bytes)
    _ -> Ok(#(outgoing, None))
  }
}

fn split_crypto_frame(
  offset: Int,
  data: BitArray,
  maximum_data_bytes: Int,
) -> Result(#(frame.Frame, Option(frame.Frame)), Error) {
  case bit_array.byte_size(data) > maximum_data_bytes {
    False -> Ok(#(frame.Crypto(offset, data), None))
    True -> {
      use #(prefix, suffix) <- result.try(split_bytes(data, maximum_data_bytes))
      Ok(#(
        frame.Crypto(offset, prefix),
        Some(frame.Crypto(offset + maximum_data_bytes, suffix)),
      ))
    }
  }
}

fn split_stream_frame(
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
  maximum_data_bytes: Int,
) -> Result(#(frame.Frame, Option(frame.Frame)), Error) {
  case bit_array.byte_size(data) > maximum_data_bytes {
    False -> Ok(#(frame.Stream(identifier, offset, data, fin), None))
    True -> {
      use #(prefix, suffix) <- result.try(split_bytes(data, maximum_data_bytes))
      Ok(#(
        frame.Stream(identifier, offset, prefix, False),
        Some(frame.Stream(identifier, offset + maximum_data_bytes, suffix, fin)),
      ))
    }
  }
}

fn split_bytes(
  bytes: BitArray,
  count: Int,
) -> Result(#(BitArray, BitArray), Error) {
  case count <= 0 || count > bit_array.byte_size(bytes) {
    True -> Error(InvalidInput)
    False -> {
      let prefix_bits = count * 8
      case bytes {
        <<prefix:bits-size(prefix_bits), suffix:bits>> -> Ok(#(prefix, suffix))
        _ -> Error(InvalidInput)
      }
    }
  }
}

fn put_queue(
  state: State,
  level: engine.EncryptionLevel,
  queue: List(frame.Frame),
) -> State {
  case level {
    engine.Initial -> State(..state, initial_queue: queue)
    engine.Handshake -> State(..state, handshake_queue: queue)
    engine.ZeroRtt -> State(..state, zero_rtt_queue: queue)
    engine.OneRtt -> State(..state, application_queue: queue)
  }
}

fn poll_stream_frame(
  state: State,
  maximum_data_bytes: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  poll_streams(
    state,
    state.stream_order,
    list.length(state.stream_order),
    maximum_data_bytes,
  )
}

fn poll_streams(
  state: State,
  order: List(Int),
  remaining_attempts: Int,
  maximum_data_bytes: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case remaining_attempts, order {
    0, _ | _, [] -> Ok(#(State(..state, stream_order: order), None))
    attempts, [identifier, ..rest] -> {
      let rotated = list.append(rest, [identifier])
      case dict.has_key(state.streams, identifier) {
        False ->
          poll_streams(
            State(..state, stream_order: rest),
            rest,
            attempts - 1,
            maximum_data_bytes,
          )
        True ->
          case dict.get(state.streams, identifier) {
            Error(_) -> Error(StreamFailure)
            Ok(stream) ->
              handle_stream_poll(
                state,
                stream,
                identifier,
                rotated,
                attempts,
                maximum_data_bytes,
              )
          }
      }
    }
  }
}

fn handle_stream_poll(
  state: State,
  original_stream: stream_state.State,
  identifier: Int,
  rotated: List(Int),
  remaining_attempts: Int,
  maximum_data_bytes: Int,
) -> Result(#(State, Option(frame.Frame)), Error) {
  case stream_state.poll_send(original_stream, maximum_data_bytes) {
    Ok(stream_state.Emit(stream, emitted)) ->
      complete_stream_emit(
        state,
        identifier,
        rotated,
        original_stream,
        stream,
        emitted,
      )
    Ok(stream_state.SendBlocked(stream, limit)) ->
      Ok(#(
        State(
          ..state,
          streams: dict.insert(state.streams, identifier, stream),
          stream_order: rotated,
        ),
        Some(frame.StreamDataBlocked(identifier, limit)),
      ))
    Ok(stream_state.SendIdle(stream)) ->
      poll_streams(
        State(
          ..state,
          streams: dict.insert(state.streams, identifier, stream),
          stream_order: rotated,
        ),
        rotated,
        remaining_attempts - 1,
        maximum_data_bytes,
      )
    Error(stream_state.WrongDirection) ->
      poll_streams(
        State(..state, stream_order: rotated),
        rotated,
        remaining_attempts - 1,
        maximum_data_bytes,
      )
    Error(_) -> Error(StreamFailure)
  }
}

fn complete_stream_emit(
  state: State,
  identifier: Int,
  rotated: List(Int),
  original: stream_state.State,
  stream: stream_state.State,
  emitted: frame.Frame,
) -> Result(#(State, Option(frame.Frame)), Error) {
  let newly_sent =
    stream_state.next_send_offset(stream)
    - stream_state.next_send_offset(original)
  case flow_control.reserve(state.connection_sender, newly_sent) {
    Ok(sender) ->
      Ok(#(
        State(
          ..state,
          connection_sender: sender,
          streams: dict.insert(state.streams, identifier, stream),
          stream_order: rotated,
        ),
        Some(emitted),
      ))
    Error(flow_control.FlowControlBlocked(limit)) ->
      Ok(#(
        State(..state, stream_order: rotated),
        Some(frame.DataBlocked(limit)),
      ))
    Error(_) -> Error(FlowControlFailure)
  }
}

fn next_packet_number_for_level(
  state: State,
  level: engine.EncryptionLevel,
) -> Int {
  packet_space.next_packet_number(packet_space_for_level(state, level))
}

fn packet_space_for_level(
  state: State,
  level: engine.EncryptionLevel,
) -> packet_space.State {
  case level {
    engine.Initial -> state.initial_space
    engine.Handshake -> state.handshake_space
    engine.ZeroRtt | engine.OneRtt -> state.application_space
  }
}

fn put_packet_space(
  state: State,
  level: engine.EncryptionLevel,
  space: packet_space.State,
) -> State {
  case level {
    engine.Initial -> State(..state, initial_space: space)
    engine.Handshake -> State(..state, handshake_space: space)
    engine.ZeroRtt | engine.OneRtt -> State(..state, application_space: space)
  }
}

fn commit_sendable_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  datagram_bytes: Int,
  codepoint: ecn.Codepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case
    valid_committed_packet(
      state,
      level,
      packet_number,
      frames,
      datagram_bytes,
      now_milliseconds,
    )
  {
    Error(error) -> Error(error)
    Ok(Nil) ->
      commit_valid_packet(
        state,
        level,
        frames,
        datagram_bytes,
        codepoint,
        now_milliseconds,
      )
  }
}

fn valid_committed_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  datagram_bytes: Int,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  let discarded = packet_space_discarded(state, level)
  let writable = keys_available(state, level, Write)
  case discarded, writable {
    True, _ -> Error(SpaceUnavailable)
    False, False -> Error(MissingWriteKeys(level))
    False, True -> {
      let maximum_datagram =
        minimum(
          state.config.maximum_udp_payload_size,
          state.peer_maximum_udp_payload_size,
        )
      case
        frames != []
        && packet_number == next_packet_number_for_level(state, level)
        && datagram_bytes > 0
        && datagram_bytes <= maximum_datagram
        && now_milliseconds >= 0
      {
        True -> Ok(Nil)
        False -> Error(InvalidInput)
      }
    }
  }
}

fn commit_valid_packet(
  state: State,
  level: engine.EncryptionLevel,
  frames: List(frame.Frame),
  datagram_bytes: Int,
  codepoint: ecn.Codepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let ack_eliciting = frames_ack_eliciting(frames)
  let in_flight = ack_eliciting || frames_have_padding(frames)
  use amplification <- result.try(debit_amplification(
    state.amplification,
    datagram_bytes,
  ))
  use congestion <- result.try(check_and_record_congestion_send(
    state.congestion,
    datagram_bytes,
    in_flight,
  ))
  use pacing <- result.try(reserve_pacing(
    state,
    datagram_bytes,
    in_flight,
    now_milliseconds,
  ))
  let space = packet_space_for_level(state, level)
  case
    packet_space.record_sent(
      space,
      now_milliseconds,
      ack_eliciting,
      in_flight,
      datagram_bytes,
      frames,
      codepoint,
    )
  {
    Error(_) -> Error(PacketSpaceFailure)
    Ok(#(space, _)) -> {
      use ecn_state <- result.try(record_ecn_send(state.ecn, codepoint))
      let state = put_packet_space(state, level, space)
      let sent =
        State(
          ..state,
          congestion: congestion,
          pacer: pacing,
          amplification: amplification,
          ecn: ecn_state,
          acknowledgements_sent: state.acknowledgements_sent
            + list.count(frames, fn(value) {
              case value {
                frame.Ack(_) -> True
                _ -> False
              }
            }),
          last_activity_milliseconds: case ack_eliciting {
            True -> now_milliseconds
            False -> state.last_activity_milliseconds
          },
        )
      Ok(sent)
    }
  }
}

fn debit_amplification(
  budget: amplification.Budget,
  datagram_bytes: Int,
) -> Result(amplification.Budget, Error) {
  case amplification.record_sent(budget, datagram_bytes) {
    Ok(updated) -> Ok(updated)
    Error(amplification.AmplificationLimited(_)) -> Error(AmplificationLimited)
    Error(_) -> Error(InvalidInput)
  }
}

fn check_and_record_congestion_send(
  congestion: CongestionState,
  datagram_bytes: Int,
  in_flight: Bool,
) -> Result(CongestionState, Error) {
  case congestion {
    RenoState(state) ->
      case !in_flight || new_reno.can_send(state, datagram_bytes) {
        False -> Error(CongestionLimited)
        True ->
          case new_reno.on_packet_sent(state, datagram_bytes, in_flight) {
            Ok(updated) -> Ok(RenoState(updated))
            Error(_) -> Error(InvalidInput)
          }
      }
    CubicState(state) ->
      case !in_flight || cubic.can_send(state, datagram_bytes) {
        False -> Error(CongestionLimited)
        True ->
          case cubic.on_packet_sent(state, datagram_bytes, in_flight) {
            Ok(updated) -> Ok(CubicState(updated))
            Error(_) -> Error(InvalidInput)
          }
      }
  }
}

fn reserve_pacing(
  state: State,
  datagram_bytes: Int,
  in_flight: Bool,
  now_milliseconds: Int,
) -> Result(pacer.State, Error) {
  case in_flight {
    False -> Ok(state.pacer)
    True ->
      case ask_pacer(state, datagram_bytes, now_milliseconds) {
        Error(_) -> Error(InvalidInput)
        Ok(pacer.Decision(updated, pacer.SendNow)) -> Ok(updated)
        Ok(pacer.Decision(_, pacer.WaitUntil(deadline))) ->
          Error(PacingLimited(deadline))
      }
  }
}

/// Ask the pacer to release one datagram against the current window and RTT.
/// The burst scales with the path so one path-sized datagram - including the
/// DPLPMTUD probe that proves the path - always fits inside a single burst.
fn ask_pacer(
  state: State,
  datagram_bytes: Int,
  now_milliseconds: Int,
) -> Result(pacer.Decision, pacer.Error) {
  let rtt.Snapshot(_, smoothed, _, _) = rtt.snapshot(state.estimator)
  use pacing <- result.try(pacer.resize_burst(
    state.pacer,
    pacer_burst_bytes(state),
  ))
  pacer.reserve(
    pacing,
    datagram_bytes,
    now_milliseconds,
    congestion_window(state),
    smoothed,
  )
}

/// Ten datagrams of the largest size the path is confirmed - or is being
/// probed - to carry.
fn pacer_burst_bytes(state: State) -> Int {
  let confirmed = path_mtu(state)
  let largest = case pmtu.outstanding_probe(state.pmtu) {
    Some(probe) -> maximum(confirmed, probe)
    None -> confirmed
  }
  pacer_burst_datagrams * largest
}

fn record_ecn_send(
  state: ecn.State,
  codepoint: ecn.Codepoint,
) -> Result(ecn.State, Error) {
  case ecn.record_sent(state, codepoint, 1) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(InvalidInput)
  }
}

fn frames_ack_eliciting(frames: List(frame.Frame)) -> Bool {
  list.any(frames, frame_ack_eliciting)
}

fn frame_ack_eliciting(value: frame.Frame) -> Bool {
  case value {
    frame.Padding(_)
    | frame.Ack(_)
    | frame.ConnectionCloseTransport(_, _, _)
    | frame.ConnectionCloseApplication(_, _) -> False
    _ -> True
  }
}

fn frames_have_padding(frames: List(frame.Frame)) -> Bool {
  list.any(frames, fn(value) {
    case value {
      frame.Padding(_) -> True
      _ -> False
    }
  })
}

fn receive_live_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let discarded = packet_space_discarded(state, level)
  let readable = keys_available(state, level, Read)
  let valid = now_milliseconds >= 0 && frames_valid_at_level(frames, level)
  case discarded, readable, valid {
    True, _, _ -> Error(SpaceUnavailable)
    False, False, _ -> Error(MissingReadKeys(level))
    False, True, False -> Error(ProtocolViolation)
    False, True, True ->
      receive_valid_packet(
        state,
        level,
        packet_number,
        frames,
        codepoint,
        now_milliseconds,
      )
  }
}

fn receive_valid_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
  frames: List(frame.Frame),
  codepoint: packet_space.ReceivedCodepoint,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let space = packet_space_for_level(state, level)
  case
    packet_space.receive(
      space,
      packet_number,
      frames_ack_eliciting(frames),
      codepoint,
      now_milliseconds,
    )
  {
    Error(_) -> Error(PacketSpaceFailure)
    Ok(packet_space.Duplicate(space)) ->
      Ok(put_packet_space(state, level, space))
    Ok(packet_space.Accepted(space, _)) -> {
      let state =
        put_packet_space(state, level, space)
        |> update_receive_activity(now_milliseconds)
      process_frames(state, level, frames, now_milliseconds)
    }
  }
}

fn update_receive_activity(state: State, now_milliseconds: Int) -> State {
  State(..state, last_activity_milliseconds: now_milliseconds)
}

fn frames_valid_at_level(
  frames: List(frame.Frame),
  level: engine.EncryptionLevel,
) -> Bool {
  list.all(frames, fn(value) { frame_valid_at_level(value, level) })
}

fn frame_valid_at_level(
  value: frame.Frame,
  level: engine.EncryptionLevel,
) -> Bool {
  case level {
    engine.Initial | engine.Handshake ->
      case value {
        frame.Padding(_)
        | frame.Ping
        | frame.Ack(_)
        | frame.Crypto(_, _)
        | frame.ConnectionCloseTransport(_, _, _) -> True
        _ -> False
      }
    engine.ZeroRtt ->
      case value {
        frame.Padding(_)
        | frame.Ping
        | frame.ResetStream(_, _, _)
        | frame.StopSending(_, _)
        | frame.Stream(_, _, _, _)
        | frame.MaxData(_)
        | frame.MaxStreamData(_, _)
        | frame.MaxStreams(_, _)
        | frame.DataBlocked(_)
        | frame.StreamDataBlocked(_, _)
        | frame.StreamsBlocked(_, _)
        | frame.ConnectionCloseApplication(_, _)
        | frame.Datagram(_) -> True
        _ -> False
      }
    engine.OneRtt -> True
  }
}

fn process_frames(
  state: State,
  level: engine.EncryptionLevel,
  frames: List(frame.Frame),
  now_milliseconds: Int,
) -> Result(State, Error) {
  case frames {
    [] -> Ok(state)
    [value, ..rest] -> {
      use state <- result.try(process_frame(
        state,
        level,
        value,
        now_milliseconds,
      ))
      process_frames(state, level, rest, now_milliseconds)
    }
  }
}

fn process_frame(
  state: State,
  level: engine.EncryptionLevel,
  value: frame.Frame,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case value {
    frame.Padding(_) | frame.Ping -> Ok(state)
    frame.Ack(acknowledgement) ->
      process_ack(state, level, acknowledgement, now_milliseconds)
    frame.Crypto(offset, data) ->
      receive_crypto(state, level, offset, data, now_milliseconds)
    frame.Stream(identifier, offset, data, fin) ->
      receive_stream_frame(state, level, identifier, offset, data, fin)
    frame.ResetStream(identifier, error_code, final_size) ->
      receive_stream_reset(state, identifier, error_code, final_size)
    frame.StopSending(identifier, error_code) ->
      receive_stop_sending(state, identifier, error_code)
    frame.MaxData(limit) ->
      Ok(
        State(
          ..state,
          connection_sender: flow_control.update_sender_limit(
            state.connection_sender,
            limit,
          ),
        ),
      )
    frame.MaxStreamData(identifier, limit) ->
      update_stream_send_limit(state, identifier, limit)
    frame.MaxStreams(direction, limit) ->
      Ok(update_local_stream_limit(state, direction, limit))
    frame.PathChallenge(challenge) -> queue_path_response(state, challenge)
    frame.PathResponse(response) -> receive_path_response(state, response)
    frame.ConnectionCloseTransport(error_code, _, reason)
    | frame.ConnectionCloseApplication(error_code, reason) ->
      Ok(enter_draining(state, error_code, reason, now_milliseconds))
    frame.HandshakeDone -> receive_handshake_done(state)
    frame.Datagram(data) -> receive_datagram(state, data)
    // RFC 9000 section 8.1.3 leaves it to the client whether to keep a token
    // for a later connection. One too wide for an Initial to repeat inside the
    // 1200-byte floor is never usable, so it is dropped here rather than
    // stored and refused at the start of the next connection.
    frame.NewToken(token) ->
      case bit_array.byte_size(token) <= maximum_initial_token_bytes() {
        False -> Ok(state)
        True -> Ok(add_event(state, NewTokenReceived(token)))
      }
    frame.NewConnectionId(sequence, retire_prior_to, identifier, reset_token) ->
      receive_new_connection_id(
        state,
        sequence,
        retire_prior_to,
        identifier,
        reset_token,
      )
    frame.RetireConnectionId(sequence) ->
      Ok(add_event(state, LocalConnectionIdRetirementRequested(sequence)))
    frame.DataBlocked(_)
    | frame.StreamDataBlocked(_, _)
    | frame.StreamsBlocked(_, _) -> Ok(state)
  }
}

fn receive_crypto(
  state: State,
  level: engine.EncryptionLevel,
  offset: Int,
  data: BitArray,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case level {
    engine.ZeroRtt -> Error(ProtocolViolation)
    engine.Initial ->
      insert_and_read_crypto(
        state,
        level,
        state.initial_crypto_receive,
        offset,
        data,
        now_milliseconds,
      )
    engine.Handshake ->
      insert_and_read_crypto(
        state,
        level,
        state.handshake_crypto_receive,
        offset,
        data,
        now_milliseconds,
      )
    engine.OneRtt ->
      insert_and_read_crypto(
        state,
        level,
        state.application_crypto_receive,
        offset,
        data,
        now_milliseconds,
      )
  }
}

fn insert_and_read_crypto(
  state: State,
  level: engine.EncryptionLevel,
  byte_stream: reassembler.Reassembler,
  offset: Int,
  data: BitArray,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case reassembler.insert(byte_stream, offset, data, False) {
    Error(_) -> Error(ProtocolViolation)
    Ok(byte_stream) ->
      case reassembler.read(byte_stream, maximum_crypto_buffer_bytes) {
        Error(_) -> Error(ProtocolViolation)
        Ok(reassembler.Read(byte_stream, contiguous, _)) -> {
          let state = put_crypto_receive(state, level, byte_stream)
          case contiguous {
            <<>> -> Ok(state)
            _ -> deliver_crypto(state, level, contiguous, now_milliseconds)
          }
        }
      }
  }
}

fn deliver_crypto(
  state: State,
  level: engine.EncryptionLevel,
  contiguous: BitArray,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case state.tls_endpoint {
    NoTlsEndpoint -> Ok(add_event(state, CryptoReceived(level, contiguous)))
    ClientTlsEndpoint(client) ->
      case
        engine.handle_client_at(client, level, contiguous, now_milliseconds)
      {
        Error(error) -> Error(TlsFailure(error))
        Ok(engine.Step(client, actions)) ->
          apply_tls_actions(
            State(..state, tls_endpoint: ClientTlsEndpoint(client)),
            actions,
          )
      }
    ServerTlsEndpoint(server) ->
      case engine.handle_server(server, level, contiguous) {
        Error(error) -> Error(TlsFailure(error))
        Ok(engine.Step(server, actions)) ->
          apply_tls_actions(
            State(..state, tls_endpoint: ServerTlsEndpoint(server)),
            actions,
          )
      }
  }
}

fn put_crypto_receive(
  state: State,
  level: engine.EncryptionLevel,
  byte_stream: reassembler.Reassembler,
) -> State {
  case level {
    engine.Initial -> State(..state, initial_crypto_receive: byte_stream)
    engine.Handshake -> State(..state, handshake_crypto_receive: byte_stream)
    engine.OneRtt -> State(..state, application_crypto_receive: byte_stream)
    engine.ZeroRtt -> state
  }
}

fn receive_stream_frame(
  state: State,
  level: engine.EncryptionLevel,
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  case
    stream_data_allowed(state, level)
    && stream_id.can_receive(identifier, local_endpoint(state.config.role))
  {
    False -> Error(ProtocolViolation)
    True -> {
      use state <- result.try(ensure_remote_stream(state, identifier))
      case dict.get(state.streams, identifier) {
        Error(Nil) ->
          case stream_was_opened(state, identifier) {
            True -> Ok(state)
            False -> Error(UnknownStream(identifier))
          }
        Ok(stream) ->
          apply_received_stream_data(
            state,
            stream,
            identifier,
            offset,
            data,
            fin,
          )
      }
    }
  }
}

fn stream_data_allowed(state: State, level: engine.EncryptionLevel) -> Bool {
  state.phase == Established
  || { level == engine.ZeroRtt && state.early_data_accepted }
}

fn apply_received_stream_data(
  state: State,
  stream: stream_state.State,
  identifier: Int,
  offset: Int,
  data: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  case stream_state.receive_data(stream, offset, data, fin) {
    Error(_) -> Error(StreamFailure)
    Ok(#(stream, newly_received)) ->
      case flow_control.receive(state.connection_receiver, newly_received) {
        Error(_) -> Error(FlowControlFailure)
        Ok(receiver) ->
          Ok(
            State(
              ..state,
              streams: dict.insert(state.streams, identifier, stream),
              connection_receiver: receiver,
            )
            |> add_event(StreamReadable(identifier)),
          )
      }
  }
}

fn receive_stream_reset(
  state: State,
  identifier: Int,
  error_code: Int,
  final_size: Int,
) -> Result(State, Error) {
  case stream_id.can_receive(identifier, local_endpoint(state.config.role)) {
    False -> Error(ProtocolViolation)
    True -> {
      use state <- result.try(ensure_remote_stream(state, identifier))
      case dict.get(state.streams, identifier) {
        Error(Nil) ->
          case stream_was_opened(state, identifier) {
            True -> Ok(state)
            False -> Error(UnknownStream(identifier))
          }
        Ok(stream) ->
          case stream_state.receive_reset(stream, error_code, final_size) {
            Error(_) -> Error(StreamFailure)
            Ok(#(stream, newly_received)) ->
              case
                flow_control.receive(state.connection_receiver, newly_received)
              {
                Error(_) -> Error(FlowControlFailure)
                Ok(receiver) ->
                  Ok(
                    State(
                      ..state,
                      streams: dict.insert(state.streams, identifier, stream),
                      connection_receiver: receiver,
                    )
                    |> add_event(StreamWasReset(identifier, error_code)),
                  )
              }
          }
      }
    }
  }
}

fn receive_stop_sending(
  state: State,
  identifier: Int,
  error_code: Int,
) -> Result(State, Error) {
  case stream_id.can_send(identifier, local_endpoint(state.config.role)) {
    False -> Error(ProtocolViolation)
    True -> {
      use state <- result.try(ensure_remote_stream(state, identifier))
      case dict.get(state.streams, identifier) {
        Error(Nil) ->
          case stream_was_opened(state, identifier) {
            True -> Ok(state)
            False -> Error(UnknownStream(identifier))
          }
        Ok(stream) ->
          case stream_state.reset_send(stream, error_code) {
            Error(_) -> Error(StreamFailure)
            Ok(#(stream, reset)) ->
              Ok(
                State(
                  ..state,
                  streams: dict.insert(state.streams, identifier, stream),
                )
                |> queue_application_frame(reset)
                |> cleanup_stream_if_terminal(identifier),
              )
          }
      }
    }
  }
}

fn update_stream_send_limit(
  state: State,
  identifier: Int,
  limit: Int,
) -> Result(State, Error) {
  case stream_id.can_send(identifier, local_endpoint(state.config.role)) {
    False -> Error(ProtocolViolation)
    True -> {
      use state <- result.try(ensure_remote_stream(state, identifier))
      case dict.get(state.streams, identifier) {
        Error(Nil) ->
          case stream_was_opened(state, identifier) {
            True -> Ok(state)
            False -> Error(UnknownStream(identifier))
          }
        Ok(stream) ->
          Ok(
            State(
              ..state,
              streams: dict.insert(
                state.streams,
                identifier,
                stream_state.update_send_limit(stream, limit),
              ),
            ),
          )
      }
    }
  }
}

fn update_local_stream_limit(
  state: State,
  direction: frame.StreamDirection,
  limit: Int,
) -> State {
  case direction {
    frame.Bidirectional ->
      State(
        ..state,
        local_bidirectional_streams: flow_control.update_stream_limit(
          state.local_bidirectional_streams,
          limit,
        ),
      )
    frame.Unidirectional ->
      State(
        ..state,
        local_unidirectional_streams: flow_control.update_stream_limit(
          state.local_unidirectional_streams,
          limit,
        ),
      )
  }
}

fn queue_application_frame(state: State, value: frame.Frame) -> State {
  State(
    ..state,
    application_queue: list.append(state.application_queue, [value]),
  )
}

fn queue_path_response(
  state: State,
  challenge: BitArray,
) -> Result(State, Error) {
  let #(already_pending, pending_count) =
    pending_path_response_state(state.application_queue, challenge, False, 0)
  case already_pending, pending_count >= maximum_pending_path_responses {
    True, _ -> Ok(state)
    False, True -> Error(ProtocolViolation)
    False, False ->
      Ok(queue_application_frame(state, frame.PathResponse(challenge)))
  }
}

fn pending_path_response_state(
  queued: List(frame.Frame),
  challenge: BitArray,
  found: Bool,
  count: Int,
) -> #(Bool, Int) {
  case queued {
    [] -> #(found, count)
    [frame.PathResponse(response), ..rest] ->
      pending_path_response_state(
        rest,
        challenge,
        found || response == challenge,
        count + 1,
      )
    [_, ..rest] -> pending_path_response_state(rest, challenge, found, count)
  }
}

fn enter_draining(
  state: State,
  error_code: Int,
  reason: String,
  now_milliseconds: Int,
) -> State {
  State(
    ..state,
    phase: Draining,
    close_deadline_milliseconds: Some(
      now_milliseconds + state.config.draining_timeout_milliseconds,
    ),
  )
  |> add_event(PeerClosed(error_code, reason))
}

fn receive_handshake_done(state: State) -> Result(State, Error) {
  case state.config.role, state.phase {
    Client, Established -> confirm_client_tls(state)
    _, _ -> Error(ProtocolViolation)
  }
}

fn confirm_client_tls(state: State) -> Result(State, Error) {
  case state.tls_endpoint {
    NoTlsEndpoint ->
      Ok(
        State(
          ..discard_level(state, engine.Handshake),
          handshake_confirmed: True,
        )
        |> confirm_key_phase,
      )
    ClientTlsEndpoint(client) ->
      case engine.confirm_client_handshake(client) {
        Error(error) -> Error(TlsFailure(error))
        Ok(engine.Step(client, actions)) -> {
          use state <- result.try(apply_tls_actions(
            State(..state, tls_endpoint: ClientTlsEndpoint(client)),
            actions,
          ))
          Ok(
            State(..state, handshake_confirmed: True)
            |> confirm_key_phase,
          )
        }
      }
    ServerTlsEndpoint(_) -> Error(ProtocolViolation)
  }
}

fn receive_datagram(state: State, data: BitArray) -> Result(State, Error) {
  let negotiated = state.config.maximum_datagram_frame_size > 0
  use encoded <- result.try(
    frame.encode(frame.Datagram(data)) |> map_frame_result,
  )
  let frame_size = bit_array.byte_size(encoded)
  case negotiated, frame_size <= state.config.maximum_datagram_frame_size {
    False, _ -> Error(DatagramNotNegotiated)
    True, False ->
      Error(DatagramTooLarge(state.config.maximum_datagram_frame_size))
    True, True -> Ok(add_event(state, DatagramReceived(data)))
  }
}

fn receive_path_response(
  state: State,
  response: BitArray,
) -> Result(State, Error) {
  case path_validation.phase(state.path_validator) {
    path_validation.Validating ->
      case
        path_validation.receive_response(
          state.path_validator,
          response,
          state.last_activity_milliseconds,
        )
      {
        Ok(validator) ->
          Ok(
            put_path_mtu(
              State(..state, path_validator: validator),
              pmtu.reset_path(state.pmtu),
            )
            |> add_event(PathValidated),
          )
        Error(path_validation.ChallengeMismatch) -> Ok(state)
        Error(error) -> Error(PathValidationFailure(error))
      }
    _ -> Ok(state)
  }
}

fn receive_new_connection_id(
  state: State,
  sequence: Int,
  retire_prior_to: Int,
  identifier: BitArray,
  reset_token: BitArray,
) -> Result(State, Error) {
  case state.peer_connection_ids {
    None -> Error(ProtocolViolation)
    Some(registry) -> {
      let was_known = connection_id.contains_sequence(registry, sequence)
      use update <- result.try(
        connection_id.receive(
          registry,
          sequence,
          retire_prior_to,
          identifier,
          reset_token,
        )
        |> map_connection_id_result,
      )
      let connection_id.Update(registry, retired_sequences) = update
      let state =
        State(..state, peer_connection_ids: Some(registry))
        |> queue_retired_connection_ids(retired_sequences)
      case !was_known && connection_id.is_active(registry, sequence) {
        True ->
          Ok(add_event(state, PeerConnectionIdAvailable(sequence, identifier)))
        False -> Ok(state)
      }
    }
  }
}

fn queue_retired_connection_ids(state: State, sequences: List(Int)) -> State {
  case sequences {
    [] -> state
    [sequence, ..rest] ->
      queue_application_frame(state, frame.RetireConnectionId(sequence))
      |> queue_retired_connection_ids(rest)
  }
}

fn tick_path_validation(state: State, now_milliseconds: Int) -> State {
  let was_validating =
    path_validation.phase(state.path_validator) == path_validation.Validating
  let validator =
    path_validation.on_timeout(state.path_validator, now_milliseconds)
  case was_validating, path_validation.phase(validator) {
    True, path_validation.Failed ->
      State(..state, path_validator: validator)
      |> add_event(PathValidationFailed)
    _, _ -> State(..state, path_validator: validator)
  }
}

fn ensure_remote_stream(state: State, identifier: Int) -> Result(State, Error) {
  case dict.has_key(state.streams, identifier) {
    True -> Ok(state)
    False ->
      case stream_was_opened(state, identifier) {
        True -> Ok(state)
        False -> create_missing_remote_streams(state, identifier)
      }
  }
}

fn stream_was_opened(state: State, identifier: Int) -> Bool {
  case stream_id.decode(identifier) {
    Error(stream_id.OutOfRange) -> False
    Ok(stream_id.StreamId(index, initiator, direction)) -> {
      let limit = case initiator == local_endpoint(state.config.role) {
        True -> local_limit(state, direction)
        False -> remote_limit(state, direction)
      }
      index < flow_control.opened_streams(limit)
    }
  }
}

fn create_missing_remote_streams(
  state: State,
  identifier: Int,
) -> Result(State, Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(ProtocolViolation)
    Ok(stream_id.StreamId(index, initiator, direction)) ->
      case initiator == local_endpoint(state.config.role) {
        True -> Error(ProtocolViolation)
        False -> open_remote_through(state, index, direction)
      }
  }
}

fn open_remote_through(
  state: State,
  target_index: Int,
  direction: stream_id.Direction,
) -> Result(State, Error) {
  let limit = remote_limit(state, direction)
  let next_index = flow_control.opened_streams(limit)
  case next_index > target_index {
    True -> Error(ProtocolViolation)
    False ->
      open_remote_range(state, direction, next_index, target_index, limit)
  }
}

fn open_remote_range(
  state: State,
  direction: stream_id.Direction,
  index: Int,
  target_index: Int,
  limit: flow_control.StreamLimit,
) -> Result(State, Error) {
  case index > target_index {
    True -> Ok(put_remote_limit(state, direction, limit))
    False -> {
      use limit <- result.try(open_limit(limit, index))
      use identifier <- result.try(encode_stream_identifier(
        index,
        remote_endpoint(state.config.role),
        direction,
      ))
      use state <- result.try(insert_new_stream(
        state,
        identifier,
        False,
        direction,
      ))
      open_remote_range(state, direction, index + 1, target_index, limit)
    }
  }
}

fn remote_limit(
  state: State,
  direction: stream_id.Direction,
) -> flow_control.StreamLimit {
  case direction {
    stream_id.Bidirectional -> state.remote_bidirectional_streams
    stream_id.Unidirectional -> state.remote_unidirectional_streams
  }
}

fn put_remote_limit(
  state: State,
  direction: stream_id.Direction,
  limit: flow_control.StreamLimit,
) -> State {
  case direction {
    stream_id.Bidirectional ->
      State(..state, remote_bidirectional_streams: limit)
    stream_id.Unidirectional ->
      State(..state, remote_unidirectional_streams: limit)
  }
}

fn open_limit(
  limit: flow_control.StreamLimit,
  index: Int,
) -> Result(flow_control.StreamLimit, Error) {
  case flow_control.open_stream(limit, index) {
    Ok(updated) -> Ok(updated)
    Error(_) -> Error(StreamLimitFailure)
  }
}

fn encode_stream_identifier(
  index: Int,
  initiator: stream_id.Initiator,
  direction: stream_id.Direction,
) -> Result(Int, Error) {
  case stream_id.encode(index, initiator, direction) {
    Ok(identifier) -> Ok(identifier)
    Error(_) -> Error(ProtocolViolation)
  }
}

fn local_endpoint(role: Role) -> stream_id.Initiator {
  case role {
    Client -> stream_id.Client
    Server -> stream_id.Server
  }
}

fn remote_endpoint(role: Role) -> stream_id.Initiator {
  case role {
    Client -> stream_id.Server
    Server -> stream_id.Client
  }
}

fn open_established_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), Error) {
  let limit = local_limit(state, direction)
  let index = flow_control.opened_streams(limit)
  use limit <- result.try(open_limit(limit, index))
  use identifier <- result.try(encode_stream_identifier(
    index,
    local_endpoint(state.config.role),
    direction,
  ))
  let state = put_local_limit(state, direction, limit)
  use state <- result.try(insert_new_stream(state, identifier, True, direction))
  Ok(#(state, identifier))
}

fn local_limit(
  state: State,
  direction: stream_id.Direction,
) -> flow_control.StreamLimit {
  case direction {
    stream_id.Bidirectional -> state.local_bidirectional_streams
    stream_id.Unidirectional -> state.local_unidirectional_streams
  }
}

fn put_local_limit(
  state: State,
  direction: stream_id.Direction,
  limit: flow_control.StreamLimit,
) -> State {
  case direction {
    stream_id.Bidirectional ->
      State(..state, local_bidirectional_streams: limit)
    stream_id.Unidirectional ->
      State(..state, local_unidirectional_streams: limit)
  }
}

fn insert_new_stream(
  state: State,
  identifier: Int,
  locally_initiated: Bool,
  direction: stream_id.Direction,
) -> Result(State, Error) {
  case dict.size(state.streams) >= state.config.maximum_total_streams {
    True -> Error(StreamLimitFailure)
    False -> {
      let send_limit =
        initial_stream_send_limit(state, locally_initiated, direction)
      case
        stream_state.new(
          identifier,
          local_endpoint(state.config.role),
          state.config.initial_receive_stream_data,
          state.config.receive_stream_window,
          state.config.maximum_receive_stream_data,
          send_limit,
          state.config.maximum_stream_receive_buffer,
          state.config.maximum_stream_send_buffer,
          state.config.maximum_stream_final_size,
        )
      {
        Error(_) -> Error(StreamFailure)
        Ok(stream) ->
          Ok(
            State(
              ..state,
              streams: dict.insert(state.streams, identifier, stream),
              stream_order: list.append(state.stream_order, [identifier]),
            )
            |> add_event(StreamOpened(identifier)),
          )
      }
    }
  }
}

fn cleanup_stream_if_terminal(state: State, identifier: Int) -> State {
  case dict.get(state.streams, identifier) {
    Error(Nil) -> state
    Ok(stream) ->
      case stream_state.is_terminal(stream) {
        False -> state
        True ->
          State(
            ..state,
            streams: dict.delete(state.streams, identifier),
            stream_order: list.filter(state.stream_order, fn(value) {
              value != identifier
            }),
          )
          |> replenish_remote_stream_credit(identifier)
      }
  }
}

fn replenish_remote_stream_credit(state: State, identifier: Int) -> State {
  case stream_id.decode(identifier) {
    Error(stream_id.OutOfRange) -> state
    Ok(stream_id.StreamId(_, initiator, direction)) ->
      case initiator == remote_endpoint(state.config.role) {
        False -> state
        True -> {
          let #(limit, advertised) =
            remote_limit(state, direction)
            |> flow_control.replenish_stream_limit
          let state = put_remote_limit(state, direction, limit)
          case advertised {
            None -> state
            Some(maximum) ->
              queue_application_frame(
                state,
                frame.MaxStreams(frame_stream_direction(direction), maximum),
              )
          }
        }
      }
  }
}

fn frame_stream_direction(
  direction: stream_id.Direction,
) -> frame.StreamDirection {
  case direction {
    stream_id.Bidirectional -> frame.Bidirectional
    stream_id.Unidirectional -> frame.Unidirectional
  }
}

fn initial_stream_send_limit(
  state: State,
  locally_initiated: Bool,
  direction: stream_id.Direction,
) -> Int {
  case locally_initiated, direction {
    True, stream_id.Bidirectional -> state.peer_stream_data_bidi_remote
    True, stream_id.Unidirectional -> state.peer_stream_data_uni
    False, stream_id.Bidirectional -> state.peer_stream_data_bidi_local
    False, stream_id.Unidirectional -> 0
  }
}

fn apply_stream_read(
  state: State,
  identifier: Int,
  outcome: stream_state.ReadOutcome,
) -> Result(#(State, stream_state.ReadOutcome), Error) {
  let #(stream, consumed, new_stream_limit) = read_effects(outcome)
  case flow_control.consume(state.connection_receiver, consumed) {
    Error(_) -> Error(FlowControlFailure)
    Ok(#(receiver, new_connection_limit)) -> {
      let state =
        State(
          ..state,
          streams: dict.insert(state.streams, identifier, stream),
          connection_receiver: receiver,
        )
      let state =
        queue_receive_credit_updates(
          state,
          identifier,
          new_stream_limit,
          new_connection_limit,
        )
      Ok(#(cleanup_stream_if_terminal(state, identifier), outcome))
    }
  }
}

fn read_effects(
  outcome: stream_state.ReadOutcome,
) -> #(stream_state.State, Int, Option(Int)) {
  case outcome {
    stream_state.ReadPending(stream) | stream_state.ReadFinished(stream) -> #(
      stream,
      0,
      None,
    )
    stream_state.ReadData(stream, data, _, new_limit) -> #(
      stream,
      bit_array.byte_size(data),
      new_limit,
    )
    stream_state.ReadReset(stream, _, discarded, new_limit) -> #(
      stream,
      discarded,
      new_limit,
    )
  }
}

fn queue_receive_credit_updates(
  state: State,
  identifier: Int,
  stream_limit: Option(Int),
  connection_limit: Option(Int),
) -> State {
  let state = case stream_limit {
    None -> state
    Some(limit) ->
      queue_application_frame(state, frame.MaxStreamData(identifier, limit))
  }
  case connection_limit {
    None -> state
    Some(limit) -> queue_application_frame(state, frame.MaxData(limit))
  }
}

fn process_ack(
  state: State,
  level: engine.EncryptionLevel,
  acknowledgement: frame.Acknowledgement,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let space = packet_space_for_level(state, level)
  case
    packet_space.on_ack(
      space,
      acknowledgement,
      state.peer_ack_delay_exponent,
      now_milliseconds,
      state.estimator,
      state.handshake_confirmed,
      timer_granularity_milliseconds,
    )
  {
    Error(_) -> Error(PacketSpaceFailure)
    Ok(packet_space.AckOutcome(space, estimator, acknowledged, lost, _)) -> {
      let smaller_packet_acknowledged =
        acknowledged_smaller_than_probe(state, acknowledged)
      let state =
        put_packet_space(state, level, space)
        |> set_estimator(estimator)
      use state <- result.try(apply_acknowledged_packets(
        state,
        level,
        acknowledged,
        now_milliseconds,
      ))
      use state <- result.try(apply_lost_packets(
        state,
        level,
        lost,
        smaller_packet_acknowledged,
        now_milliseconds,
      ))
      apply_ack_ecn(state, acknowledgement, acknowledged, now_milliseconds)
    }
  }
}

fn set_estimator(state: State, estimator: rtt.Estimator) -> State {
  State(..state, estimator: estimator)
}

fn apply_acknowledged_packets(
  state: State,
  level: engine.EncryptionLevel,
  packets: List(packet_space.SentPacket),
  now_milliseconds: Int,
) -> Result(State, Error) {
  case packets {
    [] -> Ok(state)
    [packet, ..rest] -> {
      use state <- result.try(acknowledge_congestion_packet(
        state,
        packet,
        now_milliseconds,
      ))
      use state <- result.try(acknowledge_pmtu_packet(state, packet))
      use state <- result.try(acknowledge_packet_frames(state, packet.frames))
      let state =
        acknowledge_key_phase_packet(state, level, packet.packet_number)
      apply_acknowledged_packets(state, level, rest, now_milliseconds)
    }
  }
}

fn acknowledge_key_phase_packet(
  state: State,
  level: engine.EncryptionLevel,
  packet_number: Int,
) -> State {
  case level, state.one_rtt_key_phase {
    engine.OneRtt, Some(key_state) ->
      install_key_phase_state(
        state,
        key_phase.acknowledge(key_state, packet_number),
        reset_usage: False,
      )
    _, _ -> state
  }
}

fn acknowledge_pmtu_packet(
  state: State,
  packet: packet_space.SentPacket,
) -> Result(State, Error) {
  case pmtu.outstanding_probe(state.pmtu), packet_is_pmtu_probe(packet) {
    Some(size), True if size == packet.sent_bytes ->
      case pmtu.probe_acked(state.pmtu, size) {
        Ok(path_mtu) -> Ok(put_path_mtu(state, path_mtu))
        Error(error) -> Error(PmtuFailure(error))
      }
    _, _ -> Ok(state)
  }
}

fn acknowledged_smaller_than_probe(
  state: State,
  packets: List(packet_space.SentPacket),
) -> Bool {
  case pmtu.outstanding_probe(state.pmtu) {
    None -> False
    Some(probe_size) ->
      list.any(packets, fn(packet) { packet.sent_bytes < probe_size })
  }
}

/// Whether a sent packet has the exact shape `driver` gives a DPLPMTUD probe:
/// a PING padded out to the size under test and nothing else. A PTO probe
/// carries retransmitted frames alongside its PING, so it keeps its ordinary
/// congestion response even when its size happens to match.
fn packet_is_pmtu_probe(packet: packet_space.SentPacket) -> Bool {
  case packet.frames {
    [frame.Ping, frame.Padding(_)] -> True
    _ -> False
  }
}

fn acknowledge_congestion_packet(
  state: State,
  packet: packet_space.SentPacket,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case packet.in_flight {
    False -> Ok(state)
    True -> {
      let congestion = case state.congestion {
        RenoState(reno) -> acknowledge_reno(reno, packet)
        CubicState(cubic_state) ->
          acknowledge_cubic(
            cubic_state,
            packet,
            state.estimator,
            now_milliseconds,
          )
      }
      use congestion <- result.try(congestion)
      Ok(State(..state, congestion: congestion))
    }
  }
}

fn acknowledge_reno(
  state: new_reno.State,
  packet: packet_space.SentPacket,
) -> Result(CongestionState, Error) {
  case
    new_reno.on_packet_acked(
      state,
      packet.sent_bytes,
      packet.time_sent_milliseconds,
      False,
    )
  {
    Ok(updated) -> Ok(RenoState(updated))
    Error(_) -> Error(InvalidInput)
  }
}

fn acknowledge_cubic(
  state: cubic.State,
  packet: packet_space.SentPacket,
  estimator: rtt.Estimator,
  now_milliseconds: Int,
) -> Result(CongestionState, Error) {
  let rtt.Snapshot(_, smoothed, _, _) = rtt.snapshot(estimator)
  case
    cubic.on_packet_acked(
      state,
      packet.sent_bytes,
      packet.time_sent_milliseconds,
      now_milliseconds,
      smoothed,
      False,
    )
  {
    Ok(updated) -> Ok(CubicState(updated))
    Error(_) -> Error(InvalidInput)
  }
}

fn acknowledge_packet_frames(
  state: State,
  frames: List(frame.Frame),
) -> Result(State, Error) {
  case frames {
    [] -> Ok(state)
    [frame.Stream(identifier, _, _, _) as sent, ..rest] -> {
      use state <- result.try(acknowledge_stream_frame(state, identifier, sent))
      acknowledge_packet_frames(state, rest)
    }
    [_, ..rest] -> acknowledge_packet_frames(state, rest)
  }
}

fn acknowledge_stream_frame(
  state: State,
  identifier: Int,
  sent: frame.Frame,
) -> Result(State, Error) {
  case dict.has_key(state.streams, identifier) {
    False -> Ok(state)
    True ->
      case dict.get(state.streams, identifier) {
        Error(_) -> Error(StreamFailure)
        Ok(stream) ->
          case stream_state.on_frame_acked(stream, sent) {
            Error(_) -> Error(StreamFailure)
            Ok(stream) ->
              Ok(
                State(
                  ..state,
                  streams: dict.insert(state.streams, identifier, stream),
                )
                |> cleanup_stream_if_terminal(identifier),
              )
          }
      }
  }
}

fn apply_lost_packets(
  state: State,
  level: engine.EncryptionLevel,
  packets: List(packet_space.SentPacket),
  smaller_packet_acknowledged: Bool,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case packets {
    [] -> Ok(state)
    [packet, ..rest] -> {
      let state = case frames_ack_eliciting(packet.frames) {
        True -> State(..state, retransmissions: state.retransmissions + 1)
        False -> state
      }
      use state <- result.try(case outstanding_pmtu_probe(state, packet) {
        True -> abandon_pmtu_probe(state, packet)
        False -> lose_congestion_packet(state, packet, now_milliseconds)
      })
      use state <- result.try(lose_pmtu_packet(
        state,
        packet,
        smaller_packet_acknowledged,
      ))
      use state <- result.try(requeue_lost_frames(state, level, packet.frames))
      apply_lost_packets(
        state,
        level,
        rest,
        smaller_packet_acknowledged,
        now_milliseconds,
      )
    }
  }
}

fn lose_pmtu_packet(
  state: State,
  packet: packet_space.SentPacket,
  smaller_packet_acknowledged: Bool,
) -> Result(State, Error) {
  case pmtu.outstanding_probe(state.pmtu), packet_is_pmtu_probe(packet) {
    Some(size), True if size == packet.sent_bytes ->
      case pmtu.probe_lost(state.pmtu, size, smaller_packet_acknowledged) {
        Ok(path_mtu) -> Ok(put_path_mtu(state, path_mtu))
        Error(error) -> Error(PmtuFailure(error))
      }
    _, _ -> Ok(state)
  }
}

/// Whether this lost packet is exactly the DPLPMTUD probe currently under
/// test. RFC 9002 section 3: a probe is deliberately larger than the confirmed
/// path, so losing one is not evidence of congestion.
fn outstanding_pmtu_probe(
  state: State,
  packet: packet_space.SentPacket,
) -> Bool {
  case pmtu.outstanding_probe(state.pmtu) {
    Some(size) -> size == packet.sent_bytes && packet_is_pmtu_probe(packet)
    None -> False
  }
}

/// Retire a lost probe's bytes without a congestion response.
fn abandon_pmtu_probe(
  state: State,
  packet: packet_space.SentPacket,
) -> Result(State, Error) {
  case packet.in_flight {
    False -> Ok(state)
    True ->
      abandon_early_congestion(state.congestion, packet.sent_bytes)
      |> result.map(fn(congestion) { State(..state, congestion: congestion) })
  }
}

fn lose_congestion_packet(
  state: State,
  packet: packet_space.SentPacket,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case packet.in_flight {
    False -> Ok(state)
    True -> {
      let congestion = case state.congestion {
        RenoState(reno) ->
          case
            new_reno.on_packet_lost(
              reno,
              packet.sent_bytes,
              packet.time_sent_milliseconds,
              now_milliseconds,
            )
          {
            Ok(updated) -> Ok(RenoState(updated))
            Error(_) -> Error(InvalidInput)
          }
        CubicState(cubic_state) ->
          case
            cubic.on_packet_lost(
              cubic_state,
              packet.sent_bytes,
              packet.time_sent_milliseconds,
              now_milliseconds,
            )
          {
            Ok(updated) -> Ok(CubicState(updated))
            Error(_) -> Error(InvalidInput)
          }
      }
      use congestion <- result.try(congestion)
      Ok(State(..state, congestion: congestion))
    }
  }
}

fn requeue_lost_frames(
  state: State,
  level: engine.EncryptionLevel,
  frames: List(frame.Frame),
) -> Result(State, Error) {
  case frames {
    [] -> Ok(state)
    [value, ..rest] -> {
      use state <- result.try(requeue_lost_frame(state, level, value))
      requeue_lost_frames(state, level, rest)
    }
  }
}

fn requeue_lost_frame(
  state: State,
  level: engine.EncryptionLevel,
  value: frame.Frame,
) -> Result(State, Error) {
  case value {
    frame.Stream(identifier, _, _, _) ->
      case dict.has_key(state.streams, identifier) {
        False -> Ok(state)
        True ->
          case dict.get(state.streams, identifier) {
            Error(_) -> Error(StreamFailure)
            Ok(stream) ->
              case stream_state.on_frame_lost(stream, value) {
                Error(_) -> Error(StreamFailure)
                Ok(stream) ->
                  Ok(
                    State(
                      ..state,
                      streams: dict.insert(state.streams, identifier, stream),
                    ),
                  )
              }
          }
      }
    frame.Padding(_)
    | frame.Ack(_)
    | frame.Datagram(_)
    | frame.ConnectionCloseTransport(_, _, _)
    | frame.ConnectionCloseApplication(_, _)
    | frame.PathResponse(_) -> Ok(state)
    _ -> Ok(prepend_queue(state, level, value))
  }
}

fn prepend_queue(
  state: State,
  level: engine.EncryptionLevel,
  value: frame.Frame,
) -> State {
  case level {
    engine.Initial ->
      State(..state, initial_queue: [value, ..state.initial_queue])
    engine.Handshake ->
      State(..state, handshake_queue: [value, ..state.handshake_queue])
    engine.ZeroRtt ->
      State(..state, zero_rtt_queue: [value, ..state.zero_rtt_queue])
    engine.OneRtt ->
      State(..state, application_queue: [value, ..state.application_queue])
  }
}

fn apply_ack_ecn(
  state: State,
  acknowledgement: frame.Acknowledgement,
  acknowledged: List(packet_space.SentPacket),
  now_milliseconds: Int,
) -> Result(State, Error) {
  let frame.Acknowledgement(_, ranges, feedback) = acknowledgement
  case ranges {
    [] -> Error(ProtocolViolation)
    [frame.AckRange(_, largest), ..] -> {
      let markings = acknowledged_markings(acknowledged, 0, 0)
      let feedback = map_ecn_feedback(feedback)
      case ecn.on_ack(state.ecn, largest, markings, feedback) {
        Error(_) -> Error(ProtocolViolation)
        Ok(ecn.AckResult(ecn_state, newly_ce)) ->
          finish_ecn_ack(state, ecn_state, newly_ce, now_milliseconds)
      }
    }
  }
}

fn finish_ecn_ack(
  state: State,
  ecn_state: ecn.State,
  newly_congestion_experienced: Int,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let state = State(..state, ecn: ecn_state)
  case newly_congestion_experienced > 0 {
    False -> Ok(state)
    True -> congestion_experienced(state, now_milliseconds)
  }
}

fn acknowledged_markings(
  packets: List(packet_space.SentPacket),
  ect0: Int,
  ect1: Int,
) -> ecn.Acknowledged {
  case packets {
    [] -> ecn.Acknowledged(ect0, ect1)
    [packet, ..rest] ->
      case packet.ecn {
        ecn.Ect0 -> acknowledged_markings(rest, ect0 + 1, ect1)
        ecn.Ect1 -> acknowledged_markings(rest, ect0, ect1 + 1)
        ecn.NotEct -> acknowledged_markings(rest, ect0, ect1)
      }
  }
}

fn map_ecn_feedback(feedback: Option(frame.EcnCounts)) -> Option(ecn.Counts) {
  case feedback {
    None -> None
    Some(frame.EcnCounts(ect0, ect1, ce)) -> Some(ecn.Counts(ect0, ect1, ce))
  }
}

fn congestion_experienced(
  state: State,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let congestion = case state.congestion {
    RenoState(reno) ->
      case
        new_reno.on_packet_lost(reno, 0, now_milliseconds, now_milliseconds)
      {
        Ok(updated) -> Ok(RenoState(updated))
        Error(_) -> Error(InvalidInput)
      }
    CubicState(cubic_state) ->
      case
        cubic.on_packet_lost(cubic_state, 0, now_milliseconds, now_milliseconds)
      {
        Ok(updated) -> Ok(CubicState(updated))
        Error(_) -> Error(InvalidInput)
      }
  }
  use congestion <- result.try(congestion)
  Ok(State(..state, congestion: congestion))
}

fn close_valid(
  state: State,
  application_error_code: Int,
  reason: String,
  now_milliseconds: Int,
) -> Result(State, Error) {
  let has_one_rtt = keys_available(state, engine.OneRtt, Write)
  case state.phase, has_one_rtt {
    Closed, _ | Draining, _ -> Error(ConnectionUnavailable)
    Closing, _ -> Ok(state)
    Handshaking, False -> Error(ConnectionUnavailable)
    Handshaking, True | Established, _ ->
      Ok(
        State(
          ..queue_application_frame(
            state,
            frame.ConnectionCloseApplication(
              application_error_code,
              bounded_reason(reason),
            ),
          ),
          phase: Closing,
          close_deadline_milliseconds: Some(
            now_milliseconds + state.config.draining_timeout_milliseconds,
          ),
        ),
      )
  }
}

fn tick_monotonic(state: State, now_milliseconds: Int) -> Result(State, Error) {
  case state.phase, state.close_deadline_milliseconds {
    Closed, _ -> Ok(state)
    Closing, Some(deadline) if now_milliseconds >= deadline ->
      Ok(State(..state, phase: Closed))
    Draining, Some(deadline) if now_milliseconds >= deadline ->
      Ok(State(..state, phase: Closed))
    Closing, _ | Draining, _ -> Ok(state)
    _, _
      if now_milliseconds
      >= state.last_activity_milliseconds
      + state.config.idle_timeout_milliseconds
    -> Ok(State(..state, phase: Closed))
    Handshaking, _ | Established, _ -> tick_recovery(state, now_milliseconds)
  }
}

fn tick_recovery(state: State, now_milliseconds: Int) -> Result(State, Error) {
  use state <- result.try(tick_packet_space(
    state,
    engine.Initial,
    now_milliseconds,
  ))
  use state <- result.try(tick_packet_space(
    state,
    engine.Handshake,
    now_milliseconds,
  ))
  tick_packet_space(state, engine.OneRtt, now_milliseconds)
}

fn tick_packet_space(
  state: State,
  level: engine.EncryptionLevel,
  now_milliseconds: Int,
) -> Result(State, Error) {
  case packet_space_discarded(state, level) {
    True -> Ok(state)
    False -> {
      let space = packet_space_for_level(state, level)
      case
        packet_space.on_timeout(
          space,
          now_milliseconds,
          state.estimator,
          state.handshake_confirmed,
          timer_granularity_milliseconds,
        )
      {
        Error(_) -> Error(PacketSpaceFailure)
        Ok(packet_space.NoTimeout(space)) ->
          Ok(put_packet_space(state, level, space))
        Ok(packet_space.ProbeTimeout(space, _)) ->
          Ok(
            put_packet_space(state, level, space)
            |> prepend_queue(level, frame.Ping)
            |> update_ecn_timeout,
          )
        Ok(packet_space.LossTimeout(space, lost, _)) ->
          put_packet_space(state, level, space)
          |> apply_lost_packets(level, lost, False, now_milliseconds)
      }
    }
  }
}

fn update_ecn_timeout(state: State) -> State {
  State(..state, ecn: ecn.on_probe_timeout(state.ecn))
}

fn map_frame_result(value: Result(value, frame.Error)) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(error) -> Error(FrameCodecFailure(error))
  }
}

fn map_wire_result(
  value: Result(value, wire_packet.Error),
) -> Result(value, Error) {
  case value {
    Ok(decoded) -> Ok(decoded)
    Error(wire_packet.InvalidReservedBits) -> Error(ProtocolViolation)
    Error(error) -> Error(WirePacketFailure(error))
  }
}

fn map_key_phase_result(
  value: Result(value, key_phase.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(KeyUpdateFailure(error))
  }
}

fn map_tls_result(value: Result(value, engine.Error)) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(TlsFailure(error))
  }
}

fn map_aead_usage_result(
  value: Result(value, aead_usage.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(AeadUsageFailure(error))
  }
}

fn map_path_validation_result(
  value: Result(value, path_validation.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(PathValidationFailure(error))
  }
}

fn map_connection_id_result(
  value: Result(value, connection_id.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(ConnectionIdFailure(error))
  }
}

fn datagram_payload_for_frame_limit(
  frame_limit: Int,
  candidate: Int,
) -> Result(Int, Error) {
  case candidate < 0 {
    True -> Error(DatagramTooLarge(frame_limit))
    False -> {
      use length_bytes <- result.try(
        varint.encoded_size(candidate)
        |> result.map_error(fn(_) { InvalidInput }),
      )
      let adjusted = frame_limit - 1 - length_bytes
      case adjusted == candidate {
        True -> Ok(candidate)
        False -> datagram_payload_for_frame_limit(frame_limit, adjusted)
      }
    }
  }
}

fn switch_congestion_algorithm(
  state: State,
  algorithm: CongestionAlgorithm,
) -> Result(State, Error) {
  case state.config.congestion_algorithm == algorithm {
    True -> Ok(state)
    False -> {
      let in_flight = bytes_in_flight(state)
      // The replacement controller starts on the path this connection is
      // actually sending on. Sizing it from the configured
      // max_udp_payload_size instead would hand a live connection an initial
      // window of ten datagrams it has never been able to send, and would
      // leave RFC 9002 section 7.2's window floor above every real datagram.
      let datagram_bytes = path_mtu(state)
      let next = case algorithm {
        NewReno ->
          case new_reno.new(datagram_bytes) {
            Error(_) -> Error(InvalidConfiguration)
            Ok(controller) ->
              new_reno.on_packet_sent(controller, in_flight, in_flight > 0)
              |> result.map(RenoState)
              |> result.map_error(fn(_) { InvalidInput })
          }
        Cubic ->
          case cubic.new(datagram_bytes) {
            Error(_) -> Error(InvalidConfiguration)
            Ok(controller) ->
              cubic.on_packet_sent(controller, in_flight, in_flight > 0)
              |> result.map(CubicState)
              |> result.map_error(fn(_) { InvalidInput })
          }
      }
      use next <- result.try(next)
      Ok(
        State(
          ..state,
          config: Config(..state.config, congestion_algorithm: algorithm),
          congestion: next,
        ),
      )
    }
  }
}

/// Frame-decoding limits for one decrypted 1-RTT packet.
///
/// `frame.decode_all` charges PADDING one unit per byte, so a path-sized
/// packet - a DPLPMTUD probe above all - exhausts the 4096-unit default long
/// before its frames are decoded. The budget therefore grows to the packet's
/// own length, which is the tightest bound that still admits a full-size
/// packet: no frame encodes in less than one byte, so the peer can never buy
/// more decoding work than the bytes it authenticated, and the datagram size
/// is itself bounded by the max_udp_payload_size this endpoint advertised.
///
/// This applies to 1-RTT packets alone. They are protected by keys only a
/// completed handshake yields, so the sender is an authenticated peer rather
/// than anyone who can observe a connection ID.
fn short_packet_frame_limits(plaintext: BitArray) -> frame.Limits {
  let defaults = frame.default_limits()
  frame.Limits(
    ..defaults,
    max_frames: maximum(defaults.max_frames, bit_array.byte_size(plaintext)),
  )
}

/// Truncate a caller's reason phrase to what CONNECTION_CLOSE can carry on the
/// smallest path this connection can fall back to.
///
/// The frame is reliable and indivisible: it cannot be split to fit a packet
/// and it cannot be dropped, so the phrase is bounded here rather than
/// producing an oversized datagram once a black hole resets the path to the
/// 1200-byte floor. Truncation walks graphemes so what survives is still valid
/// UTF-8.
fn bounded_reason(reason: String) -> String {
  case string.byte_size(reason) <= maximum_close_reason_bytes {
    True -> reason
    False ->
      take_reason_graphemes(
        string.to_graphemes(reason),
        maximum_close_reason_bytes,
        "",
      )
  }
}

fn take_reason_graphemes(
  graphemes: List(String),
  remaining: Int,
  taken: String,
) -> String {
  case graphemes {
    [] -> taken
    [grapheme, ..rest] ->
      case string.byte_size(grapheme) > remaining {
        True -> taken
        False ->
          take_reason_graphemes(
            rest,
            remaining - string.byte_size(grapheme),
            taken <> grapheme,
          )
      }
  }
}

fn minimum(left: Int, right: Int) -> Int {
  case left < right {
    True -> left
    False -> right
  }
}

fn maximum(left: Int, right: Int) -> Int {
  case left > right {
    True -> left
    False -> right
  }
}
