//// One reusable generic QUIC client connection and its UDP pump.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core.{type AddressFamily, DualStack, Ipv4, Ipv6}
import quic_core/internal/connection_state as transport
import quic_core/internal/crypto
import quic_core/internal/driver
import quic_core/internal/ecn
import quic_core/internal/local_connection_id
import quic_core/internal/runtime/connect_trace
import quic_core/internal/runtime/connection
import quic_core/internal/runtime/connection_race
import quic_core/internal/runtime/destination_order
import quic_core/internal/runtime/happy_eyeballs
import quic_core/internal/runtime/path_gate
import quic_core/internal/stream_state
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/hello
import quic_core/internal/tls/session_ticket
import quic_core/internal/udp
import quic_core/internal/version_negotiation
import quic_core/stream_id
import quic_core/transport_parameter
import quic_core/version.{type Version}

const maximum_packets_per_flush = 64

// Pre-validation floor for one packet's frame payload.
// The send path widens it to whatever DPLPMTUD has validated for the current path.
const maximum_frame_data_bytes = 1000

const connection_id_bytes = 8

// RFC 9000 section 18.2: max_udp_payload_size is a limit on what this endpoint is willing to receive, and its default is 65_527.
// Sending stays governed by DPLPMTUD, which starts at the 1200-byte floor and probes every larger size.
const maximum_udp_payload_size = 65_527

/// Validated client transport policy.
pub type Config {
  Config(
    /// The process this connection is being established for.
    /// Establishment blocks, so the owner has to be watched from inside those waits: without it an abandoned attempt keeps its candidate sockets until the handshake deadline, long after anything could still use the connection.
    owner: Pid,
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    connect_address: Option(BitArray),
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    total_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    trust_store: authentication.TrustStore,
    client_credential: Option(engine.ClientCredential),
    application_protocols: List(BitArray),
    resumption_ticket: Option(session_ticket.ClientTicket),
    allow_zero_rtt: Bool,
    address_token: BitArray,
    version: Version,
    congestion_control: transport.CongestionAlgorithm,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    stream_buffer_limit: Int,
    datagram_limit: Int,
    connect_port: Int,
    connect_trace: Option(connect_trace.Context),
  )
}

/// A socket, current path, and generic QUIC connection state.
pub opaque type State {
  State(
    socket: udp.Socket,
    connection: connection.State,
    previous_socket: Option(udp.Socket),
    version: Version,
    application_protocol: BitArray,
    connect_trace: Option(connect_trace.Context),
    tls_observed: Bool,
  )
}

/// Resolution, socket, TLS, QUIC, timeout, or migration failure.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  TotalTimeout
  TlsHandshakeFailed
  QuicFailure(driver.Error)
  /// The peer closed the connection during the handshake, with the close code it named when one was carried.
  PeerClosed(code: Option(Int))
  PeerTransportClosed(code: Int)
  MigrationUnavailable
  LocalConnectionIdUnavailable
  VersionNegotiationReceived(List(Version))
  VersionNegotiationFailed
  /// The process this connection was being established for exited first, so the attempt was abandoned rather than completed or timed out.
  OwnerGone
}

/// Resolve, race, authenticate, and establish one generic QUIC connection.
pub fn connect(config: Config) -> Result(State, Error) {
  connect_owned(
    config,
    None,
    udp.monotonic_millisecond() + config.total_timeout_milliseconds,
  )
}

/// Establish inside the public bootstrap's already admitted supervisor.
pub fn connect_in(
  config: Config,
  group: udp.WorkGroup,
  deadline: Int,
) -> Result(State, Error) {
  connect_owned(config, Some(group), deadline)
}

fn connect_owned(
  config: Config,
  group: Option(udp.WorkGroup),
  deadline: Int,
) -> Result(State, Error) {
  use Nil <- result.try(validate(config))
  let now = udp.monotonic_millisecond()
  let #(ipv4, ipv6) = resolved_families(config)
  connect_trace.record(config.connect_trace, 1, case config.connect_address {
    Some(_) -> 5
    None -> 1
  })
  let policy =
    connection_race.Policy(
      config.owner,
      ipv4,
      ipv6,
      int.min(deadline, now + config.dns_timeout_milliseconds),
      deadline,
    )
  let operations =
    connection_race.Operations(
      resolve: fn(family) { resolve_family(config, family) },
      dial: fn(candidate, ordinal, confirm) {
        connect_address(
          Config(
            ..config,
            connect_trace: connect_trace.candidate(
              config.connect_trace,
              ordinal,
            ),
          ),
          candidate.address,
          deadline,
          confirm,
        )
      },
      adopt: adopt_candidate,
      discard: discard_state,
      compare: destination_order.compare,
      prefer_error: fn(previous, incoming) {
        case
          candidate_error_priority(incoming)
          > candidate_error_priority(previous)
        {
          True -> incoming
          False -> previous
        }
      },
      abandon: fn(ordinal) {
        connect_trace.abandon(connect_trace.candidate(
          config.connect_trace,
          ordinal,
        ))
      },
      resolution: fn(family, outcome) {
        case config.connect_address {
          Some(_) -> Nil
          None ->
            connect_trace.resolution(config.connect_trace, family, outcome)
        }
      },
      // NameResolution ends when the first candidate becomes eligible to dial.
      // It does not claim that both asynchronous DNS queries succeeded.
      eligible: fn() {
        case config.connect_address {
          Some(_) -> Nil
          None -> connect_trace.record(config.connect_trace, 1, 2)
        }
      },
      spawn: fn(group, kind, work) {
        udp.spawn_work(group, kind, work) |> result.replace_error(Nil)
      },
      cleanup: fn(group, owns_group, owner_alive) {
        case owns_group, owner_alive {
          _, False -> udp.stop_work_group_after_owner_exit(group)
          True, True -> udp.stop_work_group(group)
          False, True -> udp.quiesce_work_group(group)
        }
        |> result.replace_error(Nil)
      },
    )
  let outcome =
    case group {
      None -> connection_race.run(policy, operations)
      Some(group) -> connection_race.run_in(group, policy, operations)
    }
    |> result.map_error(race_error)
  case outcome {
    Ok(state) -> {
      connect_trace.record(state.connect_trace, 4, 1)
      // The socket is now held by the connection actor; the bootstrap owner observes publication separately when it receives that actor's handle.
      Ok(state)
    }
    Error(error) -> {
      connect_trace.fail_resolution_if_pending(config.connect_trace)
      Error(error)
    }
  }
}

fn resolved_families(config: Config) -> #(Bool, Bool) {
  case config.connect_address {
    Some(bytes) -> #(
      bit_array.byte_size(bytes) == 4,
      bit_array.byte_size(bytes) == 16,
    )
    None ->
      case config.address_family {
        Ipv4 -> #(True, False)
        Ipv6 -> #(False, True)
        DualStack -> #(True, True)
      }
  }
}

fn resolve_family(
  config: Config,
  family: happy_eyeballs.Family,
) -> Result(List(destination_order.Candidate), Error) {
  let addresses = case config.connect_address {
    Some(bytes) ->
      udp.address_from_bytes(bytes)
      |> result.map(fn(address) { [address] })
      |> result.replace_error(InvalidInput)
    None ->
      udp.resolve(config.hostname, case family {
        happy_eyeballs.Ipv4 -> udp.Ipv4
        happy_eyeballs.Ipv6 -> udp.Ipv6
      })
      |> result.replace_error(ResolutionFailed)
  }
  use addresses <- result.try(addresses)
  Ok(
    addresses
    |> list.take(16)
    |> list.map(fn(address) {
      destination_order.observe(address, config.connect_port)
    }),
  )
}

fn adopt_candidate(state: State, owner: Pid) -> Result(State, Error) {
  case udp.transfer_owner(state.socket, owner) {
    Ok(Nil) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
  }
}

fn race_error(error: connection_race.Failure(Error)) -> Error {
  case error {
    connection_race.Rejected(error) -> error
    connection_race.ResolutionFailed -> ResolutionFailed
    connection_race.DnsTimeout -> DnsTimeout
    connection_race.TotalTimeout -> TotalTimeout
    connection_race.OwnerGone -> OwnerGone
    connection_race.WorkerLost | connection_race.CleanupFailed(_) ->
      SocketUnavailable
  }
}

/// Pull and clear ordered transport events.
pub fn take_events(
  state: State,
) -> Result(#(State, List(transport.Event)), Error) {
  let state = observe_tls(state)
  let #(next, events) = connection.take_events(state.connection)
  use state <- result.try(settle_migration(
    State(..state, connection: next),
    events,
  ))
  Ok(#(state, events))
}

pub fn local_transport_failure_code(state: State) -> Option(Int) {
  connection.local_transport_failure_code(state.connection)
}

/// Advance protocol timers and flush bounded output.
pub fn drive(state: State) -> Result(State, Error) {
  let now = udp.monotonic_millisecond()
  use next <- result.try(
    connection.tick(state.connection, now) |> result.map_error(QuicFailure),
  )
  let state = State(..state, connection: next)
  case connection.phase(next) {
    // Reaching the fixed terminal bound is successful progress.
    // There is no packet space left to flush; the owning actor now releases the sockets.
    transport.Closed | transport.Draining -> Ok(state)
    transport.Handshaking | transport.Established | transport.Closing ->
      flush(state, now, maximum_packets_per_flush)
  }
}

/// Return the earliest protocol deadline for an event-driven owner.
pub fn next_deadline(state: State, now: Int) -> Result(Option(Int), Error) {
  connection.next_deadline(state.connection, now)
  |> result.map_error(QuicFailure)
}

/// Explain the payload-free pacing decision used by `next_deadline`.
pub fn pacing_wake_progress(
  state: State,
  now: Int,
) -> transport.PacingWakeProgress {
  connection.pacing_wake_progress(state.connection, now)
}

/// Arm the current and candidate-path sockets for one mailbox delivery each.
pub fn activate_once(state: State) -> Result(Nil, Error) {
  use Nil <- result.try(
    udp.activate_once(state.socket) |> result.replace_error(SocketUnavailable),
  )
  case state.previous_socket {
    None -> Ok(Nil)
    Some(socket) ->
      udp.activate_once(socket) |> result.replace_error(SocketUnavailable)
  }
}

/// Consume one active-mode datagram from either live path.
pub fn receive_active(state: State, message: Dynamic) -> Result(State, Error) {
  case udp.receive_active(state.socket, message) {
    Ok(datagram) ->
      process_received_datagram(state, datagram, case state.previous_socket {
        Some(_) -> path_gate.Candidate
        None -> path_gate.Active
      })
    // An unauthenticated ICMP advisory cannot discard already authenticated bytes or restart path/operation deadlines.
    // The actor rearms active-once reception and normal QUIC recovery determines whether the path works.
    Error(udp.UnverifiedPathError) -> Ok(state)
    Error(udp.InvalidInput) ->
      case state.previous_socket {
        None -> Error(InvalidInput)
        Some(socket) -> receive_previous_path(state, socket, message)
      }
    Error(_) -> Error(SocketUnavailable)
  }
}

fn receive_previous_path(
  state: State,
  socket: udp.Socket,
  message: Dynamic,
) -> Result(State, Error) {
  case udp.receive_active(socket, message) {
    Ok(datagram) -> process_received_datagram(state, datagram, path_gate.Active)
    Error(udp.UnverifiedPathError) -> Ok(state)
    // A value from another selector source is unrelated to either socket.
    Error(_) -> Error(InvalidInput)
  }
}

/// Open one locally initiated bidirectional or unidirectional stream.
pub fn open_stream(
  state: State,
  direction: stream_id.Direction,
) -> Result(#(State, Int), Error) {
  connection.open_stream(state.connection, direction)
  |> result.map(fn(opened) {
    let #(next, identifier) = opened
    #(State(..state, connection: next), identifier)
  })
  |> result.map_error(QuicFailure)
}

/// Queue bytes and an optional stream FIN.
pub fn send(
  state: State,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
) -> Result(State, Error) {
  connection.send(state.connection, identifier, bytes, finish)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Return retained send bytes for synchronous backpressure.
pub fn buffered_send_bytes(
  state: State,
  identifier: Int,
) -> Result(Int, Error) {
  connection.buffered_send_bytes(state.connection, identifier)
  |> result.map_error(QuicFailure)
}

/// Return whether this stream's FIN is acknowledged or its send direction has been reset, without exposing transport mutation state.
pub fn send_finished(state: State, identifier: Int) -> Result(Bool, Error) {
  connection.send_finished(state.connection, identifier)
  |> result.map_error(QuicFailure)
}

/// Pull one bounded stream read.
pub fn read(
  state: State,
  identifier: Int,
  maximum_bytes: Int,
) -> Result(#(State, connection.Read), Error) {
  connection.read(state.connection, identifier, maximum_bytes)
  |> result.map(fn(output) {
    let #(next, read) = output
    #(State(..state, connection: next), read)
  })
  |> result.map_error(QuicFailure)
}

/// Abort every locally usable stream direction.
pub fn reset(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  connection.reset(state.connection, identifier, application_error_code)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Queue STOP_SENDING without resetting the local send direction.
pub fn stop_sending(
  state: State,
  identifier: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  connection.stop_sending(state.connection, identifier, application_error_code)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Queue one negotiated QUIC Datagram.
pub fn send_datagram(state: State, payload: BitArray) -> Result(State, Error) {
  connection.send_datagram(state.connection, payload)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Largest raw QUIC Datagram payload on the current path.
pub fn maximum_datagram_size(state: State) -> Result(Int, Error) {
  connection.maximum_datagram_size(state.connection)
  |> result.map_error(QuicFailure)
}

/// Largest raw QUIC Datagram payload guaranteed across ACK and path changes.
pub fn guaranteed_datagram_size(state: State) -> Result(Int, Error) {
  connection.guaranteed_datagram_size(state.connection)
  |> result.map_error(QuicFailure)
}

/// Queue one ack-eliciting PING.
pub fn ping(state: State) -> Result(State, Error) {
  connection.ping(state.connection)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Change the live congestion controller.
pub fn set_congestion_control(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, Error) {
  connection.set_congestion_control(state.connection, algorithm)
  |> result.map(fn(next) { State(..state, connection: next) })
  |> result.map_error(QuicFailure)
}

/// Begin migration from a fresh local UDP path.
pub fn migrate(state: State) -> Result(State, Error) {
  migrate_at(state, udp.monotonic_millisecond())
}

/// Deterministic clock entry for migration fault tests; normal callers use `migrate`, which supplies the same monotonic clock as packet/timer work.
pub fn migrate_at(state: State, now: Int) -> Result(State, Error) {
  case
    state.previous_socket,
    connection.active_migration_available(state.connection)
  {
    Some(_), _ | _, False -> Error(MigrationUnavailable)
    None, True -> {
      // A new local address must use an unused peer-issued identifier.
      // Refuse before allocating a socket when the peer has supplied no spare.
      use rotated <- result.try(
        connection.rotate_peer_connection_id(state.connection)
        |> result.replace_error(MigrationUnavailable),
      )
      use challenge <- result.try(
        crypto.secure_random(8) |> result.replace_error(MigrationUnavailable),
      )
      use socket <- result.try(
        open_for_peer(connection.peer(state.connection))
        |> result.replace_error(MigrationUnavailable),
      )
      case connection.begin_path_validation(rotated, challenge, True, now) {
        Error(_) -> {
          let _ = udp.close(socket)
          Error(MigrationUnavailable)
        }
        Ok(next) ->
          Ok(
            State(
              ..state,
              socket: socket,
              connection: next,
              previous_socket: Some(state.socket),
            ),
          )
      }
    }
  }
}

/// Current path diagnostics.
pub fn path_stats(state: State) -> transport.PathSnapshot {
  connection.path_stats(state.connection)
}

/// Bounded local-issuer occupancy without identifiers or reset tokens.
pub fn local_connection_id_snapshot(
  state: State,
) -> local_connection_id.Snapshot {
  connection.local_connection_id_snapshot(state.connection)
}

/// Fill only authenticated peer capacity, bounded by the local active/history limits.
/// The private socket accepts every active identifier directly, so no external routing registration is required before queuing NEW_CONNECTION_ID.
pub fn replenish_local_connection_ids(state: State) -> Result(State, Error) {
  case connection.local_connection_id_capacity(state.connection) > 0 {
    False -> Ok(state)
    True -> {
      use identifier <- result.try(
        crypto.secure_random(connection_id_bytes)
        |> result.replace_error(LocalConnectionIdUnavailable),
      )
      use token <- result.try(
        crypto.secure_random(16)
        |> result.replace_error(LocalConnectionIdUnavailable),
      )
      use next <- result.try(
        connection.issue_local_connection_id(
          state.connection,
          identifier,
          token,
        )
        |> result.map_error(QuicFailure),
      )
      replenish_local_connection_ids(State(..state, connection: next))
    }
  }
}

/// Runtime-owned counters.
pub fn stats(state: State) -> connection.Stats {
  connection.stats(state.connection)
}

/// Number of streams whose transport state is not yet fully terminal.
pub fn active_stream_count(state: State) -> Int {
  connection.active_stream_count(state.connection)
}

/// Payload-free connection send and recovery state for internal diagnostics.
pub fn send_progress(state: State) -> transport.SendProgress {
  connection.send_progress(state.connection)
}

/// Payload-free progress for one stream.
pub fn stream_send_progress(
  state: State,
  identifier: Int,
) -> Result(stream_state.SendProgress, Error) {
  connection.stream_send_progress(state.connection, identifier)
  |> result.map_error(QuicFailure)
}

/// Current non-fragmenting QUIC UDP payload size.
pub fn path_mtu(state: State) -> Int {
  connection.path_mtu(state.connection)
}

/// Whether DPLPMTUD has reached the current ceiling.
pub fn pmtu_discovery_complete(state: State) -> Bool {
  connection.pmtu_discovery_complete(state.connection)
}

pub fn pmtu_probe_outstanding(state: State) -> Bool {
  connection.pmtu_probe_outstanding(state.connection)
}

pub fn pmtu_probe_available(state: State) -> Bool {
  connection.pmtu_probe_available(state.connection)
}

/// Whether candidate path validation is in progress.
pub fn path_validation_in_progress(state: State) -> Bool {
  connection.path_validation_in_progress(state.connection)
}

/// Send and commit at most one DPLPMTUD probe.
pub fn probe_path_mtu(state: State, now: Int) -> Result(State, Error) {
  case connection.prepare_pmtu_probe(state.connection, now) {
    Error(error) -> Error(QuicFailure(error))
    Ok(None) -> Ok(state)
    Ok(Some(prepared)) -> {
      let bytes = connection.prepared_bytes(prepared)
      case
        udp.classify_send(udp.send(
          state.socket,
          connection.peer(state.connection),
          bytes,
          ecn.NotEct,
        ))
      {
        // The socket sets Don't-Fragment, so the kernel refuses a probe the local interface cannot carry whole.
        // Exclude this unsent size while retaining the already confirmed path; resetting only the floor and retrying the same ceiling would create an endless probe loop.
        udp.PathTooSmall ->
          connection.reject_pmtu_probe(prepared)
          |> result.map(fn(next) { State(..state, connection: next) })
          |> result.map_error(QuicFailure)
        udp.SocketLost -> Error(SocketUnavailable)
        udp.Delivered ->
          connection.commit_datagram(prepared, ecn.NotEct, now)
          |> result.map(fn(next) { State(..state, connection: next) })
          |> result.map_error(QuicFailure)
      }
    }
  }
}

/// Negotiated wire version retained without exposing TLS state.
pub fn version(state: State) -> Version {
  state.version
}

/// Negotiated application protocol retained without exposing TLS state.
pub fn application_protocol(state: State) -> BitArray {
  case connection.application_protocol(state.connection) {
    Some(protocol) -> protocol
    None -> state.application_protocol
  }
}

/// Negotiated cipher retained without exposing TLS keys or state.
pub fn cipher_suite(state: State) -> Option(hello.CipherSuite) {
  connection.cipher_suite(state.connection)
}

/// Whether the connection resumed the caller-supplied session.
pub fn resumed(state: State) -> Bool {
  connection.resumed(state.connection)
}

/// Stable connection lifecycle.
pub fn phase(state: State) -> transport.Phase {
  connection.phase(state.connection)
}

/// Enter the finite QUIC closing period without releasing either live path.
///
/// The owning actor emits the first CONNECTION_CLOSE before acknowledging the public close call, then keeps these sockets available until the transport's fixed close deadline.
/// This split is what lets a lost first close be answered when the peer retransmits.
pub fn begin_close(
  state: State,
  application_error_code: Int,
  reason: String,
) -> State {
  let now = udp.monotonic_millisecond()
  let closing =
    connection.close(state.connection, application_error_code, reason, now)
  State(..state, connection: closing)
}

/// Release every socket after a transport reached its terminal bound.
pub fn release(state: State) -> Nil {
  let _ = udp.close(state.socket)
  case state.previous_socket {
    Some(socket) -> {
      let _ = udp.close(socket)
      Nil
    }
    None -> Nil
  }
}

/// Best-effort emergency close followed by unconditional socket cleanup.
///
/// Normal public local closes use `begin_close` and retain the actor through Closing.
/// Failure paths use this operation because their owner can no longer safely drive protocol state.
pub fn close(state: State, application_error_code: Int, reason: String) -> Nil {
  connect_trace.abandon(state.connect_trace)
  let now = udp.monotonic_millisecond()
  let state = begin_close(state, application_error_code, reason)
  let _ = flush(state, now, 4)
  release(state)
}

fn settle_migration(
  state: State,
  events: List(transport.Event),
) -> Result(State, Error) {
  case state.previous_socket {
    None -> Ok(state)
    Some(previous_socket) -> {
      let validated = list.contains(events, transport.PathValidated)
      let failed = list.contains(events, transport.PathValidationFailed)
      case validated, failed {
        True, _ -> {
          let _ = udp.close(previous_socket)
          Ok(State(..state, previous_socket: None))
        }
        False, True -> {
          let _ = udp.close(state.socket)
          // The candidate consumed its identifier on a different local address.
          // Returning to the old socket therefore needs another unused identifier; it cannot reuse the candidate's identifier.
          resume_previous_socket(state, previous_socket)
        }
        False, False -> Ok(state)
      }
    }
  }
}

fn resume_previous_socket(
  state: State,
  previous_socket: udp.Socket,
) -> Result(State, Error) {
  case connection.rotate_peer_connection_id(state.connection) {
    Ok(next) ->
      Ok(
        State(
          ..state,
          socket: previous_socket,
          previous_socket: None,
          connection: next,
        ),
      )
    Error(_) -> {
      let _ = udp.close(previous_socket)
      Error(MigrationUnavailable)
    }
  }
}

fn candidate_error_priority(error: Error) -> Int {
  case error {
    TlsHandshakeFailed -> 100
    VersionNegotiationFailed | VersionNegotiationReceived(_) -> 90
    QuicFailure(_)
    | PeerClosed(_)
    | PeerTransportClosed(_)
    | LocalConnectionIdUnavailable -> 80
    HandshakeTimeout -> 60
    ConnectTimeout -> 50
    DnsTimeout | ResolutionFailed -> 40
    SocketUnavailable -> 30
    TotalTimeout -> 20
    MigrationUnavailable | InvalidInput -> 10
    // Never reported by a candidate: the race ends on owner exit without preferring one candidate's reason over another.
    OwnerGone -> 0
  }
}

fn discard_state(state: State) -> Nil {
  let _ = udp.close(state.socket)
  case state.previous_socket {
    Some(socket) -> {
      let _ = udp.close(socket)
      Nil
    }
    None -> Nil
  }
}

fn connect_address(
  config: Config,
  address: udp.Address,
  deadline: Int,
  confirm_reachability: Bool,
) -> Result(State, Error) {
  use peer <- result.try(
    udp.endpoint(address, config.connect_port)
    |> result.replace_error(InvalidInput),
  )
  connect_trace.record(config.connect_trace, 2, 1)
  let opened =
    open_for_address(address) |> result.replace_error(SocketUnavailable)
  connect_trace.record(config.connect_trace, 2, case opened {
    Ok(_) -> 2
    Error(_) -> 3
  })
  use socket <- result.try(opened)
  let connect_deadline =
    int.min(
      deadline,
      udp.monotonic_millisecond() + config.connect_timeout_milliseconds,
    )
  let outcome = case remaining_milliseconds(connect_deadline) <= 0 {
    True -> Error(ConnectTimeout)
    False -> {
      connect_trace.record(config.connect_trace, 3, 1)
      let established = establish(config, socket, peer, deadline)
      case established {
        Error(error) -> {
          connect_trace.record(config.connect_trace, 3, 3)
          Error(error)
        }
        Ok(state) ->
          confirm_candidate(config, state, deadline, confirm_reachability)
      }
    }
  }
  case outcome {
    Ok(state) -> Ok(state)
    Error(error) -> {
      let _ = udp.close(socket)
      Error(error)
    }
  }
}

fn confirm_candidate(
  config: Config,
  state: State,
  deadline: Int,
  confirm_reachability: Bool,
) -> Result(State, Error) {
  let should_confirm = case config.resumption_ticket {
    Some(ticket) ->
      config.allow_zero_rtt
      && session_ticket.early_data_allowed(ticket)
      && confirm_reachability
    None -> False
  }
  case should_confirm {
    True ->
      confirm_resumption_candidate(
        state,
        int.min(
          deadline,
          udp.monotonic_millisecond() + config.handshake_timeout_milliseconds,
        ),
      )
    False -> Ok(observe_tls(state))
  }
}

fn confirm_resumption_candidate(
  state: State,
  deadline: Int,
) -> Result(State, Error) {
  let connection.Stats(received, _, _, _, _, _, _, _) = stats(state)
  case received > 0, remaining_milliseconds(deadline) {
    True, _ -> Ok(state)
    False, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    False, _ -> {
      use state <- result.try(pump_until(state, deadline))
      confirm_resumption_candidate(state, deadline)
    }
  }
}

fn establish(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
) -> Result(State, Error) {
  use selected <- result.try(initial_connection_version(config))
  establish_version(
    config,
    socket,
    peer,
    int.min(
      deadline,
      udp.monotonic_millisecond() + config.handshake_timeout_milliseconds,
    ),
    selected,
    [],
  )
}

fn initial_connection_version(config: Config) -> Result(Version, Error) {
  case config.resumption_ticket {
    None -> Ok(config.version)
    Some(ticket) ->
      case version.from_wire(session_ticket.quic_version(ticket)) {
        Ok(version.Version1) -> Ok(version.Version1)
        Ok(version.Version2) -> Ok(version.Version2)
        _ -> Error(TlsHandshakeFailed)
      }
  }
}

fn establish_version(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(State, Error) {
  use original_destination_connection_id <- result.try(random_connection_id())
  use local_connection_id <- result.try(random_connection_id())
  let tls_config =
    engine.ClientConfig(
      version: selected_version,
      hostname: config.hostname,
      application_protocols: config.application_protocols,
      transport_parameters: client_transport_parameters(
        local_connection_id,
        config.datagram_limit,
        selected_version,
        config.resumption_ticket == None,
        config.idle_timeout_milliseconds,
        config.bidirectional_stream_limit,
        config.unidirectional_stream_limit,
      ),
      trust_store: config.trust_store,
      client_credential: config.client_credential,
      retried: False,
      version_negotiated: attempted_versions != [],
    )
  let now = udp.monotonic_millisecond()
  use tls <- result.try(
    case config.resumption_ticket {
      None -> engine.start_client(tls_config)
      Some(ticket) ->
        engine.start_client_resuming(
          tls_config,
          ticket,
          now,
          config.allow_zero_rtt && session_ticket.early_data_allowed(ticket),
        )
    }
    |> result.replace_error(TlsHandshakeFailed),
  )
  use quic <- result.try(
    driver.start_client_with_token(
      client_transport_config(
        config,
        selected_version,
        udp.dont_fragment(socket),
      ),
      tls,
      original_destination_connection_id,
      local_connection_id,
      config.address_token,
      now,
    )
    |> result.map_error(QuicFailure),
  )
  let state =
    State(
      socket,
      connection.new(peer, quic),
      None,
      selected_version,
      first_protocol(config.application_protocols),
      config.connect_trace,
      False,
    )
  let early_data = case config.resumption_ticket {
    Some(ticket) ->
      config.allow_zero_rtt && session_ticket.early_data_allowed(ticket)
    None -> False
  }
  case early_data {
    True -> Ok(state)
    False ->
      complete_handshake(
        config,
        state,
        deadline,
        selected_version,
        attempted_versions,
      )
  }
}

fn observe_tls(state: State) -> State {
  case state.tls_observed, connection.phase(state.connection) {
    False, transport.Established -> {
      connect_trace.record(state.connect_trace, 3, 2)
      State(..state, tls_observed: True)
    }
    False, transport.Closing
    | False, transport.Draining
    | False, transport.Closed
    -> {
      connect_trace.record(state.connect_trace, 3, 3)
      State(..state, tls_observed: True)
    }
    _, _ -> state
  }
}

/// Mark delivery of the actor handle to the caller after native setup.
pub fn published(state: State) -> Nil {
  connect_trace.record(state.connect_trace, 4, 2)
}

fn complete_handshake(
  config: Config,
  state: State,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(State, Error) {
  case handshake(state, deadline, attempted_versions != []) {
    Error(VersionNegotiationReceived(offered)) ->
      case
        version_negotiation.select_incompatible(selected_version, offered, [
          selected_version,
          ..attempted_versions
        ])
      {
        Error(_) -> Error(VersionNegotiationFailed)
        Ok(next_version) ->
          establish_version(
            case config.resumption_ticket {
              Some(_) -> Config(..config, resumption_ticket: None)
              None -> config
            },
            state.socket,
            connection.peer(state.connection),
            deadline,
            next_version,
            [selected_version, ..attempted_versions],
          )
      }
    outcome -> outcome
  }
}

fn handshake(
  state: State,
  deadline: Int,
  ignore_version_negotiation: Bool,
) -> Result(State, Error) {
  case phase(state), remaining_milliseconds(deadline) {
    transport.Established, _ -> Ok(state)
    // A peer that closes mid-handshake -- a server refusing this connection,
    // say -- is reported with the code it sent rather than as a deadline this attempt would otherwise have to wait out.
    transport.Closed, _ | transport.Draining, _ ->
      Error(peer_close_error(state))
    _, remaining if remaining <= 0 -> Error(HandshakeTimeout)
    _, _ -> {
      use state <- result.try(drive(state))
      let now = udp.monotonic_millisecond()
      use protocol_deadline <- result.try(next_deadline(state, now))
      use state <- result.try(receive_passive(
        state,
        wait_milliseconds(deadline, protocol_deadline, now),
        ignore_version_negotiation,
      ))
      handshake(state, deadline, ignore_version_negotiation)
    }
  }
}

/// The close the peer named, if it named one.
/// The events are taken from a connection this attempt is abandoning, so nothing else will read them.
fn peer_close_error(state: State) -> Error {
  let #(_discarded, events) = connection.take_events(state.connection)
  peer_close_code(events)
}

fn peer_close_code(events: List(transport.Event)) -> Error {
  case events {
    [] -> PeerClosed(None)
    [transport.PeerClosed(code, _reason), ..] -> PeerClosed(Some(code))
    [transport.PeerTransportClosed(code, _reason), ..] ->
      PeerTransportClosed(code)
    [_other, ..rest] -> peer_close_code(rest)
  }
}

fn pump_until(state: State, total_deadline: Int) -> Result(State, Error) {
  use state <- result.try(drive(state))
  let now = udp.monotonic_millisecond()
  use protocol_deadline <- result.try(next_deadline(state, now))
  receive_passive(
    state,
    wait_milliseconds(total_deadline, protocol_deadline, now),
    True,
  )
}

fn receive_passive(
  state: State,
  timeout: Int,
  ignore_version_negotiation: Bool,
) -> Result(State, Error) {
  case udp.receive(state.socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(peer, bytes, marking)) ->
      case same_endpoint(peer, connection.peer(state.connection)) {
        False -> Ok(state)
        True ->
          case
            connection.receive_datagram(
              state.connection,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(next) -> Ok(State(..state, connection: next))
            Error(driver.VersionNegotiationReceived(versions)) ->
              case ignore_version_negotiation {
                True -> Ok(state)
                False -> Error(VersionNegotiationReceived(versions))
              }
            Error(error) -> discard_or_fail(state, error)
          }
      }
  }
}

fn flush(
  state: State,
  now: Int,
  remaining_packets: Int,
) -> Result(State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case
        connection.prepare_datagram(
          state.connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Error(driver.ConnectionFailure(transport.PacingLimited(_)))
        | Error(driver.ConnectionFailure(transport.CongestionLimited))
        | Error(driver.ConnectionFailure(transport.RecoveryLimited)) ->
          Ok(state)
        Error(error) -> Error(QuicFailure(error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) ->
          send_prepared(state, prepared, now, remaining_packets)
      }
  }
}

/// Send one prepared datagram, then commit it and continue the flush.
///
/// A datagram the local stack refuses as too large is the path shrinking underneath a size DPLPMTUD had confirmed: the socket sets Don't-Fragment,
/// so the kernel will not split it.
/// It is dropped uncommitted, recovery retransmits its frames, and the next datagram is built for the floor.
fn send_prepared(
  state: State,
  prepared: connection.PreparedDatagram,
  now: Int,
  remaining_packets: Int,
) -> Result(State, Error) {
  case
    udp.classify_send(udp.send(
      state.socket,
      connection.peer(state.connection),
      connection.prepared_bytes(prepared),
      ecn.NotEct,
    ))
  {
    udp.PathTooSmall ->
      Ok(
        State(
          ..state,
          connection: connection.report_pmtu_black_hole(state.connection),
        ),
      )
    udp.SocketLost -> Error(SocketUnavailable)
    udp.Delivered -> {
      use next <- result.try(
        connection.commit_datagram(prepared, ecn.NotEct, now)
        |> result.map_error(QuicFailure),
      )
      flush(State(..state, connection: next), now, remaining_packets - 1)
    }
  }
}

fn process_received_datagram(
  state: State,
  datagram: udp.Datagram,
  source: path_gate.Source,
) -> Result(State, Error) {
  let udp.Datagram(peer, bytes, marking) = datagram
  case
    same_endpoint(peer, connection.peer(state.connection)),
    path_gate.may_authenticate(
      connection.path_validation_in_progress(state.connection),
      source,
    )
  {
    False, _ | _, False -> Ok(state)
    True, True ->
      case
        connection.receive_datagram(
          state.connection,
          bytes,
          marking,
          udp.monotonic_millisecond(),
        )
      {
        Ok(next) -> Ok(State(..state, connection: next))
        Error(error) -> discard_or_fail(state, error)
      }
  }
}

fn client_transport_config(
  config: Config,
  selected: Version,
  dont_fragment: Bool,
) -> transport.Config {
  let defaults = transport.default_config(transport.Client)
  transport.Config(
    ..defaults,
    version: selected,
    path_dont_fragment: dont_fragment,
    congestion_algorithm: config.congestion_control,
    idle_timeout_milliseconds: config.idle_timeout_milliseconds,
    maximum_peer_streams_bidirectional: config.bidirectional_stream_limit,
    maximum_peer_streams_unidirectional: config.unidirectional_stream_limit,
    maximum_stream_receive_buffer: config.stream_buffer_limit,
    maximum_stream_send_buffer: config.stream_buffer_limit,
    maximum_total_streams: config.bidirectional_stream_limit
      + config.unidirectional_stream_limit,
    maximum_udp_payload_size: maximum_udp_payload_size,
    maximum_datagram_frame_size: int.min(
      config.datagram_limit,
      maximum_udp_payload_size,
    ),
  )
}

fn client_transport_parameters(
  local_connection_id: BitArray,
  datagram_limit: Int,
  selected_version: Version,
  advertise_compatible_versions: Bool,
  idle_timeout_milliseconds: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
) -> List(transport_parameter.Parameter) {
  let available_versions =
    version_negotiation.available_versions(
      selected_version,
      advertise_compatible_versions,
    )
  [
    transport_parameter.GreaseQuicBit,
    transport_parameter.MaxIdleTimeout(idle_timeout_milliseconds),
    transport_parameter.MaxUdpPayloadSize(maximum_udp_payload_size),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(bidirectional_stream_limit),
    transport_parameter.InitialMaxStreamsUni(unidirectional_stream_limit),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.InitialSourceConnectionId(local_connection_id),
    transport_parameter.VersionInformation(selected_version, available_versions),
    transport_parameter.MaxDatagramFrameSize(int.min(
      datagram_limit,
      maximum_udp_payload_size,
    )),
  ]
}

fn random_connection_id() -> Result(BitArray, Error) {
  crypto.secure_random(connection_id_bytes)
  |> result.replace_error(TlsHandshakeFailed)
}

fn open_for_address(address: udp.Address) -> Result(udp.Socket, udp.Error) {
  case bit_array.byte_size(udp.address_bytes(address)) {
    4 -> {
      use wildcard <- result.try(udp.ipv4(0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    16 -> {
      use wildcard <- result.try(udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    _ -> Error(udp.InvalidInput)
  }
}

fn open_for_peer(peer: udp.Endpoint) -> Result(udp.Socket, udp.Error) {
  let #(bytes, _) = udp.endpoint_parts(peer)
  use address <- result.try(udp.address_from_bytes(bytes))
  open_for_address(address)
}

fn wait_milliseconds(
  total_deadline: Int,
  protocol_deadline: Option(Int),
  now: Int,
) -> Int {
  let target = case protocol_deadline {
    Some(deadline) if deadline < total_deadline -> deadline
    _ -> total_deadline
  }
  int.max(0, target - now)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - udp.monotonic_millisecond()
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn discard_or_fail(state: State, error: driver.Error) -> Result(State, Error) {
  case driver.discardable_receive_error(error) {
    True -> Ok(state)
    False ->
      case error {
        driver.ConnectionFailure(transport.TlsFailure(_)) ->
          Error(TlsHandshakeFailed)
        _ -> Error(QuicFailure(error))
      }
  }
}

fn first_protocol(protocols: List(BitArray)) -> BitArray {
  case protocols {
    [protocol, ..] -> protocol
    [] -> <<>>
  }
}

fn validate(config: Config) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.connect_port > 0
    && config.connect_port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.total_timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && valid_protocols(config.application_protocols)
    && config.bidirectional_stream_limit > 0
    && config.unidirectional_stream_limit > 0
    && config.stream_buffer_limit > 0
    && config.datagram_limit > 0
    && {
      config.version == version.Version1 || config.version == version.Version2
    }
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn valid_protocols(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> False
    [protocol, ..rest] -> {
      let size = bit_array.byte_size(protocol)
      bit_array.bit_size(protocol) % 8 == 0
      && size > 0
      && size <= 255
      && valid_protocols_tail(rest)
    }
  }
}

fn valid_protocols_tail(protocols: List(BitArray)) -> Bool {
  case protocols {
    [] -> True
    [protocol, ..rest] -> {
      let size = bit_array.byte_size(protocol)
      bit_array.bit_size(protocol) % 8 == 0
      && size > 0
      && size <= 255
      && valid_protocols_tail(rest)
    }
  }
}
