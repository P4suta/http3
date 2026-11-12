//// Typed actor owning one reusable generic QUIC client connection.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core.{type AddressFamily}
import quic_core/internal/connection_state as transport
import quic_core/internal/driver
import quic_core/internal/local_connection_id
import quic_core/internal/process_label
import quic_core/internal/qlog
import quic_core/internal/runtime/budget
import quic_core/internal/runtime/client_close_deadline
import quic_core/internal/runtime/client_transport
import quic_core/internal/runtime/connect_trace
import quic_core/internal/runtime/connection as runtime_connection
import quic_core/internal/runtime/qlog_admission
import quic_core/internal/runtime/qlog_budget
import quic_core/internal/runtime/send_observation.{type Observation}
import quic_core/internal/runtime/stream_lifetime
import quic_core/internal/stream_completion
import quic_core/internal/stream_state
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/hello
import quic_core/internal/tls/session_ticket
import quic_core/internal/udp
import quic_core/stream_id
import quic_core/version.{type Version}

const worker_reply_grace_milliseconds = 100

const maximum_send_chunk_bytes = 65_536

const pmtu_probe_interval_milliseconds = 50

// A NEW_TOKEN commonly follows the TLS ticket in the same handshake flight.
// Coalesce that bounded race so an opaque ticket returned for 0-RTT also carries the address-validation token needed to avoid a needless Retry.
const address_token_coalescing_milliseconds = 100

// One completion waiter per stream, capped again by the public queue limit.
// The observation owns a single bounded row and rejects delayed publication.
const maximum_completion_waiters = 256

// A close completion owns affine qlog receipts.
// Bound duplicate callers while they share that one result and let excess callers reach their own deadline.
const maximum_close_waiters = 32

// Keep the public absolute deadline as the only logical close budget.
// The final slice is reserved for forcing and observing the connection actor when its transport closing timer or a native call did not converge on its own.
const close_force_join_milliseconds = 50

/// Live actor reference with fixed origin and operation policy.
pub opaque type Connection {
  Connection(
    commands: Subject(Command),
    worker: Pid,
    timeout_milliseconds: Int,
    hostname: String,
    port: Int,
  )
}

/// One QUIC stream routed through its connection owner.
pub opaque type Stream {
  Stream(connection: Connection, identifier: Int)
}

/// One peer-initiated stream and its directionality.
pub type IncomingStream {
  IncomingStream(stream: Stream, bidirectional: Bool)
}

/// Origin-bound TLS resumption material.
pub opaque type ResumptionTicket {
  ResumptionTicket(
    hostname: String,
    port: Int,
    ticket: session_ticket.ClientTicket,
    address_token: BitArray,
  )
}

/// State of an explicit 0-RTT attempt.
pub type EarlyDataStatus {
  NotAttempted
  PendingEarlyData
  EarlyDataAccepted
  EarlyDataRejected
}

/// Outcome of an explicitly supplied resumption ticket.
pub type ResumptionStatus {
  ResumptionNotAttempted
  ResumptionPending
  Resumed
  FullHandshake
}

/// Non-secret immutable handshake inputs plus their current outcome.
pub type HandshakeAttempt {
  HandshakeAttempt(
    ticket_supplied: Bool,
    zero_rtt_enabled: Bool,
    ticket_allows_zero_rtt: Bool,
    early_data_status: EarlyDataStatus,
    resumption_status: ResumptionStatus,
  )
}

/// Bounded, payload-free state used to explain a stalled client actor.
///
/// This type remains inside the private runtime namespace.
/// It records only scheduler positions, counters, and deadlines; neither buffered bytes nor packet/frame contents cross the diagnostic seam.
pub type DevelopmentSnapshot {
  DevelopmentSnapshot(
    observed_at_milliseconds: Int,
    next_wake_milliseconds: Option(Int),
    previous_park: Option(ParkProgress),
    next_pmtu_probe_milliseconds: Int,
    path_mtu: Int,
    pacing: transport.PacingWakeProgress,
    longest_wait: Option(WaitProgress),
    transport: transport.SendProgress,
    streams: List(stream_state.SendProgress),
    actor_pending_sends: List(Int),
    actor_streams: Int,
    incoming_streams: Int,
    maximum_pto_backoff: Int,
  )
}

/// The bounded deadlines considered immediately before the actor last parked.
///
/// `operation_deadline` is the earliest application waiter across open,
/// accept, stream, Datagram, migration, and ticket operations.
/// Keeping it separate from QUIC and PMTU timers makes a timeout explain which subsystem selected the wake without retaining any application value.
pub type ParkProgress {
  ParkProgress(
    observed_at_milliseconds: Int,
    protocol_deadline: Option(Int),
    pmtu_deadline: Option(Int),
    operation_deadline: Option(Int),
    selected_deadline: Option(Int),
    path_mtu: Int,
    pacing: transport.PacingWakeProgress,
    transport: transport.SendProgress,
  )
}

/// One completed actor wait, including what actually woke it.
pub type WaitProgress {
  WaitProgress(park: ParkProgress, resumed_at_milliseconds: Int, wake: WaitWake)
}

/// The source that ended a completed actor wait.
pub type WaitWake {
  CommandWake
  NetworkWake
  TimerWake
}

/// One bounded pull from a stream receive direction.
pub type Read {
  Data(bytes: BitArray, finished: Bool)
  Finished
  Reset(application_error_code: Int)
}

/// Idempotent close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Actor, lifecycle, direction, pressure, or protocol failure.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  OperationTimeout
  TotalTimeout
  TlsHandshakeFailed
  QuicFailure
  ConnectionClosed
  /// The peer closed during the handshake and named a close code, such as the CONNECTION_REFUSED a server sends when it has no room for a connection.
  PeerClosedWithCode(Int)
  PeerTransportFailureWithCode(Int)
  TransportFailureWithCode(Int)
  StreamClosed
  StreamReset(Int)
  InvalidDirection
  ConcurrentSend
  ConcurrentReceive
  ConcurrentAccept
  ConcurrentDatagramReceive
  SendBufferExceeded(Int)
  OpenQueueExceeded(Int)
  IncomingStreamQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  DatagramTooLarge(Int)
  DatagramsNotNegotiated
  MigrationUnavailable
  CongestionLimited
  EndpointMemoryExceeded(Int)
  DiagnosticConnectionsExceeded
  TicketUnavailable
  InvalidStoredTicket
  QlogUnavailable
  VersionNegotiationFailed
}

type Command {
  Open(
    direction: stream_id.Direction,
    reply: Subject(Result(Int, Error)),
    deadline: Int,
  )
  Accept(reply: Subject(Result(IncomingStream, Error)), deadline: Option(Int))
  Send(
    identifier: Int,
    bytes: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  Receive(
    identifier: Int,
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Option(Int),
  )
  ResetStream(identifier: Int, code: Int, reply: Subject(Result(Nil, Error)))
  StopSending(identifier: Int, code: Int, reply: Subject(Result(Nil, Error)))
  SendDatagram(payload: BitArray, reply: Subject(Result(Nil, Error)))
  ReceiveDatagram(
    reply: Subject(Result(BitArray, Error)),
    deadline: Option(Int),
  )
  MaximumDatagram(reply: Subject(Result(Int, Error)))
  GuaranteedDatagram(reply: Subject(Result(Int, Error)))
  PathMtu(reply: Subject(Result(Int, Error)))
  PathValidation(reply: Subject(Result(Bool, Error)))
  Migrate(reply: Subject(Result(Nil, Error)), deadline: Int)
  Ping(reply: Subject(Result(Nil, Error)))
  SetCongestion(
    algorithm: transport.CongestionAlgorithm,
    reply: Subject(Result(Nil, Error)),
  )
  SendFinished(stream_id: Int, reply: Subject(Result(Bool, Error)))
  AwaitSendCompletion(
    stream_id: Int,
    owner: Pid,
    observation: Observation(Result(stream_completion.Outcome, Error)),
    deadline: Int,
  )
  CancelSendCompletion(
    stream_id: Int,
    observation: Observation(Result(stream_completion.Outcome, Error)),
  )
  PathStats(reply: Subject(Result(transport.PathSnapshot, Error)))
  ConnectionStats(reply: Subject(Result(runtime_connection.Stats, Error)))
  LocalConnectionIdStats(
    reply: Subject(Result(local_connection_id.Snapshot, Error)),
  )
  ResourceStats(reply: Subject(Result(#(Int, Int), Error)))
  DevelopmentState(reply: Subject(Result(DevelopmentSnapshot, Error)))
  TelemetryStats(reply: Subject(Result(qlog.Stats, Error)))
  ApplicationDiagnostics(reply: Subject(Result(Option(qlog.Writer), Error)))
  Phase(reply: Subject(Result(transport.Phase, Error)))
  EarlyData(reply: Subject(Result(EarlyDataStatus, Error)))
  Resumption(reply: Subject(Result(ResumptionStatus, Error)))
  Handshake(reply: Subject(Result(HandshakeAttempt, Error)))
  Ticket(reply: Subject(Result(ResumptionTicket, Error)), deadline: Option(Int))
  Protocol(
    reply: Subject(
      Result(
        #(
          Version,
          BitArray,
          transport.CongestionAlgorithm,
          Option(hello.CipherSuite),
        ),
        Error,
      ),
    ),
  )
  Close(
    code: Int,
    deadline_milliseconds: Int,
    reply: Subject(Result(CloseResult, Error)),
  )
}

type LoopMessage {
  ReceivedCommand(Command)
  ReceivedNetwork(Dynamic)
  OwnerExited
  CompletionCallerExited(stream_id: Int, monitor: process.Monitor)
}

type CleanupJoinMessage {
  CleanupOwnerExited(Pid)
}

type CloseWorkerJoinMessage {
  CloseWorkerExited
}

type ReadWaiter {
  ReadWaiter(
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Option(Int),
  )
}

type AcceptWaiter {
  AcceptWaiter(
    reply: Subject(Result(IncomingStream, Error)),
    deadline: Option(Int),
  )
}

type PendingOpen {
  PendingOpen(
    direction: stream_id.Direction,
    reply: Subject(Result(Int, Error)),
    deadline: Int,
  )
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Option(Int))
}

type MigrationWaiter {
  MigrationWaiter(reply: Subject(Result(Nil, Error)), deadline: Int)
}

type TicketWaiter {
  TicketWaiter(
    reply: Subject(Result(ResumptionTicket, Error)),
    deadline: Option(Int),
    token_deadline: Option(Int),
  )
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
}

type CompletionWaiter {
  CompletionWaiter(
    owner: Pid,
    monitor: process.Monitor,
    observation: Observation(Result(stream_completion.Outcome, Error)),
    deadline: Int,
  )
}

type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
}

type StreamState {
  StreamState(
    read_waiter: Option(ReadWaiter),
    pending_send: Option(PendingSend),
    send_finished: Bool,
    receive_finished: Bool,
  )
}

type CloseCompletionRequest {
  AwaitCloseCompletion(reply: Subject(Result(CloseResult, Error)))
}

type ClientCloseCompletion {
  ClientCloseCompletion(waiters: Subject(CloseCompletionRequest))
}

type Worker {
  Worker(
    connection: client_transport.State,
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    streams: Dict(Int, StreamState),
    pending_opens: Queue(PendingOpen),
    incoming: Queue(Int),
    accept_waiter: Option(AcceptWaiter),
    datagrams: Queue(BitArray),
    datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    migration_waiter: Option(MigrationWaiter),
    latest_ticket: Option(ResumptionTicket),
    latest_address_token: BitArray,
    ticket_waiter: Option(TicketWaiter),
    early_data_status: EarlyDataStatus,
    resumption_status: ResumptionStatus,
    ticket_supplied: Bool,
    zero_rtt_enabled: Bool,
    ticket_allows_zero_rtt: Bool,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    hostname: String,
    port: Int,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    qlog_cleanup: Option(qlog.CleanupTicket),
    qlog_reservation: Option(qlog_admission.Reservation),
    close_completion: Option(ClientCloseCompletion),
    close_completion_waiters: Int,
    next_pmtu_probe_milliseconds: Int,
    terminal_error: Option(Error),
    maximum_pto_backoff: Int,
    previous_park: Option(ParkProgress),
    longest_wait: Option(WaitProgress),
    application_closed: Bool,
    completion_waiters: Dict(Int, CompletionWaiter),
    completions: stream_completion.History,
  )
}

type CloseResources {
  CloseResources(
    outcome: CloseResult,
    writer: Option(qlog.Writer),
    cleanup: Option(qlog.CleanupTicket),
    reservation: Option(qlog_admission.Reservation),
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Establish a connection in an owner-monitored process.
pub fn connect(
  owner: Pid,
  hostname: String,
  port: Int,
  address_family: AddressFamily,
  connect_address: Option(BitArray),
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  handshake_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
  trust_store: authentication.TrustStore,
  client_credential: Option(engine.ClientCredential),
  application_protocols: List(BitArray),
  version: Version,
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  resumption_ticket: Option(ResumptionTicket),
  allow_zero_rtt: Bool,
  connect_port: Int,
  connect_trace: Option(connect_trace.Context),
  diagnostic_admission: qlog_admission.Identity,
  diagnostic_dependent: Option(qlog_admission.Reservation),
  diagnostic_connections: Int,
) -> Result(Connection, Error) {
  use Nil <- result.try(validate_endpoint_memory(
    endpoint_memory_limit,
    qlog_directory,
    telemetry_limit,
  ))
  use reservation <- result.try(reserve_qlog(
    diagnostic_admission,
    qlog_directory,
    telemetry_limit,
    endpoint_memory_limit,
    diagnostic_connections,
    diagnostic_dependent,
  ))
  let deadline = udp.monotonic_millisecond() + total_timeout_milliseconds
  let started_group =
    udp.start_establishment_group(owner)
    |> result.replace_error(ConnectionClosed)
  case started_group {
    Error(_) -> release_unused_qlog(reservation)
    Ok(_) -> Nil
  }
  use group <- result.try(started_group)
  let bootstrap = process.new_subject()
  let spawned =
    udp.spawn_work(group, udp.EndpointWork, fn() {
      process_label.set(process_label.Client)
      initialise(
        owner,
        bootstrap,
        hostname,
        port,
        address_family,
        connect_address,
        dns_timeout_milliseconds,
        connect_timeout_milliseconds,
        handshake_timeout_milliseconds,
        total_timeout_milliseconds,
        operation_timeout_milliseconds,
        idle_timeout_milliseconds,
        stream_buffer_limit,
        queue_limit,
        telemetry_limit,
        bidirectional_stream_limit,
        unidirectional_stream_limit,
        datagram_limit,
        trust_store,
        client_credential,
        application_protocols,
        version,
        congestion_control,
        qlog_directory,
        reservation,
        resumption_ticket,
        allow_zero_rtt,
        connect_port,
        connect_trace,
        group,
        deadline,
      )
    })
  let outcome = case spawned {
    Ok(worker) -> await_bootstrap(worker, bootstrap, group, deadline)
    Error(_) -> {
      let _ = udp.stop_work_group(group)
      Error(ConnectionClosed)
    }
  }
  case outcome {
    Error(_) -> {
      release_unused_qlog(reservation)
      connect_trace.abandon(connect_trace)
    }
    Ok(_) -> Nil
  }
  outcome
}

fn reserve_qlog(
  identity: qlog_admission.Identity,
  directory: String,
  _telemetry_limit: Int,
  maximum: Int,
  connections: Int,
  dependent: Option(qlog_admission.Reservation),
) -> Result(Option(qlog_admission.Reservation), Error) {
  case directory {
    "" -> Ok(None)
    _ ->
      qlog_admission.reserve_linked(
        identity,
        qlog_budget.connection_reservation_bytes(),
        maximum - budget.admission_quanta() * budget.quantum(),
        connections,
        dependent,
      )
      |> result.map(Some)
      |> result.map_error(fn(code) {
        case code {
          2 -> DiagnosticConnectionsExceeded
          _ -> EndpointMemoryExceeded(maximum)
        }
      })
  }
}

fn release_unused_qlog(reservation: Option(qlog_admission.Reservation)) -> Nil {
  case reservation {
    Some(reservation) -> qlog_admission.release_unused(reservation)
    None -> Nil
  }
}

fn validate_endpoint_memory(
  maximum: Int,
  qlog_directory: String,
  _telemetry_limit: Int,
) -> Result(Nil, Error) {
  let diagnostics = case qlog_directory {
    "" -> 0
    _ -> qlog_budget.connection_reservation_bytes()
  }
  let admission = budget.admission_quanta() * budget.quantum() + diagnostics
  case maximum >= admission {
    True -> Ok(Nil)
    False -> Error(EndpointMemoryExceeded(maximum))
  }
}

/// Open one locally initiated bidirectional stream.
pub fn open_bidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Bidirectional)
}

/// Open one locally initiated unidirectional stream.
pub fn open_unidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Unidirectional)
}

fn open(
  connection: Connection,
  direction: stream_id.Direction,
) -> Result(Stream, Error) {
  call(connection, fn(reply) {
    Open(
      direction,
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
  |> result.map(fn(identifier) { Stream(connection, identifier) })
}

/// Wait for one peer-initiated stream.
pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  call(connection, fn(reply) {
    Accept(
      reply,
      Some(udp.monotonic_millisecond() + connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for one peer-initiated stream.
/// Connection close or actor failure still releases the caller.
pub fn accept_stream_next(
  connection: Connection,
) -> Result(IncomingStream, Error) {
  call_forever(connection, fn(reply) { Accept(reply, None) })
}

/// Queue one byte-aligned chunk with synchronous flow-control pressure.
pub fn send(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, False)
}

/// Queue the terminal FIN after all prior bytes.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  send_with_fin(stream, <<>>, True)
}

/// Queue bytes and the terminal FIN atomically from the caller's perspective.
pub fn send_and_finish(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, True)
}

/// Return whether a stream's FIN is acknowledged or its send direction reset.
pub fn send_finished(stream: Stream) -> Result(Bool, Error) {
  call(stream.connection, fn(reply) { SendFinished(stream.identifier, reply) })
}

/// Wait for FIN acknowledgement or a terminal send-direction outcome.
///
/// The caller waits on a one-shot bounded observation while the connection actor continues to process packets and unrelated streams.
/// The configured operation timeout remains an upper bound on the requested duration.
pub fn await_send_completion(
  stream: Stream,
  within_milliseconds: Int,
) -> Result(stream_completion.Outcome, Error) {
  case within_milliseconds > 0 {
    False -> Error(InvalidInput)
    True -> {
      let connection = stream.connection
      let deadline =
        udp.monotonic_millisecond()
        + int.min(within_milliseconds, connection.timeout_milliseconds)
      let observation = send_observation.new()
      case send_observation.available(observation) {
        False -> Error(EndpointMemoryExceeded(0))
        True -> {
          process.send(
            connection.commands,
            AwaitSendCompletion(
              stream.identifier,
              process.self(),
              observation,
              deadline,
            ),
          )
          case
            send_observation.await(
              observation,
              connection.worker,
              int.max(0, deadline - udp.monotonic_millisecond()),
            )
          {
            send_observation.Replied(result) -> result
            send_observation.DeadlineExpired(_) -> {
              process.send(
                connection.commands,
                CancelSendCompletion(stream.identifier, observation),
              )
              Error(OperationTimeout)
            }
            send_observation.WorkerExited -> Error(ConnectionClosed)
            send_observation.OwnerExited -> Error(ConnectionClosed)
            send_observation.Unavailable -> {
              process.send(
                connection.commands,
                CancelSendCompletion(stream.identifier, observation),
              )
              Error(EndpointMemoryExceeded(0))
            }
          }
        }
      }
    }
  }
}

fn send_with_fin(
  stream: Stream,
  bytes: BitArray,
  finish: Bool,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    Send(
      stream.identifier,
      bytes,
      finish,
      reply,
      udp.monotonic_millisecond() + stream.connection.timeout_milliseconds,
    )
  })
}

/// Pull at most `maximum_bytes` or one terminal stream event.
pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  call(stream.connection, fn(reply) {
    Receive(
      stream.identifier,
      maximum_bytes,
      reply,
      Some(udp.monotonic_millisecond() + stream.connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for bytes or a terminal stream event.
/// Connection close or actor failure still releases the caller.
pub fn receive_next(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  call_forever(stream.connection, fn(reply) {
    Receive(stream.identifier, maximum_bytes, reply, None)
  })
}

/// Abort every locally usable direction with an application code.
pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    ResetStream(stream.identifier, application_error_code, reply)
  })
}

/// Ask the peer to reset only its send direction.
pub fn stop_sending(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    StopSending(stream.identifier, application_error_code, reply)
  })
}

/// Queue one connection-scoped QUIC Datagram.
pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SendDatagram(payload, reply) })
}

/// Pull one connection-scoped QUIC Datagram.
pub fn receive_datagram(connection: Connection) -> Result(BitArray, Error) {
  call(connection, fn(reply) {
    ReceiveDatagram(
      reply,
      Some(udp.monotonic_millisecond() + connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for one connection-scoped QUIC Datagram.
/// Connection close or actor failure still releases the caller.
pub fn receive_datagram_next(
  connection: Connection,
) -> Result(BitArray, Error) {
  call_forever(connection, fn(reply) { ReceiveDatagram(reply, None) })
}

pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  call(connection, MaximumDatagram)
}

pub fn guaranteed_datagram_size(connection: Connection) -> Result(Int, Error) {
  call(connection, GuaranteedDatagram)
}

pub fn path_mtu(connection: Connection) -> Result(Int, Error) {
  call(connection, PathMtu)
}

/// Return whether a newly selected path is still being authenticated.
pub fn path_validation_in_progress(
  connection: Connection,
) -> Result(Bool, Error) {
  call(connection, PathValidation)
}

pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  call(connection, fn(reply) {
    Migrate(
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
}

pub fn ping(connection: Connection) -> Result(Nil, Error) {
  call(connection, Ping)
}

pub fn set_congestion_control(
  connection: Connection,
  algorithm: transport.CongestionAlgorithm,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SetCongestion(algorithm, reply) })
}

pub fn path_stats(
  connection: Connection,
) -> Result(transport.PathSnapshot, Error) {
  call(connection, PathStats)
}

pub fn connection_stats(
  connection: Connection,
) -> Result(runtime_connection.Stats, Error) {
  call(connection, ConnectionStats)
}

pub fn telemetry_stats(connection: Connection) -> Result(qlog.Stats, Error) {
  call(connection, TelemetryStats)
}

pub fn local_connection_id_stats(
  connection: Connection,
) -> Result(local_connection_id.Snapshot, Error) {
  call(connection, LocalConnectionIdStats)
}

/// Borrow the connection-owned writer for the restricted public application diagnostic capability.
/// Writer lifetime remains owned by this actor.
pub fn application_diagnostics(
  connection: Connection,
) -> Result(Option(qlog.Writer), Error) {
  call(connection, ApplicationDiagnostics)
}

pub fn phase(connection: Connection) -> Result(transport.Phase, Error) {
  call(connection, Phase)
}

pub fn early_data_status(
  connection: Connection,
) -> Result(EarlyDataStatus, Error) {
  call(connection, EarlyData)
}

pub fn resumption_status(
  connection: Connection,
) -> Result(ResumptionStatus, Error) {
  call(connection, Resumption)
}

/// Snapshot non-secret handshake configuration and current outcome.
pub fn handshake_attempt(
  connection: Connection,
) -> Result(HandshakeAttempt, Error) {
  call(connection, Handshake)
}

pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  call(connection, fn(reply) {
    Ticket(
      reply,
      Some(udp.monotonic_millisecond() + connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for the next origin-bound ticket.
///
/// Once a ticket arrives, its short address-token coalescing window remains a one-shot deadline; connection close or actor failure releases the caller.
pub fn resumption_ticket_next(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  call_forever(connection, fn(reply) { Ticket(reply, None) })
}

pub fn negotiated_protocol(
  connection: Connection,
) -> Result(
  #(Version, BitArray, transport.CongestionAlgorithm, Option(hello.CipherSuite)),
  Error,
) {
  call(connection, Protocol)
}

/// Snapshot retained runtime handles and live transport streams.
pub fn resource_stats(connection: Connection) -> Result(#(Int, Int), Error) {
  call(connection, ResourceStats)
}

/// Snapshot the client actor's send path for development diagnostics.
pub fn development_snapshot(
  connection: Connection,
) -> Result(DevelopmentSnapshot, Error) {
  call(connection, DevelopmentState)
}

pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  close_with_code(connection, 0)
}

/// Fixed actor-call share used when a higher-level adapter constructs the absolute completion deadline passed to `close_with_code_until`.
pub fn close_operation_allowance_milliseconds(connection: Connection) -> Int {
  connection.timeout_milliseconds + worker_reply_grace_milliseconds
}

pub fn close_with_code(
  connection: Connection,
  application_error_code: Int,
) -> Result(CloseResult, Error) {
  let current = udp.monotonic_millisecond()
  case
    client_close_deadline.from_allowances(
      current,
      connection.timeout_milliseconds,
      worker_reply_grace_milliseconds,
      qlog.close_completion_allowance_milliseconds(),
    )
  {
    Error(_) -> Error(InvalidInput)
    Ok(deadline_milliseconds) ->
      close_with_code_until(
        connection,
        application_error_code,
        deadline_milliseconds,
      )
  }
}

/// Close transport and diagnostics under one caller-owned absolute deadline.
/// The deadline uses `quic_core/diagnostics.monotonic_milliseconds` and is neither recomputed nor extended between the actor, writer, and cleanup join.
pub fn close_with_code_until(
  connection: Connection,
  application_error_code: Int,
  deadline_milliseconds: Int,
) -> Result(CloseResult, Error) {
  use _ <- result.try(validate_client_close_deadline(deadline_milliseconds))
  call_close_until(connection, application_error_code, deadline_milliseconds)
}

pub fn stream_connection(stream: Stream) -> Connection {
  stream.connection
}

pub fn stream_identifier(stream: Stream) -> Int {
  stream.identifier
}

pub fn ticket_origin(ticket: ResumptionTicket) -> #(String, Int) {
  #(ticket.hostname, ticket.port)
}

/// Return whether the TLS ticket carries authenticated 0-RTT limits.
pub fn ticket_allows_early_data(ticket: ResumptionTicket) -> Bool {
  session_ticket.early_data_allowed(ticket.ticket)
}

pub fn ticket_native(ticket: ResumptionTicket) -> session_ticket.ClientTicket {
  ticket.ticket
}

/// Return bounded opaque application compatibility state retained by TLS.
pub fn ticket_application_context(ticket: ResumptionTicket) -> BitArray {
  session_ticket.application_context(ticket.ticket)
}

/// Attach bounded opaque application compatibility state while preserving the ticket's authenticated origin, lifetime, transport parameters, and token.
pub fn ticket_with_application_context(
  ticket: ResumptionTicket,
  context: BitArray,
) -> Result(ResumptionTicket, session_ticket.Error) {
  use native <- result.try(session_ticket.with_application_context(
    ticket.ticket,
    context,
  ))
  Ok(ResumptionTicket(..ticket, ticket: native))
}

pub fn ticket_address_token(ticket: ResumptionTicket) -> BitArray {
  ticket.address_token
}

pub fn restored_ticket(
  hostname: String,
  port: Int,
  ticket: session_ticket.ClientTicket,
  address_token: BitArray,
) -> ResumptionTicket {
  ResumptionTicket(hostname, port, ticket, address_token)
}

fn initialise(
  owner: Pid,
  bootstrap: Subject(Result(Connection, Error)),
  hostname: String,
  port: Int,
  address_family: AddressFamily,
  connect_address: Option(BitArray),
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  handshake_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
  trust_store: authentication.TrustStore,
  client_credential: Option(engine.ClientCredential),
  application_protocols: List(BitArray),
  version: Version,
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  qlog_reservation: Option(qlog_admission.Reservation),
  resumption_ticket: Option(ResumptionTicket),
  allow_zero_rtt: Bool,
  connect_port: Int,
  connect_trace: Option(connect_trace.Context),
  group: udp.WorkGroup,
  deadline: Int,
) -> Nil {
  let #(native_ticket, address_token) = case resumption_ticket {
    Some(value) -> #(Some(value.ticket), value.address_token)
    None -> #(None, <<>>)
  }
  let early_attempted = case native_ticket {
    Some(ticket) -> allow_zero_rtt && session_ticket.early_data_allowed(ticket)
    None -> False
  }
  let ticket_supplied = option.is_some(native_ticket)
  let ticket_allows_zero_rtt = case native_ticket {
    Some(ticket) -> session_ticket.early_data_allowed(ticket)
    None -> False
  }
  let config =
    client_transport.Config(
      owner,
      hostname,
      port,
      address_family,
      connect_address,
      dns_timeout_milliseconds,
      connect_timeout_milliseconds,
      handshake_timeout_milliseconds,
      total_timeout_milliseconds,
      idle_timeout_milliseconds,
      trust_store,
      client_credential,
      application_protocols,
      native_ticket,
      allow_zero_rtt,
      address_token,
      version,
      congestion_control,
      bidirectional_stream_limit,
      unidirectional_stream_limit,
      stream_buffer_limit,
      datagram_limit,
      connect_port,
      connect_trace,
    )
  case client_transport.connect_in(config, group, deadline) {
    Error(error) -> process.send(bootstrap, Error(map_transport_error(error)))
    Ok(connection) -> {
      let #(opened, cleanup) =
        open_qlog(qlog_directory, telemetry_limit, qlog_reservation)
      case opened {
        Error(error) -> {
          client_transport.close(connection, 0, "qlog unavailable")
          collect_qlog(qlog_reservation, cleanup)
          process.send(bootstrap, Error(error))
        }
        Ok(writer) -> {
          case bind_qlog_reservation(writer, qlog_reservation) {
            Error(Nil) -> {
              client_transport.close(connection, 0, "qlog unavailable")
              close_qlog(writer)
              collect_qlog(qlog_reservation, cleanup)
              process.send(bootstrap, Error(QlogUnavailable))
            }
            Ok(Nil) -> {
              let now = udp.monotonic_millisecond()
              case writer {
                Some(value) -> record_qlog_bootstrap(value, connection, now)
                None -> Nil
              }
              let commands = process.new_subject()
              let monitor = process.monitor(owner)
              let selector =
                process.new_selector()
                |> process.select_map(commands, ReceivedCommand)
                |> process.select_specific_monitor(monitor, fn(_) {
                  OwnerExited
                })
                |> process.select_other(ReceivedNetwork)
              process.send(
                bootstrap,
                Ok(Connection(
                  commands,
                  process.self(),
                  operation_timeout_milliseconds,
                  hostname,
                  port,
                )),
              )
              client_transport.published(connection)
              drive_and_loop(Worker(
                connection,
                commands,
                selector,
                dict.new(),
                queue_new(),
                queue_new(),
                None,
                queue_new(),
                0,
                None,
                None,
                None,
                address_token,
                None,
                case early_attempted {
                  True -> PendingEarlyData
                  False -> NotAttempted
                },
                case native_ticket {
                  Some(_) -> ResumptionPending
                  None -> ResumptionNotAttempted
                },
                ticket_supplied,
                allow_zero_rtt,
                ticket_allows_zero_rtt,
                operation_timeout_milliseconds,
                stream_buffer_limit,
                queue_limit,
                datagram_limit,
                hostname,
                port,
                congestion_control,
                writer,
                cleanup,
                qlog_reservation,
                None,
                0,
                now + pmtu_probe_interval_milliseconds,
                None,
                0,
                None,
                None,
                False,
                dict.new(),
                stream_completion.new(queue_limit),
              ))
            }
          }
        }
      }
    }
  }
}

fn bind_qlog_reservation(
  writer: Option(qlog.Writer),
  reservation: Option(qlog_admission.Reservation),
) -> Result(Nil, Nil) {
  case writer, reservation {
    None, None -> Ok(Nil)
    Some(writer), Some(reservation) -> qlog_admission.bind(writer, reservation)
    _, _ -> Error(Nil)
  }
}

fn loop(worker: Worker) -> Nil {
  let worker = observe_recovery_backoff(worker)
  let worker = dispatch_transport_events(worker)
  case worker.terminal_error, client_transport.phase(worker.connection) {
    Some(error), _ -> shutdown_after_peer_close(worker, error)
    None, transport.Closed -> finish_closed_transport(worker)
    None, _ -> {
      let now = udp.monotonic_millisecond()
      let worker = expire_waiters(worker, now)
      let worker = expire_completion_waiters(worker, now)
      let worker = retry_pending_opens(worker, now)
      let worker = retry_pending_sends(worker)
      case maybe_probe_path_mtu(worker, now) {
        Error(error) -> shutdown(worker, error)
        Ok(worker) -> wait_for_work(worker, now)
      }
    }
  }
}

fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case park_progress(worker, now) {
    Error(error) -> shutdown(worker, error)
    Ok(progress) -> {
      let ParkProgress(selected_deadline: deadline, ..) = progress
      let worker = Worker(..worker, previous_park: Some(progress))
      let received = case deadline {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(value) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, value - now),
          )
      }
      case received {
        Ok(OwnerExited) ->
          case worker.application_closed {
            // A public local close already detached application ownership.
            // Retain the bounded wire tombstone so a lost first close can be answered without letting the former owner extend its lifetime.
            True -> drive_and_loop(worker)
            False -> shutdown_now(worker, ConnectionClosed)
          }
        Ok(ReceivedCommand(command)) -> {
          let worker = record_wait(worker, progress, CommandWake)
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(next) -> drive_and_loop(next)
          }
        }
        Ok(ReceivedNetwork(message)) ->
          receive_and_loop(record_wait(worker, progress, NetworkWake), message)
        Ok(CompletionCallerExited(identifier, monitor)) ->
          completion_caller_exited(worker, identifier, monitor)
          |> drive_and_loop
        Error(Nil) -> drive_and_loop(record_wait(worker, progress, TimerWake))
      }
    }
  }
}

fn drive_and_loop(worker: Worker) -> Nil {
  let before = client_transport.stats(worker.connection)
  case client_transport.drive(worker.connection) {
    Error(error) -> shutdown(worker, map_transport_error(error))
    Ok(connection) -> {
      record_qlog_io(
        worker.qlog_writer,
        before,
        client_transport.stats(connection),
        connection,
      )
      let worker = Worker(..worker, connection: connection)
      case client_transport.activate_once(connection) {
        Ok(Nil) -> loop(worker)
        Error(error) -> shutdown(worker, map_transport_error(error))
      }
    }
  }
}

fn receive_and_loop(worker: Worker, message: Dynamic) -> Nil {
  let before = client_transport.stats(worker.connection)
  case client_transport.receive_active(worker.connection, message) {
    Error(client_transport.InvalidInput) ->
      case client_transport.activate_once(worker.connection) {
        Ok(Nil) -> loop(worker)
        Error(error) -> shutdown(worker, map_transport_error(error))
      }
    Error(error) -> shutdown(worker, map_transport_error(error))
    Ok(connection) -> {
      record_qlog_io(
        worker.qlog_writer,
        before,
        client_transport.stats(connection),
        connection,
      )
      // Dispatch authenticated terminal events before attempting another drive.
      // A CONNECTION_CLOSE moves the transport to Draining, where a drive is unavailable; driving first would collapse its application code into a generic local ConnectionClosed error.
      let worker =
        Worker(..worker, connection: connection)
        |> dispatch_transport_events
      // An authenticated ACK can release congestion or flow-control credit.
      // Drive that newly sendable output in this same event turn.
      // Deferring to `loop` is insufficient: when the pacer says SendNow and every prior packet was acknowledged there may be no protocol deadline left to wake the actor, so output would otherwise wait for an unrelated API command.
      // `drive_and_loop` is bounded by the transport flush cap and rearms active-once reception before parking.
      case worker.terminal_error {
        Some(error) -> shutdown_after_peer_close(worker, error)
        None -> drive_and_loop(worker)
      }
    }
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case client_transport.phase(worker.connection) {
    transport.Closing | transport.Draining | transport.Closed ->
      handle_local_terminal_command(worker, command)
    transport.Handshaking | transport.Established ->
      handle_live_command(worker, command)
  }
}

fn handle_local_terminal_command(
  worker: Worker,
  command: Command,
) -> Result(Worker, Nil) {
  case command {
    Close(_, deadline_milliseconds, reply) -> {
      case worker.close_completion {
        Some(completion) -> {
          case worker.close_completion_waiters >= maximum_close_waiters - 1 {
            True -> {
              process.send(reply, Error(OperationTimeout))
              Ok(worker)
            }
            False -> {
              await_client_close_completion(completion, reply)
              Ok(
                Worker(
                  ..worker,
                  close_completion_waiters: worker.close_completion_waiters + 1,
                ),
              )
            }
          }
        }
        None -> {
          let #(worker, resources) = take_qlog_close(worker)
          case
            start_client_close_completion(
              CloseResources(..resources, outcome: AlreadyClosed),
              process.self(),
              deadline_milliseconds,
              reply,
            )
          {
            Ok(completion) ->
              Ok(Worker(..worker, close_completion: Some(completion)))
            Error(Nil) -> {
              client_transport.release(worker.connection)
              Error(Nil)
            }
          }
        }
      }
    }
    command -> {
      let error = case
        client_transport.local_transport_failure_code(worker.connection)
      {
        Some(code) -> TransportFailureWithCode(code)
        None -> ConnectionClosed
      }
      reject_terminal_command(command, error)
      Ok(worker)
    }
  }
}

fn handle_live_command(
  worker: Worker,
  command: Command,
) -> Result(Worker, Nil) {
  case command {
    Open(direction, reply, deadline) ->
      handle_open(worker, direction, reply, deadline)
    Accept(reply, deadline) -> handle_accept(worker, reply, deadline)
    Send(identifier, bytes, finish, reply, deadline) ->
      handle_send(worker, identifier, bytes, finish, reply, deadline)
    Receive(identifier, maximum, reply, deadline) ->
      handle_receive(worker, identifier, maximum, reply, deadline)
    ResetStream(identifier, code, reply) ->
      handle_reset(worker, identifier, code, reply)
    StopSending(identifier, code, reply) ->
      handle_stop_sending(worker, identifier, code, reply)
    SendDatagram(payload, reply) -> handle_send_datagram(worker, payload, reply)
    ReceiveDatagram(reply, deadline) ->
      handle_receive_datagram(worker, reply, deadline)
    MaximumDatagram(reply) ->
      reply_with(
        worker,
        reply,
        client_transport.maximum_datagram_size(worker.connection),
      )
    GuaranteedDatagram(reply) ->
      reply_with(
        worker,
        reply,
        client_transport.guaranteed_datagram_size(worker.connection),
      )
    PathMtu(reply) -> {
      process.send(reply, Ok(client_transport.path_mtu(worker.connection)))
      Ok(worker)
    }
    PathValidation(reply) -> {
      process.send(
        reply,
        Ok(client_transport.path_validation_in_progress(worker.connection)),
      )
      Ok(worker)
    }
    Migrate(reply, deadline) ->
      case worker.migration_waiter {
        Some(_) -> reply_error(worker, reply, MigrationUnavailable)
        None -> {
          case worker.qlog_writer {
            Some(writer) ->
              qlog.migration_started(writer, udp.monotonic_millisecond())
            None -> Nil
          }
          case client_transport.migrate(worker.connection) {
            Error(error) -> {
              record_qlog_migration_abandoned(worker.qlog_writer)
              reply_error(worker, reply, map_transport_error(error))
            }
            Ok(connection) ->
              case client_transport.path_validation_in_progress(connection) {
                False -> {
                  process.send(reply, Ok(Nil))
                  Ok(Worker(..worker, connection: connection))
                }
                True ->
                  Ok(
                    Worker(
                      ..worker,
                      connection: connection,
                      migration_waiter: Some(MigrationWaiter(reply, deadline)),
                    ),
                  )
              }
          }
        }
      }
    Ping(reply) ->
      update_connection_reply(
        worker,
        reply,
        client_transport.ping(worker.connection),
      )
    SetCongestion(algorithm, reply) ->
      case
        client_transport.set_congestion_control(worker.connection, algorithm)
      {
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(
            Worker(
              ..worker,
              connection: connection,
              congestion_control: algorithm,
            ),
          )
        }
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
      }
    SendFinished(identifier, reply) ->
      reply_with(
        worker,
        reply,
        client_transport.send_finished(worker.connection, identifier),
      )
    AwaitSendCompletion(identifier, owner, observation, deadline) ->
      Ok(register_completion_waiter(
        worker,
        identifier,
        owner,
        observation,
        deadline,
      ))
    CancelSendCompletion(identifier, observation) -> {
      case dict.get(worker.completion_waiters, identifier) {
        Ok(waiter) if waiter.observation == observation ->
          Ok(remove_completion_waiter(worker, identifier))
        _ -> Ok(worker)
      }
    }
    PathStats(reply) -> {
      process.send(reply, Ok(client_transport.path_stats(worker.connection)))
      Ok(worker)
    }
    ConnectionStats(reply) -> {
      process.send(reply, Ok(client_transport.stats(worker.connection)))
      Ok(worker)
    }
    ResourceStats(reply) -> {
      process.send(
        reply,
        Ok(#(
          dict.size(worker.streams),
          client_transport.active_stream_count(worker.connection),
        )),
      )
      Ok(worker)
    }
    LocalConnectionIdStats(reply) -> {
      process.send(
        reply,
        Ok(client_transport.local_connection_id_snapshot(worker.connection)),
      )
      Ok(worker)
    }
    DevelopmentState(reply) -> handle_development_state(worker, reply)
    TelemetryStats(reply) ->
      case worker.qlog_writer {
        None -> {
          process.send(reply, Ok(qlog.Stats(0, 0, 0)))
          Ok(worker)
        }
        Some(writer) ->
          case qlog.stats(writer) {
            Ok(value) -> {
              process.send(reply, Ok(value))
              Ok(worker)
            }
            Error(_) -> reply_error(worker, reply, QlogUnavailable)
          }
      }
    ApplicationDiagnostics(reply) -> {
      process.send(reply, Ok(worker.qlog_writer))
      Ok(worker)
    }
    Phase(reply) -> {
      process.send(reply, Ok(client_transport.phase(worker.connection)))
      Ok(worker)
    }
    EarlyData(reply) -> {
      process.send(reply, Ok(worker.early_data_status))
      Ok(worker)
    }
    Resumption(reply) -> {
      process.send(reply, Ok(worker.resumption_status))
      Ok(worker)
    }
    Handshake(reply) -> {
      process.send(
        reply,
        Ok(HandshakeAttempt(
          ticket_supplied: worker.ticket_supplied,
          zero_rtt_enabled: worker.zero_rtt_enabled,
          ticket_allows_zero_rtt: worker.ticket_allows_zero_rtt,
          early_data_status: worker.early_data_status,
          resumption_status: worker.resumption_status,
        )),
      )
      Ok(worker)
    }
    Ticket(reply, deadline) -> handle_ticket(worker, reply, deadline)
    Protocol(reply) -> {
      process.send(
        reply,
        Ok(#(
          client_transport.version(worker.connection),
          client_transport.application_protocol(worker.connection),
          worker.congestion_control,
          client_transport.cipher_suite(worker.connection),
        )),
      )
      Ok(worker)
    }
    Close(code, deadline_milliseconds, reply) -> {
      let before = client_transport.stats(worker.connection)
      let closing =
        client_transport.begin_close(
          worker.connection,
          code,
          "application close",
        )
      let worker =
        fail_all(
          Worker(..worker, connection: closing, application_closed: True),
          ConnectionClosed,
        )
      // Emit the first CONNECTION_CLOSE before acknowledging the API call.
      // The actor then remains detached from its former owner until the transport's fixed closing deadline.
      case client_transport.drive(worker.connection) {
        Error(_) -> {
          client_transport.release(worker.connection)
          let #(_, resources) = take_qlog_close(worker)
          let _completion =
            start_client_close_completion(
              resources,
              process.self(),
              deadline_milliseconds,
              reply,
            )
          Error(Nil)
        }
        Ok(connection) -> {
          record_qlog_io(
            worker.qlog_writer,
            before,
            client_transport.stats(connection),
            connection,
          )
          let #(worker, resources) =
            take_qlog_close(Worker(..worker, connection: connection))
          case
            start_client_close_completion(
              resources,
              process.self(),
              deadline_milliseconds,
              reply,
            )
          {
            Ok(completion) ->
              Ok(Worker(..worker, close_completion: Some(completion)))
            Error(Nil) -> {
              client_transport.release(connection)
              Error(Nil)
            }
          }
        }
      }
    }
  }
}

fn handle_development_state(
  worker: Worker,
  reply: Subject(Result(DevelopmentSnapshot, Error)),
) -> Result(Worker, Nil) {
  let now = udp.monotonic_millisecond()
  case client_transport.next_deadline(worker.connection, now) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(deadline) -> {
      let progress = client_transport.send_progress(worker.connection)
      case snapshot_streams(worker.connection, dict.keys(worker.streams), []) {
        Error(error) -> reply_error(worker, reply, error)
        Ok(streams) -> {
          process.send(
            reply,
            Ok(DevelopmentSnapshot(
              observed_at_milliseconds: now,
              next_wake_milliseconds: deadline,
              previous_park: worker.previous_park,
              next_pmtu_probe_milliseconds: worker.next_pmtu_probe_milliseconds,
              path_mtu: client_transport.path_mtu(worker.connection),
              pacing: client_transport.pacing_wake_progress(
                worker.connection,
                now,
              ),
              longest_wait: worker.longest_wait,
              transport: progress,
              streams: streams,
              actor_pending_sends: pending_send_identifiers(
                dict.to_list(worker.streams),
                [],
              ),
              actor_streams: dict.size(worker.streams),
              incoming_streams: queue_count(worker.incoming),
              maximum_pto_backoff: worker.maximum_pto_backoff,
            )),
          )
          Ok(worker)
        }
      }
    }
  }
}

fn observe_recovery_backoff(worker: Worker) -> Worker {
  let transport.SendProgress(pto_backoff_count:, ..) =
    client_transport.send_progress(worker.connection)
  Worker(
    ..worker,
    maximum_pto_backoff: int.max(worker.maximum_pto_backoff, pto_backoff_count),
  )
}

fn snapshot_streams(
  connection: client_transport.State,
  identifiers: List(Int),
  accumulated: List(stream_state.SendProgress),
) -> Result(List(stream_state.SendProgress), Error) {
  case identifiers {
    [] -> Ok(list.reverse(accumulated))
    [identifier, ..rest] ->
      case client_transport.stream_send_progress(connection, identifier) {
        Error(error) -> Error(map_transport_error(error))
        Ok(progress) ->
          snapshot_streams(connection, rest, [progress, ..accumulated])
      }
  }
}

fn pending_send_identifiers(
  entries: List(#(Int, StreamState)),
  accumulated: List(Int),
) -> List(Int) {
  case entries {
    [] -> list.reverse(accumulated)
    [#(identifier, StreamState(pending_send: Some(_), ..)), ..rest] ->
      pending_send_identifiers(rest, [identifier, ..accumulated])
    [_, ..rest] -> pending_send_identifiers(rest, accumulated)
  }
}

fn handle_open(
  worker: Worker,
  direction: stream_id.Direction,
  reply: Subject(Result(Int, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case udp.monotonic_millisecond() >= deadline {
    True -> reply_error(worker, reply, OperationTimeout)
    False ->
      case client_transport.open_stream(worker.connection, direction) {
        Error(error) ->
          case waits_for_application_keys(worker.connection, error) {
            False -> reply_error(worker, reply, map_transport_error(error))
            True ->
              case queue_count(worker.pending_opens) >= worker.queue_limit {
                True ->
                  reply_error(
                    worker,
                    reply,
                    OpenQueueExceeded(worker.queue_limit),
                  )
                False ->
                  Ok(
                    Worker(
                      ..worker,
                      pending_opens: queue_push(
                        worker.pending_opens,
                        PendingOpen(direction, reply, deadline),
                      ),
                    ),
                  )
              }
          }
        Ok(#(connection, identifier)) -> {
          process.send(reply, Ok(identifier))
          Ok(put_stream(
            Worker(..worker, connection: connection),
            identifier,
            new_stream_state(identifier),
          ))
        }
      }
  }
}

/// Retry stream opens that lost their 0-RTT keys to authenticated Retry or early-data rejection.
/// The caller remains bounded by its original operation deadline and by the endpoint queue limit; no busy loop or unbounded mailbox growth is introduced while the independently driven handshake completes.
fn retry_pending_opens(worker: Worker, now: Int) -> Worker {
  case queue_pop(worker.pending_opens) {
    Error(Nil) -> worker
    Ok(#(PendingOpen(direction, reply, deadline) as pending, rest)) ->
      case now >= deadline {
        True -> {
          process.send(reply, Error(OperationTimeout))
          retry_pending_opens(Worker(..worker, pending_opens: rest), now)
        }
        False ->
          case client_transport.open_stream(worker.connection, direction) {
            Ok(#(connection, identifier)) -> {
              process.send(reply, Ok(identifier))
              retry_pending_opens(
                put_stream(
                  Worker(..worker, connection: connection, pending_opens: rest),
                  identifier,
                  new_stream_state(identifier),
                ),
                now,
              )
            }
            Error(error) ->
              case waits_for_application_keys(worker.connection, error) {
                True ->
                  Worker(..worker, pending_opens: queue_prepend(rest, pending))
                False -> {
                  process.send(reply, Error(map_transport_error(error)))
                  retry_pending_opens(
                    Worker(..worker, pending_opens: rest),
                    now,
                  )
                }
              }
          }
      }
  }
}

fn waits_for_application_keys(
  connection: client_transport.State,
  error: client_transport.Error,
) -> Bool {
  case error, client_transport.phase(connection) {
    client_transport.QuicFailure(driver.ConnectionFailure(
      transport.ConnectionUnavailable,
    )),
      transport.Handshaking
    -> True
    _, _ -> False
  }
}

fn handle_accept(
  worker: Worker,
  reply: Subject(Result(IncomingStream, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case queue_pop(worker.incoming), worker.accept_waiter {
    Ok(#(identifier, rest)), _ -> {
      process.send(reply, incoming_stream(worker, identifier))
      Ok(Worker(..worker, incoming: rest))
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentAccept)
    Error(Nil), None ->
      Ok(Worker(..worker, accept_waiter: Some(AcceptWaiter(reply, deadline))))
  }
}

fn handle_send(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    bit_array.bit_size(bytes) % 8,
    dict.get(worker.streams, identifier),
    stream_id.can_send(identifier, stream_id.Client)
  {
    remainder, _, _ if remainder != 0 -> reply_error(worker, reply, InvalidInput)
    _, Error(_), _ -> reply_error(worker, reply, StreamClosed)
    _, _, False -> reply_error(worker, reply, InvalidDirection)
    _, Ok(stream), True ->
      case stream.pending_send, stream.send_finished {
        Some(_), _ -> reply_error(worker, reply, ConcurrentSend)
        None, True -> reply_error(worker, reply, StreamClosed)
        None, False -> {
          let pending = PendingSend(bytes, finish, reply, deadline)
          Ok(advance_send(worker, identifier, pending))
        }
      }
  }
}

fn advance_send(
  worker: Worker,
  identifier: Int,
  pending: PendingSend,
) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(pending.reply, Error(StreamClosed))
      worker
    }
    Ok(stream) ->
      case client_transport.buffered_send_bytes(worker.connection, identifier) {
        Error(error) -> {
          process.send(pending.reply, Error(map_transport_error(error)))
          put_stream(
            worker,
            identifier,
            StreamState(..stream, pending_send: None),
          )
        }
        Ok(buffered) -> {
          let available = worker.stream_buffer_limit - buffered
          let remaining_size = bit_array.byte_size(pending.remaining)
          case remaining_size, available {
            size, available if size > 0 && available <= 0 ->
              put_stream(
                worker,
                identifier,
                StreamState(..stream, pending_send: Some(pending)),
              )
            _, _ -> {
              let take =
                int.min(
                  remaining_size,
                  int.min(maximum_send_chunk_bytes, int.max(available, 0)),
                )
              let #(chunk, rest) = take_bytes(pending.remaining, take)
              let finish = pending.finish && rest == <<>>
              case
                client_transport.send(
                  worker.connection,
                  identifier,
                  chunk,
                  finish,
                )
              {
                Error(error) -> {
                  process.send(pending.reply, Error(map_transport_error(error)))
                  put_stream(
                    worker,
                    identifier,
                    StreamState(..stream, pending_send: None),
                  )
                }
                Ok(connection) ->
                  case rest {
                    <<>> -> {
                      process.send(pending.reply, Ok(Nil))
                      put_stream(
                        Worker(..worker, connection: connection),
                        identifier,
                        StreamState(
                          ..stream,
                          pending_send: None,
                          send_finished: stream.send_finished || finish,
                        ),
                      )
                    }
                    _ -> {
                      // Keep filling the already granted, application-bounded transport buffer in this actor turn.
                      // Waiting for a packet or timer after every 64 KiB chunk can deadlock a request/response protocol: the caller is waiting for `send` to return while the peer is waiting for the remainder of that same application write.
                      // Recursion stops as soon as the configured stream buffer has no room, so growth remains bounded and subsequent progress still depends on ACK/flow-control credit.
                      let pending =
                        PendingSend(
                          rest,
                          pending.finish,
                          pending.reply,
                          pending.deadline,
                        )
                      let worker =
                        put_stream(
                          Worker(..worker, connection: connection),
                          identifier,
                          StreamState(..stream, pending_send: Some(pending)),
                        )
                      advance_send(worker, identifier, pending)
                    }
                  }
              }
            }
          }
        }
      }
  }
}

fn handle_receive(
  worker: Worker,
  identifier: Int,
  maximum_bytes: Int,
  reply: Subject(Result(Read, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case
    maximum_bytes > 0 && maximum_bytes <= worker.stream_buffer_limit,
    dict.get(worker.streams, identifier),
    stream_id.can_receive(identifier, stream_id.Client)
  {
    False, _, _ -> reply_error(worker, reply, InvalidInput)
    _, Error(_), _ -> reply_error(worker, reply, StreamClosed)
    _, _, False -> reply_error(worker, reply, InvalidDirection)
    True, Ok(stream), True ->
      case stream.read_waiter {
        Some(_) -> reply_error(worker, reply, ConcurrentReceive)
        None ->
          Ok(read_or_wait(
            worker,
            identifier,
            ReadWaiter(maximum_bytes, reply, deadline),
          ))
      }
  }
}

fn read_or_wait(worker: Worker, identifier: Int, waiter: ReadWaiter) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(waiter.reply, Error(StreamClosed))
      worker
    }
    Ok(stream) ->
      case
        client_transport.read(
          worker.connection,
          identifier,
          waiter.maximum_bytes,
        )
      {
        Error(error) -> {
          process.send(waiter.reply, Error(map_transport_error(error)))
          worker
        }
        Ok(#(connection, runtime_connection.Pending)) ->
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(..stream, read_waiter: Some(waiter)),
          )
        Ok(#(connection, runtime_connection.Data(bytes, finished))) -> {
          process.send(waiter.reply, Ok(Data(bytes, finished)))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(
              ..stream,
              read_waiter: None,
              receive_finished: stream.receive_finished || finished,
            ),
          )
        }
        Ok(#(connection, runtime_connection.Reset(code))) -> {
          process.send(waiter.reply, Ok(Reset(code)))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(..stream, read_waiter: None, receive_finished: True),
          )
        }
        Ok(#(connection, runtime_connection.Finished)) -> {
          process.send(waiter.reply, Ok(Finished))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(..stream, read_waiter: None, receive_finished: True),
          )
        }
      }
  }
}

fn handle_reset(
  worker: Worker,
  identifier: Int,
  code: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case client_transport.reset(worker.connection, identifier, code) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(Worker(..worker, connection: connection))
    }
  }
}

fn handle_stop_sending(
  worker: Worker,
  identifier: Int,
  code: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case client_transport.stop_sending(worker.connection, identifier, code) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(Worker(..worker, connection: connection))
    }
  }
}

fn handle_send_datagram(
  worker: Worker,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  let payload_size = bit_array.byte_size(payload)
  case client_transport.maximum_datagram_size(worker.connection) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(maximum) if payload_size > maximum ->
      reply_error(worker, reply, DatagramTooLarge(maximum))
    Ok(_) ->
      case client_transport.send_datagram(worker.connection, payload) {
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
        }
      }
  }
}

fn handle_receive_datagram(
  worker: Worker,
  reply: Subject(Result(BitArray, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case queue_pop(worker.datagrams), worker.datagram_waiter {
    Ok(#(payload, rest)), _ -> {
      process.send(reply, Ok(payload))
      Ok(
        Worker(
          ..worker,
          datagrams: rest,
          datagram_bytes: worker.datagram_bytes - bit_array.byte_size(payload),
        ),
      )
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentDatagramReceive)
    Error(Nil), None ->
      Ok(
        Worker(..worker, datagram_waiter: Some(DatagramWaiter(reply, deadline))),
      )
  }
}

fn handle_ticket(
  worker: Worker,
  reply: Subject(Result(ResumptionTicket, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case worker.latest_ticket, worker.ticket_waiter {
    Some(ticket), None ->
      case ticket.address_token == <<>> {
        False -> {
          process.send(reply, Ok(ticket))
          Ok(worker)
        }
        True ->
          Ok(
            Worker(
              ..worker,
              ticket_waiter: Some(TicketWaiter(
                reply,
                deadline,
                Some(ticket_token_deadline(
                  deadline,
                  udp.monotonic_millisecond(),
                )),
              )),
            ),
          )
      }
    Some(_), Some(_) -> reply_error(worker, reply, TicketUnavailable)
    None, Some(_) -> reply_error(worker, reply, TicketUnavailable)
    None, None ->
      Ok(
        Worker(
          ..worker,
          ticket_waiter: Some(TicketWaiter(reply, deadline, None)),
        ),
      )
  }
}

fn ticket_token_deadline(deadline: Option(Int), now: Int) -> Int {
  let coalescing = now + address_token_coalescing_milliseconds
  case deadline {
    Some(value) -> int.min(value, coalescing)
    None -> coalescing
  }
}

fn dispatch_transport_events(worker: Worker) -> Worker {
  case client_transport.take_events(worker.connection) {
    Ok(#(connection, events)) ->
      dispatch_events(Worker(..worker, connection: connection), events)
    Error(error) ->
      Worker(..worker, terminal_error: Some(map_transport_error(error)))
  }
}

fn dispatch_events(worker: Worker, events: List(transport.Event)) -> Worker {
  case events {
    [] -> worker
    [event, ..rest] -> dispatch_events(dispatch_event(worker, event), rest)
  }
}

fn dispatch_event(worker: Worker, event: transport.Event) -> Worker {
  case event {
    transport.StreamOpened(identifier) -> register_stream(worker, identifier)
    transport.StreamReadable(identifier) ->
      service_read_waiter(worker, identifier)
    transport.StreamWasReset(identifier, _) ->
      service_read_waiter(worker, identifier)
    transport.StreamSendCompleted(identifier, outcome) ->
      complete_send(worker, identifier, outcome)
    transport.DatagramReceived(payload) -> enqueue_datagram(worker, payload)
    transport.SessionTicketStored(ticket) -> store_ticket(worker, ticket)
    transport.NewTokenReceived(token) -> store_address_token(worker, token)
    transport.EarlyDataWasAccepted ->
      Worker(..worker, early_data_status: EarlyDataAccepted)
    transport.EarlyDataWasRejected ->
      Worker(..worker, early_data_status: EarlyDataRejected)
    transport.HandshakeEstablished ->
      Worker(..worker, resumption_status: case worker.resumption_status {
        ResumptionPending ->
          case client_transport.resumed(worker.connection) {
            True -> Resumed
            False -> FullHandshake
          }
        status -> status
      })
      |> replenish_local_connection_ids
    transport.LocalConnectionIdRetired(_, _) ->
      replenish_local_connection_ids(worker)
    transport.PathValidated -> {
      case worker.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      case worker.migration_waiter {
        Some(MigrationWaiter(reply, _)) -> {
          process.send(reply, Ok(Nil))
          Worker(..worker, migration_waiter: None)
        }
        None -> worker
      }
    }
    transport.PathValidationFailed ->
      case worker.migration_waiter {
        Some(MigrationWaiter(reply, _)) -> {
          record_qlog_migration_abandoned(worker.qlog_writer)
          process.send(reply, Error(MigrationUnavailable))
          Worker(..worker, migration_waiter: None)
        }
        None -> worker
      }
    transport.PersistentCongestionDetected -> {
      case worker.qlog_writer {
        Some(writer) ->
          qlog.congestion_state_updated_with_trigger(
            writer,
            udp.monotonic_millisecond(),
            1,
            3,
          )
        None -> Nil
      }
      worker
    }
    transport.PeerClosed(code, _) -> {
      let error = PeerClosedWithCode(code)
      Worker(..worker, terminal_error: Some(error))
    }
    transport.PeerTransportClosed(code, _) ->
      Worker(..worker, terminal_error: Some(PeerTransportFailureWithCode(code)))
    transport.LocalTransportFailure(_, code) ->
      fail_all(worker, TransportFailureWithCode(code))
    transport.StatelessResetReceived ->
      Worker(..worker, terminal_error: Some(ConnectionClosed))
    _ -> worker
  }
}

fn replenish_local_connection_ids(worker: Worker) -> Worker {
  case client_transport.replenish_local_connection_ids(worker.connection) {
    Ok(connection) -> Worker(..worker, connection: connection)
    Error(error) ->
      Worker(..worker, terminal_error: Some(map_transport_error(error)))
  }
}

fn register_stream(worker: Worker, identifier: Int) -> Worker {
  let worker = case dict.has_key(worker.streams, identifier) {
    True -> worker
    False -> put_stream(worker, identifier, new_stream_state(identifier))
  }
  case stream_id.decode(identifier) {
    Ok(stream_id.StreamId(_, stream_id.Server, _)) ->
      enqueue_incoming(worker, identifier)
    _ -> worker
  }
}

fn enqueue_incoming(worker: Worker, identifier: Int) -> Worker {
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> {
      process.send(reply, incoming_stream(worker, identifier))
      Worker(..worker, accept_waiter: None)
    }
    None ->
      case queue_count(worker.incoming) >= worker.queue_limit {
        True ->
          fail_all(worker, IncomingStreamQueueExceeded(worker.queue_limit))
        False ->
          Worker(..worker, incoming: queue_push(worker.incoming, identifier))
      }
  }
}

fn incoming_stream(
  worker: Worker,
  identifier: Int,
) -> Result(IncomingStream, Error) {
  case stream_id.decode(identifier) {
    Ok(stream_id.StreamId(_, _, direction)) ->
      Ok(IncomingStream(
        Stream(
          Connection(
            worker.commands,
            process.self(),
            worker.operation_timeout_milliseconds,
            worker.hostname,
            worker.port,
          ),
          identifier,
        ),
        direction == stream_id.Bidirectional,
      ))
    Error(_) -> Error(QuicFailure)
  }
}

fn service_read_waiter(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.streams, identifier) {
    Ok(StreamState(read_waiter: Some(waiter), ..)) ->
      read_or_wait(worker, identifier, waiter)
    _ -> worker
  }
}

fn enqueue_datagram(worker: Worker, payload: BitArray) -> Worker {
  case worker.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> {
      process.send(reply, Ok(payload))
      Worker(..worker, datagram_waiter: None)
    }
    None -> {
      let size = bit_array.byte_size(payload)
      case
        queue_count(worker.datagrams) >= worker.queue_limit
        || worker.datagram_bytes + size > worker.datagram_limit
      {
        True -> fail_all(worker, DatagramQueueExceeded(worker.queue_limit))
        False ->
          Worker(
            ..worker,
            datagrams: queue_push(worker.datagrams, payload),
            datagram_bytes: worker.datagram_bytes + size,
          )
      }
    }
  }
}

fn store_ticket(worker: Worker, ticket: session_ticket.ClientTicket) -> Worker {
  let value =
    ResumptionTicket(
      worker.hostname,
      worker.port,
      ticket,
      worker.latest_address_token,
    )
  case worker.ticket_waiter, value.address_token == <<>> {
    Some(TicketWaiter(reply, _, _)), False -> {
      process.send(reply, Ok(value))
      Worker(..worker, latest_ticket: Some(value), ticket_waiter: None)
    }
    Some(TicketWaiter(reply, deadline, _)), True ->
      Worker(
        ..worker,
        latest_ticket: Some(value),
        ticket_waiter: Some(TicketWaiter(
          reply,
          deadline,
          Some(ticket_token_deadline(deadline, udp.monotonic_millisecond())),
        )),
      )
    None, _ -> Worker(..worker, latest_ticket: Some(value))
  }
}

fn store_address_token(worker: Worker, token: BitArray) -> Worker {
  let latest_ticket = case worker.latest_ticket {
    None -> None
    Some(ResumptionTicket(hostname, port, ticket, _)) ->
      Some(ResumptionTicket(hostname, port, ticket, token))
  }
  let worker =
    Worker(..worker, latest_ticket: latest_ticket, latest_address_token: token)
  case latest_ticket, worker.ticket_waiter {
    Some(ticket), Some(TicketWaiter(reply, _, _)) -> {
      process.send(reply, Ok(ticket))
      Worker(..worker, ticket_waiter: None)
    }
    _, _ -> worker
  }
}

fn retry_pending_sends(worker: Worker) -> Worker {
  retry_pending_send_entries(worker, dict.to_list(worker.streams))
}

fn retry_pending_send_entries(
  worker: Worker,
  entries: List(#(Int, StreamState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, StreamState(pending_send: Some(pending), ..)), ..rest] ->
      retry_pending_send_entries(
        advance_send(worker, identifier, pending),
        rest,
      )
    [_, ..rest] -> retry_pending_send_entries(worker, rest)
  }
}

fn register_completion_waiter(
  worker: Worker,
  identifier: Int,
  owner: Pid,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Worker {
  case udp.monotonic_millisecond() >= deadline {
    True -> completion_reply(worker, observation, Error(OperationTimeout))
    False ->
      case stream_id.can_send(identifier, stream_id.Client) {
        False -> completion_reply(worker, observation, Error(InvalidDirection))
        True ->
          case stream_completion.get(worker.completions, identifier) {
            Some(outcome) -> completion_reply(worker, observation, Ok(outcome))
            None ->
              register_live_completion_waiter(
                worker,
                identifier,
                owner,
                observation,
                deadline,
              )
          }
      }
  }
}

fn register_live_completion_waiter(
  worker: Worker,
  identifier: Int,
  owner: Pid,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Worker {
  let worker = case dict.get(worker.completion_waiters, identifier) {
    Ok(waiter) ->
      case process.is_alive(waiter.owner) {
        False -> remove_completion_waiter(worker, identifier)
        True -> worker
      }
    Error(Nil) -> worker
  }
  case
    dict.has_key(worker.completion_waiters, identifier),
    dict.size(worker.completion_waiters)
    >= int.min(worker.queue_limit, maximum_completion_waiters)
  {
    True, _ -> completion_reply(worker, observation, Error(ConcurrentSend))
    False, True ->
      completion_reply(
        worker,
        observation,
        Error(
          IncomingStreamQueueExceeded(int.min(
            worker.queue_limit,
            maximum_completion_waiters,
          )),
        ),
      )
    False, False ->
      inspect_completion_stream(
        worker,
        identifier,
        owner,
        observation,
        deadline,
      )
  }
}

fn inspect_completion_stream(
  worker: Worker,
  identifier: Int,
  owner: Pid,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Worker {
  case client_transport.stream_send_progress(worker.connection, identifier) {
    Error(error) ->
      completion_reply(worker, observation, Error(map_transport_error(error)))
    Ok(progress) if progress.fin_acknowledged ->
      completion_reply(worker, observation, Ok(stream_completion.Acknowledged))
    Ok(progress) if progress.send_reset ->
      completion_reply(worker, observation, Error(StreamClosed))
    Ok(_) ->
      case process.is_alive(owner) {
        False -> worker
        True -> {
          let monitor = process.monitor(owner)
          Worker(
            ..worker,
            completion_waiters: dict.insert(
              worker.completion_waiters,
              identifier,
              CompletionWaiter(owner, monitor, observation, deadline),
            ),
            selector: process.select_specific_monitor(
              worker.selector,
              monitor,
              fn(_) { CompletionCallerExited(identifier, monitor) },
            ),
          )
        }
      }
  }
}

fn completion_reply(
  worker: Worker,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  outcome: Result(stream_completion.Outcome, Error),
) -> Worker {
  let _published = send_observation.publish(observation, outcome)
  worker
}

fn remove_completion_waiter(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.completion_waiters, identifier) {
    Error(Nil) -> worker
    Ok(waiter) -> {
      process.demonitor_process(waiter.monitor)
      Worker(
        ..worker,
        completion_waiters: dict.delete(worker.completion_waiters, identifier),
        selector: process.deselect_specific_monitor(
          worker.selector,
          waiter.monitor,
        ),
      )
    }
  }
}

fn completion_caller_exited(
  worker: Worker,
  identifier: Int,
  monitor: process.Monitor,
) -> Worker {
  case dict.get(worker.completion_waiters, identifier) {
    Ok(waiter) if waiter.monitor == monitor ->
      remove_completion_waiter(worker, identifier)
    _ -> worker
  }
}

fn complete_send(
  worker: Worker,
  identifier: Int,
  outcome: stream_completion.Outcome,
) -> Worker {
  let worker =
    Worker(
      ..worker,
      completions: stream_completion.record(
        worker.completions,
        identifier,
        outcome,
      ),
    )
  case dict.get(worker.completion_waiters, identifier) {
    Error(Nil) -> worker
    Ok(waiter) -> {
      let result = case udp.monotonic_millisecond() >= waiter.deadline {
        True -> Error(OperationTimeout)
        False -> Ok(outcome)
      }
      completion_reply(worker, waiter.observation, result)
      |> remove_completion_waiter(identifier)
    }
  }
}

fn expire_completion_waiters(worker: Worker, now: Int) -> Worker {
  list.fold(dict.to_list(worker.completion_waiters), worker, fn(worker, entry) {
    let #(identifier, waiter) = entry
    case now >= waiter.deadline {
      True ->
        completion_reply(worker, waiter.observation, Error(OperationTimeout))
        |> remove_completion_waiter(identifier)
      False -> worker
    }
  })
}

fn fail_completion_waiters(worker: Worker, error: Error) -> Worker {
  list.fold(dict.to_list(worker.completion_waiters), worker, fn(worker, entry) {
    let #(identifier, waiter) = entry
    completion_reply(worker, waiter.observation, Error(error))
    |> remove_completion_waiter(identifier)
  })
}

fn completion_deadlines(
  deadline: Option(Int),
  waiters: List(CompletionWaiter),
) -> Option(Int) {
  list.fold(waiters, deadline, fn(deadline, waiter) {
    earlier_deadline(deadline, Some(waiter.deadline))
  })
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let worker = expire_pending_opens(worker, now)
  let worker = case worker.accept_waiter {
    Some(AcceptWaiter(reply, Some(deadline))) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, accept_waiter: None)
    }
    _ -> worker
  }
  let worker = case worker.datagram_waiter {
    Some(DatagramWaiter(reply, Some(deadline))) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, datagram_waiter: None)
    }
    _ -> worker
  }
  let worker = case worker.migration_waiter {
    Some(MigrationWaiter(reply, deadline)) if now >= deadline -> {
      record_qlog_migration_abandoned(worker.qlog_writer)
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, migration_waiter: None)
    }
    _ -> worker
  }
  let worker = expire_ticket_waiter(worker, now)
  expire_stream_waiters(worker, dict.to_list(worker.streams), now)
}

fn expire_ticket_waiter(worker: Worker, now: Int) -> Worker {
  case worker.ticket_waiter {
    None -> worker
    Some(TicketWaiter(reply, deadline, token_deadline)) ->
      case deadline, token_deadline {
        Some(value), _ if now >= value -> complete_ticket_waiter(worker, reply)
        _, Some(value) if now >= value -> complete_ticket_waiter(worker, reply)
        _, _ -> worker
      }
  }
}

fn complete_ticket_waiter(
  worker: Worker,
  reply: Subject(Result(ResumptionTicket, Error)),
) -> Worker {
  case worker.latest_ticket {
    Some(ticket) -> process.send(reply, Ok(ticket))
    None -> process.send(reply, Error(TicketUnavailable))
  }
  Worker(..worker, ticket_waiter: None)
}

fn expire_pending_opens(worker: Worker, now: Int) -> Worker {
  Worker(
    ..worker,
    pending_opens: expire_pending_open_queue(
      worker.pending_opens,
      queue_new(),
      now,
    ),
  )
}

fn expire_pending_open_queue(
  remaining: Queue(PendingOpen),
  retained: Queue(PendingOpen),
  now: Int,
) -> Queue(PendingOpen) {
  case queue_pop(remaining) {
    Error(Nil) -> retained
    Ok(#(PendingOpen(_, reply, deadline) as pending, rest)) ->
      case now >= deadline {
        True -> {
          process.send(reply, Error(OperationTimeout))
          expire_pending_open_queue(rest, retained, now)
        }
        False ->
          expire_pending_open_queue(rest, queue_push(retained, pending), now)
      }
  }
}

fn expire_stream_waiters(
  worker: Worker,
  entries: List(#(Int, StreamState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, stream), ..rest] -> {
      let stream = case stream.read_waiter {
        Some(ReadWaiter(_, reply, Some(deadline))) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          StreamState(..stream, read_waiter: None)
        }
        _ -> stream
      }
      let stream = case stream.pending_send {
        Some(PendingSend(_, _, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          StreamState(..stream, pending_send: None)
        }
        _ -> stream
      }
      expire_stream_waiters(put_stream(worker, identifier, stream), rest, now)
    }
  }
}

fn park_progress(worker: Worker, now: Int) -> Result(ParkProgress, Error) {
  use protocol <- result.try(
    client_transport.next_deadline(worker.connection, now)
    |> result.map_error(map_transport_error),
  )
  let pmtu = positive_deadline(worker.next_pmtu_probe_milliseconds)
  let operation =
    None
    |> earlier_deadline(pending_open_deadline(worker.pending_opens))
    |> earlier_deadline(accept_deadline(worker.accept_waiter))
    |> earlier_deadline(datagram_deadline(worker.datagram_waiter))
    |> earlier_deadline(migration_deadline(worker.migration_waiter))
    |> earlier_deadline(ticket_deadline(worker.ticket_waiter))
    |> stream_deadlines(dict.values(worker.streams))
    |> completion_deadlines(dict.values(worker.completion_waiters))
  let selected =
    protocol |> earlier_deadline(pmtu) |> earlier_deadline(operation)
  Ok(ParkProgress(
    now,
    protocol,
    pmtu,
    operation,
    selected,
    client_transport.path_mtu(worker.connection),
    client_transport.pacing_wake_progress(worker.connection, now),
    client_transport.send_progress(worker.connection),
  ))
}

fn record_wait(worker: Worker, park: ParkProgress, wake: WaitWake) -> Worker {
  let completed = WaitProgress(park, udp.monotonic_millisecond(), wake)
  let longest = case worker.longest_wait {
    None -> Some(completed)
    Some(previous) ->
      case wait_duration(completed) > wait_duration(previous) {
        True -> Some(completed)
        False -> worker.longest_wait
      }
  }
  Worker(..worker, longest_wait: longest)
}

fn wait_duration(progress: WaitProgress) -> Int {
  let WaitProgress(
    park: ParkProgress(observed_at_milliseconds: started, ..),
    resumed_at_milliseconds: resumed,
    ..,
  ) = progress
  resumed - started
}

fn stream_deadlines(
  deadline: Option(Int),
  streams: List(StreamState),
) -> Option(Int) {
  case streams {
    [] -> deadline
    [stream, ..rest] ->
      stream_deadlines(
        deadline
          |> earlier_deadline(read_deadline(stream.read_waiter))
          |> earlier_deadline(send_deadline(stream.pending_send)),
        rest,
      )
  }
}

fn maybe_probe_path_mtu(worker: Worker, now: Int) -> Result(Worker, Error) {
  case
    client_transport.path_validation_in_progress(worker.connection),
    client_transport.phase(worker.connection)
  {
    True, _
    | False, transport.Handshaking
    | False, transport.Closing
    | False, transport.Draining
    | False, transport.Closed
    -> Ok(Worker(..worker, next_pmtu_probe_milliseconds: 0))
    False, transport.Established -> maybe_probe_established(worker, now)
  }
}

fn maybe_probe_established(worker: Worker, now: Int) -> Result(Worker, Error) {
  case
    client_transport.pmtu_discovery_complete(worker.connection),
    client_transport.pmtu_probe_outstanding(worker.connection),
    client_transport.pmtu_probe_available(worker.connection),
    worker.next_pmtu_probe_milliseconds
  {
    True, _, _, _ | _, True, _, _ | _, _, False, _ ->
      Ok(Worker(..worker, next_pmtu_probe_milliseconds: 0))
    False, False, True, 0 ->
      Ok(
        Worker(
          ..worker,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    False, False, True, deadline if now < deadline -> Ok(worker)
    False, False, True, _ -> send_pmtu_probe(worker, now)
  }
}

fn send_pmtu_probe(worker: Worker, now: Int) -> Result(Worker, Error) {
  case client_transport.probe_path_mtu(worker.connection, now) {
    Ok(connection) ->
      Ok(
        Worker(
          ..worker,
          connection: connection,
          next_pmtu_probe_milliseconds: case
            client_transport.pmtu_probe_outstanding(connection),
            client_transport.pmtu_probe_available(connection)
          {
            True, _ | _, False -> 0
            False, True -> now + pmtu_probe_interval_milliseconds
          },
        ),
      )
    Error(client_transport.QuicFailure(driver.ConnectionFailure(transport.PacingLimited(
      _,
    ))))
    | Error(client_transport.QuicFailure(driver.ConnectionFailure(
        transport.CongestionLimited,
      )))
    | Error(client_transport.QuicFailure(driver.ConnectionFailure(
        transport.RecoveryLimited,
      ))) -> Ok(Worker(..worker, next_pmtu_probe_milliseconds: 0))
    Error(error) -> Error(map_transport_error(error))
  }
}

fn fail_all(worker: Worker, error: Error) -> Worker {
  let worker = fail_completion_waiters(worker, error)
  fail_pending_opens(worker.pending_opens, error)
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.migration_waiter {
    Some(MigrationWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, _, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  list.each(dict.values(worker.streams), fn(stream) {
    case stream.read_waiter {
      Some(ReadWaiter(_, reply, _)) -> process.send(reply, Error(error))
      None -> Nil
    }
    case stream.pending_send {
      Some(PendingSend(_, _, reply, _)) -> process.send(reply, Error(error))
      None -> Nil
    }
  })
  Worker(
    ..worker,
    pending_opens: queue_new(),
    accept_waiter: None,
    datagram_waiter: None,
    migration_waiter: None,
    ticket_waiter: None,
    streams: dict.map_values(worker.streams, fn(_, stream) {
      StreamState(..stream, read_waiter: None, pending_send: None)
    }),
  )
}

/// A peer close terminates wire input, not bytes which the transport had already authenticated and acknowledged.
/// Keep those bounded stream receive buffers behind the existing finite terminal tombstone so a read command which lost the mailbox race with CONNECTION_CLOSE can still drain them.
/// All operations capable of creating work fail immediately, and the UDP socket plus qlog writer are released before entering the tombstone loop.
fn shutdown_after_peer_close(worker: Worker, error: Error) -> Nil {
  case worker.application_closed {
    // A local close already relinquished every application stream.
    // A peer's acknowledgement must not restart a receive-retention window, including when the old owner has already exited during the wire closing period.
    True -> shutdown_now(worker, error)
    False -> retain_peer_terminal(worker, error)
  }
}

fn retain_peer_terminal(worker: Worker, error: Error) -> Nil {
  let worker = prepare_peer_terminal(worker, error)
  client_transport.close(worker.connection, 0, "peer already closed")
  close_qlog(worker.qlog_writer)
  collect_qlog(worker.qlog_reservation, worker.qlog_cleanup)
  peer_terminal_loop(
    Worker(
      ..worker,
      qlog_writer: None,
      qlog_cleanup: None,
      qlog_reservation: None,
    ),
    error,
    udp.monotonic_millisecond() + worker.operation_timeout_milliseconds,
  )
}

fn prepare_peer_terminal(worker: Worker, error: Error) -> Worker {
  let worker = fail_completion_waiters(worker, error)
  fail_pending_opens(worker.pending_opens, error)
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.migration_waiter {
    Some(MigrationWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, _, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  let worker =
    Worker(
      ..worker,
      pending_opens: queue_new(),
      incoming: queue_new(),
      accept_waiter: None,
      datagrams: queue_new(),
      datagram_bytes: 0,
      datagram_waiter: None,
      migration_waiter: None,
      latest_ticket: None,
      latest_address_token: <<>>,
      ticket_waiter: None,
      next_pmtu_probe_milliseconds: 0,
    )
  prepare_peer_terminal_streams(worker, dict.to_list(worker.streams), error)
}

fn prepare_peer_terminal_streams(
  worker: Worker,
  streams: List(#(Int, StreamState)),
  error: Error,
) -> Worker {
  case streams {
    [] -> worker
    [#(identifier, stream), ..rest] -> {
      case stream.pending_send {
        Some(PendingSend(_, _, reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      let stream = StreamState(..stream, pending_send: None)
      let worker = put_stream(worker, identifier, stream)
      let worker = case stream.read_waiter {
        Some(waiter) ->
          terminal_read_or_error(worker, identifier, waiter, error)
        None -> worker
      }
      prepare_peer_terminal_streams(worker, rest, error)
    }
  }
}

fn terminal_read_or_error(
  worker: Worker,
  identifier: Int,
  waiter: ReadWaiter,
  terminal_error: Error,
) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(waiter.reply, Error(terminal_error))
      worker
    }
    Ok(stream) ->
      case
        client_transport.read(
          worker.connection,
          identifier,
          waiter.maximum_bytes,
        )
      {
        Error(_) | Ok(#(_, runtime_connection.Pending)) -> {
          process.send(waiter.reply, Error(terminal_error))
          put_stream(
            worker,
            identifier,
            StreamState(..stream, read_waiter: None, receive_finished: True),
          )
        }
        Ok(#(connection, runtime_connection.Data(bytes, finished))) -> {
          process.send(waiter.reply, Ok(Data(bytes, finished)))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(
              ..stream,
              read_waiter: None,
              receive_finished: stream.receive_finished || finished,
            ),
          )
        }
        Ok(#(connection, runtime_connection.Reset(code))) -> {
          process.send(waiter.reply, Ok(Reset(code)))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(..stream, read_waiter: None, receive_finished: True),
          )
        }
        Ok(#(connection, runtime_connection.Finished)) -> {
          process.send(waiter.reply, Ok(Finished))
          put_stream(
            Worker(..worker, connection: connection),
            identifier,
            StreamState(..stream, read_waiter: None, receive_finished: True),
          )
        }
      }
  }
}

fn peer_terminal_loop(worker: Worker, error: Error, deadline: Int) -> Nil {
  let remaining = deadline - udp.monotonic_millisecond()
  case remaining <= 0 {
    True -> Nil
    False ->
      case process.selector_receive(worker.selector, within: remaining) {
        Error(Nil) | Ok(OwnerExited) -> Nil
        Ok(ReceivedNetwork(_)) -> peer_terminal_loop(worker, error, deadline)
        Ok(CompletionCallerExited(identifier, monitor)) ->
          peer_terminal_loop(
            completion_caller_exited(worker, identifier, monitor),
            error,
            deadline,
          )
        Ok(ReceivedCommand(Receive(identifier, maximum, reply, _)))
          if maximum > 0 && maximum <= worker.stream_buffer_limit
        ->
          peer_terminal_loop(
            terminal_read_or_error(
              worker,
              identifier,
              ReadWaiter(maximum, reply, None),
              error,
            ),
            error,
            deadline,
          )
        // Explicit close relinquishes the retained receive buffers.
        // The wire and qlog resources were already released on entry, so there is no transport closing period left to supervise here.
        Ok(ReceivedCommand(Close(_, deadline_milliseconds, reply))) -> {
          start_terminal_close_completion(
            worker.commands,
            deadline_milliseconds,
            reply,
          )
          Nil
        }
        Ok(ReceivedCommand(command)) -> {
          reject_terminal_command(command, error)
          peer_terminal_loop(worker, error, deadline)
        }
      }
  }
}

fn shutdown(worker: Worker, error: Error) -> Nil {
  shutdown_resources(worker, error)
  terminal_loop(
    worker.commands,
    error,
    udp.monotonic_millisecond() + worker.operation_timeout_milliseconds,
  )
}

/// Release a locally closed connection only after the transport's finite Closing/Draining deadline reached Closed.
/// No terminal command loop is needed: the public handle observes the dead actor as idempotently closed.
fn finish_closed_transport(worker: Worker) -> Nil {
  let worker = fail_all(worker, ConnectionClosed)
  client_transport.release(worker.connection)
  case worker.close_completion {
    Some(completion) ->
      forward_queued_close_waiters(
        worker.commands,
        completion,
        worker.close_completion_waiters,
        maximum_close_waiters * 2,
      )
    None -> {
      close_qlog(worker.qlog_writer)
      collect_qlog(worker.qlog_reservation, worker.qlog_cleanup)
    }
  }
}

/// A close completion can still be flushing qlog when the transport reaches Closed.
/// Forward a finite mailbox prefix before this actor exits.
/// Every forwarded signal precedes this actor's DOWN at the completion owner, so its final zero-time drain cannot lose an admitted waiter.
fn forward_queued_close_waiters(
  commands: Subject(Command),
  completion: ClientCloseCompletion,
  accepted_waiters: Int,
  remaining_scan: Int,
) -> Nil {
  case remaining_scan <= 0 {
    True -> Nil
    False ->
      case process.receive(commands, within: 0) {
        Error(Nil) -> Nil
        Ok(Close(_, _, reply)) -> {
          case accepted_waiters >= maximum_close_waiters - 1 {
            True -> process.send(reply, Error(OperationTimeout))
            False -> await_client_close_completion(completion, reply)
          }
          forward_queued_close_waiters(
            commands,
            completion,
            case accepted_waiters >= maximum_close_waiters - 1 {
              True -> accepted_waiters
              False -> accepted_waiters + 1
            },
            remaining_scan - 1,
          )
        }
        Ok(command) -> {
          reject_terminal_command(command, ConnectionClosed)
          forward_queued_close_waiters(
            commands,
            completion,
            accepted_waiters,
            remaining_scan - 1,
          )
        }
      }
  }
}

fn shutdown_now(worker: Worker, error: Error) -> Nil {
  shutdown_resources(worker, error)
}

fn shutdown_resources(worker: Worker, error: Error) -> Nil {
  let _ = fail_all(worker, error)
  client_transport.close(worker.connection, 0, "worker shutdown")
  case worker.close_completion {
    // The affine qlog receipts already belong to the completion actor.
    // Forward every admitted/queued Close before this actor exits; its DOWN then forms the completion actor's final ownership barrier.
    Some(completion) ->
      forward_queued_close_waiters(
        worker.commands,
        completion,
        worker.close_completion_waiters,
        maximum_close_waiters * 2,
      )
    None -> {
      close_qlog(worker.qlog_writer)
      collect_qlog(worker.qlog_reservation, worker.qlog_cleanup)
    }
  }
}

/// Keep the authoritative peer close code observable for one finite public operation window.
/// Without this tombstone a command sent just after the close packet races the actor exit and degrades to an untyped local close.
fn terminal_loop(
  commands: Subject(Command),
  error: Error,
  deadline: Int,
) -> Nil {
  let remaining = deadline - udp.monotonic_millisecond()
  case remaining <= 0 {
    True -> Nil
    False ->
      case process.receive(commands, within: remaining) {
        Error(Nil) -> Nil
        Ok(Close(_, deadline_milliseconds, reply)) -> {
          start_terminal_close_completion(
            commands,
            deadline_milliseconds,
            reply,
          )
          Nil
        }
        Ok(command) -> {
          reject_terminal_command(command, error)
          terminal_loop(commands, error, deadline)
        }
      }
  }
}

/// Turn the terminal actor's final Close into one bounded shared completion.
/// The actor drains a finite prefix before it exits, so every caller admitted before the exit linearization point observes the same typed outcome.
fn start_terminal_close_completion(
  commands: Subject(Command),
  deadline_milliseconds: Int,
  reply: Subject(Result(CloseResult, Error)),
) -> Nil {
  case
    start_client_close_completion(
      CloseResources(AlreadyClosed, None, None, None),
      process.self(),
      deadline_milliseconds,
      reply,
    )
  {
    Ok(completion) ->
      forward_queued_close_waiters(
        commands,
        completion,
        0,
        maximum_close_waiters * 2,
      )
    // The first completion actor still owns and answers `reply`; bootstrap can fail only at the deadline.
    // Reject a bounded queued prefix explicitly so those callers do not depend on an actor which is about to exit.
    Error(Nil) ->
      reject_queued_terminal_close_waiters(commands, maximum_close_waiters * 2)
  }
}

fn reject_queued_terminal_close_waiters(
  commands: Subject(Command),
  remaining_scan: Int,
) -> Nil {
  case remaining_scan <= 0 {
    True -> Nil
    False ->
      case process.receive(commands, within: 0) {
        Error(Nil) -> Nil
        Ok(Close(_, _, reply)) -> {
          process.send(reply, Error(OperationTimeout))
          reject_queued_terminal_close_waiters(commands, remaining_scan - 1)
        }
        Ok(command) -> {
          reject_terminal_command(command, ConnectionClosed)
          reject_queued_terminal_close_waiters(commands, remaining_scan - 1)
        }
      }
  }
}

fn reject_terminal_command(command: Command, error: Error) -> Nil {
  case command {
    Open(_, reply, _) -> process.send(reply, Error(error))
    Accept(reply, _) -> process.send(reply, Error(error))
    Send(_, _, _, reply, _) -> process.send(reply, Error(error))
    Receive(_, _, reply, _) -> process.send(reply, Error(error))
    ResetStream(_, _, reply) -> process.send(reply, Error(error))
    StopSending(_, _, reply) -> process.send(reply, Error(error))
    SendDatagram(_, reply) -> process.send(reply, Error(error))
    ReceiveDatagram(reply, _) -> process.send(reply, Error(error))
    MaximumDatagram(reply) -> process.send(reply, Error(error))
    GuaranteedDatagram(reply) -> process.send(reply, Error(error))
    PathMtu(reply) -> process.send(reply, Error(error))
    PathValidation(reply) -> process.send(reply, Error(error))
    Migrate(reply, _) -> process.send(reply, Error(error))
    Ping(reply) -> process.send(reply, Error(error))
    SetCongestion(_, reply) -> process.send(reply, Error(error))
    SendFinished(_, reply) -> process.send(reply, Error(error))
    AwaitSendCompletion(_, _, observation, _) -> {
      let _published = send_observation.publish(observation, Error(error))
      Nil
    }
    CancelSendCompletion(_, _) -> Nil
    PathStats(reply) -> process.send(reply, Error(error))
    ConnectionStats(reply) -> process.send(reply, Error(error))
    LocalConnectionIdStats(reply) -> process.send(reply, Error(error))
    ResourceStats(reply) -> process.send(reply, Error(error))
    DevelopmentState(reply) -> process.send(reply, Error(error))
    TelemetryStats(reply) -> process.send(reply, Error(error))
    ApplicationDiagnostics(reply) -> process.send(reply, Error(error))
    Phase(reply) -> process.send(reply, Error(error))
    EarlyData(reply) -> process.send(reply, Error(error))
    Resumption(reply) -> process.send(reply, Error(error))
    Handshake(reply) -> process.send(reply, Error(error))
    Ticket(reply, _) -> process.send(reply, Error(error))
    Protocol(reply) -> process.send(reply, Error(error))
    Close(_, deadline_milliseconds, reply) -> {
      let _completion =
        start_client_close_completion(
          CloseResources(AlreadyClosed, None, None, None),
          process.self(),
          deadline_milliseconds,
          reply,
        )
      Nil
    }
  }
}

fn open_qlog(
  directory: String,
  telemetry_limit: Int,
  reservation: Option(qlog_admission.Reservation),
) -> #(Result(Option(qlog.Writer), Error), Option(qlog.CleanupTicket)) {
  case reservation {
    None -> #(Ok(None), None)
    Some(reservation) ->
      case qlog_admission.begin_open(reservation) {
        Error(Nil) -> #(Error(QlogUnavailable), None)
        Ok(Nil) -> open_started_qlog(directory, telemetry_limit)
      }
  }
}

fn open_started_qlog(
  directory: String,
  telemetry_limit: Int,
) -> #(Result(Option(qlog.Writer), Error), Option(qlog.CleanupTicket)) {
  case directory {
    "" -> #(Ok(None), None)
    value -> {
      let #(opened, cleanup) =
        qlog.open_accounted(
          value,
          qlog.Client,
          udp.monotonic_millisecond(),
          telemetry_limit,
        )
      #(
        opened |> result.map(Some) |> result.replace_error(QlogUnavailable),
        Some(cleanup),
      )
    }
  }
}

/// Start one deadline-owned affine completion worker before the connection actor relinquishes its qlog receipts.
/// It survives caller death, confirms both diagnostics and the connection actor are down, and exits no later than the immutable deadline.
/// Pending native cleanup is handed to the existing finite admission reconciler before this worker exits.
fn start_client_close_completion(
  resources: CloseResources,
  connection_worker: Pid,
  deadline_milliseconds: Int,
  reply: Subject(Result(CloseResult, Error)),
) -> Result(ClientCloseCompletion, Nil) {
  let bootstrap = process.new_subject()
  let _completion_worker =
    process.spawn_unlinked(fn() {
      let waiters = process.new_subject()
      process.send(bootstrap, waiters)
      complete_client_close(
        resources,
        connection_worker,
        deadline_milliseconds,
        reply,
        waiters,
      )
    })
  let bootstrap_wait = case
    remaining_client_close_milliseconds(deadline_milliseconds)
  {
    Ok(remaining) -> int.min(remaining, worker_reply_grace_milliseconds)
    Error(_) -> 0
  }
  case process.receive(bootstrap, within: bootstrap_wait) {
    Ok(waiters) -> Ok(ClientCloseCompletion(waiters))
    Error(Nil) -> Error(Nil)
  }
}

fn await_client_close_completion(
  completion: ClientCloseCompletion,
  reply: Subject(Result(CloseResult, Error)),
) -> Nil {
  process.send(completion.waiters, AwaitCloseCompletion(reply))
  Nil
}

fn complete_client_close(
  resources: CloseResources,
  connection_worker: Pid,
  deadline_milliseconds: Int,
  reply: Subject(Result(CloseResult, Error)),
  waiters: Subject(CloseCompletionRequest),
) -> Nil {
  // Install this monitor before qlog can block so an early actor DOWN remains queued as proof rather than being inferred from an is_alive snapshot.
  let worker_monitor = process.monitor(connection_worker)
  let diagnostics =
    complete_qlog_close_until(
      resources.writer,
      resources.cleanup,
      deadline_milliseconds,
    )
  collect_qlog(resources.reservation, resources.cleanup)
  let reservation = case diagnostics {
    Ok(Nil) -> confirm_qlog_reservation(resources.reservation)
    Error(_) -> Ok(Nil)
  }
  let worker_down =
    await_close_worker_exit_until(
      connection_worker,
      worker_monitor,
      deadline_milliseconds,
    )
  process.demonitor_process(worker_monitor)
  let outcome =
    client_close_completion_result(
      resources.outcome,
      diagnostics,
      reservation,
      worker_down,
    )
  let replies =
    collect_close_completion_waiters(
      waiters,
      [reply],
      maximum_close_waiters - 1,
    )
  list.each(replies, fn(waiter) { process.send(waiter, outcome) })
}

fn collect_close_completion_waiters(
  waiters: Subject(CloseCompletionRequest),
  replies: List(Subject(Result(CloseResult, Error))),
  remaining_capacity: Int,
) -> List(Subject(Result(CloseResult, Error))) {
  case remaining_capacity <= 0 {
    True -> replies
    False ->
      case process.receive(waiters, within: 0) {
        Error(Nil) -> replies
        Ok(AwaitCloseCompletion(reply)) ->
          collect_close_completion_waiters(
            waiters,
            [reply, ..replies],
            remaining_capacity - 1,
          )
      }
  }
}

fn client_close_completion_result(
  outcome: CloseResult,
  diagnostics: Result(Nil, Error),
  reservation: Result(Nil, Error),
  worker_down: Result(Nil, Error),
) -> Result(CloseResult, Error) {
  // Preserve an observed diagnostic failure even when the same attempt also exhausts its actor-join window.
  // A writer timeout remains a typed operation timeout rather than being relabelled as filesystem failure.
  case diagnostics, reservation, worker_down {
    Error(QlogUnavailable), _, _ | _, Error(QlogUnavailable), _ ->
      Error(QlogUnavailable)
    Error(error), _, _ | _, Error(error), _ | _, _, Error(error) -> Error(error)
    Ok(Nil), Ok(Nil), Ok(Nil) -> Ok(outcome)
  }
}

fn confirm_qlog_reservation(
  reservation: Option(qlog_admission.Reservation),
) -> Result(Nil, Error) {
  case reservation {
    None -> Ok(Nil)
    Some(reservation) ->
      case qlog_admission.reservation_returned(reservation) {
        True -> Ok(Nil)
        False -> Error(QlogUnavailable)
      }
  }
}

fn await_close_worker_exit_until(
  worker: Pid,
  worker_monitor: process.Monitor,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(worker_monitor, fn(_) {
      CloseWorkerExited
    })
  let current = udp.monotonic_millisecond()
  let force_at_milliseconds = case
    client_close_deadline.force_join_at(
      current,
      deadline_milliseconds,
      close_force_join_milliseconds,
    )
  {
    Ok(value) -> value
    // The public/internally bounded constructors already reject this state.
    // If corruption reaches cleanup, force immediately and converge through the typed timeout path instead of panicking or extending the deadline.
    Error(_) -> current
  }
  case await_close_worker_down(selector, force_at_milliseconds) {
    Ok(Nil) -> Ok(Nil)
    Error(_) -> {
      // `kill` is asynchronous, so keep the monitor and consume only the already-reserved final slice.
      // Success is impossible until DOWN is observed; at the deadline the completion remains a typed timeout.
      process.kill(worker)
      await_close_worker_down(selector, deadline_milliseconds)
    }
  }
}

fn await_close_worker_down(
  selector: process.Selector(CloseWorkerJoinMessage),
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  let remaining =
    int.max(0, deadline_milliseconds - udp.monotonic_millisecond())
  let outcome = process.selector_receive(selector, within: remaining)
  case outcome, udp.monotonic_millisecond() < deadline_milliseconds {
    Ok(CloseWorkerExited), True -> Ok(Nil)
    Ok(CloseWorkerExited), False | Error(Nil), _ -> Error(OperationTimeout)
  }
}

/// Remove all affine diagnostics receipts from the connection actor in one state transition.
/// Only the deadline-owned completion worker receives them.
fn take_qlog_close(worker: Worker) -> #(Worker, CloseResources) {
  case worker.qlog_writer {
    Some(writer) -> qlog.connection_closed(writer, udp.monotonic_millisecond())
    None -> Nil
  }
  #(
    // Transfer all three affine receipts together.
    // A later idempotent close must never be able to collect the same admission reservation again,
    // including when the first caller reports a writer or cleanup failure.
    Worker(
      ..worker,
      qlog_writer: None,
      qlog_cleanup: None,
      qlog_reservation: None,
    ),
    CloseResources(
      Closed,
      worker.qlog_writer,
      worker.qlog_cleanup,
      worker.qlog_reservation,
    ),
  )
}

fn complete_qlog_close_until(
  writer: Option(qlog.Writer),
  cleanup: Option(qlog.CleanupTicket),
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  let writer_outcome = close_qlog_writer_until(writer, deadline_milliseconds)
  let cleanup_outcome = await_qlog_cleanup_until(cleanup, deadline_milliseconds)
  case writer_outcome, cleanup_outcome {
    Error(QlogUnavailable), _ | _, Error(QlogUnavailable) ->
      Error(QlogUnavailable)
    Error(error), _ | _, Error(error) -> Error(error)
    Ok(Nil), Ok(Nil) -> Ok(Nil)
  }
}

fn close_qlog_writer_until(
  writer: Option(qlog.Writer),
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  case writer {
    None -> Ok(Nil)
    Some(writer) -> {
      use _ <- result.try(remaining_client_close_milliseconds(
        deadline_milliseconds,
      ))
      case qlog.close_confirmed_until(writer, deadline_milliseconds) {
        Ok(Nil) ->
          remaining_client_close_milliseconds(deadline_milliseconds)
          |> result.map(fn(_) { Nil })
        Error(qlog.WriteFailed(6)) -> Error(OperationTimeout)
        Error(_) -> Error(QlogUnavailable)
      }
    }
  }
}

fn await_qlog_cleanup_until(
  cleanup: Option(qlog.CleanupTicket),
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  use _ <- result.try(remaining_client_close_milliseconds(deadline_milliseconds))
  case cleanup {
    None -> Ok(Nil)
    Some(ticket) -> {
      let owners = qlog.cleanup_owners(ticket)
      let #(selector, monitors) = monitor_qlog_cleanup_owners(owners)
      let outcome =
        await_qlog_cleanup_owners(selector, ticket, deadline_milliseconds)
      list.each(monitors, fn(monitor) { process.demonitor_process(monitor) })
      outcome
    }
  }
}

fn monitor_qlog_cleanup_owners(
  owners: List(Pid),
) -> #(process.Selector(CleanupJoinMessage), List(process.Monitor)) {
  list.fold(owners, #(process.new_selector(), []), fn(state, owner) {
    let #(selector, monitors) = state
    let monitor = process.monitor(owner)
    #(
      process.select_specific_monitor(selector, monitor, fn(_) {
        CleanupOwnerExited(owner)
      }),
      [monitor, ..monitors],
    )
  })
}

fn await_qlog_cleanup_owners(
  selector: process.Selector(CleanupJoinMessage),
  ticket: qlog.CleanupTicket,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  use remaining <- result.try(remaining_client_close_milliseconds(
    deadline_milliseconds,
  ))
  case qlog.cleanup_state(ticket) {
    qlog.Released -> Ok(Nil)
    qlog.Pending -> {
      let owner_can_still_finish =
        qlog.cleanup_owners(ticket) |> list.any(process.is_alive)
      case owner_can_still_finish {
        False -> Error(QlogUnavailable)
        True ->
          case process.selector_receive(selector, within: remaining) {
            Ok(CleanupOwnerExited(_)) ->
              await_qlog_cleanup_owners(selector, ticket, deadline_milliseconds)
            Error(Nil) -> Error(OperationTimeout)
          }
      }
    }
  }
}

fn validate_client_close_deadline(
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    client_close_deadline.validate(
      udp.monotonic_millisecond(),
      deadline_milliseconds,
    )
  {
    Ok(Nil) -> Ok(Nil)
    Error(client_close_deadline.DeadlineExpired) -> Error(OperationTimeout)
    Error(client_close_deadline.InvalidConfiguration)
    | Error(client_close_deadline.DeadlineOutOfRange) -> Error(InvalidInput)
  }
}

fn remaining_client_close_milliseconds(
  deadline_milliseconds: Int,
) -> Result(Int, Error) {
  case
    client_close_deadline.remaining(
      udp.monotonic_millisecond(),
      deadline_milliseconds,
    )
  {
    Ok(remaining) -> Ok(remaining)
    Error(client_close_deadline.DeadlineExpired) -> Error(OperationTimeout)
    Error(client_close_deadline.InvalidConfiguration)
    | Error(client_close_deadline.DeadlineOutOfRange) -> Error(InvalidInput)
  }
}

fn collect_qlog(
  reservation: Option(qlog_admission.Reservation),
  cleanup: Option(qlog.CleanupTicket),
) -> Nil {
  case reservation, cleanup {
    Some(reservation), Some(cleanup) ->
      qlog_admission.collect(reservation, cleanup)
    _, _ -> Nil
  }
}

fn close_qlog(writer: Option(qlog.Writer)) -> Nil {
  case writer {
    Some(value) -> {
      qlog.connection_closed(value, udp.monotonic_millisecond())
      let _ = qlog.close(value)
      Nil
    }
    None -> Nil
  }
}

fn record_qlog_io(
  writer: Option(qlog.Writer),
  before: runtime_connection.Stats,
  after: runtime_connection.Stats,
  connection: client_transport.State,
) -> Nil {
  case writer {
    None -> Nil
    Some(writer) -> {
      let runtime_connection.Stats(
        before_received,
        before_sent,
        _,
        _,
        _,
        _,
        _,
        _,
      ) = before
      let runtime_connection.Stats(after_received, after_sent, _, _, _, _, _, _) =
        after
      let now = udp.monotonic_millisecond()
      let received = after_received - before_received
      let sent = after_sent - before_sent
      qlog.datagrams_received(writer, now, received)
      qlog.datagrams_sent(writer, now, sent)
      case received > 0 {
        True -> qlog.packet_received(writer, now, 8, 0)
        False -> Nil
      }
      case sent > 0 {
        True -> qlog.packet_sent(writer, now, 8, 0)
        False -> Nil
      }
      case received > 0 || sent > 0 {
        True -> record_qlog_recovery(writer, connection, now)
        False -> Nil
      }
    }
  }
}

fn record_qlog_bootstrap(
  writer: qlog.Writer,
  connection: client_transport.State,
  now: Int,
) -> Nil {
  qlog.connection_started(writer, now)
  qlog.key_updated(writer, now, 8)
  qlog.key_updated(writer, now, 7)
  qlog.key_discarded(writer, now, 4)
  qlog.key_discarded(writer, now, 3)
  record_qlog_recovery(writer, connection, now)
}

fn record_qlog_recovery(
  writer: qlog.Writer,
  connection: client_transport.State,
  now: Int,
) -> Nil {
  let transport.PathSnapshot(_, _, _, _, window, flight, recovering, congested) =
    client_transport.path_stats(connection)
  qlog.recovery_metrics(writer, now, window, flight)
  qlog.congestion_state_updated(
    writer,
    now,
    case recovering, flight, congested {
      True, _, _ -> 3
      False, 0, _ -> 4
      False, _, True -> 2
      False, _, False -> 1
    },
  )
}

fn record_qlog_migration_abandoned(writer: Option(qlog.Writer)) -> Nil {
  case writer {
    Some(writer) ->
      qlog.migration_abandoned(writer, udp.monotonic_millisecond())
    None -> Nil
  }
}

fn update_connection_reply(
  worker: Worker,
  reply: Subject(Result(Nil, Error)),
  outcome: Result(client_transport.State, client_transport.Error),
) -> Result(Worker, Nil) {
  case outcome {
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(Worker(..worker, connection: connection))
    }
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
  }
}

fn reply_with(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  outcome: Result(value, client_transport.Error),
) -> Result(Worker, Nil) {
  process.send(reply, result.map_error(outcome, map_transport_error))
  Ok(worker)
}

fn reply_error(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
}

fn put_stream(worker: Worker, identifier: Int, stream: StreamState) -> Worker {
  let streams = case stream_runtime_terminal(stream) {
    True -> dict.delete(worker.streams, identifier)
    False -> dict.insert(worker.streams, identifier, stream)
  }
  Worker(..worker, streams: streams)
}

/// The actor wrapper owns only live waiters and application-facing direction state.
/// The transport independently retains retransmission state until FIN acknowledgement, so a fully consumed wrapper can be forgotten immediately.
fn stream_runtime_terminal(stream: StreamState) -> Bool {
  stream.send_finished
  && stream.receive_finished
  && option.is_none(stream.read_waiter)
  && option.is_none(stream.pending_send)
}

fn new_stream_state(identifier: Int) -> StreamState {
  let #(send_finished, receive_finished) =
    stream_lifetime.initial_terminal_directions(stream_id.Client, identifier)
  StreamState(None, None, send_finished, receive_finished)
}

fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

fn queue_count(queue: Queue(value)) -> Int {
  queue.count
}

fn queue_push(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, back: [value, ..queue.back], count: queue.count + 1)
}

fn queue_prepend(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, front: [value, ..queue.front], count: queue.count + 1)
}

fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

/// Split off `count` bytes, or return everything when that many are not there.
///
/// The split is a pattern rather than a measured slice: a payload shorter than `count`, and a negative `count`, simply have no matching clause, so both become the fallback instead of a comparison guarding two slices that must not fail.
fn take_bytes(bytes: BitArray, count: Int) -> #(BitArray, BitArray) {
  case bytes {
    <<chunk:bytes-size(count), rest:bits>> -> #(chunk, rest)
    _ -> #(bytes, <<>>)
  }
}

fn positive_deadline(deadline: Int) -> Option(Int) {
  case deadline > 0 {
    True -> Some(deadline)
    False -> None
  }
}

fn earlier_deadline(first: Option(Int), second: Option(Int)) -> Option(Int) {
  case first, second {
    None, value | value, None -> value
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn accept_deadline(waiter: Option(AcceptWaiter)) -> Option(Int) {
  case waiter {
    Some(AcceptWaiter(_, deadline)) -> deadline
    None -> None
  }
}

fn pending_open_deadline(queue: Queue(PendingOpen)) -> Option(Int) {
  case queue_pop(queue) {
    Ok(#(PendingOpen(_, _, deadline), _)) -> Some(deadline)
    Error(Nil) -> None
  }
}

fn fail_pending_opens(queue: Queue(PendingOpen), error: Error) -> Nil {
  case queue_pop(queue) {
    Error(Nil) -> Nil
    Ok(#(PendingOpen(_, reply, _), rest)) -> {
      process.send(reply, Error(error))
      fail_pending_opens(rest, error)
    }
  }
}

fn datagram_deadline(waiter: Option(DatagramWaiter)) -> Option(Int) {
  case waiter {
    Some(DatagramWaiter(_, deadline)) -> deadline
    None -> None
  }
}

fn migration_deadline(waiter: Option(MigrationWaiter)) -> Option(Int) {
  case waiter {
    Some(MigrationWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn ticket_deadline(waiter: Option(TicketWaiter)) -> Option(Int) {
  case waiter {
    Some(TicketWaiter(_, deadline, token_deadline)) ->
      earlier_deadline(deadline, token_deadline)
    None -> None
  }
}

fn read_deadline(waiter: Option(ReadWaiter)) -> Option(Int) {
  case waiter {
    Some(ReadWaiter(_, _, deadline)) -> deadline
    None -> None
  }
}

fn send_deadline(send: Option(PendingSend)) -> Option(Int) {
  case send {
    Some(PendingSend(_, _, _, deadline)) -> Some(deadline)
    None -> None
  }
}

fn await_bootstrap(
  worker: Pid,
  bootstrap: Subject(Result(Connection, Error)),
  group: udp.WorkGroup,
  deadline: Int,
) -> Result(Connection, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(bootstrap, fn(reply) { CallReply(reply) })
    |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
    |> process.selector_receive(within: int.max(
      0,
      deadline - udp.monotonic_millisecond(),
    ))
  process.demonitor_process(monitor)
  case outcome {
    Ok(CallReply(Ok(connection))) -> {
      case udp.monotonic_millisecond() < deadline {
        True -> {
          case udp.publish_work_group(group, worker, deadline) {
            Ok(Nil) -> Ok(connection)
            Error(udp.Timeout) -> Error(TotalTimeout)
            Error(_) -> {
              let _ = udp.stop_work_group(group)
              Error(ConnectionClosed)
            }
          }
        }
        False -> {
          let _ = udp.stop_work_group(group)
          Error(TotalTimeout)
        }
      }
    }
    Ok(CallReply(Error(error))) -> {
      let _ = udp.stop_work_group(group)
      Error(error)
    }
    Ok(WorkerExited) -> {
      let _ = udp.stop_work_group(group)
      Error(ConnectionClosed)
    }
    Error(Nil) -> {
      let _ = udp.stop_work_group(group)
      Error(TotalTimeout)
    }
  }
}

fn call(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  case process.is_alive(connection.worker) {
    False -> Error(ConnectionClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(connection.worker)
      process.send(connection.commands, make_command(reply))
      let outcome =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
        |> process.selector_receive(
          within: connection.timeout_milliseconds
          + worker_reply_grace_milliseconds,
        )
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(result)) -> result
        Ok(WorkerExited) -> Error(ConnectionClosed)
        Error(Nil) -> Error(OperationTimeout)
      }
    }
  }
}

fn call_close_until(
  connection: Connection,
  application_error_code: Int,
  deadline_milliseconds: Int,
) -> Result(CloseResult, Error) {
  use _ <- result.try(remaining_client_close_milliseconds(deadline_milliseconds))
  case process.is_alive(connection.worker) {
    False -> Error(ConnectionClosed)
    True -> {
      let reply = process.new_subject()
      process.send(
        connection.commands,
        Close(application_error_code, deadline_milliseconds, reply),
      )
      case remaining_client_close_milliseconds(deadline_milliseconds) {
        Error(error) -> Error(error)
        Ok(remaining) -> {
          let outcome = process.receive(reply, within: remaining)
          case remaining_client_close_milliseconds(deadline_milliseconds) {
            Error(error) -> Error(error)
            Ok(_) ->
              case outcome {
                Ok(result) -> result
                Error(Nil) -> Error(OperationTimeout)
              }
          }
        }
      }
    }
  }
}

fn call_forever(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  case process.is_alive(connection.worker) {
    False -> Error(ConnectionClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(connection.worker)
      process.send(connection.commands, make_command(reply))
      let outcome =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
        |> process.selector_receive_forever
      process.demonitor_process(monitor)
      case outcome {
        CallReply(result) -> result
        WorkerExited -> Error(ConnectionClosed)
      }
    }
  }
}

fn map_transport_error(error: client_transport.Error) -> Error {
  case error {
    client_transport.InvalidInput -> InvalidInput
    client_transport.ResolutionFailed -> ResolutionFailed
    client_transport.SocketUnavailable -> SocketUnavailable
    client_transport.DnsTimeout -> DnsTimeout
    client_transport.ConnectTimeout -> ConnectTimeout
    client_transport.HandshakeTimeout -> HandshakeTimeout
    client_transport.TotalTimeout -> TotalTimeout
    client_transport.TlsHandshakeFailed -> TlsHandshakeFailed
    client_transport.PeerClosed(None) -> ConnectionClosed
    client_transport.PeerClosed(Some(code)) -> PeerClosedWithCode(code)
    client_transport.PeerTransportClosed(code) ->
      PeerTransportFailureWithCode(code)
    client_transport.MigrationUnavailable -> MigrationUnavailable
    client_transport.LocalConnectionIdUnavailable -> QuicFailure
    client_transport.OwnerGone -> ConnectionClosed
    client_transport.VersionNegotiationReceived(_)
    | client_transport.VersionNegotiationFailed -> VersionNegotiationFailed
    client_transport.QuicFailure(error) -> map_driver_error(error)
  }
}

fn map_driver_error(error: driver.Error) -> Error {
  case error {
    driver.ConnectionFailure(transport.CongestionLimited)
    | driver.ConnectionFailure(transport.PacingLimited(_))
    | driver.ConnectionFailure(transport.RecoveryLimited) -> CongestionLimited
    driver.ConnectionFailure(transport.DatagramNotNegotiated) ->
      DatagramsNotNegotiated
    driver.ConnectionFailure(transport.DatagramTooLarge(maximum)) ->
      DatagramTooLarge(maximum)
    driver.ConnectionFailure(transport.UnknownStream(_)) -> StreamClosed
    driver.ConnectionFailure(transport.ConnectionUnavailable) ->
      ConnectionClosed
    _ -> QuicFailure
  }
}
