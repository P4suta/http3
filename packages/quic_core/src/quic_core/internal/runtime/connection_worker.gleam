//// One supervised actor per accepted generic QUIC connection.
////
//// The listener actor (`server_worker`) keeps the UDP relay, connection-ID routing, admission, and the accept queue.
//// Everything about one accepted connection lives here instead, in its own process: the `server_transport.State`, its streams and waiters, its qlog writer, and its own keepalive and PMTU deadlines.
//// Protocol work for one connection can therefore never delay another connection on the same listener.
////
//// Sends go straight to the listener-owned socket with `udp.send`, which any process may call, so an outbound datagram never needs a listener hop.
////
//// The actor's life ends with its transport.
//// Once the phase reaches `Closed` -- a local close finished draining, the idle timeout expired, or the peer vanished and the idle timeout expired for it -- the transport arms no further deadline and owes no further output.
//// `shutdown` runs then: the every waiter still parked on it is failed with the typed closed error (`ConnectionClosed`, so its owner reads a closed connection rather than a protocol failure), the qlog writer is flushed, and only then the listener is told the connection is `Released`.
//// Thus removal from the listener is a completion barrier for diagnostics as well as admission state.
//// The loop then returns so the process exits normally.
//// A connection that fails ends the same way, with the failure as the waiters' error.
//// The listener frees the connection ID, its aliases, and the admission slot on that notice or on the monitor `Down`, whichever it sees first.
////
//// Every wait in the loop is bounded, so no phase can strand the process even if no timer announces it: `next_worker_deadline` always yields a deadline,
//// falling back to `maximum_park_milliseconds` when neither the transport nor a waiter arms one.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core/internal/address_token
import quic_core/internal/connection_state as transport
import quic_core/internal/crypto
import quic_core/internal/driver
import quic_core/internal/ecn
import quic_core/internal/local_connection_id
import quic_core/internal/packet_space
import quic_core/internal/process_label
import quic_core/internal/qlog
import quic_core/internal/runtime/budget
import quic_core/internal/runtime/connection as runtime_connection
import quic_core/internal/runtime/connection_worker_diagnostic_code as diagnostic_code
import quic_core/internal/runtime/path_gate
import quic_core/internal/runtime/qlog_packet_type
import quic_core/internal/runtime/send_observation.{type Observation}
import quic_core/internal/runtime/server_transport
import quic_core/internal/runtime/stream_lifetime
import quic_core/internal/runtime/terminal_close
import quic_core/internal/stream_completion
import quic_core/internal/stream_state
import quic_core/internal/tls/anti_replay
import quic_core/internal/tls/authentication
import quic_core/internal/tls/hello
import quic_core/internal/tls/replay_guard

const maximum_completion_feed_waiters = 16

import quic_core/internal/tls/resumption
import quic_core/internal/udp
import quic_core/stream_id
import quic_core/version.{type Version}

const maximum_packets_per_flush = 64

// Pre-validation floor for one packet's frame payload.
// The send path widens it to whatever DPLPMTUD has validated for the current path.
const maximum_frame_data_bytes = 1000

const maximum_send_chunk_bytes = 65_536

const pmtu_probe_interval_milliseconds = 50

const ticket_age_tolerance_milliseconds = 10_000

const worker_reply_grace_milliseconds = 100

const maximum_milliseconds = 9_223_372_036_854_775_807

// One admitted waiter retains a one-row ETS observation, alias/reference,
// monitor and selector closure.
// Eight KiB covers those bounded objects with allocator headroom; the grant is checked before the actor creates a monitor.
const completion_waiter_bytes = 8192

// The longest this actor parks when neither the transport nor any waiter arms a deadline of its own.
// The loop then still re-examines its phase this often,
// which is what gives every wait here a fixed upper bound.
const maximum_park_milliseconds = 1000

// A test-only connection barrier is also self-releasing.
// Its owner and gate are monitored, while this absolute ceiling prevents an incorrectly formed test command from parking a production actor indefinitely.
const diagnostic_barrier_milliseconds = 8000

/// One accepted generic QUIC connection, addressed by its own actor.
pub opaque type Connection {
  Connection(
    commands: Subject(Command),
    worker: Pid,
    timeout_milliseconds: Int,
    terminal_close: terminal_close.TerminalClose,
  )
}

/// One stream routed through its owning connection actor.
pub opaque type Stream {
  Stream(connection: Connection, identifier: Int)
}

/// One peer-initiated stream and its directionality.
pub type IncomingStream {
  IncomingStream(stream: Stream, bidirectional: Bool)
}

/// One bounded pull from a stream receive direction.
pub type Read {
  Data(bytes: BitArray, finished: Bool)
  Finished
  Reset(application_error_code: Int)
}

/// One finite causally ordered batch from the connection completion ring.
pub type CompletionBatch {
  CompletionBatch(cursor: Int, events: List(stream_completion.Event))
}

/// Test-only snapshot of one connection's endpoint-memory accounting.
///
/// This lives in the internal actor module so admission tests can establish a race-free pressure barrier without exposing grants through `quic_core`.
/// Every field is a finite counter or state bit; no payload or native handle is retained.
pub type MemoryGrantSnapshot {
  MemoryGrantSnapshot(
    buffered_send_bytes: Int,
    retained_bytes: Int,
    unmeasured_bytes: Int,
    granted_bytes: Int,
    refused: Bool,
    advertised_max_data: Int,
    outstanding_receive_credit: Int,
    credit_growth_held: Bool,
    active_streams: Int,
    stream_identifiers: List(Int),
    incoming_stream_identifiers: List(Int),
    transport_progress: transport.SendProgress,
    pending_sends: List(SendDeadlineSnapshot),
    last_send_deadline: Option(SendDeadlineSnapshot),
  )
}

/// Payload-free send provenance, retained for at most the live stream set and one most recent expiry.
/// It distinguishes an actor's resource refusal from a caller whose bounded reply wait elapsed before the actor could answer.
pub type SendDeadlineSnapshot {
  SendDeadlineSnapshot(
    stream_identifier: Int,
    deadline_milliseconds: Int,
    observed_at_milliseconds: Int,
    remaining_bytes: Int,
    held_by_grant: Bool,
  )
}

/// Idempotent connection close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Listener, connection, stream, pressure, or protocol failure.
pub type Error {
  InvalidInput
  StartFailed
  OperationTimeout
  ListenerClosed
  ConnectionClosed
  PeerClosedWithCode(Int)
  PeerTransportFailureWithCode(Int)
  StreamClosed
  InvalidDirection
  ConcurrentSend
  ConcurrentReceive
  ConcurrentAccept
  ConcurrentDatagramReceive
  ConnectionLimitExceeded(Int)
  HandshakeLimitExceeded(Int)
  AcceptQueueExceeded(Int)
  IncomingStreamQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  DatagramTooLarge(Int)
  DatagramsNotNegotiated
  CongestionLimited
  EndpointMemoryExceeded
  QlogUnavailable
  QuicFailure
  TransportFailureWithCode(Int)
  CompletionHistoryExceeded(oldest_available_cursor: Int)
  StreamQueueFailure(stream_state.Error)
}

/// A message the listener sends to a connection actor it owns.
pub type ListenerToConnection {
  /// One inbound datagram the listener routed to this connection.
  RoutedDatagram(
    peer: udp.Endpoint,
    datagram: BitArray,
    marking: packet_space.ReceivedCodepoint,
  )
}

/// A message a connection actor sends back to its listener.
pub type ConnectionToListener {
  /// The handshake completed, so this connection can be accepted.
  Established(identifier: BitArray)
  /// Request bounded routes after handshake; the listener installs them before replying.
  AllocateConnectionIds(identifier: BitArray, worker: Pid, count: Int)
  /// One authenticated peer retirement releases exactly this wire route.
  RetiredConnectionId(
    identifier: BitArray,
    worker: Pid,
    retired: BitArray,
    replace: Bool,
  )
  /// One delivered batch was consumed, so the listener may refill this connection's delivery credit by exactly what the actor took off its mailbox.
  /// Without it the window never reopens and delivery stalls.
  Consumed(identifier: BitArray, datagrams: Int, bytes: Int)
  /// This connection asks to hold `quanta` whole quanta.
  /// Sent before the room is used, not after, and only when what the connection holds comes within one growth step of its grant -- never per packet -- so the endpoint funds growth in advance without per-packet chatter reaching the listener.
  /// The sequence number is echoed in the answer, so a connection applies only the answer to its newest outstanding request.
  Request(identifier: BitArray, sequence: Int, quanta: Int)
  /// The connection ended, so the listener owns its identifiers again.
  /// The actor sends this immediately before it exits.
  /// An autonomous or peer-led close waits for the listener's acknowledgement, so its observed exit is also a release barrier.
  /// Listener-led teardown uses the monitor `Down` path as its idempotent fallback rather than waiting on itself.
  Released(identifier: BitArray, worker: Pid, acknowledged: Subject(Nil))
}

/// Everything one connection actor owns from the moment it is spawned.
pub type Bootstrap {
  Bootstrap(
    listener: Pid,
    notices: Subject(ConnectionToListener),
    socket: udp.Socket,
    identifier: BitArray,
    state: server_transport.State,
    protocol_version: Version,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    application_protocols: List(BitArray),
    ticket_keys: List(BitArray),
    address_token_key: BitArray,
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    now: Int,
    initial_datagram_bytes: Int,
  )
}

type Command {
  RegisteredConnectionIds(values: List(#(BitArray, BitArray)))
  /// One credited batch from the listener, plus the datagrams it had to drop for this connection since the last batch.
  /// An empty batch carries only that drop count.
  Deliver(deliveries: List(ListenerToConnection), dropped: Int)
  ReloadedKeys(ticket_keys: List(BitArray), address_token_key: BitArray)
  /// The listener met request `sequence` in full: this connection may hold `quanta` whole quanta.
  Granted(sequence: Int, quanta: Int)
  /// The listener could not meet request `sequence`: `quanta` is what it could actually cover, and the shortfall holds this connection where it is until the listener retries the request from memory another connection released.
  Refused(sequence: Int, quanta: Int)
  /// Test-only causal barrier.
  /// Receipt proves that every earlier actor turn,
  /// including its synchronous qlog admissions, has completed.
  /// The actor resumes when either the owner or the independently supervised gate exits.
  DiagnosticPause(
    owner: Pid,
    gate: Pid,
    entered: Subject(Nil),
    resumed: Subject(Nil),
  )
  Terminate
  TerminateAndWait(
    deadline_milliseconds: Int,
    reply: Subject(Result(Nil, Error)),
  )
  Open(direction: stream_id.Direction, reply: Subject(Result(Int, Error)))
  AcceptStream(
    reply: Subject(Result(IncomingStream, Error)),
    deadline: Option(Int),
  )
  Send(
    stream_id: Int,
    bytes: BitArray,
    finish: Bool,
    observation: Observation(Result(Nil, Error)),
    deadline: Int,
  )
  Receive(
    stream_id: Int,
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Option(Int),
  )
  ResetStream(stream_id: Int, code: Int, reply: Subject(Result(Nil, Error)))
  StopSending(stream_id: Int, code: Int, reply: Subject(Result(Nil, Error)))
  SendDatagram(payload: BitArray, reply: Subject(Result(Nil, Error)))
  ReceiveDatagram(
    reply: Subject(Result(BitArray, Error)),
    deadline: Option(Int),
  )
  MaximumDatagram(reply: Subject(Result(Int, Error)))
  GuaranteedDatagram(reply: Subject(Result(Int, Error)))
  Ping(reply: Subject(Result(Nil, Error)))
  SetCongestion(
    algorithm: transport.CongestionAlgorithm,
    reply: Subject(Result(Nil, Error)),
  )
  PeerEndpoint(reply: Subject(Result(#(BitArray, Int), Error)))
  PathMtu(reply: Subject(Result(Int, Error)))
  PathStats(reply: Subject(Result(transport.PathSnapshot, Error)))
  ConnectionStats(
    reply: Subject(Result(#(runtime_connection.Stats, Int), Error)),
  )
  ResourceStats(reply: Subject(Result(#(Int, Int), Error)))
  LocalConnectionIdStats(
    reply: Subject(Result(local_connection_id.Snapshot, Error)),
  )
  TelemetryStats(reply: Subject(Result(qlog.Stats, Error)))
  ApplicationDiagnostics(reply: Subject(Result(Option(qlog.Writer), Error)))
  /// Report what this connection's send buffers hold against the endpoint memory grant that funded them, which no public API publishes.
  SendBufferGrant(reply: Subject(Result(#(Int, Int), Error)))
  MemoryGrantState(reply: Subject(Result(MemoryGrantSnapshot, Error)))
  CompletionCounts(reply: Subject(Result(#(Int, Int, Int), Error)))
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
  NextSendCompletions(
    after_cursor: Int,
    owner: Pid,
    observation: Observation(Result(CompletionBatch, Error)),
    deadline: Int,
  )
  CancelSendCompletions(
    observation: Observation(Result(CompletionBatch, Error)),
  )
  Phase(reply: Subject(Result(transport.Phase, Error)))
  ClientIdentity(reply: Subject(Result(Option(BitArray), Error)))
  Protocol(
    reply: Subject(
      Result(
        #(
          Version,
          BitArray,
          transport.CongestionAlgorithm,
          Option(hello.CipherSuite),
          Bool,
          Bool,
          Bool,
        ),
        Error,
      ),
    ),
  )
  CloseConnection(code: Int, reply: Subject(Result(CloseResult, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
  ListenerExited
  ReleaseAcknowledged
  CompletionCallerExited(stream_id: Int, monitor: process.Monitor)
  CompletionFeedCallerExited(
    observation: Observation(Result(CompletionBatch, Error)),
    monitor: process.Monitor,
  )
}

type DiagnosticBarrierOutcome {
  DiagnosticBarrierReleased
  DiagnosticBarrierOwnerExited
}

type Bootstrapped {
  Bootstrapped(Connection)
  BootstrapExited
}

/// Bounded first-in first-out backlog.
/// Both actors bound their waiter and backlog queues with it, so the listener imports it from here rather than keeping a second copy.
pub opaque type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
}

type StreamWaiter {
  StreamWaiter(
    reply: Subject(Result(IncomingStream, Error)),
    deadline: Option(Int),
  )
}

type ReadWaiter {
  ReadWaiter(
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Option(Int),
  )
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Option(Int))
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    finish: Bool,
    observation: Observation(Result(Nil, Error)),
    deadline: Int,
    /// Whether what this send is waiting on is the endpoint memory grant rather than the `Buffer` ceiling the application chose.
    ///
    /// Decision D5.
    /// The two are different answers to the caller: a send the `Buffer` ceiling holds is waiting on its own peer to acknowledge what is already buffered, while a send the grant holds was never going to be funded until the endpoint has room, whether or not a refusal has landed yet.
    /// It is recomputed on every advance and carried across a partial send: taking the funded prefix does not change what bounds the bytes still waiting, so it always names why this send is waiting now.
    held_by_grant: Bool,
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

type CompletionFeedWaiter {
  CompletionFeedWaiter(
    after_cursor: Int,
    owner: Pid,
    monitor: process.Monitor,
    observation: Observation(Result(CompletionBatch, Error)),
    deadline: Int,
  )
}

type StreamState {
  StreamState(
    read_waiter: Option(ReadWaiter),
    pending_send: Option(PendingSend),
    send_finished: Bool,
    receive_finished: Bool,
  )
}

type CandidatePath {
  CandidatePath(endpoint: udp.Endpoint, received_bytes: Int, sent_bytes: Int)
}

type PeerState {
  PeerState(
    connection: server_transport.State,
    streams: Dict(Int, StreamState),
    incoming: Queue(Int),
    stream_waiter: Option(StreamWaiter),
    datagrams: Queue(BitArray),
    datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    version: Version,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    token_endpoint: Option(udp.Endpoint),
    candidate_path: Option(CandidatePath),
    next_pmtu_probe_milliseconds: Int,
    last_send_deadline: Option(SendDeadlineSnapshot),
    active_destination_connection_id: BitArray,
    candidate_destination_connection_id: Option(BitArray),
    candidate_rotated_peer_id: Bool,
  )
}

type Worker {
  Worker(
    socket: udp.Socket,
    identifier: BitArray,
    notices: Subject(ConnectionToListener),
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    peer: PeerState,
    dropped_datagrams: Int,
    dirty: Bool,
    failure: Option(Error),
    terminal_close: terminal_close.TerminalClose,
    established_reported: Bool,
    application_protocols: List(BitArray),
    ticket_keys: List(BitArray),
    address_token_key: BitArray,
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    // The endpoint memory this connection holds, and the room its endpoint has granted it to hold.
    // A grant that fell short is the endpoint at its budget: this connection stops advertising more receive credit (D3),
    // drops Datagrams that would grow it further (D4), and ends a parked send as an overload (D5) rather than as a bare operation timeout.
    //
    // Measuring `retained_bytes` walks every stream and every sent-packet history in three packet spaces, so it is not done per turn.
    // It is done when something could have moved it by a whole ledger quantum, which is the resolution the ledger counts in anyway: `unmeasured_bytes` is an upper bound on how far the footprint can have moved since the last walk -- every byte delivered into this actor and every byte it has admitted into a send buffer -- and `remeasure` forces the walk on the turns where the grant itself changed.
    // A peer sending a flood of small datagrams therefore costs one walk per 16 KiB rather than one per datagram.
    retained_bytes: Int,
    unmeasured_bytes: Int,
    remeasure: Bool,
    grant: budget.Grant,
    completion_waiters: Dict(Int, CompletionWaiter),
    completion_feed_waiters: List(CompletionFeedWaiter),
    completions: stream_completion.History,
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Spawn and monitor-ready one connection actor for an admitted connection.
pub fn start(bootstrap: Bootstrap) -> Result(Connection, Error) {
  let ready = process.new_subject()
  let worker =
    process.spawn_unlinked(fn() {
      process_label.set(process_label.Connection)
      initialise(bootstrap, ready)
    })
  await_bootstrap(worker, ready, bootstrap.operation_timeout_milliseconds)
}

/// The connection actor process, so the listener can monitor it.
pub fn worker_pid(connection: Connection) -> Pid {
  connection.worker
}

/// The shared listener has already installed every supplied wire route.
pub fn registered_connection_ids(
  connection: Connection,
  values: List(#(BitArray, BitArray)),
) -> Nil {
  process.send(connection.commands, RegisteredConnectionIds(values))
}

/// Hand one credited batch of inbound datagrams to the owning connection,
/// together with the datagrams the listener had to drop for it since the last batch because its delivery window was full.
pub fn deliver(
  connection: Connection,
  deliveries: List(ListenerToConnection),
  dropped: Int,
) -> Nil {
  process.send(connection.commands, Deliver(deliveries, dropped))
}

/// Install rotated ticket and address-token keys on a live connection.
pub fn reload_keys(
  connection: Connection,
  ticket_keys: List(BitArray),
  address_token_key: BitArray,
) -> Nil {
  process.send(
    connection.commands,
    ReloadedKeys(ticket_keys, address_token_key),
  )
}

/// Tell one connection actor that its request was met in full.
///
/// Decision D2, connection side: the grant is asked for in advance, in whole quanta, and it arrives asynchronously, so the actor's hot path never waits on the listener.
pub fn grant(connection: Connection, sequence: Int, quanta: Int) -> Nil {
  process.send(connection.commands, Granted(sequence, quanta))
}

/// Tell one connection actor that its request could not be met, and how much of it the endpoint could cover.
pub fn refuse(connection: Connection, sequence: Int, quanta: Int) -> Nil {
  process.send(connection.commands, Refused(sequence, quanta))
}

/// Ask one connection actor to release its resources and exit.
pub fn terminate(connection: Connection) -> Nil {
  process.send(connection.commands, Terminate)
}

/// Release one actor under a caller-owned absolute deadline.
///
/// Listener shutdown gives every connection the same value so the total wait is bounded once, independent of connection count.
/// A reply arriving at or after the boundary is not accepted as completion evidence.
pub fn terminate_and_wait_until(
  connection: Connection,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  call_termination_until(connection, deadline_milliseconds)
}

pub fn open_bidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Bidirectional)
}

pub fn open_unidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Unidirectional)
}

fn open(
  connection: Connection,
  direction: stream_id.Direction,
) -> Result(Stream, Error) {
  call(connection, fn(reply) { Open(direction, reply) })
  |> result.map(fn(identifier) { Stream(connection, identifier) })
}

pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  call(connection, fn(reply) {
    AcceptStream(
      reply,
      Some(udp.monotonic_millisecond() + connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for one peer-initiated stream.
///
/// Connection close or actor failure still releases the caller.
/// This is for a supervised protocol adapter which continuously consumes stream events;
/// ordinary application calls should use `accept_stream`.
pub fn accept_stream_next(
  connection: Connection,
) -> Result(IncomingStream, Error) {
  call_forever(connection, fn(reply) { AcceptStream(reply, None) })
}

pub fn send(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, False)
}

pub fn finish(stream: Stream) -> Result(Nil, Error) {
  send_with_fin(stream, <<>>, True)
}

pub fn send_and_finish(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, True)
}

fn send_with_fin(
  stream: Stream,
  bytes: BitArray,
  finish: Bool,
) -> Result(Nil, Error) {
  let connection = stream.connection
  let deadline = udp.monotonic_millisecond() + connection.timeout_milliseconds
  let observation = send_observation.new()
  case send_observation.available(observation) {
    False -> Error(EndpointMemoryExceeded)
    True -> {
      process.send(
        connection.commands,
        Send(stream.identifier, bytes, finish, observation, deadline),
      )
      case
        send_observation.await(
          observation,
          connection.worker,
          int.max(
            0,
            deadline
              + worker_reply_grace_milliseconds
              - udp.monotonic_millisecond(),
          ),
        )
      {
        send_observation.Replied(result) -> result
        send_observation.DeadlineExpired(True) -> Error(EndpointMemoryExceeded)
        send_observation.DeadlineExpired(False) -> Error(OperationTimeout)
        send_observation.WorkerExited -> Error(closed_error(connection))
        send_observation.OwnerExited -> Error(closed_error(connection))
        send_observation.Unavailable -> Error(EndpointMemoryExceeded)
      }
    }
  }
}

pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  let connection = stream.connection
  call(connection, fn(reply) {
    Receive(
      stream.identifier,
      maximum_bytes,
      reply,
      Some(udp.monotonic_millisecond() + connection.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for bytes or a terminal stream event.
///
/// Connection close or actor failure still releases the caller.
/// This is for a supervised protocol adapter which owns a continuously running stream reader; ordinary application calls should use `receive`.
pub fn receive_next(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  call_forever(stream.connection, fn(reply) {
    Receive(stream.identifier, maximum_bytes, reply, None)
  })
}

pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    ResetStream(stream.identifier, application_error_code, reply)
  })
}

pub fn stop_sending(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    StopSending(stream.identifier, application_error_code, reply)
  })
}

pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SendDatagram(payload, reply) })
}

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

pub fn ping(connection: Connection) -> Result(Nil, Error) {
  call(connection, Ping)
}

pub fn set_congestion_control(
  connection: Connection,
  algorithm: transport.CongestionAlgorithm,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SetCongestion(algorithm, reply) })
}

/// Return the authenticated peer path as network-order address bytes and port.
pub fn peer_endpoint(
  connection: Connection,
) -> Result(#(BitArray, Int), Error) {
  call(connection, PeerEndpoint)
}

/// Return the current discovered maximum UDP payload size for the peer path.
pub fn path_mtu(connection: Connection) -> Result(Int, Error) {
  call(connection, PathMtu)
}

pub fn path_stats(
  connection: Connection,
) -> Result(transport.PathSnapshot, Error) {
  call(connection, PathStats)
}

/// Snapshot the runtime counters of one connection together with the number of inbound datagrams the listener dropped for it, so the public diagnostics path can publish both from one call.
pub fn connection_stats(
  connection: Connection,
) -> Result(#(runtime_connection.Stats, Int), Error) {
  call(connection, ConnectionStats)
}

/// Snapshot retained runtime handles and live transport streams.
pub fn resource_stats(connection: Connection) -> Result(#(Int, Int), Error) {
  call(connection, ResourceStats)
}

/// Snapshot issuer occupancy through the owning actor.
pub fn local_connection_id_stats(
  connection: Connection,
) -> Result(local_connection_id.Snapshot, Error) {
  call(connection, LocalConnectionIdStats)
}

/// Snapshot the bytes this connection's stream send buffers hold, summed over every stream it owns, together with the endpoint memory it was granted.
///
/// This is a seam for the memory suite rather than a public diagnostic.
/// It exists because decision D5's bound -- an application's write is admitted only as far as the grant reaches past what the connection already holds -- has no observable consequence of its own that a refusal does not also produce.
/// A single parked write cannot tell a grant that bounded it from a refusal that landed while it waited; what the send buffers are holding against the grant that funded them can.
pub fn send_buffer_grant(connection: Connection) -> Result(#(Int, Int), Error) {
  call(connection, SendBufferGrant)
}

/// Snapshot the complete finite accounting seam used by endpoint-memory qualification tests.
/// This is intentionally absent from the public package facade; application diagnostics never expose admission internals.
pub fn memory_grant_snapshot(
  connection: Connection,
) -> Result(MemoryGrantSnapshot, Error) {
  call(connection, MemoryGrantState)
}

/// Internal scalar ownership and reservation evidence; no process handles.
pub fn send_completion_counts(
  connection: Connection,
) -> Result(#(Int, Int, Int), Error) {
  call(connection, CompletionCounts)
}

/// Return whether a stream's FIN is acknowledged or its send direction reset.
pub fn send_finished(stream: Stream) -> Result(Bool, Error) {
  call(stream.connection, fn(reply) { SendFinished(stream.identifier, reply) })
}

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
        False -> Error(EndpointMemoryExceeded)
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
          await_stream_send_observation(
            connection,
            stream.identifier,
            observation,
            deadline,
          )
        }
      }
    }
  }
}

fn await_stream_send_observation(
  connection: Connection,
  identifier: Int,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Result(stream_completion.Outcome, Error) {
  let outcome =
    send_observation.await(
      observation,
      connection.worker,
      int.max(0, deadline - udp.monotonic_millisecond()),
    )
  case outcome {
    send_observation.Replied(result) -> result
    send_observation.DeadlineExpired(_) -> {
      process.send(
        connection.commands,
        CancelSendCompletion(identifier, observation),
      )
      Error(OperationTimeout)
    }
    send_observation.WorkerExited -> Error(closed_error(connection))
    send_observation.OwnerExited -> Error(closed_error(connection))
    send_observation.Unavailable -> {
      process.send(
        connection.commands,
        CancelSendCompletion(identifier, observation),
      )
      Error(EndpointMemoryExceeded)
    }
  }
}

/// Pull all retained send completions after one connection-local cursor.
///
/// Multiple observers may wait concurrently.
/// Each wait is independently owner-monitored and deadline-bounded; per-stream completion waiters remain available at the same time and read the same terminal history.
pub fn next_send_completions(
  connection: Connection,
  after_cursor: Int,
  within_milliseconds: Int,
) -> Result(CompletionBatch, Error) {
  next_send_completions_with_owner(
    connection,
    after_cursor,
    within_milliseconds,
    None,
  )
}

/// Pull retained completions, ending immediately when an enclosing owner dies.
/// The connection actor still monitors this observer, so either side releases its finite waiter reservation without relying on the long-poll deadline.
pub fn next_send_completions_until_owner_exits(
  connection: Connection,
  after_cursor: Int,
  within_milliseconds: Int,
  owner: Pid,
) -> Result(CompletionBatch, Error) {
  next_send_completions_with_owner(
    connection,
    after_cursor,
    within_milliseconds,
    Some(owner),
  )
}

fn next_send_completions_with_owner(
  connection: Connection,
  after_cursor: Int,
  within_milliseconds: Int,
  owner: Option(Pid),
) -> Result(CompletionBatch, Error) {
  case after_cursor >= 0, within_milliseconds > 0 {
    False, _ | _, False -> Error(InvalidInput)
    True, True -> {
      let deadline =
        udp.monotonic_millisecond()
        + int.min(within_milliseconds, connection.timeout_milliseconds)
      let observation = send_observation.new()
      case send_observation.available(observation) {
        False -> Error(EndpointMemoryExceeded)
        True -> {
          process.send(
            connection.commands,
            NextSendCompletions(
              after_cursor,
              process.self(),
              observation,
              deadline,
            ),
          )
          await_send_batch_observation(connection, observation, deadline, owner)
        }
      }
    }
  }
}

fn await_send_batch_observation(
  connection: Connection,
  observation: Observation(Result(CompletionBatch, Error)),
  deadline: Int,
  owner: Option(Pid),
) -> Result(CompletionBatch, Error) {
  let timeout = int.max(0, deadline - udp.monotonic_millisecond())
  let awaited = case owner {
    None -> send_observation.await(observation, connection.worker, timeout)
    Some(owner) ->
      send_observation.await_with_owner(
        observation,
        connection.worker,
        owner,
        timeout,
      )
  }
  case awaited {
    send_observation.Replied(result) -> result
    send_observation.DeadlineExpired(_) -> {
      process.send(connection.commands, CancelSendCompletions(observation))
      Error(OperationTimeout)
    }
    send_observation.WorkerExited -> Error(closed_error(connection))
    send_observation.OwnerExited -> {
      process.send(connection.commands, CancelSendCompletions(observation))
      Error(ConnectionClosed)
    }
    send_observation.Unavailable -> {
      process.send(connection.commands, CancelSendCompletions(observation))
      Error(EndpointMemoryExceeded)
    }
  }
}

/// Return a redacted SHA-256 fingerprint for the verified client identity.
pub fn client_identity(
  connection: Connection,
) -> Result(Option(BitArray), Error) {
  call(connection, ClientIdentity)
}

pub fn telemetry_stats(connection: Connection) -> Result(qlog.Stats, Error) {
  call(connection, TelemetryStats)
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

pub fn negotiated_protocol(
  connection: Connection,
) -> Result(
  #(
    Version,
    BitArray,
    transport.CongestionAlgorithm,
    Option(hello.CipherSuite),
    Bool,
    Bool,
    Bool,
  ),
  Error,
) {
  call(connection, Protocol)
}

pub fn close_with_code(
  connection: Connection,
  application_error_code: Int,
) -> Result(CloseResult, Error) {
  call(connection, fn(reply) { CloseConnection(application_error_code, reply) })
}

pub fn stream_identifier(stream: Stream) -> Int {
  stream.identifier
}

fn initialise(bootstrap: Bootstrap, ready: Subject(Connection)) -> Nil {
  let bound = case bootstrap.qlog_writer {
    None -> True
    Some(writer) -> qlog.bind_owner(writer, process.self()) |> result.is_ok
  }
  // No connection handle is published if diagnostic ownership could not be established.
  // The bootstrap monitor returns the existing StartFailed error.
  case bound {
    True -> initialise_bound(bootstrap, ready)
    False -> Nil
  }
}

fn initialise_bound(bootstrap: Bootstrap, ready: Subject(Connection)) -> Nil {
  let commands = process.new_subject()
  let listener_monitor = process.monitor(bootstrap.listener)
  let selector =
    process.new_selector()
    |> process.select_map(commands, ReceivedCommand)
    |> process.select_specific_monitor(listener_monitor, fn(_) {
      ListenerExited
    })
  let peer =
    PeerState(
      bootstrap.state,
      dict.new(),
      queue_new(),
      None,
      queue_new(),
      0,
      None,
      bootstrap.protocol_version,
      bootstrap.congestion_control,
      bootstrap.qlog_writer,
      None,
      None,
      bootstrap.now + pmtu_probe_interval_milliseconds,
      None,
      bootstrap.identifier,
      None,
      False,
    )
  let terminal_close = terminal_close.new()
  process.send(
    ready,
    Connection(
      commands,
      process.self(),
      bootstrap.operation_timeout_milliseconds,
      terminal_close,
    ),
  )
  record_initial_qlog(
    bootstrap.qlog_writer,
    bootstrap.now,
    bootstrap.initial_datagram_bytes,
  )
  loop(Worker(
    bootstrap.socket,
    bootstrap.identifier,
    bootstrap.notices,
    commands,
    selector,
    peer,
    0,
    True,
    None,
    terminal_close,
    False,
    bootstrap.application_protocols,
    bootstrap.ticket_keys,
    bootstrap.address_token_key,
    bootstrap.replay_cache,
    bootstrap.replay_guard,
    bootstrap.allow_zero_rtt,
    bootstrap.operation_timeout_milliseconds,
    bootstrap.stream_buffer_limit,
    bootstrap.queue_limit,
    bootstrap.datagram_limit,
    0,
    0,
    True,
    budget.new_grant(budget.admission_quanta()),
    dict.new(),
    [],
    stream_completion.new(bootstrap.queue_limit),
  ))
}

fn record_initial_qlog(
  writer: Option(qlog.Writer),
  now: Int,
  datagram_bytes: Int,
) -> Nil {
  case writer {
    None -> Nil
    Some(writer) -> {
      qlog.connection_started(writer, now)
      qlog.datagram_received(writer, now, datagram_bytes)
      // The listener owns the first Initial before this actor exists.
      // Record a strictly redacted packet observation after ready has been published so the listener can service the writer's dynamic budget request.
      qlog.packet_received(writer, now, 1, datagram_bytes)
    }
  }
}

/// One turn of this actor's life: drain what arrived, expire what timed out,
/// then either end -- on a failure, or on a transport that reached `Closed` -- drive the work the turn made pending, or park until the next message or deadline.
fn loop(worker: Worker) -> Nil {
  let worker = when_live(worker, dispatch_all_events)
  let now = udp.monotonic_millisecond()
  let worker = when_live(worker, maintain_grant)
  let worker = when_live(worker, expire_waiters(_, now))
  let worker = when_live(worker, expire_completion_waiters(_, now))
  let worker = when_live(worker, expire_completion_feed_waiters(_, now))
  let worker = when_live(worker, retry_pending_sends)
  case worker.failure, transport_closed(worker), worker.dirty {
    Some(error), _, _ -> shutdown(worker, error, True)
    // A closed transport owes nothing further and can never reopen, so the actor releases what it owns and exits rather than staying resident.
    None, True, _ -> shutdown(worker, ConnectionClosed, True)
    None, False, True -> drive_and_loop(worker)
    None, False, False -> wait_for_work(worker, now)
  }
}

/// Whether the transport phase reached `Closed`, after a local close drained,
/// after the idle timeout expired, or after the peer vanished.
fn transport_closed(worker: Worker) -> Bool {
  case server_transport.phase(worker.peer.connection) {
    transport.Closed -> True
    transport.Closing
    | transport.Draining
    | transport.Handshaking
    | transport.Established -> False
  }
}

fn when_live(worker: Worker, step: fn(Worker) -> Worker) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> step(worker)
  }
}

// Park until the next message or the next deadline, whichever comes first.
// The deadline is never absent, so this wait is always bounded: a phase change no timer announced is still noticed within one `maximum_park_milliseconds`.
// nolint: thrown_away_error -- a failed step is connection teardown here.
fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case next_worker_deadline(worker, now) {
    Error(_) -> shutdown(worker, ConnectionClosed, True)
    Ok(deadline) -> {
      let received =
        process.selector_receive(
          worker.selector,
          within: int.max(0, deadline - now),
        )
      case received {
        Ok(ListenerExited) -> shutdown(worker, ListenerClosed, False)
        // Only the temporary shutdown selector registers this variant.
        Ok(ReleaseAcknowledged) -> wait_for_work(worker, now)
        Ok(CompletionCallerExited(identifier, monitor)) ->
          loop(completion_caller_exited(worker, identifier, monitor))
        Ok(CompletionFeedCallerExited(observation, monitor)) ->
          loop(completion_feed_caller_exited(worker, observation, monitor))
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(next) -> drive_and_loop(next)
          }
        Error(Nil) -> timer_drive_and_loop(worker)
      }
    }
  }
}

fn drive_and_loop(worker: Worker) -> Nil {
  worker
  |> when_live(flush_when_dirty)
  |> when_live(retry_pending_sends)
  |> loop
}

fn flush_when_dirty(worker: Worker) -> Worker {
  case worker.dirty {
    True -> tick_and_flush(worker)
    False -> worker
  }
}

fn timer_drive_and_loop(worker: Worker) -> Nil {
  worker |> tick_and_flush |> when_live(retry_pending_sends) |> loop
}

fn tick_and_flush(worker: Worker) -> Worker {
  let now = udp.monotonic_millisecond()
  let worker = Worker(..worker, dirty: False)
  case server_transport.tick(worker.peer.connection, now) {
    Error(error) ->
      fail_transport_operation(worker, diagnostic_code.Tick, error)
    Ok(connection) -> {
      let worker =
        put_peer(worker, PeerState(..worker.peer, connection: connection))
      // A connection the tick just closed sends nothing more; the loop turns that phase into an orderly exit.
      case transport_closed(worker) {
        True -> worker
        False ->
          worker
          |> when_live(maybe_queue_new_token(_, now))
          |> when_live(maybe_issue_session_ticket(_, now))
          |> when_live(maybe_probe(_, now))
          |> when_live(flush_connection(_, now, maximum_packets_per_flush))
      }
    }
  }
}

/// Apply one credited batch and acknowledge it, so the listener refills this connection's delivery window by exactly what left the mailbox.
/// The drops the listener reports alongside the batch are recorded first: they are already gone, and QUIC recovers them like any other loss.
fn consume_deliveries(
  worker: Worker,
  deliveries: List(ListenerToConnection),
  dropped: Int,
) -> Worker {
  let #(datagrams, bytes) = delivered_cost(deliveries, 0, 0)
  let worker =
    Worker(
      ..worker,
      dropped_datagrams: worker.dropped_datagrams + int.max(0, dropped),
      // Every delivered byte is a byte this connection's footprint may have
        // grown by, which is what decides whether the next turn walks it.
        unmeasured_bytes: worker.unmeasured_bytes + bytes,
    )
  let worker = receive_deliveries(worker, deliveries)
  process.send(worker.notices, Consumed(worker.identifier, datagrams, bytes))
  worker
}

/// What one delivered batch cost the listener's window for this connection:
/// the datagrams it carried and their total size.
/// The listener refills exactly this much, so the two sides can never drift apart.
fn delivered_cost(
  deliveries: List(ListenerToConnection),
  datagrams: Int,
  bytes: Int,
) -> #(Int, Int) {
  case deliveries {
    [] -> #(datagrams, bytes)
    [RoutedDatagram(_, datagram, _), ..rest] ->
      delivered_cost(rest, datagrams + 1, bytes + bit_array.byte_size(datagram))
  }
}

/// Apply one routed batch, dispatching each datagram's transport events before the next datagram is read.
/// A batch is only a transport detail, so a later datagram -- a peer close, say -- must never hide the events an earlier one produced, such as the completed handshake this listener has to accept.
fn receive_deliveries(
  worker: Worker,
  deliveries: List(ListenerToConnection),
) -> Worker {
  case worker.failure, deliveries {
    Some(_), _ | None, [] -> worker
    None, [RoutedDatagram(peer, datagram, marking), ..rest] ->
      receive_deliveries(
        receive_one_datagram(worker, peer, datagram, marking)
          |> when_live(dispatch_all_events),
        rest,
      )
  }
}

fn receive_one_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  let peer_state = worker.peer
  let now = udp.monotonic_millisecond()
  // Record arrival before parsing.
  // A malformed or undecryptable datagram is precisely the sort of hostile-peer evidence an operator needs, and the strict qlog profile retains only its bounded length, never wire bytes or connection identifiers.
  // One routed UDP datagram is represented by one first packet event classified only from its public header bits.
  // Coalesced packet metadata is intentionally not exposed across this runtime boundary.
  case peer_state.qlog_writer {
    Some(writer) -> {
      qlog.datagram_received(writer, now, bit_array.byte_size(datagram))
      qlog.packet_received(
        writer,
        now,
        datagram
          |> qlog_packet_type.classify
          |> qlog_packet_type.qlog_code,
        bit_array.byte_size(datagram),
      )
    }
    None -> Nil
  }
  let source = classify_received_path(peer_state, peer)
  case
    path_gate.may_authenticate(
      server_transport.path_validation_in_progress(peer_state.connection),
      source,
    )
  {
    False -> worker
    True ->
      receive_permitted_datagram(
        worker,
        peer_state,
        peer,
        datagram,
        marking,
        now,
      )
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn receive_permitted_datagram(
  worker: Worker,
  peer_state: PeerState,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  now: Int,
) -> Worker {
  case replay_policy(worker, now) {
    Error(_) ->
      fail_operation(worker, diagnostic_code.ReplayPolicy, QuicFailure)
    Ok(policy) ->
      case
        server_transport.receive_datagram(
          peer_state.connection,
          datagram,
          marking,
          now,
          policy,
        )
      {
        Error(server_transport.DriverFailure(error) as transport_error) ->
          case driver.discardable_receive_error(error) {
            True -> worker
            False ->
              fail_transport_operation(
                worker,
                diagnostic_code.ReceiveDatagram,
                transport_error,
              )
          }
        Error(error) ->
          fail_transport_operation(
            worker,
            diagnostic_code.ReceiveDatagram,
            error,
          )
        Ok(connection) -> {
          case peer_state.qlog_writer {
            Some(writer) -> record_qlog_recovery(writer, connection, now)
            None -> Nil
          }
          let previous = server_transport.peer(peer_state.connection)
          let destination =
            authenticated_destination(
              datagram,
              peer_state.active_destination_connection_id,
            )
          case same_endpoint(previous, peer) {
            True ->
              put_peer(
                worker,
                PeerState(
                  ..peer_state,
                  connection: connection,
                  active_destination_connection_id: destination,
                ),
              )
              |> update_replay_cache(connection)
              |> mark_dirty
            False ->
              handle_candidate_path(
                worker,
                peer_state,
                connection,
                peer,
                bit_array.byte_size(datagram),
                now,
                destination,
              )
          }
        }
      }
  }
}

fn classify_received_path(
  peer_state: PeerState,
  received: udp.Endpoint,
) -> path_gate.Source {
  case peer_state.candidate_path {
    Some(CandidatePath(candidate, _, _)) ->
      case
        same_endpoint(candidate, received),
        same_endpoint(server_transport.peer(peer_state.connection), received)
      {
        True, _ -> path_gate.Candidate
        False, True -> path_gate.Active
        False, False -> path_gate.Unrelated
      }
    None ->
      case
        same_endpoint(server_transport.peer(peer_state.connection), received)
      {
        True -> path_gate.Active
        False -> path_gate.Candidate
      }
  }
}

// nolint: thrown_away_error, deep_nesting -- path validation is one state tree.
fn handle_candidate_path(
  worker: Worker,
  peer_state: PeerState,
  connection: server_transport.State,
  peer: udp.Endpoint,
  received_bytes: Int,
  now: Int,
  destination: BitArray,
) -> Worker {
  case server_transport.established(connection) {
    False ->
      put_peer(
        worker,
        PeerState(
          ..peer_state,
          connection: server_transport.with_peer(connection, peer),
        ),
      )
      |> update_replay_cache(connection)
      |> mark_dirty
    True ->
      case peer_state.candidate_path {
        Some(CandidatePath(endpoint, received, sent)) ->
          case same_endpoint(endpoint, peer) {
            False -> worker
            True ->
              put_peer(
                worker,
                PeerState(
                  ..peer_state,
                  connection: connection,
                  candidate_path: Some(CandidatePath(
                    endpoint,
                    received + received_bytes,
                    sent,
                  )),
                ),
              )
              |> update_replay_cache(connection)
              |> mark_dirty
          }
        None ->
          case
            crypto.secure_random(8),
            rotate_candidate_destination(
              connection,
              destination == peer_state.active_destination_connection_id,
            )
          {
            Error(_), _ | _, Error(_) -> worker
            Ok(challenge), Ok(#(connection, rotated)) ->
              case
                server_transport.begin_path_validation(
                  connection,
                  challenge,
                  now,
                )
              {
                Error(_) -> worker
                Ok(connection) -> {
                  case peer_state.qlog_writer {
                    Some(writer) -> qlog.migration_started(writer, now)
                    None -> Nil
                  }
                  put_peer(
                    worker,
                    PeerState(
                      ..peer_state,
                      connection: connection,
                      candidate_destination_connection_id: Some(destination),
                      candidate_rotated_peer_id: rotated,
                      candidate_path: Some(CandidatePath(
                        peer,
                        received_bytes,
                        0,
                      )),
                    ),
                  )
                  |> update_replay_cache(connection)
                  |> mark_dirty
                }
              }
          }
      }
  }
}

fn authenticated_destination(
  datagram: BitArray,
  fallback: BitArray,
) -> BitArray {
  case datagram {
    <<first, destination:bytes-size(8), _:bits>> if first < 0x80 -> destination
    _ -> fallback
  }
}

fn rotate_candidate_destination(
  connection: server_transport.State,
  rebinding: Bool,
) -> Result(#(server_transport.State, Bool), server_transport.Error) {
  case server_transport.rotate_peer_connection_id(connection) {
    Ok(rotated) -> Ok(#(rotated, True))
    Error(error) ->
      case rebinding {
        True -> Ok(#(connection, False))
        False -> Error(error)
      }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn maybe_queue_new_token(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
  let endpoint = server_transport.peer(peer.connection)
  let already_issued = case peer.token_endpoint {
    Some(previous) -> same_endpoint(previous, endpoint)
    None -> False
  }
  case server_transport.established(peer.connection), already_issued {
    False, _ | _, True -> worker
    True, False -> {
      let #(address, port) = udp.endpoint_parts(endpoint)
      case
        address_token.seal(
          worker.address_token_key,
          address_token.NewToken,
          peer.version,
          address,
          port,
          <<>>,
          <<>>,
          now,
        )
      {
        Error(_) -> worker
        Ok(token) ->
          case server_transport.queue_new_token(peer.connection, token) {
            Error(_) -> worker
            Ok(connection) ->
              put_peer(
                worker,
                PeerState(
                  ..peer,
                  connection: connection,
                  token_endpoint: Some(endpoint),
                ),
              )
          }
      }
    }
  }
}

fn maybe_issue_session_ticket(worker: Worker, now: Int) -> Worker {
  case
    server_transport.issue_session_ticket_if_ready(worker.peer.connection, now)
  {
    Error(error) ->
      fail_transport_operation(
        worker,
        diagnostic_code.IssueSessionTicket,
        error,
      )
    Ok(connection) ->
      put_peer(worker, PeerState(..worker.peer, connection: connection))
  }
}

fn maybe_probe(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
  case
    server_transport.path_validation_in_progress(peer.connection),
    server_transport.established(peer.connection)
  {
    True, _ | _, False ->
      put_peer(worker, PeerState(..peer, next_pmtu_probe_milliseconds: 0))
    False, True -> maybe_probe_established(worker, peer, now)
  }
}

fn maybe_probe_established(
  worker: Worker,
  peer: PeerState,
  now: Int,
) -> Worker {
  case
    server_transport.pmtu_discovery_complete(peer.connection),
    server_transport.pmtu_probe_outstanding(peer.connection),
    server_transport.pmtu_probe_available(peer.connection),
    peer.next_pmtu_probe_milliseconds
  {
    True, _, _, _ | _, True, _, _ | _, _, False, _ ->
      put_peer(worker, PeerState(..peer, next_pmtu_probe_milliseconds: 0))
    False, False, True, 0 ->
      put_peer(
        worker,
        PeerState(
          ..peer,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    False, False, True, deadline if now < deadline -> worker
    False, False, True, _ -> send_pmtu_probe(worker, peer, now)
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn send_pmtu_probe(worker: Worker, peer: PeerState, now: Int) -> Worker {
  case server_transport.prepare_pmtu_probe(peer.connection, now) {
    Error(_) ->
      put_peer(worker, PeerState(..peer, next_pmtu_probe_milliseconds: 0))
    Ok(None) ->
      put_peer(worker, PeerState(..peer, next_pmtu_probe_milliseconds: 0))
    Ok(Some(prepared)) ->
      case
        udp.classify_send(udp.send(
          worker.socket,
          candidate_send_endpoint(peer),
          server_transport.prepared_bytes(prepared),
          ecn.NotEct,
        ))
      {
        // Don't-Fragment is set, so the local interface can reject a new probe without rejecting the already confirmed path.
        // Exclude the unsent size instead of resetting and retrying it forever.
        udp.PathTooSmall ->
          case server_transport.reject_pmtu_probe(prepared) {
            Error(error) ->
              fail_transport_operation(
                worker,
                diagnostic_code.RejectPmtuProbe,
                error,
              )
            Ok(connection) ->
              put_peer(
                worker,
                PeerState(
                  ..peer,
                  connection: connection,
                  next_pmtu_probe_milliseconds: next_pmtu_after_attempt(
                    connection,
                    now,
                  ),
                ),
              )
          }
        // A dead listener-owned socket can never make this expired probe deadline progress.
        // Fail the actor exactly as the ordinary flush path does, rather than waking immediately on the same deadline.
        udp.SocketLost ->
          fail_operation(worker, diagnostic_code.SendPmtuProbe, QuicFailure)
        udp.Delivered ->
          case server_transport.commit_datagram(prepared, ecn.NotEct, now) {
            // A prepared probe which cannot be committed is inconsistent with recovery state; retaining its expired deadline would spin.
            Error(error) ->
              fail_transport_operation(
                worker,
                diagnostic_code.CommitPmtuProbe,
                error,
              )
            Ok(connection) ->
              put_peer(
                worker,
                record_candidate_send(
                  PeerState(
                    ..peer,
                    connection: connection,
                    next_pmtu_probe_milliseconds: 0,
                  ),
                  bit_array.byte_size(server_transport.prepared_bytes(prepared)),
                ),
              )
          }
      }
  }
}

fn next_pmtu_after_attempt(
  connection: server_transport.State,
  now: Int,
) -> Int {
  case
    server_transport.pmtu_probe_outstanding(connection),
    server_transport.pmtu_probe_available(connection)
  {
    True, _ | _, False -> 0
    False, True -> now + pmtu_probe_interval_milliseconds
  }
}

// nolint: thrown_away_error, deep_nesting -- teardown; moved send tree.
fn flush_connection(worker: Worker, now: Int, remaining: Int) -> Worker {
  let peer = worker.peer
  case remaining {
    0 -> worker
    _ ->
      case
        server_transport.prepare_datagram(
          peer.connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Error(server_transport.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
          _,
        ))))
        | Error(server_transport.DriverFailure(driver.ConnectionFailure(
            transport.CongestionLimited,
          )))
        | Error(server_transport.DriverFailure(driver.ConnectionFailure(
            transport.RecoveryLimited,
          )))
        | Ok(None) -> worker
        Error(error) ->
          fail_transport_operation(
            worker,
            diagnostic_code.PrepareDatagram,
            error,
          )
        Ok(Some(prepared)) -> {
          let bytes = server_transport.prepared_bytes(prepared)
          let destination = candidate_send_endpoint(peer)
          case candidate_send_allowed(peer, bit_array.byte_size(bytes)) {
            False -> worker
            True ->
              case
                udp.classify_send(udp.send(
                  worker.socket,
                  destination,
                  bytes,
                  ecn.NotEct,
                ))
              {
                // The socket sets Don't-Fragment, so an outgoing device narrower than the path DPLPMTUD confirmed refuses the datagram instead of splitting it.
                // That is a path measurement, not a broken socket: the datagram is dropped uncommitted, its frames are still owed and are retransmitted by recovery, and the path returns to the 1200-byte floor.
                udp.PathTooSmall ->
                  put_peer(
                    worker,
                    PeerState(
                      ..peer,
                      connection: server_transport.report_pmtu_black_hole(
                        peer.connection,
                      ),
                    ),
                  )
                udp.SocketLost ->
                  fail_operation(
                    worker,
                    diagnostic_code.SendDatagram,
                    QuicFailure,
                  )
                udp.Delivered ->
                  case
                    server_transport.commit_datagram(prepared, ecn.NotEct, now)
                  {
                    Error(error) ->
                      fail_transport_operation(
                        worker,
                        diagnostic_code.CommitDatagram,
                        error,
                      )
                    Ok(connection) -> {
                      case peer.qlog_writer {
                        Some(writer) -> {
                          qlog.datagram_sent(
                            writer,
                            now,
                            bit_array.byte_size(bytes),
                          )
                          qlog.packet_sent(
                            writer,
                            now,
                            8,
                            bit_array.byte_size(bytes),
                          )
                          record_qlog_recovery(writer, connection, now)
                        }
                        None -> Nil
                      }
                      let next =
                        record_candidate_send(
                          PeerState(..peer, connection: connection),
                          bit_array.byte_size(bytes),
                        )
                      flush_connection(
                        put_peer(worker, next),
                        now,
                        remaining - 1,
                      )
                    }
                  }
              }
          }
        }
      }
  }
}

fn dispatch_all_events(worker: Worker) -> Worker {
  let #(connection, events) =
    server_transport.take_events(worker.peer.connection)
  let worker =
    put_peer(worker, PeerState(..worker.peer, connection: connection))
  dispatch_events(worker, events)
}

fn dispatch_events(worker: Worker, events: List(transport.Event)) -> Worker {
  case worker.failure, events {
    Some(_), _ | None, [] -> worker
    None, [event, ..rest] ->
      dispatch_events(dispatch_event(worker, event), rest)
  }
}

fn dispatch_event(worker: Worker, event: transport.Event) -> Worker {
  case event {
    transport.HandshakeEstablished ->
      record_server_handshake_qlog(worker)
      |> report_established
    transport.LocalConnectionIdRetired(_, identifier) -> {
      process.send(
        worker.notices,
        RetiredConnectionId(
          worker.identifier,
          process.self(),
          identifier,
          server_transport.local_connection_id_capacity(worker.peer.connection)
            > 0,
        ),
      )
      worker
    }
    transport.StreamOpened(identifier) -> register_stream(worker, identifier)
    transport.StreamReadable(identifier) ->
      service_read_waiter(worker, identifier)
    transport.StreamWasReset(identifier, _) ->
      service_read_waiter(worker, identifier)
    transport.StreamSendCompleted(identifier, outcome) ->
      complete_send(worker, identifier, outcome)
    transport.DatagramReceived(payload) -> enqueue_datagram(worker, payload)
    transport.PathValidated -> commit_candidate_path(worker)
    transport.PathValidationFailed -> discard_candidate_path(worker)
    transport.PersistentCongestionDetected -> {
      case worker.peer.qlog_writer {
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
      let _published =
        terminal_close.publish(
          close: worker.terminal_close,
          kind: terminal_close.Application,
          code:,
        )
      fail_connection(worker, closed_error(connection_handle(worker)))
    }
    transport.PeerTransportClosed(code, _) -> {
      let _published =
        terminal_close.publish(
          close: worker.terminal_close,
          kind: terminal_close.Transport,
          code:,
        )
      fail_connection(worker, closed_error(connection_handle(worker)))
    }
    transport.StatelessResetReceived ->
      fail_connection(worker, ConnectionClosed)
    transport.LocalTransportFailure(error, code) -> {
      let _published =
        terminal_close.publish(
          close: worker.terminal_close,
          kind: terminal_close.LocalTransport,
          code:,
        )
      record_diagnostic_codes(worker.peer.qlog_writer, [
        diagnostic_code.operation(diagnostic_code.ReceiveDatagram),
        ..diagnostic_code.server_transport_error(
          server_transport.DriverFailure(driver.ConnectionFailure(error)),
        )
      ])
      // Emit the first close before notifying an application that may stop its listener immediately.
      // Normal closing-state input then re-arms the same bounded response until the existing fixed close deadline.
      let worker = flush_connection(worker, udp.monotonic_millisecond(), 1)
      let peer = worker.peer
      fail_peer_waiters(peer, TransportFailureWithCode(code))
      let worker =
        fail_completion_waiters(worker, TransportFailureWithCode(code))
      let worker =
        fail_completion_feed_waiters(worker, TransportFailureWithCode(code))
      put_peer(
        worker,
        PeerState(
          ..peer,
          stream_waiter: None,
          datagram_waiter: None,
          streams: dict.map_values(peer.streams, fn(_, stream) {
            StreamState(..stream, read_waiter: None, pending_send: None)
          }),
        ),
      )
    }
    _ -> worker
  }
}

fn report_established(worker: Worker) -> Worker {
  case worker.established_reported {
    True -> worker
    False -> {
      process.send(worker.notices, Established(worker.identifier))
      process.send(
        worker.notices,
        AllocateConnectionIds(
          worker.identifier,
          process.self(),
          server_transport.local_connection_id_capacity(worker.peer.connection),
        ),
      )
      // Becoming established is what lets a withheld credit hold lift, so the next turn walks the footprint whatever the traffic has been.
      Worker(..worker, established_reported: True, remeasure: True)
    }
  }
}

/// Decision D2, connection side.
/// Keep this connection's grant ahead of what it holds, and hold its advertised credit inside that grant.
///
/// This is grant-before-growth.
/// The connection measures what it holds, tells the transport how much room it has been granted -- which is what bounds the MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS values it may advertise from here on -- and asks the listener for the next growth step once what it holds comes within one step of the grant.
/// It never has to hold more than it was granted plus what it had already advertised, because the credit it may advertise is bounded by the grant rather than charged after the fact.
///
/// The request is asynchronous, so the hot path never waits on the listener,
/// and it carries a sequence number the answer echoes, so a `Granted` racing a later request cannot install a grant sized for a footprint this connection has already grown past.
fn maintain_grant(worker: Worker) -> Worker {
  case worker.remeasure || worker.unmeasured_bytes >= budget.quantum() {
    False -> worker
    True -> measure_grant(worker)
  }
}

/// Walk this connection's footprint once, hold its advertised credit inside the grant, and ask for the next step if what it holds has come within one of the grant.
///
/// The transport accounts for stream receive reassembly, delivered-but-unread bytes, unsent and retransmittable send buffers, the three packet spaces' sent-packet histories, and crypto reassembly, and it applies the hold in the same walk.
/// This actor adds the queue it owns itself: the RFC 9221 Datagram backlog its owner has not read yet, which is paid for out of the grant before the transport is told what is left of it.
fn measure_grant(worker: Worker) -> Worker {
  let peer = worker.peer
  let completion_bytes = completion_metadata_bytes(worker)
  let #(connection, retained) =
    server_transport.apply_memory_grant(
      peer.connection,
      budget.granted_bytes(worker.grant)
        - peer.datagram_bytes
        - completion_bytes,
      budget.grant_refused(worker.grant),
    )
  let held = retained + peer.datagram_bytes + completion_bytes
  let worker =
    put_peer(
      Worker(
        ..worker,
        retained_bytes: held,
        unmeasured_bytes: 0,
        remeasure: False,
      ),
      PeerState(..peer, connection: connection),
    )
  case budget.request(worker.grant, held) {
    None -> worker
    Some(#(grant, sequence, quanta)) -> {
      process.send(worker.notices, Request(worker.identifier, sequence, quanta))
      Worker(..worker, grant: grant)
    }
  }
}

/// Decision D5.
/// How much of an application's own write this connection may take into its send buffers.
///
/// Growth has to be funded before it happens on the send side too, and the send buffers are where an application's writes become memory this endpoint holds.
/// A write is therefore admitted only as far as the grant still reaches past what this connection holds, unconditionally: not once a refusal has landed,
/// which would be charging for the growth after taking it, but on every write.
/// A connection whose grant is being met sees no throttle from this, because the grant is kept a whole growth step ahead of what it holds and that step is as wide as the per-stream `Buffer` ceiling; a connection the endpoint has stopped funding sees the ceiling close on it instead.
///
/// What it holds is counted conservatively -- the last footprint it measured plus every byte that could have grown it since -- so a turn that advances several parked streams admits one grant between them rather than one each,
/// and the send side adds no measurement slack of its own.
///
/// An application can still finish what the grant already funds: a short reply,
/// an acknowledgement.
/// Only what the grant does not fund is held back, and it parks like any other blocked write and ends on its own deadline -- as a transient endpoint overload when the endpoint has refused this connection room, so the caller can tell endpoint pressure from a slow peer.
/// Nothing else is held: reading, draining a backlog, and acknowledging are untouched.
/// What this connection's stream send buffers hold right now, summed over every stream it owns.
fn buffered_send_bytes(worker: Worker) -> Int {
  list.fold(dict.keys(worker.peer.streams), 0, fn(total, identifier) {
    case
      server_transport.buffered_send_bytes(worker.peer.connection, identifier)
    {
      // nolint: thrown_away_error -- an unknown stream buffers nothing.
      Error(_reason) -> total
      Ok(buffered) -> total + buffered
    }
  })
}

/// What one write may take into this connection's send buffers now, given what its streams already hold.
///
/// The answer is `budget`'s to give and this actor's only to carry: the allowance is opaque, so nothing here can widen it to the `Buffer` ceiling the application chose.
/// What this function contributes is the footprint -- the last walk plus everything admitted or delivered since -- which is what makes one grant bound every stream on the connection together rather than each of them separately.
fn send_allowance(worker: Worker, buffered: Int) -> budget.Admission {
  budget.send_allowance(
    worker.grant,
    worker.retained_bytes + worker.unmeasured_bytes,
    worker.stream_buffer_limit - buffered,
  )
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case server_transport.local_transport_failure_code(worker.peer.connection) {
    None -> handle_live_command(worker, command)
    Some(code) -> handle_transport_closed_command(worker, command, code)
  }
}

fn handle_transport_closed_command(
  worker: Worker,
  command: Command,
  code: Int,
) -> Result(Worker, Nil) {
  let failure = TransportFailureWithCode(code)
  case command {
    RegisteredConnectionIds(_) -> Ok(worker)
    Open(_, reply) -> reply_error(worker, reply, failure)
    AcceptStream(reply, _) -> reply_error(worker, reply, failure)
    Send(_, _, _, observation, _) -> {
      let _published = send_observation.publish(observation, Error(failure))
      Ok(worker)
    }
    AwaitSendCompletion(_, _, observation, _) -> {
      let _published = send_observation.publish(observation, Error(failure))
      Ok(worker)
    }
    NextSendCompletions(_, _, observation, _) -> {
      let _published = send_observation.publish(observation, Error(failure))
      Ok(worker)
    }
    CancelSendCompletions(_) -> Ok(worker)
    Receive(_, _, reply, _) -> reply_error(worker, reply, failure)
    ResetStream(_, _, reply)
    | StopSending(_, _, reply)
    | SendDatagram(_, reply)
    | Ping(reply)
    | SetCongestion(_, reply) -> reply_error(worker, reply, failure)
    ReceiveDatagram(reply, _) -> reply_error(worker, reply, failure)
    command -> handle_live_command(worker, command)
  }
}

fn handle_live_command(
  worker: Worker,
  command: Command,
) -> Result(Worker, Nil) {
  case command {
    CompletionCounts(reply) -> {
      process.send(
        reply,
        Ok(#(
          dict.size(worker.completion_waiters)
            + list.length(worker.completion_feed_waiters),
          stream_completion.count(worker.completions),
          completion_metadata_bytes(worker),
        )),
      )
      Ok(worker)
    }
    LocalConnectionIdStats(reply) -> {
      process.send(
        reply,
        Ok(server_transport.local_connection_id_snapshot(worker.peer.connection)),
      )
      Ok(worker)
    }
    RegisteredConnectionIds(values) ->
      Ok(install_registered_connection_ids(worker, values))
    Deliver(deliveries, dropped) ->
      Ok(consume_deliveries(worker, deliveries, dropped))
    Granted(sequence, quanta) ->
      Ok(
        Worker(
          ..worker,
          grant: budget.apply_grant(worker.grant, sequence, quanta),
          remeasure: True,
        )
        |> mark_dirty,
      )
    Refused(sequence, quanta) ->
      Ok(
        Worker(
          ..worker,
          grant: budget.apply_refusal(worker.grant, sequence, quanta),
          remeasure: True,
        ),
      )
    ReloadedKeys(ticket_keys, address_token_key) ->
      Ok(
        Worker(
          ..worker,
          ticket_keys: ticket_keys,
          address_token_key: address_token_key,
          peer: PeerState(..worker.peer, token_endpoint: None),
        )
        |> mark_dirty,
      )
    DiagnosticPause(owner, gate, entered, resumed) -> {
      let owner_monitor = process.monitor(owner)
      let gate_monitor = process.monitor(gate)
      process.send(entered, Nil)
      let _outcome =
        process.new_selector()
        |> process.select_specific_monitor(gate_monitor, fn(_) {
          DiagnosticBarrierReleased
        })
        |> process.select_specific_monitor(owner_monitor, fn(_) {
          DiagnosticBarrierOwnerExited
        })
        |> process.selector_receive(within: diagnostic_barrier_milliseconds)
      process.demonitor_process(gate_monitor)
      process.demonitor_process(owner_monitor)
      process.send(resumed, Nil)
      Ok(worker)
    }
    Terminate -> {
      shutdown(worker, ConnectionClosed, False)
      Error(Nil)
    }
    TerminateAndWait(deadline_milliseconds, reply) -> {
      let termination =
        shutdown_result_until(
          worker,
          ConnectionClosed,
          False,
          deadline_milliseconds,
        )
      process.send(reply, termination)
      Error(Nil)
    }
    Open(direction, reply) -> handle_open(worker, direction, reply)
    AcceptStream(reply, deadline) ->
      handle_accept_stream(worker, reply, deadline)
    Send(identifier, bytes, finish, reply, deadline) ->
      handle_send(worker, identifier, bytes, finish, reply, deadline)
    Receive(identifier, maximum, reply, deadline) ->
      handle_receive(worker, identifier, maximum, reply, deadline)
    ResetStream(identifier, code, reply) ->
      update_peer_reply(worker, reply, fn(peer) {
        server_transport.reset(peer.connection, identifier, code)
      })
    StopSending(identifier, code, reply) ->
      update_peer_reply(worker, reply, fn(peer) {
        server_transport.stop_sending(peer.connection, identifier, code)
      })
    SendDatagram(payload, reply) -> handle_send_datagram(worker, payload, reply)
    ReceiveDatagram(reply, deadline) ->
      handle_receive_datagram(worker, reply, deadline)
    MaximumDatagram(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        server_transport.maximum_datagram_size(peer.connection)
        |> result.map_error(map_transport_error)
      })
    GuaranteedDatagram(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        server_transport.guaranteed_datagram_size(peer.connection)
        |> result.map_error(map_transport_error)
      })
    Ping(reply) ->
      update_peer_reply(worker, reply, fn(peer) {
        server_transport.ping(peer.connection)
      })
    SetCongestion(algorithm, reply) ->
      handle_set_congestion(worker, algorithm, reply)
    PeerEndpoint(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.peer(peer.connection) |> udp.endpoint_parts)
      })
    PathMtu(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.path_mtu(peer.connection))
      })
    PathStats(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.path_stats(peer.connection))
      })
    ConnectionStats(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(#(server_transport.stats(peer.connection), worker.dropped_datagrams))
      })
    ResourceStats(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(#(
          dict.size(peer.streams),
          server_transport.active_stream_count(peer.connection),
        ))
      })
    TelemetryStats(reply) -> handle_telemetry_stats(worker, reply)
    ApplicationDiagnostics(reply) -> {
      process.send(reply, Ok(worker.peer.qlog_writer))
      Ok(worker)
    }
    SendBufferGrant(reply) -> {
      process.send(
        reply,
        Ok(#(buffered_send_bytes(worker), budget.granted_bytes(worker.grant))),
      )
      Ok(worker)
    }
    MemoryGrantState(reply) -> {
      process.send(
        reply,
        Ok(MemoryGrantSnapshot(
          buffered_send_bytes: buffered_send_bytes(worker),
          retained_bytes: worker.retained_bytes,
          unmeasured_bytes: worker.unmeasured_bytes,
          granted_bytes: budget.granted_bytes(worker.grant),
          refused: budget.grant_refused(worker.grant),
          advertised_max_data: server_transport.advertised_max_data(
            worker.peer.connection,
          ),
          outstanding_receive_credit: server_transport.outstanding_receive_credit(
            worker.peer.connection,
          ),
          credit_growth_held: server_transport.credit_growth_held(
            worker.peer.connection,
          ),
          active_streams: server_transport.active_stream_count(
            worker.peer.connection,
          ),
          stream_identifiers: server_transport.stream_identifiers(
            worker.peer.connection,
          ),
          incoming_stream_identifiers: queue_values(worker.peer.incoming),
          transport_progress: server_transport.send_progress(
            worker.peer.connection,
          ),
          pending_sends: pending_send_snapshots(
            dict.to_list(worker.peer.streams),
            udp.monotonic_millisecond(),
          ),
          last_send_deadline: worker.peer.last_send_deadline,
        )),
      )
      Ok(worker)
    }
    SendFinished(identifier, reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        server_transport.send_finished(peer.connection, identifier)
        |> result.map_error(map_transport_error)
      })
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
    NextSendCompletions(after_cursor, owner, observation, deadline) ->
      Ok(register_completion_feed_waiter(
        worker,
        after_cursor,
        owner,
        observation,
        deadline,
      ))
    CancelSendCompletions(observation) ->
      Ok(remove_completion_feed_waiter(worker, observation))
    Phase(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.phase(peer.connection))
      })
    ClientIdentity(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        case server_transport.client_identity(peer.connection) {
          None -> Ok(None)
          Some(identity) ->
            authentication.verified_peer_fingerprint(identity)
            |> result.map(Some)
            |> result.replace_error(QuicFailure)
        }
      })
    Protocol(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        let protocol = case
          server_transport.application_protocol(peer.connection)
        {
          Some(value) -> value
          None -> first_protocol(worker.application_protocols)
        }
        Ok(#(
          peer.version,
          protocol,
          peer.congestion_control,
          server_transport.cipher_suite(peer.connection),
          server_transport.resumed(peer.connection),
          server_transport.early_data_attempted(peer.connection),
          server_transport.early_data_accepted(peer.connection),
        ))
      })
    CloseConnection(code, reply) -> handle_close_connection(worker, code, reply)
  }
}

fn install_registered_connection_ids(
  worker: Worker,
  values: List(#(BitArray, BitArray)),
) -> Worker {
  case values, worker.failure {
    [], _ | _, Some(_) -> worker
    [#(identifier, token), ..rest], None ->
      case
        server_transport.issue_local_connection_id(
          worker.peer.connection,
          identifier,
          token,
        )
      {
        Error(error) ->
          fail_transport_operation(
            worker,
            diagnostic_code.IssueConnectionId,
            error,
          )
        Ok(connection) ->
          install_registered_connection_ids(
            put_peer(worker, PeerState(..worker.peer, connection: connection))
              |> mark_dirty,
            rest,
          )
      }
  }
}

fn handle_open(
  worker: Worker,
  direction: stream_id.Direction,
  reply: Subject(Result(Int, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case server_transport.open_stream(peer.connection, direction) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(#(connection, identifier)) -> {
      process.send(reply, Ok(identifier))
      Ok(
        put_peer(
          worker,
          put_peer_stream(
            PeerState(..peer, connection: connection),
            identifier,
            new_stream_state(identifier),
          ),
        )
        |> mark_dirty,
      )
    }
  }
}

fn handle_accept_stream(
  worker: Worker,
  reply: Subject(Result(IncomingStream, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case queue_pop(peer.incoming), peer.stream_waiter {
    Ok(#(identifier, rest)), _ -> {
      process.send(reply, incoming_stream(worker, identifier))
      Ok(put_peer(worker, PeerState(..peer, incoming: rest)))
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentAccept)
    Error(Nil), None ->
      Ok(put_peer(
        worker,
        PeerState(..peer, stream_waiter: Some(StreamWaiter(reply, deadline))),
      ))
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_send(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
  observation: Observation(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    bit_array.bit_size(bytes) % 8,
    stream_id.can_send(identifier, stream_id.Server)
  {
    remainder, _ if remainder != 0 ->
      send_reply_error(worker, observation, InvalidInput)
    _, False -> send_reply_error(worker, observation, InvalidDirection)
    _, True ->
      case dict.get(worker.peer.streams, identifier) {
        Error(_) -> send_reply_error(worker, observation, StreamClosed)
        Ok(stream) ->
          case stream.pending_send, stream.send_finished {
            Some(_), _ -> send_reply_error(worker, observation, ConcurrentSend)
            None, True -> send_reply_error(worker, observation, StreamClosed)
            None, False ->
              Ok(
                advance_send(
                  worker,
                  identifier,
                  PendingSend(bytes, finish, observation, deadline, False),
                )
                |> mark_dirty,
              )
          }
      }
  }
}

fn send_reply_error(
  worker: Worker,
  observation: Observation(Result(Nil, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  let _published = send_observation.publish(observation, Error(error))
  Ok(worker)
}

fn clear_pending_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
) -> Worker {
  put_peer(
    worker,
    put_peer_stream(
      worker.peer,
      identifier,
      StreamState(..stream, pending_send: None),
    ),
  )
}

// nolint: thrown_away_error -- failed transport steps complete this send.
fn advance_send(
  worker: Worker,
  identifier: Int,
  pending: PendingSend,
) -> Worker {
  let now = udp.monotonic_millisecond()
  case dict.get(worker.peer.streams, identifier) {
    Error(_) -> {
      let _published =
        send_observation.publish(pending.observation, Error(StreamClosed))
      worker
    }
    Ok(stream) if now >= pending.deadline -> {
      // Preserve the final cause observed while this operation was live.
      // A later grant must not relabel a refusal after its deadline has elapsed.
      let _published =
        send_observation.publish(
          pending.observation,
          Error(send_deadline_error(pending)),
        )
      clear_pending_send(
        put_peer(
          worker,
          PeerState(
            ..worker.peer,
            last_send_deadline: Some(send_deadline_snapshot(
              identifier,
              pending,
              now,
            )),
          ),
        ),
        identifier,
        stream,
      )
    }
    Ok(stream) -> advance_live_send(worker, identifier, stream, pending)
  }
}

fn advance_live_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  pending: PendingSend,
) -> Worker {
  case
    server_transport.buffered_send_bytes(worker.peer.connection, identifier)
  {
    Error(error) -> {
      let _published =
        send_observation.publish(
          pending.observation,
          Error(map_transport_error(error)),
        )
      clear_pending_send(worker, identifier, stream)
    }
    Ok(buffered) -> {
      let admission = send_allowance(worker, buffered)
      let pending =
        PendingSend(..pending, held_by_grant: budget.grant_bound(admission))
      case send_observation.park(pending.observation, pending.held_by_grant) {
        False -> clear_pending_send(worker, identifier, stream)
        True ->
          advance_admitted_send(
            worker,
            identifier,
            stream,
            pending,
            budget.admitted_bytes(admission),
          )
      }
    }
  }
}

// Pure transport changes become actor state only when the observation admits their commit.
// Owner expiry/death closes that gate; a later retry cannot enqueue the same bytes.
// A terminal result remains recoverable even if its notification is delayed beyond the caller's deadline.
fn advance_admitted_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  pending: PendingSend,
  available: Int,
) -> Worker {
  let remaining_size = bit_array.byte_size(pending.remaining)
  case remaining_size > 0 && available <= 0 {
    True ->
      put_peer(
        worker,
        put_peer_stream(
          worker.peer,
          identifier,
          StreamState(..stream, pending_send: Some(pending)),
        ),
      )
    False -> {
      let take =
        int.min(
          remaining_size,
          int.min(maximum_send_chunk_bytes, int.max(available, 0)),
        )
      let #(chunk, rest) = take_bytes(pending.remaining, take)
      let finish = pending.finish && rest == <<>>
      case
        server_transport.send(worker.peer.connection, identifier, chunk, finish)
      {
        Error(error) -> {
          let _published =
            send_observation.publish(
              pending.observation,
              Error(map_transport_error(error)),
            )
          clear_pending_send(worker, identifier, stream)
        }
        Ok(connection) ->
          commit_send(
            worker,
            identifier,
            stream,
            pending,
            connection,
            rest,
            take,
          )
      }
    }
  }
}

fn commit_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  pending: PendingSend,
  connection: server_transport.State,
  rest: BitArray,
  take: Int,
) -> Worker {
  let committed = case rest {
    <<>> -> send_observation.publish(pending.observation, Ok(Nil))
    _ -> send_observation.park(pending.observation, pending.held_by_grant)
  }
  case committed {
    False -> clear_pending_send(worker, identifier, stream)
    True -> {
      let pending_send = case rest {
        <<>> -> None
        _ -> Some(PendingSend(..pending, remaining: rest))
      }
      put_peer(
        Worker(..worker, unmeasured_bytes: worker.unmeasured_bytes + take),
        put_peer_stream(
          PeerState(..worker.peer, connection: connection),
          identifier,
          StreamState(
            ..stream,
            pending_send: pending_send,
            send_finished: stream.send_finished
              || pending.finish
              && rest == <<>>,
          ),
        ),
      )
    }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_receive(
  worker: Worker,
  identifier: Int,
  maximum_bytes: Int,
  reply: Subject(Result(Read, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case
    maximum_bytes > 0 && maximum_bytes <= worker.stream_buffer_limit,
    stream_id.can_receive(identifier, stream_id.Server)
  {
    False, _ -> reply_error(worker, reply, InvalidInput)
    _, False -> reply_error(worker, reply, InvalidDirection)
    True, True ->
      case dict.get(worker.peer.streams, identifier) {
        Error(_) -> reply_error(worker, reply, StreamClosed)
        Ok(StreamState(read_waiter: Some(_), ..)) ->
          reply_error(worker, reply, ConcurrentReceive)
        Ok(_) ->
          // A successful pull can queue MAX_DATA and MAX_STREAM_DATA in the transport.
          // The command path must flush those credit updates in this turn; otherwise a peer whose congestion window is full of the just-consumed bytes cannot make progress until an unrelated packet or application deadline wakes this actor.
          Ok(
            read_or_wait(
              worker,
              identifier,
              ReadWaiter(maximum_bytes, reply, deadline),
            )
            |> mark_dirty,
          )
      }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn read_or_wait(worker: Worker, identifier: Int, waiter: ReadWaiter) -> Worker {
  let peer = worker.peer
  case dict.get(peer.streams, identifier) {
    Error(_) -> {
      process.send(waiter.reply, Error(StreamClosed))
      worker
    }
    Ok(stream) ->
      case
        server_transport.read(peer.connection, identifier, waiter.maximum_bytes)
      {
        Error(error) -> {
          process.send(waiter.reply, Error(map_transport_error(error)))
          worker
        }
        Ok(#(connection, runtime_connection.Pending)) ->
          put_peer(
            worker,
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(..stream, read_waiter: Some(waiter)),
            ),
          )
        Ok(#(connection, runtime_connection.Data(bytes, finished))) -> {
          process.send(waiter.reply, Ok(Data(bytes, finished)))
          put_peer(
            worker,
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(
                ..stream,
                read_waiter: None,
                receive_finished: stream.receive_finished || finished,
              ),
            ),
          )
        }
        Ok(#(connection, runtime_connection.Reset(code))) -> {
          process.send(waiter.reply, Ok(Reset(code)))
          put_peer(
            worker,
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(..stream, read_waiter: None, receive_finished: True),
            ),
          )
        }
        Ok(#(connection, runtime_connection.Finished)) -> {
          process.send(waiter.reply, Ok(Finished))
          put_peer(
            worker,
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(..stream, read_waiter: None, receive_finished: True),
            ),
          )
        }
      }
  }
}

fn handle_send_datagram(
  worker: Worker,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case server_transport.maximum_datagram_size(worker.peer.connection) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(maximum) -> {
      let size = bit_array.byte_size(payload)
      case size > maximum {
        True -> reply_error(worker, reply, DatagramTooLarge(maximum))
        False ->
          update_peer_reply(worker, reply, fn(peer) {
            server_transport.send_datagram(peer.connection, payload)
          })
      }
    }
  }
}

fn handle_receive_datagram(
  worker: Worker,
  reply: Subject(Result(BitArray, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case queue_pop(peer.datagrams), peer.datagram_waiter {
    Ok(#(payload, rest)), _ -> {
      process.send(reply, Ok(payload))
      Ok(put_peer(
        worker,
        PeerState(
          ..peer,
          datagrams: rest,
          datagram_bytes: peer.datagram_bytes - bit_array.byte_size(payload),
        ),
      ))
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentDatagramReceive)
    Error(Nil), None ->
      Ok(put_peer(
        worker,
        PeerState(
          ..peer,
          datagram_waiter: Some(DatagramWaiter(reply, deadline)),
        ),
      ))
  }
}

fn handle_set_congestion(
  worker: Worker,
  algorithm: transport.CongestionAlgorithm,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case server_transport.set_congestion_control(peer.connection, algorithm) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(
        put_peer(
          worker,
          PeerState(
            ..peer,
            connection: connection,
            congestion_control: algorithm,
          ),
        )
        |> mark_dirty,
      )
    }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_telemetry_stats(
  worker: Worker,
  reply: Subject(Result(qlog.Stats, Error)),
) -> Result(Worker, Nil) {
  case worker.peer.qlog_writer {
    None -> {
      process.send(reply, Ok(qlog.Stats(0, 0, 0)))
      Ok(worker)
    }
    Some(writer) ->
      case qlog.stats(writer) {
        Ok(stats) -> {
          process.send(reply, Ok(stats))
          Ok(worker)
        }
        Error(_) -> reply_error(worker, reply, QlogUnavailable)
      }
  }
}

fn handle_close_connection(
  worker: Worker,
  application_error_code: Int,
  reply: Subject(Result(CloseResult, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case server_transport.phase(peer.connection) {
    transport.Closing | transport.Draining | transport.Closed -> {
      process.send(reply, Ok(AlreadyClosed))
      Ok(worker)
    }
    transport.Handshaking | transport.Established -> {
      let connection =
        server_transport.close(
          peer.connection,
          application_error_code,
          "application close",
          udp.monotonic_millisecond(),
        )
      // A listener may be stopped as soon as this synchronous public call returns.
      // Emit the first CONNECTION_CLOSE before acknowledging it so listener teardown cannot close the shared UDP relay first.
      let worker =
        put_peer(worker, PeerState(..peer, connection: connection))
        |> mark_dirty
        |> flush_when_dirty
      process.send(reply, Ok(Closed))
      Ok(worker)
    }
  }
}

fn register_stream(worker: Worker, identifier: Int) -> Worker {
  let peer = worker.peer
  let peer = case dict.has_key(peer.streams, identifier) {
    True -> peer
    False -> put_peer_stream(peer, identifier, new_stream_state(identifier))
  }
  let worker = put_peer(worker, peer)
  case stream_id.decode(identifier) {
    Ok(stream_id.StreamId(_, stream_id.Client, _)) ->
      enqueue_incoming_stream(worker, identifier)
    _ -> worker
  }
}

/// Decision D3.
/// A peer is never punished for using credit this endpoint advertised, so a stream that arrives inside the advertised limits is always accepted, whatever the endpoint's memory budget is doing.
/// What the budget holds back is the invitation to open more: while the endpoint has refused this connection room, the transport withholds the MAX_STREAMS increase a closing stream would otherwise replenish, so the peer's allowance stops growing instead of the connection being destroyed.
/// Only the standing `Queue` limit, which the application chose, is fatal here.
fn enqueue_incoming_stream(worker: Worker, identifier: Int) -> Worker {
  let peer = worker.peer
  case peer.stream_waiter {
    Some(StreamWaiter(reply, _)) -> {
      process.send(reply, incoming_stream(worker, identifier))
      put_peer(worker, PeerState(..peer, stream_waiter: None))
    }
    None ->
      case queue_count(peer.incoming) >= worker.queue_limit {
        True ->
          fail_connection(
            worker,
            IncomingStreamQueueExceeded(worker.queue_limit),
          )
        False ->
          put_peer(
            worker,
            PeerState(..peer, incoming: queue_push(peer.incoming, identifier)),
          )
      }
  }
}

fn service_read_waiter(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.peer.streams, identifier) {
    Ok(StreamState(read_waiter: Some(waiter), ..)) ->
      read_or_wait(worker, identifier, waiter)
    _ -> worker
  }
}

fn enqueue_datagram(worker: Worker, payload: BitArray) -> Worker {
  let peer = worker.peer
  case peer.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> {
      process.send(reply, Ok(payload))
      put_peer(worker, PeerState(..peer, datagram_waiter: None))
    }
    None -> {
      let size = bit_array.byte_size(payload)
      case
        // Decision D4.
        // A Datagram frame is droppable by RFC 9221, so one that would take this connection past a grant the endpoint has refused to widen is dropped rather than queued, and never fatal.
        // The drop is counted where every other inbound drop for this connection is counted, so an operator can see it.
        budget.grant_refused(worker.grant)
        && worker.retained_bytes + size > budget.granted_bytes(worker.grant)
      {
        True ->
          Worker(..worker, dropped_datagrams: worker.dropped_datagrams + 1)
        False -> enqueue_bounded_datagram(worker, peer, payload, size)
      }
    }
  }
}

fn enqueue_bounded_datagram(
  worker: Worker,
  peer: PeerState,
  payload: BitArray,
  size: Int,
) -> Worker {
  case
    queue_count(peer.datagrams) >= worker.queue_limit
    || peer.datagram_bytes + size > worker.datagram_limit
  {
    True -> fail_connection(worker, DatagramQueueExceeded(worker.queue_limit))
    False ->
      put_peer(
        worker,
        PeerState(
          ..peer,
          datagrams: queue_push(peer.datagrams, payload),
          datagram_bytes: peer.datagram_bytes + size,
        ),
      )
  }
}

fn commit_candidate_path(worker: Worker) -> Worker {
  case worker.peer {
    PeerState(candidate_path: Some(CandidatePath(endpoint, _, _)), ..) as peer -> {
      case peer.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      put_peer(
        worker,
        PeerState(
          ..peer,
          connection: server_transport.with_peer(peer.connection, endpoint),
          candidate_path: None,
          active_destination_connection_id: option.unwrap(
            peer.candidate_destination_connection_id,
            peer.active_destination_connection_id,
          ),
          candidate_destination_connection_id: None,
          candidate_rotated_peer_id: False,
        ),
      )
    }
    _ -> worker
  }
}

fn discard_candidate_path(worker: Worker) -> Worker {
  let peer = worker.peer
  case peer.candidate_path, peer.qlog_writer {
    Some(_), Some(writer) ->
      qlog.migration_abandoned(writer, udp.monotonic_millisecond())
    _, _ -> Nil
  }
  let returned = case peer.candidate_rotated_peer_id {
    True -> server_transport.rotate_peer_connection_id(peer.connection)
    False -> Ok(peer.connection)
  }
  case returned {
    Error(error) ->
      fail_transport_operation(
        worker,
        diagnostic_code.ResumePreviousPath,
        error,
      )
    Ok(connection) ->
      put_peer(
        worker,
        PeerState(
          ..peer,
          connection: connection,
          candidate_path: None,
          candidate_destination_connection_id: None,
          candidate_rotated_peer_id: False,
        ),
      )
  }
}

/// Record the redacted TLS transition once, at the same event boundary that makes the connection visible to `accept`.
/// This makes the trace an exact witness of the application-visible handshake without exposing key bytes.
fn record_server_handshake_qlog(worker: Worker) -> Worker {
  case worker.established_reported, worker.peer.qlog_writer {
    False, Some(writer) -> {
      let now = udp.monotonic_millisecond()
      qlog.key_updated(writer, now, 7)
      qlog.key_updated(writer, now, 8)
      qlog.key_discarded(writer, now, 3)
      qlog.key_discarded(writer, now, 4)
      record_qlog_recovery(writer, worker.peer.connection, now)
      worker
    }
    _, _ -> worker
  }
}

/// Snapshot bounded pressure evidence after transport state changes.
/// RTT is available through the typed diagnostics API; qlog intentionally records only the window, in-flight bytes, and semantic controller phase.
fn record_qlog_recovery(
  writer: qlog.Writer,
  connection: server_transport.State,
  now: Int,
) -> Nil {
  let transport.PathSnapshot(_, _, _, _, window, flight, recovering, congested) =
    server_transport.path_stats(connection)
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

fn retry_pending_sends(worker: Worker) -> Worker {
  retry_stream_sends(worker, dict.to_list(worker.peer.streams))
}

fn retry_stream_sends(
  worker: Worker,
  streams: List(#(Int, StreamState)),
) -> Worker {
  case streams {
    [] -> worker
    [#(identifier, StreamState(pending_send: Some(pending), ..)), ..rest] ->
      retry_stream_sends(advance_send(worker, identifier, pending), rest)
    [_, ..rest] -> retry_stream_sends(worker, rest)
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
      case stream_id.can_send(identifier, stream_id.Server) {
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
  case dict.has_key(worker.completion_waiters, identifier) {
    True -> completion_reply(worker, observation, Error(ConcurrentSend))
    False ->
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
  case
    server_transport.stream_send_progress(worker.peer.connection, identifier)
  {
    Error(error) ->
      completion_reply(worker, observation, Error(map_transport_error(error)))
    Ok(progress) if progress.fin_acknowledged ->
      completion_reply(worker, observation, Ok(stream_completion.Acknowledged))
    Ok(progress) if progress.send_reset ->
      completion_reply(worker, observation, Error(StreamClosed))
    Ok(_) ->
      register_completion_owner(
        worker,
        identifier,
        owner,
        observation,
        deadline,
      )
  }
}

fn register_completion_owner(
  worker: Worker,
  identifier: Int,
  owner: Pid,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Worker {
  case
    process.is_alive(owner),
    dict.size(worker.completion_waiters) < int.min(worker.queue_limit, 256)
  {
    False, _ -> worker
    True, False ->
      completion_reply(
        worker,
        observation,
        Error(IncomingStreamQueueExceeded(int.min(worker.queue_limit, 256))),
      )
    True, True ->
      admit_completion_waiter(worker, identifier, owner, observation, deadline)
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

fn register_completion_feed_waiter(
  worker: Worker,
  after_cursor: Int,
  owner: Pid,
  observation: Observation(Result(CompletionBatch, Error)),
  deadline: Int,
) -> Worker {
  case udp.monotonic_millisecond() >= deadline {
    True -> completion_feed_reply(worker, observation, Error(OperationTimeout))
    False ->
      case stream_completion.after(worker.completions, after_cursor) {
        Error(stream_completion.HistoryOverflow(oldest)) ->
          completion_feed_reply(
            worker,
            observation,
            Error(CompletionHistoryExceeded(oldest)),
          )
        Error(stream_completion.CursorAhead(_)) ->
          completion_feed_reply(worker, observation, Error(InvalidInput))
        Ok([]) ->
          register_live_completion_feed_waiter(
            worker,
            after_cursor,
            owner,
            observation,
            deadline,
          )
        Ok(events) ->
          case
            stream_completion.publication_allowed(
              udp.monotonic_millisecond(),
              deadline,
            )
          {
            False ->
              completion_feed_reply(
                worker,
                observation,
                Error(OperationTimeout),
              )
            True ->
              completion_feed_reply(
                worker,
                observation,
                Ok(completion_batch(events, after_cursor)),
              )
          }
      }
  }
}

fn register_live_completion_feed_waiter(
  worker: Worker,
  after_cursor: Int,
  owner: Pid,
  observation: Observation(Result(CompletionBatch, Error)),
  deadline: Int,
) -> Worker {
  let worker = remove_dead_completion_feed_waiters(worker)
  case
    process.is_alive(owner),
    list.any(worker.completion_feed_waiters, fn(waiter) {
      waiter.owner == owner
    }),
    list.length(worker.completion_feed_waiters)
    >= maximum_completion_feed_waiters
  {
    False, _, _ -> worker
    True, True, _ ->
      completion_feed_reply(worker, observation, Error(ConcurrentReceive))
    True, False, True ->
      completion_feed_reply(
        worker,
        observation,
        Error(IncomingStreamQueueExceeded(maximum_completion_feed_waiters)),
      )
    True, False, False ->
      admit_completion_feed_waiter(
        worker,
        after_cursor,
        owner,
        observation,
        deadline,
      )
  }
}

fn admit_completion_feed_waiter(
  worker: Worker,
  after_cursor: Int,
  owner: Pid,
  observation: Observation(Result(CompletionBatch, Error)),
  deadline: Int,
) -> Worker {
  let worker = measure_grant(worker)
  let admission =
    budget.send_allowance(
      worker.grant,
      worker.retained_bytes,
      completion_waiter_bytes,
    )
  case
    udp.monotonic_millisecond() >= deadline,
    budget.admitted_bytes(admission) == completion_waiter_bytes
  {
    True, _ ->
      completion_feed_reply(worker, observation, Error(OperationTimeout))
    False, False ->
      completion_feed_reply(worker, observation, Error(EndpointMemoryExceeded))
    False, True -> {
      let monitor = process.monitor(owner)
      Worker(
        ..worker,
        completion_feed_waiters: [
          CompletionFeedWaiter(
            after_cursor,
            owner,
            monitor,
            observation,
            deadline,
          ),
          ..worker.completion_feed_waiters
        ],
        selector: process.select_specific_monitor(
          worker.selector,
          monitor,
          fn(_) { CompletionFeedCallerExited(observation, monitor) },
        ),
        remeasure: True,
      )
    }
  }
}

fn completion_batch(
  events: List(stream_completion.Event),
  fallback_cursor: Int,
) -> CompletionBatch {
  let cursor = case list.last(events) {
    Ok(event) -> event.cursor
    Error(Nil) -> fallback_cursor
  }
  CompletionBatch(cursor, events)
}

fn completion_feed_reply(
  worker: Worker,
  observation: Observation(Result(CompletionBatch, Error)),
  outcome: Result(CompletionBatch, Error),
) -> Worker {
  let _published = send_observation.publish(observation, outcome)
  worker
}

fn remove_completion_feed_waiter(
  worker: Worker,
  observation: Observation(Result(CompletionBatch, Error)),
) -> Worker {
  case
    list.find(worker.completion_feed_waiters, fn(waiter) {
      waiter.observation == observation
    })
  {
    Error(Nil) -> worker
    Ok(waiter) -> {
      process.demonitor_process(waiter.monitor)
      Worker(
        ..worker,
        completion_feed_waiters: list.filter(
          worker.completion_feed_waiters,
          fn(candidate) { candidate.observation != observation },
        ),
        selector: process.deselect_specific_monitor(
          worker.selector,
          waiter.monitor,
        ),
        remeasure: True,
      )
    }
  }
}

fn completion_feed_caller_exited(
  worker: Worker,
  observation: Observation(Result(CompletionBatch, Error)),
  monitor: process.Monitor,
) -> Worker {
  case
    list.any(worker.completion_feed_waiters, fn(waiter) {
      waiter.observation == observation && waiter.monitor == monitor
    })
  {
    True -> remove_completion_feed_waiter(worker, observation)
    False -> worker
  }
}

fn remove_dead_completion_feed_waiters(worker: Worker) -> Worker {
  list.fold(worker.completion_feed_waiters, worker, fn(worker, waiter) {
    case process.is_alive(waiter.owner) {
      True -> worker
      False -> remove_completion_feed_waiter(worker, waiter.observation)
    }
  })
}

fn notify_completion_feed_waiters(worker: Worker) -> Worker {
  list.fold(worker.completion_feed_waiters, worker, fn(worker, waiter) {
    case
      stream_completion.publication_allowed(
        udp.monotonic_millisecond(),
        waiter.deadline,
      )
    {
      False ->
        completion_feed_reply(
          worker,
          waiter.observation,
          Error(OperationTimeout),
        )
        |> remove_completion_feed_waiter(waiter.observation)
      True ->
        case stream_completion.after(worker.completions, waiter.after_cursor) {
          Error(stream_completion.HistoryOverflow(oldest)) ->
            completion_feed_reply(
              worker,
              waiter.observation,
              Error(CompletionHistoryExceeded(oldest)),
            )
            |> remove_completion_feed_waiter(waiter.observation)
          Error(stream_completion.CursorAhead(_)) ->
            completion_feed_reply(
              worker,
              waiter.observation,
              Error(InvalidInput),
            )
            |> remove_completion_feed_waiter(waiter.observation)
          Ok([]) -> worker
          Ok(events) ->
            completion_feed_reply(
              worker,
              waiter.observation,
              Ok(completion_batch(events, waiter.after_cursor)),
            )
            |> remove_completion_feed_waiter(waiter.observation)
        }
    }
  })
}

fn expire_completion_feed_waiters(worker: Worker, now: Int) -> Worker {
  list.fold(worker.completion_feed_waiters, worker, fn(worker, waiter) {
    case now >= waiter.deadline {
      True ->
        completion_feed_reply(
          worker,
          waiter.observation,
          Error(OperationTimeout),
        )
        |> remove_completion_feed_waiter(waiter.observation)
      False -> worker
    }
  })
}

fn fail_completion_feed_waiters(worker: Worker, error: Error) -> Worker {
  list.fold(worker.completion_feed_waiters, worker, fn(worker, waiter) {
    completion_feed_reply(worker, waiter.observation, Error(error))
    |> remove_completion_feed_waiter(waiter.observation)
  })
}

fn completion_metadata_bytes(worker: Worker) -> Int {
  stream_completion.reserved_bytes()
  + {
    dict.size(worker.completion_waiters)
    + list.length(worker.completion_feed_waiters)
  }
  * completion_waiter_bytes
}

fn admit_completion_waiter(
  worker: Worker,
  identifier: Int,
  owner: Pid,
  observation: Observation(Result(stream_completion.Outcome, Error)),
  deadline: Int,
) -> Worker {
  // Refresh a prior waiter's release before deciding whether a replacement fits.
  // No monitor or selector entry exists until its reservation is funded.
  let worker = measure_grant(worker)
  let admission =
    budget.send_allowance(
      worker.grant,
      worker.retained_bytes,
      completion_waiter_bytes,
    )
  case
    udp.monotonic_millisecond() >= deadline,
    budget.admitted_bytes(admission) == completion_waiter_bytes
  {
    True, _ -> completion_reply(worker, observation, Error(OperationTimeout))
    False, False ->
      completion_reply(worker, observation, Error(EndpointMemoryExceeded))
    False, True -> {
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
        remeasure: True,
      )
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
        remeasure: True,
      )
    }
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
      remeasure: True,
    )
  let worker = case dict.get(worker.completion_waiters, identifier) {
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
  notify_completion_feed_waiters(worker)
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

fn completion_feed_deadlines(
  deadline: Option(Int),
  waiters: List(CompletionFeedWaiter),
) -> Option(Int) {
  list.fold(waiters, deadline, fn(deadline, waiter) {
    earlier_deadline(deadline, Some(waiter.deadline))
  })
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
  let peer = case peer.stream_waiter {
    Some(StreamWaiter(reply, Some(deadline))) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      PeerState(..peer, stream_waiter: None)
    }
    _ -> peer
  }
  let peer = case peer.datagram_waiter {
    Some(DatagramWaiter(reply, Some(deadline))) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      PeerState(..peer, datagram_waiter: None)
    }
    _ -> peer
  }
  put_peer(worker, expire_stream_waiters(peer, dict.to_list(peer.streams), now))
}

/// Decision D5.
/// A send that parked ends on its own deadline, and it names what it was waiting on.
/// A send the endpoint memory grant had no room for did not merely run late: it was never going to be funded until the endpoint has room to fund it, so its caller reads a transient endpoint overload rather than a bare operation timeout.
///
/// The reason is the parked send's own rather than the connection's, and it is the grant clamp rather than a refusal that decides it.
/// A grant that was met in full still bounds what a write may take -- that is the whole of grant-before-growth on the send side -- so a write held by a met grant is held by endpoint memory just as surely as one held by a refused grant, and waiting for a refusal to say so would leave the commonest case reported as a bare timeout.
fn send_deadline_error(pending: PendingSend) -> Error {
  case pending.held_by_grant {
    True -> EndpointMemoryExceeded
    False -> OperationTimeout
  }
}

fn expire_stream_waiters(
  peer: PeerState,
  streams: List(#(Int, StreamState)),
  now: Int,
) -> PeerState {
  case streams {
    [] -> peer
    [#(identifier, stream), ..rest] -> {
      let stream = case stream.read_waiter {
        Some(ReadWaiter(_, reply, Some(deadline))) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          StreamState(..stream, read_waiter: None)
        }
        _ -> stream
      }
      let #(stream, last_send_deadline) = case stream.pending_send {
        Some(PendingSend(deadline: deadline, ..) as pending)
          if now >= deadline
        -> {
          let expired =
            send_deadline_snapshot(
              identifier,
              pending,
              udp.monotonic_millisecond(),
            )
          let _published =
            send_observation.publish(
              pending.observation,
              Error(send_deadline_error(pending)),
            )
          #(StreamState(..stream, pending_send: None), Some(expired))
        }
        _ -> #(stream, peer.last_send_deadline)
      }
      expire_stream_waiters(
        put_peer_stream(
          PeerState(..peer, last_send_deadline: last_send_deadline),
          identifier,
          stream,
        ),
        rest,
        now,
      )
    }
  }
}

fn send_deadline_snapshot(
  identifier: Int,
  pending: PendingSend,
  now: Int,
) -> SendDeadlineSnapshot {
  SendDeadlineSnapshot(
    stream_identifier: identifier,
    deadline_milliseconds: pending.deadline,
    observed_at_milliseconds: now,
    remaining_bytes: bit_array.byte_size(pending.remaining),
    held_by_grant: pending.held_by_grant,
  )
}

fn pending_send_snapshots(
  streams: List(#(Int, StreamState)),
  now: Int,
) -> List(SendDeadlineSnapshot) {
  list.filter_map(streams, fn(entry) {
    let #(identifier, stream) = entry
    case stream.pending_send {
      None -> Error(Nil)
      Some(pending) -> Ok(send_deadline_snapshot(identifier, pending, now))
    }
  })
}

/// The next moment this actor has to wake: the earliest of the transport's own deadline, the PMTU probe, and every waiter's expiry.
/// A transport that arms no deadline at all still gets one here, so `Ok(None)` -- the unbounded park -- is not representable and every wait in this loop stays bounded.
fn next_worker_deadline(worker: Worker, now: Int) -> Result(Int, Error) {
  let peer = worker.peer
  use protocol <- result.try(
    server_transport.next_deadline(peer.connection, now)
    |> result.map_error(map_transport_error),
  )
  Ok(
    None
    |> earlier_deadline(protocol)
    |> earlier_deadline(positive_deadline(peer.next_pmtu_probe_milliseconds))
    |> earlier_deadline(stream_waiter_deadline(peer.stream_waiter))
    |> earlier_deadline(datagram_waiter_deadline(peer.datagram_waiter))
    |> stream_deadlines(dict.values(peer.streams))
    |> completion_deadlines(dict.values(worker.completion_waiters))
    |> completion_feed_deadlines(worker.completion_feed_waiters)
    |> option.unwrap(now + maximum_park_milliseconds),
  )
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
          |> earlier_deadline(read_waiter_deadline(stream.read_waiter))
          |> earlier_deadline(pending_send_deadline(stream.pending_send)),
        rest,
      )
  }
}

/// Preserve the first fatal operation in qlog before the public runtime error is deliberately collapsed.
/// The code contains no peer-controlled value.
fn fail_operation(
  worker: Worker,
  operation: diagnostic_code.Operation,
  error: Error,
) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> {
      record_diagnostic_codes(worker.peer.qlog_writer, [
        diagnostic_code.operation(operation),
      ])
      fail_connection(worker, error)
    }
  }
}

/// Preserve the finite error-class chain at every internal transport layer.
fn fail_transport_operation(
  worker: Worker,
  operation: diagnostic_code.Operation,
  error: server_transport.Error,
) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> {
      record_diagnostic_codes(worker.peer.qlog_writer, [
        diagnostic_code.operation(operation),
        ..diagnostic_code.server_transport_error(error)
      ])
      fail_connection(worker, QuicFailure)
    }
  }
}

fn record_diagnostic_codes(
  writer: Option(qlog.Writer),
  codes: List(Int),
) -> Nil {
  case writer {
    None -> Nil
    Some(writer) -> {
      let now = udp.monotonic_millisecond()
      list.each(codes, fn(code) { qlog.application_error(writer, now, code) })
    }
  }
}

fn fail_connection(worker: Worker, error: Error) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> Worker(..worker, failure: Some(error))
  }
}

fn fail_peer_waiters(peer: PeerState, error: Error) -> Nil {
  case peer.stream_waiter {
    Some(StreamWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case peer.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  list.each(dict.values(peer.streams), fn(stream) {
    case stream.read_waiter {
      Some(ReadWaiter(_, reply, _)) -> process.send(reply, Error(error))
      None -> Nil
    }
    case stream.pending_send {
      Some(pending) -> {
        let _published =
          send_observation.publish(pending.observation, Error(error))
        Nil
      }
      None -> Nil
    }
  })
}

/// End this actor and release everything it owns.
/// Every waiter is failed and the qlog writer is flushed before the listener hears `Released`.
/// While the listener is alive, an autonomous or peer-led close waits for its acknowledgement.
/// That makes actor exit a completion barrier for freeing the connection ID, aliases, accept-queue slot, admission slot, and endpoint-memory reservation.
/// While waiting, the actor still selects the listener monitor and terminate commands.
/// Consequently a listener that is synchronously joining its children cannot deadlock behind the barrier.
/// Listener-led teardown relies on the existing idempotent monitor fallback.
fn shutdown(worker: Worker, error: Error, release_barrier: Bool) -> Nil {
  let _termination = shutdown_result(worker, error, release_barrier)
  Nil
}

fn shutdown_result(
  worker: Worker,
  error: Error,
  release_barrier: Bool,
) -> Result(Nil, Error) {
  let worker = fail_completion_waiters(worker, error)
  let worker = fail_completion_feed_waiters(worker, error)
  fail_peer_waiters(worker.peer, error)
  let diagnostic_result = close_qlog(worker.peer.qlog_writer)
  let acknowledged = process.new_subject()
  process.send(
    worker.notices,
    Released(worker.identifier, process.self(), acknowledged),
  )
  case release_barrier {
    True ->
      await_release_acknowledgement(worker, acknowledged, diagnostic_result)
    False -> Nil
  }
  diagnostic_result
}

/// Listener-led termination consumes the caller's existing absolute deadline.
/// The qlog writer receives only the remaining share, and a late acknowledgement is rejected even if the native close happened to finish immediately after the boundary.
fn shutdown_result_until(
  worker: Worker,
  error: Error,
  release_barrier: Bool,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  let worker = fail_completion_waiters(worker, error)
  let worker = fail_completion_feed_waiters(worker, error)
  fail_peer_waiters(worker.peer, error)
  let diagnostic_result =
    close_qlog_until(worker.peer.qlog_writer, deadline_milliseconds)
  let acknowledged = process.new_subject()
  process.send(
    worker.notices,
    Released(worker.identifier, process.self(), acknowledged),
  )
  case release_barrier {
    True ->
      await_release_acknowledgement(worker, acknowledged, diagnostic_result)
    False -> Nil
  }
  diagnostic_result
}

fn await_release_acknowledgement(
  worker: Worker,
  acknowledged: Subject(Nil),
  termination: Result(Nil, Error),
) -> Nil {
  let selector =
    worker.selector
    |> process.select_map(acknowledged, fn(_) { ReleaseAcknowledged })
  await_release_acknowledgement_loop(
    selector,
    udp.monotonic_millisecond() + worker.operation_timeout_milliseconds,
    termination,
  )
}

fn await_release_acknowledgement_loop(
  selector: process.Selector(LoopMessage),
  deadline: Int,
  termination: Result(Nil, Error),
) -> Nil {
  case
    process.selector_receive(
      selector,
      within: int.max(0, deadline - udp.monotonic_millisecond()),
    )
  {
    Ok(ReleaseAcknowledged) | Ok(ListenerExited) | Error(Nil) -> Nil
    Ok(ReceivedCommand(TerminateAndWait(_, reply))) ->
      process.send(reply, termination)
    Ok(ReceivedCommand(Terminate)) -> Nil
    // A public call that raced shutdown observes the actor exit through its monitor.
    // Internal grants and deliveries can likewise be discarded once all waiters have already been failed.
    Ok(ReceivedCommand(_))
    | Ok(CompletionCallerExited(_, _))
    | Ok(CompletionFeedCallerExited(_, _)) ->
      await_release_acknowledgement_loop(selector, deadline, termination)
  }
}

fn replay_policy(
  worker: Worker,
  now: Int,
) -> Result(resumption.ServerPolicy, resumption.Error) {
  use policy <- result.try(resumption.server_policy_with_keys(
    worker.ticket_keys,
    now,
    ticket_age_tolerance_milliseconds,
    worker.replay_cache,
  ))
  Ok(case worker.allow_zero_rtt, worker.replay_guard {
    False, _ -> resumption.reject_early_data(policy)
    True, None -> policy
    True, Some(guard) -> resumption.with_external_replay_guard(policy, guard)
  })
}

fn update_replay_cache(
  worker: Worker,
  connection: server_transport.State,
) -> Worker {
  case server_transport.replay_cache(connection) {
    Some(cache) -> Worker(..worker, replay_cache: cache)
    None -> worker
  }
}

fn update_peer_reply(
  worker: Worker,
  reply: Subject(Result(Nil, Error)),
  operation: fn(PeerState) ->
    Result(server_transport.State, server_transport.Error),
) -> Result(Worker, Nil) {
  case operation(worker.peer) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(
        put_peer(worker, PeerState(..worker.peer, connection: connection))
        |> mark_dirty,
      )
    }
  }
}

fn with_peer_reply(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  operation: fn(PeerState) -> Result(value, Error),
) -> Result(Worker, Nil) {
  process.send(reply, operation(worker.peer))
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

fn put_peer(worker: Worker, peer: PeerState) -> Worker {
  Worker(..worker, peer: peer)
}

fn mark_dirty(worker: Worker) -> Worker {
  Worker(..worker, dirty: True)
}

fn put_peer_stream(
  peer: PeerState,
  identifier: Int,
  stream: StreamState,
) -> PeerState {
  let streams = case stream_runtime_terminal(stream) {
    True -> dict.delete(peer.streams, identifier)
    False -> dict.insert(peer.streams, identifier, stream)
  }
  PeerState(..peer, streams: streams)
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
    stream_lifetime.initial_terminal_directions(stream_id.Server, identifier)
  StreamState(None, None, send_finished, receive_finished)
}

fn connection_handle(worker: Worker) -> Connection {
  Connection(
    worker.commands,
    process.self(),
    worker.operation_timeout_milliseconds,
    worker.terminal_close,
  )
}

fn incoming_stream(
  worker: Worker,
  identifier: Int,
) -> Result(IncomingStream, Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(QuicFailure)
    Ok(stream_id.StreamId(_, _, direction)) ->
      Ok(IncomingStream(
        Stream(connection_handle(worker), identifier),
        direction == stream_id.Bidirectional,
      ))
  }
}

fn candidate_send_endpoint(peer: PeerState) -> udp.Endpoint {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(endpoint, _, _)), True -> endpoint
    _, _ -> server_transport.peer(peer.connection)
  }
}

fn candidate_send_allowed(peer: PeerState, bytes: Int) -> Bool {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(_, received, sent)), True -> sent + bytes <= received * 3
    _, _ -> True
  }
}

fn record_candidate_send(peer: PeerState, bytes: Int) -> PeerState {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(endpoint, received, sent)), True ->
      PeerState(
        ..peer,
        candidate_path: Some(CandidatePath(endpoint, received, sent + bytes)),
      )
    _, _ -> peer
  }
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn close_qlog(writer: Option(qlog.Writer)) -> Result(Nil, Error) {
  case writer {
    None -> Ok(Nil)
    Some(value) -> {
      qlog.connection_closed(value, udp.monotonic_millisecond())
      case qlog.close(value) {
        Ok(Nil) -> Ok(Nil)
        Error(_) -> Error(QlogUnavailable)
      }
    }
  }
}

fn close_qlog_until(
  writer: Option(qlog.Writer),
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  use _ <- result.try(remaining_termination_milliseconds(deadline_milliseconds))
  case writer {
    None -> Ok(Nil)
    Some(value) -> {
      qlog.connection_closed(value, udp.monotonic_millisecond())
      use _ <- result.try(
        case qlog.close_confirmed_until(value, deadline_milliseconds) {
          Ok(Nil) -> Ok(Nil)
          Error(qlog.WriteFailed(6)) -> Error(OperationTimeout)
          Error(_) -> Error(QlogUnavailable)
        },
      )
      remaining_termination_milliseconds(deadline_milliseconds)
      |> result.map(fn(_) { Nil })
    }
  }
}

fn remaining_termination_milliseconds(
  deadline_milliseconds: Int,
) -> Result(Int, Error) {
  let current = udp.monotonic_millisecond()
  case
    deadline_milliseconds >= 0
    && deadline_milliseconds <= maximum_milliseconds
    && deadline_milliseconds > current
  {
    True -> Ok(deadline_milliseconds - current)
    False if deadline_milliseconds > maximum_milliseconds -> Error(InvalidInput)
    False -> Error(OperationTimeout)
  }
}

fn first_protocol(protocols: List(BitArray)) -> BitArray {
  case protocols {
    [protocol, ..] -> protocol
    [] -> <<>>
  }
}

// The queue and deadline helpers below carry no connection state.
// They are public only because the listener actor bounds its accept queue and waiters with the same primitives.

/// An empty backlog.
pub fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

/// How many values a backlog holds.
pub fn queue_count(queue: Queue(value)) -> Int {
  queue.count
}

/// Append one value to a backlog.
pub fn queue_push(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, back: [value, ..queue.back], count: queue.count + 1)
}

/// Take the oldest value from a backlog.
pub fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

/// Keep only the backlog values a predicate accepts.
pub fn queue_filter(
  queue: Queue(value),
  keep: fn(value) -> Bool,
) -> Queue(value) {
  let values = list.filter(queue_values(queue), keep)
  Queue(values, [], list.length(values))
}

/// Every backlog value in arrival order.
pub fn queue_values(queue: Queue(value)) -> List(value) {
  list.append(queue.front, list.reverse(queue.back))
}

fn take_bytes(bytes: BitArray, count: Int) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case count >= size {
    True -> #(bytes, <<>>)
    False ->
      case
        bit_array.slice(bytes, 0, count),
        bit_array.slice(bytes, count, size - count)
      {
        Ok(chunk), Ok(rest) -> #(chunk, rest)
        _, _ -> #(bytes, <<>>)
      }
  }
}

fn positive_deadline(deadline: Int) -> Option(Int) {
  case deadline > 0 {
    True -> Some(deadline)
    False -> None
  }
}

/// The earlier of two optional deadlines.
pub fn earlier_deadline(
  first: Option(Int),
  second: Option(Int),
) -> Option(Int) {
  case first, second {
    None, value | value, None -> value
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn stream_waiter_deadline(waiter: Option(StreamWaiter)) -> Option(Int) {
  case waiter {
    Some(StreamWaiter(_, deadline)) -> deadline
    None -> None
  }
}

fn datagram_waiter_deadline(waiter: Option(DatagramWaiter)) -> Option(Int) {
  case waiter {
    Some(DatagramWaiter(_, deadline)) -> deadline
    None -> None
  }
}

fn read_waiter_deadline(waiter: Option(ReadWaiter)) -> Option(Int) {
  case waiter {
    Some(ReadWaiter(_, _, deadline)) -> deadline
    None -> None
  }
}

fn pending_send_deadline(send: Option(PendingSend)) -> Option(Int) {
  case send {
    Some(PendingSend(deadline: deadline, ..)) -> Some(deadline)
    None -> None
  }
}

fn await_bootstrap(
  worker: Pid,
  ready: Subject(Connection),
  timeout: Int,
) -> Result(Connection, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(ready, Bootstrapped)
    |> process.select_specific_monitor(monitor, fn(_) { BootstrapExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(Bootstrapped(connection)) -> Ok(connection)
    Ok(BootstrapExited) -> Error(StartFailed)
    Error(Nil) -> {
      process.kill(worker)
      Error(OperationTimeout)
    }
  }
}

fn call(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  case process.is_alive(connection.worker) {
    False -> Error(closed_error(connection))
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
        Ok(WorkerExited) -> Error(closed_error(connection))
        Error(Nil) -> Error(OperationTimeout)
      }
    }
  }
}

fn call_termination_until(
  connection: Connection,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  use _ <- result.try(remaining_termination_milliseconds(deadline_milliseconds))
  case process.is_alive(connection.worker) {
    False -> Error(closed_error(connection))
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(connection.worker)
      process.send(
        connection.commands,
        TerminateAndWait(deadline_milliseconds, reply),
      )
      let selector =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
      let outcome =
        await_termination_call_until(
          selector,
          deadline_milliseconds,
          None,
          False,
        )
      process.demonitor_process(monitor)
      outcome
    }
  }
}

fn await_termination_call_until(
  selector: process.Selector(CallOutcome(Nil)),
  deadline_milliseconds: Int,
  reply: Option(Result(Nil, Error)),
  worker_down: Bool,
) -> Result(Nil, Error) {
  case reply, worker_down {
    Some(outcome), True ->
      case remaining_termination_milliseconds(deadline_milliseconds) {
        Ok(_) -> outcome
        Error(error) -> termination_timeout_result(Some(outcome), error)
      }
    _, _ ->
      case remaining_termination_milliseconds(deadline_milliseconds) {
        Error(error) -> termination_timeout_result(reply, error)
        Ok(remaining) ->
          case process.selector_receive(selector, within: remaining) {
            Ok(CallReply(outcome)) ->
              await_termination_call_until(
                selector,
                deadline_milliseconds,
                Some(outcome),
                worker_down,
              )
            Ok(WorkerExited) ->
              await_termination_call_until(
                selector,
                deadline_milliseconds,
                reply,
                True,
              )
            Error(Nil) -> termination_timeout_result(reply, OperationTimeout)
          }
      }
  }
}

fn termination_timeout_result(
  observed: Option(Result(Nil, Error)),
  timeout: Error,
) -> Result(Nil, Error) {
  case observed {
    Some(Error(error)) -> Error(error)
    Some(Ok(_)) | None -> Error(timeout)
  }
}

fn call_forever(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  case process.is_alive(connection.worker) {
    False -> Error(closed_error(connection))
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
        WorkerExited -> Error(closed_error(connection))
      }
    }
  }
}

fn closed_error(connection: Connection) -> Error {
  case terminal_close.snapshot(connection.terminal_close) {
    terminal_close.Pending
    | terminal_close.Closed(terminal_close.Application, 0) -> ConnectionClosed
    terminal_close.Closed(terminal_close.Application, code) ->
      PeerClosedWithCode(code)
    terminal_close.Closed(terminal_close.Transport, code) ->
      PeerTransportFailureWithCode(code)
    terminal_close.Closed(terminal_close.LocalTransport, code) ->
      TransportFailureWithCode(code)
  }
}

fn map_transport_error(error: server_transport.Error) -> Error {
  case error {
    server_transport.InvalidInput -> InvalidInput
    server_transport.TlsFailure(_) -> QuicFailure
    server_transport.StatelessResetFailure(_) -> QuicFailure
    server_transport.DriverFailure(error) ->
      case error {
        driver.ConnectionFailure(transport.CongestionLimited)
        | driver.ConnectionFailure(transport.PacingLimited(_))
        | driver.ConnectionFailure(transport.RecoveryLimited) ->
          CongestionLimited
        driver.ConnectionFailure(transport.DatagramNotNegotiated) ->
          DatagramsNotNegotiated
        driver.ConnectionFailure(transport.DatagramTooLarge(maximum)) ->
          DatagramTooLarge(maximum)
        driver.ConnectionFailure(transport.UnknownStream(_)) -> StreamClosed
        driver.ConnectionFailure(transport.ConnectionUnavailable) ->
          ConnectionClosed
        driver.ConnectionFailure(transport.StreamQueueFailure(error)) ->
          StreamQueueFailure(error)
        _ -> QuicFailure
      }
  }
}
