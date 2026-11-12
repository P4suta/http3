//// Typed actor owning one reusable native HTTP/3 client connection.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/failure as runtime_failure
import http3/internal/application_headers
import http3/internal/native/client_connection
import http3/internal/native/completion_deadline
import http3/internal/native/connection_state as http3_state
import http3/internal/native/datagram
import http3/internal/native/diagnostic_code
import http3/internal/native/drain
import http3/internal/native/error_code
import http3/internal/native/header_semantics
import http3/internal/native/message_stream
import http3/internal/native/orderly_close
import http3/internal/native/protocol
import http3/internal/native/terminal_registry
import http3/internal/native/ticket_store
import http3/internal/process_label
import http3/internal/qlog_admission
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/read_deadline
import quic_core.{type AddressFamily, type Version}
import quic_core/client as core_client
import quic_core/diagnostics as qlog
import quic_core/failure as core_failure

const worker_reply_grace_milliseconds = 100

const maximum_reuse_query_milliseconds = 500

const request_cancelled_code = 0x10c

const request_rejected_code = 0x10b

const excessive_load_code = 0x107

const maximum_terminal_handles = 1024

// A connection still completing Retry or TLS can receive application calls.
// Bound those callers independently of the BEAM mailbox and wake them only when an authenticated network event makes request streams available.
const maximum_pending_open_streams = 64

// Keep each HTTP DATA frame comfortably below the per-stream retained-send bound.
// Larger public chunks are advanced incrementally by the actor.
const maximum_request_data_chunk_bytes = 65_536

// The core owns ACK processing.
// While no HTTP/3 stream event is generated for a control-stream ACK, this finite wake samples the payload-free transport barrier without changing its immutable absolute deadline.
const orderly_transport_poll_milliseconds = 10

// RFC 9114's first GOAWAY is observable for a fixed interval before the final cutoff is selected.
// The interval is capped inside the caller's immutable drain deadline, so a small configured drain never becomes an unbounded wait.
const goaway_refinement_delay_milliseconds = 100

// One close owns the protocol/core transition.
// A bounded set of concurrent callers observes that same typed result instead of claiming early success.
const maximum_close_waiters = 32

const maximum_close_mailbox_scan = 64

/// A live actor reference and fixed origin policy.
pub opaque type Connection {
  Connection(
    commands: Subject(Command),
    worker: Pid,
    timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    core_close_operation_allowance_milliseconds: Int,
    hostname: String,
    port: Int,
  )
}

/// One request stream routed through its connection owner.
pub opaque type Stream {
  Stream(connection: Connection, identifier: Int)
}

/// One server-pushed response routed through its connection owner.
pub opaque type Push {
  Push(connection: Connection, identifier: Int)
}

/// A validated server push promise and its response handle.
pub type IncomingPush {
  IncomingPush(
    push: Push,
    method: String,
    path: String,
    headers: List(#(String, String)),
  )
}

/// Origin-bound TLS session resumption material.
pub opaque type ResumptionTicket {
  ResumptionTicket(
    hostname: String,
    port: Int,
    ticket: client_connection.ResumptionTicket,
    address_token: BitArray,
  )
}

/// State of the connection's explicit 0-RTT attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Outcome of an explicitly supplied TLS resumption ticket.
pub type ResumptionStatus {
  ResumptionNotAttempted
  ResumptionPending
  Resumed
  FullHandshake
}

/// Redacted client-handshake inputs and their current protocol outcome.
pub type HandshakeAttempt {
  HandshakeAttempt(
    ticket_supplied: Bool,
    zero_rtt_enabled: Bool,
    ticket_allows_zero_rtt: Bool,
    early_data: EarlyDataStatus,
    resumption: ResumptionStatus,
  )
}

/// One pull-based response event.
pub type Event {
  Informational(status: Int, headers: List(#(String, String)))
  Response(status: Int, headers: List(#(String, String)))
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent cancellation outcome.
pub type Cancellation {
  Cancelled
  AlreadyCancelled
  AlreadyCompleted
}

/// Idempotent close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Actor, transport, protocol, or bounded-buffer failure.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  OperationTimeout
  TotalTimeout
  TrustStoreFailed
  TlsHandshakeFailed
  QuicFailure
  CoreFailure(core_failure.Failure)
  RuntimeFailure(runtime_failure.Failure)
  Http3Failure
  ConcurrentSend
  ConnectionClosed
  StreamReset(Int)
  ProtocolError
  InvalidHeaderEncoding
  InvalidContentLength
  ConsumerTooSlow(Int)
  OperationQueueFull(Int)
  ResponseEventQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  ConnectionDraining
  RequestRejected
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  CapsuleProtocolUnavailable
  MigrationUnavailable
  CongestionLimited
  UnsupportedCongestionControl
  TicketUnavailable
  InvalidStoredTicket
  QlogUnavailable
  VersionNegotiationFailed
}

type Command {
  Open(
    hostname: String,
    port: Int,
    headers: List(Header),
    reply: Subject(Result(Int, Error)),
    deadline: Int,
  )
  Send(
    stream_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  SendCapsule(
    stream_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  SendTrailers(
    stream_id: Int,
    headers: List(Header),
    reply: Subject(Result(Nil, Error)),
  )
  Finish(stream_id: Int, reply: Subject(Result(Nil, Error)))
  SendCompletionHandle(
    stream_id: Int,
    reply: Subject(Result(client_connection.SendCompletionHandle, Error)),
  )
  Next(stream_id: Int, reply: Subject(Result(Event, Error)), deadline: Int)
  Cancel(stream_id: Int, reply: Subject(Result(Cancellation, Error)))
  NextPush(reply: Subject(Result(IncomingPush, Error)), deadline: Int)
  NextPushEvent(
    push_id: Int,
    reply: Subject(Result(Event, Error)),
    deadline: Int,
  )
  CancelPush(push_id: Int, reply: Subject(Result(Cancellation, Error)))
  Close(
    reply: Subject(Result(CloseResult, Error)),
    protocol_deadline_milliseconds: Int,
    completion_deadline_milliseconds: Int,
  )
  ConnectionReusable(reply: Subject(Result(Bool, Error)))
  Capabilities(reply: Subject(Result(#(Bool, Bool, Bool, Bool), Error)))
  MaximumDatagram(stream_id: Int, reply: Subject(Result(Int, Error)))
  GuaranteedDatagram(stream_id: Int, reply: Subject(Result(Int, Error)))
  SendDatagram(
    stream_id: Int,
    payload: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  NextDatagram(
    stream_id: Int,
    reply: Subject(Result(BitArray, Error)),
    deadline: Int,
  )
  SetPriority(
    stream_id: Int,
    urgency: Int,
    incremental: Bool,
    reply: Subject(Result(Nil, Error)),
  )
  GetPriority(stream_id: Int, reply: Subject(Result(#(Int, Bool), Error)))
  EarlyData(reply: Subject(Result(EarlyDataStatus, Error)))
  Resumption(reply: Subject(Result(ResumptionStatus, Error)))
  Handshake(reply: Subject(Result(HandshakeAttempt, Error)))
  Ticket(reply: Subject(Result(ResumptionTicket, Error)), deadline: Int)
  Migrate(reply: Subject(Result(Nil, Error)))
  SetCongestion(algorithm: Int, reply: Subject(Result(Nil, Error)))
  Ping(reply: Subject(Result(Nil, Error)))
  MaximumTransmissionUnit(reply: Subject(Result(Int, Error)))
  PathStats(reply: Subject(Result(qlog.PathStats, Error)))
  ConnectionStats(reply: Subject(Result(client_connection.Stats, Error)))
  ResourceStateStats(
    reply: Subject(
      Result(#(Int, Int, Int, Int, Int, Int, Int, Int, Int), Error),
    ),
  )
  TelemetryStats(reply: Subject(Result(#(Int, Int, Int), Error)))
  RecordApplicationError(code: Int)
}

type LoopMessage {
  ReceivedCommand(Command)
  ReceivedNetwork(client_connection.NetworkEvent)
  OwnerExited
}

type Waiter {
  Waiter(reply: Subject(Result(Event, Error)), deadline: Int)
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Int)
}

type TicketWaiter {
  TicketWaiter(reply: Subject(Result(ResumptionTicket, Error)), deadline: Int)
}

type PushWaiter {
  PushWaiter(reply: Subject(Result(IncomingPush, Error)), deadline: Int)
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
}

type PendingOpen {
  PendingOpen(
    headers: List(Header),
    reply: Subject(Result(Int, Error)),
    deadline: Int,
  )
}

// Two stacks provide amortized O(1) FIFO enqueue/dequeue for every peer-controlled queue, including zero-length DATA and Datagram frames.
type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
}

fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

fn queue_count(queue: Queue(value)) -> Int {
  queue.count
}

fn queue_is_empty(queue: Queue(value)) -> Bool {
  queue.count == 0
}

fn queue_push(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, back: [value, ..queue.back], count: queue.count + 1)
}

fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

fn queue_filter(queue: Queue(value), keep: fn(value) -> Bool) -> Queue(value) {
  let values = list.append(queue.front, list.reverse(queue.back))
  let values = list.filter(values, keep)
  Queue(values, [], list.length(values))
}

// Two stacks provide amortized O(1) enqueue/dequeue while preserving the order in which callers asked to open streams.
type PendingOpenQueue {
  PendingOpenQueue(
    front: List(PendingOpen),
    back: List(PendingOpen),
    count: Int,
  )
}

type StreamState {
  StreamState(
    events: Queue(Event),
    buffered_data_bytes: Int,
    waiter: Option(Waiter),
    pending_send: Option(PendingSend),
    datagrams: Queue(BitArray),
    buffered_datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    datagram_failure: Option(Error),
    capsule_candidate: Bool,
    capsule_established: Bool,
    request_finished: Bool,
    response_finished: Bool,
    cancelled: Bool,
    failure: Option(Error),
  )
}

type PushState {
  PushState(
    method: String,
    path: String,
    headers: List(#(String, String)),
    events: Queue(Event),
    buffered_data_bytes: Int,
    waiter: Option(Waiter),
    response_finished: Bool,
    delivered: Bool,
    cancelled: Bool,
    failure: Option(Error),
  )
}

type TerminalState {
  TerminalCompleted
  TerminalCancelled
  TerminalFailed(Error)
}

type Worker {
  Worker(
    connection: client_connection.State,
    streams: Dict(Int, StreamState),
    stream_terminals: terminal_registry.Registry(TerminalState),
    pushes: Dict(Int, PushState),
    push_terminals: terminal_registry.Registry(TerminalState),
    pending_pushes: Queue(Int),
    push_waiter: Option(PushWaiter),
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    pending_opens: PendingOpenQueue,
    timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    hostname: String,
    port: Int,
    http_datagrams: Bool,
    qlog_sink: Option(qlog.ApplicationSink),
    early_data_attempted: Bool,
    resumption_attempted: Bool,
    early_data_status: EarlyDataStatus,
    latest_ticket: Option(ResumptionTicket),
    latest_address_token: BitArray,
    ticket_waiter: Option(TicketWaiter),
    priorities: Dict(Int, #(Int, Bool)),
    keepalive_milliseconds: Int,
    next_keepalive_milliseconds: Int,
    core_close_operation_allowance_milliseconds: Int,
    orderly_close: Option(orderly_close.State),
    close_reply: Option(Subject(Result(CloseResult, Error))),
    close_waiters: List(Subject(Result(CloseResult, Error))),
    close_completion_deadline_milliseconds: Option(Int),
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Establish the connection in an unlinked owner-monitoring process.
pub fn connect(
  hostname: String,
  port: Int,
  address_family: AddressFamily,
  connect_address: Option(BitArray),
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  handshake_timeout_milliseconds: Int,
  timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
  ca_certificates: Option(List(BitArray)),
  http_datagrams: Bool,
  maximum_pushes: Int,
  keepalive_milliseconds: Int,
  quic_version: Version,
  qlog_directory: String,
  resumption_ticket: Option(ResumptionTicket),
  connect_port: Int,
  connect_trace: Option(qlog.ConnectTrace),
  qlog_reservation: Option(qlog_admission.Reservation),
) -> Result(Connection, Error) {
  case
    hostname != ""
    && port > 0
    && port <= 65_535
    && connect_port > 0
    && connect_port <= 65_535
    && dns_timeout_milliseconds > 0
    && connect_timeout_milliseconds > 0
    && handshake_timeout_milliseconds > 0
    && timeout_milliseconds > 0
    && operation_timeout_milliseconds > 0
    && idle_timeout_milliseconds > 0
    && drain_timeout_milliseconds > 0
    && stream_buffer_limit > 0
    && endpoint_memory_limit > 0
    && queue_limit > 0
    && telemetry_limit > 0
    && bidirectional_stream_limit > 0
    && unidirectional_stream_limit >= 3
    && frame_limit > 0
    && datagram_limit > 0
    && qpack_table_limit > 0
    && qpack_blocked_stream_limit > 0
    && maximum_pushes >= 0
    && maximum_pushes <= 1024
    && {
      keepalive_milliseconds == 0
      || { keepalive_milliseconds >= 1000 && keepalive_milliseconds <= 29_000 }
    }
  {
    False -> Error(InvalidInput)
    True -> {
      case valid_resumption_origin(resumption_ticket, hostname, port) {
        False -> Error(ResumptionOriginMismatch)
        True -> {
          let owner = process.self()
          let bootstrap = process.new_subject()
          let worker =
            process.spawn_unlinked(fn() {
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
                timeout_milliseconds,
                operation_timeout_milliseconds,
                idle_timeout_milliseconds,
                drain_timeout_milliseconds,
                stream_buffer_limit,
                endpoint_memory_limit,
                queue_limit,
                telemetry_limit,
                bidirectional_stream_limit,
                unidirectional_stream_limit,
                frame_limit,
                datagram_limit,
                qpack_table_limit,
                qpack_blocked_stream_limit,
                ca_certificates,
                http_datagrams,
                maximum_pushes,
                keepalive_milliseconds,
                quic_version,
                qlog_directory,
                resumption_ticket,
                connect_port,
                connect_trace,
                qlog_reservation,
              )
            })
          await_bootstrap(
            worker,
            bootstrap,
            timeout_milliseconds + worker_reply_grace_milliseconds,
          )
        }
      }
    }
  }
}

/// Open one request stream for this connection's fixed origin.
pub fn open_stream(
  connection: Connection,
  hostname: String,
  port: Int,
  headers: List(Header),
) -> Result(Stream, Error) {
  let deadline = now() + connection.timeout_milliseconds
  use identifier <- result.try(
    call_with_timeout(
      connection,
      connection.timeout_milliseconds + worker_reply_grace_milliseconds,
      fn(reply) { Open(hostname, port, headers, reply, deadline) },
    ),
  )
  Ok(Stream(connection, identifier))
}

/// Queue one request body chunk with synchronous actor feedback.
pub fn send_data(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let deadline = now() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Send(stream.identifier, bytes, reply, deadline) },
  )
}

/// Queue Capsule Protocol bytes only after an Extended CONNECT succeeds.
pub fn send_capsule(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let deadline = now() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { SendCapsule(stream.identifier, bytes, reply, deadline) },
  )
}

/// Queue request trailers and finish the request stream atomically.
pub fn send_trailers(
  stream: Stream,
  headers: List(Header),
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    SendTrailers(stream.identifier, headers, reply)
  })
}

/// Finish a request body.
pub fn finish(stream: Stream) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) { Finish(stream.identifier, reply) })
}

/// Wait outside the HTTP/3 actor until the request FIN is acknowledged.
///
/// The short actor call only captures the opaque core-stream capability.
/// The bounded transport wait therefore cannot stall response reads or unrelated streams on this HTTP/3 connection.
pub fn await_request_completion(stream: Stream) -> Result(Nil, Error) {
  use handle <- result.try(
    call(stream.connection, fn(reply) {
      SendCompletionHandle(stream.identifier, reply)
    }),
  )
  client_connection.await_send_completion(
    handle,
    stream.connection.timeout_milliseconds,
  )
  |> result.map_error(map_connection_error)
}

/// Queue one validated payload-free application diagnostic when qlog is on.
pub fn record_application_error(stream: Stream, code: Int) -> Nil {
  process.send(stream.connection.commands, RecordApplicationError(code))
}

/// Configured per-operation limit, without allocating a read or waiter.
@internal
pub fn operation_timeout_milliseconds(stream: Stream) -> Int {
  stream.connection.timeout_milliseconds
}

/// Pull one response event.
pub fn next_event(stream: Stream) -> Result(Event, Error) {
  let deadline = now() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Next(stream.identifier, reply, deadline) },
  )
}

/// Pull under a shared absolute deadline, with the original operation cap.
@internal
pub fn next_event_until(
  stream: Stream,
  deadline_milliseconds: Int,
) -> Result(Event, Error) {
  use #(deadline, remaining) <- result.try(
    read_deadline.plan(
      now: now(),
      deadline: deadline_milliseconds,
      operation: stream.connection.timeout_milliseconds,
    )
    |> result.replace_error(OperationTimeout),
  )
  let outcome =
    call_with_timeout(
      stream.connection,
      remaining + worker_reply_grace_milliseconds,
      fn(reply) { Next(stream.identifier, reply, deadline) },
    )
  let observed = now()
  case outcome {
    Ok(_) if observed >= deadline -> Error(OperationTimeout)
    _ -> outcome
  }
}

/// Cancel both stream directions idempotently.
pub fn cancel(stream: Stream) -> Result(Cancellation, Error) {
  call(stream.connection, fn(reply) { Cancel(stream.identifier, reply) })
}

/// Pull the next validated server push promise.
pub fn next_push(connection: Connection) -> Result(IncomingPush, Error) {
  let deadline = now() + connection.timeout_milliseconds
  call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextPush(reply, deadline) },
  )
}

/// Pull one response event for a server push.
pub fn next_push_event(push: Push) -> Result(Event, Error) {
  let deadline = now() + push.connection.timeout_milliseconds
  call_with_timeout(
    push.connection,
    push.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextPushEvent(push.identifier, reply, deadline) },
  )
}

/// Cancel one server push idempotently.
pub fn cancel_push(push: Push) -> Result(Cancellation, Error) {
  call(push.connection, fn(reply) { CancelPush(push.identifier, reply) })
}

/// Close one connection idempotently.
///
/// The finite caller wait is fixed once from the configured HTTP/3 drain, the connection-specific core actor share, the core diagnostic-close allowance,
/// and this actor's reply-only grace.
/// HTTP/3 passes the same absolute cleanup boundary through core and qlog, so no phase starts a replacement timeout.
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  close_with_budget(connection, None)
}

pub fn close_within(
  connection: Connection,
  within_milliseconds: Int,
) -> Result(CloseResult, Error) {
  close_with_budget(connection, Some(within_milliseconds))
}

fn close_with_budget(
  connection: Connection,
  budget: Option(Int),
) -> Result(CloseResult, Error) {
  case process.is_alive(connection.worker) {
    False -> Ok(AlreadyClosed)
    True -> {
      let started = now()
      case
        completion_deadline.new(
          started,
          connection.drain_timeout_milliseconds,
          connection.core_close_operation_allowance_milliseconds
            + core_client.close_completion_allowance_milliseconds(),
          worker_reply_grace_milliseconds,
        )
        |> result.try(fn(plan) {
          case budget {
            None -> Ok(plan)
            Some(milliseconds) -> completion_deadline.limit(plan, milliseconds)
          }
        })
      {
        Error(_) -> Error(OperationTimeout)
        Ok(close_plan) ->
          case
            call_until(
              connection,
              completion_deadline.caller_deadline_milliseconds(close_plan),
              fn(reply) {
                Close(
                  reply,
                  completion_deadline.protocol_deadline_milliseconds(close_plan),
                  completion_deadline.completion_deadline_milliseconds(
                    close_plan,
                  ),
                )
              },
            )
          {
            Error(ConnectionClosed) -> Ok(AlreadyClosed)
            outcome -> outcome
          }
      }
    }
  }
}

/// Query actor-owned GOAWAY and core-close state within a fixed small bound.
pub fn connection_reusable(connection: Connection) -> Result(Bool, Error) {
  call_with_timeout(
    connection,
    int.min(connection.timeout_milliseconds, maximum_reuse_query_milliseconds)
      + worker_reply_grace_milliseconds,
    ConnectionReusable,
  )
}

/// Return negotiated and explicitly enabled advanced capabilities.
pub fn capabilities(
  connection: Connection,
) -> Result(#(Bool, Bool, Bool, Bool), Error) {
  call(connection, Capabilities)
}

/// Return the largest HTTP Datagram payload for this request stream.
pub fn maximum_datagram_size(stream: Stream) -> Result(Int, Error) {
  call(stream.connection, fn(reply) {
    MaximumDatagram(stream.identifier, reply)
  })
}

/// Return the HTTP Datagram payload ceiling stable across ACK and path changes.
pub fn guaranteed_datagram_size(stream: Stream) -> Result(Int, Error) {
  call(stream.connection, fn(reply) {
    GuaranteedDatagram(stream.identifier, reply)
  })
}

/// Queue one unreliable HTTP Datagram.
pub fn send_datagram(stream: Stream, payload: BitArray) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    SendDatagram(stream.identifier, payload, reply)
  })
}

/// Pull one HTTP Datagram with one waiter per stream.
pub fn next_datagram(stream: Stream) -> Result(BitArray, Error) {
  let deadline = now() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextDatagram(stream.identifier, reply, deadline) },
  )
}

/// Set one request's RFC 9218 priority.
pub fn set_priority(
  stream: Stream,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    SetPriority(stream.identifier, urgency, incremental, reply)
  })
}

/// Return one request's effective priority.
pub fn get_priority(stream: Stream) -> Result(#(Int, Bool), Error) {
  call(stream.connection, fn(reply) { GetPriority(stream.identifier, reply) })
}

/// Return the explicit 0-RTT attempt state.
pub fn early_data_status(
  connection: Connection,
) -> Result(EarlyDataStatus, Error) {
  call(connection, EarlyData)
}

/// Return whether a supplied ticket resumed TLS or used a full handshake.
pub fn resumption_status(
  connection: Connection,
) -> Result(ResumptionStatus, Error) {
  call(connection, Resumption)
}

/// Return one bounded snapshot with no ticket, identity, endpoint, or payload.
pub fn handshake_attempt(
  connection: Connection,
) -> Result(HandshakeAttempt, Error) {
  call(connection, Handshake)
}

/// Wait for the newest origin-bound TLS ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let deadline = now() + connection.timeout_milliseconds
  call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Ticket(reply, deadline) },
  )
}

/// Encrypt all origin-bound resumption state with a caller-managed key.
pub fn export_resumption_ticket(
  ticket: ResumptionTicket,
  storage_key: BitArray,
) -> Result(BitArray, Error) {
  let ResumptionTicket(hostname, port, native, address_token) = ticket
  ticket_store.export(
    ticket_store.Stored(hostname, port, native, address_token),
    storage_key,
  )
  |> result.replace_error(InvalidStoredTicket)
}

/// Authenticate and restore caller-encrypted resumption state.
pub fn import_resumption_ticket(
  bytes: BitArray,
  storage_key: BitArray,
) -> Result(ResumptionTicket, Error) {
  use stored <- result.try(
    ticket_store.restore(bytes, storage_key)
    |> result.replace_error(InvalidStoredTicket),
  )
  let ticket_store.Stored(hostname, port, ticket, address_token) = stored
  Ok(ResumptionTicket(hostname, port, ticket, address_token))
}

/// Trigger active migration to a fresh local UDP port.
pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  call(connection, Migrate)
}

/// Change the live congestion controller by stable adapter code.
pub fn set_congestion_control(
  connection: Connection,
  algorithm: Int,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SetCongestion(algorithm, reply) })
}

/// Send a liveness PING.
pub fn ping(connection: Connection) -> Result(Nil, Error) {
  call(connection, Ping)
}

/// Return the current QUIC path MTU.
pub fn maximum_transmission_unit(connection: Connection) -> Result(Int, Error) {
  call(connection, MaximumTransmissionUnit)
}

/// Snapshot RTT and congestion state.
pub fn path_stats(connection: Connection) -> Result(qlog.PathStats, Error) {
  call(connection, PathStats)
}

/// Snapshot runtime traffic counters.
pub fn connection_stats(
  connection: Connection,
) -> Result(client_connection.Stats, Error) {
  call(connection, ConnectionStats)
}

/// Test-only payload-free snapshot of retained stream and connection state.
@internal
pub fn resource_state_stats(
  connection: Connection,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int, Int, Int), Error) {
  call(connection, ResourceStateStats)
}

/// Snapshot bounded diagnostic-writer counters.
pub fn telemetry_stats(
  connection: Connection,
) -> Result(#(Int, Int, Int), Error) {
  call(connection, TelemetryStats)
}

/// Return the underlying fixed connection for native advanced controls.
pub fn stream_connection(stream: Stream) -> Connection {
  stream.connection
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
  timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
  ca_certificates: Option(List(BitArray)),
  http_datagrams: Bool,
  maximum_pushes: Int,
  keepalive_milliseconds: Int,
  quic_version: Version,
  qlog_directory: String,
  resumption_ticket: Option(ResumptionTicket),
  connect_port: Int,
  connect_trace: Option(qlog.ConnectTrace),
  qlog_reservation: Option(qlog_admission.Reservation),
) -> Nil {
  let #(native_ticket, initial_address_token) = case resumption_ticket {
    Some(ResumptionTicket(_, _, ticket, token)) -> #(Some(ticket), token)
    None -> #(None, <<>>)
  }
  let early_data_attempted = case native_ticket {
    Some(ticket) ->
      client_connection.resumption_ticket_allows_early_data(ticket)
    None -> False
  }
  let resumption_attempted = option.is_some(native_ticket)
  let config =
    client_connection.Config(
      hostname,
      port,
      address_family,
      connect_address,
      dns_timeout_milliseconds,
      connect_timeout_milliseconds,
      handshake_timeout_milliseconds,
      timeout_milliseconds,
      idle_timeout_milliseconds,
      ca_certificates,
      http_datagrams,
      native_ticket,
      initial_address_token,
      maximum_pushes,
      quic_version,
      stream_buffer_limit,
      endpoint_memory_limit,
      bidirectional_stream_limit,
      unidirectional_stream_limit,
      frame_limit,
      datagram_limit,
      qpack_table_limit,
      qpack_blocked_stream_limit,
      telemetry_limit,
      qlog_directory,
      connect_port,
      connect_trace,
      qlog_reservation,
    )
  case client_connection.connect(config) {
    Error(error) -> process.send(bootstrap, Error(map_connection_error(error)))
    Ok(connection) ->
      case client_connection.application_diagnostics(connection) {
        Error(error) -> {
          client_connection.close(
            connection,
            error_code.runtime_greased_no_error(now()),
            "",
          )
          process.send(bootstrap, Error(map_connection_error(error)))
        }
        Ok(qlog_sink) -> {
          case qlog_sink {
            Some(writer) -> record_qlog_bootstrap(writer, now())
            None -> Nil
          }
          let commands = process.new_subject()
          let core_close_operation_allowance_milliseconds =
            client_connection.close_operation_allowance_milliseconds(connection)
          let owner_monitor = process.monitor(owner)
          let selector =
            process.new_selector()
            |> process.select_map(commands, ReceivedCommand)
            |> process.select_specific_monitor(owner_monitor, fn(_) {
              OwnerExited
            })
            |> process.select_map(
              client_connection.network_events(connection),
              ReceivedNetwork,
            )
          process.send(
            bootstrap,
            Ok(Connection(
              commands,
              process.self(),
              operation_timeout_milliseconds,
              drain_timeout_milliseconds,
              core_close_operation_allowance_milliseconds,
              hostname,
              port,
            )),
          )
          drive_and_loop(Worker(
            connection,
            dict.new(),
            terminal_registry.new(maximum_terminal_handles),
            dict.new(),
            terminal_registry.new(maximum_terminal_handles),
            queue_new(),
            None,
            commands,
            selector,
            pending_open_queue(),
            operation_timeout_milliseconds,
            drain_timeout_milliseconds,
            stream_buffer_limit,
            queue_limit,
            hostname,
            port,
            http_datagrams,
            qlog_sink,
            early_data_attempted,
            resumption_attempted,
            case early_data_attempted {
              True -> Pending
              False -> NotAttempted
            },
            None,
            initial_address_token,
            None,
            dict.new(),
            keepalive_milliseconds,
            case keepalive_milliseconds {
              0 -> 0
              interval -> now() + interval
            },
            core_close_operation_allowance_milliseconds,
            None,
            None,
            [],
            None,
          ))
        }
      }
  }
  Nil
}

fn loop(worker: Worker) -> Nil {
  let worker = dispatch_connection_events(worker)
  let current = now()
  case advance_orderly_close(worker, current) {
    Error(Nil) -> Nil
    Ok(worker) -> {
      let worker = expire_waiters(worker, current)
      let worker = retry_pending_opens(worker, current)
      let worker = maybe_queue_keepalive(worker, current)
      wait_for_work(worker, current)
    }
  }
}

fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case next_worker_deadline(worker, now) {
    Error(error) -> terminate_with_error(worker, error)
    Ok(deadline) -> {
      let received = case deadline {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(deadline) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, deadline - now),
          )
      }
      case received {
        Ok(OwnerExited) -> shutdown(worker, "owner exited")
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(worker) -> drive_and_loop(worker)
          }
        Ok(ReceivedNetwork(message)) -> receive_and_loop(worker, message)
        Error(Nil) -> drive_and_loop(worker)
      }
    }
  }
}

fn next_worker_deadline(
  worker: Worker,
  now: Int,
) -> Result(Option(Int), Error) {
  use protocol <- result.try(
    client_connection.next_deadline(worker.connection, now)
    |> result.map_error(map_connection_error),
  )
  let deadline =
    protocol
    |> earlier_deadline(positive_deadline(worker.next_keepalive_milliseconds))
    |> earlier_deadline(push_waiter_deadline(worker.push_waiter))
    |> earlier_deadline(ticket_waiter_deadline(worker.ticket_waiter))
    |> earlier_deadline(pending_open_deadline(worker.pending_opens))
    |> stream_deadlines(dict.values(worker.streams))
    |> push_deadlines(dict.values(worker.pushes))
  Ok(case worker.orderly_close {
    None -> deadline
    Some(close_state) -> {
      let deadline =
        earlier_deadline(
          deadline,
          Some(orderly_close.deadline_milliseconds(close_state)),
        )
      case orderly_close.final_goaway_queued(close_state) {
        False ->
          earlier_deadline(
            deadline,
            Some(orderly_close.refine_not_before_milliseconds(close_state)),
          )
        True ->
          earlier_deadline(
            deadline,
            Some(now + orderly_transport_poll_milliseconds),
          )
      }
    }
  })
}

fn stream_deadlines(
  deadline: Option(Int),
  streams: List(StreamState),
) -> Option(Int) {
  case streams {
    [] -> deadline
    [stream, ..rest] -> {
      let deadline =
        deadline
        |> earlier_deadline(waiter_deadline(stream.waiter))
        |> earlier_deadline(pending_send_deadline(stream.pending_send))
        |> earlier_deadline(datagram_waiter_deadline(stream.datagram_waiter))
      stream_deadlines(deadline, rest)
    }
  }
}

fn push_deadlines(
  deadline: Option(Int),
  pushes: List(PushState),
) -> Option(Int) {
  case pushes {
    [] -> deadline
    [push, ..rest] ->
      push_deadlines(
        earlier_deadline(deadline, waiter_deadline(push.waiter)),
        rest,
      )
  }
}

fn positive_deadline(deadline: Int) -> Option(Int) {
  case deadline > 0 {
    True -> Some(deadline)
    False -> None
  }
}

fn waiter_deadline(waiter: Option(Waiter)) -> Option(Int) {
  case waiter {
    Some(Waiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn pending_send_deadline(send: Option(PendingSend)) -> Option(Int) {
  case send {
    Some(PendingSend(_, _, deadline)) -> Some(deadline)
    None -> None
  }
}

fn datagram_waiter_deadline(waiter: Option(DatagramWaiter)) -> Option(Int) {
  case waiter {
    Some(DatagramWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn push_waiter_deadline(waiter: Option(PushWaiter)) -> Option(Int) {
  case waiter {
    Some(PushWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn ticket_waiter_deadline(waiter: Option(TicketWaiter)) -> Option(Int) {
  case waiter {
    Some(TicketWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn pending_open_queue() -> PendingOpenQueue {
  PendingOpenQueue([], [], 0)
}

fn pending_open_count(queue: PendingOpenQueue) -> Int {
  queue.count
}

fn pending_open_enqueue(
  queue: PendingOpenQueue,
  pending: PendingOpen,
) -> PendingOpenQueue {
  PendingOpenQueue(
    ..queue,
    back: [pending, ..queue.back],
    count: queue.count + 1,
  )
}

fn pending_open_dequeue(
  queue: PendingOpenQueue,
) -> Result(#(PendingOpen, PendingOpenQueue), Nil) {
  case queue.front, queue.back {
    [pending, ..rest], _ ->
      Ok(#(
        pending,
        PendingOpenQueue(..queue, front: rest, count: queue.count - 1),
      ))
    [], [] -> Error(Nil)
    [], back ->
      pending_open_dequeue(
        PendingOpenQueue(..queue, front: list.reverse(back), back: []),
      )
  }
}

fn pending_open_deadline(queue: PendingOpenQueue) -> Option(Int) {
  case queue.front, queue.back {
    [PendingOpen(_, _, deadline), ..], _ -> Some(deadline)
    [], [] -> None
    [], back ->
      pending_open_deadline(
        PendingOpenQueue(..queue, front: list.reverse(back), back: []),
      )
  }
}

fn earlier_deadline(first: Option(Int), second: Option(Int)) -> Option(Int) {
  case first, second {
    None, deadline | deadline, None -> deadline
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn maybe_queue_keepalive(worker: Worker, now: Int) -> Worker {
  case
    option.is_none(worker.orderly_close)
    && worker.keepalive_milliseconds > 0
    && now >= worker.next_keepalive_milliseconds
  {
    False -> worker
    True ->
      case client_connection.ping(worker.connection) {
        Error(_) -> worker
        Ok(connection) ->
          Worker(
            ..worker,
            connection: connection,
            next_keepalive_milliseconds: now + worker.keepalive_milliseconds,
          )
      }
  }
}

fn drive_and_loop(worker: Worker) -> Nil {
  case client_connection.drive(worker.connection) {
    Ok(connection) -> {
      let worker = Worker(..worker, connection: connection)
      case client_connection.activate_once(connection) {
        Error(error) ->
          terminate_with_error(worker, map_connection_error(error))
        Ok(Nil) -> worker |> retry_pending_sends |> loop
      }
    }
    Error(error) -> {
      record_connection_error(worker.qlog_sink, error)
      close_peer_protocol_failure(worker.connection, error)
      terminate_with_error(worker, map_connection_error(error))
    }
  }
}

fn receive_and_loop(
  worker: Worker,
  message: client_connection.NetworkEvent,
) -> Nil {
  case client_connection.receive_active(worker.connection, message) {
    Error(client_connection.InvalidInput) ->
      case client_connection.activate_once(worker.connection) {
        Ok(Nil) -> loop(worker)
        Error(error) ->
          terminate_with_error(worker, map_connection_error(error))
      }
    Error(error) -> {
      record_connection_error(worker.qlog_sink, error)
      close_peer_protocol_failure(worker.connection, error)
      terminate_with_error(worker, map_connection_error(error))
    }
    Ok(connection) -> {
      let worker = Worker(..worker, connection: connection)
      // ACK and MAX_STREAM_DATA input can release both congestion and stream buffer credit.
      // Retry one bounded application chunk before driving so a pending sender cannot sleep until its operation deadline when the transport itself has no earlier timer.
      // Dispatch first so a queued peer close keeps its authoritative terminal reason if the next drive fails.
      worker
      |> dispatch_connection_events
      |> retry_pending_sends
      |> drive_and_loop
    }
  }
}

fn record_connection_error(
  writer: Option(qlog.ApplicationSink),
  error: client_connection.Error,
) -> Nil {
  case writer {
    None -> Nil
    Some(writer) ->
      list.each(diagnostic_code.connection_errors(error), fn(value) {
        case qlog.application_code(value) {
          Ok(code) -> qlog.emit_application_error(writer, now(), code)
          Error(_) -> Nil
        }
      })
  }
}

fn close_peer_protocol_failure(
  connection: client_connection.State,
  error: client_connection.Error,
) -> Nil {
  case client_connection.peer_application_error_code(error) {
    Some(code) -> client_connection.close(connection, code, "")
    None -> Nil
  }
}

/// Add the authenticated HTTP/3 setup to the already funded core trace.
fn record_qlog_bootstrap(writer: qlog.ApplicationSink, now: Int) -> Nil {
  qlog.emit_http3_parameters_set(writer, now, qlog.LocalInitiator)
  qlog.emit_http3_parameters_set(writer, now, qlog.RemoteInitiator)
  qlog.emit_http3_stream_type_set(
    writer,
    now,
    quic_core.StreamId(2),
    qlog.ControlStream,
  )
  qlog.emit_http3_stream_type_set(
    writer,
    now,
    quic_core.StreamId(6),
    qlog.QpackEncoderStream,
  )
  qlog.emit_http3_stream_type_set(
    writer,
    now,
    quic_core.StreamId(10),
    qlog.QpackDecoderStream,
  )
}

fn record_http3_stream_type(
  writer: Option(qlog.ApplicationSink),
  stream_id: Int,
  stream_type: qlog.Http3StreamType,
) -> Nil {
  case writer {
    Some(writer) ->
      qlog.emit_http3_stream_type_set(
        writer,
        now(),
        quic_core.StreamId(stream_id),
        stream_type,
      )
    None -> Nil
  }
}

fn record_http3_frame_created(
  writer: Option(qlog.ApplicationSink),
  stream_id: Int,
  frame_type: qlog.Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  case writer {
    Some(writer) ->
      qlog.emit_http3_frame_created(
        writer,
        now(),
        quic_core.StreamId(stream_id),
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
}

fn record_http3_frame_parsed(
  worker: Worker,
  stream_id: Int,
  frame_type: qlog.Http3FrameType,
  payload_bytes: Int,
) -> Worker {
  case worker.qlog_sink {
    Some(writer) ->
      qlog.emit_http3_frame_parsed(
        writer,
        now(),
        quic_core.StreamId(stream_id),
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
  worker
}

fn open_request_and_reply(
  worker: Worker,
  headers: List(Header),
  reply: Subject(Result(Int, Error)),
) -> Worker {
  case
    client_connection.open_request(
      worker.connection,
      headers,
      False,
      worker.timeout_milliseconds,
    )
  {
    Error(error) -> {
      record_connection_error(worker.qlog_sink, error)
      process.send(reply, Error(map_connection_error(error)))
      worker
    }
    Ok(#(connection, identifier)) -> {
      record_http3_stream_type(worker.qlog_sink, identifier, qlog.RequestStream)
      record_http3_frame_created(
        worker.qlog_sink,
        identifier,
        qlog.HeadersFrame,
        0,
      )
      process.send(reply, Ok(identifier))
      Worker(
        ..worker,
        connection: connection,
        streams: dict.insert(
          worker.streams,
          identifier,
          new_stream_state(headers),
        ),
      )
    }
  }
}

fn retry_pending_opens(worker: Worker, now: Int) -> Worker {
  case client_connection.request_streams_available(worker.connection) {
    False -> worker
    True ->
      case pending_open_dequeue(worker.pending_opens) {
        Error(Nil) -> worker
        Ok(#(PendingOpen(headers, reply, deadline), remaining)) -> {
          let worker = Worker(..worker, pending_opens: remaining)
          let worker = case now >= deadline {
            True -> {
              process.send(reply, Error(OperationTimeout))
              worker
            }
            False -> open_request_and_reply(worker, headers, reply)
          }
          retry_pending_opens(worker, now)
        }
      }
  }
}

fn handle_orderly_close(
  worker: Worker,
  reply: Subject(Result(CloseResult, Error)),
  protocol_deadline_milliseconds: Int,
  completion_deadline_milliseconds: Int,
) -> Result(Worker, Nil) {
  case worker.close_reply {
    Some(_) -> {
      case list.length(worker.close_waiters) >= maximum_close_waiters - 1 {
        True -> {
          process.send(reply, Error(OperationTimeout))
          Ok(worker)
        }
        False ->
          Ok(Worker(..worker, close_waiters: [reply, ..worker.close_waiters]))
      }
    }
    None -> {
      let current = now()
      case
        orderly_close.refinement_not_before(
          current,
          protocol_deadline_milliseconds,
          goaway_refinement_delay_milliseconds,
        )
      {
        Error(_) ->
          finish_abortive_close(worker, reply, completion_deadline_milliseconds)
        Ok(refine_not_before) ->
          case
            orderly_close.new(
              orderly_close.Client,
              current,
              protocol_deadline_milliseconds - current,
              refine_not_before,
            )
          {
            Error(_) ->
              finish_abortive_close(
                worker,
                reply,
                completion_deadline_milliseconds,
              )
            Ok(close_state) ->
              begin_client_goaway(
                worker,
                close_state,
                reply,
                current,
                completion_deadline_milliseconds,
              )
          }
      }
    }
  }
}

fn begin_client_goaway(
  worker: Worker,
  close_state: orderly_close.State,
  reply: Subject(Result(CloseResult, Error)),
  current: Int,
  completion_deadline_milliseconds: Int,
) -> Result(Worker, Nil) {
  let initial_identifier =
    orderly_close.initial_goaway_identifier(orderly_close.Client)
  case
    orderly_close.initial_queued(close_state, initial_identifier),
    client_connection.start_drain(worker.connection, current)
  {
    Ok(#(close_state, _)), Ok(connection) ->
      Ok(
        Worker(
          ..worker,
          connection: connection,
          orderly_close: Some(close_state),
          close_reply: Some(reply),
          close_completion_deadline_milliseconds: Some(
            completion_deadline_milliseconds,
          ),
        )
        |> settle_client_application,
      )
    _, Ok(connection) ->
      finish_abortive_close(
        Worker(..worker, connection: connection),
        reply,
        completion_deadline_milliseconds,
      )
    _, Error(_) ->
      finish_abortive_close(worker, reply, completion_deadline_milliseconds)
  }
}

fn settle_client_application(worker: Worker) -> Worker {
  let worker = abort_client_streams(worker, dict.keys(worker.streams))
  let worker = cancel_client_pushes(worker, dict.keys(worker.pushes))
  fail_all_work(worker, ConnectionClosed)
}

fn abort_client_streams(worker: Worker, identifiers: List(Int)) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] -> {
      let worker = case
        client_connection.abort_stream(
          worker.connection,
          identifier,
          request_cancelled_code,
        )
      {
        Error(_) -> worker
        Ok(connection) -> Worker(..worker, connection: connection)
      }
      abort_client_streams(worker, rest)
    }
  }
}

fn cancel_client_pushes(worker: Worker, identifiers: List(Int)) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] -> {
      let worker = case
        client_connection.cancel_push(worker.connection, identifier)
      {
        Error(_) -> worker
        Ok(connection) -> Worker(..worker, connection: connection)
      }
      cancel_client_pushes(worker, rest)
    }
  }
}

fn advance_orderly_close(worker: Worker, current: Int) -> Result(Worker, Nil) {
  case worker.orderly_close, client_connection.terminated(worker.connection) {
    None, _ -> Ok(worker)
    Some(_), True -> finish_pending_abortive_close(worker)
    Some(close_state), False ->
      case refine_client_goaway(worker, close_state, current) {
        Error(Nil) -> Error(Nil)
        Ok(worker) ->
          case worker.orderly_close {
            None -> finish_pending_abortive_close(worker)
            Some(close_state) ->
              observe_client_orderly_close(worker, close_state, current)
          }
      }
  }
}

fn observe_client_orderly_close(
  worker: Worker,
  close_state: orderly_close.State,
  current: Int,
) -> Result(Worker, Nil) {
  case orderly_close.final_goaway_queued(close_state) {
    False -> Ok(worker)
    True -> {
      let application_settled = client_application_settled(worker)
      let transport_flushed = case application_settled {
        False -> False
        True ->
          client_connection.application_send_settled(worker.connection)
          == Ok(True)
      }
      case
        orderly_close.observe(
          close_state,
          current,
          application_settled,
          transport_flushed,
        )
      {
        Error(_) | Ok(orderly_close.Abort(_, _)) ->
          finish_pending_abortive_close(worker)
        Ok(orderly_close.Continue(close_state, _)) ->
          Ok(Worker(..worker, orderly_close: Some(close_state)))
        Ok(orderly_close.Close(close_state, step)) ->
          case step {
            orderly_close.CloseWithNoError(code) ->
              finish_orderly_close(worker, close_state, code)
            _ -> finish_pending_abortive_close(worker)
          }
      }
    }
  }
}

fn refine_client_goaway(
  worker: Worker,
  close_state: orderly_close.State,
  current: Int,
) -> Result(Worker, Nil) {
  case
    orderly_close.final_goaway_queued(close_state),
    current < orderly_close.refine_not_before_milliseconds(close_state)
  {
    True, _ | False, True -> Ok(worker)
    False, False ->
      case
        orderly_close.final_queued(close_state, 0, current),
        client_connection.refine_drain(worker.connection, 0)
      {
        Ok(#(close_state, _)), Ok(#(connection, _rejected)) ->
          Ok(
            Worker(
              ..worker,
              connection: connection,
              orderly_close: Some(close_state),
            ),
          )
        _, _ -> finish_pending_abortive_close(worker)
      }
  }
}

fn client_application_settled(worker: Worker) -> Bool {
  pending_open_count(worker.pending_opens) == 0
  && option.is_none(worker.push_waiter)
  && list.all(dict.values(worker.streams), fn(stream) {
    option.is_some(stream.failure)
    || stream.cancelled
    || stream.request_finished
    && stream.response_finished
  })
  && list.all(dict.values(worker.pushes), fn(push) {
    option.is_some(push.failure) || push.cancelled || push.response_finished
  })
}

fn finish_orderly_close(
  worker: Worker,
  close_state: orderly_close.State,
  code: Int,
) -> Result(Worker, Nil) {
  case client_connection.close_drained(worker.connection) {
    Error(_) -> finish_pending_abortive_close(worker)
    Ok(connection) -> {
      let outcome =
        close_worker_connection_until(
          Worker(..worker, connection: connection),
          code,
        )
        |> result.map(fn(_) { Closed })
        |> result.map_error(map_connection_error)
      notify_close_replies(worker, outcome)
      case outcome {
        Ok(_) -> {
          let _closed = orderly_close.confirm_closed(close_state, code)
          Nil
        }
        Error(_) -> Nil
      }
      Error(Nil)
    }
  }
}

fn finish_pending_abortive_close(worker: Worker) -> Result(Worker, Nil) {
  let worker = fail_all_work(worker, ConnectionClosed)
  let outcome =
    close_worker_connection_until(
      worker,
      error_code.runtime_greased_no_error(now()),
    )
    |> result.map(fn(_) { Closed })
    |> result.map_error(map_connection_error)
  notify_close_replies(worker, outcome)
  Error(Nil)
}

fn finish_abortive_close(
  worker: Worker,
  reply: Subject(Result(CloseResult, Error)),
  completion_deadline_milliseconds: Int,
) -> Result(Worker, Nil) {
  // Publish this first close attempt in state before entering the synchronous core join.
  // A concurrent Close can then either join through handle_command or be collected from the bounded mailbox prefix immediately before exit.
  let worker =
    Worker(
      ..worker,
      close_reply: Some(reply),
      close_completion_deadline_milliseconds: Some(
        completion_deadline_milliseconds,
      ),
    )
    |> fail_all_work(ConnectionClosed)
  let outcome =
    client_connection.close_result_until(
      worker.connection,
      error_code.runtime_greased_no_error(now()),
      completion_deadline_milliseconds,
    )
    |> result.map(fn(_) { Closed })
    |> result.map_error(map_connection_error)
  notify_close_replies(worker, outcome)
  Error(Nil)
}

fn close_worker_connection_until(
  worker: Worker,
  application_error_code: Int,
) -> Result(Nil, client_connection.Error) {
  case worker.close_completion_deadline_milliseconds {
    Some(deadline_milliseconds) ->
      client_connection.close_result_until(
        worker.connection,
        application_error_code,
        deadline_milliseconds,
      )
    // This state is not constructed by the close command.
    // Treat corruption as an incomplete bounded close and let the dying actor's core monitor own final cleanup; never invent a fresh relative timeout here.
    None -> Error(client_connection.OperationTimeout)
  }
}

fn notify_close_replies(
  worker: Worker,
  outcome: Result(CloseResult, Error),
) -> Nil {
  let replies = case worker.close_reply {
    None -> worker.close_waiters
    Some(reply) -> [reply, ..worker.close_waiters]
  }
  let remaining_waiters = maximum_close_waiters - list.length(replies)
  let replies =
    collect_queued_close_replies(
      worker.commands,
      replies,
      remaining_waiters,
      maximum_close_mailbox_scan,
    )
  list.each(replies, fn(reply) { process.send(reply, outcome) })
}

/// The HTTP/3 actor can be synchronously inside the core completion call when another close arrives.
/// Drain only a finite mailbox prefix before exit so those callers share the first outcome without making teardown unbounded.
fn collect_queued_close_replies(
  commands: Subject(Command),
  replies: List(Subject(Result(CloseResult, Error))),
  remaining_waiters: Int,
  remaining_scan: Int,
) -> List(Subject(Result(CloseResult, Error))) {
  case remaining_waiters <= 0 || remaining_scan <= 0 {
    True -> replies
    False ->
      case process.receive(commands, within: 0) {
        Error(Nil) -> replies
        Ok(Close(reply, _, _)) ->
          collect_queued_close_replies(
            commands,
            [reply, ..replies],
            remaining_waiters - 1,
            remaining_scan - 1,
          )
        Ok(_) ->
          collect_queued_close_replies(
            commands,
            replies,
            remaining_waiters,
            remaining_scan - 1,
          )
      }
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    Open(hostname, port, headers, reply, deadline) -> {
      case
        hostname == worker.hostname && port == worker.port,
        unsafe_early_method(worker.early_data_attempted, headers)
      {
        False, _ -> {
          process.send(reply, Error(OriginMismatch))
          Ok(worker)
        }
        True, Some(method) -> {
          process.send(reply, Error(UnsafeEarlyDataMethod(method)))
          Ok(worker)
        }
        True, None ->
          case
            client_connection.request_streams_available(worker.connection),
            pending_open_count(worker.pending_opens)
          {
            True, _ -> Ok(open_request_and_reply(worker, headers, reply))
            False, count if count >= maximum_pending_open_streams -> {
              process.send(
                reply,
                Error(OperationQueueFull(maximum_pending_open_streams)),
              )
              Ok(worker)
            }
            False, _ ->
              Ok(
                Worker(
                  ..worker,
                  pending_opens: pending_open_enqueue(
                    worker.pending_opens,
                    PendingOpen(headers, reply, deadline),
                  ),
                ),
              )
          }
      }
    }
    Send(identifier, bytes, reply, deadline) ->
      handle_send(worker, identifier, bytes, reply, deadline)
    SendCapsule(identifier, bytes, reply, deadline) ->
      handle_send_capsule(worker, identifier, bytes, reply, deadline)
    SendTrailers(identifier, headers, reply) ->
      update_stream(worker, identifier, reply, fn(worker, stream) {
        case stream.cancelled, stream.request_finished, stream.pending_send {
          True, _, _ -> Error(StreamCancelled)
          _, True, _ -> Error(RequestAlreadyFinished)
          False, False, Some(_) -> Error(ConcurrentSend)
          False, False, None ->
            client_connection.finish_with_trailers(
              worker.connection,
              identifier,
              headers,
            )
            |> result.map(fn(connection) {
              record_http3_frame_created(
                worker.qlog_sink,
                identifier,
                qlog.HeadersFrame,
                0,
              )
              #(
                Worker(..worker, connection: connection),
                StreamState(..stream, request_finished: True),
                Nil,
              )
            })
            |> result.map_error(map_connection_error)
        }
      })
    Finish(identifier, reply) ->
      case
        dict.has_key(worker.streams, identifier),
        stream_terminal_error(worker, identifier)
      {
        // `fail_stream` may already have compacted a GOAWAY-rejected stream into the finite terminal registry.
        // Preserve the same empty-FIN race contract in both the live and compacted representations.
        False, RequestRejected -> {
          process.send(reply, Ok(Nil))
          Ok(worker)
        }
        _, _ ->
          update_stream(worker, identifier, reply, fn(worker, stream) {
            case stream.request_finished, stream.failure {
              True, _ -> Error(RequestAlreadyFinished)
              // A GOAWAY race can reject the stream after open but before its empty FIN command is handled.
              // The FIN was already semantically committed by the caller; preserve that success and expose the authoritative rejection through `next_event`.
              False, Some(RequestRejected) ->
                Ok(#(worker, StreamState(..stream, request_finished: True), Nil))
              False, _ ->
                case stream.cancelled, stream.pending_send {
                  True, _ -> Error(StreamCancelled)
                  False, Some(_) -> Error(ConcurrentSend)
                  False, None ->
                    client_connection.finish_stream(
                      worker.connection,
                      identifier,
                    )
                    |> result.map(fn(connection) {
                      #(
                        Worker(..worker, connection: connection),
                        StreamState(..stream, request_finished: True),
                        Nil,
                      )
                    })
                    |> result.map_error(map_connection_error)
                }
            }
          })
      }
    SendCompletionHandle(identifier, reply) -> {
      let outcome = case dict.has_key(worker.streams, identifier) {
        False -> Error(stream_terminal_error(worker, identifier))
        True ->
          client_connection.send_completion_handle(
            worker.connection,
            identifier,
          )
          |> result.map_error(map_connection_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    Next(identifier, reply, deadline) ->
      case deadline <= now() {
        True -> {
          process.send(reply, Error(OperationTimeout))
          Ok(worker)
        }
        False ->
          case dict.get(worker.streams, identifier) {
            Error(_) -> {
              process.send(
                reply,
                Error(stream_terminal_error(worker, identifier)),
              )
              Ok(worker)
            }
            Ok(stream) ->
              handle_next(worker, identifier, stream, reply, deadline)
          }
      }
    Cancel(identifier, reply) -> handle_cancel(worker, identifier, reply)
    NextPush(reply, deadline) -> handle_next_push(worker, reply, deadline)
    NextPushEvent(identifier, reply, deadline) ->
      handle_next_push_event(worker, identifier, reply, deadline)
    CancelPush(identifier, reply) ->
      handle_cancel_push(worker, identifier, reply)
    Close(reply, protocol_deadline, completion_deadline) ->
      handle_orderly_close(
        worker,
        reply,
        protocol_deadline,
        completion_deadline,
      )
    ConnectionReusable(reply) -> {
      process.send(
        reply,
        Ok(client_connection.connection_reusable(worker.connection)),
      )
      Ok(worker)
    }
    Capabilities(reply) -> {
      process.send(
        reply,
        Ok(#(
          client_connection.datagrams_available(worker.connection),
          client_connection.active_migration_available(worker.connection),
          worker.early_data_attempted,
          option.is_some(worker.qlog_sink),
        )),
      )
      Ok(worker)
    }
    MaximumDatagram(identifier, reply) -> {
      process.send(reply, case dict.has_key(worker.streams, identifier) {
        False -> Error(StreamFinished)
        True ->
          client_connection.maximum_http_datagram_size(
            worker.connection,
            identifier,
          )
          |> result.map_error(map_connection_error)
      })
      Ok(worker)
    }
    GuaranteedDatagram(identifier, reply) -> {
      process.send(reply, case dict.has_key(worker.streams, identifier) {
        False -> Error(StreamFinished)
        True ->
          client_connection.guaranteed_http_datagram_size(
            worker.connection,
            identifier,
          )
          |> result.map_error(map_connection_error)
      })
      Ok(worker)
    }
    SendDatagram(identifier, payload, reply) ->
      handle_send_datagram(worker, identifier, payload, reply)
    NextDatagram(identifier, reply, deadline) ->
      handle_next_datagram(worker, identifier, reply, deadline)
    SetPriority(identifier, urgency, incremental, reply) ->
      handle_set_priority(worker, identifier, urgency, incremental, reply)
    GetPriority(identifier, reply) -> {
      let outcome = case dict.has_key(worker.streams, identifier) {
        False -> Error(StreamFinished)
        True ->
          Ok(
            dict.get(worker.priorities, identifier)
            |> result.unwrap(#(3, False)),
          )
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    EarlyData(reply) -> {
      // The generic core actor can finish accepting or rejecting 0-RTT while this HTTP actor is otherwise idle.
      // Refresh its bounded semantic events before answering a synchronous status query.
      let worker = dispatch_connection_events(worker)
      let status = case client_connection.early_data_status(worker.connection) {
        qlog.NotAttempted -> NotAttempted
        qlog.Pending -> Pending
        qlog.Accepted -> Accepted
        qlog.Rejected -> Rejected
      }
      process.send(reply, Ok(status))
      Ok(Worker(..worker, early_data_status: status))
    }
    Resumption(reply) -> {
      let status = case
        worker.resumption_attempted,
        client_connection.handshake_established(worker.connection)
      {
        False, _ -> ResumptionNotAttempted
        True, False -> ResumptionPending
        True, True ->
          case client_connection.resumed(worker.connection) {
            True -> Resumed
            False -> FullHandshake
          }
      }
      process.send(reply, Ok(status))
      Ok(worker)
    }
    Handshake(reply) -> {
      let worker = dispatch_connection_events(worker)
      let outcome = case
        client_connection.handshake_attempt(worker.connection)
      {
        Error(error) -> Error(map_connection_error(error))
        Ok(qlog.HandshakeAttempt(
          ticket_supplied,
          zero_rtt_enabled,
          ticket_allows_zero_rtt,
          early,
          resumption,
        )) ->
          Ok(
            HandshakeAttempt(
              ticket_supplied:,
              zero_rtt_enabled:,
              ticket_allows_zero_rtt:,
              early_data: case early {
                qlog.NotAttempted -> NotAttempted
                qlog.Pending -> Pending
                qlog.Accepted -> Accepted
                qlog.Rejected -> Rejected
              },
              resumption: case resumption {
                qlog.ResumptionNotAttempted -> ResumptionNotAttempted
                qlog.ResumptionPending -> ResumptionPending
                qlog.Resumed -> Resumed
                qlog.FullHandshake -> FullHandshake
              },
            ),
          )
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    Ticket(reply, deadline) -> handle_ticket(worker, reply, deadline)
    Migrate(reply) -> {
      case client_connection.migrate(worker.connection) {
        Error(error) -> {
          process.send(reply, Error(map_connection_error(error)))
          Ok(worker)
        }
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
        }
      }
    }
    SetCongestion(algorithm, reply) ->
      handle_set_congestion(worker, algorithm, reply)
    Ping(reply) ->
      case client_connection.ping(worker.connection) {
        Error(error) -> {
          process.send(reply, Error(map_connection_error(error)))
          Ok(worker)
        }
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
        }
      }
    MaximumTransmissionUnit(reply) -> {
      process.send(reply, Ok(client_connection.path_mtu(worker.connection)))
      Ok(worker)
    }
    PathStats(reply) -> {
      process.send(reply, Ok(client_connection.path_stats(worker.connection)))
      Ok(worker)
    }
    ConnectionStats(reply) -> {
      process.send(reply, Ok(client_connection.stats(worker.connection)))
      Ok(worker)
    }
    ResourceStateStats(reply) -> {
      let outcome =
        client_connection.resource_stats(worker.connection)
        |> result.map(fn(resources) {
          let #(
            core_handles,
            runtime_handles,
            transport_streams,
            protocol_inputs,
            transactions,
            push_transactions,
            blocked_streams,
          ) = resources
          #(
            dict.size(worker.streams),
            terminal_registry.size(worker.stream_terminals),
            core_handles,
            runtime_handles,
            transport_streams,
            protocol_inputs,
            transactions,
            push_transactions,
            blocked_streams,
          )
        })
        |> result.map_error(map_connection_error)
      process.send(reply, outcome)
      Ok(worker)
    }
    TelemetryStats(reply) -> {
      process.send(
        reply,
        client_connection.telemetry_stats(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    RecordApplicationError(code) -> {
      case worker.qlog_sink, qlog.application_code(code) {
        Some(sink), Ok(code) -> qlog.emit_application_error(sink, now(), code)
        _, _ -> Nil
      }
      Ok(worker)
    }
  }
}

fn handle_next(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  reply: Subject(Result(Event, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case queue_pop(stream.events) {
    Ok(#(event, rest)) -> {
      process.send(reply, Ok(event))
      let buffered = case event {
        Data(bytes) -> stream.buffered_data_bytes - bit_array.byte_size(bytes)
        _ -> stream.buffered_data_bytes
      }
      Ok(put_stream(
        worker,
        identifier,
        StreamState(..stream, events: rest, buffered_data_bytes: buffered),
      ))
    }
    Error(Nil) ->
      case stream.failure, stream.cancelled, stream.response_finished {
        Some(error), _, _ -> {
          process.send(reply, Error(error))
          Ok(worker)
        }
        None, True, _ -> {
          process.send(reply, Error(StreamCancelled))
          Ok(worker)
        }
        None, False, True -> {
          process.send(reply, Error(StreamFinished))
          Ok(worker)
        }
        None, False, False ->
          case stream.waiter {
            Some(_) -> {
              process.send(reply, Error(ConcurrentReceive))
              Ok(worker)
            }
            None ->
              Ok(put_stream(
                worker,
                identifier,
                StreamState(..stream, waiter: Some(Waiter(reply, deadline))),
              ))
          }
      }
  }
}

fn handle_next_push(
  worker: Worker,
  reply: Subject(Result(IncomingPush, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case queue_pop(worker.pending_pushes), worker.push_waiter {
    Ok(#(identifier, rest)), _ -> {
      process.send(reply, incoming_push(worker, identifier))
      Ok(mark_push_delivered(Worker(..worker, pending_pushes: rest), identifier))
    }
    Error(Nil), Some(_) -> {
      process.send(reply, Error(ConcurrentReceive))
      Ok(worker)
    }
    Error(Nil), None ->
      Ok(Worker(..worker, push_waiter: Some(PushWaiter(reply, deadline))))
  }
}

fn handle_next_push_event(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Event, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> {
      process.send(reply, Error(push_terminal_error(worker, identifier)))
      Ok(worker)
    }
    Ok(push) ->
      case push.delivered {
        False -> {
          process.send(reply, Error(ProtocolError))
          Ok(worker)
        }
        True ->
          case queue_pop(push.events) {
            Ok(#(event, rest)) -> {
              process.send(reply, Ok(event))
              let buffered = case event {
                Data(bytes) ->
                  push.buffered_data_bytes - bit_array.byte_size(bytes)
                _ -> push.buffered_data_bytes
              }
              Ok(put_push(
                worker,
                identifier,
                PushState(
                  ..push,
                  events: rest,
                  buffered_data_bytes: int.max(buffered, 0),
                ),
              ))
            }
            Error(Nil) ->
              case push.failure, push.cancelled, push.response_finished {
                Some(error), _, _ -> {
                  process.send(reply, Error(error))
                  Ok(worker)
                }
                None, True, _ -> {
                  process.send(reply, Error(StreamCancelled))
                  Ok(worker)
                }
                None, False, True -> {
                  process.send(reply, Error(StreamFinished))
                  Ok(worker)
                }
                None, False, False ->
                  case push.waiter {
                    Some(_) -> {
                      process.send(reply, Error(ConcurrentReceive))
                      Ok(worker)
                    }
                    None ->
                      Ok(put_push(
                        worker,
                        identifier,
                        PushState(..push, waiter: Some(Waiter(reply, deadline))),
                      ))
                  }
              }
          }
      }
  }
}

fn handle_cancel_push(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> {
      process.send(
        reply,
        Ok(terminal_cancellation(worker.push_terminals, identifier)),
      )
      Ok(worker)
    }
    Ok(push) ->
      case push.cancelled, push.response_finished {
        True, _ -> {
          process.send(reply, Ok(AlreadyCancelled))
          Ok(worker)
        }
        False, True -> {
          process.send(reply, Ok(AlreadyCompleted))
          Ok(worker)
        }
        False, False ->
          case client_connection.cancel_push(worker.connection, identifier) {
            Error(error) -> {
              process.send(reply, Error(map_connection_error(error)))
              Ok(worker)
            }
            Ok(connection) -> {
              notify_waiter(push.waiter, Error(StreamCancelled))
              process.send(reply, Ok(Cancelled))
              Ok(put_push(
                Worker(
                  ..worker,
                  connection: connection,
                  pending_pushes: queue_filter(worker.pending_pushes, fn(value) {
                    value != identifier
                  }),
                ),
                identifier,
                PushState(
                  ..push,
                  events: queue_new(),
                  buffered_data_bytes: 0,
                  waiter: None,
                  cancelled: True,
                ),
              ))
            }
          }
      }
  }
}

fn handle_send_datagram(
  worker: Worker,
  identifier: Int,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  let payload_size = bit_array.byte_size(payload)
  let outcome = case
    dict.has_key(worker.streams, identifier),
    bit_array.bit_size(payload) % 8 == 0
  {
    False, _ -> Error(StreamFinished)
    _, False -> Error(InvalidInput)
    True, True ->
      case
        client_connection.maximum_http_datagram_size(
          worker.connection,
          identifier,
        )
      {
        Error(error) -> Error(map_connection_error(error))
        Ok(maximum) if payload_size > maximum -> Error(DatagramTooLarge(maximum))
        Ok(_) ->
          client_connection.send_http_datagram(
            worker.connection,
            identifier,
            payload,
          )
          |> result.map(fn(connection) {
            Worker(..worker, connection: connection)
          })
          |> result.map_error(map_connection_error)
      }
  }
  case outcome {
    Error(error) -> {
      process.send(reply, Error(error))
      Ok(worker)
    }
    Ok(worker) -> {
      process.send(reply, Ok(Nil))
      Ok(worker)
    }
  }
}

fn handle_next_datagram(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(BitArray, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(reply, Error(stream_terminal_error(worker, identifier)))
      Ok(worker)
    }
    Ok(stream) ->
      case client_connection.datagrams_available(worker.connection) {
        False -> {
          process.send(reply, Error(DatagramsNotNegotiated))
          Ok(worker)
        }
        True ->
          case queue_pop(stream.datagrams) {
            Ok(#(datagram, rest)) -> {
              process.send(reply, Ok(datagram))
              Ok(put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagrams: rest,
                  buffered_datagram_bytes: stream.buffered_datagram_bytes
                    - bit_array.byte_size(datagram),
                ),
              ))
            }
            Error(Nil) ->
              case stream.datagram_failure, stream.datagram_waiter {
                Some(error), _ -> {
                  process.send(reply, Error(error))
                  Ok(worker)
                }
                None, Some(_) -> {
                  process.send(reply, Error(ConcurrentDatagramReceive))
                  Ok(worker)
                }
                None, None ->
                  Ok(put_stream(
                    worker,
                    identifier,
                    StreamState(
                      ..stream,
                      datagram_waiter: Some(DatagramWaiter(reply, deadline)),
                    ),
                  ))
              }
          }
      }
  }
}

fn handle_set_priority(
  worker: Worker,
  identifier: Int,
  urgency: Int,
  incremental: Bool,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.has_key(worker.streams, identifier), urgency >= 0 && urgency <= 7 {
    False, _ -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    _, False -> {
      process.send(reply, Error(InvalidInput))
      Ok(worker)
    }
    True, True ->
      case
        client_connection.set_request_priority(
          worker.connection,
          identifier,
          urgency,
          incremental,
        )
      {
        Error(error) -> {
          process.send(reply, Error(map_connection_error(error)))
          Ok(worker)
        }
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(
            Worker(
              ..worker,
              connection: connection,
              priorities: dict.insert(worker.priorities, identifier, #(
                urgency,
                incremental,
              )),
            ),
          )
        }
      }
  }
}

fn handle_ticket(
  worker: Worker,
  reply: Subject(Result(ResumptionTicket, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case worker.latest_ticket, worker.ticket_waiter {
    Some(ticket), _ -> {
      process.send(reply, Ok(ticket))
      Ok(worker)
    }
    None, Some(_) -> {
      process.send(reply, Error(ConcurrentReceive))
      Ok(worker)
    }
    None, None ->
      Ok(Worker(..worker, ticket_waiter: Some(TicketWaiter(reply, deadline))))
  }
}

fn handle_set_congestion(
  worker: Worker,
  algorithm: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  let algorithm = case algorithm {
    1 -> Ok(client_connection.NewReno)
    2 -> Ok(client_connection.Cubic)
    _ -> Error(UnsupportedCongestionControl)
  }
  case algorithm {
    Error(error) -> {
      process.send(reply, Error(error))
      Ok(worker)
    }
    Ok(algorithm) ->
      case
        client_connection.set_congestion_algorithm(worker.connection, algorithm)
      {
        Error(error) -> {
          process.send(reply, Error(map_connection_error(error)))
          Ok(worker)
        }
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
        }
      }
  }
}

fn handle_send(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(reply, Error(stream_terminal_error(worker, identifier)))
      Ok(worker)
    }
    Ok(stream) ->
      case stream.cancelled, stream.request_finished, stream.pending_send {
        True, _, _ -> {
          process.send(reply, Error(StreamCancelled))
          Ok(worker)
        }
        _, True, _ -> {
          process.send(reply, Error(RequestAlreadyFinished))
          Ok(worker)
        }
        False, False, Some(_) -> {
          process.send(reply, Error(ConcurrentSend))
          Ok(worker)
        }
        False, False, None ->
          advance_send(
            worker,
            identifier,
            stream,
            PendingSend(bytes, reply, deadline),
          )
      }
  }
}

fn handle_send_capsule(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(reply, Error(stream_terminal_error(worker, identifier)))
      Ok(worker)
    }
    Ok(StreamState(capsule_established: False, ..)) -> {
      process.send(reply, Error(CapsuleProtocolUnavailable))
      Ok(worker)
    }
    Ok(_) -> handle_send(worker, identifier, bytes, reply, deadline)
  }
}

fn advance_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  pending: PendingSend,
) -> Result(Worker, Nil) {
  let PendingSend(remaining, reply, deadline) = pending
  case now() >= deadline {
    True -> {
      process.send(reply, Error(OperationTimeout))
      Ok(put_stream(
        worker,
        identifier,
        StreamState(..stream, pending_send: None),
      ))
    }
    False -> {
      let #(chunk, rest) = take_send_chunk(remaining)
      case client_connection.send_data(worker.connection, identifier, chunk) {
        Ok(connection) -> {
          record_http3_frame_created(
            worker.qlog_sink,
            identifier,
            qlog.DataFrame,
            bit_array.byte_size(chunk),
          )
          case bit_array.byte_size(rest) {
            0 -> {
              process.send(reply, Ok(Nil))
              Ok(put_stream(
                Worker(..worker, connection: connection),
                identifier,
                StreamState(..stream, pending_send: None),
              ))
            }
            _ -> {
              // Continue while the public core accepts bounded data.
              // The core is the authority for transport/flow-control pressure; pausing here after every application chunk can leave both HTTP actors waiting even though the core still has granted buffer space.
              // Once the core reports pressure, the error branch below keeps this finite remainder for ACK/MAX_STREAM_DATA progress.
              let pending = PendingSend(rest, reply, deadline)
              let worker = Worker(..worker, connection: connection)
              let stream = StreamState(..stream, pending_send: Some(pending))
              advance_send(
                put_stream(worker, identifier, stream),
                identifier,
                stream,
                pending,
              )
            }
          }
        }
        Error(error) ->
          case send_buffer_full(error) {
            True ->
              Ok(put_stream(
                worker,
                identifier,
                StreamState(..stream, pending_send: Some(pending)),
              ))
            False -> {
              process.send(reply, Error(map_connection_error(error)))
              Ok(put_stream(
                worker,
                identifier,
                StreamState(..stream, pending_send: None),
              ))
            }
          }
      }
    }
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
    [#(identifier, stream), ..rest] -> {
      let worker = case stream.pending_send {
        None -> worker
        Some(pending) ->
          case advance_send(worker, identifier, stream, pending) {
            Ok(worker) -> worker
            Error(Nil) -> worker
          }
      }
      retry_pending_send_entries(worker, rest)
    }
  }
}

/// Split off one chunk, or return everything when a whole chunk is not there.
///
/// The split is a pattern rather than a measured slice: a payload shorter than one chunk simply has no matching clause, so the short case is the fallback instead of a length comparison guarding two slices that must not fail.
fn take_send_chunk(bytes: BitArray) -> #(BitArray, BitArray) {
  case bytes {
    <<chunk:bytes-size(maximum_request_data_chunk_bytes), rest:bits>> -> #(
      chunk,
      rest,
    )
    _ -> #(bytes, <<>>)
  }
}

fn send_buffer_full(error: client_connection.Error) -> Bool {
  client_connection.is_stream_send_buffer_full(error)
}

fn handle_cancel(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(
        reply,
        Ok(terminal_cancellation(worker.stream_terminals, identifier)),
      )
      Ok(worker)
    }
    Ok(stream) ->
      case
        stream.cancelled,
        stream.request_finished && stream.response_finished
      {
        True, _ -> {
          process.send(reply, Ok(AlreadyCancelled))
          Ok(worker)
        }
        False, True -> {
          process.send(reply, Ok(AlreadyCompleted))
          Ok(worker)
        }
        False, False ->
          case
            client_connection.abort_stream(
              worker.connection,
              identifier,
              request_cancelled_code,
            )
          {
            Error(client_connection.Http3OperationFailed(
              _,
              protocol.ResourceFailure(protocol.ResourceStreamFinished),
            ))
              if stream.response_finished
            ->
              // The peer has already finished our receive direction and the core confirms the send direction is terminal.
              // Retire the application handle without pretending another RESET was sent.
              retire_finished_cancelled_stream(
                worker,
                identifier,
                stream,
                reply,
              )
            Error(error) -> {
              process.send(reply, Error(map_connection_error(error)))
              Ok(worker)
            }
            Ok(connection) -> {
              finish_cancelled_stream(
                Worker(..worker, connection: connection),
                identifier,
                stream,
                reply,
              )
            }
          }
      }
  }
}

fn retire_finished_cancelled_stream(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  case client_connection.retire_aborted_stream(worker.connection, identifier) {
    Error(error) -> {
      process.send(reply, Error(map_connection_error(error)))
      Ok(worker)
    }
    Ok(connection) ->
      finish_cancelled_stream(
        Worker(..worker, connection: connection),
        identifier,
        stream,
        reply,
      )
  }
}

fn finish_cancelled_stream(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  notify_waiter(stream.waiter, Error(StreamCancelled))
  notify_pending_send(stream.pending_send, Error(StreamCancelled))
  notify_datagram_waiter(stream.datagram_waiter, Error(StreamCancelled))
  process.send(reply, Ok(Cancelled))
  Ok(put_stream(
    worker,
    identifier,
    StreamState(
      ..stream,
      events: queue_new(),
      buffered_data_bytes: 0,
      waiter: None,
      pending_send: None,
      datagram_waiter: None,
      cancelled: True,
    ),
  ))
}

fn update_stream(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(value, Error)),
  update: fn(Worker, StreamState) ->
    Result(#(Worker, StreamState, value), Error),
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(reply, Error(stream_terminal_error(worker, identifier)))
      Ok(worker)
    }
    Ok(stream) ->
      case update(worker, stream) {
        Error(error) -> {
          process.send(reply, Error(error))
          Ok(worker)
        }
        Ok(#(worker, stream, value)) -> {
          process.send(reply, Ok(value))
          Ok(put_stream(worker, identifier, stream))
        }
      }
  }
}

fn dispatch_connection_events(worker: Worker) -> Worker {
  let #(connection, events) = client_connection.take_events(worker.connection)
  dispatch_events(Worker(..worker, connection: connection), events)
}

fn dispatch_events(
  worker: Worker,
  events: List(client_connection.Event),
) -> Worker {
  case events {
    [] -> worker
    [event, ..rest] -> dispatch_events(dispatch_event(worker, event), rest)
  }
}

fn dispatch_event(worker: Worker, event: client_connection.Event) -> Worker {
  case event {
    client_connection.DataFrameParsed(identifier, bytes) ->
      record_http3_frame_parsed(worker, identifier, qlog.DataFrame, bytes)
    client_connection.Http3Event(http3_state.InformationalResponse(
      identifier,
      validated,
    )) ->
      worker
      |> record_http3_frame_parsed(identifier, qlog.HeadersFrame, 0)
      |> enqueue_validated(identifier, validated, True)
    client_connection.Http3Event(http3_state.ResponseHeaders(
      identifier,
      validated,
    )) ->
      worker
      |> record_http3_frame_parsed(identifier, qlog.HeadersFrame, 0)
      |> enqueue_validated(identifier, validated, False)
    client_connection.Http3Event(http3_state.Trailers(identifier, validated)) -> {
      let worker =
        record_http3_frame_parsed(worker, identifier, qlog.HeadersFrame, 0)
      case decode_regular_headers(validated) {
        Error(error) -> fail_stream(worker, identifier, error)
        Ok(headers) -> enqueue(worker, identifier, Trailers(headers))
      }
    }
    client_connection.Http3Event(http3_state.Data(_, <<>>)) ->
      // Zero-length DATA is legal framing and remains visible in qlog, but the public `Data` event promises a non-empty application chunk.
      worker
    client_connection.Http3Event(http3_state.Data(identifier, bytes)) ->
      enqueue_data(worker, identifier, bytes)
    client_connection.Http3Event(http3_state.StreamFinished(identifier)) ->
      finish_response(worker, identifier)
    client_connection.StreamWasReset(identifier, code)
      if code == request_rejected_code
    -> fail_stream(worker, identifier, RequestRejected)
    client_connection.StreamWasReset(identifier, code) ->
      fail_stream(worker, identifier, StreamReset(code))
    client_connection.PushStreamWasReset(push_id, stream_id, code) -> {
      let worker = fail_push(worker, push_id, StreamReset(code))
      Worker(
        ..worker,
        connection: client_connection.retire_stream(
          worker.connection,
          stream_id,
        ),
      )
    }
    client_connection.Http3Event(http3_state.HttpDatagram(identifier, payload)) ->
      enqueue_datagram(worker, identifier, payload)
    client_connection.Http3Event(http3_state.PushPromised(identifier, validated)) ->
      worker
      |> record_http3_frame_parsed(identifier, qlog.PushPromiseFrame, 0)
      |> register_push(identifier, validated)
    client_connection.Http3Event(http3_state.PushPromiseRejected(identifier, _)) ->
      // The protocol layer already sent CANCEL_PUSH.
      // Keep only bounded frame metadata; no push handle, request fields, or response data is exposed.
      worker
      |> record_http3_frame_parsed(identifier, qlog.PushPromiseFrame, 0)
      |> discard_rejected_push(identifier)
    client_connection.Http3Event(http3_state.PushInformationalResponse(
      identifier,
      _,
      validated,
    )) -> enqueue_push_validated(worker, identifier, validated, True)
    client_connection.Http3Event(http3_state.PushResponseHeaders(
      identifier,
      _,
      validated,
    )) -> enqueue_push_validated(worker, identifier, validated, False)
    client_connection.Http3Event(http3_state.PushData(identifier, _, bytes)) ->
      enqueue_push_data(worker, identifier, bytes)
    client_connection.Http3Event(http3_state.PushTrailers(
      identifier,
      _,
      validated,
    )) ->
      case decode_regular_headers(validated) {
        Error(error) -> fail_push(worker, identifier, error)
        Ok(headers) -> enqueue_push(worker, identifier, Trailers(headers))
      }
    client_connection.Http3Event(http3_state.PushFinished(identifier, _)) ->
      finish_push_response(worker, identifier)
    client_connection.Http3Event(http3_state.PushCancelled(identifier)) ->
      fail_push(worker, identifier, StreamCancelled)
    client_connection.Http3Event(http3_state.GoAwayReceived(_, rejected)) ->
      worker
      |> record_http3_frame_parsed(3, qlog.GoAwayFrame, 0)
      |> fail_stream_ids(rejected, RequestRejected)
    client_connection.Http3Event(http3_state.PeerSettings(_)) -> {
      case worker.qlog_sink {
        Some(writer) ->
          qlog.emit_http3_parameters_set(writer, now(), qlog.RemoteInitiator)
        None -> Nil
      }
      record_http3_frame_parsed(worker, 3, qlog.SettingsFrame, 0)
    }
    client_connection.Http3Event(http3_state.OriginsReceived(_)) -> worker
    client_connection.EarlyDataWasAccepted ->
      Worker(..worker, early_data_status: Accepted)
    client_connection.EarlyDataWasRejected ->
      Worker(..worker, early_data_status: Rejected)
    client_connection.NewTokenReceived(token) ->
      store_address_token(worker, token)
    client_connection.SessionTicketStored(ticket) ->
      store_ticket(
        worker,
        ResumptionTicket(
          worker.hostname,
          worker.port,
          ticket,
          worker.latest_address_token,
        ),
      )
    client_connection.PathValidated -> worker
    client_connection.ConnectionTerminated ->
      fail_all_work(worker, ConnectionClosed)
    _ -> worker
  }
}

fn register_push(
  worker: Worker,
  identifier: Int,
  validated: header_semantics.Validated,
) -> Worker {
  case
    decode_pushed_request(validated),
    dict.has_key(worker.pushes, identifier)
  {
    Error(_), _ -> worker
    _, True -> worker
    Ok(#(method, path, headers)), False -> {
      let push =
        PushState(
          method,
          path,
          headers,
          queue_new(),
          0,
          None,
          False,
          False,
          False,
          None,
        )
      let worker = put_push(worker, identifier, push)
      case worker.push_waiter {
        Some(PushWaiter(reply, _)) -> {
          process.send(reply, incoming_push(worker, identifier))
          mark_push_delivered(Worker(..worker, push_waiter: None), identifier)
        }
        None ->
          Worker(
            ..worker,
            pending_pushes: queue_push(worker.pending_pushes, identifier),
          )
      }
    }
  }
}

fn enqueue_push_validated(
  worker: Worker,
  identifier: Int,
  validated: header_semantics.Validated,
  informational: Bool,
) -> Worker {
  case decode_validated_headers(validated) {
    Error(error) -> fail_push(worker, identifier, error)
    Ok(#(status, headers)) ->
      enqueue_push(worker, identifier, case informational {
        True -> Informational(status, headers)
        False -> Response(status, headers)
      })
  }
}

fn enqueue_push_data(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(PushState(failure: Some(_), ..)) -> worker
    Ok(PushState(cancelled: True, ..)) -> worker
    Ok(push) -> {
      let buffered = push.buffered_data_bytes + bit_array.byte_size(bytes)
      case buffered > worker.stream_buffer_limit {
        True ->
          case client_connection.cancel_push(worker.connection, identifier) {
            Error(_) ->
              fail_push(
                worker,
                identifier,
                ConsumerTooSlow(worker.stream_buffer_limit),
              )
            Ok(connection) ->
              fail_push(
                Worker(..worker, connection: connection),
                identifier,
                ConsumerTooSlow(worker.stream_buffer_limit),
              )
          }
        False ->
          enqueue_push_with_buffer(
            worker,
            identifier,
            push,
            Data(bytes),
            buffered,
          )
      }
    }
  }
}

fn enqueue_push(worker: Worker, identifier: Int, event: Event) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(PushState(failure: Some(_), ..)) -> worker
    Ok(PushState(cancelled: True, ..)) -> worker
    Ok(push) ->
      enqueue_push_with_buffer(
        worker,
        identifier,
        push,
        event,
        push.buffered_data_bytes,
      )
  }
}

fn enqueue_push_with_buffer(
  worker: Worker,
  identifier: Int,
  push: PushState,
  event: Event,
  buffered: Int,
) -> Worker {
  case push.waiter, queue_is_empty(push.events), push.delivered {
    Some(Waiter(reply, _)), True, True -> {
      process.send(reply, Ok(event))
      put_push(worker, identifier, PushState(..push, waiter: None))
    }
    _, _, _ ->
      case queue_count(push.events) >= worker.queue_limit {
        True ->
          case client_connection.cancel_push(worker.connection, identifier) {
            Error(_) ->
              fail_push(
                worker,
                identifier,
                ResponseEventQueueExceeded(worker.queue_limit),
              )
            Ok(connection) ->
              fail_push(
                Worker(..worker, connection: connection),
                identifier,
                ResponseEventQueueExceeded(worker.queue_limit),
              )
          }
        False ->
          put_push(
            worker,
            identifier,
            PushState(
              ..push,
              events: queue_push(push.events, event),
              buffered_data_bytes: buffered,
            ),
          )
      }
  }
}

fn finish_push_response(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(PushState(failure: Some(_), ..)) -> worker
    Ok(PushState(cancelled: True, ..)) -> worker
    Ok(_) -> {
      let worker = enqueue_push(worker, identifier, End)
      case dict.get(worker.pushes, identifier) {
        Error(_) -> worker
        Ok(push) ->
          put_push(
            worker,
            identifier,
            PushState(..push, response_finished: True),
          )
      }
    }
  }
}

fn fail_push(worker: Worker, identifier: Int, error: Error) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(PushState(failure: Some(_), ..)) -> worker
    Ok(push) -> {
      notify_waiter(push.waiter, Error(error))
      put_push(
        Worker(
          ..worker,
          pending_pushes: queue_filter(worker.pending_pushes, fn(value) {
            value != identifier
          }),
        ),
        identifier,
        PushState(
          ..push,
          waiter: None,
          cancelled: push.cancelled || error == StreamCancelled,
          failure: Some(error),
        ),
      )
    }
  }
}

// A duplicate promise can become unusable after a same-ID push was already announced to the actor.
// Drop every queued response event before installing a value-free terminal so none of that response can be consumed or cached.
fn discard_rejected_push(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(push) -> {
      notify_waiter(push.waiter, Error(StreamCancelled))
      put_push(
        Worker(
          ..worker,
          pending_pushes: queue_filter(worker.pending_pushes, fn(value) {
            value != identifier
          }),
        ),
        identifier,
        PushState(
          ..push,
          events: queue_new(),
          buffered_data_bytes: 0,
          waiter: None,
          cancelled: True,
          failure: Some(StreamCancelled),
        ),
      )
    }
  }
}

fn enqueue_datagram(
  worker: Worker,
  identifier: Int,
  payload: BitArray,
) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(StreamState(cancelled: True, ..)) -> worker
    Ok(stream) ->
      case stream.datagram_waiter, stream.datagram_failure {
        Some(DatagramWaiter(reply, _)), _ -> {
          process.send(reply, Ok(payload))
          put_stream(
            worker,
            identifier,
            StreamState(..stream, datagram_waiter: None),
          )
        }
        None, Some(_) -> worker
        None, None -> {
          let buffered =
            stream.buffered_datagram_bytes + bit_array.byte_size(payload)
          case
            queue_count(stream.datagrams) >= worker.queue_limit,
            buffered > worker.stream_buffer_limit
          {
            True, _ ->
              put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagram_failure: Some(DatagramQueueExceeded(
                    worker.queue_limit,
                  )),
                ),
              )
            False, True ->
              put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagram_failure: Some(DatagramBufferExceeded(
                    worker.stream_buffer_limit,
                  )),
                ),
              )
            False, False ->
              put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagrams: queue_push(stream.datagrams, payload),
                  buffered_datagram_bytes: buffered,
                ),
              )
          }
        }
      }
  }
}

fn store_ticket(worker: Worker, ticket: ResumptionTicket) -> Worker {
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, _)) -> {
      process.send(reply, Ok(ticket))
      Worker(..worker, latest_ticket: Some(ticket), ticket_waiter: None)
    }
    None -> Worker(..worker, latest_ticket: Some(ticket))
  }
}

fn store_address_token(worker: Worker, token: BitArray) -> Worker {
  let latest_ticket = case worker.latest_ticket {
    None -> None
    Some(ResumptionTicket(hostname, port, ticket, _)) ->
      Some(ResumptionTicket(hostname, port, ticket, token))
  }
  Worker(..worker, latest_ticket: latest_ticket, latest_address_token: token)
}

fn enqueue_validated(
  worker: Worker,
  identifier: Int,
  validated: header_semantics.Validated,
  informational: Bool,
) -> Worker {
  case decode_validated_headers(validated) {
    Error(error) -> fail_stream(worker, identifier, error)
    Ok(#(status, headers)) -> {
      let worker = case informational, dict.get(worker.streams, identifier) {
        False, Ok(stream) ->
          put_stream(
            worker,
            identifier,
            StreamState(
              ..stream,
              capsule_established: stream.capsule_candidate
                && capsule_success_status(status)
                && !has_forbidden_capsule_field(headers),
            ),
          )
        _, _ -> worker
      }
      case informational {
        True -> enqueue(worker, identifier, Informational(status, headers))
        False -> enqueue(worker, identifier, Response(status, headers))
      }
    }
  }
}

fn enqueue_data(worker: Worker, identifier: Int, bytes: BitArray) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(StreamState(failure: Some(_), ..)) -> worker
    Ok(StreamState(cancelled: True, ..)) -> worker
    Ok(stream) -> {
      let buffered = stream.buffered_data_bytes + bit_array.byte_size(bytes)
      case buffered > worker.stream_buffer_limit {
        True ->
          case
            client_connection.abort_stream(
              worker.connection,
              identifier,
              request_cancelled_code,
            )
          {
            Error(_) ->
              fail_stream(
                worker,
                identifier,
                ConsumerTooSlow(worker.stream_buffer_limit),
              )
            Ok(connection) ->
              fail_stream(
                Worker(..worker, connection: connection),
                identifier,
                ConsumerTooSlow(worker.stream_buffer_limit),
              )
          }
        False ->
          enqueue_with_buffer(worker, identifier, stream, Data(bytes), buffered)
      }
    }
  }
}

fn enqueue(worker: Worker, identifier: Int, event: Event) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(StreamState(failure: Some(_), ..)) -> worker
    Ok(StreamState(cancelled: True, ..)) -> worker
    Ok(stream) ->
      enqueue_with_buffer(
        worker,
        identifier,
        stream,
        event,
        stream.buffered_data_bytes,
      )
  }
}

fn enqueue_with_buffer(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  event: Event,
  buffered: Int,
) -> Worker {
  // Network delivery can precede the next periodic waiter-expiry pass.
  // Retire an expired reader before deciding whether this event is consumed.
  let stream =
    StreamState(..stream, waiter: unexpired_read_waiter(stream.waiter, now()))
  case stream.waiter, queue_is_empty(stream.events) {
    Some(Waiter(reply, _)), True -> {
      process.send(reply, Ok(event))
      put_stream(worker, identifier, StreamState(..stream, waiter: None))
    }
    _, _ ->
      case queue_count(stream.events) >= worker.queue_limit {
        True ->
          case
            client_connection.abort_stream(
              worker.connection,
              identifier,
              excessive_load_code,
            )
          {
            Error(_) ->
              fail_stream(
                worker,
                identifier,
                ResponseEventQueueExceeded(worker.queue_limit),
              )
            Ok(connection) ->
              fail_stream(
                Worker(..worker, connection: connection),
                identifier,
                ResponseEventQueueExceeded(worker.queue_limit),
              )
          }
        False ->
          put_stream(
            worker,
            identifier,
            StreamState(
              ..stream,
              events: queue_push(stream.events, event),
              buffered_data_bytes: buffered,
            ),
          )
      }
  }
}

fn unexpired_read_waiter(
  waiter: Option(Waiter),
  current: Int,
) -> Option(Waiter) {
  case waiter {
    Some(Waiter(reply, deadline)) if current >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      None
    }
    _ -> waiter
  }
}

fn finish_response(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(StreamState(failure: Some(_), ..)) -> worker
    Ok(StreamState(cancelled: True, ..)) -> worker
    Ok(_) -> {
      let worker = enqueue(worker, identifier, End)
      case dict.get(worker.streams, identifier) {
        Error(_) -> worker
        Ok(stream) ->
          put_stream(
            worker,
            identifier,
            StreamState(..stream, response_finished: True),
          )
      }
    }
  }
}

fn fail_stream(worker: Worker, identifier: Int, error: Error) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(StreamState(failure: Some(_), ..)) -> worker
    Ok(stream) -> {
      notify_waiter(stream.waiter, Error(error))
      notify_pending_send(stream.pending_send, Error(error))
      notify_datagram_waiter(stream.datagram_waiter, Error(error))
      put_stream(
        worker,
        identifier,
        StreamState(
          ..stream,
          waiter: None,
          pending_send: None,
          datagram_waiter: None,
          cancelled: stream.cancelled || locally_cancelled(error),
          failure: Some(error),
        ),
      )
    }
  }
}

fn fail_all_streams(worker: Worker, error: Error) -> Worker {
  fail_stream_entries(worker, dict.to_list(worker.streams), error)
}

fn fail_stream_ids(
  worker: Worker,
  identifiers: List(Int),
  error: Error,
) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_stream_ids(fail_stream(worker, identifier, error), rest, error)
  }
}

fn fail_all_pushes(worker: Worker, error: Error) -> Worker {
  fail_push_entries(worker, dict.keys(worker.pushes), error)
}

fn fail_push_entries(
  worker: Worker,
  identifiers: List(Int),
  error: Error,
) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_push_entries(fail_push(worker, identifier, error), rest, error)
  }
}

fn fail_all_work(worker: Worker, error: Error) -> Worker {
  let worker =
    fail_all_streams(worker, error)
    |> fail_all_pushes(error)
    |> fail_pending_opens(error)
  case worker.push_waiter {
    Some(PushWaiter(reply, _)) -> {
      process.send(reply, Error(error))
      Worker(..worker, push_waiter: None)
    }
    None -> worker
  }
}

fn fail_pending_opens(worker: Worker, error: Error) -> Worker {
  case pending_open_dequeue(worker.pending_opens) {
    Error(Nil) -> worker
    Ok(#(PendingOpen(_, reply, _), remaining)) -> {
      process.send(reply, Error(error))
      fail_pending_opens(Worker(..worker, pending_opens: remaining), error)
    }
  }
}

fn fail_stream_entries(
  worker: Worker,
  entries: List(#(Int, StreamState)),
  error: Error,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, _), ..rest] ->
      fail_stream_entries(fail_stream(worker, identifier, error), rest, error)
  }
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let worker = expire_pending_opens(worker, now)
  let worker = expire_waiter_entries(worker, dict.to_list(worker.streams), now)
  let worker = expire_push_waiters(worker, dict.to_list(worker.pushes), now)
  let worker = case worker.push_waiter {
    Some(PushWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, push_waiter: None)
    }
    _ -> worker
  }
  expire_ticket_waiter(worker, now)
}

fn expire_pending_opens(worker: Worker, now: Int) -> Worker {
  case pending_open_deadline(worker.pending_opens) {
    Some(deadline) if now >= deadline ->
      case pending_open_dequeue(worker.pending_opens) {
        Error(Nil) -> worker
        Ok(#(PendingOpen(_, reply, _), remaining)) -> {
          process.send(reply, Error(OperationTimeout))
          expire_pending_opens(Worker(..worker, pending_opens: remaining), now)
        }
      }
    _ -> worker
  }
}

fn expire_push_waiters(
  worker: Worker,
  entries: List(#(Int, PushState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, push), ..rest] -> {
      let worker = case push.waiter {
        Some(Waiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          put_push(worker, identifier, PushState(..push, waiter: None))
        }
        _ -> worker
      }
      expire_push_waiters(worker, rest, now)
    }
  }
}

fn expire_waiter_entries(
  worker: Worker,
  entries: List(#(Int, StreamState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, stream), ..rest] -> {
      let worker = case stream.waiter {
        Some(Waiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          put_stream(worker, identifier, StreamState(..stream, waiter: None))
        }
        _ -> worker
      }
      let worker = expire_pending_send(worker, identifier, now)
      let worker = expire_datagram_waiter(worker, identifier, now)
      expire_waiter_entries(worker, rest, now)
    }
  }
}

fn terminate_with_error(worker: Worker, error: Error) -> Nil {
  let worker = fail_all_work(worker, error)
  notify_close_replies(worker, Error(error))
  shutdown(worker, "connection failed")
}

fn shutdown(worker: Worker, reason: String) -> Nil {
  let worker = fail_all_work(worker, ConnectionClosed)
  client_connection.close(
    worker.connection,
    error_code.runtime_greased_no_error(now()),
    reason,
  )
}

fn now() -> Int {
  qlog.monotonic_milliseconds()
}

fn new_stream_state(headers: List(Header)) -> StreamState {
  StreamState(
    queue_new(),
    0,
    None,
    None,
    queue_new(),
    0,
    None,
    None,
    is_capsule_candidate(headers),
    False,
    False,
    False,
    False,
    None,
  )
}

fn is_capsule_candidate(headers: List(Header)) -> Bool {
  list.any(headers, fn(header) {
    header == Header(<<":method">>, <<"CONNECT">>, False)
  })
  && list.any(headers, fn(header) {
    let Header(name, value, _) = header
    name == <<":protocol">> && bit_array.byte_size(value) > 0
  })
  && !list.any(headers, fn(header) {
    let Header(name, _, _) = header
    name == <<"content-length">>
    || name == <<"content-type">>
    || name == <<"transfer-encoding">>
  })
}

fn capsule_success_status(status: Int) -> Bool {
  status >= 200
  && status < 300
  && status != 204
  && status != 205
  && status != 206
}

fn has_forbidden_capsule_field(headers: List(#(String, String))) -> Bool {
  list.any(headers, fn(field) {
    let #(name, _) = field
    name == "content-length"
    || name == "content-type"
    || name == "transfer-encoding"
  })
}

fn put_stream(worker: Worker, identifier: Int, stream: StreamState) -> Worker {
  case stream_terminal(stream) {
    None ->
      Worker(..worker, streams: dict.insert(worker.streams, identifier, stream))
    Some(terminal) -> {
      let error = terminal_error(terminal)
      notify_waiter(stream.waiter, Error(error))
      notify_pending_send(stream.pending_send, Error(error))
      notify_datagram_waiter(stream.datagram_waiter, Error(error))
      Worker(
        ..worker,
        connection: client_connection.retire_stream(
          worker.connection,
          identifier,
        ),
        streams: dict.delete(worker.streams, identifier),
        stream_terminals: terminal_registry.insert(
          worker.stream_terminals,
          identifier,
          terminal,
        ),
        priorities: dict.delete(worker.priorities, identifier),
      )
    }
  }
}

fn put_push(worker: Worker, identifier: Int, push: PushState) -> Worker {
  case push_terminal(push) {
    None ->
      Worker(..worker, pushes: dict.insert(worker.pushes, identifier, push))
    Some(terminal) -> {
      notify_waiter(push.waiter, Error(terminal_error(terminal)))
      Worker(
        ..worker,
        pushes: dict.delete(worker.pushes, identifier),
        push_terminals: terminal_registry.insert(
          worker.push_terminals,
          identifier,
          terminal,
        ),
        pending_pushes: queue_filter(worker.pending_pushes, fn(value) {
          value != identifier
        }),
      )
    }
  }
}

fn stream_terminal(stream: StreamState) -> Option(TerminalState) {
  case
    queue_is_empty(stream.events),
    stream.failure,
    stream.cancelled,
    stream.request_finished && stream.response_finished
  {
    True, Some(error), _, _ -> Some(TerminalFailed(error))
    True, None, True, _ -> Some(TerminalCancelled)
    True, None, False, True -> Some(TerminalCompleted)
    _, _, _, _ -> None
  }
}

fn push_terminal(push: PushState) -> Option(TerminalState) {
  case
    queue_is_empty(push.events),
    push.failure,
    push.cancelled,
    push.response_finished
  {
    True, Some(error), _, _ -> Some(TerminalFailed(error))
    True, None, True, _ -> Some(TerminalCancelled)
    True, None, False, True -> Some(TerminalCompleted)
    _, _, _, _ -> None
  }
}

fn stream_terminal_error(worker: Worker, identifier: Int) -> Error {
  retained_terminal_error(worker.stream_terminals, identifier)
}

fn push_terminal_error(worker: Worker, identifier: Int) -> Error {
  retained_terminal_error(worker.push_terminals, identifier)
}

fn retained_terminal_error(
  terminals: terminal_registry.Registry(TerminalState),
  identifier: Int,
) -> Error {
  terminal_registry.get(terminals, identifier)
  |> result.map(terminal_error)
  |> result.unwrap(StreamFinished)
}

fn terminal_error(terminal: TerminalState) -> Error {
  case terminal {
    TerminalCompleted -> StreamFinished
    TerminalCancelled -> StreamCancelled
    TerminalFailed(error) -> error
  }
}

fn terminal_cancellation(
  terminals: terminal_registry.Registry(TerminalState),
  identifier: Int,
) -> Cancellation {
  case terminal_registry.get(terminals, identifier) {
    Ok(TerminalCancelled) -> AlreadyCancelled
    Ok(TerminalFailed(error)) ->
      case locally_cancelled(error) {
        True -> AlreadyCancelled
        False -> AlreadyCompleted
      }
    Ok(_) | Error(_) -> AlreadyCompleted
  }
}

fn mark_push_delivered(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(push) -> put_push(worker, identifier, PushState(..push, delivered: True))
  }
}

fn incoming_push(
  worker: Worker,
  identifier: Int,
) -> Result(IncomingPush, Error) {
  use push <- result.try(
    dict.get(worker.pushes, identifier) |> result.replace_error(StreamFinished),
  )
  Ok(IncomingPush(
    Push(
      Connection(
        worker.commands,
        process.self(),
        worker.timeout_milliseconds,
        worker.drain_timeout_milliseconds,
        worker.core_close_operation_allowance_milliseconds,
        worker.hostname,
        worker.port,
      ),
      identifier,
    ),
    push.method,
    push.path,
    push.headers,
  ))
}

fn notify_waiter(waiter: Option(Waiter), outcome: Result(Event, Error)) -> Nil {
  case waiter {
    Some(Waiter(reply, _)) -> process.send(reply, outcome)
    None -> Nil
  }
}

fn notify_pending_send(
  pending: Option(PendingSend),
  outcome: Result(Nil, Error),
) -> Nil {
  case pending {
    Some(PendingSend(_, reply, _)) -> process.send(reply, outcome)
    None -> Nil
  }
}

fn notify_datagram_waiter(
  waiter: Option(DatagramWaiter),
  outcome: Result(BitArray, Error),
) -> Nil {
  case waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, outcome)
    None -> Nil
  }
}

fn expire_pending_send(worker: Worker, identifier: Int, now: Int) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(stream) ->
      case stream.pending_send {
        Some(PendingSend(_, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          put_stream(
            worker,
            identifier,
            StreamState(..stream, pending_send: None),
          )
        }
        _ -> worker
      }
  }
}

fn expire_datagram_waiter(worker: Worker, identifier: Int, now: Int) -> Worker {
  case dict.get(worker.streams, identifier) {
    Error(_) -> worker
    Ok(stream) ->
      case stream.datagram_waiter {
        Some(DatagramWaiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          put_stream(
            worker,
            identifier,
            StreamState(..stream, datagram_waiter: None),
          )
        }
        _ -> worker
      }
  }
}

fn expire_ticket_waiter(worker: Worker, now: Int) -> Worker {
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(TicketUnavailable))
      Worker(..worker, ticket_waiter: None)
    }
    _ -> worker
  }
}

fn decode_validated_headers(
  validated: header_semantics.Validated,
) -> Result(#(Int, List(#(String, String))), Error) {
  let header_semantics.Validated(control, fields, _) = validated
  use status <- result.try(case control {
    header_semantics.ResponseControlData(status) -> Ok(status)
    _ -> Error(ProtocolError)
  })
  use headers <- result.try(decode_headers(fields))
  Ok(#(status, headers))
}

fn decode_pushed_request(
  validated: header_semantics.Validated,
) -> Result(#(String, String, List(#(String, String))), Error) {
  let header_semantics.Validated(control, fields, _) = validated
  use request <- result.try(case control {
    header_semantics.RequestControlData(request) -> Ok(request)
    _ -> Error(ProtocolError)
  })
  let header_semantics.RequestControl(method, _, _, path, protocol) = request
  use _ <- result.try(case protocol {
    None -> Ok(Nil)
    Some(_) -> Error(ProtocolError)
  })
  use method <- result.try(
    bit_array.to_string(method)
    |> result.replace_error(InvalidHeaderEncoding),
  )
  use path <- result.try(case path {
    Some(value) ->
      bit_array.to_string(value)
      |> result.replace_error(InvalidHeaderEncoding)
    None -> Error(ProtocolError)
  })
  use headers <- result.try(decode_headers(fields))
  Ok(#(method, path, headers))
}

fn decode_regular_headers(
  validated: header_semantics.Validated,
) -> Result(List(#(String, String)), Error) {
  let header_semantics.Validated(_, fields, _) = validated
  decode_headers(fields)
}

fn decode_headers(
  fields: List(Header),
) -> Result(List(#(String, String)), Error) {
  decode_headers_raw(fields)
  |> result.map(application_headers.combine_cookie_fields)
}

fn decode_headers_raw(
  fields: List(Header),
) -> Result(List(#(String, String)), Error) {
  case fields {
    [] -> Ok([])
    [Header(name, value, _), ..rest] -> {
      use name <- result.try(
        bit_array.to_string(name)
        |> result.replace_error(InvalidHeaderEncoding),
      )
      use value <- result.try(
        bit_array.to_string(value)
        |> result.replace_error(InvalidHeaderEncoding),
      )
      use rest <- result.try(decode_headers_raw(rest))
      Ok([#(name, value), ..rest])
    }
  }
}

fn await_bootstrap(
  worker: Pid,
  bootstrap: Subject(Result(Connection, Error)),
  timeout: Int,
) -> Result(Connection, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(bootstrap, fn(reply) { CallReply(reply) })
    |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(CallReply(reply)) -> reply
    Ok(WorkerExited) -> Error(ConnectionClosed)
    Error(Nil) -> {
      process.kill(worker)
      Error(TotalTimeout)
    }
  }
}

fn call(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    make_command,
  )
}

fn call_with_timeout(
  connection: Connection,
  timeout: Int,
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
        |> process.selector_receive(within: timeout)
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(result)) -> result
        Ok(WorkerExited) -> Error(ConnectionClosed)
        Error(Nil) -> Error(OperationTimeout)
      }
    }
  }
}

fn call_until(
  connection: Connection,
  deadline_milliseconds: Int,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  use _ <- result.try(remaining_close_call_milliseconds(deadline_milliseconds))
  case process.is_alive(connection.worker) {
    False -> Error(ConnectionClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(connection.worker)
      process.send(connection.commands, make_command(reply))
      let selector =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
      let outcome =
        await_close_call_until(selector, deadline_milliseconds, None, False)
      process.demonitor_process(monitor)
      outcome
    }
  }
}

/// A close succeeds only after its typed result and this HTTP/3 owner actor's DOWN are both observed.
/// Core has already applied the same absolute boundary to its transport actor, qlog writer, cleanup ticket, and reservation.
fn await_close_call_until(
  selector: process.Selector(CallOutcome(value)),
  deadline_milliseconds: Int,
  reply: Option(Result(value, Error)),
  worker_down: Bool,
) -> Result(value, Error) {
  case reply, worker_down {
    Some(outcome), True ->
      case remaining_close_call_milliseconds(deadline_milliseconds) {
        Ok(_) -> outcome
        Error(error) -> close_call_timeout_result(Some(outcome), error)
      }
    _, _ ->
      case remaining_close_call_milliseconds(deadline_milliseconds) {
        Error(error) -> close_call_timeout_result(reply, error)
        Ok(remaining) ->
          case process.selector_receive(selector, within: remaining) {
            Ok(CallReply(outcome)) ->
              continue_close_call_until(
                selector,
                deadline_milliseconds,
                Some(outcome),
                worker_down,
              )
            Ok(WorkerExited) ->
              continue_close_call_until(
                selector,
                deadline_milliseconds,
                reply,
                True,
              )
            Error(Nil) -> close_call_timeout_result(reply, OperationTimeout)
          }
      }
  }
}

fn continue_close_call_until(
  selector: process.Selector(CallOutcome(value)),
  deadline_milliseconds: Int,
  reply: Option(Result(value, Error)),
  worker_down: Bool,
) -> Result(value, Error) {
  case remaining_close_call_milliseconds(deadline_milliseconds) {
    Ok(_) ->
      await_close_call_until(
        selector,
        deadline_milliseconds,
        reply,
        worker_down,
      )
    Error(error) -> close_call_timeout_result(reply, error)
  }
}

fn close_call_timeout_result(
  observed: Option(Result(value, Error)),
  timeout: Error,
) -> Result(value, Error) {
  case observed {
    Some(Error(error)) -> Error(error)
    Some(Ok(_)) | None -> Error(timeout)
  }
}

fn remaining_close_call_milliseconds(
  deadline_milliseconds: Int,
) -> Result(Int, Error) {
  let remaining = deadline_milliseconds - now()
  case deadline_milliseconds >= 0 && remaining > 0 {
    True -> Ok(remaining)
    False -> Error(OperationTimeout)
  }
}

fn map_connection_error(error: client_connection.Error) -> Error {
  case client_connection.operation_failure(error) {
    Some(client_connection.DatagramsNotNegotiated) -> DatagramsNotNegotiated
    Some(client_connection.DatagramTooLarge(maximum)) ->
      DatagramTooLarge(maximum)
    Some(client_connection.CongestionLimited) -> CongestionLimited
    None -> map_unclassified_connection_error(error)
  }
}

fn map_unclassified_connection_error(error: client_connection.Error) -> Error {
  case error {
    client_connection.InvalidInput -> InvalidInput
    client_connection.ResolutionFailed -> ResolutionFailed
    client_connection.SocketUnavailable -> SocketUnavailable
    client_connection.DnsTimeout -> DnsTimeout
    client_connection.ConnectTimeout -> ConnectTimeout
    client_connection.HandshakeTimeout -> HandshakeTimeout
    client_connection.OperationTimeout -> OperationTimeout
    client_connection.TotalTimeout -> TotalTimeout
    client_connection.TrustStoreFailed -> TrustStoreFailed
    client_connection.TlsHandshakeFailed -> TlsHandshakeFailed
    client_connection.QuicTransportFailed(_) -> QuicFailure
    client_connection.CoreFailure(core_failure.Socket(core_failure.WriteFile)) ->
      QlogUnavailable
    client_connection.CoreFailure(failure) -> CoreFailure(failure)
    client_connection.Http3OperationFailed(
      _,
      protocol.FrameParserFailure(error),
    ) -> RuntimeFailure(protocol.frame_parser_runtime_failure(error))
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.InvalidMessageFraming),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.MessageFailure(message_stream.ContentLengthExceeded(
        _,
        _,
      ))),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.MessageFailure(message_stream.ContentLengthMismatch(
        _,
        _,
      ))),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.DatagramFailure(datagram.UnknownAssociation(
        _,
      ))),
    ) -> DatagramNotAssociated
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.DatagramFailure(
        datagram.UnreliableDatagramNotNegotiated,
      )),
    ) -> DatagramsNotNegotiated
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.DrainFailure(drain.NewWorkAfterGoAway)),
    ) -> ConnectionDraining
    client_connection.Http3OperationFailed(
      _,
      protocol.Http3Failure(http3_state.RequestRejected(_)),
    ) -> RequestRejected
    client_connection.Http3OperationFailed(_, _) -> Http3Failure
    client_connection.PeerClosed -> ConnectionClosed
    client_connection.MigrationUnavailable -> MigrationUnavailable
    client_connection.VersionNegotiationReceived(_) -> VersionNegotiationFailed
    client_connection.VersionNegotiationFailed -> VersionNegotiationFailed
  }
}

fn valid_resumption_origin(
  ticket: Option(ResumptionTicket),
  hostname: String,
  port: Int,
) -> Bool {
  case ticket {
    None -> True
    Some(ResumptionTicket(bound_hostname, bound_port, _, _)) ->
      hostname == bound_hostname && port == bound_port
  }
}

fn unsafe_early_method(
  early_data_attempted: Bool,
  headers: List(Header),
) -> Option(String) {
  case early_data_attempted {
    False -> None
    True ->
      case request_method(headers) {
        Some("GET") | Some("HEAD") | Some("OPTIONS") | None -> None
        Some(method) -> Some(method)
      }
  }
}

fn request_method(headers: List(Header)) -> Option(String) {
  case headers {
    [] -> None
    [Header(name, value, _), ..rest] ->
      case name == <<":method":utf8>>, bit_array.to_string(value) {
        True, Ok(method) -> Some(method)
        _, _ -> request_method(rest)
      }
  }
}

fn locally_cancelled(error: Error) -> Bool {
  case error {
    ConsumerTooSlow(_) -> True
    _ -> False
  }
}
