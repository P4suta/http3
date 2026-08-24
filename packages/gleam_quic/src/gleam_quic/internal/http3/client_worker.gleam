//// Typed actor owning one reusable native HTTP/3 client connection.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/http3/client_connection
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/datagram
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/http3/message_stream
import gleam_quic/internal/http3/session
import gleam_quic/internal/qlog
import gleam_quic/internal/qpack/header.{type Header, Header}
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/udp

const network_poll_milliseconds = 10

const worker_reply_grace_milliseconds = 100

const request_cancelled_code = 0x10c

// Keep each HTTP DATA frame comfortably below the per-stream retained-send
// bound. Larger public chunks are advanced incrementally by the actor.
const maximum_request_data_chunk_bytes = 65_536

/// A live actor reference and fixed origin policy.
pub opaque type Connection {
  Connection(
    commands: Subject(Command),
    worker: Pid,
    timeout_milliseconds: Int,
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
    ticket: session_ticket.ClientTicket,
  )
}

/// State of the connection's explicit 0-RTT attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
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
  Timeout
  TlsHandshakeFailed
  TransportFailed(String)
  Http3Failed(String)
  ConnectionClosed
  StreamReset(Int)
  ProtocolError
  InvalidHeaderEncoding
  InvalidContentLength
  ConsumerTooSlow(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  MigrationUnavailable
  CongestionLimited
  UnsupportedCongestionControl
  TicketUnavailable
  QlogUnavailable
}

type Command {
  Open(
    hostname: String,
    port: Int,
    headers: List(Header),
    reply: Subject(Result(Int, Error)),
  )
  Send(
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
  Next(stream_id: Int, reply: Subject(Result(Event, Error)), deadline: Int)
  Cancel(stream_id: Int, reply: Subject(Result(Cancellation, Error)))
  NextPush(reply: Subject(Result(IncomingPush, Error)), deadline: Int)
  NextPushEvent(
    push_id: Int,
    reply: Subject(Result(Event, Error)),
    deadline: Int,
  )
  CancelPush(push_id: Int, reply: Subject(Result(Cancellation, Error)))
  Close(reply: Subject(Result(CloseResult, Error)))
  Capabilities(reply: Subject(Result(#(Bool, Bool, Bool, Bool), Error)))
  MaximumDatagram(stream_id: Int, reply: Subject(Result(Int, Error)))
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
  Ticket(reply: Subject(Result(ResumptionTicket, Error)), deadline: Int)
  Migrate(reply: Subject(Result(Nil, Error)))
  SetCongestion(algorithm: Int, reply: Subject(Result(Nil, Error)))
  Ping(reply: Subject(Result(Nil, Error)))
  MaximumTransmissionUnit(reply: Subject(Result(Int, Error)))
  PathStats(reply: Subject(Result(transport.PathSnapshot, Error)))
  ConnectionStats(reply: Subject(Result(client_connection.Stats, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
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

type StreamState {
  StreamState(
    events: List(Event),
    buffered_data_bytes: Int,
    waiter: Option(Waiter),
    pending_send: Option(PendingSend),
    datagrams: List(BitArray),
    buffered_datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    datagram_failure: Option(Error),
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
    events: List(Event),
    buffered_data_bytes: Int,
    waiter: Option(Waiter),
    response_finished: Bool,
    delivered: Bool,
    cancelled: Bool,
    failure: Option(Error),
  )
}

type Worker {
  Worker(
    connection: client_connection.State,
    streams: Dict(Int, StreamState),
    pushes: Dict(Int, PushState),
    pending_pushes: List(Int),
    push_waiter: Option(PushWaiter),
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    hostname: String,
    port: Int,
    http_datagrams: Bool,
    qlog_writer: Option(qlog.Writer),
    resumption_attempted: Bool,
    early_data_status: EarlyDataStatus,
    latest_ticket: Option(ResumptionTicket),
    ticket_waiter: Option(TicketWaiter),
    priorities: Dict(Int, #(Int, Bool)),
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
  timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  trust_store: authentication.TrustStore,
  http_datagrams: Bool,
  maximum_pushes: Int,
  qlog_directory: String,
  resumption_ticket: Option(ResumptionTicket),
) -> Result(Connection, Error) {
  case
    hostname != ""
    && port > 0
    && port <= 65_535
    && timeout_milliseconds > 0
    && stream_buffer_limit > 0
    && maximum_pushes >= 0
    && maximum_pushes <= 1024
  {
    False -> Error(InvalidInput)
    True ->
      case valid_resumption_origin(resumption_ticket, hostname, port) {
        False -> Error(ResumptionOriginMismatch)
        True -> {
          let owner = process.self()
          let bootstrap = process.new_subject()
          let worker =
            process.spawn_unlinked(fn() {
              initialise(
                owner,
                bootstrap,
                hostname,
                port,
                timeout_milliseconds,
                stream_buffer_limit,
                trust_store,
                http_datagrams,
                maximum_pushes,
                qlog_directory,
                resumption_ticket,
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

/// Open one request stream for this connection's fixed origin.
pub fn open_stream(
  connection: Connection,
  hostname: String,
  port: Int,
  headers: List(Header),
) -> Result(Stream, Error) {
  use identifier <- result.try(
    call(connection, fn(reply) { Open(hostname, port, headers, reply) }),
  )
  Ok(Stream(connection, identifier))
}

/// Queue one request body chunk with synchronous actor feedback.
pub fn send_data(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  let deadline =
    udp.monotonic_millisecond() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Send(stream.identifier, bytes, reply, deadline) },
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

/// Pull one response event.
pub fn next_event(stream: Stream) -> Result(Event, Error) {
  let deadline =
    udp.monotonic_millisecond() + stream.connection.timeout_milliseconds
  call_with_timeout(
    stream.connection,
    stream.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Next(stream.identifier, reply, deadline) },
  )
}

/// Cancel both stream directions idempotently.
pub fn cancel(stream: Stream) -> Result(Cancellation, Error) {
  call(stream.connection, fn(reply) { Cancel(stream.identifier, reply) })
}

/// Pull the next validated server push promise.
pub fn next_push(connection: Connection) -> Result(IncomingPush, Error) {
  let deadline = udp.monotonic_millisecond() + connection.timeout_milliseconds
  call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextPush(reply, deadline) },
  )
}

/// Pull one response event for a server push.
pub fn next_push_event(push: Push) -> Result(Event, Error) {
  let deadline =
    udp.monotonic_millisecond() + push.connection.timeout_milliseconds
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
pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  case process.is_alive(connection.worker) {
    False -> Ok(AlreadyClosed)
    True ->
      case call(connection, Close) {
        Error(ConnectionClosed) -> Ok(AlreadyClosed)
        outcome -> outcome
      }
  }
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

/// Queue one unreliable HTTP Datagram.
pub fn send_datagram(stream: Stream, payload: BitArray) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    SendDatagram(stream.identifier, payload, reply)
  })
}

/// Pull one HTTP Datagram with one waiter per stream.
pub fn next_datagram(stream: Stream) -> Result(BitArray, Error) {
  let deadline =
    udp.monotonic_millisecond() + stream.connection.timeout_milliseconds
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

/// Wait for the newest origin-bound TLS ticket.
pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  let deadline = udp.monotonic_millisecond() + connection.timeout_milliseconds
  call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Ticket(reply, deadline) },
  )
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
pub fn path_stats(
  connection: Connection,
) -> Result(transport.PathSnapshot, Error) {
  call(connection, PathStats)
}

/// Snapshot runtime traffic counters.
pub fn connection_stats(
  connection: Connection,
) -> Result(client_connection.Stats, Error) {
  call(connection, ConnectionStats)
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
  timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  trust_store: authentication.TrustStore,
  http_datagrams: Bool,
  maximum_pushes: Int,
  qlog_directory: String,
  resumption_ticket: Option(ResumptionTicket),
) -> Nil {
  let native_ticket = case resumption_ticket {
    Some(ResumptionTicket(_, _, ticket)) -> Some(ticket)
    None -> None
  }
  let config =
    client_connection.Config(
      hostname,
      port,
      timeout_milliseconds,
      trust_store,
      http_datagrams,
      native_ticket,
      maximum_pushes,
    )
  case client_connection.connect(config) {
    Error(error) -> process.send(bootstrap, Error(map_connection_error(error)))
    Ok(connection) ->
      case open_qlog(qlog_directory) {
        Error(_) -> {
          client_connection.close(connection, 0x100, "qlog unavailable")
          process.send(bootstrap, Error(QlogUnavailable))
        }
        Ok(qlog_writer) -> {
          case qlog_writer {
            Some(writer) ->
              qlog.connection_started(writer, udp.monotonic_millisecond())
            None -> Nil
          }
          let commands = process.new_subject()
          let owner_monitor = process.monitor(owner)
          let selector =
            process.new_selector()
            |> process.select_map(commands, ReceivedCommand)
            |> process.select_specific_monitor(owner_monitor, fn(_) {
              OwnerExited
            })
          process.send(
            bootstrap,
            Ok(Connection(
              commands,
              process.self(),
              timeout_milliseconds,
              hostname,
              port,
            )),
          )
          loop(Worker(
            connection,
            dict.new(),
            dict.new(),
            [],
            None,
            commands,
            selector,
            timeout_milliseconds,
            stream_buffer_limit,
            hostname,
            port,
            http_datagrams,
            qlog_writer,
            option.is_some(resumption_ticket),
            case resumption_ticket {
              Some(_) -> Pending
              None -> NotAttempted
            },
            None,
            None,
            dict.new(),
          ))
        }
      }
  }
  Nil
}

fn loop(worker: Worker) -> Nil {
  let worker = dispatch_connection_events(worker)
  let worker = expire_waiters(worker, udp.monotonic_millisecond())
  case process.selector_receive(worker.selector, within: 0) {
    Ok(OwnerExited) -> shutdown(worker, "owner exited")
    Ok(ReceivedCommand(command)) ->
      case handle_command(worker, command) {
        Error(Nil) -> Nil
        Ok(worker) -> loop_after_network(worker)
      }
    Error(Nil) -> loop_after_network(worker)
  }
}

fn loop_after_network(worker: Worker) -> Nil {
  case client_connection.pump(worker.connection, network_poll_milliseconds) {
    Ok(connection) ->
      Worker(..worker, connection: connection)
      |> retry_pending_sends
      |> loop
    Error(error) -> terminate_with_error(worker, map_connection_error(error))
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    Open(hostname, port, headers, reply) -> {
      let outcome = case
        hostname == worker.hostname && port == worker.port,
        unsafe_early_method(worker.resumption_attempted, headers)
      {
        False, _ -> Error(OriginMismatch)
        True, Some(method) -> Error(UnsafeEarlyDataMethod(method))
        True, None ->
          case
            client_connection.open_request(worker.connection, headers, False)
          {
            Error(error) -> Error(map_connection_error(error))
            Ok(#(connection, identifier)) ->
              Ok(#(
                Worker(
                  ..worker,
                  connection: connection,
                  streams: dict.insert(
                    worker.streams,
                    identifier,
                    new_stream_state(),
                  ),
                ),
                identifier,
              ))
          }
      }
      case outcome {
        Error(error) -> {
          process.send(reply, Error(error))
          Ok(worker)
        }
        Ok(#(worker, identifier)) -> {
          process.send(reply, Ok(identifier))
          Ok(worker)
        }
      }
    }
    Send(identifier, bytes, reply, deadline) ->
      handle_send(worker, identifier, bytes, reply, deadline)
    SendTrailers(identifier, headers, reply) ->
      update_stream(worker, identifier, reply, fn(worker, stream) {
        case stream.cancelled, stream.request_finished, stream.pending_send {
          True, _, _ -> Error(StreamCancelled)
          _, True, _ -> Error(RequestAlreadyFinished)
          False, False, Some(_) -> Error(TransportFailed("send in progress"))
          False, False, None ->
            client_connection.finish_with_trailers(
              worker.connection,
              identifier,
              headers,
              False,
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
      })
    Finish(identifier, reply) ->
      update_stream(worker, identifier, reply, fn(worker, stream) {
        case stream.cancelled, stream.request_finished, stream.pending_send {
          True, _, _ -> Error(StreamCancelled)
          _, True, _ -> Error(RequestAlreadyFinished)
          False, False, Some(_) -> Error(TransportFailed("send in progress"))
          False, False, None ->
            client_connection.finish_stream(worker.connection, identifier)
            |> result.map(fn(connection) {
              #(
                Worker(..worker, connection: connection),
                StreamState(..stream, request_finished: True),
                Nil,
              )
            })
            |> result.map_error(map_connection_error)
        }
      })
    Next(identifier, reply, deadline) ->
      case dict.get(worker.streams, identifier) {
        Error(_) -> {
          process.send(reply, Error(StreamFinished))
          Ok(worker)
        }
        Ok(stream) -> handle_next(worker, identifier, stream, reply, deadline)
      }
    Cancel(identifier, reply) -> handle_cancel(worker, identifier, reply)
    NextPush(reply, deadline) -> handle_next_push(worker, reply, deadline)
    NextPushEvent(identifier, reply, deadline) ->
      handle_next_push_event(worker, identifier, reply, deadline)
    CancelPush(identifier, reply) ->
      handle_cancel_push(worker, identifier, reply)
    Close(reply) -> {
      process.send(reply, Ok(Closed))
      shutdown(worker, "application close")
      Error(Nil)
    }
    Capabilities(reply) -> {
      process.send(
        reply,
        Ok(#(
          client_connection.datagrams_available(worker.connection),
          client_connection.active_migration_available(worker.connection),
          worker.resumption_attempted,
          option.is_some(worker.qlog_writer),
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
      process.send(reply, Ok(worker.early_data_status))
      Ok(worker)
    }
    Ticket(reply, deadline) -> handle_ticket(worker, reply, deadline)
    Migrate(reply) ->
      case client_connection.migrate(worker.connection) {
        Error(error) -> {
          process.send(reply, Error(map_connection_error(error)))
          Ok(worker)
        }
        Ok(connection) -> {
          case worker.qlog_writer {
            Some(writer) ->
              qlog.path_updated(writer, udp.monotonic_millisecond())
            None -> Nil
          }
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
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
      process.send(
        reply,
        Ok(client_connection.path_snapshot(worker.connection)),
      )
      Ok(worker)
    }
    ConnectionStats(reply) -> {
      process.send(reply, Ok(client_connection.stats(worker.connection)))
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
  case
    stream.events,
    stream.failure,
    stream.cancelled,
    stream.response_finished
  {
    [event, ..rest], _, _, _ -> {
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
    [], Some(error), _, _ -> {
      process.send(reply, Error(error))
      Ok(worker)
    }
    [], None, True, _ -> {
      process.send(reply, Error(StreamCancelled))
      Ok(worker)
    }
    [], None, False, True -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    [], None, False, False ->
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

fn handle_next_push(
  worker: Worker,
  reply: Subject(Result(IncomingPush, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case worker.pending_pushes, worker.push_waiter {
    [identifier, ..rest], _ -> {
      process.send(reply, incoming_push(worker, identifier))
      Ok(mark_push_delivered(Worker(..worker, pending_pushes: rest), identifier))
    }
    [], Some(_) -> {
      process.send(reply, Error(ConcurrentReceive))
      Ok(worker)
    }
    [], None ->
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
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(push) ->
      case push.delivered {
        False -> {
          process.send(reply, Error(ProtocolError))
          Ok(worker)
        }
        True ->
          case
            push.events,
            push.failure,
            push.cancelled,
            push.response_finished
          {
            [event, ..rest], _, _, _ -> {
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
            [], Some(error), _, _ -> {
              process.send(reply, Error(error))
              Ok(worker)
            }
            [], None, True, _ -> {
              process.send(reply, Error(StreamCancelled))
              Ok(worker)
            }
            [], None, False, True -> {
              process.send(reply, Error(StreamFinished))
              Ok(worker)
            }
            [], None, False, False ->
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

fn handle_cancel_push(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> {
      process.send(reply, Ok(AlreadyCompleted))
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
                  pending_pushes: list.filter(worker.pending_pushes, fn(value) {
                    value != identifier
                  }),
                ),
                identifier,
                PushState(
                  ..push,
                  events: [],
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
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(stream) ->
      case client_connection.datagrams_available(worker.connection) {
        False -> {
          process.send(reply, Error(DatagramsNotNegotiated))
          Ok(worker)
        }
        True ->
          case
            stream.datagrams,
            stream.datagram_failure,
            stream.datagram_waiter
          {
            [datagram, ..rest], _, _ -> {
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
            [], Some(error), _ -> {
              process.send(reply, Error(error))
              Ok(worker)
            }
            [], None, Some(_) -> {
              process.send(reply, Error(ConcurrentDatagramReceive))
              Ok(worker)
            }
            [], None, None ->
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
    1 -> Ok(transport.NewReno)
    2 -> Ok(transport.Cubic)
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
      process.send(reply, Error(StreamFinished))
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
          process.send(reply, Error(TransportFailed("concurrent send")))
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

fn advance_send(
  worker: Worker,
  identifier: Int,
  stream: StreamState,
  pending: PendingSend,
) -> Result(Worker, Nil) {
  let PendingSend(remaining, reply, deadline) = pending
  case udp.monotonic_millisecond() >= deadline {
    True -> {
      process.send(reply, Error(Timeout))
      Ok(put_stream(
        worker,
        identifier,
        StreamState(..stream, pending_send: None),
      ))
    }
    False -> {
      let #(chunk, rest) = take_send_chunk(remaining)
      case client_connection.send_data(worker.connection, identifier, chunk) {
        Ok(connection) ->
          case bit_array.byte_size(rest) {
            0 -> {
              process.send(reply, Ok(Nil))
              Ok(put_stream(
                Worker(..worker, connection: connection),
                identifier,
                StreamState(..stream, pending_send: None),
              ))
            }
            _ ->
              Ok(put_stream(
                Worker(..worker, connection: connection),
                identifier,
                StreamState(
                  ..stream,
                  pending_send: Some(PendingSend(rest, reply, deadline)),
                ),
              ))
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

fn take_send_chunk(bytes: BitArray) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_request_data_chunk_bytes {
    True -> #(bytes, <<>>)
    False -> {
      let assert Ok(chunk) =
        bit_array.slice(
          from: bytes,
          at: 0,
          take: maximum_request_data_chunk_bytes,
        )
      let assert Ok(rest) =
        bit_array.slice(
          from: bytes,
          at: maximum_request_data_chunk_bytes,
          take: size - maximum_request_data_chunk_bytes,
        )
      #(chunk, rest)
    }
  }
}

fn send_buffer_full(error: client_connection.Error) -> Bool {
  case error {
    client_connection.Http3OperationFailed(
      "send_data",
      session.TransportFailure(transport.StreamFailure),
    ) -> True
    _ -> False
  }
}

fn handle_cancel(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.streams, identifier) {
    Error(_) -> {
      process.send(reply, Ok(AlreadyCompleted))
      Ok(worker)
    }
    Ok(stream) ->
      case stream.cancelled, stream.response_finished {
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
            Error(error) -> {
              process.send(reply, Error(map_connection_error(error)))
              Ok(worker)
            }
            Ok(connection) -> {
              notify_waiter(stream.waiter, Error(StreamCancelled))
              notify_pending_send(stream.pending_send, Error(StreamCancelled))
              notify_datagram_waiter(
                stream.datagram_waiter,
                Error(StreamCancelled),
              )
              process.send(reply, Ok(Cancelled))
              Ok(put_stream(
                Worker(..worker, connection: connection),
                identifier,
                StreamState(
                  ..stream,
                  events: [],
                  buffered_data_bytes: 0,
                  waiter: None,
                  pending_send: None,
                  datagram_waiter: None,
                  cancelled: True,
                ),
              ))
            }
          }
      }
  }
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
      process.send(reply, Error(StreamFinished))
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

fn dispatch_events(worker: Worker, events: List(session.Event)) -> Worker {
  case events {
    [] -> worker
    [event, ..rest] -> dispatch_events(dispatch_event(worker, event), rest)
  }
}

fn dispatch_event(worker: Worker, event: session.Event) -> Worker {
  case event {
    session.Http3Event(http3_state.InformationalResponse(identifier, validated)) ->
      enqueue_validated(worker, identifier, validated, True)
    session.Http3Event(http3_state.ResponseHeaders(identifier, validated)) ->
      enqueue_validated(worker, identifier, validated, False)
    session.Http3Event(http3_state.Trailers(identifier, validated)) ->
      case decode_regular_headers(validated) {
        Error(error) -> fail_stream(worker, identifier, error)
        Ok(headers) -> enqueue(worker, identifier, Trailers(headers))
      }
    session.Http3Event(http3_state.Data(identifier, bytes)) ->
      enqueue_data(worker, identifier, bytes)
    session.Http3Event(http3_state.StreamFinished(identifier)) ->
      finish_response(worker, identifier)
    session.TransportEvent(transport.StreamWasReset(identifier, code)) ->
      fail_stream(worker, identifier, StreamReset(code))
    session.Http3Event(http3_state.HttpDatagram(identifier, payload)) ->
      enqueue_datagram(worker, identifier, payload)
    session.Http3Event(http3_state.PushPromised(identifier, validated)) ->
      register_push(worker, identifier, validated)
    session.Http3Event(http3_state.PushInformationalResponse(
      identifier,
      _,
      validated,
    )) -> enqueue_push_validated(worker, identifier, validated, True)
    session.Http3Event(http3_state.PushResponseHeaders(identifier, _, validated)) ->
      enqueue_push_validated(worker, identifier, validated, False)
    session.Http3Event(http3_state.PushData(identifier, _, bytes)) ->
      enqueue_push_data(worker, identifier, bytes)
    session.Http3Event(http3_state.PushTrailers(identifier, _, validated)) ->
      case decode_regular_headers(validated) {
        Error(error) -> fail_push(worker, identifier, error)
        Ok(headers) -> enqueue_push(worker, identifier, Trailers(headers))
      }
    session.Http3Event(http3_state.PushFinished(identifier, _)) ->
      finish_push_response(worker, identifier)
    session.Http3Event(http3_state.PushCancelled(identifier)) ->
      fail_push(worker, identifier, StreamCancelled)
    session.TransportEvent(transport.EarlyDataWasAccepted) ->
      Worker(..worker, early_data_status: Accepted)
    session.TransportEvent(transport.EarlyDataWasRejected) ->
      Worker(..worker, early_data_status: Rejected)
    session.TransportEvent(transport.SessionTicketStored(ticket)) ->
      store_ticket(
        worker,
        ResumptionTicket(worker.hostname, worker.port, ticket),
      )
    session.TransportEvent(transport.PeerClosed(_, _))
    | session.TransportEvent(transport.StatelessResetReceived) ->
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
        PushState(method, path, headers, [], 0, None, False, False, False, None)
      let worker = put_push(worker, identifier, push)
      case worker.push_waiter {
        Some(PushWaiter(reply, _)) -> {
          process.send(reply, incoming_push(worker, identifier))
          mark_push_delivered(Worker(..worker, push_waiter: None), identifier)
        }
        None ->
          Worker(
            ..worker,
            pending_pushes: list.append(worker.pending_pushes, [identifier]),
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
  case push.waiter, push.events, push.delivered {
    Some(Waiter(reply, _)), [], True -> {
      process.send(reply, Ok(event))
      put_push(worker, identifier, PushState(..push, waiter: None))
    }
    _, _, _ ->
      put_push(
        worker,
        identifier,
        PushState(
          ..push,
          events: list.append(push.events, [event]),
          buffered_data_bytes: buffered,
        ),
      )
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
    Ok(push) -> {
      notify_waiter(push.waiter, Error(error))
      put_push(
        Worker(
          ..worker,
          pending_pushes: list.filter(worker.pending_pushes, fn(value) {
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
          case buffered > worker.stream_buffer_limit {
            True ->
              put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagrams: [],
                  buffered_datagram_bytes: 0,
                  datagram_failure: Some(DatagramBufferExceeded(
                    worker.stream_buffer_limit,
                  )),
                ),
              )
            False ->
              put_stream(
                worker,
                identifier,
                StreamState(
                  ..stream,
                  datagrams: list.append(stream.datagrams, [payload]),
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

fn enqueue_validated(
  worker: Worker,
  identifier: Int,
  validated: header_semantics.Validated,
  informational: Bool,
) -> Worker {
  case decode_validated_headers(validated) {
    Error(error) -> fail_stream(worker, identifier, error)
    Ok(#(status, headers)) ->
      case informational {
        True -> enqueue(worker, identifier, Informational(status, headers))
        False -> enqueue(worker, identifier, Response(status, headers))
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
  case stream.waiter, stream.events {
    Some(Waiter(reply, _)), [] -> {
      process.send(reply, Ok(event))
      put_stream(worker, identifier, StreamState(..stream, waiter: None))
    }
    _, _ ->
      put_stream(
        worker,
        identifier,
        StreamState(
          ..stream,
          events: list.append(stream.events, [event]),
          buffered_data_bytes: buffered,
        ),
      )
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
  let worker = fail_all_streams(worker, error) |> fail_all_pushes(error)
  case worker.push_waiter {
    Some(PushWaiter(reply, _)) -> {
      process.send(reply, Error(error))
      Worker(..worker, push_waiter: None)
    }
    None -> worker
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
  let worker = expire_waiter_entries(worker, dict.to_list(worker.streams), now)
  let worker = expire_push_waiters(worker, dict.to_list(worker.pushes), now)
  let worker = case worker.push_waiter {
    Some(PushWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(Timeout))
      Worker(..worker, push_waiter: None)
    }
    _ -> worker
  }
  expire_ticket_waiter(worker, now)
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
          process.send(reply, Error(Timeout))
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
          process.send(reply, Error(Timeout))
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
  shutdown(worker, "connection failed")
}

fn shutdown(worker: Worker, reason: String) -> Nil {
  client_connection.close(worker.connection, 0x100, reason)
  case worker.qlog_writer {
    Some(writer) -> {
      qlog.connection_closed(writer, udp.monotonic_millisecond())
      let _ = qlog.close(writer)
      Nil
    }
    None -> Nil
  }
}

fn open_qlog(directory: String) -> Result(Option(qlog.Writer), qlog.Error) {
  case directory {
    "" -> Ok(None)
    _ ->
      qlog.open(directory, qlog.Client, udp.monotonic_millisecond())
      |> result.map(Some)
  }
}

fn new_stream_state() -> StreamState {
  StreamState([], 0, None, None, [], 0, None, None, False, False, False, None)
}

fn put_stream(worker: Worker, identifier: Int, stream: StreamState) -> Worker {
  Worker(..worker, streams: dict.insert(worker.streams, identifier, stream))
}

fn put_push(worker: Worker, identifier: Int, push: PushState) -> Worker {
  Worker(..worker, pushes: dict.insert(worker.pushes, identifier, push))
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
          process.send(reply, Error(Timeout))
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
          process.send(reply, Error(Timeout))
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
      use rest <- result.try(decode_headers(rest))
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
      Error(Timeout)
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
        Error(Nil) -> Error(Timeout)
      }
    }
  }
}

fn map_connection_error(error: client_connection.Error) -> Error {
  case error {
    client_connection.InvalidInput -> InvalidInput
    client_connection.ResolutionFailed -> ResolutionFailed
    client_connection.SocketUnavailable -> SocketUnavailable
    client_connection.Timeout -> Timeout
    client_connection.TlsHandshakeFailed -> TlsHandshakeFailed
    client_connection.QuicTransportFailed(operation, _) ->
      TransportFailed(operation)
    client_connection.Http3OperationFailed(
      _,
      session.Http3Failure(http3_state.InvalidMessageFraming),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      session.Http3Failure(http3_state.MessageFailure(message_stream.ContentLengthExceeded(
        _,
        _,
      ))),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      session.Http3Failure(http3_state.MessageFailure(message_stream.ContentLengthMismatch(
        _,
        _,
      ))),
    ) -> InvalidContentLength
    client_connection.Http3OperationFailed(
      _,
      session.TransportFailure(transport.DatagramNotNegotiated),
    ) -> DatagramsNotNegotiated
    client_connection.Http3OperationFailed(
      _,
      session.Http3Failure(http3_state.DatagramFailure(datagram.UnknownAssociation(
        _,
      ))),
    ) -> DatagramNotAssociated
    client_connection.Http3OperationFailed(
      _,
      session.Http3Failure(http3_state.DatagramFailure(
        datagram.UnreliableDatagramNotNegotiated,
      )),
    ) -> DatagramsNotNegotiated
    client_connection.Http3OperationFailed(
      _,
      session.TransportFailure(transport.DatagramTooLarge(maximum)),
    ) -> DatagramTooLarge(maximum)
    client_connection.Http3OperationFailed(
      _,
      session.DriverFailure(driver.ConnectionFailure(
        transport.CongestionLimited,
      )),
    ) -> CongestionLimited
    client_connection.Http3OperationFailed(operation, _) ->
      Http3Failed(operation)
    client_connection.PeerClosed -> ConnectionClosed
    client_connection.MigrationUnavailable -> MigrationUnavailable
  }
}

fn valid_resumption_origin(
  ticket: Option(ResumptionTicket),
  hostname: String,
  port: Int,
) -> Bool {
  case ticket {
    None -> True
    Some(ResumptionTicket(bound_hostname, bound_port, _)) ->
      hostname == bound_hostname && port == bound_port
  }
}

fn unsafe_early_method(
  resumption_attempted: Bool,
  headers: List(Header),
) -> Option(String) {
  case resumption_attempted {
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
