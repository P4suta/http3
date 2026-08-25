//// Typed actor owning one reusable generic QUIC client connection.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic.{type AddressFamily}
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/process_label
import gleam_quic/internal/qlog
import gleam_quic/internal/runtime/client_transport
import gleam_quic/internal/runtime/connection as runtime_connection
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/session_ticket
import gleam_quic/internal/udp
import gleam_quic/stream_id
import gleam_quic/version.{type Version}

const worker_reply_grace_milliseconds = 100

const maximum_send_chunk_bytes = 65_536

const pmtu_probe_interval_milliseconds = 50

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
  StreamClosed
  StreamReset(Int)
  InvalidDirection
  ConcurrentSend
  ConcurrentReceive
  ConcurrentAccept
  ConcurrentDatagramReceive
  SendBufferExceeded(Int)
  IncomingStreamQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  DatagramTooLarge(Int)
  DatagramsNotNegotiated
  MigrationUnavailable
  CongestionLimited
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
  Accept(reply: Subject(Result(IncomingStream, Error)), deadline: Int)
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
    deadline: Int,
  )
  ResetStream(identifier: Int, code: Int, reply: Subject(Result(Nil, Error)))
  SendDatagram(payload: BitArray, reply: Subject(Result(Nil, Error)))
  ReceiveDatagram(reply: Subject(Result(BitArray, Error)), deadline: Int)
  MaximumDatagram(reply: Subject(Result(Int, Error)))
  Migrate(reply: Subject(Result(Nil, Error)))
  Ping(reply: Subject(Result(Nil, Error)))
  SetCongestion(
    algorithm: transport.CongestionAlgorithm,
    reply: Subject(Result(Nil, Error)),
  )
  PathStats(reply: Subject(Result(transport.PathSnapshot, Error)))
  ConnectionStats(reply: Subject(Result(runtime_connection.Stats, Error)))
  TelemetryStats(reply: Subject(Result(qlog.Stats, Error)))
  Phase(reply: Subject(Result(transport.Phase, Error)))
  EarlyData(reply: Subject(Result(EarlyDataStatus, Error)))
  Resumption(reply: Subject(Result(ResumptionStatus, Error)))
  Ticket(reply: Subject(Result(ResumptionTicket, Error)), deadline: Int)
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
  Close(reply: Subject(Result(CloseResult, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
  ReceivedNetwork(Dynamic)
  OwnerExited
}

type ReadWaiter {
  ReadWaiter(
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Int,
  )
}

type AcceptWaiter {
  AcceptWaiter(reply: Subject(Result(IncomingStream, Error)), deadline: Int)
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Int)
}

type TicketWaiter {
  TicketWaiter(reply: Subject(Result(ResumptionTicket, Error)), deadline: Int)
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
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

type Worker {
  Worker(
    connection: client_transport.State,
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    streams: Dict(Int, StreamState),
    incoming: Queue(Int),
    accept_waiter: Option(AcceptWaiter),
    datagrams: Queue(BitArray),
    datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    latest_ticket: Option(ResumptionTicket),
    latest_address_token: BitArray,
    ticket_waiter: Option(TicketWaiter),
    early_data_status: EarlyDataStatus,
    resumption_status: ResumptionStatus,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    hostname: String,
    port: Int,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    next_pmtu_probe_milliseconds: Int,
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
  resumption_ticket: Option(ResumptionTicket),
  allow_zero_rtt: Bool,
) -> Result(Connection, Error) {
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
        resumption_ticket,
        allow_zero_rtt,
      )
    })
  await_bootstrap(worker, bootstrap, total_timeout_milliseconds)
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
    Accept(reply, udp.monotonic_millisecond() + connection.timeout_milliseconds)
  })
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
      udp.monotonic_millisecond() + stream.connection.timeout_milliseconds,
    )
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
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
}

pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  call(connection, MaximumDatagram)
}

pub fn migrate(connection: Connection) -> Result(Nil, Error) {
  call(connection, Migrate)
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

pub fn resumption_ticket(
  connection: Connection,
) -> Result(ResumptionTicket, Error) {
  call(connection, fn(reply) {
    Ticket(reply, udp.monotonic_millisecond() + connection.timeout_milliseconds)
  })
}

pub fn negotiated_protocol(
  connection: Connection,
) -> Result(
  #(Version, BitArray, transport.CongestionAlgorithm, Option(hello.CipherSuite)),
  Error,
) {
  call(connection, Protocol)
}

pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  call(connection, Close)
}

pub fn stream_connection(stream: Stream) -> Connection {
  stream.connection
}

pub fn ticket_origin(ticket: ResumptionTicket) -> #(String, Int) {
  #(ticket.hostname, ticket.port)
}

pub fn ticket_native(ticket: ResumptionTicket) -> session_ticket.ClientTicket {
  ticket.ticket
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
  resumption_ticket: Option(ResumptionTicket),
  allow_zero_rtt: Bool,
) -> Nil {
  let #(native_ticket, address_token) = case resumption_ticket {
    Some(value) -> #(Some(value.ticket), value.address_token)
    None -> #(None, <<>>)
  }
  let early_attempted = case native_ticket {
    Some(ticket) -> allow_zero_rtt && session_ticket.early_data_allowed(ticket)
    None -> False
  }
  let config =
    client_transport.Config(
      hostname,
      port,
      address_family,
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
    )
  case client_transport.connect(config) {
    Error(error) -> process.send(bootstrap, Error(map_transport_error(error)))
    Ok(connection) ->
      case open_qlog(qlog_directory, telemetry_limit) {
        Error(error) -> {
          client_transport.close(connection, 0, "qlog unavailable")
          process.send(bootstrap, Error(error))
        }
        Ok(writer) -> {
          let now = udp.monotonic_millisecond()
          case writer {
            Some(value) -> qlog.connection_started(value, now)
            None -> Nil
          }
          let commands = process.new_subject()
          let monitor = process.monitor(owner)
          let selector =
            process.new_selector()
            |> process.select_map(commands, ReceivedCommand)
            |> process.select_specific_monitor(monitor, fn(_) { OwnerExited })
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
          drive_and_loop(Worker(
            connection,
            commands,
            selector,
            dict.new(),
            queue_new(),
            None,
            queue_new(),
            0,
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
            operation_timeout_milliseconds,
            stream_buffer_limit,
            queue_limit,
            datagram_limit,
            hostname,
            port,
            congestion_control,
            writer,
            now + pmtu_probe_interval_milliseconds,
          ))
        }
      }
  }
}

fn loop(worker: Worker) -> Nil {
  let worker = dispatch_transport_events(worker)
  let now = udp.monotonic_millisecond()
  let worker = expire_waiters(worker, now)
  let worker = retry_pending_sends(worker)
  case maybe_probe_path_mtu(worker, now) {
    Error(error) -> shutdown(worker, error)
    Ok(worker) -> wait_for_work(worker, now)
  }
}

fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case next_worker_deadline(worker, now) {
    Error(error) -> shutdown(worker, error)
    Ok(deadline) -> {
      let received = case deadline {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(value) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, value - now),
          )
      }
      case received {
        Ok(OwnerExited) -> shutdown(worker, ConnectionClosed)
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(next) -> drive_and_loop(next)
          }
        Ok(ReceivedNetwork(message)) -> receive_and_loop(worker, message)
        Error(Nil) -> drive_and_loop(worker)
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
      )
      let worker = Worker(..worker, connection: connection)
      case client_transport.activate_once(connection) {
        Ok(Nil) -> loop(worker)
        Error(error) -> shutdown(worker, map_transport_error(error))
      }
    }
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
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
    SendDatagram(payload, reply) -> handle_send_datagram(worker, payload, reply)
    ReceiveDatagram(reply, deadline) ->
      handle_receive_datagram(worker, reply, deadline)
    MaximumDatagram(reply) ->
      reply_with(
        worker,
        reply,
        client_transport.maximum_datagram_size(worker.connection),
      )
    Migrate(reply) ->
      case client_transport.migrate(worker.connection) {
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(Worker(..worker, connection: connection))
        }
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
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
    PathStats(reply) -> {
      process.send(reply, Ok(client_transport.path_stats(worker.connection)))
      Ok(worker)
    }
    ConnectionStats(reply) -> {
      process.send(reply, Ok(client_transport.stats(worker.connection)))
      Ok(worker)
    }
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
    Close(reply) -> {
      process.send(reply, Ok(Closed))
      client_transport.close(worker.connection, 0, "application close")
      close_qlog(worker.qlog_writer)
      Error(Nil)
    }
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
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(#(connection, identifier)) -> {
          process.send(reply, Ok(identifier))
          Ok(put_stream(
            Worker(..worker, connection: connection),
            identifier,
            new_stream_state(),
          ))
        }
      }
  }
}

fn handle_accept(
  worker: Worker,
  reply: Subject(Result(IncomingStream, Error)),
  deadline: Int,
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
                    _ ->
                      put_stream(
                        Worker(..worker, connection: connection),
                        identifier,
                        StreamState(
                          ..stream,
                          pending_send: Some(PendingSend(
                            rest,
                            pending.finish,
                            pending.reply,
                            pending.deadline,
                          )),
                        ),
                      )
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
  deadline: Int,
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
  deadline: Int,
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
  deadline: Int,
) -> Result(Worker, Nil) {
  case worker.latest_ticket, worker.ticket_waiter {
    Some(ticket), _ -> {
      process.send(reply, Ok(ticket))
      Ok(worker)
    }
    None, Some(_) -> reply_error(worker, reply, TicketUnavailable)
    None, None ->
      Ok(Worker(..worker, ticket_waiter: Some(TicketWaiter(reply, deadline))))
  }
}

fn dispatch_transport_events(worker: Worker) -> Worker {
  let #(connection, events) = client_transport.take_events(worker.connection)
  dispatch_events(Worker(..worker, connection: connection), events)
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
    transport.PathValidated -> {
      case worker.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      worker
    }
    transport.PeerClosed(_, _) | transport.StatelessResetReceived ->
      fail_all(worker, ConnectionClosed)
    _ -> worker
  }
}

fn register_stream(worker: Worker, identifier: Int) -> Worker {
  let worker = case dict.has_key(worker.streams, identifier) {
    True -> worker
    False -> put_stream(worker, identifier, new_stream_state())
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
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, _)) -> process.send(reply, Ok(value))
    None -> Nil
  }
  Worker(..worker, latest_ticket: Some(value), ticket_waiter: None)
}

fn store_address_token(worker: Worker, token: BitArray) -> Worker {
  let latest_ticket = case worker.latest_ticket {
    None -> None
    Some(ResumptionTicket(hostname, port, ticket, _)) ->
      Some(ResumptionTicket(hostname, port, ticket, token))
  }
  Worker(..worker, latest_ticket: latest_ticket, latest_address_token: token)
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

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let worker = case worker.accept_waiter {
    Some(AcceptWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, accept_waiter: None)
    }
    _ -> worker
  }
  let worker = case worker.datagram_waiter {
    Some(DatagramWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(OperationTimeout))
      Worker(..worker, datagram_waiter: None)
    }
    _ -> worker
  }
  let worker = case worker.ticket_waiter {
    Some(TicketWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(TicketUnavailable))
      Worker(..worker, ticket_waiter: None)
    }
    _ -> worker
  }
  expire_stream_waiters(worker, dict.to_list(worker.streams), now)
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
        Some(ReadWaiter(_, reply, deadline)) if now >= deadline -> {
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

fn next_worker_deadline(
  worker: Worker,
  now: Int,
) -> Result(Option(Int), Error) {
  use protocol <- result.try(
    client_transport.next_deadline(worker.connection, now)
    |> result.map_error(map_transport_error),
  )
  let deadline =
    protocol
    |> earlier_deadline(positive_deadline(worker.next_pmtu_probe_milliseconds))
    |> earlier_deadline(accept_deadline(worker.accept_waiter))
    |> earlier_deadline(datagram_deadline(worker.datagram_waiter))
    |> earlier_deadline(ticket_deadline(worker.ticket_waiter))
  Ok(stream_deadlines(deadline, dict.values(worker.streams)))
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
    worker.next_pmtu_probe_milliseconds,
    client_transport.path_validation_in_progress(worker.connection),
    client_transport.phase(worker.connection)
  {
    0, _, _ | _, True, _ -> Ok(worker)
    _, _, phase if phase != transport.Established ->
      Ok(
        Worker(
          ..worker,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    deadline, _, _ if now < deadline -> Ok(worker)
    _, _, _ ->
      case client_transport.pmtu_discovery_complete(worker.connection) {
        True -> Ok(Worker(..worker, next_pmtu_probe_milliseconds: 0))
        False ->
          case client_transport.probe_path_mtu(worker.connection, now) {
            Ok(connection) ->
              Ok(
                Worker(
                  ..worker,
                  connection: connection,
                  next_pmtu_probe_milliseconds: now
                    + pmtu_probe_interval_milliseconds,
                ),
              )
            Error(client_transport.QuicFailure(driver.ConnectionFailure(transport.PacingLimited(
              _,
            ))))
            | Error(client_transport.QuicFailure(driver.ConnectionFailure(
                transport.CongestionLimited,
              ))) ->
              Ok(
                Worker(
                  ..worker,
                  next_pmtu_probe_milliseconds: now
                    + pmtu_probe_interval_milliseconds,
                ),
              )
            Error(error) -> Error(map_transport_error(error))
          }
      }
  }
}

fn fail_all(worker: Worker, error: Error) -> Worker {
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case worker.ticket_waiter {
    Some(TicketWaiter(reply, _)) -> process.send(reply, Error(error))
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
    accept_waiter: None,
    datagram_waiter: None,
    ticket_waiter: None,
  )
}

fn shutdown(worker: Worker, error: Error) -> Nil {
  let _ = fail_all(worker, error)
  client_transport.close(worker.connection, 0, "worker shutdown")
  close_qlog(worker.qlog_writer)
}

fn open_qlog(
  directory: String,
  telemetry_limit: Int,
) -> Result(Option(qlog.Writer), Error) {
  case directory {
    "" -> Ok(None)
    value ->
      qlog.open(
        value,
        qlog.Client,
        udp.monotonic_millisecond(),
        telemetry_limit,
      )
      |> result.map(Some)
      |> result.replace_error(QlogUnavailable)
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
      qlog.datagrams_received(writer, now, after_received - before_received)
      qlog.datagrams_sent(writer, now, after_sent - before_sent)
    }
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
  Worker(..worker, streams: dict.insert(worker.streams, identifier, stream))
}

fn new_stream_state() -> StreamState {
  StreamState(None, None, False, False)
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

fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

fn take_bytes(bytes: BitArray, count: Int) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case count >= size {
    True -> #(bytes, <<>>)
    False -> {
      let assert Ok(chunk) = bit_array.slice(bytes, 0, count)
      let assert Ok(rest) = bit_array.slice(bytes, count, size - count)
      #(chunk, rest)
    }
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
    Some(AcceptWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn datagram_deadline(waiter: Option(DatagramWaiter)) -> Option(Int) {
  case waiter {
    Some(DatagramWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn ticket_deadline(waiter: Option(TicketWaiter)) -> Option(Int) {
  case waiter {
    Some(TicketWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn read_deadline(waiter: Option(ReadWaiter)) -> Option(Int) {
  case waiter {
    Some(ReadWaiter(_, _, deadline)) -> Some(deadline)
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
    client_transport.PeerClosed -> ConnectionClosed
    client_transport.MigrationUnavailable -> MigrationUnavailable
    client_transport.VersionNegotiationReceived(_)
    | client_transport.VersionNegotiationFailed -> VersionNegotiationFailed
    client_transport.QuicFailure(error) -> map_driver_error(error)
  }
}

fn map_driver_error(error: driver.Error) -> Error {
  case error {
    driver.ConnectionFailure(transport.CongestionLimited)
    | driver.ConnectionFailure(transport.PacingLimited(_)) -> CongestionLimited
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
