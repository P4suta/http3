//// Listener actor owning UDP, native QUIC connections, and HTTP/3 requests.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/address_token
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/datagram
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/http3/message_stream
import gleam_quic/internal/http3/priority
import gleam_quic/internal/http3/server_connection
import gleam_quic/internal/http3/session
import gleam_quic/internal/packet_space
import gleam_quic/internal/qlog
import gleam_quic/internal/qpack/header.{type Header, Header}
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/packet
import gleam_quic/version

const network_poll_milliseconds = 10

const worker_reply_grace_milliseconds = 100

const maximum_connections = 1024

const maximum_pending_requests = 1024

const maximum_packets_per_connection_flush = 16

const maximum_frame_data_bytes = 1000

const connection_id_bytes = 8

const maximum_response_data_chunk_bytes = 65_536

const request_cancelled_code = 0x10c

const request_rejected_code = 0x10b

const excessive_load_code = 0x107

const replay_window_milliseconds = 600_000

const replay_cache_capacity = 65_536

const ticket_age_tolerance_milliseconds = 10_000

const retry_token_lifetime_milliseconds = 10_000

/// A live listener command subject and its owner-monitoring actor.
pub opaque type Listener {
  Listener(commands: Subject(Command), worker: Pid, timeout_milliseconds: Int)
}

/// One request identity retained entirely inside its listener actor.
pub opaque type Request {
  Request(listener: Listener, identifier: Int)
}

/// One listener-owned server push response.
pub opaque type Push {
  Push(listener: Listener, identifier: Int)
}

/// Primitive accepted request data.
pub type Incoming {
  Incoming(
    request: Request,
    method: String,
    path: String,
    protocol: Option(String),
    headers: List(#(String, String)),
  )
}

/// Pull-based request-body events.
pub type Event {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent listener-stop result.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// Outcome of a GOAWAY-based listener drain.
pub type DrainResult {
  Drained
  Forced
  AlreadyDrained
}

/// Listener, connection, request, or bounded-resource failure.
pub type Error {
  InvalidInput
  StartFailed
  Timeout
  ListenerClosed
  ConnectionClosed
  StreamReset(Int)
  ProtocolError(Int, String)
  RequestBodyTooLarge(Int)
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentAccept
  ConcurrentDrain
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  InvalidContentLength
  InvalidHeaderEncoding
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  StreamFinished
  PushCancelled
  CongestionLimited
  BackendFailure(String)
}

type Command {
  Port(reply: Subject(Result(Int, Error)))
  Accept(reply: Subject(Result(Incoming, Error)), deadline: Int)
  Next(request_id: Int, reply: Subject(Result(Event, Error)), deadline: Int)
  SendResponse(
    request_id: Int,
    status: Int,
    headers: List(#(String, String)),
    declared_content_length: Option(Int),
    reply: Subject(Result(Nil, Error)),
  )
  SendInformational(
    request_id: Int,
    status: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  SendChunk(
    request_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  FinishResponse(request_id: Int, reply: Subject(Result(Nil, Error)))
  FinishWithTrailers(
    request_id: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  PromisePush(
    request_id: Int,
    path: String,
    headers: List(#(String, String)),
    reply: Subject(Result(Int, Error)),
  )
  SendPushResponse(
    push_handle_id: Int,
    status: Int,
    headers: List(#(String, String)),
    declared_content_length: Option(Int),
    reply: Subject(Result(Nil, Error)),
  )
  SendPushChunk(
    push_handle_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  FinishPush(push_handle_id: Int, reply: Subject(Result(Nil, Error)))
  FinishPushWithTrailers(
    push_handle_id: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  Stop(reply: Subject(Result(StopResult, Error)))
  GracefulStop(
    reply: Subject(Result(DrainResult, Error)),
    deadline: Int,
    refine_at: Int,
  )
  Capabilities(
    request_id: Int,
    reply: Subject(Result(#(Bool, Bool, Bool, Bool), Error)),
  )
  MaximumDatagram(request_id: Int, reply: Subject(Result(Int, Error)))
  SendDatagram(
    request_id: Int,
    payload: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  NextDatagram(
    request_id: Int,
    reply: Subject(Result(BitArray, Error)),
    deadline: Int,
  )
  SetPriority(
    request_id: Int,
    urgency: Int,
    incremental: Bool,
    reply: Subject(Result(Nil, Error)),
  )
  GetPriority(request_id: Int, reply: Subject(Result(#(Int, Bool), Error)))
  EarlyData(
    request_id: Int,
    reply: Subject(Result(server_connection.EarlyDataStatus, Error)),
  )
}

type LoopMessage {
  ReceivedCommand(Command)
  OwnerExited
}

type AcceptWaiter {
  AcceptWaiter(reply: Subject(Result(Incoming, Error)), deadline: Int)
}

type EventWaiter {
  EventWaiter(reply: Subject(Result(Event, Error)), deadline: Int)
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Int)
}

type DrainWaiter {
  DrainWaiter(
    reply: Subject(Result(DrainResult, Error)),
    deadline: Int,
    refine_at: Int,
    refined: Bool,
  )
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
}

type RequestState {
  RequestState(
    connection_id: BitArray,
    stream_id: Int,
    method: String,
    path: String,
    protocol: Option(String),
    scheme: String,
    authority: String,
    headers: List(#(String, String)),
    events: List(Event),
    buffered_body_bytes: Int,
    received_body_bytes: Int,
    event_waiter: Option(EventWaiter),
    datagrams: List(BitArray),
    buffered_datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    pending_send: Option(PendingSend),
    request_finished: Bool,
    response_started: Bool,
    response_finished: Bool,
    response_body_bytes: Int,
    declared_content_length: Option(Int),
    priority: #(Int, Bool),
    failure: Option(Error),
  )
}

type PushState {
  PushState(
    connection_id: BitArray,
    push_id: Int,
    stream_id: Int,
    pending_send: Option(PendingSend),
    response_started: Bool,
    response_finished: Bool,
    response_body_bytes: Int,
    declared_content_length: Option(Int),
    failure: Option(Error),
  )
}

type CandidatePath {
  CandidatePath(endpoint: udp.Endpoint, received_bytes: Int, sent_bytes: Int)
}

type PeerState {
  PeerState(
    connection: server_connection.State,
    candidate_path: Option(CandidatePath),
    requests: Dict(Int, Int),
    pushes: Dict(Int, Int),
    priorities: Dict(Int, #(Int, Bool)),
    next_request_stream_id: Int,
  )
}

type Worker {
  Worker(
    socket: udp.Socket,
    port: Int,
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    server_config: server_connection.Config,
    ticket_key: BitArray,
    address_token_key: BitArray,
    replay_cache: anti_replay.Cache,
    connections: Dict(BitArray, PeerState),
    aliases: Dict(BitArray, BitArray),
    requests: Dict(Int, RequestState),
    next_request_id: Int,
    pushes: Dict(Int, PushState),
    next_push_handle_id: Int,
    pending_requests: List(Int),
    accept_waiter: Option(AcceptWaiter),
    drain_waiter: Option(DrainWaiter),
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    qlog_writer: Option(qlog.Writer),
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Bind one IPv4 UDP listener and start its unlinked owner-monitoring actor.
pub fn start(
  port: Int,
  timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  http_datagrams: Bool,
  ipv6: Bool,
  qlog_directory: String,
) -> Result(Listener, Error) {
  case
    port >= 0
    && port <= 65_535
    && timeout_milliseconds > 0
    && request_body_limit > 0
    && response_body_limit > 0
    && stream_buffer_limit > 0
    && certificate_chain != []
  {
    False -> Error(InvalidInput)
    True -> {
      let owner = process.self()
      let bootstrap = process.new_subject()
      let worker =
        process.spawn_unlinked(fn() {
          initialise(
            owner,
            bootstrap,
            port,
            timeout_milliseconds,
            request_body_limit,
            response_body_limit,
            stream_buffer_limit,
            certificate_chain,
            signing_key,
            signature_scheme,
            http_datagrams,
            ipv6,
            qlog_directory,
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

/// Return the concrete bound UDP port.
pub fn port(listener: Listener) -> Result(Int, Error) {
  call(listener, Port)
}

/// Pull the next validated request head.
pub fn accept(listener: Listener) -> Result(Incoming, Error) {
  let deadline = udp.monotonic_millisecond() + listener.timeout_milliseconds
  call_with_timeout(
    listener,
    listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Accept(reply, deadline) },
  )
}

/// Pull one request-body event.
pub fn next_event(request: Request) -> Result(Event, Error) {
  let deadline =
    udp.monotonic_millisecond() + request.listener.timeout_milliseconds
  call_with_timeout(
    request.listener,
    request.listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Next(request.identifier, reply, deadline) },
  )
}

/// Queue one final response head.
pub fn send_response(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  call(request.listener, fn(reply) {
    SendResponse(
      request.identifier,
      status,
      headers,
      declared_content_length,
      reply,
    )
  })
}

/// Queue one informational response head before the final response.
pub fn send_informational(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  call(request.listener, fn(reply) {
    SendInformational(request.identifier, status, headers, reply)
  })
}

/// Queue one response chunk with producer backpressure.
pub fn send_chunk(request: Request, bytes: BitArray) -> Result(Nil, Error) {
  let deadline =
    udp.monotonic_millisecond() + request.listener.timeout_milliseconds
  call_with_timeout(
    request.listener,
    request.listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { SendChunk(request.identifier, bytes, reply, deadline) },
  )
}

/// Validate response framing and queue FIN.
pub fn finish_response(request: Request) -> Result(Nil, Error) {
  call(request.listener, fn(reply) { FinishResponse(request.identifier, reply) })
}

/// Queue response trailers and the terminal FIN atomically.
pub fn send_trailers(
  request: Request,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  call(request.listener, fn(reply) {
    FinishWithTrailers(request.identifier, headers, reply)
  })
}

/// Promise one same-origin GET and open its server push response stream.
pub fn promise_push(
  request: Request,
  path: String,
  headers: List(#(String, String)),
) -> Result(Push, Error) {
  use identifier <- result.try(
    call(request.listener, fn(reply) {
      PromisePush(request.identifier, path, headers, reply)
    }),
  )
  Ok(Push(request.listener, identifier))
}

/// Queue one final pushed response head.
pub fn send_push_response(
  push: Push,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  call(push.listener, fn(reply) {
    SendPushResponse(
      push.identifier,
      status,
      headers,
      declared_content_length,
      reply,
    )
  })
}

/// Queue one pushed response chunk with producer backpressure.
pub fn send_push_chunk(push: Push, bytes: BitArray) -> Result(Nil, Error) {
  let deadline =
    udp.monotonic_millisecond() + push.listener.timeout_milliseconds
  call_with_timeout(
    push.listener,
    push.listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { SendPushChunk(push.identifier, bytes, reply, deadline) },
  )
}

/// Validate pushed response framing and queue FIN.
pub fn finish_push(push: Push) -> Result(Nil, Error) {
  call(push.listener, fn(reply) { FinishPush(push.identifier, reply) })
}

/// Queue pushed response trailers and the terminal FIN atomically.
pub fn send_push_trailers(
  push: Push,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  call(push.listener, fn(reply) {
    FinishPushWithTrailers(push.identifier, headers, reply)
  })
}

/// Stop all connections and release the listener socket idempotently.
pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  case process.is_alive(listener.worker) {
    False -> Ok(AlreadyStopped)
    True ->
      case call(listener, Stop) {
        Error(ListenerClosed) -> Ok(AlreadyStopped)
        outcome -> outcome
      }
  }
}

/// Stop accepting new work, send two-stage GOAWAY, and drain active requests.
pub fn graceful_stop(listener: Listener) -> Result(DrainResult, Error) {
  case process.is_alive(listener.worker) {
    False -> Ok(AlreadyDrained)
    True -> {
      let now = udp.monotonic_millisecond()
      let deadline = now + listener.timeout_milliseconds
      let refine_delay =
        int.max(1, int.min(100, listener.timeout_milliseconds / 4))
      case
        call_with_timeout(
          listener,
          listener.timeout_milliseconds + worker_reply_grace_milliseconds,
          fn(reply) { GracefulStop(reply, deadline, now + refine_delay) },
        )
      {
        Error(ListenerClosed) -> Ok(AlreadyDrained)
        outcome -> outcome
      }
    }
  }
}

/// Return typed advanced capabilities for one request stream.
pub fn capabilities(
  request: Request,
) -> Result(#(Bool, Bool, Bool, Bool), Error) {
  call(request.listener, fn(reply) { Capabilities(request.identifier, reply) })
}

/// Return the maximum HTTP Datagram payload for one request.
pub fn maximum_datagram_size(request: Request) -> Result(Int, Error) {
  call(request.listener, fn(reply) {
    MaximumDatagram(request.identifier, reply)
  })
}

/// Queue one HTTP Datagram.
pub fn send_datagram(
  request: Request,
  payload: BitArray,
) -> Result(Nil, Error) {
  call(request.listener, fn(reply) {
    SendDatagram(request.identifier, payload, reply)
  })
}

/// Pull one HTTP Datagram.
pub fn next_datagram(request: Request) -> Result(BitArray, Error) {
  let deadline =
    udp.monotonic_millisecond() + request.listener.timeout_milliseconds
  call_with_timeout(
    request.listener,
    request.listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextDatagram(request.identifier, reply, deadline) },
  )
}

/// Set one locally effective response priority.
pub fn set_priority(
  request: Request,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  call(request.listener, fn(reply) {
    SetPriority(request.identifier, urgency, incremental, reply)
  })
}

/// Return one locally effective response priority.
pub fn get_priority(request: Request) -> Result(#(Int, Bool), Error) {
  call(request.listener, fn(reply) { GetPriority(request.identifier, reply) })
}

/// Return the connection-level early-data outcome for one request.
pub fn early_data_status(
  request: Request,
) -> Result(server_connection.EarlyDataStatus, Error) {
  call(request.listener, fn(reply) { EarlyData(request.identifier, reply) })
}

fn initialise(
  owner: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  port: Int,
  timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  http_datagrams: Bool,
  ipv6: Bool,
  qlog_directory: String,
) -> Nil {
  let startup = {
    use wildcard <- result.try(
      case ipv6 {
        False -> udp.ipv4(0, 0, 0, 0)
        True -> udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0)
      }
      |> result.replace_error(StartFailed),
    )
    use endpoint <- result.try(
      udp.endpoint(wildcard, port) |> result.replace_error(StartFailed),
    )
    use socket <- result.try(
      udp.open(endpoint) |> result.replace_error(StartFailed),
    )
    use local <- result.try(
      udp.local_endpoint(socket) |> result.replace_error(StartFailed),
    )
    let #(_, bound_port) = udp.endpoint_parts(local)
    use ticket_key <- result.try(
      crypto.secure_random(32) |> result.replace_error(StartFailed),
    )
    use address_token_key <- result.try(
      crypto.secure_random(32) |> result.replace_error(StartFailed),
    )
    use replay_cache <- result.try(
      anti_replay.new(replay_window_milliseconds, replay_cache_capacity)
      |> result.replace_error(StartFailed),
    )
    use qlog_writer <- result.try(
      open_qlog(qlog_directory) |> result.replace_error(StartFailed),
    )
    Ok(#(
      socket,
      bound_port,
      ticket_key,
      address_token_key,
      replay_cache,
      qlog_writer,
    ))
  }
  case startup {
    Error(error) -> process.send(bootstrap, Error(error))
    Ok(#(
      socket,
      bound_port,
      ticket_key,
      address_token_key,
      replay_cache,
      qlog_writer,
    )) -> {
      case qlog_writer {
        Some(writer) ->
          qlog.server_listening(writer, udp.monotonic_millisecond(), bound_port)
        None -> Nil
      }
      let commands = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedCommand)
        |> process.select_specific_monitor(owner_monitor, fn(_) { OwnerExited })
      let config =
        server_connection.Config(
          certificate_chain,
          signing_key,
          signature_scheme,
          ticket_key,
          http_datagrams,
          int.max(request_body_limit, response_body_limit),
        )
      process.send(
        bootstrap,
        Ok(Listener(commands, process.self(), timeout_milliseconds)),
      )
      loop(Worker(
        socket,
        bound_port,
        commands,
        selector,
        config,
        ticket_key,
        address_token_key,
        replay_cache,
        dict.new(),
        dict.new(),
        dict.new(),
        0,
        dict.new(),
        0,
        [],
        None,
        None,
        timeout_milliseconds,
        request_body_limit,
        response_body_limit,
        stream_buffer_limit,
        qlog_writer,
      ))
    }
  }
}

fn loop(worker: Worker) -> Nil {
  let worker = dispatch_all_events(worker)
  let now = udp.monotonic_millisecond()
  let worker = expire_waiters(worker, now)
  case advance_graceful_drain(worker, now) {
    Error(Nil) -> Nil
    Ok(worker) ->
      case process.selector_receive(worker.selector, within: 0) {
        Ok(OwnerExited) -> shutdown(worker, "owner exited")
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(worker) -> network_step(worker)
          }
        Error(Nil) -> network_step(worker)
      }
  }
}

fn network_step(worker: Worker) -> Nil {
  case udp.receive(worker.socket, network_poll_milliseconds) {
    Ok(udp.Datagram(peer, datagram, marking)) ->
      continue_network_step(route_datagram(worker, peer, datagram, marking))
    Error(udp.Timeout) -> continue_network_step(worker)
    Error(udp.Closed) -> shutdown(worker, "socket closed")
    Error(_) -> continue_network_step(worker)
  }
}

fn continue_network_step(worker: Worker) -> Nil {
  worker
  |> tick_and_flush_all
  |> retry_pending_sends
  |> loop
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    Port(reply) -> {
      process.send(reply, Ok(worker.port))
      Ok(worker)
    }
    Accept(reply, deadline) -> handle_accept(worker, reply, deadline)
    Next(identifier, reply, deadline) ->
      handle_next(worker, identifier, reply, deadline)
    SendResponse(identifier, status, headers, declared, reply) ->
      handle_send_response(worker, identifier, status, headers, declared, reply)
    SendInformational(identifier, status, headers, reply) ->
      handle_send_informational(worker, identifier, status, headers, reply)
    SendChunk(identifier, bytes, reply, deadline) ->
      handle_send_chunk(worker, identifier, bytes, reply, deadline)
    FinishResponse(identifier, reply) ->
      handle_finish_response(worker, identifier, reply)
    FinishWithTrailers(identifier, headers, reply) ->
      handle_send_trailers(worker, identifier, headers, reply)
    PromisePush(identifier, path, headers, reply) ->
      handle_promise_push(worker, identifier, path, headers, reply)
    SendPushResponse(identifier, status, headers, declared, reply) ->
      handle_send_push_response(
        worker,
        identifier,
        status,
        headers,
        declared,
        reply,
      )
    SendPushChunk(identifier, bytes, reply, deadline) ->
      handle_send_push_chunk(worker, identifier, bytes, reply, deadline)
    FinishPush(identifier, reply) ->
      handle_finish_push(worker, identifier, reply)
    FinishPushWithTrailers(identifier, headers, reply) ->
      handle_send_push_trailers(worker, identifier, headers, reply)
    Stop(reply) -> {
      process.send(reply, Ok(Stopped))
      shutdown(worker, "application stop")
      Error(Nil)
    }
    GracefulStop(reply, deadline, refine_at) ->
      handle_graceful_stop(worker, reply, deadline, refine_at)
    Capabilities(identifier, reply) -> {
      let outcome =
        with_request_connection(worker, identifier, fn(_, peer, _) {
          let status = server_connection.early_data_status(peer.connection)
          Ok(#(
            server_connection.datagrams_available(peer.connection),
            True,
            status != server_connection.NotAttempted,
            option.is_some(worker.qlog_writer),
          ))
        })
      process.send(reply, outcome)
      Ok(worker)
    }
    MaximumDatagram(identifier, reply) -> {
      let outcome =
        with_request_connection(worker, identifier, fn(request, peer, _) {
          server_connection.maximum_http_datagram_size(
            peer.connection,
            request.stream_id,
          )
          |> result.map_error(map_connection_error)
        })
      process.send(reply, outcome)
      Ok(worker)
    }
    SendDatagram(identifier, payload, reply) ->
      handle_send_datagram(worker, identifier, payload, reply)
    NextDatagram(identifier, reply, deadline) ->
      handle_next_datagram(worker, identifier, reply, deadline)
    SetPriority(identifier, urgency, incremental, reply) ->
      handle_set_priority(worker, identifier, urgency, incremental, reply)
    GetPriority(identifier, reply) -> {
      let outcome =
        dict.get(worker.requests, identifier)
        |> result.map(fn(request) { request.priority })
        |> result.replace_error(StreamFinished)
      process.send(reply, outcome)
      Ok(worker)
    }
    EarlyData(identifier, reply) -> {
      let outcome =
        with_request_connection(worker, identifier, fn(_, peer, _) {
          Ok(server_connection.early_data_status(peer.connection))
        })
      process.send(reply, outcome)
      Ok(worker)
    }
  }
}

fn handle_accept(
  worker: Worker,
  reply: Subject(Result(Incoming, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case worker.drain_waiter, worker.pending_requests, worker.accept_waiter {
    Some(_), _, _ -> {
      process.send(reply, Error(ListenerClosed))
      Ok(worker)
    }
    None, [identifier, ..rest], _ -> {
      process.send(reply, incoming(worker, identifier))
      Ok(Worker(..worker, pending_requests: rest))
    }
    None, [], Some(_) -> {
      process.send(reply, Error(ConcurrentAccept))
      Ok(worker)
    }
    None, [], None ->
      Ok(Worker(..worker, accept_waiter: Some(AcceptWaiter(reply, deadline))))
  }
}

fn handle_graceful_stop(
  worker: Worker,
  reply: Subject(Result(DrainResult, Error)),
  deadline: Int,
  refine_at: Int,
) -> Result(Worker, Nil) {
  case worker.drain_waiter {
    Some(_) -> {
      process.send(reply, Error(ConcurrentDrain))
      Ok(worker)
    }
    None -> {
      case worker.accept_waiter {
        Some(AcceptWaiter(waiting, _)) ->
          process.send(waiting, Error(ListenerClosed))
        None -> Nil
      }
      let worker =
        reject_pending_requests(worker, worker.pending_requests)
        |> start_drain_connections(udp.monotonic_millisecond())
      Ok(
        Worker(
          ..worker,
          pending_requests: [],
          accept_waiter: None,
          drain_waiter: Some(DrainWaiter(reply, deadline, refine_at, False)),
        ),
      )
    }
  }
}

fn advance_graceful_drain(worker: Worker, now: Int) -> Result(Worker, Nil) {
  case worker.drain_waiter {
    None -> Ok(worker)
    Some(DrainWaiter(reply, deadline, _, _)) if now >= deadline -> {
      process.send(reply, Ok(Forced))
      shutdown(Worker(..worker, drain_waiter: None), "drain timeout")
      Error(Nil)
    }
    Some(DrainWaiter(reply, deadline, refine_at, False)) if now >= refine_at -> {
      let worker = refine_drain_connections(worker)
      advance_graceful_drain(
        Worker(
          ..worker,
          drain_waiter: Some(DrainWaiter(reply, deadline, refine_at, True)),
        ),
        now,
      )
    }
    Some(DrainWaiter(reply, _, _, True)) ->
      case all_requests_complete(worker) {
        False -> Ok(worker)
        True -> {
          process.send(reply, Ok(Drained))
          let worker = close_drained_connections(worker)
          shutdown(Worker(..worker, drain_waiter: None), "graceful drain")
          Error(Nil)
        }
      }
    Some(_) -> Ok(worker)
  }
}

fn close_drained_connections(worker: Worker) -> Worker {
  close_drained_entries(worker, dict.to_list(worker.connections))
}

fn close_drained_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let worker = case server_connection.close_drained(peer.connection) {
        Error(_) -> worker
        Ok(connection) ->
          put_peer(
            worker,
            connection_id,
            PeerState(..peer, connection: connection),
          )
      }
      close_drained_entries(worker, rest)
    }
  }
}

fn start_drain_connections(worker: Worker, now: Int) -> Worker {
  start_drain_entries(worker, dict.to_list(worker.connections), now)
}

fn start_drain_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let worker = case server_connection.start_drain(peer.connection, now) {
        Error(_) -> worker
        Ok(connection) ->
          put_peer(
            worker,
            connection_id,
            PeerState(..peer, connection: connection),
          )
      }
      start_drain_entries(worker, rest, now)
    }
  }
}

fn refine_drain_connections(worker: Worker) -> Worker {
  refine_drain_entries(worker, dict.to_list(worker.connections))
}

fn refine_drain_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let worker = case
        server_connection.refine_drain(
          peer.connection,
          peer.next_request_stream_id,
        )
      {
        Error(_) -> worker
        Ok(#(connection, rejected)) -> {
          let worker =
            put_peer(
              worker,
              connection_id,
              PeerState(..peer, connection: connection),
            )
          reject_streams(worker, connection_id, rejected)
        }
      }
      refine_drain_entries(worker, rest)
    }
  }
}

fn reject_streams(
  worker: Worker,
  connection_id: BitArray,
  stream_ids: List(Int),
) -> Worker {
  case stream_ids {
    [] -> worker
    [stream_id, ..rest] -> {
      let worker =
        fail_stream(worker, connection_id, stream_id, ListenerClosed)
        |> abort_stream_id(connection_id, stream_id, request_rejected_code)
      reject_streams(worker, connection_id, rest)
    }
  }
}

fn abort_stream_id(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  code: Int,
) -> Worker {
  case
    update_peer_connection(worker, connection_id, fn(connection) {
      server_connection.abort_stream(connection, stream_id, code)
    })
  {
    Ok(worker) -> worker
    Error(_) -> worker
  }
}

fn reject_pending_requests(worker: Worker, identifiers: List(Int)) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] -> {
      let worker =
        fail_request(worker, identifier, ListenerClosed)
        |> abort_request(identifier, request_rejected_code)
      reject_pending_requests(worker, rest)
    }
  }
}

fn all_requests_complete(worker: Worker) -> Bool {
  let requests_complete =
    dict.values(worker.requests)
    |> list.all(fn(request) {
      option.is_some(request.failure)
      || request.request_finished
      && request.response_finished
    })
  requests_complete
  && dict.values(worker.pushes)
  |> list.all(fn(push) {
    option.is_some(push.failure) || push.response_finished
  })
}

fn handle_next(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Event, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(request) ->
      case request.events, request.failure, request.event_waiter {
        [event, ..rest], _, _ -> {
          process.send(reply, Ok(event))
          let buffered = case event {
            Data(bytes) ->
              request.buffered_body_bytes - bit_array.byte_size(bytes)
            _ -> request.buffered_body_bytes
          }
          Ok(put_request(
            worker,
            identifier,
            RequestState(
              ..request,
              events: rest,
              buffered_body_bytes: int.max(buffered, 0),
            ),
          ))
        }
        [], Some(error), _ -> {
          process.send(reply, Error(error))
          Ok(worker)
        }
        [], None, Some(_) -> {
          process.send(reply, Error(ConcurrentReceive))
          Ok(worker)
        }
        [], None, None ->
          Ok(put_request(
            worker,
            identifier,
            RequestState(
              ..request,
              event_waiter: Some(EventWaiter(reply, deadline)),
            ),
          ))
      }
  }
}

fn handle_send_response(
  worker: Worker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(_) if status < 200 || status > 599 ->
      reply_error(worker, reply, InvalidInput)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure,
        exceeds_response_body_limit(
          declared_content_length,
          worker.response_body_limit,
        )
      {
        _, _, Some(error), _ -> {
          process.send(reply, Error(error))
          Ok(worker)
        }
        True, _, _, _ -> {
          process.send(reply, Error(ResponseAlreadyStarted))
          Ok(worker)
        }
        _, True, _, _ -> {
          process.send(reply, Error(ResponseAlreadyFinished))
          Ok(worker)
        }
        False, False, None, True -> {
          process.send(
            reply,
            Error(ResponseBodyTooLarge(worker.response_body_limit)),
          )
          Ok(worker)
        }
        False, False, None, False ->
          case response_headers(status, headers) {
            Error(error) -> {
              process.send(reply, Error(error))
              Ok(worker)
            }
            Ok(encoded) ->
              case
                update_peer_connection(
                  worker,
                  request.connection_id,
                  fn(connection) {
                    server_connection.send_response_headers(
                      connection,
                      request.stream_id,
                      encoded,
                    )
                  },
                )
              {
                Error(error) -> {
                  process.send(reply, Error(error))
                  Ok(worker)
                }
                Ok(worker) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_request(
                    worker,
                    identifier,
                    RequestState(
                      ..request,
                      response_started: True,
                      declared_content_length: declared_content_length,
                    ),
                  ))
                }
              }
          }
      }
  }
}

fn handle_send_informational(
  worker: Worker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(_) if status < 100 || status >= 200 || status == 101 ->
      reply_error(worker, reply, InvalidInput)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure
      {
        _, _, Some(error) -> reply_error(worker, reply, error)
        True, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(encoded) ->
              case
                update_peer_connection(
                  worker,
                  request.connection_id,
                  fn(connection) {
                    server_connection.send_response_headers(
                      connection,
                      request.stream_id,
                      encoded,
                    )
                  },
                )
              {
                Error(error) -> reply_error(worker, reply, error)
                Ok(worker) -> {
                  process.send(reply, Ok(Nil))
                  Ok(worker)
                }
              }
          }
      }
  }
}

fn handle_send_chunk(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(request) -> {
      let new_total = request.response_body_bytes + bit_array.byte_size(bytes)
      case
        request.response_started,
        request.response_finished,
        request.pending_send,
        request.failure,
        new_total > worker.response_body_limit,
        exceeds_declared_length(request.declared_content_length, new_total)
      {
        False, _, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _, _ ->
          reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _, _ ->
          reply_error(worker, reply, BackendFailure("concurrent response send"))
        _, _, _, Some(error), _, _ -> reply_error(worker, reply, error)
        _, _, _, _, True, _ ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        _, _, _, _, _, True -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, False, False ->
          advance_response_send(
            worker,
            identifier,
            RequestState(..request, response_body_bytes: new_total),
            PendingSend(bytes, reply, deadline),
          )
      }
    }
  }
}

fn handle_finish_response(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.pending_send,
        request.failure,
        declared_length_matches(
          request.declared_content_length,
          request.response_body_bytes,
        )
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _ ->
          reply_error(
            worker,
            reply,
            BackendFailure("response send in progress"),
          )
        _, _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, True ->
          case
            update_peer_connection(
              worker,
              request.connection_id,
              fn(connection) {
                server_connection.finish_stream(connection, request.stream_id)
              },
            )
          {
            Error(error) -> reply_error(worker, reply, error)
            Ok(worker) -> {
              process.send(reply, Ok(Nil))
              Ok(put_request(
                worker,
                identifier,
                RequestState(..request, response_finished: True),
              ))
            }
          }
      }
  }
}

fn handle_send_trailers(
  worker: Worker,
  identifier: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.pending_send,
        request.failure,
        declared_length_matches(
          request.declared_content_length,
          request.response_body_bytes,
        )
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _ ->
          reply_error(
            worker,
            reply,
            BackendFailure("response send in progress"),
          )
        _, _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, True ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(encoded) ->
              case
                update_peer_connection(
                  worker,
                  request.connection_id,
                  fn(connection) {
                    use connection <- result.try(
                      server_connection.send_trailers(
                        connection,
                        request.stream_id,
                        encoded,
                      ),
                    )
                    server_connection.finish_stream(
                      connection,
                      request.stream_id,
                    )
                  },
                )
              {
                Error(error) -> reply_error(worker, reply, error)
                Ok(worker) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_request(
                    worker,
                    identifier,
                    RequestState(..request, response_finished: True),
                  ))
                }
              }
          }
      }
  }
}

fn handle_promise_push(
  worker: Worker,
  request_identifier: Int,
  path: String,
  headers: List(#(String, String)),
  reply: Subject(Result(Int, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, request_identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(request) ->
      case request.failure, request.scheme, request.authority, path {
        Some(error), _, _, _ -> reply_error(worker, reply, error)
        None, "", _, _ | None, _, "", _ | None, _, _, "" ->
          reply_error(worker, reply, InvalidInput)
        None, scheme, authority, path ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(regular) -> {
              let fields = [
                Header(<<":method">>, <<"GET">>, False),
                Header(<<":scheme">>, <<scheme:utf8>>, False),
                Header(<<":authority">>, <<authority:utf8>>, False),
                Header(<<":path">>, <<path:utf8>>, False),
                ..regular
              ]
              case dict.get(worker.connections, request.connection_id) {
                Error(_) -> reply_error(worker, reply, ConnectionClosed)
                Ok(peer) ->
                  case
                    server_connection.promise_push(
                      peer.connection,
                      request.stream_id,
                      fields,
                      udp.monotonic_millisecond(),
                    )
                  {
                    Error(error) ->
                      reply_error(worker, reply, map_connection_error(error))
                    Ok(#(connection, push_id, stream_id)) -> {
                      let identifier = worker.next_push_handle_id
                      let peer =
                        PeerState(
                          ..peer,
                          connection: connection,
                          pushes: dict.insert(peer.pushes, push_id, identifier),
                        )
                      let push =
                        PushState(
                          request.connection_id,
                          push_id,
                          stream_id,
                          None,
                          False,
                          False,
                          0,
                          None,
                          None,
                        )
                      process.send(reply, Ok(identifier))
                      Ok(
                        put_peer(worker, request.connection_id, peer)
                        |> put_push(identifier, push)
                        |> fn(next) {
                          Worker(..next, next_push_handle_id: identifier + 1)
                        },
                      )
                    }
                  }
              }
            }
          }
      }
  }
}

fn handle_send_push_response(
  worker: Worker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(_) if status < 200 || status > 599 ->
      reply_error(worker, reply, InvalidInput)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.failure,
        exceeds_response_body_limit(
          declared_content_length,
          worker.response_body_limit,
        )
      {
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None, True ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        False, False, None, False ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(encoded) ->
              case
                update_push_connection(worker, push, fn(connection) {
                  server_connection.send_push_response_headers(
                    connection,
                    push.stream_id,
                    encoded,
                  )
                })
              {
                Error(error) -> reply_error(worker, reply, error)
                Ok(worker) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_push(
                    worker,
                    identifier,
                    PushState(
                      ..push,
                      response_started: True,
                      declared_content_length: declared_content_length,
                    ),
                  ))
                }
              }
          }
      }
  }
}

fn handle_send_push_chunk(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(push) -> {
      let total = push.response_body_bytes + bit_array.byte_size(bytes)
      case
        push.response_started,
        push.response_finished,
        push.pending_send,
        push.failure,
        total > worker.response_body_limit,
        exceeds_declared_length(push.declared_content_length, total)
      {
        False, _, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _, _ ->
          reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _, _ ->
          reply_error(worker, reply, BackendFailure("concurrent push send"))
        _, _, _, Some(error), _, _ -> reply_error(worker, reply, error)
        _, _, _, _, True, _ ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        _, _, _, _, _, True -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, False, False ->
          advance_push_send(
            worker,
            identifier,
            PushState(..push, response_body_bytes: total),
            PendingSend(bytes, reply, deadline),
          )
      }
    }
  }
}

fn handle_finish_push(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.pending_send,
        push.failure,
        declared_length_matches(
          push.declared_content_length,
          push.response_body_bytes,
        )
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _ ->
          reply_error(worker, reply, BackendFailure("push send in progress"))
        _, _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, True ->
          case
            update_push_connection(worker, push, fn(connection) {
              server_connection.finish_push(connection, push.stream_id)
            })
          {
            Error(error) -> reply_error(worker, reply, error)
            Ok(worker) -> {
              process.send(reply, Ok(Nil))
              Ok(put_push(
                worker,
                identifier,
                PushState(..push, response_finished: True),
              ))
            }
          }
      }
  }
}

fn handle_send_push_trailers(
  worker: Worker,
  identifier: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.pending_send,
        push.failure,
        declared_length_matches(
          push.declared_content_length,
          push.response_body_bytes,
        )
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(_), _, _ ->
          reply_error(worker, reply, BackendFailure("push send in progress"))
        _, _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, None, True ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(encoded) ->
              case
                update_push_connection(worker, push, fn(connection) {
                  use connection <- result.try(
                    server_connection.send_push_trailers(
                      connection,
                      push.stream_id,
                      encoded,
                    ),
                  )
                  server_connection.finish_push(connection, push.stream_id)
                })
              {
                Error(error) -> reply_error(worker, reply, error)
                Ok(worker) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_push(
                    worker,
                    identifier,
                    PushState(..push, response_finished: True),
                  ))
                }
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
  case dict.get(worker.requests, identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(request) ->
      case
        update_peer_connection(worker, request.connection_id, fn(connection) {
          server_connection.send_http_datagram(
            connection,
            request.stream_id,
            payload,
          )
        })
      {
        Error(error) -> reply_error(worker, reply, error)
        Ok(worker) -> {
          process.send(reply, Ok(Nil))
          Ok(worker)
        }
      }
  }
}

fn handle_next_datagram(
  worker: Worker,
  identifier: Int,
  reply: Subject(Result(BitArray, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> {
      process.send(reply, Error(StreamFinished))
      Ok(worker)
    }
    Ok(request) ->
      case request.datagrams, request.failure, request.datagram_waiter {
        [payload, ..rest], _, _ -> {
          process.send(reply, Ok(payload))
          Ok(put_request(
            worker,
            identifier,
            RequestState(
              ..request,
              datagrams: rest,
              buffered_datagram_bytes: int.max(
                request.buffered_datagram_bytes - bit_array.byte_size(payload),
                0,
              ),
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
          Ok(put_request(
            worker,
            identifier,
            RequestState(
              ..request,
              datagram_waiter: Some(DatagramWaiter(reply, deadline)),
            ),
          ))
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
  case dict.get(worker.requests, identifier), urgency >= 0 && urgency <= 7 {
    Error(_), _ -> reply_error(worker, reply, StreamFinished)
    _, False -> reply_error(worker, reply, InvalidInput)
    Ok(request), True -> {
      process.send(reply, Ok(Nil))
      Ok(put_request(
        worker,
        identifier,
        RequestState(..request, priority: #(urgency, incremental)),
      ))
    }
  }
}

fn route_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case datagram {
    <<first, _rest:bits>> if first >= 0x80 ->
      route_long_datagram(worker, peer, datagram, marking)
    <<_first, destination:bytes-size(connection_id_bytes), _rest:bits>> ->
      route_existing(worker, destination, peer, datagram, marking)
    _ -> worker
  }
}

fn route_long_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case packet.parse_long(datagram) {
    Error(_) -> worker
    Ok(#(parsed, _)) -> {
      let header = packet_header(parsed)
      let packet.LongHeader(_, protocol_version, destination, source) = header
      case resolve_alias(worker, destination) {
        Some(connection_id) ->
          route_existing(worker, connection_id, peer, datagram, marking)
        None ->
          case worker.drain_waiter, parsed, protocol_version {
            Some(_), _, _ -> worker
            None, packet.Initial(_, token, _), version.Version1
            | None, packet.Initial(_, token, _), version.Version2
            ->
              route_initial(
                worker,
                peer,
                protocol_version,
                destination,
                source,
                token,
                datagram,
                marking,
              )
            None, packet.UnknownVersion(_, _), _ ->
              send_version_negotiation(worker, peer, destination, source)
            _, _, _ -> worker
          }
      }
    }
  }
}

fn route_initial(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  destination: BitArray,
  peer_connection_id: BitArray,
  token: BitArray,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case token {
    <<>> ->
      send_retry(
        worker,
        peer,
        protocol_version,
        destination,
        peer_connection_id,
      )
    _ -> {
      let #(address, port) = udp.endpoint_parts(peer)
      let now = udp.monotonic_millisecond()
      case
        address_token.open(
          worker.address_token_key,
          token,
          address,
          port,
          now,
          retry_token_lifetime_milliseconds,
        )
      {
        Ok(address_token.Token(
          address_token.Retry,
          original_destination,
          retry_source,
          _,
        ))
          if retry_source == destination
        ->
          accept_connection(
            worker,
            peer,
            protocol_version,
            original_destination,
            Some(retry_source),
            peer_connection_id,
            Some(retry_source),
            datagram,
            marking,
          )
        Ok(address_token.Token(address_token.NewToken, <<>>, <<>>, _)) ->
          accept_connection(
            worker,
            peer,
            protocol_version,
            destination,
            None,
            peer_connection_id,
            None,
            datagram,
            marking,
          )
        _ -> worker
      }
    }
  }
}

fn route_existing(
  worker: Worker,
  connection_id: BitArray,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer_state) -> {
      let now = udp.monotonic_millisecond()
      let assert Ok(policy) = replay_policy(worker, now)
      case
        server_connection.receive_datagram(
          peer_state.connection,
          datagram,
          marking,
          now,
          policy,
        )
      {
        Error(error) -> {
          case discard_connection_error(error) {
            True -> worker
            False ->
              fail_connection(
                worker,
                connection_id,
                map_connection_error(error),
              )
          }
        }
        Ok(connection) -> {
          let previous_peer = server_connection.peer(peer_state.connection)
          case worker.qlog_writer {
            Some(writer) ->
              qlog.datagram_received(writer, now, bit_array.byte_size(datagram))
            None -> Nil
          }
          case same_endpoint(previous_peer, peer) {
            True -> {
              let next = PeerState(..peer_state, connection: connection)
              put_peer(worker, connection_id, next)
              |> update_replay_cache(connection)
            }
            False ->
              case server_connection.is_established(connection) {
                False -> {
                  let connection = server_connection.with_peer(connection, peer)
                  let next = PeerState(..peer_state, connection: connection)
                  put_peer(worker, connection_id, next)
                  |> update_replay_cache(connection)
                }
                True ->
                  case
                    receive_candidate_path(
                      peer_state,
                      connection,
                      peer,
                      bit_array.byte_size(datagram),
                      now,
                    )
                  {
                    Error(_) -> worker
                    Ok(next) ->
                      put_peer(worker, connection_id, next)
                      |> update_replay_cache(next.connection)
                  }
              }
          }
        }
      }
    }
  }
}

fn receive_candidate_path(
  peer_state: PeerState,
  connection: server_connection.State,
  endpoint: udp.Endpoint,
  received_bytes: Int,
  now: Int,
) -> Result(PeerState, Nil) {
  case peer_state.candidate_path {
    Some(CandidatePath(candidate, received, sent)) ->
      case same_endpoint(candidate, endpoint) {
        False -> Error(Nil)
        True ->
          Ok(
            PeerState(
              ..peer_state,
              connection: connection,
              candidate_path: Some(CandidatePath(
                candidate,
                received + received_bytes,
                sent,
              )),
            ),
          )
      }
    None -> {
      use challenge <- result.try(
        crypto.secure_random(8) |> result.replace_error(Nil),
      )
      use connection <- result.try(
        server_connection.begin_path_validation(connection, challenge, now)
        |> result.replace_error(Nil),
      )
      Ok(
        PeerState(
          ..peer_state,
          connection: connection,
          candidate_path: Some(CandidatePath(endpoint, received_bytes, 0)),
        ),
      )
    }
  }
}

fn accept_connection(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  original_destination: BitArray,
  selected_local_connection_id: Option(BitArray),
  peer_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case
    dict.size(worker.connections) >= maximum_connections,
    bit_array.byte_size(original_destination) >= 8,
    bit_array.byte_size(peer_connection_id) >= 8,
    bit_array.byte_size(datagram) >= 1200
  {
    True, _, _, _ | _, False, _, _ | _, _, False, _ | _, _, _, False -> worker
    False, True, True, True ->
      case
        case selected_local_connection_id {
          Some(value) -> Ok(value)
          None -> unique_connection_id(worker, 8)
        }
      {
        Error(_) -> worker
        Ok(local_connection_id) -> {
          let now = udp.monotonic_millisecond()
          let assert Ok(policy) = replay_policy(worker, now)
          case
            server_connection.accept_initial(
              worker.server_config,
              protocol_version,
              original_destination,
              local_connection_id,
              peer_connection_id,
              retry_source_connection_id,
              peer,
              datagram,
              marking,
              now,
              policy,
            )
          {
            Error(_) -> worker
            Ok(connection) -> {
              case worker.qlog_writer {
                Some(writer) -> {
                  qlog.connection_started(writer, now)
                  qlog.datagram_received(
                    writer,
                    now,
                    bit_array.byte_size(datagram),
                  )
                }
                None -> Nil
              }
              let worker =
                Worker(
                  ..worker,
                  connections: dict.insert(
                    worker.connections,
                    local_connection_id,
                    PeerState(
                      connection,
                      None,
                      dict.new(),
                      dict.new(),
                      dict.new(),
                      0,
                    ),
                  ),
                  aliases: case retry_source_connection_id {
                    Some(_) -> worker.aliases
                    None ->
                      dict.insert(
                        worker.aliases,
                        original_destination,
                        local_connection_id,
                      )
                  },
                )
              update_replay_cache(worker, connection)
            }
          }
        }
      }
  }
}

fn send_retry(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  original_destination: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  case
    bit_array.byte_size(original_destination) >= 8,
    bit_array.byte_size(peer_connection_id) >= 8,
    unique_connection_id(worker, 8)
  {
    False, _, _ | _, False, _ | _, _, Error(_) -> worker
    True, True, Ok(retry_source) -> {
      let #(address, port) = udp.endpoint_parts(peer)
      let now = udp.monotonic_millisecond()
      case
        address_token.seal(
          worker.address_token_key,
          address_token.Retry,
          address,
          port,
          original_destination,
          retry_source,
          now,
        ),
        retry_first_byte(protocol_version)
      {
        Ok(token), Ok(first_byte) ->
          send_retry_packet(
            worker,
            peer,
            protocol_version,
            original_destination,
            peer_connection_id,
            retry_source,
            first_byte,
            token,
          )
        _, _ -> worker
      }
    }
  }
}

fn send_retry_packet(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  original_destination: BitArray,
  peer_connection_id: BitArray,
  retry_source: BitArray,
  first_byte: Int,
  token: BitArray,
) -> Worker {
  let placeholder =
    packet.Retry(
      packet.LongHeader(
        first_byte,
        protocol_version,
        peer_connection_id,
        retry_source,
      ),
      token,
      <<0:128>>,
    )
  case packet.encode_long(placeholder) {
    Error(_) -> worker
    Ok(encoded) ->
      case bit_array.slice(encoded, 0, bit_array.byte_size(encoded) - 16) {
        Error(_) -> worker
        Ok(retry_without_tag) ->
          case
            retry_integrity.tag(
              protocol_version,
              original_destination,
              retry_without_tag,
            )
          {
            Error(_) -> worker
            Ok(tag) -> {
              let _ =
                udp.send(
                  worker.socket,
                  peer,
                  <<retry_without_tag:bits, tag:bits>>,
                  ecn.NotEct,
                )
              worker
            }
          }
      }
  }
}

fn retry_first_byte(
  protocol_version: version.Version,
) -> Result(Int, crypto.Error) {
  use random <- result.try(crypto.secure_random(1))
  let assert <<random_low_bits>> = random
  let base = case protocol_version {
    version.Version1 -> 0xf0
    version.Version2 -> 0xc0
    _ -> 0
  }
  case base {
    0 -> Error(crypto.InvalidInput)
    _ -> Ok(int.bitwise_or(base, int.bitwise_and(random_low_bits, 0x0f)))
  }
}

fn send_version_negotiation(
  worker: Worker,
  peer: udp.Endpoint,
  original_destination: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  let response =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        peer_connection_id,
        original_destination,
      ),
      [version.Version2, version.Version1],
    )
  case packet.encode_long(response) {
    Error(_) -> worker
    Ok(bytes) -> {
      let _ = udp.send(worker.socket, peer, bytes, ecn.NotEct)
      worker
    }
  }
}

fn tick_and_flush_all(worker: Worker) -> Worker {
  tick_and_flush_entries(
    worker,
    dict.to_list(worker.connections),
    udp.monotonic_millisecond(),
  )
}

fn tick_and_flush_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let worker = case server_connection.tick(peer.connection, now) {
        Error(error) ->
          fail_connection(worker, connection_id, map_connection_error(error))
        Ok(connection) ->
          flush_connection(
            put_peer(
              worker,
              connection_id,
              PeerState(..peer, connection: connection),
            ),
            connection_id,
            maximum_packets_per_connection_flush,
            now,
          )
      }
      tick_and_flush_entries(worker, rest, now)
    }
  }
}

fn flush_connection(
  worker: Worker,
  connection_id: BitArray,
  remaining: Int,
  now: Int,
) -> Worker {
  case remaining, dict.get(worker.connections, connection_id) {
    0, _ | _, Error(_) -> worker
    _, Ok(peer) ->
      case
        server_connection.prepare_datagram(
          peer.connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Error(error) ->
          case is_send_pressure(error) {
            True -> worker
            False ->
              fail_connection(
                worker,
                connection_id,
                map_connection_error(error),
              )
          }
        Ok(None) -> worker
        Ok(Some(prepared)) -> {
          let bytes = server_connection.prepared_bytes(prepared)
          case candidate_send_endpoint(peer, bit_array.byte_size(bytes)) {
            Error(_) -> worker
            Ok(endpoint) ->
              case udp.send(worker.socket, endpoint, bytes, ecn.NotEct) {
                Error(_) ->
                  fail_connection(worker, connection_id, ConnectionClosed)
                Ok(Nil) -> {
                  let peer =
                    record_candidate_send(peer, bit_array.byte_size(bytes))
                  case worker.qlog_writer {
                    Some(writer) ->
                      qlog.datagram_sent(
                        writer,
                        now,
                        bit_array.byte_size(bytes),
                      )
                    None -> Nil
                  }
                  case
                    server_connection.commit_datagram(prepared, ecn.NotEct, now)
                  {
                    Error(error) ->
                      fail_connection(
                        worker,
                        connection_id,
                        map_connection_error(error),
                      )
                    Ok(connection) ->
                      flush_connection(
                        put_peer(
                          worker,
                          connection_id,
                          PeerState(..peer, connection: connection),
                        ),
                        connection_id,
                        remaining - 1,
                        now,
                      )
                  }
                }
              }
          }
        }
      }
  }
}

fn candidate_send_endpoint(
  peer: PeerState,
  datagram_bytes: Int,
) -> Result(udp.Endpoint, Nil) {
  case peer.candidate_path {
    None -> Ok(server_connection.peer(peer.connection))
    Some(CandidatePath(endpoint, received, sent)) ->
      case sent + datagram_bytes <= received * 3 {
        True -> Ok(endpoint)
        False -> Error(Nil)
      }
  }
}

fn record_candidate_send(peer: PeerState, datagram_bytes: Int) -> PeerState {
  case peer.candidate_path {
    None -> peer
    Some(CandidatePath(endpoint, received, sent)) ->
      PeerState(
        ..peer,
        candidate_path: Some(CandidatePath(
          endpoint,
          received,
          sent + datagram_bytes,
        )),
      )
  }
}

fn dispatch_all_events(worker: Worker) -> Worker {
  dispatch_connection_entries(worker, dict.to_list(worker.connections))
}

fn dispatch_connection_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let #(connection, events) = server_connection.take_events(peer.connection)
      let worker =
        put_peer(
          worker,
          connection_id,
          PeerState(..peer, connection: connection),
        )
      let worker = dispatch_events(worker, connection_id, events)
      dispatch_connection_entries(worker, rest)
    }
  }
}

fn dispatch_events(
  worker: Worker,
  connection_id: BitArray,
  events: List(session.Event),
) -> Worker {
  case events {
    [] -> worker
    [event, ..rest] ->
      dispatch_events(
        dispatch_event(worker, connection_id, event),
        connection_id,
        rest,
      )
  }
}

fn dispatch_event(
  worker: Worker,
  connection_id: BitArray,
  event: session.Event,
) -> Worker {
  case event {
    session.Http3Event(http3_state.RequestHeaders(stream_id, validated)) ->
      accept_request_head(worker, connection_id, stream_id, validated)
    session.Http3Event(http3_state.Data(_, <<>>)) -> worker
    session.Http3Event(http3_state.Data(stream_id, bytes)) ->
      enqueue_body_data(worker, connection_id, stream_id, bytes)
    session.Http3Event(http3_state.Trailers(stream_id, validated)) ->
      case decode_trailers(validated) {
        Ok(headers) ->
          enqueue_stream_event(
            worker,
            connection_id,
            stream_id,
            Trailers(headers),
          )
        Error(error) -> fail_stream(worker, connection_id, stream_id, error)
      }
    session.Http3Event(http3_state.StreamFinished(stream_id)) ->
      mark_request_finished(worker, connection_id, stream_id)
      |> enqueue_stream_event(connection_id, stream_id, End)
    session.TransportEvent(transport.StreamWasReset(stream_id, code)) ->
      fail_stream(worker, connection_id, stream_id, StreamReset(code))
    session.Http3Event(http3_state.HttpDatagram(stream_id, payload)) ->
      enqueue_datagram(worker, connection_id, stream_id, payload)
    session.TransportEvent(transport.PeerClosed(_, _))
    | session.TransportEvent(transport.StatelessResetReceived) ->
      fail_connection(worker, connection_id, ConnectionClosed)
    session.TransportEvent(transport.PathValidated) ->
      commit_candidate_path(worker, connection_id)
    session.TransportEvent(transport.PathValidationFailed) ->
      discard_candidate_path(worker, connection_id)
    session.Http3Event(http3_state.PriorityChanged(update)) ->
      apply_peer_priority(worker, connection_id, update)
    session.Http3Event(http3_state.PushCancelled(push_id)) ->
      fail_server_push(worker, connection_id, push_id, PushCancelled)
    session.Http3Event(http3_state.PushStreamCancellationRequested(
      push_id,
      stream_id,
    )) ->
      fail_server_push(worker, connection_id, push_id, PushCancelled)
      |> abort_stream_id(connection_id, stream_id, request_cancelled_code)
    _ -> worker
  }
}

fn commit_candidate_path(worker: Worker, connection_id: BitArray) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(PeerState(candidate_path: None, ..)) -> worker
    Ok(peer) -> {
      let assert Some(CandidatePath(endpoint, _, _)) = peer.candidate_path
      case worker.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      put_peer(
        worker,
        connection_id,
        PeerState(
          ..peer,
          connection: server_connection.with_peer(peer.connection, endpoint),
          candidate_path: None,
        ),
      )
    }
  }
}

fn discard_candidate_path(worker: Worker, connection_id: BitArray) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) ->
      put_peer(worker, connection_id, PeerState(..peer, candidate_path: None))
  }
}

fn accept_request_head(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  validated: header_semantics.Validated,
) -> Worker {
  case decode_request(validated), dict.get(worker.connections, connection_id) {
    Error(_), _ | _, Error(_) -> worker
    Ok(#(method, path, protocol, scheme, authority, headers)), Ok(peer) -> {
      let identifier = worker.next_request_id
      let effective_priority =
        dict.get(peer.priorities, stream_id)
        |> result.unwrap(#(3, False))
      let request =
        RequestState(
          connection_id,
          stream_id,
          method,
          path,
          protocol,
          scheme,
          authority,
          headers,
          [],
          0,
          0,
          None,
          [],
          0,
          None,
          None,
          False,
          False,
          False,
          0,
          None,
          effective_priority,
          None,
        )
      let worker =
        Worker(
          ..worker,
          connections: dict.insert(
            worker.connections,
            connection_id,
            PeerState(
              ..peer,
              requests: dict.insert(peer.requests, stream_id, identifier),
              next_request_stream_id: int.max(
                peer.next_request_stream_id,
                stream_id + 4,
              ),
            ),
          ),
          requests: dict.insert(worker.requests, identifier, request),
          next_request_id: identifier + 1,
        )
      deliver_request(worker, identifier)
    }
  }
}

fn deliver_request(worker: Worker, identifier: Int) -> Worker {
  case worker.drain_waiter, worker.accept_waiter {
    Some(_), _ ->
      fail_request(worker, identifier, ListenerClosed)
      |> abort_request(identifier, request_rejected_code)
    None, Some(AcceptWaiter(reply, _)) -> {
      process.send(reply, incoming(worker, identifier))
      Worker(..worker, accept_waiter: None)
    }
    None, None ->
      case list.length(worker.pending_requests) >= maximum_pending_requests {
        True -> abort_request(worker, identifier, excessive_load_code)
        False ->
          Worker(
            ..worker,
            pending_requests: list.append(worker.pending_requests, [identifier]),
          )
      }
  }
}

fn enqueue_body_data(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  bytes: BitArray,
) -> Worker {
  case request_for_stream(worker, connection_id, stream_id) {
    Error(_) -> worker
    Ok(#(identifier, request)) -> {
      let total = request.received_body_bytes + bit_array.byte_size(bytes)
      case total > worker.request_body_limit {
        True ->
          abort_request(
            fail_request(
              worker,
              identifier,
              RequestBodyTooLarge(worker.request_body_limit),
            ),
            identifier,
            request_cancelled_code,
          )
        False -> {
          let request = RequestState(..request, received_body_bytes: total)
          enqueue_request_event(worker, identifier, request, Data(bytes))
        }
      }
    }
  }
}

fn enqueue_stream_event(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  event: Event,
) -> Worker {
  case request_for_stream(worker, connection_id, stream_id) {
    Error(_) -> worker
    Ok(#(identifier, request)) ->
      enqueue_request_event(worker, identifier, request, event)
  }
}

fn mark_request_finished(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
) -> Worker {
  case request_for_stream(worker, connection_id, stream_id) {
    Error(_) -> worker
    Ok(#(identifier, request)) ->
      put_request(
        worker,
        identifier,
        RequestState(..request, request_finished: True),
      )
  }
}

fn enqueue_request_event(
  worker: Worker,
  identifier: Int,
  request: RequestState,
  event: Event,
) -> Worker {
  case request.failure, request.event_waiter, request.events {
    Some(_), _, _ -> worker
    None, Some(EventWaiter(reply, _)), [] -> {
      process.send(reply, Ok(event))
      put_request(
        worker,
        identifier,
        RequestState(..request, event_waiter: None),
      )
    }
    None, _, _ -> {
      let buffered = case event {
        Data(bytes) -> request.buffered_body_bytes + bit_array.byte_size(bytes)
        _ -> request.buffered_body_bytes
      }
      case buffered > worker.stream_buffer_limit {
        True ->
          abort_request(
            fail_request(
              worker,
              identifier,
              ConsumerTooSlow(worker.stream_buffer_limit),
            ),
            identifier,
            request_cancelled_code,
          )
        False ->
          put_request(
            worker,
            identifier,
            RequestState(
              ..request,
              events: list.append(request.events, [event]),
              buffered_body_bytes: buffered,
            ),
          )
      }
    }
  }
}

fn enqueue_datagram(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  payload: BitArray,
) -> Worker {
  case request_for_stream(worker, connection_id, stream_id) {
    Error(_) -> worker
    Ok(#(identifier, request)) ->
      case request.failure, request.datagram_waiter {
        Some(_), _ -> worker
        None, Some(DatagramWaiter(reply, _)) -> {
          process.send(reply, Ok(payload))
          put_request(
            worker,
            identifier,
            RequestState(..request, datagram_waiter: None),
          )
        }
        None, None -> {
          let buffered =
            request.buffered_datagram_bytes + bit_array.byte_size(payload)
          case buffered > worker.stream_buffer_limit {
            True ->
              fail_request(
                worker,
                identifier,
                DatagramBufferExceeded(worker.stream_buffer_limit),
              )
            False ->
              put_request(
                worker,
                identifier,
                RequestState(
                  ..request,
                  datagrams: list.append(request.datagrams, [payload]),
                  buffered_datagram_bytes: buffered,
                ),
              )
          }
        }
      }
  }
}

fn advance_response_send(
  worker: Worker,
  identifier: Int,
  request: RequestState,
  pending: PendingSend,
) -> Result(Worker, Nil) {
  let PendingSend(remaining, reply, deadline) = pending
  case udp.monotonic_millisecond() >= deadline {
    True ->
      reply_error(
        put_request(
          worker,
          identifier,
          RequestState(..request, pending_send: None),
        ),
        reply,
        Timeout,
      )
    False -> {
      let #(chunk, rest) = take_response_chunk(remaining)
      case
        update_peer_connection(worker, request.connection_id, fn(connection) {
          server_connection.send_data(connection, request.stream_id, chunk)
        })
      {
        Ok(worker) ->
          case bit_array.byte_size(rest) {
            0 -> {
              process.send(reply, Ok(Nil))
              Ok(put_request(
                worker,
                identifier,
                RequestState(..request, pending_send: None),
              ))
            }
            _ ->
              Ok(put_request(
                worker,
                identifier,
                RequestState(
                  ..request,
                  pending_send: Some(PendingSend(rest, reply, deadline)),
                ),
              ))
          }
        Error(CongestionLimited) ->
          Ok(put_request(
            worker,
            identifier,
            RequestState(..request, pending_send: Some(pending)),
          ))
        Error(error) ->
          reply_error(
            put_request(
              worker,
              identifier,
              RequestState(..request, pending_send: None),
            ),
            reply,
            error,
          )
      }
    }
  }
}

fn advance_push_send(
  worker: Worker,
  identifier: Int,
  push: PushState,
  pending: PendingSend,
) -> Result(Worker, Nil) {
  let PendingSend(remaining, reply, deadline) = pending
  case udp.monotonic_millisecond() >= deadline {
    True ->
      reply_error(
        put_push(worker, identifier, PushState(..push, pending_send: None)),
        reply,
        Timeout,
      )
    False -> {
      let #(chunk, rest) = take_response_chunk(remaining)
      case
        update_push_connection(worker, push, fn(connection) {
          server_connection.send_push_data(connection, push.stream_id, chunk)
        })
      {
        Ok(worker) ->
          case bit_array.byte_size(rest) {
            0 -> {
              process.send(reply, Ok(Nil))
              Ok(put_push(
                worker,
                identifier,
                PushState(..push, pending_send: None),
              ))
            }
            _ ->
              Ok(put_push(
                worker,
                identifier,
                PushState(
                  ..push,
                  pending_send: Some(PendingSend(rest, reply, deadline)),
                ),
              ))
          }
        Error(CongestionLimited) ->
          Ok(put_push(
            worker,
            identifier,
            PushState(..push, pending_send: Some(pending)),
          ))
        Error(error) ->
          reply_error(
            put_push(worker, identifier, PushState(..push, pending_send: None)),
            reply,
            error,
          )
      }
    }
  }
}

fn retry_pending_sends(worker: Worker) -> Worker {
  let worker = retry_pending_send_entries(worker, dict.to_list(worker.requests))
  retry_pending_push_entries(worker, dict.to_list(worker.pushes))
}

fn retry_pending_push_entries(
  worker: Worker,
  entries: List(#(Int, PushState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, push), ..rest] -> {
      let worker = case push.pending_send {
        None -> worker
        Some(pending) ->
          case advance_push_send(worker, identifier, push, pending) {
            Ok(worker) -> worker
            Error(Nil) -> worker
          }
      }
      retry_pending_push_entries(worker, rest)
    }
  }
}

fn retry_pending_send_entries(
  worker: Worker,
  entries: List(#(Int, RequestState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, request), ..rest] -> {
      let worker = case request.pending_send {
        None -> worker
        Some(pending) ->
          case advance_response_send(worker, identifier, request, pending) {
            Ok(worker) -> worker
            Error(Nil) -> worker
          }
      }
      retry_pending_send_entries(worker, rest)
    }
  }
}

fn take_response_chunk(bytes: BitArray) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_response_data_chunk_bytes {
    True -> #(bytes, <<>>)
    False -> {
      let assert Ok(chunk) =
        bit_array.slice(bytes, 0, maximum_response_data_chunk_bytes)
      let assert Ok(rest) =
        bit_array.slice(
          bytes,
          maximum_response_data_chunk_bytes,
          size - maximum_response_data_chunk_bytes,
        )
      #(chunk, rest)
    }
  }
}

fn update_peer_connection(
  worker: Worker,
  connection_id: BitArray,
  update: fn(server_connection.State) ->
    Result(server_connection.State, server_connection.Error),
) -> Result(Worker, Error) {
  use peer <- result.try(
    dict.get(worker.connections, connection_id)
    |> result.replace_error(ConnectionClosed),
  )
  case update(peer.connection) {
    Ok(connection) ->
      Ok(put_peer(
        worker,
        connection_id,
        PeerState(..peer, connection: connection),
      ))
    Error(error) -> Error(map_connection_error(error))
  }
}

fn update_push_connection(
  worker: Worker,
  push: PushState,
  update: fn(server_connection.State) ->
    Result(server_connection.State, server_connection.Error),
) -> Result(Worker, Error) {
  update_peer_connection(worker, push.connection_id, update)
}

fn with_request_connection(
  worker: Worker,
  identifier: Int,
  operation: fn(RequestState, PeerState, Worker) -> Result(value, Error),
) -> Result(value, Error) {
  use request <- result.try(
    dict.get(worker.requests, identifier)
    |> result.replace_error(StreamFinished),
  )
  use peer <- result.try(
    dict.get(worker.connections, request.connection_id)
    |> result.replace_error(ConnectionClosed),
  )
  operation(request, peer, worker)
}

fn request_for_stream(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
) -> Result(#(Int, RequestState), Nil) {
  use peer <- result.try(dict.get(worker.connections, connection_id))
  use identifier <- result.try(dict.get(peer.requests, stream_id))
  use request <- result.try(dict.get(worker.requests, identifier))
  Ok(#(identifier, request))
}

fn incoming(worker: Worker, identifier: Int) -> Result(Incoming, Error) {
  use request <- result.try(
    dict.get(worker.requests, identifier)
    |> result.replace_error(StreamFinished),
  )
  Ok(Incoming(
    Request(
      Listener(worker.commands, process.self(), worker.timeout_milliseconds),
      identifier,
    ),
    request.method,
    request.path,
    request.protocol,
    request.headers,
  ))
}

fn response_headers(
  status: Int,
  headers: List(#(String, String)),
) -> Result(List(Header), Error) {
  use regular <- result.try(encode_headers(headers))
  Ok([Header(<<":status">>, <<int.to_string(status):utf8>>, False), ..regular])
}

fn encode_headers(
  headers: List(#(String, String)),
) -> Result(List(Header), Error) {
  case headers {
    [] -> Ok([])
    [#(name, value), ..rest] -> {
      use rest <- result.try(encode_headers(rest))
      Ok([Header(<<name:utf8>>, <<value:utf8>>, False), ..rest])
    }
  }
}

fn decode_request(
  validated: header_semantics.Validated,
) -> Result(
  #(String, String, Option(String), String, String, List(#(String, String))),
  Error,
) {
  let header_semantics.Validated(control, fields, _) = validated
  use request <- result.try(case control {
    header_semantics.RequestControlData(request) -> Ok(request)
    _ -> Error(ProtocolError(0x105, "invalid request control"))
  })
  let header_semantics.RequestControl(method, scheme, authority, path, protocol) =
    request
  use method <- result.try(
    bit_array.to_string(method) |> result.replace_error(InvalidHeaderEncoding),
  )
  let path = case path {
    Some(value) -> bit_array.to_string(value) |> result.unwrap("")
    None -> ""
  }
  let scheme = case scheme {
    Some(value) -> bit_array.to_string(value) |> result.unwrap("")
    None -> ""
  }
  let authority = case authority {
    Some(value) -> bit_array.to_string(value) |> result.unwrap("")
    None -> ""
  }
  use protocol <- result.try(case protocol {
    None -> Ok(None)
    Some(value) ->
      bit_array.to_string(value)
      |> result.map(Some)
      |> result.replace_error(InvalidHeaderEncoding)
  })
  use fields <- result.try(decode_headers(fields))
  Ok(#(method, path, protocol, scheme, authority, fields))
}

fn decode_trailers(
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
        bit_array.to_string(name) |> result.replace_error(InvalidHeaderEncoding),
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

fn packet_header(parsed: packet.Packet) -> packet.LongHeader {
  case parsed {
    packet.VersionNegotiation(header, _)
    | packet.UnknownVersion(header, _)
    | packet.Initial(header, _, _)
    | packet.ZeroRtt(header, _)
    | packet.Handshake(header, _)
    | packet.Retry(header, _, _) -> header
  }
}

fn resolve_alias(worker: Worker, destination: BitArray) -> Option(BitArray) {
  case dict.has_key(worker.connections, destination) {
    True -> Some(destination)
    False ->
      case dict.get(worker.aliases, destination) {
        Ok(value) -> Some(value)
        Error(_) -> None
      }
  }
}

fn unique_connection_id(
  worker: Worker,
  attempts: Int,
) -> Result(BitArray, Nil) {
  case attempts {
    0 -> Error(Nil)
    _ ->
      case crypto.secure_random(connection_id_bytes) {
        Error(_) -> unique_connection_id(worker, attempts - 1)
        Ok(value) ->
          case dict.has_key(worker.connections, value) {
            False -> Ok(value)
            True -> unique_connection_id(worker, attempts - 1)
          }
      }
  }
}

fn replay_policy(
  worker: Worker,
  now: Int,
) -> Result(resumption.ServerPolicy, resumption.Error) {
  resumption.server_policy(
    worker.ticket_key,
    now,
    ticket_age_tolerance_milliseconds,
    worker.replay_cache,
  )
}

fn update_replay_cache(
  worker: Worker,
  connection: server_connection.State,
) -> Worker {
  case server_connection.replay_cache(connection) {
    Some(cache) -> Worker(..worker, replay_cache: cache)
    None -> worker
  }
}

fn apply_peer_priority(
  worker: Worker,
  connection_id: BitArray,
  update: priority.Update,
) -> Worker {
  case dict.get(worker.connections, connection_id), update {
    Error(_), _ -> worker
    Ok(_peer), priority.PushUpdate(_, _) -> worker
    Ok(peer),
      priority.RequestUpdate(stream_id, priority.Priority(urgency, incremental))
    -> {
      let peer =
        PeerState(
          ..peer,
          priorities: dict.insert(peer.priorities, stream_id, #(
            urgency,
            incremental,
          )),
        )
      let worker = put_peer(worker, connection_id, peer)
      case dict.get(peer.requests, stream_id) {
        Error(_) -> worker
        Ok(identifier) ->
          case dict.get(worker.requests, identifier) {
            Error(_) -> worker
            Ok(request) ->
              put_request(
                worker,
                identifier,
                RequestState(..request, priority: #(urgency, incremental)),
              )
          }
      }
    }
  }
}

fn abort_request(worker: Worker, identifier: Int, code: Int) -> Worker {
  case dict.get(worker.requests, identifier) {
    Error(_) -> worker
    Ok(request) ->
      case
        update_peer_connection(worker, request.connection_id, fn(connection) {
          server_connection.abort_stream(connection, request.stream_id, code)
        })
      {
        Ok(worker) -> worker
        Error(_) -> worker
      }
  }
}

fn fail_stream(
  worker: Worker,
  connection_id: BitArray,
  stream_id: Int,
  error: Error,
) -> Worker {
  case request_for_stream(worker, connection_id, stream_id) {
    Error(_) -> worker
    Ok(#(identifier, _)) -> fail_request(worker, identifier, error)
  }
}

fn fail_request(worker: Worker, identifier: Int, error: Error) -> Worker {
  case dict.get(worker.requests, identifier) {
    Error(_) -> worker
    Ok(request) -> {
      notify_event_waiter(request.event_waiter, Error(error))
      notify_datagram_waiter(request.datagram_waiter, Error(error))
      notify_pending_send(request.pending_send, Error(error))
      put_request(
        worker,
        identifier,
        RequestState(
          ..request,
          event_waiter: None,
          datagram_waiter: None,
          pending_send: None,
          failure: Some(error),
        ),
      )
    }
  }
}

fn fail_server_push(
  worker: Worker,
  connection_id: BitArray,
  push_id: Int,
  error: Error,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) ->
      case dict.get(peer.pushes, push_id) {
        Error(_) -> worker
        Ok(identifier) -> fail_push(worker, identifier, error)
      }
  }
}

fn fail_push(worker: Worker, identifier: Int, error: Error) -> Worker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(push) -> {
      notify_pending_send(push.pending_send, Error(error))
      put_push(
        worker,
        identifier,
        PushState(..push, pending_send: None, failure: Some(error)),
      )
    }
  }
}

fn fail_push_ids(
  worker: Worker,
  identifiers: List(Int),
  error: Error,
) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_push_ids(fail_push(worker, identifier, error), rest, error)
  }
}

fn fail_connection(
  worker: Worker,
  connection_id: BitArray,
  error: Error,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) -> {
      let worker = fail_request_ids(worker, dict.values(peer.requests), error)
      let worker = fail_push_ids(worker, dict.values(peer.pushes), error)
      Worker(
        ..worker,
        connections: dict.delete(worker.connections, connection_id),
        aliases: dict.filter(worker.aliases, fn(_, value) {
          value != connection_id
        }),
      )
    }
  }
}

fn fail_request_ids(
  worker: Worker,
  identifiers: List(Int),
  error: Error,
) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_request_ids(fail_request(worker, identifier, error), rest, error)
  }
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let worker = case worker.accept_waiter {
    Some(AcceptWaiter(reply, deadline)) if now >= deadline -> {
      process.send(reply, Error(Timeout))
      Worker(..worker, accept_waiter: None)
    }
    _ -> worker
  }
  let worker =
    expire_request_waiters(worker, dict.to_list(worker.requests), now)
  expire_push_waiters(worker, dict.to_list(worker.pushes), now)
}

fn expire_push_waiters(
  worker: Worker,
  entries: List(#(Int, PushState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, push), ..rest] -> {
      let push = case push.pending_send {
        Some(PendingSend(_, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(Timeout))
          PushState(..push, pending_send: None)
        }
        _ -> push
      }
      expire_push_waiters(put_push(worker, identifier, push), rest, now)
    }
  }
}

fn expire_request_waiters(
  worker: Worker,
  entries: List(#(Int, RequestState)),
  now: Int,
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, request), ..rest] -> {
      let request = case request.event_waiter {
        Some(EventWaiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(Timeout))
          RequestState(..request, event_waiter: None)
        }
        _ -> request
      }
      let request = case request.datagram_waiter {
        Some(DatagramWaiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(Timeout))
          RequestState(..request, datagram_waiter: None)
        }
        _ -> request
      }
      let request = case request.pending_send {
        Some(PendingSend(_, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(Timeout))
          RequestState(..request, pending_send: None)
        }
        _ -> request
      }
      expire_request_waiters(
        put_request(worker, identifier, request),
        rest,
        now,
      )
    }
  }
}

fn shutdown(worker: Worker, reason: String) -> Nil {
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> process.send(reply, Error(ListenerClosed))
    None -> Nil
  }
  case worker.drain_waiter {
    Some(DrainWaiter(reply, _, _, _)) -> process.send(reply, Ok(Forced))
    None -> Nil
  }
  let worker =
    fail_request_ids(worker, dict.keys(worker.requests), ListenerClosed)
    |> fail_push_ids(dict.keys(worker.pushes), ListenerClosed)
  close_connections(
    worker.socket,
    dict.values(worker.connections),
    udp.monotonic_millisecond(),
    reason,
  )
  case worker.qlog_writer {
    Some(writer) -> {
      qlog.connection_closed(writer, udp.monotonic_millisecond())
      let _ = qlog.close(writer)
      Nil
    }
    None -> Nil
  }
  let _ = udp.close(worker.socket)
  Nil
}

fn open_qlog(directory: String) -> Result(Option(qlog.Writer), qlog.Error) {
  case directory {
    "" -> Ok(None)
    _ ->
      qlog.open(directory, qlog.Server, udp.monotonic_millisecond())
      |> result.map(Some)
  }
}

fn close_connections(
  socket: udp.Socket,
  peers: List(PeerState),
  now: Int,
  reason: String,
) -> Nil {
  case peers {
    [] -> Nil
    [peer, ..rest] -> {
      let connection =
        server_connection.close(peer.connection, 0x100, reason, now)
      case
        server_connection.prepare_datagram(
          connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Ok(Some(prepared)) -> {
          let _sent =
            udp.send(
              socket,
              server_connection.peer(connection),
              server_connection.prepared_bytes(prepared),
              ecn.NotEct,
            )
          Nil
        }
        _ -> Nil
      }
      close_connections(socket, rest, now, reason)
    }
  }
}

fn put_peer(worker: Worker, identifier: BitArray, peer: PeerState) -> Worker {
  Worker(
    ..worker,
    connections: dict.insert(worker.connections, identifier, peer),
  )
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn put_request(
  worker: Worker,
  identifier: Int,
  request: RequestState,
) -> Worker {
  Worker(..worker, requests: dict.insert(worker.requests, identifier, request))
}

fn put_push(worker: Worker, identifier: Int, push: PushState) -> Worker {
  Worker(..worker, pushes: dict.insert(worker.pushes, identifier, push))
}

fn reply_error(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
}

fn exceeds_declared_length(length: Option(Int), actual: Int) -> Bool {
  case length {
    Some(expected) -> actual > expected
    None -> False
  }
}

fn exceeds_response_body_limit(length: Option(Int), limit: Int) -> Bool {
  case length {
    Some(expected) -> expected > limit
    None -> False
  }
}

fn declared_length_matches(length: Option(Int), actual: Int) -> Bool {
  case length {
    Some(expected) -> actual == expected
    None -> True
  }
}

fn is_send_pressure(error: server_connection.Error) -> Bool {
  case error {
    server_connection.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
      _,
    )))
    | server_connection.DriverFailure(driver.ConnectionFailure(
        transport.CongestionLimited,
      ))
    | server_connection.SessionFailure(session.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
        _,
      ))))
    | server_connection.SessionFailure(session.DriverFailure(driver.ConnectionFailure(
        transport.CongestionLimited,
      ))) -> True
    _ -> False
  }
}

fn discard_connection_error(error: server_connection.Error) -> Bool {
  case error {
    server_connection.DriverFailure(driver.InvalidInput)
    | server_connection.DriverFailure(driver.DestinationConnectionIdMismatch)
    | server_connection.DriverFailure(driver.PacketFailure(_))
    | server_connection.DriverFailure(driver.ConnectionFailure(transport.MissingReadKeys(
        _,
      )))
    | server_connection.DriverFailure(driver.ConnectionFailure(transport.MissingWriteKeys(
        _,
      )))
    | server_connection.SessionFailure(session.DriverFailure(
        driver.InvalidInput,
      ))
    | server_connection.SessionFailure(session.DriverFailure(
        driver.DestinationConnectionIdMismatch,
      ))
    | server_connection.SessionFailure(session.DriverFailure(driver.PacketFailure(
        _,
      )))
    | server_connection.SessionFailure(session.DriverFailure(driver.ConnectionFailure(transport.MissingReadKeys(
        _,
      ))))
    | server_connection.SessionFailure(session.DriverFailure(driver.ConnectionFailure(transport.MissingWriteKeys(
        _,
      )))) -> True
    _ -> False
  }
}

fn map_connection_error(error: server_connection.Error) -> Error {
  case error {
    server_connection.InvalidInput -> BackendFailure("invalid connection state")
    server_connection.TlsFailure(_) -> ProtocolError(0x100, "TLS failure")
    server_connection.DriverFailure(driver.ConnectionFailure(
      transport.StreamFailure,
    ))
    | server_connection.SessionFailure(session.TransportFailure(
        transport.StreamFailure,
      )) -> CongestionLimited
    server_connection.SessionFailure(session.TransportFailure(
      transport.DatagramNotNegotiated,
    )) -> DatagramsNotNegotiated
    server_connection.SessionFailure(session.Http3Failure(http3_state.DatagramFailure(datagram.UnknownAssociation(
      _,
    )))) -> DatagramNotAssociated
    server_connection.SessionFailure(session.Http3Failure(http3_state.DatagramFailure(
      datagram.UnreliableDatagramNotNegotiated,
    ))) -> DatagramsNotNegotiated
    server_connection.SessionFailure(session.TransportFailure(transport.DatagramTooLarge(
      limit,
    ))) -> DatagramTooLarge(limit)
    server_connection.SessionFailure(session.Http3Failure(http3_state.MessageFailure(
      message_stream.ContentLengthExceeded(..),
    )))
    | server_connection.SessionFailure(session.Http3Failure(http3_state.MessageFailure(
        message_stream.ContentLengthMismatch(..),
      ))) -> InvalidContentLength
    server_connection.DriverFailure(_) -> ConnectionClosed
    server_connection.SessionFailure(_) -> ConnectionClosed
  }
}

fn notify_event_waiter(
  waiter: Option(EventWaiter),
  outcome: Result(Event, Error),
) -> Nil {
  case waiter {
    Some(EventWaiter(reply, _)) -> process.send(reply, outcome)
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

fn notify_pending_send(
  pending: Option(PendingSend),
  outcome: Result(Nil, Error),
) -> Nil {
  case pending {
    Some(PendingSend(_, reply, _)) -> process.send(reply, outcome)
    None -> Nil
  }
}

fn await_bootstrap(
  worker: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  timeout: Int,
) -> Result(Listener, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(bootstrap, fn(reply) { CallReply(reply) })
    |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(CallReply(reply)) -> reply
    Ok(WorkerExited) -> Error(StartFailed)
    Error(Nil) -> {
      process.kill(worker)
      Error(Timeout)
    }
  }
}

fn call(
  listener: Listener,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  call_with_timeout(
    listener,
    listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    make_command,
  )
}

fn call_with_timeout(
  listener: Listener,
  timeout: Int,
  make_command: fn(Subject(Result(value, Error))) -> Command,
) -> Result(value, Error) {
  case process.is_alive(listener.worker) {
    False -> Error(ListenerClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(listener.worker)
      process.send(listener.commands, make_command(reply))
      let outcome =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
        |> process.selector_receive(within: timeout)
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(result)) -> result
        Ok(WorkerExited) -> Error(ListenerClosed)
        Error(Nil) -> Error(Timeout)
      }
    }
  }
}
