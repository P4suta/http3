//// Listener actor owning UDP, native QUIC connections, and HTTP/3 requests.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/http3/message_stream
import gleam_quic/internal/http3/priority
import gleam_quic/internal/http3/server_connection
import gleam_quic/internal/http3/session
import gleam_quic/internal/packet_space
import gleam_quic/internal/qlog
import gleam_quic/internal/qpack/header.{type Header, Header}
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/packet
import gleam_quic/varint
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

const excessive_load_code = 0x107

const replay_window_milliseconds = 600_000

const replay_cache_capacity = 65_536

const ticket_age_tolerance_milliseconds = 10_000

/// A live listener command subject and its owner-monitoring actor.
pub opaque type Listener {
  Listener(commands: Subject(Command), worker: Pid, timeout_milliseconds: Int)
}

/// One request identity retained entirely inside its listener actor.
pub opaque type Request {
  Request(listener: Listener, identifier: Int)
}

/// Primitive accepted request data.
pub type Incoming {
  Incoming(
    request: Request,
    method: String,
    path: String,
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
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  InvalidContentLength
  InvalidHeaderEncoding
  DatagramsNotNegotiated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  StreamFinished
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
  SendChunk(
    request_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  FinishResponse(request_id: Int, reply: Subject(Result(Nil, Error)))
  Stop(reply: Subject(Result(StopResult, Error)))
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
    headers: List(#(String, String)),
    events: List(Event),
    buffered_body_bytes: Int,
    received_body_bytes: Int,
    event_waiter: Option(EventWaiter),
    datagrams: List(BitArray),
    buffered_datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    pending_send: Option(PendingSend),
    response_started: Bool,
    response_finished: Bool,
    response_body_bytes: Int,
    declared_content_length: Option(Int),
    priority: #(Int, Bool),
    failure: Option(Error),
  )
}

type PeerState {
  PeerState(connection: server_connection.State, requests: Dict(Int, Int))
}

type Worker {
  Worker(
    socket: udp.Socket,
    port: Int,
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    server_config: server_connection.Config,
    ticket_key: BitArray,
    replay_cache: anti_replay.Cache,
    connections: Dict(BitArray, PeerState),
    aliases: Dict(BitArray, BitArray),
    requests: Dict(Int, RequestState),
    next_request_id: Int,
    pending_requests: List(Int),
    accept_waiter: Option(AcceptWaiter),
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
  qlog_directory: String,
) -> Nil {
  let startup = {
    use wildcard <- result.try(
      udp.ipv4(0, 0, 0, 0) |> result.replace_error(StartFailed),
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
    use replay_cache <- result.try(
      anti_replay.new(replay_window_milliseconds, replay_cache_capacity)
      |> result.replace_error(StartFailed),
    )
    use qlog_writer <- result.try(
      open_qlog(qlog_directory) |> result.replace_error(StartFailed),
    )
    Ok(#(socket, bound_port, ticket_key, replay_cache, qlog_writer))
  }
  case startup {
    Error(error) -> process.send(bootstrap, Error(error))
    Ok(#(socket, bound_port, ticket_key, replay_cache, qlog_writer)) -> {
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
        replay_cache,
        dict.new(),
        dict.new(),
        dict.new(),
        0,
        [],
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
  let worker = expire_waiters(worker, udp.monotonic_millisecond())
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

fn network_step(worker: Worker) -> Nil {
  let worker = case udp.receive(worker.socket, network_poll_milliseconds) {
    Ok(udp.Datagram(peer, datagram, marking)) ->
      route_datagram(worker, peer, datagram, marking)
    Error(udp.Timeout) -> worker
    Error(udp.Closed) -> {
      shutdown(worker, "socket closed")
      worker
    }
    Error(_) -> worker
  }
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
    SendChunk(identifier, bytes, reply, deadline) ->
      handle_send_chunk(worker, identifier, bytes, reply, deadline)
    FinishResponse(identifier, reply) ->
      handle_finish_response(worker, identifier, reply)
    Stop(reply) -> {
      process.send(reply, Ok(Stopped))
      shutdown(worker, "application stop")
      Error(Nil)
    }
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
  case worker.pending_requests, worker.accept_waiter {
    [identifier, ..rest], _ -> {
      process.send(reply, incoming(worker, identifier))
      Ok(Worker(..worker, pending_requests: rest))
    }
    [], Some(_) -> {
      process.send(reply, Error(ConcurrentAccept))
      Ok(worker)
    }
    [], None ->
      Ok(Worker(..worker, accept_waiter: Some(AcceptWaiter(reply, deadline))))
  }
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
          case parsed, protocol_version {
            packet.Initial(_, _, _), version.Version1
            | packet.Initial(_, _, _), version.Version2
            ->
              accept_connection(
                worker,
                peer,
                protocol_version,
                destination,
                source,
                datagram,
                marking,
              )
            packet.UnknownVersion(_, _), _ ->
              send_version_negotiation(worker, peer, destination, source)
            _, _ -> worker
          }
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
        Error(error) ->
          case discard_connection_error(error) {
            True -> worker
            False ->
              fail_connection(
                worker,
                connection_id,
                map_connection_error(error),
              )
          }
        Ok(connection) -> {
          let previous_peer = server_connection.peer(peer_state.connection)
          let migrated =
            udp.endpoint_parts(previous_peer) != udp.endpoint_parts(peer)
          case worker.qlog_writer {
            Some(writer) -> {
              qlog.datagram_received(writer, now, bit_array.byte_size(datagram))
              case migrated {
                True -> qlog.path_updated(writer, now)
                False -> Nil
              }
            }
            None -> Nil
          }
          // Header protection and AEAD authentication completed before the
          // listener adopts a new source address, so spoofed UDP packets
          // cannot redirect response traffic.
          let connection = server_connection.with_peer(connection, peer)
          let worker =
            put_peer(
              worker,
              connection_id,
              PeerState(..peer_state, connection: connection),
            )
          update_replay_cache(worker, connection)
        }
      }
    }
  }
}

fn accept_connection(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: version.Version,
  original_destination: BitArray,
  peer_connection_id: BitArray,
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
      case unique_connection_id(worker, 8) {
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
                    PeerState(connection, dict.new()),
                  ),
                  aliases: dict.insert(
                    worker.aliases,
                    original_destination,
                    local_connection_id,
                  ),
                )
              update_replay_cache(worker, connection)
            }
          }
        }
      }
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
        Ok(Some(prepared)) ->
          case
            udp.send(
              worker.socket,
              server_connection.peer(peer.connection),
              server_connection.prepared_bytes(prepared),
              ecn.NotEct,
            )
          {
            Error(_) -> fail_connection(worker, connection_id, ConnectionClosed)
            Ok(Nil) -> {
              case worker.qlog_writer {
                Some(writer) ->
                  qlog.datagram_sent(
                    writer,
                    now,
                    bit_array.byte_size(server_connection.prepared_bytes(
                      prepared,
                    )),
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
      enqueue_stream_event(worker, connection_id, stream_id, End)
    session.TransportEvent(transport.StreamWasReset(stream_id, code)) ->
      fail_stream(worker, connection_id, stream_id, StreamReset(code))
    session.TransportEvent(transport.DatagramReceived(encoded)) ->
      case varint.decode(encoded) {
        Ok(#(quarter_stream_id, payload)) ->
          enqueue_datagram(
            worker,
            connection_id,
            quarter_stream_id * 4,
            payload,
          )
        Error(_) -> worker
      }
    session.TransportEvent(transport.PeerClosed(_, _))
    | session.TransportEvent(transport.StatelessResetReceived) ->
      fail_connection(worker, connection_id, ConnectionClosed)
    session.Http3Event(http3_state.PriorityChanged(update)) ->
      apply_peer_priority(worker, connection_id, update)
    _ -> worker
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
    Ok(#(method, path, headers)), Ok(peer) -> {
      let identifier = worker.next_request_id
      let request =
        RequestState(
          connection_id,
          stream_id,
          method,
          path,
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
          0,
          None,
          #(3, False),
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
  case worker.accept_waiter {
    Some(AcceptWaiter(reply, _)) -> {
      process.send(reply, incoming(worker, identifier))
      Worker(..worker, accept_waiter: None)
    }
    None ->
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

fn retry_pending_sends(worker: Worker) -> Worker {
  retry_pending_send_entries(worker, dict.to_list(worker.requests))
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
) -> Result(#(String, String, List(#(String, String))), Error) {
  let header_semantics.Validated(control, fields, _) = validated
  use request <- result.try(case control {
    header_semantics.RequestControlData(request) -> Ok(request)
    _ -> Error(ProtocolError(0x105, "invalid request control"))
  })
  let header_semantics.RequestControl(method, _, _, path, _) = request
  use method <- result.try(
    bit_array.to_string(method) |> result.replace_error(InvalidHeaderEncoding),
  )
  let path = case path {
    Some(value) -> bit_array.to_string(value) |> result.unwrap("")
    None -> ""
  }
  use fields <- result.try(decode_headers(fields))
  Ok(#(method, path, fields))
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
  // The strongly typed priority value is retained in the HTTP/3 scheduler.
  // Public request handles expose the locally selected effective value.
  let _ = connection_id
  let _ = update
  worker
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

fn fail_connection(
  worker: Worker,
  connection_id: BitArray,
  error: Error,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) -> {
      let worker = fail_request_ids(worker, dict.values(peer.requests), error)
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
  expire_request_waiters(worker, dict.to_list(worker.requests), now)
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
  let worker =
    fail_request_ids(worker, dict.keys(worker.requests), ListenerClosed)
  close_connections(
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

fn close_connections(peers: List(PeerState), now: Int, reason: String) -> Nil {
  case peers {
    [] -> Nil
    [peer, ..rest] -> {
      let _ = server_connection.close(peer.connection, 0x100, reason, now)
      close_connections(rest, now, reason)
    }
  }
}

fn put_peer(worker: Worker, identifier: BitArray, peer: PeerState) -> Worker {
  Worker(
    ..worker,
    connections: dict.insert(worker.connections, identifier, peer),
  )
}

fn put_request(
  worker: Worker,
  identifier: Int,
  request: RequestState,
) -> Worker {
  Worker(..worker, requests: dict.insert(worker.requests, identifier, request))
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
