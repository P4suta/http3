//// Active-once HTTP/2 listener and multiplexed connection adapter.

import gleam/bit_array
import gleam/erlang/process.{type Monitor, type Pid, type Subject, type Timer}
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/body
import http/context
import http/error
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/message
import http/internal/http2/priority
import http/internal/http2/priority_scheduler
import http/internal/http2/response_reader
import http/internal/http2/settings
import http/internal/http2/wire
import http/internal/transport

const h2_alpn = <<"h2":utf8>>

const startup_milliseconds = 1000

const accept_poll_milliseconds = 25

const reader_ack_milliseconds = 1000

const maximum_milliseconds = 3_600_000

const maximum_configured_bytes = 1_073_741_824

const maximum_header_table_bytes = 16_777_216

/// A protocol-neutral callback installed by `http/server`.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// Finite HTTP/2 listener, connection, HPACK, stream, and body policy.
pub opaque type Config {
  Config(
    backlog: Int,
    maximum_connections: Int,
    maximum_active_streams: Int,
    maximum_frame_bytes: Int,
    maximum_feed_bytes: Int,
    maximum_frames_per_feed: Int,
    maximum_header_block_bytes: Int,
    maximum_header_list_bytes: Int,
    maximum_header_table_bytes: Int,
    maximum_body_bytes: Int,
    maximum_stream_buffer_bytes: Int,
    extended_connect_enabled: Bool,
    idle_timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    tls_timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    send_timeout_milliseconds: Int,
  )
}

type Lifecycle

type ListenerDiagnostics

/// Fixed-size, payload-free listener and graceful-drain phase counters.
pub type ListenerSnapshot {
  ListenerSnapshot(
    consistent: Bool,
    state: Int,
    listener_ready_milliseconds: Int,
    accepted_connections: Int,
    accept_failures: Int,
    connection_start_attempts: Int,
    started_connections: Int,
    connection_start_failures: Int,
    active_connections: Int,
    exited_connections: Int,
    drain_requests: Int,
    connection_drain_commands: Int,
    connection_drain_receipts: Int,
    goaway_attempts: Int,
    goaways_sent: Int,
    goaway_failures: Int,
    drain_completions: Int,
    connection_failures: Int,
    last_connection_start_milliseconds: Int,
    maximum_connection_start_milliseconds: Int,
    last_goaway_milliseconds: Int,
    maximum_goaway_milliseconds: Int,
  )
}

/// One listener actor and all of its supervised HTTP/2 connections.
pub opaque type Listener {
  Listener(
    commands: Subject(ListenerCommand),
    lifecycle: Lifecycle,
    endpoint: context.Endpoint,
    config: Config,
    diagnostics: ListenerDiagnostics,
  )
}

type ListenerBoot {
  ListenerBoot(
    commands: Subject(ListenerCommand),
    start: Subject(transport.Listener),
    proceed: Subject(Nil),
  )
}

type ListenerCommand {
  BeginDrain(reply: Subject(Result(Nil, error.Error)))
  Stop(reply: Subject(Result(Nil, error.Error)))
}

type ListenerMessage {
  ListenerControl(ListenerCommand)
  ConnectionExited(process.Down)
}

type ConnectionCommand {
  DrainConnection
  StopConnection
}

type ConnectionMessage {
  ConnectionControl(ConnectionCommand)
  ReaderData(
    socket: transport.Socket,
    bytes: BitArray,
    acknowledgement: Subject(Nil),
  )
  ReaderEnded(socket: transport.Socket)
  ReaderFailed(transport.Error)
  HandlerCompleted(
    stream_id: Int,
    outcome: Result(Result(Response(body.Body), error.Error), Nil),
    acknowledgement: Subject(Nil),
  )
  HandlerExited(stream_id: Int)
  HandlerTimedOut(stream_id: Int, worker: Pid)
  ResponseRead(
    stream_id: Int,
    outcome: Result(Result(body.Read, error.Error), Nil),
    acknowledgement: Subject(Nil),
  )
  ResponseReaderExited(stream_id: Int)
  ResponseReadTimedOut(stream_id: Int, worker: Pid)
  RetiredWorkerExited
  FlushResponses
  PullRequest(
    stream_id: Int,
    sequence: Int,
    maximum_bytes: Int,
    reply: Subject(Result(RequestReply, error.Error)),
  )
  CancelRequest(stream_id: Int)
}

type RequestReply {
  RequestData(bytes: BitArray, next_sequence: Int)
  RequestEnd(trailers: body.Headers)
}

type RequestWaiter {
  RequestWaiter(
    sequence: Int,
    maximum_bytes: Int,
    reply: Subject(Result(RequestReply, error.Error)),
  )
}

type RequestProgress {
  RequestWaiting
  RequestReady(state: wire.State, stream: StreamEntry, reply: RequestReply)
}

type ResponsePending {
  ResponsePending(bytes: BitArray, trailers: body.Headers, closes_stream: Bool)
}

type ResponseWrite {
  ResponseBlocked(
    state: wire.State,
    pending: ResponsePending,
    made_progress: Bool,
  )
  ResponseFinished(state: wire.State, stream_finished: Bool)
}

type ConnectionBoot {
  ConnectionBoot(
    commands: Subject(ConnectionMessage),
    start: Subject(transport.Socket),
    proceed: Subject(Nil),
  )
}

type ConnectionEntry {
  ConnectionEntry(
    pid: Pid,
    monitor: Monitor,
    commands: Subject(ConnectionMessage),
  )
}

type ListenerRuntime {
  ListenerRuntime(
    listener: transport.Listener,
    commands: Subject(ListenerCommand),
    lifecycle: Lifecycle,
    handler: Handler,
    config: Config,
    security: Security,
    diagnostics: ListenerDiagnostics,
    connections: List(ConnectionEntry),
    drain_waiters: List(Subject(Result(Nil, error.Error))),
  )
}

type Security {
  CleartextSecurity
  TlsSecurity(
    certificate_pem: BitArray,
    private_key_pem: BitArray,
    service_identity: String,
  )
}

type StreamEntry {
  StreamEntry(
    stream_id: Int,
    method: gleam_http.Method,
    worker: Pid,
    monitor: Monitor,
    request_body: body.Body,
    request_context: context.Context,
    request_chunks: List(response_reader.Chunk),
    request_terminal: Option(body.Headers),
    request_waiter: Option(RequestWaiter),
    request_sequence: Int,
    request_body_bytes: Int,
    request_content_length: Option(Int),
    handler_timer: Option(Timer),
    response_body: Option(body.Body),
    response_reading: Bool,
    response_timer: Option(Timer),
    response_body_bytes: Int,
    response_pending: Option(ResponsePending),
    response_complete: Bool,
  )
}

type ConnectionRuntime {
  ConnectionRuntime(
    socket: transport.Socket,
    commands: Subject(ConnectionMessage),
    reader: Pid,
    reader_monitor: Monitor,
    wire: wire.State,
    scheduler: priority_scheduler.State,
    streams: List(StreamEntry),
    handler: Handler,
    config: Config,
    scheme: gleam_http.Scheme,
    tls_identity: context.TlsIdentity,
    peer_endpoint: context.Endpoint,
    local_endpoint: context.Endpoint,
    diagnostics: ListenerDiagnostics,
    draining: Bool,
    flush_scheduled: Bool,
  )
}

const fairness_coalesce_milliseconds = 1

@external(erlang, "http_server_ffi", "new_server_lifecycle")
fn new_lifecycle() -> Lifecycle

@external(erlang, "http_server_ffi", "server_lifecycle_state")
fn lifecycle_state(lifecycle: Lifecycle) -> Int

@external(erlang, "http_server_ffi", "mark_server_draining")
fn mark_draining(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "mark_server_stopped")
fn mark_stopped(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "run_guarded")
fn run_guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_http2_listener_ffi", "new")
fn new_listener_diagnostics() -> ListenerDiagnostics

@external(erlang, "http_http2_listener_ffi", "record_listener_ready")
fn record_listener_ready(
  diagnostics: ListenerDiagnostics,
  elapsed_milliseconds: Int,
) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_state")
fn record_listener_state(diagnostics: ListenerDiagnostics, state: Int) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_accept")
fn record_accept(diagnostics: ListenerDiagnostics, succeeded: Bool) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_connection_start")
fn record_connection_start(
  diagnostics: ListenerDiagnostics,
  succeeded: Bool,
  elapsed_milliseconds: Int,
) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_connection_exit")
fn record_connection_exit(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_connection_failure")
fn record_connection_failure(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_drain_request")
fn record_drain_request(
  diagnostics: ListenerDiagnostics,
  connection_commands: Int,
) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_drain_receipt")
fn record_drain_receipt(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_goaway")
fn record_goaway(
  diagnostics: ListenerDiagnostics,
  succeeded: Bool,
  elapsed_milliseconds: Int,
) -> Nil

@external(erlang, "http_http2_listener_ffi", "record_drain_completion")
fn record_drain_completion(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http2_listener_ffi", "snapshot")
fn raw_listener_snapshot(
  diagnostics: ListenerDiagnostics,
) -> #(
  Bool,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

/// Construct finite HTTP/2 defaults. Server push and Extended CONNECT are not
/// enabled by this adapter.
pub fn defaults() -> Config {
  Config(
    backlog: 128,
    maximum_connections: 256,
    maximum_active_streams: 100,
    maximum_frame_bytes: 16_384,
    maximum_feed_bytes: 262_144,
    maximum_frames_per_feed: 64,
    maximum_header_block_bytes: 65_536,
    maximum_header_list_bytes: 65_536,
    maximum_header_table_bytes: 4096,
    maximum_body_bytes: 67_108_864,
    maximum_stream_buffer_bytes: 262_144,
    extended_connect_enabled: False,
    idle_timeout_milliseconds: 30_000,
    operation_timeout_milliseconds: 30_000,
    tls_timeout_milliseconds: 10_000,
    drain_timeout_milliseconds: 30_000,
    send_timeout_milliseconds: 30_000,
  )
}

/// Advertise and accept RFC 8441 Extended CONNECT on this listener.
pub fn enable_extended_connect(config: Config) -> Config {
  Config(..config, extended_connect_enabled: True)
}

/// Replace every finite network, worker, and drain deadline.
pub fn with_timeouts(
  config: Config,
  idle_milliseconds: Int,
  operation_milliseconds: Int,
  tls_milliseconds: Int,
  drain_milliseconds: Int,
  send_milliseconds: Int,
) -> Result(Config, error.Error) {
  use <- require(
    valid_timeout(idle_milliseconds)
      && valid_timeout(operation_milliseconds)
      && valid_timeout(tls_milliseconds)
      && valid_timeout(drain_milliseconds)
      && valid_timeout(send_milliseconds),
    policy_error(),
  )
  Ok(
    Config(
      ..config,
      idle_timeout_milliseconds: idle_milliseconds,
      operation_timeout_milliseconds: operation_milliseconds,
      tls_timeout_milliseconds: tls_milliseconds,
      drain_timeout_milliseconds: drain_milliseconds,
      send_timeout_milliseconds: send_milliseconds,
    ),
  )
}

/// Replace listener connection and per-connection stream admission ceilings.
pub fn with_connection_limits(
  config: Config,
  maximum_connections: Int,
  maximum_active_streams: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_connections > 0
      && maximum_connections <= 1_000_000
      && maximum_active_streams > 0
      && maximum_active_streams <= 1_000_000,
    policy_error(),
  )
  Ok(Config(..config, maximum_connections:, maximum_active_streams:))
}

/// Replace HPACK field-section, decoded-list, and dynamic-table ceilings.
pub fn with_header_limits(
  config: Config,
  maximum_header_block_bytes: Int,
  maximum_header_list_bytes: Int,
  maximum_header_table_bytes configured_table_bytes: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_header_block_bytes > 0
      && maximum_header_block_bytes <= maximum_configured_bytes
      && maximum_header_list_bytes > 0
      && maximum_header_list_bytes <= maximum_configured_bytes
      && configured_table_bytes >= 0
      && configured_table_bytes <= maximum_header_table_bytes,
    policy_error(),
  )
  Ok(
    Config(
      ..config,
      maximum_header_block_bytes:,
      maximum_header_list_bytes:,
      maximum_header_table_bytes: configured_table_bytes,
    ),
  )
}

/// Replace aggregate message-body and one-pull stream-buffer ceilings.
pub fn with_body_limits(
  config: Config,
  maximum_body_bytes: Int,
  maximum_stream_buffer_bytes: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_body_bytes > 0
      && maximum_body_bytes <= maximum_configured_bytes
      && maximum_stream_buffer_bytes > 0
      && maximum_stream_buffer_bytes <= maximum_body_bytes,
    policy_error(),
  )
  Ok(Config(..config, maximum_body_bytes:, maximum_stream_buffer_bytes:))
}

/// Bind and start an authenticated HTTP/2 listener.
pub fn listen_tls(
  handler: Handler,
  address: BitArray,
  port: Int,
  config: Config,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  service_identity: String,
) -> Result(Listener, error.Error) {
  use <- require(
    bit_array.byte_size(certificate_pem) > 0
      && bit_array.byte_size(private_key_pem) > 0
      && service_identity != "",
    policy_error(),
  )
  listen(
    handler,
    address,
    port,
    config,
    TlsSecurity(certificate_pem, private_key_pem, service_identity),
  )
}

/// Bind a cleartext HTTP/2 prior-knowledge listener.
/// Public policy must explicitly opt in before reaching this adapter.
pub fn listen_cleartext(
  handler: Handler,
  address: BitArray,
  port: Int,
  config: Config,
) -> Result(Listener, error.Error) {
  listen(handler, address, port, config, CleartextSecurity)
}

fn listen(
  handler: Handler,
  address: BitArray,
  port: Int,
  config: Config,
  security: Security,
) -> Result(Listener, error.Error) {
  use listener <- result.try(
    transport.listen(
      address,
      port,
      config.backlog,
      config.send_timeout_milliseconds,
    )
    |> result.map_error(map_listen_error),
  )
  case start_listener(listener, handler, config, security) {
    Ok(started) -> Ok(started)
    Error(failure) -> {
      let _closed = transport.stop(listener)
      Error(failure)
    }
  }
}

/// Return the concrete bound endpoint.
pub fn endpoint(listener: Listener) -> context.Endpoint {
  listener.endpoint
}

/// Inspect fixed-size listener and graceful-drain phases without handles.
pub fn snapshot(listener: Listener) -> ListenerSnapshot {
  let #(
    consistent,
    state,
    listener_ready_milliseconds,
    accepted_connections,
    accept_failures,
    connection_start_attempts,
    started_connections,
    connection_start_failures,
    active_connections,
    exited_connections,
    drain_requests,
    connection_drain_commands,
    connection_drain_receipts,
    goaway_attempts,
    goaways_sent,
    goaway_failures,
    drain_completions,
    connection_failures,
    last_connection_start_milliseconds,
    maximum_connection_start_milliseconds,
    last_goaway_milliseconds,
    maximum_goaway_milliseconds,
  ) = raw_listener_snapshot(listener.diagnostics)
  ListenerSnapshot(
    consistent:,
    state:,
    listener_ready_milliseconds:,
    accepted_connections:,
    accept_failures:,
    connection_start_attempts:,
    started_connections:,
    connection_start_failures:,
    active_connections:,
    exited_connections:,
    drain_requests:,
    connection_drain_commands:,
    connection_drain_receipts:,
    goaway_attempts:,
    goaways_sent:,
    goaway_failures:,
    drain_completions:,
    connection_failures:,
    last_connection_start_milliseconds:,
    maximum_connection_start_milliseconds:,
    last_goaway_milliseconds:,
    maximum_goaway_milliseconds:,
  )
}

/// Stop admission and wait for existing connection actors.
pub fn drain(listener: Listener) -> Result(Nil, error.Error) {
  case lifecycle_state(listener.lifecycle) {
    2 -> Ok(Nil)
    _ ->
      listener_call(
        listener,
        fn(reply) { BeginDrain(reply) },
        listener.config.drain_timeout_milliseconds,
      )
  }
}

/// Stop the listener and all remaining connection actors idempotently.
pub fn stop(listener: Listener) -> Result(Nil, error.Error) {
  case lifecycle_state(listener.lifecycle) {
    2 -> Ok(Nil)
    _ ->
      listener_call(
        listener,
        fn(reply) { Stop(reply) },
        listener.config.operation_timeout_milliseconds,
      )
  }
}

fn start_listener(
  listener: transport.Listener,
  handler: Handler,
  config: Config,
  security: Security,
) -> Result(Listener, error.Error) {
  use #(address, port) <- result.try(
    transport.local_endpoint(listener) |> result.map_error(map_transport_error),
  )
  use host <- result.try(address_string(address))
  let lifecycle = new_lifecycle()
  let diagnostics = new_listener_diagnostics()
  let started_milliseconds = transport.monotonic_millisecond()
  let startup_deadline = started_milliseconds + startup_milliseconds
  let ready = process.new_subject()
  let started = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      let start = process.new_subject()
      let proceed = process.new_subject()
      process.send(ready, ListenerBoot(commands, start, proceed))
      case receive_before(start, startup_deadline) {
        Error(Nil) -> {
          let _stopped = mark_stopped(lifecycle)
          record_listener_state(diagnostics, 2)
          Nil
        }
        Ok(listener) -> {
          process.send(started, Nil)
          case receive_before(proceed, startup_deadline) {
            Error(Nil) -> {
              let _stopped = mark_stopped(lifecycle)
              record_listener_state(diagnostics, 2)
              Nil
            }
            Ok(Nil) ->
              listener_loop(
                ListenerRuntime(
                  listener:,
                  commands:,
                  lifecycle:,
                  handler:,
                  config:,
                  security:,
                  diagnostics:,
                  connections: [],
                  drain_waiters: [],
                ),
              )
          }
        }
      }
    })
  case receive_before(ready, startup_deadline) {
    Error(Nil) -> {
      process.kill(pid)
      let _stopped = mark_stopped(lifecycle)
      record_listener_state(diagnostics, 2)
      Error(service_error())
    }
    Ok(ListenerBoot(commands, start, proceed)) ->
      case transport.transfer_listener_owner(listener, pid) {
        Error(_) -> {
          process.kill(pid)
          let _stopped = mark_stopped(lifecycle)
          record_listener_state(diagnostics, 2)
          Error(service_error())
        }
        Ok(Nil) -> {
          process.send(start, listener)
          case receive_before(started, startup_deadline) {
            Error(Nil) -> {
              process.kill(pid)
              let _stopped = mark_stopped(lifecycle)
              record_listener_state(diagnostics, 2)
              Error(service_error())
            }
            Ok(Nil) -> {
              record_listener_ready(
                diagnostics,
                elapsed_milliseconds(started_milliseconds),
              )
              process.send(proceed, Nil)
              Ok(Listener(
                commands:,
                lifecycle:,
                endpoint: context.Endpoint(host, port),
                config:,
                diagnostics:,
              ))
            }
          }
        }
      }
  }
}

fn listener_call(
  listener: Listener,
  command: fn(Subject(Result(Nil, error.Error))) -> ListenerCommand,
  timeout: Int,
) -> Result(Nil, error.Error) {
  let reply = process.new_subject()
  process.send(listener.commands, command(reply))
  case process.receive(reply, within: timeout) {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn listener_loop(runtime: ListenerRuntime) -> Nil {
  let selector =
    process.new_selector()
    |> process.select_map(runtime.commands, ListenerControl)
    |> process.select_monitors(ConnectionExited)
  case process.selector_receive(selector, within: 1) {
    Ok(message) ->
      case handle_listener_message(runtime, message) {
        Some(next) -> listener_loop(next)
        None -> Nil
      }
    Error(Nil) ->
      case lifecycle_state(runtime.lifecycle) {
        0 -> listener_accept(runtime)
        _ -> listener_loop(runtime)
      }
  }
}

fn listener_accept(runtime: ListenerRuntime) -> Nil {
  case list.length(runtime.connections) >= runtime.config.maximum_connections {
    True -> {
      process.sleep(accept_poll_milliseconds)
      listener_loop(runtime)
    }
    False ->
      case transport.accept(runtime.listener, accept_poll_milliseconds) {
        Error(transport.Timeout) | Error(transport.Closed) ->
          listener_loop(runtime)
        Error(_) -> {
          record_accept(runtime.diagnostics, False)
          process.sleep(accept_poll_milliseconds)
          listener_loop(runtime)
        }
        Ok(socket) -> {
          record_accept(runtime.diagnostics, True)
          case spawn_connection(socket, runtime) {
            Error(_) -> {
              let _closed = transport.close(socket)
              listener_loop(runtime)
            }
            Ok(entry) ->
              listener_loop(
                ListenerRuntime(..runtime, connections: [
                  entry,
                  ..runtime.connections
                ]),
              )
          }
        }
      }
  }
}

fn handle_listener_message(
  runtime: ListenerRuntime,
  message: ListenerMessage,
) -> Option(ListenerRuntime) {
  case message {
    ConnectionExited(down) -> Some(connection_exited(runtime, down))
    ListenerControl(BeginDrain(reply)) -> Some(begin_drain(runtime, reply))
    ListenerControl(Stop(reply)) -> {
      stop_runtime(runtime, reply)
      None
    }
  }
}

fn begin_drain(
  runtime: ListenerRuntime,
  reply: Subject(Result(Nil, error.Error)),
) -> ListenerRuntime {
  let first = mark_draining(runtime.lifecycle)
  let commands = case first {
    True -> list.length(runtime.connections)
    False -> 0
  }
  record_drain_request(runtime.diagnostics, commands)
  case first {
    True -> {
      record_listener_state(runtime.diagnostics, 1)
      let _closed = transport.stop(runtime.listener)
      list.each(runtime.connections, fn(connection) {
        process.send(connection.commands, ConnectionControl(DrainConnection))
      })
    }
    False -> Nil
  }
  case runtime.connections {
    [] -> {
      record_drain_completion(runtime.diagnostics)
      process.send(reply, Ok(Nil))
      runtime
    }
    _ ->
      ListenerRuntime(..runtime, drain_waiters: [reply, ..runtime.drain_waiters])
  }
}

fn stop_runtime(
  runtime: ListenerRuntime,
  reply: Subject(Result(Nil, error.Error)),
) -> Nil {
  let _closed = transport.stop(runtime.listener)
  list.each(runtime.connections, fn(connection) {
    process.send(connection.commands, ConnectionControl(StopConnection))
    process.kill(connection.pid)
    process.demonitor_process(connection.monitor)
    record_connection_exit(runtime.diagnostics)
  })
  list.each(runtime.drain_waiters, fn(waiter) {
    record_drain_completion(runtime.diagnostics)
    process.send(waiter, Ok(Nil))
  })
  let _stopped = mark_stopped(runtime.lifecycle)
  record_listener_state(runtime.diagnostics, 2)
  process.send(reply, Ok(Nil))
}

fn connection_exited(
  runtime: ListenerRuntime,
  down: process.Down,
) -> ListenerRuntime {
  case down {
    process.PortDown(..) -> runtime
    process.ProcessDown(pid: pid, ..) -> {
      let tracked =
        list.any(runtime.connections, fn(connection) { connection.pid == pid })
      let remaining = remove_connection(runtime.connections, pid, [])
      case tracked {
        True -> record_connection_exit(runtime.diagnostics)
        False -> Nil
      }
      case tracked, remaining, lifecycle_state(runtime.lifecycle) {
        True, [], state if state != 0 -> {
          list.each(runtime.drain_waiters, fn(waiter) {
            record_drain_completion(runtime.diagnostics)
            process.send(waiter, Ok(Nil))
          })
          ListenerRuntime(..runtime, connections: [], drain_waiters: [])
        }
        _, _, _ -> ListenerRuntime(..runtime, connections: remaining)
      }
    }
  }
}

fn remove_connection(
  connections: List(ConnectionEntry),
  pid: Pid,
  reversed: List(ConnectionEntry),
) -> List(ConnectionEntry) {
  case connections {
    [] -> list.reverse(reversed)
    [connection, ..rest] ->
      case connection.pid == pid {
        True -> list.append(list.reverse(reversed), rest)
        False -> remove_connection(rest, pid, [connection, ..reversed])
      }
  }
}

fn spawn_connection(
  socket: transport.Socket,
  runtime: ListenerRuntime,
) -> Result(ConnectionEntry, error.Error) {
  let started_milliseconds = transport.monotonic_millisecond()
  let startup_deadline = started_milliseconds + startup_milliseconds
  let ready = process.new_subject()
  let started = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      let start = process.new_subject()
      let proceed = process.new_subject()
      process.send(ready, ConnectionBoot(commands, start, proceed))
      case receive_before(start, startup_deadline) {
        Error(Nil) -> Nil
        Ok(socket) -> {
          process.send(started, Nil)
          let completed = case receive_before(proceed, startup_deadline) {
            Error(Nil) -> Ok(Nil)
            Ok(Nil) -> run_connection(socket, commands, runtime)
          }
          case completed {
            Ok(Nil) -> Nil
            Error(_) -> record_connection_failure(runtime.diagnostics)
          }
          let _closed = transport.close(socket)
          Nil
        }
      }
    })
  case receive_before(ready, startup_deadline) {
    Error(Nil) -> {
      process.kill(pid)
      record_connection_start(
        runtime.diagnostics,
        False,
        elapsed_milliseconds(started_milliseconds),
      )
      Error(service_error())
    }
    Ok(ConnectionBoot(commands, start, proceed)) ->
      case transport.transfer_owner(socket, pid) {
        Error(_) -> {
          process.kill(pid)
          record_connection_start(
            runtime.diagnostics,
            False,
            elapsed_milliseconds(started_milliseconds),
          )
          Error(service_error())
        }
        Ok(Nil) -> {
          let monitor = process.monitor(pid)
          process.send(start, socket)
          case receive_before(started, startup_deadline) {
            Error(Nil) -> {
              process.kill(pid)
              process.demonitor_process(monitor)
              record_connection_start(
                runtime.diagnostics,
                False,
                elapsed_milliseconds(started_milliseconds),
              )
              Error(service_error())
            }
            Ok(Nil) -> {
              record_connection_start(
                runtime.diagnostics,
                True,
                elapsed_milliseconds(started_milliseconds),
              )
              process.send(proceed, Nil)
              Ok(ConnectionEntry(pid:, monitor:, commands:))
            }
          }
        }
      }
  }
}

fn run_connection(
  socket: transport.Socket,
  commands: Subject(ConnectionMessage),
  listener: ListenerRuntime,
) -> Result(Nil, error.Error) {
  use peer <- result.try(
    transport.peer_endpoint(socket) |> result.map_error(map_transport_error),
  )
  use local <- result.try(
    transport.socket_local_endpoint(socket)
    |> result.map_error(map_transport_error),
  )
  use peer_endpoint <- result.try(context_endpoint(peer))
  use local_endpoint <- result.try(context_endpoint(local))
  use prepared <- result.try(prepare_connection(socket, listener))
  let #(socket, scheme, tls_identity) = prepared
  use state <- result.try(
    wire.new_with_capabilities(
      connection.Server,
      connection_limits(listener.config),
      connection.Capabilities(
        extended_connect_enabled: listener.config.extended_connect_enabled,
      ),
      wire_limits(listener.config),
    )
    |> result.map_error(map_wire_error),
  )
  use started <- result.try(
    wire.initial_bytes(state, local_settings(listener.config))
    |> result.map_error(map_wire_error),
  )
  let wire.Started(state, initial) = started
  use scheduler <- result.try(
    priority_scheduler.new(listener.config.maximum_active_streams, 64, 16)
    |> result.map_error(map_priority_scheduler_error),
  )
  use _ <- result.try(
    transport.send(socket, initial) |> result.map_error(map_transport_error),
  )
  use reader <- result.try(start_reader(
    socket,
    commands,
    listener.config.maximum_stream_buffer_bytes,
    listener.config.idle_timeout_milliseconds,
  ))
  let #(reader, reader_monitor) = reader
  connection_loop(ConnectionRuntime(
    socket:,
    commands:,
    reader:,
    reader_monitor:,
    wire: state,
    scheduler:,
    streams: [],
    handler: listener.handler,
    config: listener.config,
    scheme:,
    tls_identity:,
    peer_endpoint:,
    local_endpoint:,
    diagnostics: listener.diagnostics,
    draining: False,
    flush_scheduled: False,
  ))
}

fn prepare_connection(
  socket: transport.Socket,
  listener: ListenerRuntime,
) -> Result(
  #(transport.Socket, gleam_http.Scheme, context.TlsIdentity),
  error.Error,
) {
  case listener.security {
    CleartextSecurity ->
      Ok(#(socket, gleam_http.Http, context.CleartextIdentity))
    TlsSecurity(certificate_pem, private_key_pem, service_identity) -> {
      use ready <- result.try(
        transport.upgrade_server_tls(
          socket,
          certificate_pem,
          private_key_pem,
          [h2_alpn],
          listener.config.tls_timeout_milliseconds,
        )
        |> result.map_error(map_tls_error),
      )
      let transport.TlsReady(socket, selected, _) = ready
      use <- require(selected == h2_alpn, protocol_error())
      Ok(#(
        socket,
        gleam_http.Https,
        context.TlsIdentity(service_identity, None),
      ))
    }
  }
}

fn start_reader(
  socket: transport.Socket,
  commands: Subject(ConnectionMessage),
  maximum_read_bytes: Int,
  idle_timeout_milliseconds: Int,
) -> Result(#(Pid, Monitor), error.Error) {
  let ready = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let start = process.new_subject()
      process.send(ready, start)
      case process.receive(start, within: startup_milliseconds) {
        Error(Nil) -> Nil
        Ok(socket) ->
          reader_loop(
            socket,
            commands,
            maximum_read_bytes,
            idle_timeout_milliseconds,
          )
      }
    })
  case process.receive(ready, within: startup_milliseconds) {
    Error(Nil) -> {
      process.kill(pid)
      Error(service_error())
    }
    Ok(start) ->
      case transport.transfer_owner(socket, pid) {
        Error(_) -> {
          process.kill(pid)
          Error(service_error())
        }
        Ok(Nil) -> {
          let monitor = process.monitor(pid)
          process.send(start, socket)
          Ok(#(pid, monitor))
        }
      }
  }
}

fn reader_loop(
  socket: transport.Socket,
  commands: Subject(ConnectionMessage),
  maximum_read_bytes: Int,
  idle_timeout_milliseconds: Int,
) -> Nil {
  case transport.read(socket, maximum_read_bytes, idle_timeout_milliseconds) {
    Error(failure) -> process.send(commands, ReaderFailed(failure))
    Ok(transport.ReadEnd(socket)) -> process.send(commands, ReaderEnded(socket))
    Ok(transport.ReadData(bytes, socket)) -> {
      let acknowledgement = process.new_subject()
      process.send(commands, ReaderData(socket:, bytes:, acknowledgement:))
      case process.receive(acknowledgement, within: reader_ack_milliseconds) {
        Ok(Nil) ->
          reader_loop(
            socket,
            commands,
            maximum_read_bytes,
            idle_timeout_milliseconds,
          )
        Error(Nil) -> {
          let _closed = transport.close(socket)
          Nil
        }
      }
    }
  }
}

fn connection_loop(runtime: ConnectionRuntime) -> Result(Nil, error.Error) {
  let selector =
    process.new_selector()
    |> process.select(runtime.commands)
    |> process.select_monitors(fn(down) {
      case down {
        process.PortDown(..) -> ReaderFailed(transport.SocketFailure)
        process.ProcessDown(pid: pid, ..) -> worker_down_message(runtime, pid)
      }
    })
  case process.selector_receive_forever(selector) {
    ConnectionControl(StopConnection) -> stop_connection(runtime)
    ConnectionControl(DrainConnection) -> {
      record_drain_receipt(runtime.diagnostics)
      let started_milliseconds = transport.monotonic_millisecond()
      case begin_connection_drain(runtime) {
        Error(failure) -> {
          record_goaway(
            runtime.diagnostics,
            False,
            elapsed_milliseconds(started_milliseconds),
          )
          stop_connection_with_error(runtime, failure)
        }
        Ok(next) -> {
          record_goaway(
            next.diagnostics,
            True,
            elapsed_milliseconds(started_milliseconds),
          )
          case next.streams {
            [] -> stop_connection(next)
            _ -> connection_loop(next)
          }
        }
      }
    }
    ReaderEnded(socket) ->
      stop_connection(ConnectionRuntime(..runtime, socket:))
    ReaderFailed(_) -> stop_connection(runtime)
    ReaderData(socket, bytes, acknowledgement) ->
      case receive_wire(ConnectionRuntime(..runtime, socket:), bytes) {
        Error(failure) -> stop_connection_with_error(runtime, failure)
        Ok(next) -> {
          process.send(acknowledgement, Nil)
          continue_or_drain(next)
        }
      }
    HandlerCompleted(stream_id, outcome, acknowledgement) ->
      handle_handler_completion(
        runtime,
        stream_id,
        outcome,
        Some(acknowledgement),
      )
    HandlerExited(stream_id) ->
      handle_handler_completion(runtime, stream_id, Error(Nil), None)
    HandlerTimedOut(stream_id, worker) ->
      case handle_handler_timeout(runtime, stream_id, worker) {
        Error(failure) -> stop_connection_with_error(runtime, failure)
        Ok(next) -> continue_or_drain(next)
      }
    ResponseRead(stream_id, outcome, acknowledgement) ->
      handle_response_read(runtime, stream_id, outcome, Some(acknowledgement))
    ResponseReaderExited(stream_id) ->
      handle_response_read(runtime, stream_id, Error(Nil), None)
    ResponseReadTimedOut(stream_id, worker) ->
      case handle_response_timeout(runtime, stream_id, worker) {
        Error(failure) -> stop_connection_with_error(runtime, failure)
        Ok(next) -> continue_or_drain(next)
      }
    RetiredWorkerExited -> connection_loop(runtime)
    FlushResponses ->
      case
        flush_pending_responses(
          ConnectionRuntime(..runtime, flush_scheduled: False),
        )
      {
        Error(failure) -> stop_connection_with_error(runtime, failure)
        Ok(next) -> continue_or_drain(next)
      }
    PullRequest(stream_id, sequence, maximum_bytes, reply) ->
      case
        handle_request_pull(runtime, stream_id, sequence, maximum_bytes, reply)
      {
        Error(failure) -> {
          process.send(reply, Error(failure))
          stop_connection_with_error(runtime, failure)
        }
        Ok(next) -> continue_or_drain(next)
      }
    CancelRequest(stream_id) ->
      continue_or_drain(cancel_stream(runtime, stream_id))
  }
}

fn worker_down_message(
  runtime: ConnectionRuntime,
  pid: Pid,
) -> ConnectionMessage {
  case pid == runtime.reader, stream_for_worker(runtime.streams, pid) {
    True, _ -> ReaderFailed(transport.Closed)
    False, Some(stream) ->
      case stream.response_reading {
        True -> ResponseReaderExited(stream.stream_id)
        False -> HandlerExited(stream.stream_id)
      }
    // A worker can exit after its stream has completed or been reset but
    // before an already-delivered monitor message is flushed. It no longer
    // owns connection state, so that delayed Down must not be mistaken for
    // the independently monitored socket reader failing.
    False, None -> RetiredWorkerExited
  }
}

fn receive_wire(
  runtime: ConnectionRuntime,
  bytes: BitArray,
) -> Result(ConnectionRuntime, error.Error) {
  use fed <- result.try(
    wire.feed(runtime.wire, bytes) |> result.map_error(map_wire_error),
  )
  let wire.Fed(state, actions) = fed
  use automatic <- result.try(
    wire.automatic_writes(actions, runtime.config.maximum_frame_bytes)
    |> result.map_error(map_wire_error),
  )
  use _ <- result.try(send_frames(runtime.socket, automatic))
  handle_actions(ConnectionRuntime(..runtime, wire: state), actions)
}

fn handle_actions(
  runtime: ConnectionRuntime,
  actions: List(connection.Action),
) -> Result(ConnectionRuntime, error.Error) {
  case actions {
    [] -> flush_pending_responses(runtime)
    [connection.HeadersReceived(section), ..rest] -> {
      use runtime <- result.try(handle_headers(runtime, section))
      handle_actions(runtime, rest)
    }
    [connection.PriorityUpdated(stream_id, value), ..rest] -> {
      use runtime <- result.try(update_stream_priority(
        runtime,
        stream_id,
        value,
      ))
      handle_actions(runtime, rest)
    }
    [connection.StreamReset(stream_id, _), ..rest] -> {
      let runtime = cancel_stream(runtime, stream_id)
      handle_actions(runtime, rest)
    }
    [connection.DataReceived(stream_id, bytes, end_stream, controlled), ..rest] -> {
      use runtime <- result.try(handle_request_data(
        runtime,
        stream_id,
        bytes,
        end_stream,
        controlled,
      ))
      handle_actions(runtime, rest)
    }
    [_, ..rest] -> handle_actions(runtime, rest)
  }
}

fn update_stream_priority(
  runtime: ConnectionRuntime,
  stream_id: Int,
  value: priority.Priority,
) -> Result(ConnectionRuntime, error.Error) {
  case priority_scheduler.update(runtime.scheduler, stream_id, value) {
    Ok(scheduler) -> Ok(ConnectionRuntime(..runtime, scheduler: scheduler))
    // PRIORITY_UPDATE can precede the request. The wire state retains the
    // latest bounded value, which start_handler reads when the stream opens.
    Error(priority_scheduler.MissingStream(_)) -> Ok(runtime)
    Error(failure) -> Error(map_priority_scheduler_error(failure))
  }
}

fn handle_headers(
  runtime: ConnectionRuntime,
  section: header_codec.HeaderSection,
) -> Result(ConnectionRuntime, error.Error) {
  let header_codec.HeaderSection(stream_id, end_stream, validated, _) = section
  case stream_present(runtime.streams, stream_id), end_stream, validated {
    True,
      True,
      header_semantics.Validated(header_semantics.TrailerControlData, _, _)
    -> complete_request_trailers(runtime, stream_id, validated)
    True, _, _ -> Error(protocol_error())
    False,
      _,
      header_semantics.Validated(header_semantics.RequestControlData(_), _, _)
    ->
      case runtime.draining {
        True -> refuse_stream(runtime, stream_id)
        False -> start_handler(runtime, stream_id, validated, end_stream)
      }
    _, _, _ -> Error(protocol_error())
  }
}

fn begin_connection_drain(
  runtime: ConnectionRuntime,
) -> Result(ConnectionRuntime, error.Error) {
  use written <- result.try(
    wire.begin_drain(runtime.wire) |> result.map_error(map_wire_error),
  )
  let wire.ControlWritten(state, frames) = written
  use _ <- result.try(send_frames(runtime.socket, frames))
  Ok(ConnectionRuntime(..runtime, wire: state, draining: True))
}

fn refuse_stream(
  runtime: ConnectionRuntime,
  stream_id: Int,
) -> Result(ConnectionRuntime, error.Error) {
  use written <- result.try(
    wire.reset_stream(runtime.wire, stream_id:, error_code: 0x7)
    |> result.map_error(map_wire_error),
  )
  let wire.ControlWritten(state, frames) = written
  use _ <- result.try(send_frames(runtime.socket, frames))
  Ok(ConnectionRuntime(..runtime, wire: state))
}

fn start_handler(
  runtime: ConnectionRuntime,
  stream_id: Int,
  validated: header_semantics.Validated,
  end_stream: Bool,
) -> Result(ConnectionRuntime, error.Error) {
  let header_semantics.Validated(_, _, content_length) = validated
  use <- require(
    !end_stream || content_length == None || content_length == Some(0),
    protocol_error(),
  )
  let request_body_result = case end_stream {
    True -> Ok(body.empty())
    False ->
      body.from_pull(
        request_body_source(
          runtime.commands,
          stream_id,
          0,
          runtime.config.operation_timeout_milliseconds,
        ),
        content_length,
        None,
        fn() { process.send(runtime.commands, CancelRequest(stream_id)) },
      )
  }
  use request_body <- result.try(request_body_result)
  use incoming <- result.try(
    message.request_from_validated(
      validated,
      body: request_body,
      connection_scheme: runtime.scheme,
    )
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use request_context <- result.try(context.new(
    protocol: context.Http2,
    peer_endpoint: runtime.peer_endpoint,
    local_endpoint: runtime.local_endpoint,
    within_milliseconds: runtime.config.operation_timeout_milliseconds,
    tls_identity: runtime.tls_identity,
    early_data: context.EarlyDataDisabled,
  ))
  use request_context <- result.try(attach_extended_connect_protocol(
    request_context,
    validated,
  ))
  let effective_priority = case
    connection.stream_priority(wire.connection_state(runtime.wire), stream_id)
  {
    Some(value) -> value
    None -> priority.default()
  }
  use scheduler <- result.try(
    priority_scheduler.register(
      runtime.scheduler,
      stream_id,
      effective_priority,
    )
    |> result.map_error(map_priority_scheduler_error),
  )
  let pid =
    process.spawn_unlinked(fn() {
      let acknowledgement = process.new_subject()
      process.send(
        runtime.commands,
        HandlerCompleted(
          stream_id,
          run_guarded(fn() { runtime.handler(incoming, request_context) }),
          acknowledgement,
        ),
      )
      // Keep the producer alive until the connection actor has consumed its
      // explicit result. Otherwise an immediate monitor Down can race ahead
      // of the result and turn a successful response into a worker failure.
      let _acknowledged =
        process.receive(acknowledgement, within: maximum_milliseconds)
      Nil
    })
  let monitor = process.monitor(pid)
  let handler_timer =
    process.send_after(
      runtime.commands,
      runtime.config.operation_timeout_milliseconds,
      HandlerTimedOut(stream_id, pid),
    )
  Ok(
    ConnectionRuntime(..runtime, scheduler: scheduler, streams: [
      StreamEntry(
        stream_id:,
        method: incoming.method,
        worker: pid,
        monitor:,
        request_body:,
        request_context:,
        request_chunks: [],
        request_terminal: case end_stream {
          True -> Some([])
          False -> None
        },
        request_waiter: None,
        request_sequence: 0,
        request_body_bytes: 0,
        request_content_length: content_length,
        handler_timer: Some(handler_timer),
        response_body: None,
        response_reading: False,
        response_timer: None,
        response_body_bytes: 0,
        response_pending: None,
        response_complete: False,
      ),
      ..runtime.streams
    ]),
  )
}

fn attach_extended_connect_protocol(
  request_context: context.Context,
  validated: header_semantics.Validated,
) -> Result(context.Context, error.Error) {
  case validated {
    header_semantics.Validated(
      header_semantics.RequestControlData(header_semantics.RequestControl(
        _,
        _,
        _,
        _,
        Some(protocol),
      )),
      _,
      _,
    ) -> {
      use protocol <- result.try(
        bit_array.to_string(protocol)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      context.with_extended_connect_protocol(request_context, protocol)
    }
    _ -> Ok(request_context)
  }
}

fn request_body_source(
  commands: Subject(ConnectionMessage),
  stream_id: Int,
  sequence: Int,
  timeout_milliseconds: Int,
) -> body.Pull {
  body.pull(fn(maximum_bytes) {
    let reply = process.new_subject()
    process.send(
      commands,
      PullRequest(stream_id, sequence, maximum_bytes, reply),
    )
    case process.receive(reply, within: timeout_milliseconds) {
      Error(Nil) -> Error(error.new(error.Timeout(error.Idle)))
      Ok(Error(failure)) -> Error(failure)
      Ok(Ok(RequestEnd(trailers))) -> Ok(body.PullEnd(trailers))
      Ok(Ok(RequestData(bytes, next_sequence))) ->
        Ok(body.PullData(
          bytes,
          request_body_source(
            commands,
            stream_id,
            next_sequence,
            timeout_milliseconds,
          ),
        ))
    }
  })
}

fn handle_request_pull(
  runtime: ConnectionRuntime,
  stream_id: Int,
  sequence: Int,
  maximum_bytes: Int,
  reply: Subject(Result(RequestReply, error.Error)),
) -> Result(ConnectionRuntime, error.Error) {
  case maximum_bytes > 0, take_stream(runtime.streams, stream_id, []) {
    False, _ -> {
      process.send(reply, Error(error.new(error.Body(error.InvalidLimit))))
      Ok(runtime)
    }
    True, None -> {
      process.send(reply, Error(error.new(error.Cancelled)))
      Ok(runtime)
    }
    True, Some(#(stream, rest)) ->
      case sequence == stream.request_sequence, stream.request_waiter {
        False, _ -> {
          process.send(reply, Error(error.new(error.Cancelled)))
          Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
        }
        True, Some(_) -> {
          process.send(reply, Error(error.new(error.Resource(error.Queue))))
          Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
        }
        True, None -> {
          let stream =
            StreamEntry(
              ..stream,
              request_waiter: Some(RequestWaiter(
                sequence:,
                maximum_bytes:,
                reply:,
              )),
            )
          use progress <- result.try(request_progress(
            runtime.socket,
            runtime.wire,
            stream,
            maximum_bytes,
          ))
          case progress {
            RequestWaiting ->
              Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
            RequestReady(state, stream, request_reply) -> {
              process.send(reply, Ok(request_reply))
              Ok(
                ConnectionRuntime(..runtime, wire: state, streams: [
                  stream,
                  ..rest
                ]),
              )
            }
          }
        }
      }
  }
}

fn request_progress(
  socket: transport.Socket,
  state: wire.State,
  stream: StreamEntry,
  maximum_bytes: Int,
) -> Result(RequestProgress, error.Error) {
  case stream.request_chunks, stream.request_terminal {
    [], None -> Ok(RequestWaiting)
    [], Some(trailers) ->
      Ok(RequestReady(
        state,
        StreamEntry(..stream, request_waiter: None),
        RequestEnd(trailers),
      ))
    [chunk, ..rest], _ -> {
      use read <- result.try(
        response_reader.read_chunk(chunk, maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      let response_reader.ChunkPart(bytes, remaining, released_credit) = read
      use state <- result.try(release_request_credit(
        socket,
        state,
        stream.stream_id,
        released_credit,
      ))
      let chunks = case remaining {
        Some(remaining) -> [remaining, ..rest]
        None -> rest
      }
      let stream = StreamEntry(..stream, request_chunks: chunks)
      case bit_array.byte_size(bytes) {
        0 -> request_progress(socket, state, stream, maximum_bytes)
        _ -> {
          let next_sequence = stream.request_sequence + 1
          Ok(RequestReady(
            state,
            StreamEntry(
              ..stream,
              request_waiter: None,
              request_sequence: next_sequence,
            ),
            RequestData(bytes, next_sequence),
          ))
        }
      }
    }
  }
}

fn release_request_credit(
  socket: transport.Socket,
  state: wire.State,
  stream_id: Int,
  controlled: Int,
) -> Result(wire.State, error.Error) {
  case controlled <= 0 {
    True -> Ok(state)
    False -> {
      use released <- result.try(
        wire.release_receive_credit(
          state,
          stream_id: stream_id,
          octets: controlled,
        )
        |> result.map_error(map_wire_error),
      )
      let wire.ReceiveCreditReleased(state, frames) = released
      use _ <- result.try(send_frames(socket, frames))
      Ok(state)
    }
  }
}

fn handle_request_data(
  runtime: ConnectionRuntime,
  stream_id: Int,
  bytes: BitArray,
  end_stream: Bool,
  controlled: Int,
) -> Result(ConnectionRuntime, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> Error(protocol_error())
    Some(#(stream, rest)) -> {
      use <- require(stream.request_terminal == None, protocol_error())
      let received = stream.request_body_bytes + bit_array.byte_size(bytes)
      use <- require(
        received <= runtime.config.maximum_body_bytes,
        error.new(error.Body(error.TooLarge(runtime.config.maximum_body_bytes))),
      )
      use <- require(
        !end_stream || request_length_matches(stream, received),
        protocol_error(),
      )
      let chunks = case bit_array.byte_size(bytes) > 0 || controlled > 0 {
        True ->
          list.append(stream.request_chunks, [
            response_reader.Chunk(bytes, controlled),
          ])
        False -> stream.request_chunks
      }
      let stream =
        StreamEntry(
          ..stream,
          request_chunks: chunks,
          request_terminal: case end_stream {
            True -> Some([])
            False -> None
          },
          request_body_bytes: received,
        )
      use runtime <- result.try(satisfy_request_waiter(
        ConnectionRuntime(..runtime, streams: [stream, ..rest]),
        stream_id,
      ))
      cleanup_finished_streams(runtime)
    }
  }
}

fn complete_request_trailers(
  runtime: ConnectionRuntime,
  stream_id: Int,
  validated: header_semantics.Validated,
) -> Result(ConnectionRuntime, error.Error) {
  use trailers <- result.try(
    message.trailers_from_validated(validated)
    |> result.map_error(fn(_) { protocol_error() }),
  )
  case take_stream(runtime.streams, stream_id, []) {
    None -> Error(protocol_error())
    Some(#(stream, rest)) -> {
      use <- require(stream.request_terminal == None, protocol_error())
      use <- require(
        request_length_matches(stream, stream.request_body_bytes),
        protocol_error(),
      )
      let stream = StreamEntry(..stream, request_terminal: Some(trailers))
      use runtime <- result.try(satisfy_request_waiter(
        ConnectionRuntime(..runtime, streams: [stream, ..rest]),
        stream_id,
      ))
      cleanup_finished_streams(runtime)
    }
  }
}

fn request_length_matches(stream: StreamEntry, received: Int) -> Bool {
  case stream.request_content_length {
    None -> True
    Some(expected) -> expected == received
  }
}

fn satisfy_request_waiter(
  runtime: ConnectionRuntime,
  stream_id: Int,
) -> Result(ConnectionRuntime, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> Ok(runtime)
    Some(#(stream, rest)) ->
      case stream.request_waiter {
        None -> Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
        Some(RequestWaiter(_, maximum_bytes, reply)) -> {
          use progress <- result.try(request_progress(
            runtime.socket,
            runtime.wire,
            stream,
            maximum_bytes,
          ))
          case progress {
            RequestWaiting ->
              Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
            RequestReady(state, stream, request_reply) -> {
              process.send(reply, Ok(request_reply))
              Ok(
                ConnectionRuntime(..runtime, wire: state, streams: [
                  stream,
                  ..rest
                ]),
              )
            }
          }
        }
      }
  }
}

fn handle_handler_completion(
  runtime: ConnectionRuntime,
  stream_id: Int,
  outcome: Result(Result(Response(body.Body), error.Error), Nil),
  acknowledgement: Option(Subject(Nil)),
) -> Result(Nil, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> {
      acknowledge_completion(acknowledgement)
      continue_or_drain(runtime)
    }
    Some(#(stream, rest)) -> {
      process.demonitor_process(stream.monitor)
      cancel_timer(stream.handler_timer)
      acknowledge_completion(acknowledgement)
      let stream = StreamEntry(..stream, handler_timer: None)
      case handler_response(outcome) {
        None -> {
          // The common executor and this adapter enforce the same request
          // deadline. Normalize either timer winning to one stream-local
          // outcome instead of racing an HTTP 408 against RST_STREAM.
          use runtime <- result.try(reset_application_stream(
            runtime,
            stream,
            rest,
            0x2,
          ))
          continue_or_drain(runtime)
        }
        Some(response) ->
          case response_has_no_body(stream.method, response.status) {
            True -> {
              body.cancel(response.body)
              use state <- result.try(send_response_head(
                runtime.socket,
                runtime.wire,
                stream_id,
                response,
                True,
              ))
              let stream =
                StreamEntry(
                  ..stream,
                  response_body: None,
                  response_pending: None,
                  response_complete: True,
                )
              use runtime <- result.try(cleanup_finished_streams(
                ConnectionRuntime(..runtime, wire: state, streams: [
                  stream,
                  ..rest
                ]),
              ))
              continue_or_drain(runtime)
            }
            False -> {
              use state <- result.try(send_response_head(
                runtime.socket,
                runtime.wire,
                stream_id,
                response,
                False,
              ))
              let stream =
                StreamEntry(
                  ..stream,
                  response_body: Some(response.body),
                  response_reading: False,
                  response_body_bytes: 0,
                  response_pending: None,
                  response_complete: False,
                )
              use runtime <- result.try(flush_pending_responses(
                ConnectionRuntime(..runtime, wire: state, streams: [
                  stream,
                  ..rest
                ]),
              ))
              continue_or_drain(runtime)
            }
          }
      }
    }
  }
}

fn handler_response(
  outcome: Result(Result(Response(body.Body), error.Error), Nil),
) -> Option(Response(body.Body)) {
  case outcome {
    Ok(Ok(response)) -> Some(response)
    Ok(Error(failure)) ->
      case error.kind(failure) {
        error.Timeout(_) | error.Cancelled -> None
        _ -> Some(error_response(failure))
      }
    Error(Nil) -> Some(error_response(service_error()))
  }
}

fn handle_handler_timeout(
  runtime: ConnectionRuntime,
  stream_id: Int,
  worker: Pid,
) -> Result(ConnectionRuntime, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> Ok(runtime)
    Some(#(stream, rest)) ->
      case stream.handler_timer, stream.worker == worker {
        Some(_), True -> reset_application_stream(runtime, stream, rest, 0x2)
        _, _ -> Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
      }
  }
}

fn spawn_body_reader(
  commands: Subject(ConnectionMessage),
  stream_id: Int,
  outgoing: body.Body,
  maximum_read_bytes: Int,
) -> #(Pid, Monitor) {
  let pid =
    process.spawn_unlinked(fn() {
      let acknowledgement = process.new_subject()
      process.send(
        commands,
        ResponseRead(
          stream_id,
          run_guarded(fn() { body.read(outgoing, maximum_read_bytes) }),
          acknowledgement,
        ),
      )
      let _acknowledged =
        process.receive(acknowledgement, within: maximum_milliseconds)
      Nil
    })
  #(pid, process.monitor(pid))
}

fn handle_response_read(
  runtime: ConnectionRuntime,
  stream_id: Int,
  outcome: Result(Result(body.Read, error.Error), Nil),
  acknowledgement: Option(Subject(Nil)),
) -> Result(Nil, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> {
      acknowledge_completion(acknowledgement)
      continue_or_drain(runtime)
    }
    Some(#(stream, rest)) -> {
      process.demonitor_process(stream.monitor)
      cancel_timer(stream.response_timer)
      acknowledge_completion(acknowledgement)
      let stream =
        StreamEntry(..stream, response_reading: False, response_timer: None)
      case outcome {
        Error(Nil) -> {
          use runtime <- result.try(reset_application_stream(
            runtime,
            stream,
            rest,
            0x2,
          ))
          continue_or_drain(runtime)
        }
        Ok(Error(_failure)) -> {
          use runtime <- result.try(reset_application_stream(
            runtime,
            stream,
            rest,
            0x2,
          ))
          continue_or_drain(runtime)
        }
        Ok(Ok(body.Data(bytes, next))) -> {
          let received = stream.response_body_bytes + bit_array.byte_size(bytes)
          case received <= runtime.config.maximum_body_bytes {
            False -> {
              body.cancel(next)
              use runtime <- result.try(reset_application_stream(
                runtime,
                stream,
                rest,
                0x2,
              ))
              continue_or_drain(runtime)
            }
            True -> {
              let stream =
                StreamEntry(
                  ..stream,
                  response_body: Some(next),
                  response_body_bytes: received,
                  response_pending: Some(ResponsePending(bytes, [], False)),
                )
              use runtime <- result.try(queue_pending_responses(
                ConnectionRuntime(..runtime, streams: [stream, ..rest]),
              ))
              continue_or_drain(runtime)
            }
          }
        }
        Ok(Ok(body.Done(completed))) -> {
          case completed_trailers(completed) {
            Error(_) -> {
              use runtime <- result.try(reset_application_stream(
                runtime,
                stream,
                rest,
                0x2,
              ))
              continue_or_drain(runtime)
            }
            Ok(trailers) -> {
              let stream =
                StreamEntry(
                  ..stream,
                  response_body: None,
                  response_pending: Some(ResponsePending(<<>>, trailers, True)),
                )
              use runtime <- result.try(queue_pending_responses(
                ConnectionRuntime(..runtime, streams: [stream, ..rest]),
              ))
              continue_or_drain(runtime)
            }
          }
        }
      }
    }
  }
}

fn handle_response_timeout(
  runtime: ConnectionRuntime,
  stream_id: Int,
  worker: Pid,
) -> Result(ConnectionRuntime, error.Error) {
  case take_stream(runtime.streams, stream_id, []) {
    None -> Ok(runtime)
    Some(#(stream, rest)) ->
      case stream.response_reading && stream.worker == worker {
        False -> Ok(ConnectionRuntime(..runtime, streams: [stream, ..rest]))
        True -> reset_application_stream(runtime, stream, rest, 0x2)
      }
  }
}

fn reset_application_stream(
  runtime: ConnectionRuntime,
  stream: StreamEntry,
  rest: List(StreamEntry),
  error_code: Int,
) -> Result(ConnectionRuntime, error.Error) {
  use written <- result.try(
    wire.reset_stream(
      runtime.wire,
      stream_id: stream.stream_id,
      error_code: error_code,
    )
    |> result.map_error(map_wire_error),
  )
  let wire.ControlWritten(state, frames) = written
  use _ <- result.try(send_frames(runtime.socket, frames))
  cancel_stream_entry(stream)
  Ok(
    ConnectionRuntime(
      ..runtime,
      wire: state,
      scheduler: priority_scheduler.remove(runtime.scheduler, stream.stream_id),
      streams: rest,
    ),
  )
}

fn completed_trailers(
  completed: body.Body,
) -> Result(body.Headers, error.Error) {
  case body.trailers(completed) {
    Some(trailers) -> Ok(trailers)
    None -> Error(protocol_error())
  }
}

fn flush_pending_responses(
  runtime: ConnectionRuntime,
) -> Result(ConnectionRuntime, error.Error) {
  use scheduler <- result.try(sync_scheduler_readiness(
    runtime.scheduler,
    runtime.streams,
  ))
  use flushed <- result.try(flush_one_scheduled_stream(
    runtime.socket,
    runtime.wire,
    runtime.streams,
    scheduler,
    runtime.config.maximum_frame_bytes,
    list.length(runtime.streams),
  ))
  let #(state, streams, scheduler, made_progress) = flushed
  use runtime <- result.try(cleanup_finished_streams(
    ConnectionRuntime(
      ..runtime,
      wire: state,
      scheduler: scheduler,
      streams: streams,
    ),
  ))
  let runtime = start_response_readers(runtime)
  Ok(case made_progress && has_pending_response(runtime.streams) {
    True -> schedule_flush(runtime, 0)
    False -> runtime
  })
}

fn sync_scheduler_readiness(
  scheduler: priority_scheduler.State,
  streams: List(StreamEntry),
) -> Result(priority_scheduler.State, error.Error) {
  case streams {
    [] -> Ok(scheduler)
    [stream, ..rest] -> {
      let ready = case stream.response_pending {
        Some(_) -> True
        None -> False
      }
      use scheduler <- result.try(
        priority_scheduler.set_ready(scheduler, stream.stream_id, ready)
        |> result.map_error(map_priority_scheduler_error),
      )
      sync_scheduler_readiness(scheduler, rest)
    }
  }
}

fn flush_one_scheduled_stream(
  socket: transport.Socket,
  state: wire.State,
  streams: List(StreamEntry),
  scheduler: priority_scheduler.State,
  maximum_frame_bytes: Int,
  remaining_attempts: Int,
) -> Result(
  #(wire.State, List(StreamEntry), priority_scheduler.State, Bool),
  error.Error,
) {
  case remaining_attempts > 0, priority_scheduler.next(scheduler) {
    False, _ | _, None -> Ok(#(state, streams, scheduler, False))
    True, Some(priority_scheduler.Selection(scheduler, stream_id)) ->
      case take_stream(streams, stream_id, []) {
        None -> Error(protocol_error())
        Some(#(stream, rest)) ->
          case stream.response_pending {
            None -> {
              use scheduler <- result.try(
                priority_scheduler.set_ready(scheduler, stream_id, False)
                |> result.map_error(map_priority_scheduler_error),
              )
              flush_one_scheduled_stream(
                socket,
                state,
                [stream, ..rest],
                scheduler,
                maximum_frame_bytes,
                remaining_attempts - 1,
              )
            }
            Some(pending) -> {
              use written <- result.try(write_pending_response(
                socket,
                state,
                stream_id,
                pending,
                maximum_frame_bytes,
              ))
              case written {
                ResponseBlocked(state, pending, True) ->
                  Ok(#(
                    state,
                    [
                      StreamEntry(..stream, response_pending: Some(pending)),
                      ..rest
                    ],
                    scheduler,
                    True,
                  ))
                ResponseBlocked(state, pending, False) -> {
                  use scheduler <- result.try(
                    priority_scheduler.set_ready(scheduler, stream_id, False)
                    |> result.map_error(map_priority_scheduler_error),
                  )
                  flush_one_scheduled_stream(
                    socket,
                    state,
                    [
                      StreamEntry(..stream, response_pending: Some(pending)),
                      ..rest
                    ],
                    scheduler,
                    maximum_frame_bytes,
                    remaining_attempts - 1,
                  )
                }
                ResponseFinished(state, stream_finished) ->
                  Ok(#(
                    state,
                    [
                      StreamEntry(
                        ..stream,
                        response_pending: None,
                        response_complete: stream_finished,
                      ),
                      ..rest
                    ],
                    scheduler,
                    True,
                  ))
              }
            }
          }
      }
  }
}

fn queue_pending_responses(
  runtime: ConnectionRuntime,
) -> Result(ConnectionRuntime, error.Error) {
  case active_stream_count(runtime.streams, 0) > 1 {
    True -> Ok(schedule_flush(runtime, fairness_coalesce_milliseconds))
    False -> flush_pending_responses(runtime)
  }
}

fn schedule_flush(
  runtime: ConnectionRuntime,
  after_milliseconds: Int,
) -> ConnectionRuntime {
  case runtime.flush_scheduled {
    True -> runtime
    False -> {
      let _timer =
        process.send_after(runtime.commands, after_milliseconds, FlushResponses)
      ConnectionRuntime(..runtime, flush_scheduled: True)
    }
  }
}

fn active_stream_count(streams: List(StreamEntry), count: Int) -> Int {
  case streams {
    [] -> count
    [StreamEntry(response_complete: True, ..), ..rest] ->
      active_stream_count(rest, count)
    [_, ..rest] -> active_stream_count(rest, count + 1)
  }
}

fn has_pending_response(streams: List(StreamEntry)) -> Bool {
  case streams {
    [] -> False
    [StreamEntry(response_pending: Some(_), ..), ..] -> True
    [_, ..rest] -> has_pending_response(rest)
  }
}

fn start_response_readers(runtime: ConnectionRuntime) -> ConnectionRuntime {
  let streams =
    runtime.streams
    |> list.map(fn(stream) {
      case
        stream.response_body,
        stream.response_pending,
        stream.response_reading,
        stream.response_complete
      {
        Some(outgoing), None, False, False -> {
          let #(pid, monitor) =
            spawn_body_reader(
              runtime.commands,
              stream.stream_id,
              outgoing,
              runtime.config.maximum_stream_buffer_bytes,
            )
          let timer =
            process.send_after(
              runtime.commands,
              runtime.config.operation_timeout_milliseconds,
              ResponseReadTimedOut(stream.stream_id, pid),
            )
          StreamEntry(
            ..stream,
            worker: pid,
            monitor:,
            response_reading: True,
            response_timer: Some(timer),
          )
        }
        _, _, _, _ -> stream
      }
    })
  ConnectionRuntime(..runtime, streams: streams)
}

fn write_pending_response(
  socket: transport.Socket,
  state: wire.State,
  stream_id: Int,
  pending: ResponsePending,
  maximum_frame_bytes: Int,
) -> Result(ResponseWrite, error.Error) {
  let ResponsePending(bytes, trailers, closes_stream) = pending
  case bit_array.byte_size(bytes), trailers, closes_stream {
    0, [_, ..], True -> {
      use written <- result.try(
        wire.send_trailers(state, stream_id, trailers)
        |> result.map_error(map_wire_error),
      )
      let wire.HeadersWritten(state, _, frames) = written
      use _ <- result.try(send_frames(socket, frames))
      Ok(ResponseFinished(state, True))
    }
    0, [_, ..], False -> Error(protocol_error())
    _, _, _ -> {
      use sliced <- result.try(response_write_slice(bytes, maximum_frame_bytes))
      let #(sendable, deferred) = sliced
      let end_stream =
        closes_stream
        && list.is_empty(trailers)
        && bit_array.byte_size(deferred) == 0
      use written <- result.try(
        wire.send_data(state, stream_id:, bytes: sendable, end_stream:)
        |> result.map_error(map_wire_error),
      )
      case written {
        wire.DataBlocked(state) -> Ok(ResponseBlocked(state, pending, False))
        wire.DataWritten(state, frames, remaining, end_stream_sent) -> {
          use _ <- result.try(send_frames(socket, frames))
          let remaining = <<remaining:bits, deferred:bits>>
          case
            bit_array.byte_size(remaining),
            trailers,
            end_stream_sent,
            closes_stream
          {
            size, _, _, _ if size > 0 ->
              Ok(ResponseBlocked(
                state,
                ResponsePending(remaining, trailers, closes_stream),
                True,
              ))
            0, [], True, True -> Ok(ResponseFinished(state, True))
            0, [], False, False -> Ok(ResponseFinished(state, False))
            0, [_, ..], False, True ->
              write_pending_response(
                socket,
                state,
                stream_id,
                ResponsePending(<<>>, trailers, True),
                maximum_frame_bytes,
              )
            _, _, _, _ -> Error(protocol_error())
          }
        }
      }
    }
  }
}

fn response_write_slice(
  bytes: BitArray,
  maximum_frame_bytes: Int,
) -> Result(#(BitArray, BitArray), error.Error) {
  let size = bit_array.byte_size(bytes)
  let take = int.min(size, maximum_frame_bytes)
  use sendable <- result.try(
    bit_array.slice(bytes, at: 0, take: take)
    |> result.replace_error(protocol_error()),
  )
  use deferred <- result.try(
    bit_array.slice(bytes, at: take, take: size - take)
    |> result.replace_error(protocol_error()),
  )
  Ok(#(sendable, deferred))
}

fn cleanup_finished_streams(
  runtime: ConnectionRuntime,
) -> Result(ConnectionRuntime, error.Error) {
  use cleaned <- result.try(
    cleanup_finished_stream_list(
      runtime.socket,
      runtime.wire,
      runtime.streams,
      [],
      [],
    ),
  )
  let #(state, streams, removed) = cleaned
  let scheduler = remove_scheduled_streams(runtime.scheduler, removed)
  Ok(
    ConnectionRuntime(
      ..runtime,
      wire: state,
      scheduler: scheduler,
      streams: streams,
    ),
  )
}

fn cleanup_finished_stream_list(
  socket: transport.Socket,
  state: wire.State,
  streams: List(StreamEntry),
  reversed: List(StreamEntry),
  removed_reversed: List(Int),
) -> Result(#(wire.State, List(StreamEntry), List(Int)), error.Error) {
  case streams {
    [] -> Ok(#(state, list.reverse(reversed), list.reverse(removed_reversed)))
    [stream, ..rest] ->
      case stream.response_complete, stream.request_terminal {
        True, Some(_) -> {
          use state <- result.try(release_request_credit(
            socket,
            state,
            stream.stream_id,
            request_credit(stream.request_chunks),
          ))
          cleanup_finished_stream_list(socket, state, rest, reversed, [
            stream.stream_id,
            ..removed_reversed
          ])
        }
        _, _ ->
          cleanup_finished_stream_list(
            socket,
            state,
            rest,
            [stream, ..reversed],
            removed_reversed,
          )
      }
  }
}

fn remove_scheduled_streams(
  scheduler: priority_scheduler.State,
  stream_ids: List(Int),
) -> priority_scheduler.State {
  case stream_ids {
    [] -> scheduler
    [stream_id, ..rest] ->
      remove_scheduled_streams(
        priority_scheduler.remove(scheduler, stream_id),
        rest,
      )
  }
}

fn request_credit(chunks: List(response_reader.Chunk)) -> Int {
  case chunks {
    [] -> 0
    [response_reader.Chunk(_, controlled), ..rest] ->
      controlled + request_credit(rest)
  }
}

fn send_response_head(
  socket: transport.Socket,
  state: wire.State,
  stream_id: Int,
  response: Response(body.Body),
  end_stream: Bool,
) -> Result(wire.State, error.Error) {
  use written <- result.try(
    wire.send_response_headers(
      state,
      stream_id,
      response,
      end_stream: end_stream,
    )
    |> result.map_error(map_wire_error),
  )
  let wire.HeadersWritten(state, _, frames) = written
  use _ <- result.try(send_frames(socket, frames))
  Ok(state)
}

fn continue_or_drain(runtime: ConnectionRuntime) -> Result(Nil, error.Error) {
  case runtime.draining && list.is_empty(runtime.streams) {
    True -> stop_connection(runtime)
    False -> connection_loop(runtime)
  }
}

fn stop_connection(runtime: ConnectionRuntime) -> Result(Nil, error.Error) {
  process.kill(runtime.reader)
  process.demonitor_process(runtime.reader_monitor)
  list.each(runtime.streams, fn(stream) { cancel_stream_entry(stream) })
  let _closed = transport.close(runtime.socket)
  Ok(Nil)
}

fn stop_connection_with_error(
  runtime: ConnectionRuntime,
  failure: error.Error,
) -> Result(Nil, error.Error) {
  let _stopped = stop_connection(runtime)
  Error(failure)
}

fn cancel_stream(
  runtime: ConnectionRuntime,
  stream_id: Int,
) -> ConnectionRuntime {
  case take_stream(runtime.streams, stream_id, []) {
    None -> runtime
    Some(#(stream, rest)) -> {
      cancel_stream_entry(stream)
      ConnectionRuntime(
        ..runtime,
        scheduler: priority_scheduler.remove(runtime.scheduler, stream_id),
        streams: rest,
      )
    }
  }
}

fn cancel_stream_entry(stream: StreamEntry) -> Nil {
  context.cancel(stream.request_context)
  body.cancel(stream.request_body)
  cancel_timer(stream.handler_timer)
  cancel_timer(stream.response_timer)
  process.kill(stream.worker)
  process.demonitor_process(stream.monitor)
  case stream.response_body {
    Some(outgoing) -> body.cancel(outgoing)
    None -> Nil
  }
}

fn cancel_timer(timer: Option(Timer)) -> Nil {
  case timer {
    Some(timer) -> {
      let _cancelled = process.cancel_timer(timer)
      Nil
    }
    None -> Nil
  }
}

fn acknowledge_completion(acknowledgement: Option(Subject(Nil))) -> Nil {
  case acknowledgement {
    Some(subject) -> process.send(subject, Nil)
    None -> Nil
  }
}

fn stream_for_worker(
  streams: List(StreamEntry),
  pid: Pid,
) -> Option(StreamEntry) {
  case streams {
    [] -> None
    [stream, ..rest] ->
      case stream.worker == pid {
        True -> Some(stream)
        False -> stream_for_worker(rest, pid)
      }
  }
}

fn stream_present(streams: List(StreamEntry), stream_id: Int) -> Bool {
  case streams {
    [] -> False
    [stream, ..rest] ->
      stream.stream_id == stream_id || stream_present(rest, stream_id)
  }
}

fn take_stream(
  streams: List(StreamEntry),
  stream_id: Int,
  reversed: List(StreamEntry),
) -> Option(#(StreamEntry, List(StreamEntry))) {
  case streams {
    [] -> None
    [stream, ..rest] ->
      case stream.stream_id == stream_id {
        True -> Some(#(stream, list.append(list.reverse(reversed), rest)))
        False -> take_stream(rest, stream_id, [stream, ..reversed])
      }
  }
}

fn send_frames(
  socket: transport.Socket,
  frames: List(BitArray),
) -> Result(Nil, error.Error) {
  case frames {
    [] -> Ok(Nil)
    [frame, ..rest] -> {
      use _ <- result.try(
        transport.send(socket, frame) |> result.map_error(map_transport_error),
      )
      send_frames(socket, rest)
    }
  }
}

fn response_has_no_body(method: gleam_http.Method, status: Int) -> Bool {
  method == gleam_http.Head
  || status >= 100
  && status < 200
  || status == 204
  || status == 304
}

fn error_response(failure: error.Error) -> Response(body.Body) {
  let status = case error.kind(failure) {
    error.Timeout(_) | error.Cancelled -> 408
    error.Resource(_) -> 503
    _ -> 500
  }
  Response(status:, headers: [], body: body.empty())
}

fn connection_limits(config: Config) -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 64,
    maximum_active_streams: config.maximum_active_streams,
    header_limits: header_codec.Limits(
      maximum_block_bytes: config.maximum_header_block_bytes,
      maximum_header_list_bytes: config.maximum_header_list_bytes,
      maximum_table_capacity: config.maximum_header_table_bytes,
      maximum_tracked_streams: config.maximum_active_streams,
    ),
  )
}

fn wire_limits(config: Config) -> wire.Limits {
  wire.Limits(
    maximum_frame_bytes: config.maximum_frame_bytes,
    maximum_feed_bytes: config.maximum_feed_bytes,
    maximum_frames_per_feed: config.maximum_frames_per_feed,
  )
}

fn local_settings(config: Config) -> List(settings.Setting) {
  let common = [
    settings.HeaderTableSize(config.maximum_header_table_bytes),
    settings.MaxConcurrentStreams(config.maximum_active_streams),
    settings.MaxHeaderListSize(config.maximum_header_list_bytes),
  ]
  case config.extended_connect_enabled {
    True -> [settings.EnableConnectProtocol(True), ..common]
    False -> common
  }
}

fn context_endpoint(
  raw: #(BitArray, Int),
) -> Result(context.Endpoint, error.Error) {
  let #(address, port) = raw
  use host <- result.try(address_string(address))
  Ok(context.Endpoint(host, port))
}

fn address_string(address: BitArray) -> Result(String, error.Error) {
  case address {
    <<a, b, c, d>> ->
      Ok(
        int.to_string(a)
        <> "."
        <> int.to_string(b)
        <> "."
        <> int.to_string(c)
        <> "."
        <> int.to_string(d),
      )
    <<a:16, b:16, c:16, d:16, e:16, f:16, g:16, h:16>> ->
      Ok(
        [a, b, c, d, e, f, g, h]
        |> list.map(int.to_base16)
        |> string.join(":"),
      )
    _ -> Error(service_error())
  }
}

fn map_listen_error(failure: transport.Error) -> error.Error {
  case failure {
    transport.PermissionDenied
    | transport.AddressInUse
    | transport.AddressUnavailable -> error.new(error.ConnectFailed)
    transport.InvalidInput -> policy_error()
    _ -> service_error()
  }
}

fn map_tls_error(failure: transport.Error) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(error.TlsHandshake))
    transport.InvalidInput -> policy_error()
    _ -> error.new(error.Tls)
  }
}

fn map_transport_error(failure: transport.Error) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(error.Idle))
    transport.InvalidInput -> policy_error()
    _ -> protocol_error()
  }
}

fn map_wire_error(_failure: wire.Error) -> error.Error {
  protocol_error()
}

fn map_priority_scheduler_error(
  _failure: priority_scheduler.Error,
) -> error.Error {
  protocol_error()
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http2))
}

fn policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}

fn service_error() -> error.Error {
  error.new(error.Service)
}

fn receive_before(
  subject: Subject(value),
  deadline_milliseconds: Int,
) -> Result(value, Nil) {
  let remaining = deadline_milliseconds - transport.monotonic_millisecond()
  case remaining > 0 {
    True -> process.receive(subject, within: remaining)
    False -> Error(Nil)
  }
}

fn elapsed_milliseconds(started_milliseconds: Int) -> Int {
  let elapsed = transport.monotonic_millisecond() - started_milliseconds
  case elapsed > 0 {
    True -> elapsed
    False -> 0
  }
}

fn valid_timeout(milliseconds: Int) -> Bool {
  milliseconds > 0 && milliseconds <= maximum_milliseconds
}

fn require(
  condition: Bool,
  failure: error,
  next: fn() -> Result(value, error),
) -> Result(value, error) {
  case condition {
    True -> next()
    False -> Error(failure)
  }
}
