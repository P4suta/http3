//// Active-once HTTP/1.1 listener and connection adapter.

import gleam/bit_array
import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri.{Uri}
import http/body
import http/context
import http/error
import http/internal/date
import http/internal/http1
import http/internal/http1/body as http1_body
import http/internal/http1/encode
import http/internal/transport
import http/internal/upload

const http1_alpn = <<"http/1.1":utf8>>

const startup_milliseconds = 1000

const handler_cleanup_milliseconds = 1000

const accept_poll_milliseconds = 25

/// A protocol-neutral callback installed by `http/server`.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// Finite HTTP/1.1 listener, connection, parser, and body policy.
pub opaque type Config {
  Config(
    backlog: Int,
    maximum_connections: Int,
    maximum_requests_per_connection: Int,
    maximum_head_bytes: Int,
    maximum_header_count: Int,
    maximum_line_bytes: Int,
    maximum_body_bytes: Int,
    maximum_stream_buffer_bytes: Int,
    maximum_trailer_bytes: Int,
    maximum_trailer_count: Int,
    idle_timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    tls_timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    send_timeout_milliseconds: Int,
  )
}

/// The transport security installed before an HTTP request is read.
pub type Security {
  Cleartext
  Tls(
    certificate_pem: BitArray,
    private_key_pem: BitArray,
    service_identity: String,
  )
}

type Lifecycle

type ListenerDiagnostics

/// Fixed-size, payload-free listener phase counters for the public adapter.
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
    parsed_request_heads: Int,
    handler_dispatches: Int,
    handler_completions: Int,
    handler_failures: Int,
    connection_failures: Int,
    last_connection_start_milliseconds: Int,
    maximum_connection_start_milliseconds: Int,
  )
}

/// One listener actor and all of its supervised connection actors.
pub opaque type Listener {
  Listener(
    pid: Pid,
    commands: Subject(ListenerCommand),
    lifecycle: Lifecycle,
    endpoint: context.Endpoint,
    transport_listener: transport.Listener,
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

type HeadReceive {
  HeadReceived(transport.Socket, http1.RequestHead, BitArray)
  HeadReceiveEnded
}

type ConnectionBoot {
  ConnectionBoot(
    commands: Subject(ConnectionCommand),
    start: Subject(transport.Socket),
    proceed: Subject(Nil),
  )
}

type ConnectionEntry {
  ConnectionEntry(
    pid: Pid,
    monitor: Monitor,
    commands: Subject(ConnectionCommand),
    socket: transport.Socket,
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

type Expectation {
  NoExpectation
  ContinueExpected
  UnsupportedExpectation
}

type IncomingCommand {
  PullIncoming(
    sequence: Int,
    maximum_bytes: Int,
    reply: Subject(Result(IncomingReply, error.Error)),
  )
  CancelIncoming
}

type IncomingReply {
  IncomingData(bytes: BitArray, next_sequence: Int)
  IncomingEnd(trailers: body.Headers)
}

type IncomingTerminal {
  IncomingTerminal(trailers: body.Headers, remaining: BitArray)
}

type IncomingState {
  IncomingState(
    socket: transport.Socket,
    decoder: Option(http1_body.Decoder),
    input: BitArray,
    pending: BitArray,
    terminal: Option(IncomingTerminal),
    sequence: Int,
    expect_continue: Bool,
    continue_sent: Bool,
  )
}

type DispatchReply {
  DispatchReply(Result(Response(body.Body), error.Error))
}

type HandlerTermination {
  HandlerTimedOut
  HandlerStopped
}

type HandlerCommand {
  TerminateHandler(termination: HandlerTermination, requested_at: Int)
}

type HandlerStartFailure {
  HandlerStartTimedOut
  HandlerStartFailed
}

type HandlerEvent {
  HandlerResult(DispatchReply)
  HandlerFailed
  HandlerTerminated(HandlerTermination)
  HandlerCleanupUnconfirmed(HandlerTermination)
}

type HandlerMessage {
  IncomingMessage(IncomingCommand)
  HandlerEventMessage(HandlerEvent)
  HandlerGuardianExited(process.Down)
  ConnectionControl(ConnectionCommand)
}

type ResponseMessage {
  ResponseSource(upload.Event)
  ResponseControl(ConnectionCommand)
}

type ResponseStream {
  ResponseStream(
    socket: transport.Socket,
    input: BitArray,
    read_ended: Bool,
    draining: Bool,
  )
}

type HandlerOutcome {
  HandlerOutcome(
    result: Result(Response(body.Body), error.Error),
    incoming: IncomingState,
    draining: Bool,
  )
  HandlerAborted
}

@external(erlang, "http_server_ffi", "new_server_lifecycle")
fn new_lifecycle() -> Lifecycle

@external(erlang, "http_server_ffi", "server_lifecycle_state")
fn lifecycle_state(lifecycle: Lifecycle) -> Int

@external(erlang, "http_server_ffi", "mark_server_draining")
fn mark_draining(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "mark_server_stopped")
fn mark_stopped(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "start_http1_handler_guardian")
fn start_http1_handler_guardian(
  events: Subject(HandlerEvent),
  run: fn() -> DispatchReply,
  cancel: fn() -> Nil,
  discard: fn(DispatchReply) -> Nil,
  probe: fn(Int, Pid) -> Nil,
  after_result: fn() -> Nil,
  terminate: fn(Pid) -> Nil,
  handler_deadline: Int,
  cleanup_milliseconds: Int,
  startup_milliseconds: Int,
) -> Result(#(Monitor, Subject(HandlerCommand)), HandlerStartFailure)

@external(erlang, "http_http1_listener_ffi", "new")
fn new_listener_diagnostics() -> ListenerDiagnostics

@external(erlang, "http_http1_listener_ffi", "record_listener_ready")
fn record_listener_ready(
  diagnostics: ListenerDiagnostics,
  elapsed_milliseconds: Int,
) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_state")
fn record_listener_state(diagnostics: ListenerDiagnostics, state: Int) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_accept")
fn record_accept(diagnostics: ListenerDiagnostics, succeeded: Bool) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_connection_start")
fn record_connection_start(
  diagnostics: ListenerDiagnostics,
  succeeded: Bool,
  elapsed_milliseconds: Int,
) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_connection_exit")
fn record_connection_exit(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_request_head")
fn record_request_head(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_handler_dispatch")
fn record_handler_dispatch(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_handler_completion")
fn record_handler_completion(
  diagnostics: ListenerDiagnostics,
  succeeded: Bool,
) -> Nil

@external(erlang, "http_http1_listener_ffi", "record_connection_failure")
fn record_connection_failure(diagnostics: ListenerDiagnostics) -> Nil

@external(erlang, "http_http1_listener_ffi", "snapshot")
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
)

/// Construct finite server defaults.
/// Cleartext permission is enforced by the public server configuration rather than represented here.
pub fn defaults() -> Config {
  Config(
    backlog: 128,
    maximum_connections: 256,
    maximum_requests_per_connection: 1000,
    maximum_head_bytes: 65_536,
    maximum_header_count: 100,
    maximum_line_bytes: 8192,
    maximum_body_bytes: 67_108_864,
    maximum_stream_buffer_bytes: 262_144,
    maximum_trailer_bytes: 65_536,
    maximum_trailer_count: 100,
    idle_timeout_milliseconds: 30_000,
    operation_timeout_milliseconds: 30_000,
    tls_timeout_milliseconds: 10_000,
    drain_timeout_milliseconds: 30_000,
    send_timeout_milliseconds: 30_000,
  )
}

/// Replace the idle deadline after validation.
pub fn with_idle_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, error.Error) {
  use <- require(valid_timeout(milliseconds), policy_error())
  Ok(Config(..config, idle_timeout_milliseconds: milliseconds))
}

/// Replace every finite network and adapter deadline.
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

/// Replace finite connection and per-connection request ceilings.
pub fn with_connection_limits(
  config: Config,
  maximum_connections: Int,
  maximum_requests_per_connection: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_connections > 0
      && maximum_connections <= 1_000_000
      && maximum_requests_per_connection > 0
      && maximum_requests_per_connection <= 1_000_000,
    policy_error(),
  )
  Ok(Config(..config, maximum_connections:, maximum_requests_per_connection:))
}

/// Replace request-head and streaming-body resource ceilings.
pub fn with_limits(
  config: Config,
  maximum_head_bytes: Int,
  maximum_header_count: Int,
  maximum_line_bytes: Int,
  maximum_body_bytes: Int,
  maximum_stream_buffer_bytes: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_head_bytes > 0
      && maximum_header_count > 0
      && maximum_line_bytes > 0
      && maximum_line_bytes <= maximum_head_bytes
      && maximum_body_bytes > 0
      && maximum_stream_buffer_bytes > 0,
    policy_error(),
  )
  Ok(
    Config(
      ..config,
      maximum_head_bytes:,
      maximum_header_count:,
      maximum_line_bytes:,
      maximum_body_bytes:,
      maximum_stream_buffer_bytes:,
      maximum_trailer_bytes: smallest(
        config.maximum_trailer_bytes,
        maximum_stream_buffer_bytes,
      ),
    ),
  )
}

/// Bind and start one listener actor.
pub fn listen(
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

/// Inspect fixed-size listener phases without exposing transport/runtime data.
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
    parsed_request_heads,
    handler_dispatches,
    handler_completions,
    handler_failures,
    connection_failures,
    last_connection_start_milliseconds,
    maximum_connection_start_milliseconds,
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
    parsed_request_heads:,
    handler_dispatches:,
    handler_completions:,
    handler_failures:,
    connection_failures:,
    last_connection_start_milliseconds:,
    maximum_connection_start_milliseconds:,
  )
}

/// Stop accepting and wait for existing connection actors.
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
    transport.local_endpoint(listener)
    |> result.map_error(map_transport_error),
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
        Ok(listener) -> {
          process.send(started, Nil)
          case process.receive(proceed, within: startup_milliseconds) {
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
            Error(Nil) -> {
              let _stopped = mark_stopped(lifecycle)
              record_listener_state(diagnostics, 2)
              Nil
            }
          }
        }
        Error(Nil) -> {
          let _stopped = mark_stopped(lifecycle)
          record_listener_state(diagnostics, 2)
          Nil
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
                pid:,
                commands:,
                lifecycle:,
                endpoint: context.Endpoint(host, port),
                transport_listener: listener,
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
        Error(transport.Timeout) -> listener_loop(runtime)
        Error(transport.Closed) -> {
          record_accept(runtime.diagnostics, False)
          process.sleep(accept_poll_milliseconds)
          listener_loop(runtime)
        }
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
  case first {
    True -> {
      record_listener_state(runtime.diagnostics, 1)
      let _closed = transport.stop(runtime.listener)
      list.each(runtime.connections, fn(connection) {
        process.send(connection.commands, DrainConnection)
      })
    }
    False -> Nil
  }
  case runtime.connections {
    [] -> {
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
    process.send(connection.commands, StopConnection)
    let _closed = transport.close(connection.socket)
  })
  let deadline =
    transport.monotonic_millisecond()
    + int.min(
      runtime.config.drain_timeout_milliseconds,
      runtime.config.operation_timeout_milliseconds,
    )
  let joined =
    list.fold(runtime.connections, True, fn(joined, connection) {
      let exited =
        process.new_selector()
        |> process.select_specific_monitor(connection.monitor, fn(_) { Nil })
        |> process.selector_receive(within: int.max(
          0,
          deadline - transport.monotonic_millisecond(),
        ))
      case exited {
        Ok(Nil) -> {
          process.demonitor_process(connection.monitor)
          record_connection_exit(runtime.diagnostics)
          joined
        }
        Error(Nil) -> {
          // A forced exit is a failed graceful join, never a successful stop.
          process.kill(connection.pid)
          let killed =
            process.new_selector()
            |> process.select_specific_monitor(connection.monitor, fn(_) { Nil })
            |> process.selector_receive(within: int.max(
              0,
              deadline + 1000 - transport.monotonic_millisecond(),
            ))
          process.demonitor_process(connection.monitor)
          case killed {
            Ok(Nil) -> record_connection_exit(runtime.diagnostics)
            Error(Nil) -> Nil
          }
          False
        }
      }
    })
  let outcome = case joined {
    True -> Ok(Nil)
    False -> Error(error.new(error.Timeout(error.Operation)))
  }
  list.each(runtime.drain_waiters, fn(waiter) { process.send(waiter, outcome) })
  case joined {
    True -> {
      let _stopped = mark_stopped(runtime.lifecycle)
      record_listener_state(runtime.diagnostics, 2)
    }
    False -> {
      let _draining = mark_draining(runtime.lifecycle)
      record_listener_state(runtime.diagnostics, 1)
    }
  }
  process.send(reply, outcome)
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
      case remaining, lifecycle_state(runtime.lifecycle) {
        [], state if state != 0 -> {
          list.each(runtime.drain_waiters, fn(waiter) {
            process.send(waiter, Ok(Nil))
          })
          ListenerRuntime(..runtime, connections: [], drain_waiters: [])
        }
        _, _ -> ListenerRuntime(..runtime, connections: remaining)
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
          case process.receive(proceed, within: startup_milliseconds) {
            Error(Nil) -> Nil
            Ok(Nil) -> {
              let completed =
                run_connection(
                  socket,
                  commands,
                  runtime.handler,
                  runtime.config,
                  runtime.security,
                  runtime.diagnostics,
                )
              case completed {
                Ok(Nil) -> Nil
                Error(_) -> record_connection_failure(runtime.diagnostics)
              }
            }
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
              Ok(ConnectionEntry(pid:, monitor:, commands:, socket:))
            }
          }
        }
      }
  }
}

fn run_connection(
  socket: transport.Socket,
  commands: Subject(ConnectionCommand),
  handler: Handler,
  config: Config,
  security: Security,
  diagnostics: ListenerDiagnostics,
) -> Result(Nil, error.Error) {
  use peer <- result.try(
    transport.peer_endpoint(socket)
    |> result.map_error(map_transport_error),
  )
  use local <- result.try(
    transport.socket_local_endpoint(socket)
    |> result.map_error(map_transport_error),
  )
  use peer_endpoint <- result.try(context_endpoint(peer))
  use local_endpoint <- result.try(context_endpoint(local))
  use #(socket, tls_identity, scheme) <- result.try(secure(
    socket,
    security,
    config,
  ))
  connection_loop(
    socket,
    <<>>,
    0,
    commands,
    handler,
    config,
    diagnostics,
    scheme,
    tls_identity,
    peer_endpoint,
    local_endpoint,
  )
}

fn secure(
  socket: transport.Socket,
  security: Security,
  config: Config,
) -> Result(
  #(transport.Socket, context.TlsIdentity, gleam_http.Scheme),
  error.Error,
) {
  case security {
    Cleartext -> {
      use _ <- result.try(
        transport.enable_half_close(socket)
        |> result.map_error(map_transport_error),
      )
      Ok(#(socket, context.CleartextIdentity, gleam_http.Http))
    }
    Tls(certificate_pem, private_key_pem, service_identity) -> {
      use ready <- result.try(
        transport.upgrade_server_tls(
          socket,
          certificate_pem,
          private_key_pem,
          [http1_alpn],
          config.tls_timeout_milliseconds,
        )
        |> result.map_error(map_tls_error),
      )
      let transport.TlsReady(socket, selected, _) = ready
      // HTTP/1.1 predates ALPN.
      // An absent extension keeps that protocol; an explicitly incompatible selection must never be reinterpreted as H1.
      use <- require(
        selected == <<>> || selected == http1_alpn,
        protocol_error(),
      )
      Ok(#(
        socket,
        context.TlsIdentity(service_identity, None),
        gleam_http.Https,
      ))
    }
  }
}

fn connection_loop(
  socket: transport.Socket,
  buffered: BitArray,
  request_count: Int,
  commands: Subject(ConnectionCommand),
  handler: Handler,
  config: Config,
  diagnostics: ListenerDiagnostics,
  scheme: gleam_http.Scheme,
  tls_identity: context.TlsIdentity,
  peer_endpoint: context.Endpoint,
  local_endpoint: context.Endpoint,
) -> Result(Nil, error.Error) {
  case process.receive(commands, within: 0) {
    Ok(DrainConnection) | Ok(StopConnection) -> Ok(Nil)
    Error(Nil) ->
      case request_count >= config.maximum_requests_per_connection {
        True -> Ok(Nil)
        False ->
          receive_and_handle_request(
            socket,
            buffered,
            request_count,
            commands,
            handler,
            config,
            diagnostics,
            scheme,
            tls_identity,
            peer_endpoint,
            local_endpoint,
          )
      }
  }
}

fn receive_and_handle_request(
  socket: transport.Socket,
  buffered: BitArray,
  request_count: Int,
  commands: Subject(ConnectionCommand),
  handler: Handler,
  config: Config,
  diagnostics: ListenerDiagnostics,
  scheme: gleam_http.Scheme,
  tls_identity: context.TlsIdentity,
  peer_endpoint: context.Endpoint,
  local_endpoint: context.Endpoint,
) -> Result(Nil, error.Error) {
  use parser <- result.try(
    http1.request_parser(head_limits(config))
    |> result.map_error(fn(_) { protocol_error() }),
  )
  case receive_head(socket, parser, buffered, config, commands, False) {
    Error(#(status, failure)) -> {
      let _sent =
        send_simple_error(socket, status, reason_phrase(status), config)
      Error(failure)
    }
    Ok(HeadReceiveEnded) -> Ok(Nil)
    Ok(HeadReceived(socket, head, remaining)) -> {
      record_request_head(diagnostics)
      case expectation(head.headers) {
        UnsupportedExpectation -> {
          let _sent =
            send_simple_error(socket, 417, "Expectation Failed", config)
          Ok(Nil)
        }
        expected ->
          handle_valid_request(
            socket,
            head,
            remaining,
            request_count,
            commands,
            handler,
            config,
            diagnostics,
            scheme,
            tls_identity,
            peer_endpoint,
            local_endpoint,
            expected == ContinueExpected,
          )
      }
    }
  }
}

/// Read one request head, naming the status its failure is answered with.
///
/// RFC 9112 section 3 asks for 414 when a request target is longer than the server will parse, which the parser names apart from any other framing failure.
/// Every other failure keeps the 400 this section's own error handling calls for.
fn receive_head(
  socket: transport.Socket,
  parser: http1.RequestParser,
  input: BitArray,
  config: Config,
  commands: Subject(ConnectionCommand),
  received_input: Bool,
) -> Result(HeadReceive, #(Int, error.Error)) {
  let received_input = received_input || bit_array.byte_size(input) > 0
  case http1.feed_request(parser, input) {
    Error(failure) -> Error(#(head_failure_status(failure), protocol_error()))
    Ok(http1.RequestReady(head, remaining)) ->
      case
        bit_array.byte_size(remaining) <= config.maximum_stream_buffer_bytes
      {
        False -> Error(#(400, resource_error()))
        True -> Ok(HeadReceived(socket, head, remaining))
      }
    Ok(http1.NeedMore(parser)) ->
      read_next_head(socket, parser, config, commands, received_input)
  }
}

fn read_next_head(
  socket: transport.Socket,
  parser: http1.RequestParser,
  config: Config,
  commands: Subject(ConnectionCommand),
  received_input: Bool,
) -> Result(HeadReceive, #(Int, error.Error)) {
  let controls = process.new_selector() |> process.select(commands)
  case
    transport.read_or_select(
      socket,
      config.maximum_stream_buffer_bytes,
      config.idle_timeout_milliseconds,
      controls,
    )
  {
    Error(transport.Closed) | Ok(transport.ReadSocket(transport.ReadEnd(_))) ->
      head_receive_ended(commands, received_input)
    Error(failure) -> Error(#(400, map_transport_error(failure)))
    Ok(transport.ReadMessage(_, _)) -> Ok(HeadReceiveEnded)
    Ok(transport.ReadSocket(transport.ReadData(bytes, socket))) ->
      receive_head(socket, parser, bytes, config, commands, received_input)
  }
}

fn head_receive_ended(
  commands: Subject(ConnectionCommand),
  received_input: Bool,
) -> Result(HeadReceive, #(Int, error.Error)) {
  // Local shutdown may close the socket before the selector observes its already-issued control.
  // A peer EOF is normal only between request heads.
  case process.receive(commands, within: 0), received_input {
    Ok(_), _ | Error(Nil), False -> Ok(HeadReceiveEnded)
    Error(Nil), True -> Error(#(400, protocol_error()))
  }
}

fn head_failure_status(failure: http1.Error) -> Int {
  case failure {
    http1.RequestLineTooLong(_) -> 414
    _ -> 400
  }
}

fn handle_valid_request(
  socket: transport.Socket,
  head: http1.RequestHead,
  remaining: BitArray,
  request_count: Int,
  commands: Subject(ConnectionCommand),
  handler: Handler,
  config: Config,
  diagnostics: ListenerDiagnostics,
  scheme: gleam_http.Scheme,
  tls_identity: context.TlsIdentity,
  peer_endpoint: context.Endpoint,
  local_endpoint: context.Endpoint,
  expect_continue: Bool,
) -> Result(Nil, error.Error) {
  let incoming_commands = process.new_subject()
  use #(request_body, incoming) <- result.try(make_incoming_body(
    socket,
    head.framing,
    remaining,
    expect_continue,
    incoming_commands,
    config,
  ))
  use request <- result.try(make_request_or_reject(
    socket,
    head,
    request_body,
    scheme,
    config,
  ))
  use request_context <- result.try(context.new(
    protocol: context.Http1,
    peer_endpoint:,
    local_endpoint:,
    within_milliseconds: config.operation_timeout_milliseconds,
    tls_identity:,
    early_data: context.EarlyDataDisabled,
  ))
  let outcome =
    run_handler(
      handler,
      request,
      request_context,
      incoming,
      incoming_commands,
      commands,
      config,
      diagnostics,
    )
  case outcome {
    HandlerAborted -> Error(error.new(error.Cancelled))
    HandlerOutcome(Error(failure), _, _) -> {
      let #(status, reason) = handler_error_status(failure)
      let _sent = send_simple_error(socket, status, reason, config)
      Ok(Nil)
    }
    HandlerOutcome(Ok(response), incoming, draining) -> {
      let close =
        draining
        || request_count + 1 >= config.maximum_requests_per_connection
        || request_requests_close(head.headers)
        || response_requests_close(response.headers)
        || !incoming_wire_complete(incoming)
        || response.status == 101
        || request.method == gleam_http.Connect
      let buffered = case incoming_remaining(incoming) {
        Ok(buffered) -> buffered
        Error(_) -> <<>>
      }
      case
        write_response(
          incoming.socket,
          buffered,
          request.method,
          response,
          close,
          commands,
          request_context,
          config,
        )
      {
        Error(failure) -> Error(failure)
        Ok(stream) ->
          case close || stream.draining || stream.read_ended {
            True -> Ok(Nil)
            False ->
              connection_loop(
                stream.socket,
                stream.input,
                request_count + 1,
                commands,
                handler,
                config,
                diagnostics,
                scheme,
                tls_identity,
                peer_endpoint,
                local_endpoint,
              )
          }
      }
    }
  }
}

fn make_incoming_body(
  socket: transport.Socket,
  framing: http1.Framing,
  remaining: BitArray,
  expect_continue: Bool,
  commands: Subject(IncomingCommand),
  config: Config,
) -> Result(#(body.Body, IncomingState), error.Error) {
  case framing {
    http1.NoBody | http1.ContentLength(0) ->
      Ok(#(
        body.empty(),
        IncomingState(
          socket:,
          decoder: None,
          input: <<>>,
          pending: <<>>,
          terminal: Some(IncomingTerminal([], remaining)),
          sequence: 0,
          expect_continue: False,
          continue_sent: False,
        ),
      ))
    http1.CloseDelimited | http1.Tunnel -> Error(protocol_error())
    framing -> {
      use decoder <- result.try(
        http1_body.decoder(framing, body_limits(config))
        |> result.map_error(map_body_error),
      )
      let known_length = case framing {
        http1.ContentLength(length) -> Some(length)
        _ -> None
      }
      use incoming <- result.try(
        body.from_pull(
          incoming_pull(commands, 0, config.idle_timeout_milliseconds),
          known_length,
          None,
          fn() { process.send(commands, CancelIncoming) },
        ),
      )
      Ok(#(
        incoming,
        IncomingState(
          socket:,
          decoder: Some(decoder),
          input: remaining,
          pending: <<>>,
          terminal: None,
          sequence: 0,
          expect_continue:,
          continue_sent: False,
        ),
      ))
    }
  }
}

fn incoming_pull(
  commands: Subject(IncomingCommand),
  sequence: Int,
  timeout: Int,
) -> body.Pull {
  body.pull(fn(maximum_bytes) {
    let reply = process.new_subject()
    process.send(commands, PullIncoming(sequence, maximum_bytes, reply))
    case process.receive(reply, within: timeout) {
      Error(Nil) -> Error(error.new(error.Timeout(error.Idle)))
      Ok(Error(failure)) -> Error(failure)
      Ok(Ok(IncomingEnd(trailers))) -> Ok(body.PullEnd(trailers))
      Ok(Ok(IncomingData(bytes, next_sequence))) ->
        Ok(body.PullData(bytes, incoming_pull(commands, next_sequence, timeout)))
    }
  })
}

fn run_handler(
  handler: Handler,
  request: Request(body.Body),
  request_context: context.Context,
  incoming: IncomingState,
  incoming_commands: Subject(IncomingCommand),
  connection_commands: Subject(ConnectionCommand),
  config: Config,
  diagnostics: ListenerDiagnostics,
) -> HandlerOutcome {
  let events = process.new_subject()
  let handler_deadline =
    transport.monotonic_millisecond()
    + context.remaining_milliseconds(request_context)
  let started =
    start_http1_handler_guardian(
      events,
      fn() {
        record_handler_dispatch(diagnostics)
        DispatchReply(handler(request, request_context))
      },
      fn() { context.cancel(request_context) },
      discard_dispatch_reply,
      fn(_, _) { Nil },
      fn() { Nil },
      fn(pid) { process.kill(pid) },
      handler_deadline,
      handler_cleanup_milliseconds,
      startup_milliseconds,
    )
  let outcome = case started {
    Error(failure) -> {
      context.cancel(request_context)
      body.cancel(request.body)
      case failure {
        HandlerStartTimedOut ->
          HandlerOutcome(
            Error(error.new(error.Timeout(error.Operation))),
            incoming,
            True,
          )
        HandlerStartFailed ->
          HandlerOutcome(Error(service_error()), incoming, True)
      }
    }
    Ok(#(guardian_monitor, guardian_commands)) ->
      await_handler(
        incoming,
        incoming_commands,
        events,
        guardian_commands,
        connection_commands,
        guardian_monitor,
        False,
        config,
        handler_deadline,
      )
  }
  record_handler_completion(diagnostics, handler_succeeded(outcome))
  outcome
}

fn await_handler(
  incoming: IncomingState,
  incoming_commands: Subject(IncomingCommand),
  events: Subject(HandlerEvent),
  guardian_commands: Subject(HandlerCommand),
  connection_commands: Subject(ConnectionCommand),
  guardian_monitor: Monitor,
  draining: Bool,
  config: Config,
  handler_deadline: Int,
) -> HandlerOutcome {
  let remaining = handler_remaining(handler_deadline)
  let selector =
    process.new_selector()
    |> process.select_map(events, HandlerEventMessage)
    |> process.select_specific_monitor(guardian_monitor, HandlerGuardianExited)
  let selector = case remaining > 0 {
    True ->
      selector
      |> process.select_map(incoming_commands, IncomingMessage)
      |> process.select_map(connection_commands, ConnectionControl)
    False -> selector
  }
  case
    receive_http1_handler_message(
      selector,
      handler_deadline,
      config.operation_timeout_milliseconds,
    )
  {
    Error(Nil) ->
      terminate_handler_and_await(
        incoming,
        events,
        guardian_commands,
        guardian_monitor,
        HandlerTimedOut,
        handler_deadline,
      )
    Ok(ConnectionControl(StopConnection)) ->
      terminate_handler_and_await(
        incoming,
        events,
        guardian_commands,
        guardian_monitor,
        HandlerStopped,
        transport.monotonic_millisecond(),
      )
    Ok(ConnectionControl(DrainConnection)) ->
      await_handler(
        incoming,
        incoming_commands,
        events,
        guardian_commands,
        connection_commands,
        guardian_monitor,
        True,
        config,
        handler_deadline,
      )
    Ok(HandlerEventMessage(event)) ->
      finish_handler_event(event, guardian_monitor, incoming, draining)
    Ok(HandlerGuardianExited(_)) ->
      reconcile_handler_guardian_exit(events, incoming, draining)
    Ok(IncomingMessage(CancelIncoming)) ->
      await_handler(
        incoming,
        incoming_commands,
        events,
        guardian_commands,
        connection_commands,
        guardian_monitor,
        draining,
        config,
        handler_deadline,
      )
    Ok(IncomingMessage(PullIncoming(sequence, maximum, reply))) -> {
      case sequence == incoming.sequence && maximum > 0 {
        False -> {
          process.send(reply, Error(protocol_error()))
          await_handler(
            incoming,
            incoming_commands,
            events,
            guardian_commands,
            connection_commands,
            guardian_monitor,
            True,
            config,
            handler_deadline,
          )
        }
        True ->
          case fulfill_incoming(incoming, maximum, config, handler_deadline) {
            Error(failure) -> {
              process.send(reply, Error(failure))
              await_handler(
                incoming,
                incoming_commands,
                events,
                guardian_commands,
                connection_commands,
                guardian_monitor,
                True,
                config,
                handler_deadline,
              )
            }
            Ok(#(incoming, event)) -> {
              process.send(reply, Ok(event))
              await_handler(
                incoming,
                incoming_commands,
                events,
                guardian_commands,
                connection_commands,
                guardian_monitor,
                draining,
                config,
                handler_deadline,
              )
            }
          }
      }
    }
  }
}

fn terminate_handler_and_await(
  incoming: IncomingState,
  events: Subject(HandlerEvent),
  guardian_commands: Subject(HandlerCommand),
  guardian_monitor: Monitor,
  termination: HandlerTermination,
  requested_at: Int,
) -> HandlerOutcome {
  process.send(guardian_commands, TerminateHandler(termination, requested_at))
  await_handler_termination(
    incoming,
    events,
    guardian_monitor,
    termination,
    requested_at + handler_cleanup_milliseconds,
  )
}

fn await_handler_termination(
  incoming: IncomingState,
  events: Subject(HandlerEvent),
  guardian_monitor: Monitor,
  termination: HandlerTermination,
  cleanup_deadline: Int,
) -> HandlerOutcome {
  let selector =
    process.new_selector()
    |> process.select_map(events, HandlerEventMessage)
    |> process.select_specific_monitor(guardian_monitor, HandlerGuardianExited)
  case
    process.selector_receive(
      selector,
      within: handler_remaining(cleanup_deadline),
    )
  {
    Error(Nil) -> handler_termination_outcome(termination, incoming)
    Ok(HandlerEventMessage(event)) -> {
      discard_handler_event_result(event)
      case event {
        HandlerCleanupUnconfirmed(_) -> Nil
        _ -> {
          let _joined =
            await_handler_guardian_down(guardian_monitor, cleanup_deadline)
          Nil
        }
      }
      handler_termination_outcome(termination, incoming)
    }
    Ok(HandlerGuardianExited(_)) ->
      case process.receive(events, within: 0) {
        Error(Nil) -> HandlerOutcome(Error(service_error()), incoming, True)
        Ok(event) -> {
          discard_handler_event_result(event)
          handler_termination_outcome(termination, incoming)
        }
      }
    Ok(IncomingMessage(_)) | Ok(ConnectionControl(_)) ->
      handler_termination_outcome(termination, incoming)
  }
}

fn finish_handler_event(
  event: HandlerEvent,
  guardian_monitor: Monitor,
  incoming: IncomingState,
  draining: Bool,
) -> HandlerOutcome {
  case event {
    HandlerCleanupUnconfirmed(termination) ->
      handler_termination_outcome(termination, incoming)
    _ -> {
      let cleanup_deadline =
        transport.monotonic_millisecond() + handler_cleanup_milliseconds
      case await_handler_guardian_down(guardian_monitor, cleanup_deadline) {
        True -> handler_event_outcome(event, incoming, draining)
        False -> {
          discard_handler_event_result(event)
          HandlerOutcome(Error(service_error()), incoming, True)
        }
      }
    }
  }
}

fn reconcile_handler_guardian_exit(
  events: Subject(HandlerEvent),
  incoming: IncomingState,
  draining: Bool,
) -> HandlerOutcome {
  case process.receive(events, within: 0) {
    Error(Nil) -> HandlerOutcome(Error(service_error()), incoming, True)
    Ok(event) -> handler_event_outcome(event, incoming, draining)
  }
}

fn await_handler_guardian_down(
  guardian_monitor: Monitor,
  cleanup_deadline: Int,
) -> Bool {
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(guardian_monitor, fn(_) { Nil })
  process.selector_receive(
    selector,
    within: handler_remaining(cleanup_deadline),
  )
  == Ok(Nil)
}

fn handler_event_outcome(
  event: HandlerEvent,
  incoming: IncomingState,
  draining: Bool,
) -> HandlerOutcome {
  case event {
    HandlerResult(DispatchReply(outcome)) ->
      HandlerOutcome(outcome, incoming, draining)
    HandlerFailed -> HandlerOutcome(Error(service_error()), incoming, True)
    HandlerTerminated(termination) | HandlerCleanupUnconfirmed(termination) ->
      handler_termination_outcome(termination, incoming)
  }
}

fn handler_termination_outcome(
  termination: HandlerTermination,
  incoming: IncomingState,
) -> HandlerOutcome {
  case termination {
    HandlerTimedOut ->
      HandlerOutcome(
        Error(error.new(error.Timeout(error.Operation))),
        incoming,
        True,
      )
    HandlerStopped -> HandlerAborted
  }
}

fn discard_handler_event_result(event: HandlerEvent) -> Nil {
  case event {
    HandlerResult(reply) -> discard_dispatch_reply(reply)
    _ -> Nil
  }
}

fn discard_dispatch_reply(reply: DispatchReply) -> Nil {
  case reply {
    DispatchReply(Ok(response)) -> body.cancel(response.body)
    DispatchReply(Error(_)) -> Nil
  }
}

fn handler_remaining(deadline: Int) -> Int {
  int.max(0, deadline - transport.monotonic_millisecond())
}

fn receive_http1_handler_message(
  selector: process.Selector(HandlerMessage),
  handler_deadline: Int,
  relative_timeout_milliseconds: Int,
) -> Result(HandlerMessage, Nil) {
  let _relative_timeout_milliseconds = relative_timeout_milliseconds
  process.selector_receive(
    selector,
    within: handler_remaining(handler_deadline),
  )
}

/// Exercise the exact absolute receive primitive with synchronized traffic.
/// This internal seam exposes only a finite count and no request data.
@internal
pub fn handler_deadline_traffic_control(
  traffic: Subject(Subject(Nil)),
  ready: Subject(Nil),
  within_milliseconds within_milliseconds: Int,
  relative_timeout_milliseconds relative_timeout_milliseconds: Int,
) -> Int {
  case
    within_milliseconds > 0
    && within_milliseconds <= 10_000
    && relative_timeout_milliseconds > 0
    && relative_timeout_milliseconds <= 10_000
  {
    False -> 0
    True -> {
      let handler_deadline =
        transport.monotonic_millisecond() + within_milliseconds
      process.send(ready, Nil)
      handler_deadline_traffic_loop(
        traffic,
        handler_deadline,
        relative_timeout_milliseconds,
        0,
      )
    }
  }
}

fn handler_deadline_traffic_loop(
  traffic: Subject(Subject(Nil)),
  handler_deadline: Int,
  relative_timeout_milliseconds: Int,
  received: Int,
) -> Int {
  let selector =
    process.new_selector()
    |> process.select_map(traffic, fn(reply) {
      process.send(reply, Nil)
      IncomingMessage(CancelIncoming)
    })
  case
    receive_http1_handler_message(
      selector,
      handler_deadline,
      relative_timeout_milliseconds,
    )
  {
    Error(Nil) -> received
    Ok(_) ->
      handler_deadline_traffic_loop(
        traffic,
        handler_deadline,
        relative_timeout_milliseconds,
        received + 1,
      )
  }
}

fn fulfill_incoming(
  incoming: IncomingState,
  maximum: Int,
  config: Config,
  handler_deadline: Int,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  case handler_remaining(handler_deadline) > 0 {
    False -> Error(error.new(error.Timeout(error.Operation)))
    True -> {
      use incoming <- result.try(send_continue_if_needed(incoming))
      case incoming.pending {
        <<>> ->
          fulfill_without_pending(incoming, maximum, config, handler_deadline)
        pending -> emit_incoming(incoming, pending, maximum)
      }
    }
  }
}

fn send_continue_if_needed(
  incoming: IncomingState,
) -> Result(IncomingState, error.Error) {
  case incoming.expect_continue && !incoming.continue_sent {
    False -> Ok(incoming)
    True -> {
      use _ <- result.try(
        transport.send(incoming.socket, <<"HTTP/1.1 100 Continue\r\n\r\n":utf8>>)
        |> result.map_error(map_transport_error),
      )
      Ok(IncomingState(..incoming, continue_sent: True))
    }
  }
}

fn fulfill_without_pending(
  incoming: IncomingState,
  maximum: Int,
  config: Config,
  handler_deadline: Int,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  case incoming.terminal, incoming.decoder {
    Some(IncomingTerminal(trailers, _)), _ ->
      Ok(#(incoming, IncomingEnd(trailers)))
    None, None -> Error(protocol_error())
    None, Some(decoder) ->
      case incoming.input {
        <<>> -> {
          let remaining = handler_remaining(handler_deadline)
          case remaining > 0 {
            False -> Error(error.new(error.Timeout(error.Operation)))
            True ->
              case
                transport.read(
                  incoming.socket,
                  smallest(maximum, config.maximum_stream_buffer_bytes),
                  smallest(config.idle_timeout_milliseconds, remaining),
                )
              {
                Error(failure) -> Error(map_transport_error(failure))
                Ok(transport.ReadEnd(socket)) ->
                  case http1_body.finish(decoder) {
                    Error(failure) -> Error(map_body_error(failure))
                    Ok(outcome) ->
                      handle_body_outcome(
                        IncomingState(..incoming, socket:, input: <<>>),
                        outcome,
                        maximum,
                        config,
                        handler_deadline,
                      )
                  }
                Ok(transport.ReadData(bytes, socket)) ->
                  handle_body_feed(
                    IncomingState(..incoming, socket:, input: <<>>),
                    decoder,
                    bytes,
                    maximum,
                    config,
                    handler_deadline,
                  )
              }
          }
        }
        input ->
          handle_body_feed(
            IncomingState(..incoming, input: <<>>),
            decoder,
            input,
            maximum,
            config,
            handler_deadline,
          )
      }
  }
}

fn handle_body_feed(
  incoming: IncomingState,
  decoder: http1_body.Decoder,
  bytes: BitArray,
  maximum: Int,
  config: Config,
  handler_deadline: Int,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  use outcome <- result.try(
    http1_body.feed(decoder, bytes)
    |> result.map_error(map_body_error),
  )
  handle_body_outcome(incoming, outcome, maximum, config, handler_deadline)
}

fn handle_body_outcome(
  incoming: IncomingState,
  outcome: http1_body.Outcome,
  maximum: Int,
  config: Config,
  handler_deadline: Int,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  case outcome {
    http1_body.BodyNeedMore(decoder) ->
      fulfill_without_pending(
        IncomingState(..incoming, decoder: Some(decoder)),
        maximum,
        config,
        handler_deadline,
      )
    http1_body.BodyData(bytes, decoder) ->
      emit_incoming(
        IncomingState(..incoming, decoder: Some(decoder)),
        bytes,
        maximum,
      )
    http1_body.BodyComplete(bytes, trailers, remaining) -> {
      use trailers <- result.try(headers_to_strings(trailers))
      let incoming =
        IncomingState(
          ..incoming,
          decoder: None,
          terminal: Some(IncomingTerminal(trailers, remaining)),
        )
      case bytes {
        <<>> -> Ok(#(incoming, IncomingEnd(trailers)))
        _ -> emit_incoming(incoming, bytes, maximum)
      }
    }
  }
}

fn emit_incoming(
  incoming: IncomingState,
  bytes: BitArray,
  maximum: Int,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  use #(chunk, pending) <- result.try(take_at_most(bytes, maximum))
  let next_sequence = incoming.sequence + 1
  Ok(#(
    IncomingState(..incoming, pending:, sequence: next_sequence),
    IncomingData(chunk, next_sequence),
  ))
}

fn incoming_wire_complete(incoming: IncomingState) -> Bool {
  incoming.pending == <<>>
  && case incoming.terminal {
    Some(_) -> True
    None -> False
  }
}

fn incoming_remaining(
  incoming: IncomingState,
) -> Result(BitArray, error.Error) {
  case incoming.pending, incoming.terminal {
    <<>>, Some(IncomingTerminal(_, remaining)) -> Ok(remaining)
    _, _ -> Error(protocol_error())
  }
}

fn make_request(
  head: http1.RequestHead,
  incoming: body.Body,
  scheme: gleam_http.Scheme,
) -> Result(Request(body.Body), error.Error) {
  use method_text <- result.try(bytes_to_string(head.method))
  use method <- result.try(
    gleam_http.parse_method(method_text)
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use target <- result.try(bytes_to_string(head.target))
  use parts <- result.try(parse_target(method, target, scheme))
  let TargetParts(path, query, target_authority) = parts
  use headers <- result.try(headers_to_strings(head.headers))
  // RFC 9112 section 3.2.2: an absolute-form target carries the authority the request is for, and the Host field is ignored in its favour.
  // Where there is no such authority the Host field is the only one there is, and section 3.2 requires it.
  use authority <- result.try(case target_authority {
    Some(authority) -> Ok(authority)
    None ->
      find_header(headers, "host")
      |> result.map_error(fn(_) { protocol_error() })
  })
  use #(host, port) <- result.try(parse_authority(authority))
  Ok(request.Request(
    method:,
    headers:,
    body: incoming,
    scheme:,
    host:,
    port:,
    path:,
    query:,
  ))
}

fn make_request_or_reject(
  socket: transport.Socket,
  head: http1.RequestHead,
  incoming: body.Body,
  scheme: gleam_http.Scheme,
  config: Config,
) -> Result(Request(body.Body), error.Error) {
  case make_request(head, incoming, scheme) {
    Ok(request) -> Ok(request)
    Error(failure) -> {
      // Head parsing cannot validate method-specific request-target rules.
      // Send a deterministic client error before the connection actor closes.
      let _sent = send_simple_error(socket, 400, "Bad Request", config)
      Error(failure)
    }
  }
}

/// What a request needs from its target.
///
/// The authority is present only for the absolute form, which RFC 9112 section 3.2.2 says is the one a server uses in place of the Host field.
/// Carrying it here rather than reading the Host field twice is what makes the two impossible to disagree about which resource was asked for.
type TargetParts {
  TargetParts(path: String, query: Option(String), authority: Option(String))
}

fn parse_target(
  method: gleam_http.Method,
  target: String,
  scheme: gleam_http.Scheme,
) -> Result(TargetParts, error.Error) {
  case method, target {
    gleam_http.Connect, target -> {
      use _ <- result.try(parse_connect_authority(target))
      Ok(TargetParts(target, None, None))
    }
    gleam_http.Options, "*" -> Ok(TargetParts("*", None, None))
    _, target ->
      case string.starts_with(target, "/") {
        True -> Ok(origin_form(target, None))
        False -> parse_absolute_form(target, scheme)
      }
  }
}

fn origin_form(target: String, authority: Option(String)) -> TargetParts {
  case string.split_once(target, on: "?") {
    Ok(#(path, query)) -> TargetParts(path, Some(query), authority)
    Error(Nil) -> TargetParts(target, None, authority)
  }
}

/// Read an absolute-form request target.
///
/// The scheme has to be the one this listener serves.
/// A target naming the other one is a request for a resource this connection cannot be answering, and answering it anyway would let the scheme a client asked for and the scheme its bytes travelled under differ.
fn parse_absolute_form(
  target: String,
  scheme: gleam_http.Scheme,
) -> Result(TargetParts, error.Error) {
  use #(target_scheme, rest) <- result.try(
    string.split_once(target, on: "://")
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use <- require(
    string.lowercase(target_scheme) == gleam_http.scheme_to_string(scheme),
    protocol_error(),
  )
  let #(authority, path) = split_authority(rest)
  use <- require(authority != "", protocol_error())
  use _ <- result.try(parse_authority(authority))
  Ok(origin_form(path, Some(authority)))
}

/// Split an absolute form's authority from the path and query after it.
///
/// A query may follow the authority with no path between them, in which case the path is the root the origin form would have spelled explicitly.
fn split_authority(rest: String) -> #(String, String) {
  case string.split_once(rest, on: "/") {
    Ok(#(authority, tail)) -> #(authority, "/" <> tail)
    Error(Nil) ->
      case string.split_once(rest, on: "?") {
        Ok(#(authority, query)) -> #(authority, "/?" <> query)
        Error(Nil) -> #(rest, "/")
      }
  }
}

fn parse_connect_authority(target: String) -> Result(Nil, error.Error) {
  case uri.parse("http://" <> target) {
    Ok(Uri(
      scheme: Some("http"),
      userinfo: None,
      host: Some(host),
      port: Some(port),
      path: "",
      query: None,
      fragment: None,
    ))
      if host != "" && port > 0 && port <= 65_535
    -> Ok(Nil)
    _ -> Error(protocol_error())
  }
}

fn parse_authority(
  authority: String,
) -> Result(#(String, Option(Int)), error.Error) {
  case uri.parse("http://" <> authority) {
    Ok(Uri(
      scheme: Some("http"),
      userinfo: None,
      host: Some(host),
      port:,
      path: "",
      query: None,
      fragment: None,
    ))
      if host != ""
    -> Ok(#(host, port))
    _ -> Error(protocol_error())
  }
}

fn expectation(headers: List(http1.Header)) -> Expectation {
  expectation_loop(headers, NoExpectation)
}

fn expectation_loop(
  headers: List(http1.Header),
  found: Expectation,
) -> Expectation {
  case headers {
    [] -> found
    [header, ..rest] ->
      case http1.header_name_equals(header, <<"expect":utf8>>) {
        False -> expectation_loop(rest, found)
        True -> {
          let http1.Header(_, value) = header
          case bytes_to_string(value), found {
            Ok(value), NoExpectation ->
              case string.lowercase(value) == "100-continue" {
                True -> expectation_loop(rest, ContinueExpected)
                False -> UnsupportedExpectation
              }
            _, _ -> UnsupportedExpectation
          }
        }
      }
  }
}

fn request_requests_close(headers: List(http1.Header)) -> Bool {
  header_contains_token(headers, "connection", "close")
}

fn response_requests_close(headers: List(#(String, String))) -> Bool {
  string_headers_contain_token(headers, "connection", "close")
}

fn header_contains_token(
  headers: List(http1.Header),
  expected_name: String,
  expected_token: String,
) -> Bool {
  case headers {
    [] -> False
    [header, ..rest] -> {
      let http1.Header(_, value) = header
      case
        http1.header_name_equals(header, bit_array.from_string(expected_name)),
        bytes_to_string(value)
      {
        True, Ok(value) -> token_list_contains(value, expected_token)
        _, _ -> header_contains_token(rest, expected_name, expected_token)
      }
    }
  }
}

fn string_headers_contain_token(
  headers: List(#(String, String)),
  expected_name: String,
  expected_token: String,
) -> Bool {
  case headers {
    [] -> False
    [#(name, value), ..rest] ->
      case string.lowercase(name) == expected_name {
        True -> token_list_contains(value, expected_token)
        False ->
          string_headers_contain_token(rest, expected_name, expected_token)
      }
  }
}

fn token_list_contains(value: String, expected: String) -> Bool {
  value
  |> string.split(",")
  |> list.any(fn(token) { token |> string.trim |> string.lowercase == expected })
}

fn write_response(
  socket: transport.Socket,
  input: BitArray,
  method: gleam_http.Method,
  response: Response(body.Body),
  close: Bool,
  commands: Subject(ConnectionCommand),
  request_context: context.Context,
  config: Config,
) -> Result(ResponseStream, error.Error) {
  let stream = ResponseStream(socket, input, False, False)
  let outcome =
    write_response_body(
      stream,
      method,
      response,
      close,
      commands,
      request_context,
      config,
    )
  body.transfer_finished(response.body, result.map(outcome, fn(_) { Nil }))
  case outcome {
    Error(failure) -> {
      body.transfer_finished(response.body, Error(failure))
      body.cancel(response.body)
    }
    Ok(_) -> Nil
  }
  outcome
}

fn write_response_body(
  stream: ResponseStream,
  method: gleam_http.Method,
  response: Response(body.Body),
  close: Bool,
  commands: Subject(ConnectionCommand),
  request_context: context.Context,
  config: Config,
) -> Result(ResponseStream, error.Error) {
  use framing <- result.try(response_framing(method, response))
  use headers <- result.try(response_headers(
    response.status,
    response.headers,
    close,
  ))
  use head <- result.try(
    encode.response(
      response.status,
      bit_array.from_string(reason_phrase(response.status)),
      headers,
      framing,
      head_limits(config),
    )
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use _ <- result.try(
    transport.send(stream.socket, head)
    |> result.map_error(map_transport_error),
  )
  case framing {
    http1.NoBody -> {
      body.transfer_finished(response.body, Ok(Nil))
      body.cancel(response.body)
      Ok(stream)
    }
    http1.ContentLength(_) | http1.Chunked -> {
      let deadline =
        transport.monotonic_millisecond()
        + context.remaining_milliseconds(request_context)
      use source <- result.try(
        upload.start(
          source: response.body,
          maximum_chunk: config.maximum_stream_buffer_bytes,
          deadline: deadline,
          expiry: error.Operation,
          total_deadline: deadline,
          resources: None,
          lifecycle_owner: None,
          abandon: fn(_) {
            let _closed = transport.close(stream.socket)
            Nil
          },
          released: fn(_) { Nil },
        ),
      )
      let outcome =
        write_stream_body(stream, source, framing, commands, deadline, config)
      let transferred = result.map(outcome, fn(_) { Nil })
      let disposed = upload.finish_source(source, transferred)
      let released = upload.release(source, transferred)
      case outcome, disposed, released {
        Error(failure), _, _ -> Error(failure)
        _, Error(failure), _ | _, _, Error(failure) -> Error(failure)
        Ok(stream), Ok(Nil), Ok(Nil) -> Ok(stream)
      }
    }
    http1.CloseDelimited | http1.Tunnel -> Error(protocol_error())
  }
}

fn response_framing(
  method: gleam_http.Method,
  response: Response(body.Body),
) -> Result(http1.Framing, error.Error) {
  use <- require(
    response.status >= 100 && response.status <= 999,
    protocol_error(),
  )
  case method, response.status {
    gleam_http.Head, _ -> Ok(http1.NoBody)
    _, status if status >= 100 && status < 200 -> Ok(http1.NoBody)
    _, 204 | _, 304 -> Ok(http1.NoBody)
    gleam_http.Connect, status if status >= 200 && status < 300 ->
      Ok(http1.NoBody)
    _, _ ->
      case
        body.may_have_trailers(response.body),
        body.known_length(response.body)
      {
        True, _ -> Ok(http1.Chunked)
        False, Some(length) -> Ok(http1.ContentLength(length))
        False, None -> Ok(http1.Chunked)
      }
  }
}

fn response_headers(
  status: Int,
  headers: List(#(String, String)),
  close: Bool,
) -> Result(List(http1.Header), error.Error) {
  let headers = date.with_date(status: status, headers: headers)
  use converted <- result.try(convert_response_headers(headers, close, []))
  case close {
    True ->
      Ok(
        list.append(converted, [
          http1.Header(<<"Connection":utf8>>, <<"close":utf8>>),
        ]),
      )
    False -> Ok(converted)
  }
}

fn convert_response_headers(
  headers: List(#(String, String)),
  close: Bool,
  reversed: List(http1.Header),
) -> Result(List(http1.Header), error.Error) {
  case headers {
    [] -> Ok(list.reverse(reversed))
    [#(name, value), ..rest] -> {
      let lower = string.lowercase(name)
      case
        lower == "content-length"
        || lower == "transfer-encoding"
        || { close && lower == "connection" }
      {
        True -> convert_response_headers(rest, close, reversed)
        False ->
          convert_response_headers(rest, close, [
            http1.Header(
              bit_array.from_string(name),
              bit_array.from_string(value),
            ),
            ..reversed
          ])
      }
    }
  }
}

fn write_stream_body(
  stream: ResponseStream,
  source: upload.Upload,
  framing: http1.Framing,
  commands: Subject(ConnectionCommand),
  deadline: Int,
  config: Config,
) -> Result(ResponseStream, error.Error) {
  upload.request_next(source)
  use #(event, stream) <- result.try(await_response_source(
    stream,
    source,
    commands,
    deadline,
    config,
  ))
  case event {
    upload.Chunk(bytes) -> {
      use encoded <- result.try(case framing {
        http1.Chunked ->
          encode.chunk(bytes) |> result.map_error(fn(_) { protocol_error() })
        _ -> Ok(bytes)
      })
      use _ <- result.try(
        transport.send(stream.socket, encoded)
        |> result.map_error(map_transport_error),
      )
      write_stream_body(stream, source, framing, commands, deadline, config)
    }
    upload.End(trailers) -> {
      use _ <- result.try(case framing {
        http1.Chunked -> {
          let fields =
            list.map(trailers, fn(header) {
              http1.Header(
                bit_array.from_string(header.0),
                bit_array.from_string(header.1),
              )
            })
          use final <- result.try(
            encode.final_chunk(fields, head_limits(config))
            |> result.map_error(fn(_) { protocol_error() }),
          )
          transport.send(stream.socket, final)
          |> result.map_error(map_transport_error)
        }
        _ -> Ok(Nil)
      })
      Ok(stream)
    }
    upload.Failed(failure) -> Error(failure)
    upload.SourceDisposed -> Error(service_error())
  }
}

fn await_response_source(
  stream: ResponseStream,
  source: upload.Upload,
  commands: Subject(ConnectionCommand),
  deadline: Int,
  config: Config,
) -> Result(#(upload.Event, ResponseStream), error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  use <- require(remaining > 0, error.new(error.Timeout(error.Operation)))
  let selector =
    process.new_selector()
    |> process.select_map(upload.events(source), ResponseSource)
    |> process.select_map(commands, ResponseControl)
  let received = case stream.read_ended {
    True ->
      process.selector_receive(selector, within: remaining)
      |> result.map(fn(event) { transport.ReadMessage(event, stream.socket) })
      |> result.map_error(fn(_) { error.new(error.Timeout(error.Operation)) })
    False ->
      transport.read_or_select(
        stream.socket,
        int.max(
          1,
          config.maximum_stream_buffer_bytes - bit_array.byte_size(stream.input),
        ),
        remaining,
        selector,
      )
      |> result.map_error(map_transport_error)
  }
  use received <- result.try(received)
  case received {
    transport.ReadMessage(ResponseSource(event), socket) ->
      Ok(#(event, ResponseStream(..stream, socket:)))
    transport.ReadMessage(ResponseControl(StopConnection), _) ->
      Error(error.new(error.Cancelled))
    transport.ReadMessage(ResponseControl(DrainConnection), socket) ->
      await_response_source(
        ResponseStream(..stream, socket:, draining: True),
        source,
        commands,
        deadline,
        config,
      )
    transport.ReadSocket(transport.ReadEnd(socket)) -> {
      use <- require(
        !transport.read_end_is_terminal(socket),
        error.new(error.Cancelled),
      )
      await_response_source(
        ResponseStream(..stream, socket:, read_ended: True),
        source,
        commands,
        deadline,
        config,
      )
    }
    transport.ReadSocket(transport.ReadData(bytes, socket)) -> {
      use <- require(
        bit_array.byte_size(stream.input) + bit_array.byte_size(bytes)
          <= config.maximum_stream_buffer_bytes,
        resource_error(),
      )
      await_response_source(
        ResponseStream(..stream, socket:, input: <<
          stream.input:bits,
          bytes:bits,
        >>),
        source,
        commands,
        deadline,
        config,
      )
    }
  }
}

fn send_simple_error(
  socket: transport.Socket,
  status: Int,
  reason: String,
  config: Config,
) -> Result(Nil, error.Error) {
  use bytes <- result.try(
    encode.response(
      status,
      bit_array.from_string(reason),
      [http1.Header(<<"Connection":utf8>>, <<"close":utf8>>)],
      http1.ContentLength(0),
      head_limits(config),
    )
    |> result.map_error(fn(_) { protocol_error() }),
  )
  transport.send(socket, bytes) |> result.map_error(map_transport_error)
}

fn handler_error_status(failure: error.Error) -> #(Int, String) {
  case error.kind(failure) {
    error.Protocol(error.Http1) | error.Body(_) -> #(400, "Bad Request")
    error.Timeout(_) | error.Cancelled -> #(408, "Request Timeout")
    error.Resource(_) -> #(503, "Service Unavailable")
    _ -> #(500, "Internal Server Error")
  }
}

fn reason_phrase(status: Int) -> String {
  case status {
    100 -> "Continue"
    101 -> "Switching Protocols"
    200 -> "OK"
    201 -> "Created"
    202 -> "Accepted"
    204 -> "No Content"
    206 -> "Partial Content"
    301 -> "Moved Permanently"
    302 -> "Found"
    303 -> "See Other"
    304 -> "Not Modified"
    307 -> "Temporary Redirect"
    308 -> "Permanent Redirect"
    400 -> "Bad Request"
    401 -> "Unauthorized"
    403 -> "Forbidden"
    404 -> "Not Found"
    405 -> "Method Not Allowed"
    408 -> "Request Timeout"
    413 -> "Content Too Large"
    414 -> "URI Too Long"
    417 -> "Expectation Failed"
    421 -> "Misdirected Request"
    429 -> "Too Many Requests"
    500 -> "Internal Server Error"
    501 -> "Not Implemented"
    502 -> "Bad Gateway"
    503 -> "Service Unavailable"
    504 -> "Gateway Timeout"
    _ -> ""
  }
}

fn head_limits(config: Config) -> http1.Limits {
  http1.Limits(
    maximum_head_bytes: config.maximum_head_bytes,
    maximum_header_count: config.maximum_header_count,
    maximum_line_bytes: config.maximum_line_bytes,
  )
}

fn body_limits(config: Config) -> http1_body.Limits {
  http1_body.Limits(
    maximum_body_bytes: config.maximum_body_bytes,
    maximum_buffered_bytes: config.maximum_stream_buffer_bytes,
    maximum_trailer_bytes: config.maximum_trailer_bytes,
    maximum_trailer_count: config.maximum_trailer_count,
    maximum_line_bytes: config.maximum_line_bytes,
  )
}

fn headers_to_strings(
  headers: List(http1.Header),
) -> Result(List(#(String, String)), error.Error) {
  list.try_map(headers, fn(header) {
    let http1.Header(name, value) = header
    use name <- result.try(bytes_to_string(name))
    use value <- result.try(bytes_to_string(value))
    Ok(#(string.lowercase(name), value))
  })
}

fn find_header(
  headers: List(#(String, String)),
  expected: String,
) -> Result(String, Nil) {
  case headers {
    [] -> Error(Nil)
    [#(name, value), ..rest] ->
      case name == expected {
        True -> Ok(value)
        False -> find_header(rest, expected)
      }
  }
}

fn bytes_to_string(bytes: BitArray) -> Result(String, error.Error) {
  bit_array.to_string(bytes)
  |> result.map_error(fn(_) { protocol_error() })
}

fn context_endpoint(
  endpoint: #(BitArray, Int),
) -> Result(context.Endpoint, error.Error) {
  use host <- result.try(address_string(endpoint.0))
  Ok(context.Endpoint(host, endpoint.1))
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

fn take_at_most(
  bytes: BitArray,
  maximum: Int,
) -> Result(#(BitArray, BitArray), error.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum {
    True -> Ok(#(bytes, <<>>))
    False -> {
      use chunk <- result.try(
        bit_array.slice(bytes, at: 0, take: maximum)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      use remaining <- result.try(
        bit_array.slice(bytes, at: maximum, take: size - maximum)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      Ok(#(chunk, remaining))
    }
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

fn map_body_error(failure: http1_body.Error) -> error.Error {
  case failure {
    http1_body.BodyTooLarge(maximum) ->
      error.new(error.Body(error.TooLarge(maximum)))
    http1_body.InvalidLimit -> policy_error()
    _ -> protocol_error()
  }
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http1))
}

fn resource_error() -> error.Error {
  error.new(error.Resource(error.Memory))
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

fn handler_succeeded(outcome: HandlerOutcome) -> Bool {
  case outcome {
    HandlerOutcome(Ok(_), _, _) -> True
    HandlerOutcome(Error(_), _, _) | HandlerAborted -> False
  }
}

fn valid_timeout(milliseconds: Int) -> Bool {
  milliseconds > 0 && milliseconds <= 2_147_483_647
}

fn smallest(first: Int, second: Int) -> Int {
  case first < second {
    True -> first
    False -> second
  }
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
