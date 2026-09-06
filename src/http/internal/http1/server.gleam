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
import http/internal/http1
import http/internal/http1/body as http1_body
import http/internal/http1/encode
import http/internal/transport

const http1_alpn = <<"http/1.1":utf8>>

const startup_milliseconds = 1000

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

type HandlerMessage {
  IncomingMessage(IncomingCommand)
  HandlerCompleted(DispatchReply)
  HandlerExited(process.Down)
  ConnectionControl(ConnectionCommand)
}

type ResponseReadMessage {
  ResponseReadCompleted(Result(body.Read, error.Error))
  ResponseReaderExited(process.Down)
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

@external(erlang, "http_server_ffi", "run_guarded")
fn run_guarded(run: fn() -> value) -> Result(value, Nil)

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

/// Construct finite server defaults. Cleartext permission is enforced by the
/// public server configuration rather than represented here.
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
    process.kill(connection.pid)
    process.demonitor_process(connection.monitor)
    record_connection_exit(runtime.diagnostics)
  })
  list.each(runtime.drain_waiters, fn(waiter) { process.send(waiter, Ok(Nil)) })
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
              Ok(ConnectionEntry(pid:, monitor:, commands:))
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
      use <- require(selected == http1_alpn, protocol_error())
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
  case receive_head(socket, parser, buffered, config) {
    Error(failure) -> {
      let _sent = send_simple_error(socket, 400, "Bad Request", config)
      Error(failure)
    }
    Ok(#(socket, head, remaining)) -> {
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

fn receive_head(
  socket: transport.Socket,
  parser: http1.RequestParser,
  input: BitArray,
  config: Config,
) -> Result(#(transport.Socket, http1.RequestHead, BitArray), error.Error) {
  case http1.feed_request(parser, input) {
    Error(_) -> Error(protocol_error())
    Ok(http1.RequestReady(head, remaining)) -> {
      use <- require(
        bit_array.byte_size(remaining) <= config.maximum_stream_buffer_bytes,
        resource_error(),
      )
      Ok(#(socket, head, remaining))
    }
    Ok(http1.NeedMore(parser)) ->
      case
        transport.read(
          socket,
          config.maximum_stream_buffer_bytes,
          config.idle_timeout_milliseconds,
        )
      {
        Error(failure) -> Error(map_transport_error(failure))
        Ok(transport.ReadEnd(_)) -> Error(protocol_error())
        Ok(transport.ReadData(bytes, socket)) ->
          receive_head(socket, parser, bytes, config)
      }
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
      case
        write_response(incoming.socket, request.method, response, close, config)
      {
        Error(failure) -> Error(failure)
        Ok(socket) ->
          case close {
            True -> Ok(Nil)
            False ->
              case incoming_remaining(incoming) {
                Error(failure) -> Error(failure)
                Ok(buffered) ->
                  connection_loop(
                    socket,
                    buffered,
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
  let completed = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      record_handler_dispatch(diagnostics)
      process.send(completed, DispatchReply(handler(request, request_context)))
    })
  let monitor = process.monitor(pid)
  let outcome =
    await_handler(
      incoming,
      incoming_commands,
      completed,
      connection_commands,
      monitor,
      pid,
      request_context,
      False,
      config,
    )
  record_handler_completion(diagnostics, handler_succeeded(outcome))
  outcome
}

fn await_handler(
  incoming: IncomingState,
  incoming_commands: Subject(IncomingCommand),
  completed: Subject(DispatchReply),
  connection_commands: Subject(ConnectionCommand),
  monitor: Monitor,
  pid: Pid,
  request_context: context.Context,
  draining: Bool,
  config: Config,
) -> HandlerOutcome {
  let selector =
    process.new_selector()
    |> process.select_map(incoming_commands, IncomingMessage)
    |> process.select_map(completed, HandlerCompleted)
    |> process.select_map(connection_commands, ConnectionControl)
    |> process.select_specific_monitor(monitor, HandlerExited)
  case
    process.selector_receive(
      selector,
      within: config.operation_timeout_milliseconds,
    )
  {
    Error(Nil) -> {
      context.cancel(request_context)
      process.kill(pid)
      process.demonitor_process(monitor)
      HandlerOutcome(
        Error(error.new(error.Timeout(error.Operation))),
        incoming,
        True,
      )
    }
    Ok(ConnectionControl(StopConnection)) -> {
      context.cancel(request_context)
      process.kill(pid)
      process.demonitor_process(monitor)
      HandlerAborted
    }
    Ok(ConnectionControl(DrainConnection)) ->
      await_handler(
        incoming,
        incoming_commands,
        completed,
        connection_commands,
        monitor,
        pid,
        request_context,
        True,
        config,
      )
    Ok(HandlerCompleted(DispatchReply(outcome))) -> {
      process.demonitor_process(monitor)
      HandlerOutcome(outcome, incoming, draining)
    }
    Ok(HandlerExited(_)) ->
      HandlerOutcome(Error(service_error()), incoming, True)
    Ok(IncomingMessage(CancelIncoming)) ->
      await_handler(
        incoming,
        incoming_commands,
        completed,
        connection_commands,
        monitor,
        pid,
        request_context,
        draining,
        config,
      )
    Ok(IncomingMessage(PullIncoming(sequence, maximum, reply))) -> {
      case sequence == incoming.sequence && maximum > 0 {
        False -> {
          process.send(reply, Error(protocol_error()))
          await_handler(
            incoming,
            incoming_commands,
            completed,
            connection_commands,
            monitor,
            pid,
            request_context,
            True,
            config,
          )
        }
        True ->
          case fulfill_incoming(incoming, maximum, config) {
            Error(failure) -> {
              process.send(reply, Error(failure))
              await_handler(
                incoming,
                incoming_commands,
                completed,
                connection_commands,
                monitor,
                pid,
                request_context,
                True,
                config,
              )
            }
            Ok(#(incoming, event)) -> {
              process.send(reply, Ok(event))
              await_handler(
                incoming,
                incoming_commands,
                completed,
                connection_commands,
                monitor,
                pid,
                request_context,
                draining,
                config,
              )
            }
          }
      }
    }
  }
}

fn fulfill_incoming(
  incoming: IncomingState,
  maximum: Int,
  config: Config,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  use incoming <- result.try(send_continue_if_needed(incoming))
  case incoming.pending {
    <<>> -> fulfill_without_pending(incoming, maximum, config)
    pending -> emit_incoming(incoming, pending, maximum)
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
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  case incoming.terminal, incoming.decoder {
    Some(IncomingTerminal(trailers, _)), _ ->
      Ok(#(incoming, IncomingEnd(trailers)))
    None, None -> Error(protocol_error())
    None, Some(decoder) ->
      case incoming.input {
        <<>> ->
          case
            transport.read(
              incoming.socket,
              smallest(maximum, config.maximum_stream_buffer_bytes),
              config.idle_timeout_milliseconds,
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
                  )
              }
            Ok(transport.ReadData(bytes, socket)) ->
              handle_body_feed(
                IncomingState(..incoming, socket:, input: <<>>),
                decoder,
                bytes,
                maximum,
                config,
              )
          }
        input ->
          handle_body_feed(
            IncomingState(..incoming, input: <<>>),
            decoder,
            input,
            maximum,
            config,
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
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  use outcome <- result.try(
    http1_body.feed(decoder, bytes)
    |> result.map_error(map_body_error),
  )
  handle_body_outcome(incoming, outcome, maximum, config)
}

fn handle_body_outcome(
  incoming: IncomingState,
  outcome: http1_body.Outcome,
  maximum: Int,
  config: Config,
) -> Result(#(IncomingState, IncomingReply), error.Error) {
  case outcome {
    http1_body.BodyNeedMore(decoder) ->
      fulfill_without_pending(
        IncomingState(..incoming, decoder: Some(decoder)),
        maximum,
        config,
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
  use #(path, query) <- result.try(parse_target(method, target))
  use headers <- result.try(headers_to_strings(head.headers))
  use authority <- result.try(
    find_header(headers, "host")
    |> result.map_error(fn(_) { protocol_error() }),
  )
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

fn parse_target(
  method: gleam_http.Method,
  target: String,
) -> Result(#(String, Option(String)), error.Error) {
  case method, target {
    gleam_http.Connect, target -> {
      use _ <- result.try(parse_connect_authority(target))
      Ok(#(target, None))
    }
    gleam_http.Options, "*" -> Ok(#("*", None))
    _, target ->
      case string.starts_with(target, "/") {
        False -> Error(protocol_error())
        True ->
          case string.split_once(target, on: "?") {
            Ok(#(path, query)) -> Ok(#(path, Some(query)))
            Error(Nil) -> Ok(#(target, None))
          }
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
  method: gleam_http.Method,
  response: Response(body.Body),
  close: Bool,
  config: Config,
) -> Result(transport.Socket, error.Error) {
  use framing <- result.try(response_framing(method, response))
  use headers <- result.try(response_headers(response.headers, close))
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
    transport.send(socket, head)
    |> result.map_error(map_transport_error),
  )
  case framing {
    http1.NoBody -> {
      body.cancel(response.body)
      Ok(socket)
    }
    http1.ContentLength(_) -> write_fixed_body(socket, response.body, config)
    http1.Chunked -> write_chunked_body(socket, response.body, config)
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
      case body.known_length(response.body) {
        Some(length) -> Ok(http1.ContentLength(length))
        None -> Ok(http1.Chunked)
      }
  }
}

fn response_headers(
  headers: List(#(String, String)),
  close: Bool,
) -> Result(List(http1.Header), error.Error) {
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

fn write_fixed_body(
  socket: transport.Socket,
  outgoing: body.Body,
  config: Config,
) -> Result(transport.Socket, error.Error) {
  case read_response_body(outgoing, config) {
    Error(failure) -> cancel_body(outgoing, failure)
    Ok(body.Done(_)) -> Ok(socket)
    Ok(body.Data(bytes, next)) ->
      case transport.send(socket, bytes) {
        Error(failure) -> cancel_body(next, map_transport_error(failure))
        Ok(Nil) -> write_fixed_body(socket, next, config)
      }
  }
}

fn write_chunked_body(
  socket: transport.Socket,
  outgoing: body.Body,
  config: Config,
) -> Result(transport.Socket, error.Error) {
  case read_response_body(outgoing, config) {
    Error(failure) -> cancel_body(outgoing, failure)
    Ok(body.Data(bytes, next)) ->
      case encode.chunk(bytes) {
        Error(_) -> cancel_body(next, protocol_error())
        Ok(chunk) ->
          case transport.send(socket, chunk) {
            Error(failure) -> cancel_body(next, map_transport_error(failure))
            Ok(Nil) -> write_chunked_body(socket, next, config)
          }
      }
    Ok(body.Done(completed)) -> {
      let trailers =
        body.trailers(completed)
        |> option_headers
        |> list.map(fn(header) {
          http1.Header(
            bit_array.from_string(header.0),
            bit_array.from_string(header.1),
          )
        })
      case encode.final_chunk(trailers, head_limits(config)) {
        Error(_) -> cancel_body(completed, protocol_error())
        Ok(final) ->
          case transport.send(socket, final) {
            Error(failure) ->
              cancel_body(completed, map_transport_error(failure))
            Ok(Nil) -> Ok(socket)
          }
      }
    }
  }
}

fn read_response_body(
  outgoing: body.Body,
  config: Config,
) -> Result(body.Read, error.Error) {
  let completed = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let read = case
        run_guarded(fn() {
          body.read(outgoing, config.maximum_stream_buffer_bytes)
        })
      {
        Ok(result) -> result
        Error(Nil) -> Error(service_error())
      }
      process.send(completed, read)
    })
  let monitor = process.monitor(pid)
  let outcome =
    process.new_selector()
    |> process.select_map(completed, ResponseReadCompleted)
    |> process.select_specific_monitor(monitor, ResponseReaderExited)
    |> process.selector_receive(within: config.operation_timeout_milliseconds)
  let read = case outcome {
    Ok(ResponseReadCompleted(result)) -> result
    Ok(ResponseReaderExited(_)) ->
      // A successful reply is sent before the worker exits. Preserve it if
      // both signals reached the mailbox before the selector ran.
      case process.receive(completed, within: 0) {
        Ok(result) -> result
        Error(Nil) -> Error(service_error())
      }
    Error(Nil) -> {
      process.kill(pid)
      Error(error.new(error.Timeout(error.Operation)))
    }
  }
  process.demonitor_process(monitor)
  read
}

fn cancel_body(
  outgoing: body.Body,
  failure: error.Error,
) -> Result(value, error.Error) {
  body.cancel(outgoing)
  Error(failure)
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

fn option_headers(headers: Option(body.Headers)) -> body.Headers {
  case headers {
    Some(headers) -> headers
    None -> []
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
