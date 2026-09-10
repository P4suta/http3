//// Protocol-neutral, supervised HTTP request execution.
////
//// Protocol adapters construct a typed `http/context.Context` and submit a
//// standard `gleam_http` request through `handle`. One finite unlinked worker
//// runs each admitted handler. Handler panics and exits are monitored and
//// collapse to the shared redacted service error.

import gleam/bit_array
import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/http1/server as http1_server
import http/internal/http2/server as http2_server
import http/internal/http3/server as http3_server
import http/middleware
import http/resource

const maximum_milliseconds = 3_600_000

const cancellation_ack_milliseconds = 1000

const startup_milliseconds = 1000

type Lifecycle

type Token

/// The stable application handler contract.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// Server lifecycle state.
pub type State {
  Running
  Draining
  Stopped
}

/// Fixed-size, payload-free HTTP/1.1 listener phase diagnostics.
///
/// The snapshot contains no endpoint, request target, header, body, TLS
/// material, process identifier, socket, or backend failure term. A finite
/// multi-writer retry protects cross-field consistency; `consistent` is false
/// when that retry budget expires and the remaining values are best effort.
pub type Http1ListenerSnapshot {
  Http1ListenerSnapshot(
    consistent: Bool,
    state: State,
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

/// Fixed-size, payload-free HTTP/2 listener and graceful-drain diagnostics.
///
/// Connection handoff, drain-command receipt, and GOAWAY write are separate
/// phases so a scheduler stall, actor failure, and wire-observation timeout do
/// not collapse into one symptom. Counters and timings retain no endpoint,
/// request data, TLS material, process identifier, socket, or backend reason.
pub type Http2ListenerSnapshot {
  Http2ListenerSnapshot(
    consistent: Bool,
    state: State,
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

/// Finite protocol-neutral server configuration.
pub opaque type Config {
  Config(
    resource_limits: resource.Limits,
    worker_memory_bytes: Int,
    operation_timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    middlewares: List(middleware.Middleware),
    reporter: Option(diagnostics.Reporter),
  )
}

/// One owned server executor. Processes, monitors, subjects, and resource
/// handles are private.
pub opaque type Server {
  Server(
    pid: Pid,
    commands: Subject(Command),
    lifecycle: Lifecycle,
    controller: resource.Controller,
    config: Config,
  )
}

/// Finite HTTP/1.1 network-adapter configuration.
///
/// Cleartext is disabled until `allow_http1_cleartext` is called. TLS
/// listeners always require an in-memory certificate, private key, and
/// service identity.
pub opaque type Http1Config {
  Http1Config(config: http1_server.Config, allow_cleartext: Bool)
}

/// Finite HTTP/2 TLS listener and multiplexed connection policy.
pub opaque type Http2Config {
  Http2Config(
    config: http2_server.Config,
    allow_cleartext_prior_knowledge: Bool,
  )
}

/// Finite authenticated HTTP/3 listener policy backed only by the public
/// `http3` package API.
pub opaque type Http3Config {
  Http3Config(config: http3_server.Config)
}

/// One owned protocol listener without a public transport handle.
pub opaque type Listener {
  Http1Listener(listener: http1_server.Listener)
  Http2Listener(listener: http2_server.Listener)
  Http3Listener(listener: http3_server.Listener)
}

type Job {
  Job(
    token: Token,
    pid: Pid,
    monitor: Monitor,
    reply: Subject(Result(Response(body.Body), error.Error)),
    request_body: body.Body,
    diagnostic_request_id: diagnostics.RequestId,
    protocol: context.Protocol,
    started_milliseconds: Int,
    lease: resource.Lease,
  )
}

type Runtime {
  Runtime(
    commands: Subject(Command),
    lifecycle: Lifecycle,
    controller: resource.Controller,
    config: Config,
    handler: Handler,
    jobs: List(Job),
    drain_waiters: List(Subject(Result(Nil, error.Error))),
  )
}

type Command {
  Dispatch(
    token: Token,
    request: Request(body.Body),
    context: context.Context,
    lease: resource.Lease,
    reply: Subject(Result(Response(body.Body), error.Error)),
  )
  WorkerCompleted(
    token: Token,
    outcome: Result(Result(Response(body.Body), error.Error), Nil),
  )
  Cancel(token: Token, failure: error.Error)
  CancelAll(failure: error.Error)
  Reload(handler: Handler, reply: Subject(Result(Nil, error.Error)))
  BeginDrain(reply: Subject(Result(Nil, error.Error)))
  Stop(reply: Subject(Result(Nil, error.Error)))
}

type LoopMessage {
  ServerCommand(Command)
  WorkerDown(process.Down)
}

type AwaitMessage(value) {
  Reply(value)
  ExecutorDown
  ContextCancelled
}

@external(erlang, "http_server_ffi", "new_server_lifecycle")
fn new_lifecycle() -> Lifecycle

@external(erlang, "http_server_ffi", "server_lifecycle_state")
fn lifecycle_state(lifecycle: Lifecycle) -> Int

@external(erlang, "http_server_ffi", "mark_server_draining")
fn mark_draining(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "mark_server_stopped")
fn mark_stopped(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "new_token")
fn new_token() -> Token

@external(erlang, "http_server_ffi", "run_guarded")
fn run_guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_server_ffi", "spawn_monitor")
fn spawn_monitor(run: fn() -> Nil) -> #(Pid, Monitor)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

/// Construct secure finite defaults.
pub fn defaults() -> Config {
  Config(
    resource_limits: resource.default_limits(),
    worker_memory_bytes: 65_536,
    operation_timeout_milliseconds: 30_000,
    drain_timeout_milliseconds: 30_000,
    middlewares: [],
    reporter: None,
  )
}

/// Construct finite HTTP/1.1 defaults with cleartext disabled.
pub fn http1_defaults() -> Http1Config {
  Http1Config(config: http1_server.defaults(), allow_cleartext: False)
}

/// Construct finite HTTP/2 TLS defaults with push disabled.
pub fn http2_defaults() -> Http2Config {
  Http2Config(
    config: http2_server.defaults(),
    allow_cleartext_prior_knowledge: False,
  )
}

/// Construct authenticated HTTP/3 defaults with 0-RTT disabled.
pub fn http3_defaults(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  service_identity service_identity: String,
) -> Result(Http3Config, error.Error) {
  http3_server.defaults(certificate_pem, private_key_pem, service_identity)
  |> result.map(Http3Config)
}

/// Replace every HTTP/3 transport and handler-adapter deadline.
pub fn with_http3_timeout(
  config: Http3Config,
  milliseconds: Int,
) -> Result(Http3Config, error.Error) {
  http3_server.with_timeout(config.config, milliseconds)
  |> result.map(Http3Config)
}

/// Replace HTTP/3 request, response, and one-pull byte ceilings.
pub fn with_http3_body_limits(
  config: Http3Config,
  request_bytes request_bytes: Int,
  response_bytes response_bytes: Int,
  pull_bytes pull_bytes: Int,
) -> Result(Http3Config, error.Error) {
  http3_server.with_body_limits(
    config.config,
    request_bytes,
    response_bytes,
    pull_bytes,
  )
  |> result.map(Http3Config)
}

/// Explicitly permit cleartext HTTP/2 prior knowledge (h2c).
/// This does not enable HTTP/1.1 Upgrade and cannot weaken TLS verification.
pub fn allow_http2_cleartext_prior_knowledge(
  config: Http2Config,
) -> Http2Config {
  Http2Config(..config, allow_cleartext_prior_knowledge: True)
}

/// Explicitly advertise and accept HTTP/2 Extended CONNECT.
pub fn enable_http2_extended_connect(config: Http2Config) -> Http2Config {
  Http2Config(
    ..config,
    config: http2_server.enable_extended_connect(config.config),
  )
}

/// Replace every finite HTTP/2 listener, worker, and drain deadline.
pub fn with_http2_timeouts(
  config: Http2Config,
  idle_milliseconds idle_milliseconds: Int,
  operation_milliseconds operation_milliseconds: Int,
  tls_milliseconds tls_milliseconds: Int,
  drain_milliseconds drain_milliseconds: Int,
  send_milliseconds send_milliseconds: Int,
) -> Result(Http2Config, error.Error) {
  use adapter <- result.try(http2_server.with_timeouts(
    config.config,
    idle_milliseconds,
    operation_milliseconds,
    tls_milliseconds,
    drain_milliseconds,
    send_milliseconds,
  ))
  Ok(Http2Config(..config, config: adapter))
}

/// Replace HTTP/2 listener connection and per-connection stream ceilings.
pub fn with_http2_connection_limits(
  config: Http2Config,
  maximum_connections maximum_connections: Int,
  maximum_active_streams maximum_active_streams: Int,
) -> Result(Http2Config, error.Error) {
  use adapter <- result.try(http2_server.with_connection_limits(
    config.config,
    maximum_connections,
    maximum_active_streams,
  ))
  Ok(Http2Config(..config, config: adapter))
}

/// Replace HTTP/2 compressed block, decoded header-list, and HPACK ceilings.
pub fn with_http2_header_limits(
  config: Http2Config,
  maximum_header_block_bytes maximum_header_block_bytes: Int,
  maximum_header_list_bytes maximum_header_list_bytes: Int,
  maximum_header_table_bytes maximum_header_table_bytes: Int,
) -> Result(Http2Config, error.Error) {
  use adapter <- result.try(http2_server.with_header_limits(
    config.config,
    maximum_header_block_bytes,
    maximum_header_list_bytes,
    maximum_header_table_bytes,
  ))
  Ok(Http2Config(..config, config: adapter))
}

/// Replace HTTP/2 aggregate body and one-pull stream-buffer ceilings.
pub fn with_http2_body_limits(
  config: Http2Config,
  maximum_body_bytes maximum_body_bytes: Int,
  maximum_stream_buffer_bytes maximum_stream_buffer_bytes: Int,
) -> Result(Http2Config, error.Error) {
  use adapter <- result.try(http2_server.with_body_limits(
    config.config,
    maximum_body_bytes,
    maximum_stream_buffer_bytes,
  ))
  Ok(Http2Config(..config, config: adapter))
}

/// Explicitly permit a cleartext HTTP/1.1 listener.
pub fn allow_http1_cleartext(config: Http1Config) -> Http1Config {
  Http1Config(..config, allow_cleartext: True)
}

/// Replace the finite idle deadline used for request heads and bodies.
pub fn with_http1_idle_timeout(
  config: Http1Config,
  milliseconds: Int,
) -> Result(Http1Config, error.Error) {
  use adapter <- result.try(http1_server.with_idle_timeout(
    config.config,
    milliseconds,
  ))
  Ok(Http1Config(..config, config: adapter))
}

/// Replace every finite HTTP/1.1 listener and connection deadline.
pub fn with_http1_timeouts(
  config: Http1Config,
  idle_milliseconds idle_milliseconds: Int,
  operation_milliseconds operation_milliseconds: Int,
  tls_milliseconds tls_milliseconds: Int,
  drain_milliseconds drain_milliseconds: Int,
  send_milliseconds send_milliseconds: Int,
) -> Result(Http1Config, error.Error) {
  use adapter <- result.try(http1_server.with_timeouts(
    config.config,
    idle_milliseconds,
    operation_milliseconds,
    tls_milliseconds,
    drain_milliseconds,
    send_milliseconds,
  ))
  Ok(Http1Config(..config, config: adapter))
}

/// Replace the finite connection and per-connection request ceilings.
pub fn with_http1_connection_limits(
  config: Http1Config,
  maximum_connections maximum_connections: Int,
  maximum_requests_per_connection maximum_requests_per_connection: Int,
) -> Result(Http1Config, error.Error) {
  use adapter <- result.try(http1_server.with_connection_limits(
    config.config,
    maximum_connections,
    maximum_requests_per_connection,
  ))
  Ok(Http1Config(..config, config: adapter))
}

/// Replace HTTP/1.1 head, body, and per-read memory ceilings.
pub fn with_http1_limits(
  config: Http1Config,
  maximum_head_bytes maximum_head_bytes: Int,
  maximum_header_count maximum_header_count: Int,
  maximum_line_bytes maximum_line_bytes: Int,
  maximum_body_bytes maximum_body_bytes: Int,
  maximum_stream_buffer_bytes maximum_stream_buffer_bytes: Int,
) -> Result(Http1Config, error.Error) {
  use adapter <- result.try(http1_server.with_limits(
    config.config,
    maximum_head_bytes,
    maximum_header_count,
    maximum_line_bytes,
    maximum_body_bytes,
    maximum_stream_buffer_bytes,
  ))
  Ok(Http1Config(..config, config: adapter))
}

/// Start an explicitly enabled cleartext HTTP/1.1 listener.
pub fn listen_http1(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http1Config,
) -> Result(Listener, error.Error) {
  case config.allow_cleartext, state(server) {
    True, Running ->
      http1_server.listen(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        config.config,
        http1_server.Cleartext,
      )
      |> result.map(Http1Listener)
    _, _ -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Start an authenticated HTTP/1.1 TLS listener. TLS 1.2/1.3 negotiation is
/// finite, and ALPN is restricted to `http/1.1`.
pub fn listen_http1_tls(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http1Config,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  service_identity service_identity: String,
) -> Result(Listener, error.Error) {
  case
    state(server),
    bit_array.byte_size(certificate_pem),
    bit_array.byte_size(private_key_pem),
    service_identity
  {
    Running, certificate_size, key_size, identity
      if certificate_size > 0 && key_size > 0 && identity != ""
    ->
      http1_server.listen(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        config.config,
        http1_server.Tls(certificate_pem:, private_key_pem:, service_identity:),
      )
      |> result.map(Http1Listener)
    _, _, _, _ -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Start a cleartext HTTP/2 prior-knowledge listener after explicit opt-in.
/// HTTP/1.1 Upgrade is deliberately not accepted on this endpoint.
pub fn listen_http2_cleartext(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http2Config,
) -> Result(Listener, error.Error) {
  case config.allow_cleartext_prior_knowledge, state(server) {
    True, Running ->
      http2_server.listen_cleartext(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        config.config,
      )
      |> result.map(Http2Listener)
    _, _ -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Start an authenticated multiplexed HTTP/2 listener. TLS 1.2/1.3
/// negotiation is finite and ALPN is restricted to `h2`.
pub fn listen_http2_tls(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http2Config,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
  service_identity service_identity: String,
) -> Result(Listener, error.Error) {
  case state(server) {
    Running ->
      http2_server.listen_tls(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        config.config,
        certificate_pem,
        private_key_pem,
        service_identity,
      )
      |> result.map(Http2Listener)
    _ -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Start an authenticated HTTP/3 listener through the public HTTP/3 API.
/// QUIC sockets, TLS state, Retry, tokens, and connection actors stay owned
/// by the `http3` and `quic_core` packages.
pub fn listen_http3(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http3Config,
) -> Result(Listener, error.Error) {
  case state(server) {
    Running ->
      http3_server.listen(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        config.config,
      )
      |> result.map(Http3Listener)
    _ -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Return the concrete bound endpoint without exposing a socket handle.
pub fn listener_endpoint(listener: Listener) -> context.Endpoint {
  case listener {
    Http1Listener(adapter) -> http1_server.endpoint(adapter)
    Http2Listener(adapter) -> http2_server.endpoint(adapter)
    Http3Listener(adapter) -> http3_server.endpoint(adapter)
  }
}

/// Inspect HTTP/1.1 readiness, connection handoff, parse, and handler phases.
///
/// Passing a listener for another protocol fails with a fixed redacted
/// protocol classification rather than exposing its private adapter.
pub fn http1_listener_snapshot(
  listener: Listener,
) -> Result(Http1ListenerSnapshot, error.Error) {
  case listener {
    Http1Listener(adapter) -> {
      let http1_server.ListenerSnapshot(
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
      ) = http1_server.snapshot(adapter)
      Ok(Http1ListenerSnapshot(
        consistent:,
        state: case state {
          0 -> Running
          1 -> Draining
          _ -> Stopped
        },
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
      ))
    }
    Http2Listener(_) | Http3Listener(_) ->
      Error(error.new(error.Protocol(error.Http1)))
  }
}

/// Inspect HTTP/2 readiness, connection handoff, and graceful-drain phases.
///
/// Passing a listener for another protocol fails with a fixed redacted
/// protocol classification rather than exposing its private adapter.
pub fn http2_listener_snapshot(
  listener: Listener,
) -> Result(Http2ListenerSnapshot, error.Error) {
  case listener {
    Http2Listener(adapter) -> {
      let http2_server.ListenerSnapshot(
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
      ) = http2_server.snapshot(adapter)
      Ok(Http2ListenerSnapshot(
        consistent:,
        state: case state {
          0 -> Running
          1 -> Draining
          _ -> Stopped
        },
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
      ))
    }
    Http1Listener(_) | Http3Listener(_) ->
      Error(error.new(error.Protocol(error.Http2)))
  }
}

/// Stop listener admission and wait for existing connection actors.
pub fn drain_listener(listener: Listener) -> Result(Nil, error.Error) {
  case listener {
    Http1Listener(adapter) -> http1_server.drain(adapter)
    Http2Listener(adapter) -> http2_server.drain(adapter)
    Http3Listener(adapter) -> http3_server.drain(adapter)
  }
}

/// Stop a listener and all remaining connection actors idempotently.
pub fn stop_listener(listener: Listener) -> Result(Nil, error.Error) {
  case listener {
    Http1Listener(adapter) -> http1_server.stop(adapter)
    Http2Listener(adapter) -> http2_server.stop(adapter)
    Http3Listener(adapter) -> http3_server.stop(adapter)
  }
}

/// Replace finite worker and aggregate memory policy.
pub fn with_resource_limits(
  config: Config,
  limits: resource.Limits,
  worker_memory_bytes worker_memory_bytes: Int,
) -> Result(Config, error.Error) {
  case
    worker_memory_bytes > 0
    && worker_memory_bytes <= resource.maximum_memory_bytes(limits)
  {
    True -> Ok(Config(..config, resource_limits: limits, worker_memory_bytes:))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Replace the finite per-request handler deadline.
pub fn with_operation_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, error.Error) {
  case valid_timeout(milliseconds) {
    True -> Ok(Config(..config, operation_timeout_milliseconds: milliseconds))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Replace the finite graceful-drain deadline.
pub fn with_drain_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, error.Error) {
  case valid_timeout(milliseconds) {
    True -> Ok(Config(..config, drain_timeout_milliseconds: milliseconds))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Install middleware in declaration order.
pub fn with_middlewares(
  config: Config,
  middlewares: List(middleware.Middleware),
) -> Config {
  Config(..config, middlewares:)
}

/// Install an optional bounded diagnostic reporter.
pub fn with_diagnostics(
  config: Config,
  reporter: diagnostics.Reporter,
) -> Config {
  Config(..config, reporter: Some(reporter))
}

/// Return configured request-worker policy.
pub fn resource_limits(config: Config) -> resource.Limits {
  config.resource_limits
}

/// Return the bytes reserved before each worker starts.
pub fn worker_memory_bytes(config: Config) -> Int {
  config.worker_memory_bytes
}

/// Return the handler deadline.
pub fn operation_timeout_milliseconds(config: Config) -> Int {
  config.operation_timeout_milliseconds
}

/// Return the graceful-drain deadline.
pub fn drain_timeout_milliseconds(config: Config) -> Int {
  config.drain_timeout_milliseconds
}

/// Start one protocol-neutral request executor.
pub fn start(config: Config, handler: Handler) -> Result(Server, error.Error) {
  let lifecycle = new_lifecycle()
  let controller = resource.start(config.resource_limits)
  let ready = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      process.send(ready, commands)
      server_loop(
        Runtime(
          commands:,
          lifecycle:,
          controller:,
          config:,
          handler: middleware.stack(config.middlewares, handler),
          jobs: [],
          drain_waiters: [],
        ),
      )
    })
  case process.receive(ready, within: startup_milliseconds) {
    Ok(commands) ->
      Ok(Server(pid:, commands:, lifecycle:, controller:, config:))
    Error(Nil) -> {
      process.kill(pid)
      resource.stop(controller)
      let _stopped = mark_stopped(lifecycle)
      Error(error.new(error.Service))
    }
  }
}

/// Execute one standard request in a finite supervised worker.
///
/// This is the common adapter boundary used by HTTP/1.1, HTTP/2, and HTTP/3.
/// It never buffers either body. Capacity is granted before the worker is
/// spawned; excess work is refused synchronously.
pub fn handle(
  server: Server,
  request: Request(body.Body),
  context: context.Context,
) -> Result(Response(body.Body), error.Error) {
  case state(server) {
    Running -> handle_running(server, request, context)
    Draining | Stopped -> {
      body.cancel(request.body)
      Error(error.new(error.Service))
    }
  }
}

/// Atomically replace the handler used by requests admitted afterwards.
/// Existing workers retain the handler snapshot they started with.
pub fn reload_handler(
  server: Server,
  handler: Handler,
) -> Result(Nil, error.Error) {
  case state(server) {
    Running ->
      control_call(
        server,
        fn(reply) { Reload(handler, reply) },
        server.config.operation_timeout_milliseconds,
      )
    Draining | Stopped -> Error(error.new(error.Service))
  }
}

/// Stop admitting work and wait for admitted workers up to the drain deadline.
pub fn drain(server: Server) -> Result(Nil, error.Error) {
  case state(server) {
    Stopped -> Error(error.new(error.Service))
    Running | Draining -> {
      let reply = process.new_subject()
      process.send(server.commands, BeginDrain(reply))
      case
        process.receive(reply, within: server.config.drain_timeout_milliseconds)
      {
        Ok(outcome) -> outcome
        Error(Nil) -> {
          let failure = error.new(error.Timeout(error.Operation))
          process.send(server.commands, CancelAll(failure))
          Error(failure)
        }
      }
    }
  }
}

/// Stop immediately. Repeated calls are harmless.
pub fn stop(server: Server) -> Result(Nil, error.Error) {
  case state(server) {
    Stopped -> Ok(Nil)
    Running | Draining ->
      control_call(
        server,
        fn(reply) { Stop(reply) },
        server.config.operation_timeout_milliseconds,
      )
  }
}

/// Inspect lifecycle state without exposing the executor process.
pub fn state(server: Server) -> State {
  case lifecycle_state(server.lifecycle) {
    0 -> Running
    1 -> Draining
    _ -> Stopped
  }
}

fn handle_running(
  server: Server,
  request: Request(body.Body),
  context: context.Context,
) -> Result(Response(body.Body), error.Error) {
  case context.is_cancelled(context) {
    True -> {
      body.cancel(request.body)
      Error(error.new(error.Cancelled))
    }
    False ->
      case
        resource.acquire(
          server.controller,
          memory_bytes: server.config.worker_memory_bytes,
        )
      {
        Error(failure) -> {
          body.cancel(request.body)
          emit_refusal(server.config.reporter, failure)
          Error(failure)
        }
        Ok(lease) -> dispatch(server, request, context, lease)
      }
  }
}

fn dispatch(
  server: Server,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
) -> Result(Response(body.Body), error.Error) {
  let token = new_token()
  let reply = process.new_subject()
  process.send(server.commands, Dispatch(token, request, context, lease, reply))
  let monitor = process.monitor(server.pid)
  let cancellation_signal = process.new_subject()
  let cancellation_subscription =
    context.subscribe_cancellation(context, cancellation_signal)
  let selector =
    process.new_selector()
    |> process.select_map(reply, Reply)
    |> process.select_specific_monitor(monitor, fn(_) { ExecutorDown })
    |> process.select_map(cancellation_signal, fn(_) { ContextCancelled })
  let outcome =
    await_handler(
      server,
      token,
      request.body,
      context,
      selector,
      server.config.operation_timeout_milliseconds,
    )
  context.unsubscribe_cancellation(cancellation_subscription)
  process.demonitor_process(monitor)
  resource.release(lease)
  outcome
}

fn await_handler(
  server: Server,
  token: Token,
  request_body: body.Body,
  context: context.Context,
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  operation_remaining: Int,
) -> Result(Response(body.Body), error.Error) {
  case context.is_cancelled(context) {
    True ->
      cancel_and_await(
        server,
        token,
        request_body,
        selector,
        error.new(error.Cancelled),
      )
    False -> {
      let context_remaining = context.remaining_milliseconds(context)
      case operation_remaining <= 0 || context_remaining <= 0 {
        True -> {
          context.cancel(context)
          cancel_and_await(
            server,
            token,
            request_body,
            selector,
            error.new(error.Timeout(error.Operation)),
          )
        }
        False -> {
          let remaining = smallest(operation_remaining, context_remaining)
          case process.selector_receive(selector, within: remaining) {
            Ok(Reply(outcome)) -> outcome
            Ok(ExecutorDown) -> {
              body.cancel(request_body)
              Error(error.new(error.Service))
            }
            Ok(ContextCancelled) ->
              cancel_and_await(
                server,
                token,
                request_body,
                selector,
                error.new(error.Cancelled),
              )
            Error(Nil) -> {
              context.cancel(context)
              cancel_and_await(
                server,
                token,
                request_body,
                selector,
                error.new(error.Timeout(error.Operation)),
              )
            }
          }
        }
      }
    }
  }
}

fn cancel_and_await(
  server: Server,
  token: Token,
  request_body: body.Body,
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
  body.cancel(request_body)
  process.send(server.commands, Cancel(token, failure))
  await_cancel_ack(
    selector,
    failure,
    monotonic_millisecond() + cancellation_ack_milliseconds,
  )
}

fn await_cancel_ack(
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  failure: error.Error,
  deadline_milliseconds: Int,
) -> Result(Response(body.Body), error.Error) {
  let remaining = deadline_milliseconds - monotonic_millisecond()
  case remaining <= 0 {
    True -> Error(failure)
    False ->
      case process.selector_receive(selector, within: remaining) {
        Ok(Reply(outcome)) -> outcome
        Ok(ContextCancelled) ->
          await_cancel_ack(selector, failure, deadline_milliseconds)
        Ok(ExecutorDown) | Error(Nil) -> Error(failure)
      }
  }
}

fn control_call(
  server: Server,
  command: fn(Subject(Result(Nil, error.Error))) -> Command,
  timeout: Int,
) -> Result(Nil, error.Error) {
  let reply = process.new_subject()
  process.send(server.commands, command(reply))
  case process.receive(reply, within: timeout) {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn server_loop(runtime: Runtime) -> Nil {
  let selector =
    process.new_selector()
    |> process.select_map(runtime.commands, ServerCommand)
    |> process.select_monitors(WorkerDown)
  case process.selector_receive_forever(selector) {
    ServerCommand(command) ->
      case handle_command(runtime, command) {
        Some(next) -> server_loop(next)
        None -> Nil
      }
    WorkerDown(down) -> server_loop(handle_worker_down(runtime, down))
  }
}

fn handle_command(runtime: Runtime, command: Command) -> Option(Runtime) {
  case command {
    Dispatch(token, request, context, lease, reply) ->
      Some(admit_dispatch(runtime, token, request, context, lease, reply))
    WorkerCompleted(token, guarded) ->
      Some(complete_worker(runtime, token, guarded))
    Cancel(token, failure) -> Some(cancel_worker(runtime, token, failure))
    CancelAll(failure) -> Some(cancel_all(runtime, failure))
    Reload(handler, reply) -> Some(reload(runtime, handler, reply))
    BeginDrain(reply) -> Some(begin_drain(runtime, reply))
    Stop(reply) -> {
      stop_runtime(runtime, reply)
      None
    }
  }
}

fn admit_dispatch(
  runtime: Runtime,
  token: Token,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
  reply: Subject(Result(Response(body.Body), error.Error)),
) -> Runtime {
  case lifecycle_state(runtime.lifecycle), context.is_cancelled(context) {
    0, False -> {
      let started = monotonic_millisecond()
      let protocol = context.protocol(context)
      let diagnostic_request_id = diagnostics.request_id()
      let handler = runtime.handler
      let commands = runtime.commands
      let #(pid, monitor) =
        spawn_monitor(fn() {
          let guarded = run_guarded(fn() { handler(request, context) })
          process.send(commands, WorkerCompleted(token, guarded))
        })
      emit(
        runtime.config.reporter,
        diagnostics.RequestStarted(diagnostic_request_id, protocol),
      )
      Runtime(..runtime, jobs: [
        Job(
          token:,
          pid:,
          monitor:,
          reply:,
          request_body: request.body,
          diagnostic_request_id:,
          protocol:,
          started_milliseconds: started,
          lease:,
        ),
        ..runtime.jobs
      ])
    }
    _, cancelled -> {
      let failure = case cancelled {
        True -> error.new(error.Cancelled)
        False -> error.new(error.Service)
      }
      body.cancel(request.body)
      resource.release(lease)
      process.send(reply, Error(failure))
      runtime
    }
  }
}

fn complete_worker(
  runtime: Runtime,
  token: Token,
  guarded: Result(Result(Response(body.Body), error.Error), Nil),
) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> runtime
    Some(job) -> {
      let outcome = case guarded {
        Ok(handler_outcome) -> handler_outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      finish_job(runtime, job, remaining, outcome)
    }
  }
}

fn handle_worker_down(runtime: Runtime, down: process.Down) -> Runtime {
  case down {
    process.PortDown(..) -> runtime
    process.ProcessDown(pid: pid, ..) -> {
      let #(job, remaining) = take_job_by_pid(runtime.jobs, pid, [])
      case job {
        None -> runtime
        Some(job) ->
          finish_job(runtime, job, remaining, Error(error.new(error.Service)))
      }
    }
  }
}

fn finish_job(
  runtime: Runtime,
  job: Job,
  remaining: List(Job),
  outcome: Result(Response(body.Body), error.Error),
) -> Runtime {
  process.demonitor_process(job.monitor)
  case outcome {
    Ok(_) -> Nil
    Error(_) -> body.cancel(job.request_body)
  }
  resource.release(job.lease)
  process.send(job.reply, outcome)
  let elapsed = largest(0, monotonic_millisecond() - job.started_milliseconds)
  case outcome {
    Ok(response) ->
      emit(
        runtime.config.reporter,
        diagnostics.RequestFinished(
          job.diagnostic_request_id,
          job.protocol,
          response.status,
          elapsed,
        ),
      )
    Error(failure) ->
      emit(
        runtime.config.reporter,
        diagnostics.RequestFailed(
          job.diagnostic_request_id,
          job.protocol,
          failure,
          elapsed,
        ),
      )
  }
  after_jobs_removed(Runtime(..runtime, jobs: remaining))
}

fn cancel_worker(
  runtime: Runtime,
  token: Token,
  failure: error.Error,
) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> runtime
    Some(job) -> {
      process.kill(job.pid)
      process.demonitor_process(job.monitor)
      body.cancel(job.request_body)
      resource.release(job.lease)
      process.send(job.reply, Error(failure))
      emit(
        runtime.config.reporter,
        diagnostics.RequestFailed(
          job.diagnostic_request_id,
          job.protocol,
          failure,
          largest(0, monotonic_millisecond() - job.started_milliseconds),
        ),
      )
      after_jobs_removed(Runtime(..runtime, jobs: remaining))
    }
  }
}

fn cancel_all(runtime: Runtime, failure: error.Error) -> Runtime {
  let runtime =
    list.fold(runtime.jobs, Runtime(..runtime, jobs: []), fn(acc, job) {
      process.kill(job.pid)
      process.demonitor_process(job.monitor)
      body.cancel(job.request_body)
      resource.release(job.lease)
      process.send(job.reply, Error(failure))
      emit(
        runtime.config.reporter,
        diagnostics.RequestFailed(
          job.diagnostic_request_id,
          job.protocol,
          failure,
          largest(0, monotonic_millisecond() - job.started_milliseconds),
        ),
      )
      acc
    })
  after_jobs_removed(runtime)
}

fn reload(
  runtime: Runtime,
  handler: Handler,
  reply: Subject(Result(Nil, error.Error)),
) -> Runtime {
  case lifecycle_state(runtime.lifecycle) {
    0 -> {
      process.send(reply, Ok(Nil))
      emit(runtime.config.reporter, diagnostics.HandlerReloaded)
      Runtime(
        ..runtime,
        handler: middleware.stack(runtime.config.middlewares, handler),
      )
    }
    _ -> {
      process.send(reply, Error(error.new(error.Service)))
      runtime
    }
  }
}

fn begin_drain(
  runtime: Runtime,
  reply: Subject(Result(Nil, error.Error)),
) -> Runtime {
  let first = mark_draining(runtime.lifecycle)
  case first {
    True -> emit(runtime.config.reporter, diagnostics.ServerDraining)
    False -> Nil
  }
  case runtime.jobs {
    [] -> {
      process.send(reply, Ok(Nil))
      runtime
    }
    _ -> Runtime(..runtime, drain_waiters: [reply, ..runtime.drain_waiters])
  }
}

fn stop_runtime(
  runtime: Runtime,
  reply: Subject(Result(Nil, error.Error)),
) -> Nil {
  let _first = mark_stopped(runtime.lifecycle)
  resource.stop(runtime.controller)
  let _cancelled = cancel_all(runtime, error.new(error.Cancelled))
  emit(runtime.config.reporter, diagnostics.ServerStopped)
  process.send(reply, Ok(Nil))
}

fn after_jobs_removed(runtime: Runtime) -> Runtime {
  case runtime.jobs {
    [] -> {
      list.each(runtime.drain_waiters, fn(waiter) {
        process.send(waiter, Ok(Nil))
      })
      Runtime(..runtime, drain_waiters: [])
    }
    _ -> runtime
  }
}

fn take_job_by_token(
  jobs: List(Job),
  token: Token,
  reversed: List(Job),
) -> #(Option(Job), List(Job)) {
  case jobs {
    [] -> #(None, list.reverse(reversed))
    [job, ..rest] ->
      case job.token == token {
        True -> #(Some(job), list.append(list.reverse(reversed), rest))
        False -> take_job_by_token(rest, token, [job, ..reversed])
      }
  }
}

fn take_job_by_pid(
  jobs: List(Job),
  pid: Pid,
  reversed: List(Job),
) -> #(Option(Job), List(Job)) {
  case jobs {
    [] -> #(None, list.reverse(reversed))
    [job, ..rest] ->
      case job.pid == pid {
        True -> #(Some(job), list.append(list.reverse(reversed), rest))
        False -> take_job_by_pid(rest, pid, [job, ..reversed])
      }
  }
}

fn emit(
  reporter: Option(diagnostics.Reporter),
  event: diagnostics.Event,
) -> Nil {
  case reporter {
    None -> Nil
    Some(reporter) -> {
      let _accepted = diagnostics.emit(reporter, event)
      Nil
    }
  }
}

fn emit_refusal(
  reporter: Option(diagnostics.Reporter),
  failure: error.Error,
) -> Nil {
  case error.kind(failure) {
    error.Resource(resource) ->
      emit(reporter, diagnostics.RequestRefused(resource))
    _ -> Nil
  }
}

fn valid_timeout(milliseconds: Int) -> Bool {
  milliseconds > 0 && milliseconds <= maximum_milliseconds
}

fn smallest(first: Int, second: Int) -> Int {
  case first < second {
    True -> first
    False -> second
  }
}

fn largest(first: Int, second: Int) -> Int {
  case first > second {
    True -> first
    False -> second
  }
}
