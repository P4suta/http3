//// Protocol-neutral, supervised HTTP request execution.
////
//// Protocol adapters construct a typed `http/context.Context` and submit a standard `gleam_http` request through `handle`.
//// A bounded guardian and reaper supervise each admitted handler.
//// Handler panics and exits are monitored and collapse to the shared redacted service error.

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
import http/internal/process_role
import http/middleware
import http/resource

const maximum_milliseconds = 3_600_000

const cancellation_ack_milliseconds = 1000

const startup_milliseconds = 1000

const handler_join_milliseconds = 1000

type Lifecycle

type Token

type ReaperDisposition {
  ReleaseLease
  QuarantineLease
}

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
/// The snapshot contains no endpoint, request target, header, body, TLS material, process identifier, socket, or backend failure term.
/// A finite multi-writer retry protects cross-field consistency; `consistent` is false when that retry budget expires and the remaining values are best effort.
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
/// Connection handoff, drain-command receipt, and GOAWAY write are separate phases so a scheduler stall, actor failure, and wire-observation timeout do not collapse into one symptom.
/// Counters and timings retain no endpoint,
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
    worker_adoption_probe: Option(fn() -> Nil),
    worker_spawn_failure_probe: Option(fn() -> Nil),
    startup_failure_probe: Option(fn(resource.Controller) -> Nil),
  )
}

/// One owned server executor.
/// Processes, monitors, subjects, and resource handles are private.
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
/// Cleartext is disabled until `allow_http1_cleartext` is called.
/// TLS listeners always require an in-memory certificate, private key, and service identity.
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

/// Finite authenticated HTTP/3 listener policy backed only by the public `http3` package API.
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
    diagnostic_request_id: diagnostics.RequestId,
    protocol: context.Protocol,
    started_milliseconds: Int,
    response_control: Option(Subject(ResponseControl)),
    worker_control: Subject(ResponseControl),
    adopted: Bool,
    cancellation_failure: Option(error.Error),
    cleanup_outcome: Option(Result(Nil, error.Error)),
  )
}

type Runtime {
  Runtime(
    owner: Pid,
    stopping: Bool,
    commands: Subject(Command),
    lifecycle: Lifecycle,
    controller: resource.Controller,
    config: Config,
    handler: Handler,
    jobs: List(Job),
    drain_waiters: List(Subject(Result(Nil, error.Error))),
    stop_waiters: List(Subject(Result(Nil, error.Error))),
  )
}

type Command {
  Dispatch(
    token: Token,
    trace: RequestTrace,
    request: Request(body.Body),
    context: context.Context,
    lease: resource.Lease,
    reply: Subject(Result(Response(body.Body), error.Error)),
    deadline: Int,
  )
  WorkerCompleted(
    token: Token,
    outcome: Result(Result(Response(body.Body), error.Error), Nil),
    response_control: Option(Subject(ResponseControl)),
  )
  WorkerAdopted(token: Token)
  WorkerAbandoned(token: Token)
  WorkerReleased(token: Token, outcome: Result(Nil, error.Error))
  Cancel(token: Token, failure: error.Error)
  CancelAll(failure: error.Error)
  Reload(handler: Handler, reply: Subject(Result(Nil, error.Error)))
  BeginDrain(reply: Subject(Result(Nil, error.Error)))
  Stop(reply: Subject(Result(Nil, error.Error)))
}

type ResponseControl {
  ResponseTransferred(Result(Nil, error.Error))
  ResponseReleased(Result(Nil, error.Error))
  AbortResponse(error.Error)
}

type ResponseMessage {
  ResponseCommand(ResponseControl)
  ResponseContextCancelled
  ResponseExecutorDown
}

type RequestTrace {
  RequestTrace(
    reporter: Option(diagnostics.Reporter),
    request_id: diagnostics.RequestId,
    protocol: context.Protocol,
    started: Int,
  )
}

type WorkerTask {
  WorkerTask(
    token: Token,
    commands: Subject(Command),
    request: Request(body.Body),
    context: context.Context,
    handler: Handler,
    trace: RequestTrace,
    adoption_probe: Option(fn() -> Nil),
    requester: Pid,
    deadline: Int,
  )
}

type HandlerMessage {
  HandlerReturned(Result(Result(Response(body.Body), error.Error), Nil))
  HandlerDown
  HandlerAbort(error.Error)
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

@external(erlang, "http_server_ffi", "adopt_token")
fn adopt_token(token: Token) -> Bool

@external(erlang, "http_server_ffi", "abandon_token")
fn abandon_token(token: Token) -> Bool

@external(erlang, "http_server_ffi", "worker_subject")
fn worker_subject(token: Token, owner: Pid) -> Subject(ResponseControl)

@external(erlang, "http_server_ffi", "worker_reports")
fn worker_reports(token: Token, owner: Pid) -> Subject(Command)

@external(erlang, "http_server_ffi", "reap_worker")
fn reap_worker(
  token: Token,
  commands: Subject(Command),
  run: fn() -> ReaperDisposition,
  release: fn() -> Nil,
) -> Nil

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
    worker_adoption_probe: None,
    worker_spawn_failure_probe: None,
    startup_failure_probe: None,
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

/// Change only the native HTTP/3 drain deadline for deterministic lifecycle verification while preserving the opaque public configuration boundary.
@internal
pub fn with_http3_drain_timeout(
  config: Http3Config,
  milliseconds: Int,
) -> Result(Http3Config, Nil) {
  http3_server.with_http3_drain_timeout(config.config, milliseconds)
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

/// Start an authenticated HTTP/1.1 TLS listener.
/// TLS 1.2/1.3 negotiation is finite, and ALPN is restricted to `http/1.1`.
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

/// Start an authenticated multiplexed HTTP/2 listener.
/// TLS 1.2/1.3 negotiation is finite and ALPN is restricted to `h2`.
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
/// QUIC sockets, TLS state, Retry, tokens, and connection actors stay owned by the `http3` and `quic_core` packages.
pub fn listen_http3(
  server: Server,
  address: BitArray,
  port: Int,
  config: Http3Config,
) -> Result(Listener, error.Error) {
  case state(server) {
    Running -> {
      use adapter_config <- result.try(http3_server.with_response_worker_limit(
        config.config,
        resource.maximum_workers(server.config.resource_limits),
      ))
      http3_server.listen(
        fn(request, request_context) {
          handle(server, request, request_context)
        },
        address,
        port,
        adapter_config,
      )
      |> result.map(Http3Listener)
    }
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
/// Passing a listener for another protocol fails with a fixed redacted protocol classification rather than exposing its private adapter.
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
/// Passing a listener for another protocol fails with a fixed redacted protocol classification rather than exposing its private adapter.
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

/// Pause the acquire-to-guardian ownership transition at a deterministic package-internal synchronization point.
/// Production configurations leave this unset; it exists so cancellation and stop races have repeatable tests.
@internal
pub fn with_worker_adoption_probe(
  config: Config,
  probe: fn() -> Nil,
) -> Config {
  Config(..config, worker_adoption_probe: Some(probe))
}

/// Install a deterministic test-only failure point at the worker spawn boundary.
/// The probe runs inside the executor's guarded allocation section;
/// production configurations leave it unset.
@internal
pub fn with_worker_spawn_failure_probe(
  config: Config,
  probe: fn() -> Nil,
) -> Config {
  Config(..config, worker_spawn_failure_probe: Some(probe))
}

/// Install a test-only failure point after the finite resource controller is allocated and before the executor is spawned.
/// The controller is supplied so the test can prove that startup rollback stopped it without exposing a VM handle or process identifier.
@internal
pub fn with_startup_failure_probe(
  config: Config,
  probe: fn(resource.Controller) -> Nil,
) -> Config {
  Config(..config, startup_failure_probe: Some(probe))
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

/// Start one protocol-neutral request executor owned by the calling process.
/// Owner termination disposes every admitted handler and response source.
pub fn start(config: Config, handler: Handler) -> Result(Server, error.Error) {
  case run_guarded(fn() { new_lifecycle() }) {
    Error(Nil) -> Error(startup_resource_failure())
    Ok(lifecycle) ->
      case resource.start_checked(config.resource_limits) {
        Error(failure) -> {
          let _stopped = mark_stopped(lifecycle)
          Error(failure)
        }
        Ok(controller) ->
          start_with_resources(config, handler, lifecycle, controller)
      }
  }
}

fn start_with_resources(
  config: Config,
  handler: Handler,
  lifecycle: Lifecycle,
  controller: resource.Controller,
) -> Result(Server, error.Error) {
  case run_guarded(fn() { middleware.stack(config.middlewares, handler) }) {
    Error(Nil) -> {
      stop_failed_start(lifecycle, controller)
      Error(error.new(error.Service))
    }
    Ok(stacked_handler) ->
      start_executor(config, stacked_handler, lifecycle, controller)
  }
}

fn start_executor(
  config: Config,
  handler: Handler,
  lifecycle: Lifecycle,
  controller: resource.Controller,
) -> Result(Server, error.Error) {
  let deadline = monotonic_millisecond() + startup_milliseconds
  let started =
    run_guarded(fn() {
      case config.startup_failure_probe {
        Some(probe) -> probe(controller)
        None -> Nil
      }
      let ready = process.new_subject()
      let owner = process.self()
      let #(pid, monitor) =
        spawn_monitor(fn() {
          case
            run_guarded(fn() {
              process_role.set(process_role.ServerExecutor)
              let _owner_monitor = process.monitor(owner)
              process.new_subject()
            })
          {
            Error(Nil) -> process.send(ready, Error(Nil))
            Ok(commands) -> {
              process.send(ready, Ok(commands))
              server_loop(
                Runtime(
                  owner:,
                  stopping: False,
                  commands:,
                  lifecycle:,
                  controller:,
                  config:,
                  handler:,
                  jobs: [],
                  drain_waiters: [],
                  stop_waiters: [],
                ),
              )
            }
          }
        })
      #(pid, monitor, ready)
    })
  case started {
    Error(Nil) -> {
      stop_failed_start(lifecycle, controller)
      Error(startup_resource_failure())
    }
    Ok(#(pid, monitor, ready)) ->
      case
        process.receive(
          ready,
          within: largest(0, deadline - monotonic_millisecond()),
        )
      {
        Ok(Ok(commands)) -> {
          process.demonitor_process(monitor)
          Ok(Server(pid:, commands:, lifecycle:, controller:, config:))
        }
        Ok(Error(Nil)) -> {
          let _joined = stop_startup_executor(pid, monitor, deadline)
          stop_failed_start(lifecycle, controller)
          Error(startup_resource_failure())
        }
        Error(Nil) -> {
          let _joined = stop_startup_executor(pid, monitor, deadline)
          stop_failed_start(lifecycle, controller)
          Error(error.new(error.Service))
        }
      }
  }
}

fn stop_startup_executor(pid: Pid, monitor: Monitor, deadline: Int) -> Bool {
  process.kill(pid)
  let joined =
    run_guarded(fn() {
      process.new_selector()
      |> process.select_specific_monitor(monitor, fn(_) { Nil })
      |> process.selector_receive(within: largest(
        0,
        deadline - monotonic_millisecond(),
      ))
      |> result.is_ok
    })
  process.demonitor_process(monitor)
  case joined {
    Ok(confirmed) -> confirmed
    Error(Nil) -> False
  }
}

fn stop_failed_start(
  lifecycle: Lifecycle,
  controller: resource.Controller,
) -> Nil {
  resource.stop(controller)
  let _stopped = mark_stopped(lifecycle)
  Nil
}

fn startup_resource_failure() -> error.Error {
  error.new(error.Resource(error.Memory))
}

/// Execute one standard request in a finite supervised worker.
///
/// This is the common adapter boundary used by HTTP/1.1, HTTP/2, and HTTP/3.
/// It never buffers either body.
/// Capacity is granted before the worker is spawned; excess work is refused synchronously.
/// The reservation remains live through response transfer and source cleanup.
/// Direct callers must dispose the returned body, including empty bodies,
/// using `body.cancel` when finished; protocol listeners do this automatically.
pub fn handle(
  server: Server,
  request: Request(body.Body),
  context: context.Context,
) -> Result(Response(body.Body), error.Error) {
  let trace = begin_request_trace(server.config.reporter, context)
  case state(server) {
    Running -> handle_running(server, request, context, trace)
    Draining | Stopped ->
      fail_before_admission(request.body, trace, error.new(error.Service))
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

/// Stop immediately.
/// Repeated calls are harmless.
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
  trace: RequestTrace,
) -> Result(Response(body.Body), error.Error) {
  case context.is_cancelled(context) {
    True ->
      fail_before_admission(request.body, trace, error.new(error.Cancelled))
    False -> {
      case
        resource.acquire(
          server.controller,
          memory_bytes: server.config.worker_memory_bytes,
        )
      {
        Error(failure) -> refuse_before_admission(request.body, trace, failure)
        Ok(lease) -> dispatch(server, trace, request, context, lease)
      }
    }
  }
}

fn begin_request_trace(
  reporter: Option(diagnostics.Reporter),
  request_context: context.Context,
) -> RequestTrace {
  let trace =
    RequestTrace(
      reporter:,
      request_id: diagnostics.request_id(),
      protocol: context.protocol(request_context),
      started: monotonic_millisecond(),
    )
  emit(reporter, diagnostics.RequestStarted(trace.request_id, trace.protocol))
  trace
}

fn fail_before_admission(
  incoming: body.Body,
  trace: RequestTrace,
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
  emit_trace_failure(trace, failure)
  let cleanup = body.cancel_within(incoming, cancellation_ack_milliseconds)
  emit_trace_release(trace, cleanup)
  Error(failure)
}

fn refuse_before_admission(
  incoming: body.Body,
  trace: RequestTrace,
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
  case error.kind(failure) {
    error.Resource(_) ->
      emit_refusal(trace.reporter, trace.request_id, trace.protocol, failure)
    _ -> emit_trace_failure(trace, failure)
  }
  let cleanup = body.cancel_within(incoming, cancellation_ack_milliseconds)
  emit_trace_release(trace, cleanup)
  Error(failure)
}

fn fail_after_acquire(
  incoming: body.Body,
  lease: resource.Lease,
  trace: RequestTrace,
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
  emit_trace_failure(trace, failure)
  let cleanup = body.cancel_within(incoming, cancellation_ack_milliseconds)
  resource.release(lease)
  emit_trace_release(trace, cleanup)
  Error(failure)
}

fn emit_trace_failure(trace: RequestTrace, failure: error.Error) -> Nil {
  emit(
    trace.reporter,
    diagnostics.RequestFailed(
      trace.request_id,
      trace.protocol,
      failure,
      largest(0, monotonic_millisecond() - trace.started),
    ),
  )
}

fn emit_trace_release(
  trace: RequestTrace,
  cleanup: Result(Nil, error.Error),
) -> Nil {
  emit(
    trace.reporter,
    diagnostics.RequestReleased(
      trace.request_id,
      trace.protocol,
      cleanup,
      largest(0, monotonic_millisecond() - trace.started),
    ),
  )
}

fn dispatch(
  server: Server,
  trace: RequestTrace,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
) -> Result(Response(body.Body), error.Error) {
  let deadline =
    monotonic_millisecond()
    + smallest(
      server.config.operation_timeout_milliseconds,
      context.remaining_milliseconds(context),
    )
  case
    run_guarded(fn() {
      #(new_token(), process.new_subject(), process.new_subject())
    })
  {
    Error(Nil) ->
      fail_after_acquire(request.body, lease, trace, startup_resource_failure())
    Ok(#(token, reply, cancellation_signal)) ->
      dispatch_with_primitives(
        server,
        trace,
        request,
        context,
        lease,
        token,
        reply,
        cancellation_signal,
        deadline,
      )
  }
}

fn dispatch_with_primitives(
  server: Server,
  trace: RequestTrace,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
  token: Token,
  reply: Subject(Result(Response(body.Body), error.Error)),
  cancellation_signal: Subject(Nil),
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  case run_guarded(fn() { process.monitor(server.pid) }) {
    Error(Nil) -> fail_unpublished_dispatch(request.body, lease, trace, token)
    Ok(monitor) ->
      case
        run_guarded(fn() {
          process.new_selector()
          |> process.select_map(reply, Reply)
          |> process.select_specific_monitor(monitor, fn(_) { ExecutorDown })
          |> process.select_map(cancellation_signal, fn(_) { ContextCancelled })
        })
      {
        Error(Nil) -> {
          process.demonitor_process(monitor)
          fail_unpublished_dispatch(request.body, lease, trace, token)
        }
        Ok(selector) ->
          dispatch_with_monitor(
            server,
            trace,
            request,
            context,
            lease,
            token,
            reply,
            cancellation_signal,
            monitor,
            selector,
            deadline,
          )
      }
  }
}

fn dispatch_with_monitor(
  server: Server,
  trace: RequestTrace,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
  token: Token,
  reply: Subject(Result(Response(body.Body), error.Error)),
  cancellation_signal: Subject(Nil),
  monitor: Monitor,
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  let subscribed =
    run_guarded(fn() {
      context.subscribe_cancellation(context, cancellation_signal)
    })
  case subscribed {
    Error(Nil) -> {
      process.demonitor_process(monitor)
      fail_unpublished_dispatch(request.body, lease, trace, token)
    }
    Ok(cancellation_subscription) -> {
      process.send(
        server.commands,
        Dispatch(token, trace, request, context, lease, reply, deadline),
      )
      let outcome =
        await_handler(
          server,
          token,
          context,
          selector,
          deadline - monotonic_millisecond(),
        )
      context.unsubscribe_cancellation(cancellation_subscription)
      process.demonitor_process(monitor)
      finish_dispatch(request, lease, trace, token, outcome)
    }
  }
}

fn fail_unpublished_dispatch(
  incoming: body.Body,
  lease: resource.Lease,
  trace: RequestTrace,
  token: Token,
) -> Result(Response(body.Body), error.Error) {
  let _abandoned = abandon_token(token)
  fail_after_acquire(incoming, lease, trace, startup_resource_failure())
}

fn finish_dispatch(
  request: Request(body.Body),
  lease: resource.Lease,
  trace: RequestTrace,
  token: Token,
  outcome: Result(Response(body.Body), error.Error),
) -> Result(Response(body.Body), error.Error) {
  // This also reclaims an expired Dispatch still queued in a live executor.
  // An adopted guardian owns the lease and cannot lose it to this cleanup.
  case abandon_token(token), outcome {
    False, _ -> outcome
    True, Error(failure) ->
      fail_after_acquire(request.body, lease, trace, failure)
    True, Ok(response) -> {
      // A response cannot be published before the guardian adopts the token.
      // If a malformed backend violates that contract, dispose both bodies and retain a fixed service classification rather than report success.
      body.cancel(response.body)
      fail_after_acquire(request.body, lease, trace, error.new(error.Service))
    }
  }
}

fn await_handler(
  server: Server,
  token: Token,
  context: context.Context,
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  operation_remaining: Int,
) -> Result(Response(body.Body), error.Error) {
  case context.is_cancelled(context) {
    True ->
      cancel_and_await(server, token, selector, error.new(error.Cancelled))
    False -> {
      let context_remaining = context.remaining_milliseconds(context)
      case operation_remaining <= 0 || context_remaining <= 0 {
        True -> {
          context.cancel(context)
          cancel_and_await(
            server,
            token,
            selector,
            error.new(error.Timeout(error.Operation)),
          )
        }
        False -> {
          let remaining = smallest(operation_remaining, context_remaining)
          case process.selector_receive(selector, within: remaining) {
            Ok(Reply(outcome)) -> outcome
            Ok(ExecutorDown) -> Error(error.new(error.Service))
            Ok(ContextCancelled) ->
              cancel_and_await(
                server,
                token,
                selector,
                error.new(error.Cancelled),
              )
            Error(Nil) -> {
              context.cancel(context)
              cancel_and_await(
                server,
                token,
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
  selector: process.Selector(
    AwaitMessage(Result(Response(body.Body), error.Error)),
  ),
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
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
        Some(next) -> continue_server(next)
        None -> Nil
      }
    WorkerDown(down) -> continue_server(handle_worker_down(runtime, down))
  }
}

fn continue_server(runtime: Runtime) -> Nil {
  case lifecycle_state(runtime.lifecycle) {
    2 -> Nil
    _ -> server_loop(runtime)
  }
}

fn handle_command(runtime: Runtime, command: Command) -> Option(Runtime) {
  case command {
    Dispatch(token, trace, request, context, lease, reply, deadline) ->
      Some(admit_dispatch(
        runtime,
        token,
        trace,
        request,
        context,
        lease,
        reply,
        deadline,
      ))
    WorkerCompleted(token, guarded, response_control) ->
      Some(complete_worker(runtime, token, guarded, response_control))
    WorkerAdopted(token) -> Some(mark_worker_adopted(runtime, token))
    WorkerAbandoned(token) -> Some(remove_abandoned_worker(runtime, token))
    WorkerReleased(token, outcome) ->
      Some(record_release(runtime, token, outcome))
    Cancel(token, failure) -> Some(cancel_worker(runtime, token, failure))
    CancelAll(failure) -> Some(cancel_all(runtime, failure))
    Reload(handler, reply) -> Some(reload(runtime, handler, reply))
    BeginDrain(reply) -> Some(begin_drain(runtime, reply))
    Stop(reply) -> Some(stop_runtime(runtime, reply))
  }
}

fn admit_dispatch(
  runtime: Runtime,
  token: Token,
  trace: RequestTrace,
  request: Request(body.Body),
  context: context.Context,
  lease: resource.Lease,
  reply: Subject(Result(Response(body.Body), error.Error)),
  deadline: Int,
) -> Runtime {
  case lifecycle_state(runtime.lifecycle), context.is_cancelled(context) {
    0, False -> {
      let handler = runtime.handler
      let commands = runtime.commands
      let task =
        WorkerTask(
          token:,
          commands:,
          request:,
          context:,
          handler:,
          trace:,
          adoption_probe: runtime.config.worker_adoption_probe,
          requester: case process.subject_owner(reply) {
            Ok(owner) -> owner
            Error(Nil) -> runtime.owner
          },
          deadline:,
        )
      let spawned =
        run_guarded(fn() {
          case runtime.config.worker_spawn_failure_probe {
            Some(probe) -> probe()
            None -> Nil
          }
          spawn_monitor(fn() {
            let reports = worker_reports(token, process.self())
            reap_worker(
              token,
              commands,
              fn() { run_request_worker(task, reports) },
              fn() { resource.release(lease) },
            )
          })
        })
      case spawned {
        Ok(#(pid, monitor)) ->
          Runtime(..runtime, jobs: [
            Job(
              token:,
              pid:,
              monitor:,
              reply:,
              diagnostic_request_id: trace.request_id,
              protocol: trace.protocol,
              started_milliseconds: trace.started,
              response_control: None,
              worker_control: worker_subject(token, pid),
              adopted: False,
              cancellation_failure: None,
              cleanup_outcome: None,
            ),
            ..runtime.jobs
          ])
        Error(Nil) -> {
          let failure = error.new(error.Resource(error.RequestWorkers))
          case abandon_token(token) {
            True -> {
              let _failed =
                fail_after_acquire(request.body, lease, trace, failure)
              Nil
            }
            False -> Nil
          }
          process.send(reply, Error(failure))
          runtime
        }
      }
    }
    _, cancelled -> {
      let failure = case cancelled {
        True -> error.new(error.Cancelled)
        False -> error.new(error.Service)
      }
      case abandon_token(token) {
        True -> {
          let _failed = fail_after_acquire(request.body, lease, trace, failure)
          Nil
        }
        False -> Nil
      }
      process.send(reply, Error(failure))
      runtime
    }
  }
}

fn complete_worker(
  runtime: Runtime,
  token: Token,
  guarded: Result(Result(Response(body.Body), error.Error), Nil),
  response_control: Option(Subject(ResponseControl)),
) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> {
      case guarded {
        Ok(Ok(response)) -> body.cancel(response.body)
        _ -> Nil
      }
      runtime
    }
    Some(Job(cancellation_failure: Some(_), ..)) -> {
      case guarded {
        Ok(Ok(response)) -> body.cancel(response.body)
        _ -> Nil
      }
      runtime
    }
    Some(job) -> {
      let outcome = case guarded {
        Ok(handler_outcome) -> handler_outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      finish_job(runtime, Job(..job, response_control:), remaining, outcome)
    }
  }
}

fn handle_worker_down(runtime: Runtime, down: process.Down) -> Runtime {
  case down {
    process.PortDown(..) -> runtime
    process.ProcessDown(pid: pid, ..) -> {
      case pid == runtime.owner {
        True -> stop_owned_runtime(runtime)
        False -> {
          let #(job, remaining) = take_job_by_pid(runtime.jobs, pid, [])
          case job {
            None -> runtime
            Some(job) -> finish_release(runtime, job, remaining)
          }
        }
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
  let elapsed = largest(0, monotonic_millisecond() - job.started_milliseconds)
  case outcome {
    Ok(response) -> {
      emit(
        runtime.config.reporter,
        diagnostics.HandlerFinished(
          job.diagnostic_request_id,
          job.protocol,
          response.status,
          elapsed,
        ),
      )
      process.send(job.reply, Ok(response))
      Runtime(..runtime, jobs: [job, ..remaining])
    }
    Error(failure) -> begin_cleanup(runtime, job, remaining, failure)
  }
}

fn begin_cleanup(
  runtime: Runtime,
  job: Job,
  remaining: List(Job),
  failure: error.Error,
) -> Runtime {
  emit(
    runtime.config.reporter,
    diagnostics.RequestFailed(
      job.diagnostic_request_id,
      job.protocol,
      failure,
      largest(0, monotonic_millisecond() - job.started_milliseconds),
    ),
  )
  process.send(job.worker_control, AbortResponse(failure))
  Runtime(..runtime, jobs: [
    Job(..job, cancellation_failure: Some(failure)),
    ..remaining
  ])
}

fn defer_cleanup_until_adopted(
  runtime: Runtime,
  job: Job,
  remaining: List(Job),
  failure: error.Error,
) -> Runtime {
  process.send(job.worker_control, AbortResponse(failure))
  Runtime(..runtime, jobs: [
    Job(..job, cancellation_failure: Some(failure)),
    ..remaining
  ])
}

fn record_release(
  runtime: Runtime,
  token: Token,
  outcome: Result(Nil, error.Error),
) -> Runtime {
  Runtime(
    ..runtime,
    jobs: list.map(runtime.jobs, fn(job) {
      case job.token == token {
        True -> Job(..job, cleanup_outcome: Some(outcome))
        False -> job
      }
    }),
  )
}

fn mark_worker_adopted(runtime: Runtime, token: Token) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> runtime
    Some(Job(adopted: True, ..)) -> runtime
    Some(job) -> {
      case job.cancellation_failure {
        Some(failure) ->
          emit(
            runtime.config.reporter,
            diagnostics.RequestFailed(
              job.diagnostic_request_id,
              job.protocol,
              failure,
              largest(0, monotonic_millisecond() - job.started_milliseconds),
            ),
          )
        None -> Nil
      }
      Runtime(..runtime, jobs: [Job(..job, adopted: True), ..remaining])
    }
  }
}

fn remove_abandoned_worker(runtime: Runtime, token: Token) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> runtime
    Some(job) -> {
      // The submitting process won the token and owns input and lease cleanup.
      // The reaper has reported this before exiting, so its later DOWN must not synthesize a second release result for the same request.
      process.demonitor_process(job.monitor)
      after_jobs_removed(Runtime(..runtime, jobs: remaining))
    }
  }
}

fn finish_release(runtime: Runtime, job: Job, remaining: List(Job)) -> Runtime {
  case job.adopted {
    False ->
      // WorkerAdopted and WorkerAbandoned are forwarded before reaper DOWN.
      // Without either ownership proof the submitting process retains the token and is the only side allowed to publish cleanup.
      after_jobs_removed(Runtime(..runtime, jobs: remaining))
    True -> {
      let outcome = case job.cleanup_outcome {
        Some(outcome) -> outcome
        None -> Error(error.new(error.Service))
      }
      case job.cancellation_failure, job.response_control {
        None, None -> {
          let failure = error.new(error.Service)
          emit(
            runtime.config.reporter,
            diagnostics.RequestFailed(
              job.diagnostic_request_id,
              job.protocol,
              failure,
              largest(0, monotonic_millisecond() - job.started_milliseconds),
            ),
          )
          process.send(job.reply, Error(failure))
        }
        Some(failure), None -> process.send(job.reply, Error(failure))
        _, Some(_) -> Nil
      }
      emit_release(runtime.config.reporter, job, outcome)
      after_jobs_removed(Runtime(..runtime, jobs: remaining))
    }
  }
}

fn emit_release(
  reporter: Option(diagnostics.Reporter),
  job: Job,
  outcome: Result(Nil, error.Error),
) -> Nil {
  emit(
    reporter,
    diagnostics.RequestReleased(
      job.diagnostic_request_id,
      job.protocol,
      outcome,
      largest(0, monotonic_millisecond() - job.started_milliseconds),
    ),
  )
}

fn run_request_worker(
  task: WorkerTask,
  reports: Subject(Command),
) -> ReaperDisposition {
  case task.adoption_probe {
    Some(probe) -> {
      let _guarded_probe = run_guarded(probe)
      Nil
    }
    None -> Nil
  }
  case adopt_token(task.token) {
    False -> {
      process.send(reports, WorkerAbandoned(task.token))
      QuarantineLease
    }
    True -> {
      process.send(reports, WorkerAdopted(task.token))
      run_adopted_worker(task, reports)
    }
  }
}

fn run_adopted_worker(
  task: WorkerTask,
  reports: Subject(Command),
) -> ReaperDisposition {
  let control = worker_subject(task.token, process.self())
  let cancellation = process.new_subject()
  let subscription = context.subscribe_cancellation(task.context, cancellation)
  let #(guarded, handler_joined) =
    supervise_handler(task, control, cancellation)
  case guarded {
    Ok(Ok(response)) -> {
      let outgoing =
        observe_response(
          task.trace.reporter,
          task.trace.request_id,
          task.trace.protocol,
          response.status,
          task.trace.started,
          response.body,
          control,
        )
        |> body.observe_release(fn(outcome) {
          process.send(control, ResponseReleased(outcome))
        })
      process.send(
        reports,
        WorkerCompleted(
          task.token,
          Ok(Ok(response.set_body(response, outgoing))),
          Some(control),
        ),
      )
      let cleanup = supervise_response(task, outgoing, control, cancellation)
      context.unsubscribe_cancellation(subscription)
      process.send(reports, WorkerReleased(task.token, cleanup))
      reaper_disposition(handler_joined)
    }
    _ -> {
      // The handler is joined before source cleanup or reservation release.
      let cleanup = body.cancel_within(task.request.body, 1000)
      context.unsubscribe_cancellation(subscription)
      process.send(reports, WorkerCompleted(task.token, guarded, None))
      process.send(reports, WorkerReleased(task.token, cleanup))
      reaper_disposition(handler_joined)
    }
  }
}

fn reaper_disposition(handler_joined: Bool) -> ReaperDisposition {
  case handler_joined {
    True -> ReleaseLease
    False -> QuarantineLease
  }
}

fn supervise_handler(
  task: WorkerTask,
  control: Subject(ResponseControl),
  cancellation: Subject(Nil),
) -> #(Result(Result(Response(body.Body), error.Error), Nil), Bool) {
  case process.subject_owner(task.commands) {
    Error(Nil) -> #(Ok(Error(error.new(error.Service))), True)
    Ok(executor) -> {
      case handler_admission_failure(task, executor) {
        Some(failure) -> #(Ok(Error(failure)), True)
        None -> run_handler_child(task, control, cancellation, executor)
      }
    }
  }
}

fn handler_admission_failure(
  task: WorkerTask,
  executor: Pid,
) -> Option(error.Error) {
  case process.is_alive(executor), process.is_alive(task.requester) {
    False, _ -> Some(error.new(error.Service))
    _, False -> Some(error.new(error.Cancelled))
    True, True ->
      case monotonic_millisecond() >= task.deadline {
        True -> Some(error.new(error.Timeout(error.Operation)))
        False ->
          case context.is_cancelled(task.context) {
            True -> Some(error.new(error.Cancelled))
            False -> None
          }
      }
  }
}

fn run_handler_child(
  task: WorkerTask,
  control: Subject(ResponseControl),
  cancellation: Subject(Nil),
  executor: Pid,
) -> #(Result(Result(Response(body.Body), error.Error), Nil), Bool) {
  let executor_monitor = process.monitor(executor)
  let requester_monitor = process.monitor(task.requester)
  let reply = process.new_subject()
  let #(child, child_monitor) =
    spawn_monitor(fn() {
      process_role.set(process_role.RequestHandler)
      process.send(
        reply,
        run_guarded(fn() { task.handler(task.request, task.context) }),
      )
    })
  let selector =
    process.new_selector()
    |> process.select_map(reply, HandlerReturned)
    |> process.select_specific_monitor(child_monitor, fn(_) { HandlerDown })
    |> process.select_specific_monitor(executor_monitor, fn(_) {
      HandlerAbort(error.new(error.Service))
    })
    |> process.select_specific_monitor(requester_monitor, fn(_) {
      HandlerAbort(error.new(error.Cancelled))
    })
    |> process.select_map(cancellation, fn(_) {
      HandlerAbort(error.new(error.Cancelled))
    })
    |> process.select_map(control, fn(command) {
      case command {
        AbortResponse(failure) -> HandlerAbort(failure)
        ResponseTransferred(_) | ResponseReleased(_) ->
          HandlerAbort(error.new(error.Service))
      }
    })
  let received =
    process.selector_receive(
      selector,
      within: largest(0, task.deadline - monotonic_millisecond()),
    )
  let #(outcome, child_joined) = case received {
    Ok(HandlerReturned(outcome)) -> {
      let joined = join_handler(child_monitor)
      #(outcome, joined)
    }
    Ok(HandlerDown) -> #(Error(Nil), True)
    Ok(HandlerAbort(failure)) -> {
      let joined = stop_handler(child, child_monitor, reply)
      #(Ok(Error(failure)), joined)
    }
    Error(Nil) -> {
      let joined = stop_handler(child, child_monitor, reply)
      #(Ok(Error(error.new(error.Timeout(error.Operation)))), joined)
    }
  }
  process.demonitor_process(executor_monitor)
  process.demonitor_process(requester_monitor)
  process.demonitor_process(child_monitor)
  #(outcome, child_joined)
}

fn stop_handler(
  child: Pid,
  monitor: Monitor,
  reply: Subject(Result(Result(Response(body.Body), error.Error), Nil)),
) -> Bool {
  process.kill(child)
  let joined = join_handler(monitor)
  // A return may already be queued when cancellation wins the selector.
  case process.receive(reply, within: 0) {
    Ok(Ok(Ok(response))) -> body.cancel(response.body)
    _ -> Nil
  }
  joined
}

fn join_handler(monitor: Monitor) -> Bool {
  // A native call can defer a kill signal.
  // Do not extend request or stop work indefinitely, and do not release admission without observing DOWN.
  process.new_selector()
  |> process.select_specific_monitor(monitor, fn(_) { Nil })
  |> process.selector_receive(within: handler_join_milliseconds)
  |> result.is_ok
}

fn supervise_response(
  task: WorkerTask,
  outgoing: body.Body,
  control: Subject(ResponseControl),
  cancellation: Subject(Nil),
) -> Result(Nil, error.Error) {
  let owner = process.subject_owner(task.commands)
  case owner {
    Error(Nil) ->
      dispose_response(task.request.body, outgoing, error.new(error.Service))
    Ok(owner) -> {
      let monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(control, ResponseCommand)
        |> process.select_map(cancellation, fn(_) { ResponseContextCancelled })
        |> process.select_specific_monitor(monitor, fn(_) {
          ResponseExecutorDown
        })
      let outcome =
        process.selector_receive(
          selector,
          within: largest(0, context.remaining_milliseconds(task.context)),
        )
      process.demonitor_process(monitor)
      case outcome {
        Ok(ResponseCommand(ResponseTransferred(_))) ->
          // The adapter has recorded its final write.
          // Dispose both sources here, off the connection actor, before this guardian exits and returns its admission grant.
          // Cleanup keeps its separate outcome.
          combine_cleanup(
            body.cancel_within(outgoing, 1000),
            body.cancel_within(task.request.body, 1000),
          )
        Ok(ResponseCommand(ResponseReleased(response_cleanup))) ->
          combine_cleanup(
            response_cleanup,
            body.cancel_within(task.request.body, 1000),
          )
        Ok(ResponseCommand(AbortResponse(failure))) ->
          dispose_response(task.request.body, outgoing, failure)
        Ok(ResponseContextCancelled) ->
          dispose_response(
            task.request.body,
            outgoing,
            error.new(error.Cancelled),
          )
        Ok(ResponseExecutorDown) ->
          dispose_response(
            task.request.body,
            outgoing,
            error.new(error.Service),
          )
        Error(Nil) ->
          dispose_response(
            task.request.body,
            outgoing,
            error.new(error.Timeout(error.Operation)),
          )
      }
    }
  }
}

fn dispose_response(
  incoming: body.Body,
  outgoing: body.Body,
  failure: error.Error,
) -> Result(Nil, error.Error) {
  body.transfer_finished(outgoing, Error(failure))
  let response_cleanup = body.cancel_within(outgoing, 1000)
  let request_cleanup = body.cancel_within(incoming, 1000)
  combine_cleanup(response_cleanup, request_cleanup)
}

fn combine_cleanup(
  first: Result(Nil, error.Error),
  second: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  case first {
    Error(failure) -> Error(failure)
    Ok(Nil) -> second
  }
}

fn observe_response(
  reporter: Option(diagnostics.Reporter),
  request_id: diagnostics.RequestId,
  protocol: context.Protocol,
  status: Int,
  started: Int,
  outgoing: body.Body,
  control: Subject(ResponseControl),
) -> body.Body {
  body.observe_transfer(
    outgoing,
    fn() {
      emit(
        reporter,
        diagnostics.ResponseBodyReadFinished(
          request_id,
          protocol,
          largest(0, monotonic_millisecond() - started),
        ),
      )
    },
    fn(outcome) {
      let elapsed = largest(0, monotonic_millisecond() - started)
      let event = case outcome {
        Ok(Nil) ->
          diagnostics.RequestFinished(request_id, protocol, status, elapsed)
        Error(failure) ->
          diagnostics.RequestFailed(request_id, protocol, failure, elapsed)
      }
      emit(reporter, event)
      process.send(control, ResponseTransferred(outcome))
    },
  )
}

fn cancel_worker(
  runtime: Runtime,
  token: Token,
  failure: error.Error,
) -> Runtime {
  let #(job, remaining) = take_job_by_token(runtime.jobs, token, [])
  case job {
    None -> runtime
    Some(Job(cancellation_failure: Some(_), ..)) -> runtime
    Some(job) -> {
      case job.response_control {
        Some(control) -> {
          process.send(control, AbortResponse(failure))
          runtime
        }
        None ->
          case job.adopted {
            True -> begin_cleanup(runtime, job, remaining, failure)
            False ->
              defer_cleanup_until_adopted(runtime, job, remaining, failure)
          }
      }
    }
  }
}

fn cancel_all(runtime: Runtime, failure: error.Error) -> Runtime {
  list.fold(runtime.jobs, runtime, fn(acc, job) {
    cancel_worker(acc, job.token, failure)
  })
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
) -> Runtime {
  let runtime =
    Runtime(..runtime, stop_waiters: [reply, ..runtime.stop_waiters])
  stop_owned_runtime(runtime)
}

fn stop_owned_runtime(runtime: Runtime) -> Runtime {
  let _first = mark_draining(runtime.lifecycle)
  resource.stop(runtime.controller)
  let runtime = Runtime(..runtime, stopping: True)
  cancel_all(runtime, error.new(error.Cancelled)) |> after_jobs_removed
}

fn after_jobs_removed(runtime: Runtime) -> Runtime {
  case runtime.jobs {
    [] -> {
      list.each(runtime.drain_waiters, fn(waiter) {
        process.send(waiter, Ok(Nil))
      })
      case runtime.stopping {
        False -> Nil
        True -> {
          let _stopped = mark_stopped(runtime.lifecycle)
          emit(runtime.config.reporter, diagnostics.ServerStopped)
          list.each(runtime.stop_waiters, fn(waiter) {
            process.send(waiter, Ok(Nil))
          })
        }
      }
      Runtime(..runtime, drain_waiters: [], stop_waiters: [])
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
  request_id: diagnostics.RequestId,
  protocol: context.Protocol,
  failure: error.Error,
) -> Nil {
  case error.kind(failure) {
    error.Resource(resource) ->
      emit(reporter, diagnostics.RequestRefused(request_id, protocol, resource))
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
