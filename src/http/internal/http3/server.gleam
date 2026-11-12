//// Public-HTTP/3 adapter for the protocol-neutral server executor.
////
//// QUIC, UDP, TLS, Retry, token, and connection ownership remain entirely in the public `http3/server` implementation.
//// This module only translates standard messages, pull-based bodies, and redacted request context.

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
import gleam/uri
import http/body
import http/context
import http/error
import http/internal/date
import http/internal/http3/failure as adapter_failure
import http/internal/process_role
import http3/address as h3_address
import http3/failure as h3_failure
import http3/server as h3_server
import http3/transport as h3_transport

const default_operation_milliseconds = 30_000

const default_pull_bytes = 65_536

const maximum_response_workers = 128

const startup_milliseconds = 1000

const cleanup_milliseconds = 1000

const shutdown_milliseconds = 5000

// Immutable, finite shutdown outcome codes shared with http_server_ffi.
// Zero is pending and one is success; every other value is a redacted http.ErrorKind constructor.
// Body sizes are deliberately not retained.
const shutdown_success = 1

const shutdown_dns = 2

const shutdown_connect_failed = 3

const shutdown_tls = 4

const shutdown_timeout_dns = 5

const shutdown_timeout_connect = 6

const shutdown_timeout_tls = 7

const shutdown_timeout_operation = 8

const shutdown_timeout_idle = 9

const shutdown_timeout_total = 10

const shutdown_protocol_http1 = 11

const shutdown_protocol_http2 = 12

const shutdown_protocol_http3 = 13

const shutdown_protocol_quic = 14

const shutdown_policy_redirect = 15

const shutdown_policy_retry = 16

const shutdown_policy_security = 17

const shutdown_policy_proxy = 18

const shutdown_policy_cache = 19

const shutdown_body_invalid_limit = 20

const shutdown_body_read_failed = 21

const shutdown_body_too_large = 22

const shutdown_body_invalid_chunk = 23

const shutdown_body_length_mismatch = 24

const shutdown_body_not_replayable = 25

const shutdown_resource_connections = 26

const shutdown_resource_streams = 27

const shutdown_resource_request_workers = 28

const shutdown_resource_memory = 29

const shutdown_resource_queue = 30

const shutdown_resource_buffered_body = 31

const shutdown_resource_file_handles = 32

const shutdown_cancelled = 33

const shutdown_service = 34

type Control {
  BeginDrain(Subject(Nil))
  Stop(Subject(Result(Nil, error.Error)), Option(error.Error))
}

type ListenerMessage {
  Accepted(Result(h3_server.Request, h3_server.Error))
  ChildExited(process.Down)
  LinkedExited
  Control(Control)
}

type ResponseWorker {
  ResponseWorker(pid: Pid, monitor: Monitor, shutdown: Subject(Nil))
}

type ListenerRuntime {
  ListenerRuntime(
    listener: h3_server.Listener,
    endpoint: context.Endpoint,
    handler: Handler,
    config: Config,
    commands: Subject(Control),
    accepted: Subject(Result(h3_server.Request, h3_server.Error)),
    owner: Pid,
    owner_monitor: Monitor,
    acceptor: Option(#(Pid, Monitor)),
    workers: List(ResponseWorker),
    draining: Bool,
    lifecycle: Lifecycle,
  )
}

type Lifecycle

type WorkMessage(value) {
  WorkCompleted(Result(value, error.Error))
  WorkExited
  WorkCancelled
  PeerFailed(error.Error, Subject(Nil))
}

type WorkRun(value) {
  WorkRun(outcome: Result(value, error.Error), join: Result(Nil, error.Error))
}

type DeliveryMessage {
  DeliveryCompleted(Subject(Nil))
  DeliveryFailed(error.Error, Subject(Nil))
  DeliveryCancelled
  DeliveryObserverExited
}

type DeliveryRun {
  DeliveryRun(outcome: Result(Nil, error.Error), peer_down_observed: Bool)
}

type StopMessage {
  StopCompleted(Result(Nil, error.Error))
  StopCoordinatorExited
}

type CleanupMessage {
  CleanupCompleted(Result(Nil, error.Error))
  CleanupExited
}

type JoinObservation(worker) {
  JoinObservation(unconfirmed: List(worker), observation_complete: Bool)
}

/// The owned child phase whose termination must be confirmed before request or response state may be released.
@internal
pub type ResponseWorkPhase {
  RequestSetup
  RequestHandler
  ResponseSend
  PeerTerminal
}

/// A typed observation point for deterministic join downgrade tests.
/// The integer identifies successive quarantine observations after the initial join could not be confirmed.
@internal
pub type ResponseJoinStage {
  InitialJoin
  QuarantineJoin(Int)
}

@external(erlang, "http_server_ffi", "run_guarded")
fn run_guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_server_ffi", "spawn_link_monitor")
fn spawn_link_monitor(run: fn() -> Nil) -> #(Pid, Monitor)

@external(erlang, "http_server_ffi", "spawn_monitor")
fn spawn_monitor(run: fn() -> Nil) -> #(Pid, Monitor)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

@external(erlang, "http_server_ffi", "new_server_lifecycle")
fn new_lifecycle() -> Lifecycle

@external(erlang, "http_server_ffi", "mark_server_draining")
fn mark_draining(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "mark_server_stopped")
fn mark_stopped(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_server_ffi", "record_server_shutdown_outcome")
fn record_shutdown_outcome(lifecycle: Lifecycle, outcome: Int) -> Int

@external(erlang, "http_server_ffi", "record_server_shutdown_provisional")
fn record_shutdown_provisional(lifecycle: Lifecycle, outcome: Int) -> Int

@external(erlang, "http_server_ffi", "server_shutdown_outcome")
fn shutdown_outcome(lifecycle: Lifecycle) -> Int

@external(erlang, "http_server_ffi", "server_shutdown_provisional")
fn shutdown_provisional(lifecycle: Lifecycle) -> Int

/// The structurally shared application handler contract.
pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

/// Validated HTTP/3 listener policy without transport handles.
pub opaque type Config {
  Config(
    configuration: h3_server.Configuration,
    service_identity: String,
    operation_milliseconds: Int,
    pull_bytes: Int,
    maximum_response_workers: Int,
    listener_port: fn(h3_server.Listener) -> Result(Int, h3_server.Error),
    accept_request: fn(h3_server.Listener) ->
      Result(h3_server.Request, h3_server.Error),
    request_setup: fn(h3_server.Request, body.Body) ->
      Result(Request(body.Body), error.Error),
    request_disposed_probe: Option(fn() -> Nil),
    shutdown_join_results: Option(fn(Int, Int) -> List(Bool)),
    coordinator_startup: Option(fn() -> Nil),
    startup_join_confirmation: Option(fn() -> Bool),
    coordinator_join_confirmation: Option(fn(Int, Int) -> Bool),
    response_supervisor_startup: Option(fn() -> Nil),
    response_start_join_confirmation: Option(fn(Int, Int) -> Bool),
    response_phase_join_confirmation: Option(
      fn(ResponseWorkPhase, ResponseJoinStage, Int) -> Bool,
    ),
  )
}

/// An owned public HTTP/3 listener and its redacted local endpoint.
pub opaque type Listener {
  Listener(
    listener: h3_server.Listener,
    endpoint: context.Endpoint,
    coordinator: Pid,
    commands: Subject(Control),
    lifecycle: Lifecycle,
    coordinator_join_confirmation: Option(fn(Int, Int) -> Bool),
  )
}

/// Build secure HTTP/3 defaults.
/// Certificate and key parsing is eager.
pub fn defaults(
  certificate: BitArray,
  private_key: BitArray,
  service_identity: String,
) -> Result(Config, error.Error) {
  use _ <- result.try(require(service_identity != "", security_policy_error()))
  use configuration <- result.try(
    h3_server.new(certificate, private_key)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(
    configuration:,
    service_identity:,
    operation_milliseconds: default_operation_milliseconds,
    pull_bytes: default_pull_bytes,
    maximum_response_workers: maximum_response_workers,
    listener_port: h3_server.port,
    accept_request: h3_server.accept,
    request_setup: make_request,
    request_disposed_probe: None,
    shutdown_join_results: None,
    coordinator_startup: None,
    startup_join_confirmation: None,
    coordinator_join_confirmation: None,
    response_supervisor_startup: None,
    response_start_join_confirmation: None,
    response_phase_join_confirmation: None,
  ))
}

/// Replace the accept operation for deterministic lifecycle verification.
/// Production configurations retain the native finite accept operation.
@internal
pub fn with_accept_probe(
  config: Config,
  accept_request: fn(h3_server.Listener) ->
    Result(h3_server.Request, h3_server.Error),
) -> Config {
  Config(..config, accept_request:)
}

/// Replace bound-port discovery after native listener ownership is acquired.
/// A failed probe must still drive bounded native listener rollback.
@internal
pub fn with_listener_port_probe(
  config: Config,
  listener_port: fn(h3_server.Listener) -> Result(Int, h3_server.Error),
) -> Config {
  Config(..config, listener_port:)
}

/// Observe confirmed request-stream disposal without exposing its handle.
@internal
pub fn with_request_disposed_probe(
  config: Config,
  request_disposed_probe: fn() -> Nil,
) -> Config {
  Config(..config, request_disposed_probe: Some(request_disposed_probe))
}

/// Replace request validation after body construction for deterministic cleanup-failure verification.
@internal
pub fn with_request_setup_probe(
  config: Config,
  request_setup: fn(h3_server.Request, body.Body) ->
    Result(Request(body.Body), error.Error),
) -> Config {
  Config(..config, request_setup:)
}

/// Inject payload-free worker-join observations for deterministic shutdown failure tests.
/// Production configurations always observe process monitors.
@internal
pub fn with_shutdown_join_probe(
  config: Config,
  shutdown_join_results: fn(Int, Int) -> List(Bool),
) -> Config {
  Config(..config, shutdown_join_results: Some(shutdown_join_results))
}

/// Run a deterministic coordinator startup hook before readiness is published.
/// Tests may block or terminate this hook to exercise bounded startup rollback; production configurations do not install one.
@internal
pub fn with_coordinator_startup_probe(
  config: Config,
  coordinator_startup: fn() -> Nil,
) -> Config {
  Config(..config, coordinator_startup: Some(coordinator_startup))
}

/// Downgrade startup coordinator join confirmation for a deterministic fail-closed rollback test.
/// The real monitor is always consumed first.
@internal
pub fn with_startup_join_probe(
  config: Config,
  startup_join_confirmation: fn() -> Bool,
) -> Config {
  Config(..config, startup_join_confirmation: Some(startup_join_confirmation))
}

/// Downgrade either coordinator join phase after consuming its real monitor.
/// Phase one observes the normal exit and phase two observes the forced exit.
@internal
pub fn with_coordinator_join_probe(
  config: Config,
  coordinator_join_confirmation: fn(Int, Int) -> Bool,
) -> Config {
  Config(
    ..config,
    coordinator_join_confirmation: Some(coordinator_join_confirmation),
  )
}

/// Run a deterministic response-supervisor hook before readiness is published.
/// A blocked hook exercises startup ownership rollback.
@internal
pub fn with_response_startup_probe(
  config: Config,
  response_supervisor_startup: fn() -> Nil,
) -> Config {
  Config(
    ..config,
    response_supervisor_startup: Some(response_supervisor_startup),
  )
}

/// Downgrade response-supervisor startup join phases after consuming their real monitors.
/// Production configurations do not install this probe.
@internal
pub fn with_response_start_join_probe(
  config: Config,
  response_start_join_confirmation: fn(Int, Int) -> Bool,
) -> Config {
  Config(
    ..config,
    response_start_join_confirmation: Some(response_start_join_confirmation),
  )
}

/// Downgrade a real child-DOWN observation at one typed response phase.
/// The callback cannot upgrade an unobserved DOWN and is used only by deterministic ownership tests.
@internal
pub fn with_response_phase_join_probe(
  config: Config,
  response_phase_join_confirmation: fn(
    ResponseWorkPhase,
    ResponseJoinStage,
    Int,
  ) -> Bool,
) -> Config {
  Config(
    ..config,
    response_phase_join_confirmation: Some(response_phase_join_confirmation),
  )
}

/// Interrupt the coordinator before it can record a shutdown outcome.
/// The subsequent public stop must close the native listener yet remain failed,
/// because it cannot reconstruct the coordinator's worker observations.
@internal
pub fn interrupt_coordinator_before_shutdown(listener: Listener) -> Bool {
  let monitor = process.monitor(listener.coordinator)
  process.kill(listener.coordinator)
  join_child(monitor, cleanup_milliseconds)
}

/// Bound response supervisors using the common server's worker admission limit.
pub fn with_response_worker_limit(
  config: Config,
  maximum: Int,
) -> Result(Config, error.Error) {
  use _ <- result.try(require(
    maximum > 0 && maximum <= 2_147_483_647,
    error.new(error.Resource(error.RequestWorkers)),
  ))
  Ok(Config(..config, maximum_response_workers: maximum))
}

/// Replace all HTTP/3 deadlines with one finite upper bound.
pub fn with_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, error.Error) {
  use configuration <- result.try(
    h3_server.with_timeout(config.configuration, milliseconds)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(..config, configuration:, operation_milliseconds: milliseconds))
}

/// Shorten only the native drain deadline for deterministic drain tests while keeping this opaque adapter configuration independent of its Erlang layout.
@internal
pub fn with_http3_drain_timeout(
  config: Config,
  milliseconds: Int,
) -> Result(Config, Nil) {
  use configuration <- result.try(
    h3_server.with_deadline(
      configuration: config.configuration,
      phase: h3_failure.Drain,
      milliseconds: milliseconds,
    )
    |> result.map_error(fn(_) { Nil }),
  )
  Ok(Config(..config, configuration:))
}

/// Replace request, response, and one-pull retained-byte limits.
pub fn with_body_limits(
  config: Config,
  request_bytes: Int,
  response_bytes: Int,
  pull_bytes: Int,
) -> Result(Config, error.Error) {
  use configuration <- result.try(
    h3_server.with_request_body_limit(config.configuration, request_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_response_body_limit(configuration, response_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_stream_buffer_limit(configuration, pull_bytes)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  Ok(Config(..config, configuration:, pull_bytes:))
}

/// Start the public HTTP/3 listener and one finite accept loop.
pub fn listen(
  handler: Handler,
  address: BitArray,
  port: Int,
  config: Config,
) -> Result(Listener, error.Error) {
  use bind_address <- result.try(
    h3_address.from_bytes(address)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use configuration <- result.try(
    h3_server.with_port(config.configuration, port)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  let configuration = h3_server.with_bind_address(configuration, bind_address)
  use listener <- result.try(
    h3_server.start(configuration) |> result.map_error(map_h3_error),
  )
  case config.listener_port(listener) {
    Error(failure) -> {
      let initiating_failure = map_h3_error(failure)
      // Native ownership begins at start(), so even metadata discovery failure must synchronously close that listener before returning.
      case h3_server.stop(listener) {
        Ok(_) | Error(_) -> Error(initiating_failure)
      }
    }
    Ok(bound_port) -> {
      let endpoint =
        context.Endpoint(h3_address.to_string(bind_address), bound_port)
      let ready = process.new_subject()
      let owner = process.self()
      let lifecycle = new_lifecycle()
      let #(coordinator, monitor) =
        spawn_monitor(fn() {
          process_role.set(process_role.Http3Listener)
          process.trap_exits(True)
          let commands = process.new_subject()
          let accepted = process.new_subject()
          let runtime =
            start_accept(ListenerRuntime(
              listener:,
              endpoint:,
              handler:,
              config:,
              commands:,
              accepted:,
              owner:,
              owner_monitor: process.monitor(owner),
              acceptor: None,
              workers: [],
              draining: False,
              lifecycle:,
            ))
          case config.coordinator_startup {
            Some(startup) -> startup()
            None -> Nil
          }
          process.send(ready, commands)
          listener_loop(runtime)
        })
      let started =
        process.new_selector()
        |> process.select_map(ready, Ok)
        |> process.select_specific_monitor(monitor, fn(_) { Error(Nil) })
        |> process.selector_receive(within: startup_milliseconds)
      case started {
        Ok(Ok(commands)) -> {
          process.demonitor_process(monitor)
          Ok(Listener(
            listener,
            endpoint,
            coordinator,
            commands,
            lifecycle,
            config.coordinator_join_confirmation,
          ))
        }
        Ok(Error(Nil)) -> {
          process.demonitor_process(monitor)
          listener_startup_failure(
            coordinator_joined: confirm_startup_join(config, True),
            lower_stopped: stop_lower_listener(listener),
          )
        }
        Error(Nil) -> {
          process.kill(coordinator)
          let coordinator_joined =
            confirm_startup_join(
              config,
              join_child(monitor, cleanup_milliseconds),
            )
          listener_startup_failure(
            coordinator_joined:,
            lower_stopped: stop_lower_listener(listener),
          )
        }
      }
    }
  }
}

fn stop_lower_listener(
  listener: h3_server.Listener,
) -> Result(Nil, error.Error) {
  h3_server.stop(listener)
  |> result.map(fn(_) { Nil })
  |> result.map_error(map_h3_error)
}

fn confirm_startup_join(config: Config, observed: Bool) -> Bool {
  case observed, config.startup_join_confirmation {
    False, _ -> False
    True, None -> True
    True, Some(confirm) -> run_guarded(confirm) == Ok(True)
  }
}

fn listener_startup_failure(
  coordinator_joined coordinator_joined: Bool,
  lower_stopped lower_stopped: Result(Nil, error.Error),
) -> Result(Listener, error.Error) {
  Error(startup_rollback_error(coordinator_joined, lower_stopped))
}

/// Reduce startup rollback observations to one stable failure.
/// An unconfirmed coordinator always takes precedence over the lower listener result.
@internal
pub fn startup_rollback_error(
  coordinator_joined: Bool,
  lower_stopped: Result(Nil, error.Error),
) -> error.Error {
  case coordinator_joined, lower_stopped {
    False, _ -> error.new(error.Timeout(error.Operation))
    True, Error(failure) -> failure
    True, Ok(Nil) -> error.new(error.Service)
  }
}

/// Return the bound local endpoint without exposing the UDP socket.
pub fn endpoint(listener: Listener) -> context.Endpoint {
  listener.endpoint
}

/// Send GOAWAY and wait for accepted request streams to complete.
pub fn drain(listener: Listener) -> Result(Nil, error.Error) {
  let prepared = case mark_draining(listener.lifecycle) {
    False -> Ok(Nil)
    True -> {
      let ready = process.new_subject()
      process.send(listener.commands, BeginDrain(ready))
      process.receive(ready, within: startup_milliseconds)
      |> result.map_error(fn(_) { error.new(error.Timeout(error.Operation)) })
    }
  }
  case prepared {
    Error(failure) -> stop_coordinator(listener, Some(failure))
    Ok(Nil) -> {
      let initiating_failure = case h3_server.graceful_stop(listener.listener) {
        Error(failure) -> Some(map_h3_error(failure))
        Ok(h3_server.Forced) -> Some(error.new(error.Timeout(error.Operation)))
        Ok(h3_server.Drained) | Ok(h3_server.AlreadyDrained) -> None
      }
      stop_coordinator(listener, initiating_failure)
    }
  }
}

/// Stop the listener and join its response supervisors idempotently.
pub fn stop(listener: Listener) -> Result(Nil, error.Error) {
  stop_coordinator(listener, None)
}

fn start_accept(runtime: ListenerRuntime) -> ListenerRuntime {
  case
    runtime.acceptor,
    !runtime.draining
    && list.length(runtime.workers) < runtime.config.maximum_response_workers
  {
    None, True -> {
      let #(pid, monitor) =
        spawn_link_monitor(fn() {
          process_role.set(process_role.Http3Acceptor)
          process.send(
            runtime.accepted,
            runtime.config.accept_request(runtime.listener),
          )
        })
      ListenerRuntime(..runtime, acceptor: Some(#(pid, monitor)))
    }
    _, _ -> runtime
  }
}

fn listener_loop(runtime: ListenerRuntime) -> Nil {
  let received =
    process.new_selector()
    |> process.select_map(runtime.commands, Control)
    |> process.select_map(runtime.accepted, Accepted)
    |> process.select_monitors(ChildExited)
    |> process.select_trapped_exits(fn(_) { LinkedExited })
    |> process.selector_receive(within: runtime.config.operation_milliseconds)
  case received {
    Error(Nil) -> listener_loop(runtime)
    Ok(Control(Stop(reply, initiating_failure))) -> {
      let outcome = shutdown_listener(runtime, initiating_failure, False)
      process.send(reply, outcome)
      Nil
    }
    Ok(Control(BeginDrain(ready))) -> {
      process.send(ready, Nil)
      listener_loop(ListenerRuntime(..runtime, draining: True))
    }
    Ok(Accepted(outcome)) -> accept_completed(runtime, outcome)
    Ok(ChildExited(process.ProcessDown(pid: pid, ..))) ->
      case pid == runtime.owner, runtime.acceptor {
        True, _ -> {
          let _outcome = shutdown_listener(runtime, None, True)
          Nil
        }
        False, Some(#(acceptor, _)) if acceptor == pid -> {
          let _outcome =
            shutdown_listener(runtime, Some(error.new(error.Service)), True)
          Nil
        }
        False, _ -> {
          let workers =
            list.filter(runtime.workers, fn(worker) { worker.pid != pid })
          listener_loop(start_accept(ListenerRuntime(..runtime, workers:)))
        }
      }
    Ok(ChildExited(process.PortDown(..))) -> listener_loop(runtime)
    Ok(LinkedExited) -> listener_loop(runtime)
  }
}

fn accept_completed(
  runtime: ListenerRuntime,
  outcome: Result(h3_server.Request, h3_server.Error),
) -> Nil {
  case runtime.acceptor {
    Some(#(_, monitor)) -> process.demonitor_process(monitor)
    None -> Nil
  }
  let runtime = ListenerRuntime(..runtime, acceptor: None)
  case outcome, runtime.draining {
    Error(_), True -> listener_loop(runtime)
    Ok(incoming), True -> {
      let _cleanup =
        bounded_cleanup(fn() {
          let _cancelled = h3_server.cancel(incoming)
          Nil
        })
      listener_loop(runtime)
    }
    Error(h3_server.Failure(h3_failure.Timeout(h3_failure.Operation))), False ->
      listener_loop(start_accept(runtime))
    Error(failure), False -> {
      let _outcome =
        shutdown_listener(runtime, Some(map_h3_error(failure)), True)
      Nil
    }
    Ok(incoming), False -> {
      let ready = process.new_subject()
      let owner = process.self()
      let #(pid, monitor) =
        spawn_monitor(fn() {
          process_role.set(process_role.Http3ResponseSupervisor)
          process.trap_exits(True)
          let shutdown = process.new_subject()
          let owner_monitor = process.monitor(owner)
          case runtime.config.response_supervisor_startup {
            Some(startup) -> startup()
            None -> Nil
          }
          process.send(ready, shutdown)
          serve_request(
            incoming,
            runtime.handler,
            runtime.endpoint,
            runtime.config,
            shutdown,
            owner_monitor,
          )
          process.demonitor_process(owner_monitor)
        })
      case process.receive(ready, within: startup_milliseconds) {
        Ok(shutdown) ->
          listener_loop(start_accept(
            ListenerRuntime(..runtime, workers: [
              ResponseWorker(pid, monitor, shutdown),
              ..runtime.workers
            ]),
          ))
        Error(Nil) ->
          abandon_response_start(
            runtime: runtime,
            incoming: incoming,
            pid: pid,
            monitor: monitor,
          )
      }
    }
  }
}

fn abandon_response_start(
  runtime runtime: ListenerRuntime,
  incoming incoming: h3_server.Request,
  pid pid: Pid,
  monitor monitor: Monitor,
) -> Nil {
  case stop_unready_response_supervisor(runtime.config, pid, monitor) {
    False -> {
      let _outcome =
        shutdown_listener(
          runtime,
          Some(error.new(error.Timeout(error.Operation))),
          True,
        )
      Nil
    }
    True ->
      case cancel_startup_request(incoming) {
        Ok(Nil) -> listener_loop(start_accept(runtime))
        Error(failure) -> {
          let _outcome = shutdown_listener(runtime, Some(failure), True)
          Nil
        }
      }
  }
}

fn stop_unready_response_supervisor(
  config: Config,
  pid: Pid,
  monitor: Monitor,
) -> Bool {
  process.kill(pid)
  let deadline = monotonic_millisecond() + cleanup_milliseconds
  let observed =
    join_child(monitor, int.max(0, deadline - monotonic_millisecond()))
  case confirm_response_start_join(config, 1, deadline, observed) {
    True -> True
    False -> {
      let monitor = process.monitor(pid)
      process.kill(pid)
      let deadline = monotonic_millisecond() + cleanup_milliseconds
      let observed =
        join_child(monitor, int.max(0, deadline - monotonic_millisecond()))
      confirm_response_start_join(config, 2, deadline, observed)
    }
  }
}

fn confirm_response_start_join(
  config: Config,
  phase: Int,
  deadline: Int,
  observed: Bool,
) -> Bool {
  case observed, config.response_start_join_confirmation {
    False, _ -> False
    True, None -> True
    True, Some(confirm) ->
      run_guarded(fn() { confirm(phase, deadline) }) == Ok(True)
  }
}

fn cancel_startup_request(
  incoming: h3_server.Request,
) -> Result(Nil, error.Error) {
  bounded_cleanup_result(fn() {
    h3_server.cancel(incoming)
    |> result.map(fn(_) { Nil })
    |> result.map_error(map_h3_error)
  })
}

fn shutdown_listener(
  runtime: ListenerRuntime,
  initiating_failure: Option(error.Error),
  latch_initiating_failure: Bool,
) -> Result(Nil, error.Error) {
  let _stopped = mark_stopped(runtime.lifecycle)
  let acceptor_joined = case runtime.acceptor {
    Some(#(pid, monitor)) -> {
      process.kill(pid)
      join_child(monitor, cleanup_milliseconds)
    }
    None -> True
  }
  list.each(runtime.workers, fn(worker) { process.send(worker.shutdown, Nil) })
  let graceful_deadline = monotonic_millisecond() + shutdown_milliseconds
  let JoinObservation(
    unconfirmed: survivors,
    observation_complete: graceful_observation_complete,
  ) =
    observe_shutdown_joins(
      runtime.config,
      runtime.workers,
      graceful_deadline,
      fn(worker, deadline) {
        join_child(
          worker.monitor,
          int.max(0, deadline - monotonic_millisecond()),
        )
      },
    )
  // A response supervisor owns its request stream and both Bodies until all of its inner callback children have a confirmed DOWN.
  // Do not force-kill an unconfirmed supervisor: doing so would discard that ownership without running its once-only cleanup.
  // A second bounded observation distinguishes a late normal exit while preserving live supervisors in quarantine.
  list.each(survivors, fn(worker) { process.send(worker.shutdown, Nil) })
  let retrying =
    list.map(survivors, fn(worker) {
      #(worker.pid, process.monitor(worker.pid))
    })
  let retry_deadline = monotonic_millisecond() + cleanup_milliseconds
  let JoinObservation(
    unconfirmed: retry_unconfirmed,
    observation_complete: retry_observation_complete,
  ) =
    observe_shutdown_joins(
      runtime.config,
      retrying,
      retry_deadline,
      fn(entry, deadline) {
        let #(_, monitor) = entry
        join_child(monitor, int.max(0, deadline - monotonic_millisecond()))
      },
    )
  process.demonitor_process(runtime.owner_monitor)
  let lower_stopped =
    h3_server.stop(runtime.listener) |> result.map_error(map_h3_error)
  let cleanup_outcome = case
    lower_stopped,
    acceptor_joined
    && graceful_observation_complete
    && retry_observation_complete
    && list.is_empty(retry_unconfirmed)
  {
    Error(failure), _ -> Error(failure)
    Ok(_), True -> Ok(Nil)
    Ok(_), False -> Error(error.new(error.Timeout(error.Operation)))
  }
  let outcome = case initiating_failure {
    Some(failure) -> prefer_operation_outcome(Error(failure), cleanup_outcome)
    None -> cleanup_outcome
  }
  // A public drain reports its initiating failure while its lifecycle latch records whether the listener and every owned child actually shut down.
  // Thus a forced drain followed by complete cleanup remains visible to that caller, and a later idempotent stop reports that no ownership remains.
  // Failures that originated inside the coordinator still remain sticky.
  let terminal_outcome = case latch_initiating_failure, initiating_failure {
    True, Some(failure) ->
      prefer_operation_outcome(Error(failure), cleanup_outcome)
    _, _ -> cleanup_outcome
  }
  let provisional =
    record_shutdown_provisional(
      runtime.lifecycle,
      shutdown_outcome_code(terminal_outcome),
    )
    |> shutdown_result_from_code
  case provisional {
    // Failed cleanup is terminal without relying on a later observer.
    // A successful cleanup remains provisional until the caller confirms the coordinator DOWN.
    Error(failure) -> {
      let _recorded =
        record_terminal_shutdown_outcome(runtime.lifecycle, Error(failure))
      outcome
    }
    Ok(Nil) -> outcome
  }
}

fn record_terminal_shutdown_outcome(
  lifecycle: Lifecycle,
  outcome: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  record_shutdown_outcome(lifecycle, shutdown_outcome_code(outcome))
  |> shutdown_result_from_code
}

fn shutdown_outcome_code(outcome: Result(Nil, error.Error)) -> Int {
  case outcome {
    Ok(Nil) -> shutdown_success
    Error(failure) -> shutdown_failure_code(error.kind(failure))
  }
}

fn shutdown_failure_code(kind: error.ErrorKind) -> Int {
  case kind {
    error.Dns -> shutdown_dns
    error.ConnectFailed -> shutdown_connect_failed
    error.Tls -> shutdown_tls
    error.Timeout(error.DnsLookup) -> shutdown_timeout_dns
    error.Timeout(error.Connect) -> shutdown_timeout_connect
    error.Timeout(error.TlsHandshake) -> shutdown_timeout_tls
    error.Timeout(error.Operation) -> shutdown_timeout_operation
    error.Timeout(error.Idle) -> shutdown_timeout_idle
    error.Timeout(error.Total) -> shutdown_timeout_total
    error.Protocol(error.Http1) -> shutdown_protocol_http1
    error.Protocol(error.Http2) -> shutdown_protocol_http2
    error.Protocol(error.Http3) -> shutdown_protocol_http3
    error.Protocol(error.Quic) -> shutdown_protocol_quic
    error.Policy(error.RedirectPolicy) -> shutdown_policy_redirect
    error.Policy(error.RetryPolicy) -> shutdown_policy_retry
    error.Policy(error.SecurityPolicy) -> shutdown_policy_security
    error.Policy(error.ProxyPolicy) -> shutdown_policy_proxy
    error.Policy(error.CachePolicy) -> shutdown_policy_cache
    error.Body(error.InvalidLimit) -> shutdown_body_invalid_limit
    error.Body(error.ReadFailed) -> shutdown_body_read_failed
    error.Body(error.TooLarge(_)) -> shutdown_body_too_large
    error.Body(error.InvalidChunk) -> shutdown_body_invalid_chunk
    error.Body(error.LengthMismatch(_, _)) -> shutdown_body_length_mismatch
    error.Body(error.NotReplayable) -> shutdown_body_not_replayable
    error.Resource(error.Connections) -> shutdown_resource_connections
    error.Resource(error.Streams) -> shutdown_resource_streams
    error.Resource(error.RequestWorkers) -> shutdown_resource_request_workers
    error.Resource(error.Memory) -> shutdown_resource_memory
    error.Resource(error.Queue) -> shutdown_resource_queue
    error.Resource(error.BufferedBody) -> shutdown_resource_buffered_body
    error.Resource(error.FileHandles) -> shutdown_resource_file_handles
    error.Cancelled -> shutdown_cancelled
    error.Service -> shutdown_service
  }
}

/// Round-trip one stable error constructor through the terminal latch codec.
/// Value-bearing body counts are canonicalized to zero by contract.
@internal
pub fn shutdown_classification_round_trip(
  kind: error.ErrorKind,
) -> error.ErrorKind {
  case shutdown_result_from_code(shutdown_failure_code(kind)) {
    Error(failure) -> error.kind(failure)
    Ok(Nil) -> error.Service
  }
}

/// Record two terminal observations against one fresh latch and return the safe reconstructed outcomes.
/// This verifies first-writer immutability without exposing the atomic reference.
@internal
pub fn shutdown_latch_sequence(
  first: Result(Nil, error.Error),
  second: Result(Nil, error.Error),
) -> #(Result(Nil, error.Error), Result(Nil, error.Error)) {
  let lifecycle = new_lifecycle()
  let first = record_terminal_shutdown_outcome(lifecycle, first)
  let second = record_terminal_shutdown_outcome(lifecycle, second)
  #(first, second)
}

fn shutdown_result_from_code(code: Int) -> Result(Nil, error.Error) {
  case code {
    1 -> Ok(Nil)
    2 -> Error(error.new(error.Dns))
    3 -> Error(error.new(error.ConnectFailed))
    4 -> Error(error.new(error.Tls))
    5 -> Error(error.new(error.Timeout(error.DnsLookup)))
    6 -> Error(error.new(error.Timeout(error.Connect)))
    7 -> Error(error.new(error.Timeout(error.TlsHandshake)))
    8 -> Error(error.new(error.Timeout(error.Operation)))
    9 -> Error(error.new(error.Timeout(error.Idle)))
    10 -> Error(error.new(error.Timeout(error.Total)))
    11 -> Error(error.new(error.Protocol(error.Http1)))
    12 -> Error(error.new(error.Protocol(error.Http2)))
    13 -> Error(error.new(error.Protocol(error.Http3)))
    14 -> Error(error.new(error.Protocol(error.Quic)))
    15 -> Error(error.new(error.Policy(error.RedirectPolicy)))
    16 -> Error(error.new(error.Policy(error.RetryPolicy)))
    17 -> Error(error.new(error.Policy(error.SecurityPolicy)))
    18 -> Error(error.new(error.Policy(error.ProxyPolicy)))
    19 -> Error(error.new(error.Policy(error.CachePolicy)))
    20 -> Error(error.new(error.Body(error.InvalidLimit)))
    21 -> Error(error.new(error.Body(error.ReadFailed)))
    // Value-bearing body failures are not produced by listener shutdown.
    // If a lower backend violates that contract, retain the public constructor while replacing peer/configuration-derived counts with zero.
    22 -> Error(error.new(error.Body(error.TooLarge(0))))
    23 -> Error(error.new(error.Body(error.InvalidChunk)))
    24 -> Error(error.new(error.Body(error.LengthMismatch(0, 0))))
    25 -> Error(error.new(error.Body(error.NotReplayable)))
    26 -> Error(error.new(error.Resource(error.Connections)))
    27 -> Error(error.new(error.Resource(error.Streams)))
    28 -> Error(error.new(error.Resource(error.RequestWorkers)))
    29 -> Error(error.new(error.Resource(error.Memory)))
    30 -> Error(error.new(error.Resource(error.Queue)))
    31 -> Error(error.new(error.Resource(error.BufferedBody)))
    32 -> Error(error.new(error.Resource(error.FileHandles)))
    33 -> Error(error.new(error.Cancelled))
    _ -> Error(error.new(error.Service))
  }
}

fn observe_shutdown_joins(
  config: Config,
  workers: List(worker),
  shared_deadline: Int,
  observe: fn(worker, Int) -> Bool,
) -> JoinObservation(worker) {
  // Always consume the real monitors.
  // The injected payload-free observation may only downgrade confirmation; it can never hide a live worker.
  let observed_unconfirmed =
    shutdown_join_probe(workers, shared_deadline, observe)
  case config.shutdown_join_results {
    None ->
      JoinObservation(
        unconfirmed: observed_unconfirmed,
        observation_complete: True,
      )
    Some(injected) ->
      case
        run_guarded(fn() { injected(list.length(workers), shared_deadline) })
      {
        Error(Nil) ->
          JoinObservation(unconfirmed: workers, observation_complete: False)
        Ok(observations) -> {
          let injected = apply_shutdown_join_results(workers, observations, [])
          case
            injected.observation_complete && list.is_empty(injected.unconfirmed)
          {
            True ->
              JoinObservation(
                unconfirmed: observed_unconfirmed,
                observation_complete: True,
              )
            False ->
              JoinObservation(
                unconfirmed: workers,
                observation_complete: injected.observation_complete,
              )
          }
        }
      }
  }
}

fn apply_shutdown_join_results(
  workers: List(worker),
  observations: List(Bool),
  unconfirmed: List(worker),
) -> JoinObservation(worker) {
  case workers, observations {
    [], [] ->
      JoinObservation(
        unconfirmed: list.reverse(unconfirmed),
        observation_complete: True,
      )
    [], [_, ..] ->
      JoinObservation(
        unconfirmed: list.reverse(unconfirmed),
        observation_complete: False,
      )
    [worker, ..rest], [] ->
      apply_shutdown_join_results(rest, [], [worker, ..unconfirmed])
      |> invalidate_join_observation
    [worker, ..rest], [joined, ..remaining] ->
      apply_shutdown_join_results(rest, remaining, case joined {
        True -> unconfirmed
        False -> [worker, ..unconfirmed]
      })
  }
}

fn invalidate_join_observation(
  observation: JoinObservation(worker),
) -> JoinObservation(worker) {
  JoinObservation(..observation, observation_complete: False)
}

/// Produce one absolute join deadline per worker.
/// The caller kills every survivor before consuming this plan, so cleanup cannot grow by one timeout per worker.
@internal
pub fn shutdown_join_plan(
  worker_count: Int,
  shared_deadline: Int,
) -> List(Int) {
  list.repeat(shared_deadline, int.max(0, worker_count))
}

/// Apply a deterministic join result probe to the shared deadline plan and retain every worker whose termination was not confirmed.
/// Production passes monitor joins; tests can inject fixed results without wall-clock sleeps.
@internal
pub fn shutdown_join_probe(
  workers: List(worker),
  shared_deadline: Int,
  probe: fn(worker, Int) -> Bool,
) -> List(worker) {
  shutdown_join_with_plan(
    workers,
    shutdown_join_plan(list.length(workers), shared_deadline),
    probe,
    [],
  )
}

fn shutdown_join_with_plan(
  workers: List(worker),
  deadlines: List(Int),
  probe: fn(worker, Int) -> Bool,
  unconfirmed: List(worker),
) -> List(worker) {
  case workers, deadlines {
    [], _ -> list.reverse(unconfirmed)
    [worker, ..rest], [deadline, ..remaining_deadlines] -> {
      shutdown_join_with_plan(
        rest,
        remaining_deadlines,
        probe,
        case probe(worker, deadline) {
          True -> unconfirmed
          False -> [worker, ..unconfirmed]
        },
      )
    }
    [worker, ..rest], [] ->
      shutdown_join_with_plan(rest, [], probe, [worker, ..unconfirmed])
  }
}

fn join_child(monitor: Monitor, milliseconds: Int) -> Bool {
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: milliseconds)
  process.demonitor_process(monitor)
  joined == Ok(Nil)
}

fn stop_coordinator(
  listener: Listener,
  initiating_failure: Option(error.Error),
) -> Result(Nil, error.Error) {
  let monitor = process.monitor(listener.coordinator)
  let reply = process.new_subject()
  process.send(listener.commands, Stop(reply, initiating_failure))
  let received =
    process.new_selector()
    |> process.select_map(reply, StopCompleted)
    |> process.select_specific_monitor(monitor, fn(_) { StopCoordinatorExited })
    |> process.selector_receive(
      within: shutdown_milliseconds + 2 * cleanup_milliseconds,
    )
  case received {
    Ok(StopCompleted(outcome)) -> {
      let joined = confirm_coordinator_termination(listener, monitor)
      case joined {
        True -> finalize_joined_shutdown(listener, outcome)
        False -> {
          close_lower_after_coordinator_failure(listener)
          record_terminal_shutdown_outcome(
            listener.lifecycle,
            Error(error.new(error.Timeout(error.Operation))),
          )
        }
      }
    }
    Ok(StopCoordinatorExited) -> {
      process.demonitor_process(monitor)
      case process.receive(reply, within: 0) {
        Ok(outcome) -> finalize_joined_shutdown(listener, outcome)
        Error(Nil) -> recorded_shutdown_result(listener)
      }
    }
    Error(Nil) -> {
      process.demonitor_process(monitor)
      let _joined = force_join_coordinator(listener)
      close_lower_after_coordinator_failure(listener)
      record_terminal_shutdown_outcome(
        listener.lifecycle,
        Error(error.new(error.Timeout(error.Operation))),
      )
    }
  }
}

fn confirm_coordinator_termination(
  listener: Listener,
  monitor: Monitor,
) -> Bool {
  let deadline = monotonic_millisecond() + cleanup_milliseconds
  let observed =
    join_child(monitor, int.max(0, deadline - monotonic_millisecond()))
  case confirm_coordinator_join(listener, 1, deadline, observed) {
    True -> True
    False -> force_join_coordinator(listener)
  }
}

fn force_join_coordinator(listener: Listener) -> Bool {
  let monitor = process.monitor(listener.coordinator)
  process.kill(listener.coordinator)
  let deadline = monotonic_millisecond() + cleanup_milliseconds
  let observed =
    join_child(monitor, int.max(0, deadline - monotonic_millisecond()))
  confirm_coordinator_join(listener, 2, deadline, observed)
}

fn confirm_coordinator_join(
  listener: Listener,
  phase: Int,
  deadline: Int,
  observed: Bool,
) -> Bool {
  case observed, listener.coordinator_join_confirmation {
    False, _ -> False
    True, None -> True
    True, Some(confirm) ->
      run_guarded(fn() { confirm(phase, deadline) }) == Ok(True)
  }
}

fn finalize_joined_shutdown(
  listener: Listener,
  outcome: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let provisional = case shutdown_provisional(listener.lifecycle) {
    0 ->
      record_shutdown_provisional(
        listener.lifecycle,
        shutdown_outcome_code(outcome),
      )
    recorded -> recorded
  }
  let terminal =
    record_shutdown_outcome(listener.lifecycle, provisional)
    |> shutdown_result_from_code
  prefer_operation_outcome(outcome, terminal)
}

fn recorded_shutdown_result(listener: Listener) -> Result(Nil, error.Error) {
  case shutdown_outcome(listener.lifecycle) {
    0 -> {
      case shutdown_provisional(listener.lifecycle) {
        0 -> {
          // The coordinator crashed before publishing any outcome.
          // Close the lower listener, but never infer that its result reconstructs the acceptor and response-worker join observations that were lost.
          close_lower_after_coordinator_failure(listener)
          record_terminal_shutdown_outcome(
            listener.lifecycle,
            Error(error.new(error.Service)),
          )
        }
        provisional ->
          record_shutdown_outcome(listener.lifecycle, provisional)
          |> shutdown_result_from_code
      }
    }
    recorded -> shutdown_result_from_code(recorded)
  }
}

fn close_lower_after_coordinator_failure(listener: Listener) -> Nil {
  case h3_server.stop(listener.listener) {
    Ok(_) | Error(_) -> Nil
  }
}

fn serve_request(
  incoming: h3_server.Request,
  handler: Handler,
  local_endpoint: context.Endpoint,
  config: Config,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
) -> Nil {
  let outcome = case
    make_request_body(incoming, config.request_disposed_probe)
  {
    Error(failure) -> Error(failure)
    Ok(request_body) -> {
      let outcome =
        serve_request_body(
          incoming,
          request_body,
          handler,
          local_endpoint,
          config,
          shutdown,
          owner_monitor,
        )
      // This scope is outside every request-validation `result.try`, so an invalid authority, peer lookup failure, or context rejection cannot bypass disposal of the already-created stream body.
      let cleanup = dispose_body(request_body)
      prefer_operation_outcome(outcome, cleanup)
    }
  }
  case outcome {
    Ok(Nil) -> Nil
    Error(failure) -> {
      let _cleanup =
        bounded_cleanup(fn() { finish_failed_request(incoming, failure) })
      Nil
    }
  }
}

fn serve_request_body(
  incoming: h3_server.Request,
  request_body: body.Body,
  handler: Handler,
  local_endpoint: context.Endpoint,
  config: Config,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
) -> Result(Nil, error.Error) {
  use #(request, remote_endpoint, extended_protocol, request_early_data) <- result.try(
    run_setup_work(config, shutdown, owner_monitor, fn() {
      use request <- result.try(config.request_setup(incoming, request_body))
      use remote_endpoint <- result.try(peer_endpoint(incoming))
      Ok(#(
        request,
        remote_endpoint,
        h3_server.protocol(incoming),
        early_data(incoming),
      ))
    })
    |> work_run_result,
  )
  // Context cancellation brokers are owned by the process that creates them.
  // Construct the context only after the setup child has a confirmed DOWN so its broker remains owned by this request supervisor for the whole stream.
  use request_context <- result.try(context.new(
    protocol: context.Http3,
    peer_endpoint: remote_endpoint,
    local_endpoint:,
    within_milliseconds: config.operation_milliseconds,
    tls_identity: context.TlsIdentity(config.service_identity, None),
    early_data: request_early_data,
  ))
  use request_context <- result.try(attach_extended_connect_protocol(
    request_context,
    extended_protocol,
  ))
  let cancellation = process.new_subject()
  let subscription =
    context.subscribe_cancellation(request_context, cancellation)
  let peer_failures = process.new_subject()
  let peer_completed = process.new_subject()
  // The already admitted request supervisor owns exactly one terminal observer.
  // A terminal publication carries a private acknowledgement, and the observer cannot exit until the supervisor has consumed and acknowledged that exact result.
  // DOWN therefore proves either a confirmed publication or a crash before publication, without a timing-based drain.
  let #(peer_observer, peer_monitor) =
    spawn_link_monitor(fn() {
      process_role.set(process_role.Http3ResponseTerminal)
      let outcome = case
        run_guarded(fn() {
          h3_server.await_response_completion(incoming)
          |> result.map_error(map_h3_error)
        })
      {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      let acknowledgement = process.new_subject()
      case outcome {
        Ok(Nil) -> process.send(peer_completed, acknowledgement)
        Error(failure) ->
          process.send(peer_failures, #(failure, acknowledgement))
      }
      process.receive_forever(acknowledgement)
    })
  let outcome =
    serve_context(
      incoming,
      request,
      request_context,
      handler,
      config.pull_bytes,
      shutdown,
      owner_monitor,
      cancellation,
      peer_failures,
      peer_completed,
      config,
      peer_observer,
      peer_monitor,
    )
  context.unsubscribe_cancellation(subscription)
  case outcome {
    Ok(Nil) -> Ok(Nil)
    Error(failure) -> {
      context.cancel(request_context)
      Error(failure)
    }
  }
}

fn run_setup_work(
  config: Config,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  work: fn() -> Result(value, error.Error),
) -> WorkRun(value) {
  let completed = process.new_subject()
  let #(pid, monitor) =
    spawn_link_monitor(fn() {
      process_role.set(process_role.Http3ResponseWork)
      let outcome = case run_guarded(work) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      process.send(completed, outcome)
    })
  let received =
    process.new_selector()
    |> process.select_map(completed, WorkCompleted)
    |> process.select_specific_monitor(monitor, fn(_) { WorkExited })
    |> process.select_specific_monitor(owner_monitor, fn(_) { WorkCancelled })
    |> process.select_map(shutdown, fn(_) { WorkCancelled })
    |> process.selector_receive(within: config.operation_milliseconds)
  let outcome = case received {
    Ok(WorkCompleted(outcome)) -> outcome
    Ok(WorkExited) ->
      case process.receive(completed, within: 0) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
    Ok(WorkCancelled) -> Error(error.new(error.Cancelled))
    Ok(PeerFailed(failure, acknowledgement)) -> {
      process.send(acknowledgement, Nil)
      Error(failure)
    }
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
  process.kill(pid)
  let exited = case received {
    Ok(WorkExited) -> True
    _ -> False
  }
  let join =
    finish_response_phase_child(config, RequestSetup, pid, monitor, exited)
  WorkRun(outcome:, join:)
}

fn serve_context(
  incoming: h3_server.Request,
  request: Request(body.Body),
  request_context: context.Context,
  handler: Handler,
  pull_bytes: Int,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  peer_completed: Subject(Subject(Nil)),
  config: Config,
  peer_observer: Pid,
  peer_monitor: Monitor,
) -> Result(Nil, error.Error) {
  let WorkRun(outcome: handled, join: handler_join) =
    run_request_work(
      config,
      RequestHandler,
      request_context,
      shutdown,
      owner_monitor,
      cancellation,
      peer_failures,
      fn() { handler(request, request_context) },
    )
  case handled {
    Error(failure) -> {
      let operation = require_join_confirmation(Error(failure), handler_join)
      require_join_confirmation(
        operation,
        finish_peer_terminal(config, peer_observer, peer_monitor, False),
      )
    }
    Ok(outgoing) -> {
      let sent = {
        use _ <- result.try(handler_join)
        let WorkRun(outcome: sent, join: send_join) =
          run_request_work(
            config,
            ResponseSend,
            request_context,
            shutdown,
            owner_monitor,
            cancellation,
            peer_failures,
            fn() {
              send_response(incoming, request.method, outgoing, pull_bytes)
            },
          )
        require_join_confirmation(sent, send_join)
      }
      let DeliveryRun(outcome: delivered, peer_down_observed:) = case sent {
        Error(failure) -> DeliveryRun(Error(failure), False)
        Ok(Nil) ->
          await_response_delivery(
            request_context,
            shutdown,
            owner_monitor,
            cancellation,
            peer_failures,
            peer_completed,
            peer_monitor,
          )
      }
      let delivered =
        require_join_confirmation(
          delivered,
          finish_peer_terminal(
            config,
            peer_observer,
            peer_monitor,
            peer_down_observed,
          ),
        )
      finish_response_source(outgoing.body, delivered)
    }
  }
}

fn await_response_delivery(
  request_context: context.Context,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  peer_completed: Subject(Subject(Nil)),
  peer_monitor: Monitor,
) -> DeliveryRun {
  case context.is_cancelled(request_context) {
    True -> DeliveryRun(Error(error.new(error.Cancelled)), False)
    False ->
      await_response_delivery_ready(
        request_context,
        shutdown,
        owner_monitor,
        cancellation,
        peer_failures,
        peer_completed,
        peer_monitor,
      )
  }
}

fn await_response_delivery_ready(
  request_context: context.Context,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  peer_completed: Subject(Subject(Nil)),
  peer_monitor: Monitor,
) -> DeliveryRun {
  let remaining = context.remaining_milliseconds(request_context)
  case remaining > 0 {
    False ->
      DeliveryRun(Error(error.new(error.Timeout(error.Operation))), False)
    True -> {
      let received =
        process.new_selector()
        |> process.select_map(peer_completed, DeliveryCompleted)
        |> process.select_map(peer_failures, fn(publication) {
          let #(failure, acknowledgement) = publication
          DeliveryFailed(failure, acknowledgement)
        })
        |> process.select_specific_monitor(owner_monitor, fn(_) {
          DeliveryCancelled
        })
        |> process.select_map(shutdown, fn(_) { DeliveryCancelled })
        |> process.select_map(cancellation, fn(_) { DeliveryCancelled })
        |> process.select_specific_monitor(peer_monitor, fn(_) {
          DeliveryObserverExited
        })
        |> process.selector_receive(within: remaining)
      case received {
        Ok(DeliveryCompleted(acknowledgement)) -> {
          process.send(acknowledgement, Nil)
          DeliveryRun(Ok(Nil), False)
        }
        Ok(DeliveryFailed(failure, acknowledgement)) -> {
          process.send(acknowledgement, Nil)
          context.cancel(request_context)
          DeliveryRun(Error(failure), False)
        }
        Ok(DeliveryCancelled) ->
          DeliveryRun(Error(error.new(error.Cancelled)), False)
        // The observer waits for a private acknowledgement after publishing.
        // No terminal result can remain unconsumed when DOWN wins selection.
        Ok(DeliveryObserverExited) ->
          DeliveryRun(Error(error.new(error.Service)), True)
        Error(Nil) ->
          DeliveryRun(Error(error.new(error.Timeout(error.Operation))), False)
      }
    }
  }
}

fn run_request_work(
  config: Config,
  phase: ResponseWorkPhase,
  request_context: context.Context,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  work: fn() -> Result(value, error.Error),
) -> WorkRun(value) {
  case
    require(!context.is_cancelled(request_context), error.new(error.Cancelled))
  {
    Error(failure) -> WorkRun(Error(failure), Ok(Nil))
    Ok(Nil) ->
      run_request_work_ready(
        config,
        phase,
        request_context,
        shutdown,
        owner_monitor,
        cancellation,
        peer_failures,
        work,
      )
  }
}

fn run_request_work_ready(
  config: Config,
  phase: ResponseWorkPhase,
  request_context: context.Context,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  work: fn() -> Result(value, error.Error),
) -> WorkRun(value) {
  let remaining = context.remaining_milliseconds(request_context)
  case remaining > 0 {
    False -> WorkRun(Error(error.new(error.Timeout(error.Operation))), Ok(Nil))
    True ->
      run_request_work_with_deadline(
        config,
        phase,
        request_context,
        shutdown,
        owner_monitor,
        cancellation,
        peer_failures,
        work,
        remaining,
      )
  }
}

fn run_request_work_with_deadline(
  config: Config,
  phase: ResponseWorkPhase,
  request_context: context.Context,
  shutdown: Subject(Nil),
  owner_monitor: Monitor,
  cancellation: Subject(Nil),
  peer_failures: Subject(#(error.Error, Subject(Nil))),
  work: fn() -> Result(value, error.Error),
  remaining: Int,
) -> WorkRun(value) {
  let completed = process.new_subject()
  // Only private supervisors trap exits.
  // Linking these callback workers ensures that killing a supervisor cannot orphan a stuck source.
  let #(pid, monitor) =
    spawn_link_monitor(fn() {
      process_role.set(process_role.Http3ResponseWork)
      let outcome = case run_guarded(work) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      process.send(completed, outcome)
    })
  let received =
    process.new_selector()
    |> process.select_map(completed, WorkCompleted)
    |> process.select_specific_monitor(monitor, fn(_) { WorkExited })
    |> process.select_specific_monitor(owner_monitor, fn(_) { WorkCancelled })
    |> process.select_map(shutdown, fn(_) { WorkCancelled })
    |> process.select_map(cancellation, fn(_) { WorkCancelled })
    |> process.select_map(peer_failures, fn(publication) {
      let #(failure, acknowledgement) = publication
      PeerFailed(failure, acknowledgement)
    })
    |> process.selector_receive(within: remaining)
  let outcome = case received {
    Ok(WorkCompleted(outcome)) -> outcome
    Ok(WorkExited) ->
      case process.receive(completed, within: 0) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
    Ok(WorkCancelled) -> Error(error.new(error.Cancelled))
    Ok(PeerFailed(failure, acknowledgement)) -> {
      process.send(acknowledgement, Nil)
      context.cancel(request_context)
      Error(failure)
    }
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
  process.kill(pid)
  let exited = case received {
    Ok(WorkExited) -> True
    _ -> False
  }
  let join = finish_response_phase_child(config, phase, pid, monitor, exited)
  WorkRun(outcome:, join:)
}

fn work_run_result(run: WorkRun(value)) -> Result(value, error.Error) {
  let WorkRun(outcome:, join:) = run
  require_join_confirmation(outcome, join)
}

fn require_join_confirmation(
  operation: Result(value, error.Error),
  join: Result(Nil, error.Error),
) -> Result(value, error.Error) {
  case join {
    Ok(Nil) -> operation
    Error(failure) -> Error(failure)
  }
}

fn finish_peer_terminal(
  config: Config,
  peer_observer: Pid,
  peer_monitor: Monitor,
  down_already_observed: Bool,
) -> Result(Nil, error.Error) {
  process.kill(peer_observer)
  finish_response_phase_child(
    config,
    PeerTerminal,
    peer_observer,
    peer_monitor,
    down_already_observed,
  )
}

fn finish_response_source(
  source: body.Body,
  delivered: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let transfer_cleanup =
    bounded_cleanup(fn() { body.transfer_finished(source, delivered) })
  let source_cleanup = dispose_body(source)
  prefer_operation_outcome(
    delivered,
    prefer_operation_outcome(transfer_cleanup, source_cleanup),
  )
}

fn finish_response_phase_child(
  config: Config,
  phase: ResponseWorkPhase,
  pid: Pid,
  monitor: Monitor,
  down_already_observed: Bool,
) -> Result(Nil, error.Error) {
  let deadline = monotonic_millisecond() + cleanup_milliseconds
  let observed = case down_already_observed {
    True -> {
      process.demonitor_process(monitor)
      True
    }
    False ->
      observe_child_down(
        monitor,
        int.max(0, deadline - monotonic_millisecond()),
      )
  }
  case
    confirm_response_phase_join(config, phase, InitialJoin, deadline, observed)
  {
    True -> Ok(Nil)
    False -> {
      let monitor = case observed {
        True -> process.monitor(pid)
        False -> monitor
      }
      await_quarantined_phase_join(config, phase, pid, monitor, 1)
      Error(error.new(error.Timeout(error.Operation)))
    }
  }
}

fn await_quarantined_phase_join(
  config: Config,
  phase: ResponseWorkPhase,
  pid: Pid,
  monitor: Monitor,
  attempt: Int,
) -> Nil {
  let deadline = monotonic_millisecond() + cleanup_milliseconds
  let observed =
    observe_child_down(monitor, int.max(0, deadline - monotonic_millisecond()))
  case
    confirm_response_phase_join(
      config,
      phase,
      QuarantineJoin(attempt),
      deadline,
      observed,
    )
  {
    True -> Nil
    False -> {
      process.kill(pid)
      let monitor = case observed {
        True -> {
          // A test-only downgrade can reject a real DOWN.
          // Re-monitoring the same child proves it remains dead before a later confirmation;
          // the short pause prevents an adversarial probe from spinning.
          process.sleep(10)
          process.monitor(pid)
        }
        False -> monitor
      }
      await_quarantined_phase_join(
        config,
        phase,
        pid,
        monitor,
        int.min(2_147_483_647, attempt + 1),
      )
    }
  }
}

fn observe_child_down(monitor: Monitor, milliseconds: Int) -> Bool {
  let observed =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: milliseconds)
  case observed {
    Ok(Nil) -> {
      process.demonitor_process(monitor)
      True
    }
    Error(Nil) -> False
  }
}

fn confirm_response_phase_join(
  config: Config,
  phase: ResponseWorkPhase,
  stage: ResponseJoinStage,
  deadline: Int,
  observed: Bool,
) -> Bool {
  case observed, config.response_phase_join_confirmation {
    False, _ -> False
    True, None -> True
    True, Some(confirm) ->
      run_guarded(fn() { confirm(phase, stage, deadline) }) == Ok(True)
  }
}

fn bounded_cleanup(cleanup: fn() -> Nil) -> Result(Nil, error.Error) {
  bounded_cleanup_result(fn() {
    cleanup()
    Ok(Nil)
  })
}

fn bounded_cleanup_result(
  cleanup: fn() -> Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let completed = process.new_subject()
  let #(pid, monitor) =
    spawn_link_monitor(fn() {
      process_role.set(process_role.Http3ResponseCleanup)
      let outcome = case run_guarded(cleanup) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      process.send(completed, outcome)
    })
  let received =
    process.new_selector()
    |> process.select_map(completed, CleanupCompleted)
    |> process.select_specific_monitor(monitor, fn(_) { CleanupExited })
    |> process.selector_receive(within: cleanup_milliseconds)
  case received {
    Ok(CleanupCompleted(outcome)) ->
      case join_child(monitor, cleanup_milliseconds) {
        True -> outcome
        False -> Error(error.new(error.Timeout(error.Operation)))
      }
    Ok(CleanupExited) -> {
      process.demonitor_process(monitor)
      case process.receive(completed, within: 0) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
    }
    Error(Nil) -> {
      process.kill(pid)
      case join_child(monitor, cleanup_milliseconds) {
        True -> Error(error.new(error.Timeout(error.Operation)))
        False -> Error(error.new(error.Service))
      }
    }
  }
}

fn dispose_body(source: body.Body) -> Result(Nil, error.Error) {
  let attempted =
    bounded_cleanup_result(fn() {
      // The outer one-second supervisor owns the operational bound.
      // A longer inner deadline makes an outer timeout deterministically abandon and stop the callback instead of racing the same clock edge.
      body.cancel_within(source, 2 * cleanup_milliseconds)
    })
  case attempted {
    Ok(Nil) -> Ok(Nil)
    Error(failure) ->
      case body.await_release(source, cleanup_milliseconds) {
        body.ReleasePending -> Error(failure)
        body.Released(outcome) -> outcome
      }
  }
}

fn prefer_operation_outcome(
  operation: Result(Nil, error.Error),
  cleanup: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  case operation {
    Error(failure) -> Error(failure)
    Ok(Nil) -> cleanup
  }
}

fn finish_failed_request(
  incoming: h3_server.Request,
  failure: error.Error,
) -> Nil {
  case error.kind(failure) {
    error.Cancelled | error.Timeout(_) -> {
      let _cancelled = h3_server.cancel(incoming)
      Nil
    }
    _ -> {
      case h3_server.respond(incoming, 500, [], <<>>) {
        Ok(Nil) -> Nil
        Error(_) -> {
          let _cancelled = h3_server.cancel(incoming)
          Nil
        }
      }
    }
  }
}

fn attach_extended_connect_protocol(
  request_context: context.Context,
  protocol: Option(String),
) -> Result(context.Context, error.Error) {
  case protocol {
    None -> Ok(request_context)
    Some(protocol) ->
      context.with_extended_connect_protocol(request_context, protocol)
  }
}

fn make_request_body(
  incoming: h3_server.Request,
  disposed_probe: Option(fn() -> Nil),
) -> Result(body.Body, error.Error) {
  body.from_pull(
    request_pull(incoming, <<>>, None),
    content_length(h3_server.headers(incoming)),
    None,
    fn() {
      case h3_server.cancel(incoming), disposed_probe {
        Ok(_), Some(probe) -> {
          let _observed = run_guarded(probe)
          Nil
        }
        _, _ -> Nil
      }
      Nil
    },
  )
}

fn request_pull(
  incoming: h3_server.Request,
  pending: BitArray,
  trailers: Option(body.Headers),
) -> body.Pull {
  body.pull(fn(maximum_bytes) {
    pull_request(incoming, pending, trailers, maximum_bytes)
  })
}

fn pull_request(
  incoming: h3_server.Request,
  pending: BitArray,
  trailers: Option(body.Headers),
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case bit_array.byte_size(pending) > 0 {
    True -> emit_request_bytes(incoming, pending, trailers, maximum_bytes)
    False ->
      case h3_server.next_event(incoming) {
        Ok(h3_server.Data(bytes)) ->
          case bit_array.byte_size(bytes) {
            0 -> pull_request(incoming, <<>>, trailers, maximum_bytes)
            _ -> emit_request_bytes(incoming, bytes, trailers, maximum_bytes)
          }
        Ok(h3_server.Trailers(received)) ->
          case trailers {
            None -> pull_request(incoming, <<>>, Some(received), maximum_bytes)
            Some(_) -> Error(protocol_error())
          }
        Ok(h3_server.End) -> Ok(body.PullEnd(option_trailers(trailers)))
        Error(failure) -> Error(map_h3_error(failure))
      }
  }
}

fn emit_request_bytes(
  incoming: h3_server.Request,
  bytes: BitArray,
  trailers: Option(body.Headers),
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_bytes {
    True -> Ok(body.PullData(bytes, request_pull(incoming, <<>>, trailers)))
    False -> {
      use chunk <- result.try(
        bit_array.slice(bytes, at: 0, take: maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      use pending <- result.try(
        bit_array.slice(bytes, at: maximum_bytes, take: size - maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      Ok(body.PullData(chunk, request_pull(incoming, pending, trailers)))
    }
  }
}

fn make_request(
  incoming: h3_server.Request,
  request_body: body.Body,
) -> Result(Request(body.Body), error.Error) {
  use _ <- result.try(require(
    h3_server.scheme(incoming) == "https",
    protocol_error(),
  ))
  use #(host, port) <- result.try(
    parse_authority(h3_server.authority(incoming)),
  )
  let #(path, query) = split_target(h3_server.path(incoming))
  Ok(request.Request(
    method: h3_server.method(incoming),
    headers: h3_server.headers(incoming),
    body: request_body,
    scheme: gleam_http.Https,
    host:,
    port:,
    path:,
    query:,
  ))
}

fn parse_authority(
  authority: String,
) -> Result(#(String, Option(Int)), error.Error) {
  case uri.parse("https://" <> authority) {
    Ok(uri.Uri(
      scheme: Some("https"),
      userinfo: None,
      host: Some(host),
      port:,
      path: "",
      query: None,
      fragment: None,
    )) ->
      case host != "" && valid_port(port) {
        True -> Ok(#(host, port))
        False -> Error(protocol_error())
      }
    _ -> Error(protocol_error())
  }
}

fn split_target(target: String) -> #(String, Option(String)) {
  case string.split_once(target, on: "?") {
    Ok(#(path, query)) -> #(path, Some(query))
    Error(Nil) -> #(target, None)
  }
}

fn peer_endpoint(
  incoming: h3_server.Request,
) -> Result(context.Endpoint, error.Error) {
  use endpoint <- result.try(
    h3_server.peer_endpoint(incoming) |> result.map_error(map_h3_error),
  )
  Ok(context.Endpoint(
    h3_address.to_string(h3_address.endpoint_address(endpoint)),
    h3_address.port(endpoint),
  ))
}

fn early_data(incoming: h3_server.Request) -> context.EarlyData {
  case
    h3_server.request_transport(incoming)
    |> h3_transport.stream_early_data_status
  {
    Ok(h3_transport.Accepted) -> context.EarlyDataAccepted
    Ok(h3_transport.Rejected) -> context.EarlyDataRejected
    _ -> context.EarlyDataDisabled
  }
}

fn send_response(
  incoming: h3_server.Request,
  method: gleam_http.Method,
  outgoing: Response(body.Body),
  pull_bytes: Int,
) -> Result(Nil, error.Error) {
  use _ <- result.try(
    h3_server.send_response(
      incoming,
      outgoing.status,
      date.with_date(status: outgoing.status, headers: outgoing.headers),
    )
    |> result.map_error(map_h3_error),
  )
  case method {
    gleam_http.Head ->
      h3_server.finish_response(incoming) |> result.map_error(map_h3_error)
    _ -> send_response_body(incoming, outgoing.body, pull_bytes)
  }
}

fn send_response_body(
  incoming: h3_server.Request,
  outgoing: body.Body,
  pull_bytes: Int,
) -> Result(Nil, error.Error) {
  case body.read(outgoing, pull_bytes) {
    Error(failure) -> Error(failure)
    Ok(body.Data(bytes, next)) -> {
      use _ <- result.try(
        h3_server.send_chunk(incoming, bytes) |> result.map_error(map_h3_error),
      )
      send_response_body(incoming, next, pull_bytes)
    }
    Ok(body.Done(completed)) ->
      case body.trailers(completed) {
        Some([_, ..] as trailers) ->
          h3_server.send_trailers(incoming, trailers)
          |> result.map_error(map_h3_error)
        _ ->
          h3_server.finish_response(incoming) |> result.map_error(map_h3_error)
      }
  }
}

fn content_length(headers: List(#(String, String))) -> Option(Int) {
  case headers {
    [] -> None
    [#(name, value), ..rest] ->
      case string.lowercase(name) {
        "content-length" ->
          case int.parse(value) {
            Ok(length) if length >= 0 -> Some(length)
            _ -> None
          }
        _ -> content_length(rest)
      }
  }
}

fn option_trailers(trailers: Option(body.Headers)) -> body.Headers {
  case trailers {
    Some(headers) -> headers
    None -> []
  }
}

fn valid_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(value) -> value > 0 && value <= 65_535
  }
}

fn map_h3_error(failure: h3_server.Error) -> error.Error {
  case failure {
    h3_server.Failure(failure) -> adapter_failure.from_runtime(failure)
    h3_server.RequestBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    h3_server.ResponseBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    h3_server.ConsumerTooSlow(_) -> error.new(error.Resource(error.Memory))
    _ -> protocol_error()
  }
}

fn require(condition: Bool, failure: error.Error) -> Result(Nil, error.Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(failure)
  }
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http3))
}

fn security_policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}
