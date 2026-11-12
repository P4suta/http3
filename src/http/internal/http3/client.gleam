//// Supervised, bounded streaming over the public reusable HTTP/3 client.

import gleam/bit_array
import gleam/bool
import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/cleanup_result
import http/internal/client_trace
import http/internal/http3/failure as failure_adapter
import http/internal/process_role
import http/resource
import http3/client as native

const cleanup_milliseconds = 1000

const response_pull_cleanup_milliseconds = 8000

type Once

/// An opaque, process-owned capability that can request an orderly connection shutdown without running user code in the lifecycle guardian.
@internal
pub type CloseHandle

@external(erlang, "http_body_ffi", "new_cancel_handle")
fn new_once() -> Once

@external(erlang, "http_body_ffi", "mark_cancelled")
fn claim_once(once: Once) -> Bool

@external(erlang, "http_body_ffi", "is_cancelled")
fn was_claimed(once: Once) -> Bool

@external(erlang, "http_server_ffi", "run_guarded")
fn guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn now() -> Int

@external(erlang, "http_client_ffi", "new_http3_close_handle")
fn new_http3_close_handle(commands: Subject(OwnerCommand)) -> CloseHandle

/// Finite request supervision and retained-byte policy.
pub opaque type Config {
  Config(
    native: native.Client,
    pull_bytes: Int,
    maximum_body_bytes: Int,
    connect_milliseconds: Int,
    operation_milliseconds: Int,
    idle_milliseconds: Int,
    limits: resource.Limits,
    shared_resources: Option(resource.Controller),
    lifecycle_owner: Option(Pid),
    source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
    child_cleanup_probe: Option(fn() -> Result(Nil, error.Error)),
    request_supervisor_start_probe: Option(fn() -> Result(Nil, error.Error)),
    stream_open_refusal_probe: Option(fn() -> Result(Bool, Nil)),
    native_cleanup_probe: Option(fn() -> Result(Bool, Nil)),
    request_lease_release_probe: Option(fn() -> Nil),
  )
}

/// A verified connection whose native owner outlives individual exchanges.
pub opaque type Connection {
  Connection(
    native: native.Connection,
    owner: Pid,
    commands: Subject(OwnerCommand),
    resources: resource.Controller,
    config: Config,
  )
}

type OwnerCommand {
  Track(Pid, Subject(Command), Subject(Nil))
  Close(deadline: Int)
}

type OwnerEvent {
  OwnerCommand(OwnerCommand)
  WorkerDown(process.Down)
}

type Worker {
  Worker(pid: Pid, monitor: Monitor, commands: Subject(Command))
}

type Command {
  Read(Int, Subject(Result(body.PullEvent, error.Error)))
  Cancel(Option(Subject(Result(Nil, error.Error))))
}

type SourceDisposition {
  DisposeSource(protocol: Option(context.Protocol))
  RetainUnstarted(failure: error.Error)
}

type RequestCompletion {
  RequestCompletion(
    cleanup: CleanupProof,
    native: NativeProof,
    response_release_ack: Option(Subject(Result(Nil, error.Error))),
    source_disposition: SourceDisposition,
  )
}

// A semantic cleanup result is not a process-lifetime proof.
// `pending` keeps every unconfirmed PID explicit.
// Request-scoped PIDs are monitored by the detached lease reaper before work; pre-admission helpers are handed to a passive monitor owner before this proof is discarded.
type CleanupProof {
  CleanupProof(outcome: Result(Nil, error.Error), pending: List(Pid))
}

type NativeProof {
  NativeNotStarted
  NativeStreamTerminal
  NativeDrainRequired
}

/// A stream-open result whose unstarted branch returns the original Body ownership only after the refused connection and its admission are released.
@internal
pub type RoutedResponse {
  ResponseStarted(response: Response(body.Body))
  RequestUnstarted(failure: error.Error, source: body.Body)
}

type DeferredRecoveryReply {
  ReturnUnstarted(
    replied: Subject(Result(RoutedResponse, error.Error)),
    failure: error.Error,
    source: body.Body,
  )
}

type RecoveryPlan {
  RecoveryPlan(
    dispose_source: Bool,
    drain_physical: Bool,
    deferred_reply: Option(DeferredRecoveryReply),
  )
}

type LeaseReaper {
  LeaseReaper(
    pid: Pid,
    commands: Subject(LeaseReaperCommand),
    begin: Subject(Nil),
    accepted: Subject(Nil),
  )
}

type LeaseReaperStart {
  LeaseReaperPrepared(Subject(LeaseReaperCommand), Subject(Nil))
  LeaseReaperExited
}

type LeaseReaperCommand {
  TrackCoordinator(pid: Pid, accepted: Subject(Nil))
  TrackLocal(pid: Pid, accepted: Subject(Nil))
  Settle(
    plan: RecoveryPlan,
    coordinator: Pid,
    released: Subject(Result(Nil, error.Error)),
  )
}

type LeaseReaperEvent {
  LeaseReaperCommand(LeaseReaperCommand)
  LeaseReaperDown(process.Down)
}

type TrackedLocal {
  TrackedLocal(pid: Pid, coordinator: Bool)
}

type LeaseReaperRuntime {
  LeaseReaperRuntime(
    commands: Subject(LeaseReaperCommand),
    lease: resource.Lease,
    source: body.Body,
    connection: Connection,
    parent: Pid,
    tracked: List(TrackedLocal),
    plan: Option(RecoveryPlan),
    release_confirmation: Option(Subject(Result(Nil, error.Error))),
    plan_deadline: Int,
    source_cancel_started: Bool,
    physical_close_deadline: Option(Int),
    physical_owner_down: Bool,
  )
}

// The request supervisor creates the gate that it receives from.
// The parent owns only this readiness subject and can therefore open the gate after the logical HTTP/3 lease has been adopted by that exact supervisor process.
type RequestSupervisorStartEvent {
  RequestSupervisorPrepared(gate: Subject(Bool))
  RequestSupervisorExited
}

type Incoming {
  Head(Int, body.Headers)
  Chunk(BitArray, BitArray, Int)
  Finished(body.Headers)
}

type StartedExchangeEvent {
  StartedExchangeReply(Result(RoutedResponse, error.Error))
  StartedExchangeGuardianDown
}

type Event {
  Command(Command)
  Uploaded(Result(Nil, error.Error))
  Received(Result(Incoming, error.Error))
  ChildDown(process.Down)
  OwnerDown
  LifecycleDown
  CallerDown
  LinkedExit
}

type ResponsePullSelection {
  ResponsePullReply(Result(body.PullEvent, error.Error))
  ResponsePullWorkerDown
  ResponsePullGuardianDown
}

type Runtime {
  Runtime(
    stream: native.Stream,
    source: body.Body,
    commands: Subject(Command),
    uploaded: Subject(Result(Nil, error.Error)),
    received: Subject(Result(Incoming, error.Error)),
    upload: Option(#(Pid, Monitor)),
    reader: Option(#(Pid, Monitor)),
    child_cleanup: CleanupProof,
    owner_monitor: Monitor,
    caller_monitor: Monitor,
    lifecycle_monitor: Option(Monitor),
    headers: Option(Subject(Result(RoutedResponse, error.Error))),
    waiting: Option(Subject(Result(body.PullEvent, error.Error))),
    pending: BitArray,
    response_bytes: Int,
    deadline: Int,
    config: Config,
    guardian: Pid,
    completed: Subject(RequestCompletion),
    trace: Option(client_trace.Trace),
    terminal_cancelled: Once,
    response_cleanup: cleanup_result.Completion,
    lease_reaper: LeaseReaper,
  )
}

/// Validate all limits before allocating a connection owner or worker.
pub fn configure(
  native native: native.Client,
  pull_bytes pull_bytes: Int,
  maximum_body_bytes maximum_body_bytes: Int,
  operation_milliseconds operation_milliseconds: Int,
  idle_milliseconds idle_milliseconds: Int,
) -> Result(Config, error.Error) {
  use _ <- result.try(require(
    pull_bytes > 0
      && maximum_body_bytes >= pull_bytes
      && operation_milliseconds > 0
      && operation_milliseconds <= 3_600_000
      && idle_milliseconds > 0
      && idle_milliseconds <= 3_600_000,
    error.new(error.Policy(error.SecurityPolicy)),
  ))
  use limits <- result.try(resource.limits(
    maximum_workers: int.max(1, int.min(100, maximum_body_bytes / pull_bytes)),
    memory_bytes: maximum_body_bytes,
  ))
  Ok(Config(
    native:,
    pull_bytes:,
    maximum_body_bytes:,
    connect_milliseconds: operation_milliseconds,
    operation_milliseconds:,
    idle_milliseconds:,
    limits:,
    shared_resources: None,
    lifecycle_owner: None,
    source_cleanup: body.cancel_within,
    child_cleanup_probe: None,
    request_supervisor_start_probe: None,
    stream_open_refusal_probe: None,
    native_cleanup_probe: None,
    request_lease_release_probe: None,
  ))
}

/// Bound only connection-owner publication and authentication.
/// Once adopted,
/// the connection keeps the stable per-request operation budget configured by `configure`; a short first request cannot shorten later streams.
@internal
pub fn with_connection_budget(
  config config: Config,
  milliseconds milliseconds: Int,
) -> Result(Config, error.Error) {
  use _ <- result.try(require(
    milliseconds > 0 && milliseconds <= 3_600_000,
    error.new(error.Policy(error.SecurityPolicy)),
  ))
  Ok(Config(..config, connect_milliseconds: milliseconds))
}

/// Test-facing finite observation of the two independent timeout contracts.
@internal
pub fn timeout_budgets(config: Config) -> #(Int, Int) {
  #(config.connect_milliseconds, config.operation_milliseconds)
}

/// Share stream admission and observe the lifetime of the whole HTTP client.
pub fn with_supervision(
  config config: Config,
  resources resources: resource.Controller,
  lifecycle_owner lifecycle_owner: Pid,
) -> Config {
  Config(
    ..config,
    shared_resources: Some(resources),
    lifecycle_owner: Some(lifecycle_owner),
  )
}

/// Replace source cleanup observation for deterministic lifecycle tests.
/// Production configurations use `body.cancel_within` and never need this.
@internal
pub fn with_source_cleanup_probe(
  config config: Config,
  cleanup cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
) -> Config {
  Config(..config, source_cleanup: cleanup)
}

/// Replace child termination observation for deterministic lifecycle tests.
@internal
pub fn with_child_cleanup_probe(
  config config: Config,
  cleanup cleanup: fn() -> Result(Nil, error.Error),
) -> Config {
  Config(..config, child_cleanup_probe: Some(cleanup))
}

/// Fail request-supervisor startup before spawning for deterministic lifecycle tests.
/// Production configurations use the guarded native spawn below.
@internal
pub fn with_request_supervisor_start_probe(
  config config: Config,
  start start: fn() -> Result(Nil, error.Error),
) -> Config {
  Config(..config, request_supervisor_start_probe: Some(start))
}

/// Refuse the next native stream open at a deterministic synchronization point.
/// Production configurations never install this test-only probe.
@internal
pub fn with_stream_open_refusal_probe(
  config config: Config,
  probe probe: fn() -> Result(Bool, Nil),
) -> Config {
  Config(..config, stream_open_refusal_probe: Some(probe))
}

/// Replace native stream termination only for deterministic recovery tests.
/// `True` means a terminal native result; every other result requires closing and joining the physical connection owner.
@internal
pub fn with_native_cleanup_probe(
  config config: Config,
  probe probe: fn() -> Result(Bool, Nil),
) -> Config {
  Config(..config, native_cleanup_probe: Some(probe))
}

/// Pause immediately before the global request admission is synchronously returned.
/// This test-only synchronization point makes publication ordering observable without relying on scheduler timing.
@internal
pub fn with_request_lease_release_probe(
  config config: Config,
  probe probe: fn() -> Nil,
) -> Config {
  Config(..config, request_lease_release_probe: Some(probe))
}

/// Payload-free owner liveness observation for recovery fixtures.
@internal
pub fn connection_owner_is_alive(connection: Connection) -> Bool {
  process.is_alive(connection.owner)
}

/// Establish a connection after the caller reserved global admission.
/// The adoption callback transfers that reservation to this private owner.
pub fn connect(
  config: Config,
  host: String,
  port: Int,
  adopt: fn(Pid) -> Result(fn() -> Nil, error.Error),
) -> Result(Connection, error.Error) {
  connect_to(config, host, port, port, adopt)
}

/// Dial an authenticated origin's alternate port without changing authority.
fn connect_to(
  config: Config,
  host: String,
  port: Int,
  endpoint_port: Int,
  adopt: fn(Pid) -> Result(fn() -> Nil, error.Error),
) -> Result(Connection, error.Error) {
  connect_to_managed(config, host, port, endpoint_port, fn(owner, _) {
    adopt(owner)
  })
}

/// Establish a connection whose lifecycle registration retains the typed capability used to ask this owner to close gracefully.
@internal
pub fn connect_to_managed(
  config: Config,
  host: String,
  port: Int,
  endpoint_port: Int,
  adopt: fn(Pid, CloseHandle) -> Result(fn() -> Nil, error.Error),
) -> Result(Connection, error.Error) {
  let ready = process.new_subject()
  let result = process.new_subject()
  let caller = process.self()
  let owner =
    process.spawn_unlinked(fn() {
      process_role.set(process_role.Http3ConnectionOwner)
      process.trap_exits(True)
      let begin = process.new_subject()
      let commands = process.new_subject()
      process.send(ready, #(begin, new_http3_close_handle(commands)))
      case process.receive(begin, within: cleanup_milliseconds) {
        Error(Nil) -> Nil
        Ok(cleanup) ->
          open_owned_connection(
            config,
            host,
            port,
            endpoint_port,
            caller,
            result,
            commands,
            cleanup,
          )
      }
    })
  let monitor = process.monitor(owner)
  let connected = {
    use #(begin, close_handle) <- result.try(
      process.receive(ready, within: cleanup_milliseconds)
      |> result.map_error(unavailable_owner),
    )
    use cleanup <- result.try(adopt(owner, close_handle))
    process.send(begin, cleanup)
    case
      process.new_selector()
      |> process.select_map(result, fn(outcome) { outcome })
      |> process.select_specific_monitor(monitor, fn(_) {
        Error(error.new(error.Cancelled))
      })
      |> process.selector_receive(within: config.connect_milliseconds)
    {
      Ok(Ok(#(connection, accepted))) -> {
        process.send(accepted, Nil)
        Ok(connection)
      }
      Ok(Error(failure)) -> Error(failure)
      Error(Nil) -> Error(error.new(error.Timeout(error.Connect)))
    }
  }
  process.demonitor_process(monitor)
  case connected {
    Ok(connection) -> Ok(connection)
    Error(failure) -> {
      let _joined = terminate_within(owner, cleanup_milliseconds)
      Error(failure)
    }
  }
}

/// Shut down the owner and join it.
/// Native ownership closes QUIC on owner exit.
pub fn close(connection: Connection) -> Nil {
  let monitor = process.monitor(connection.owner)
  let deadline = now() + 5 * cleanup_milliseconds
  process.send(connection.commands, Close(deadline))
  case join(monitor, int.max(0, deadline - now())) {
    True -> Nil
    False -> {
      let _joined = terminate_within(connection.owner, cleanup_milliseconds)
      Nil
    }
  }
}

@internal
pub fn await_owner_exit_before(
  connection connection: Connection,
  deadline deadline: Int,
) -> Result(Nil, error.Error) {
  use <- bool.guard(
    when: join(process.monitor(connection.owner), int.max(0, deadline - now())),
    return: Ok(Nil),
  )
  Error(error.new(error.Timeout(error.Total)))
}

/// Ask the connection owner whether a future request stream may still be opened.
/// A positive answer is advisory because GOAWAY can race the next stream-open operation; callers must continue to treat that operation as authoritative.
pub fn connection_reusable(
  connection: Connection,
) -> Result(Bool, error.Error) {
  native.connection_reusable(connection.native)
  |> result.map_error(map_error)
}

fn open_owned_connection(
  config: Config,
  host: String,
  port: Int,
  endpoint_port: Int,
  caller: Pid,
  reply: Subject(Result(#(Connection, Subject(Nil)), error.Error)),
  commands: Subject(OwnerCommand),
  release: fn() -> Nil,
) -> Nil {
  case native.connect_to(config.native, host, port, endpoint_port) {
    Error(failure) -> process.send(reply, Error(map_error(failure)))
    Ok(native) -> {
      let connection =
        Connection(
          native,
          process.self(),
          commands,
          case config.shared_resources {
            Some(resources) -> resources
            None -> resource.start(config.limits)
          },
          config,
        )
      publish_connection(connection: connection, caller: caller, reply: reply)
    }
  }
  let _released =
    cleanup_result(fn() {
      case guarded(release) {
        Ok(Nil) -> Ok(Nil)
        Error(Nil) -> Error(error.new(error.Service))
      }
    })
  Nil
}

fn publish_connection(
  connection connection: Connection,
  caller caller: Pid,
  reply reply: Subject(Result(#(Connection, Subject(Nil)), error.Error)),
) -> Nil {
  let accepted = process.new_subject()
  let caller_monitor = process.monitor(caller)
  process.send(reply, Ok(#(connection, accepted)))
  let published =
    process.new_selector()
    |> process.select_map(accepted, fn(_) { True })
    |> process.select_specific_monitor(caller_monitor, fn(_) { False })
    |> process.selector_receive(within: cleanup_milliseconds)
  process.demonitor_process(caller_monitor)
  case published {
    Ok(True) ->
      owner_loop(
        connection.native,
        connection.commands,
        connection.resources,
        [],
        connection.config,
      )
    _ -> {
      let _closed = native.close(connection.native)
      Nil
    }
  }
}

// nolint: label_possible -- the private owner advances its fixed state in order.
fn owner_loop(
  connection: native.Connection,
  commands: Subject(OwnerCommand),
  resources: resource.Controller,
  workers: List(Worker),
  config: Config,
) -> Nil {
  let selected =
    process.new_selector()
    |> process.select_map(commands, OwnerCommand)
    |> process.select_monitors(WorkerDown)
    |> process.selector_receive(within: config.idle_milliseconds)
  case selected {
    Ok(OwnerCommand(Track(pid, worker_commands, accepted))) -> {
      process.send(accepted, Nil)
      owner_loop(
        connection,
        commands,
        resources,
        [Worker(pid, process.monitor(pid), worker_commands), ..workers],
        config,
      )
    }
    Ok(WorkerDown(process.ProcessDown(pid: pid, ..))) -> {
      let workers =
        list.filter(workers, fn(worker) { retain_live_worker(worker, pid) })
      owner_loop(connection, commands, resources, workers, config)
    }
    Ok(WorkerDown(process.PortDown(..))) ->
      owner_loop(connection, commands, resources, workers, config)
    Ok(OwnerCommand(Close(deadline))) ->
      close_owned_connection(
        connection: connection,
        resources: resources,
        workers: workers,
        config: config,
        deadline: deadline,
      )
    Error(Nil) if workers != [] ->
      owner_loop(connection, commands, resources, workers, config)
    Error(Nil) ->
      close_owned_connection(
        connection: connection,
        resources: resources,
        workers: workers,
        config: config,
        deadline: now() + 5 * cleanup_milliseconds,
      )
  }
}

fn close_owned_connection(
  connection connection: native.Connection,
  resources resources: resource.Controller,
  workers workers: List(Worker),
  config config: Config,
  deadline deadline: Int,
) -> Nil {
  case config.shared_resources {
    None -> resource.stop(resources)
    Some(_) -> Nil
  }
  list.each(workers, fn(worker) { process.send(worker.commands, Cancel(None)) })
  list.each(workers, fn(worker) {
    case join(worker.monitor, int.max(0, deadline - now())) {
      True -> Nil
      False -> process.kill(worker.pid)
    }
  })
  let _closed =
    native.close_within(
      connection: connection,
      within_milliseconds: int.max(1, deadline - now() - 50),
    )
  Nil
}

fn retain_live_worker(worker: Worker, exited: Pid) -> Bool {
  worker.pid != exited
}

// The detached reaper is created before request work and captures the only global admission lease.
// Local processes must be monitored by it before their start gate opens.
// It can therefore finish recovery after the public request deadline, after its controller has stopped, or after the request coordinator itself has exited.
fn new_request_lease_reaper(
  connection connection: Connection,
  source source: body.Body,
  lease lease: resource.Lease,
  request_deadline request_deadline: Int,
) -> Result(LeaseReaper, error.Error) {
  let prepared = process.new_subject()
  let accepted = process.new_subject()
  let parent = process.self()
  case
    guarded(fn() {
      process.spawn_unlinked(fn() {
        run_request_lease_reaper(
          connection: connection,
          source: source,
          lease: lease,
          request_deadline: request_deadline,
          parent: parent,
          prepared: prepared,
          accepted: accepted,
        )
      })
    })
  {
    Error(Nil) -> {
      resource.release(lease)
      Error(error.new(error.Service))
    }
    Ok(pid) -> {
      let monitor = process.monitor(pid)
      let started =
        process.new_selector()
        |> process.select_map(prepared, fn(event) { event })
        |> process.select_specific_monitor(monitor, fn(_) { LeaseReaperExited })
        |> process.selector_receive(within: lease_reaper_start_wait(
          request_deadline: request_deadline,
          current: now(),
        ))
      case started {
        Ok(LeaseReaperPrepared(commands, begin)) -> {
          process.demonitor_process(monitor)
          Ok(LeaseReaper(pid:, commands:, begin:, accepted:))
        }
        Ok(LeaseReaperExited) -> {
          process.demonitor_process(monitor)
          resource.release(lease)
          Error(error.new(error.Service))
        }
        Error(Nil) -> {
          release_failed_reaper(
            pid: pid,
            monitor: monitor,
            lease: lease,
            request_deadline: request_deadline,
          )
          Error(error.new(error.Timeout(error.Operation)))
        }
      }
    }
  }
}

fn release_failed_reaper(
  pid pid: Pid,
  monitor monitor: Monitor,
  lease lease: resource.Lease,
  request_deadline request_deadline: Int,
) -> Nil {
  use <- bool.guard(
    when: !terminate_with_monitor_within(
      pid: pid,
      monitor: monitor,
      milliseconds: lease_reaper_start_wait(
        request_deadline: request_deadline,
        current: now(),
      ),
    ),
    return: Nil,
  )
  resource.release(lease)
}

fn run_request_lease_reaper(
  connection connection: Connection,
  source source: body.Body,
  lease lease: resource.Lease,
  request_deadline request_deadline: Int,
  parent parent: Pid,
  prepared prepared: Subject(LeaseReaperStart),
  accepted accepted: Subject(Nil),
) -> Nil {
  process_role.set(process_role.Http3RequestReaper)
  let commands = process.new_subject()
  let begin = process.new_subject()
  let parent_monitor = process.monitor(parent)
  process.send(prepared, LeaseReaperPrepared(commands, begin))
  let started =
    process.new_selector()
    |> process.select_map(begin, fn(_) { Ok(Nil) })
    |> process.select_specific_monitor(parent_monitor, fn(_) { Error(Nil) })
    |> process.selector_receive(within: lease_reaper_start_wait(
      request_deadline: request_deadline,
      current: now(),
    ))
  let started = case started {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(Nil)
  }
  case started {
    Ok(Nil) -> process.send(accepted, Nil)
    Error(Nil) -> Nil
  }
  lease_reaper_loop(LeaseReaperRuntime(
    commands:,
    lease:,
    source:,
    connection:,
    parent:,
    tracked: [],
    plan: case started {
      Ok(Nil) -> None
      Error(Nil) -> Some(RecoveryPlan(True, True, None))
    },
    release_confirmation: None,
    plan_deadline: request_deadline
      + response_pull_cleanup_milliseconds
      + 3
      * cleanup_milliseconds,
    source_cancel_started: False,
    physical_close_deadline: None,
    physical_owner_down: False,
  ))
  process.demonitor_process(parent_monitor)
}

fn begin_request_lease_reaper(
  reaper reaper: LeaseReaper,
  adopt_lease adopt_lease: Option(fn(Pid) -> Result(Nil, error.Error)),
  deadline deadline: Int,
) -> Result(Nil, error.Error) {
  let adopted = case adopt_lease {
    None -> Ok(Nil)
    Some(adopt) ->
      case guarded(fn() { adopt(reaper.pid) }) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
  }
  process.send(reaper.begin, Nil)
  let started =
    process.receive(
      reaper.accepted,
      within: lease_reaper_start_wait(
        request_deadline: deadline,
        current: now(),
      ),
    )
  case adopted, started {
    Error(failure), _ -> Error(failure)
    Ok(Nil), Ok(Nil) -> Ok(Nil)
    Ok(Nil), Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

/// Keep lease-reaper startup inside the one cleanup allowance derived from the request's original absolute deadline.
/// A scheduler stall after the request deadline consumes this allowance instead of granting a fresh one.
@internal
pub fn lease_reaper_start_wait(
  request_deadline request_deadline: Int,
  current current: Int,
) -> Int {
  int.max(0, request_deadline + cleanup_milliseconds - current)
}

fn track_request_coordinator(
  reaper reaper: LeaseReaper,
  pid pid: Pid,
  deadline deadline: Int,
) -> Result(Nil, error.Error) {
  let accepted = process.new_subject()
  process.send(reaper.commands, TrackCoordinator(pid, accepted))
  process.receive(accepted, within: int.max(0, deadline - now()))
  |> result.map_error(unavailable_owner)
}

fn track_local_process(
  reaper: LeaseReaper,
  registration_deadline: Int,
) -> Result(Nil, error.Error) {
  let accepted = process.new_subject()
  process.send(reaper.commands, TrackLocal(process.self(), accepted))
  process.receive(
    accepted,
    within: local_process_registration_wait(
      deadline: registration_deadline,
      current: now(),
    ),
  )
  |> result.map_error(unavailable_owner)
}

@internal
pub fn local_process_registration_wait(
  deadline deadline: Int,
  current current: Int,
) -> Int {
  int.max(0, deadline - current)
}

fn settle_request_lease(
  reaper: LeaseReaper,
  plan: RecoveryPlan,
) -> Result(Nil, error.Error) {
  let released = process.new_subject()
  process.send(reaper.commands, Settle(plan, process.self(), released))
  case process.receive(released, within: cleanup_milliseconds) {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn lease_reaper_loop(runtime: LeaseReaperRuntime) -> Nil {
  let runtime = advance_lease_recovery(runtime)
  case lease_recovery_complete(runtime) {
    True -> finish_lease_recovery(runtime)
    False -> {
      let selected =
        process.new_selector()
        |> process.select_map(runtime.commands, LeaseReaperCommand)
        |> process.select_monitors(LeaseReaperDown)
        |> process.selector_receive(within: lease_reaper_wait(runtime))
      case selected {
        Ok(LeaseReaperCommand(command)) ->
          lease_reaper_loop(handle_lease_reaper_command(runtime, command))
        Ok(LeaseReaperDown(down)) ->
          lease_reaper_loop(handle_lease_reaper_down(runtime, down))
        Error(Nil) -> lease_reaper_loop(runtime)
      }
    }
  }
}

fn advance_lease_recovery(runtime: LeaseReaperRuntime) -> LeaseReaperRuntime {
  let runtime = case runtime.plan, now() >= runtime.plan_deadline {
    None, True ->
      LeaseReaperRuntime(..runtime, plan: Some(RecoveryPlan(True, True, None)))
    _, _ -> runtime
  }
  let runtime = case runtime.plan, runtime.source_cancel_started {
    Some(RecoveryPlan(dispose_source: True, ..)), False ->
      case body.await_release(runtime.source, 0) {
        body.Released(_) ->
          LeaseReaperRuntime(..runtime, source_cancel_started: True)
        body.ReleasePending -> {
          let _outcome =
            body.cancel_within(runtime.source, cleanup_milliseconds)
          LeaseReaperRuntime(..runtime, source_cancel_started: True)
        }
      }
    _, _ -> runtime
  }
  let runtime = case
    runtime.plan,
    runtime.physical_close_deadline,
    runtime.physical_owner_down
  {
    Some(RecoveryPlan(drain_physical: True, ..)), None, False -> {
      let deadline = now() + 5 * cleanup_milliseconds
      let _owner_monitor = process.monitor(runtime.connection.owner)
      process.send(runtime.connection.commands, Close(deadline))
      LeaseReaperRuntime(..runtime, physical_close_deadline: Some(deadline))
    }
    _, _, _ -> runtime
  }
  let current = now()
  case
    runtime.physical_close_deadline,
    runtime.physical_owner_down,
    process.is_alive(runtime.connection.owner)
  {
    Some(deadline), False, True if deadline > 0 && current >= deadline -> {
      process.kill(runtime.connection.owner)
      LeaseReaperRuntime(..runtime, physical_close_deadline: Some(0))
    }
    _, _, _ -> runtime
  }
}

fn lease_recovery_complete(runtime: LeaseReaperRuntime) -> Bool {
  case runtime.plan {
    None -> False
    Some(RecoveryPlan(dispose_source:, drain_physical:, ..)) -> {
      let source_complete = case dispose_source {
        False -> True
        True ->
          case body.await_release(runtime.source, 0) {
            body.Released(_) -> True
            body.ReleasePending -> False
          }
      }
      let physical_complete = !drain_physical || runtime.physical_owner_down
      request_lease_recovery_ready(
        local_processes_down: runtime.tracked == [],
        body_released: source_complete,
        physical_terminal: physical_complete,
      )
    }
  }
}

fn finish_lease_recovery(runtime: LeaseReaperRuntime) -> Nil {
  case runtime.connection.config.request_lease_release_probe {
    None -> Nil
    Some(probe) -> {
      let _observed = guarded(probe)
      Nil
    }
  }
  resource.release(runtime.lease)
  let plan_accepted = case runtime.plan {
    Some(_) -> True
    None -> False
  }
  case
    request_lease_publication_ready(
      plan_accepted: plan_accepted,
      global_lease_released: True,
    ),
    runtime.release_confirmation
  {
    True, Some(released) -> process.send(released, Ok(Nil))
    _, _ -> Nil
  }
  case runtime.plan {
    Some(RecoveryPlan(
      deferred_reply: Some(ReturnUnstarted(replied, failure, source)),
      ..,
    )) -> process.send(replied, Ok(RequestUnstarted(failure, source)))
    _ -> Nil
  }
}

/// A settlement command transfers recovery ownership, but is not evidence that the global request admission has been returned.
/// Success may be published only after the synchronous resource release has completed.
@internal
pub fn request_lease_publication_ready(
  plan_accepted plan_accepted: Bool,
  global_lease_released global_lease_released: Bool,
) -> Bool {
  plan_accepted && global_lease_released
}

/// The three independent ownership proofs required before the detached actor returns the global request admission.
/// Kept as a small mutation seam so each omitted barrier is detected without timing a real scheduler race.
@internal
pub fn request_lease_recovery_ready(
  local_processes_down local_processes_down: Bool,
  body_released body_released: Bool,
  physical_terminal physical_terminal: Bool,
) -> Bool {
  local_processes_down && body_released && physical_terminal
}

/// Decide whether an uncertain cleanup must close the physical HTTP/3 owner.
/// A semantic success without process/publication proof is never reusable.
@internal
pub fn request_recovery_requires_drain(
  local_cleanup_confirmed local_cleanup_confirmed: Bool,
  native_terminal native_terminal: Bool,
  publication_confirmed publication_confirmed: Bool,
) -> Bool {
  !{ local_cleanup_confirmed && native_terminal && publication_confirmed }
}

fn lease_reaper_wait(runtime: LeaseReaperRuntime) -> Int {
  let poll = 50
  case runtime.plan, runtime.physical_close_deadline {
    None, _ -> int.min(poll, int.max(0, runtime.plan_deadline - now()))
    Some(_), Some(deadline) if deadline > 0 ->
      int.min(poll, int.max(0, deadline - now()))
    _, _ -> poll
  }
}

fn handle_lease_reaper_command(
  runtime: LeaseReaperRuntime,
  command: LeaseReaperCommand,
) -> LeaseReaperRuntime {
  case command {
    TrackCoordinator(pid, accepted) -> {
      let runtime =
        track_reaper_pid(runtime: runtime, pid: pid, coordinator: True)
      process.send(accepted, Nil)
      runtime
    }
    TrackLocal(pid, accepted) -> {
      let runtime =
        track_reaper_pid(runtime: runtime, pid: pid, coordinator: False)
      process.send(accepted, Nil)
      runtime
    }
    Settle(plan, coordinator, released) ->
      case runtime.plan {
        None ->
          LeaseReaperRuntime(
            ..runtime,
            // Once settlement is accepted the coordinator performs no more resource-owning work.
            // Retiring it from the completion barrier lets it wait for the post-release terminal without deadlocking recovery on its own DOWN signal.
            tracked: list.filter(runtime.tracked, fn(entry) {
              !{ entry.coordinator && entry.pid == coordinator }
            }),
            plan: Some(plan),
            release_confirmation: Some(released),
          )
        Some(_) -> {
          process.send(released, Error(error.new(error.Service)))
          runtime
        }
      }
  }
}

fn track_reaper_pid(
  runtime runtime: LeaseReaperRuntime,
  pid pid: Pid,
  coordinator coordinator: Bool,
) -> LeaseReaperRuntime {
  use <- bool.guard(
    when: list.any(runtime.tracked, fn(entry) { entry.pid == pid }),
    return: runtime,
  )
  let _monitor = process.monitor(pid)
  LeaseReaperRuntime(..runtime, tracked: [
    TrackedLocal(pid:, coordinator:),
    ..runtime.tracked
  ])
}

fn handle_lease_reaper_down(
  runtime: LeaseReaperRuntime,
  down: process.Down,
) -> LeaseReaperRuntime {
  case down {
    process.PortDown(..) -> runtime
    process.ProcessDown(pid: pid, ..) -> {
      let coordinator_down =
        list.any(runtime.tracked, fn(entry) {
          entry.pid == pid && entry.coordinator
        })
      let plan = case runtime.plan, pid == runtime.parent || coordinator_down {
        None, True -> Some(RecoveryPlan(True, True, None))
        plan, _ -> plan
      }
      LeaseReaperRuntime(
        ..runtime,
        tracked: list.filter(runtime.tracked, fn(entry) { entry.pid != pid }),
        plan:,
        physical_owner_down: runtime.physical_owner_down
          || pid == runtime.connection.owner,
      )
    }
  }
}

/// Open one stream exactly once and return final headers without waiting for a stalled upload.
/// Native admission and a memory grant precede its workers.
pub fn exchange(
  connection: Connection,
  outgoing: Request(body.Body),
  total_deadline: Int,
  released: fn() -> Nil,
) -> Result(Response(body.Body), error.Error) {
  exchange_observed(connection, outgoing, total_deadline, released, None)
}

/// Attach one attempt's observation without retaining it in a pooled connection.
pub fn exchange_observed(
  connection: Connection,
  outgoing: Request(body.Body),
  total_deadline: Int,
  released: fn() -> Nil,
  trace: Option(client_trace.Trace),
) -> Result(Response(body.Body), error.Error) {
  case
    exchange_observed_with_routing(
      connection,
      outgoing,
      total_deadline,
      fn() {
        released()
        Ok(Nil)
      },
      None,
      None,
      trace,
    )
  {
    Ok(ResponseStarted(incoming)) -> Ok(incoming)
    Ok(RequestUnstarted(failure, source)) -> {
      body.cancel(source)
      Error(failure)
    }
    Error(failure) -> Error(failure)
  }
}

/// Adopt a logical shared-connection lease into the request reaper before any request work, including stream open, can begin.
@internal
pub fn exchange_observed_with_lease_adoption(
  connection: Connection,
  outgoing: Request(body.Body),
  total_deadline: Int,
  released: fn() -> Result(Nil, error.Error),
  adopt_lease: fn(Pid) -> Result(Nil, error.Error),
  trace: Option(client_trace.Trace),
) -> Result(Response(body.Body), error.Error) {
  case
    exchange_observed_with_routing(
      connection,
      outgoing,
      total_deadline,
      released,
      None,
      Some(adopt_lease),
      trace,
    )
  {
    Ok(ResponseStarted(incoming)) -> Ok(incoming)
    Ok(RequestUnstarted(failure, source)) -> {
      body.cancel(source)
      Error(failure)
    }
    Error(failure) -> Error(failure)
  }
}

/// Preserve a Body when the authoritative native stream open reports that the peer did not accept new work.
/// The typed unstarted result is published only after `retire_unstarted` and all local request resources are confirmed.
@internal
pub fn exchange_observed_routable(
  connection connection: Connection,
  outgoing outgoing: Request(body.Body),
  total_deadline total_deadline: Int,
  released released: fn() -> Nil,
  retire_unstarted retire_unstarted: fn() -> Result(Nil, error.Error),
  trace trace: Option(client_trace.Trace),
) -> Result(RoutedResponse, error.Error) {
  exchange_observed_with_routing(
    connection,
    outgoing,
    total_deadline,
    fn() {
      released()
      Ok(Nil)
    },
    Some(retire_unstarted),
    None,
    trace,
  )
}

/// Preserve a replayable request on an authoritative stream-open refusal while adopting the shared physical connection's logical lease into the request reaper before opening that stream.
@internal
pub fn exchange_observed_routable_with_lease_adoption(
  connection connection: Connection,
  outgoing outgoing: Request(body.Body),
  total_deadline total_deadline: Int,
  released released: fn() -> Result(Nil, error.Error),
  retire_unstarted retire_unstarted: fn() -> Result(Nil, error.Error),
  adopt_lease adopt_lease: fn(Pid) -> Result(Nil, error.Error),
  trace trace: Option(client_trace.Trace),
) -> Result(RoutedResponse, error.Error) {
  exchange_observed_with_routing(
    connection,
    outgoing,
    total_deadline,
    released,
    Some(retire_unstarted),
    Some(adopt_lease),
    trace,
  )
}

fn exchange_observed_with_routing(
  connection: Connection,
  outgoing: Request(body.Body),
  total_deadline: Int,
  released: fn() -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  adopt_lease: Option(fn(Pid) -> Result(Nil, error.Error)),
  trace: Option(client_trace.Trace),
) -> Result(RoutedResponse, error.Error) {
  let deadline =
    request_operation_deadline(
      config: connection.config,
      total_deadline: total_deadline,
      current: now(),
    )
  case deadline > now() {
    False ->
      release_unstarted_exchange(
        outgoing.body,
        connection.config.source_cleanup,
        released,
        trace,
        None,
        error.new(error.Timeout(error.Total)),
      )
      |> result.map(ResponseStarted)
    True ->
      admit_exchange(
        connection,
        outgoing,
        deadline,
        released,
        retire_unstarted,
        adopt_lease,
        trace,
      )
  }
}

/// Clamp a request by its own total deadline and the connection's stable per-operation policy, independently of the original connection budget.
@internal
pub fn request_operation_deadline(
  config config: Config,
  total_deadline total_deadline: Int,
  current current: Int,
) -> Int {
  int.min(total_deadline, current + config.operation_milliseconds)
}

fn admit_exchange(
  connection: Connection,
  outgoing: Request(body.Body),
  deadline: Int,
  released: fn() -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  adopt_lease: Option(fn(Pid) -> Result(Nil, error.Error)),
  trace: Option(client_trace.Trace),
) -> Result(RoutedResponse, error.Error) {
  client_trace.phase_started(trace, diagnostics.ResourceAdmission)
  let acquired =
    resource.acquire(
      connection.resources,
      memory_bytes: connection.config.pull_bytes,
    )
  client_trace.phase_finished(
    trace,
    diagnostics.ResourceAdmission,
    result.map(acquired, fn(_) { Nil }),
  )
  case acquired {
    Error(failure) ->
      release_unstarted_exchange(
        outgoing.body,
        connection.config.source_cleanup,
        released,
        trace,
        None,
        failure,
      )
      |> result.map(ResponseStarted)
    Ok(lease) ->
      start_admitted_exchange(
        connection,
        outgoing,
        deadline,
        released,
        retire_unstarted,
        adopt_lease,
        trace,
        lease,
      )
  }
}

fn start_admitted_exchange(
  connection: Connection,
  outgoing: Request(body.Body),
  deadline: Int,
  released: fn() -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  adopt_lease: Option(fn(Pid) -> Result(Nil, error.Error)),
  trace: Option(client_trace.Trace),
  lease: resource.Lease,
) -> Result(RoutedResponse, error.Error) {
  case
    new_request_lease_reaper(
      connection: connection,
      source: outgoing.body,
      lease: lease,
      request_deadline: deadline,
    )
  {
    Error(failure) ->
      release_unstarted_exchange(
        outgoing.body,
        connection.config.source_cleanup,
        released,
        trace,
        None,
        failure,
      )
      |> result.map(ResponseStarted)
    Ok(lease_reaper) ->
      start_prepared_exchange(
        connection,
        outgoing,
        deadline,
        released,
        retire_unstarted,
        adopt_lease,
        trace,
        lease_reaper,
      )
  }
}

fn start_prepared_exchange(
  connection: Connection,
  outgoing: Request(body.Body),
  deadline: Int,
  released: fn() -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  adopt_lease: Option(fn(Pid) -> Result(Nil, error.Error)),
  trace: Option(client_trace.Trace),
  lease_reaper: LeaseReaper,
) -> Result(RoutedResponse, error.Error) {
  let replied = process.new_subject()
  let cleanup_completed = new_once()
  let response_cleanup = cleanup_result.new()
  let caller = process.self()
  let retain_unstarted = case retire_unstarted {
    Some(_) -> True
    None -> False
  }
  let work = fn() {
    let guardian = process.self()
    supervise_request(
      lease_reaper,
      released,
      retire_unstarted,
      replied,
      outgoing.body,
      connection.config.source_cleanup,
      fn(source, completed, lease_reaper) {
        begin_request(
          connection: connection,
          outgoing: request.set_body(outgoing, source),
          replied: replied,
          guardian: guardian,
          caller: caller,
          deadline: deadline,
          completed: completed,
          retain_unstarted: retain_unstarted,
          trace: trace,
          lease_reaper: lease_reaper,
          response_cleanup: response_cleanup,
        )
      },
      deadline,
      trace,
      cleanup_completed,
      response_cleanup,
    )
  }
  case
    begin_request_lease_reaper(
      reaper: lease_reaper,
      adopt_lease: adopt_lease,
      deadline: deadline,
    )
  {
    Error(failure) ->
      release_unstarted_exchange(
        outgoing.body,
        connection.config.source_cleanup,
        released,
        trace,
        Some(lease_reaper),
        failure,
      )
      |> result.map(ResponseStarted)
    Ok(Nil) ->
      case
        start_request_supervisor(
          connection.config,
          work,
          lease_reaper,
          deadline,
        )
      {
        Error(failure) ->
          release_unstarted_exchange(
            outgoing.body,
            connection.config.source_cleanup,
            released,
            trace,
            Some(lease_reaper),
            failure,
          )
          |> result.map(ResponseStarted)
        Ok(pid) ->
          await_started_exchange(
            pid: pid,
            replied: replied,
            deadline: deadline,
            trace: trace,
            cleanup_completed: cleanup_completed,
          )
      }
  }
}

fn start_request_supervisor(
  config: Config,
  work: fn() -> Nil,
  lease_reaper: LeaseReaper,
  deadline: Int,
) -> Result(Pid, error.Error) {
  use _ <- result.try(case config.request_supervisor_start_probe {
    None -> Ok(Nil)
    Some(probe) ->
      case guarded(probe) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
  })
  let prepared = process.new_subject()
  case
    guarded(fn() {
      process.spawn_unlinked(fn() {
        process_role.set(process_role.Http3RequestReaper)
        let gate = process.new_subject()
        process.send(prepared, RequestSupervisorPrepared(gate))
        case process.receive(gate, within: int.max(0, deadline - now())) {
          Ok(True) -> work()
          Ok(False) | Error(Nil) -> Nil
        }
      })
    })
  {
    Error(Nil) -> Error(error.new(error.Service))
    Ok(pid) -> {
      let monitor = process.monitor(pid)
      let start =
        process.new_selector()
        |> process.select_map(prepared, fn(event) { event })
        |> process.select_specific_monitor(monitor, fn(_) {
          RequestSupervisorExited
        })
        |> process.selector_receive(within: int.max(0, deadline - now()))
      case start {
        Ok(RequestSupervisorPrepared(gate)) ->
          finish_request_supervisor_start(
            pid: pid,
            monitor: monitor,
            gate: gate,
            lease_reaper: lease_reaper,
            deadline: deadline,
          )
        Ok(RequestSupervisorExited) -> {
          process.demonitor_process(monitor)
          Error(error.new(error.Service))
        }
        Error(Nil) -> {
          let _terminated =
            terminate_with_monitor_within(
              pid: pid,
              monitor: monitor,
              milliseconds: cleanup_milliseconds,
            )
          Error(error.new(error.Timeout(error.Operation)))
        }
      }
    }
  }
}

fn finish_request_supervisor_start(
  pid pid: Pid,
  monitor monitor: Monitor,
  gate gate: Subject(Bool),
  lease_reaper lease_reaper: LeaseReaper,
  deadline deadline: Int,
) -> Result(Pid, error.Error) {
  case
    track_request_coordinator(
      reaper: lease_reaper,
      pid: pid,
      deadline: deadline,
    )
  {
    Ok(Nil) -> {
      process.send(gate, True)
      process.demonitor_process(monitor)
      Ok(pid)
    }
    Error(failure) -> {
      process.send(gate, False)
      let _terminated =
        terminate_with_monitor_within(
          pid: pid,
          monitor: monitor,
          milliseconds: cleanup_milliseconds,
        )
      Error(failure)
    }
  }
}

fn terminate_with_monitor_within(
  pid pid: Pid,
  monitor monitor: Monitor,
  milliseconds milliseconds: Int,
) -> Bool {
  process.kill(pid)
  join(monitor, milliseconds)
}

fn await_started_exchange(
  pid pid: Pid,
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  deadline deadline: Int,
  trace trace: Option(client_trace.Trace),
  cleanup_completed cleanup_completed: Once,
) -> Result(RoutedResponse, error.Error) {
  let monitor = process.monitor(pid)
  let received =
    process.new_selector()
    |> process.select_map(replied, StartedExchangeReply)
    |> process.select_specific_monitor(monitor, fn(_) {
      StartedExchangeGuardianDown
    })
    |> process.selector_receive(within: int.max(0, deadline - now()))
  case received {
    Ok(StartedExchangeReply(Ok(RequestUnstarted(_, source)) as outcome)) ->
      case
        join(monitor, cleanup_milliseconds) && was_claimed(cleanup_completed)
      {
        True -> outcome
        False -> {
          let _terminated = terminate_within(pid, cleanup_milliseconds)
          let _disposed = body.cancel_within(source, cleanup_milliseconds)
          Error(error.new(error.Timeout(error.Operation)))
        }
      }
    Ok(StartedExchangeReply(Error(failure))) -> {
      process.demonitor_process(monitor)
      await_failed_started_exchange(
        guardian: pid,
        replied: replied,
        trace: trace,
        cleanup_completed: cleanup_completed,
        failure: failure,
      )
    }
    Ok(StartedExchangeReply(outcome)) -> {
      process.demonitor_process(monitor)
      outcome
    }
    Ok(StartedExchangeGuardianDown) ->
      await_started_exchange_after_guardian_down(
        replied: replied,
        trace: trace,
        cleanup_completed: cleanup_completed,
      )
    Error(Nil) ->
      await_start_timeout_cleanup(
        guardian: pid,
        monitor: monitor,
        replied: replied,
        trace: trace,
        cleanup_completed: cleanup_completed,
      )
  }
}

fn await_started_exchange_after_guardian_down(
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  trace trace: Option(client_trace.Trace),
  cleanup_completed cleanup_completed: Once,
) -> Result(RoutedResponse, error.Error) {
  case process.receive(replied, within: cleanup_milliseconds) {
    Ok(Ok(RequestUnstarted(_, source)) as outcome) ->
      case was_claimed(cleanup_completed) {
        True -> outcome
        False -> {
          let _disposed = body.cancel_within(source, cleanup_milliseconds)
          let failure = error.new(error.Timeout(error.Operation))
          client_trace.finished_if_missing(
            trace,
            Some(context.Http3),
            Error(failure),
          )
          Error(failure)
        }
      }
    Ok(Ok(ResponseStarted(_)) as outcome) -> outcome
    Ok(Error(failure)) -> {
      client_trace.finished_if_missing(
        trace,
        Some(context.Http3),
        Error(failure),
      )
      Error(failure)
    }
    Error(Nil) -> {
      let failure = error.new(error.Service)
      client_trace.finished_if_missing(
        trace,
        Some(context.Http3),
        Error(failure),
      )
      Error(failure)
    }
  }
}

fn await_failed_started_exchange(
  guardian guardian: Pid,
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  trace trace: Option(client_trace.Trace),
  cleanup_completed cleanup_completed: Once,
  failure failure: error.Error,
) -> Result(RoutedResponse, error.Error) {
  let joined = join(process.monitor(guardian), 3 * cleanup_milliseconds)
  case joined && was_claimed(cleanup_completed) {
    True -> {
      client_trace.finished_if_missing(
        trace,
        Some(context.Http3),
        Error(failure),
      )
      discard_late_started_reply(replied)
      Error(failure)
    }
    False ->
      quarantine_unconfirmed_started(
        guardian: guardian,
        replied: replied,
        trace: trace,
        original_failure: failure,
      )
  }
}

/// A pre-header deadline does not return request ownership while its coordinator can still publish a response.
/// Coordinator DOWN plus the completion bit means either cleanup completed or the already-running detached lease reaper took sole responsibility for every remaining proof.
/// If that handoff expires, an untrappable stop is safe because the detached actor monitored the coordinator before its start gate opened.
fn await_start_timeout_cleanup(
  guardian guardian: Pid,
  monitor monitor: Monitor,
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  trace trace: Option(client_trace.Trace),
  cleanup_completed cleanup_completed: Once,
) -> Result(RoutedResponse, error.Error) {
  let total_failure = error.new(error.Timeout(error.Total))
  case join(monitor, 3 * cleanup_milliseconds) {
    True ->
      case was_claimed(cleanup_completed) {
        True -> {
          client_trace.finished_if_missing(
            trace,
            Some(context.Http3),
            Error(total_failure),
          )
          discard_late_started_reply(replied)
          Error(total_failure)
        }
        False ->
          quarantine_unconfirmed_started(
            guardian: guardian,
            replied: replied,
            trace: trace,
            original_failure: total_failure,
          )
      }
    False ->
      quarantine_unconfirmed_started(
        guardian: guardian,
        replied: replied,
        trace: trace,
        original_failure: total_failure,
      )
  }
}

fn quarantine_unconfirmed_started(
  guardian guardian: Pid,
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  trace trace: Option(client_trace.Trace),
  original_failure original_failure: error.Error,
) -> Result(RoutedResponse, error.Error) {
  let cleanup_failure = error.new(error.Timeout(error.Operation))
  case process.is_alive(guardian) {
    True -> {
      let _stopped = terminate_within(guardian, cleanup_milliseconds)
      Nil
    }
    False -> Nil
  }
  client_trace.finished_if_missing(
    trace,
    Some(context.Http3),
    Error(original_failure),
  )
  client_trace.cleanup_failed_if_missing(
    trace: trace,
    protocol: Some(context.Http3),
    failure: cleanup_failure,
  )
  discard_late_started_reply(replied)
  Error(original_failure)
}

fn discard_late_started_reply(
  replied: Subject(Result(RoutedResponse, error.Error)),
) -> Nil {
  case process.receive(replied, within: 0) {
    Ok(Ok(ResponseStarted(incoming))) -> body.cancel(incoming.body)
    Ok(Ok(RequestUnstarted(_, source))) -> body.cancel(source)
    Ok(Error(_)) | Error(Nil) -> Nil
  }
}

fn release_unstarted_exchange(
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
  released: fn() -> Result(Nil, error.Error),
  trace: Option(client_trace.Trace),
  lease_reaper: Option(LeaseReaper),
  failure: error.Error,
) -> Result(Response(body.Body), error.Error) {
  client_trace.finished(trace, Some(context.Http3), Error(failure))
  client_trace.phase_started(trace, diagnostics.ResourceRelease)
  let cleanup = case lease_reaper {
    None -> {
      let source_outcome = cleanup_source_untracked(source, source_cleanup)
      let publication = publish_release_untracked(released)
      combine_cleanup(source_outcome, publication)
    }
    Some(reaper) -> {
      let source_proof = cleanup_source(reaper, source, source_cleanup)
      let source_proof = require_body_release_proof(source, source_proof)
      let publication = case cleanup_proof_is_success(source_proof) {
        True -> publish_release(reaper, released)
        False -> terminated_cleanup(source_proof.outcome)
      }
      let proof = combine_cleanup_proofs(source_proof, publication)
      combine_cleanup(
        proof.outcome,
        settle_request_lease(
          reaper,
          RecoveryPlan(
            dispose_source: True,
            drain_physical: request_recovery_requires_drain(
              local_cleanup_confirmed: cleanup_proof_is_success(source_proof),
              native_terminal: True,
              publication_confirmed: cleanup_proof_is_success(publication),
            ),
            deferred_reply: None,
          ),
        ),
      )
    }
  }
  client_trace.phase_finished(trace, diagnostics.ResourceRelease, cleanup)
  client_trace.released(trace, Some(context.Http3), cleanup)
  Error(failure)
}

fn supervise_request(
  lease_reaper: LeaseReaper,
  released: fn() -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  replied: Subject(Result(RoutedResponse, error.Error)),
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
  work: fn(body.Body, Subject(RequestCompletion), LeaseReaper) -> Nil,
  deadline: Int,
  trace: Option(client_trace.Trace),
  cleanup_completed: Once,
  response_cleanup: cleanup_result.Completion,
) -> Nil {
  // Cleanup helpers stay linked to this coordinator.
  // The detached lease reaper independently monitors each helper before its start gate opens.
  process.trap_exits(True)
  let completed = process.new_subject()
  let worker_result = process.new_subject()
  let #(worker, monitor) =
    spawn_tracked_work(
      lease_reaper,
      deadline,
      fn() {
        process_role.set(process_role.Http3RequestWorker)
        work(source, completed, lease_reaper)
        Ok(Nil)
      },
      worker_result,
    )
  let worker_cleanup = case
    join(
      monitor,
      request_worker_join_wait(request_deadline: deadline, current: now()),
    )
  {
    True -> terminated_cleanup(Ok(Nil))
    False -> {
      let joined =
        terminate_within(
          worker,
          request_worker_termination_wait(
            request_deadline: deadline,
            current: now(),
          ),
        )
      CleanupProof(
        outcome: Error(error.new(error.Timeout(error.Operation))),
        pending: case joined {
          True -> []
          False -> [worker]
        },
      )
    }
  }
  let #(request_cleanup, native_proof, response_release_ack, source_disposition) = case
    process.receive(completed, within: 0)
  {
    Ok(RequestCompletion(outcome, native, response_release_ack, disposition)) -> #(
      outcome,
      native,
      response_release_ack,
      disposition,
    )
    Error(Nil) -> {
      let failure = error.new(error.Service)
      client_trace.finished(trace, Some(context.Http3), Error(failure))
      #(
        terminated_cleanup(Error(failure)),
        NativeDrainRequired,
        None,
        DisposeSource(Some(context.Http3)),
      )
    }
  }
  let local_cleanup = combine_cleanup_proofs(worker_cleanup, request_cleanup)
  client_trace.phase_started(trace, diagnostics.ResourceRelease)
  let #(cleanup_before_settlement, source_retained, recovery) = case
    source_disposition
  {
    DisposeSource(_) ->
      dispose_completed_source(
        local_cleanup,
        native_proof,
        source,
        source_cleanup,
        released,
        lease_reaper,
      )
    RetainUnstarted(_) ->
      retire_before_source_reuse(
        local_cleanup,
        native_proof,
        source,
        source_cleanup,
        retire_unstarted,
        lease_reaper,
      )
  }
  let release_protocol = case source_disposition {
    DisposeSource(protocol) -> protocol
    RetainUnstarted(_) -> None
  }
  let recovery = case
    source_disposition,
    source_retained,
    cleanup_before_settlement
  {
    RetainUnstarted(failure), True, Ok(Nil) ->
      RecoveryPlan(
        ..recovery,
        deferred_reply: Some(ReturnUnstarted(replied, failure, source)),
      )
    _, _, _ -> recovery
  }
  let settlement = settle_request_lease(lease_reaper, recovery)
  let cleanup = combine_cleanup(cleanup_before_settlement, settlement)
  cleanup_result.complete(response_cleanup, cleanup)
  client_trace.phase_finished(trace, diagnostics.ResourceRelease, cleanup)
  client_trace.released(trace, release_protocol, cleanup)
  case result.is_ok(settlement) {
    True -> {
      let _recorded = claim_once(cleanup_completed)
      Nil
    }
    False -> Nil
  }
  send_response_release_ack(response_release_ack, cleanup)
  case source_disposition, source_retained, cleanup {
    // The lease reaper returns a reusable source only after its global admission has been synchronously released.
    // This preserves max-one admission pools across immediate protocol reroutes.
    RetainUnstarted(_), True, Ok(Nil) -> Nil
    RetainUnstarted(_), _, Error(failure) ->
      process.send(replied, Error(failure))
    _, _, _ -> Nil
  }
  Nil
}

/// Keep the request worker's cooperative and forced joins inside one plan derived from the original request deadline.
/// These seams are public only to internal mutation tests.
@internal
pub fn request_worker_join_wait(
  request_deadline request_deadline: Int,
  current current: Int,
) -> Int {
  int.max(0, request_deadline + 3 * cleanup_milliseconds - current)
}

@internal
pub fn request_worker_termination_wait(
  request_deadline request_deadline: Int,
  current current: Int,
) -> Int {
  int.max(0, request_deadline + 4 * cleanup_milliseconds - current)
}

fn dispose_completed_source(
  local_cleanup: CleanupProof,
  native_proof: NativeProof,
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
  released: fn() -> Result(Nil, error.Error),
  lease_reaper: LeaseReaper,
) -> #(Result(Nil, error.Error), Bool, RecoveryPlan) {
  let source_proof = cleanup_source(lease_reaper, source, source_cleanup)
  let source_proof = require_body_release_proof(source, source_proof)
  let local_cleanup = combine_cleanup_proofs(local_cleanup, source_proof)
  let native_terminal = native_proof != NativeDrainRequired
  let publication = case
    cleanup_proof_is_success(local_cleanup) && native_terminal
  {
    True -> publish_release(lease_reaper, released)
    False -> terminated_cleanup(local_cleanup.outcome)
  }
  let cleanup = combine_cleanup_proofs(local_cleanup, publication)
  let drain =
    request_recovery_requires_drain(
      local_cleanup_confirmed: cleanup_proof_is_success(local_cleanup),
      native_terminal: native_terminal,
      publication_confirmed: cleanup_proof_is_success(publication),
    )
  #(
    cleanup.outcome,
    False,
    RecoveryPlan(
      dispose_source: True,
      drain_physical: drain,
      deferred_reply: None,
    ),
  )
}

fn retire_before_source_reuse(
  local_cleanup: CleanupProof,
  native_proof: NativeProof,
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
  retire_unstarted: Option(fn() -> Result(Nil, error.Error)),
  lease_reaper: LeaseReaper,
) -> #(Result(Nil, error.Error), Bool, RecoveryPlan) {
  let retirement = case retire_unstarted {
    None -> terminated_cleanup(Error(error.new(error.Service)))
    Some(retire) ->
      tracked_cleanup_result(lease_reaper, fn() {
        case guarded(retire) {
          Ok(outcome) -> outcome
          Error(Nil) -> Error(error.new(error.Service))
        }
      })
  }
  let cleanup = combine_cleanup_proofs(local_cleanup, retirement)
  let safe =
    cleanup_proof_is_success(cleanup) && native_proof == NativeNotStarted
  case safe {
    True -> #(
      Ok(Nil),
      True,
      RecoveryPlan(
        dispose_source: False,
        drain_physical: False,
        deferred_reply: None,
      ),
    )
    False -> {
      let source_cleanup = cleanup_source(lease_reaper, source, source_cleanup)
      let source_cleanup = require_body_release_proof(source, source_cleanup)
      let failed = combine_cleanup_proofs(cleanup, source_cleanup)
      #(
        failed.outcome,
        False,
        RecoveryPlan(
          dispose_source: True,
          drain_physical: True,
          deferred_reply: None,
        ),
      )
    }
  }
}

fn cleanup_source(
  lease_reaper: LeaseReaper,
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
) -> CleanupProof {
  let configured =
    tracked_cleanup_result(lease_reaper, fn() {
      case guarded(fn() { source_cleanup(source, cleanup_milliseconds) }) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
    })
  case body.await_release(source, 0) {
    body.Released(outcome) ->
      combine_cleanup_proofs(configured, terminated_cleanup(outcome))
    body.ReleasePending -> {
      // A test probe or failed adapter callback may not have claimed the Body.
      // The authoritative fallback is independently supervised by Body itself;
      // this helper only supplies a finite foreground observation.
      let authoritative =
        tracked_cleanup_result(lease_reaper, fn() {
          body.cancel_within(source, cleanup_milliseconds)
        })
      combine_cleanup_proofs(configured, authoritative)
    }
  }
}

fn cleanup_source_untracked(
  source: body.Body,
  source_cleanup: fn(body.Body, Int) -> Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let configured =
    untracked_cleanup_result(fn() {
      case guarded(fn() { source_cleanup(source, cleanup_milliseconds) }) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
    })
  let authoritative = case body.await_release(source, 0) {
    body.Released(outcome) -> terminated_cleanup(outcome)
    body.ReleasePending ->
      untracked_cleanup_result(fn() {
        body.cancel_within(source, cleanup_milliseconds)
      })
  }
  let proof = combine_cleanup_proofs(configured, authoritative)
  let proof = require_body_release_proof(source, proof)
  retain_pending_cleanup(proof.pending)
  proof.outcome
}

fn publish_release(
  lease_reaper: LeaseReaper,
  released: fn() -> Result(Nil, error.Error),
) -> CleanupProof {
  tracked_cleanup_result(lease_reaper, fn() {
    case guarded(released) {
      Ok(outcome) -> outcome
      Error(Nil) -> Error(error.new(error.Service))
    }
  })
}

fn publish_release_untracked(
  released: fn() -> Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  cleanup_result(fn() {
    case guarded(released) {
      Ok(outcome) -> outcome
      Error(Nil) -> Error(error.new(error.Service))
    }
  })
}

fn require_body_release_proof(
  source: body.Body,
  proof: CleanupProof,
) -> CleanupProof {
  case body.await_release(source, 0), result.is_error(proof.outcome) {
    body.Released(_), _ -> proof
    body.ReleasePending, True -> proof
    body.ReleasePending, False ->
      CleanupProof(
        ..proof,
        outcome: Error(error.new(error.Timeout(error.Operation))),
      )
  }
}

fn send_response_release_ack(
  acknowledgement: Option(Subject(Result(Nil, error.Error))),
  cleanup: Result(Nil, error.Error),
) -> Nil {
  case acknowledgement {
    Some(reply) -> process.send(reply, cleanup)
    None -> Nil
  }
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

fn terminated_cleanup(outcome: Result(Nil, error.Error)) -> CleanupProof {
  CleanupProof(outcome:, pending: [])
}

fn cleanup_proof_is_success(proof: CleanupProof) -> Bool {
  proof.outcome == Ok(Nil) && proof.pending == []
}

fn combine_cleanup_proofs(
  first: CleanupProof,
  second: CleanupProof,
) -> CleanupProof {
  CleanupProof(
    outcome: combine_cleanup(first.outcome, second.outcome),
    pending: list.append(first.pending, second.pending),
  )
}

fn tracked_cleanup_result(
  reaper: LeaseReaper,
  run: fn() -> Result(Nil, error.Error),
) -> CleanupProof {
  let started = now()
  let registration_deadline = started + cleanup_milliseconds
  let completion_deadline = started + 2 * cleanup_milliseconds
  let termination_deadline = started + 3 * cleanup_milliseconds
  let replied = process.new_subject()
  let #(pid, monitor) =
    spawn_tracked_work(reaper, registration_deadline, run, replied)
  case join(monitor, int.max(0, completion_deadline - now())) {
    True ->
      case process.receive(replied, within: 0) {
        Ok(outcome) -> terminated_cleanup(outcome)
        Error(Nil) -> terminated_cleanup(Error(error.new(error.Service)))
      }
    False -> {
      let joined =
        terminate_within(pid, int.max(0, termination_deadline - now()))
      CleanupProof(
        outcome: Error(error.new(error.Timeout(error.Operation))),
        pending: case joined {
          True -> []
          False -> [pid]
        },
      )
    }
  }
}

fn begin_request(
  connection connection: Connection,
  outgoing outgoing: Request(body.Body),
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  guardian guardian: Pid,
  caller caller: Pid,
  deadline deadline: Int,
  completed completed: Subject(RequestCompletion),
  retain_unstarted retain_unstarted: Bool,
  trace trace: Option(client_trace.Trace),
  lease_reaper lease_reaper: LeaseReaper,
  response_cleanup response_cleanup: cleanup_result.Completion,
) -> Nil {
  process.trap_exits(True)
  let accepted = process.new_subject()
  let commands = process.new_subject()
  let owner_monitor = process.monitor(connection.owner)
  process.send(connection.commands, Track(process.self(), commands, accepted))
  case process.receive(accepted, within: cleanup_milliseconds) {
    Error(Nil) -> {
      let failure = error.new(error.Cancelled)
      body.transfer_finished(outgoing.body, Error(failure))
      client_trace.finished(trace, Some(context.Http3), Error(failure))
      process.send(
        completed,
        RequestCompletion(
          terminated_cleanup(Ok(Nil)),
          NativeNotStarted,
          None,
          DisposeSource(Some(context.Http3)),
        ),
      )
      process.send(replied, Error(failure))
    }
    Ok(Nil) ->
      open_request(
        connection: connection,
        outgoing: outgoing,
        replied: replied,
        guardian: guardian,
        caller: caller,
        owner_monitor: owner_monitor,
        commands: commands,
        deadline: deadline,
        completed: completed,
        retain_unstarted: retain_unstarted,
        trace: trace,
        lease_reaper: lease_reaper,
        response_cleanup: response_cleanup,
      )
  }
  process.demonitor_process(owner_monitor)
}

fn open_request(
  connection connection: Connection,
  outgoing outgoing: Request(body.Body),
  replied replied: Subject(Result(RoutedResponse, error.Error)),
  guardian guardian: Pid,
  caller caller: Pid,
  owner_monitor owner_monitor: Monitor,
  commands commands: Subject(Command),
  deadline deadline: Int,
  completed completed: Subject(RequestCompletion),
  retain_unstarted retain_unstarted: Bool,
  trace trace: Option(client_trace.Trace),
  lease_reaper lease_reaper: LeaseReaper,
  response_cleanup response_cleanup: cleanup_result.Completion,
) -> Nil {
  case open_stream(connection, outgoing) {
    Error(failure) ->
      case retain_unstarted && reroutable_open_refusal(failure) {
        True -> {
          let failure = map_error(failure)
          client_trace.finished(trace, None, Error(failure))
          process.send(
            completed,
            RequestCompletion(
              terminated_cleanup(Ok(Nil)),
              NativeNotStarted,
              None,
              RetainUnstarted(failure),
            ),
          )
        }
        False -> {
          let failure = map_error(failure)
          body.transfer_finished(outgoing.body, Error(failure))
          client_trace.finished(trace, Some(context.Http3), Error(failure))
          process.send(
            completed,
            RequestCompletion(
              terminated_cleanup(Ok(Nil)),
              NativeNotStarted,
              None,
              DisposeSource(Some(context.Http3)),
            ),
          )
          process.send(replied, Error(failure))
        }
      }
    Ok(stream) -> {
      client_trace.protocol_selected(trace, context.Http3)
      client_trace.phase_started(
        trace,
        diagnostics.RequestTransmission(context.Http3),
      )
      let uploaded = process.new_subject()
      let received = process.new_subject()
      let terminal_cancelled = new_once()
      let upload =
        spawn_tracked_work(
          lease_reaper,
          deadline,
          fn() { upload(stream, outgoing.body, connection.config, 0) },
          uploaded,
        )
      client_trace.phase_started(
        trace,
        diagnostics.ResponseReception(context.Http3),
      )
      let reader =
        spawn_tracked_work(
          lease_reaper,
          deadline,
          fn() { read_head(stream, 8) },
          received,
        )
      run(Runtime(
        stream:,
        source: outgoing.body,
        commands:,
        uploaded:,
        received:,
        upload: Some(upload),
        reader: Some(reader),
        child_cleanup: terminated_cleanup(Ok(Nil)),
        owner_monitor:,
        caller_monitor: process.monitor(caller),
        lifecycle_monitor: option.map(
          connection.config.lifecycle_owner,
          process.monitor,
        ),
        headers: Some(replied),
        waiting: None,
        pending: <<>>,
        response_bytes: 0,
        deadline:,
        config: connection.config,
        guardian:,
        completed:,
        trace:,
        terminal_cancelled:,
        response_cleanup:,
        lease_reaper:,
      ))
    }
  }
}

fn reroutable_open_refusal(failure: native.Error) -> Bool {
  case failure {
    native.ConnectionDraining | native.RequestRejected -> True
    _ -> False
  }
}

fn open_stream(
  connection: Connection,
  outgoing: Request(body.Body),
) -> Result(native.Stream, native.Error) {
  case connection.config.stream_open_refusal_probe {
    None ->
      native.open_stream(connection.native, request.set_body(outgoing, Nil))
    Some(probe) ->
      case guarded(probe) {
        Ok(Ok(True)) -> Error(native.ConnectionDraining)
        Ok(Ok(False)) ->
          native.open_stream(connection.native, request.set_body(outgoing, Nil))
        Ok(Error(Nil)) | Error(Nil) -> Error(native.InvalidScheme)
      }
  }
}

fn run(runtime: Runtime) -> Nil {
  let selected =
    process.new_selector()
    |> process.select_map(runtime.commands, Command)
    |> process.select_map(runtime.uploaded, Uploaded)
    |> process.select_map(runtime.received, Received)
    |> process.select_specific_monitor(runtime.owner_monitor, fn(_) {
      OwnerDown
    })
    |> process.select_specific_monitor(runtime.caller_monitor, fn(_) {
      CallerDown
    })
    |> select_lifecycle(runtime.lifecycle_monitor, fn() { LifecycleDown })
    |> process.select_monitors(ChildDown)
    |> process.select_trapped_exits(fn(_) { LinkedExit })
    |> process.selector_receive(within: int.max(0, runtime.deadline - now()))
  case selected {
    Error(Nil) -> fail(runtime, error.new(error.Timeout(error.Total)))
    Ok(OwnerDown)
    | Ok(CallerDown)
    | Ok(LifecycleDown)
    | Ok(Command(Cancel(None))) -> fail(runtime, error.new(error.Cancelled))
    Ok(Command(Cancel(Some(response_release_ack)))) ->
      fail_with_response_release_ack(
        runtime: runtime,
        failure: error.new(error.Cancelled),
        response_release_ack: response_release_ack,
      )
    Ok(Uploaded(Error(failure))) -> {
      let upload_cleanup = retire_upload(runtime, Error(failure))
      fail(
        Runtime(
          ..runtime,
          upload: None,
          child_cleanup: combine_cleanup_proofs(
            runtime.child_cleanup,
            upload_cleanup,
          ),
        ),
        failure,
      )
    }
    Ok(Received(Error(failure))) -> fail(runtime, failure)
    Ok(Uploaded(Ok(Nil))) -> {
      let retired = retire_upload(runtime, Ok(Nil))
      let runtime =
        Runtime(
          ..runtime,
          upload: None,
          child_cleanup: combine_cleanup_proofs(runtime.child_cleanup, retired),
        )
      case retired.outcome {
        Ok(Nil) -> run(runtime)
        Error(failure) -> fail(runtime, failure)
      }
    }
    Ok(Received(Ok(incoming))) -> {
      let retired =
        retire_child(
          config: runtime.config,
          lease_reaper: runtime.lease_reaper,
          child: runtime.reader,
        )
      let runtime =
        Runtime(
          ..runtime,
          reader: None,
          child_cleanup: combine_cleanup_proofs(runtime.child_cleanup, retired),
        )
      case retired.outcome {
        Ok(Nil) -> receive_completed(runtime, incoming)
        Error(failure) -> fail(runtime, failure)
      }
    }
    Ok(Command(Read(maximum, reply))) ->
      start_read(runtime: runtime, maximum: maximum, reply: reply)
    Ok(ChildDown(process.ProcessDown(pid: pid, ..))) ->
      handle_request_child_down(runtime, pid)
    Ok(ChildDown(process.PortDown(..))) | Ok(LinkedExit) -> run(runtime)
  }
}

fn handle_request_child_down(runtime: Runtime, pid: Pid) -> Nil {
  case is_child(runtime.upload, pid), is_child(runtime.reader, pid) {
    True, _ ->
      case process.receive(runtime.uploaded, within: 0) {
        Ok(Ok(Nil)) -> {
          client_trace.phase_finished(
            runtime.trace,
            diagnostics.RequestTransmission(context.Http3),
            Ok(Nil),
          )
          run(Runtime(..runtime, upload: None))
        }
        Ok(Error(failure)) -> {
          client_trace.phase_finished(
            runtime.trace,
            diagnostics.RequestTransmission(context.Http3),
            Error(failure),
          )
          fail(Runtime(..runtime, upload: None), failure)
        }
        Error(Nil) -> {
          let failure = error.new(error.Service)
          client_trace.phase_finished(
            runtime.trace,
            diagnostics.RequestTransmission(context.Http3),
            Error(failure),
          )
          fail(Runtime(..runtime, upload: None), failure)
        }
      }
    _, True ->
      case process.receive(runtime.received, within: 0) {
        Ok(Ok(incoming)) ->
          receive_completed(Runtime(..runtime, reader: None), incoming)
        Ok(Error(failure)) -> fail(Runtime(..runtime, reader: None), failure)
        Error(Nil) ->
          fail(Runtime(..runtime, reader: None), error.new(error.Service))
      }
    _, _ -> run(runtime)
  }
}

fn start_read(
  runtime runtime: Runtime,
  maximum maximum: Int,
  reply reply: Subject(Result(body.PullEvent, error.Error)),
) -> Nil {
  case runtime.waiting, runtime.reader {
    None, None -> {
      let reader =
        spawn_tracked_work(
          runtime.lease_reaper,
          runtime.deadline,
          fn() {
            read_body(
              runtime.stream,
              runtime.pending,
              [],
              int.min(maximum, runtime.config.pull_bytes),
              runtime.response_bytes,
              runtime.config.maximum_body_bytes,
            )
          },
          runtime.received,
        )
      run(Runtime(..runtime, reader: Some(reader), waiting: Some(reply)))
    }
    _, _ -> {
      process.send(reply, Error(error.new(error.Resource(error.Queue))))
      run(runtime)
    }
  }
}

fn receive_completed(runtime: Runtime, incoming: Incoming) -> Nil {
  case incoming, runtime.headers, runtime.waiting {
    Head(status, headers), Some(reply), None -> {
      client_trace.headers(runtime.trace, context.Http3, status)
      case
        body.from_pull_with_cleanup(
          response_pull(
            runtime.commands,
            process.self(),
            runtime.guardian,
            runtime.deadline,
            runtime.terminal_cancelled,
          ),
          None,
          None,
          fn() {
            cancel_response_and_wait(
              commands: runtime.commands,
              guardian: runtime.guardian,
              completed: runtime.response_cleanup,
            )
          },
        )
      {
        Error(failure) -> fail(runtime, failure)
        Ok(source) -> {
          process.send(
            reply,
            Ok(ResponseStarted(response.Response(status, headers, source))),
          )
          run(Runtime(..runtime, headers: None))
        }
      }
    }
    Chunk(bytes, pending, total), None, Some(reply) -> {
      process.send(
        reply,
        Ok(body.PullData(
          bytes,
          response_pull(
            runtime.commands,
            process.self(),
            runtime.guardian,
            runtime.deadline,
            runtime.terminal_cancelled,
          ),
        )),
      )
      run(Runtime(..runtime, waiting: None, pending:, response_bytes: total))
    }
    Finished(trailers), None, Some(reply) -> {
      let cancelled = error.new(error.Cancelled)
      case runtime.upload {
        Some(_) -> body.transfer_finished(runtime.source, Error(cancelled))
        None -> Nil
      }
      let upload_cleanup = retire_upload(runtime, Error(cancelled))
      let child_cleanup =
        combine_cleanup_proofs(runtime.child_cleanup, upload_cleanup)
      client_trace.phase_finished(
        runtime.trace,
        diagnostics.ResponseReception(context.Http3),
        Ok(Nil),
      )
      client_trace.finished(runtime.trace, Some(context.Http3), Ok(Nil))
      let #(native_cleanup, native_proof) = cancel_native_stream(runtime)
      process.send(
        runtime.completed,
        RequestCompletion(
          combine_cleanup_proofs(child_cleanup, native_cleanup),
          native_proof,
          None,
          DisposeSource(Some(context.Http3)),
        ),
      )
      process.send(reply, Ok(body.PullEnd(trailers)))
      process.demonitor_process(runtime.caller_monitor)
      demonitor_lifecycle(runtime.lifecycle_monitor)
    }
    _, _, _ -> fail(runtime, error.new(error.Protocol(error.Http3)))
  }
}

fn fail(runtime: Runtime, failure: error.Error) -> Nil {
  fail_with_ack(runtime: runtime, failure: failure, response_release_ack: None)
}

fn fail_with_response_release_ack(
  runtime runtime: Runtime,
  failure failure: error.Error,
  response_release_ack response_release_ack: Subject(Result(Nil, error.Error)),
) -> Nil {
  fail_with_ack(
    runtime: runtime,
    failure: failure,
    response_release_ack: Some(response_release_ack),
  )
}

fn cancel_native_stream(runtime: Runtime) -> #(CleanupProof, NativeProof) {
  let proof =
    tracked_cleanup_result(runtime.lease_reaper, fn() {
      case runtime.config.native_cleanup_probe {
        None ->
          native.cancel(runtime.stream)
          |> result.map(fn(_) { Nil })
          |> result.map_error(map_error)
        Some(probe) ->
          case guarded(probe) {
            Ok(Ok(True)) -> Ok(Nil)
            Ok(Ok(False)) | Ok(Error(Nil)) | Error(Nil) ->
              Error(error.new(error.Service))
          }
      }
    })
  let native_proof = case cleanup_proof_is_success(proof) {
    True -> NativeStreamTerminal
    False -> NativeDrainRequired
  }
  #(proof, native_proof)
}

fn fail_with_ack(
  runtime runtime: Runtime,
  failure failure: error.Error,
  response_release_ack response_release_ack: Option(
    Subject(Result(Nil, error.Error)),
  ),
) -> Nil {
  case error.kind(failure) {
    error.Cancelled -> {
      let _published = claim_once(runtime.terminal_cancelled)
      Nil
    }
    _ -> Nil
  }
  let upload_cleanup = retire_upload(runtime, Error(failure))
  let child_cleanup =
    combine_cleanup_proofs(
      runtime.child_cleanup,
      combine_cleanup_proofs(
        upload_cleanup,
        retire_child(
          config: runtime.config,
          lease_reaper: runtime.lease_reaper,
          child: runtime.reader,
        ),
      ),
    )
  body.transfer_finished(runtime.source, Error(failure))
  client_trace.phase_finished(
    runtime.trace,
    diagnostics.ResponseReception(context.Http3),
    Error(failure),
  )
  client_trace.finished(runtime.trace, Some(context.Http3), Error(failure))
  let #(native_cleanup, native_proof) = cancel_native_stream(runtime)
  process.send(
    runtime.completed,
    RequestCompletion(
      combine_cleanup_proofs(child_cleanup, native_cleanup),
      native_proof,
      response_release_ack,
      DisposeSource(Some(context.Http3)),
    ),
  )
  case runtime.headers, runtime.waiting {
    Some(reply), _ -> {
      process.send(reply, Error(failure))
      process.demonitor_process(runtime.caller_monitor)
      demonitor_lifecycle(runtime.lifecycle_monitor)
    }
    _, Some(reply) -> {
      process.send(reply, Error(failure))
      process.demonitor_process(runtime.caller_monitor)
      demonitor_lifecycle(runtime.lifecycle_monitor)
    }
    None, None ->
      case error.kind(failure) {
        error.Cancelled -> {
          process.demonitor_process(runtime.caller_monitor)
          demonitor_lifecycle(runtime.lifecycle_monitor)
        }
        _ ->
          terminal(
            runtime.commands,
            runtime.caller_monitor,
            runtime.lifecycle_monitor,
            runtime.deadline,
            failure,
          )
      }
  }
}

// nolint: label_possible -- one terminal continuation retains only bounded control state.
fn terminal(
  commands: Subject(Command),
  caller: Monitor,
  lifecycle: Option(Monitor),
  deadline: Int,
  failure: error.Error,
) -> Nil {
  let selected =
    process.new_selector()
    |> process.select_map(commands, Some)
    |> process.select_specific_monitor(caller, fn(_) { None })
    |> select_lifecycle(lifecycle, fn() { None })
    |> process.selector_receive(within: int.max(0, deadline - now()))
  case selected {
    Ok(Some(Read(_, reply))) -> {
      let failure = case deadline > now() {
        True -> failure
        False -> error.new(error.Timeout(error.Total))
      }
      process.send(reply, Error(failure))
    }
    _ -> Nil
  }
  process.demonitor_process(caller)
  demonitor_lifecycle(lifecycle)
}

// Response disposal is a terminal ownership barrier.
// The coordinator sends its typed acknowledgement only after the detached reaper has synchronously returned the global request admission.
// A successful acknowledgement also means every foreground cleanup proof succeeded; an Error retains its original failure while the detached actor continues safe recovery.
fn cancel_response_and_wait(
  commands commands: Subject(Command),
  guardian guardian: Pid,
  completed completed: cleanup_result.Completion,
) -> Result(Nil, error.Error) {
  let acknowledgement = process.new_subject()
  process.send(commands, Cancel(Some(acknowledgement)))
  case join(process.monitor(guardian), response_pull_cleanup_milliseconds) {
    False -> Error(error.new(error.Timeout(error.Operation)))
    True ->
      case cleanup_result.outcome(completed) {
        Some(outcome) -> outcome
        None -> Error(error.new(error.Service))
      }
  }
}

/// Wait for both the reaper's typed cleanup result and its actual termination.
/// The caller supplies an absolute monotonic deadline so observation work can never extend the allowed cleanup interval.
@internal
pub fn await_response_release_ack(
  guardian guardian: Pid,
  acknowledgement acknowledgement: Subject(Result(Nil, error.Error)),
  deadline deadline: Int,
) -> Result(Nil, error.Error) {
  let reaped =
    join(
      process.monitor(guardian),
      response_pull_wait_milliseconds(deadline: deadline, current: now()),
    )
  case reaped {
    False -> Error(error.new(error.Timeout(error.Operation)))
    True ->
      case process.receive(acknowledgement, within: 0) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
  }
}

fn select_lifecycle(
  selector: process.Selector(message),
  monitor: Option(Monitor),
  on_down: fn() -> message,
) -> process.Selector(message) {
  case monitor {
    Some(monitor) ->
      process.select_specific_monitor(selector, monitor, fn(_) { on_down() })
    None -> selector
  }
}

fn demonitor_lifecycle(monitor: Option(Monitor)) -> Nil {
  case monitor {
    Some(monitor) -> process.demonitor_process(monitor)
    None -> Nil
  }
}

// nolint: label_possible -- these private cursor handles are carried together.
fn response_pull(
  commands: Subject(Command),
  worker: Pid,
  guardian: Pid,
  deadline: Int,
  terminal_cancelled: Once,
) -> body.Pull {
  response_pull_with_terminal_marker(
    worker: worker,
    guardian: guardian,
    deadline: deadline,
    cleanup_budget_milliseconds: response_pull_cleanup_milliseconds,
    terminal_cancelled: Some(terminal_cancelled),
    clock: now,
    dispatch_read: fn(maximum, reply) {
      process.send(commands, Read(maximum, reply))
    },
    dispatch_cancel: fn() { process.send(commands, Cancel(None)) },
  )
}

/// Return the one strict selector wait permitted by the total deadline.
@internal
pub fn response_pull_wait_milliseconds(
  deadline deadline: Int,
  current current: Int,
) -> Int {
  int.max(0, deadline - current)
}

/// Replace the clock and command delivery for deterministic deadline tests.
/// Production response bodies always use the private wrapper above.
@internal
pub fn response_pull_with_deadline_probe(
  worker worker: Pid,
  guardian guardian: Pid,
  deadline deadline: Int,
  cleanup_budget_milliseconds cleanup_budget_milliseconds: Int,
  clock clock: fn() -> Int,
  dispatch_read dispatch_read: fn(
    Int,
    Subject(Result(body.PullEvent, error.Error)),
  ) -> Nil,
  dispatch_cancel dispatch_cancel: fn() -> Nil,
) -> body.Pull {
  response_pull_with_terminal_marker(
    worker:,
    guardian:,
    deadline:,
    cleanup_budget_milliseconds:,
    terminal_cancelled: None,
    clock:,
    dispatch_read:,
    dispatch_cancel:,
  )
}

/// Exercise production's one-shot durable cancellation classification without adding a Body owner around the worker/guardian ordering under test.
@internal
pub fn response_pull_once_with_cancelled_marker_probe(
  worker worker: Pid,
  guardian guardian: Pid,
  deadline deadline: Int,
  cleanup_budget_milliseconds cleanup_budget_milliseconds: Int,
  terminal_cancelled terminal_cancelled: Bool,
  clock clock: fn() -> Int,
  dispatch_read dispatch_read: fn(
    Int,
    Subject(Result(body.PullEvent, error.Error)),
  ) -> Nil,
  dispatch_cancel dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  let marker = new_once()
  case terminal_cancelled {
    True -> {
      let _published = claim_once(marker)
      Nil
    }
    False -> Nil
  }
  response_pull_once(
    1,
    worker,
    guardian,
    deadline,
    int.max(
      0,
      int.min(response_pull_cleanup_milliseconds, cleanup_budget_milliseconds),
    ),
    Some(marker),
    clock,
    dispatch_read,
    dispatch_cancel,
  )
}

fn response_pull_with_terminal_marker(
  worker worker: Pid,
  guardian guardian: Pid,
  deadline deadline: Int,
  cleanup_budget_milliseconds cleanup_budget_milliseconds: Int,
  terminal_cancelled terminal_cancelled: Option(Once),
  clock clock: fn() -> Int,
  dispatch_read dispatch_read: fn(
    Int,
    Subject(Result(body.PullEvent, error.Error)),
  ) -> Nil,
  dispatch_cancel dispatch_cancel: fn() -> Nil,
) -> body.Pull {
  let cleanup_budget_milliseconds =
    int.max(
      0,
      int.min(response_pull_cleanup_milliseconds, cleanup_budget_milliseconds),
    )
  let once = new_once()
  body.pull(fn(maximum) {
    use _ <- result.try(require(
      claim_once(once),
      error.new(error.Body(error.NotReplayable)),
    ))
    response_pull_once(
      maximum,
      worker,
      guardian,
      deadline,
      cleanup_budget_milliseconds,
      terminal_cancelled,
      clock,
      dispatch_read,
      dispatch_cancel,
    )
  })
}

fn response_pull_once(
  maximum: Int,
  worker: Pid,
  guardian: Pid,
  deadline: Int,
  cleanup_budget_milliseconds: Int,
  terminal_cancelled: Option(Once),
  clock: fn() -> Int,
  dispatch_read: fn(Int, Subject(Result(body.PullEvent, error.Error))) -> Nil,
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  let reply = process.new_subject()
  let worker_monitor = process.monitor(worker)
  let guardian_monitor = process.monitor(guardian)
  case deadline > clock() {
    False ->
      response_pull_timeout(
        worker,
        worker_monitor,
        guardian,
        guardian_monitor,
        False,
        False,
        reply,
        cleanup_budget_milliseconds,
        terminal_cancelled,
        dispatch_cancel,
      )
    True -> {
      dispatch_read(maximum, reply)
      let received =
        process.new_selector()
        |> process.select_map(reply, ResponsePullReply)
        |> process.select_specific_monitor(worker_monitor, fn(_) {
          ResponsePullWorkerDown
        })
        |> process.select_specific_monitor(guardian_monitor, fn(_) {
          ResponsePullGuardianDown
        })
        |> process.selector_receive(within: response_pull_wait_milliseconds(
          deadline: deadline,
          current: clock(),
        ))
      response_pull_received(
        received,
        worker,
        worker_monitor,
        guardian,
        guardian_monitor,
        deadline,
        cleanup_budget_milliseconds,
        terminal_cancelled,
        clock,
        reply,
        dispatch_cancel,
      )
    }
  }
}

fn response_pull_received(
  received: Result(ResponsePullSelection, Nil),
  worker: Pid,
  worker_monitor: Monitor,
  guardian: Pid,
  guardian_monitor: Monitor,
  deadline: Int,
  cleanup_budget_milliseconds: Int,
  terminal_cancelled: Option(Once),
  clock: fn() -> Int,
  reply: Subject(Result(body.PullEvent, error.Error)),
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  case received {
    Error(Nil) ->
      response_pull_timeout(
        worker,
        worker_monitor,
        guardian,
        guardian_monitor,
        False,
        False,
        reply,
        cleanup_budget_milliseconds,
        terminal_cancelled,
        dispatch_cancel,
      )
    Ok(selection) ->
      case deadline > clock() {
        False -> {
          let #(worker_down, guardian_down) = case selection {
            ResponsePullWorkerDown -> #(True, False)
            ResponsePullGuardianDown -> #(False, True)
            ResponsePullReply(_) -> #(False, False)
          }
          response_pull_timeout(
            worker,
            worker_monitor,
            guardian,
            guardian_monitor,
            worker_down,
            guardian_down,
            reply,
            cleanup_budget_milliseconds,
            terminal_cancelled,
            dispatch_cancel,
          )
        }
        True ->
          response_pull_before_deadline(
            selection,
            worker,
            worker_monitor,
            guardian,
            guardian_monitor,
            reply,
            cleanup_budget_milliseconds,
            terminal_cancelled,
            dispatch_cancel,
          )
      }
  }
}

fn response_pull_before_deadline(
  selection: ResponsePullSelection,
  worker: Pid,
  worker_monitor: Monitor,
  guardian: Pid,
  guardian_monitor: Monitor,
  reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds: Int,
  terminal_cancelled: Option(Once),
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  case selection {
    ResponsePullWorkerDown ->
      response_pull_worker_down(
        worker_monitor,
        guardian,
        guardian_monitor,
        reply,
        cleanup_budget_milliseconds,
        terminal_cancelled,
        dispatch_cancel,
      )
    ResponsePullGuardianDown ->
      response_pull_guardian_down(
        worker,
        worker_monitor,
        guardian_monitor,
        reply,
        cleanup_budget_milliseconds,
        terminal_cancelled,
        dispatch_cancel,
      )
    ResponsePullReply(Ok(body.PullEnd(_)) as outcome)
    | ResponsePullReply(Error(_) as outcome) ->
      await_response_pull_release(
        worker: worker,
        worker_monitor: worker_monitor,
        guardian: guardian,
        guardian_monitor: guardian_monitor,
        reply: reply,
        cleanup_budget_milliseconds: cleanup_budget_milliseconds,
        outcome: outcome,
      )
    ResponsePullReply(outcome) -> {
      process.demonitor_process(worker_monitor)
      process.demonitor_process(guardian_monitor)
      outcome
    }
  }
}

// A process monitor signal is ordered after every earlier signal from the same worker.
// Reconcile a queued terminal reply before classifying an unexpected worker exit, then use a separate finite budget to prove guardian release.
fn response_pull_worker_down(
  worker_monitor: Monitor,
  guardian: Pid,
  guardian_monitor: Monitor,
  reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds: Int,
  terminal_cancelled: Option(Once),
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  process.demonitor_process(worker_monitor)
  let terminal = process.receive(reply, within: 0)
  case terminal {
    Ok(Ok(body.PullEnd(_)) as outcome) | Ok(Error(_) as outcome) ->
      await_response_pull_guardian_release(
        guardian: guardian,
        guardian_monitor: guardian_monitor,
        reply: reply,
        cleanup_budget_milliseconds: cleanup_budget_milliseconds,
        outcome: outcome,
      )
    _ -> {
      dispatch_cancel()
      let cleanup_deadline = now() + cleanup_budget_milliseconds
      let guardian_reaped =
        reap_response_pull_process(
          pid: guardian,
          monitor: guardian_monitor,
          cleanup_deadline: cleanup_deadline,
        )
      discard_response_pull_reply(reply)
      case guardian_reaped {
        True -> terminal_down_failure(terminal_cancelled, error.Service)
        False -> Error(error.new(error.Timeout(error.Operation)))
      }
    }
  }
}

// The worker publishes a terminal reply before it exits, while the guardian's DOWN signal has a different sender.
// Reap the worker first so Erlang's signal ordering makes an already-published terminal reply observable before it is classified as a guardian failure.
fn response_pull_guardian_down(
  worker: Pid,
  worker_monitor: Monitor,
  guardian_monitor: Monitor,
  reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds: Int,
  terminal_cancelled: Option(Once),
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  dispatch_cancel()
  let cleanup_deadline = now() + cleanup_budget_milliseconds
  let worker_reaped =
    reap_response_pull_process(
      pid: worker,
      monitor: worker_monitor,
      cleanup_deadline: cleanup_deadline,
    )
  process.demonitor_process(guardian_monitor)
  let terminal = process.receive(reply, within: 0)
  discard_response_pull_reply(reply)
  case worker_reaped, terminal {
    True, Ok(Ok(body.PullEnd(_)) as outcome) | True, Ok(Error(_) as outcome) ->
      outcome
    True, _ -> terminal_down_failure(terminal_cancelled, error.Cancelled)
    False, _ -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn terminal_down_failure(
  terminal_cancelled: Option(Once),
  legacy: error.ErrorKind,
) -> Result(value, error.Error) {
  case terminal_cancelled {
    Some(marker) ->
      case was_claimed(marker) {
        True -> Error(error.new(error.Cancelled))
        False -> Error(error.new(error.Service))
      }
    None -> Error(error.new(legacy))
  }
}

fn response_pull_timeout(
  worker: Pid,
  worker_monitor: Monitor,
  guardian: Pid,
  guardian_monitor: Monitor,
  worker_down: Bool,
  guardian_down: Bool,
  reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds: Int,
  _terminal_cancelled: Option(Once),
  dispatch_cancel: fn() -> Nil,
) -> Result(body.PullEvent, error.Error) {
  let cleaned =
    cancel_and_reap_response_pull(
      worker,
      worker_monitor,
      guardian,
      guardian_monitor,
      worker_down,
      guardian_down,
      reply,
      cleanup_budget_milliseconds,
      dispatch_cancel,
    )
  case cleaned {
    True -> Error(error.new(error.Timeout(error.Total)))
    False -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn cancel_and_reap_response_pull(
  worker: Pid,
  worker_monitor: Monitor,
  guardian: Pid,
  guardian_monitor: Monitor,
  worker_down: Bool,
  guardian_down: Bool,
  reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds: Int,
  dispatch_cancel: fn() -> Nil,
) -> Bool {
  dispatch_cancel()
  let cleanup_deadline = now() + cleanup_budget_milliseconds
  let worker_reaped = case worker_down {
    True -> {
      process.demonitor_process(worker_monitor)
      True
    }
    False ->
      reap_response_pull_process(
        pid: worker,
        monitor: worker_monitor,
        cleanup_deadline: cleanup_deadline,
      )
  }
  let guardian_reaped = case guardian_down {
    True -> {
      process.demonitor_process(guardian_monitor)
      True
    }
    False ->
      reap_response_pull_process(
        pid: guardian,
        monitor: guardian_monitor,
        cleanup_deadline: cleanup_deadline,
      )
  }
  discard_response_pull_reply(reply)
  worker_reaped && guardian_reaped
}

fn await_response_pull_guardian_release(
  guardian guardian: Pid,
  guardian_monitor guardian_monitor: Monitor,
  reply reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds cleanup_budget_milliseconds: Int,
  outcome outcome: Result(value, error.Error),
) -> Result(value, error.Error) {
  let cleanup_deadline = now() + cleanup_budget_milliseconds
  let guardian_reaped =
    reap_response_pull_process(
      pid: guardian,
      monitor: guardian_monitor,
      cleanup_deadline: cleanup_deadline,
    )
  discard_response_pull_reply(reply)
  case guardian_reaped {
    True -> outcome
    False -> Error(error.new(error.Timeout(error.Operation)))
  }
}

fn await_response_pull_release(
  worker worker: Pid,
  worker_monitor worker_monitor: Monitor,
  guardian guardian: Pid,
  guardian_monitor guardian_monitor: Monitor,
  reply reply: Subject(Result(body.PullEvent, error.Error)),
  cleanup_budget_milliseconds cleanup_budget_milliseconds: Int,
  outcome outcome: Result(value, error.Error),
) -> Result(value, error.Error) {
  let cleanup_deadline = now() + cleanup_budget_milliseconds
  let worker_reaped =
    reap_response_pull_process(
      pid: worker,
      monitor: worker_monitor,
      cleanup_deadline: cleanup_deadline,
    )
  let guardian_reaped =
    reap_response_pull_process(
      pid: guardian,
      monitor: guardian_monitor,
      cleanup_deadline: cleanup_deadline,
    )
  discard_response_pull_reply(reply)
  case worker_reaped && guardian_reaped {
    True -> outcome
    False -> Error(error.new(error.Timeout(error.Operation)))
  }
}

// A forced stop reaps the process but cannot certify its ordered cleanup path.
fn reap_response_pull_process(
  pid pid: Pid,
  monitor monitor: Monitor,
  cleanup_deadline cleanup_deadline: Int,
) -> Bool {
  let remaining =
    response_pull_wait_milliseconds(deadline: cleanup_deadline, current: now())
  let reserve = int.min(cleanup_milliseconds, int.max(0, remaining / 4))
  let graceful = int.max(0, remaining - reserve)
  case join(monitor, graceful) {
    True -> True
    False -> {
      let forced_monitor = process.monitor(pid)
      process.kill(pid)
      let _forced =
        join(
          forced_monitor,
          response_pull_wait_milliseconds(
            deadline: cleanup_deadline,
            current: now(),
          ),
        )
      False
    }
  }
}

fn discard_response_pull_reply(
  reply: Subject(Result(body.PullEvent, error.Error)),
) -> Nil {
  let _discarded = process.receive(reply, within: 0)
  Nil
}

// nolint: label_possible -- recursive upload state advances one cursor and byte count.
fn upload(
  stream: native.Stream,
  source: body.Body,
  config: Config,
  sent: Int,
) -> Result(Nil, error.Error) {
  case body.read(source, config.pull_bytes) {
    Error(failure) -> Error(failure)
    Ok(body.Data(bytes, next)) -> {
      let total = sent + bit_array.byte_size(bytes)
      use _ <- result.try(require(
        total <= config.maximum_body_bytes,
        error.new(error.Body(error.TooLarge(config.maximum_body_bytes))),
      ))
      use _ <- result.try(
        native.send_chunk(stream, bytes) |> result.map_error(map_error),
      )
      upload(stream, next, config, total)
    }
    Ok(body.Done(completed)) -> {
      let sent =
        case body.trailers(completed) {
          Some([_, ..] as trailers) -> native.send_trailers(stream, trailers)
          _ -> native.finish(stream)
        }
        |> result.map_error(map_error)
      body.transfer_finished(source, sent)
      sent
    }
  }
}

fn read_head(
  stream: native.Stream,
  informational_left: Int,
) -> Result(Incoming, error.Error) {
  case native.next_event(stream) {
    Ok(native.Response(status, headers)) -> Ok(Head(status, headers))
    Ok(native.InformationalResponse(..)) if informational_left > 0 ->
      read_head(stream, informational_left - 1)
    Error(failure) -> Error(map_error(failure))
    _ -> Error(error.new(error.Protocol(error.Http3)))
  }
}

// nolint: label_possible -- recursive reader state keeps the wire and retained-byte cursors adjacent.
fn read_body(
  stream: native.Stream,
  pending: BitArray,
  trailers: body.Headers,
  maximum: Int,
  consumed: Int,
  limit: Int,
) -> Result(Incoming, error.Error) {
  case bit_array.byte_size(pending) > 0 {
    True -> {
      let size = bit_array.byte_size(pending)
      let take = int.min(size, maximum)
      use bytes <- result.try(
        bit_array.slice(pending, at: 0, take: take)
        |> result.map_error(invalid_slice),
      )
      use rest <- result.try(
        bit_array.slice(pending, at: take, take: size - take)
        |> result.map_error(invalid_slice),
      )
      Ok(Chunk(bytes, rest, consumed))
    }
    False ->
      case native.next_event(stream) {
        Ok(native.Data(bytes)) -> {
          let total = consumed + bit_array.byte_size(bytes)
          use _ <- result.try(require(
            total <= limit,
            error.new(error.Body(error.TooLarge(limit))),
          ))
          read_body(stream, bytes, trailers, maximum, total, limit)
        }
        Ok(native.Trailers(received)) if trailers == [] ->
          read_body(stream, <<>>, received, maximum, consumed, limit)
        Ok(native.End) -> Ok(Finished(trailers))
        Error(failure) -> Error(map_error(failure))
        _ -> Error(error.new(error.Protocol(error.Http3)))
      }
  }
}

fn spawn_work(
  work: fn() -> Result(value, error.Error),
  reply: Subject(Result(value, error.Error)),
) -> #(Pid, Monitor) {
  let pid =
    process.spawn(fn() {
      process_role.set(process_role.Http3IoWorker)
      let outcome = case guarded(work) {
        Ok(outcome) -> outcome
        Error(Nil) -> Error(error.new(error.Service))
      }
      process.send(reply, outcome)
    })
  #(pid, process.monitor(pid))
}

fn spawn_tracked_work(
  reaper: LeaseReaper,
  registration_deadline: Int,
  work: fn() -> Result(value, error.Error),
  reply: Subject(Result(value, error.Error)),
) -> #(Pid, Monitor) {
  let pid =
    process.spawn(fn() {
      process_role.set(process_role.Http3IoWorker)
      let outcome = case track_local_process(reaper, registration_deadline) {
        Error(failure) -> Error(failure)
        Ok(Nil) ->
          case guarded(work) {
            Ok(outcome) -> outcome
            Error(Nil) -> Error(error.new(error.Service))
          }
      }
      process.send(reply, outcome)
    })
  #(pid, process.monitor(pid))
}

fn is_child(child: Option(#(Pid, Monitor)), pid: Pid) -> Bool {
  case child {
    Some(#(candidate, _)) -> candidate == pid
    None -> False
  }
}

fn stop_child(child: Option(#(Pid, Monitor))) -> CleanupProof {
  case child {
    None -> terminated_cleanup(Ok(Nil))
    Some(#(pid, monitor)) -> {
      process.kill(pid)
      case join(monitor, cleanup_milliseconds) {
        True -> terminated_cleanup(Ok(Nil))
        False ->
          CleanupProof(
            outcome: Error(error.new(error.Timeout(error.Operation))),
            pending: [pid],
          )
      }
    }
  }
}

fn retire_child(
  config config: Config,
  lease_reaper lease_reaper: LeaseReaper,
  child child: Option(#(Pid, Monitor)),
) -> CleanupProof {
  let retired = stop_child(child)
  case child, config.child_cleanup_probe {
    None, _ -> retired
    Some(_), Some(cleanup) -> {
      let observed =
        tracked_cleanup_result(lease_reaper, fn() {
          case guarded(cleanup) {
            Ok(outcome) -> outcome
            Error(Nil) -> Error(error.new(error.Service))
          }
        })
      combine_cleanup_proofs(retired, observed)
    }
    Some(_), None -> retired
  }
}

fn retire_upload(
  runtime: Runtime,
  outcome: Result(Nil, error.Error),
) -> CleanupProof {
  let retired =
    retire_child(
      config: runtime.config,
      lease_reaper: runtime.lease_reaper,
      child: runtime.upload,
    )
  case runtime.upload {
    None -> Nil
    Some(_) ->
      client_trace.phase_finished(
        runtime.trace,
        diagnostics.RequestTransmission(context.Http3),
        combine_cleanup(outcome, retired.outcome),
      )
  }
  retired
}

fn join(monitor: Monitor, milliseconds: Int) -> Bool {
  let received =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: milliseconds)
  process.demonitor_process(monitor)
  received == Ok(Nil)
}

fn cleanup_result(
  run: fn() -> Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let proof = untracked_cleanup_result(run)
  retain_pending_cleanup(proof.pending)
  proof.outcome
}

fn untracked_cleanup_result(
  run: fn() -> Result(Nil, error.Error),
) -> CleanupProof {
  let replied = process.new_subject()
  let #(pid, monitor) = spawn_work(run, replied)
  case join(monitor, cleanup_milliseconds) {
    True ->
      case process.receive(replied, within: 0) {
        Ok(outcome) -> terminated_cleanup(outcome)
        Error(Nil) -> terminated_cleanup(Error(error.new(error.Service)))
      }
    False -> {
      let joined = terminate_within(pid, cleanup_milliseconds)
      CleanupProof(
        outcome: Error(error.new(error.Timeout(error.Operation))),
        pending: case joined {
          True -> []
          False -> [pid]
        },
      )
    }
  }
}

fn retain_pending_cleanup(pending: List(Pid)) -> Nil {
  case pending {
    [] -> Nil
    _ -> {
      let _observer =
        process.spawn_unlinked(fn() {
          process_role.set(process_role.Http3IoWorker)
          list.each(pending, fn(pid) {
            let _monitor = process.monitor(pid)
            Nil
          })
          await_pending_cleanup(pending)
        })
      Nil
    }
  }
}

fn await_pending_cleanup(pending: List(Pid)) -> Nil {
  case pending {
    [] -> Nil
    _ -> {
      let down =
        process.new_selector()
        |> process.select_monitors(fn(value) { value })
        |> process.selector_receive_forever()
      case down {
        process.ProcessDown(pid: pid, ..) ->
          await_pending_cleanup(list.filter(pending, fn(item) { item != pid }))
        process.PortDown(..) -> await_pending_cleanup(pending)
      }
    }
  }
}

fn terminate_within(pid: Pid, milliseconds: Int) -> Bool {
  process.kill(pid)
  join(process.monitor(pid), milliseconds)
}

/// Preserve redacted native failure categories at the package boundary.
/// Kept internal and visible to focused contract tests so changing the peer-unprocessed signal into a generic protocol failure is detected.
@internal
pub fn map_error(failure: native.Error) -> error.Error {
  case failure {
    native.RequestRejected -> error.peer_rejected_before_processing(error.Http3)
    native.Failure(failure) -> failure_adapter.from_runtime(failure)
    native.InvalidBody -> error.new(error.Body(error.InvalidChunk))
    native.RequestBodyTooLarge(limit) | native.ResponseBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    native.ConsumerTooSlow(_) -> error.new(error.Resource(error.Memory))
    _ -> error.new(error.Protocol(error.Http3))
  }
}

fn require(condition: Bool, failure: error.Error) -> Result(Nil, error.Error) {
  use <- bool.guard(when: !condition, return: Error(failure))
  Ok(Nil)
}

fn unavailable_owner(_reason: Nil) -> error.Error {
  error.new(error.Service)
}

fn invalid_slice(_reason: Nil) -> error.Error {
  error.new(error.Protocol(error.Http3))
}
