//// One bounded body-source worker, retained until transfer disposal.
//// Request uploads and HTTP/1 responses share the same cleanup ownership.
//// Socket ownership and protocol state stay in the adapter process.
//// Only a single bounded pull is outstanding, so peer input can interrupt a stalled source without consuming or replaying the body in another contender.

import gleam/bool
import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import http/body
import http/error
import http/internal/process_role
import http/resource

const cleanup_milliseconds = 1000

type Token

type Observation

// The reaper must distinguish a fully joined upload from an abandoned or crashed guardian.
// Keep this explicit at the FFI boundary: returning `Nil` made every normal upload look like an unconfirmed cleanup and permanently quarantined its resource lease.
type ReaperDisposition {
  ReleaseLease
  QuarantineLease
}

pub type Event {
  Chunk(BitArray)
  End(body.Headers)
  Failed(error.Error)
  SourceDisposed
}

type Command {
  Pull
  Finish(Result(Nil, error.Error))
  Release(Result(Nil, error.Error))
}

type Message {
  Control(Command)
  Returned(Result(body.Read, error.Error))
  ReaderDown
  OwnerDown
}

pub opaque type Upload {
  Upload(
    pid: Pid,
    commands: Subject(Command),
    events: Subject(Event),
    observation: Observation,
  )
}

type Runtime {
  Runtime(
    source: body.Body,
    current: body.Body,
    commands: Subject(Command),
    reports: Subject(Event),
    returned: Subject(Result(body.Read, error.Error)),
    reader: Option(#(Pid, Monitor)),
    owner_monitor: Monitor,
    lifecycle_monitor: Option(Monitor),
    maximum_chunk: Int,
    deadline: Int,
    expiry: error.TimeoutPhase,
    total_deadline: Int,
    source_finished: Bool,
    observation: Observation,
    abandon: fn(error.Error) -> Nil,
  )
}

@external(erlang, "http_server_ffi", "new_token")
fn new_token() -> Token

@external(erlang, "http_server_ffi", "adopt_token")
fn adopt(token: Token) -> Bool

@external(erlang, "http_server_ffi", "worker_subject")
fn command_subject(token: Token, owner: Pid) -> Subject(Command)

@external(erlang, "http_server_ffi", "worker_reports")
fn report_subject(token: Token, owner: Pid) -> Subject(Event)

@external(erlang, "http_server_ffi", "reap_worker")
fn reap(
  token: Token,
  events: Subject(Event),
  run: fn() -> ReaperDisposition,
  release: fn() -> Nil,
) -> Nil

@external(erlang, "http_server_ffi", "run_guarded")
fn guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_server_ffi", "spawn_monitor")
fn spawn_monitor(run: fn() -> Nil) -> #(Pid, Monitor)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn now() -> Int

@external(erlang, "http_upload_ffi", "new_observation")
fn new_observation() -> Observation

@external(erlang, "http_upload_ffi", "set_cleanup")
fn set_cleanup(observation: Observation, code: Int) -> Nil

@external(erlang, "http_upload_ffi", "get_cleanup")
fn get_cleanup(observation: Observation) -> Int

@external(erlang, "http_upload_ffi", "set_failure")
fn set_failure(observation: Observation, code: Int) -> Nil

@external(erlang, "http_upload_ffi", "get_failure")
fn get_failure(observation: Observation) -> Int

@external(erlang, "http_upload_ffi", "flush_events")
fn flush_events(events: Subject(Event)) -> Nil

/// Grant callback memory before spawning either the guardian or its reader.
/// `abandon` closes the connection on owner loss or an independent deadline.
/// `released` runs only after the guardian and every reader have terminated.
pub fn start(
  source source: body.Body,
  maximum_chunk maximum_chunk: Int,
  deadline deadline: Int,
  expiry expiry: error.TimeoutPhase,
  total_deadline total_deadline: Int,
  resources resources: Option(resource.Controller),
  lifecycle_owner lifecycle_owner: Option(Pid),
  abandon abandon: fn(error.Error) -> Nil,
  released released: fn(Result(Nil, error.Error)) -> Nil,
) -> Result(Upload, error.Error) {
  use controller <- result.try(case resources {
    Some(controller) -> Ok(controller)
    None -> resource.limits(1, maximum_chunk) |> result.map(resource.start)
  })
  use lease <- result.try(resource.acquire(controller, maximum_chunk))
  let token = new_token()
  let observation = new_observation()
  let events = process.new_subject()
  let owner = process.self()
  let pid =
    process.spawn_unlinked(fn() {
      let reports = report_subject(token, process.self())
      reap(
        token,
        events,
        fn() {
          case adopt(token) {
            False -> QuarantineLease
            True -> {
              let runtime =
                Runtime(
                  source:,
                  current: source,
                  commands: command_subject(token, process.self()),
                  reports:,
                  returned: process.new_subject(),
                  reader: None,
                  owner_monitor: process.monitor(owner),
                  lifecycle_monitor: monitor_owner(lifecycle_owner),
                  maximum_chunk:,
                  deadline:,
                  expiry:,
                  total_deadline:,
                  source_finished: False,
                  observation:,
                  abandon:,
                )
              loop(runtime)
              ReleaseLease
            }
          }
        },
        fn() {
          resource.release(lease)
          released(cleanup_result(observation))
        },
      )
    })
  Ok(Upload(pid, command_subject(token, pid), events, observation))
}

/// The exchange's single completion subject can share a selective socket read.
pub fn events(upload: Upload) -> Subject(Event) {
  upload.events
}

/// Request exactly one chunk.
/// Protocol flow control decides when to call this.
pub fn request_next(upload: Upload) -> Nil {
  process.send(upload.commands, Pull)
}

/// Dispose the source after the final request frame, or an early response.
/// A failed cleanup remains recorded separately from the transfer outcome.
pub fn finish_source(
  upload upload: Upload,
  outcome outcome: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  process.send(upload.commands, Finish(outcome))
  await_source(upload, now() + cleanup_milliseconds)
}

/// Preserve a protocol failure without delaying immediate socket closure.
/// The ordered release command still joins source cleanup and the guardian.
pub fn fail_source(upload upload: Upload, failure failure: error.Error) -> Nil {
  process.send(upload.commands, Finish(Error(failure)))
}

fn await_source(upload: Upload, deadline: Int) -> Result(Nil, error.Error) {
  case process.receive(upload.events, within: int.max(0, deadline - now())) {
    Ok(SourceDisposed) -> Ok(Nil)
    Ok(Chunk(_)) | Ok(End(_)) -> await_source(upload, deadline)
    Ok(Failed(failure)) -> Error(failure)
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

/// Join the owner before releasing its worker reservation or reporting cleanup.
/// A slow native cleanup may outlive this caller's finite wait; its reaper continues holding capacity and publishes the actual completion afterwards.
pub fn release(
  upload upload: Upload,
  outcome outcome: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let monitor = process.monitor(upload.pid)
  process.send(upload.commands, Release(outcome))
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: cleanup_milliseconds)
  process.demonitor_process(monitor)
  flush_events(upload.events)
  case joined {
    Ok(Nil) -> cleanup_result(upload.observation)
    Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
  }
}

/// Recover an independently observed owner/deadline failure after socket close.
pub fn failure(upload: Upload) -> Option(error.Error) {
  case get_failure(upload.observation) {
    1 -> Some(error.new(error.Cancelled))
    2 -> Some(error.new(error.Timeout(error.Operation)))
    3 -> Some(error.new(error.Timeout(error.Total)))
    4 -> Some(error.new(error.Service))
    _ -> None
  }
}

fn loop(runtime: Runtime) -> Nil {
  let selector =
    process.new_selector()
    |> process.select_map(runtime.commands, Control)
    |> process.select_map(runtime.returned, Returned)
    |> process.select_specific_monitor(runtime.owner_monitor, fn(_) {
      OwnerDown
    })
  let selector = case runtime.lifecycle_monitor {
    None -> selector
    Some(monitor) ->
      process.select_specific_monitor(selector, monitor, fn(_) { OwnerDown })
  }
  let selector = case runtime.reader {
    None -> selector
    Some(#(_, monitor)) ->
      process.select_specific_monitor(selector, monitor, fn(_) { ReaderDown })
  }
  case
    process.selector_receive(
      selector,
      within: int.max(0, runtime.deadline - now()),
    )
  {
    Ok(Control(Pull)) -> start_reader(runtime)
    Ok(Returned(outcome)) -> accept_read(runtime, outcome)
    Ok(ReaderDown) -> {
      process.send(runtime.reports, Failed(error.new(error.Service)))
      loop(Runtime(..runtime, reader: None))
    }
    Ok(Control(Finish(outcome))) -> {
      let runtime = dispose_source(runtime, outcome)
      process.send(runtime.reports, SourceDisposed)
      loop(
        Runtime(
          ..runtime,
          deadline: runtime.total_deadline,
          expiry: error.Total,
        ),
      )
    }
    Ok(Control(Release(outcome))) -> {
      let runtime = dispose_source(runtime, Error(error.new(error.Cancelled)))
      remember_cleanup(runtime.observation, outcome)
    }
    Ok(OwnerDown) -> abandon_runtime(runtime, error.new(error.Cancelled))
    Error(Nil) ->
      abandon_runtime(runtime, error.new(error.Timeout(runtime.expiry)))
  }
}

fn start_reader(runtime: Runtime) -> Nil {
  case runtime.reader, runtime.source_finished {
    None, False -> {
      let #(pid, monitor) =
        spawn_monitor(fn() {
          process_role.set(process_role.UploadReader)
          let outcome = guarded_read(runtime.current, runtime.maximum_chunk)
          process.send(runtime.returned, outcome)
        })
      loop(Runtime(..runtime, reader: Some(#(pid, monitor))))
    }
    _, _ -> abandon_runtime(runtime, error.new(error.Service))
  }
}

fn accept_read(
  runtime: Runtime,
  outcome: Result(body.Read, error.Error),
) -> Nil {
  join_reader(runtime.reader, False)
  let runtime = Runtime(..runtime, reader: None)
  case outcome {
    Error(failure) -> {
      process.send(runtime.reports, Failed(failure))
      loop(runtime)
    }
    Ok(body.Data(bytes, next)) -> {
      process.send(runtime.reports, Chunk(bytes))
      loop(Runtime(..runtime, current: next))
    }
    Ok(body.Done(completed)) -> {
      process.send(
        runtime.reports,
        End(case body.trailers(completed) {
          None -> []
          Some(trailers) -> trailers
        }),
      )
      loop(Runtime(..runtime, current: completed))
    }
  }
}

fn join_reader(reader: Option(#(Pid, Monitor)), kill: Bool) -> Nil {
  case reader {
    None -> Nil
    Some(#(pid, monitor)) -> {
      case kill {
        True -> process.kill(pid)
        False -> Nil
      }
      process.new_selector()
      |> process.select_specific_monitor(monitor, fn(_) { Nil })
      |> process.selector_receive_forever
      process.demonitor_process(monitor)
    }
  }
}

fn dispose_source(
  runtime: Runtime,
  outcome: Result(Nil, error.Error),
) -> Runtime {
  use <- bool.guard(runtime.source_finished, runtime)
  let runtime = stop_reader(runtime)
  body.transfer_finished(runtime.source, outcome)
  let _requested = body.cancel_within(runtime.source, cleanup_milliseconds)
  let cleanup = await_cleanup(runtime.source)
  remember_cleanup(runtime.observation, cleanup)
  Runtime(
    ..runtime,
    source: body.empty(),
    current: body.empty(),
    source_finished: True,
  )
}

fn stop_reader(runtime: Runtime) -> Runtime {
  join_reader(runtime.reader, True)
  case process.receive(runtime.returned, within: 0) {
    Ok(_) | Error(Nil) -> Nil
  }
  Runtime(..runtime, reader: None)
}

fn monitor_owner(owner: Option(Pid)) -> Option(Monitor) {
  case owner {
    None -> None
    Some(pid) -> Some(process.monitor(pid))
  }
}

fn guarded_read(
  source: body.Body,
  maximum: Int,
) -> Result(body.Read, error.Error) {
  case guarded(fn() { body.read(source, maximum) }) {
    Ok(outcome) -> outcome
    Error(Nil) -> Error(error.new(error.Service))
  }
}

fn await_cleanup(source: body.Body) -> Result(Nil, error.Error) {
  case body.await_release(source, 100) {
    body.Released(outcome) -> outcome
    body.ReleasePending -> await_cleanup(source)
  }
}

fn abandon_runtime(runtime: Runtime, failure: error.Error) -> Nil {
  set_failure(runtime.observation, case error.kind(failure) {
    error.Cancelled -> 1
    error.Timeout(error.Operation) -> 2
    error.Timeout(error.Total) -> 3
    _ -> 4
  })
  let runtime = stop_reader(runtime)
  let closed = case guarded(fn() { runtime.abandon(failure) }) {
    Ok(Nil) -> Ok(Nil)
    Error(Nil) -> Error(error.new(error.Service))
  }
  remember_cleanup(runtime.observation, closed)
  let runtime = dispose_source(runtime, Error(failure))
  process.send(runtime.reports, Failed(failure))
}

fn remember_cleanup(
  observation: Observation,
  outcome: Result(Nil, error.Error),
) -> Nil {
  set_cleanup(observation, case outcome {
    Ok(Nil) -> 1
    Error(failure) ->
      case error.kind(failure) {
        error.Timeout(_) -> 2
        error.Cancelled -> 3
        _ -> 4
      }
  })
}

fn cleanup_result(observation: Observation) -> Result(Nil, error.Error) {
  case get_cleanup(observation) {
    1 -> Ok(Nil)
    2 -> Error(error.new(error.Timeout(error.Operation)))
    3 -> Error(error.new(error.Cancelled))
    _ -> Error(error.new(error.Service))
  }
}
