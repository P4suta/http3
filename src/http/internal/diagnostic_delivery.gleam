//// Completion and process lifetime for one admitted diagnostic sink.

import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/int

const shutdown_margin_milliseconds = 100

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn now() -> Int

type Delivery {
  SinkResult(Result(Result(Nil, Nil), Nil))
  SinkDown
}

/// The finite outcome of one sink delivery and its owned process join.
///
/// `Unconfirmed` means the sink did not acknowledge termination before the shared absolute teardown deadline.
/// Its reporter credit must remain held unless a final bounded reaper observes the process exit.
pub type Outcome {
  Delivered
  Failed
  Unconfirmed
}

/// Await one finite callback result under its already-reserved delivery grant.
pub fn await(
  sink sink: Pid,
  monitor monitor: Monitor,
  completed completed: Subject(Result(Result(Nil, Nil), Nil)),
  milliseconds milliseconds: Int,
) -> Outcome {
  await_with_termination(
    sink: sink,
    monitor: monitor,
    completed: completed,
    milliseconds: milliseconds,
    terminate: terminate_and_join,
  )
}

/// Inject only the payload-free kill/join observation for deterministic tests.
@internal
pub fn await_with_termination(
  sink sink: Pid,
  monitor monitor: Monitor,
  completed completed: Subject(Result(Result(Nil, Nil), Nil)),
  milliseconds milliseconds: Int,
  terminate terminate: fn(Pid, Monitor, Int) -> Bool,
) -> Outcome {
  await_with_clock_and_termination(
    sink: sink,
    monitor: monitor,
    completed: completed,
    milliseconds: milliseconds,
    clock: now,
    terminate: terminate,
  )
}

/// Inject monotonic scalar observations and termination for state tests.
@internal
pub fn await_with_clock_and_termination(
  sink sink: Pid,
  monitor monitor: Monitor,
  completed completed: Subject(Result(Result(Nil, Nil), Nil)),
  milliseconds milliseconds: Int,
  clock clock: fn() -> Int,
  terminate terminate: fn(Pid, Monitor, Int) -> Bool,
) -> Outcome {
  let deadline = clock() + milliseconds
  let teardown_deadline = deadline + shutdown_margin_milliseconds
  let outcome =
    process.new_selector()
    |> process.select_map(completed, SinkResult)
    |> process.select_specific_monitor(monitor, fn(_) { SinkDown })
    |> process.selector_receive(within: milliseconds)
  let delivered = case outcome {
    Ok(SinkResult(result)) ->
      case await_exit(monitor, int.max(0, deadline - clock())) {
        True ->
          case result == Ok(Ok(Nil)) {
            True -> Delivered
            False -> Failed
          }
        False -> {
          case terminate(sink, monitor, teardown_deadline) {
            True -> Failed
            False -> Unconfirmed
          }
        }
      }
    Ok(SinkDown) -> Failed
    Error(Nil) -> {
      case terminate(sink, monitor, teardown_deadline) {
        True -> Failed
        False -> Unconfirmed
      }
    }
  }
  process.demonitor_process(monitor)
  delivered
}

fn await_exit(monitor: Monitor, milliseconds: Int) -> Bool {
  process.new_selector()
  |> process.select_specific_monitor(monitor, fn(_) { Nil })
  |> process.selector_receive(within: milliseconds)
  == Ok(Nil)
}

fn terminate_and_join(
  sink sink: Pid,
  monitor monitor: Monitor,
  deadline_milliseconds deadline_milliseconds: Int,
) -> Bool {
  process.kill(sink)
  await_exit(monitor, int.max(0, deadline_milliseconds - now()))
}

/// Make one final finite observation of an already-killed sink.
pub fn reap(sink sink: Pid, milliseconds milliseconds: Int) -> Bool {
  let monitor = process.monitor(sink)
  let joined = await_exit(monitor, int.max(0, milliseconds))
  process.demonitor_process(monitor)
  joined
}
