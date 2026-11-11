//// Owned asynchronous DNS and connection attempts around a pure scheduler.
//// Callbacks and runtime handles never cross the public QUIC boundary.

import gleam/erlang/process.{type Monitor, type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order.{type Order}
import gleam/result
import quic_core/internal/runtime/happy_eyeballs as schedule
import quic_core/internal/udp

/// One original total deadline and a separately bounded resolution phase.
pub type Policy {
  Policy(
    owner: Pid,
    ipv4: Bool,
    ipv6: Bool,
    dns_deadline: Int,
    total_deadline: Int,
  )
}

/// Typed dependency injection used by real transport and deterministic tests.
/// Resolver and dial callbacks run only in admitted, supervised children.
pub type Operations(address, value, error) {
  Operations(
    resolve: fn(schedule.Family) -> Result(List(address), error),
    dial: fn(address, Int, Bool) -> Result(value, error),
    adopt: fn(value, Pid) -> Result(value, error),
    discard: fn(value) -> Nil,
    compare: fn(address, address) -> Order,
    prefer_error: fn(error, error) -> error,
    abandon: fn(Int) -> Nil,
    resolution: fn(schedule.Family, schedule.ResolutionOutcome) -> Nil,
    eligible: fn() -> Nil,
    spawn: fn(udp.WorkGroup, udp.WorkKind, fn() -> Nil) -> Result(Pid, Nil),
    cleanup: fn(udp.WorkGroup, Bool, Bool) -> Result(Nil, Nil),
  )
}

/// Fixed phase failures, with a typed candidate cause retained when available.
pub type Failure(error) {
  Rejected(error)
  ResolutionFailed
  DnsTimeout
  TotalTimeout
  OwnerGone
  WorkerLost
  CleanupFailed(primary: Option(Failure(error)))
}

type Decision {
  Adopt
  Cancel
}

type Message(address, value, error) {
  Resolved(schedule.Family, Result(List(address), error), Subject(Nil))
  Failed(Int, error, Subject(Nil))
  Ready(Int, Subject(Decision), value)
  Adopted(Int, Result(value, error), Subject(Nil))
  Released(Int, Subject(Nil))
}

type Work {
  Resolver(schedule.Family)
  Candidate(Int)
}

type Worker {
  Worker(pid: Pid, monitor: Monitor, work: Work)
}

type Event(address, value, error) {
  Message(Message(address, value, error))
  Down(Work)
  OwnerExited
  SupervisorExited
}

type Running(address, value, error) {
  Running(
    policy: Policy,
    operations: Operations(address, value, error),
    scheduler: schedule.State(address),
    group: udp.WorkGroup,
    owner_monitor: Monitor,
    supervisor_monitor: Monitor,
    messages: Subject(Message(address, value, error)),
    workers: List(Worker),
    last_error: Option(error),
    dns_expired: Bool,
    deferred: List(Event(address, value, error)),
    eligible: Bool,
    owns_group: Bool,
    resolver_worker_lost: Bool,
  )
}

/// Resolve independently, launch on demand, adopt once, and join before return.
pub fn run(
  policy: Policy,
  operations: Operations(address, value, error),
) -> Result(value, Failure(error)) {
  use group <- result.try(
    udp.start_work_group(policy.owner) |> result.replace_error(WorkerLost),
  )
  run_group(group, True, policy, operations)
}

/// Use the public bootstrap's admitted group and leave its endpoint owned.
pub fn run_in(
  group: udp.WorkGroup,
  policy: Policy,
  operations: Operations(address, value, error),
) -> Result(value, Failure(error)) {
  run_group(group, False, policy, operations)
}

fn run_group(
  group: udp.WorkGroup,
  owns_group: Bool,
  policy: Policy,
  operations: Operations(address, value, error),
) -> Result(value, Failure(error)) {
  let running =
    Running(
      policy,
      operations,
      schedule.new(
        policy.ipv4,
        policy.ipv6,
        policy.dns_deadline,
        policy.total_deadline,
        operations.compare,
      ),
      group,
      process.monitor(policy.owner),
      process.monitor(udp.work_group_pid(group)),
      process.new_subject(),
      [],
      None,
      False,
      [],
      False,
      owns_group,
      False,
    )
  let running =
    schedule.resolution_order(policy.ipv4, policy.ipv6)
    |> list.fold(running, fn(running, family) {
      start_resolution(running, family)
    })
  loop(running)
}

fn start_resolution(
  running: Running(a, v, e),
  family: schedule.Family,
) -> Running(a, v, e) {
  let messages = running.messages
  let resolve = running.operations.resolve
  let observe = running.operations.resolution
  case
    running.operations.spawn(running.group, udp.ResolverWork, fn() {
      resolve_into(messages, family, resolve, observe)
    })
    |> result.replace_error(Nil)
  {
    Ok(pid) ->
      Running(..running, workers: [
        Worker(pid, process.monitor(pid), Resolver(family)),
        ..running.workers
      ])
    Error(Nil) -> {
      observe(family, schedule.ResolutionStartFailed)
      Running(
        ..running,
        scheduler: schedule.answer(
          running.scheduler,
          family,
          [],
          udp.monotonic_millisecond(),
        ),
        resolver_worker_lost: True,
      )
    }
  }
}

fn resolve_into(
  messages: Subject(Message(a, v, e)),
  family: schedule.Family,
  resolve: fn(schedule.Family) -> Result(List(a), e),
  observe: fn(schedule.Family, schedule.ResolutionOutcome) -> Nil,
) -> Nil {
  observe(family, schedule.ResolutionStarted)
  let result = resolve(family)
  // The full typed resolver failure is forwarded below; this projection is only the bounded, payload-free diagnostic classification.
  observe(family, case result.replace_error(result, Nil) {
    Ok([]) -> schedule.ResolutionEmpty
    Ok(_) -> schedule.ResolutionUsable
    Error(Nil) -> schedule.ResolutionRejected
  })
  let acknowledged = process.new_subject()
  process.send(messages, Resolved(family, result, acknowledged))
  let _acknowledged = process.receive(acknowledged, within: 2000)
  Nil
}

fn loop(running: Running(a, v, e)) -> Result(v, Failure(e)) {
  case running.deferred {
    [observed, ..rest] -> event(Running(..running, deferred: rest), observed)
    [] -> advance(running)
  }
}

fn advance(running: Running(a, v, e)) -> Result(v, Failure(e)) {
  let now = udp.monotonic_millisecond()
  case schedule.next(running.scheduler, now) {
    schedule.TotalExpired -> finish(running, Error(TotalTimeout), None, None)
    schedule.Exhausted -> finish(running, Error(exhausted(running)), None, None)
    schedule.DnsExpired(next) -> {
      case expire_resolvers(running.workers, running.operations) {
        Ok(workers) ->
          loop(
            Running(
              ..running,
              scheduler: next,
              workers: workers,
              dns_expired: True,
            ),
          )
        Error(Nil) -> finish(running, Error(CleanupFailed(None)), None, None)
      }
    }
    schedule.Launch(address, ordinal, next) ->
      launch(Running(..running, scheduler: next), address, ordinal)
    schedule.Wait(until, next) -> {
      let running = Running(..running, scheduler: next)
      case
        process.selector_receive(
          selector(running),
          within: int.max(0, until - now),
        )
      {
        Error(Nil) -> loop(running)
        Ok(observed) -> event(running, observed)
      }
    }
  }
}

fn expire_resolvers(
  workers: List(Worker),
  operations: Operations(a, v, e),
) -> Result(List(Worker), Nil) {
  list.try_fold(workers, [], fn(kept, worker) {
    case worker.work {
      Resolver(family) -> {
        process.kill(worker.pid)
        use Nil <- result.try(join(worker))
        process.demonitor_process(worker.monitor)
        operations.resolution(family, schedule.ResolutionExpired)
        Ok(kept)
      }
      Candidate(_) -> Ok([worker, ..kept])
    }
  })
}

fn selector(running: Running(a, v, e)) -> process.Selector(Event(a, v, e)) {
  let selector =
    process.new_selector()
    |> process.select_map(running.messages, Message)
    |> process.select_specific_monitor(running.owner_monitor, fn(_) {
      OwnerExited
    })
    |> process.select_specific_monitor(running.supervisor_monitor, fn(_) {
      SupervisorExited
    })
  list.fold(running.workers, selector, fn(selector, worker) {
    process.select_specific_monitor(selector, worker.monitor, fn(_) {
      Down(worker.work)
    })
  })
}

fn launch(
  running: Running(a, v, e),
  address: a,
  ordinal: Int,
) -> Result(v, Failure(e)) {
  case running.eligible {
    True -> Nil
    False -> running.operations.eligible()
  }
  let running = Running(..running, eligible: True)
  let operations = running.operations
  let messages = running.messages
  let owner = process.self()
  let deadline = running.policy.total_deadline
  let confirm = schedule.requires_peer_confirmation(running.scheduler)
  case
    running.operations.spawn(running.group, udp.CandidateWork, fn() {
      case operations.dial(address, ordinal, confirm) {
        Error(error) -> {
          let acknowledged = process.new_subject()
          process.send(messages, Failed(ordinal, error, acknowledged))
          let _acknowledged = process.receive(acknowledged, within: 2000)
          Nil
        }
        Ok(value) ->
          offer(value, ordinal, owner, deadline, messages, operations)
      }
    })
    |> result.replace_error(Nil)
  {
    Ok(pid) ->
      loop(
        Running(..running, workers: [
          Worker(pid, process.monitor(pid), Candidate(ordinal)),
          ..running.workers
        ]),
      )
    Error(Nil) -> finish(running, Error(WorkerLost), None, None)
  }
}

fn offer(
  value: v,
  ordinal: Int,
  owner: Pid,
  deadline: Int,
  messages: Subject(Message(a, v, e)),
  operations: Operations(a, v, e),
) -> Nil {
  let decision = process.new_subject()
  // Retain the close capability before asking the candidate to transfer it.
  // Cancellation may occur after OS ownership changes but before Adopted.
  process.send(messages, Ready(ordinal, decision, value))
  case
    process.receive(
      decision,
      within: int.max(0, deadline - udp.monotonic_millisecond()),
    )
  {
    Ok(Adopt) -> {
      let acknowledged = process.new_subject()
      process.send(
        messages,
        Adopted(ordinal, operations.adopt(value, owner), acknowledged),
      )
      Nil
    }
    Ok(Cancel) | Error(Nil) -> {
      operations.discard(value)
      let acknowledged = process.new_subject()
      process.send(messages, Released(ordinal, acknowledged))
      let _acknowledged = process.receive(acknowledged, within: 2000)
      Nil
    }
  }
}

fn event(
  running: Running(a, v, e),
  event: Event(a, v, e),
) -> Result(v, Failure(e)) {
  case event {
    OwnerExited -> finish(running, Error(OwnerGone), None, None)
    SupervisorExited ->
      finish(
        running,
        Error(case process.is_alive(running.policy.owner) {
          True -> WorkerLost
          False -> OwnerGone
        }),
        None,
        None,
      )
    Down(Resolver(family)) -> {
      case retire_down(running, Resolver(family)) {
        None -> loop(running)
        Some(running) -> {
          running.operations.resolution(family, schedule.ResolutionWorkerExited)
          loop(
            Running(
              ..running,
              scheduler: schedule.answer(
                running.scheduler,
                family,
                [],
                udp.monotonic_millisecond(),
              ),
              resolver_worker_lost: True,
            ),
          )
        }
      }
    }
    Down(Candidate(ordinal)) -> {
      case retire_down(running, Candidate(ordinal)) {
        None -> loop(running)
        Some(running) -> {
          running.operations.abandon(ordinal)
          loop(
            Running(
              ..running,
              scheduler: schedule.failed(running.scheduler, ordinal),
            ),
          )
        }
      }
    }
    Message(Resolved(family, resolved, acknowledged)) ->
      handle_resolved(running, family, resolved, acknowledged)
    Message(Failed(ordinal, error, acknowledged)) -> {
      case retire_terminal(running, Candidate(ordinal), acknowledged) {
        Error(Nil) -> finish(running, Error(CleanupFailed(None)), None, None)
        Ok(running) -> {
          running.operations.abandon(ordinal)
          loop(
            Running(
              ..remember(running, error),
              scheduler: schedule.failed(running.scheduler, ordinal),
            ),
          )
        }
      }
    }
    Message(Ready(ordinal, decision, offered)) -> {
      process.send(decision, Adopt)
      await_adoption(running, ordinal, offered)
    }
    Message(Adopted(ordinal, adopted, acknowledged)) ->
      handle_unselected_adoption(running, ordinal, adopted, acknowledged)
    Message(Released(ordinal, acknowledged)) -> {
      case retire_terminal(running, Candidate(ordinal), acknowledged) {
        Error(Nil) -> finish(running, Error(CleanupFailed(None)), None, None)
        Ok(running) -> {
          running.operations.abandon(ordinal)
          loop(
            Running(
              ..running,
              scheduler: schedule.failed(running.scheduler, ordinal),
            ),
          )
        }
      }
    }
  }
}

fn handle_resolved(
  running: Running(a, v, e),
  family: schedule.Family,
  resolved: Result(List(a), e),
  acknowledged: Subject(Nil),
) -> Result(v, Failure(e)) {
  case retire_terminal(running, Resolver(family), acknowledged) {
    Error(Nil) -> finish(running, Error(CleanupFailed(None)), None, None)
    Ok(running) -> {
      let #(addresses, running) = case resolved {
        Ok(addresses) -> #(addresses, running)
        Error(error) -> #([], remember(running, error))
      }
      loop(
        Running(
          ..running,
          scheduler: schedule.answer(
            running.scheduler,
            family,
            addresses,
            udp.monotonic_millisecond(),
          ),
        ),
      )
    }
  }
}

fn handle_unselected_adoption(
  running: Running(a, v, e),
  ordinal: Int,
  adopted: Result(v, e),
  acknowledged: Subject(Nil),
) -> Result(v, Failure(e)) {
  case retire_terminal(running, Candidate(ordinal), acknowledged) {
    Error(Nil) -> {
      let running = case adopted {
        Ok(value) -> {
          running.operations.discard(value)
          running
        }
        Error(error) -> remember(running, error)
      }
      finish(running, Error(CleanupFailed(None)), None, None)
    }
    Ok(running) -> {
      running.operations.abandon(ordinal)
      case adopted {
        Ok(value) -> {
          running.operations.discard(value)
          loop(
            Running(
              ..running,
              scheduler: schedule.failed(running.scheduler, ordinal),
            ),
          )
        }
        Error(error) ->
          loop(
            Running(
              ..remember(running, error),
              scheduler: schedule.failed(running.scheduler, ordinal),
            ),
          )
      }
    }
  }
}

fn await_adoption(
  running: Running(a, v, e),
  ordinal: Int,
  offered: v,
) -> Result(v, Failure(e)) {
  let remaining =
    int.max(0, running.policy.total_deadline - udp.monotonic_millisecond())
  case process.selector_receive(selector(running), within: remaining) {
    Error(Nil) -> finish_offered(running, TotalTimeout, ordinal, offered)
    Ok(Message(Adopted(id, adopted, acknowledged))) if id == ordinal ->
      case retire_terminal(running, Candidate(ordinal), acknowledged) {
        Error(Nil) ->
          finish_offered(running, CleanupFailed(None), ordinal, offered)
        Ok(running) ->
          case adopted {
            Ok(value) -> finish(running, Ok(value), Some(ordinal), None)
            Error(error) -> adoption_failed(running, ordinal, offered, error)
          }
      }
    Ok(OwnerExited) -> finish_offered(running, OwnerGone, ordinal, offered)
    Ok(SupervisorExited) ->
      finish_offered(
        running,
        case process.is_alive(running.policy.owner) {
          True -> WorkerLost
          False -> OwnerGone
        },
        ordinal,
        offered,
      )
    Ok(Down(Candidate(id))) if id == ordinal ->
      finish_offered(running, WorkerLost, ordinal, offered)
    Ok(observed) -> {
      case release_terminal_before_defer(running, observed) {
        Error(Nil) ->
          finish_offered(running, CleanupFailed(None), ordinal, offered)
        Ok(running) ->
          case list.length(running.deferred) < 54 {
            True ->
              await_adoption(
                Running(
                  ..running,
                  deferred: list.append(running.deferred, [observed]),
                ),
                ordinal,
                offered,
              )
            False -> finish_offered(running, WorkerLost, ordinal, offered)
          }
      }
    }
  }
}

fn release_terminal_before_defer(
  running: Running(a, v, e),
  observed: Event(a, v, e),
) -> Result(Running(a, v, e), Nil) {
  case observed {
    Message(Resolved(family, _, acknowledged)) ->
      retire_terminal(running, Resolver(family), acknowledged)
    Message(Failed(ordinal, _, acknowledged))
    | Message(Adopted(ordinal, _, acknowledged))
    | Message(Released(ordinal, acknowledged)) ->
      retire_terminal(running, Candidate(ordinal), acknowledged)
    _ -> Ok(running)
  }
}

fn adoption_failed(
  running: Running(a, v, e),
  ordinal: Int,
  offered: v,
  error: e,
) -> Result(v, Failure(e)) {
  running.operations.discard(offered)
  running.operations.abandon(ordinal)
  loop(
    Running(
      ..remember(running, error),
      scheduler: schedule.failed(running.scheduler, ordinal),
    ),
  )
}

fn finish_offered(
  running: Running(a, v, e),
  error: Failure(e),
  ordinal: Int,
  offered: v,
) -> Result(v, Failure(e)) {
  finish(running, Error(error), None, Some(#(ordinal, offered)))
}

fn finish(
  running: Running(a, v, e),
  outcome: Result(v, Failure(e)),
  winner: Option(Int),
  current: Option(#(Int, v)),
) -> Result(v, Failure(e)) {
  let before_cleanup =
    list.append(running.deferred, drain_messages(running.messages, 72))
  list.each(before_cleanup, signal_finish_event)
  let owner_alive = process.is_alive(running.policy.owner)
  let cleanup =
    running.operations.cleanup(running.group, running.owns_group, owner_alive)
  let after_cleanup = drain_messages(running.messages, 72)
  list.each(after_cleanup, signal_finish_event)
  let buffered = list.append(before_cleanup, after_cleanup)
  list.each(running.workers, fn(worker) {
    process.demonitor_process(worker.monitor)
    case worker.work {
      Resolver(family) -> {
        case
          has_resolved(buffered, family),
          has_resolver_down(buffered, family)
        {
          True, _ -> Nil
          False, True ->
            running.operations.resolution(
              family,
              schedule.ResolutionWorkerExited,
            )
          False, False ->
            running.operations.resolution(family, schedule.ResolutionCancelled)
        }
      }
      Candidate(ordinal) if winner != Some(ordinal) ->
        running.operations.abandon(ordinal)
      _ -> Nil
    }
  })
  process.demonitor_process(running.owner_monitor)
  process.demonitor_process(running.supervisor_monitor)
  discard_pending(buffered, current, winner, running.operations)
  let alive = process.is_alive(running.policy.owner)
  let timely = udp.monotonic_millisecond() < running.policy.total_deadline
  case outcome, cleanup, alive, timely {
    Ok(value), Ok(Nil), True, True -> Ok(value)
    Ok(value), cleanup, alive, timely -> {
      running.operations.discard(value)
      Error(case cleanup, alive, timely {
        Error(Nil), False, _ -> CleanupFailed(Some(OwnerGone))
        Error(Nil), True, False -> CleanupFailed(Some(TotalTimeout))
        Error(Nil), True, True -> CleanupFailed(None)
        Ok(Nil), False, _ -> OwnerGone
        Ok(Nil), True, False -> TotalTimeout
        Ok(Nil), True, True -> TotalTimeout
      })
    }
    Error(error), Error(Nil), _, _ -> Error(CleanupFailed(Some(error)))
    Error(error), Ok(Nil), _, _ -> Error(error)
  }
}

fn retire_terminal(
  running: Running(a, v, e),
  work: Work,
  acknowledged: Subject(Nil),
) -> Result(Running(a, v, e), Nil) {
  process.send(acknowledged, Nil)
  let #(worker, workers) = pop_worker(running.workers, work)
  case worker {
    // A terminal message deferred while another candidate was being adopted has already joined and removed its worker before reaching the main loop.
    None -> Ok(running)
    Some(worker) -> {
      use Nil <- result.try(join(worker))
      process.demonitor_process(worker.monitor)
      Ok(Running(..running, workers: workers))
    }
  }
}

fn retire_down(
  running: Running(a, v, e),
  work: Work,
) -> Option(Running(a, v, e)) {
  let #(worker, workers) = pop_worker(running.workers, work)
  case worker {
    None -> None
    Some(worker) -> {
      process.demonitor_process(worker.monitor)
      Some(Running(..running, workers: workers))
    }
  }
}

fn pop_worker(
  workers: List(Worker),
  work: Work,
) -> #(Option(Worker), List(Worker)) {
  case workers {
    [] -> #(None, [])
    [worker, ..rest] ->
      case same_work(worker.work, work) {
        True -> #(Some(worker), rest)
        False -> {
          let #(found, remaining) = pop_worker(rest, work)
          #(found, [worker, ..remaining])
        }
      }
  }
}

fn same_work(left: Work, right: Work) -> Bool {
  case left, right {
    Resolver(left), Resolver(right) -> left == right
    Candidate(left), Candidate(right) -> left == right
    _, _ -> False
  }
}

fn drain_messages(
  messages: Subject(Message(a, v, e)),
  remaining: Int,
) -> List(Event(a, v, e)) {
  case remaining <= 0 {
    True -> []
    False ->
      case process.receive(messages, within: 0) {
        Error(Nil) -> []
        Ok(message) -> [
          Message(message),
          ..drain_messages(messages, remaining - 1)
        ]
      }
  }
}

fn signal_finish_event(event: Event(a, v, e)) -> Nil {
  case event {
    Message(Resolved(_, _, acknowledged))
    | Message(Failed(_, _, acknowledged))
    | Message(Adopted(_, _, acknowledged))
    | Message(Released(_, acknowledged)) -> process.send(acknowledged, Nil)
    Message(Ready(_, decision, _)) -> process.send(decision, Cancel)
    _ -> Nil
  }
}

fn has_resolved(events: List(Event(a, v, e)), family: schedule.Family) -> Bool {
  list.any(events, fn(event) {
    case event {
      Message(Resolved(observed, _, _)) -> observed == family
      _ -> False
    }
  })
}

fn has_resolver_down(
  events: List(Event(a, v, e)),
  family: schedule.Family,
) -> Bool {
  list.any(events, fn(event) {
    case event {
      Down(Resolver(observed)) -> observed == family
      _ -> False
    }
  })
}

fn pending_ordinals(
  events: List(Event(a, v, e)),
  current: Option(#(Int, v)),
) -> List(Int) {
  let ordinals =
    list.fold(events, [], fn(ordinals, event) {
      let ordinal = case event {
        Message(Ready(ordinal, _, _))
        | Message(Adopted(ordinal, _, _))
        | Message(Released(ordinal, _)) -> Some(ordinal)
        _ -> None
      }
      case ordinal {
        Some(ordinal) ->
          case list.contains(ordinals, ordinal) {
            True -> ordinals
            False -> [ordinal, ..ordinals]
          }
        None -> ordinals
      }
    })
  case current {
    Some(#(ordinal, _)) ->
      case list.contains(ordinals, ordinal) {
        True -> ordinals
        False -> [ordinal, ..ordinals]
      }
    None -> ordinals
  }
}

fn was_released(events: List(Event(a, v, e)), ordinal: Int) -> Bool {
  list.any(events, fn(event) {
    case event {
      Message(Released(observed, _)) -> observed == ordinal
      _ -> False
    }
  })
}

fn adopted_value(events: List(Event(a, v, e)), ordinal: Int) -> Option(v) {
  case events {
    [] -> None
    [event, ..rest] ->
      case event {
        Message(Adopted(observed, Ok(value), _)) if observed == ordinal ->
          Some(value)
        _ -> adopted_value(rest, ordinal)
      }
  }
}

fn ready_value(events: List(Event(a, v, e)), ordinal: Int) -> Option(v) {
  case events {
    [] -> None
    [event, ..rest] ->
      case event {
        Message(Ready(observed, _, value)) if observed == ordinal -> Some(value)
        _ -> ready_value(rest, ordinal)
      }
  }
}

fn current_value(current: Option(#(Int, v)), ordinal: Int) -> Option(v) {
  case current {
    Some(#(observed, value)) if observed == ordinal -> Some(value)
    _ -> None
  }
}

fn discard_pending(
  events: List(Event(a, v, e)),
  current: Option(#(Int, v)),
  winner: Option(Int),
  operations: Operations(a, v, e),
) -> Nil {
  list.each(pending_ordinals(events, current), fn(ordinal) {
    case winner == Some(ordinal) || was_released(events, ordinal) {
      True -> Nil
      False ->
        case
          adopted_value(events, ordinal),
          current_value(current, ordinal),
          ready_value(events, ordinal)
        {
          Some(value), _, _ | None, Some(value), _ | None, None, Some(value) ->
            operations.discard(value)
          None, None, None -> Nil
        }
    }
  })
}

fn remember(running: Running(a, v, e), error: e) -> Running(a, v, e) {
  Running(
    ..running,
    last_error: Some(case running.last_error {
      None -> error
      Some(previous) -> running.operations.prefer_error(previous, error)
    }),
  )
}

fn join(worker: Worker) -> Result(Nil, Nil) {
  // Use a fresh monitor: the event loop may already have consumed its first DOWN.
  // The callback cannot publish after this join observes termination.
  let monitor = process.monitor(worker.pid)
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
  let outcome = process.selector_receive(selector, within: 1000)
  process.demonitor_process(monitor)
  outcome
}

fn exhausted(running: Running(a, v, e)) -> Failure(e) {
  case running.resolver_worker_lost, running.last_error, running.dns_expired {
    True, _, _ -> WorkerLost
    False, Some(error), _ -> Rejected(error)
    False, None, True -> DnsTimeout
    False, None, False -> ResolutionFailed
  }
}
