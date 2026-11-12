import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{Some}
import gleam/result
import quic_core/internal/runtime/connection_race as race
import quic_core/internal/runtime/happy_eyeballs as schedule
import quic_core/internal/udp

@external(erlang, "quic_bootstrap_join_test_ffi", "suspended_until")
fn suspended_until(pid: process.Pid, deadline: Int, during: fn() -> Nil) -> Bool

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn queued_adoption_cannot_publish_after_the_original_deadline_test() -> Nil {
  let adopting = process.new_subject()
  let discarded = process.new_subject()
  let completed = process.new_subject()
  let now = udp.monotonic_millisecond()
  let deadline = now + 1000
  let policy = race.Policy(process.self(), True, False, now + 500, deadline)
  let operations = operations(fn(_) { Ok([4]) })
  let operations =
    race.Operations(
      ..operations,
      adopt: fn(value, _) {
        let gate = process.new_subject()
        process.send(adopting, #(process.self(), gate))
        let assert Ok(Nil) = process.receive(gate, within: 1500)
        Ok(value)
      },
      discard: fn(_) { process.send(discarded, True) },
    )
  let coordinator =
    process.spawn_unlinked(fn() {
      process.send(completed, race.run(policy, operations))
    })
  let assert Ok(#(candidate, gate)) = process.receive(adopting, within: 750)
  let suspended =
    suspended_until(coordinator, deadline, fn() {
      let monitor = process.monitor(candidate)
      process.send(gate, Nil)
      let selector =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
      let assert Ok(Nil) = process.selector_receive(selector, within: 750)
      Nil
    })
  assert suspended
  assert process.receive(completed, within: 1000)
    == Ok(Error(race.TotalTimeout))
  assert process.receive(discarded, within: 100) == Ok(True)
  // The offered handle and the successful adopted handle describe one ownership transfer.
  // Deadline cleanup must dispose that resource once.
  assert process.receive(discarded, within: 0) == Error(Nil)
}

fn policy() -> race.Policy {
  let now = udp.monotonic_millisecond()
  race.Policy(process.self(), True, True, now + 500, now + 1500)
}

fn operations(
  resolve: fn(schedule.Family) -> Result(List(Int), Int),
) -> race.Operations(Int, Int, Int) {
  race.Operations(
    resolve,
    fn(address, _, _) { Ok(address) },
    fn(value, _) { Ok(value) },
    fn(_) { Nil },
    int.compare,
    int.max,
    fn(_) { Nil },
    fn(_, _) { Nil },
    fn() { Nil },
    spawn_work,
    cleanup_group,
  )
}

fn spawn_work(
  group: udp.WorkGroup,
  kind: udp.WorkKind,
  work: fn() -> Nil,
) -> Result(process.Pid, Nil) {
  udp.spawn_work(group, kind, work) |> result.replace_error(Nil)
}

fn cleanup_group(
  group: udp.WorkGroup,
  owns_group: Bool,
  owner_alive: Bool,
) -> Result(Nil, Nil) {
  case owns_group, owner_alive {
    _, False -> udp.stop_work_group_after_owner_exit(group)
    True, True -> udp.stop_work_group(group)
    False, True -> udp.quiesce_work_group(group)
  }
  |> result.replace_error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn usable_ipv4_finishes_and_joins_a_stalled_ipv6_resolver_test() -> Nil {
  let observed = process.new_subject()
  let resolution = process.new_subject()
  let operations =
    operations(fn(family) {
      process.send(observed, process.self())
      case family {
        schedule.Ipv4 -> Ok([4])
        schedule.Ipv6 -> {
          let hold = process.new_subject()
          let _expired = process.receive(hold, within: 1200)
          Error(6)
        }
      }
    })
  let operations =
    race.Operations(..operations, resolution: fn(family, outcome) {
      process.send(resolution, #(family, outcome))
    })
  let started = udp.monotonic_millisecond()
  let result = race.run(policy(), operations)
  let elapsed = udp.monotonic_millisecond() - started
  let assert Ok(first) = process.receive(observed, within: 100)
  let assert Ok(second) = process.receive(observed, within: 100)
  assert result == Ok(4)
  assert elapsed >= 50
  assert elapsed < 500
  assert !process.is_alive(first)
  assert !process.is_alive(second)
  let observations = drain(resolution, 8)
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionUsable,
    )
    == 1
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionCancelled,
    )
    == 0
  assert count_resolution(
      observations,
      schedule.Ipv6,
      schedule.ResolutionCancelled,
    )
    == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dns_expiry_marks_only_the_still_pending_family_test() -> Nil {
  let resolution = process.new_subject()
  let now = udp.monotonic_millisecond()
  let policy = race.Policy(process.self(), True, True, now + 80, now + 500)
  let operations =
    operations(fn(family) {
      case family {
        schedule.Ipv4 -> Ok([])
        schedule.Ipv6 -> {
          let blocked = process.new_subject()
          let _blocked = process.receive(blocked, within: 750)
          Ok([])
        }
      }
    })
  let operations =
    race.Operations(..operations, resolution: fn(family, outcome) {
      process.send(resolution, #(family, outcome))
    })
  assert race.run(policy, operations) == Error(race.DnsTimeout)
  let observations = drain(resolution, 10)
  assert count_resolution(observations, schedule.Ipv4, schedule.ResolutionEmpty)
    == 1
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionExpired,
    )
    == 0
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionCancelled,
    )
    == 0
  assert count_resolution(
      observations,
      schedule.Ipv6,
      schedule.ResolutionExpired,
    )
    == 1
}

fn drain(subject: process.Subject(value), remaining: Int) -> List(value) {
  case remaining <= 0 {
    True -> []
    False ->
      case process.receive(subject, within: 0) {
        Error(Nil) -> []
        Ok(value) -> [value, ..drain(subject, remaining - 1)]
      }
  }
}

fn count_resolution(
  observations: List(#(schedule.Family, schedule.ResolutionOutcome)),
  family: schedule.Family,
  outcome: schedule.ResolutionOutcome,
) -> Int {
  observations
  |> list.filter(fn(observation) { observation == #(family, outcome) })
  |> list.length
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn both_resolver_spawn_failures_are_worker_loss_not_empty_dns_test() -> Nil {
  let resolution = process.new_subject()
  let operations = operations(fn(_) { Ok([]) })
  let operations =
    race.Operations(
      ..operations,
      spawn: fn(_, kind, _) {
        case kind {
          udp.ResolverWork -> Error(Nil)
          _ -> panic as "only resolver work is expected"
        }
      },
      resolution: fn(family, outcome) {
        process.send(resolution, #(family, outcome))
      },
    )
  assert race.run(policy(), operations) == Error(race.WorkerLost)
  let observations = drain(resolution, 8)
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionStartFailed,
    )
    == 1
  assert count_resolution(
      observations,
      schedule.Ipv6,
      schedule.ResolutionStartFailed,
    )
    == 1
  assert count_resolution(observations, schedule.Ipv4, schedule.ResolutionEmpty)
    == 0
  assert count_resolution(observations, schedule.Ipv6, schedule.ResolutionEmpty)
    == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn one_resolver_spawn_failure_does_not_block_the_other_family_test() -> Nil {
  let decisions = process.new_subject()
  let resolution = process.new_subject()
  // Resolution order is IPv6 then IPv4.
  // Fail the first admission only.
  process.send(decisions, False)
  process.send(decisions, True)
  let operations =
    operations(fn(family) {
      case family {
        schedule.Ipv4 -> Ok([4])
        schedule.Ipv6 -> Ok([6])
      }
    })
  let operations =
    race.Operations(
      ..operations,
      spawn: fn(group, kind, work) {
        case kind {
          udp.ResolverWork -> {
            let assert Ok(admit) = process.receive(decisions, within: 0)
            case admit {
              True -> spawn_work(group, kind, work)
              False -> Error(Nil)
            }
          }
          _ -> spawn_work(group, kind, work)
        }
      },
      resolution: fn(family, outcome) {
        process.send(resolution, #(family, outcome))
      },
    )
  assert race.run(policy(), operations) == Ok(4)
  let observations = drain(resolution, 8)
  assert count_resolution(
      observations,
      schedule.Ipv6,
      schedule.ResolutionStartFailed,
    )
    == 1
  assert count_resolution(observations, schedule.Ipv6, schedule.ResolutionEmpty)
    == 0
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionUsable,
    )
    == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resolver_exit_before_result_is_typed_worker_loss_test() -> Nil {
  let resolution = process.new_subject()
  let now = udp.monotonic_millisecond()
  let policy = race.Policy(process.self(), True, False, now + 300, now + 600)
  let operations = operations(fn(_) { Ok([4]) })
  let operations =
    race.Operations(
      ..operations,
      spawn: fn(group, kind, _) { spawn_work(group, kind, fn() { Nil }) },
      resolution: fn(family, outcome) {
        process.send(resolution, #(family, outcome))
      },
    )
  assert race.run(policy, operations) == Error(race.WorkerLost)
  let observations = drain(resolution, 4)
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionWorkerExited,
    )
    == 1
  assert count_resolution(
      observations,
      schedule.Ipv4,
      schedule.ResolutionCancelled,
    )
    == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cleanup_failure_retains_the_primary_candidate_error_test() -> Nil {
  let operations = operations(fn(_) { Ok([4]) })
  let operations =
    race.Operations(
      ..operations,
      dial: fn(_, _, _) { Error(91) },
      cleanup: fn(group, owns_group, owner_alive) {
        let _joined = cleanup_group(group, owns_group, owner_alive)
        Error(Nil)
      },
    )
  assert race.run(policy(), operations)
    == Error(race.CleanupFailed(Some(race.Rejected(91))))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn failed_candidate_is_abandoned_exactly_once_test() -> Nil {
  let abandoned = process.new_subject()
  let operations = operations(fn(_) { Ok([4]) })
  let operations =
    race.Operations(
      ..operations,
      dial: fn(_, _, _) { Error(7) },
      abandon: fn(ordinal) { process.send(abandoned, ordinal) },
    )
  assert race.run(policy(), operations) == Error(race.Rejected(7))
  assert process.receive(abandoned, within: 100) == Ok(1)
  assert process.receive(abandoned, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn failed_adoption_discards_and_abandons_exactly_once_test() -> Nil {
  let discarded = process.new_subject()
  let abandoned = process.new_subject()
  let operations = operations(fn(_) { Ok([4]) })
  let operations =
    race.Operations(
      ..operations,
      adopt: fn(_, _) { Error(8) },
      discard: fn(value) { process.send(discarded, value) },
      abandon: fn(ordinal) { process.send(abandoned, ordinal) },
    )
  assert race.run(policy(), operations) == Error(race.Rejected(8))
  assert process.receive(discarded, within: 100) == Ok(4)
  assert process.receive(discarded, within: 0) == Error(Nil)
  assert process.receive(abandoned, within: 100) == Ok(1)
  assert process.receive(abandoned, within: 0) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn winning_candidate_prevents_unstarted_candidates_from_dialing_test() -> Nil {
  let dialed = process.new_subject()
  let operations =
    operations(fn(family) {
      case family {
        schedule.Ipv6 -> Ok([6, 7])
        schedule.Ipv4 -> Ok([])
      }
    })
  let operations =
    race.Operations(..operations, dial: fn(address, _, _) {
      process.send(dialed, address)
      Ok(address)
    })
  assert race.run(policy(), operations) == Ok(6)
  assert process.receive(dialed, within: 100) == Ok(6)
  assert process.receive(dialed, within: 100) == Error(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn late_ipv4_result_recovers_a_failed_ipv6_candidate_test() -> Nil {
  let resolver = process.new_subject()
  let candidate = process.new_subject()
  let operations =
    operations(fn(family) {
      case family {
        schedule.Ipv6 -> Ok([6])
        schedule.Ipv4 -> {
          let gate = process.new_subject()
          process.send(resolver, gate)
          let assert Ok(Nil) = process.receive(gate, within: 1200)
          Ok([4])
        }
      }
    })
  let operations =
    race.Operations(..operations, dial: fn(address, _, _) {
      case address {
        6 -> {
          let gate = process.new_subject()
          process.send(candidate, gate)
          let assert Ok(Nil) = process.receive(gate, within: 1000)
          Error(6)
        }
        _ -> Ok(address)
      }
    })
  let completed = start(operations)
  let assert Ok(resolver_gate) = process.receive(resolver, within: 1000)
  let assert Ok(candidate_gate) = process.receive(candidate, within: 1000)
  process.send(candidate_gate, Nil)
  process.send(resolver_gate, Nil)
  assert process.receive(completed, within: 2000) == Ok(Ok(4))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resolution_events_arriving_during_failed_adoption_are_not_lost_test() -> Nil {
  let resolver = process.new_subject()
  let adopting = process.new_subject()
  let operations =
    operations(fn(family) {
      case family {
        schedule.Ipv6 -> Ok([6])
        schedule.Ipv4 -> {
          let gate = process.new_subject()
          process.send(resolver, #(process.self(), gate))
          let assert Ok(Nil) = process.receive(gate, within: 1000)
          Ok([4])
        }
      }
    })
  let operations =
    race.Operations(..operations, adopt: fn(value, _) {
      case value {
        6 -> {
          let gate = process.new_subject()
          process.send(adopting, gate)
          let assert Ok(Nil) = process.receive(gate, within: 1000)
          Error(6)
        }
        _ -> Ok(value)
      }
    })
  let completed = start(operations)
  let assert Ok(#(resolver_pid, resolver_gate)) =
    process.receive(resolver, within: 1000)
  let assert Ok(adopt_gate) = process.receive(adopting, within: 1000)
  let monitor = process.monitor(resolver_pid)
  process.send(resolver_gate, Nil)
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
  let assert Ok(Nil) = process.selector_receive(selector, within: 1000)
  // The complete resolver callback has exited before adoption can fail.
  process.send(adopt_gate, Nil)
  assert process.receive(completed, within: 2000) == Ok(Ok(4))
}

fn start(
  operations: race.Operations(Int, Int, Int),
) -> process.Subject(Result(Int, race.Failure(Int))) {
  let completed = process.new_subject()
  let policy = policy()
  let _worker =
    process.spawn_unlinked(fn() {
      process.send(completed, race.run(policy, operations))
    })
  completed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owner_exit_between_socket_transfer_and_publication_closes_the_socket_test() -> Nil {
  let adopted = process.new_subject()
  let completed = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      let hold = process.new_subject()
      let _expired = process.receive(hold, within: 3000)
      Nil
    })
  let now = udp.monotonic_millisecond()
  let policy = race.Policy(owner, True, False, now + 1000, now + 2000)
  let operations =
    race.Operations(
      resolve: fn(_) { Ok([4]) },
      dial: fn(_, _, _) {
        let assert Ok(address) = udp.ipv4(127, 0, 0, 1)
        let assert Ok(endpoint) = udp.endpoint(address, 0)
        udp.open(endpoint) |> result.replace_error(1)
      },
      adopt: fn(socket, recipient) {
        let assert Ok(Nil) = udp.transfer_owner(socket, recipient)
        process.send(adopted, #(process.self(), socket))
        let hold = process.new_subject()
        let _expired = process.receive(hold, within: 2500)
        Ok(socket)
      },
      discard: fn(socket) {
        let _closed = udp.close(socket)
        Nil
      },
      compare: int.compare,
      prefer_error: int.max,
      abandon: fn(_) { Nil },
      resolution: fn(_, _) { Nil },
      eligible: fn() { Nil },
      spawn: spawn_work,
      cleanup: cleanup_group,
    )
  let caller =
    process.spawn_unlinked(fn() {
      let result = race.run(policy, operations)
      let release = process.new_subject()
      process.send(completed, #(result, release))
      let _expired = process.receive(release, within: 3000)
      Nil
    })
  let assert Ok(#(candidate, socket)) = process.receive(adopted, within: 1000)
  process.kill(owner)
  let assert Ok(#(result, release)) = process.receive(completed, within: 1500)
  let closed = udp.local_endpoint(socket) |> result.is_error
  let candidate_exited = !process.is_alive(candidate)
  let caller_still_alive = process.is_alive(caller)
  process.send(release, Nil)
  assert result == Error(race.OwnerGone)
  assert candidate_exited
  assert caller_still_alive
  assert closed
}
