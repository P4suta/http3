import gleam/int
import gleam/list
import quic_core/internal/runtime/happy_eyeballs as race

fn new() -> race.State(Int) {
  race.new(True, True, 1000, 2000, int.compare)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resolver_launch_order_prefers_ipv6_and_preserves_single_family_test() -> Nil {
  assert race.resolution_order(True, True) == [race.Ipv6, race.Ipv4]
  assert race.resolution_order(True, False) == [race.Ipv4]
  assert race.resolution_order(False, True) == [race.Ipv6]
  assert race.resolution_order(False, False) == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ipv4_can_start_after_resolution_delay_while_ipv6_is_stalled_test() -> Nil {
  let state = race.answer(new(), race.Ipv4, [4], 10)
  let assert race.Wait(60, _) = race.next(state, 10)
  let assert race.Wait(60, _) = race.next(state, 59)
  let assert race.Launch(4, 1, _) = race.next(state, 60)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ipv6_can_start_without_waiting_for_stalled_ipv4_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [6], 10)
  let assert race.Launch(6, 1, _) = race.next(state, 10)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ipv6_negative_answer_releases_ipv4_resolution_wait_test() -> Nil {
  let state = race.answer(new(), race.Ipv4, [4], 10)
  let state = race.answer(state, race.Ipv6, [], 20)
  let assert race.Launch(4, 1, _) = race.next(state, 20)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn late_family_can_recover_after_first_candidate_failed_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [6], 0)
  let assert race.Launch(6, 1, state) = race.next(state, 0)
  let state = race.failed(state, 1)
  let assert race.Wait(1000, _) = race.next(state, 10)
  let state = race.answer(state, race.Ipv4, [4], 20)
  let assert race.Wait(100, _) = race.next(state, 20)
  let assert race.Launch(4, 2, _) = race.next(state, 100)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn attempts_are_launched_on_demand_at_250_millisecond_intervals_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [1, 3, 5], 0)
  let assert race.Launch(1, 1, state) = race.next(state, 0)
  let assert race.Wait(250, _) = race.next(state, 249)
  let assert race.Launch(3, 2, state) = race.next(state, 250)
  let assert race.Wait(500, _) = race.next(state, 250)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn failure_acceleration_preserves_minimum_attempt_delay_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [1, 3], 0)
  let assert race.Launch(1, 1, state) = race.next(state, 5)
  let state = race.failed(state, 1)
  let assert race.Wait(105, _) = race.next(state, 6)
  let assert race.Launch(3, 2, _) = race.next(state, 105)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn late_family_interleaves_before_unstarted_same_family_candidates_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [1, 3, 5], 0)
  let assert race.Launch(1, 1, state) = race.next(state, 0)
  let state = race.answer(state, race.Ipv4, [2, 4], 20)
  let assert race.Launch(2, 2, state) = race.next(state, 250)
  let assert race.Launch(3, 3, state) = race.next(state, 500)
  let assert race.Launch(4, 4, _) = race.next(state, 750)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sorting_precedes_family_interleaving_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [9, 5], 0)
  let state = race.answer(state, race.Ipv4, [8, 2], 0)
  let assert race.Launch(2, 1, state) = race.next(state, 0)
  let assert race.Launch(5, 2, state) = race.next(state, 250)
  let assert race.Launch(8, 3, state) = race.next(state, 500)
  let assert race.Launch(9, 4, _) = race.next(state, 750)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn duplicate_results_and_duplicate_failure_cannot_create_extra_work_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [6, 6], 0)
  let state = race.answer(state, race.Ipv6, [8], 0)
  let state = race.answer(state, race.Ipv4, [], 0)
  let assert race.Launch(6, 1, state) = race.next(state, 0)
  let state = race.failed(state, 1) |> race.failed(1) |> race.failed(42)
  assert race.next(state, 1) == race.Exhausted
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn repeated_dns_rows_do_not_use_distinct_candidate_capacity_test() -> Nil {
  let addresses = list.append(list.repeat(6, 20), [8])
  let state = race.answer(new(), race.Ipv6, addresses, 0)
  let assert race.Launch(6, 1, state) = race.next(state, 0)
  let assert race.Launch(8, 2, _) = race.next(state, 250)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn previously_attempted_values_do_not_hide_new_late_candidates_test() -> Nil {
  let state = race.answer(new(), race.Ipv6, [6], 0)
  let assert race.Launch(6, 1, state) = race.next(state, 0)
  let state = race.failed(state, 1)
  let addresses = list.append(list.repeat(6, 20), [8])
  let state = race.answer(state, race.Ipv4, addresses, 10)
  let assert race.Launch(8, 2, _) = race.next(state, 100)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dns_expiry_keeps_existing_candidates_and_releases_resolution_wait_test() -> Nil {
  let state =
    race.new(True, True, 30, 2000, int.compare)
    |> race.answer(race.Ipv4, [4], 10)
  let assert race.DnsExpired(state) = race.next(state, 30)
  let assert race.Launch(4, 1, _) = race.next(state, 30)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn total_deadline_wins_over_dns_and_pending_launch_test() -> Nil {
  let state =
    race.new(True, True, 1000, 1000, int.compare)
    |> race.answer(race.Ipv6, [6], 0)
  assert race.next(state, 1000) == race.TotalExpired
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn candidate_admission_is_globally_bounded_after_late_family_test() -> Nil {
  let state =
    race.new(True, True, 10_000, 20_000, int.compare)
    |> race.answer(race.Ipv6, numbers(1, 40), 0)
  let assert race.Launch(1, 1, state) = race.next(state, 0)
  let state = race.answer(state, race.Ipv4, numbers(41, 80), 10)
  let #(count, values) = drain(state, 250, 1, [1])
  assert count == 16
  assert list.contains(values, 41)
  assert list.unique(values) == values
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn sole_known_destination_preserves_the_early_data_path_test() -> Nil {
  let state =
    race.new(True, False, 1000, 2000, int.compare)
    |> race.answer(race.Ipv4, [4], 0)
  let assert race.Launch(_, _, state) = race.next(state, 0)
  assert !race.requires_peer_confirmation(state)
  let state = new() |> race.answer(race.Ipv6, [6], 0)
  let assert race.Launch(_, _, state) = race.next(state, 0)
  assert race.requires_peer_confirmation(state)
}

fn numbers(first: Int, last: Int) -> List(Int) {
  int.range(first, last, with: [], run: fn(values, value) { [value, ..values] })
  |> list.reverse
}

fn drain(
  state: race.State(Int),
  now: Int,
  count: Int,
  values: List(Int),
) -> #(Int, List(Int)) {
  case race.next(state, now) {
    race.Launch(value, index, next) ->
      drain(race.failed(next, index), now + 250, count + 1, [value, ..values])
    race.Wait(_, _) -> #(count, values)
    race.Exhausted -> #(count, values)
    race.DnsExpired(next) -> drain(next, now, count, values)
    race.TotalExpired -> #(count, values)
  }
}
