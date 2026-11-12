import http3/internal/native/completion_deadline

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parent_budget_clamps_every_phase_without_extending_a_shorter_plan_test() -> Nil {
  let assert Ok(plan) = completion_deadline.new(100, 1000, 5000, 100)
  let assert Ok(limited) = completion_deadline.limit(plan, 1000)
  assert completion_deadline.protocol_deadline_milliseconds(limited) == 250
  assert completion_deadline.completion_deadline_milliseconds(limited) == 1000
  assert completion_deadline.caller_deadline_milliseconds(limited) == 1100
  assert completion_deadline.limit(plan, 10_000) == Ok(plan)
  assert completion_deadline.limit(plan, 0)
    == Error(completion_deadline.InvalidConfiguration)
  assert completion_deadline.limit(plan, 1)
    == Error(completion_deadline.InvalidConfiguration)
  let assert Ok(short) = completion_deadline.limit(plan, 4)
  assert completion_deadline.protocol_deadline_milliseconds(short) == 101
  assert completion_deadline.completion_deadline_milliseconds(short) == 103
  assert completion_deadline.caller_deadline_milliseconds(short) == 104
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn protocol_and_qlog_completion_share_one_injected_plan_test() -> Nil {
  let assert Ok(plan) = completion_deadline.new(100, 250, 5000, 100)
  assert completion_deadline.protocol_deadline_milliseconds(plan) == 350
  assert completion_deadline.completion_deadline_milliseconds(plan) == 5350
  assert completion_deadline.caller_deadline_milliseconds(plan) == 5450
  assert completion_deadline.total_wait_milliseconds(plan) == 5350

  // Sampling later cannot recompute or extend either absolute boundary.
  let later_sample = 349
  assert completion_deadline.protocol_deadline_milliseconds(plan) - later_sample
    == 1
  assert completion_deadline.completion_deadline_milliseconds(plan) == 5350
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_allowances_are_finite_and_validated_test() -> Nil {
  assert completion_deadline.new(0, 0, 5000, 100)
    == Error(completion_deadline.InvalidConfiguration)
  assert completion_deadline.new(0, 1, -1, 100)
    == Error(completion_deadline.InvalidConfiguration)
  assert completion_deadline.new(-1, 1, 0, 0)
    == Error(completion_deadline.InvalidConfiguration)
  assert completion_deadline.new(9_223_372_036_854_775_807, 1, 0, 0)
    == Error(completion_deadline.InvalidConfiguration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_actor_tail_cannot_reduce_or_extend_core_allowance_test() -> Nil {
  let core_allowance = 5000
  let actor_tail = 50
  let assert Ok(plan) =
    completion_deadline.new(100, 250, core_allowance + actor_tail, 100)
  let protocol = completion_deadline.protocol_deadline_milliseconds(plan)
  let completion = completion_deadline.completion_deadline_milliseconds(plan)
  let core_deadline = completion - actor_tail

  assert protocol == 350
  assert core_deadline - protocol == core_allowance
  assert completion - core_deadline == actor_tail
  assert completion_deadline.caller_deadline_milliseconds(plan) == 5500
}
