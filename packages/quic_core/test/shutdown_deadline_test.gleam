import gleam/list
import quic_core/internal/runtime/shutdown_deadline

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn all_connection_joins_share_one_absolute_deadline_test() -> Nil {
  let assert Ok(plan) = shutdown_deadline.new(1000, 250, 50)
  assert shutdown_deadline.join_deadline_milliseconds(plan) == 1200
  assert shutdown_deadline.final_deadline_milliseconds(plan) == 1250

  let assert Ok(one) = shutdown_deadline.fanout_deadlines(plan, 1)
  let assert Ok(thousand) = shutdown_deadline.fanout_deadlines(plan, 1000)
  assert one == [1200]
  assert thousand == list.repeat(1200, times: 1000)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cleanup_tail_is_capped_inside_original_timeout_test() -> Nil {
  let assert Ok(plan) = shutdown_deadline.new(100, 10, 50)
  assert shutdown_deadline.join_deadline_milliseconds(plan) == 100
  assert shutdown_deadline.final_deadline_milliseconds(plan) == 110
  assert shutdown_deadline.new(100, 0, 0)
    == Error(shutdown_deadline.InvalidConfiguration)
  assert shutdown_deadline.fanout_deadlines(plan, -1)
    == Error(shutdown_deadline.InvalidConfiguration)

  let fallback = shutdown_deadline.bounded(-1, 0, -1)
  assert shutdown_deadline.join_deadline_milliseconds(fallback) == 1
  assert shutdown_deadline.final_deadline_milliseconds(fallback) == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn injected_listener_deadline_is_validated_without_extension_test() -> Nil {
  let assert Ok(plan) = shutdown_deadline.from_deadline(100, 350, 50)
  assert shutdown_deadline.join_deadline_milliseconds(plan) == 300
  assert shutdown_deadline.final_deadline_milliseconds(plan) == 350
  assert shutdown_deadline.from_deadline(100, 100, 50)
    == Error(shutdown_deadline.DeadlineExpired)
  assert shutdown_deadline.from_deadline(100, -1, 50)
    == Error(shutdown_deadline.InvalidConfiguration)
  assert shutdown_deadline.from_deadline(100, 9_223_372_036_854_775_808, 50)
    == Error(shutdown_deadline.DeadlineOutOfRange)
}
