import quic_core/internal/runtime/client_close_deadline

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn one_injected_deadline_covers_actor_and_diagnostics_test() -> Nil {
  let assert Ok(deadline) =
    client_close_deadline.from_allowances(100, 250, 100, 5000)
  assert deadline == 5450
  assert client_close_deadline.validate(100, deadline) == Ok(Nil)
  assert client_close_deadline.remaining(101, deadline) == Ok(5349)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn invalid_expired_and_non_portable_deadlines_are_typed_test() -> Nil {
  assert client_close_deadline.validate(100, 100)
    == Error(client_close_deadline.DeadlineExpired)
  assert client_close_deadline.validate(100, -1)
    == Error(client_close_deadline.InvalidConfiguration)
  assert client_close_deadline.validate(100, 9_223_372_036_854_775_808)
    == Error(client_close_deadline.DeadlineOutOfRange)
  assert client_close_deadline.from_allowances(
      9_223_372_036_854_775_807,
      1,
      0,
      0,
    )
    == Error(client_close_deadline.DeadlineOutOfRange)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn forced_join_tail_stays_inside_injected_deadline_test() -> Nil {
  assert client_close_deadline.force_join_at(100, 350, 50) == Ok(300)
  // A short remainder begins forcing immediately; the caller's boundary is still 110 and is never replaced with `now + tail`.
  assert client_close_deadline.force_join_at(100, 110, 50) == Ok(100)
  assert client_close_deadline.force_join_at(100, 350, -1)
    == Error(client_close_deadline.InvalidConfiguration)
  assert client_close_deadline.force_join_at(100, 100, 50)
    == Error(client_close_deadline.DeadlineExpired)
}
