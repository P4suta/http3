import quic_core/internal/runtime/qlog_close_deadline

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn scheduler_stall_cannot_rebase_absolute_qlog_deadline_test() -> Nil {
  assert qlog_close_deadline.effective(100, 110, 5000) == Ok(110)

  // The same injected boundary is already expired after a scheduling stall.
  // It is never reconstructed as the later sample plus the old remainder.
  assert qlog_close_deadline.effective(111, 110, 5000)
    == Error(qlog_close_deadline.DeadlineExpired)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn native_qlog_allowance_only_shortens_absolute_deadline_test() -> Nil {
  assert qlog_close_deadline.effective(100, 10_000, 5000) == Ok(5100)
  assert qlog_close_deadline.effective(100, 4000, 5000) == Ok(4000)
  assert qlog_close_deadline.effective(
      9_223_372_036_854_775_806,
      9_223_372_036_854_775_807,
      5000,
    )
    == Ok(9_223_372_036_854_775_807)
  assert qlog_close_deadline.effective(
      9_223_372_036_854_775_808,
      9_223_372_036_854_775_807,
      5000,
    )
    == Error(qlog_close_deadline.InvalidConfiguration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn relative_compatibility_boundary_is_created_once_test() -> Nil {
  assert qlog_close_deadline.from_remaining(100, 50, 5000) == Ok(150)
  assert qlog_close_deadline.from_remaining(100, 10_000, 5000) == Ok(5100)
  assert qlog_close_deadline.from_remaining(100, 0, 5000)
    == Error(qlog_close_deadline.InvalidConfiguration)
  assert qlog_close_deadline.from_remaining(9_223_372_036_854_775_807, 1, 5000)
    == Error(qlog_close_deadline.DeadlineOutOfRange)
}
