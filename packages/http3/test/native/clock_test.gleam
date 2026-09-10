import http3/internal/clock

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn clocks_are_nonnegative_and_monotonic_test() -> Nil {
  let before = clock.monotonic_milliseconds()
  let unix = clock.unix_milliseconds()
  let after = clock.monotonic_milliseconds()

  assert before >= 0
  assert after >= before
  assert unix > 0
}
