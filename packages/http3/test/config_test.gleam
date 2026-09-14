import http3/config
import http3/failure

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn defaults_are_finite_and_match_public_body_bounds_test() -> Nil {
  let deadlines = config.default_deadlines()
  let limits = config.default_limits()
  assert config.deadline(deadlines, failure.Dns) == 5000
  assert config.deadline(deadlines, failure.Total) == 30_000
  assert config.limit(limits, failure.RequestBody) == 8_388_608
  assert config.limit(limits, failure.ResponseBody) == 8_388_608
  assert config.limit(limits, failure.Buffer) == 262_144
  assert config.limit(limits, failure.Connections) == 1024
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn policy_updates_are_typed_and_zero_is_never_unlimited_test() -> Nil {
  let deadlines = config.default_deadlines()
  let limits = config.default_limits()
  assert config.with_deadline(deadlines, failure.Handshake, 0)
    == Error(config.InvalidDeadline(failure.Handshake, 0))
  assert config.with_limit(limits, failure.Queue, 0)
    == Error(config.InvalidLimit(failure.Queue, 0))

  // nolint: assert_ok_pattern -- a valid finite update is the assertion.
  let assert Ok(deadlines) =
    config.with_deadline(deadlines, failure.Handshake, 2500)
  // nolint: assert_ok_pattern -- a valid finite update is the assertion.
  let assert Ok(limits) = config.with_limit(limits, failure.Queue, 64)
  assert config.deadline(deadlines, failure.Handshake) == 2500
  assert config.limit(limits, failure.Queue) == 64
}
