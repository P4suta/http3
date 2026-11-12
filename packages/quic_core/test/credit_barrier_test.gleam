//// The real router-drop trace must be scalar, one-shot, scoped and joined.

@external(erlang, "quic_core_test_ffi", "credit_barrier_contract")
fn contract(case_: Int) -> Bool

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn router_trace_emits_one_scalar_envelope_test() -> Nil {
  assert contract(0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn router_drop_releases_held_actor_test() -> Nil {
  assert contract(1)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn missing_drop_deadline_releases_held_actor_test() -> Nil {
  assert contract(2)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn action_exception_releases_held_actor_test() -> Nil {
  assert contract(3)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owner_death_reaps_guardian_and_releases_held_actor_test() -> Nil {
  assert contract(4)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn listener_death_releases_held_actor_test() -> Nil {
  assert contract(5)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn independent_trace_session_survives_one_shot_cleanup_test() -> Nil {
  assert contract(6)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn held_actor_death_reaps_guardian_test() -> Nil {
  assert contract(7)
}
