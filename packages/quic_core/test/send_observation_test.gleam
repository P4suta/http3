import gleeunit/should

@external(erlang, "quic_core_test_ffi", "send_observation_contract")
fn contract(case_number: Int) -> Bool

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn delayed_memory_refusal_preserves_public_cause_test() -> Nil {
  contract(0) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn expired_owner_closes_admission_and_publication_test() -> Nil {
  contract(1) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_updates_the_current_park_cause_test() -> Nil {
  contract(2) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exact_terminal_result_wins_once_test() -> Nil {
  contract(3) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn terminal_result_survives_delayed_notification_test() -> Nil {
  contract(4) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn terminal_result_survives_worker_exit_test() -> Nil {
  contract(5) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owner_death_releases_observation_and_refuses_work_test() -> Nil {
  contract(6) |> should.be_true
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_expiry_races_have_one_terminal_winner_test() -> Nil {
  contract(7) |> should.be_true
}
