import gleam/result
import quic_core/config
import quic_core/failure
import quic_core/internal/runtime/budget

@external(erlang, "quic_send_completion_test_ffi", "observation_storage_is_bounded")
fn observation_storage_is_bounded() -> Bool

@external(erlang, "quic_send_completion_test_ffi", "history_storage_is_bounded")
fn history_storage_is_bounded() -> Bool

@external(erlang, "quic_send_completion_test_ffi", "owner_death_wins_ready_race")
fn owner_death_wins_ready_race() -> Bool

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maximum_code_history_and_replacement_fit_the_prepaid_reservation_test() -> Nil {
  assert history_storage_is_bounded()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn actual_observation_storage_fits_within_its_conservative_admission_test() -> Nil {
  assert observation_storage_is_bounded()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn owner_death_precedes_a_late_ready_notification_test() -> Nil {
  assert owner_death_wins_ready_race()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn admission_prepays_the_terminal_history_in_addition_to_existing_credit_and_working_set_test() -> Nil {
  assert budget.admission_quanta() * budget.quantum() >= 16_384 + 32_768 + 4096
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn admission_boundary_rejects_one_byte_below_and_accepts_the_exact_charge_test() -> Nil {
  let charge = budget.admission_quanta() * budget.quantum()
  assert budget.reserve(budget.new(65_535), <<1>>, charge)
    |> result.replace(Nil)
    == Error(failure.Limit(failure.EndpointMemory, 65_535))
  let assert Ok(ledger) = budget.reserve(budget.new(65_536), <<1>>, charge)
  assert budget.used(ledger) == 65_536
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn default_limits_still_fund_all_default_connection_reservations_test() -> Nil {
  let limits = config.default_limits()
  assert config.limit(limits, failure.Connections)
    * budget.admission_quanta()
    * budget.quantum()
    <= config.limit(limits, failure.EndpointMemory)
}
