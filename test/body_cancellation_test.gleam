import gleam/option.{None}
import gleeunit
import gleeunit/should
import http/body
import http/error

@external(erlang, "http_body_cancel_test_ffi", "timeout_cause_survives_pending_registry_confirmation")
fn timeout_cause_survives_pending_registry_confirmation() -> Bool

pub fn cleanup_timeout_cause_survives_pending_registry_confirmation_test() -> Nil {
  assert timeout_cause_survives_pending_registry_confirmation()
}

@external(erlang, "http_body_cancel_test_ffi", "success_requires_registry_confirmation")
fn success_requires_registry_confirmation() -> Bool

pub fn cleanup_success_requires_registry_confirmation_test() -> Nil {
  assert success_requires_registry_confirmation()
}

@external(erlang, "http_body_cancel_test_ffi", "normal_guardian_exit_waits_for_delegated_result")
fn normal_guardian_exit_waits_for_delegated_result() -> Bool

pub fn normal_guardian_exit_keeps_waiting_for_the_delegated_cleanup_result_test() -> Nil {
  assert normal_guardian_exit_waits_for_delegated_result()
}

pub fn typed_cleanup_timeout_is_preserved_after_callback_exit_test() -> Nil {
  assert_typed_cleanup(error.new(error.Timeout(error.Operation)))
}

pub fn typed_cleanup_cancellation_is_preserved_after_callback_exit_test() -> Nil {
  assert_typed_cleanup(error.new(error.Cancelled))
}

fn assert_typed_cleanup(failure: error.Error) -> Nil {
  let source =
    body.from_pull_with_cleanup(
      body.pull(fn(_) { Ok(body.PullEnd([])) }),
      None,
      None,
      fn() { Error(failure) },
    )
    |> should.be_ok
  assert body.cancel_within(source, 1000) == Error(failure)
  assert body.await_release(source, 0) == body.Released(Error(failure))
  assert body.cancel_within(source, 1000) == Error(failure)
}

@external(erlang, "http_body_cancel_test_ffi", "callback_outcomes")
fn callback_outcomes() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "timeout_joins_callback")
fn timeout_joins_callback() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "owner_death_joins_callback")
fn owner_death_joins_callback() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "concurrent_cancel_once")
fn concurrent_cancel_once() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "concurrent_cancel_preserves_cleanup_result")
fn concurrent_cancel_preserves_cleanup_result() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "owner_death_publishes_cleanup_result")
fn owner_death_publishes_cleanup_result() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "pending_and_completed_timeout_are_distinct")
fn pending_and_completed_timeout_are_distinct() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "success_joins_guardian_and_worker")
fn success_joins_guardian_and_worker() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "guardian_death_joins_trapping_callback")
fn guardian_death_joins_trapping_callback() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "guardian_death_stabilizes_shared_result")
fn guardian_death_stabilizes_shared_result() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "guardian_death_during_release_observer_is_reaped")
fn guardian_death_during_release_observer_is_reaped() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "detached_observer_owner_death_is_reaped")
fn detached_observer_owner_death_is_reaped() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "prearmed_recovery_survives_pre_callback_primary_death")
fn prearmed_recovery_survives_pre_callback_primary_death() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "completion_and_owner_down_observe_release_once")
fn completion_and_owner_down_observe_release_once() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "await_release_joins_recovery_controller")
fn await_release_joins_recovery_controller() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "orphaned_recovery_registration_is_removed_after_controller_down")
fn orphaned_recovery_registration_is_removed_after_controller_down() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "recovery_registry_restart_is_fail_closed_and_private")
fn recovery_registry_restart_is_fail_closed_and_private() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "scheduler_stall_keeps_the_original_deadline")
fn scheduler_stall_keeps_the_original_deadline() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "expired_registration_never_starts_callback")
fn expired_registration_never_starts_callback() -> Bool

@external(erlang, "http_body_cancel_test_ffi", "release_observer_is_bounded_and_once")
fn release_observer_is_bounded_and_once() -> Bool

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn cancellation_callback_failure_is_redacted_and_isolated_test() -> Nil {
  assert callback_outcomes()
}

pub fn cancellation_timeout_observes_callback_worker_exit_test() -> Nil {
  assert timeout_joins_callback()
}

pub fn cancelling_owner_exit_reclaims_guardian_and_callback_test() -> Nil {
  assert owner_death_joins_callback()
}

pub fn concurrent_body_cancellation_invokes_cleanup_once_test() -> Nil {
  assert concurrent_cancel_once()
}

pub fn concurrent_cancellation_waits_for_the_actual_cleanup_result_test() -> Nil {
  assert concurrent_cancel_preserves_cleanup_result()
}

pub fn cancelling_owner_exit_publishes_the_shared_cleanup_result_test() -> Nil {
  assert owner_death_publishes_cleanup_result()
}

pub fn pending_cleanup_and_completed_callback_timeout_are_distinct_test() -> Nil {
  assert pending_and_completed_timeout_are_distinct()
}

pub fn successful_cancellation_returns_after_its_guardian_and_worker_exit_test() -> Nil {
  assert success_joins_guardian_and_worker()
}

pub fn guardian_death_cannot_orphan_a_trapping_callback_test() -> Nil {
  assert guardian_death_joins_trapping_callback()
}

pub fn guardian_death_publishes_one_stable_shared_result_test() -> Nil {
  assert guardian_death_stabilizes_shared_result()
}

pub fn guardian_death_during_release_observer_joins_the_delegated_tree_test() -> Nil {
  assert guardian_death_during_release_observer_is_reaped()
}

pub fn detached_observer_owner_death_joins_the_tree_and_publishes_failure_test() -> Nil {
  assert detached_observer_owner_death_is_reaped()
}

pub fn a_prearmed_recovery_owner_closes_a_claim_before_callback_start_test() -> Nil {
  assert prearmed_recovery_survives_pre_callback_primary_death()
}

pub fn callback_completion_racing_owner_down_still_observes_release_once_test() -> Nil {
  assert completion_and_owner_down_observe_release_once()
}

pub fn await_release_waits_until_the_recovery_controller_is_down_test() -> Nil {
  assert await_release_joins_recovery_controller()
}

pub fn orphaned_recovery_registry_state_converges_after_controller_down_test() -> Nil {
  assert orphaned_recovery_registration_is_removed_after_controller_down()
}

pub fn recovery_registry_restart_fails_closed_and_public_tampering_is_rejected_test() -> Nil {
  assert recovery_registry_restart_is_fail_closed_and_private()
}

pub fn a_stalled_guardian_cannot_rebase_the_callback_deadline_test() -> Nil {
  assert scheduler_stall_keeps_the_original_deadline()
}

pub fn a_callback_is_not_started_after_its_registration_deadline_test() -> Nil {
  assert expired_registration_never_starts_callback()
}

pub fn a_stalled_release_observer_is_bounded_and_invoked_once_test() -> Nil {
  assert release_observer_is_bounded_and_once()
}
