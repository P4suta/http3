import gleeunit

pub fn main() -> Nil {
  gleeunit.main()
}

@external(erlang, "http3_shared_lease_test_ffi", "concurrent_candidates_deduplicate_and_join_loser_test")
pub fn concurrent_candidates_deduplicate_and_join_loser_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "logical_full_scales_to_a_new_physical_candidate_test")
pub fn logical_full_scales_to_a_new_physical_candidate_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "without_pooling_never_shares_physical_candidates_test")
pub fn without_pooling_never_shares_physical_candidates_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "one_bad_lease_drains_only_after_its_sibling_finishes_test")
pub fn one_bad_lease_drains_only_after_its_sibling_finishes_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "expired_adoption_keeps_original_holder_and_drops_late_reply_test")
pub fn expired_adoption_keeps_original_holder_and_drops_late_reply_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "late_activated_candidate_is_joined_instead_of_becoming_idle_test")
pub fn late_activated_candidate_is_joined_instead_of_becoming_idle_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "terminal_close_owns_every_lease_guard_and_joins_once_test")
pub fn terminal_close_owns_every_lease_guard_and_joins_once_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "capability_calls_reject_non_result_replies_test")
pub fn capability_calls_reject_non_result_replies_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "unregistering_a_live_shared_owner_starts_and_joins_shutdown_test")
pub fn unregistering_a_live_shared_owner_starts_and_joins_shutdown_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "retire_timeout_drops_late_reply_without_crashing_lifecycle_test")
pub fn retire_timeout_drops_late_reply_without_crashing_lifecycle_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "close_deadline_is_bounded_and_never_extended_test")
pub fn close_deadline_is_bounded_and_never_extended_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "deduplicated_nonresponsive_candidate_is_forced_test")
pub fn deduplicated_nonresponsive_candidate_is_forced_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "nonreusable_nonresponsive_shared_owner_is_forced_test")
pub fn nonreusable_nonresponsive_shared_owner_is_forced_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "idle_nonresponsive_shared_owner_is_forced_test")
pub fn idle_nonresponsive_shared_owner_is_forced_test() -> Nil

@external(erlang, "http3_shared_lease_test_ffi", "repeated_unregister_nonresponsive_shared_owner_is_forced_test")
pub fn repeated_unregister_nonresponsive_shared_owner_is_forced_test() -> Nil
