//// Deterministic runtime faults included in the ordinary Gleam test gate.

@external(erlang, "http_transport_fault_ffi", "delayed_ipv6_does_not_starve_ipv4_case")
pub fn delayed_ipv6_does_not_starve_ipv4_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "delayed_dns_family_does_not_block_a_usable_answer_case")
pub fn delayed_dns_family_does_not_block_a_usable_answer_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "address_cap_preserves_both_families_case")
pub fn address_cap_preserves_both_families_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "duplicate_answers_do_not_consume_candidate_capacity_case")
pub fn duplicate_answers_do_not_consume_candidate_capacity_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "all_candidates_share_the_connect_deadline_case")
pub fn all_candidates_share_the_connect_deadline_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "total_deadline_remains_distinct_from_connect_case")
pub fn total_deadline_remains_distinct_from_connect_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "dns_deadline_remains_distinct_from_connect_case")
pub fn dns_deadline_remains_distinct_from_connect_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "failed_dials_leave_no_workers_or_messages_case")
pub fn failed_dials_leave_no_workers_or_messages_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "caller_exit_stops_pending_dials_case")
pub fn caller_exit_stops_pending_dials_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "trace_is_bounded_and_contains_only_scalar_metadata_case")
pub fn trace_is_bounded_and_contains_only_scalar_metadata_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "simultaneous_success_closes_every_losing_socket_case")
pub fn simultaneous_success_closes_every_losing_socket_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "late_connected_success_closes_the_losing_socket_case")
pub fn late_connected_success_closes_the_losing_socket_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "worker_registry_rejects_unsealed_and_live_processes_case")
pub fn worker_registry_rejects_unsealed_and_live_processes_test() -> Nil

@external(erlang, "http_transport_fault_ffi", "malformed_dial_results_are_redacted_case")
pub fn malformed_dial_results_are_redacted_test() -> Nil
