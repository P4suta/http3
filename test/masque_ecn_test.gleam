//// Deterministic runtime faults included in the ordinary Gleam test gate.

@external(erlang, "http_masque_ecn_test_ffi", "unsupported_options_preserve_explicit_unobserved_default_case")
pub fn unsupported_options_preserve_explicit_unobserved_default_test() -> Nil

@external(erlang, "http_masque_ecn_test_ffi", "accepted_option_without_readback_is_unobserved_case")
pub fn accepted_option_without_readback_is_unobserved_test() -> Nil

@external(erlang, "http_masque_ecn_test_ffi", "observed_socket_default_is_distinct_from_wire_evidence_case")
pub fn observed_socket_default_is_distinct_from_wire_evidence_test() -> Nil

@external(erlang, "http_masque_ecn_test_ffi", "observed_nonzero_ecn_never_claims_not_ect_case")
pub fn observed_nonzero_ecn_never_claims_not_ect_test() -> Nil

@external(erlang, "http_masque_ecn_test_ffi", "option_exceptions_are_redacted_as_unobserved_case")
pub fn option_exceptions_are_redacted_as_unobserved_test() -> Nil
