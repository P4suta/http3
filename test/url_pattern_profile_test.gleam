//// The combined profile's input and finite matrix contract.

import gleam/dynamic

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_pattern_profile_test", "profile_contracts")
pub fn urlpattern_profile_contracts_test_() -> dynamic.Dynamic

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_pattern_profile_test", "matrix_contracts")
pub fn urlpattern_profile_matrix_test_() -> dynamic.Dynamic
