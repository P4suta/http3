//// Static contract checks for the public RFC 9525 identity profile.

import gleam/dynamic

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_certificate_identity_profile_test", "contracts")
pub fn certificate_identity_profile_contracts_test_() -> dynamic.Dynamic
