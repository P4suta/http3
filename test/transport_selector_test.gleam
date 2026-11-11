import gleam/dynamic.{type Dynamic}

// nolint: trailing_underscore -- EUnit's generator convention discovers the finite native contract leaves.
@external(erlang, "http_transport_selector_test", "contracts")
pub fn selectors_test_() -> Dynamic
