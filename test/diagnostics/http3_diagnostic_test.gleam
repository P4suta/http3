import diagnostics/http3_diagnostic
import gleeunit/should

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn diagnostic_scenarios_are_a_fixed_allowlist_test() -> Nil {
  http3_diagnostic.supported_scenarios()
  |> should.equal([
    "round-trip",
    "connection-isolation",
    "slow-consumer",
    "cleanup",
  ])
  http3_diagnostic.is_supported_scenario("round-trip") |> should.be_true
  http3_diagnostic.is_supported_scenario("../../unbounded") |> should.be_false
}
