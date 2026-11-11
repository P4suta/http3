import gleam/io
import http3_client_adapter_test.{
  Multiplexed, SecondStreamUnavailableWhileFirstBodyOpen, UnexpectedFinitePhase,
}

@external(erlang, "erlang", "halt")
fn halt(status: Int) -> Nil

/// Isolated repetitions for the unified HTTP/3 multiplexing regression.
pub fn main() -> Nil {
  case batch_observation() {
    0 -> io.println("HTTP3_MULTIPLEXING_READY_COMPLETED_3")
    42 -> {
      io.println("HTTP3_MULTIPLEXING_EXPECTED_RED_UNAVAILABLE_3")
      halt(42)
    }
    _ -> {
      io.println("HTTP3_MULTIPLEXING_UNEXPECTED_FINITE_PHASE")
      halt(43)
    }
  }
}

/// Run the three deterministic observations without printing or halting.
///
/// The attested evidence child uses this finite status to write its loaded BEAM receipt before terminating with the corresponding process status.
@internal
pub fn batch_observation() -> Int {
  let #(status, _, _, _, _, _, _) = batch_observation_summary()
  status
}

/// Return only finite aggregate counters from the three fully cleaned cases.
/// Each expected case has already proved zero lifecycle/resource baselines and final fixture-role convergence before it contributes to `census_verified`.
@internal
pub fn batch_observation_summary() -> #(Int, Int, Int, Int, Int, Int, Int) {
  let baseline = http3_client_adapter_test.multiplexing_fixture_role_count()
  case baseline {
    0 -> {
      let #(status, multiplexed, unavailable, unexpected) =
        repeat(
          remaining: 3,
          multiplexed: 0,
          unavailable: 0,
          unexpected: 0,
          baseline_roles: baseline,
        )
      let final_roles =
        http3_client_adapter_test.multiplexing_fixture_role_count()
      #(
        status,
        multiplexed,
        unavailable,
        unexpected,
        baseline,
        final_roles,
        multiplexed + unavailable,
      )
    }
    _ -> #(43, 0, 0, 1, baseline, baseline, 0)
  }
}

fn repeat(
  remaining remaining: Int,
  multiplexed multiplexed: Int,
  unavailable unavailable: Int,
  unexpected unexpected: Int,
  baseline_roles baseline_roles: Int,
) -> #(Int, Int, Int, Int) {
  case remaining {
    0 ->
      case multiplexed, unavailable, unexpected {
        3, 0, 0 -> #(0, multiplexed, unavailable, unexpected)
        0, 3, 0 -> #(42, multiplexed, unavailable, unexpected)
        _, _, _ -> #(43, multiplexed, unavailable, unexpected)
      }
    _ -> {
      let baseline_before =
        http3_client_adapter_test.multiplexing_fixture_role_count()
        == baseline_roles
      let observation = http3_client_adapter_test.observe_http3_multiplexing()
      let baseline_after =
        http3_client_adapter_test.multiplexing_fixture_role_count()
        == baseline_roles
      case baseline_before && baseline_after {
        False ->
          repeat(
            remaining: remaining - 1,
            multiplexed: multiplexed,
            unavailable: unavailable,
            unexpected: unexpected + 1,
            baseline_roles: baseline_roles,
          )
        True ->
          case observation {
            Multiplexed ->
              repeat(
                remaining: remaining - 1,
                multiplexed: multiplexed + 1,
                unavailable: unavailable,
                unexpected: unexpected,
                baseline_roles: baseline_roles,
              )
            SecondStreamUnavailableWhileFirstBodyOpen ->
              repeat(
                remaining: remaining - 1,
                multiplexed: multiplexed,
                unavailable: unavailable + 1,
                unexpected: unexpected,
                baseline_roles: baseline_roles,
              )
            UnexpectedFinitePhase(_) ->
              repeat(
                remaining: remaining - 1,
                multiplexed: multiplexed,
                unavailable: unavailable,
                unexpected: unexpected + 1,
                baseline_roles: baseline_roles,
              )
          }
      }
    }
  }
}
