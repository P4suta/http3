import client_diagnostics_test
import client_test
import http3_client_adapter_test

/// A narrow executable used by the supervised Windows regression harness.
/// It keeps test compilation and execution in the normal Gleam dev profile while avoiding unrelated long-running integration suites.
pub fn main() -> Nil {
  repeat(20)
}

fn repeat(remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      client_test.automatic_retry_requires_safe_progress_method_body_and_budget_test()
      client_test.retry_failure_progress_is_conservative_without_peer_evidence_test()
      client_test.http3_connection_loss_without_goaway_is_possibly_processed_test()
      client_test.failed_attempt_replay_is_constructed_only_after_source_release_test()
      client_test.failed_attempt_replay_survives_prior_terminal_source_release_test()
      client_test.failed_attempt_release_timeout_never_constructs_replay_test()
      client_test.possibly_processed_failure_neither_releases_nor_replays_again_test()
      http3_client_adapter_test.request_rejected_preserves_peer_unprocessed_evidence_test()
      client_test.status_503_retry_waits_for_response_release_before_replay_test()
      client_test.status_retry_release_timeout_never_constructs_replay_test()
      client_test.temporary_redirect_307_waits_for_response_release_before_replay_test()
      client_test.permanent_redirect_308_waits_for_response_release_before_replay_test()
      client_diagnostics_test.status_retry_releases_old_attempt_before_new_attempt_test()
      repeat(remaining - 1)
    }
  }
}
