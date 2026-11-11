import client_test

/// Focused mutation runner for status retry cleanup ordering.
pub fn main() -> Nil {
  repeat(20)
}

fn repeat(remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      client_test.status_503_retry_waits_for_response_release_before_replay_test()
      client_test.status_retry_release_timeout_never_constructs_replay_test()
      repeat(remaining - 1)
    }
  }
}
