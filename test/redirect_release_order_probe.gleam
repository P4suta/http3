import client_test

/// Focused mutation runner for 307/308 cleanup ordering.
pub fn main() -> Nil {
  repeat(20)
}

fn repeat(remaining: Int) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      client_test.temporary_redirect_307_waits_for_response_release_before_replay_test()
      client_test.permanent_redirect_308_waits_for_response_release_before_replay_test()
      repeat(remaining - 1)
    }
  }
}
