import gleam/io
import same_connection_test.{
  DistinctActorMismatch, RetainedDistinctActorMismatch,
  RetainedSameActorMismatch, SameActorMismatch, StableActorIdentity,
}

@external(erlang, "erlang", "halt")
fn halt(status: Int) -> Nil

pub fn main() -> Nil {
  case same_connection_test.observe_same_connection_identity() {
    StableActorIdentity -> io.println("HTTP3_SAME_CONNECTION_IDENTITY_READY")
    SameActorMismatch -> {
      io.println("HTTP3_SAME_CONNECTION_SAME_LIVE_MISMATCH")
      halt(42)
    }
    DistinctActorMismatch -> {
      io.println("HTTP3_SAME_CONNECTION_DISTINCT_LIVE_MISMATCH")
      halt(43)
    }
    RetainedSameActorMismatch -> {
      io.println("HTTP3_SAME_CONNECTION_RETAINED_SAME_MISMATCH")
      halt(44)
    }
    RetainedDistinctActorMismatch -> {
      io.println("HTTP3_SAME_CONNECTION_RETAINED_DISTINCT_MISMATCH")
      halt(45)
    }
  }
}
