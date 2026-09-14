//// Type-level contract for the bounded live frame trace.
////
//// The Erlang tracer constructs these terms across an FFI boundary. Keeping
//// one Gleam consumer pins the constructor layout and makes every retained
//// field visibly metadata-only: endpoint, packet/stream number, offset, byte
//// count, FIN state, and monotonic time. No payload slot exists.

import public_memory_test.{
  AckCommitted, ClientEndpoint, ConnectionTicked, ServerEndpoint,
  StreamCommitted,
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn live_trace_contract_retains_metadata_without_payload_test() -> Nil {
  let sent = StreamCommitted(ClientEndpoint, 7, 4, 1024, 31, True, 99)
  let acknowledged = AckCommitted(ServerEndpoint, 8, 100)
  let ticked = ConnectionTicked(ClientEndpoint, 101)

  assert sent == StreamCommitted(ClientEndpoint, 7, 4, 1024, 31, True, 99)
  assert acknowledged == AckCommitted(ServerEndpoint, 8, 100)
  assert ticked == ConnectionTicked(ClientEndpoint, 101)
}
