//// Test-only HTTP/3 loopback fixtures.

import http3/client

@external(erlang, "http3_test_ffi", "with_server")
pub fn with_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that drops the first client datagram.
@external(erlang, "http3_test_ffi", "with_lossy_server")
pub fn with_lossy_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that reverses the first two client datagrams.
@external(erlang, "http3_test_ffi", "with_reordering_proxy")
pub fn with_reordering_proxy(run: fn(Int, BitArray) -> result) -> result

/// Race two receivers, cancel the blocked one, and return both outcomes.
@external(erlang, "http3_test_ffi", "concurrent_next_events")
pub fn concurrent_next_events(
  stream: client.Stream,
) -> List(Result(client.ResponseEvent, client.Error))

/// Race two idempotent cancellation calls.
@external(erlang, "http3_test_ffi", "concurrent_cancellations")
pub fn concurrent_cancellations(
  stream: client.Stream,
) -> List(Result(client.Cancellation, client.Error))

/// Verify that a connection worker exits when its creating process exits.
@external(erlang, "http3_test_ffi", "connection_owner_cleanup")
pub fn connection_owner_cleanup(
  configuration: client.Client,
  host: String,
  port: Int,
) -> Bool
