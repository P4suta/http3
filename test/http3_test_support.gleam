//// Test-only HTTP/3 loopback fixtures.

@external(erlang, "http3_test_ffi", "with_server")
pub fn with_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that drops the first client datagram.
@external(erlang, "http3_test_ffi", "with_lossy_server")
pub fn with_lossy_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that reverses the first two client datagrams.
@external(erlang, "http3_test_ffi", "with_reordering_proxy")
pub fn with_reordering_proxy(run: fn(Int, BitArray) -> result) -> result
