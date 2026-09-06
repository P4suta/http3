//// Runtime clocks used by HTTP/3-owned persistence and deadline adapters.

import quic_core/diagnostics

@external(erlang, "http3_internal_transport_ffi", "unix_milliseconds")
fn raw_unix_milliseconds() -> Int

/// Return a nonnegative monotonic timestamp for finite deadline arithmetic.
pub fn monotonic_milliseconds() -> Int {
  diagnostics.monotonic_milliseconds()
}

/// Return the current Unix timestamp for versioned persisted state.
///
/// This value must never be used to calculate in-process deadlines.
pub fn unix_milliseconds() -> Int {
  raw_unix_milliseconds()
}
