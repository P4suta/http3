//// A Gleam-native HTTP/3 API.
////
//// This pre-alpha package provides bounded and streaming clients and server,
//// plus typed advanced transport controls, without exposing backend-specific
//// Erlang values.

import http3/internal/backend

/// Returns whether the native QUIC core is available on this runtime.
///
/// This probes the required OTP cryptographic primitives. It does not make a
/// network connection or assert that a particular peer is reachable.
pub fn is_supported() -> Bool {
  backend.is_supported()
}
