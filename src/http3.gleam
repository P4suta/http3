//// A Gleam-native HTTP/3 API.
////
//// This pre-alpha bootstrap exposes backend capability discovery and a
//// bounded, buffered client. Streaming, connection reuse, and server APIs
//// will be added without exposing backend-specific Erlang values.

import http3/internal/backend

/// Returns whether the configured QUIC backend is available on this runtime.
///
/// This probes the backend itself. It does not make a network connection or
/// assert that a particular peer is reachable.
pub fn is_supported() -> Bool {
  backend.is_supported()
}
