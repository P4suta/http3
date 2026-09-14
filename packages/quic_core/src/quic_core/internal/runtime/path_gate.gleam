//// Fail-closed receive-path binding during QUIC path validation.
////
//// The transport state deliberately contains no socket or endpoint values.
//// Consequently, once a PATH_RESPONSE has been decrypted it cannot itself
//// prove which local socket or remote tuple delivered it. Runtime owners use
//// this gate before authentication while a validation attempt is active.
//// Only the exact candidate path reaches the shared transport state; traffic
//// from the former path and unrelated paths is treated as ordinary network
//// loss until the candidate succeeds or times out.

/// Runtime classification of the socket/tuple that delivered one datagram.
pub type Source {
  Active
  Candidate
  Unrelated
}

/// Whether one datagram may reach the shared QUIC authentication state.
///
/// Outside validation, the runtime must accept an authenticated active path
/// and may inspect a new tuple in order to discover NAT rebinding. During
/// validation, accepting anything but `Candidate` could authenticate the
/// challenge on a different path.
pub fn may_authenticate(validation_in_progress: Bool, source: Source) -> Bool {
  case validation_in_progress, source {
    False, _ -> True
    True, Candidate -> True
    True, Active | True, Unrelated -> False
  }
}
