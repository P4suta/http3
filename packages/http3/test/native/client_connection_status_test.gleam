import http3/internal/native/client_connection
import quic_core/diagnostics

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn settled_handshake_status_needs_no_actor_refresh_test() -> Nil {
  assert !client_connection.status_refresh_needed(
    diagnostics.NotAttempted,
    diagnostics.ResumptionNotAttempted,
  )
  assert !client_connection.status_refresh_needed(
    diagnostics.Accepted,
    diagnostics.Resumed,
  )
  assert !client_connection.status_refresh_needed(
    diagnostics.Rejected,
    diagnostics.FullHandshake,
  )
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn pending_handshake_status_requires_actor_refresh_test() -> Nil {
  assert client_connection.status_refresh_needed(
    diagnostics.Pending,
    diagnostics.FullHandshake,
  )
  assert client_connection.status_refresh_needed(
    diagnostics.NotAttempted,
    diagnostics.ResumptionPending,
  )
}
