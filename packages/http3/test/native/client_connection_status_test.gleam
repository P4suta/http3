import gleam/option.{None, Some}
import http3/internal/native/client_connection
import http3/internal/native/settings_memory
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

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn peer_settings_wait_uses_one_absolute_injected_deadline_test() -> Nil {
  assert client_connection.settings_wait_decision(False, 100, 125)
    == client_connection.WaitForSettings(25)
  assert client_connection.settings_wait_decision(False, 125, 125)
    == client_connection.SettingsWaitExpired
  assert client_connection.settings_wait_decision(False, 126, 125)
    == client_connection.SettingsWaitExpired
  // Receipt wins even if the caller observes it at the exact deadline.
  assert client_connection.settings_wait_decision(True, 125, 125)
    == client_connection.SettingsReady
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn ticket_settings_context_fails_closed_and_defaults_when_absent_test() -> Nil {
  assert client_connection.decode_remembered_settings_context(<<>>) == Ok(None)
  let assert Ok(snapshot) =
    settings_memory.advertised(4096, 65_536, 16, True, False)
  let assert Ok(encoded) = settings_memory.encode(snapshot)
  assert client_connection.decode_remembered_settings_context(encoded)
    == Ok(Some(snapshot))
  assert client_connection.decode_remembered_settings_context(<<1, 2, 3>>)
    == Error(settings_memory.InvalidEncoding)
}
