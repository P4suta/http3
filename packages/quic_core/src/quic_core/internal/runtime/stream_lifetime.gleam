//// Role-neutral initialization for application-facing stream wrappers.
////
//// A unidirectional QUIC stream has only one usable direction. Treating the
//// unavailable direction as live would retain an otherwise completed wrapper
//// forever, while treating an invalid identifier as terminal could release
//// state prematurely. This helper centralizes that distinction for both
//// endpoint actors.

import quic_core/stream_id

/// Return initial `send_finished` and `receive_finished` direction state.
pub fn initial_terminal_directions(
  endpoint: stream_id.Initiator,
  identifier: Int,
) -> #(Bool, Bool) {
  case stream_id.decode(identifier) {
    // nolint: thrown_away_error -- Invalid IDs keep both directions live.
    Error(_) -> #(False, False)
    Ok(_) -> #(
      !stream_id.can_send(identifier, endpoint),
      !stream_id.can_receive(identifier, endpoint),
    )
  }
}
