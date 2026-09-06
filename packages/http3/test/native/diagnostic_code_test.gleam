import http3/internal/native/client_connection
import http3/internal/native/connection_state
import http3/internal/native/diagnostic_code
import http3/internal/native/protocol

// Diagnostic codes are stable categories, never raw stream identifiers,
// operation strings, peer text, or implementation terms.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn classifies_internal_failures_without_payloads_test() -> Nil {
  assert diagnostic_code.connection_error(client_connection.OperationTimeout)
    == 1007
  assert diagnostic_code.connection_error(
      client_connection.Http3OperationFailed(
        "receive_stream",
        protocol.MissingInput(987_654),
      ),
    )
    == 2002
  assert diagnostic_code.connection_error(
      client_connection.Http3OperationFailed(
        "receive_stream",
        protocol.Http3Failure(connection_state.InvalidMessageFraming),
      ),
    )
    == 2115
}
