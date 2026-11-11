import gleam/list
import http3/internal/native/client_connection
import http3/internal/native/connection_state
import http3/internal/native/diagnostic_code
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/origin
import http3/internal/native/protocol
import http3/internal/varint

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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn frame_parser_diagnostics_preserve_primary_and_redact_subordinate_values_test() -> Nil {
  let errors = [
    #(frame_parser.InvalidConfiguration, 2301),
    #(frame_parser.NonByteAligned, 2302),
    #(frame_parser.BufferLimitExceeded(987_654), 2303),
    #(frame_parser.TruncatedFrame, 2304),
    #(frame_parser.FrameFailure(frame.NonByteAligned), 2310),
    #(frame_parser.FrameFailure(frame.InvalidLimits), 2311),
    #(frame_parser.FrameFailure(frame.Truncated), 2312),
    #(frame_parser.FrameFailure(frame.InvalidFrame), 2313),
    #(frame_parser.FrameFailure(frame.ProhibitedHttp2FrameType(987_654)), 2314),
    #(frame_parser.FrameFailure(frame.DuplicateSetting(987_654)), 2315),
    #(frame_parser.FrameFailure(frame.ProhibitedSetting(987_654)), 2316),
    #(frame_parser.FrameFailure(frame.PayloadLimitExceeded(987_654)), 2317),
    #(frame_parser.FrameFailure(frame.FieldSectionLimitExceeded(987_654)), 2318),
    #(frame_parser.FrameFailure(frame.SettingsLimitExceeded(987_654)), 2319),
    #(
      frame_parser.FrameFailure(
        frame.OriginFailure(origin.OriginTooLong(987_654)),
      ),
      2320,
    ),
    #(frame_parser.FrameFailure(frame.IntegerFailure(varint.OutOfRange)), 2321),
  ]
  list.each(errors, fn(pair) {
    let #(error, code) = pair
    let failure =
      client_connection.Http3OperationFailed(
        "private-operation-certificate-key-signature-marker",
        protocol.FrameParserFailure(error),
      )
    assert diagnostic_code.connection_error(failure) == 2005
    assert diagnostic_code.connection_errors(failure) == [2005, code]
    assert diagnostic_code.protocol_errors(protocol.FrameParserFailure(error))
      == [2005, code]
  })
  assert diagnostic_code.connection_errors(client_connection.OperationTimeout)
    == [1007]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn websocket_diagnostics_have_stable_payload_free_codes_test() -> Nil {
  let failures = [
    #(diagnostic_code.WebsocketFrameSyntax, 2401),
    #(diagnostic_code.WebsocketInvalidUtf8, 2402),
    #(diagnostic_code.WebsocketMessageLimit, 2403),
    #(diagnostic_code.WebsocketProtocolState, 2404),
    #(diagnostic_code.WebsocketInvalidClose, 2405),
    #(diagnostic_code.WebsocketInvalidHandshake, 2410),
    #(diagnostic_code.WebsocketUnsupportedVersion, 2411),
  ]
  list.each(failures, fn(pair) {
    let #(failure, expected) = pair
    assert diagnostic_code.websocket_failure(failure) == expected
  })
}
