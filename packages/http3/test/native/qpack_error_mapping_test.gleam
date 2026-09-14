import gleam/option.{None, Some}
import http3/internal/native/client_connection
import http3/internal/native/connection_state
import http3/internal/native/protocol
import http3/internal/native/server_connection
import http3/internal/native/stream_registry
import http3/internal/qpack/decoder
import http3/internal/qpack/encoder
import http3/internal/qpack/instruction_stream
import quic_core/server as core_server

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_each_qpack_failure_context_to_its_registered_code_test() -> Nil {
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(connection_state.QpackDecompressionFailure(
        decoder.InvalidRequiredInsertCount,
      )),
    )
    == Some(0x200)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(connection_state.QpackEncoderStreamFailure(
        decoder.EncoderInstructionFailure,
      )),
    )
    == Some(0x201)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(connection_state.QpackDecoderStreamFailure(
        encoder.InvalidInsertCountIncrement,
      )),
    )
    == Some(0x202)
  assert protocol.peer_application_error_code(protocol.InstructionParserFailure(
      instruction_stream.EncoderStream,
      instruction_stream.BufferLimitExceeded(1),
    ))
    == Some(0x201)
  assert protocol.peer_application_error_code(protocol.InstructionParserFailure(
      instruction_stream.DecoderStream,
      instruction_stream.BufferLimitExceeded(1),
    ))
    == Some(0x202)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_critical_stream_failures_without_misclassifying_local_errors_test() -> Nil {
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(connection_state.StreamRegistryFailure(
        stream_registry.DuplicateQpackEncoderStream,
      )),
    )
    == Some(0x103)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        connection_state.StreamRegistryFailure(
          stream_registry.ClosedCriticalStream(6),
        ),
      ),
    )
    == Some(0x104)
  assert protocol.peer_application_error_code(protocol.ResourceFailure(
      protocol.ResourceClosed,
    ))
    == None
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_owners_close_only_peer_attributable_protocol_failures_test() -> Nil {
  let qpack_failure =
    protocol.Http3Failure(connection_state.QpackDecompressionFailure(
      decoder.InvalidRequiredInsertCount,
    ))
  assert client_connection.peer_application_error_code(
      client_connection.Http3OperationFailed("receive_stream", qpack_failure),
    )
    == Some(0x200)
  assert client_connection.peer_application_error_code(
      client_connection.PeerClosed,
    )
    == None
  assert server_connection.peer_application_error_code(
      server_connection.ProtocolFailure(qpack_failure),
    )
    == Some(0x200)
  assert server_connection.peer_application_error_code(
      server_connection.CoreFailure(core_server.InvalidOperation),
    )
    == None
}
