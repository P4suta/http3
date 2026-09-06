//// Stable payload-free diagnostic taxonomy for the HTTP/3 runtime.
////
//// Codes are grouped by layer so traces can be compared across runs without
//// retaining operation strings, stream identifiers, peer reasons, headers,
//// bodies, or native terms. Existing meanings are never reused.

import http3/internal/native/client_connection
import http3/internal/native/connection_state as http3_state
import http3/internal/native/protocol

/// Classify one internal client failure into a finite non-secret code.
pub fn connection_error(error: client_connection.Error) -> Int {
  case error {
    client_connection.InvalidInput -> 1001
    client_connection.ResolutionFailed -> 1002
    client_connection.SocketUnavailable -> 1003
    client_connection.DnsTimeout -> 1004
    client_connection.ConnectTimeout -> 1005
    client_connection.HandshakeTimeout -> 1006
    client_connection.OperationTimeout -> 1007
    client_connection.TotalTimeout -> 1008
    client_connection.TrustStoreFailed -> 1009
    client_connection.TlsHandshakeFailed -> 1010
    client_connection.QuicTransportFailed(_) -> 1011
    client_connection.CoreFailure(_) -> 1012
    client_connection.PeerClosed -> 1013
    client_connection.MigrationUnavailable -> 1014
    client_connection.VersionNegotiationReceived(_) -> 1015
    client_connection.VersionNegotiationFailed -> 1016
    client_connection.Http3OperationFailed(_, protocol_error) ->
      protocol_failure(protocol_error)
  }
}

fn protocol_failure(error: protocol.Error) -> Int {
  case error {
    protocol.InvalidPeerStream(_) -> 2001
    protocol.MissingInput(_) -> 2002
    protocol.PrefaceLimitExceeded -> 2003
    protocol.ResourceFailure(_) -> 2004
    protocol.FrameParserFailure(_) -> 2005
    protocol.InstructionParserFailure(_, _) -> 2006
    protocol.Http3Failure(error) -> http3_failure(error)
  }
}

fn http3_failure(error: http3_state.Error) -> Int {
  case error {
    http3_state.InvalidConfiguration -> 2101
    http3_state.WrongRole -> 2102
    http3_state.InvalidStreamId(_) -> 2103
    http3_state.DuplicateCriticalStreamId -> 2104
    http3_state.CriticalStreamsAlreadyInstalled -> 2105
    http3_state.CriticalStreamsNotInstalled -> 2106
    http3_state.TransactionLimitExceeded(_) -> 2107
    http3_state.DuplicateTransaction(_) -> 2108
    http3_state.MissingTransaction(_) -> 2109
    http3_state.StreamBlocked(_) -> 2110
    http3_state.FrameUnexpected -> 2111
    http3_state.RequestRejected(_) -> 2112
    http3_state.PushRejected(_) -> 2113
    http3_state.MissingPushPromise(_) -> 2114
    http3_state.InvalidMessageFraming -> 2115
    http3_state.ControlFailure(_) -> 2116
    http3_state.FrameFailure(_) -> 2117
    http3_state.HeaderFailure(_) -> 2118
    http3_state.MessageFailure(_) -> 2119
    http3_state.EncoderFailure(_) -> 2120
    http3_state.DecoderFailure(_) -> 2121
    http3_state.InstructionFailure(_) -> 2122
    http3_state.PushFailure(_) -> 2123
    http3_state.DrainFailure(_) -> 2124
    http3_state.DatagramFailure(_) -> 2125
    http3_state.StreamRegistryFailure(_) -> 2126
    http3_state.PriorityFailure(_) -> 2127
    http3_state.SchedulerFailure(_) -> 2128
    http3_state.IntegerFailure(_) -> 2129
    http3_state.BlockedStreamBufferExceeded(_) -> 2130
    http3_state.BlockedConnectionBufferExceeded(_) -> 2131
    http3_state.QpackDecompressionFailure(_) -> 2132
    http3_state.QpackEncoderStreamFailure(_) -> 2133
    http3_state.QpackDecoderStreamFailure(_) -> 2134
  }
}
