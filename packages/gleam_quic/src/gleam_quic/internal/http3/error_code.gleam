//// Registered HTTP/3, QPACK, and HTTP Datagram application error codes.

/// Stable semantic error names used instead of raw integers internally.
pub type ErrorCode {
  NoError
  GeneralProtocolError
  InternalError
  StreamCreationError
  ClosedCriticalStream
  FrameUnexpected
  FrameError
  ExcessiveLoad
  IdError
  SettingsError
  MissingSettings
  RequestRejected
  RequestCancelled
  RequestIncomplete
  MessageError
  ConnectError
  VersionFallback
  DatagramError
  QpackDecompressionFailed
  QpackEncoderStreamError
  QpackDecoderStreamError
  ReservedOrUnknown(Int)
}

/// Encode a registered application error value.
pub fn encode(error: ErrorCode) -> Int {
  case error {
    NoError -> 0x100
    GeneralProtocolError -> 0x101
    InternalError -> 0x102
    StreamCreationError -> 0x103
    ClosedCriticalStream -> 0x104
    FrameUnexpected -> 0x105
    FrameError -> 0x106
    ExcessiveLoad -> 0x107
    IdError -> 0x108
    SettingsError -> 0x109
    MissingSettings -> 0x10a
    RequestRejected -> 0x10b
    RequestCancelled -> 0x10c
    RequestIncomplete -> 0x10d
    MessageError -> 0x10e
    ConnectError -> 0x10f
    VersionFallback -> 0x110
    DatagramError -> 0x33
    QpackDecompressionFailed -> 0x200
    QpackEncoderStreamError -> 0x201
    QpackDecoderStreamError -> 0x202
    ReservedOrUnknown(value) -> value
  }
}

/// Decode known values. Unregistered values are deliberately treated like
/// H3_NO_ERROR by protocol handling while their integer remains diagnostic.
pub fn decode(value: Int) -> ErrorCode {
  case value {
    0x100 -> NoError
    0x101 -> GeneralProtocolError
    0x102 -> InternalError
    0x103 -> StreamCreationError
    0x104 -> ClosedCriticalStream
    0x105 -> FrameUnexpected
    0x106 -> FrameError
    0x107 -> ExcessiveLoad
    0x108 -> IdError
    0x109 -> SettingsError
    0x10a -> MissingSettings
    0x10b -> RequestRejected
    0x10c -> RequestCancelled
    0x10d -> RequestIncomplete
    0x10e -> MessageError
    0x10f -> ConnectError
    0x110 -> VersionFallback
    0x33 -> DatagramError
    0x200 -> QpackDecompressionFailed
    0x201 -> QpackEncoderStreamError
    0x202 -> QpackDecoderStreamError
    unknown -> ReservedOrUnknown(unknown)
  }
}

/// RFC 9114 requires unknown error codes to have the semantics of NO_ERROR.
pub fn effective(error: ErrorCode) -> ErrorCode {
  case error {
    ReservedOrUnknown(_) -> NoError
    known -> known
  }
}
