//// Stable, non-secret failures shared by the HTTP/3 public API.
////
//// These values identify where an operation failed without exposing runtime
//// handles, mailbox messages, certificate contents, traffic secrets, or
//// backend-formatted strings.

import gleam/option.{type Option}

/// The endpoint that produced or initiated a protocol outcome.
pub type Origin {
  Local
  Peer
}

/// A UDP or diagnostic file-system operation.
pub type SocketOperation {
  OpenSocket
  BindSocket
  ConnectSocket
  SendDatagram
  ReceiveDatagram
  ReadFile
  WriteFile
}

/// The finite deadline that expired.
pub type TimeoutPhase {
  Dns
  Connect
  Handshake
  Operation
  Idle
  Drain
  Total
}

/// A bounded resource controlled by configuration or admission policy.
pub type Resource {
  Connections
  Handshakes
  BidirectionalStreams
  UnidirectionalStreams
  RequestBody
  ResponseBody
  Buffer
  EndpointMemory
  Queue
  Frame
  Datagram
  QpackTable
  QpackBlockedStreams
  AcceptWaiters
  Telemetry
}

/// One typed runtime, transport, or application failure.
///
/// Protocol and close codes are present only when a trustworthy code was
/// available. Unknown codes are represented by `None`, never by a sentinel.
pub type Failure {
  Resolution
  Socket(operation: SocketOperation)
  Tls(origin: Origin)
  Quic(origin: Origin, code: Option(Int))
  Http3(origin: Origin, code: Option(Int))
  Timeout(phase: TimeoutPhase)
  Cancelled
  Closed(origin: Origin, code: Option(Int))
  Limit(resource: Resource, maximum: Int)
  Overload(resource: Resource)
}
