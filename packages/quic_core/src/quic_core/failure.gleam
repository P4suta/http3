//// Stable, non-secret failures shared by the QUIC public API.
////
//// Values identify the failing phase without exposing runtime handles,
//// mailbox messages, certificate contents, traffic secrets, or backend text.

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

/// A bounded QUIC endpoint or transport resource.
pub type Resource {
  Connections
  Handshakes
  BidirectionalStreams
  UnidirectionalStreams
  Buffer
  EndpointMemory
  Queue
  Datagram
  AcceptWaiters
  Telemetry
}

/// One typed resolution, I/O, TLS, QUIC transport, or limit failure.
///
/// Protocol and close codes are present only when a trustworthy code is
/// available. Unknown codes use `None`; no backend-formatted string crosses
/// this boundary.
pub type Failure {
  Resolution
  Socket(operation: SocketOperation)
  Tls(origin: Origin)
  Quic(origin: Origin, code: Option(Int))
  Timeout(phase: TimeoutPhase)
  Cancelled
  Closed(origin: Origin, code: Option(Int))
  Limit(resource: Resource, maximum: Int)
  Overload(resource: Resource)
}
