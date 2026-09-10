//// Stable, redacted errors shared by every HTTP protocol.

/// The operation phase in which a finite deadline expired.
pub type TimeoutPhase {
  DnsLookup
  Connect
  TlsHandshake
  Operation
  Idle
  Total
}

/// A protocol layer that rejected or terminated an exchange.
pub type ProtocolLayer {
  Http1
  Http2
  Http3
  Quic
}

/// A client or server policy that refused an operation.
pub type PolicyKind {
  RedirectPolicy
  RetryPolicy
  SecurityPolicy
  ProxyPolicy
  CachePolicy
}

/// A bounded resource that was exhausted or refused.
pub type ResourceKind {
  Connections
  Streams
  RequestWorkers
  Memory
  Queue
  BufferedBody
  FileHandles
}

/// A body-specific failure that is safe to inspect and log.
pub type BodyErrorKind {
  InvalidLimit
  ReadFailed
  TooLarge(maximum_bytes: Int)
  InvalidChunk
  LengthMismatch(expected_bytes: Int, received_bytes: Int)
  NotReplayable
}

/// Stable top-level error classification.
pub type ErrorKind {
  Dns
  ConnectFailed
  Tls
  Timeout(TimeoutPhase)
  Protocol(ProtocolLayer)
  Policy(PolicyKind)
  Body(BodyErrorKind)
  Resource(ResourceKind)
  Cancelled
  Service
}

/// A redacted HTTP error.
///
/// Runtime exception text, peer-controlled reason phrases, paths, credentials,
/// and backend terms are deliberately not retained in this value.
pub opaque type Error {
  ErrorValue(kind: ErrorKind)
}

/// Construct a redacted error from its stable classification.
pub fn new(kind: ErrorKind) -> Error {
  ErrorValue(kind)
}

/// Return the stable classification of an error.
pub fn kind(error: Error) -> ErrorKind {
  error.kind
}

/// Return a fixed, redacted description suitable for diagnostics.
pub fn message(error: Error) -> String {
  case error.kind {
    Dns -> "DNS lookup failed"
    ConnectFailed -> "HTTP connection failed"
    Tls -> "TLS authentication or handshake failed"
    Timeout(DnsLookup) -> "DNS lookup timed out"
    Timeout(Connect) -> "HTTP connection timed out"
    Timeout(TlsHandshake) -> "TLS handshake timed out"
    Timeout(Operation) -> "HTTP operation timed out"
    Timeout(Idle) -> "HTTP connection became idle"
    Timeout(Total) -> "HTTP operation exceeded its total deadline"
    Protocol(Http1) -> "HTTP/1.1 protocol failure"
    Protocol(Http2) -> "HTTP/2 protocol failure"
    Protocol(Http3) -> "HTTP/3 protocol failure"
    Protocol(Quic) -> "QUIC transport failure"
    Policy(RedirectPolicy) -> "HTTP redirect policy refused the request"
    Policy(RetryPolicy) -> "HTTP retry policy refused the request"
    Policy(SecurityPolicy) -> "HTTP security policy refused the request"
    Policy(ProxyPolicy) -> "HTTP proxy policy refused the request"
    Policy(CachePolicy) -> "HTTP cache policy refused the request"
    Body(InvalidLimit) -> "HTTP body limit is invalid"
    Body(ReadFailed) -> "HTTP body source could not be read"
    Body(TooLarge(_)) -> "HTTP body exceeds its configured limit"
    Body(InvalidChunk) -> "HTTP body source returned an invalid chunk"
    Body(LengthMismatch(_, _)) ->
      "HTTP body length does not match its declaration"
    Body(NotReplayable) -> "HTTP body cannot be regenerated"
    Resource(Connections) -> "HTTP connection capacity is exhausted"
    Resource(Streams) -> "HTTP stream capacity is exhausted"
    Resource(RequestWorkers) -> "HTTP request worker capacity is exhausted"
    Resource(Memory) -> "HTTP memory budget is exhausted"
    Resource(Queue) -> "HTTP queue capacity is exhausted"
    Resource(BufferedBody) -> "HTTP body buffer capacity is exhausted"
    Resource(FileHandles) -> "HTTP file capacity is exhausted"
    Cancelled -> "HTTP operation was cancelled"
    Service -> "HTTP service failed"
  }
}
