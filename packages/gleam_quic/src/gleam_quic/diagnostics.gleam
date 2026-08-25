//// Redacted, immutable diagnostics for generic QUIC connections.
////
//// These values contain counters and negotiated public metadata only. They
//// never expose sockets, processes, native terms, certificate contents,
//// session-ticket fields, or traffic secrets.

import gleam_quic.{type CongestionControl, type Version}

/// Stable connection lifecycle.
pub type Phase {
  Handshaking
  Established
  Closing
  Draining
  Closed
}

/// Outcome of an explicit early-data attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Outcome of an explicitly supplied resumption ticket.
pub type ResumptionStatus {
  ResumptionNotAttempted
  ResumptionPending
  Resumed
  FullHandshake
}

/// Authenticated TLS 1.3 cipher suite without key material.
pub type CipherSuite {
  Aes128GcmSha256
  Aes256GcmSha384
  Chacha20Poly1305Sha256
}

/// Current path timings are milliseconds; window and flight values are bytes.
pub type PathStats {
  PathStats(
    latest_rtt_milliseconds: Int,
    smoothed_rtt_milliseconds: Int,
    minimum_rtt_milliseconds: Int,
    rtt_variation_milliseconds: Int,
    congestion_window: Int,
    bytes_in_flight: Int,
    in_recovery: Bool,
    congested: Bool,
  )
}

/// Runtime-owned packet, byte, ACK, retransmission, and batching counters.
pub type ConnectionStats {
  ConnectionStats(
    packets_received: Int,
    packets_sent: Int,
    bytes_received: Int,
    bytes_sent: Int,
    acknowledgements_sent: Int,
    retransmissions: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
  )
}

/// Bounded diagnostic writer counters without trace contents.
pub type TelemetryStats {
  TelemetryStats(
    qlog_dropped_events: Int,
    qlog_write_errors: Int,
    qlog_queued_events: Int,
  )
}

/// Non-secret connection configuration and negotiated metadata.
pub type ConnectionInfo {
  ConnectionInfo(
    version: Version,
    application_protocol: String,
    cipher_suite: CipherSuite,
    congestion_control: CongestionControl,
    early_data: EarlyDataStatus,
    resumption: ResumptionStatus,
  )
}
