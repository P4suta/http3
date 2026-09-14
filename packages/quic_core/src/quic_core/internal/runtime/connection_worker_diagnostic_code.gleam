//// Stable payload-free failure codes for the server connection actor.
////
//// A failure is recorded as an ordered chain: the worker operation first,
//// followed by the server-transport, driver, connection-state, and TLS class
//// where those layers exist. The chain deliberately excludes identifiers,
//// endpoints, packet bytes, TLS messages, key material, numeric peer values,
//// and implementation terms. Existing meanings must never be reused.

import quic_core/internal/connection_state
import quic_core/internal/driver
import quic_core/internal/runtime/server_transport
import quic_core/internal/tls/engine

/// Connection-worker operation which observed a fatal internal result.
pub type Operation {
  NextDeadline
  Tick
  ReplayPolicy
  ReceiveDatagram
  IssueSessionTicket
  RejectPmtuProbe
  SendPmtuProbe
  CommitPmtuProbe
  PrepareDatagram
  SendDatagram
  CommitDatagram
}

/// Stable operation code in the 3000 range.
pub fn operation(operation: Operation) -> Int {
  case operation {
    NextDeadline -> 3001
    Tick -> 3002
    ReplayPolicy -> 3003
    ReceiveDatagram -> 3004
    IssueSessionTicket -> 3005
    RejectPmtuProbe -> 3006
    SendPmtuProbe -> 3007
    CommitPmtuProbe -> 3008
    PrepareDatagram -> 3009
    SendDatagram -> 3010
    CommitDatagram -> 3011
  }
}

/// Classify the error layers visible at the server-transport boundary.
pub fn server_transport_error(error: server_transport.Error) -> List(Int) {
  case error {
    server_transport.InvalidInput -> [3101]
    server_transport.TlsFailure(error) -> [3102, engine_error(error)]
    server_transport.DriverFailure(error) -> [3103, ..driver_error(error)]
    server_transport.StatelessResetFailure(_) -> [3104]
  }
}

fn driver_error(error: driver.Error) -> List(Int) {
  case error {
    driver.InvalidInput -> [3201]
    driver.DestinationConnectionIdMismatch -> [3202]
    driver.VersionNegotiationReceived(_) -> [3203]
    driver.PacketFailure(_) -> [3204]
    driver.ConnectionFailure(error) -> [3205, ..connection_error(error)]
    driver.RetryTokenTooLarge(_, _) -> [3206]
  }
}

fn connection_error(error: connection_state.Error) -> List(Int) {
  case error {
    connection_state.InvalidConfiguration -> [3301]
    connection_state.InvalidInput -> [3302]
    connection_state.ConnectionUnavailable -> [3303]
    connection_state.SpaceUnavailable -> [3304]
    connection_state.MissingReadKeys(_) -> [3305]
    connection_state.MissingWriteKeys(_) -> [3306]
    connection_state.PacketSpaceFailure -> [3307]
    connection_state.FlowControlFailure -> [3308]
    connection_state.StreamFailure -> [3309]
    connection_state.StreamQueueFailure(_) -> [3310]
    connection_state.UnknownStream(_) -> [3311]
    connection_state.StreamLimitFailure -> [3312]
    connection_state.ProtocolViolation(reason) -> [
      3313,
      protocol_violation_reason(reason),
    ]
    connection_state.CongestionLimited -> [3314]
    connection_state.PacingLimited(_) -> [3315]
    connection_state.RecoveryLimited -> [3316]
    connection_state.AmplificationLimited -> [3317]
    connection_state.DatagramNotNegotiated -> [3318]
    connection_state.DatagramTooLarge(_) -> [3319]
    connection_state.InitialKeyFailure(_) -> [3320]
    connection_state.FrameCodecFailure(_) -> [3321]
    connection_state.WirePacketFailure(_) -> [3322]
    connection_state.KeyUpdateFailure(_) -> [3323]
    connection_state.AeadUsageFailure(_) -> [3324]
    connection_state.PathValidationFailure(_) -> [3325]
    connection_state.ActiveMigrationDisabled -> [3326]
    connection_state.ConnectionIdFailure(_) -> [3327]
    connection_state.PmtuFailure(_) -> [3328]
    // 3329 is permanently reserved for a retired pre-v1 classification.
    connection_state.TlsFailure(error) -> [3330, engine_error(error)]
    connection_state.FrameAtWrongEncryptionLevel(level, kind) -> [
      3331,
      encryption_level(level),
      frame_kind(kind),
    ]
  }
}

fn protocol_violation_reason(
  reason: connection_state.ProtocolViolationReason,
) -> Int {
  case reason {
    connection_state.PacketVersionMismatch -> 3701
    connection_state.KeyPhaseCandidateRejected -> 3702
    connection_state.LongPacketHeaderMismatch -> 3703
    connection_state.CryptoSendAtZeroRtt -> 3704
    connection_state.EarlyDatagramLimitReduced -> 3705
    connection_state.InvalidPeerAckDelay -> 3706
    connection_state.InvalidPeerUdpPayloadSize -> 3707
    connection_state.NegativePacketTimestamp -> 3708
    connection_state.HandshakeFailureCloseAtZeroRtt -> 3709
    connection_state.CryptoFrameAtZeroRtt -> 3710
    connection_state.CryptoReassemblyInsertFailure -> 3711
    connection_state.CryptoReassemblyReadFailure -> 3712
    connection_state.StreamFrameDirectionViolation -> 3713
    connection_state.ResetStreamDirectionViolation -> 3714
    connection_state.StopSendingDirectionViolation -> 3715
    connection_state.MaxStreamDataDirectionViolation -> 3716
    connection_state.PathResponseQueueLimitExceeded -> 3717
    connection_state.HandshakeDoneStateViolation -> 3718
    connection_state.ServerEndpointClientConfirmation -> 3719
    connection_state.DatagramNotNegotiatedViolation -> 3720
    connection_state.DatagramFrameTooLargeViolation -> 3721
    connection_state.PeerConnectionIdRegistryMissing -> 3722
    connection_state.RemoteStreamIdentifierInvalid -> 3723
    connection_state.RemoteUsedLocalStream -> 3724
    connection_state.RemoteStreamIndexRegression -> 3725
    connection_state.StreamIdentifierEncodeFailure -> 3726
    connection_state.AckEcnRangesEmpty -> 3727
    connection_state.AckEcnValidationFailure -> 3728
    connection_state.ReservedBitsViolation -> 3729
  }
}

fn encryption_level(level: engine.EncryptionLevel) -> Int {
  case level {
    engine.Initial -> 3501
    engine.Handshake -> 3502
    engine.ZeroRtt -> 3503
    engine.OneRtt -> 3504
  }
}

fn frame_kind(kind: connection_state.FrameKind) -> Int {
  case kind {
    connection_state.PaddingFrame -> 3601
    connection_state.PingFrame -> 3602
    connection_state.AckFrame -> 3603
    connection_state.ResetStreamFrame -> 3604
    connection_state.StopSendingFrame -> 3605
    connection_state.CryptoFrame -> 3606
    connection_state.NewTokenFrame -> 3607
    connection_state.StreamFrame -> 3608
    connection_state.MaxDataFrame -> 3609
    connection_state.MaxStreamDataFrame -> 3610
    connection_state.MaxStreamsFrame -> 3611
    connection_state.DataBlockedFrame -> 3612
    connection_state.StreamDataBlockedFrame -> 3613
    connection_state.StreamsBlockedFrame -> 3614
    connection_state.NewConnectionIdFrame -> 3615
    connection_state.RetireConnectionIdFrame -> 3616
    connection_state.PathChallengeFrame -> 3617
    connection_state.PathResponseFrame -> 3618
    connection_state.ConnectionCloseTransportFrame -> 3619
    connection_state.ConnectionCloseApplicationFrame -> 3620
    connection_state.HandshakeDoneFrame -> 3621
    connection_state.DatagramFrame -> 3622
  }
}

fn engine_error(error: engine.Error) -> Int {
  case error {
    engine.InvalidConfiguration -> 3401
    engine.UnexpectedEncryptionLevel -> 3402
    engine.UnexpectedMessage -> 3403
    engine.TruncatedHandshake -> 3404
    engine.UnsupportedVersion(_) -> 3405
    engine.UnsupportedCipherSuite(_) -> 3406
    engine.UnsupportedKeyShare -> 3407
    engine.InvalidHelloRetryRequest -> 3408
    engine.MissingExtension(_) -> 3409
    engine.NoApplicationProtocol -> 3410
    engine.FinishedMismatch -> 3411
    engine.ClientCertificateRequired -> 3412
    engine.HandshakeFailure(_) -> 3413
    engine.HelloFailure(_) -> 3414
    engine.ExtensionValueFailure(_) -> 3415
    engine.TransportParameterFailure(_) -> 3416
    engine.VersionNegotiationFailure -> 3417
    engine.CryptoFailure(_) -> 3418
    engine.KeyExchangeFailure(_) -> 3419
    engine.TranscriptFailure(_) -> 3420
    engine.TrafficKeyFailure(_) -> 3421
    engine.MessageBodyFailure(_) -> 3422
    engine.AuthenticationFailure(_) -> 3423
    engine.ResumptionFailure(_) -> 3424
    engine.SessionTicketFailure(_) -> 3425
  }
}
