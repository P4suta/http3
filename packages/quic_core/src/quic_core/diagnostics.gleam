//// Redacted, immutable diagnostics for generic QUIC connections.
////
//// These values contain counters and negotiated public metadata only. They
//// never expose sockets, processes, native terms, certificate contents,
//// session-ticket fields, or traffic secrets.

import gleam/result
import quic_core.{type CongestionControl, type Version}
import quic_core/internal/qlog
import quic_core/internal/udp

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

/// Current stream resources retained by the connection actor and transport.
///
/// Both values are instantaneous counts rather than lifetime counters. They
/// contain no stream identifiers or payload metadata, so operators can use
/// them to detect a retention regression without widening the opaque handle
/// boundary.
pub type ResourceStats {
  ResourceStats(runtime_stream_handles: Int, transport_streams: Int)
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

/// Redacted configuration and outcome of the current client handshake.
///
/// The booleans distinguish caller policy, ticket capability, and the actual
/// protocol result without exposing ticket bytes, identities, endpoints, or
/// TLS key material. This snapshot is finite and does not retain a history.
pub type HandshakeAttempt {
  HandshakeAttempt(
    ticket_supplied: Bool,
    zero_rtt_enabled: Bool,
    ticket_allows_zero_rtt: Bool,
    early_data: EarlyDataStatus,
    resumption: ResumptionStatus,
  )
}

/// Redacted QUIC packet class. `UnknownPacket` is used when a runtime can
/// count a packet but deliberately does not retain its decoded header.
pub type PacketType {
  Initial
  Handshake
  ZeroRtt
  OneRtt
  Retry
  VersionNegotiation
  StatelessReset
  UnknownPacket
}

/// Traffic-key class for lifecycle events. No key bytes can be supplied.
pub type KeyType {
  ServerInitialSecret
  ClientInitialSecret
  ServerHandshakeSecret
  ClientHandshakeSecret
  ServerZeroRttSecret
  ClientZeroRttSecret
  ServerOneRttSecret
  ClientOneRttSecret
}

/// High-level congestion-controller phase for portable traces.
pub type CongestionState {
  SlowStart
  CongestionAvoidance
  Recovery
  ApplicationLimited
}

/// Payload-free cause of a congestion-controller state transition.
pub type CongestionTrigger {
  PacketLoss
  EcnCe
  PersistentCongestion
}

/// Side responsible for an HTTP/3 settings or stream observation.
pub type Initiator {
  LocalInitiator
  RemoteInitiator
}

/// HTTP/3 stream role after its preface or request direction is known.
pub type Http3StreamType {
  RequestStream
  ControlStream
  PushStream
  ReservedStream
  UnknownStream
  QpackEncoderStream
  QpackDecoderStream
}

/// HTTP/3 frame class. This intentionally excludes header fields and payload.
pub type Http3FrameType {
  DataFrame
  HeadersFrame
  CancelPushFrame
  SettingsFrame
  PushPromiseFrame
  GoAwayFrame
  MaxPushIdFrame
  UnknownFrame
}

/// One opaque bounded writer for an opt-in qlog trace.
///
/// The API and its redaction guarantees are stable. The emitted qlog schema
/// revision is revision-pinned experimental output and is not a stable data
/// format contract.
pub opaque type Writer {
  Writer(handle: qlog.Writer)
}

/// A connection-owned, payload-free bridge into its existing diagnostic trace.
///
/// Unlike `Writer`, this capability cannot close the trace, inspect its queue,
/// or emit transport events. Application protocols can only add the bounded,
/// typed observations exposed by the `emit_*` functions below. The QUIC
/// connection remains the sole owner of writer lifetime and flushing.
pub opaque type ApplicationSink {
  ApplicationSink(handle: qlog.Writer)
}

/// One finite payload-free application diagnostic code.
///
/// The wrapper is intentionally opaque: an application can publish a stable
/// integer taxonomy, but cannot attach text, terms, headers, or body bytes to
/// the transport trace.
pub opaque type ApplicationCode {
  ApplicationCode(value: Int)
}

/// Endpoint perspective recorded without peer identity or application data.
pub type VantagePoint {
  Client
  Server
}

/// Filesystem, configured-bound, or asynchronous output failure.
pub type Error {
  InvalidDirectory
  InvalidLimit
  InvalidDiagnosticCode
  OpenFailed(Int)
  WriteFailed(Int)
}

/// Bounded writer counters without paths, payloads, or peer identifiers.
pub type Stats {
  Stats(dropped_events: Int, write_errors: Int, queued_events: Int)
}

/// Milliseconds elapsed in the runtime's non-negative monotonic clock domain.
///
/// Values are suitable for deadline arithmetic and the qlog functions in this
/// module. They are process-local observations, not wall-clock timestamps, and
/// must not be persisted or compared across runtime instances.
pub fn monotonic_milliseconds() -> Int {
  udp.monotonic_millisecond()
}

/// Verify that an explicit qlog directory is writable without retaining an
/// open file or enabling diagnostics implicitly.
pub fn validate_directory(directory: String) -> Result(Nil, Error) {
  qlog.validate_directory(directory) |> map_qlog_result
}

/// Open a finite asynchronous qlog writer. No global writer is installed.
///
/// The maximum includes the event currently being written, so accepted but
/// unfinished diagnostic work never exceeds this bound even if the filesystem
/// stalls. One writer-wide watermark serializes timestamps from every producer:
/// an accepted observation older than the preceding accepted observation is
/// emitted at the preceding time. Dropped observations never move the watermark.
pub fn open(
  directory: String,
  vantage_point: VantagePoint,
  now_milliseconds: Int,
  maximum_queued_events: Int,
) -> Result(Writer, Error) {
  qlog.open(
    directory,
    case vantage_point {
      Client -> qlog.Client
      Server -> qlog.Server
    },
    now_milliseconds,
    maximum_queued_events,
  )
  |> map_qlog_result
  |> result.map(Writer)
}

/// Record a connection attempt or acceptance without endpoint identifiers.
pub fn connection_started(writer: Writer, now_milliseconds: Int) -> Nil {
  let Writer(handle) = writer
  qlog.connection_started(handle, now_milliseconds)
}

/// Record only the size of one received UDP datagram.
pub fn datagram_received(
  writer: Writer,
  now_milliseconds: Int,
  bytes: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.datagram_received(handle, now_milliseconds, bytes)
}

/// Record only the size of one sent UDP datagram.
pub fn datagram_sent(writer: Writer, now_milliseconds: Int, bytes: Int) -> Nil {
  let Writer(handle) = writer
  qlog.datagram_sent(handle, now_milliseconds, bytes)
}

/// Record a received batch when only its datagram count is available.
pub fn datagrams_received(
  writer: Writer,
  now_milliseconds: Int,
  count: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.datagrams_received(handle, now_milliseconds, count)
}

/// Record a sent batch when only its datagram count is available.
pub fn datagrams_sent(
  writer: Writer,
  now_milliseconds: Int,
  count: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.datagrams_sent(handle, now_milliseconds, count)
}

/// Record one received packet without packet number, connection ID, or data.
pub fn packet_received(
  writer: Writer,
  now_milliseconds: Int,
  packet_type: PacketType,
  bytes: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.packet_received(
    handle,
    now_milliseconds,
    packet_type_code(packet_type),
    bytes,
  )
}

/// Record one sent packet without packet number, connection ID, or data.
pub fn packet_sent(
  writer: Writer,
  now_milliseconds: Int,
  packet_type: PacketType,
  bytes: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.packet_sent(
    handle,
    now_milliseconds,
    packet_type_code(packet_type),
    bytes,
  )
}

/// Record installation of a traffic-key class without accepting key bytes.
pub fn key_updated(
  writer: Writer,
  now_milliseconds: Int,
  key_type: KeyType,
) -> Nil {
  let Writer(handle) = writer
  qlog.key_updated(handle, now_milliseconds, key_type_code(key_type))
}

/// Record disposal of a traffic-key class without accepting key bytes.
pub fn key_discarded(
  writer: Writer,
  now_milliseconds: Int,
  key_type: KeyType,
) -> Nil {
  let Writer(handle) = writer
  qlog.key_discarded(handle, now_milliseconds, key_type_code(key_type))
}

/// Record congestion window and in-flight bytes from an immutable snapshot.
pub fn recovery_metrics(
  writer: Writer,
  now_milliseconds: Int,
  path: PathStats,
) -> Nil {
  let Writer(handle) = writer
  let PathStats(_, _, _, _, congestion_window, bytes_in_flight, _, _) = path
  qlog.recovery_metrics(
    handle,
    now_milliseconds,
    congestion_window,
    bytes_in_flight,
  )
}

/// Record a portable semantic congestion-controller phase.
pub fn congestion_state_updated(
  writer: Writer,
  now_milliseconds: Int,
  state: CongestionState,
) -> Nil {
  let Writer(handle) = writer
  qlog.congestion_state_updated(
    handle,
    now_milliseconds,
    congestion_state_code(state),
  )
}

/// Record a portable state transition and its bounded semantic cause.
pub fn congestion_state_updated_with_trigger(
  writer: Writer,
  now_milliseconds: Int,
  state: CongestionState,
  trigger: CongestionTrigger,
) -> Nil {
  let Writer(handle) = writer
  qlog.congestion_state_updated_with_trigger(
    handle,
    now_milliseconds,
    congestion_state_code(state),
    congestion_trigger_code(trigger),
  )
}

/// Record that HTTP/3 settings were produced or authenticated.
pub fn http3_parameters_set(
  writer: Writer,
  now_milliseconds: Int,
  initiator: Initiator,
) -> Nil {
  let Writer(handle) = writer
  qlog.http3_parameters_set(handle, now_milliseconds, initiator_code(initiator))
}

/// Record a stream's known HTTP/3 role without stream data.
pub fn http3_stream_type_set(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  stream_type: Http3StreamType,
) -> Nil {
  let Writer(handle) = writer
  qlog.http3_stream_type_set(
    handle,
    now_milliseconds,
    stream_id,
    stream_type_code(stream_type),
  )
}

/// Record one locally created HTTP/3 frame with only bounded metadata.
pub fn http3_frame_created(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  frame_type: Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.http3_frame_created(
    handle,
    now_milliseconds,
    stream_id,
    frame_type_code(frame_type),
    payload_bytes,
  )
}

/// Record one parsed HTTP/3 frame with only bounded metadata.
pub fn http3_frame_parsed(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  frame_type: Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  let Writer(handle) = writer
  qlog.http3_frame_parsed(
    handle,
    now_milliseconds,
    stream_id,
    frame_type_code(frame_type),
    payload_bytes,
  )
}

/// Validate one non-secret application diagnostic code.
pub fn application_code(value: Int) -> Result(ApplicationCode, Error) {
  case value >= 0 && value <= 2_147_483_647 {
    True -> Ok(ApplicationCode(value))
    False -> Error(InvalidDiagnosticCode)
  }
}

/// Record only a validated application code using qlog's generic error event.
/// No API exists here for a message or arbitrary event payload.
pub fn application_error(
  writer: Writer,
  now_milliseconds: Int,
  code: ApplicationCode,
) -> Nil {
  let Writer(handle) = writer
  let ApplicationCode(value) = code
  qlog.application_error(handle, now_milliseconds, value)
}

/// Wrap a connection-owned writer in the restricted application capability.
///
/// This constructor is package-internal so only `quic_core/client` and
/// `quic_core/server` can obtain it from their supervised connection actors.
@internal
pub fn application_sink(writer: qlog.Writer) -> ApplicationSink {
  ApplicationSink(writer)
}

/// Record local or peer HTTP/3 settings without field values.
pub fn emit_http3_parameters_set(
  sink: ApplicationSink,
  now_milliseconds: Int,
  initiator: Initiator,
) -> Nil {
  let ApplicationSink(handle) = sink
  qlog.http3_parameters_set(handle, now_milliseconds, initiator_code(initiator))
}

/// Record a typed QUIC stream's HTTP/3 role without stream contents.
pub fn emit_http3_stream_type_set(
  sink: ApplicationSink,
  now_milliseconds: Int,
  stream_id: quic_core.StreamId,
  stream_type: Http3StreamType,
) -> Nil {
  let ApplicationSink(handle) = sink
  qlog.http3_stream_type_set(
    handle,
    now_milliseconds,
    quic_core.stream_id_value(stream_id),
    stream_type_code(stream_type),
  )
}

/// Record a locally created HTTP/3 frame without fields or payload bytes.
///
/// `payload_bytes` is only the finite encoded payload length retained by qlog;
/// callers cannot attach the payload itself.
pub fn emit_http3_frame_created(
  sink: ApplicationSink,
  now_milliseconds: Int,
  stream_id: quic_core.StreamId,
  frame_type: Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  let ApplicationSink(handle) = sink
  qlog.http3_frame_created(
    handle,
    now_milliseconds,
    quic_core.stream_id_value(stream_id),
    frame_type_code(frame_type),
    payload_bytes,
  )
}

/// Record a parsed HTTP/3 frame without fields or payload bytes.
///
/// `payload_bytes` is only the finite encoded payload length retained by qlog;
/// callers cannot attach the payload itself.
pub fn emit_http3_frame_parsed(
  sink: ApplicationSink,
  now_milliseconds: Int,
  stream_id: quic_core.StreamId,
  frame_type: Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  let ApplicationSink(handle) = sink
  qlog.http3_frame_parsed(
    handle,
    now_milliseconds,
    quic_core.stream_id_value(stream_id),
    frame_type_code(frame_type),
    payload_bytes,
  )
}

/// Record one validated application code without a message or arbitrary data.
pub fn emit_application_error(
  sink: ApplicationSink,
  now_milliseconds: Int,
  code: ApplicationCode,
) -> Nil {
  let ApplicationSink(handle) = sink
  let ApplicationCode(value) = code
  qlog.application_error(handle, now_milliseconds, value)
}

/// Record the start of active path migration without endpoint tuples.
pub fn migration_started(writer: Writer, now_milliseconds: Int) -> Nil {
  let Writer(handle) = writer
  qlog.migration_started(handle, now_milliseconds)
}

/// Record abandonment of a candidate path without its failure payload.
pub fn migration_abandoned(writer: Writer, now_milliseconds: Int) -> Nil {
  let Writer(handle) = writer
  qlog.migration_abandoned(handle, now_milliseconds)
}

/// Record an authenticated path update without recording either address.
pub fn path_updated(writer: Writer, now_milliseconds: Int) -> Nil {
  let Writer(handle) = writer
  qlog.path_updated(handle, now_milliseconds)
}

/// Record local connection shutdown without its reason or application data.
pub fn connection_closed(writer: Writer, now_milliseconds: Int) -> Nil {
  let Writer(handle) = writer
  qlog.connection_closed(handle, now_milliseconds)
}

/// Flush and close the writer idempotently.
pub fn close(writer: Writer) -> Result(Nil, Error) {
  let Writer(handle) = writer
  qlog.close(handle) |> map_qlog_result
}

/// Snapshot finite-queue health without trace contents.
///
/// `queued_events` includes the in-flight device write and never exceeds the
/// maximum supplied to `open`.
pub fn stats(writer: Writer) -> Result(Stats, Error) {
  let Writer(handle) = writer
  case qlog.stats(handle) {
    Ok(qlog.Stats(dropped, errors, queued)) ->
      Ok(Stats(dropped, errors, queued))
    Error(error) -> Error(map_qlog_error(error))
  }
}

fn packet_type_code(packet_type: PacketType) -> Int {
  case packet_type {
    Initial -> 1
    Handshake -> 2
    ZeroRtt -> 3
    OneRtt -> 4
    Retry -> 5
    VersionNegotiation -> 6
    StatelessReset -> 7
    UnknownPacket -> 8
  }
}

fn key_type_code(key_type: KeyType) -> Int {
  case key_type {
    ServerInitialSecret -> 1
    ClientInitialSecret -> 2
    ServerHandshakeSecret -> 3
    ClientHandshakeSecret -> 4
    ServerZeroRttSecret -> 5
    ClientZeroRttSecret -> 6
    ServerOneRttSecret -> 7
    ClientOneRttSecret -> 8
  }
}

fn congestion_state_code(state: CongestionState) -> Int {
  case state {
    SlowStart -> 1
    CongestionAvoidance -> 2
    Recovery -> 3
    ApplicationLimited -> 4
  }
}

fn congestion_trigger_code(trigger: CongestionTrigger) -> Int {
  case trigger {
    PacketLoss -> 1
    EcnCe -> 2
    PersistentCongestion -> 3
  }
}

fn initiator_code(initiator: Initiator) -> Int {
  case initiator {
    LocalInitiator -> 1
    RemoteInitiator -> 2
  }
}

fn stream_type_code(stream_type: Http3StreamType) -> Int {
  case stream_type {
    RequestStream -> 1
    ControlStream -> 2
    PushStream -> 3
    ReservedStream -> 4
    UnknownStream -> 5
    QpackEncoderStream -> 6
    QpackDecoderStream -> 7
  }
}

fn frame_type_code(frame_type: Http3FrameType) -> Int {
  case frame_type {
    DataFrame -> 1
    HeadersFrame -> 2
    CancelPushFrame -> 3
    SettingsFrame -> 4
    PushPromiseFrame -> 5
    GoAwayFrame -> 6
    MaxPushIdFrame -> 7
    UnknownFrame -> 8
  }
}

fn map_qlog_result(value: Result(value, qlog.Error)) -> Result(value, Error) {
  case value {
    Ok(value) -> Ok(value)
    Error(error) -> Error(map_qlog_error(error))
  }
}

fn map_qlog_error(error: qlog.Error) -> Error {
  case error {
    qlog.InvalidDirectory -> InvalidDirectory
    qlog.InvalidLimit -> InvalidLimit
    qlog.OpenFailed(reason) -> OpenFailed(reason)
    qlog.WriteFailed(reason) -> WriteFailed(reason)
  }
}
