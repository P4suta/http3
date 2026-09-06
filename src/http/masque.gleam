//// Bounded RFC 9298 CONNECT-UDP and RFC 9484 CONNECT-IP building blocks.
////
//// Client payload is held until a successful response confirms the Capsule
//// Protocol. Proxy authorization starts deny-all and uses exact UDP targets,
//// exact CONNECT-IP scopes, and explicit destination prefixes. Only permanent
//// Capsule registrations used by UDP/IP, plus the current permanent external
//// registration, are surfaced; provisional types are treated as unknown.

import gleam/bit_array
import gleam/bool
import gleam/erlang/process.{type Pid, type Subject}
import gleam/http
import gleam/http/request.{type Request}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import http/context
import http/status
import http/structured_fields
import http3/address as http3_address
import http3/capsule as http3_capsule
import http3/server as http3_server
import http3/transport as http3_transport

const maximum_integer = 4_611_686_018_427_387_903

const maximum_udp_payload_bytes = 65_527

const maximum_proxy_request_fields = 128

const maximum_default_udp_path_bytes = 2048

const minimum_udp_idle_timeout_milliseconds = 120_000

const maximum_datagram_capacity_attempts = 64

/// HTTP mapping selected for a MASQUE request.
pub type Protocol {
  Http1
  Http2
  Http3
}

/// All endpoint, wire, state, and authorization ceilings.
pub type Limits {
  Limits(
    maximum_datagram_bytes: Int,
    maximum_capsule_bytes: Int,
    maximum_address_entries: Int,
    maximum_route_entries: Int,
    maximum_policy_rules: Int,
  )
}

/// Validated target-socket idle policy for one CONNECT-UDP session.
///
/// Disabled is the default. A configured timeout can never be below the
/// RFC 9298 recommendation of two minutes or above the BEAM timer ceiling.
pub opaque type UdpProxyIdlePolicy {
  UdpProxyIdlePolicy(timeout_milliseconds: Option(Int))
}

/// Payload-free lifecycle of the optional single-deadline idle owner.
pub type UdpProxyIdleState {
  UdpIdleDisabled
  UdpIdleWatching
  UdpIdleStopped
  UdpIdleExpired
}

/// Bounded diagnostics for the optional CONNECT-UDP idle owner.
///
/// Activity counters contain no endpoint, packet size, payload, stream ID, or
/// runtime handle. Directional counters distinguish successful target sends
/// from validated target receives and always sum to `activity_events`.
/// `maximum_pending_commands` is always one when enabled.
pub type UdpProxyIdleSnapshot {
  UdpProxyIdleSnapshot(
    state: UdpProxyIdleState,
    timeout_milliseconds: Option(Int),
    remaining_milliseconds: Option(Int),
    maximum_pending_commands: Int,
    pending_command: Bool,
    activity_events: Int,
    outbound_activity_events: Int,
    inbound_activity_events: Int,
    wake_signals: Int,
    owner_wakeups: Int,
    deadline_checks: Int,
    expirations: Int,
    stop_signals: Int,
  )
}

/// One exact CONNECT-UDP target.
pub type UdpTarget {
  UdpTarget(host: String, port: Int)
}

/// One resolved IP address and UDP port admitted by proxy policy.
pub type UdpEndpoint {
  UdpEndpoint(address: IpAddress, port: Int)
}

/// Optional RFC 9484 request scope. `None` serializes as the wildcard `*`.
pub type IpScope {
  IpScope(target: Option(String), ip_protocol: Option(Int))
}

/// An encoded IPv4 or IPv6 address.
pub type IpAddress {
  Ipv4(BitArray)
  Ipv6(BitArray)
}

/// A canonical network prefix whose uncovered low bits are zero.
pub type IpPrefix {
  IpPrefix(address: IpAddress, length: Int)
}

/// One ADDRESS_ASSIGN entry.
pub type AssignedAddress {
  AssignedAddress(request_id: Int, prefix: IpPrefix)
}

/// One ADDRESS_REQUEST entry.
pub type RequestedAddress {
  RequestedAddress(request_id: Int, prefix: IpPrefix)
}

/// One inclusive ROUTE_ADVERTISEMENT entry.
pub type IpRoute {
  IpRoute(start: IpAddress, end: IpAddress, ip_protocol: Int)
}

/// Permanent Capsule types understood by this stable UDP/IP surface.
pub type Capsule {
  DatagramCapsule(BitArray)
  AddressAssign(List(AssignedAddress))
  AddressRequest(List(RequestedAddress))
  RouteAdvertisement(List(IpRoute))
  PermanentExtension(capsule_type: Int, value: BitArray)
}

/// Typed configuration, protocol, wire, and policy failures.
pub type Error {
  InvalidLimits
  InvalidIdleTimeout
  InvalidProxySetup
  InvalidAuthority
  InvalidTarget
  InvalidScope
  InvalidResponse
  UnexpectedStatus(Int)
  NotEstablished
  NonByteAligned
  DatagramLimitExceeded(Int)
  CapsuleLimitExceeded(Int)
  UnknownContext(Int)
  InvalidCapsule
  InvalidAddress
  InvalidRoute
  EntryLimitExceeded(Int)
  RequestIdReused(Int)
  PolicyLimitExceeded(Int)
  DestinationForbidden
  InvalidIpPacket
  HopLimitExceeded
}

/// A payload-free resolver failure returned by an application adapter.
pub type DnsLookupFailure {
  DnsLookupFailed
}

/// A classified UDP socket-open failure returned by an application adapter.
pub type UdpSocketOpenFailure {
  UdpConnectionRefused
  UdpDestinationUnroutable
  UdpDestinationUnavailable
  UdpSocketOpenTimedOut
}

/// Redacted reason a supervised UDP proxy setup was rejected.
pub type ProxySetupFailure {
  ProxyDnsError
  ProxyDnsTimeout
  ProxyDnsAdapterFailed
  ProxyDnsAnswerInvalid
  ProxyDestinationForbidden
  ProxySocketRefused
  ProxySocketUnroutable
  ProxySocketUnavailable
  ProxySocketTimeout
  ProxySocketAdapterFailed
  ProxySocketCleanupFailed
  ProxySocketCleanupTimeout
  ProxySocketCleanupInProgress
}

/// One payload-free, target-free setup trace event.
///
/// Generic setup emits at most six events. The production socket adapter adds
/// two adoption events. Failure adds exactly one final event, so tracing cannot
/// grow with peer input or retain resolver details.
pub type ProxySetupEvent {
  ProxyTargetAuthorized
  ProxyDnsStarted
  ProxyDnsSkippedForLiteral
  ProxyDnsCompleted(addresses: Int)
  ProxyDestinationsAuthorized(addresses: Int)
  ProxySocketStarted
  ProxySocketOpened
  ProxySocketAdoptionStarted
  ProxySocketAdopted
  ProxySetupFailed(ProxySetupFailure)
}

/// Fixed-size, payload-free observation of one supervised adapter callback.
pub type AdapterExecutionTimingSnapshot {
  AdapterExecutionTimingSnapshot(
    callback_started: Bool,
    queue_milliseconds: Int,
    callback_milliseconds: Int,
    supervisor_timed_out: Bool,
  )
}

/// Fixed-size phase timings plus scheduler/callback attribution.
///
/// Durations expose neither the target nor adapter error text. A phase that was
/// skipped is zero. The timeout flags distinguish an exhausted DNS, socket
/// open, socket adoption, or cleanup budget even when each maps to the same
/// redacted HTTP failure.
///
/// `queue_milliseconds` includes the bounded worker's scheduling delay. If the
/// callback never starts, `callback_milliseconds` remains zero and the queue
/// duration records the full observed wait. `supervisor_timed_out` is false for
/// a timeout classification returned by the adapter itself.
pub type ProxySetupTimingSnapshot {
  ProxySetupTimingSnapshot(
    dns_milliseconds: Int,
    socket_open_milliseconds: Int,
    socket_adoption_milliseconds: Int,
    socket_cleanup_milliseconds: Int,
    dns_timed_out: Bool,
    socket_open_timed_out: Bool,
    socket_adoption_timed_out: Bool,
    socket_cleanup_timed_out: Bool,
    dns_adapter: AdapterExecutionTimingSnapshot,
    socket_open_adapter: AdapterExecutionTimingSnapshot,
  )
}

/// Bounded setup diagnostics with no authority, target, payload, or error text.
pub type ProxySetupSnapshot {
  ProxySetupSnapshot(
    events: List(ProxySetupEvent),
    dns_required: Bool,
    dns_completed: Bool,
    resolved_addresses: Int,
    authorized_addresses: Int,
    socket_attempted: Bool,
    adapter_failures: Int,
    adapter_timeouts: Int,
    timing: ProxySetupTimingSnapshot,
  )
}

/// Current application-owned UDP socket lifecycle.
pub type UdpProxyResourceState {
  UdpProxyOpen
  UdpProxyClosing
  UdpProxyClosed
}

/// Saturating cleanup counters for leak and convergence diagnostics.
pub type UdpProxyResourceSnapshot {
  UdpProxyResourceSnapshot(
    state: UdpProxyResourceState,
    close_calls: Int,
    cleanup_attempts: Int,
    cleanup_failures: Int,
    cleanup_timeouts: Int,
  )
}

/// The first event that ended one bound UDP-socket/request-stream lifetime.
///
/// The first reason wins under concurrent notifications. It contains no peer,
/// target, payload, stream identifier, socket term, or callback failure text.
pub type UdpProxyTerminationReason {
  RequestStreamEnded
  SocketUnusable
  ApplicationClosed
  IdleTimeout
}

/// Saturating request-stream cleanup counters for convergence diagnostics.
pub type UdpRequestStreamSnapshot {
  UdpRequestStreamSnapshot(
    state: UdpProxyResourceState,
    close_calls: Int,
    cleanup_attempts: Int,
    cleanup_failures: Int,
    cleanup_timeouts: Int,
  )
}

/// Finite, payload-free state for one bound socket/request-stream lifetime.
pub type UdpProxySessionSnapshot {
  UdpProxySessionSnapshot(
    state: UdpProxyResourceState,
    termination: Option(UdpProxyTerminationReason),
    termination_notifications: Int,
    cleanup_attempts: Int,
    cleanup_failures: Int,
    cleanup_timeouts: Int,
    socket: UdpProxyResourceSnapshot,
    request_stream: UdpRequestStreamSnapshot,
  )
}

/// A bounded request-stream close adapter did not converge.
pub type UdpRequestStreamCleanupFailure {
  UdpRequestStreamCleanupFailed
  UdpRequestStreamCleanupTimeout
  UdpRequestStreamCleanupInProgress
}

/// Coordinated socket/request-stream teardown remains incomplete.
pub type UdpProxySessionFailure {
  UdpProxyTerminationInProgress
  UdpProxyCleanupIncomplete(
    socket: Option(ProxySetupFailure),
    request_stream: Option(UdpRequestStreamCleanupFailure),
  )
}

/// One production OTP UDP socket hidden behind a dedicated bounded owner.
///
/// The owner admits at most eight queued commands and arms its operating-
/// system socket with `active, once`, so neither callers nor target traffic
/// can create an unbounded actor mailbox.
pub type SystemUdpSocket

/// Redacted lifecycle of one production target-facing UDP socket.
pub type SystemUdpSocketState {
  SystemUdpSetup
  SystemUdpOpen
  SystemUdpUnusable
  SystemUdpClosed
}

/// Payload-free production UDP operation failure.
pub type SystemUdpFailure {
  SystemUdpInvalidInput
  SystemUdpTimedOut
  SystemUdpBusy
  SystemUdpSocketClosed
  SystemUdpMessageTooLarge
  SystemUdpSocketFailure
}

/// Address family of one payload-free Packet Too Big report.
pub type PacketTooBigAddressFamily {
  PacketTooBigIpv4
  PacketTooBigIpv6
}

/// Terminal outcome of one bounded Packet Too Big delivery decision.
///
/// Permission and platform failures are cached per target socket. ICMP error
/// generation is token-bucket limited before any raw socket is opened.
pub type PacketTooBigDelivery {
  PacketTooBigDelivered
  PacketTooBigRateLimited
  PacketTooBigPermissionDenied
  PacketTooBigUnsupported
  PacketTooBigTimedOut
  PacketTooBigProhibited
  PacketTooBigDeliveryFailed
}

/// Payload-free result for one oversized packet received from the target.
pub type PacketTooBigReport {
  PacketTooBigReport(
    family: PacketTooBigAddressFamily,
    maximum_udp_payload_bytes: Int,
    advertised_mtu_bytes: Int,
    quoted_packet_bytes: Int,
    delivery: PacketTooBigDelivery,
  )
}

/// Atomic, bounded diagnostics for target-side MTU feedback.
///
/// `retained_payload_bytes` is contractually zero: an oversized packet is
/// replaced by a payload-free event inside the dedicated socket owner before
/// it can enter the caller mailbox. Terminal outcome counters always sum to
/// `oversized_target_packets` when `consistent` is true.
pub type PacketTooBigSnapshot {
  PacketTooBigSnapshot(
    consistent: Bool,
    target_payload_limit_bytes: Int,
    maximum_response_burst: Int,
    response_refill_per_second: Int,
    maximum_send_deadline_milliseconds: Int,
    buffered_events: Int,
    retained_payload_bytes: Int,
    oversized_target_packets: Int,
    oversized_target_bytes: Int,
    delivery_attempts: Int,
    delivered_messages: Int,
    delivered_bytes: Int,
    rate_limited: Int,
    permission_denied: Int,
    unsupported: Int,
    timed_out: Int,
    prohibited: Int,
    failures: Int,
    cached_results: Int,
    maximum_quote_bytes: Int,
    advertised_mtu_bytes: Int,
    maximum_send_microseconds: Int,
  )
}

/// Payload-free lifecycle of the built-in HTTP/3 CONNECT-UDP route listener.
pub type UdpProxyListenerState {
  UdpProxyListening
  UdpProxyStopped
}

/// Bounded diagnostics for one default-location UDP proxy listener.
///
/// The snapshot never contains an authority, path, target, peer address,
/// header, payload, request handle, or transport error. All counters saturate
/// and are read atomically with the lifecycle state. `consistent` is false
/// when the finite snapshot retry budget expires. The payload-free fields are
/// then a best-effort observation and must not be treated as one atomic state.
pub type UdpProxyListenerSnapshot {
  UdpProxyListenerSnapshot(
    consistent: Bool,
    state: UdpProxyListenerState,
    accept_calls: Int,
    accepted_requests: Int,
    rejected_requests: Int,
    accept_failures: Int,
    rejection_response_failures: Int,
    setup_calls: Int,
    established_requests: Int,
    policy_rejections: Int,
    setup_rejections: Int,
    setup_response_failures: Int,
    duplicate_setup_attempts: Int,
    setup_response_cleanup_calls: Int,
    setup_response_cleanup_failures: Int,
    drain_calls: Int,
    stop_calls: Int,
    lifecycle_failures: Int,
  )
}

/// Redacted setup and lifecycle failures for the default-location listener.
pub type UdpProxyListenerFailure {
  UdpProxyListenerInvalidLimits
  UdpProxyListenerStartFailed
  UdpProxyListenerPortFailed
  UdpProxyListenerAcceptFailed
  UdpProxyListenerDatagramsNotNegotiated
  UdpProxyListenerDatagramNotAssociated
  UdpProxyListenerDatagramCapacityInvalid
  UdpProxyListenerDatagramCapacityFailed
  UdpProxyListenerRejectResponseFailed
  UdpProxyListenerSetupResponseFailed
  UdpProxyListenerSetupAlreadyStarted
  UdpProxyListenerLifecycleFailed
}

/// One exact-route admission decision. Rejected requests have already
/// received a bounded empty 400 response before this value is returned.
pub type UdpProxyRequestAccept {
  UdpProxyRequestAccepted(UdpProxyRequest)
  UdpProxyRequestRejected(ProxyRequestViolation)
}

/// Idempotent default-location listener stop result.
pub type UdpProxyListenerStop {
  UdpProxyListenerStopped
  UdpProxyListenerAlreadyStopped
}

/// Graceful default-location listener drain result.
pub type UdpProxyListenerDrain {
  UdpProxyListenerDrained
  UdpProxyListenerForced
  UdpProxyListenerAlreadyDrained
}

/// Finite diagnostics for one production UDP owner.
///
/// No endpoint, payload, process identifier, socket term, operating-system
/// reason, or late reply is retained or returned.
pub type SystemUdpSocketSnapshot {
  SystemUdpSocketSnapshot(
    state: SystemUdpSocketState,
    maximum_queued_commands: Int,
    requested_socket_buffer_bytes: Int,
    receive_socket_buffer_bytes: Int,
    send_socket_buffer_bytes: Int,
    maximum_payload_bytes: Int,
    queued_commands: Int,
    buffered_packets: Int,
    buffered_payload_bytes: Int,
    receive_waiting: Bool,
    event_waiting: Bool,
    rejected_commands: Int,
    sent_packets: Int,
    sent_bytes: Int,
    received_packets: Int,
    received_bytes: Int,
    receive_timeouts: Int,
    event_timeouts: Int,
    socket_failures: Int,
    dont_fragment: Bool,
    not_ect: Bool,
    relay_timing_samples: Int,
    maximum_send_batch_packets: Int,
    maximum_relay_delay_microseconds: Int,
    maximum_send_service_microseconds: Int,
    material_burst_compressions: Int,
    maximum_burst_compression_microseconds: Int,
    message_too_large_sends: Int,
    fragmentation_retries: Int,
  )
}

/// One immediate target-facing UDP I/O transition.
///
/// HTTP datagrams are never queued for batching. Fatal results observed by a
/// typed operation run coordinated socket/request-stream cleanup under the
/// session's existing finite limits. An asynchronous socket failure wakes a
/// pending datagram receive and the independent terminal-event waiter. If no
/// waiter exists, the owner retains only the typed terminal state until the
/// next typed operation observes it.
pub type SystemUdpIo {
  SystemUdpSessionInactive(session: UdpProxySession(SystemUdpSocket))
  SystemUdpSent(session: UdpProxySession(SystemUdpSocket))
  SystemUdpDatagramDiscarded(
    session: UdpProxySession(SystemUdpSocket),
    reason: DatagramDropReason,
  )
  SystemUdpRequestStreamAbort(
    session: UdpProxySession(SystemUdpSocket),
    error: Error,
    cleanup: Result(Nil, UdpProxySessionFailure),
  )
  SystemUdpForward(
    session: UdpProxySession(SystemUdpSocket),
    datagram: BitArray,
  )
  SystemUdpTargetPayloadTooLarge(
    session: UdpProxySession(SystemUdpSocket),
    report: PacketTooBigReport,
  )
  SystemUdpSocketPacketDiscarded(
    session: UdpProxySession(SystemUdpSocket),
    reason: UdpSocketDropReason,
  )
  SystemUdpReceiveTimedOut(session: UdpProxySession(SystemUdpSocket))
  SystemUdpReceiveBusy(session: UdpProxySession(SystemUdpSocket))
  SystemUdpReceiveFailed(
    session: UdpProxySession(SystemUdpSocket),
    failure: SystemUdpFailure,
  )
  SystemUdpSendBusy(session: UdpProxySession(SystemUdpSocket))
  SystemUdpSendFailed(
    session: UdpProxySession(SystemUdpSocket),
    failure: SystemUdpFailure,
  )
  SystemUdpSocketTerminated(
    session: UdpProxySession(SystemUdpSocket),
    failure: SystemUdpFailure,
    cleanup: Result(Nil, UdpProxySessionFailure),
  )
}

/// One bounded wait for a target-facing socket lifecycle event.
///
/// The event carries no endpoint, payload, runtime identifier, native socket,
/// or operating-system reason. At most one event waiter exists per socket.
pub type SystemUdpEventWait {
  SystemUdpEventObserved(
    session: UdpProxySession(SystemUdpSocket),
    failure: SystemUdpFailure,
    cleanup: Result(Nil, UdpProxySessionFailure),
  )
  SystemUdpEventTimedOut(session: UdpProxySession(SystemUdpSocket))
  SystemUdpEventBusy(session: UdpProxySession(SystemUdpSocket))
  SystemUdpEventStopped(session: UdpProxySession(SystemUdpSocket))
  SystemUdpEventFailed(
    session: UdpProxySession(SystemUdpSocket),
    failure: SystemUdpFailure,
  )
}

/// Payload-free reason a packet read from the target UDP socket was dropped.
pub type UdpSocketDropReason {
  SocketSourceMismatch
  SocketPayloadTooLarge(maximum_bytes: Int)
  SocketPayloadMalformed(error: Error)
  SocketTunnelInactive
}

/// One target-socket receive decision with an updated opaque tunnel.
pub type UdpSocketReceive(socket) {
  ForwardHttpDatagram(tunnel: UdpProxyTunnel(socket), datagram: BitArray)
  DiscardUdpPacket(tunnel: UdpProxyTunnel(socket), reason: UdpSocketDropReason)
}

/// One target-socket receive decision that preserves the bound lifetime.
pub type UdpProxySessionReceive(socket) {
  ForwardSessionHttpDatagram(
    session: UdpProxySession(socket),
    datagram: BitArray,
  )
  DiscardSessionUdpPacket(
    session: UdpProxySession(socket),
    reason: UdpSocketDropReason,
  )
}

/// Saturating target-socket counters without endpoint or payload retention.
pub type UdpSocketReceiverSnapshot {
  UdpSocketReceiverSnapshot(
    forwarded_packets: Int,
    forwarded_bytes: Int,
    dropped_source_mismatch: Int,
    dropped_oversized: Int,
    dropped_malformed: Int,
    dropped_inactive: Int,
  )
}

type RequestKind {
  Udp(UdpTarget)
  Ip(IpScope)
}

/// Fully validated request metadata for an HTTP adapter.
pub opaque type PreparedRequest {
  PreparedRequest(
    kind: RequestKind,
    protocol: Protocol,
    method: http.Method,
    authority: String,
    path: String,
    extended_protocol: Option(String),
    headers: List(#(String, String)),
    limits: Limits,
  )
}

/// An authenticated HTTP/3 request admitted at the default CONNECT-UDP path.
///
/// The raw request remains opaque in the `http3` package. The separate
/// `PreparedRequest` contains only the already validated routing metadata.
pub opaque type UdpProxyRequest {
  UdpProxyRequest(
    request: http3_server.Request,
    prepared: PreparedRequest,
    diagnostics: UdpProxyListenerDiagnostics,
    setup_guard: CloseGuard,
  )
}

/// A supervised HTTP/3 listener with HTTP Datagrams unconditionally enabled.
///
/// QUIC sockets, TLS, Retry, token validation, and connection actors remain
/// owned by the public `http3` listener. This wrapper adds only the fixed RFC
/// 9298 default-route admission and payload-free diagnostics.
pub opaque type UdpProxyListener {
  UdpProxyListener(
    listener: http3_server.Listener,
    limits: Limits,
    diagnostics: UdpProxyListenerDiagnostics,
  )
}

/// One successfully established default-location CONNECT-UDP request.
///
/// Neither the HTTP/3 transport stream nor the bound UDP session is
/// obtainable until target authorization, DNS, destination authorization,
/// socket open, and the successful response head have all completed.
pub opaque type SystemUdpProxy {
  SystemUdpProxy(
    transport: http3_transport.Stream,
    session: UdpProxySession(SystemUdpSocket),
  )
}

/// Terminal result of the safe default-listener setup sequence.
///
/// Rejection variants are returned only after their finite response has been
/// sent. A response failure is returned separately as
/// `UdpProxyListenerSetupResponseFailed`, so callers never mistake an
/// unconfirmed stream for an established relay.
pub type SystemUdpProxyEstablishment {
  SystemUdpProxyEstablished(proxy: SystemUdpProxy, snapshot: ProxySetupSnapshot)
  SystemUdpProxyPolicyRejected(response_status: Int)
  SystemUdpProxySetupRejected(
    response_status: Int,
    failure: ProxySetupFailure,
    snapshot: ProxySetupSnapshot,
  )
}

/// A CONNECT-UDP request proven to match the exact target allowlist.
pub opaque type AuthorizedUdpRequest {
  AuthorizedUdpRequest(
    request: PreparedRequest,
    target: UdpTarget,
    policy: ProxyPolicy,
  )
}

/// Finite resolver, socket setup, and socket-operation limits plus a validated
/// Proxy-Status member.
pub opaque type ProxySetupConfig {
  ProxySetupConfig(
    proxy: status.Identifier,
    dns_timeout_milliseconds: Int,
    socket_setup_timeout_milliseconds: Int,
    socket_timeout_milliseconds: Int,
    maximum_adapter_heap_words: Int,
  )
}

/// An application-owned UDP socket and its bounded cleanup callback.
pub opaque type UdpSocketResource(socket) {
  UdpSocketResource(
    socket: socket,
    close: fn(Int) -> Result(Nil, Nil),
    close_guard: CloseGuard,
  )
}

/// One HTTP request-stream close adapter with idempotent bounded cleanup.
pub opaque type UdpRequestStreamResource {
  UdpRequestStreamResource(
    close: fn(UdpProxyTerminationReason, Int) -> Result(Nil, Nil),
    close_guard: CloseGuard,
  )
}

/// One established UDP resource with an exact peer and directional receivers.
pub opaque type UdpProxyTunnel(socket) {
  UdpProxyTunnel(
    resource: UdpSocketResource(socket),
    peer: UdpEndpoint,
    receiver: UdpReceiver,
    socket_receiver: UdpSocketReceiver,
    config: ProxySetupConfig,
  )
}

/// One coordinated target-socket/request-stream lifetime.
///
/// Once a tunnel is bound, adapters use this owner for every terminal event.
/// Its guards are shared across copied values, so duplicate and concurrent
/// notifications converge without an unbounded actor mailbox.
pub opaque type UdpProxySession(socket) {
  UdpProxySession(
    tunnel: UdpProxyTunnel(socket),
    request_stream: UdpRequestStreamResource,
    termination_guard: TerminationGuard,
    cleanup_guard: CloseGuard,
    idle_guard: Option(UdpProxyIdleGuard),
  )
}

/// A supervised setup outcome. Successful response fields only exist in the
/// `UdpProxyReady` branch after DNS, destination authorization, and socket open.
pub type UdpProxySetup(socket) {
  UdpProxyReady(
    tunnel: UdpProxyTunnel(socket),
    response_status: Int,
    response_headers: List(#(String, String)),
    snapshot: ProxySetupSnapshot,
  )
  UdpProxyRejected(
    response_status: Int,
    response_headers: List(#(String, String)),
    failure: ProxySetupFailure,
    snapshot: ProxySetupSnapshot,
  )
}

type BoundedAdapterFailure {
  BoundedAdapterFailed
  BoundedAdapterTimedOut
}

type DnsAdapterOutcome {
  DnsLookupRejected
  DnsAnswerRejected(observed_addresses: Int)
  DnsAddressesReady(List(IpAddress))
}

type SocketAdapterOutcome(socket) {
  SocketOpenRejected(ProxySetupFailure)
  SocketResourceReady(UdpSocketResource(socket))
}

type RawSystemUdpReceive {
  RawSystemUdpPacket(address: BitArray, port: Int, payload: BitArray)
  RawSystemUdpPayloadTooLarge(
    family: Int,
    maximum_payload_bytes: Int,
    advertised_mtu_bytes: Int,
    quoted_packet_bytes: Int,
    delivery: Int,
  )
}

type CloseGuard

type TerminationGuard

type UdpProxyListenerDiagnostics

type UdpProxyIdleRuntime

type UdpProxyIdleCommand {
  UdpIdleWake
}

type UdpProxyActivityDirection {
  UdpActivityToTarget
  UdpActivityToHttp
}

type UdpProxyIdleGuard {
  UdpProxyIdleGuard(
    commands: Subject(UdpProxyIdleCommand),
    runtime: UdpProxyIdleRuntime,
  )
}

type CloseClaim {
  CloseAcquired
  CloseInProgress
  CloseCompleted
}

type CloseCompletion {
  CloseSucceeded
  CloseFailed
  CloseTimedOut
}

/// Redacted CONNECT-UDP request violations.
///
/// Variants deliberately contain no authority, path, field value, or body.
pub type ProxyRequestViolation {
  MethodMustBeGet
  MethodMustBeConnect
  ConnectUdpProtocolRequired
  HttpsSchemeRequired
  SingleHostRequired
  ProxyAuthorityInvalid
  ProxyAuthorityMismatch
  ConnectionUpgradeRequired
  SingleConnectUdpUpgradeRequired
  CapsuleProtocolRequired
  MessageContentForbidden
  DefaultUdpTargetInvalid
  RequestMetadataLimitExceeded(Int)
}

/// One server-side validation decision for a CONNECT-UDP request.
///
/// Malformed peer input always carries the recommended status 400. Invalid
/// library limits are separated so an adapter cannot misreport them as a peer
/// protocol error.
pub type ProxyRequestValidation {
  AcceptProxyRequest(PreparedRequest)
  RejectProxyRequest(status: Int, violation: ProxyRequestViolation)
  ProxyRequestConfigurationFailure(Error)
}

/// Client-side confirmation state. Payload methods fail before confirmation.
pub opaque type ClientTunnel {
  ClientTunnel(request: PreparedRequest, established: Bool)
}

/// Payload-free reason that a proxy receiver deliberately discarded one
/// datagram. The datagram bytes are never retained in this diagnostic value.
pub type DatagramDropReason {
  RequestNotReady
  ContextNotRegistered(Int)
  CapsuleValueTooLarge(Int)
}

/// One finite proxy receive transition. An HTTP adapter must enact
/// `AbortRequestStream` before reading another datagram for that request.
pub type DatagramReceive {
  ForwardPayload(receiver: UdpReceiver, payload: BitArray)
  DropDatagram(receiver: UdpReceiver, reason: DatagramDropReason)
  AbortRequestStream(receiver: UdpReceiver, error: Error)
}

/// One payload-free DATAGRAM Capsule admission decision.
///
/// An adapter first reads only the Capsule framing length. When active, it
/// then decodes at most the eight-byte Context ID prefix and calls
/// `classify_proxy_datagram_capsule_context` before reading any payload bytes.
pub type DatagramCapsuleAdmission {
  InspectDatagramCapsuleContext(
    receiver: UdpReceiver,
    declared_value_bytes: Int,
  )
  ReadDatagramCapsulePayload(receiver: UdpReceiver, payload_bytes: Int)
  DiscardDatagramCapsule(receiver: UdpReceiver, reason: DatagramDropReason)
  AbortDatagramCapsuleStream(receiver: UdpReceiver, error: Error)
}

/// Bounded counters for live diagnostics; no target or payload bytes appear.
pub type UdpReceiverSnapshot {
  UdpReceiverSnapshot(
    active: Bool,
    accepted: Int,
    dropped_before_request: Int,
    dropped_unknown_context: Int,
    discarded_capsules: Int,
    aborts_required: Int,
  )
}

/// A no-buffer CONNECT-UDP proxy receive policy for one request stream.
pub opaque type UdpReceiver {
  UdpReceiver(
    limits: Limits,
    active: Bool,
    accepted: Int,
    dropped_before_request: Int,
    dropped_unknown_context: Int,
    discarded_capsules: Int,
    aborts_required: Int,
  )
}

/// Counters for packets read from the application-owned target UDP socket.
type UdpSocketReceiver {
  UdpSocketReceiver(
    forwarded_packets: Int,
    forwarded_bytes: Int,
    dropped_source_mismatch: Int,
    dropped_oversized: Int,
    dropped_malformed: Int,
    dropped_inactive: Int,
  )
}

type DestinationRule {
  DestinationRule(prefix: IpPrefix, protocol: Option(Int))
}

/// Finite, default-deny proxy policy.
pub opaque type ProxyPolicy {
  ProxyPolicy(
    limits: Limits,
    udp_targets: List(UdpTarget),
    udp_destinations: List(IpPrefix),
    ip_scopes: List(IpScope),
    destinations: List(DestinationRule),
  )
}

@external(erlang, "http_server_ffi", "call_bounded_adapter")
fn call_bounded_adapter(
  run: fn() -> Result(value, adapter_error),
  timeout_milliseconds: Int,
  maximum_heap_words: Int,
) -> Result(Result(value, adapter_error), BoundedAdapterFailure)

@external(erlang, "http_server_ffi", "call_bounded_adapter_traced")
fn call_bounded_adapter_traced(
  run: fn() -> Result(value, adapter_error),
  timeout_milliseconds: Int,
  maximum_heap_words: Int,
) -> #(
  Result(Result(value, adapter_error), BoundedAdapterFailure),
  Bool,
  Int,
  Int,
  Bool,
)

@external(erlang, "http_server_ffi", "new_close_guard")
fn new_close_guard() -> CloseGuard

@external(erlang, "http_server_ffi", "claim_close_guard")
fn claim_close_guard(guard: CloseGuard) -> CloseClaim

@external(erlang, "http_server_ffi", "finish_close_guard")
fn finish_close_guard(guard: CloseGuard, completion: CloseCompletion) -> Nil

@external(erlang, "http_server_ffi", "close_guard_snapshot")
fn close_guard_snapshot(guard: CloseGuard) -> #(Int, Int, Int, Int, Int)

@external(erlang, "http_server_ffi", "new_udp_proxy_termination_guard")
fn new_udp_proxy_termination_guard() -> TerminationGuard

@external(erlang, "http_server_ffi", "record_udp_proxy_termination")
fn record_udp_proxy_termination(guard: TerminationGuard, reason: Int) -> Int

@external(erlang, "http_server_ffi", "udp_proxy_termination_snapshot")
fn udp_proxy_termination_snapshot(guard: TerminationGuard) -> #(Int, Int)

@external(erlang, "http_masque_udp_ffi", "open")
fn raw_open_system_udp_socket(
  address: BitArray,
  port: Int,
  owner: Pid,
  target_payload_limit_bytes: Int,
  timeout_milliseconds: Int,
) -> Result(SystemUdpSocket, Int)

@external(erlang, "http_masque_udp_ffi", "adopt")
fn raw_adopt_system_udp_socket(
  socket: SystemUdpSocket,
  owner: Pid,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_masque_udp_ffi", "send")
fn raw_send_system_udp_socket(
  socket: SystemUdpSocket,
  payload: BitArray,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_masque_udp_ffi", "recv")
fn raw_receive_system_udp_socket(
  socket: SystemUdpSocket,
  timeout_milliseconds: Int,
) -> Result(RawSystemUdpReceive, Int)

@external(erlang, "http_masque_udp_ffi", "wait_event")
fn raw_wait_system_udp_event(
  socket: SystemUdpSocket,
  timeout_milliseconds: Int,
) -> Result(Int, Int)

@external(erlang, "http_masque_udp_ffi", "wait_event_forever")
fn raw_wait_system_udp_event_forever(
  socket: SystemUdpSocket,
) -> Result(Int, Int)

@external(erlang, "http_masque_udp_ffi", "idle_new")
fn new_udp_proxy_idle_runtime(
  timeout_milliseconds: Int,
  now_milliseconds: Int,
) -> UdpProxyIdleRuntime

@external(erlang, "http_masque_udp_ffi", "idle_activity")
fn record_udp_proxy_idle_activity(
  runtime: UdpProxyIdleRuntime,
  now_milliseconds: Int,
  direction: Int,
) -> Int

@external(erlang, "http_masque_udp_ffi", "idle_ack")
fn acknowledge_udp_proxy_idle_wake(runtime: UdpProxyIdleRuntime) -> Int

@external(erlang, "http_masque_udp_ffi", "idle_due")
fn claim_udp_proxy_idle_deadline(
  runtime: UdpProxyIdleRuntime,
  now_milliseconds: Int,
) -> #(Int, Int)

@external(erlang, "http_masque_udp_ffi", "idle_stop")
fn stop_udp_proxy_idle_runtime(runtime: UdpProxyIdleRuntime) -> Int

@external(erlang, "http_masque_udp_ffi", "idle_snapshot")
fn raw_udp_proxy_idle_snapshot(
  runtime: UdpProxyIdleRuntime,
) -> #(Int, Int, Int, Bool, Int, Int, Int, Int, Int, Int, Int, Int)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

@external(erlang, "http_masque_listener_ffi", "new")
fn new_udp_proxy_listener_diagnostics() -> UdpProxyListenerDiagnostics

@external(erlang, "http_masque_listener_ffi", "record_accept")
fn record_udp_proxy_listener_accept(
  diagnostics: UdpProxyListenerDiagnostics,
  outcome: Int,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "record_drain")
fn record_udp_proxy_listener_drain(
  diagnostics: UdpProxyListenerDiagnostics,
  succeeded: Bool,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "record_setup")
fn record_udp_proxy_listener_setup(
  diagnostics: UdpProxyListenerDiagnostics,
  outcome: Int,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "record_setup_duplicate")
fn record_udp_proxy_listener_setup_duplicate(
  diagnostics: UdpProxyListenerDiagnostics,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "record_setup_cleanup")
fn record_udp_proxy_listener_setup_cleanup(
  diagnostics: UdpProxyListenerDiagnostics,
  succeeded: Bool,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "record_stop")
fn record_udp_proxy_listener_stop(
  diagnostics: UdpProxyListenerDiagnostics,
  succeeded: Bool,
) -> Nil

@external(erlang, "http_masque_listener_ffi", "snapshot")
fn raw_udp_proxy_listener_snapshot(
  diagnostics: UdpProxyListenerDiagnostics,
) -> #(
  Bool,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

@external(erlang, "http_masque_udp_ffi", "close")
fn raw_close_system_udp_socket(
  socket: SystemUdpSocket,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_masque_udp_ffi", "snapshot")
fn raw_system_udp_socket_snapshot(
  socket: SystemUdpSocket,
) -> #(
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Bool,
  Bool,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Bool,
  Bool,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

@external(erlang, "http_masque_udp_ffi", "packet_too_big_snapshot")
fn raw_system_udp_packet_too_big_snapshot(
  socket: SystemUdpSocket,
) -> #(
  Bool,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
  Int,
)

/// Finite CONNECT-IP configuration and request-ID state.
pub opaque type IpState {
  IpState(
    limits: Limits,
    used_request_ids: List(Int),
    assignments: List(AssignedAddress),
    routes: List(IpRoute),
  )
}

type ParsedPacket {
  ParsedIpv4(
    first: Int,
    differentiated_services: Int,
    total_length: Int,
    identification: Int,
    flags_and_fragment: Int,
    hop_limit: Int,
    protocol: Int,
    source: BitArray,
    destination: BitArray,
    options: BitArray,
    payload: BitArray,
  )
  ParsedIpv6(
    traffic_class: Int,
    flow_label: Int,
    payload_length: Int,
    next_header: Int,
    hop_limit: Int,
    source: BitArray,
    destination: BitArray,
    payload: BitArray,
  )
}

/// Disable application-level UDP idleness expiry.
///
/// The request stream and socket still terminate together on explicit close,
/// request-stream end, or an operating-system socket failure.
pub fn udp_proxy_idle_timeout_disabled() -> UdpProxyIdlePolicy {
  UdpProxyIdlePolicy(None)
}

/// Configure an event-driven CONNECT-UDP idle deadline.
///
/// RFC 9298 recommends against values below two minutes. This constructor
/// makes that lower bound, and the BEAM timer upper bound, impossible to
/// bypass through the stable API.
pub fn udp_proxy_idle_timeout(
  milliseconds: Int,
) -> Result(UdpProxyIdlePolicy, Error) {
  case
    milliseconds >= minimum_udp_idle_timeout_milliseconds
    && milliseconds <= 2_147_483_647
  {
    True -> Ok(UdpProxyIdlePolicy(Some(milliseconds)))
    False -> Error(InvalidIdleTimeout)
  }
}

/// Construct a short timer only for deterministic package qualification.
///
/// This symbol is excluded from the published package interface. Stable
/// callers can only use `udp_proxy_idle_timeout`, which enforces two minutes.
@internal
pub fn udp_proxy_idle_timeout_for_testing(
  milliseconds: Int,
) -> UdpProxyIdlePolicy {
  UdpProxyIdlePolicy(Some(milliseconds))
}

/// Return the validated timeout, or `None` when idle expiry is disabled.
pub fn udp_proxy_idle_timeout_milliseconds(
  policy: UdpProxyIdlePolicy,
) -> Option(Int) {
  policy.timeout_milliseconds
}

// nolint: error_context_lost -- HTTP/3 peer data is redacted; the operation class remains.
/// Start the authenticated HTTP/3 endpoint for the RFC 9298 default URI.
///
/// HTTP Datagrams are enabled unconditionally. The supplied HTTP/3
/// configuration retains its finite transport, request, memory, and drain
/// limits; invalid MASQUE limits fail before any listener is opened.
pub fn start_udp_proxy_listener(
  configuration: http3_server.Configuration,
  limits: Limits,
) -> Result(UdpProxyListener, UdpProxyListenerFailure) {
  case validate_limits(limits) {
    Error(_) -> Error(UdpProxyListenerInvalidLimits)
    Ok(Nil) ->
      configuration
      |> http3_server.with_http_datagrams
      |> http3_server.start
      |> result.map(fn(listener) {
        UdpProxyListener(
          listener:,
          limits:,
          diagnostics: new_udp_proxy_listener_diagnostics(),
        )
      })
      |> result.map_error(fn(_) { UdpProxyListenerStartFailed })
  }
}

// nolint: error_context_lost -- transport internals are redacted; the operation class remains.
/// Return the concrete UDP port bound by the default-location listener.
pub fn udp_proxy_listener_port(
  listener: UdpProxyListener,
) -> Result(Int, UdpProxyListenerFailure) {
  http3_server.port(listener.listener)
  |> result.map_error(fn(_) { UdpProxyListenerPortFailed })
}

/// Accept one HTTP/3 request and admit only the RFC 9298 default URI.
///
/// A malformed request receives an empty 400 response before its redacted
/// violation is returned. No target or peer-controlled metadata is copied
/// into listener diagnostics.
pub fn accept_udp_proxy_request(
  listener: UdpProxyListener,
) -> Result(UdpProxyRequestAccept, UdpProxyListenerFailure) {
  case http3_server.accept(listener.listener) {
    Error(_) -> {
      record_udp_proxy_listener_accept(listener.diagnostics, 3)
      Error(UdpProxyListenerAcceptFailed)
    }
    Ok(request) ->
      case validate_http3_udp_proxy_request(request, listener.limits) {
        AcceptProxyRequest(prepared) -> {
          case
            await_http3_request_datagram_capacity(
              request,
              maximum_datagram_capacity_attempts,
            )
          {
            Error(error) -> {
              record_udp_proxy_listener_accept(listener.diagnostics, 3)
              let _cancelled = http3_server.cancel(request)
              Error(udp_proxy_datagram_capacity_failure(error))
            }
            Ok(maximum_http_datagram_bytes) ->
              case
                cap_http3_udp_proxy_limits(
                  prepared,
                  maximum_http_datagram_bytes,
                )
              {
                Error(Nil) -> {
                  record_udp_proxy_listener_accept(listener.diagnostics, 3)
                  let _cancelled = http3_server.cancel(request)
                  Error(UdpProxyListenerDatagramCapacityInvalid)
                }
                Ok(prepared) -> {
                  record_udp_proxy_listener_accept(listener.diagnostics, 1)
                  Ok(
                    UdpProxyRequestAccepted(UdpProxyRequest(
                      request,
                      prepared,
                      listener.diagnostics,
                      new_close_guard(),
                    )),
                  )
                }
              }
          }
        }
        RejectProxyRequest(status, violation) ->
          case http3_server.respond(request, status, [], <<>>) {
            Ok(Nil) -> {
              record_udp_proxy_listener_accept(listener.diagnostics, 2)
              Ok(UdpProxyRequestRejected(violation))
            }
            Error(_) -> {
              record_udp_proxy_listener_accept(listener.diagnostics, 4)
              Error(UdpProxyListenerRejectResponseFailed)
            }
          }
        ProxyRequestConfigurationFailure(_) -> {
          record_udp_proxy_listener_accept(listener.diagnostics, 3)
          let _cancelled = http3_server.cancel(request)
          Error(UdpProxyListenerInvalidLimits)
        }
      }
  }
}

fn await_http3_request_datagram_capacity(
  request: http3_server.Request,
  remaining: Int,
) -> Result(Int, http3_transport.Error) {
  case http3_server.request_datagram_capacity(request) {
    Error(http3_transport.DatagramsNotNegotiated) if remaining > 1 -> {
      process.sleep(1)
      await_http3_request_datagram_capacity(request, remaining - 1)
    }
    outcome -> outcome
  }
}

fn udp_proxy_datagram_capacity_failure(
  error: http3_transport.Error,
) -> UdpProxyListenerFailure {
  case error {
    http3_transport.DatagramsNotNegotiated ->
      UdpProxyListenerDatagramsNotNegotiated
    http3_transport.DatagramNotAssociated ->
      UdpProxyListenerDatagramNotAssociated
    _ -> UdpProxyListenerDatagramCapacityFailed
  }
}

/// Return the validated routing metadata for one admitted request.
pub fn udp_proxy_prepared_request(request: UdpProxyRequest) -> PreparedRequest {
  request.prepared
}

/// Read an atomic, payload-free listener diagnostic snapshot.
pub fn udp_proxy_listener_snapshot(
  listener: UdpProxyListener,
) -> UdpProxyListenerSnapshot {
  let #(
    consistent,
    state,
    accept_calls,
    accepted_requests,
    rejected_requests,
    accept_failures,
    rejection_response_failures,
    setup_calls,
    established_requests,
    policy_rejections,
    setup_rejections,
    setup_response_failures,
    duplicate_setup_attempts,
    setup_response_cleanup_calls,
    setup_response_cleanup_failures,
    drain_calls,
    stop_calls,
    lifecycle_failures,
  ) = raw_udp_proxy_listener_snapshot(listener.diagnostics)
  UdpProxyListenerSnapshot(
    consistent:,
    state: case state {
      1 -> UdpProxyListening
      _ -> UdpProxyStopped
    },
    accept_calls:,
    accepted_requests:,
    rejected_requests:,
    accept_failures:,
    rejection_response_failures:,
    setup_calls:,
    established_requests:,
    policy_rejections:,
    setup_rejections:,
    setup_response_failures:,
    duplicate_setup_attempts:,
    setup_response_cleanup_calls:,
    setup_response_cleanup_failures:,
    drain_calls:,
    stop_calls:,
    lifecycle_failures:,
  )
}

/// Stop admission, issue GOAWAY, and drain or finitely force live requests.
pub fn drain_udp_proxy_listener(
  listener: UdpProxyListener,
) -> Result(UdpProxyListenerDrain, UdpProxyListenerFailure) {
  case http3_server.graceful_stop(listener.listener) {
    Ok(http3_server.Drained) -> {
      record_udp_proxy_listener_drain(listener.diagnostics, True)
      Ok(UdpProxyListenerDrained)
    }
    Ok(http3_server.Forced) -> {
      record_udp_proxy_listener_drain(listener.diagnostics, True)
      Ok(UdpProxyListenerForced)
    }
    Ok(http3_server.AlreadyDrained) -> {
      record_udp_proxy_listener_drain(listener.diagnostics, True)
      Ok(UdpProxyListenerAlreadyDrained)
    }
    Error(_) -> {
      record_udp_proxy_listener_drain(listener.diagnostics, False)
      Error(UdpProxyListenerLifecycleFailed)
    }
  }
}

/// Stop the listener and all owned connections idempotently.
pub fn stop_udp_proxy_listener(
  listener: UdpProxyListener,
) -> Result(UdpProxyListenerStop, UdpProxyListenerFailure) {
  case http3_server.stop(listener.listener) {
    Ok(http3_server.Stopped) -> {
      record_udp_proxy_listener_stop(listener.diagnostics, True)
      Ok(UdpProxyListenerStopped)
    }
    Ok(http3_server.AlreadyStopped) -> {
      record_udp_proxy_listener_stop(listener.diagnostics, True)
      Ok(UdpProxyListenerAlreadyStopped)
    }
    Error(_) -> {
      record_udp_proxy_listener_stop(listener.diagnostics, False)
      Error(UdpProxyListenerLifecycleFailed)
    }
  }
}

/// Prepare the RFC 9298 default-template CONNECT-UDP request.
pub fn connect_udp(
  protocol: Protocol,
  proxy_authority: String,
  target: UdpTarget,
  limits: Limits,
) -> Result(PreparedRequest, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(validate_authority(proxy_authority))
  use _ <- result.try(validate_udp_target(target))
  let UdpTarget(host, port) = target
  let path =
    "/.well-known/masque/udp/"
    <> uri.percent_encode(host)
    <> "/"
    <> int.to_string(port)
    <> "/"
  prepare_request(Udp(target), protocol, proxy_authority, path, limits)
}

/// Prepare the RFC 9484 default-template CONNECT-IP request.
pub fn connect_ip(
  protocol: Protocol,
  proxy_authority: String,
  scope: IpScope,
  limits: Limits,
) -> Result(PreparedRequest, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(validate_authority(proxy_authority))
  use _ <- result.try(validate_scope(scope))
  let IpScope(target, protocol_number) = scope
  let encoded_target = case target {
    None -> "*"
    Some(value) -> uri.percent_encode(value)
  }
  let encoded_protocol = case protocol_number {
    None -> "*"
    Some(value) -> int.to_string(value)
  }
  let path =
    "/.well-known/masque/ip/"
    <> encoded_target
    <> "/"
    <> encoded_protocol
    <> "/"
  prepare_request(Ip(scope), protocol, proxy_authority, path, limits)
}

fn prepare_request(
  kind: RequestKind,
  protocol: Protocol,
  authority: String,
  path: String,
  limits: Limits,
) -> Result(PreparedRequest, Error) {
  let upgrade = kind_protocol(kind)
  let #(method, extended_protocol, headers) = case protocol {
    Http1 -> #(http.Get, None, [
      #("host", authority),
      #("connection", "Upgrade"),
      #("upgrade", upgrade),
      #("capsule-protocol", "?1"),
    ])
    Http2 | Http3 -> #(http.Connect, Some(upgrade), [
      #("capsule-protocol", "?1"),
    ])
  }
  Ok(PreparedRequest(
    kind,
    protocol,
    method,
    authority,
    path,
    extended_protocol,
    headers,
    limits,
  ))
}

/// Return the request method an HTTP adapter must emit.
pub fn request_method(request: PreparedRequest) -> http.Method {
  request.method
}

/// Return the verified HTTPS proxy authority.
pub fn request_authority(request: PreparedRequest) -> String {
  request.authority
}

/// Return the expanded absolute path and query.
pub fn request_path(request: PreparedRequest) -> String {
  request.path
}

/// Return the H2/H3 Extended CONNECT protocol, or `None` for H1 Upgrade.
pub fn request_protocol(request: PreparedRequest) -> Option(String) {
  request.extended_protocol
}

/// Return regular fields required by the selected HTTP mapping.
pub fn request_headers(request: PreparedRequest) -> List(#(String, String)) {
  request.headers
}

/// Return the CONNECT-UDP target, or `None` for a CONNECT-IP request.
pub fn request_udp_target(request: PreparedRequest) -> Option(UdpTarget) {
  case request.kind {
    Udp(target) -> Some(target)
    Ip(_) -> None
  }
}

/// Validate an inbound HTTP/1.1 request for the default CONNECT-UDP route.
///
/// This function accepts the standard `gleam_http` request type used by the
/// unified server. It applies finite metadata limits before parsing and emits
/// only payload-free rejection diagnostics.
pub fn validate_http1_udp_proxy_request(
  incoming: Request(body),
  limits: Limits,
) -> ProxyRequestValidation {
  case validate_limits(limits) {
    Error(error) -> ProxyRequestConfigurationFailure(error)
    Ok(Nil) ->
      case validate_http1_udp_metadata(incoming) {
        Error(violation) -> RejectProxyRequest(400, violation)
        Ok(#(authority, target)) ->
          AcceptProxyRequest(PreparedRequest(
            kind: Udp(target),
            protocol: Http1,
            method: http.Get,
            authority: authority,
            path: incoming.path,
            extended_protocol: None,
            headers: incoming.headers,
            limits: limits,
          ))
      }
  }
}

/// Validate an accepted HTTP/3 request for the default CONNECT-UDP route.
///
/// The HTTP/3 package has already authenticated and decoded the request head.
/// This additional admission step enforces the RFC 9298 method, protocol,
/// scheme, authority, Capsule Protocol, message-content, and fixed-route
/// requirements before an application may authorize a target.
pub fn validate_http3_udp_proxy_request(
  incoming: http3_server.Request,
  limits: Limits,
) -> ProxyRequestValidation {
  case validate_limits(limits) {
    Error(error) -> ProxyRequestConfigurationFailure(error)
    Ok(Nil) ->
      case validate_http3_udp_metadata(incoming) {
        Error(violation) -> RejectProxyRequest(400, violation)
        Ok(#(authority, path, target)) ->
          AcceptProxyRequest(PreparedRequest(
            kind: Udp(target),
            protocol: Http3,
            method: http.Connect,
            authority:,
            path:,
            extended_protocol: Some("connect-udp"),
            headers: http3_server.headers(incoming),
            limits:,
          ))
      }
  }
}

// Freeze the HTTP/3 connection-lifetime guarantee at request admission. It is
// the complete HTTP Datagram payload after the quarter-stream ID, while
// CONNECT-UDP reserves one further byte for Context ID zero. The underlying
// QUIC guarantee budgets the 1200-byte path floor and worst ACK reservation,
// so neither path fallback nor later ACK fragmentation invalidates this target
// ceiling. A fresh request may still choose a different connection guarantee.
fn cap_http3_udp_proxy_limits(
  request: PreparedRequest,
  maximum_http_datagram_bytes: Int,
) -> Result(PreparedRequest, Nil) {
  case maximum_http_datagram_bytes > 1 {
    False -> Error(Nil)
    True -> {
      let limits = request.limits
      let limits =
        Limits(
          ..limits,
          maximum_datagram_bytes: int.min(
            limits.maximum_datagram_bytes,
            maximum_http_datagram_bytes,
          ),
        )
      Ok(PreparedRequest(..request, limits: limits))
    }
  }
}

/// Build successful response fields after proxy setup has opened its socket.
///
/// This helper is deliberately private: public successful response fields are
/// obtainable only from `establish_udp_proxy`'s `UdpProxyReady` branch.
fn successful_response_headers(
  request: PreparedRequest,
  status: Int,
) -> Result(List(#(String, String)), Error) {
  let successful = case request.protocol {
    Http1 -> status == 101
    Http2 | Http3 -> status >= 200 && status <= 299
  }
  use <- bool.guard(when: !successful, return: Error(UnexpectedStatus(status)))
  Ok(case request.protocol {
    Http1 -> [
      #("connection", "Upgrade"),
      #("upgrade", kind_protocol(request.kind)),
      #("capsule-protocol", "?1"),
    ]
    Http2 | Http3 -> [#("capsule-protocol", "?1")]
  })
}

/// Construct finite, supervised proxy limits with one shared socket deadline.
///
/// The Proxy-Status identifier is validated up front. Adapter processes have
/// both a hard deadline and a BEAM heap ceiling, and heap-limit termination is
/// classified as an adapter failure without exposing the exit reason. Use
/// `proxy_setup_config_with_socket_timeouts` when startup and established I/O
/// need different finite deadlines.
pub fn proxy_setup_config(
  proxy: status.Identifier,
  dns_timeout_milliseconds dns_timeout_milliseconds: Int,
  socket_timeout_milliseconds socket_timeout_milliseconds: Int,
  maximum_adapter_heap_words maximum_adapter_heap_words: Int,
) -> Result(ProxySetupConfig, Error) {
  proxy_setup_config_with_socket_timeouts(
    proxy,
    dns_timeout_milliseconds: dns_timeout_milliseconds,
    socket_setup_timeout_milliseconds: socket_timeout_milliseconds,
    socket_operation_timeout_milliseconds: socket_timeout_milliseconds,
    maximum_adapter_heap_words: maximum_adapter_heap_words,
  )
}

/// Construct finite setup limits with independent socket startup and I/O.
///
/// The setup deadline bounds socket-owner creation and adoption. The operation
/// deadline is retained by the established tunnel for send, cleanup, and
/// request-stream callbacks. Separating them lets latency-sensitive relay I/O
/// remain strict without making one-time VM or networking initialization an
/// accidental admission failure.
pub fn proxy_setup_config_with_socket_timeouts(
  proxy: status.Identifier,
  dns_timeout_milliseconds dns_timeout_milliseconds: Int,
  socket_setup_timeout_milliseconds socket_setup_timeout_milliseconds: Int,
  socket_operation_timeout_milliseconds socket_operation_timeout_milliseconds: Int,
  maximum_adapter_heap_words maximum_adapter_heap_words: Int,
) -> Result(ProxySetupConfig, Error) {
  use <- bool.guard(
    when: !valid_setup_timeout(dns_timeout_milliseconds)
      || !valid_setup_timeout(socket_setup_timeout_milliseconds)
      || !valid_setup_timeout(socket_operation_timeout_milliseconds)
      || maximum_adapter_heap_words < 1024
      || maximum_adapter_heap_words > 16_777_216,
    return: Error(InvalidProxySetup),
  )
  use _ <- result.try(proxy_status_header(proxy, "dns_error"))
  Ok(ProxySetupConfig(
    proxy,
    dns_timeout_milliseconds,
    socket_setup_timeout_milliseconds,
    socket_operation_timeout_milliseconds,
    maximum_adapter_heap_words,
  ))
}

/// Prove that a CONNECT-UDP request matches the exact configured target.
///
/// Resolved IP authorization remains a separate mandatory setup step, so a
/// permitted DNS name cannot bypass destination-prefix policy through rebinding.
pub fn authorize_udp_proxy(
  policy: ProxyPolicy,
  request: PreparedRequest,
) -> Result(AuthorizedUdpRequest, Error) {
  use _ <- result.try(authorize(policy, request))
  case request.kind {
    Udp(target) -> Ok(AuthorizedUdpRequest(request, target, policy))
    Ip(_) -> Error(InvalidTarget)
  }
}

/// Resolve, re-authorize, and open one UDP target under bounded adapters.
///
/// A DNS-name request cannot yield `UdpProxyReady` until resolution has
/// completed. Every resolved address is validated and filtered through the
/// explicit destination-prefix allowlist before the socket callback runs.
pub fn establish_udp_proxy(
  authorized: AuthorizedUdpRequest,
  config: ProxySetupConfig,
  resolver resolver: fn(String, Int) ->
    Result(List(IpAddress), DnsLookupFailure),
  open_socket open_socket: fn(UdpEndpoint, Int) ->
    Result(UdpSocketResource(socket), UdpSocketOpenFailure),
) -> UdpProxySetup(socket) {
  let AuthorizedUdpRequest(request, target, policy) = authorized
  let initial =
    initial_proxy_setup_snapshot()
    |> append_proxy_setup_event(ProxyTargetAuthorized)
  case literal_target_address(target.host) {
    Ok(address) ->
      authorize_proxy_addresses(
        request,
        target,
        policy,
        config,
        [address],
        open_socket,
        ProxySetupSnapshot(
          ..initial,
          events: list.append(initial.events, [ProxyDnsSkippedForLiteral]),
          resolved_addresses: 1,
        ),
      )
    Error(Nil) ->
      resolve_proxy_addresses(
        request,
        target,
        policy,
        config,
        resolver,
        open_socket,
        ProxySetupSnapshot(
          ..initial,
          events: list.append(initial.events, [ProxyDnsStarted]),
          dns_required: True,
        ),
      )
  }
}

/// Establish a target-facing UDP socket using the production OTP adapter.
///
/// The stable caller process is captured before generic setup starts. The
/// socket itself is opened by a dedicated owner and must be adopted here
/// before the setup lease expires; a killed, timed-out, or malformed setup
/// worker therefore cannot orphan an operating-system socket.
pub fn establish_system_udp_proxy(
  authorized: AuthorizedUdpRequest,
  config: ProxySetupConfig,
  resolver resolver: fn(String, Int) ->
    Result(List(IpAddress), DnsLookupFailure),
) -> UdpProxySetup(SystemUdpSocket) {
  let owner = process.self()
  let target_payload_limit = udp_payload_limit(authorized.request.limits)
  let setup =
    establish_udp_proxy(
      authorized,
      config,
      resolver: resolver,
      open_socket: fn(endpoint, timeout_milliseconds) {
        open_system_udp_resource(
          endpoint,
          owner,
          target_payload_limit,
          timeout_milliseconds,
        )
      },
    )
  case setup {
    UdpProxyRejected(..) -> setup
    UdpProxyReady(
      tunnel: tunnel,
      response_status: response_status,
      response_headers: response_headers,
      snapshot: opened_snapshot,
    ) -> {
      let started_snapshot =
        append_proxy_setup_event(opened_snapshot, ProxySocketAdoptionStarted)
      let adoption_started = monotonic_millisecond()
      let adoption =
        raw_adopt_system_udp_socket(
          tunnel.resource.socket,
          owner,
          config.socket_setup_timeout_milliseconds,
        )
      let snapshot =
        ProxySetupSnapshot(
          ..started_snapshot,
          timing: ProxySetupTimingSnapshot(
            ..started_snapshot.timing,
            socket_adoption_milliseconds: setup_elapsed_milliseconds(
              adoption_started,
            ),
          ),
        )
      case adoption {
        Ok(Nil) ->
          UdpProxyReady(
            tunnel: tunnel,
            response_status: response_status,
            response_headers: response_headers,
            snapshot: append_proxy_setup_event(snapshot, ProxySocketAdopted),
          )
        Error(adoption_code) -> {
          let adoption_timeouts = case system_udp_failure(adoption_code) {
            SystemUdpTimedOut -> 1
            _ -> 0
          }
          let snapshot = case adoption_timeouts {
            1 ->
              ProxySetupSnapshot(
                ..snapshot,
                timing: ProxySetupTimingSnapshot(
                  ..snapshot.timing,
                  socket_adoption_timed_out: True,
                ),
              )
            _ -> snapshot
          }
          let cleanup_started = monotonic_millisecond()
          let cleanup = close_udp_proxy(tunnel)
          let cleanup_elapsed = setup_elapsed_milliseconds(cleanup_started)
          let #(cleanup_failures, cleanup_timeouts) = case cleanup {
            Ok(Nil) -> #(0, 0)
            Error(ProxySocketCleanupTimeout) -> #(0, 1)
            Error(ProxyDnsError)
            | Error(ProxyDnsTimeout)
            | Error(ProxyDnsAdapterFailed)
            | Error(ProxyDnsAnswerInvalid)
            | Error(ProxyDestinationForbidden)
            | Error(ProxySocketRefused)
            | Error(ProxySocketUnroutable)
            | Error(ProxySocketUnavailable)
            | Error(ProxySocketTimeout)
            | Error(ProxySocketAdapterFailed)
            | Error(ProxySocketCleanupFailed)
            | Error(ProxySocketCleanupInProgress) -> #(1, 0)
          }
          let adapter_timeouts =
            bounded_add(
              snapshot.adapter_timeouts,
              adoption_timeouts + cleanup_timeouts,
            )
          let adapter_failures =
            bounded_add(snapshot.adapter_failures, 1 + cleanup_failures)
          let failure = case adoption_timeouts {
            1 -> ProxySocketTimeout
            _ -> ProxySocketAdapterFailed
          }
          reject_proxy_setup(
            config.proxy,
            failure,
            ProxySetupSnapshot(
              ..snapshot,
              adapter_failures: adapter_failures,
              adapter_timeouts: adapter_timeouts,
              timing: ProxySetupTimingSnapshot(
                ..snapshot.timing,
                socket_cleanup_milliseconds: cleanup_elapsed,
                socket_cleanup_timed_out: cleanup_timeouts == 1,
              ),
            ),
          )
        }
      }
    }
  }
}

/// Authorize and establish one accepted default-location request safely.
///
/// The sequence is fixed: exact-target policy, DNS and resolved-address
/// policy, production UDP socket open/adoption, successful HTTP/3 response,
/// then coordinated request-stream binding. The accepted request deliberately
/// has no raw HTTP/3 accessor, so a caller cannot emit an optimistic 2xx or
/// obtain Datagram I/O before this function returns `SystemUdpProxyEstablished`.
/// Call this from the long-lived per-request worker that will relay datagrams;
/// the production socket owner monitors that process and closes on its exit.
pub fn establish_system_udp_proxy_request(
  request: UdpProxyRequest,
  policy: ProxyPolicy,
  config: ProxySetupConfig,
  idle_policy: UdpProxyIdlePolicy,
  resolver resolver: fn(String, Int) ->
    Result(List(IpAddress), DnsLookupFailure),
) -> Result(SystemUdpProxyEstablishment, UdpProxyListenerFailure) {
  case claim_close_guard(request.setup_guard) {
    CloseInProgress | CloseCompleted -> {
      record_udp_proxy_listener_setup_duplicate(request.diagnostics)
      Error(UdpProxyListenerSetupAlreadyStarted)
    }
    CloseAcquired -> {
      let outcome =
        run_system_udp_proxy_request_setup(
          request,
          policy,
          config,
          idle_policy,
          resolver: resolver,
        )
      finish_close_guard(request.setup_guard, CloseSucceeded)
      outcome
    }
  }
}

// nolint: thrown_away_error -- policy/HTTP3 details are redacted after atomic classification.
fn run_system_udp_proxy_request_setup(
  request: UdpProxyRequest,
  policy: ProxyPolicy,
  config: ProxySetupConfig,
  idle_policy: UdpProxyIdlePolicy,
  resolver resolver: fn(String, Int) ->
    Result(List(IpAddress), DnsLookupFailure),
) -> Result(SystemUdpProxyEstablishment, UdpProxyListenerFailure) {
  case authorize_udp_proxy(policy, request.prepared) {
    Error(_) -> respond_udp_proxy_policy_rejection(request, config)
    Ok(authorized) ->
      case establish_system_udp_proxy(authorized, config, resolver: resolver) {
        UdpProxyRejected(response_status, response_headers, failure, snapshot) ->
          case
            http3_server.respond(
              request.request,
              response_status,
              response_headers,
              <<>>,
            )
          {
            Ok(Nil) -> {
              record_udp_proxy_listener_setup(request.diagnostics, 3)
              Ok(SystemUdpProxySetupRejected(response_status, failure, snapshot))
            }
            Error(_) -> fail_udp_proxy_setup_response(request)
          }
        UdpProxyReady(tunnel, response_status, response_headers, snapshot) ->
          case
            http3_server.send_response(
              request.request,
              response_status,
              response_headers,
            )
          {
            Error(_) -> {
              let cleanup = close_udp_proxy(tunnel)
              record_udp_proxy_listener_setup_cleanup(
                request.diagnostics,
                result.is_ok(cleanup),
              )
              fail_udp_proxy_setup_response(request)
            }
            Ok(Nil) -> {
              let session =
                bind_supervised_system_udp_proxy_stream_with_idle(
                  tunnel,
                  http3_udp_request_stream_resource(request.request),
                  idle_policy,
                )
              let proxy =
                SystemUdpProxy(
                  http3_server.request_transport(request.request),
                  session,
                )
              record_udp_proxy_listener_setup(request.diagnostics, 1)
              Ok(SystemUdpProxyEstablished(proxy, snapshot))
            }
          }
      }
  }
}

// nolint: thrown_away_error -- internal/header failures are counted and the request is cancelled.
fn respond_udp_proxy_policy_rejection(
  request: UdpProxyRequest,
  config: ProxySetupConfig,
) -> Result(SystemUdpProxyEstablishment, UdpProxyListenerFailure) {
  case proxy_status_header(config.proxy, "destination_ip_prohibited") {
    Error(_) -> fail_udp_proxy_setup_response(request)
    Ok(proxy_status) ->
      case http3_server.respond(request.request, 502, [proxy_status], <<>>) {
        Ok(Nil) -> {
          record_udp_proxy_listener_setup(request.diagnostics, 2)
          Ok(SystemUdpProxyPolicyRejected(502))
        }
        Error(_) -> fail_udp_proxy_setup_response(request)
      }
  }
}

fn fail_udp_proxy_setup_response(
  request: UdpProxyRequest,
) -> Result(SystemUdpProxyEstablishment, UdpProxyListenerFailure) {
  record_udp_proxy_listener_setup(request.diagnostics, 4)
  let _cancelled = http3_server.cancel(request.request)
  Error(UdpProxyListenerSetupResponseFailed)
}

/// Return typed HTTP/3 Datagram controls after safe setup has completed.
pub fn system_udp_proxy_transport(
  proxy: SystemUdpProxy,
) -> http3_transport.Stream {
  proxy.transport
}

/// Return the bound target-socket/request-stream lifetime after safe setup.
pub fn system_udp_proxy_session(
  proxy: SystemUdpProxy,
) -> UdpProxySession(SystemUdpSocket) {
  proxy.session
}

fn open_system_udp_resource(
  endpoint: UdpEndpoint,
  owner: Pid,
  target_payload_limit_bytes: Int,
  timeout_milliseconds: Int,
) -> Result(UdpSocketResource(SystemUdpSocket), UdpSocketOpenFailure) {
  let UdpEndpoint(address, port) = endpoint
  let bytes = case address {
    Ipv4(bytes) | Ipv6(bytes) -> bytes
  }
  case
    raw_open_system_udp_socket(
      bytes,
      port,
      owner,
      target_payload_limit_bytes,
      timeout_milliseconds,
    )
  {
    Error(2) -> Error(UdpSocketOpenTimedOut)
    Error(5) -> Error(UdpConnectionRefused)
    Error(6) -> Error(UdpDestinationUnroutable)
    Error(_) -> Error(UdpDestinationUnavailable)
    Ok(socket) ->
      Ok(
        udp_socket_resource(socket, fn(close_timeout_milliseconds) {
          case raw_close_system_udp_socket(socket, close_timeout_milliseconds) {
            Ok(Nil) -> Ok(Nil)
            Error(_) -> Error(Nil)
          }
        }),
      )
  }
}

/// Return the application socket resource from an established tunnel.
pub fn udp_proxy_socket(tunnel: UdpProxyTunnel(socket)) -> socket {
  tunnel.resource.socket
}

/// Return the exact resolved peer selected by the socket adapter.
pub fn udp_proxy_peer(tunnel: UdpProxyTunnel(socket)) -> UdpEndpoint {
  tunnel.peer
}

/// Return the active, no-buffer receiver for an established tunnel.
pub fn udp_proxy_receiver(tunnel: UdpProxyTunnel(socket)) -> UdpReceiver {
  tunnel.receiver
}

/// Classify one packet read from the target UDP socket.
///
/// Every adapter, including one backed by a connected socket, routes packets
/// through this transition. The exact resolved address and port are checked
/// before payload alignment or length, so spoofed packets are discarded
/// without parsing or retaining their payload. Continue with the tunnel
/// returned by the decision to preserve its saturating diagnostic counters.
pub fn receive_udp_socket_packet(
  tunnel: UdpProxyTunnel(socket),
  source: UdpEndpoint,
  payload: BitArray,
) -> UdpSocketReceive(socket) {
  let #(resource_state, _, _, _, _) =
    close_guard_snapshot(tunnel.resource.close_guard)
  case resource_state {
    0 -> receive_open_udp_socket_packet(tunnel, source, payload)
    _ -> discard_udp_socket_packet(tunnel, SocketTunnelInactive)
  }
}

/// Classify one target packet through a bound lifetime.
///
/// A terminal notification is checked before source-address, port, alignment,
/// or length inspection. Continue with the returned session to preserve the
/// finite receiver counters; its termination and cleanup guards are shared.
pub fn receive_udp_proxy_session_packet(
  session: UdpProxySession(socket),
  source: UdpEndpoint,
  payload: BitArray,
) -> UdpProxySessionReceive(socket) {
  let #(termination, _) =
    udp_proxy_termination_snapshot(session.termination_guard)
  let decision = case termination {
    0 -> receive_udp_socket_packet(session.tunnel, source, payload)
    _ -> discard_udp_socket_packet(session.tunnel, SocketTunnelInactive)
  }
  case decision {
    ForwardHttpDatagram(tunnel, datagram) ->
      ForwardSessionHttpDatagram(
        UdpProxySession(..session, tunnel: tunnel),
        datagram,
      )
    DiscardUdpPacket(tunnel, reason) ->
      DiscardSessionUdpPacket(
        UdpProxySession(..session, tunnel: tunnel),
        reason,
      )
  }
}

/// Immediately forward one HTTP UDP Proxying Datagram to the selected target.
///
/// An already-terminal session is rejected before Context, alignment, payload,
/// timeout, or socket inspection. Otherwise those ceilings are applied before
/// a command is admitted. No retry or batching queue exists. A fatal socket
/// result invokes the session's first-reason lifetime transition.
pub fn forward_system_udp_datagram(
  session: UdpProxySession(SystemUdpSocket),
  datagram: BitArray,
) -> SystemUdpIo {
  case system_udp_session_is_open(session) {
    False -> SystemUdpSessionInactive(session)
    True -> forward_open_system_udp_datagram(session, datagram)
  }
}

fn forward_open_system_udp_datagram(
  session: UdpProxySession(SystemUdpSocket),
  datagram: BitArray,
) -> SystemUdpIo {
  case receive_proxy_datagram(session.tunnel.receiver, datagram) {
    DropDatagram(receiver, reason) ->
      SystemUdpDatagramDiscarded(
        session: system_udp_session_receiver(session, receiver),
        reason: reason,
      )
    AbortRequestStream(receiver, error) -> {
      let session = system_udp_session_receiver(session, receiver)
      SystemUdpRequestStreamAbort(
        session: session,
        error: error,
        cleanup: close_udp_proxy_session(session),
      )
    }
    ForwardPayload(receiver, payload) -> {
      let session = system_udp_session_receiver(session, receiver)
      let timeout = session.tunnel.config.socket_timeout_milliseconds
      case
        raw_send_system_udp_socket(
          session.tunnel.resource.socket,
          payload,
          timeout,
        )
      {
        Ok(Nil) ->
          SystemUdpSent(observe_udp_proxy_activity(session, UdpActivityToTarget))
        Error(3) -> SystemUdpSendBusy(session)
        Error(code) ->
          system_udp_operation_failure(session, code, sending: True)
      }
    }
  }
}

/// Wait for at most one target-facing UDP packet under a finite deadline.
///
/// An already-terminal session returns without validating the deadline or
/// contacting the socket owner. Otherwise only one receive waiter is admitted.
/// The owner has at most one active UDP event or retained datagram, and it does
/// not return receive credit until the packet is consumed by this call.
pub fn receive_system_udp_datagram(
  session: UdpProxySession(SystemUdpSocket),
  timeout_milliseconds: Int,
) -> SystemUdpIo {
  case system_udp_session_is_open(session) {
    False -> SystemUdpSessionInactive(session)
    True -> receive_open_system_udp_datagram(session, timeout_milliseconds)
  }
}

fn receive_open_system_udp_datagram(
  session: UdpProxySession(SystemUdpSocket),
  timeout_milliseconds: Int,
) -> SystemUdpIo {
  case valid_setup_timeout(timeout_milliseconds) {
    False -> SystemUdpReceiveFailed(session, SystemUdpInvalidInput)
    True ->
      case
        raw_receive_system_udp_socket(
          session.tunnel.resource.socket,
          timeout_milliseconds,
        )
      {
        Ok(RawSystemUdpPacket(address, port, payload)) ->
          case system_udp_endpoint(address, port) {
            Error(Nil) ->
              terminate_system_udp_socket(session, SystemUdpSocketFailure)
            Ok(source) ->
              case receive_udp_proxy_session_packet(session, source, payload) {
                ForwardSessionHttpDatagram(session, datagram) ->
                  SystemUdpForward(
                    session: observe_udp_proxy_activity(
                      session,
                      UdpActivityToHttp,
                    ),
                    datagram:,
                  )
                DiscardSessionUdpPacket(session, reason) ->
                  SystemUdpSocketPacketDiscarded(session:, reason:)
              }
          }
        Ok(RawSystemUdpPayloadTooLarge(
          family,
          maximum_payload_bytes,
          advertised_mtu_bytes,
          quoted_packet_bytes,
          delivery,
        )) ->
          SystemUdpTargetPayloadTooLarge(
            session: session,
            report: PacketTooBigReport(
              family: packet_too_big_address_family(family),
              maximum_udp_payload_bytes: maximum_payload_bytes,
              advertised_mtu_bytes: advertised_mtu_bytes,
              quoted_packet_bytes: quoted_packet_bytes,
              delivery: packet_too_big_delivery(delivery),
            ),
          )
        Error(2) -> SystemUdpReceiveTimedOut(session)
        Error(3) -> SystemUdpReceiveBusy(session)
        Error(code) ->
          system_udp_operation_failure(session, code, sending: False)
      }
  }
}

fn system_udp_session_is_open(
  session: UdpProxySession(SystemUdpSocket),
) -> Bool {
  let #(termination, _) =
    udp_proxy_termination_snapshot(session.termination_guard)
  termination == 0
}

/// Wait for the socket owner to report a terminal event under one deadline.
///
/// A protocol actor can keep this wait outstanding alongside its request-
/// stream loop. It consumes no UDP receive credit and has no polling timer
/// beyond the caller-provided deadline. A reported failure immediately enters
/// the shared first-reason cleanup transition. Normal application cleanup
/// wakes the waiter as `SystemUdpEventStopped` without reclassifying the cause.
pub fn wait_system_udp_event(
  session: UdpProxySession(SystemUdpSocket),
  timeout_milliseconds: Int,
) -> SystemUdpEventWait {
  case valid_setup_timeout(timeout_milliseconds) {
    False -> SystemUdpEventFailed(session, SystemUdpInvalidInput)
    True ->
      case
        raw_wait_system_udp_event(
          session.tunnel.resource.socket,
          timeout_milliseconds,
        )
      {
        Ok(code) -> observe_system_udp_event(session, system_udp_failure(code))
        Error(2) -> SystemUdpEventTimedOut(session)
        Error(3) -> SystemUdpEventBusy(session)
        Error(4) ->
          case system_udp_socket_snapshot(session).socket_failures > 0 {
            True -> observe_system_udp_event(session, SystemUdpSocketClosed)
            False -> SystemUdpEventStopped(session)
          }
        Error(code) ->
          case system_udp_failure(code) {
            SystemUdpSocketFailure as failure ->
              observe_system_udp_event(session, failure)
            failure -> SystemUdpEventFailed(session, failure)
          }
      }
  }
}

fn observe_system_udp_event(
  session: UdpProxySession(SystemUdpSocket),
  failure: SystemUdpFailure,
) -> SystemUdpEventWait {
  SystemUdpEventObserved(
    session: session,
    failure: failure,
    cleanup: notify_udp_socket_unusable(session),
  )
}

/// Inspect the production socket owner without exposing runtime or peer data.
pub fn system_udp_socket_snapshot(
  session: UdpProxySession(SystemUdpSocket),
) -> SystemUdpSocketSnapshot {
  let #(
    state,
    maximum_queued_commands,
    requested_socket_buffer_bytes,
    receive_socket_buffer_bytes,
    send_socket_buffer_bytes,
    maximum_payload_bytes,
    queued_commands,
    buffered_packets,
    buffered_payload_bytes,
    receive_waiting,
    event_waiting,
    rejected_commands,
    sent_packets,
    sent_bytes,
    received_packets,
    received_bytes,
    receive_timeouts,
    event_timeouts,
    socket_failures,
    dont_fragment,
    not_ect,
    relay_timing_samples,
    maximum_send_batch_packets,
    maximum_relay_delay_microseconds,
    maximum_send_service_microseconds,
    material_burst_compressions,
    maximum_burst_compression_microseconds,
    message_too_large_sends,
    fragmentation_retries,
  ) = raw_system_udp_socket_snapshot(session.tunnel.resource.socket)
  SystemUdpSocketSnapshot(
    state: system_udp_socket_state(state),
    maximum_queued_commands: maximum_queued_commands,
    requested_socket_buffer_bytes: requested_socket_buffer_bytes,
    receive_socket_buffer_bytes: receive_socket_buffer_bytes,
    send_socket_buffer_bytes: send_socket_buffer_bytes,
    maximum_payload_bytes: maximum_payload_bytes,
    queued_commands: queued_commands,
    buffered_packets: buffered_packets,
    buffered_payload_bytes: buffered_payload_bytes,
    receive_waiting: receive_waiting,
    event_waiting: event_waiting,
    rejected_commands: rejected_commands,
    sent_packets: sent_packets,
    sent_bytes: sent_bytes,
    received_packets: received_packets,
    received_bytes: received_bytes,
    receive_timeouts: receive_timeouts,
    event_timeouts: event_timeouts,
    socket_failures: socket_failures,
    dont_fragment: dont_fragment,
    not_ect: not_ect,
    relay_timing_samples: relay_timing_samples,
    maximum_send_batch_packets: maximum_send_batch_packets,
    maximum_relay_delay_microseconds: maximum_relay_delay_microseconds,
    maximum_send_service_microseconds: maximum_send_service_microseconds,
    material_burst_compressions: material_burst_compressions,
    maximum_burst_compression_microseconds: maximum_burst_compression_microseconds,
    message_too_large_sends: message_too_large_sends,
    fragmentation_retries: fragmentation_retries,
  )
}

/// Inspect target-side MTU feedback without exposing an endpoint or payload.
///
/// The underlying seqlock retries concurrent writes a bounded number of times.
/// A `consistent: False` result is still finite and explicitly prevents a
/// caller from treating cross-counter invariants as an atomic observation.
pub fn system_udp_packet_too_big_snapshot(
  session: UdpProxySession(SystemUdpSocket),
) -> PacketTooBigSnapshot {
  let #(
    consistent,
    target_payload_limit_bytes,
    maximum_response_burst,
    response_refill_per_second,
    maximum_send_deadline_milliseconds,
    buffered_events,
    retained_payload_bytes,
    oversized_target_packets,
    oversized_target_bytes,
    delivery_attempts,
    delivered_messages,
    delivered_bytes,
    rate_limited,
    permission_denied,
    unsupported,
    timed_out,
    prohibited,
    failures,
    cached_results,
    maximum_quote_bytes,
    advertised_mtu_bytes,
    maximum_send_microseconds,
  ) = raw_system_udp_packet_too_big_snapshot(session.tunnel.resource.socket)
  PacketTooBigSnapshot(
    consistent: consistent,
    target_payload_limit_bytes: target_payload_limit_bytes,
    maximum_response_burst: maximum_response_burst,
    response_refill_per_second: response_refill_per_second,
    maximum_send_deadline_milliseconds: maximum_send_deadline_milliseconds,
    buffered_events: buffered_events,
    retained_payload_bytes: retained_payload_bytes,
    oversized_target_packets: oversized_target_packets,
    oversized_target_bytes: oversized_target_bytes,
    delivery_attempts: delivery_attempts,
    delivered_messages: delivered_messages,
    delivered_bytes: delivered_bytes,
    rate_limited: rate_limited,
    permission_denied: permission_denied,
    unsupported: unsupported,
    timed_out: timed_out,
    prohibited: prohibited,
    failures: failures,
    cached_results: cached_results,
    maximum_quote_bytes: maximum_quote_bytes,
    advertised_mtu_bytes: advertised_mtu_bytes,
    maximum_send_microseconds: maximum_send_microseconds,
  )
}

fn system_udp_session_receiver(
  session: UdpProxySession(SystemUdpSocket),
  receiver: UdpReceiver,
) -> UdpProxySession(SystemUdpSocket) {
  let tunnel = UdpProxyTunnel(..session.tunnel, receiver: receiver)
  UdpProxySession(..session, tunnel: tunnel)
}

fn system_udp_endpoint(
  address: BitArray,
  port: Int,
) -> Result(UdpEndpoint, Nil) {
  case bit_array.bit_size(address) % 8, bit_array.byte_size(address), port {
    0, 4, port if port > 0 && port <= 65_535 ->
      Ok(UdpEndpoint(Ipv4(address), port))
    0, 16, port if port > 0 && port <= 65_535 ->
      Ok(UdpEndpoint(Ipv6(address), port))
    _, _, _ -> Error(Nil)
  }
}

fn system_udp_operation_failure(
  session: UdpProxySession(SystemUdpSocket),
  code: Int,
  sending sending: Bool,
) -> SystemUdpIo {
  let failure = system_udp_failure(code)
  case failure {
    SystemUdpSocketClosed | SystemUdpSocketFailure ->
      terminate_system_udp_socket(session, failure)
    SystemUdpBusy if sending -> SystemUdpSendBusy(session)
    SystemUdpBusy -> SystemUdpReceiveBusy(session)
    _ if sending -> SystemUdpSendFailed(session, failure)
    _ -> SystemUdpReceiveFailed(session, failure)
  }
}

fn terminate_system_udp_socket(
  session: UdpProxySession(SystemUdpSocket),
  failure: SystemUdpFailure,
) -> SystemUdpIo {
  SystemUdpSocketTerminated(
    session: session,
    failure: failure,
    cleanup: notify_udp_socket_unusable(session),
  )
}

fn system_udp_failure(code: Int) -> SystemUdpFailure {
  case code {
    1 -> SystemUdpInvalidInput
    2 -> SystemUdpTimedOut
    3 -> SystemUdpBusy
    4 -> SystemUdpSocketClosed
    7 -> SystemUdpMessageTooLarge
    _ -> SystemUdpSocketFailure
  }
}

fn packet_too_big_address_family(code: Int) -> PacketTooBigAddressFamily {
  case code {
    6 -> PacketTooBigIpv6
    _ -> PacketTooBigIpv4
  }
}

fn packet_too_big_delivery(code: Int) -> PacketTooBigDelivery {
  case code {
    1 -> PacketTooBigDelivered
    2 -> PacketTooBigRateLimited
    3 -> PacketTooBigPermissionDenied
    4 -> PacketTooBigUnsupported
    6 -> PacketTooBigProhibited
    7 -> PacketTooBigTimedOut
    _ -> PacketTooBigDeliveryFailed
  }
}

fn system_udp_socket_state(code: Int) -> SystemUdpSocketState {
  case code {
    0 -> SystemUdpSetup
    1 -> SystemUdpOpen
    2 -> SystemUdpUnusable
    _ -> SystemUdpClosed
  }
}

/// Inspect the bound target-socket receive counters without retaining data.
pub fn udp_proxy_session_receiver_snapshot(
  session: UdpProxySession(socket),
) -> UdpSocketReceiverSnapshot {
  udp_socket_receiver_snapshot(session.tunnel)
}

/// Inspect target-socket forwarding and drop counters without retaining an
/// endpoint, payload, socket, or callback term.
pub fn udp_socket_receiver_snapshot(
  tunnel: UdpProxyTunnel(socket),
) -> UdpSocketReceiverSnapshot {
  let receiver = tunnel.socket_receiver
  UdpSocketReceiverSnapshot(
    forwarded_packets: receiver.forwarded_packets,
    forwarded_bytes: receiver.forwarded_bytes,
    dropped_source_mismatch: receiver.dropped_source_mismatch,
    dropped_oversized: receiver.dropped_oversized,
    dropped_malformed: receiver.dropped_malformed,
    dropped_inactive: receiver.dropped_inactive,
  )
}

fn new_udp_socket_receiver() -> UdpSocketReceiver {
  UdpSocketReceiver(0, 0, 0, 0, 0, 0)
}

fn receive_open_udp_socket_packet(
  tunnel: UdpProxyTunnel(socket),
  source: UdpEndpoint,
  payload: BitArray,
) -> UdpSocketReceive(socket) {
  case exact_udp_source(tunnel.peer, source) {
    False -> discard_udp_socket_packet(tunnel, SocketSourceMismatch)
    True ->
      case encode_udp_datagram(payload, tunnel.receiver.limits) {
        Ok(datagram) -> {
          let receiver = tunnel.socket_receiver
          let receiver =
            UdpSocketReceiver(
              ..receiver,
              forwarded_packets: bounded_increment(receiver.forwarded_packets),
              forwarded_bytes: bounded_add(
                receiver.forwarded_bytes,
                bit_array.byte_size(payload),
              ),
            )
          ForwardHttpDatagram(
            UdpProxyTunnel(..tunnel, socket_receiver: receiver),
            datagram,
          )
        }
        Error(DatagramLimitExceeded(maximum)) ->
          discard_udp_socket_packet(tunnel, SocketPayloadTooLarge(maximum))
        Error(error) ->
          discard_udp_socket_packet(tunnel, SocketPayloadMalformed(error))
      }
  }
}

fn exact_udp_source(expected: UdpEndpoint, source: UdpEndpoint) -> Bool {
  source.port >= 1
  && source.port <= 65_535
  && result.is_ok(address_number(source.address))
  && source == expected
}

fn discard_udp_socket_packet(
  tunnel: UdpProxyTunnel(socket),
  reason: UdpSocketDropReason,
) -> UdpSocketReceive(socket) {
  let receiver = tunnel.socket_receiver
  let receiver = case reason {
    SocketSourceMismatch ->
      UdpSocketReceiver(
        ..receiver,
        dropped_source_mismatch: bounded_increment(
          receiver.dropped_source_mismatch,
        ),
      )
    SocketPayloadTooLarge(_) ->
      UdpSocketReceiver(
        ..receiver,
        dropped_oversized: bounded_increment(receiver.dropped_oversized),
      )
    SocketPayloadMalformed(_) ->
      UdpSocketReceiver(
        ..receiver,
        dropped_malformed: bounded_increment(receiver.dropped_malformed),
      )
    SocketTunnelInactive ->
      UdpSocketReceiver(
        ..receiver,
        dropped_inactive: bounded_increment(receiver.dropped_inactive),
      )
  }
  DiscardUdpPacket(UdpProxyTunnel(..tunnel, socket_receiver: receiver), reason)
}

/// Inspect socket ownership and saturating cleanup counters without exposing
/// the socket, selected peer, target, or callback failure term.
pub fn udp_proxy_resource_snapshot(
  tunnel: UdpProxyTunnel(socket),
) -> UdpProxyResourceSnapshot {
  let #(state, close_calls, attempts, failures, timeouts) =
    close_guard_snapshot(tunnel.resource.close_guard)
  let state = case state {
    0 -> UdpProxyOpen
    1 -> UdpProxyClosing
    _ -> UdpProxyClosed
  }
  UdpProxyResourceSnapshot(state, close_calls, attempts, failures, timeouts)
}

/// Wrap one adapter socket with its finite-deadline cleanup operation.
///
/// The close callback receives the setup socket timeout and is supervised by
/// the same heap and deadline limits when `close_udp_proxy` is called.
pub fn udp_socket_resource(
  socket: socket,
  close: fn(Int) -> Result(Nil, Nil),
) -> UdpSocketResource(socket) {
  UdpSocketResource(socket, close, new_close_guard())
}

/// Wrap the corresponding HTTP request stream with bounded close behavior.
///
/// The callback receives the first terminal reason and the socket deadline
/// from `ProxySetupConfig`. It is always run in a monitored worker with that
/// deadline and the configured heap ceiling.
pub fn udp_request_stream_resource(
  close: fn(UdpProxyTerminationReason, Int) -> Result(Nil, Nil),
) -> UdpRequestStreamResource {
  UdpRequestStreamResource(close, new_close_guard())
}

/// Bind a protocol-neutral server context to coordinated UDP-proxy cleanup.
///
/// The first socket failure signals the context's shared cancellation state.
/// The unified HTTP/1.1, HTTP/2, or HTTP/3 adapter then performs its native
/// request-stream shutdown while its supervised handler is being cancelled.
/// Repeated notifications remain harmless through the resource close guard.
pub fn context_udp_request_stream_resource(
  request_context: context.Context,
) -> UdpRequestStreamResource {
  udp_request_stream_resource(fn(_, _) {
    context.cancel(request_context)
    Ok(Nil)
  })
}

/// Bind a public HTTP/3 server request to coordinated UDP-proxy cleanup.
///
/// A target UDP failure or application close cancels both QUIC stream
/// directions with `H3_REQUEST_CANCELLED` (0x10c). The HTTP/3 actor performs
/// the cancellation idempotently; this resource's existing monitored worker,
/// heap ceiling, and finite socket deadline supervise the call. No transport
/// handle, stream identifier, peer metadata, or backend failure escapes.
pub fn http3_udp_request_stream_resource(
  request: http3_server.Request,
) -> UdpRequestStreamResource {
  udp_request_stream_resource(fn(_, _) {
    case http3_server.cancel(request) {
      Ok(http3_server.Cancelled)
      | Ok(http3_server.AlreadyCancelled)
      | Ok(http3_server.AlreadyCompleted) -> Ok(Nil)
      Error(_) -> Error(Nil)
    }
  })
}

/// Bind one established UDP socket to its corresponding HTTP request stream.
///
/// Binding performs no cleanup and shortens neither lifetime. After binding,
/// the adapter reports terminal events through the session notification
/// functions so socket and stream cleanup converge as one finite operation.
pub fn bind_udp_proxy_stream(
  tunnel: UdpProxyTunnel(socket),
  request_stream: UdpRequestStreamResource,
) -> UdpProxySession(socket) {
  UdpProxySession(
    tunnel,
    request_stream,
    new_udp_proxy_termination_guard(),
    new_close_guard(),
    None,
  )
}

/// Bind a production UDP socket and start its terminal-lifetime owner.
///
/// The owner immediately installs the socket's single event waiter without a
/// polling deadline. It remains blocked while an otherwise idle request
/// stream is open. An operating-system socket failure therefore enters the
/// shared socket/request-stream cleanup transition without waiting for another
/// application send or receive. Normal request-stream or application cleanup
/// closes the socket, wakes this owner, and preserves the already-recorded
/// first termination reason.
///
/// A failure racing watcher installation is retained by the UDP socket owner
/// and observed by this process. The process owns no packet queue and every
/// diagnostic remains available through the existing payload-free snapshots.
pub fn bind_supervised_system_udp_proxy_stream(
  tunnel: UdpProxyTunnel(SystemUdpSocket),
  request_stream: UdpRequestStreamResource,
) -> UdpProxySession(SystemUdpSocket) {
  bind_supervised_system_udp_proxy_stream_with_idle(
    tunnel,
    request_stream,
    udp_proxy_idle_timeout_disabled(),
  )
}

/// Bind a production UDP lifetime with an optional validated idle deadline.
///
/// The idle owner uses one monotonic deadline and an activity wake credit of
/// one. It has no periodic wakeup. Valid HTTP-to-target sends and validated
/// target-to-HTTP forwards move the deadline; malformed or rejected packets do
/// not. Deadline expiry atomically records `IdleTimeout` before coordinated
/// cleanup of the request stream and socket.
pub fn bind_supervised_system_udp_proxy_stream_with_idle(
  tunnel: UdpProxyTunnel(SystemUdpSocket),
  request_stream: UdpRequestStreamResource,
  idle_policy: UdpProxyIdlePolicy,
) -> UdpProxySession(SystemUdpSocket) {
  let session = bind_udp_proxy_stream(tunnel, request_stream)
  let session = case idle_policy.timeout_milliseconds {
    None -> session
    Some(timeout_milliseconds) ->
      start_udp_proxy_idle_owner(session, timeout_milliseconds)
  }
  let _owner =
    process.spawn_unlinked(fn() { supervise_system_udp_proxy_session(session) })
  session
}

/// Bind a unified HTTP request context to a supervised production UDP socket.
///
/// This is the common HTTP/1.1, HTTP/2, and HTTP/3 server-adapter entry point.
/// It subscribes once to the context's event-driven cancellation broker. A
/// request-stream end closes the target socket with `RequestStreamEnded`; a
/// socket failure cancels the context through the request-stream resource.
/// Either direction wakes and reclaims both waiters, so no periodic deadline
/// poll or protocol-specific lifetime loop is required.
pub fn bind_supervised_system_udp_proxy_context(
  tunnel: UdpProxyTunnel(SystemUdpSocket),
  request_context: context.Context,
) -> UdpProxySession(SystemUdpSocket) {
  bind_supervised_system_udp_proxy_context_with_idle(
    tunnel,
    request_context,
    udp_proxy_idle_timeout_disabled(),
  )
}

/// Bind a unified HTTP context with an optional validated idle deadline.
pub fn bind_supervised_system_udp_proxy_context_with_idle(
  tunnel: UdpProxyTunnel(SystemUdpSocket),
  request_context: context.Context,
  idle_policy: UdpProxyIdlePolicy,
) -> UdpProxySession(SystemUdpSocket) {
  let session =
    bind_supervised_system_udp_proxy_stream_with_idle(
      tunnel,
      context_udp_request_stream_resource(request_context),
      idle_policy,
    )
  let ready = process.new_subject()
  let _request_stream_owner =
    process.spawn_unlinked(fn() {
      // A Subject is bound to the mailbox of the process that creates it.
      // Construct both the cancellation subject and subscription here, then
      // acknowledge installation to the binding process.
      let cancelled = process.new_subject()
      let subscription =
        context.subscribe_cancellation(request_context, cancelled)
      process.send(ready, Nil)
      let _cancelled = process.receive_forever(cancelled)
      context.unsubscribe_cancellation(subscription)
      let _cleanup = notify_udp_request_stream_ended(session)
      Nil
    })
  case
    process.receive(
      ready,
      within: session.tunnel.config.socket_timeout_milliseconds,
    )
  {
    Ok(Nil) -> Nil
    Error(Nil) -> {
      let _cleanup = close_udp_proxy_session(session)
      Nil
    }
  }
  session
}

fn start_udp_proxy_idle_owner(
  session: UdpProxySession(SystemUdpSocket),
  timeout_milliseconds: Int,
) -> UdpProxySession(SystemUdpSocket) {
  let ready = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      let runtime =
        new_udp_proxy_idle_runtime(
          timeout_milliseconds,
          monotonic_millisecond(),
        )
      let guard = UdpProxyIdleGuard(commands, runtime)
      process.send(ready, guard)
      udp_proxy_idle_owner_loop(session, guard)
    })
  case
    process.receive(
      ready,
      within: session.tunnel.config.socket_timeout_milliseconds,
    )
  {
    Ok(guard) -> UdpProxySession(..session, idle_guard: Some(guard))
    Error(Nil) -> {
      process.kill(owner)
      let _late_start = process.receive(ready, within: 0)
      let _cleanup = close_udp_proxy_session(session)
      session
    }
  }
}

fn udp_proxy_idle_owner_loop(
  session: UdpProxySession(SystemUdpSocket),
  guard: UdpProxyIdleGuard,
) -> Nil {
  let UdpProxyIdleGuard(commands, runtime) = guard
  let #(state, _, deadline, _, _, _, _, _, _, _, _, _) =
    raw_udp_proxy_idle_snapshot(runtime)
  case state {
    0 -> {
      let now = monotonic_millisecond()
      let remaining = case deadline - now {
        value if value > 0 -> value
        _ -> 0
      }
      case process.receive(commands, within: remaining) {
        Ok(UdpIdleWake) -> {
          let state = acknowledge_udp_proxy_idle_wake(runtime)
          case state {
            0 -> udp_proxy_idle_owner_loop(session, guard)
            _ -> Nil
          }
        }
        Error(Nil) ->
          case claim_udp_proxy_idle_deadline(runtime, monotonic_millisecond()) {
            #(0, _) -> udp_proxy_idle_owner_loop(session, guard)
            #(2, _) -> {
              let _cleanup = terminate_udp_proxy_session(session, IdleTimeout)
              Nil
            }
            _ -> Nil
          }
      }
    }
    _ -> Nil
  }
}

fn supervise_system_udp_proxy_session(
  session: UdpProxySession(SystemUdpSocket),
) -> Nil {
  case udp_proxy_session_snapshot(session).state {
    UdpProxyClosing | UdpProxyClosed -> Nil
    UdpProxyOpen ->
      case raw_wait_system_udp_event_forever(session.tunnel.resource.socket) {
        Ok(code) -> {
          let _observed =
            observe_system_udp_event(session, system_udp_failure(code))
          Nil
        }
        Error(3) -> {
          // A finite diagnostic waiter may already own the independent event
          // credit. It cannot hide a terminal event: it performs the same
          // cleanup, and this owner retries only while the session stays open.
          process.sleep(1)
          supervise_system_udp_proxy_session(session)
        }
        Error(4) ->
          case system_udp_socket_snapshot(session).socket_failures > 0 {
            True -> {
              let _observed =
                observe_system_udp_event(session, SystemUdpSocketClosed)
              Nil
            }
            False -> Nil
          }
        Error(code) -> {
          let _observed =
            observe_system_udp_event(session, system_udp_failure(code))
          Nil
        }
      }
  }
}

/// Report that the operating system says the target UDP socket is unusable.
///
/// The first reason is recorded before either adapter is invoked, making the
/// session inactive at this transition. Request-stream and socket cleanup are
/// both attempted even if either one fails, exits, or times out.
pub fn notify_udp_socket_unusable(
  session: UdpProxySession(socket),
) -> Result(Nil, UdpProxySessionFailure) {
  terminate_udp_proxy_session(session, SocketUnusable)
}

/// Report that the corresponding HTTP request stream has ended.
///
/// The stream is already terminal, so its close adapter is not invoked. The
/// same coordinated transition closes the target UDP socket and marks both
/// resource guards complete before returning.
pub fn notify_udp_request_stream_ended(
  session: UdpProxySession(socket),
) -> Result(Nil, UdpProxySessionFailure) {
  terminate_udp_proxy_session(session, RequestStreamEnded)
}

/// Close a bound session at application request.
///
/// Both resource adapters run under the same finite limits as an unusable
/// socket transition. Repeated calls retry only components whose cleanup did
/// not already converge.
pub fn close_udp_proxy_session(
  session: UdpProxySession(socket),
) -> Result(Nil, UdpProxySessionFailure) {
  terminate_udp_proxy_session(session, ApplicationClosed)
}

/// Inspect a bound lifetime without exposing callbacks, handles, or payload.
pub fn udp_proxy_session_snapshot(
  session: UdpProxySession(socket),
) -> UdpProxySessionSnapshot {
  let #(reason_code, notifications) =
    udp_proxy_termination_snapshot(session.termination_guard)
  let #(cleanup_state, _, attempts, failures, timeouts) =
    close_guard_snapshot(session.cleanup_guard)
  let state = case reason_code, cleanup_state {
    0, _ -> UdpProxyOpen
    _, 2 -> UdpProxyClosed
    _, _ -> UdpProxyClosing
  }
  UdpProxySessionSnapshot(
    state:,
    termination: termination_reason(reason_code),
    termination_notifications: notifications,
    cleanup_attempts: attempts,
    cleanup_failures: failures,
    cleanup_timeouts: timeouts,
    socket: udp_proxy_resource_snapshot(session.tunnel),
    request_stream: udp_request_stream_snapshot(session.request_stream),
  )
}

/// Inspect the optional idle owner without exposing its process or commands.
pub fn udp_proxy_idle_snapshot(
  session: UdpProxySession(socket),
) -> UdpProxyIdleSnapshot {
  case session.idle_guard {
    None ->
      UdpProxyIdleSnapshot(
        state: UdpIdleDisabled,
        timeout_milliseconds: None,
        remaining_milliseconds: None,
        maximum_pending_commands: 0,
        pending_command: False,
        activity_events: 0,
        outbound_activity_events: 0,
        inbound_activity_events: 0,
        wake_signals: 0,
        owner_wakeups: 0,
        deadline_checks: 0,
        expirations: 0,
        stop_signals: 0,
      )
    Some(UdpProxyIdleGuard(_, runtime)) -> {
      let #(
        state,
        timeout,
        deadline,
        pending,
        activity_events,
        outbound_activity_events,
        inbound_activity_events,
        wake_signals,
        owner_wakeups,
        deadline_checks,
        expirations,
        stop_signals,
      ) = raw_udp_proxy_idle_snapshot(runtime)
      let #(state, remaining_milliseconds) = case state {
        0 -> {
          let remaining = case deadline - monotonic_millisecond() {
            value if value > 0 -> value
            _ -> 0
          }
          #(UdpIdleWatching, Some(remaining))
        }
        2 -> #(UdpIdleExpired, None)
        _ -> #(UdpIdleStopped, None)
      }
      UdpProxyIdleSnapshot(
        state:,
        timeout_milliseconds: Some(timeout),
        remaining_milliseconds:,
        maximum_pending_commands: 1,
        pending_command: pending,
        activity_events:,
        outbound_activity_events:,
        inbound_activity_events:,
        wake_signals:,
        owner_wakeups:,
        deadline_checks:,
        expirations:,
        stop_signals:,
      )
    }
  }
}

fn observe_udp_proxy_activity(
  session: UdpProxySession(SystemUdpSocket),
  direction: UdpProxyActivityDirection,
) -> UdpProxySession(SystemUdpSocket) {
  case session.idle_guard {
    None -> session
    Some(UdpProxyIdleGuard(commands, runtime)) -> {
      let direction = case direction {
        UdpActivityToTarget -> 1
        UdpActivityToHttp -> 2
      }
      case
        record_udp_proxy_idle_activity(
          runtime,
          monotonic_millisecond(),
          direction,
        )
      {
        1 -> process.send(commands, UdpIdleWake)
        _ -> Nil
      }
      session
    }
  }
}

fn stop_udp_proxy_idle_owner(session: UdpProxySession(socket)) -> Nil {
  case session.idle_guard {
    None -> Nil
    Some(UdpProxyIdleGuard(commands, runtime)) -> {
      case stop_udp_proxy_idle_runtime(runtime) {
        1 -> process.send(commands, UdpIdleWake)
        _ -> Nil
      }
    }
  }
}

fn terminate_udp_proxy_session(
  session: UdpProxySession(socket),
  reason: UdpProxyTerminationReason,
) -> Result(Nil, UdpProxySessionFailure) {
  let reason =
    record_udp_proxy_termination(
      session.termination_guard,
      termination_reason_code(reason),
    )
    |> termination_reason_from_code
  stop_udp_proxy_idle_owner(session)
  case claim_close_guard(session.cleanup_guard) {
    CloseCompleted -> Ok(Nil)
    CloseInProgress -> Error(UdpProxyTerminationInProgress)
    CloseAcquired -> {
      let request_stream = close_udp_request_stream(session, reason)
      let socket = close_udp_proxy(session.tunnel)
      let outcome = session_cleanup_outcome(socket, request_stream)
      finish_close_guard(
        session.cleanup_guard,
        session_cleanup_completion(socket, request_stream),
      )
      outcome
    }
  }
}

fn close_udp_request_stream(
  session: UdpProxySession(socket),
  reason: UdpProxyTerminationReason,
) -> Result(Nil, UdpRequestStreamCleanupFailure) {
  case reason {
    RequestStreamEnded -> mark_udp_request_stream_ended(session.request_stream)
    SocketUnusable | ApplicationClosed | IdleTimeout ->
      run_udp_request_stream_close(session, reason)
  }
}

fn mark_udp_request_stream_ended(
  stream: UdpRequestStreamResource,
) -> Result(Nil, UdpRequestStreamCleanupFailure) {
  case claim_close_guard(stream.close_guard) {
    CloseCompleted -> Ok(Nil)
    CloseInProgress -> Error(UdpRequestStreamCleanupInProgress)
    CloseAcquired -> {
      finish_close_guard(stream.close_guard, CloseSucceeded)
      Ok(Nil)
    }
  }
}

fn run_udp_request_stream_close(
  session: UdpProxySession(socket),
  reason: UdpProxyTerminationReason,
) -> Result(Nil, UdpRequestStreamCleanupFailure) {
  let ProxySetupConfig(
    socket_timeout_milliseconds: timeout,
    maximum_adapter_heap_words: maximum_heap_words,
    ..,
  ) = session.tunnel.config
  case claim_close_guard(session.request_stream.close_guard) {
    CloseCompleted -> Ok(Nil)
    CloseInProgress -> Error(UdpRequestStreamCleanupInProgress)
    CloseAcquired -> {
      let #(outcome, completion) = case
        call_bounded_adapter(
          fn() { session.request_stream.close(reason, timeout) },
          timeout,
          maximum_heap_words,
        )
      {
        Ok(Ok(Nil)) -> #(Ok(Nil), CloseSucceeded)
        Error(BoundedAdapterTimedOut) -> #(
          Error(UdpRequestStreamCleanupTimeout),
          CloseTimedOut,
        )
        Ok(Error(Nil)) | Error(BoundedAdapterFailed) -> #(
          Error(UdpRequestStreamCleanupFailed),
          CloseFailed,
        )
      }
      finish_close_guard(session.request_stream.close_guard, completion)
      outcome
    }
  }
}

fn session_cleanup_outcome(
  socket: Result(Nil, ProxySetupFailure),
  request_stream: Result(Nil, UdpRequestStreamCleanupFailure),
) -> Result(Nil, UdpProxySessionFailure) {
  case socket, request_stream {
    Ok(Nil), Ok(Nil) -> Ok(Nil)
    _, _ ->
      Error(UdpProxyCleanupIncomplete(
        socket: result_error(socket),
        request_stream: result_error(request_stream),
      ))
  }
}

fn session_cleanup_completion(
  socket: Result(Nil, ProxySetupFailure),
  request_stream: Result(Nil, UdpRequestStreamCleanupFailure),
) -> CloseCompletion {
  case socket, request_stream {
    Ok(Nil), Ok(Nil) -> CloseSucceeded
    Error(ProxySocketCleanupTimeout), _
    | _, Error(UdpRequestStreamCleanupTimeout)
    -> CloseTimedOut
    _, _ -> CloseFailed
  }
}

fn result_error(outcome: Result(Nil, failure)) -> Option(failure) {
  case outcome {
    Ok(Nil) -> None
    Error(failure) -> Some(failure)
  }
}

fn udp_request_stream_snapshot(
  stream: UdpRequestStreamResource,
) -> UdpRequestStreamSnapshot {
  let #(state, close_calls, attempts, failures, timeouts) =
    close_guard_snapshot(stream.close_guard)
  UdpRequestStreamSnapshot(
    state: cleanup_state(state),
    close_calls:,
    cleanup_attempts: attempts,
    cleanup_failures: failures,
    cleanup_timeouts: timeouts,
  )
}

fn cleanup_state(state: Int) -> UdpProxyResourceState {
  case state {
    0 -> UdpProxyOpen
    1 -> UdpProxyClosing
    _ -> UdpProxyClosed
  }
}

fn termination_reason_code(reason: UdpProxyTerminationReason) -> Int {
  case reason {
    RequestStreamEnded -> 1
    SocketUnusable -> 2
    ApplicationClosed -> 3
    IdleTimeout -> 4
  }
}

fn termination_reason(code: Int) -> Option(UdpProxyTerminationReason) {
  case code {
    0 -> None
    value -> Some(termination_reason_from_code(value))
  }
}

fn termination_reason_from_code(code: Int) -> UdpProxyTerminationReason {
  case code {
    1 -> RequestStreamEnded
    2 -> SocketUnusable
    3 -> ApplicationClosed
    _ -> IdleTimeout
  }
}

/// Close an established UDP resource without allowing callback errors, exits,
/// panics, or late replies to escape into the request process.
pub fn close_udp_proxy(
  tunnel: UdpProxyTunnel(socket),
) -> Result(Nil, ProxySetupFailure) {
  let ProxySetupConfig(
    socket_timeout_milliseconds: timeout,
    maximum_adapter_heap_words: maximum_heap_words,
    ..,
  ) = tunnel.config
  case claim_close_guard(tunnel.resource.close_guard) {
    CloseCompleted -> Ok(Nil)
    CloseInProgress -> Error(ProxySocketCleanupInProgress)
    CloseAcquired -> {
      let #(outcome, completion) = case
        call_bounded_adapter(
          fn() { tunnel.resource.close(timeout) },
          timeout,
          maximum_heap_words,
        )
      {
        Ok(Ok(Nil)) -> #(Ok(Nil), CloseSucceeded)
        Error(BoundedAdapterTimedOut) -> #(
          Error(ProxySocketCleanupTimeout),
          CloseTimedOut,
        )
        Ok(Error(Nil)) | Error(BoundedAdapterFailed) -> #(
          Error(ProxySocketCleanupFailed),
          CloseFailed,
        )
      }
      finish_close_guard(tunnel.resource.close_guard, completion)
      outcome
    }
  }
}

fn resolve_proxy_addresses(
  request: PreparedRequest,
  target: UdpTarget,
  policy: ProxyPolicy,
  config: ProxySetupConfig,
  resolver: fn(String, Int) -> Result(List(IpAddress), DnsLookupFailure),
  open_socket: fn(UdpEndpoint, Int) ->
    Result(UdpSocketResource(socket), UdpSocketOpenFailure),
  snapshot: ProxySetupSnapshot,
) -> UdpProxySetup(socket) {
  let started = monotonic_millisecond()
  let #(
    outcome,
    callback_started,
    queue_milliseconds,
    callback_milliseconds,
    supervisor_timed_out,
  ) =
    call_bounded_adapter_traced(
      fn() {
        run_dns_adapter(
          target.host,
          config.dns_timeout_milliseconds,
          policy.limits.maximum_address_entries,
          resolver,
        )
      },
      config.dns_timeout_milliseconds,
      config.maximum_adapter_heap_words,
    )
  let timing =
    ProxySetupTimingSnapshot(
      ..snapshot.timing,
      dns_milliseconds: setup_elapsed_milliseconds(started),
      dns_adapter: AdapterExecutionTimingSnapshot(
        callback_started: callback_started,
        queue_milliseconds: queue_milliseconds,
        callback_milliseconds: callback_milliseconds,
        supervisor_timed_out: supervisor_timed_out,
      ),
    )
  let snapshot = ProxySetupSnapshot(..snapshot, timing: timing)
  case outcome {
    Error(BoundedAdapterTimedOut) ->
      reject_proxy_setup(
        config.proxy,
        ProxyDnsTimeout,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_timeouts: snapshot.adapter_timeouts + 1,
          timing: ProxySetupTimingSnapshot(
            ..snapshot.timing,
            dns_timed_out: True,
          ),
        ),
      )
    Error(BoundedAdapterFailed) ->
      reject_proxy_setup(
        config.proxy,
        ProxyDnsAdapterFailed,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_failures: snapshot.adapter_failures + 1,
        ),
      )
    Ok(Error(Nil)) ->
      reject_proxy_setup(
        config.proxy,
        ProxyDnsAdapterFailed,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_failures: snapshot.adapter_failures + 1,
        ),
      )
    Ok(Ok(DnsLookupRejected)) ->
      reject_proxy_setup(config.proxy, ProxyDnsError, snapshot)
    Ok(Ok(DnsAnswerRejected(observed))) -> {
      let completed =
        ProxySetupSnapshot(
          ..snapshot,
          dns_completed: True,
          resolved_addresses: observed,
        )
      reject_proxy_setup(config.proxy, ProxyDnsAnswerInvalid, completed)
    }
    Ok(Ok(DnsAddressesReady(addresses))) -> {
      let completed =
        ProxySetupSnapshot(
          ..snapshot,
          events: list.append(snapshot.events, [
            ProxyDnsCompleted(list.length(addresses)),
          ]),
          dns_completed: True,
          resolved_addresses: list.length(addresses),
        )
      authorize_proxy_addresses(
        request,
        target,
        policy,
        config,
        addresses,
        open_socket,
        completed,
      )
    }
  }
}

fn run_dns_adapter(
  host: String,
  timeout_milliseconds: Int,
  maximum_addresses: Int,
  resolver: fn(String, Int) -> Result(List(IpAddress), DnsLookupFailure),
) -> Result(DnsAdapterOutcome, Nil) {
  case resolver(host, timeout_milliseconds) {
    Error(DnsLookupFailed) -> Ok(DnsLookupRejected)
    Ok(addresses) -> {
      let observed = bounded_list_count(addresses, maximum_addresses)
      case validate_dns_addresses(addresses, maximum_addresses) {
        Error(Nil) -> Ok(DnsAnswerRejected(observed))
        Ok(addresses) -> Ok(DnsAddressesReady(addresses))
      }
    }
  }
}

fn authorize_proxy_addresses(
  request: PreparedRequest,
  target: UdpTarget,
  policy: ProxyPolicy,
  config: ProxySetupConfig,
  addresses: List(IpAddress),
  open_socket: fn(UdpEndpoint, Int) ->
    Result(UdpSocketResource(socket), UdpSocketOpenFailure),
  snapshot: ProxySetupSnapshot,
) -> UdpProxySetup(socket) {
  let authorized =
    list.filter(addresses, fn(address) {
      list.any(policy.udp_destinations, fn(prefix) {
        prefix_contains(prefix, address)
      })
    })
  let count = list.length(authorized)
  let snapshot = ProxySetupSnapshot(..snapshot, authorized_addresses: count)
  case authorized {
    [] -> reject_proxy_setup(config.proxy, ProxyDestinationForbidden, snapshot)
    [address, ..] ->
      open_proxy_socket(
        request,
        UdpEndpoint(address, target.port),
        config,
        open_socket,
        ProxySetupSnapshot(
          ..snapshot,
          events: list.append(snapshot.events, [
            ProxyDestinationsAuthorized(count),
          ]),
        ),
      )
  }
}

fn open_proxy_socket(
  request: PreparedRequest,
  endpoint: UdpEndpoint,
  config: ProxySetupConfig,
  open_socket: fn(UdpEndpoint, Int) ->
    Result(UdpSocketResource(socket), UdpSocketOpenFailure),
  snapshot: ProxySetupSnapshot,
) -> UdpProxySetup(socket) {
  let snapshot =
    ProxySetupSnapshot(
      ..snapshot,
      events: list.append(snapshot.events, [ProxySocketStarted]),
      socket_attempted: True,
    )
  let started = monotonic_millisecond()
  let #(
    outcome,
    callback_started,
    queue_milliseconds,
    callback_milliseconds,
    supervisor_timed_out,
  ) =
    call_bounded_adapter_traced(
      fn() {
        run_socket_adapter(
          endpoint,
          config.socket_setup_timeout_milliseconds,
          open_socket,
        )
      },
      config.socket_setup_timeout_milliseconds,
      config.maximum_adapter_heap_words,
    )
  let timing =
    ProxySetupTimingSnapshot(
      ..snapshot.timing,
      socket_open_milliseconds: setup_elapsed_milliseconds(started),
      socket_open_adapter: AdapterExecutionTimingSnapshot(
        callback_started: callback_started,
        queue_milliseconds: queue_milliseconds,
        callback_milliseconds: callback_milliseconds,
        supervisor_timed_out: supervisor_timed_out,
      ),
    )
  let snapshot = ProxySetupSnapshot(..snapshot, timing: timing)
  case outcome {
    Error(BoundedAdapterTimedOut) ->
      reject_proxy_setup(
        config.proxy,
        ProxySocketTimeout,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_timeouts: snapshot.adapter_timeouts + 1,
          timing: ProxySetupTimingSnapshot(
            ..snapshot.timing,
            socket_open_timed_out: True,
          ),
        ),
      )
    Error(BoundedAdapterFailed) ->
      reject_proxy_setup(
        config.proxy,
        ProxySocketAdapterFailed,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_failures: snapshot.adapter_failures + 1,
        ),
      )
    Ok(Error(Nil)) ->
      reject_proxy_setup(
        config.proxy,
        ProxySocketAdapterFailed,
        ProxySetupSnapshot(
          ..snapshot,
          adapter_failures: snapshot.adapter_failures + 1,
        ),
      )
    Ok(Ok(SocketOpenRejected(failure))) -> {
      let snapshot = case failure {
        ProxySocketTimeout ->
          ProxySetupSnapshot(
            ..snapshot,
            adapter_timeouts: bounded_increment(snapshot.adapter_timeouts),
            timing: ProxySetupTimingSnapshot(
              ..snapshot.timing,
              socket_open_timed_out: True,
            ),
          )
        _ -> snapshot
      }
      reject_proxy_setup(config.proxy, failure, snapshot)
    }
    Ok(Ok(SocketResourceReady(resource))) -> {
      let response_status = case request.protocol {
        Http1 -> 101
        Http2 | Http3 -> 200
      }
      let assert Ok(response_headers) =
        successful_response_headers(request, response_status)
      let assert Ok(receiver) = udp_receiver(request.limits)
      let receiver = activate_udp_receiver(receiver)
      UdpProxyReady(
        tunnel: UdpProxyTunnel(
          resource,
          endpoint,
          receiver,
          new_udp_socket_receiver(),
          config,
        ),
        response_status: response_status,
        response_headers: response_headers,
        snapshot: ProxySetupSnapshot(
          ..snapshot,
          events: list.append(snapshot.events, [ProxySocketOpened]),
        ),
      )
    }
  }
}

fn run_socket_adapter(
  endpoint: UdpEndpoint,
  timeout_milliseconds: Int,
  open_socket: fn(UdpEndpoint, Int) ->
    Result(UdpSocketResource(socket), UdpSocketOpenFailure),
) -> Result(SocketAdapterOutcome(socket), Nil) {
  case open_socket(endpoint, timeout_milliseconds) {
    Error(failure) -> Ok(SocketOpenRejected(socket_setup_failure(failure)))
    Ok(resource) -> {
      let UdpSocketResource(socket, close, close_guard) = resource
      Ok(SocketResourceReady(UdpSocketResource(socket, close, close_guard)))
    }
  }
}

fn reject_proxy_setup(
  proxy: status.Identifier,
  failure: ProxySetupFailure,
  snapshot: ProxySetupSnapshot,
) -> UdpProxySetup(socket) {
  let #(response_status, error_type) = proxy_setup_failure_response(failure)
  let assert Ok(proxy_status) = proxy_status_header(proxy, error_type)
  UdpProxyRejected(
    response_status: response_status,
    response_headers: [proxy_status],
    failure: failure,
    snapshot: append_proxy_setup_event(snapshot, ProxySetupFailed(failure)),
  )
}

fn proxy_setup_failure_response(failure: ProxySetupFailure) -> #(Int, String) {
  case failure {
    ProxyDnsError | ProxyDnsAdapterFailed | ProxyDnsAnswerInvalid -> #(
      502,
      "dns_error",
    )
    ProxyDnsTimeout -> #(504, "dns_timeout")
    ProxyDestinationForbidden -> #(502, "destination_ip_prohibited")
    ProxySocketRefused -> #(502, "connection_refused")
    ProxySocketUnroutable -> #(502, "destination_ip_unroutable")
    ProxySocketUnavailable -> #(503, "destination_unavailable")
    ProxySocketTimeout -> #(504, "connection_timeout")
    ProxySocketAdapterFailed
    | ProxySocketCleanupFailed
    | ProxySocketCleanupTimeout
    | ProxySocketCleanupInProgress -> #(500, "proxy_internal_error")
  }
}

fn socket_setup_failure(failure: UdpSocketOpenFailure) -> ProxySetupFailure {
  case failure {
    UdpConnectionRefused -> ProxySocketRefused
    UdpDestinationUnroutable -> ProxySocketUnroutable
    UdpDestinationUnavailable -> ProxySocketUnavailable
    UdpSocketOpenTimedOut -> ProxySocketTimeout
  }
}

fn proxy_status_header(
  proxy: status.Identifier,
  error_type: String,
) -> Result(#(String, String), Error) {
  status.serialize_proxy_for(status.Intermediary, status.ProxyHeader, [
    status.ProxyStatus(
      proxy: proxy,
      error: Some(error_type),
      next_hop: None,
      next_protocol: None,
      received_status: None,
      details: None,
      extensions: [],
    ),
  ])
  |> result.map(fn(value) { #("proxy-status", value) })
  |> result.replace_error(InvalidProxySetup)
}

fn initial_proxy_setup_snapshot() -> ProxySetupSnapshot {
  ProxySetupSnapshot(
    events: [],
    dns_required: False,
    dns_completed: False,
    resolved_addresses: 0,
    authorized_addresses: 0,
    socket_attempted: False,
    adapter_failures: 0,
    adapter_timeouts: 0,
    timing: ProxySetupTimingSnapshot(
      dns_milliseconds: 0,
      socket_open_milliseconds: 0,
      socket_adoption_milliseconds: 0,
      socket_cleanup_milliseconds: 0,
      dns_timed_out: False,
      socket_open_timed_out: False,
      socket_adoption_timed_out: False,
      socket_cleanup_timed_out: False,
      dns_adapter: empty_adapter_execution_timing_snapshot(),
      socket_open_adapter: empty_adapter_execution_timing_snapshot(),
    ),
  )
}

fn empty_adapter_execution_timing_snapshot() -> AdapterExecutionTimingSnapshot {
  AdapterExecutionTimingSnapshot(
    callback_started: False,
    queue_milliseconds: 0,
    callback_milliseconds: 0,
    supervisor_timed_out: False,
  )
}

fn setup_elapsed_milliseconds(started: Int) -> Int {
  let elapsed = monotonic_millisecond() - started
  case elapsed < 0, elapsed > maximum_integer {
    True, _ -> 0
    _, True -> maximum_integer
    False, False -> elapsed
  }
}

fn append_proxy_setup_event(
  snapshot: ProxySetupSnapshot,
  event: ProxySetupEvent,
) -> ProxySetupSnapshot {
  ProxySetupSnapshot(..snapshot, events: list.append(snapshot.events, [event]))
}

fn literal_target_address(host: String) -> Result(IpAddress, Nil) {
  case http3_address.parse(host) {
    Error(_) -> Error(Nil)
    Ok(address) -> {
      let bytes = http3_address.to_bytes(address)
      case bit_array.byte_size(bytes) {
        4 -> Ok(Ipv4(bytes))
        16 -> Ok(Ipv6(bytes))
        _ -> Error(Nil)
      }
    }
  }
}

fn validate_dns_addresses(
  addresses: List(IpAddress),
  maximum: Int,
) -> Result(List(IpAddress), Nil) {
  validate_dns_address_list(addresses, maximum, 0, [])
}

fn validate_dns_address_list(
  addresses: List(IpAddress),
  maximum: Int,
  observed: Int,
  reversed: List(IpAddress),
) -> Result(List(IpAddress), Nil) {
  case addresses {
    [] ->
      case reversed {
        [] -> Error(Nil)
        _ -> Ok(list.reverse(reversed))
      }
    [address, ..rest] -> {
      use <- bool.guard(
        when: observed >= maximum || result.is_error(address_number(address)),
        return: Error(Nil),
      )
      let reversed = case list.contains(reversed, address) {
        True -> reversed
        False -> [address, ..reversed]
      }
      validate_dns_address_list(rest, maximum, observed + 1, reversed)
    }
  }
}

fn bounded_list_count(values: List(value), maximum: Int) -> Int {
  bounded_list_count_loop(values, maximum, 0)
}

fn bounded_list_count_loop(
  values: List(value),
  maximum: Int,
  count: Int,
) -> Int {
  case values {
    [] -> count
    [_, ..rest] if count < maximum ->
      bounded_list_count_loop(rest, maximum, count + 1)
    _ -> maximum + 1
  }
}

fn valid_setup_timeout(milliseconds: Int) -> Bool {
  milliseconds > 0 && milliseconds <= 2_147_483_647
}

/// Begin a tunnel in pre-response state.
pub fn client_tunnel(request: PreparedRequest) -> ClientTunnel {
  ClientTunnel(request, False)
}

/// Confirm a successful response before allowing any proxied payload.
pub fn confirm(
  tunnel: ClientTunnel,
  status: Int,
  headers: List(#(String, String)),
) -> Result(ClientTunnel, Error) {
  let request = tunnel.request
  let successful = case request.protocol {
    Http1 -> status == 101
    Http2 | Http3 -> status >= 200 && status <= 299
  }
  use <- bool.guard(when: !successful, return: Error(UnexpectedStatus(status)))
  use <- bool.guard(
    when: has_header(headers, "content-length")
      || has_header(headers, "content-type")
      || has_header(headers, "transfer-encoding"),
    return: Error(InvalidResponse),
  )
  use <- bool.guard(
    when: !capsule_protocol_enabled(headers),
    return: Error(InvalidResponse),
  )
  use <- bool.guard(
    when: case request.protocol {
      Http1 ->
        !headers_contain_token(headers, "connection", "upgrade")
        || !single_token_header(headers, "upgrade", kind_protocol(request.kind))
      Http2 | Http3 ->
        has_header(headers, "connection") || has_header(headers, "upgrade")
    },
    return: Error(InvalidResponse),
  )
  Ok(ClientTunnel(..tunnel, established: True))
}

/// Encode one active tunnel payload with Context ID zero.
pub fn send_datagram(
  tunnel: ClientTunnel,
  payload: BitArray,
) -> Result(BitArray, Error) {
  use <- bool.guard(when: !tunnel.established, return: Error(NotEstablished))
  case tunnel.request.kind {
    Udp(_) -> encode_udp_datagram(payload, tunnel.request.limits)
    Ip(_) -> encode_ip_datagram(payload, tunnel.request.limits)
  }
}

/// Encode an RFC 9298 Context ID zero UDP payload.
pub fn encode_udp_datagram(
  payload: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_byte_aligned(payload))
  let maximum = udp_payload_limit(limits)
  use <- bool.guard(
    when: bit_array.byte_size(payload) > maximum,
    return: Error(DatagramLimitExceeded(maximum)),
  )
  Ok(<<0, payload:bits>>)
}

/// Decode only the registered Context ID zero UDP payload.
pub fn decode_udp_datagram(
  datagram: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_byte_aligned(datagram))
  use <- bool.guard(
    when: bit_array.byte_size(datagram) > limits.maximum_datagram_bytes,
    return: Error(DatagramLimitExceeded(limits.maximum_datagram_bytes)),
  )
  use #(context, payload) <- result.try(
    decode_integer(datagram) |> result.replace_error(InvalidCapsule),
  )
  use <- bool.guard(when: context != 0, return: Error(UnknownContext(context)))
  let maximum = udp_payload_limit(limits)
  use <- bool.guard(
    when: bit_array.byte_size(payload) > maximum,
    return: Error(DatagramLimitExceeded(maximum)),
  )
  Ok(payload)
}

/// Create a finite receiver before its associated request is available.
/// Datagrams received in this state are dropped without parsing or buffering.
pub fn udp_receiver(limits: Limits) -> Result(UdpReceiver, Error) {
  use _ <- result.try(validate_limits(limits))
  Ok(UdpReceiver(limits, False, 0, 0, 0, 0, 0))
}

/// Mark the corresponding request ready. Context ID zero is then registered.
pub fn activate_udp_receiver(receiver: UdpReceiver) -> UdpReceiver {
  UdpReceiver(..receiver, active: True)
}

/// Decide whether a DATAGRAM Capsule's Context ID prefix may be inspected.
///
/// A pre-request receiver discards from framing metadata alone, so no Context
/// ID or payload bytes need to be read or retained. Active receivers admit at
/// most the Context ID prefix; payload admission is a separate decision.
pub fn admit_proxy_datagram_capsule(
  receiver: UdpReceiver,
  declared_value_bytes: Int,
) -> Result(DatagramCapsuleAdmission, Error) {
  use <- bool.guard(
    when: declared_value_bytes < 0 || declared_value_bytes > maximum_integer,
    return: Error(InvalidCapsule),
  )
  case receiver.active {
    False ->
      Ok(DiscardDatagramCapsule(
        receiver_with_pre_request_drop(receiver),
        RequestNotReady,
      ))
    True -> Ok(InspectDatagramCapsuleContext(receiver, declared_value_bytes))
  }
}

/// Classify a DATAGRAM Capsule after decoding only its Context ID prefix.
///
/// Unknown contexts are discarded regardless of declared payload size.
/// Context ID zero above the absolute UDP limit requires stream abort. A value
/// above a configured transport or Capsule ceiling is discarded before its
/// payload is read. No branch stores payload, target, or request metadata.
pub fn classify_proxy_datagram_capsule_context(
  receiver: UdpReceiver,
  declared_value_bytes declared_value_bytes: Int,
  context context: Int,
  encoded_context_bytes encoded_context_bytes: Int,
) -> Result(DatagramCapsuleAdmission, Error) {
  use <- bool.guard(
    when: !valid_capsule_context_metadata(
      declared_value_bytes,
      context,
      encoded_context_bytes,
    ),
    return: Error(InvalidCapsule),
  )
  case receiver.active, context {
    False, _ ->
      Ok(DiscardDatagramCapsule(
        receiver_with_pre_request_drop(receiver),
        RequestNotReady,
      ))
    True, context if context != 0 ->
      Ok(DiscardDatagramCapsule(
        receiver_with_unknown_context_drop(receiver),
        ContextNotRegistered(context),
      ))
    True, _ -> {
      let payload_bytes = declared_value_bytes - encoded_context_bytes
      case payload_bytes > maximum_udp_payload_bytes {
        True ->
          Ok(AbortDatagramCapsuleStream(
            receiver_with_required_abort(receiver),
            DatagramLimitExceeded(maximum_udp_payload_bytes),
          ))
        False -> {
          let maximum_value_bytes =
            int.min(
              receiver.limits.maximum_capsule_bytes,
              receiver.limits.maximum_datagram_bytes,
            )
          case declared_value_bytes > maximum_value_bytes {
            True ->
              Ok(DiscardDatagramCapsule(
                receiver_with_discarded_capsule(receiver),
                CapsuleValueTooLarge(maximum_value_bytes),
              ))
            False -> Ok(ReadDatagramCapsulePayload(receiver, payload_bytes))
          }
        }
      }
    }
  }
}

/// Apply the no-buffer RFC 9298 receive policy to one HTTP Datagram.
///
/// Pre-request and unknown-context datagrams are dropped. A malformed or
/// oversized Context ID zero datagram produces an explicit stream-abort action.
pub fn receive_proxy_datagram(
  receiver: UdpReceiver,
  datagram: BitArray,
) -> DatagramReceive {
  case receiver.active {
    False ->
      DropDatagram(
        UdpReceiver(
          ..receiver,
          dropped_before_request: bounded_increment(
            receiver.dropped_before_request,
          ),
        ),
        RequestNotReady,
      )
    True -> receive_active_proxy_datagram(receiver, datagram)
  }
}

/// Inspect saturating receiver counters without exposing buffered input.
pub fn udp_receiver_snapshot(receiver: UdpReceiver) -> UdpReceiverSnapshot {
  UdpReceiverSnapshot(
    active: receiver.active,
    accepted: receiver.accepted,
    dropped_before_request: receiver.dropped_before_request,
    dropped_unknown_context: receiver.dropped_unknown_context,
    discarded_capsules: receiver.discarded_capsules,
    aborts_required: receiver.aborts_required,
  )
}

fn receive_active_proxy_datagram(
  receiver: UdpReceiver,
  datagram: BitArray,
) -> DatagramReceive {
  case require_byte_aligned(datagram) {
    Error(error) -> abort_proxy_request(receiver, error)
    Ok(_) ->
      case decode_integer(datagram) {
        Error(Nil) -> abort_proxy_request(receiver, InvalidCapsule)
        Ok(#(context, _)) if context != 0 ->
          DropDatagram(
            UdpReceiver(
              ..receiver,
              dropped_unknown_context: bounded_increment(
                receiver.dropped_unknown_context,
              ),
            ),
            ContextNotRegistered(context),
          )
        Ok(#(_, payload)) -> {
          let maximum = udp_payload_limit(receiver.limits)
          case bit_array.byte_size(payload) > maximum {
            True ->
              abort_proxy_request(receiver, DatagramLimitExceeded(maximum))
            False ->
              ForwardPayload(
                UdpReceiver(
                  ..receiver,
                  accepted: bounded_increment(receiver.accepted),
                ),
                payload,
              )
          }
        }
      }
  }
}

fn abort_proxy_request(receiver: UdpReceiver, error: Error) -> DatagramReceive {
  AbortRequestStream(receiver_with_required_abort(receiver), error)
}

fn receiver_with_pre_request_drop(receiver: UdpReceiver) -> UdpReceiver {
  UdpReceiver(
    ..receiver,
    dropped_before_request: bounded_increment(receiver.dropped_before_request),
  )
}

fn receiver_with_unknown_context_drop(receiver: UdpReceiver) -> UdpReceiver {
  UdpReceiver(
    ..receiver,
    dropped_unknown_context: bounded_increment(receiver.dropped_unknown_context),
  )
}

fn receiver_with_discarded_capsule(receiver: UdpReceiver) -> UdpReceiver {
  UdpReceiver(
    ..receiver,
    discarded_capsules: bounded_increment(receiver.discarded_capsules),
  )
}

fn receiver_with_required_abort(receiver: UdpReceiver) -> UdpReceiver {
  UdpReceiver(
    ..receiver,
    aborts_required: bounded_increment(receiver.aborts_required),
  )
}

fn valid_capsule_context_metadata(
  declared_value_bytes: Int,
  context: Int,
  encoded_context_bytes: Int,
) -> Bool {
  declared_value_bytes >= encoded_context_bytes
  && declared_value_bytes <= maximum_integer
  && context >= 0
  && case encoded_context_bytes {
    1 -> context <= 63
    2 -> context <= 16_383
    4 -> context <= 1_073_741_823
    8 -> context <= maximum_integer
    _ -> False
  }
}

fn bounded_increment(value: Int) -> Int {
  case value < maximum_integer {
    True -> value + 1
    False -> maximum_integer
  }
}

fn bounded_add(value: Int, additional: Int) -> Int {
  case additional >= maximum_integer - value {
    True -> maximum_integer
    False -> value + additional
  }
}

/// Encode one structurally valid IP packet with Context ID zero.
pub fn encode_ip_datagram(
  packet: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_byte_aligned(packet))
  use <- bool.guard(
    when: bit_array.byte_size(packet) + 1 > limits.maximum_datagram_bytes,
    return: Error(DatagramLimitExceeded(limits.maximum_datagram_bytes)),
  )
  use _ <- result.try(parse_ip_packet(packet))
  Ok(<<0, packet:bits>>)
}

/// Decode a Context ID zero IP packet and validate its complete wire length.
pub fn decode_ip_datagram(
  datagram: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_byte_aligned(datagram))
  use <- bool.guard(
    when: bit_array.byte_size(datagram) > limits.maximum_datagram_bytes,
    return: Error(DatagramLimitExceeded(limits.maximum_datagram_bytes)),
  )
  use #(context, packet) <- result.try(
    decode_integer(datagram) |> result.replace_error(InvalidCapsule),
  )
  use <- bool.guard(when: context != 0, return: Error(UnknownContext(context)))
  use _ <- result.try(parse_ip_packet(packet))
  Ok(packet)
}

/// Create an empty finite proxy allowlist.
pub fn deny_all(limits: Limits) -> Result(ProxyPolicy, Error) {
  use _ <- result.try(validate_limits(limits))
  Ok(ProxyPolicy(limits, [], [], [], []))
}

/// Add one exact UDP target without wildcard or DNS suffix matching.
pub fn allow_udp(
  policy: ProxyPolicy,
  target: UdpTarget,
) -> Result(ProxyPolicy, Error) {
  use _ <- result.try(validate_udp_target(target))
  case list.contains(policy.udp_targets, target) {
    True -> Ok(policy)
    False -> {
      use _ <- result.try(require_policy_capacity(policy, 1))
      Ok(ProxyPolicy(..policy, udp_targets: [target, ..policy.udp_targets]))
    }
  }
}

/// Add one IP prefix that DNS or literal CONNECT-UDP targets may resolve to.
///
/// Exact target authorization and resolved-address authorization are both
/// mandatory, preventing an allowlisted DNS name from rebinding into an
/// unapproved local, link-local, multicast, or private destination.
pub fn allow_udp_destination(
  policy: ProxyPolicy,
  prefix: IpPrefix,
) -> Result(ProxyPolicy, Error) {
  use _ <- result.try(validate_prefix(prefix))
  case list.contains(policy.udp_destinations, prefix) {
    True -> Ok(policy)
    False -> {
      use _ <- result.try(require_policy_capacity(policy, 1))
      Ok(
        ProxyPolicy(..policy, udp_destinations: [
          prefix,
          ..policy.udp_destinations
        ]),
      )
    }
  }
}

/// Add one exact CONNECT-IP request scope.
pub fn allow_ip_scope(
  policy: ProxyPolicy,
  scope: IpScope,
) -> Result(ProxyPolicy, Error) {
  use _ <- result.try(validate_scope(scope))
  case list.contains(policy.ip_scopes, scope) {
    True -> Ok(policy)
    False -> {
      use _ <- result.try(require_policy_capacity(policy, 1))
      Ok(ProxyPolicy(..policy, ip_scopes: [scope, ..policy.ip_scopes]))
    }
  }
}

/// Add one destination prefix and optional outer IP protocol.
pub fn allow_ip_destination(
  policy: ProxyPolicy,
  prefix: IpPrefix,
  protocol: Option(Int),
) -> Result(ProxyPolicy, Error) {
  use _ <- result.try(validate_prefix(prefix))
  use _ <- result.try(validate_optional_protocol(protocol))
  let rule = DestinationRule(prefix, protocol)
  case list.contains(policy.destinations, rule) {
    True -> Ok(policy)
    False -> {
      use _ <- result.try(require_policy_capacity(policy, 1))
      Ok(ProxyPolicy(..policy, destinations: [rule, ..policy.destinations]))
    }
  }
}

/// Authorize a prepared request. Empty policies always deny.
pub fn authorize(
  policy: ProxyPolicy,
  request: PreparedRequest,
) -> Result(Nil, Error) {
  let allowed = case request.kind {
    Udp(target) -> list.contains(policy.udp_targets, target)
    Ip(scope) -> list.contains(policy.ip_scopes, scope)
  }
  case allowed {
    True -> Ok(Nil)
    False -> Error(DestinationForbidden)
  }
}

/// Validate, authorize, decrement TTL/Hop Limit, and return an IP packet.
///
/// IPv4 header checksums are verified and recomputed. An exhausted hop limit
/// is never forwarded.
pub fn forward_ip_packet(
  policy: ProxyPolicy,
  packet: BitArray,
  limits: Limits,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_limits(limits))
  use _ <- result.try(require_byte_aligned(packet))
  use <- bool.guard(
    when: bit_array.byte_size(packet) + 1 > limits.maximum_datagram_bytes,
    return: Error(DatagramLimitExceeded(limits.maximum_datagram_bytes)),
  )
  use parsed <- result.try(parse_ip_packet(packet))
  let #(destination, protocol, hop_limit) = packet_routing(parsed)
  use <- bool.guard(
    when: !destination_allowed(policy.destinations, destination, protocol),
    return: Error(DestinationForbidden),
  )
  use <- bool.guard(when: hop_limit <= 1, return: Error(HopLimitExceeded))
  Ok(decrement_hop_limit(parsed))
}

/// Encode a permanent UDP/IP Capsule into the shared HTTP/3 Capsule type.
pub fn encode_capsule(
  capsule: Capsule,
  limits: Limits,
) -> Result(http3_capsule.Capsule, Error) {
  use _ <- result.try(validate_limits(limits))
  case capsule {
    DatagramCapsule(payload) ->
      finalize_capsule(http3_capsule.Datagram(payload), payload, limits)
    AddressAssign(entries) -> {
      use _ <- result.try(validate_assigned(entries, limits))
      use payload <- result.try(encode_assigned(entries, <<>>))
      finalize_capsule(http3_capsule.Extension(1, payload), payload, limits)
    }
    AddressRequest(entries) -> {
      use _ <- result.try(validate_requested(entries, limits))
      use payload <- result.try(encode_requested(entries, <<>>))
      finalize_capsule(http3_capsule.Extension(2, payload), payload, limits)
    }
    RouteAdvertisement(routes) -> {
      use _ <- result.try(validate_routes(routes, limits))
      use payload <- result.try(encode_routes(routes, <<>>))
      finalize_capsule(http3_capsule.Extension(3, payload), payload, limits)
    }
    PermanentExtension(0x243f, payload) ->
      finalize_capsule(
        http3_capsule.Extension(0x243f, payload),
        payload,
        limits,
      )
    PermanentExtension(_, _) -> Error(InvalidCapsule)
  }
}

/// Decode supported permanent Capsules. Unknown and provisional types are
/// returned as `None`, matching RFC 9297's silent-drop rule.
pub fn decode_capsule(
  capsule: http3_capsule.Capsule,
  limits: Limits,
) -> Result(Option(Capsule), Error) {
  use _ <- result.try(validate_limits(limits))
  let payload = case capsule {
    http3_capsule.Datagram(value) | http3_capsule.Extension(_, value) -> value
  }
  use _ <- result.try(require_byte_aligned(payload))
  use <- bool.guard(
    when: bit_array.byte_size(payload) > limits.maximum_capsule_bytes,
    return: Error(CapsuleLimitExceeded(limits.maximum_capsule_bytes)),
  )
  case capsule {
    http3_capsule.Datagram(payload) -> Ok(Some(DatagramCapsule(payload)))
    http3_capsule.Extension(1, payload) -> {
      use entries <- result.try(decode_assigned(payload, limits, []))
      Ok(Some(AddressAssign(entries)))
    }
    http3_capsule.Extension(2, payload) -> {
      use entries <- result.try(decode_requested(payload, limits, []))
      use _ <- result.try(validate_requested(entries, limits))
      Ok(Some(AddressRequest(entries)))
    }
    http3_capsule.Extension(3, payload) -> {
      use routes <- result.try(decode_routes(payload, limits, []))
      use _ <- result.try(validate_routes(routes, limits))
      Ok(Some(RouteAdvertisement(routes)))
    }
    http3_capsule.Extension(0x243f, payload) ->
      Ok(Some(PermanentExtension(0x243f, payload)))
    http3_capsule.Extension(_, _) -> Ok(None)
  }
}

/// Whether a Capsule type is permanently registered at the frozen baseline.
pub fn permanent_capsule_type(capsule_type: Int) -> Bool {
  list.contains([0, 1, 2, 3, 0x243f], capsule_type)
}

/// Create empty finite CONNECT-IP state.
pub fn ip_state(limits: Limits) -> IpState {
  IpState(limits, [], [], [])
}

/// Allocate and encode address requests, rejecting ID reuse for this tunnel.
pub fn request_addresses(
  state: IpState,
  requests: List(RequestedAddress),
) -> Result(#(IpState, http3_capsule.Capsule), Error) {
  use _ <- result.try(validate_limits(state.limits))
  use _ <- result.try(validate_requested(requests, state.limits))
  use _ <- result.try(reject_reused_ids(requests, state.used_request_ids))
  use encoded <- result.try(encode_capsule(
    AddressRequest(requests),
    state.limits,
  ))
  let ids = list.map(requests, fn(entry) { entry.request_id })
  Ok(#(
    IpState(..state, used_request_ids: list.append(ids, state.used_request_ids)),
    encoded,
  ))
}

/// Apply a complete configuration Capsule. Assignments and routes replace the
/// previous full list; unknown types leave state unchanged.
pub fn apply_ip_capsule(
  state: IpState,
  capsule: http3_capsule.Capsule,
) -> Result(IpState, Error) {
  use decoded <- result.try(decode_capsule(capsule, state.limits))
  case decoded {
    Some(AddressAssign(entries)) -> Ok(IpState(..state, assignments: entries))
    Some(RouteAdvertisement(routes)) -> Ok(IpState(..state, routes: routes))
    _ -> Ok(state)
  }
}

/// Return the latest complete assigned-address set.
pub fn assigned_addresses(state: IpState) -> List(AssignedAddress) {
  state.assignments
}

/// Return the latest complete advertised-route set.
pub fn advertised_routes(state: IpState) -> List(IpRoute) {
  state.routes
}

fn validate_http1_udp_metadata(
  incoming: Request(body),
) -> Result(#(String, UdpTarget), ProxyRequestViolation) {
  use _ <- result.try(require_proxy_metadata(
    list.length(incoming.headers) <= maximum_proxy_request_fields,
    RequestMetadataLimitExceeded(maximum_proxy_request_fields),
  ))
  use _ <- result.try(require_proxy_metadata(
    incoming.method == http.Get,
    MethodMustBeGet,
  ))
  use authority <- result.try(case header_values(incoming.headers, "host") {
    [value] ->
      case string.trim(value) {
        "" -> Error(SingleHostRequired)
        authority -> Ok(authority)
      }
    _ -> Error(SingleHostRequired)
  })
  use expected_authority <- result.try(
    incoming_request_authority(incoming)
    |> result.replace_error(ProxyAuthorityInvalid),
  )
  use _ <- result.try(require_proxy_metadata(
    validate_authority(authority) == Ok(Nil),
    ProxyAuthorityInvalid,
  ))
  use _ <- result.try(require_proxy_metadata(
    string.lowercase(authority) == string.lowercase(expected_authority),
    ProxyAuthorityMismatch,
  ))
  use _ <- result.try(require_proxy_metadata(
    headers_contain_token(incoming.headers, "connection", "upgrade"),
    ConnectionUpgradeRequired,
  ))
  use _ <- result.try(require_proxy_metadata(
    single_token_header(incoming.headers, "upgrade", "connect-udp"),
    SingleConnectUdpUpgradeRequired,
  ))
  use _ <- result.try(require_proxy_metadata(
    !has_header(incoming.headers, "content-length")
      && !has_header(incoming.headers, "content-type")
      && !has_header(incoming.headers, "transfer-encoding"),
    MessageContentForbidden,
  ))
  use _ <- result.try(require_proxy_metadata(
    capsule_protocol_enabled(incoming.headers),
    CapsuleProtocolRequired,
  ))
  use target <- result.try(default_udp_target(incoming.path, incoming.query))
  Ok(#(authority, target))
}

fn validate_http3_udp_metadata(
  incoming: http3_server.Request,
) -> Result(#(String, String, UdpTarget), ProxyRequestViolation) {
  let headers = http3_server.headers(incoming)
  use _ <- result.try(require_proxy_metadata(
    list.length(headers) <= maximum_proxy_request_fields,
    RequestMetadataLimitExceeded(maximum_proxy_request_fields),
  ))
  use _ <- result.try(require_proxy_metadata(
    http3_server.method(incoming) == http.Connect,
    MethodMustBeConnect,
  ))
  use _ <- result.try(require_proxy_metadata(
    http3_server.protocol(incoming) == Some("connect-udp"),
    ConnectUdpProtocolRequired,
  ))
  use _ <- result.try(require_proxy_metadata(
    http3_server.scheme(incoming) == "https",
    HttpsSchemeRequired,
  ))
  let authority = http3_server.authority(incoming)
  use _ <- result.try(require_proxy_metadata(
    validate_authority(authority) == Ok(Nil),
    ProxyAuthorityInvalid,
  ))
  use _ <- result.try(require_proxy_metadata(
    !has_header(headers, "content-length")
      && !has_header(headers, "content-type")
      && !has_header(headers, "transfer-encoding"),
    MessageContentForbidden,
  ))
  use _ <- result.try(require_proxy_metadata(
    capsule_protocol_enabled(headers),
    CapsuleProtocolRequired,
  ))
  let #(path, query) = split_request_target(http3_server.path(incoming))
  use target <- result.try(default_udp_target(path, query))
  Ok(#(authority, path, target))
}

fn split_request_target(target: String) -> #(String, Option(String)) {
  case string.split_once(target, on: "?") {
    Ok(#(path, query)) -> #(path, Some(query))
    Error(Nil) -> #(target, None)
  }
}

fn incoming_request_authority(incoming: Request(body)) -> Result(String, Nil) {
  use <- bool.guard(when: !safe_ascii(incoming.host, 1024), return: Error(Nil))
  let host = case string.contains(incoming.host, ":") {
    True -> "[" <> incoming.host <> "]"
    False -> incoming.host
  }
  case incoming.port {
    None -> Ok(host)
    Some(port) if port > 0 && port <= 65_535 ->
      Ok(host <> ":" <> int.to_string(port))
    Some(_) -> Error(Nil)
  }
}

fn default_udp_target(
  path: String,
  query: Option(String),
) -> Result(UdpTarget, ProxyRequestViolation) {
  use _ <- result.try(require_proxy_metadata(
    string.byte_size(path) <= maximum_default_udp_path_bytes && query == None,
    DefaultUdpTargetInvalid,
  ))
  use #(encoded_host, encoded_port) <- result.try(
    case string.split(path, on: "/") {
      ["", ".well-known", "masque", "udp", host, port, ""] -> Ok(#(host, port))
      _ -> Error(DefaultUdpTargetInvalid)
    },
  )
  use _ <- result.try(require_proxy_metadata(
    encoded_host != ""
      && !string.contains(encoded_host, ":")
      && decimal_port(encoded_port),
    DefaultUdpTargetInvalid,
  ))
  use host <- result.try(
    uri.percent_decode(encoded_host)
    |> result.replace_error(DefaultUdpTargetInvalid),
  )
  use port <- result.try(
    int.parse(encoded_port)
    |> result.replace_error(DefaultUdpTargetInvalid),
  )
  let target = UdpTarget(host, port)
  use _ <- result.try(
    validate_udp_target(target)
    |> result.replace_error(DefaultUdpTargetInvalid),
  )
  Ok(target)
}

fn decimal_port(value: String) -> Bool {
  let characters = string.to_utf_codepoints(value)
  characters != []
  && list.all(characters, fn(character) {
    character |> string.utf_codepoint_to_int |> is_ascii_digit
  })
}

fn require_proxy_metadata(
  accepted: Bool,
  violation: ProxyRequestViolation,
) -> Result(Nil, ProxyRequestViolation) {
  case accepted {
    True -> Ok(Nil)
    False -> Error(violation)
  }
}

fn kind_protocol(kind: RequestKind) -> String {
  case kind {
    Udp(_) -> "connect-udp"
    Ip(_) -> "connect-ip"
  }
}

fn validate_limits(limits: Limits) -> Result(Nil, Error) {
  case
    limits.maximum_datagram_bytes > 0
    && limits.maximum_datagram_bytes <= 1_048_576
    && limits.maximum_capsule_bytes >= 0
    && limits.maximum_capsule_bytes <= 1_048_576
    && limits.maximum_address_entries > 0
    && limits.maximum_address_entries <= 65_536
    && limits.maximum_route_entries > 0
    && limits.maximum_route_entries <= 65_536
    && limits.maximum_policy_rules > 0
    && limits.maximum_policy_rules <= 65_536
  {
    True -> Ok(Nil)
    False -> Error(InvalidLimits)
  }
}

fn validate_authority(authority: String) -> Result(Nil, Error) {
  case
    safe_ascii(authority, 1024)
    && !string.contains(authority, "/")
    && !string.contains(authority, "?")
    && !string.contains(authority, "#")
    && !string.contains(authority, "@")
    && !string.contains(authority, " ")
  {
    True -> Ok(Nil)
    False -> Error(InvalidAuthority)
  }
}

fn validate_udp_target(target: UdpTarget) -> Result(Nil, Error) {
  case
    target.port > 0 && target.port <= 65_535 && valid_target_host(target.host)
  {
    True -> Ok(Nil)
    False -> Error(InvalidTarget)
  }
}

fn valid_target_host(host: String) -> Bool {
  use <- bool.guard(when: !safe_ascii(host, 1024), return: False)
  use <- bool.guard(when: string.contains(host, "%"), return: False)
  case string.contains(host, ":") {
    True -> valid_ipv6_address(host)
    False ->
      host |> string.to_utf_codepoints |> list.all(valid_reg_name_character)
  }
}

fn valid_reg_name_character(character: UtfCodepoint) -> Bool {
  let value = string.utf_codepoint_to_int(character)
  is_ascii_alpha(value)
  || is_ascii_digit(value)
  || list.contains(
    [
      0x2d,
      0x2e,
      0x5f,
      0x7e,
      0x21,
      0x24,
      0x26,
      0x27,
      0x28,
      0x29,
      0x2a,
      0x2b,
      0x2c,
      0x3b,
      0x3d,
    ],
    value,
  )
}

fn valid_ipv6_address(address: String) -> Bool {
  case string.split(address, on: "::") {
    [uncompressed] -> count_ipv6_units(uncompressed, True) == Ok(8)
    [left, right] ->
      case count_ipv6_units(left, right == ""), count_ipv6_units(right, True) {
        Ok(left_units), Ok(right_units) -> left_units + right_units < 8
        _, _ -> False
      }
    _ -> False
  }
}

fn count_ipv6_units(value: String, allow_ipv4: Bool) -> Result(Int, Nil) {
  case value {
    "" -> Ok(0)
    _ -> count_ipv6_segments(string.split(value, on: ":"), allow_ipv4, 0)
  }
}

fn count_ipv6_segments(
  segments: List(String),
  allow_ipv4: Bool,
  count: Int,
) -> Result(Int, Nil) {
  case segments {
    [] -> Ok(count)
    [segment] ->
      case string.contains(segment, ".") {
        True ->
          case allow_ipv4 && valid_ipv4_address(segment) {
            True -> Ok(count + 2)
            False -> Error(Nil)
          }
        False ->
          case valid_h16(segment) {
            True -> Ok(count + 1)
            False -> Error(Nil)
          }
      }
    [segment, ..rest] ->
      case valid_h16(segment) {
        True -> count_ipv6_segments(rest, allow_ipv4, count + 1)
        False -> Error(Nil)
      }
  }
}

fn valid_h16(segment: String) -> Bool {
  let size = string.byte_size(segment)
  size >= 1
  && size <= 4
  && { segment |> string.to_utf_codepoints |> list.all(is_ascii_hex_character) }
}

fn valid_ipv4_address(address: String) -> Bool {
  case string.split(address, on: ".") {
    [first, second, third, fourth] ->
      list.all([first, second, third, fourth], valid_ipv4_octet)
    _ -> False
  }
}

fn valid_ipv4_octet(octet: String) -> Bool {
  let characters = string.to_utf_codepoints(octet)
  use <- bool.guard(
    when: characters == [] || list.length(characters) > 3,
    return: False,
  )
  use <- bool.guard(
    when: !list.all(characters, fn(character) {
      character |> string.utf_codepoint_to_int |> is_ascii_digit
    }),
    return: False,
  )
  case int.parse(octet) {
    Ok(value) -> value <= 255 && int.to_string(value) == octet
    Error(Nil) -> False
  }
}

fn is_ascii_hex_character(character: UtfCodepoint) -> Bool {
  let value = string.utf_codepoint_to_int(character)
  is_ascii_digit(value)
  || { value >= 0x41 && value <= 0x46 }
  || { value >= 0x61 && value <= 0x66 }
}

fn is_ascii_alpha(value: Int) -> Bool {
  { value >= 0x41 && value <= 0x5a } || { value >= 0x61 && value <= 0x7a }
}

fn is_ascii_digit(value: Int) -> Bool {
  value >= 0x30 && value <= 0x39
}

fn validate_scope(scope: IpScope) -> Result(Nil, Error) {
  let valid_target = case scope.target {
    None -> True
    Some(value) ->
      value != "*"
      && safe_ascii(value, 1024)
      && !string.contains(value, "%")
      && !string.contains(value, "?")
      && !string.contains(value, "#")
      && !string.contains(value, " ")
  }
  case valid_target && valid_optional_protocol(scope.ip_protocol) {
    True -> Ok(Nil)
    False -> Error(InvalidScope)
  }
}

fn validate_optional_protocol(protocol: Option(Int)) -> Result(Nil, Error) {
  case valid_optional_protocol(protocol) {
    True -> Ok(Nil)
    False -> Error(InvalidScope)
  }
}

fn valid_optional_protocol(protocol: Option(Int)) -> Bool {
  case protocol {
    None -> True
    Some(value) -> value >= 0 && value <= 255
  }
}

fn safe_ascii(value: String, maximum_bytes: Int) -> Bool {
  !string.is_empty(value)
  && string.byte_size(value) <= maximum_bytes
  && list.all(string.to_utf_codepoints(value), fn(character) {
    let value = string.utf_codepoint_to_int(character)
    value >= 0x21 && value <= 0x7e
  })
}

fn udp_payload_limit(limits: Limits) -> Int {
  let configured = limits.maximum_datagram_bytes - 1
  case configured < maximum_udp_payload_bytes {
    True -> configured
    False -> maximum_udp_payload_bytes
  }
}

fn require_byte_aligned(value: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(value) % 8 == 0 {
    True -> Ok(Nil)
    False -> Error(NonByteAligned)
  }
}

fn policy_rule_count(policy: ProxyPolicy) -> Int {
  list.length(policy.udp_targets)
  + list.length(policy.udp_destinations)
  + list.length(policy.ip_scopes)
  + list.length(policy.destinations)
}

fn require_policy_capacity(
  policy: ProxyPolicy,
  additional: Int,
) -> Result(Nil, Error) {
  case
    policy_rule_count(policy) + additional > policy.limits.maximum_policy_rules
  {
    True -> Error(PolicyLimitExceeded(policy.limits.maximum_policy_rules))
    False -> Ok(Nil)
  }
}

fn destination_allowed(
  rules: List(DestinationRule),
  destination: IpAddress,
  protocol: Int,
) -> Bool {
  list.any(rules, fn(rule) {
    prefix_contains(rule.prefix, destination)
    && case rule.protocol {
      None -> True
      Some(expected) -> expected == protocol
    }
  })
}

fn prefix_contains(prefix: IpPrefix, address: IpAddress) -> Bool {
  let IpPrefix(network, length) = prefix
  case address_number(network), address_number(address) {
    Ok(#(network_version, network_value, bits)),
      Ok(#(address_version, address_value, _))
      if network_version == address_version
    -> {
      let host_bits = bits - length
      int.bitwise_shift_right(network_value, host_bits)
      == int.bitwise_shift_right(address_value, host_bits)
    }
    _, _ -> False
  }
}

fn validate_prefix(prefix: IpPrefix) -> Result(Nil, Error) {
  let IpPrefix(address, length) = prefix
  case address_number(address) {
    Error(_) -> Error(InvalidAddress)
    Ok(#(_, value, bits)) ->
      case length >= 0 && length <= bits {
        False -> Error(InvalidAddress)
        True -> {
          let host_bits = bits - length
          let host_mask = case host_bits {
            0 -> 0
            value -> int.bitwise_shift_left(1, value) - 1
          }
          case int.bitwise_and(value, host_mask) == 0 {
            True -> Ok(Nil)
            False -> Error(InvalidAddress)
          }
        }
      }
  }
}

fn address_number(address: IpAddress) -> Result(#(Int, Int, Int), Nil) {
  case address {
    Ipv4(<<value:size(32)>>) -> Ok(#(4, value, 32))
    Ipv6(<<value:size(128)>>) -> Ok(#(6, value, 128))
    _ -> Error(Nil)
  }
}

fn parse_ip_packet(packet: BitArray) -> Result(ParsedPacket, Error) {
  case packet {
    <<4:4, header_words:4, _rest:bits>> -> parse_ipv4(packet, header_words * 32)
    <<
      6:4,
      traffic_class:8,
      flow_label:20,
      payload_length:size(16),
      next_header,
      hop_limit,
      source:bytes-size(16),
      destination:bytes-size(16),
      payload:bits,
    >> -> {
      use <- bool.guard(
        when: bit_array.byte_size(payload) != payload_length,
        return: Error(InvalidIpPacket),
      )
      Ok(ParsedIpv6(
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
        payload,
      ))
    }
    _ -> Error(InvalidIpPacket)
  }
}

fn parse_ipv4(
  packet: BitArray,
  header_bits: Int,
) -> Result(ParsedPacket, Error) {
  let header_bytes = header_bits / 8
  use <- bool.guard(
    when: header_bytes < 20 || header_bytes > bit_array.byte_size(packet),
    return: Error(InvalidIpPacket),
  )
  use #(header, payload) <- result.try(
    take(packet, header_bytes) |> result.replace_error(InvalidIpPacket),
  )
  case header {
    <<
      first,
      differentiated_services,
      total_length:size(16),
      identification:size(16),
      flags_and_fragment:size(16),
      hop_limit,
      protocol,
      checksum:size(16),
      source:bytes-size(4),
      destination:bytes-size(4),
      options:bits,
    >> -> {
      let without_checksum = <<
        first,
        differentiated_services,
        total_length:size(16),
        identification:size(16),
        flags_and_fragment:size(16),
        hop_limit,
        protocol,
        0:size(16),
        source:bits,
        destination:bits,
        options:bits,
      >>
      use <- bool.guard(
        when: total_length != bit_array.byte_size(packet)
          || ipv4_checksum(without_checksum) != checksum,
        return: Error(InvalidIpPacket),
      )
      Ok(ParsedIpv4(
        first,
        differentiated_services,
        total_length,
        identification,
        flags_and_fragment,
        hop_limit,
        protocol,
        source,
        destination,
        options,
        payload,
      ))
    }
    _ -> Error(InvalidIpPacket)
  }
}

fn packet_routing(packet: ParsedPacket) -> #(IpAddress, Int, Int) {
  case packet {
    ParsedIpv4(_, _, _, _, _, hop, protocol, _, destination, _, _) -> #(
      Ipv4(destination),
      protocol,
      hop,
    )
    ParsedIpv6(_, _, _, next_header, hop, _, destination, _) -> #(
      Ipv6(destination),
      next_header,
      hop,
    )
  }
}

fn decrement_hop_limit(packet: ParsedPacket) -> BitArray {
  case packet {
    ParsedIpv4(
      first,
      differentiated_services,
      total_length,
      identification,
      flags_and_fragment,
      hop_limit,
      protocol,
      source,
      destination,
      options,
      payload,
    ) -> {
      let new_hop_limit = hop_limit - 1
      let header = <<
        first,
        differentiated_services,
        total_length:size(16),
        identification:size(16),
        flags_and_fragment:size(16),
        new_hop_limit,
        protocol,
        0:size(16),
        source:bits,
        destination:bits,
        options:bits,
      >>
      let checksum = ipv4_checksum(header)
      <<
        first,
        differentiated_services,
        total_length:size(16),
        identification:size(16),
        flags_and_fragment:size(16),
        new_hop_limit,
        protocol,
        checksum:size(16),
        source:bits,
        destination:bits,
        options:bits,
        payload:bits,
      >>
    }
    ParsedIpv6(
      traffic_class,
      flow_label,
      payload_length,
      next_header,
      hop_limit,
      source,
      destination,
      payload,
    ) -> {
      let new_hop_limit = hop_limit - 1
      <<
        6:4,
        traffic_class:8,
        flow_label:20,
        payload_length:size(16),
        next_header,
        new_hop_limit,
        source:bits,
        destination:bits,
        payload:bits,
      >>
    }
  }
}

fn ipv4_checksum(header: BitArray) -> Int {
  header
  |> checksum_words(0)
  |> fold_checksum
  |> int.bitwise_not
  |> int.bitwise_and(0xffff)
}

fn checksum_words(bytes: BitArray, accumulator: Int) -> Int {
  case bytes {
    <<word:size(16), rest:bits>> -> checksum_words(rest, accumulator + word)
    <<last>> -> accumulator + int.bitwise_shift_left(last, 8)
    <<>> -> accumulator
    _ -> accumulator
  }
}

fn fold_checksum(value: Int) -> Int {
  case value > 0xffff {
    True ->
      fold_checksum(
        int.bitwise_and(value, 0xffff) + int.bitwise_shift_right(value, 16),
      )
    False -> value
  }
}

fn finalize_capsule(
  capsule: http3_capsule.Capsule,
  payload: BitArray,
  limits: Limits,
) -> Result(http3_capsule.Capsule, Error) {
  use _ <- result.try(require_byte_aligned(payload))
  case bit_array.byte_size(payload) > limits.maximum_capsule_bytes {
    True -> Error(CapsuleLimitExceeded(limits.maximum_capsule_bytes))
    False -> Ok(capsule)
  }
}

fn validate_assigned(
  entries: List(AssignedAddress),
  limits: Limits,
) -> Result(Nil, Error) {
  use _ <- result.try(require_entry_limit(
    list.length(entries),
    limits.maximum_address_entries,
  ))
  case
    list.all(entries, fn(entry) {
      entry.request_id >= 0
      && entry.request_id <= maximum_integer
      && validate_prefix(entry.prefix) == Ok(Nil)
    })
  {
    True -> Ok(Nil)
    False -> Error(InvalidAddress)
  }
}

fn validate_requested(
  entries: List(RequestedAddress),
  limits: Limits,
) -> Result(Nil, Error) {
  use <- bool.guard(when: entries == [], return: Error(InvalidCapsule))
  use _ <- result.try(require_entry_limit(
    list.length(entries),
    limits.maximum_address_entries,
  ))
  let ids = list.map(entries, fn(entry) { entry.request_id })
  case
    list.unique(ids) == ids
    && list.all(entries, fn(entry) {
      entry.request_id > 0
      && entry.request_id <= maximum_integer
      && validate_prefix(entry.prefix) == Ok(Nil)
    })
  {
    True -> Ok(Nil)
    False -> Error(InvalidAddress)
  }
}

fn validate_routes(
  routes: List(IpRoute),
  limits: Limits,
) -> Result(Nil, Error) {
  use _ <- result.try(require_entry_limit(
    list.length(routes),
    limits.maximum_route_entries,
  ))
  case
    list.all(routes, route_valid)
    && routes_are_ordered(routes)
    && !routes_have_forbidden_overlap(routes)
  {
    True -> Ok(Nil)
    False -> Error(InvalidRoute)
  }
}

fn route_valid(route: IpRoute) -> Bool {
  case address_number(route.start), address_number(route.end) {
    Ok(#(start_version, start, _)), Ok(#(end_version, end, _)) ->
      start_version == end_version
      && start <= end
      && route.ip_protocol >= 0
      && route.ip_protocol <= 255
    _, _ -> False
  }
}

fn routes_are_ordered(routes: List(IpRoute)) -> Bool {
  case routes {
    [] | [_] -> True
    [first, second, ..rest] ->
      route_precedes(first, second) && routes_are_ordered([second, ..rest])
  }
}

fn route_precedes(first: IpRoute, second: IpRoute) -> Bool {
  let assert Ok(#(first_version, _, _)) = address_number(first.start)
  let assert Ok(#(second_version, second_start, _)) =
    address_number(second.start)
  let assert Ok(#(_, first_end, _)) = address_number(first.end)
  first_version < second_version
  || first_version == second_version
  && {
    first.ip_protocol < second.ip_protocol
    || first.ip_protocol == second.ip_protocol
    && first_end < second_start
  }
}

fn routes_have_forbidden_overlap(routes: List(IpRoute)) -> Bool {
  case routes {
    [] -> False
    [route, ..rest] ->
      list.any(rest, fn(other) { forbidden_overlap(route, other) })
      || routes_have_forbidden_overlap(rest)
  }
}

fn forbidden_overlap(first: IpRoute, second: IpRoute) -> Bool {
  let assert Ok(#(first_version, first_start, _)) = address_number(first.start)
  let assert Ok(#(_, first_end, _)) = address_number(first.end)
  let assert Ok(#(second_version, second_start, _)) =
    address_number(second.start)
  let assert Ok(#(_, second_end, _)) = address_number(second.end)
  first_version == second_version
  && {
    first.ip_protocol == second.ip_protocol
    || first.ip_protocol == 0
    || second.ip_protocol == 0
  }
  && first_start <= second_end
  && second_start <= first_end
}

fn require_entry_limit(count: Int, maximum: Int) -> Result(Nil, Error) {
  case count > maximum {
    True -> Error(EntryLimitExceeded(maximum))
    False -> Ok(Nil)
  }
}

fn encode_assigned(
  entries: List(AssignedAddress),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case entries {
    [] -> Ok(accumulator)
    [entry, ..rest] -> {
      use encoded <- result.try(encode_address(entry.request_id, entry.prefix))
      encode_assigned(rest, <<accumulator:bits, encoded:bits>>)
    }
  }
}

fn encode_requested(
  entries: List(RequestedAddress),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case entries {
    [] -> Ok(accumulator)
    [entry, ..rest] -> {
      use encoded <- result.try(encode_address(entry.request_id, entry.prefix))
      encode_requested(rest, <<accumulator:bits, encoded:bits>>)
    }
  }
}

fn encode_address(
  request_id: Int,
  prefix: IpPrefix,
) -> Result(BitArray, Error) {
  use identifier <- result.try(
    encode_integer(request_id) |> result.replace_error(InvalidAddress),
  )
  let IpPrefix(address, prefix_length) = prefix
  let #(version, bytes) = case address {
    Ipv4(bytes) -> #(4, bytes)
    Ipv6(bytes) -> #(6, bytes)
  }
  Ok(<<identifier:bits, version, bytes:bits, prefix_length>>)
}

fn decode_assigned(
  bytes: BitArray,
  limits: Limits,
  reversed: List(AssignedAddress),
) -> Result(List(AssignedAddress), Error) {
  case bytes {
    <<>> -> {
      let entries = list.reverse(reversed)
      use _ <- result.try(validate_assigned(entries, limits))
      Ok(entries)
    }
    _ -> {
      use #(request_id, prefix, rest) <- result.try(decode_address(bytes))
      use _ <- result.try(require_entry_limit(
        list.length(reversed) + 1,
        limits.maximum_address_entries,
      ))
      decode_assigned(rest, limits, [
        AssignedAddress(request_id, prefix),
        ..reversed
      ])
    }
  }
}

fn decode_requested(
  bytes: BitArray,
  limits: Limits,
  reversed: List(RequestedAddress),
) -> Result(List(RequestedAddress), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    _ -> {
      use #(request_id, prefix, rest) <- result.try(decode_address(bytes))
      use _ <- result.try(require_entry_limit(
        list.length(reversed) + 1,
        limits.maximum_address_entries,
      ))
      decode_requested(rest, limits, [
        RequestedAddress(request_id, prefix),
        ..reversed
      ])
    }
  }
}

fn decode_address(
  bytes: BitArray,
) -> Result(#(Int, IpPrefix, BitArray), Error) {
  use #(request_id, rest) <- result.try(
    decode_integer(bytes) |> result.replace_error(InvalidCapsule),
  )
  let decoded = case rest {
    <<4, address:bytes-size(4), prefix_length, remaining:bits>> ->
      Ok(#(request_id, IpPrefix(Ipv4(address), prefix_length), remaining))
    <<6, address:bytes-size(16), prefix_length, remaining:bits>> ->
      Ok(#(request_id, IpPrefix(Ipv6(address), prefix_length), remaining))
    _ -> Error(InvalidAddress)
  }
  use #(request_id, prefix, remaining) <- result.try(decoded)
  use _ <- result.try(validate_prefix(prefix))
  Ok(#(request_id, prefix, remaining))
}

fn encode_routes(
  routes: List(IpRoute),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case routes {
    [] -> Ok(accumulator)
    [route, ..rest] -> {
      let #(version, start, end) = case route.start, route.end {
        Ipv4(start), Ipv4(end) -> #(4, start, end)
        Ipv6(start), Ipv6(end) -> #(6, start, end)
        _, _ -> #(0, <<>>, <<>>)
      }
      use <- bool.guard(when: version == 0, return: Error(InvalidRoute))
      encode_routes(rest, <<
        accumulator:bits,
        version,
        start:bits,
        end:bits,
        route.ip_protocol,
      >>)
    }
  }
}

fn decode_routes(
  bytes: BitArray,
  limits: Limits,
  reversed: List(IpRoute),
) -> Result(List(IpRoute), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<4, start:bytes-size(4), end:bytes-size(4), protocol, rest:bits>> -> {
      use _ <- result.try(require_entry_limit(
        list.length(reversed) + 1,
        limits.maximum_route_entries,
      ))
      decode_routes(rest, limits, [
        IpRoute(Ipv4(start), Ipv4(end), protocol),
        ..reversed
      ])
    }
    <<6, start:bytes-size(16), end:bytes-size(16), protocol, rest:bits>> -> {
      use _ <- result.try(require_entry_limit(
        list.length(reversed) + 1,
        limits.maximum_route_entries,
      ))
      decode_routes(rest, limits, [
        IpRoute(Ipv6(start), Ipv6(end), protocol),
        ..reversed
      ])
    }
    _ -> Error(InvalidRoute)
  }
}

fn reject_reused_ids(
  requests: List(RequestedAddress),
  used: List(Int),
) -> Result(Nil, Error) {
  case requests {
    [] -> Ok(Nil)
    [request, ..rest] ->
      case list.contains(used, request.request_id) {
        True -> Error(RequestIdReused(request.request_id))
        False -> reject_reused_ids(rest, used)
      }
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Nil) {
  case value {
    value if value < 0 || value > maximum_integer -> Error(Nil)
    value if value <= 63 -> Ok(<<0:2, value:6>>)
    value if value <= 16_383 -> Ok(<<1:2, value:14>>)
    value if value <= 1_073_741_823 -> Ok(<<2:2, value:30>>)
    value -> Ok(<<3:2, value:62>>)
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Nil) {
  case bytes {
    <<0:2, value:6, rest:bits>> -> Ok(#(value, rest))
    <<1:2, value:14, rest:bits>> -> Ok(#(value, rest))
    <<2:2, value:30, rest:bits>> -> Ok(#(value, rest))
    <<3:2, value:62, rest:bits>> -> Ok(#(value, rest))
    _ -> Error(Nil)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Nil) {
  let bits = length * 8
  case bytes {
    <<value:bits-size(bits), rest:bits>> -> Ok(#(value, rest))
    _ -> Error(Nil)
  }
}

fn capsule_protocol_enabled(headers: List(#(String, String))) -> Bool {
  case header_values(headers, "capsule-protocol") {
    [value] ->
      case structured_fields.parse_item(value) {
        Ok(structured_fields.Item(structured_fields.Boolean(True), _)) -> True
        _ -> False
      }
    _ -> False
  }
}

fn single_token_header(
  headers: List(#(String, String)),
  name: String,
  expected: String,
) -> Bool {
  case header_values(headers, name) {
    [value] -> string.lowercase(string.trim(value)) == expected
    _ -> False
  }
}

fn headers_contain_token(
  headers: List(#(String, String)),
  name: String,
  expected: String,
) -> Bool {
  headers
  |> header_values(name)
  |> list.flat_map(fn(value) { string.split(value, on: ",") })
  |> list.any(fn(value) { string.lowercase(string.trim(value)) == expected })
}

fn has_header(headers: List(#(String, String)), name: String) -> Bool {
  header_values(headers, name) != []
}

fn header_values(
  headers: List(#(String, String)),
  name: String,
) -> List(String) {
  headers
  |> list.filter(fn(header) {
    let #(header_name, _) = header
    string.lowercase(header_name) == name
  })
  |> list.map(fn(header) {
    let #(_, value) = header
    value
  })
}
