//// Reusable, explicitly owned unified HTTP client.

import gleam/bit_array
import gleam/bool
import gleam/erlang/process
import gleam/http.{
  type Method, type Scheme, Delete, Get, Head, Http, Https, Options, Put, Trace,
}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/body
import http/client_store
import http/context
import http/diagnostics
import http/error
import http/internal/alt_svc
import http/internal/cache
import http/internal/client_trace
import http/internal/cookie
import http/internal/hsts
import http/internal/http1/exchange as http1_exchange
import http/internal/http2/exchange as http2_exchange
import http/internal/http2/wire as http2_wire
import http/internal/http3/client as http3_exchange
import http/internal/process_role
import http/internal/redirect
import http/internal/tcp_reservation
import http/internal/transport
import http/resource
import http3/client as h3_client
import http3/config as h3_config
import http3/failure as h3_failure

const http3_pool_transition_milliseconds = 1000

/// Finite client deadlines.
/// DNS lookup has its own budget and is never an unbounded part of connection establishment.
pub type Timeouts {
  Timeouts(
    dns_milliseconds: Int,
    connect_milliseconds: Int,
    tls_milliseconds: Int,
    operation_milliseconds: Int,
    idle_milliseconds: Int,
    total_milliseconds: Int,
  )
}

/// Per-body and per-endpoint memory policy.
pub type BodyLimits {
  BodyLimits(
    buffered_bytes: Int,
    stream_buffer_bytes: Int,
    endpoint_memory_bytes: Int,
  )
}

/// Finite HTTP connection-pool policy.
pub type PoolLimits {
  PoolLimits(
    maximum_connections: Int,
    maximum_connections_per_origin: Int,
    idle_milliseconds: Int,
  )
}

/// Security switches.
/// Certificate-chain and hostname verification have no switch and therefore cannot be disabled.
pub type Security {
  Security(allow_plain_http: Bool)
}

/// Finite automatic redirect policy.
pub type RedirectPolicy {
  RedirectPolicy(enabled: Bool, maximum: Int)
}

/// Finite automatic retry policy.
///
/// A retry is considered only when the method is idempotent, the Body can be regenerated, and the request is proven unstarted or explicitly rejected as unprocessed by the peer.
/// An unexplained connection loss might have been processed and is never retried.
/// Response-status retries require an explicit status entry and happen before any response body is exposed to the caller.
pub type RetryPolicy {
  RetryPolicy(enabled: Bool, maximum: Int, retry_statuses: List(Int))
}

/// Finite entry and retained-byte limits for one in-memory policy store.
pub type StoreLimits {
  StoreLimits(maximum_entries: Int, maximum_bytes: Int)
}

/// Cookie processing policy.
/// It is disabled by default.
pub type CookiePolicy {
  CookiePolicy(enabled: Bool, limits: StoreLimits)
}

/// Complete-response cache policy.
/// It is disabled by default.
pub type CachePolicy {
  CachePolicy(enabled: Bool, limits: StoreLimits)
}

/// Strict-Transport-Security policy.
/// Learning is enabled by default.
pub type HstsPolicy {
  HstsPolicy(enabled: Bool, limits: StoreLimits)
}

/// Safe protocol-discovery policy.
pub type DiscoveryPolicy {
  DiscoveryPolicy(
    enabled: Bool,
    alt_svc_limits: StoreLimits,
    https_record_timeout_milliseconds: Int,
  )
}

/// One HTTPS resource-record service binding supplied by a typed resolver.
pub type HttpsRecord {
  HttpsRecord(
    alpns: List(String),
    port: Int,
    authenticated: Bool,
    expires_in_milliseconds: Int,
  )
}

/// One explicitly configured HTTP forward proxy.
pub type Proxy {
  Proxy(host: String, port: Int, authorization: Option(String))
}

/// Proxy selection policy.
/// The default has no proxy.
pub type ProxyPolicy {
  ProxyPolicy(proxy: Option(Proxy))
}

/// Partition key applied to every stateful client policy.
pub type NetworkIsolationKey {
  NetworkIsolationKey(top_level_site: String, profile: String)
}

/// The protocol selected for an exchange.
pub type Protocol {
  Http1
  Http2
  Http3
}

/// A redirect origin without path, query, user information, or credentials.
pub type Origin {
  Origin(scheme: Scheme, host: String, port: Int)
}

/// One followed redirect with only non-secret routing metadata.
pub type RedirectHop {
  RedirectHop(status: Int, from: Origin, to: Origin, protocol: Protocol)
}

/// Validated client configuration.
pub opaque type Config {
  Config(
    timeouts: Timeouts,
    body_limits: BodyLimits,
    pool_limits: PoolLimits,
    pooling_enabled: Bool,
    security: Security,
    redirect_policy: RedirectPolicy,
    retry_policy: RetryPolicy,
    cookie_policy: CookiePolicy,
    cache_policy: CachePolicy,
    hsts_policy: HstsPolicy,
    discovery_policy: DiscoveryPolicy,
    https_record_resolver: Option(
      fn(String, Int, Int) -> Result(List(HttpsRecord), Nil),
    ),
    proxy_policy: ProxyPolicy,
    network_isolation_key: NetworkIsolationKey,
    cookie_store_adapter: Option(
      client_store.Adapter(client_store.CookieRecord),
    ),
    cache_store_adapter: Option(client_store.Adapter(client_store.CacheRecord)),
    hsts_store_adapter: Option(client_store.Adapter(client_store.HstsRecord)),
    alt_svc_store_adapter: Option(
      client_store.Adapter(client_store.AltSvcRecord),
    ),
    ca_certificates: List(BitArray),
    diagnostics: Option(diagnostics.Reporter),
    race_join_confirmation: Bool,
    race_claim_offer_confirmation: Bool,
    race_claim_commit_confirmation: Bool,
    http3_release_reuse_probe: Option(fn() -> Result(Bool, Nil)),
    http3_stream_open_refusal_probe: Option(fn() -> Result(Bool, Nil)),
    http3_resource_limit_terminal_probe: Option(fn() -> Bool),
    http3_connect_gate: Option(fn() -> Result(Nil, error.Error)),
    https_race_candidate_gate: Option(
      fn(HttpsRaceCandidate, Int) -> Result(Nil, error.Error),
    ),
    lifecycle_close_join_confirmation: Bool,
  )
}

type Lifecycle

type Http2Pool

type PolicyStore

type Registration

type Http3DialWait

type Http3DialAdmission {
  Http3DialLeader(Registration)
  Http3DialWaiting(Http3DialWait)
  Http3DialPublished
}

type TunnelGuard

type RaceCancellation

/// A payload-free synchronization point after transport authentication and before either HTTPS race candidate can be selected for request delivery.
@internal
pub type HttpsRaceCandidate {
  Http3AuthenticatedCandidate
  TcpAuthenticatedCandidate
}

type TcpRaceGuard {
  TcpRaceGuard(
    commands: process.Subject(TcpRaceCommand),
    cancellation: RaceCancellation,
    pid: process.Pid,
    deadline: Int,
    join_confirmation: Bool,
    commit_confirmation: Bool,
  )
}

type TcpRaceCommand {
  RaceStart(
    http3: fn() -> Nil,
    tcp: fn() -> Nil,
    reply: process.Subject(#(process.Pid, process.Pid)),
  )
  RaceAttach(
    socket: transport.Socket,
    cleanup: fn() -> Nil,
    cleanup_before: fn(Int) -> Bool,
    reply: process.Subject(Result(Int, Nil)),
  )
  RaceRelease(identifier: Int)
  RaceCancel(reply: process.Subject(Bool))
  RaceSelectHttp3(reply: process.Subject(Bool))
  RaceClaim(reply: process.Subject(Result(TcpRaceClaimOffer, Bool)))
  RaceCommit(identifier: Int, reply: process.Subject(Bool))
}

type TcpRaceClaimOffer {
  TcpRaceClaimOffer(identifier: Int, cleanup: fn() -> Nil)
}

type TcpCandidateHandoff {
  TcpCandidateHandoff(
    owner: process.Pid,
    reply: process.Subject(TcpCandidateTransfer),
  )
}

type TcpCandidateTransfer {
  TcpCandidateOffer(
    ready: http2_exchange.Ready,
    acknowledge: process.Subject(Nil),
  )
  TcpCandidateCommit(Result(Nil, error.Error))
}

type TcpRaceCandidate {
  TcpRaceCandidate(
    ready: http2_exchange.Ready,
    handoff: process.Subject(TcpCandidateHandoff),
  )
}

type TcpRaceRuntime {
  TcpRaceRuntime(
    commands: process.Subject(TcpRaceCommand),
    cancellation: RaceCancellation,
    guarded: Option(GuardedSocket),
    next_identifier: Int,
    requester: process.Monitor,
    lifecycle: process.Monitor,
    deadline: Int,
    candidate: Registration,
    helpers: List(process.Pid),
    cleanup_confirmed: Bool,
    join_confirmation: Bool,
    claim_offer_confirmation: Bool,
  )
}

type GuardedSocket {
  GuardedSocket(
    identifier: Int,
    socket: transport.Socket,
    cleanup: fn() -> Nil,
    cleanup_before: fn(Int) -> Bool,
  )
}

type RaceEvent {
  Http3Ready(Result(Http3Candidate, error.Error))
  TcpReady(Result(TcpRaceCandidate, error.Error))
  Http3Exited
  TcpExited
}

type Http3Candidate {
  Http3Candidate(
    connection: http3_exchange.Connection,
    registration: Registration,
    key: String,
  )
}

type Http3Lease

type PooledHttp3 {
  PooledHttp3(
    connection: http3_exchange.Connection,
    lease: Http3Lease,
    key: String,
  )
}

/// A reusable client lifecycle owner.
/// Runtime handles are never public.
pub opaque type Client {
  Client(
    config: Config,
    lifecycle: Lifecycle,
    http2_pool: Http2Pool,
    http3_resources: resource.Controller,
    cookie_store: PolicyStore,
    cache_store: PolicyStore,
    hsts_store: PolicyStore,
    alt_svc_store: PolicyStore,
    trace: Option(client_trace.Trace),
  )
}

/// A streaming response and non-secret exchange metadata.
pub opaque type Exchange {
  Exchange(
    response: Response(body.Body),
    selected_protocol: Protocol,
    redirect_history: List(RedirectHop),
    trace: Option(client_trace.Trace),
  )
}

/// One established HTTP/1.1 CONNECT or Upgrade byte stream.
///
/// Its socket, lifecycle registration, buffered bytes, and close guard remain private.
/// Each successful read returns the next cursor.
pub opaque type Tunnel {
  Tunnel(
    socket: transport.Socket,
    buffered: BitArray,
    cleanup: fn() -> Nil,
    guard: TunnelGuard,
    maximum_read_bytes: Int,
    idle_timeout_milliseconds: Int,
  )
}

/// A successful response and its newly established tunnel.
pub opaque type TunnelHandshake {
  TunnelHandshake(response: Response(body.Body), tunnel: Tunnel)
}

/// One bounded active-once tunnel read.
pub type TunnelRead {
  TunnelData(bytes: BitArray, next: Tunnel)
  TunnelEnd
}

@external(erlang, "http_client_ffi", "new_lifecycle")
fn new_lifecycle(
  maximum_connections: Int,
  maximum_connections_per_origin: Int,
  idle_milliseconds: Int,
) -> Lifecycle

@external(erlang, "http_client_ffi", "new_http2_pool")
fn new_http2_pool(
  maximum_connections: Int,
  maximum_connections_per_origin: Int,
  idle_milliseconds: Int,
) -> Http2Pool

@external(erlang, "http_client_ffi", "checkout_http2")
fn raw_checkout_http2(
  pool: Http2Pool,
  lifecycle: Lifecycle,
  origin: String,
) -> Result(#(transport.Socket, http2_wire.State, fn() -> Nil), Int)

@external(erlang, "http_client_ffi", "checkin_http2")
fn checkin_http2(
  pool: Http2Pool,
  lifecycle: Lifecycle,
  origin: String,
  socket: transport.Socket,
  state: http2_wire.State,
  cleanup: fn() -> Nil,
) -> Bool

@external(erlang, "http_client_ffi", "drain_http2_pool")
fn drain_http2_pool(pool: Http2Pool) -> Nil

@external(erlang, "http_client_ffi", "close_http2_pool")
fn close_http2_pool(pool: Http2Pool) -> Nil

@external(erlang, "http_client_ffi", "new_policy_store")
fn new_policy_store(maximum_entries: Int, maximum_bytes: Int) -> PolicyStore

@external(erlang, "http_client_ffi", "policy_store_put")
fn policy_store_put(
  store: PolicyStore,
  partition: String,
  key: String,
  value: cookie.Cookie,
  expires_at: Int,
  retained_bytes: Int,
) -> Bool

@external(erlang, "http_client_ffi", "new_grouped_policy_store")
fn new_grouped_policy_store(
  maximum_entries: Int,
  maximum_bytes: Int,
  maximum_per_group: Int,
) -> PolicyStore

@external(erlang, "http_client_ffi", "policy_store_put_grouped")
fn policy_store_put_grouped(
  store: PolicyStore,
  partition: String,
  key: String,
  value: cookie.Cookie,
  expires_at: Int,
  retained_bytes: Int,
  group: String,
) -> Bool

@external(erlang, "http_client_ffi", "policy_store_touch")
fn policy_store_touch(
  store: PolicyStore,
  partition: String,
  keys: List(String),
) -> Nil

@external(erlang, "http_client_ffi", "policy_store_list")
fn policy_store_list(
  store: PolicyStore,
  partition: String,
) -> List(cookie.Cookie)

@external(erlang, "http_client_ffi", "policy_store_get")
fn cookie_store_get(
  store: PolicyStore,
  partition: String,
  key: String,
) -> Result(cookie.Cookie, Int)

@external(erlang, "http_client_ffi", "policy_store_put")
fn cache_store_put(
  store: PolicyStore,
  partition: String,
  key: String,
  value: cache.Entry,
  expires_at: Int,
  retained_bytes: Int,
) -> Bool

@external(erlang, "http_client_ffi", "policy_store_get")
fn cache_store_get(
  store: PolicyStore,
  partition: String,
  key: String,
) -> Result(cache.Entry, Int)

@external(erlang, "http_client_ffi", "policy_store_put")
fn hsts_store_put(
  store: PolicyStore,
  partition: String,
  key: String,
  value: hsts.Entry,
  expires_at: Int,
  retained_bytes: Int,
) -> Bool

@external(erlang, "http_client_ffi", "policy_store_list")
fn hsts_store_list(store: PolicyStore, partition: String) -> List(hsts.Entry)

@external(erlang, "http_client_ffi", "policy_store_put")
fn alt_svc_store_put(
  store: PolicyStore,
  partition: String,
  key: String,
  value: alt_svc.Entry,
  expires_at: Int,
  retained_bytes: Int,
) -> Bool

@external(erlang, "http_client_ffi", "policy_store_list")
fn alt_svc_store_list(
  store: PolicyStore,
  partition: String,
) -> List(alt_svc.Entry)

@external(erlang, "http_client_ffi", "call_https_resolver_before")
fn call_https_resolver_before(
  resolver: fn(String, Int, Int) -> Result(List(HttpsRecord), Nil),
  host: String,
  port: Int,
  allocated_milliseconds: Int,
  deadline_milliseconds: Int,
) -> Result(List(HttpsRecord), Int)

@external(erlang, "http_client_ffi", "close_policy_store")
fn close_policy_store(store: PolicyStore) -> Nil

@external(erlang, "http_client_ffi", "state")
fn lifecycle_state(lifecycle: Lifecycle) -> Int

@external(erlang, "http_client_ffi", "drain")
fn lifecycle_drain(lifecycle: Lifecycle) -> Int

@external(erlang, "http_client_ffi", "close_before")
fn lifecycle_close(
  lifecycle: Lifecycle,
  deadline: Int,
  join_confirmation: Bool,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "lifecycle_owner")
fn lifecycle_owner(lifecycle: Lifecycle) -> process.Pid

@external(erlang, "http_client_ffi", "lifecycle_snapshot")
fn raw_lifecycle_snapshot(lifecycle: Lifecycle) -> #(Int, Int, Int, Int)

@external(erlang, "http_client_ffi", "lifecycle_pending_count")
fn raw_lifecycle_pending_count(lifecycle: Lifecycle) -> Int

@external(erlang, "http_client_ffi", "http3_dial_snapshot")
fn raw_http3_dial_snapshot(lifecycle: Lifecycle) -> #(Int, Int)

@external(erlang, "http_client_ffi", "is_closed")
fn lifecycle_is_closed(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_client_ffi", "register_socket")
fn register_socket(
  lifecycle: Lifecycle,
  origin: String,
  socket: transport.Socket,
) -> Result(Registration, Int)

@external(erlang, "http_client_ffi", "register_socket_before")
fn register_socket_before(
  lifecycle: Lifecycle,
  origin: String,
  socket: transport.Socket,
  deadline: Int,
) -> Result(Registration, Int)

@external(erlang, "http_client_ffi", "attach_reserved_socket")
fn attach_reserved_socket(
  registration: Registration,
  socket: transport.Socket,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "attach_reserved_socket_before")
fn attach_reserved_socket_before(
  registration: Registration,
  socket: transport.Socket,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "replace_socket")
fn replace_registered_socket(
  lifecycle: Lifecycle,
  previous: transport.Socket,
  socket: transport.Socket,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "replace_socket_before")
fn replace_registered_socket_before(
  lifecycle: Lifecycle,
  previous: transport.Socket,
  socket: transport.Socket,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "transfer_and_adopt_socket_owner")
fn transfer_and_adopt_registered_socket_owner(
  lifecycle: Lifecycle,
  socket: transport.Socket,
  owner: process.Pid,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "transfer_and_adopt_socket_owner_before")
fn transfer_and_adopt_registered_socket_owner_before(
  lifecycle: Lifecycle,
  socket: transport.Socket,
  owner: process.Pid,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "unregister_socket")
fn unregister_socket(registration: Registration) -> Nil

@external(erlang, "http_client_ffi", "unregister_socket_before")
fn unregister_socket_before(registration: Registration, deadline: Int) -> Bool

@external(erlang, "http_client_ffi", "reserve_resource")
fn reserve_resource(
  lifecycle: Lifecycle,
  origin: String,
) -> Result(Registration, Int)

@external(erlang, "http_client_ffi", "reserve_resource_before")
fn reserve_resource_before(
  lifecycle: Lifecycle,
  origin: String,
  deadline: Int,
) -> Result(Registration, Int)

@external(erlang, "http_client_ffi", "begin_http3_dial_within")
fn begin_http3_dial_within(
  lifecycle: Lifecycle,
  origin: String,
  key: String,
  timeout_milliseconds: Int,
) -> Result(Http3DialAdmission, Int)

@external(erlang, "http_client_ffi", "begin_http3_dial_before")
fn begin_http3_dial_before(
  lifecycle: Lifecycle,
  origin: String,
  key: String,
  deadline: Int,
) -> Result(Http3DialAdmission, Int)

@external(erlang, "http_client_ffi", "await_http3_dial")
fn await_http3_dial(wait: Http3DialWait) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "settle_http3_dial_probe_within")
fn settle_http3_dial_probe_within(
  registration: Registration,
  published: Bool,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "expire_http3_dial_waiters_probe_within")
fn expire_http3_dial_waiters_probe_within(
  registration: Registration,
  advance_milliseconds: Int,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "attach_http3_resource")
fn attach_http3_resource(
  registration: Registration,
  owner: process.Pid,
  close_handle: http3_exchange.CloseHandle,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "cancel_resource")
fn cancel_resource(registration: Registration) -> Nil

@external(erlang, "http_client_ffi", "activate_http3_candidate_before")
fn activate_http3_candidate_before(
  registration: Registration,
  key: String,
  connection: http3_exchange.Connection,
  allow_share: Bool,
  deadline: Int,
) -> Result(#(http3_exchange.Connection, Http3Lease), Int)

@external(erlang, "http_client_ffi", "checkout_http3_shared_before")
fn checkout_http3_shared_before(
  lifecycle: Lifecycle,
  key: String,
  deadline: Int,
) -> Result(#(http3_exchange.Connection, Http3Lease), Int)

@external(erlang, "http_client_ffi", "adopt_http3_lease_before")
fn adopt_http3_lease_before(
  lease: Http3Lease,
  holder: process.Pid,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "release_http3_lease_before")
fn release_http3_lease_before(
  lease: Http3Lease,
  reusable: Bool,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "retire_http3_candidate_confirmed_before")
fn retire_http3_candidate_confirmed_before(
  registration: Registration,
  deadline: Int,
) -> Result(Nil, Int)

@external(erlang, "http_client_ffi", "checkout_socket")
fn raw_checkout_socket(
  lifecycle: Lifecycle,
  origin: String,
) -> Result(transport.Socket, Int)

@external(erlang, "http_client_ffi", "checkin_socket")
fn checkin_socket(
  lifecycle: Lifecycle,
  origin: String,
  socket: transport.Socket,
) -> Bool

@external(erlang, "http_client_ffi", "new_connection_guard")
fn new_tunnel_guard() -> TunnelGuard

@external(erlang, "http_client_ffi", "claim_connection_close")
fn claim_tunnel_close(guard: TunnelGuard) -> Bool

@external(erlang, "http_client_ffi", "new_race_cancellation")
fn new_race_cancellation() -> RaceCancellation

@external(erlang, "http_client_ffi", "cancel_race")
fn mark_race_cancelled(cancellation: RaceCancellation) -> Nil

@external(erlang, "http_client_ffi", "race_cancelled")
fn race_is_cancelled(cancellation: RaceCancellation) -> Bool

@external(erlang, "http_client_ffi", "call_policy_adapter_before")
fn call_policy_adapter_before(
  run: fn() -> Result(value, Nil),
  deadline_milliseconds: Int,
) -> Result(value, Int)

@external(erlang, "http_client_ffi", "call_http3_reuse_before")
fn call_http3_reuse_before(
  run: fn() -> Result(Bool, error.Error),
  deadline: Int,
) -> Result(Result(Bool, error.Error), Int)

/// Construct the safe, finite product defaults.
pub fn defaults() -> Config {
  Config(
    timeouts: Timeouts(
      dns_milliseconds: 5000,
      connect_milliseconds: 10_000,
      tls_milliseconds: 10_000,
      operation_milliseconds: 30_000,
      idle_milliseconds: 30_000,
      total_milliseconds: 30_000,
    ),
    body_limits: BodyLimits(
      buffered_bytes: 8_388_608,
      stream_buffer_bytes: 262_144,
      endpoint_memory_bytes: 67_108_864,
    ),
    pool_limits: PoolLimits(
      maximum_connections: 256,
      maximum_connections_per_origin: 8,
      idle_milliseconds: 30_000,
    ),
    pooling_enabled: True,
    security: Security(allow_plain_http: False),
    redirect_policy: RedirectPolicy(enabled: True, maximum: 10),
    retry_policy: RetryPolicy(enabled: True, maximum: 1, retry_statuses: []),
    cookie_policy: CookiePolicy(
      enabled: False,
      limits: StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
    ),
    cache_policy: CachePolicy(
      enabled: False,
      limits: StoreLimits(maximum_entries: 256, maximum_bytes: 16_777_216),
    ),
    hsts_policy: HstsPolicy(
      enabled: True,
      limits: StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
    ),
    discovery_policy: DiscoveryPolicy(
      enabled: True,
      alt_svc_limits: StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
      https_record_timeout_milliseconds: 1000,
    ),
    https_record_resolver: None,
    proxy_policy: ProxyPolicy(proxy: None),
    network_isolation_key: NetworkIsolationKey(
      top_level_site: "",
      profile: "default",
    ),
    cookie_store_adapter: None,
    cache_store_adapter: None,
    hsts_store_adapter: None,
    alt_svc_store_adapter: None,
    ca_certificates: [],
    diagnostics: None,
    race_join_confirmation: True,
    race_claim_offer_confirmation: True,
    race_claim_commit_confirmation: True,
    http3_release_reuse_probe: None,
    http3_stream_open_refusal_probe: None,
    http3_resource_limit_terminal_probe: None,
    http3_connect_gate: None,
    https_race_candidate_gate: None,
    lifecycle_close_join_confirmation: True,
  )
}

/// Inspect the finite deadline policy.
pub fn timeouts(config: Config) -> Timeouts {
  config.timeouts
}

/// Inspect the finite body and endpoint limits.
pub fn body_limits(config: Config) -> BodyLimits {
  config.body_limits
}

/// Inspect finite connection-pool limits.
pub fn pool_limits(config: Config) -> PoolLimits {
  config.pool_limits
}

/// Return finite registered-resource and idle-pool counts for deterministic lifecycle tests.
/// Runtime handles, owners, origins, and keys stay private.
@internal
pub fn lifecycle_pool_counts(client: Client) -> #(Int, Int) {
  let #(registered, pooled, _, _) = raw_lifecycle_snapshot(client.lifecycle)
  #(registered, pooled)
}

/// Finite lifecycle and HTTP/3 resource counts for deterministic fixtures.
/// No runtime handle, origin, pool key, endpoint, or process identity escapes.
@internal
pub type LifecycleCensus {
  LifecycleCensus(
    registered_resources: Int,
    pooled_resources: Int,
    caller_owned_resources: Int,
    monitored_resources: Int,
    pending_resources: Int,
    active_workers: Int,
    memory_bytes: Int,
  )
}

/// Observe the lifecycle and request-resource ledger at one finite instant.
@internal
pub fn lifecycle_census(client: Client) -> LifecycleCensus {
  let #(registered, pooled, caller_owned, monitored) =
    raw_lifecycle_snapshot(client.lifecycle)
  let usage = resource.snapshot(client.http3_resources)
  LifecycleCensus(
    registered_resources: registered,
    pooled_resources: pooled,
    caller_owned_resources: caller_owned,
    monitored_resources: monitored,
    pending_resources: raw_lifecycle_pending_count(client.lifecycle),
    active_workers: usage.active_workers,
    memory_bytes: usage.memory_bytes,
  )
}

/// Bounded, identity-free view of the HTTP/3 connection-generation broker.
@internal
pub type Http3DialCensus {
  Http3DialCensus(inflight: Int, waiters: Int)
}

/// Opaque deterministic handle for broker state-machine tests.
/// Its lifecycle registration, process identity, pool key, and reply capability stay private.
@internal
pub opaque type Http3DialProbe {
  Http3DialProbe(admission: Http3DialAdmission)
}

/// Safe observation of the role assigned by one atomic broker admission.
@internal
pub type Http3DialRole {
  Http3DialLeaderRole
  Http3DialWaitingRole
  Http3DialPublishedRole
}

/// Enter a fixed private broker partition.
/// A Waiting result is returned only after the lifecycle actor has installed the caller monitor and deadline.
@internal
pub fn http3_dial_probe_begin(
  client: Client,
  timeout_milliseconds: Int,
) -> Result(Http3DialProbe, error.Error) {
  begin_http3_dial_within(
    client.lifecycle,
    "https://http3-dial-probe.invalid:443",
    "http3-dial-probe",
    timeout_milliseconds,
  )
  |> result.map(Http3DialProbe)
  |> result.map_error(http3_dial_probe_error)
}

/// Return the safe role of an opaque broker admission.
@internal
pub fn http3_dial_probe_role(probe: Http3DialProbe) -> Http3DialRole {
  case probe.admission {
    Http3DialLeader(_) -> Http3DialLeaderRole
    Http3DialWaiting(_) -> Http3DialWaitingRole
    Http3DialPublished -> Http3DialPublishedRole
  }
}

/// Wait for a follower's original absolute deadline.
/// Leader probes cannot wait for their own publication because they hold the sole generation right.
@internal
pub fn http3_dial_probe_await(
  probe: Http3DialProbe,
) -> Result(Nil, error.Error) {
  case probe.admission {
    Http3DialWaiting(wait) ->
      await_http3_dial(wait)
      |> result.map_error(http3_dial_probe_error)
    Http3DialPublished -> Ok(Nil)
    Http3DialLeader(_) -> Error(error.new(error.Service))
  }
}

/// Settle a leader through the same waiter publication path as the real actor.
@internal
pub fn http3_dial_probe_settle(
  probe: Http3DialProbe,
  published: Bool,
  timeout_milliseconds: Int,
) -> Result(Nil, error.Error) {
  case probe.admission {
    Http3DialLeader(registration) ->
      settle_http3_dial_probe_within(
        registration,
        published,
        timeout_milliseconds,
      )
      |> result.map_error(http3_dial_probe_error)
    Http3DialWaiting(_) | Http3DialPublished -> Error(error.new(error.Service))
  }
}

/// Advance only the lifecycle actor's waiter-deadline view and acknowledge after the corresponding prune.
/// This leaves the leader and its connection reservation intact, so deadline tests never depend on elapsed wall time.
@internal
pub fn http3_dial_probe_expire_waiters(
  probe: Http3DialProbe,
  advance_milliseconds: Int,
  timeout_milliseconds: Int,
) -> Result(Nil, error.Error) {
  case probe.admission {
    Http3DialLeader(registration) ->
      expire_http3_dial_waiters_probe_within(
        registration,
        advance_milliseconds,
        timeout_milliseconds,
      )
      |> result.map_error(http3_dial_probe_error)
    Http3DialWaiting(_) | Http3DialPublished -> Error(error.new(error.Service))
  }
}

/// Observe only finite broker cardinalities.
@internal
pub fn http3_dial_census(client: Client) -> Http3DialCensus {
  let #(inflight, waiters) = raw_http3_dial_snapshot(client.lifecycle)
  Http3DialCensus(inflight, waiters)
}

fn http3_dial_probe_error(code: Int) -> error.Error {
  case code {
    2 -> error.new(error.Resource(error.Connections))
    3 -> error.new(error.Service)
    _ -> error.new(error.Cancelled)
  }
}

/// Observe only the resource controller after lifecycle shutdown.
@internal
pub fn http3_resource_usage(client: Client) -> #(Int, Int) {
  let usage = resource.snapshot(client.http3_resources)
  #(usage.active_workers, usage.memory_bytes)
}

/// Return whether connection reuse is enabled.
pub fn pooling_enabled(config: Config) -> Bool {
  config.pooling_enabled
}

/// Inspect explicit security opt-ins.
pub fn security(config: Config) -> Security {
  config.security
}

/// Inspect the bounded automatic redirect policy.
pub fn redirect_policy(config: Config) -> RedirectPolicy {
  config.redirect_policy
}

/// Inspect the bounded automatic retry policy.
pub fn retry_policy(config: Config) -> RetryPolicy {
  config.retry_policy
}

/// Inspect the bounded cookie policy.
pub fn cookie_policy(config: Config) -> CookiePolicy {
  config.cookie_policy
}

/// Inspect the bounded complete-response cache policy.
pub fn cache_policy(config: Config) -> CachePolicy {
  config.cache_policy
}

/// Inspect Strict-Transport-Security learning and store limits.
pub fn hsts_policy(config: Config) -> HstsPolicy {
  config.hsts_policy
}

/// Inspect safe Alt-Svc and HTTPS-record discovery limits.
pub fn discovery_policy(config: Config) -> DiscoveryPolicy {
  config.discovery_policy
}

/// Inspect explicit proxy selection.
pub fn proxy_policy(config: Config) -> ProxyPolicy {
  config.proxy_policy
}

/// Inspect the partition key used by stateful policy stores.
pub fn network_isolation_key(config: Config) -> NetworkIsolationKey {
  config.network_isolation_key
}

/// Inspect the optional typed cookie persistence adapter.
pub fn cookie_store_adapter(
  config: Config,
) -> Option(client_store.Adapter(client_store.CookieRecord)) {
  config.cookie_store_adapter
}

/// Inspect the optional typed cache persistence adapter.
pub fn cache_store_adapter(
  config: Config,
) -> Option(client_store.Adapter(client_store.CacheRecord)) {
  config.cache_store_adapter
}

/// Inspect the optional typed HSTS persistence adapter.
pub fn hsts_store_adapter(
  config: Config,
) -> Option(client_store.Adapter(client_store.HstsRecord)) {
  config.hsts_store_adapter
}

/// Inspect the optional typed Alt-Svc persistence adapter.
pub fn alt_svc_store_adapter(
  config: Config,
) -> Option(client_store.Adapter(client_store.AltSvcRecord)) {
  config.alt_svc_store_adapter
}

/// Explicitly allow cleartext HTTP for this client.
pub fn allow_plain_http(config: Config) -> Config {
  Config(..config, security: Security(allow_plain_http: True))
}

/// Attach a bounded, payload-free Reporter shared with application exporters.
/// The caller owns the Reporter and stops it after its clients have closed.
/// Network exchanges correlate retries and redirects; cached fetch results and tunnel operations currently do not create exchange observations.
pub fn with_diagnostics(
  config: Config,
  reporter: diagnostics.Reporter,
) -> Config {
  Config(..config, diagnostics: Some(reporter))
}

/// Inject whether a completed race-helper join may be trusted.
/// Production configurations always use `True`; deterministic lifecycle tests set this to `False` to verify conservative quarantine after an unconfirmed join.
@internal
pub fn with_race_join_confirmation(config: Config, confirmed: Bool) -> Config {
  Config(..config, race_join_confirmation: confirmed)
}

/// Inject whether lifecycle owner termination may be trusted by `close`.
/// Production configurations always use `True`; deterministic lifecycle tests set this to `False` to prove that unconfirmed cleanup cannot report success.
@internal
pub fn with_lifecycle_close_join_confirmation(
  config: Config,
  confirmed: Bool,
) -> Config {
  Config(..config, lifecycle_close_join_confirmation: confirmed)
}

/// Inject delivery and commit confirmation at the private TCP winner handoff.
/// Production always confirms both phases; lifecycle tests can deterministically exercise a missing offer or commit without wall-clock races.
@internal
pub fn with_race_handoff_confirmation(
  config: Config,
  offer_confirmed: Bool,
  commit_confirmed: Bool,
) -> Config {
  Config(
    ..config,
    race_claim_offer_confirmation: offer_confirmed,
    race_claim_commit_confirmation: commit_confirmed,
  )
}

/// Inject the release-time reuse decision for deterministic pool lifecycle tests.
/// Production configurations always query the actor-owned connection.
@internal
pub fn with_http3_release_reuse_probe(
  config: Config,
  probe: fn() -> Result(Bool, Nil),
) -> Config {
  Config(..config, http3_release_reuse_probe: Some(probe))
}

/// Refuse a native HTTP/3 stream open at its deterministic pre-open test seam.
/// Production configurations never install this probe.
@internal
pub fn with_http3_stream_open_refusal_probe(
  config config: Config,
  probe probe: fn() -> Result(Bool, Nil),
) -> Config {
  Config(..config, http3_stream_open_refusal_probe: Some(probe))
}

/// Surface the connection-capacity result before protocol fallback at the deterministic multiplexing fixture boundary.
/// Production configurations always retain the normal TCP fallback.
@internal
pub fn with_http3_resource_limit_terminal_probe(
  config config: Config,
  terminal terminal: fn() -> Bool,
) -> Config {
  Config(..config, http3_resource_limit_terminal_probe: Some(terminal))
}

/// Inject a deterministic synchronization or failure point immediately before HTTP/3 connection establishment.
/// Production configurations never install this gate.
/// Tests use it to prove the TCP route remains live after a known UDP/QUIC connection failure without relying on relative scheduling.
@internal
pub fn with_http3_connect_gate(
  config config: Config,
  gate gate: fn() -> Result(Nil, error.Error),
) -> Config {
  Config(..config, http3_connect_gate: Some(gate))
}

/// Inject a deterministic, payload-free barrier after each HTTPS contender is authenticated and before it publishes readiness.
/// The supplied deadline is the exchange's original absolute monotonic deadline.
/// Production configurations never install this gate; cancellation kills the contender executing it, so the normal race guardian still owns all connection cleanup.
@internal
pub fn with_https_race_candidate_gate(
  config config: Config,
  gate gate: fn(HttpsRaceCandidate, Int) -> Result(Nil, error.Error),
) -> Config {
  Config(..config, https_race_candidate_gate: Some(gate))
}

/// Run the TCP fallback for an HTTP/3 resource failure only while the original total deadline still has a positive budget.
/// `now` is explicit so lifecycle tests can exercise the exact boundary without sleeping.
@internal
pub fn run_tcp_fallback_before_total_deadline(
  deadline: Int,
  now: Int,
  start: fn(Int) -> Result(a, error.Error),
) -> Result(a, error.Error) {
  let remaining = deadline - now
  case remaining > 0 {
    True -> start(remaining)
    False -> Error(error.new(error.Timeout(error.Total)))
  }
}

/// Disable connection reuse for this client.
pub fn without_pooling(config: Config) -> Config {
  Config(..config, pooling_enabled: False)
}

/// Disable automatic redirects while still returning redirect responses.
pub fn without_redirects(config: Config) -> Config {
  Config(
    ..config,
    redirect_policy: RedirectPolicy(..config.redirect_policy, enabled: False),
  )
}

/// Disable all automatic retries.
pub fn without_retries(config: Config) -> Config {
  Config(
    ..config,
    retry_policy: RetryPolicy(..config.retry_policy, enabled: False),
  )
}

/// Disable HSTS learning and URI upgrades for this client.
pub fn without_hsts(config: Config) -> Config {
  Config(
    ..config,
    hsts_policy: HstsPolicy(..config.hsts_policy, enabled: False),
  )
}

/// Disable Alt-Svc and HTTPS-record protocol discovery.
pub fn without_protocol_discovery(config: Config) -> Config {
  Config(
    ..config,
    discovery_policy: DiscoveryPolicy(..config.discovery_policy, enabled: False),
  )
}

/// Replace finite protocol-discovery policy.
pub fn with_discovery_policy(
  config: Config,
  discovery_policy: DiscoveryPolicy,
) -> Result(Config, error.Error) {
  use <- require(
    valid_store_limits(discovery_policy.alt_svc_limits)
      && valid_timeout(discovery_policy.https_record_timeout_milliseconds),
    security_policy_error(),
  )
  Ok(Config(..config, discovery_policy:))
}

/// Install a typed HTTPS-record resolver behind the configured finite timeout.
///
/// Only authenticated records advertising `h3` are eligible.
/// Callback errors,
/// exits, malformed records, and timeouts are ignored and planning continues with the authenticated TCP path.
pub fn with_https_record_resolver(
  config: Config,
  resolver: fn(String, Int, Int) -> Result(List(HttpsRecord), Nil),
) -> Config {
  Config(..config, https_record_resolver: Some(resolver))
}

/// Route supported requests through one validated explicit HTTP proxy.
pub fn with_proxy(config: Config, proxy: Proxy) -> Result(Config, error.Error) {
  use <- require(valid_proxy(proxy), proxy_policy_error())
  Ok(Config(..config, proxy_policy: ProxyPolicy(Some(proxy))))
}

/// Disable explicit proxy routing.
pub fn without_proxy(config: Config) -> Config {
  Config(..config, proxy_policy: ProxyPolicy(None))
}

/// Replace HSTS learning and finite-store policy.
pub fn with_hsts_policy(
  config: Config,
  hsts_policy: HstsPolicy,
) -> Result(Config, error.Error) {
  use <- require(
    valid_store_limits(hsts_policy.limits),
    security_policy_error(),
  )
  Ok(Config(..config, hsts_policy:))
}

/// Replace the finite retry policy.
///
/// Status codes must be error responses (400 through 599).
/// An empty list keeps status retries disabled while retaining retries backed by explicit evidence that the request was not processed.
pub fn with_retry_policy(
  config: Config,
  retry_policy: RetryPolicy,
) -> Result(Config, error.Error) {
  use <- require(valid_retry_policy(retry_policy), retry_policy_error())
  Ok(Config(..config, retry_policy:))
}

/// Enable the finite in-memory cookie store.
pub fn enable_cookies(
  config: Config,
  limits: StoreLimits,
) -> Result(Config, error.Error) {
  use <- require(valid_store_limits(limits), security_policy_error())
  Ok(Config(..config, cookie_policy: CookiePolicy(True, limits)))
}

/// Enable conservative caching of explicitly fresh complete GET responses.
pub fn enable_cache(
  config: Config,
  limits: StoreLimits,
) -> Result(Config, error.Error) {
  use <- require(valid_store_limits(limits), cache_policy_error())
  Ok(Config(..config, cache_policy: CachePolicy(True, limits)))
}

/// Replace the network-isolation partition used by all stateful policies.
pub fn with_network_isolation_key(
  config: Config,
  network_isolation_key: NetworkIsolationKey,
) -> Result(Config, error.Error) {
  use <- require(
    valid_network_isolation_key(network_isolation_key),
    security_policy_error(),
  )
  Ok(Config(..config, network_isolation_key:))
}

/// Replace the in-memory cookie store's optional persistence adapter.
pub fn with_cookie_store_adapter(
  config: Config,
  adapter: client_store.Adapter(client_store.CookieRecord),
) -> Config {
  Config(..config, cookie_store_adapter: Some(adapter))
}

/// Replace the in-memory cache store's optional persistence adapter.
pub fn with_cache_store_adapter(
  config: Config,
  adapter: client_store.Adapter(client_store.CacheRecord),
) -> Config {
  Config(..config, cache_store_adapter: Some(adapter))
}

/// Replace the in-memory HSTS store's optional persistence adapter.
pub fn with_hsts_store_adapter(
  config: Config,
  adapter: client_store.Adapter(client_store.HstsRecord),
) -> Config {
  Config(..config, hsts_store_adapter: Some(adapter))
}

/// Replace the in-memory Alt-Svc store's optional persistence adapter.
pub fn with_alt_svc_store_adapter(
  config: Config,
  adapter: client_store.Adapter(client_store.AltSvcRecord),
) -> Config {
  Config(..config, alt_svc_store_adapter: Some(adapter))
}

/// Set the finite maximum number of automatic redirect hops.
pub fn with_redirect_limit(
  config config: Config,
  maximum maximum: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum > 0 && maximum <= 2_147_483_647,
    redirect_policy_error(),
  )
  Ok(
    Config(
      ..config,
      redirect_policy: RedirectPolicy(..config.redirect_policy, maximum:),
    ),
  )
}

/// Replace the finite connection-pool limits.
pub fn with_pool_limits(
  config config: Config,
  pool_limits pool_limits: PoolLimits,
) -> Result(Config, error.Error) {
  use <- require(valid_pool_limits(pool_limits), security_policy_error())
  Ok(Config(..config, pool_limits:))
}

/// Replace all finite response-body memory limits.
pub fn with_body_limits(
  config config: Config,
  body_limits body_limits: BodyLimits,
) -> Result(Config, error.Error) {
  use <- require(valid_body_limits(body_limits), security_policy_error())
  Ok(Config(..config, body_limits:))
}

/// Use an explicit DER CA set instead of the operating-system trust store.
pub fn with_ca_certificates(
  config config: Config,
  ca_certificates ca_certificates: List(BitArray),
) -> Config {
  Config(..config, ca_certificates:)
}

/// Replace every deadline after checking that all waits remain finite.
pub fn with_timeouts(
  config config: Config,
  timeouts timeouts: Timeouts,
) -> Result(Config, error.Error) {
  use <- require(valid_timeouts(timeouts), security_policy_error())
  Ok(Config(..config, timeouts:))
}

/// Allocate one reusable client owner.
pub fn start(config: Config) -> Result(Client, error.Error) {
  use http3_limits <- result.try(resource.limits(
    maximum_workers: http3_request_worker_limit(config.pool_limits),
    memory_bytes: config.body_limits.endpoint_memory_bytes,
  ))
  let CookiePolicy(_, cookie_limits) = config.cookie_policy
  let CachePolicy(_, cache_limits) = config.cache_policy
  let HstsPolicy(_, hsts_limits) = config.hsts_policy
  let DiscoveryPolicy(_, alt_svc_limits, _) = config.discovery_policy
  let client =
    Client(
      config:,
      lifecycle: new_lifecycle(
        config.pool_limits.maximum_connections,
        config.pool_limits.maximum_connections_per_origin,
        config.pool_limits.idle_milliseconds,
      ),
      http2_pool: new_http2_pool(
        config.pool_limits.maximum_connections,
        config.pool_limits.maximum_connections_per_origin,
        config.pool_limits.idle_milliseconds,
      ),
      http3_resources: resource.start(http3_limits),
      cookie_store: new_grouped_policy_store(
        cookie_limits.maximum_entries,
        cookie_limits.maximum_bytes,
        cookie_domain_ceiling(cookie_limits.maximum_entries),
      ),
      cache_store: new_policy_store(
        cache_limits.maximum_entries,
        cache_limits.maximum_bytes,
      ),
      hsts_store: new_policy_store(
        hsts_limits.maximum_entries,
        hsts_limits.maximum_bytes,
      ),
      alt_svc_store: new_policy_store(
        alt_svc_limits.maximum_entries,
        alt_svc_limits.maximum_bytes,
      ),
      trace: None,
    )
  case load_policy_adapters(client) {
    Ok(Nil) -> Ok(client)
    Error(failure) -> {
      let _closed = close(client)
      Error(failure)
    }
  }
}

/// Finite aggregate HTTP/3 stream budget across every admitted physical connection.
/// Each physical lifecycle ledger has the matching fixed factor,
/// so exhausting one ledger still leaves admission for a scale-out candidate.
@internal
pub fn http3_request_worker_limit(pool_limits: PoolLimits) -> Int {
  int.min(2_147_483_647, pool_limits.maximum_connections * 100)
}

fn load_policy_adapters(client: Client) -> Result(Nil, error.Error) {
  use _ <- result.try(load_cookie_adapter(client))
  use _ <- result.try(load_cache_adapter(client))
  use _ <- result.try(load_hsts_adapter(client))
  load_alt_svc_adapter(client)
}

fn load_cookie_adapter(client: Client) -> Result(Nil, error.Error) {
  case client.config.cookie_store_adapter {
    None -> Ok(Nil)
    Some(adapter) -> {
      use records <- result.try(
        run_policy_adapter(adapter, fn() {
          client_store.load(adapter, adapter_partition(client.config))
        }),
      )
      let CookiePolicy(_, limits) = client.config.cookie_policy
      use <- require(
        list.length(records) <= limits.maximum_entries,
        security_policy_error(),
      )
      load_cookie_records(
        records,
        client.cookie_store,
        policy_partition(client.config.network_isolation_key),
        transport.monotonic_millisecond(),
        limits.maximum_bytes,
        [],
      )
    }
  }
}

fn load_cookie_records(
  records: List(client_store.CookieRecord),
  store: PolicyStore,
  partition: String,
  now: Int,
  remaining_bytes: Int,
  keys: List(String),
) -> Result(Nil, error.Error) {
  case records {
    [] -> Ok(Nil)
    [record, ..rest] -> {
      use entry <- result.try(
        cookie.from_persisted(
          record.name,
          record.value,
          record.domain,
          record.path,
          record.host_only,
          record.secure,
          record.expires_in_milliseconds,
          record.age_milliseconds,
          now,
        )
        |> option.to_result(security_policy_error()),
      )
      use <- require(
        record.key == cookie.key(entry)
          && !list.contains(keys, record.key)
          && entry.retained_bytes <= remaining_bytes
          && policy_store_put(
          store,
          partition,
          record.key,
          entry,
          entry.expires_at,
          entry.retained_bytes,
        ),
        security_policy_error(),
      )
      load_cookie_records(
        rest,
        store,
        partition,
        now,
        remaining_bytes - entry.retained_bytes,
        [record.key, ..keys],
      )
    }
  }
}

fn load_cache_adapter(client: Client) -> Result(Nil, error.Error) {
  case client.config.cache_store_adapter {
    None -> Ok(Nil)
    Some(adapter) -> {
      use records <- result.try(
        run_policy_adapter(adapter, fn() {
          client_store.load(adapter, adapter_partition(client.config))
        }),
      )
      let CachePolicy(_, limits) = client.config.cache_policy
      use <- require(
        list.length(records) <= limits.maximum_entries,
        security_policy_error(),
      )
      load_cache_records(
        records,
        client.cache_store,
        policy_partition(client.config.network_isolation_key),
        transport.monotonic_millisecond(),
        limits.maximum_bytes,
        [],
      )
    }
  }
}

fn load_cache_records(
  records: List(client_store.CacheRecord),
  store: PolicyStore,
  partition: String,
  now: Int,
  remaining_bytes: Int,
  keys: List(String),
) -> Result(Nil, error.Error) {
  case records {
    [] -> Ok(Nil)
    [record, ..rest] -> {
      use entry <- result.try(
        cache.from_persisted(
          record.key,
          record.status,
          record.headers,
          record.bytes,
          record.trailers,
          record.expires_in_milliseconds,
          now,
        )
        |> option.to_result(security_policy_error()),
      )
      use <- require(
        !list.contains(keys, record.key)
          && entry.retained_bytes <= remaining_bytes
          && cache_store_put(
          store,
          partition,
          record.key,
          entry,
          entry.expires_at,
          entry.retained_bytes,
        ),
        security_policy_error(),
      )
      load_cache_records(
        rest,
        store,
        partition,
        now,
        remaining_bytes - entry.retained_bytes,
        [record.key, ..keys],
      )
    }
  }
}

fn load_hsts_adapter(client: Client) -> Result(Nil, error.Error) {
  case client.config.hsts_store_adapter {
    None -> Ok(Nil)
    Some(adapter) -> {
      use records <- result.try(
        run_policy_adapter(adapter, fn() {
          client_store.load(adapter, adapter_partition(client.config))
        }),
      )
      let HstsPolicy(_, limits) = client.config.hsts_policy
      use <- require(
        list.length(records) <= limits.maximum_entries,
        security_policy_error(),
      )
      load_hsts_records(
        records,
        client.hsts_store,
        policy_partition(client.config.network_isolation_key),
        transport.monotonic_millisecond(),
        limits.maximum_bytes,
        [],
      )
    }
  }
}

fn load_hsts_records(
  records: List(client_store.HstsRecord),
  store: PolicyStore,
  partition: String,
  now: Int,
  remaining_bytes: Int,
  keys: List(String),
) -> Result(Nil, error.Error) {
  case records {
    [] -> Ok(Nil)
    [record, ..rest] -> {
      use entry <- result.try(
        hsts.from_persisted(
          record.host,
          record.include_subdomains,
          record.expires_in_milliseconds,
          now,
        )
        |> option.to_result(security_policy_error()),
      )
      use <- require(
        record.key == entry.host
          && !list.contains(keys, record.key)
          && entry.retained_bytes <= remaining_bytes
          && hsts_store_put(
          store,
          partition,
          record.key,
          entry,
          entry.expires_at,
          entry.retained_bytes,
        ),
        security_policy_error(),
      )
      load_hsts_records(
        rest,
        store,
        partition,
        now,
        remaining_bytes - entry.retained_bytes,
        [record.key, ..keys],
      )
    }
  }
}

fn load_alt_svc_adapter(client: Client) -> Result(Nil, error.Error) {
  case client.config.alt_svc_store_adapter {
    None -> Ok(Nil)
    Some(adapter) -> {
      use records <- result.try(
        run_policy_adapter(adapter, fn() {
          client_store.load(adapter, adapter_partition(client.config))
        }),
      )
      let DiscoveryPolicy(_, limits, _) = client.config.discovery_policy
      use <- require(
        list.length(records) <= limits.maximum_entries,
        security_policy_error(),
      )
      load_alt_svc_records(
        records,
        client.alt_svc_store,
        policy_partition(client.config.network_isolation_key),
        transport.monotonic_millisecond(),
        limits.maximum_bytes,
        [],
      )
    }
  }
}

fn load_alt_svc_records(
  records: List(client_store.AltSvcRecord),
  store: PolicyStore,
  partition: String,
  now: Int,
  remaining_bytes: Int,
  keys: List(String),
) -> Result(Nil, error.Error) {
  case records {
    [] -> Ok(Nil)
    [record, ..rest] -> {
      use entry <- result.try(
        alt_svc.from_https_record(
          record.origin_host,
          record.origin_port,
          record.alternative_port,
          record.expires_in_milliseconds,
          now,
        )
        |> option.to_result(security_policy_error()),
      )
      use <- require(
        record.key == alt_svc.key(entry.origin_host, entry.origin_port)
          && !list.contains(keys, record.key)
          && entry.retained_bytes <= remaining_bytes
          && alt_svc_store_put(
          store,
          partition,
          record.key,
          entry,
          entry.expires_at,
          entry.retained_bytes,
        ),
        security_policy_error(),
      )
      load_alt_svc_records(
        rest,
        store,
        partition,
        now,
        remaining_bytes - entry.retained_bytes,
        [record.key, ..keys],
      )
    }
  }
}

fn run_policy_adapter(
  adapter: client_store.Adapter(record),
  operation: fn() -> Result(value, Nil),
) -> Result(value, error.Error) {
  let deadline =
    transport.monotonic_millisecond()
    + client_store.timeout_milliseconds(adapter)
  call_policy_adapter_before(operation, deadline)
  |> result.map_error(fn(_) { security_policy_error() })
}

fn adapter_partition(config: Config) -> client_store.Partition {
  let NetworkIsolationKey(top_level_site, profile) =
    config.network_isolation_key
  client_store.Partition(top_level_site:, profile:)
}

/// Execute a buffered request and return a detached, replayable response.
///
/// The response body is collected under `BodyLimits.buffered_bytes`, including trailers, before this function returns.
/// Use `exchange` for streaming.
pub fn fetch(
  client client: Client,
  outgoing outgoing: Request(BitArray),
) -> Result(Response(body.Body), error.Error) {
  use _ <- result.try(require_open(client))
  let outgoing = apply_hsts_policy(client, outgoing)
  use _ <- result.try(require_scheme(client.config, outgoing.scheme == Http))
  use <- require(
    bit_array.bit_size(outgoing.body) % 8 == 0,
    error.new(error.Body(error.InvalidChunk)),
  )
  case cached_response(client, outgoing) {
    Some(incoming) -> Ok(incoming)
    None -> {
      let cache_request = request.set_body(outgoing, Nil)
      let outgoing = request.set_body(outgoing, body.from_bytes(outgoing.body))
      use completed <- result.try(run_exchange(client, outgoing))
      buffer_response(
        client,
        cache_request,
        completed,
        client.config.body_limits.buffered_bytes,
      )
    }
  }
}

/// Execute a streaming request and retain typed exchange metadata.
/// The exchange owns and disposes its request body.
/// Use `body.replay` or a fresh body before submitting another request with the same source.
pub fn exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
) -> Result(Exchange, error.Error) {
  run_exchange(client, outgoing)
}

/// Return the standard streaming response.
pub fn response(exchange: Exchange) -> Response(body.Body) {
  exchange.response
}

/// Return the negotiated application protocol.
pub fn selected_protocol(exchange: Exchange) -> Protocol {
  exchange.selected_protocol
}

/// Return followed redirects in wire order without paths, queries, or headers.
pub fn redirect_history(exchange: Exchange) -> List(RedirectHop) {
  exchange.redirect_history
}

/// Establish a CONNECT or Upgrade tunnel without optimistic application data.
///
/// The request body must be empty.
/// A stream is returned only after a CONNECT 2xx or Upgrade 101 response; rejected handshakes close their connection.
pub fn open_tunnel(
  client client: Client,
  outgoing outgoing: Request(BitArray),
) -> Result(TunnelHandshake, error.Error) {
  use _ <- result.try(require_open(client))
  use _ <- result.try(require_scheme(client.config, outgoing.scheme == Http))
  use <- require(
    bit_array.bit_size(outgoing.body) % 8 == 0
      && bit_array.byte_size(outgoing.body) == 0,
    security_policy_error(),
  )
  use config <- result.try(http1_config(
    client,
    client.config.timeouts.total_milliseconds,
  ))
  let outgoing = request.set_body(outgoing, body.empty())
  use ready <- result.try(http1_exchange.run_tunnel(outgoing, config))
  let http1_exchange.TunnelReady(status, headers, socket, buffered, cleanup) =
    ready
  let tunnel =
    Tunnel(
      socket:,
      buffered:,
      cleanup:,
      guard: new_tunnel_guard(),
      maximum_read_bytes: client.config.body_limits.stream_buffer_bytes,
      idle_timeout_milliseconds: client.config.timeouts.idle_milliseconds,
    )
  Ok(TunnelHandshake(
    response: response.Response(status:, headers:, body: body.empty()),
    tunnel:,
  ))
}

/// Return the successful standard handshake response.
pub fn tunnel_response(handshake: TunnelHandshake) -> Response(body.Body) {
  handshake.response
}

/// Return the opaque stream established by a successful handshake.
pub fn tunnel_connection(handshake: TunnelHandshake) -> Tunnel {
  handshake.tunnel
}

/// Send one byte-aligned post-handshake application chunk.
pub fn send_tunnel(
  tunnel tunnel: Tunnel,
  bytes bytes: BitArray,
) -> Result(Nil, error.Error) {
  case bit_array.bit_size(bytes) % 8 {
    0 ->
      transport.send(tunnel.socket, bytes)
      |> result.map_error(map_tunnel_transport_error)
    _ -> Error(error.new(error.Body(error.InvalidChunk)))
  }
}

/// Read at most `maximum_bytes` through one active-once operation.
pub fn read_tunnel(
  tunnel tunnel: Tunnel,
  maximum_bytes maximum_bytes: Int,
) -> Result(TunnelRead, error.Error) {
  use <- bool.guard(
    when: maximum_bytes <= 0 || maximum_bytes > tunnel.maximum_read_bytes,
    return: Error(security_policy_error()),
  )
  case tunnel.buffered {
    <<>> -> read_tunnel_transport(tunnel, maximum_bytes)
    bytes -> emit_tunnel_bytes(tunnel:, bytes:, maximum_bytes:)
  }
}

/// Close and unregister a tunnel idempotently.
pub fn close_tunnel(tunnel: Tunnel) -> Result(Nil, error.Error) {
  use <- bool.guard(when: !claim_tunnel_close(tunnel.guard), return: Ok(Nil))
  let outcome =
    transport.close(tunnel.socket)
    |> result.map_error(map_tunnel_transport_error)
  tunnel.cleanup()
  outcome
}

/// Stop admitting new requests.
/// Repeated calls are harmless.
pub fn drain(client: Client) -> Result(Nil, error.Error) {
  resource.stop(client.http3_resources)
  let _state = lifecycle_drain(client.lifecycle)
  drain_http2_pool(client.http2_pool)
  Ok(Nil)
}

/// Close the client idempotently.
pub fn close(client: Client) -> Result(Nil, error.Error) {
  let ClosePhaseObservation(_, lifecycle_outcome, _, _, resource_outcome, _, _) =
    close_observed(client)
  case lifecycle_outcome, resource_outcome {
    Error(failure), _ -> Error(failure)
    _, Error(failure) -> Error(failure)
    Ok(Nil), Ok(Nil) -> Ok(Nil)
  }
}

/// Finite close-phase evidence for deterministic lifecycle diagnostics.
/// It exposes no process, socket, origin, request, or response value.
@internal
pub type ClosePhaseObservation {
  ClosePhaseObservation(
    active_workers_before: Int,
    lifecycle_outcome: Result(Nil, error.Error),
    lifecycle_milliseconds: Int,
    active_workers_after_lifecycle: Int,
    resource_outcome: Result(Nil, error.Error),
    resource_milliseconds: Int,
    active_workers_after_resource: Int,
  )
}

/// Close the client while retaining only bounded, non-sensitive phase results.
@internal
pub fn close_observed(client: Client) -> ClosePhaseObservation {
  let active_workers_before =
    resource.snapshot(client.http3_resources).active_workers
  let close_started = transport.monotonic_millisecond()
  let lifecycle_deadline = close_started + 5000
  let resource_deadline = lifecycle_deadline
  resource.stop(client.http3_resources)
  close_http2_pool(client.http2_pool)
  close_policy_store(client.cookie_store)
  close_policy_store(client.cache_store)
  close_policy_store(client.hsts_store)
  close_policy_store(client.alt_svc_store)
  let lifecycle_started = transport.monotonic_millisecond()
  let lifecycle_outcome =
    lifecycle_close(
      client.lifecycle,
      lifecycle_deadline,
      client.config.lifecycle_close_join_confirmation,
    )
    |> result.map_error(fn(_) { error.new(error.Timeout(error.Operation)) })
  let lifecycle_finished = transport.monotonic_millisecond()
  let active_workers_after_lifecycle =
    resource.snapshot(client.http3_resources).active_workers
  let resource_started = transport.monotonic_millisecond()
  let resource_outcome = case lifecycle_outcome {
    Ok(Nil) -> await_http3_release(client.http3_resources, resource_deadline)
    Error(failure) -> Error(failure)
  }
  let resource_finished = transport.monotonic_millisecond()
  ClosePhaseObservation(
    active_workers_before:,
    lifecycle_outcome:,
    lifecycle_milliseconds: int.max(0, lifecycle_finished - lifecycle_started),
    active_workers_after_lifecycle:,
    resource_outcome:,
    resource_milliseconds: int.max(0, resource_finished - resource_started),
    active_workers_after_resource: resource.snapshot(client.http3_resources).active_workers,
  )
}

fn await_http3_release(
  resources: resource.Controller,
  deadline: Int,
) -> Result(Nil, error.Error) {
  case resource.snapshot(resources).active_workers {
    0 -> Ok(Nil)
    _ -> {
      use <- require(
        transport.monotonic_millisecond() < deadline,
        error.new(error.Timeout(error.Operation)),
      )
      process.sleep(1)
      await_http3_release(resources, deadline)
    }
  }
}

fn run_exchange(
  client: Client,
  outgoing: Request(body.Body),
) -> Result(Exchange, error.Error) {
  let client =
    Client(..client, trace: client_trace.start(client.config.diagnostics))
  let deadline =
    transport.monotonic_millisecond()
    + client.config.timeouts.total_milliseconds
  let outcome =
    run_exchange_redirects(
      client: client,
      outgoing: outgoing,
      redirects_followed: 0,
      reversed_history: [],
      deadline: deadline,
    )
  case outcome {
    Error(failure) -> {
      client_trace.exchange_finished(client.trace, Error(failure))
      Error(failure)
    }
    Ok(Exchange(trace: None, ..) as exchange) -> Ok(exchange)
    Ok(exchange) -> {
      let protocol = diagnostic_protocol(exchange.selected_protocol)
      let source =
        body.observe_transfer(
          exchange.response.body,
          fn() {
            client_trace.read_finished(exchange.trace, protocol)
            client_trace.exchange_finished(exchange.trace, Ok(Nil))
          },
          fn(result) {
            case result {
              Ok(Nil) -> Nil
              Error(failure) ->
                client_trace.exchange_finished(exchange.trace, Error(failure))
            }
          },
        )
      Ok(
        Exchange(
          ..exchange,
          response: response.set_body(exchange.response, source),
        ),
      )
    }
  }
}

fn diagnostic_protocol(protocol: Protocol) -> context.Protocol {
  case protocol {
    Http1 -> context.Http1
    Http2 -> context.Http2
    Http3 -> context.Http3
  }
}

fn run_exchange_redirects(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  redirects_followed redirects_followed: Int,
  reversed_history reversed_history: List(RedirectHop),
  deadline deadline: Int,
) -> Result(Exchange, error.Error) {
  case require_open(client) {
    Error(failure) -> reject_unstarted_attempt(client, outgoing, failure)
    Ok(Nil) -> {
      let outgoing = apply_hsts_policy(client, outgoing)
      let outgoing = apply_cookie_policy(client, outgoing)
      let remaining = deadline - transport.monotonic_millisecond()
      let preflight = {
        use _ <- result.try(require_scheme(
          client.config,
          outgoing.scheme == Http,
        ))
        use <- require(remaining > 0, error.new(error.Timeout(error.Total)))
        Ok(Nil)
      }
      case preflight {
        Error(failure) -> reject_unstarted_attempt(client, outgoing, failure)
        Ok(Nil) -> {
          use completed <- result.try(run_exchange_attempts(
            client: client,
            outgoing: outgoing,
            deadline: deadline,
            retries_remaining: client.config.retry_policy.maximum,
          ))
          capture_response_policies(client, outgoing, completed)
          case redirect_location(completed.response) {
            None -> Ok(with_redirect_history(completed, reversed_history))
            Some(_) if !client.config.redirect_policy.enabled ->
              Ok(with_redirect_history(completed, reversed_history))
            Some(_)
              if redirects_followed >= client.config.redirect_policy.maximum
            -> {
              use _ <- result.try(release_response_before(
                completed.response.body,
                deadline,
              ))
              Error(redirect_policy_error())
            }
            Some(location) -> {
              let remaining = deadline - transport.monotonic_millisecond()
              case
                redirect_after_response_release(
                  outgoing: outgoing,
                  status: completed.response.status,
                  location: location,
                  response_body: completed.response.body,
                  within_milliseconds: remaining,
                )
              {
                Error(failure) -> {
                  Error(failure)
                }
                Ok(next) -> {
                  let hop =
                    RedirectHop(
                      status: completed.response.status,
                      from: request_origin(outgoing),
                      to: request_origin(next),
                      protocol: completed.selected_protocol,
                    )
                  run_exchange_redirects(
                    client: client,
                    outgoing: next,
                    redirects_followed: redirects_followed + 1,
                    reversed_history: [hop, ..reversed_history],
                    deadline: deadline,
                  )
                }
              }
            }
          }
        }
      }
    }
  }
}

fn reject_unstarted_attempt(
  client: Client,
  outgoing: Request(body.Body),
  failure: error.Error,
) -> Result(value, error.Error) {
  let trace = client_trace.attempt(client.trace)
  let _claimed =
    client_trace.claim_finished_if_missing(trace, None, Error(failure))
  dispose_unowned_request(trace, outgoing.body, failure)
}

fn dispose_unowned_request(
  trace: Option(client_trace.Trace),
  source: body.Body,
  failure: error.Error,
) -> Result(value, error.Error) {
  body.transfer_finished(source, Error(failure))
  client_trace.phase_started(trace, diagnostics.ResourceRelease)
  let cleanup = body.cancel_within(source, 1000)
  client_trace.phase_finished(trace, diagnostics.ResourceRelease, cleanup)
  client_trace.released_if_missing(trace, None, cleanup)
  Error(failure)
}

/// Evidence available when deciding whether one automatic retry is safe.
///
/// A response-body failure is included so tests and future adapters cannot accidentally collapse it into a generic pre-response failure.
/// The unified client never retries after returning response headers to its caller.
@internal
pub type RetryTrigger {
  RequestUnstarted(failure: error.Error)
  RequestRejected
  RequestPossiblyProcessed(failure: error.Error)
  ResponseHeadersReceived(status: Int)
  ResponseBodyPartiallyReceived(failure: error.Error)
}

/// Apply the complete bounded automatic-retry policy without consuming a Body.
/// This pure surface keeps every safety input explicit for model and mutation tests.
@internal
pub fn automatic_retry_allowed(
  policy policy: RetryPolicy,
  method method: Method,
  body_replayable body_replayable: Bool,
  retries_remaining retries_remaining: Int,
  trigger trigger: RetryTrigger,
) -> Bool {
  policy.enabled
  && policy.maximum >= 0
  && retries_remaining > 0
  && retries_remaining <= policy.maximum
  && idempotent_method(method)
  && body_replayable
  && case trigger {
    RequestUnstarted(failure) -> retryable_unstarted_failure(failure)
    RequestRejected -> True
    ResponseHeadersReceived(status) -> retry_status(policy, status)
    RequestPossiblyProcessed(_) | ResponseBodyPartiallyReceived(_) -> False
  }
}

/// Derive retry evidence conservatively from a redacted failure.
/// DNS,
/// connection establishment, and TLS failures precede request transmission.
/// Every untagged operation or protocol failure might have followed a send.
@internal
pub fn retry_trigger_for_failure(failure: error.Error) -> RetryTrigger {
  case error.retry_evidence(failure) {
    error.PeerGuaranteedUnprocessed -> RequestRejected
    error.NoRetryEvidence ->
      case error.kind(failure) {
        error.Dns
        | error.ConnectFailed
        | error.Tls
        | error.Timeout(error.DnsLookup)
        | error.Timeout(error.Connect)
        | error.Timeout(error.TlsHandshake) -> RequestUnstarted(failure)
        _ -> RequestPossiblyProcessed(failure)
      }
  }
}

fn run_exchange_attempts(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  deadline deadline: Int,
  retries_remaining retries_remaining: Int,
) -> Result(Exchange, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining > 0 {
    False ->
      reject_unstarted_attempt(
        client,
        outgoing,
        error.new(error.Timeout(error.Total)),
      )
    True ->
      case
        run_exchange_once(
          client: client,
          outgoing: outgoing,
          total_milliseconds: remaining,
        )
      {
        Ok(completed) -> {
          let should_retry =
            automatic_retry_allowed(
              policy: client.config.retry_policy,
              method: outgoing.method,
              body_replayable: body.is_replayable(outgoing.body),
              retries_remaining: retries_remaining,
              trigger: ResponseHeadersReceived(completed.response.status),
            )
          case should_retry {
            False -> Ok(completed)
            True -> {
              let remaining = deadline - transport.monotonic_millisecond()
              case
                status_retry_after_response_release(
                  policy: client.config.retry_policy,
                  status: completed.response.status,
                  outgoing: outgoing,
                  response_body: completed.response.body,
                  within_milliseconds: remaining,
                )
              {
                Error(failure) -> Error(failure)
                Ok(None) -> Ok(completed)
                Ok(Some(replayed)) ->
                  run_exchange_attempts(
                    client: client,
                    outgoing: replayed,
                    deadline: deadline,
                    retries_remaining: retries_remaining - 1,
                  )
              }
            }
          }
        }
        Error(failure) -> {
          // Protocol adapters return an error only after their old admission and connection reservation reaches its terminal release barrier.
          // Confirm the request source independently before constructing a replay so source cleanup can never overlap the next attempt.
          let remaining = deadline - transport.monotonic_millisecond()
          case
            failed_attempt_retry_after_release(
              policy: client.config.retry_policy,
              outgoing: outgoing,
              retries_remaining: retries_remaining,
              failure: failure,
              within_milliseconds: remaining,
            )
          {
            Error(cleanup_failure) -> Error(cleanup_failure)
            Ok(None) -> Error(failure)
            Ok(Some(replayed)) ->
              run_exchange_attempts(
                client: client,
                outgoing: replayed,
                deadline: deadline,
                retries_remaining: retries_remaining - 1,
              )
          }
        }
      }
  }
}

/// Confirm failed request-source cleanup before constructing a replay.
/// `None` leaves an ineligible attempt untouched; its protocol adapter already owns terminal cleanup.
/// The original attempt failure has been recorded before this function is entered.
@internal
pub fn failed_attempt_retry_after_release(
  policy policy: RetryPolicy,
  outgoing outgoing: Request(body.Body),
  retries_remaining retries_remaining: Int,
  failure failure: error.Error,
  within_milliseconds within_milliseconds: Int,
) -> Result(Option(Request(body.Body)), error.Error) {
  let trigger = retry_trigger_for_failure(failure)
  case
    automatic_retry_allowed(
      policy: policy,
      method: outgoing.method,
      body_replayable: body.is_replayable(outgoing.body),
      retries_remaining: retries_remaining,
      trigger: trigger,
    )
  {
    False -> Ok(None)
    True -> {
      use _ <- result.try(release_body_within(
        outgoing.body,
        within_milliseconds,
      ))
      body.replay(outgoing.body)
      |> result.map(fn(replayed) { Some(request.set_body(outgoing, replayed)) })
    }
  }
}

/// Confirm response cleanup before constructing a status-retry body.
/// `None` leaves an ineligible response untouched so callers can return it normally.
@internal
pub fn status_retry_after_response_release(
  policy policy: RetryPolicy,
  status status: Int,
  outgoing outgoing: Request(body.Body),
  response_body response_body: body.Body,
  within_milliseconds within_milliseconds: Int,
) -> Result(Option(Request(body.Body)), error.Error) {
  case can_retry_request(policy, status, outgoing) {
    False -> Ok(None)
    True -> {
      use _ <- result.try(release_body_within(
        response_body,
        within_milliseconds,
      ))
      body.replay(outgoing.body)
      |> result.map(fn(replayed) { Some(request.set_body(outgoing, replayed)) })
    }
  }
}

/// Validate a redirect without replaying, confirm cleanup of the previous response, and only then materialise the next request body.
@internal
pub fn redirect_after_response_release(
  outgoing outgoing: Request(body.Body),
  status status: Int,
  location location: String,
  response_body response_body: body.Body,
  within_milliseconds within_milliseconds: Int,
) -> Result(Request(body.Body), error.Error) {
  let planned = redirect.plan(outgoing, status, location)
  use _ <- result.try(release_body_within(response_body, within_milliseconds))
  use plan <- result.try(planned)
  redirect.materialise(outgoing, plan)
}

fn release_response_before(
  response_body: body.Body,
  deadline: Int,
) -> Result(Nil, error.Error) {
  release_body_within(
    response_body,
    deadline - transport.monotonic_millisecond(),
  )
}

fn release_body_within(
  source: body.Body,
  within_milliseconds: Int,
) -> Result(Nil, error.Error) {
  case within_milliseconds > 0 {
    True ->
      body.cancel_within(source, int.min(within_milliseconds, 2_147_482_647))
    False -> {
      // Cancellation still starts under a finite cleanup grace after the logical total deadline; no replay or next attempt may use that grace.
      let _cleanup = body.cancel_within(source, 1)
      Error(error.new(error.Timeout(error.Total)))
    }
  }
}

fn can_retry_request(
  policy: RetryPolicy,
  status: Int,
  outgoing: Request(body.Body),
) -> Bool {
  automatic_retry_allowed(
    policy: policy,
    method: outgoing.method,
    body_replayable: body.is_replayable(outgoing.body),
    retries_remaining: 1,
    trigger: ResponseHeadersReceived(status),
  )
}

fn idempotent_method(method: Method) -> Bool {
  case method {
    Get | Head | Put | Delete | Options | Trace -> True
    _ -> False
  }
}

fn retry_status(policy: RetryPolicy, status: Int) -> Bool {
  policy.enabled && list.contains(policy.retry_statuses, status)
}

fn retryable_unstarted_failure(failure: error.Error) -> Bool {
  case error.kind(failure) {
    error.Dns
    | error.ConnectFailed
    | error.Tls
    | error.Timeout(error.DnsLookup)
    | error.Timeout(error.Connect)
    | error.Timeout(error.TlsHandshake)
    | error.Timeout(error.Operation)
    | error.Timeout(error.Idle)
    | error.Protocol(_) -> True
    _ -> False
  }
}

fn run_exchange_once(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  total_milliseconds total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  let client = Client(..client, trace: client_trace.attempt(client.trace))
  let outcome = case outgoing.scheme {
    Http ->
      run_http1_exchange(
        client: client,
        outgoing: outgoing,
        total_milliseconds: total_milliseconds,
      )
    Https ->
      run_https_exchange(
        client: client,
        outgoing: outgoing,
        total_milliseconds: total_milliseconds,
      )
  }
  case outcome {
    Error(failure) -> {
      case
        client_trace.claim_finished_if_missing(
          client.trace,
          None,
          Error(failure),
        )
      {
        True -> dispose_unowned_request(client.trace, outgoing.body, failure)
        False -> Error(failure)
      }
    }
    Ok(Exchange(trace: Some(_), ..) as exchange) -> Ok(exchange)
    Ok(exchange) -> Ok(Exchange(..exchange, trace: client.trace))
  }
}

fn run_http1_exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  total_milliseconds total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  use config <- result.try(http1_config(client, total_milliseconds))
  use incoming <- result.try(http1_exchange.run(outgoing, config))
  Ok(Exchange(
    response: incoming,
    selected_protocol: Http1,
    redirect_history: [],
    trace: client.trace,
  ))
}

fn run_https_exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  total_milliseconds total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  let deadline = transport.monotonic_millisecond() + total_milliseconds
  refresh_https_records(client, outgoing, deadline)
  case should_attempt_http3(client, outgoing) {
    False ->
      case deadline - transport.monotonic_millisecond() {
        remaining if remaining > 0 ->
          run_tcp_https_exchange(client, outgoing, remaining)
        _ -> Error(error.new(error.Timeout(error.Total)))
      }
    True -> race_https_routes(client, outgoing, deadline)
  }
}

fn refresh_https_records(
  client: Client,
  outgoing: Request(body),
  total_deadline: Int,
) -> Nil {
  let origin = request_origin(outgoing)
  let now = transport.monotonic_millisecond()
  let existing =
    alt_svc_store_list(
      client.alt_svc_store,
      policy_partition(client.config.network_isolation_key),
    )
  case
    client.config.discovery_policy.enabled,
    alt_svc.alternative_port(existing, outgoing.host, origin.port, now),
    client.config.https_record_resolver
  {
    True, None, Some(resolver) -> {
      let resolver_budget =
        https_record_resolver_budget(
          client.config.discovery_policy.https_record_timeout_milliseconds,
          total_deadline,
          now,
        )
      case resolver_budget > 0 {
        False -> Nil
        True ->
          case
            call_https_resolver_before(
              resolver,
              outgoing.host,
              origin.port,
              resolver_budget,
              now + resolver_budget,
            )
          {
            Ok(records) ->
              store_https_records(
                client,
                outgoing.host,
                origin.port,
                records,
                now,
              )
            Error(_) -> Nil
          }
      }
    }
    _, _, _ -> Nil
  }
}

/// Allocate discovery time without extending the exchange's absolute total deadline.
/// Keeping this calculation pure makes scheduler-stall and expired boundary regressions directly reproducible.
@internal
pub fn https_record_resolver_budget(
  configured_milliseconds: Int,
  total_deadline: Int,
  current_milliseconds: Int,
) -> Int {
  int.max(
    0,
    int.min(configured_milliseconds, total_deadline - current_milliseconds),
  )
}

fn store_https_records(
  client: Client,
  host: String,
  origin_port: Int,
  records: List(HttpsRecord),
  now: Int,
) -> Nil {
  case records {
    [] -> Nil
    [record, ..rest] -> {
      case
        record.authenticated,
        list.contains(record.alpns, "h3"),
        alt_svc.from_https_record(
          host,
          origin_port,
          record.port,
          record.expires_in_milliseconds,
          now,
        )
      {
        True, True, Some(entry) -> {
          let _stored = store_alt_svc_policy(client, entry, now)
          Nil
        }
        _, _, _ -> Nil
      }
      store_https_records(client, host, origin_port, rest, now)
    }
  }
}

fn run_tcp_https_exchange(
  client: Client,
  outgoing: Request(body.Body),
  total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  use http1 <- result.try(http1_config(client, total_milliseconds))
  let http1 = http1_exchange.without_proxy(http1)
  use config <- result.try(http2_config(client, total_milliseconds))
  let config =
    http2_exchange.with_http1_fallback(
      config,
      fn(socket, outgoing, cleanup, total_deadline) {
        http1_exchange.run_presecured(
          outgoing,
          socket,
          cleanup,
          http1,
          total_deadline,
        )
      },
    )
  run_configured_tcp_https(outgoing, config)
}

fn run_configured_tcp_https(
  outgoing: Request(body.Body),
  config: http2_exchange.Config,
) -> Result(Exchange, error.Error) {
  case http2_exchange.run(outgoing, config) {
    Error(failure) -> Error(failure)
    Ok(http2_exchange.Http2Response(incoming)) ->
      Ok(Exchange(
        response: incoming,
        selected_protocol: Http2,
        redirect_history: [],
        trace: None,
      ))
    Ok(http2_exchange.Http1Response(incoming)) ->
      Ok(Exchange(
        response: incoming,
        selected_protocol: Http1,
        redirect_history: [],
        trace: None,
      ))
    Ok(http2_exchange.Http1Required) ->
      Error(error.new(error.Protocol(error.Http1)))
  }
}

fn race_https_routes(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
) -> Result(Exchange, error.Error) {
  let origin = request_origin(outgoing)
  let endpoint_port = http3_endpoint_port(client, outgoing)
  let key = http3_pool_key(origin, client.config.network_isolation_key)
  case deadline - transport.monotonic_millisecond() > 0 {
    False -> Error(error.new(error.Timeout(error.Total)))
    True -> {
      let pooled = case client.config.pooling_enabled {
        True ->
          checkout_http3_shared_before(client.lifecycle, key, deadline)
          |> result.map(fn(shared) {
            let #(connection, lease) = shared
            PooledHttp3(connection, lease, key)
          })
        False -> Error(0)
      }
      case pooled {
        Ok(session) ->
          run_or_retire_pooled_http3(
            client,
            outgoing,
            session,
            deadline,
            origin,
            endpoint_port,
            key,
          )
        Error(0) ->
          start_new_https_route(
            client,
            outgoing,
            deadline,
            origin,
            endpoint_port,
            key,
          )
        Error(2) -> Error(error.new(error.Resource(error.Connections)))
        Error(_) ->
          case deadline - transport.monotonic_millisecond() > 0 {
            True -> Error(error.new(error.Cancelled))
            False -> Error(error.new(error.Timeout(error.Total)))
          }
      }
    }
  }
}

fn run_or_retire_pooled_http3(
  client: Client,
  outgoing: Request(body.Body),
  session: PooledHttp3,
  deadline: Int,
  origin: Origin,
  endpoint_port: Int,
  key: String,
) -> Result(Exchange, error.Error) {
  case deadline - transport.monotonic_millisecond() > 0 {
    False -> {
      let _retirement_enqueued = retire_http3_session_before(session, deadline)
      Error(error.new(error.Timeout(error.Total)))
    }
    True ->
      case http3_connection_reusable_until(session.connection, deadline) {
        Ok(True) ->
          case deadline - transport.monotonic_millisecond() > 0 {
            True ->
              run_pooled_http3_session(
                client,
                outgoing,
                session,
                deadline,
                origin,
                key,
              )
            False -> {
              let _retirement_enqueued =
                retire_http3_session_before(session, deadline)
              Error(error.new(error.Timeout(error.Total)))
            }
          }
        Ok(False) | Error(_) -> {
          let retired = case retire_http3_session_before(session, deadline) {
            Ok(Nil) ->
              result.is_ok(http3_exchange.await_owner_exit_before(
                connection: session.connection,
                deadline: deadline,
              ))
            Error(_) -> False
          }
          case retired, deadline - transport.monotonic_millisecond() > 0 {
            True, True ->
              start_new_https_route(
                client,
                outgoing,
                deadline,
                origin,
                endpoint_port,
                key,
              )
            _, False -> Error(error.new(error.Timeout(error.Total)))
            False, True -> Error(error.new(error.Cancelled))
          }
        }
      }
  }
}

fn http3_connection_reusable_until(
  connection: http3_exchange.Connection,
  deadline: Int,
) -> Result(Bool, error.Error) {
  case
    call_http3_reuse_before(
      fn() {
        process_role.set(process_role.ClientConnectionCandidate)
        http3_exchange.connection_reusable(connection)
      },
      deadline,
    )
  {
    Ok(outcome) -> outcome
    Error(0) -> Error(error.new(error.Timeout(error.Total)))
    Error(2) -> Error(error.new(error.Timeout(error.Operation)))
    Error(_) -> Error(error.new(error.Service))
  }
}

fn start_new_https_route(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  origin: Origin,
  endpoint_port: Int,
  key: String,
) -> Result(Exchange, error.Error) {
  case deadline - transport.monotonic_millisecond() > 0 {
    False -> Error(error.new(error.Timeout(error.Total)))
    True -> {
      let origin_identity =
        "https://" <> origin.host <> ":" <> int.to_string(origin.port)
      let admission = case client.config.pooling_enabled {
        True ->
          begin_http3_dial_before(
            client.lifecycle,
            origin_identity,
            key,
            deadline,
          )
        False ->
          reserve_resource_before(client.lifecycle, origin_identity, deadline)
          |> result.map(Http3DialLeader)
      }
      case admission {
        Ok(Http3DialLeader(registration)) ->
          case deadline - transport.monotonic_millisecond() > 0 {
            True ->
              race_new_https_connections(
                client,
                outgoing,
                deadline,
                endpoint_port,
                key,
                registration,
              )
            False -> {
              let _cancellation_enqueued =
                retire_http3_candidate_confirmed_before(registration, deadline)
              Error(error.new(error.Timeout(error.Total)))
            }
          }
        Ok(Http3DialWaiting(wait)) ->
          case await_http3_dial(wait) {
            Ok(Nil) ->
              run_after_http3_dial_publication(
                client,
                outgoing,
                deadline,
                origin,
                endpoint_port,
                key,
              )
            Error(3) ->
              run_tcp_fallback_before_total_deadline(
                deadline,
                transport.monotonic_millisecond(),
                fn(remaining) {
                  run_tcp_https_exchange(client, outgoing, remaining)
                },
              )
            Error(_) ->
              case deadline - transport.monotonic_millisecond() > 0 {
                True -> Error(error.new(error.Cancelled))
                False -> Error(error.new(error.Timeout(error.Total)))
              }
          }
        Ok(Http3DialPublished) ->
          run_after_http3_dial_publication(
            client,
            outgoing,
            deadline,
            origin,
            endpoint_port,
            key,
          )
        Error(2) -> handle_http3_connection_capacity(client, outgoing, deadline)
        Error(_) ->
          case deadline - transport.monotonic_millisecond() > 0 {
            True -> Error(error.new(error.Cancelled))
            False -> Error(error.new(error.Timeout(error.Total)))
          }
      }
    }
  }
}

fn run_after_http3_dial_publication(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  origin: Origin,
  endpoint_port: Int,
  key: String,
) -> Result(Exchange, error.Error) {
  case deadline - transport.monotonic_millisecond() > 0 {
    False -> Error(error.new(error.Timeout(error.Total)))
    True ->
      case checkout_http3_shared_before(client.lifecycle, key, deadline) {
        Ok(shared) -> {
          let #(connection, lease) = shared
          run_or_retire_pooled_http3(
            client,
            outgoing,
            PooledHttp3(connection, lease, key),
            deadline,
            origin,
            endpoint_port,
            key,
          )
        }
        Error(0) ->
          start_new_https_route(
            client,
            outgoing,
            deadline,
            origin,
            endpoint_port,
            key,
          )
        Error(2) -> handle_http3_connection_capacity(client, outgoing, deadline)
        Error(_) ->
          case deadline - transport.monotonic_millisecond() > 0 {
            True -> Error(error.new(error.Cancelled))
            False -> Error(error.new(error.Timeout(error.Total)))
          }
      }
  }
}

fn handle_http3_connection_capacity(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
) -> Result(Exchange, error.Error) {
  case client.config.http3_resource_limit_terminal_probe {
    Some(terminal) ->
      case terminal() {
        True -> Error(error.new(error.Resource(error.Connections)))
        False ->
          run_tcp_fallback_before_total_deadline(
            deadline,
            transport.monotonic_millisecond(),
            fn(remaining) {
              run_tcp_https_exchange(client, outgoing, remaining)
            },
          )
      }
    None ->
      run_tcp_fallback_before_total_deadline(
        deadline,
        transport.monotonic_millisecond(),
        fn(remaining) { run_tcp_https_exchange(client, outgoing, remaining) },
      )
  }
}

/// Build the authenticated-origin and network-partition identity of an HTTP/3 connection.
/// The currently selected Alt-Svc endpoint is routing metadata;
/// changing it does not invalidate an already authenticated connection.
@internal
pub fn http3_pool_key(
  origin: Origin,
  network_isolation_key: NetworkIsolationKey,
) -> String {
  let scheme = case origin.scheme {
    Http -> "http"
    Https -> "https"
  }
  "h3|"
  <> pool_key_component(scheme)
  <> pool_key_component(origin.host)
  <> pool_key_component(int.to_string(origin.port))
  <> pool_key_component(network_isolation_key.top_level_site)
  <> pool_key_component(network_isolation_key.profile)
}

fn pool_key_component(value: String) -> String {
  int.to_string(string.byte_size(value)) <> ":" <> value
}

fn race_new_https_connections(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  endpoint_port: Int,
  key: String,
  registration: Registration,
) -> Result(Exchange, error.Error) {
  let native_trace = case client.trace {
    None -> None
    Some(_) -> Some(h3_client.new_connect_trace())
  }
  let guarded = start_tcp_race_guard(client, registration, deadline)
  case guarded {
    Error(failure) -> {
      let _cleanup_confirmed = cancel_resource_until(registration, deadline)
      Error(failure)
    }
    Ok(guard) -> {
      let outcomes = process.new_subject()
      let http3_work = fn() {
        let outcome = {
          use _ <- result.try(case client.config.http3_connect_gate {
            None -> Ok(Nil)
            Some(gate) -> gate()
          })
          use config <- result.try(http3_config(client, deadline, native_trace))
          let origin = request_origin(outgoing)
          use connection <- result.try(
            http3_exchange.connect_to_managed(
              config,
              outgoing.host,
              origin.port,
              endpoint_port,
              fn(owner, close_handle) {
                case attach_http3_resource(registration, owner, close_handle) {
                  Ok(Nil) -> Ok(fn() { unregister_socket(registration) })
                  Error(_) -> Error(error.new(error.Cancelled))
                }
              },
            ),
          )
          use _ <- result.try(run_https_race_candidate_gate(
            client,
            Http3AuthenticatedCandidate,
            deadline,
          ))
          Ok(Http3Candidate(connection, registration, key))
        }
        process.send(outcomes, Http3Ready(outcome))
      }
      let tcp_work = fn() {
        case prepare_tcp_race(client, outgoing, deadline, guard) {
          Error(failure) -> process.send(outcomes, TcpReady(Error(failure)))
          Ok(ready) ->
            case
              run_https_race_candidate_gate(
                client,
                TcpAuthenticatedCandidate,
                deadline,
              )
            {
              Error(failure) -> {
                http2_exchange.discard_ready(ready)
                process.send(outcomes, TcpReady(Error(failure)))
              }
              Ok(Nil) -> {
                let handoff = process.new_subject()
                process.send(
                  outcomes,
                  TcpReady(Ok(TcpRaceCandidate(ready, handoff))),
                )
                await_tcp_candidate_handoff(ready, handoff, deadline)
              }
            }
        }
      }
      use #(h3_pid, tcp_pid) <- result.try(start_race_contenders(
        guard,
        http3_work,
        tcp_work,
      ))
      let h3_monitor = process.monitor(h3_pid)
      let tcp_monitor = process.monitor(tcp_pid)
      let h3_join_monitor = process.monitor(h3_pid)
      let tcp_join_monitor = process.monitor(tcp_pid)
      let selector =
        process.new_selector()
        |> process.select(outcomes)
        |> process.select_specific_monitor(h3_monitor, fn(_) { Http3Exited })
        |> process.select_specific_monitor(tcp_monitor, fn(_) { TcpExited })
      let selected = await_verified_route(selector, deadline, None, None)
      let completed =
        complete_verified_route(client, outgoing, deadline, guard, selected)
      let completed = case completed {
        Ok(_) -> completed
        Error(failure) -> {
          let helpers_confirmed =
            stop_race_contenders(
              [h3_pid, tcp_pid],
              client.config.race_join_confirmation,
              deadline,
            )
          case helpers_confirmed {
            True -> Error(failure)
            False -> Error(error.new(error.Timeout(error.Operation)))
          }
        }
      }
      let route_monitors_confirmed =
        join_race_contenders(
          [#(h3_pid, h3_join_monitor), #(tcp_pid, tcp_join_monitor)],
          client.config.race_join_confirmation,
          deadline,
        )
      process.demonitor_process(h3_monitor)
      process.demonitor_process(tcp_monitor)
      let completed = case route_monitors_confirmed, completed {
        True, _ -> completed
        False, Ok(exchange) -> {
          body.cancel(response(exchange).body)
          Error(error.new(error.Timeout(error.Operation)))
        }
        False, Error(_) -> Error(error.new(error.Timeout(error.Operation)))
      }
      case native_trace {
        None -> Nil
        Some(trace) ->
          client_trace.http3_snapshot(
            client.trace,
            h3_client.connect_snapshot(trace),
          )
      }
      completed
    }
  }
}

fn await_tcp_candidate_handoff(
  ready: http2_exchange.Ready,
  handoff: process.Subject(TcpCandidateHandoff),
  deadline: Int,
) -> Nil {
  case
    process.receive(
      handoff,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  {
    Ok(TcpCandidateHandoff(owner, reply)) -> {
      let acknowledge = process.new_subject()
      process.send(reply, TcpCandidateOffer(ready, acknowledge))
      let accepted =
        process.receive(
          acknowledge,
          within: int.max(0, deadline - transport.monotonic_millisecond()),
        )
      let outcome = case
        accepted,
        deadline > transport.monotonic_millisecond()
      {
        Ok(Nil), True ->
          http2_exchange.transfer_ready(ready, owner)
          |> result.map(fn(_) { Nil })
        _, _ -> {
          http2_exchange.discard_ready(ready)
          Error(error.new(error.Timeout(error.Total)))
        }
      }
      process.send(reply, TcpCandidateCommit(outcome))
    }
    Error(Nil) -> http2_exchange.discard_ready(ready)
  }
}

fn receive_tcp_candidate_handoff(
  transfer: process.Subject(TcpCandidateTransfer),
  deadline: Int,
) -> Result(http2_exchange.Ready, Nil) {
  case
    process.receive(
      transfer,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  {
    Ok(TcpCandidateOffer(ready, acknowledge)) -> {
      // The selected caller retains this provisional handle before the contender changes the controlling process.
      // A contender death at the following instruction therefore has an informed closer on both sides.
      process.send(acknowledge, Nil)
      case
        process.receive(
          transfer,
          within: int.max(0, deadline - transport.monotonic_millisecond()),
        )
      {
        Ok(TcpCandidateCommit(Ok(Nil))) ->
          case deadline > transport.monotonic_millisecond() {
            True -> Ok(ready)
            False -> {
              http2_exchange.discard_ready(ready)
              Error(Nil)
            }
          }
        Ok(TcpCandidateCommit(Error(_))) -> {
          // The transfer may already have changed the controlling process.
          // Cleanup therefore runs in the informed recipient, which is the only side guaranteed to be allowed to close both TCP and TLS.
          http2_exchange.discard_ready(ready)
          Error(Nil)
        }
        Ok(TcpCandidateOffer(_, _)) | Error(Nil) -> {
          http2_exchange.discard_ready(ready)
          Error(Nil)
        }
      }
    }
    Ok(TcpCandidateCommit(_)) | Error(Nil) -> Error(Nil)
  }
}

fn run_https_race_candidate_gate(
  client: Client,
  candidate: HttpsRaceCandidate,
  deadline: Int,
) -> Result(Nil, error.Error) {
  case client.config.https_race_candidate_gate {
    None -> Ok(Nil)
    Some(gate) -> gate(candidate, deadline)
  }
}

fn complete_verified_route(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  guard: TcpRaceGuard,
  selected: Result(VerifiedRoute, error.Error),
) -> Result(Exchange, error.Error) {
  // Ready messages are observations, not cleanup capabilities.
  // The race guardian owns both candidate registrations and acknowledges selection only after the loser transport and contender DOWN are confirmed.
  // This keeps correctness independent of an after-0 drain of the outcome mailbox.
  case selected {
    Ok(Http3Route(candidate)) -> {
      case select_http3_race_guard(guard) {
        True -> {
          use session <- result.try(activate_http3_candidate(
            candidate,
            client.config.pooling_enabled,
            deadline,
          ))
          run_http3_session(client, outgoing, session, deadline)
        }
        False -> {
          discard_http3_candidate(candidate, deadline)
          Error(error.new(error.Timeout(error.Operation)))
        }
      }
    }
    Ok(TcpRoute(candidate)) -> {
      case claim_tcp_race_guard(guard, candidate) {
        Error(True) -> Error(error.new(error.Cancelled))
        Error(False) -> Error(error.new(error.Timeout(error.Operation)))
        Ok(ready) ->
          run_prepared_tcp(
            ready
            |> http2_exchange.with_ready_trace(client.trace),
          )
      }
    }
    Error(failure) -> {
      let cleanup_confirmed = cancel_tcp_race_guard(guard)
      case cleanup_confirmed, error.kind(failure) {
        False, _ -> Error(error.new(error.Timeout(error.Operation)))
        True, error.Resource(error.Connections) ->
          run_tcp_fallback_before_total_deadline(
            deadline,
            transport.monotonic_millisecond(),
            fn(remaining) {
              run_tcp_https_exchange(client, outgoing, remaining)
            },
          )
        True, _ -> Error(failure)
      }
    }
  }
}

fn discard_http3_candidate(candidate: Http3Candidate, deadline: Int) -> Nil {
  let _retired =
    retire_http3_candidate_confirmed_before(candidate.registration, deadline)
  Nil
}

type VerifiedRoute {
  Http3Route(Http3Candidate)
  TcpRoute(TcpRaceCandidate)
}

fn await_verified_route(
  selector: process.Selector(RaceEvent),
  deadline: Int,
  h3_failure: Option(error.Error),
  tcp_failure: Option(error.Error),
) -> Result(VerifiedRoute, error.Error) {
  case h3_failure, tcp_failure {
    Some(_), Some(failure) -> Error(failure)
    _, _ -> {
      let remaining = int.max(0, deadline - transport.monotonic_millisecond())
      case process.selector_receive(selector, within: remaining) {
        Error(Nil) -> Error(error.new(error.Timeout(error.Total)))
        Ok(Http3Ready(Ok(session))) -> Ok(Http3Route(session))
        Ok(TcpReady(Ok(ready))) -> Ok(TcpRoute(ready))
        Ok(Http3Ready(Error(failure))) ->
          await_verified_route(selector, deadline, Some(failure), tcp_failure)
        Ok(TcpReady(Error(failure))) ->
          await_verified_route(selector, deadline, h3_failure, Some(failure))
        Ok(Http3Exited) ->
          await_verified_route(
            selector,
            deadline,
            case h3_failure {
              None -> Some(error.new(error.Service))
              Some(_) -> h3_failure
            },
            tcp_failure,
          )
        Ok(TcpExited) ->
          await_verified_route(
            selector,
            deadline,
            h3_failure,
            case tcp_failure {
              None -> Some(error.new(error.Service))
              Some(_) -> tcp_failure
            },
          )
      }
    }
  }
}

fn join_race_helper_until(
  _pid: process.Pid,
  monitor: process.Monitor,
  deadline: Int,
  confirmation: Bool,
) -> Bool {
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: int.max(
      0,
      deadline - transport.monotonic_millisecond(),
    ))
  process.demonitor_process(monitor)
  joined == Ok(Nil) && confirmation
}

fn prepare_tcp_race(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  guard: TcpRaceGuard,
) -> Result(http2_exchange.Ready, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  use <- require(remaining > 0, error.new(error.Timeout(error.Total)))
  use http1 <- result.try(http1_config(client, remaining))
  use http2 <- result.try(http2_config(client, remaining))
  let http2 =
    http2
    |> http2_exchange.with_trace(None)
    |> http2_exchange.with_admission(
      fn(origin) {
        reserve_tcp_socket_until(client.lifecycle, origin, deadline)
      },
      fn(previous, socket) {
        replace_registered_socket_before(
          client.lifecycle,
          previous,
          socket,
          deadline,
        )
        |> result.map_error(fn(code) { race_lifecycle_failure(code, deadline) })
      },
    )
    |> http2_exchange.with_lifecycle(
      fn(origin, socket) {
        attach_tcp_race_socket(client, guard, origin, socket)
      },
      fn() {
        lifecycle_is_closed(client.lifecycle)
        || race_is_cancelled(guard.cancellation)
      },
    )
    |> http2_exchange.with_owner_adoption(fn(socket, owner) {
      transfer_and_adopt_registered_socket_owner_before(
        client.lifecycle,
        socket,
        owner,
        deadline,
      )
      |> result.map_error(fn(code) { race_lifecycle_failure(code, deadline) })
    })
    |> http2_exchange.with_http1_fallback(
      fn(socket, outgoing, cleanup, total_deadline) {
        http1_exchange.run_presecured(
          outgoing,
          socket,
          cleanup,
          http1,
          total_deadline,
        )
      },
    )
  http2_exchange.prepare_connection_before(outgoing, http2, deadline)
}

fn run_prepared_tcp(
  ready: http2_exchange.Ready,
) -> Result(Exchange, error.Error) {
  case http2_exchange.run_ready(ready) {
    Error(failure) -> Error(failure)
    Ok(http2_exchange.Http2Response(incoming)) ->
      Ok(Exchange(incoming, Http2, [], None))
    Ok(http2_exchange.Http1Response(incoming)) ->
      Ok(Exchange(incoming, Http1, [], None))
    Ok(http2_exchange.Http1Required) ->
      Error(error.new(error.Protocol(error.Http1)))
  }
}

fn should_attempt_http3(client: Client, outgoing: Request(body.Body)) -> Bool {
  let origin = request_origin(outgoing)
  client.config.discovery_policy.enabled
  && client.config.proxy_policy.proxy == None
  && alt_svc.alternative_port(
    alt_svc_store_list(
      client.alt_svc_store,
      policy_partition(client.config.network_isolation_key),
    ),
    outgoing.host,
    origin.port,
    transport.monotonic_millisecond(),
  )
  != None
}

fn http3_endpoint_port(client: Client, outgoing: Request(body.Body)) -> Int {
  let origin = request_origin(outgoing)
  case
    alt_svc.alternative_port(
      alt_svc_store_list(
        client.alt_svc_store,
        policy_partition(client.config.network_isolation_key),
      ),
      outgoing.host,
      origin.port,
      transport.monotonic_millisecond(),
    )
  {
    Some(port) -> port
    None -> origin.port
  }
}

fn activate_http3_candidate(
  candidate: Http3Candidate,
  allow_share: Bool,
  deadline: Int,
) -> Result(PooledHttp3, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining > 0 {
    False -> {
      discard_http3_candidate(candidate, deadline)
      Error(error.new(error.Timeout(error.Total)))
    }
    True ->
      case
        activate_http3_candidate_before(
          candidate.registration,
          candidate.key,
          candidate.connection,
          allow_share,
          deadline,
        )
      {
        Ok(shared) -> {
          let #(connection, lease) = shared
          Ok(PooledHttp3(connection, lease, candidate.key))
        }
        Error(code) -> {
          discard_http3_candidate(candidate, deadline)
          case code, deadline - transport.monotonic_millisecond() > 0 {
            2, _ -> Error(error.new(error.Resource(error.Connections)))
            _, True -> Error(error.new(error.Cancelled))
            _, False -> Error(error.new(error.Timeout(error.Total)))
          }
        }
      }
  }
}

fn adopt_http3_session(
  session: PooledHttp3,
  holder: process.Pid,
  deadline: Int,
) -> Result(Nil, error.Error) {
  case adopt_http3_lease_before(session.lease, holder, deadline) {
    Ok(Nil) -> Ok(Nil)
    Error(_) ->
      case deadline - transport.monotonic_millisecond() > 0 {
        True -> Error(error.new(error.Cancelled))
        False -> Error(error.new(error.Timeout(error.Total)))
      }
  }
}

fn run_http3_session(
  client: Client,
  outgoing: Request(body.Body),
  session: PooledHttp3,
  deadline: Int,
) -> Result(Exchange, error.Error) {
  let outgoing = with_http3_alt_used(client, outgoing)
  http3_exchange.exchange_observed_with_lease_adoption(
    session.connection,
    outgoing,
    deadline,
    fn() { release_http3_session(client, session) },
    fn(holder) { adopt_http3_session(session, holder, deadline) },
    client.trace,
  )
  |> result.map(fn(incoming) { Exchange(incoming, Http3, [], client.trace) })
}

fn run_pooled_http3_session(
  client: Client,
  outgoing: Request(body.Body),
  session: PooledHttp3,
  deadline: Int,
  origin: Origin,
  key: String,
) -> Result(Exchange, error.Error) {
  let http3_outgoing = with_http3_alt_used(client, outgoing)
  case
    http3_exchange.exchange_observed_routable_with_lease_adoption(
      session.connection,
      http3_outgoing,
      deadline,
      fn() { release_http3_session(client, session) },
      fn() { retire_http3_session_before(session, deadline) },
      fn(holder) { adopt_http3_session(session, holder, deadline) },
      client.trace,
    )
  {
    Error(failure) -> Error(failure)
    Ok(http3_exchange.ResponseStarted(incoming)) ->
      Ok(Exchange(incoming, Http3, [], client.trace))
    Ok(http3_exchange.RequestUnstarted(_, source)) -> {
      let outgoing = request.set_body(outgoing, source)
      case
        http3_exchange.await_owner_exit_before(
          connection: session.connection,
          deadline: deadline,
        )
      {
        Ok(Nil) ->
          reroute_unstarted_http3(client, outgoing, deadline, origin, key)
        Error(failure) ->
          dispose_unowned_request(client.trace, outgoing.body, failure)
      }
    }
  }
}

fn reroute_unstarted_http3(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
  origin: Origin,
  key: String,
) -> Result(Exchange, error.Error) {
  let client = Client(..client, trace: client_trace.attempt(client.trace))
  let endpoint_port = http3_endpoint_port(client, outgoing)
  case
    start_new_https_route(
      client,
      outgoing,
      deadline,
      origin,
      endpoint_port,
      key,
    )
  {
    Ok(Exchange(trace: Some(_), ..) as exchange) -> Ok(exchange)
    Ok(exchange) -> Ok(Exchange(..exchange, trace: client.trace))
    Error(failure) ->
      case
        client_trace.claim_finished_if_missing(
          client.trace,
          None,
          Error(failure),
        )
      {
        True -> dispose_unowned_request(client.trace, outgoing.body, failure)
        False -> Error(failure)
      }
  }
}

fn retire_http3_session_before(
  session: PooledHttp3,
  deadline: Int,
) -> Result(Nil, error.Error) {
  case release_http3_lease_before(session.lease, False, deadline) {
    Ok(Nil) -> Ok(Nil)
    Error(_) ->
      case deadline - transport.monotonic_millisecond() > 0 {
        True -> Error(error.new(error.Cancelled))
        False -> Error(error.new(error.Timeout(error.Total)))
      }
  }
}

fn with_http3_alt_used(
  client: Client,
  outgoing: Request(body.Body),
) -> Request(body.Body) {
  request.set_header(
    outgoing,
    "alt-used",
    alt_svc.used_authority(outgoing.host, http3_endpoint_port(client, outgoing)),
  )
}

fn release_http3_session(
  client: Client,
  session: PooledHttp3,
) -> Result(Nil, error.Error) {
  case lifecycle_is_closed(client.lifecycle) {
    True -> {
      // Terminal close already owns the physical registration, connection monitor, and its absolute join deadline.
      // Waiting for that same lifecycle actor here would form a release cycle and quarantine this request's otherwise-complete local lease.
      Ok(Nil)
    }
    False -> {
      let cleanup_deadline =
        transport.monotonic_millisecond() + http3_pool_transition_milliseconds
      let reusable =
        client.config.pooling_enabled && http3_release_reusable(client, session)
      case
        release_http3_lease_before(session.lease, reusable, cleanup_deadline)
      {
        Ok(Nil) -> Ok(Nil)
        Error(_) ->
          case cleanup_deadline - transport.monotonic_millisecond() > 0 {
            True -> Error(error.new(error.Service))
            False -> Error(error.new(error.Timeout(error.Operation)))
          }
      }
    }
  }
}

fn http3_release_reusable(client: Client, session: PooledHttp3) -> Bool {
  case client.config.http3_release_reuse_probe {
    Some(probe) ->
      case probe() {
        Ok(reusable) -> reusable
        Error(Nil) -> False
      }
    None ->
      case http3_exchange.connection_reusable(session.connection) {
        Ok(reusable) -> reusable
        Error(_) -> False
      }
  }
}

fn http3_config(
  client: Client,
  deadline: Int,
  native_trace: Option(h3_client.ConnectTrace),
) -> Result(http3_exchange.Config, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  use <- require(remaining > 0, error.new(error.Timeout(error.Total)))
  let timeouts = client.config.timeouts
  use deadlines <- result.try(
    http3_deadlines(h3_config.default_deadlines(), [
      #(h3_failure.Dns, timeouts.dns_milliseconds),
      #(h3_failure.Connect, timeouts.connect_milliseconds),
      #(h3_failure.Handshake, timeouts.tls_milliseconds),
      #(h3_failure.Operation, timeouts.operation_milliseconds),
      #(h3_failure.Idle, timeouts.idle_milliseconds),
      #(h3_failure.Total, remaining),
    ]),
  )
  let limits = client.config.body_limits
  use native_limits <- result.try(
    h3_config.with_limit(
      h3_config.default_limits(),
      h3_failure.EndpointMemory,
      limits.endpoint_memory_bytes,
    )
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  let native_config =
    h3_client.new()
    |> h3_client.with_deadlines(deadlines)
    |> h3_client.with_limits(native_limits)
  let native_config = case native_trace {
    None -> native_config
    Some(trace) ->
      h3_client.with_connect_trace(client: native_config, trace: trace)
  }
  use native_config <- result.try(
    h3_client.with_stream_buffer_limit(
      native_config,
      limits.stream_buffer_bytes,
    )
    |> result.map_error(map_http3_configuration_error),
  )
  use native_config <- result.try(add_http3_ca_certificates(
    native_config,
    client.config.ca_certificates,
  ))
  use adapter_config <- result.try(http3_exchange.configure(
    native: native_config,
    pull_bytes: limits.stream_buffer_bytes,
    maximum_body_bytes: limits.endpoint_memory_bytes,
    operation_milliseconds: int.min(3_600_000, timeouts.operation_milliseconds),
    idle_milliseconds: int.min(
      3_600_000,
      client.config.pool_limits.idle_milliseconds,
    ),
  ))
  use adapter_config <- result.try(http3_exchange.with_connection_budget(
    adapter_config,
    int.min(3_600_000, remaining),
  ))
  let adapter_config =
    http3_exchange.with_supervision(
      adapter_config,
      client.http3_resources,
      lifecycle_owner(client.lifecycle),
    )
  Ok(case client.config.http3_stream_open_refusal_probe {
    None -> adapter_config
    Some(probe) ->
      http3_exchange.with_stream_open_refusal_probe(adapter_config, probe)
  })
}

fn http3_deadlines(
  deadlines: h3_config.Deadlines,
  phases: List(#(h3_failure.TimeoutPhase, Int)),
) -> Result(h3_config.Deadlines, error.Error) {
  case phases {
    [] -> Ok(deadlines)
    [#(phase, milliseconds), ..rest] -> {
      use deadlines <- result.try(
        h3_config.with_deadline(
          deadlines,
          phase,
          int.min(3_600_000, milliseconds),
        )
        |> result.map_error(fn(_) { security_policy_error() }),
      )
      http3_deadlines(deadlines, rest)
    }
  }
}

fn add_http3_ca_certificates(
  configuration: h3_client.Client,
  certificates: List(BitArray),
) -> Result(h3_client.Client, error.Error) {
  case certificates {
    [] -> Ok(configuration)
    [certificate, ..rest] -> {
      use configuration <- result.try(
        h3_client.with_ca_certificate(configuration, certificate)
        |> result.map_error(map_http3_configuration_error),
      )
      add_http3_ca_certificates(configuration, rest)
    }
  }
}

fn map_http3_configuration_error(
  _failure: h3_client.ConfigurationError,
) -> error.Error {
  security_policy_error()
}

// RFC 6265 section 5.3 evicts cookies that share a domain with more than a predetermined number of others before it evicts any cookie.
// The number here is half the store's own entry ceiling, so no single domain can occupy more than half of it while other domains are being dropped, and a store of one entry still admits a cookie.
fn cookie_domain_ceiling(maximum_entries: Int) -> Int {
  int.max(1, maximum_entries / 2)
}

fn apply_cookie_policy(
  client: Client,
  outgoing: Request(body.Body),
) -> Request(body.Body) {
  case
    client.config.cookie_policy.enabled,
    request.get_header(outgoing, "cookie")
  {
    False, _ -> outgoing
    True, Ok(value) -> set_only_cookie_header(outgoing, value)
    True, Error(_) -> {
      let retained =
        policy_store_list(
          client.cookie_store,
          policy_partition(client.config.network_isolation_key),
        )
      let partition = policy_partition(client.config.network_isolation_key)
      let #(header, accessed) =
        cookie.request_selection(
          retained,
          outgoing.scheme,
          outgoing.host,
          outgoing.path,
          transport.monotonic_millisecond(),
        )
      policy_store_touch(client.cookie_store, partition, accessed)
      case header {
        None -> outgoing
        Some(value) -> set_only_cookie_header(outgoing, value)
      }
    }
  }
}

fn set_only_cookie_header(
  outgoing: Request(body),
  value: String,
) -> Request(body) {
  request.Request(..outgoing, headers: [
    #("cookie", value),
    ..list.filter(outgoing.headers, fn(header) {
      string.lowercase(header.0) != "cookie"
    })
  ])
}

fn apply_hsts_policy(client: Client, outgoing: Request(body)) -> Request(body) {
  case outgoing.scheme, client.config.hsts_policy.enabled {
    Https, _ | Http, False -> outgoing
    Http, True -> {
      let policies =
        hsts_store_list(
          client.hsts_store,
          policy_partition(client.config.network_isolation_key),
        )
      case
        hsts.applies(policies, outgoing.host, transport.monotonic_millisecond())
      {
        False -> outgoing
        True -> {
          let port = hsts.upgrade_port(outgoing.port)
          request.Request(..outgoing, scheme: Https, port:)
        }
      }
    }
  }
}

fn capture_response_policies(
  client: Client,
  outgoing: Request(body.Body),
  completed: Exchange,
) -> Nil {
  let incoming = completed.response
  capture_response_cookies(client, outgoing, incoming)
  capture_hsts_headers(
    client,
    outgoing,
    incoming.headers,
    transport.monotonic_millisecond(),
  )
  case incoming.status, completed.selected_protocol {
    421, Http3 ->
      invalidate_alt_svc_policy(
        client,
        outgoing,
        transport.monotonic_millisecond(),
      )
    421, _ -> Nil
    _, _ ->
      capture_alt_svc_headers(
        client,
        outgoing,
        incoming.headers,
        transport.monotonic_millisecond(),
        response_age_seconds(incoming),
      )
  }
  invalidate_cache_entry(client, outgoing, incoming.status)
}

fn response_age_seconds(incoming: Response(body)) -> Int {
  case response.get_header(incoming, "age") {
    Error(_) -> 0
    Ok(value) ->
      case int.parse(string.trim(value)) {
        Ok(age) if age >= 0 -> age
        _ -> 0
      }
  }
}

fn invalidate_cache_entry(
  client: Client,
  outgoing: Request(body),
  status: Int,
) -> Nil {
  case
    client.config.cache_policy.enabled,
    cache.invalidated_key(outgoing, status)
  {
    True, Some(key) -> {
      let now = transport.monotonic_millisecond()
      let _removed = store_cache_policy(client, cache.tombstone(key, now), now)
      Nil
    }
    _, _ -> Nil
  }
}

fn capture_response_cookies(
  client: Client,
  outgoing: Request(body.Body),
  incoming: Response(body.Body),
) -> Nil {
  case client.config.cookie_policy.enabled {
    False -> Nil
    True ->
      capture_cookie_headers(
        client: client,
        headers: incoming.headers,
        scheme: outgoing.scheme,
        host: outgoing.host,
        path: outgoing.path,
        now: transport.monotonic_millisecond(),
      )
  }
}

fn capture_hsts_headers(
  client: Client,
  outgoing: Request(body),
  headers: List(#(String, String)),
  now: Int,
) -> Nil {
  case outgoing.scheme, client.config.hsts_policy.enabled, headers {
    _, False, _ | Http, _, _ | _, _, [] -> Nil
    Https, True, [#(name, value), ..rest] -> {
      case string.lowercase(name) {
        "strict-transport-security" -> {
          case hsts.parse(value, outgoing.host, now) {
            Some(entry) -> {
              let _stored = store_hsts_policy(client, entry, now)
              Nil
            }
            None -> Nil
          }
        }
        _ -> capture_hsts_headers(client, outgoing, rest, now)
      }
    }
  }
}

fn capture_alt_svc_headers(
  client: Client,
  outgoing: Request(body),
  headers: List(#(String, String)),
  now: Int,
  response_age_seconds: Int,
) -> Nil {
  case outgoing.scheme, client.config.discovery_policy.enabled {
    _, False | Http, _ -> Nil
    Https, True -> {
      let origin = request_origin(outgoing)
      case
        first_alt_svc_entry(
          headers,
          outgoing.host,
          origin.port,
          now,
          response_age_seconds,
        )
      {
        Some(entry) -> {
          let _stored = store_alt_svc_policy(client, entry, now)
          Nil
        }
        None -> Nil
      }
    }
  }
}

fn first_alt_svc_entry(
  headers: List(#(String, String)),
  host: String,
  port: Int,
  now: Int,
  response_age_seconds: Int,
) -> Option(alt_svc.Entry) {
  case alt_svc_clear_requested(headers) {
    True -> alt_svc.parse("clear", host, port, now)
    False ->
      first_supported_alt_svc_entry(
        headers,
        host,
        port,
        now,
        response_age_seconds,
      )
  }
}

fn alt_svc_clear_requested(headers: List(#(String, String))) -> Bool {
  list.any(headers, fn(field) {
    string.lowercase(field.0) == "alt-svc" && alt_svc.requests_clear(field.1)
  })
}

fn first_supported_alt_svc_entry(
  headers: List(#(String, String)),
  host: String,
  port: Int,
  now: Int,
  response_age_seconds: Int,
) -> Option(alt_svc.Entry) {
  case headers {
    [] -> None
    [#(name, value), ..rest] ->
      case string.lowercase(name) {
        "alt-svc" ->
          case
            alt_svc.parse_with_age(value, host, port, now, response_age_seconds)
          {
            Some(entry) -> Some(entry)
            None ->
              first_supported_alt_svc_entry(
                rest,
                host,
                port,
                now,
                response_age_seconds,
              )
          }
        _ ->
          first_supported_alt_svc_entry(
            rest,
            host,
            port,
            now,
            response_age_seconds,
          )
      }
  }
}

fn invalidate_alt_svc_policy(
  client: Client,
  outgoing: Request(body),
  now: Int,
) -> Nil {
  let origin = request_origin(outgoing)
  case alt_svc.parse("clear", outgoing.host, origin.port, now) {
    Some(entry) -> {
      // Always remove the live in-memory route, even if a persistence adapter has stopped.
      // A future client load will validate and reauthenticate any independently retained record before use.
      let key = alt_svc.key(entry.origin_host, entry.origin_port)
      let _removed =
        alt_svc_store_put(
          client.alt_svc_store,
          policy_partition(client.config.network_isolation_key),
          key,
          entry,
          entry.expires_at,
          entry.retained_bytes,
        )
      let _persisted = persist_alt_svc_policy(client, entry, now)
      Nil
    }
    None -> Nil
  }
}

fn capture_cookie_headers(
  client client: Client,
  headers headers: List(#(String, String)),
  scheme scheme: Scheme,
  host host: String,
  path path: String,
  now now: Int,
) -> Nil {
  case headers {
    [] -> Nil
    [#(name, value), ..rest] -> {
      case
        string.lowercase(name),
        cookie.parse_with_unix_milliseconds(
          value,
          scheme,
          host,
          path,
          now,
          transport.unix_millisecond(),
        )
      {
        "set-cookie", Some(parsed) -> {
          let _stored = store_cookie_policy(client, parsed, now)
          Nil
        }
        _, _ -> Nil
      }
      capture_cookie_headers(
        client: client,
        headers: rest,
        scheme: scheme,
        host: host,
        path: path,
        now: now,
      )
    }
  }
}

fn store_cookie_policy(client: Client, entry: cookie.Cookie, now: Int) -> Bool {
  let partition = policy_partition(client.config.network_isolation_key)
  let entry = case
    cookie_store_get(client.cookie_store, partition, cookie.key(entry))
  {
    Ok(previous) -> cookie.with_creation(entry, previous.creation_milliseconds)
    Error(_) -> entry
  }
  case persist_cookie_policy(client, entry, now) {
    False -> False
    True ->
      policy_store_put_grouped(
        client.cookie_store,
        partition,
        cookie.key(entry),
        entry,
        entry.expires_at,
        entry.retained_bytes,
        entry.domain,
      )
  }
}

fn persist_cookie_policy(
  client: Client,
  entry: cookie.Cookie,
  now: Int,
) -> Bool {
  case client.config.cookie_store_adapter {
    None -> True
    Some(adapter) -> {
      let operation = case entry.expires_at <= now, entry.persistent {
        True, _ | _, False -> fn() {
          client_store.remove(
            adapter,
            adapter_partition(client.config),
            cookie.key(entry),
          )
        }
        False, True -> fn() {
          client_store.put(
            adapter,
            adapter_partition(client.config),
            client_store.CookieRecord(
              key: cookie.key(entry),
              name: entry.name,
              value: entry.value,
              domain: entry.domain,
              path: entry.path,
              host_only: entry.host_only,
              secure: entry.secure,
              expires_in_milliseconds: entry.expires_at - now,
              age_milliseconds: int.max(0, now - entry.creation_milliseconds),
            ),
          )
        }
      }
      policy_adapter_succeeded(run_policy_adapter(adapter, operation))
    }
  }
}

fn store_cache_policy(client: Client, entry: cache.Entry, now: Int) -> Bool {
  case persist_cache_policy(client, entry, now) {
    False -> False
    True ->
      cache_store_put(
        client.cache_store,
        policy_partition(client.config.network_isolation_key),
        entry.key,
        entry,
        entry.expires_at,
        entry.retained_bytes,
      )
  }
}

fn persist_cache_policy(client: Client, entry: cache.Entry, now: Int) -> Bool {
  case client.config.cache_store_adapter {
    None -> True
    Some(adapter) -> {
      let operation = case entry.expires_at <= now {
        True -> fn() {
          client_store.remove(
            adapter,
            adapter_partition(client.config),
            entry.key,
          )
        }
        False -> fn() {
          client_store.put(
            adapter,
            adapter_partition(client.config),
            client_store.CacheRecord(
              key: entry.key,
              status: entry.status,
              headers: entry.headers,
              bytes: entry.bytes,
              trailers: entry.trailers,
              expires_in_milliseconds: entry.expires_at - now,
            ),
          )
        }
      }
      policy_adapter_succeeded(run_policy_adapter(adapter, operation))
    }
  }
}

fn store_hsts_policy(client: Client, entry: hsts.Entry, now: Int) -> Bool {
  case persist_hsts_policy(client, entry, now) {
    False -> False
    True ->
      hsts_store_put(
        client.hsts_store,
        policy_partition(client.config.network_isolation_key),
        entry.host,
        entry,
        entry.expires_at,
        entry.retained_bytes,
      )
  }
}

fn persist_hsts_policy(client: Client, entry: hsts.Entry, now: Int) -> Bool {
  case client.config.hsts_store_adapter {
    None -> True
    Some(adapter) -> {
      let operation = case entry.expires_at <= now {
        True -> fn() {
          client_store.remove(
            adapter,
            adapter_partition(client.config),
            entry.host,
          )
        }
        False -> fn() {
          client_store.put(
            adapter,
            adapter_partition(client.config),
            client_store.HstsRecord(
              key: entry.host,
              host: entry.host,
              include_subdomains: entry.include_subdomains,
              expires_in_milliseconds: entry.expires_at - now,
            ),
          )
        }
      }
      policy_adapter_succeeded(run_policy_adapter(adapter, operation))
    }
  }
}

fn store_alt_svc_policy(
  client: Client,
  entry: alt_svc.Entry,
  now: Int,
) -> Bool {
  case persist_alt_svc_policy(client, entry, now) {
    False -> False
    True -> {
      let key = alt_svc.key(entry.origin_host, entry.origin_port)
      alt_svc_store_put(
        client.alt_svc_store,
        policy_partition(client.config.network_isolation_key),
        key,
        entry,
        entry.expires_at,
        entry.retained_bytes,
      )
    }
  }
}

fn persist_alt_svc_policy(
  client: Client,
  entry: alt_svc.Entry,
  now: Int,
) -> Bool {
  case client.config.alt_svc_store_adapter {
    None -> True
    Some(adapter) -> {
      let key = alt_svc.key(entry.origin_host, entry.origin_port)
      let operation = case entry.expires_at <= now {
        True -> fn() {
          client_store.remove(adapter, adapter_partition(client.config), key)
        }
        False -> fn() {
          client_store.put(
            adapter,
            adapter_partition(client.config),
            client_store.AltSvcRecord(
              key:,
              origin_host: entry.origin_host,
              origin_port: entry.origin_port,
              alternative_port: entry.alternative_port,
              expires_in_milliseconds: entry.expires_at - now,
            ),
          )
        }
      }
      policy_adapter_succeeded(run_policy_adapter(adapter, operation))
    }
  }
}

fn policy_adapter_succeeded(outcome: Result(value, error.Error)) -> Bool {
  case outcome {
    Ok(_) -> True
    Error(_) -> False
  }
}

fn policy_partition(key: NetworkIsolationKey) -> String {
  int.to_string(string.byte_size(key.top_level_site))
  <> ":"
  <> key.top_level_site
  <> int.to_string(string.byte_size(key.profile))
  <> ":"
  <> key.profile
}

fn cached_response(
  client: Client,
  outgoing: Request(BitArray),
) -> Option(Response(body.Body)) {
  case client.config.cache_policy.enabled, cache.key(outgoing) {
    True, Some(key) ->
      case
        cache_store_get(
          client.cache_store,
          policy_partition(client.config.network_isolation_key),
          key,
        )
      {
        Ok(entry) ->
          Some(cache.response(entry, transport.monotonic_millisecond()))
        Error(_) -> None
      }
    _, _ -> None
  }
}

fn buffer_response(
  client: Client,
  outgoing: Request(Nil),
  completed: Exchange,
  maximum_bytes: Int,
) -> Result(Response(body.Body), error.Error) {
  let incoming = completed.response
  case body.read_all(incoming.body, maximum_bytes) {
    Ok(#(bytes, trailers)) -> {
      store_cache_entry(client, outgoing, completed, bytes, trailers)
      Ok(response.set_body(
        incoming,
        body.from_bytes_with_trailers(bytes, trailers),
      ))
    }
    Error(failure) -> {
      body.cancel(incoming.body)
      Error(failure)
    }
  }
}

fn store_cache_entry(
  client: Client,
  outgoing: Request(Nil),
  completed: Exchange,
  bytes: BitArray,
  trailers: body.Headers,
) -> Nil {
  case
    client.config.cache_policy.enabled,
    completed.redirect_history,
    cache.entry(
      outgoing,
      completed.response,
      bytes,
      trailers,
      transport.monotonic_millisecond(),
    )
  {
    True, [], Some(entry) -> {
      let _stored =
        store_cache_policy(client, entry, transport.monotonic_millisecond())
      Nil
    }
    _, _, _ -> Nil
  }
}

fn redirect_location(incoming: Response(body.Body)) -> Option(String) {
  case incoming.status {
    301 | 302 | 303 | 307 | 308 ->
      case response.get_header(incoming, "location") {
        Ok(location) -> Some(location)
        Error(Nil) -> None
      }
    _ -> None
  }
}

fn with_redirect_history(
  exchange: Exchange,
  reversed_history: List(RedirectHop),
) -> Exchange {
  Exchange(..exchange, redirect_history: list.reverse(reversed_history))
}

fn request_origin(outgoing: Request(body)) -> Origin {
  Origin(
    outgoing.scheme,
    string.lowercase(outgoing.host),
    case outgoing.port, outgoing.scheme {
      Some(port), _ -> port
      None, Http -> 80
      None, Https -> 443
    },
  )
}

fn http1_config(
  client: Client,
  maximum_total_milliseconds: Int,
) -> Result(http1_exchange.Config, error.Error) {
  let config = client.config
  let Timeouts(
    dns_milliseconds: dns,
    connect_milliseconds: connect,
    tls_milliseconds: tls,
    operation_milliseconds: operation,
    idle_milliseconds: idle,
    total_milliseconds: configured_total,
  ) = config.timeouts
  let total = smallest(configured_total, maximum_total_milliseconds)
  use http1 <- result.try(http1_exchange.with_dns_timeout(
    http1_exchange.defaults(),
    dns,
  ))
  use http1 <- result.try(http1_exchange.with_timeouts(
    http1,
    connect,
    tls,
    operation,
    idle,
    total,
  ))
  use http1 <- result.try(http1_exchange.with_body_limits(
    http1,
    config.body_limits.endpoint_memory_bytes,
    config.body_limits.stream_buffer_bytes,
  ))
  let http1 = http1_exchange.with_ca_certificates(http1, config.ca_certificates)
  let http1 =
    http1
    |> http1_exchange.without_reused_connection_retry
    |> http1_exchange.with_trace(client.trace)
  let http1 =
    http1
    |> http1_exchange.with_connect_trace(client.trace)
    |> http1_exchange.with_supervision(
      resources: client.http3_resources,
      lifecycle_owner: lifecycle_owner(client.lifecycle),
    )
  let http1 = case config.proxy_policy.proxy {
    None -> http1
    Some(proxy) ->
      http1_exchange.with_proxy(
        http1,
        proxy.host,
        proxy.port,
        proxy.authorization,
      )
  }
  let http1 =
    http1_exchange.with_lifecycle(
      http1,
      fn(origin, socket) {
        attach_socket(
          lifecycle: client.lifecycle,
          origin: origin,
          socket: socket,
        )
      },
      fn() { lifecycle_is_closed(client.lifecycle) },
    )
  let http1 =
    http1_exchange.with_admission(
      http1,
      fn(origin) { reserve_tcp_socket(client.lifecycle, origin) },
      fn(previous, socket) {
        replace_registered_socket(client.lifecycle, previous, socket)
        |> result.map_error(fn(_) { error.new(error.Cancelled) })
      },
    )
  case config.pooling_enabled {
    False -> Ok(http1)
    True ->
      Ok(
        http1_exchange.with_pool(
          http1,
          fn(origin) { checkout_socket(client.lifecycle, origin) },
          fn(origin, socket) {
            checkin_socket(client.lifecycle, origin, socket)
          },
        ),
      )
  }
}

fn http2_config(
  client: Client,
  maximum_total_milliseconds: Int,
) -> Result(http2_exchange.Config, error.Error) {
  let config = client.config
  let Timeouts(
    dns_milliseconds: dns,
    connect_milliseconds: connect,
    tls_milliseconds: tls,
    operation_milliseconds: operation,
    idle_milliseconds: idle,
    total_milliseconds: configured_total,
  ) = config.timeouts
  let total = smallest(configured_total, maximum_total_milliseconds)
  use http2 <- result.try(http2_exchange.with_timeouts(
    http2_exchange.defaults(),
    dns,
    connect,
    tls,
    operation,
    idle,
    total,
  ))
  use http2 <- result.try(http2_exchange.with_body_limits(
    http2,
    config.body_limits.endpoint_memory_bytes,
    config.body_limits.stream_buffer_bytes,
  ))
  let http2 =
    http2
    |> http2_exchange.with_ca_certificates(config.ca_certificates)
    |> http2_exchange.with_trace(client.trace)
    |> http2_exchange.with_connect_trace(client.trace)
    |> http2_exchange.with_supervision(
      resources: client.http3_resources,
      lifecycle_owner: lifecycle_owner(client.lifecycle),
    )
    |> http2_exchange.with_lifecycle(
      fn(origin, socket) {
        attach_socket(
          lifecycle: client.lifecycle,
          origin: origin,
          socket: socket,
        )
      },
      fn() { lifecycle_is_closed(client.lifecycle) },
    )
    |> http2_exchange.with_owner_adoption(fn(socket, owner) {
      transfer_and_adopt_registered_socket_owner(
        client.lifecycle,
        socket,
        owner,
      )
      |> result.map_error(fn(_) { error.new(error.Cancelled) })
    })
  let http2 =
    http2_exchange.with_admission(
      http2,
      fn(origin) { reserve_tcp_socket(client.lifecycle, origin) },
      fn(previous, socket) {
        replace_registered_socket(client.lifecycle, previous, socket)
        |> result.map_error(fn(_) { error.new(error.Cancelled) })
      },
    )
  let http2 = case config.proxy_policy.proxy {
    None -> http2
    Some(proxy) ->
      http2_exchange.with_proxy(
        http2,
        proxy.host,
        proxy.port,
        proxy.authorization,
      )
  }
  case config.pooling_enabled {
    False -> Ok(http2)
    True ->
      Ok(
        http2_exchange.with_pool(
          http2,
          fn(origin) {
            checkout_http2(client.http2_pool, client.lifecycle, origin)
          },
          fn(origin, socket, state, cleanup) {
            checkin_http2(
              client.http2_pool,
              client.lifecycle,
              origin,
              socket,
              state,
              cleanup,
            )
          },
        )
        |> http2_exchange.with_http1_pool(fn(origin) {
          checkout_socket(client.lifecycle, origin)
        }),
      )
  }
}

fn checkout_http2(
  pool: Http2Pool,
  lifecycle: Lifecycle,
  origin: String,
) -> Result(
  Option(#(transport.Socket, http2_wire.State, fn() -> Nil)),
  error.Error,
) {
  case raw_checkout_http2(pool, lifecycle, origin) {
    Ok(session) -> Ok(Some(session))
    Error(0) -> Ok(None)
    Error(_) -> Error(error.new(error.Cancelled))
  }
}

fn checkout_socket(
  lifecycle: Lifecycle,
  origin: String,
) -> Result(Option(transport.Socket), error.Error) {
  case raw_checkout_socket(lifecycle, origin) {
    Ok(socket) -> Ok(Some(socket))
    Error(0) -> Ok(None)
    Error(_) -> Error(error.new(error.Cancelled))
  }
}

fn reserve_tcp_socket(
  lifecycle: Lifecycle,
  origin: String,
) -> Result(tcp_reservation.Reservation, error.Error) {
  case reserve_resource(lifecycle, origin) {
    Error(2) -> Error(error.new(error.Resource(error.Connections)))
    Error(_) -> Error(error.new(error.Cancelled))
    Ok(registration) ->
      Ok(
        tcp_reservation.new(
          fn(socket) {
            attach_reserved_socket(registration, socket)
            |> result.map_error(fn(_) { error.new(error.Cancelled) })
          },
          fn() { cancel_resource(registration) },
        ),
      )
  }
}

fn reserve_tcp_socket_until(
  lifecycle: Lifecycle,
  origin: String,
  deadline: Int,
) -> Result(tcp_reservation.Reservation, error.Error) {
  use registration <- result.try(
    reserve_resource_before(lifecycle, origin, deadline)
    |> result.map_error(fn(code) { race_lifecycle_failure(code, deadline) }),
  )
  Ok(
    tcp_reservation.new(
      fn(socket) {
        attach_reserved_socket_before(registration, socket, deadline)
        |> result.map_error(fn(code) { race_lifecycle_failure(code, deadline) })
      },
      fn() {
        let _released = cancel_resource_until(registration, deadline)
        Nil
      },
    ),
  )
}

fn race_lifecycle_failure(code: Int, deadline: Int) -> error.Error {
  case code, deadline > transport.monotonic_millisecond() {
    2, _ -> error.new(error.Resource(error.Connections))
    _, True -> error.new(error.Cancelled)
    _, False -> error.new(error.Timeout(error.Total))
  }
}

fn attach_socket(
  lifecycle lifecycle: Lifecycle,
  origin origin: String,
  socket socket: transport.Socket,
) -> Result(fn() -> Nil, error.Error) {
  case register_socket(lifecycle, origin, socket) {
    Error(2) -> Error(error.new(error.Resource(error.Connections)))
    Error(_) -> Error(error.new(error.Cancelled))
    Ok(registration) -> Ok(fn() { unregister_socket(registration) })
  }
}

fn cancel_resource_until(registration: Registration, deadline: Int) -> Bool {
  retire_http3_candidate_confirmed_before(registration, deadline) == Ok(Nil)
}

fn start_tcp_race_guard(
  client: Client,
  candidate: Registration,
  deadline: Int,
) -> Result(TcpRaceGuard, error.Error) {
  use lease <- result.try(resource.acquire(
    client.http3_resources,
    memory_bytes: 0,
  ))
  let cancellation = new_race_cancellation()
  let ready = process.new_subject()
  let requester = process.self()
  let lifecycle = lifecycle_owner(client.lifecycle)
  let pid =
    process.spawn_unlinked(fn() {
      process_role.set(process_role.ClientRaceGuardian)
      let commands = process.new_subject()
      let requester = process.monitor(requester)
      let lifecycle = process.monitor(lifecycle)
      process.send(ready, commands)
      let cleanup_confirmed =
        tcp_race_guard_loop(TcpRaceRuntime(
          commands:,
          cancellation:,
          guarded: None,
          next_identifier: 1,
          requester:,
          lifecycle:,
          deadline:,
          candidate:,
          helpers: [],
          cleanup_confirmed: True,
          join_confirmation: client.config.race_join_confirmation,
          claim_offer_confirmation: client.config.race_claim_offer_confirmation,
        ))
      process.demonitor_process(requester)
      process.demonitor_process(lifecycle)
      case cleanup_confirmed {
        True -> resource.release(lease)
        False -> Nil
      }
    })
  case
    process.receive(
      ready,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  {
    Ok(commands) ->
      Ok(TcpRaceGuard(
        commands,
        cancellation,
        pid,
        deadline,
        client.config.race_join_confirmation,
        client.config.race_claim_commit_confirmation,
      ))
    Error(Nil) -> {
      let monitor = process.monitor(pid)
      mark_race_cancelled(cancellation)
      process.kill(pid)
      case
        join_race_helper_until(
          pid,
          monitor,
          deadline,
          client.config.race_join_confirmation,
        )
      {
        True -> {
          resource.release(lease)
          Error(error.new(error.Service))
        }
        False -> Error(error.new(error.Timeout(error.Operation)))
      }
    }
  }
}

fn tcp_race_guard_loop(runtime: TcpRaceRuntime) -> Bool {
  let selected =
    process.new_selector()
    |> process.select_map(runtime.commands, Some)
    |> process.select_specific_monitor(runtime.requester, fn(_) { None })
    |> process.select_specific_monitor(runtime.lifecycle, fn(_) { None })
    |> process.selector_receive(within: int.max(
      0,
      runtime.deadline - transport.monotonic_millisecond(),
    ))
  case selected {
    Error(Nil) | Ok(None) -> {
      mark_race_cancelled(runtime.cancellation)
      let socket_confirmed =
        close_optional_guarded_socket(runtime.guarded, runtime.deadline)
      let candidate_confirmed =
        cancel_resource_until(runtime.candidate, runtime.deadline)
      let contenders_confirmed =
        stop_race_contenders(
          runtime.helpers,
          runtime.join_confirmation,
          runtime.deadline,
        )
      runtime.cleanup_confirmed
      && socket_confirmed
      && candidate_confirmed
      && contenders_confirmed
    }
    Ok(Some(RaceStart(http3, tcp, reply))) -> {
      let http3 =
        process.spawn_unlinked(fn() {
          process_role.set(process_role.ClientConnectionCandidate)
          http3()
        })
      let tcp =
        process.spawn_unlinked(fn() {
          process_role.set(process_role.ClientConnectionCandidate)
          tcp()
        })
      process.send(reply, #(http3, tcp))
      tcp_race_guard_loop(TcpRaceRuntime(..runtime, helpers: [http3, tcp]))
    }
    Ok(Some(RaceAttach(socket, cleanup, cleanup_before, reply))) ->
      case race_is_cancelled(runtime.cancellation), runtime.guarded {
        True, _ | False, Some(_) -> {
          let closed =
            close_race_socket(socket, cleanup_before, runtime.deadline)
          process.send(reply, Error(Nil))
          tcp_race_guard_loop(
            TcpRaceRuntime(
              ..runtime,
              cleanup_confirmed: runtime.cleanup_confirmed && closed,
            ),
          )
        }
        False, None -> {
          process.send(reply, Ok(runtime.next_identifier))
          tcp_race_guard_loop(
            TcpRaceRuntime(
              ..runtime,
              guarded: Some(GuardedSocket(
                runtime.next_identifier,
                socket,
                cleanup,
                cleanup_before,
              )),
              next_identifier: runtime.next_identifier + 1,
            ),
          )
        }
      }
    Ok(Some(RaceRelease(identifier))) ->
      case runtime.guarded {
        Some(GuardedSocket(current, _, _, cleanup_before))
          if current == identifier
        -> {
          let released = cleanup_before(runtime.deadline)
          tcp_race_guard_loop(
            TcpRaceRuntime(
              ..runtime,
              guarded: None,
              cleanup_confirmed: runtime.cleanup_confirmed && released,
            ),
          )
        }
        _ -> tcp_race_guard_loop(runtime)
      }
    Ok(Some(RaceCancel(reply))) -> {
      mark_race_cancelled(runtime.cancellation)
      let socket_confirmed =
        close_optional_guarded_socket(runtime.guarded, runtime.deadline)
      let candidate_confirmed =
        cancel_resource_until(runtime.candidate, runtime.deadline)
      let contenders_confirmed =
        stop_race_contenders(
          runtime.helpers,
          runtime.join_confirmation,
          runtime.deadline,
        )
      let confirmed =
        runtime.cleanup_confirmed
        && socket_confirmed
        && candidate_confirmed
        && contenders_confirmed
      process.send(reply, confirmed)
      confirmed
    }
    Ok(Some(RaceSelectHttp3(reply))) -> {
      mark_race_cancelled(runtime.cancellation)
      let socket_confirmed =
        close_optional_guarded_socket(runtime.guarded, runtime.deadline)
      let contenders_confirmed =
        stop_race_contenders(
          runtime.helpers,
          runtime.join_confirmation,
          runtime.deadline,
        )
      let confirmed =
        runtime.cleanup_confirmed && socket_confirmed && contenders_confirmed
      process.send(reply, confirmed)
      confirmed
    }
    Ok(Some(RaceClaim(reply))) -> {
      let candidate_confirmed =
        cancel_resource_until(runtime.candidate, runtime.deadline)
      let loser_confirmed =
        stop_race_contenders(
          http3_race_contenders(runtime.helpers),
          runtime.join_confirmation,
          runtime.deadline,
        )
      let confirmed =
        runtime.cleanup_confirmed && candidate_confirmed && loser_confirmed
      case confirmed, runtime.guarded {
        True, Some(GuardedSocket(identifier, _, cleanup, _) as guarded) -> {
          case runtime.claim_offer_confirmation {
            True -> {
              process.send(reply, Ok(TcpRaceClaimOffer(identifier, cleanup)))
              await_tcp_race_claim_commit(runtime, guarded, runtime.deadline)
            }
            False -> {
              mark_race_cancelled(runtime.cancellation)
              let closed =
                close_optional_guarded_socket(Some(guarded), runtime.deadline)
              let winner_stopped =
                stop_race_contenders(
                  tcp_race_contenders(runtime.helpers),
                  runtime.join_confirmation,
                  runtime.deadline,
                )
              runtime.cleanup_confirmed && closed && winner_stopped
            }
          }
        }
        False, Some(guarded) -> {
          mark_race_cancelled(runtime.cancellation)
          let closed =
            close_optional_guarded_socket(Some(guarded), runtime.deadline)
          let winner_stopped =
            stop_race_contenders(
              tcp_race_contenders(runtime.helpers),
              runtime.join_confirmation,
              runtime.deadline,
            )
          process.send(reply, Error(False))
          confirmed && closed && winner_stopped
        }
        _, None -> {
          mark_race_cancelled(runtime.cancellation)
          let _winner_stopped =
            stop_race_contenders(
              tcp_race_contenders(runtime.helpers),
              runtime.join_confirmation,
              runtime.deadline,
            )
          process.send(reply, Error(False))
          False
        }
      }
    }
    Ok(Some(RaceCommit(_, reply))) -> {
      process.send(reply, False)
      tcp_race_guard_loop(runtime)
    }
  }
}

fn await_tcp_race_claim_commit(
  runtime: TcpRaceRuntime,
  guarded: GuardedSocket,
  deadline: Int,
) -> Bool {
  let selected =
    process.new_selector()
    |> process.select_map(runtime.commands, Some)
    |> process.select_specific_monitor(runtime.requester, fn(_) { None })
    |> process.select_specific_monitor(runtime.lifecycle, fn(_) { None })
    |> process.selector_receive(within: int.max(
      0,
      deadline - transport.monotonic_millisecond(),
    ))
  let GuardedSocket(identifier, _, _, _) = guarded
  case selected {
    Error(Nil) | Ok(None) -> {
      mark_race_cancelled(runtime.cancellation)
      let closed = close_optional_guarded_socket(Some(guarded), deadline)
      let winner_stopped =
        stop_race_contenders(
          tcp_race_contenders(runtime.helpers),
          runtime.join_confirmation,
          deadline,
        )
      closed && winner_stopped
    }
    Ok(Some(RaceCommit(offered, reply))) if offered == identifier -> {
      let winner_stopped =
        stop_race_contenders(
          tcp_race_contenders(runtime.helpers),
          runtime.join_confirmation,
          deadline,
        )
      let confirmed = runtime.cleanup_confirmed && winner_stopped
      process.send(reply, confirmed)
      confirmed
    }
    Ok(Some(RaceCommit(_, reply))) -> {
      process.send(reply, False)
      await_tcp_race_claim_commit(runtime, guarded, deadline)
    }
    Ok(Some(RaceRelease(released))) if released == identifier -> {
      mark_race_cancelled(runtime.cancellation)
      let closed = close_optional_guarded_socket(Some(guarded), deadline)
      let winner_stopped =
        stop_race_contenders(
          tcp_race_contenders(runtime.helpers),
          runtime.join_confirmation,
          deadline,
        )
      closed && winner_stopped
    }
    Ok(Some(RaceRelease(_))) ->
      await_tcp_race_claim_commit(runtime, guarded, deadline)
    Ok(Some(RaceCancel(reply))) | Ok(Some(RaceSelectHttp3(reply))) -> {
      mark_race_cancelled(runtime.cancellation)
      let closed = close_optional_guarded_socket(Some(guarded), deadline)
      let winner_stopped =
        stop_race_contenders(
          tcp_race_contenders(runtime.helpers),
          runtime.join_confirmation,
          deadline,
        )
      let confirmed = runtime.cleanup_confirmed && closed && winner_stopped
      process.send(reply, confirmed)
      confirmed
    }
    Ok(Some(RaceClaim(reply))) -> {
      process.send(reply, Error(True))
      await_tcp_race_claim_commit(runtime, guarded, deadline)
    }
    Ok(Some(RaceAttach(socket, _, cleanup_before, reply))) -> {
      let closed = close_race_socket(socket, cleanup_before, deadline)
      process.send(reply, Error(Nil))
      let committed = await_tcp_race_claim_commit(runtime, guarded, deadline)
      closed && committed
    }
    Ok(Some(RaceStart(_, _, _))) ->
      await_tcp_race_claim_commit(runtime, guarded, deadline)
  }
}

fn start_race_contenders(
  guard: TcpRaceGuard,
  http3: fn() -> Nil,
  tcp: fn() -> Nil,
) -> Result(#(process.Pid, process.Pid), error.Error) {
  let reply = process.new_subject()
  process.send(guard.commands, RaceStart(http3, tcp, reply))
  case
    process.receive(
      reply,
      within: int.max(0, guard.deadline - transport.monotonic_millisecond()),
    )
  {
    Ok(contenders) -> Ok(contenders)
    Error(Nil) -> {
      case cancel_tcp_race_guard(guard) {
        True -> Error(error.new(error.Cancelled))
        False -> Error(error.new(error.Timeout(error.Operation)))
      }
    }
  }
}

fn stop_race_contenders(
  contenders: List(process.Pid),
  confirmation: Bool,
  deadline: Int,
) -> Bool {
  let monitored = monitor_race_contenders(contenders)
  kill_race_contenders(monitored)
  join_race_contenders(monitored, confirmation, deadline)
}

fn monitor_race_contenders(
  contenders: List(process.Pid),
) -> List(#(process.Pid, process.Monitor)) {
  case contenders {
    [] -> []
    [pid, ..rest] -> {
      let monitor = process.monitor(pid)
      [#(pid, monitor), ..monitor_race_contenders(rest)]
    }
  }
}

fn kill_race_contenders(
  contenders: List(#(process.Pid, process.Monitor)),
) -> Nil {
  case contenders {
    [] -> Nil
    [#(pid, _), ..rest] -> {
      process.kill(pid)
      kill_race_contenders(rest)
    }
  }
}

fn join_race_contenders(
  contenders: List(#(process.Pid, process.Monitor)),
  confirmation: Bool,
  deadline: Int,
) -> Bool {
  case contenders {
    [] -> True
    [#(_, monitor), ..rest] -> {
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: int.max(
          0,
          deadline - transport.monotonic_millisecond(),
        ))
      process.demonitor_process(monitor)
      let rest_joined = join_race_contenders(rest, confirmation, deadline)
      joined == Ok(Nil) && confirmation && rest_joined
    }
  }
}

fn http3_race_contenders(contenders: List(process.Pid)) -> List(process.Pid) {
  case contenders {
    [http3, _, ..] -> [http3]
    _ -> []
  }
}

fn tcp_race_contenders(contenders: List(process.Pid)) -> List(process.Pid) {
  case contenders {
    [_, tcp, ..] -> [tcp]
    _ -> []
  }
}

fn attach_tcp_race_socket(
  client: Client,
  guard: TcpRaceGuard,
  origin: String,
  socket: transport.Socket,
) -> Result(fn() -> Nil, error.Error) {
  use registration <- result.try(
    register_socket_before(client.lifecycle, origin, socket, guard.deadline)
    |> result.map_error(fn(code) {
      case code, guard.deadline - transport.monotonic_millisecond() > 0 {
        2, _ -> error.new(error.Resource(error.Connections))
        _, True -> error.new(error.Cancelled)
        _, False -> error.new(error.Timeout(error.Total))
      }
    }),
  )
  let cleanup = fn() {
    let _released = unregister_socket_before(registration, guard.deadline)
    Nil
  }
  let cleanup_before = fn(deadline) {
    unregister_socket_before(registration, deadline)
  }
  case race_is_cancelled(guard.cancellation) {
    True -> {
      let _closed = close_race_socket(socket, cleanup_before, guard.deadline)
      Error(error.new(error.Cancelled))
    }
    False -> {
      let reply = process.new_subject()
      process.send(
        guard.commands,
        RaceAttach(socket, cleanup, cleanup_before, reply),
      )
      case
        process.receive(
          reply,
          within: int.max(0, guard.deadline - transport.monotonic_millisecond()),
        )
      {
        Ok(Ok(identifier)) ->
          Ok(fn() { process.send(guard.commands, RaceRelease(identifier)) })
        Ok(Error(Nil)) -> Error(error.new(error.Cancelled))
        Error(Nil) -> {
          let _closed =
            close_race_socket(socket, cleanup_before, guard.deadline)
          case guard.deadline - transport.monotonic_millisecond() > 0 {
            True -> Error(error.new(error.Cancelled))
            False -> Error(error.new(error.Timeout(error.Total)))
          }
        }
      }
    }
  }
}

fn cancel_tcp_race_guard(guard: TcpRaceGuard) -> Bool {
  let monitor = process.monitor(guard.pid)
  cancel_tcp_race_guard_with_monitor(guard, monitor)
}

fn cancel_tcp_race_guard_with_monitor(
  guard: TcpRaceGuard,
  monitor: process.Monitor,
) -> Bool {
  mark_race_cancelled(guard.cancellation)
  let deadline = guard.deadline
  let reply = process.new_subject()
  process.send(guard.commands, RaceCancel(reply))
  let acknowledged =
    process.receive(
      reply,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  let joined =
    join_race_helper_until(
      guard.pid,
      monitor,
      deadline,
      guard.join_confirmation,
    )
  let confirmed = case acknowledged {
    Ok(cleaned) -> cleaned && joined
    Error(Nil) -> False
  }
  case confirmed {
    True -> True
    False -> {
      process.kill(guard.pid)
      False
    }
  }
}

fn select_http3_race_guard(guard: TcpRaceGuard) -> Bool {
  let deadline = guard.deadline
  let monitor = process.monitor(guard.pid)
  let reply = process.new_subject()
  process.send(guard.commands, RaceSelectHttp3(reply))
  let acknowledged =
    process.receive(
      reply,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  let joined =
    join_race_helper_until(
      guard.pid,
      monitor,
      deadline,
      guard.join_confirmation,
    )
  let confirmed = case acknowledged {
    Ok(cleaned) -> cleaned && joined
    Error(Nil) -> False
  }
  case confirmed {
    True -> True
    False -> {
      process.kill(guard.pid)
      False
    }
  }
}

fn claim_tcp_race_guard(
  guard: TcpRaceGuard,
  candidate: TcpRaceCandidate,
) -> Result(http2_exchange.Ready, Bool) {
  let TcpRaceCandidate(_, handoff) = candidate
  let deadline = guard.deadline
  let monitor = process.monitor(guard.pid)
  let reply = process.new_subject()
  process.send(guard.commands, RaceClaim(reply))
  let outcome =
    process.receive(
      reply,
      within: int.max(0, deadline - transport.monotonic_millisecond()),
    )
  case outcome {
    Ok(Ok(TcpRaceClaimOffer(identifier, cleanup))) -> {
      let transferred = process.new_subject()
      process.send(handoff, TcpCandidateHandoff(process.self(), transferred))
      let handoff_outcome = receive_tcp_candidate_handoff(transferred, deadline)
      case handoff_outcome {
        Ok(ready) -> {
          let ready = http2_exchange.with_ready_cleanup(ready, cleanup)
          case guard.commit_confirmation {
            True -> {
              let committed = process.new_subject()
              process.send(guard.commands, RaceCommit(identifier, committed))
              let acknowledged =
                process.receive(
                  committed,
                  within: int.max(
                    0,
                    deadline - transport.monotonic_millisecond(),
                  ),
                )
              let joined =
                join_race_helper_until(
                  guard.pid,
                  monitor,
                  deadline,
                  guard.join_confirmation,
                )
              case acknowledged, joined {
                Ok(True), True -> Ok(ready)
                _, _ -> {
                  process.kill(guard.pid)
                  http2_exchange.discard_ready(ready)
                  Error(False)
                }
              }
            }
            False -> {
              let cancelled = process.new_subject()
              process.send(guard.commands, RaceCancel(cancelled))
              let acknowledged =
                process.receive(
                  cancelled,
                  within: int.max(
                    0,
                    deadline - transport.monotonic_millisecond(),
                  ),
                )
              let joined =
                join_race_helper_until(
                  guard.pid,
                  monitor,
                  deadline,
                  guard.join_confirmation,
                )
              case acknowledged, joined {
                Ok(True), True -> Nil
                _, _ -> process.kill(guard.pid)
              }
              http2_exchange.discard_ready(ready)
              Error(False)
            }
          }
        }
        Error(Nil) -> {
          let _cleanup_confirmed =
            cancel_tcp_race_guard_with_monitor(guard, monitor)
          Error(False)
        }
      }
    }
    Ok(Error(reason)) -> {
      let joined =
        join_race_helper_until(
          guard.pid,
          monitor,
          deadline,
          guard.join_confirmation,
        )
      case joined {
        True -> Error(reason)
        False -> {
          process.kill(guard.pid)
          Error(False)
        }
      }
    }
    Error(Nil) -> {
      mark_race_cancelled(guard.cancellation)
      process.kill(guard.pid)
      let _joined =
        join_race_helper_until(
          guard.pid,
          monitor,
          deadline,
          guard.join_confirmation,
        )
      Error(False)
    }
  }
}

fn close_optional_guarded_socket(
  guarded: Option(GuardedSocket),
  deadline: Int,
) -> Bool {
  case guarded {
    None -> True
    Some(GuardedSocket(_, socket, _, cleanup_before)) ->
      close_race_socket(socket, cleanup_before, deadline)
  }
}

fn close_race_socket(
  socket: transport.Socket,
  cleanup_before: fn(Int) -> Bool,
  deadline: Int,
) -> Bool {
  let socket_closed = transport.close(socket) == Ok(Nil)
  let lifecycle_released = cleanup_before(deadline)
  socket_closed && lifecycle_released
}

fn read_tunnel_transport(
  tunnel: Tunnel,
  maximum_bytes: Int,
) -> Result(TunnelRead, error.Error) {
  case
    transport.read(
      tunnel.socket,
      maximum_bytes,
      tunnel.idle_timeout_milliseconds,
    )
  {
    Error(failure) -> {
      let _closed = close_tunnel(tunnel)
      Error(map_tunnel_transport_error(failure))
    }
    Ok(transport.ReadEnd(socket)) -> {
      use _ <- result.try(close_tunnel(Tunnel(..tunnel, socket:)))
      Ok(TunnelEnd)
    }
    Ok(transport.ReadData(bytes, socket)) ->
      Ok(TunnelData(bytes, Tunnel(..tunnel, socket:, buffered: <<>>)))
  }
}

fn emit_tunnel_bytes(
  tunnel tunnel: Tunnel,
  bytes bytes: BitArray,
  maximum_bytes maximum_bytes: Int,
) -> Result(TunnelRead, error.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_bytes {
    True -> Ok(TunnelData(bytes, Tunnel(..tunnel, buffered: <<>>)))
    False -> {
      use chunk <- result.try(tunnel_slice(bytes:, at: 0, take: maximum_bytes))
      use remaining <- result.try(tunnel_slice(
        bytes:,
        at: maximum_bytes,
        take: size - maximum_bytes,
      ))
      Ok(TunnelData(chunk, Tunnel(..tunnel, buffered: remaining)))
    }
  }
}

fn tunnel_slice(
  bytes bytes: BitArray,
  at at: Int,
  take take: Int,
) -> Result(BitArray, error.Error) {
  case bit_array.slice(bytes, at:, take:) {
    Ok(slice) -> Ok(slice)
    Error(Nil) -> Error(error.new(error.Protocol(error.Http1)))
  }
}

fn map_tunnel_transport_error(failure: transport.Error) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(error.Idle))
    transport.Closed -> error.new(error.Cancelled)
    transport.InvalidInput -> security_policy_error()
    _ -> error.new(error.Protocol(error.Http1))
  }
}

fn require_open(client: Client) -> Result(Nil, error.Error) {
  case lifecycle_state(client.lifecycle) {
    0 -> Ok(Nil)
    _ -> Error(error.new(error.Cancelled))
  }
}

fn require_scheme(
  config: Config,
  is_plain_http: Bool,
) -> Result(Nil, error.Error) {
  case is_plain_http, config.security.allow_plain_http {
    True, False -> Error(security_policy_error())
    _, _ -> Ok(Nil)
  }
}

fn valid_timeouts(timeouts: Timeouts) -> Bool {
  valid_timeout(timeouts.dns_milliseconds)
  && valid_timeout(timeouts.connect_milliseconds)
  && valid_timeout(timeouts.tls_milliseconds)
  && valid_timeout(timeouts.operation_milliseconds)
  && valid_timeout(timeouts.idle_milliseconds)
  && valid_timeout(timeouts.total_milliseconds)
}

fn valid_timeout(value: Int) -> Bool {
  value > 0 && value <= 2_147_483_647
}

fn valid_pool_limits(limits: PoolLimits) -> Bool {
  limits.maximum_connections > 0
  && limits.maximum_connections <= 2_147_483_647
  && limits.maximum_connections_per_origin > 0
  && limits.maximum_connections_per_origin <= limits.maximum_connections
  && valid_timeout(limits.idle_milliseconds)
}

fn valid_body_limits(limits: BodyLimits) -> Bool {
  limits.buffered_bytes > 0
  && limits.buffered_bytes <= limits.endpoint_memory_bytes
  && limits.stream_buffer_bytes > 0
  && limits.stream_buffer_bytes <= limits.endpoint_memory_bytes
  && limits.endpoint_memory_bytes > 0
  && limits.endpoint_memory_bytes <= 2_147_483_647
}

fn valid_store_limits(limits: StoreLimits) -> Bool {
  limits.maximum_entries > 0
  && limits.maximum_entries <= 65_536
  && limits.maximum_bytes > 0
  && limits.maximum_bytes <= 67_108_864
}

fn valid_network_isolation_key(key: NetworkIsolationKey) -> Bool {
  valid_partition_component(key.top_level_site, allow_empty: True)
  && valid_partition_component(key.profile, allow_empty: False)
}

fn valid_proxy(proxy: Proxy) -> Bool {
  proxy.host != ""
  && string.byte_size(proxy.host) <= 1024
  && !string.contains(proxy.host, " ")
  && !string.contains(proxy.host, "\r")
  && !string.contains(proxy.host, "\n")
  && !string.contains(proxy.host, "\u{0000}")
  && proxy.port > 0
  && proxy.port <= 65_535
  && valid_proxy_authorization(proxy.authorization)
}

fn valid_proxy_authorization(authorization: Option(String)) -> Bool {
  case authorization {
    None -> True
    Some(value) ->
      value != ""
      && string.byte_size(value) <= 8192
      && !string.contains(value, "\r")
      && !string.contains(value, "\n")
      && !string.contains(value, "\u{0000}")
  }
}

fn valid_partition_component(
  value: String,
  allow_empty allow_empty: Bool,
) -> Bool {
  { allow_empty || value != "" }
  && string.byte_size(value) <= 1024
  && !string.contains(value, "\r")
  && !string.contains(value, "\n")
  && !string.contains(value, "\u{0000}")
}

fn valid_retry_policy(policy: RetryPolicy) -> Bool {
  policy.maximum >= 0
  && policy.maximum <= 10
  && list.length(policy.retry_statuses) <= 32
  && valid_retry_statuses(policy.retry_statuses)
}

fn valid_retry_statuses(statuses: List(Int)) -> Bool {
  case statuses {
    [] -> True
    [status, ..rest] ->
      status >= 400
      && status <= 599
      && !list.contains(rest, status)
      && valid_retry_statuses(rest)
  }
}

fn security_policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}

fn redirect_policy_error() -> error.Error {
  error.new(error.Policy(error.RedirectPolicy))
}

fn cache_policy_error() -> error.Error {
  error.new(error.Policy(error.CachePolicy))
}

fn proxy_policy_error() -> error.Error {
  error.new(error.Policy(error.ProxyPolicy))
}

fn retry_policy_error() -> error.Error {
  error.new(error.Policy(error.RetryPolicy))
}

fn smallest(first: Int, second: Int) -> Int {
  use <- bool.guard(when: first >= second, return: second)
  first
}

fn require(
  condition: Bool,
  failure: error,
  continue: fn() -> Result(value, error),
) -> Result(value, error) {
  use <- bool.guard(when: !condition, return: Error(failure))
  continue()
}
