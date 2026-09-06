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
import http/error
import http/internal/alt_svc
import http/internal/cache
import http/internal/cookie
import http/internal/hsts
import http/internal/http1/exchange as http1_exchange
import http/internal/http2/exchange as http2_exchange
import http/internal/http2/wire as http2_wire
import http/internal/redirect
import http/internal/transport
import http3/client as h3_client

/// Finite client deadlines. DNS lookup has its own budget and is never an
/// unbounded part of connection establishment.
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

/// Security switches. Certificate-chain and hostname verification have no
/// switch and therefore cannot be disabled.
pub type Security {
  Security(allow_plain_http: Bool)
}

/// Finite automatic redirect policy.
pub type RedirectPolicy {
  RedirectPolicy(enabled: Bool, maximum: Int)
}

/// Finite automatic retry policy.
///
/// A retry is considered only when the method is idempotent and the Body can
/// be regenerated. Response-status retries require an explicit status entry.
pub type RetryPolicy {
  RetryPolicy(enabled: Bool, maximum: Int, retry_statuses: List(Int))
}

/// Finite entry and retained-byte limits for one in-memory policy store.
pub type StoreLimits {
  StoreLimits(maximum_entries: Int, maximum_bytes: Int)
}

/// Cookie processing policy. It is disabled by default.
pub type CookiePolicy {
  CookiePolicy(enabled: Bool, limits: StoreLimits)
}

/// Complete-response cache policy. It is disabled by default.
pub type CachePolicy {
  CachePolicy(enabled: Bool, limits: StoreLimits)
}

/// Strict-Transport-Security policy. Learning is enabled by default.
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

/// Proxy selection policy. The default has no proxy.
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
  )
}

type Lifecycle

type Http2Pool

type PolicyStore

type Registration

type TunnelGuard

type RaceCancellation

type TcpRaceGuard {
  TcpRaceGuard(
    commands: process.Subject(TcpRaceCommand),
    cancellation: RaceCancellation,
    pid: process.Pid,
  )
}

type TcpRaceCommand {
  RaceAttach(
    socket: transport.Socket,
    cleanup: fn() -> Nil,
    reply: process.Subject(Result(Int, Nil)),
  )
  RaceRelease(identifier: Int)
  RaceCancel(reply: process.Subject(Nil))
  RaceStop(reply: process.Subject(Nil))
}

type GuardedSocket {
  GuardedSocket(identifier: Int, socket: transport.Socket, cleanup: fn() -> Nil)
}

type RaceEvent {
  Http3Finished(Result(Exchange, error.Error))
  TcpFinished(Result(Exchange, error.Error))
  Http3Exited
  TcpExited
}

/// A reusable client lifecycle owner. Runtime handles are never public.
pub opaque type Client {
  Client(
    config: Config,
    lifecycle: Lifecycle,
    http2_pool: Http2Pool,
    cookie_store: PolicyStore,
    cache_store: PolicyStore,
    hsts_store: PolicyStore,
    alt_svc_store: PolicyStore,
  )
}

/// A streaming response and non-secret exchange metadata.
pub opaque type Exchange {
  Exchange(
    response: Response(body.Body),
    selected_protocol: Protocol,
    redirect_history: List(RedirectHop),
  )
}

/// One established HTTP/1.1 CONNECT or Upgrade byte stream.
///
/// Its socket, lifecycle registration, buffered bytes, and close guard remain
/// private. Each successful read returns the next cursor.
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
  origin: String,
) -> Result(#(transport.Socket, http2_wire.State, fn() -> Nil), Int)

@external(erlang, "http_client_ffi", "checkin_http2")
fn checkin_http2(
  pool: Http2Pool,
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

@external(erlang, "http_client_ffi", "policy_store_list")
fn policy_store_list(
  store: PolicyStore,
  partition: String,
) -> List(cookie.Cookie)

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

@external(erlang, "http_client_ffi", "call_https_resolver")
fn call_https_resolver(
  resolver: fn(String, Int, Int) -> Result(List(HttpsRecord), Nil),
  host: String,
  port: Int,
  timeout_milliseconds: Int,
) -> Result(List(HttpsRecord), Int)

@external(erlang, "http_client_ffi", "close_policy_store")
fn close_policy_store(store: PolicyStore) -> Nil

@external(erlang, "http_client_ffi", "state")
fn lifecycle_state(lifecycle: Lifecycle) -> Int

@external(erlang, "http_client_ffi", "drain")
fn lifecycle_drain(lifecycle: Lifecycle) -> Int

@external(erlang, "http_client_ffi", "close")
fn lifecycle_close(lifecycle: Lifecycle) -> Nil

@external(erlang, "http_client_ffi", "is_closed")
fn lifecycle_is_closed(lifecycle: Lifecycle) -> Bool

@external(erlang, "http_client_ffi", "register_socket")
fn register_socket(
  lifecycle: Lifecycle,
  origin: String,
  socket: transport.Socket,
) -> Result(Registration, Int)

@external(erlang, "http_client_ffi", "unregister_socket")
fn unregister_socket(registration: Registration) -> Nil

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

@external(erlang, "http_client_ffi", "call_policy_adapter")
fn call_policy_adapter(
  run: fn() -> Result(value, Nil),
  timeout_milliseconds: Int,
) -> Result(value, Int)

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
/// Only authenticated records advertising `h3` are eligible. Callback errors,
/// exits, malformed records, and timeouts are ignored and planning continues
/// with the authenticated TCP path.
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
/// Status codes must be error responses (400 through 599). An empty list keeps
/// status retries disabled while retaining the safe pre-response retry.
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
      cookie_store: new_policy_store(
        cookie_limits.maximum_entries,
        cookie_limits.maximum_bytes,
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
    )
  case load_policy_adapters(client) {
    Ok(Nil) -> Ok(client)
    Error(failure) -> {
      let _closed = close(client)
      Error(failure)
    }
  }
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
  call_policy_adapter(operation, client_store.timeout_milliseconds(adapter))
  |> result.map_error(fn(_) { security_policy_error() })
}

fn adapter_partition(config: Config) -> client_store.Partition {
  let NetworkIsolationKey(top_level_site, profile) =
    config.network_isolation_key
  client_store.Partition(top_level_site:, profile:)
}

/// Execute a buffered request and return a detached, replayable response.
///
/// The response body is collected under `BodyLimits.buffered_bytes`, including
/// trailers, before this function returns. Use `exchange` for streaming.
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
pub fn exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
) -> Result(Exchange, error.Error) {
  use _ <- result.try(require_open(client))
  let outgoing = apply_hsts_policy(client, outgoing)
  use _ <- result.try(require_scheme(client.config, outgoing.scheme == Http))
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
/// The request body must be empty. A stream is returned only after a CONNECT
/// 2xx or Upgrade 101 response; rejected handshakes close their connection.
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

/// Stop admitting new requests. Repeated calls are harmless.
pub fn drain(client: Client) -> Result(Nil, error.Error) {
  let _state = lifecycle_drain(client.lifecycle)
  drain_http2_pool(client.http2_pool)
  Ok(Nil)
}

/// Close the client idempotently.
pub fn close(client: Client) -> Result(Nil, error.Error) {
  close_http2_pool(client.http2_pool)
  close_policy_store(client.cookie_store)
  close_policy_store(client.cache_store)
  close_policy_store(client.hsts_store)
  close_policy_store(client.alt_svc_store)
  lifecycle_close(client.lifecycle)
  Ok(Nil)
}

fn run_exchange(
  client: Client,
  outgoing: Request(body.Body),
) -> Result(Exchange, error.Error) {
  let deadline =
    transport.monotonic_millisecond()
    + client.config.timeouts.total_milliseconds
  run_exchange_redirects(
    client: client,
    outgoing: outgoing,
    redirects_followed: 0,
    reversed_history: [],
    deadline: deadline,
  )
}

fn run_exchange_redirects(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  redirects_followed redirects_followed: Int,
  reversed_history reversed_history: List(RedirectHop),
  deadline deadline: Int,
) -> Result(Exchange, error.Error) {
  let outgoing = apply_hsts_policy(client, outgoing)
  let outgoing = apply_cookie_policy(client, outgoing)
  use _ <- result.try(require_open(client))
  use _ <- result.try(require_scheme(client.config, outgoing.scheme == Http))
  let remaining = deadline - transport.monotonic_millisecond()
  use <- require(remaining > 0, error.new(error.Timeout(error.Total)))
  use completed <- result.try(run_exchange_attempts(
    client: client,
    outgoing: outgoing,
    deadline: deadline,
    retries_remaining: client.config.retry_policy.maximum,
  ))
  capture_response_policies(client, outgoing, completed.response)
  case redirect_location(completed.response) {
    None -> Ok(with_redirect_history(completed, reversed_history))
    Some(_) if !client.config.redirect_policy.enabled ->
      Ok(with_redirect_history(completed, reversed_history))
    Some(_) if redirects_followed >= client.config.redirect_policy.maximum -> {
      body.cancel(completed.response.body)
      Error(redirect_policy_error())
    }
    Some(location) ->
      case redirect.follow(outgoing, completed.response.status, location) {
        Error(failure) -> {
          body.cancel(completed.response.body)
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
          body.cancel(completed.response.body)
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

fn run_exchange_attempts(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  deadline deadline: Int,
  retries_remaining retries_remaining: Int,
) -> Result(Exchange, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  use <- require(remaining > 0, error.new(error.Timeout(error.Total)))
  let replay = retry_request(client.config.retry_policy, outgoing)
  case
    run_exchange_once(
      client: client,
      outgoing: outgoing,
      total_milliseconds: remaining,
    )
  {
    Ok(completed) ->
      case
        retries_remaining > 0,
        replay,
        retry_status(client.config.retry_policy, completed.response.status)
      {
        True, Some(replayed), True -> {
          body.cancel(completed.response.body)
          run_exchange_attempts(
            client: client,
            outgoing: replayed,
            deadline: deadline,
            retries_remaining: retries_remaining - 1,
          )
        }
        _, _, _ -> Ok(completed)
      }
    Error(failure) ->
      case
        retries_remaining > 0,
        replay,
        retryable_pre_response_failure(failure)
      {
        True, Some(replayed), True ->
          run_exchange_attempts(
            client: client,
            outgoing: replayed,
            deadline: deadline,
            retries_remaining: retries_remaining - 1,
          )
        _, _, _ -> Error(failure)
      }
  }
}

fn retry_request(
  policy: RetryPolicy,
  outgoing: Request(body.Body),
) -> Option(Request(body.Body)) {
  case policy.enabled && idempotent_method(outgoing.method) {
    False -> None
    True ->
      case body.replay(outgoing.body) {
        Ok(replayed) -> Some(request.set_body(outgoing, replayed))
        Error(_) -> None
      }
  }
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

fn retryable_pre_response_failure(failure: error.Error) -> Bool {
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
  case outgoing.scheme {
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
}

fn run_http1_exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  total_milliseconds total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  use config <- result.try(http1_config(client, total_milliseconds))
  use incoming <- result.try(http1_exchange.run(outgoing, config))
  Ok(
    Exchange(response: incoming, selected_protocol: Http1, redirect_history: []),
  )
}

fn run_https_exchange(
  client client: Client,
  outgoing outgoing: Request(body.Body),
  total_milliseconds total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  let deadline = transport.monotonic_millisecond() + total_milliseconds
  refresh_https_records(client, outgoing)
  case should_attempt_http3(client, outgoing) {
    False -> run_tcp_https_exchange(client, outgoing, total_milliseconds)
    True -> race_https_routes(client, outgoing, deadline)
  }
}

fn refresh_https_records(client: Client, outgoing: Request(body)) -> Nil {
  let origin = request_origin(outgoing)
  let now = transport.monotonic_millisecond()
  let existing =
    alt_svc_store_list(
      client.alt_svc_store,
      policy_partition(client.config.network_isolation_key),
    )
  case
    client.config.discovery_policy.enabled,
    alt_svc.supports_same_port(existing, outgoing.host, origin.port, now),
    client.config.https_record_resolver
  {
    True, False, Some(resolver) ->
      case
        call_https_resolver(
          resolver,
          outgoing.host,
          origin.port,
          client.config.discovery_policy.https_record_timeout_milliseconds,
        )
      {
        Ok(records) ->
          store_https_records(client, outgoing.host, origin.port, records, now)
        Error(_) -> Nil
      }
    _, _, _ -> Nil
  }
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
      Ok(
        Exchange(
          response: incoming,
          selected_protocol: Http2,
          redirect_history: [],
        ),
      )
    Ok(http2_exchange.Http1Response(incoming)) ->
      Ok(
        Exchange(
          response: incoming,
          selected_protocol: Http1,
          redirect_history: [],
        ),
      )
    Ok(http2_exchange.Http1Required) ->
      Error(error.new(error.Protocol(error.Http1)))
  }
}

fn race_https_routes(
  client: Client,
  outgoing: Request(body.Body),
  deadline: Int,
) -> Result(Exchange, error.Error) {
  use h3_body <- result.try(body.replay(outgoing.body))
  use tcp_body <- result.try(body.replay(outgoing.body))
  use guard <- result.try(start_tcp_race_guard())
  let outcomes = process.new_subject()
  let h3_outgoing = request.set_body(outgoing, h3_body)
  let tcp_outgoing = request.set_body(outgoing, tcp_body)
  let h3_pid =
    process.spawn_unlinked(fn() {
      let remaining = deadline - transport.monotonic_millisecond()
      let outcome = case remaining > 0 {
        True -> run_http3_exchange(client, h3_outgoing, remaining)
        False -> Error(error.new(error.Timeout(error.Total)))
      }
      process.send(outcomes, Http3Finished(outcome))
    })
  let tcp_pid =
    process.spawn_unlinked(fn() {
      let remaining = deadline - transport.monotonic_millisecond()
      let outcome = case remaining > 0 {
        True -> run_buffered_tcp_race(client, tcp_outgoing, remaining, guard)
        False -> Error(error.new(error.Timeout(error.Total)))
      }
      stop_tcp_race_guard(guard)
      process.send(outcomes, TcpFinished(outcome))
    })
  let h3_monitor = process.monitor(h3_pid)
  let tcp_monitor = process.monitor(tcp_pid)
  let selector =
    process.new_selector()
    |> process.select(outcomes)
    |> process.select_specific_monitor(h3_monitor, fn(_) { Http3Exited })
    |> process.select_specific_monitor(tcp_monitor, fn(_) { TcpExited })
  await_https_race(
    selector,
    h3_pid,
    tcp_pid,
    h3_monitor,
    tcp_monitor,
    guard,
    deadline,
    None,
    None,
  )
}

fn await_https_race(
  selector: process.Selector(RaceEvent),
  h3_pid: process.Pid,
  tcp_pid: process.Pid,
  h3_monitor: process.Monitor,
  tcp_monitor: process.Monitor,
  guard: TcpRaceGuard,
  deadline: Int,
  h3_failure: Option(error.Error),
  tcp_failure: Option(error.Error),
) -> Result(Exchange, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining > 0 {
    False ->
      finish_race_timeout(
        h3_pid,
        tcp_pid,
        h3_monitor,
        tcp_monitor,
        guard,
        h3_failure,
        tcp_failure,
      )
    True ->
      case process.selector_receive(selector, within: remaining) {
        Error(Nil) ->
          finish_race_timeout(
            h3_pid,
            tcp_pid,
            h3_monitor,
            tcp_monitor,
            guard,
            h3_failure,
            tcp_failure,
          )
        Ok(Http3Finished(Ok(completed))) -> {
          case tcp_failure {
            None -> {
              cancel_tcp_race_guard(guard)
              process.kill(tcp_pid)
            }
            Some(_) -> Nil
          }
          finish_race_monitors(h3_monitor, tcp_monitor)
          Ok(completed)
        }
        Ok(TcpFinished(Ok(completed))) -> {
          case h3_failure {
            None -> process.kill(h3_pid)
            Some(_) -> Nil
          }
          finish_race_monitors(h3_monitor, tcp_monitor)
          Ok(completed)
        }
        Ok(Http3Finished(Error(failure))) ->
          case tcp_failure {
            Some(tcp_failure) -> {
              finish_race_monitors(h3_monitor, tcp_monitor)
              Error(tcp_failure)
            }
            None ->
              await_https_race(
                selector,
                h3_pid,
                tcp_pid,
                h3_monitor,
                tcp_monitor,
                guard,
                deadline,
                Some(failure),
                None,
              )
          }
        Ok(TcpFinished(Error(failure))) ->
          case h3_failure {
            Some(_) -> {
              finish_race_monitors(h3_monitor, tcp_monitor)
              Error(failure)
            }
            None ->
              await_https_race(
                selector,
                h3_pid,
                tcp_pid,
                h3_monitor,
                tcp_monitor,
                guard,
                deadline,
                None,
                Some(failure),
              )
          }
        Ok(Http3Exited) ->
          await_https_race(
            selector,
            h3_pid,
            tcp_pid,
            h3_monitor,
            tcp_monitor,
            guard,
            deadline,
            Some(error.new(error.Protocol(error.Http3))),
            tcp_failure,
          )
        Ok(TcpExited) -> {
          cancel_tcp_race_guard(guard)
          case h3_failure {
            Some(_) -> {
              finish_race_monitors(h3_monitor, tcp_monitor)
              Error(error.new(error.Protocol(error.Http2)))
            }
            None ->
              await_https_race(
                selector,
                h3_pid,
                tcp_pid,
                h3_monitor,
                tcp_monitor,
                guard,
                deadline,
                None,
                Some(error.new(error.Protocol(error.Http2))),
              )
          }
        }
      }
  }
}

fn finish_race_timeout(
  h3_pid: process.Pid,
  tcp_pid: process.Pid,
  h3_monitor: process.Monitor,
  tcp_monitor: process.Monitor,
  guard: TcpRaceGuard,
  h3_failure: Option(error.Error),
  tcp_failure: Option(error.Error),
) -> Result(Exchange, error.Error) {
  case tcp_failure {
    None -> {
      cancel_tcp_race_guard(guard)
      process.kill(tcp_pid)
    }
    Some(_) -> Nil
  }
  case h3_failure {
    None -> process.kill(h3_pid)
    Some(_) -> Nil
  }
  finish_race_monitors(h3_monitor, tcp_monitor)
  Error(error.new(error.Timeout(error.Total)))
}

fn finish_race_monitors(
  h3_monitor: process.Monitor,
  tcp_monitor: process.Monitor,
) -> Nil {
  process.demonitor_process(h3_monitor)
  process.demonitor_process(tcp_monitor)
}

fn run_buffered_tcp_race(
  client: Client,
  outgoing: Request(body.Body),
  total_milliseconds: Int,
  guard: TcpRaceGuard,
) -> Result(Exchange, error.Error) {
  use http1 <- result.try(http1_config(client, total_milliseconds))
  let http1 =
    http1
    |> http1_exchange.without_proxy
    |> http1_exchange.without_pool
    |> http1_exchange.with_lifecycle(
      fn(origin, socket) {
        attach_tcp_race_socket(client, guard, origin, socket)
      },
      fn() {
        lifecycle_is_closed(client.lifecycle)
        || race_is_cancelled(guard.cancellation)
      },
    )
  use http2 <- result.try(http2_config(client, total_milliseconds))
  let http2 =
    http2
    |> http2_exchange.without_pool
    |> http2_exchange.with_lifecycle(
      fn(origin, socket) {
        attach_tcp_race_socket(client, guard, origin, socket)
      },
      fn() {
        lifecycle_is_closed(client.lifecycle)
        || race_is_cancelled(guard.cancellation)
      },
    )
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
  use completed <- result.try(run_configured_tcp_https(outgoing, http2))
  use collected <- result.try(body.read_all(
    completed.response.body,
    client.config.body_limits.buffered_bytes,
  ))
  let #(bytes, trailers) = collected
  Ok(
    Exchange(
      ..completed,
      response: response.set_body(
        completed.response,
        body.from_bytes_with_trailers(bytes, trailers),
      ),
    ),
  )
}

fn should_attempt_http3(client: Client, outgoing: Request(body.Body)) -> Bool {
  let origin = request_origin(outgoing)
  client.config.discovery_policy.enabled
  && client.config.proxy_policy.proxy == None
  && idempotent_method(outgoing.method)
  && body.is_replayable(outgoing.body)
  && alt_svc.supports_same_port(
    alt_svc_store_list(
      client.alt_svc_store,
      policy_partition(client.config.network_isolation_key),
    ),
    outgoing.host,
    origin.port,
    transport.monotonic_millisecond(),
  )
}

fn run_http3_exchange(
  client: Client,
  outgoing: Request(body.Body),
  total_milliseconds: Int,
) -> Result(Exchange, error.Error) {
  use replayed <- result.try(body.replay(outgoing.body))
  use collected <- result.try(body.read_all(
    replayed,
    client.config.body_limits.endpoint_memory_bytes,
  ))
  let #(bytes, trailers) = collected
  use <- require(
    list.is_empty(trailers),
    error.new(error.Body(error.NotReplayable)),
  )
  use configuration <- result.try(
    h3_client.with_timeout(
      h3_client.new(),
      int.min(total_milliseconds, 3_600_000),
    )
    |> result.map_error(map_http3_configuration_error),
  )
  use configuration <- result.try(
    h3_client.with_request_body_limit(
      configuration,
      client.config.body_limits.endpoint_memory_bytes,
    )
    |> result.map_error(map_http3_configuration_error),
  )
  use configuration <- result.try(
    h3_client.with_response_body_limit(
      configuration,
      client.config.body_limits.buffered_bytes,
    )
    |> result.map_error(map_http3_configuration_error),
  )
  use configuration <- result.try(
    h3_client.with_stream_buffer_limit(
      configuration,
      client.config.body_limits.stream_buffer_bytes,
    )
    |> result.map_error(map_http3_configuration_error),
  )
  use configuration <- result.try(add_http3_ca_certificates(
    configuration,
    client.config.ca_certificates,
  ))
  use incoming <- result.try(
    h3_client.send(configuration, request.set_body(outgoing, bytes))
    |> result.map_error(map_http3_error),
  )
  Ok(
    Exchange(
      response: response.set_body(incoming, body.from_bytes(incoming.body)),
      selected_protocol: Http3,
      redirect_history: [],
    ),
  )
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

fn map_http3_error(failure: h3_client.Error) -> error.Error {
  case failure {
    h3_client.InvalidBody -> error.new(error.Body(error.InvalidChunk))
    h3_client.RequestBodyTooLarge(limit)
    | h3_client.ResponseBodyTooLarge(limit) ->
      error.new(error.Body(error.TooLarge(limit)))
    h3_client.ConsumerTooSlow(_) -> error.new(error.Resource(error.Memory))
    h3_client.ConnectionDraining | h3_client.RequestRejected ->
      error.new(error.Protocol(error.Http3))
    _ -> error.new(error.Protocol(error.Http3))
  }
}

fn apply_cookie_policy(
  client: Client,
  outgoing: Request(body.Body),
) -> Request(body.Body) {
  case
    client.config.cookie_policy.enabled,
    request.get_header(outgoing, "cookie")
  {
    False, _ | True, Ok(_) -> outgoing
    True, Error(_) -> {
      let retained =
        policy_store_list(
          client.cookie_store,
          policy_partition(client.config.network_isolation_key),
        )
      case
        cookie.request_header(
          retained,
          outgoing.scheme,
          outgoing.host,
          outgoing.path,
          transport.monotonic_millisecond(),
        )
      {
        None -> outgoing
        Some(value) -> request.set_header(outgoing, "cookie", value)
      }
    }
  }
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
          let port = case outgoing.port {
            Some(80) -> Some(443)
            configured -> configured
          }
          request.Request(..outgoing, scheme: Https, port:)
        }
      }
    }
  }
}

fn capture_response_policies(
  client: Client,
  outgoing: Request(body.Body),
  incoming: Response(body.Body),
) -> Nil {
  capture_response_cookies(client, outgoing, incoming)
  capture_hsts_headers(
    client,
    outgoing,
    incoming.headers,
    transport.monotonic_millisecond(),
  )
  capture_alt_svc_headers(
    client,
    outgoing,
    incoming.headers,
    transport.monotonic_millisecond(),
  )
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
      case string.lowercase(name), hsts.parse(value, outgoing.host, now) {
        "strict-transport-security", Some(entry) -> {
          let _stored = store_hsts_policy(client, entry, now)
          Nil
        }
        _, _ -> Nil
      }
      capture_hsts_headers(client, outgoing, rest, now)
    }
  }
}

fn capture_alt_svc_headers(
  client: Client,
  outgoing: Request(body),
  headers: List(#(String, String)),
  now: Int,
) -> Nil {
  case outgoing.scheme, client.config.discovery_policy.enabled, headers {
    _, False, _ | Http, _, _ | _, _, [] -> Nil
    Https, True, [#(name, value), ..rest] -> {
      let origin = request_origin(outgoing)
      case
        string.lowercase(name),
        alt_svc.parse(value, outgoing.host, origin.port, now)
      {
        "alt-svc", Some(entry) -> {
          let _stored = store_alt_svc_policy(client, entry, now)
          Nil
        }
        _, _ -> Nil
      }
      capture_alt_svc_headers(client, outgoing, rest, now)
    }
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
        cookie.parse(value, scheme, host, path, now)
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
  case persist_cookie_policy(client, entry, now) {
    False -> False
    True ->
      policy_store_put(
        client.cookie_store,
        policy_partition(client.config.network_isolation_key),
        cookie.key(entry),
        entry,
        entry.expires_at,
        entry.retained_bytes,
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
      let operation = case entry.expires_at <= now {
        True -> fn() {
          client_store.remove(
            adapter,
            adapter_partition(client.config),
            cookie.key(entry),
          )
        }
        False -> fn() {
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
        Ok(entry) -> Some(cache.response(entry))
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
          fn(origin) { checkout_http2(client.http2_pool, origin) },
          fn(origin, socket, state, cleanup) {
            checkin_http2(client.http2_pool, origin, socket, state, cleanup)
          },
        ),
      )
  }
}

fn checkout_http2(
  pool: Http2Pool,
  origin: String,
) -> Result(
  Option(#(transport.Socket, http2_wire.State, fn() -> Nil)),
  error.Error,
) {
  case raw_checkout_http2(pool, origin) {
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

fn start_tcp_race_guard() -> Result(TcpRaceGuard, error.Error) {
  let cancellation = new_race_cancellation()
  let ready = process.new_subject()
  let pid =
    process.spawn_unlinked(fn() {
      let commands = process.new_subject()
      process.send(ready, commands)
      tcp_race_guard_loop(commands, cancellation, None, 1)
    })
  case process.receive(ready, within: 1000) {
    Ok(commands) -> Ok(TcpRaceGuard(commands, cancellation, pid))
    Error(Nil) -> {
      mark_race_cancelled(cancellation)
      process.kill(pid)
      Error(error.new(error.Service))
    }
  }
}

fn tcp_race_guard_loop(
  commands: process.Subject(TcpRaceCommand),
  cancellation: RaceCancellation,
  guarded: Option(GuardedSocket),
  next_identifier: Int,
) -> Nil {
  case process.receive_forever(commands) {
    RaceAttach(socket, cleanup, reply) ->
      case race_is_cancelled(cancellation), guarded {
        True, _ | False, Some(_) -> {
          close_guarded_socket(socket, cleanup)
          process.send(reply, Error(Nil))
          tcp_race_guard_loop(commands, cancellation, guarded, next_identifier)
        }
        False, None -> {
          process.send(reply, Ok(next_identifier))
          tcp_race_guard_loop(
            commands,
            cancellation,
            Some(GuardedSocket(next_identifier, socket, cleanup)),
            next_identifier + 1,
          )
        }
      }
    RaceRelease(identifier) ->
      case guarded {
        Some(GuardedSocket(current, _, cleanup)) if current == identifier -> {
          cleanup()
          tcp_race_guard_loop(commands, cancellation, None, next_identifier)
        }
        _ ->
          tcp_race_guard_loop(commands, cancellation, guarded, next_identifier)
      }
    RaceCancel(reply) -> {
      close_optional_guarded_socket(guarded)
      process.send(reply, Nil)
      tcp_race_cancelled_loop(commands)
    }
    RaceStop(reply) -> {
      close_optional_guarded_socket(guarded)
      process.send(reply, Nil)
      Nil
    }
  }
}

fn tcp_race_cancelled_loop(commands: process.Subject(TcpRaceCommand)) -> Nil {
  case process.receive(commands, within: 1000) {
    Error(Nil) -> Nil
    Ok(RaceAttach(socket, cleanup, reply)) -> {
      close_guarded_socket(socket, cleanup)
      process.send(reply, Error(Nil))
      tcp_race_cancelled_loop(commands)
    }
    Ok(RaceRelease(_)) -> tcp_race_cancelled_loop(commands)
    Ok(RaceCancel(reply)) -> {
      process.send(reply, Nil)
      tcp_race_cancelled_loop(commands)
    }
    Ok(RaceStop(reply)) -> process.send(reply, Nil)
  }
}

fn attach_tcp_race_socket(
  client: Client,
  guard: TcpRaceGuard,
  origin: String,
  socket: transport.Socket,
) -> Result(fn() -> Nil, error.Error) {
  use cleanup <- result.try(attach_socket(
    lifecycle: client.lifecycle,
    origin: origin,
    socket: socket,
  ))
  case race_is_cancelled(guard.cancellation) {
    True -> {
      close_guarded_socket(socket, cleanup)
      Error(error.new(error.Cancelled))
    }
    False -> {
      let reply = process.new_subject()
      process.send(guard.commands, RaceAttach(socket, cleanup, reply))
      case process.receive(reply, within: 1000) {
        Ok(Ok(identifier)) ->
          Ok(fn() { process.send(guard.commands, RaceRelease(identifier)) })
        Ok(Error(Nil)) -> Error(error.new(error.Cancelled))
        Error(Nil) -> {
          close_guarded_socket(socket, cleanup)
          Error(error.new(error.Cancelled))
        }
      }
    }
  }
}

fn cancel_tcp_race_guard(guard: TcpRaceGuard) -> Nil {
  mark_race_cancelled(guard.cancellation)
  let reply = process.new_subject()
  process.send(guard.commands, RaceCancel(reply))
  let _acknowledged = process.receive(reply, within: 1000)
  Nil
}

fn stop_tcp_race_guard(guard: TcpRaceGuard) -> Nil {
  let reply = process.new_subject()
  process.send(guard.commands, RaceStop(reply))
  let _acknowledged = process.receive(reply, within: 1000)
  Nil
}

fn close_optional_guarded_socket(guarded: Option(GuardedSocket)) -> Nil {
  case guarded {
    None -> Nil
    Some(GuardedSocket(_, socket, cleanup)) ->
      close_guarded_socket(socket, cleanup)
  }
}

fn close_guarded_socket(socket: transport.Socket, cleanup: fn() -> Nil) -> Nil {
  let _closed = transport.close(socket)
  cleanup()
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
