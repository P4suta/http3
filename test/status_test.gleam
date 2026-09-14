import gleam/option.{type Option, None, Some}
import gleeunit
import http/status
import http/structured_fields

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn cache_status_round_trips_registered_and_extension_parameters_test() -> Nil {
  let input =
    "OriginCache;hit;ttl=1100;key=\"private-key\";vendor=abc, \"CDN Company\";fwd=uri-miss;stored"
  let assert Ok(parsed) = status.parse_cache(input)

  assert parsed
    == [
      status.CacheStatus(
        cache: status.TokenIdentifier("OriginCache"),
        hit: Some(True),
        forwarded: None,
        forward_status: None,
        ttl: Some(1100),
        stored: None,
        collapsed: None,
        key: Some("private-key"),
        detail: None,
        extensions: [
          structured_fields.Parameter("vendor", structured_fields.Token("abc")),
        ],
      ),
      status.CacheStatus(
        cache: status.StringIdentifier("CDN Company"),
        hit: None,
        forwarded: Some("uri-miss"),
        forward_status: None,
        ttl: None,
        stored: Some(True),
        collapsed: None,
        key: None,
        detail: None,
        extensions: [],
      ),
    ]
  assert status.serialize_cache(parsed) == Ok(input)
}

pub fn cache_status_rejects_conflicting_or_mistyped_registered_values_test() -> Nil {
  assert status.parse_cache("cache;hit;fwd=miss") == Error(status.Invalid)
  assert status.parse_cache("cache;hit=1") == Error(status.Invalid)
  assert status.parse_cache("cache;fwd=miss;fwd-status=99")
    == Error(status.Invalid)
  assert status.parse_cache("(cache);hit") == Error(status.Invalid)
  assert status.parse_cache("123") == Error(status.Invalid)
}

pub fn cache_status_generation_policy_rejects_unstored_local_response_test() -> Nil {
  let entry = cache_entry("edge")
  assert status.serialize_cache_for(status.ForwardedResponse, [entry])
    == Ok("edge;hit")
  assert status.serialize_cache_for(
      status.LocallyGeneratedResponse(based_on_stored_response: True),
      [entry],
    )
    == Ok("edge;hit")
  assert status.serialize_cache_for(
      status.LocallyGeneratedResponse(based_on_stored_response: False),
      [entry],
    )
    == Error(status.Invalid)
}

pub fn append_cache_preserves_existing_chain_order_test() -> Nil {
  let origin = cache_entry("origin")
  let edge = cache_entry("edge")
  assert status.append_cache([origin], edge) == [origin, edge]
}

pub fn proxy_status_round_trips_and_preserves_unknown_parameters_test() -> Nil {
  let input =
    "edge.example;error=connection_timeout;next-hop=origin.example:443;next-protocol=h2;received-status=504;details=\"timed out\";trace=:AQI=:"
  let assert Ok(parsed) = status.parse_proxy(input)

  assert parsed
    == [
      status.ProxyStatus(
        proxy: status.TokenIdentifier("edge.example"),
        error: Some("connection_timeout"),
        next_hop: Some(status.TokenIdentifier("origin.example:443")),
        next_protocol: Some(status.ProtocolToken("h2")),
        received_status: Some(504),
        details: Some("timed out"),
        extensions: [
          structured_fields.Parameter(
            "trace",
            structured_fields.ByteSequence(<<1, 2>>),
          ),
        ],
      ),
    ]
  assert status.serialize_proxy(parsed) == Ok(input)
  let assert Ok(binary_protocol) =
    status.parse_proxy("gateway;next-protocol=:/w==:")
  assert binary_protocol
    == [
      status.ProxyStatus(
        proxy: status.TokenIdentifier("gateway"),
        error: None,
        next_hop: None,
        next_protocol: Some(status.ProtocolBytes(<<255>>)),
        received_status: None,
        details: None,
        extensions: [],
      ),
    ]
  assert status.serialize_proxy(binary_protocol)
    == Ok("gateway;next-protocol=:/w==:")
}

pub fn proxy_status_rejects_invalid_registered_parameter_types_test() -> Nil {
  assert status.parse_proxy("proxy;error=\"connection_timeout\"")
    == Error(status.Invalid)
  assert status.parse_proxy("proxy;next-protocol=\"h2\"")
    == Error(status.Invalid)
  assert status.parse_proxy("proxy;received-status=600")
    == Error(status.Invalid)
  assert status.parse_proxy("proxy;received-status=\"200\"")
    == Error(status.Invalid)
  assert status.parse_proxy("proxy;details=not-a-string")
    == Error(status.Invalid)
  assert status.parse_proxy("123") == Error(status.Invalid)
  assert status.parse_proxy("(proxy)") == Error(status.Invalid)
}

pub fn proxy_status_requires_token_form_for_ascii_alpn_test() -> Nil {
  assert status.parse_proxy("gateway;next-protocol=::") == Error(status.Invalid)
  assert status.parse_proxy("gateway;next-protocol=:aDMtMjk=:")
    == Error(status.Invalid)
  assert status.serialize_proxy([
      status.ProxyStatus(
        ..proxy_entry("gateway"),
        next_protocol: Some(status.ProtocolBytes(<<"h3-29":utf8>>)),
      ),
    ])
    == Error(status.Invalid)
}

pub fn proxy_status_role_and_trailer_policy_is_fail_closed_test() -> Nil {
  let entry = proxy_entry("edge")
  assert status.serialize_proxy_for(status.OriginServer, status.ProxyHeader, [
      entry,
    ])
    == Error(status.Invalid)
  assert status.serialize_proxy_for(status.Intermediary, status.ProxyHeader, [
      entry,
    ])
    == Ok("edge")
  assert status.serialize_proxy_for(
      status.Intermediary,
      status.ProxyTrailer(
        announced: [status.StringIdentifier("edge")],
        header_was_available: False,
      ),
      [entry],
    )
    == Ok("edge")
  assert status.serialize_proxy_for(
      status.Intermediary,
      status.ProxyTrailer(announced: [], header_was_available: False),
      [entry],
    )
    == Error(status.Invalid)
  assert status.serialize_proxy_for(
      status.Intermediary,
      status.ProxyTrailer(
        announced: [status.TokenIdentifier("edge")],
        header_was_available: True,
      ),
      [entry],
    )
    == Error(status.Invalid)
}

pub fn append_proxy_preserves_existing_chain_order_test() -> Nil {
  let upstream = proxy_entry("upstream")
  let edge = proxy_entry("edge")
  assert status.append_proxy([upstream], edge) == [upstream, edge]
}

pub fn public_view_removes_sensitive_and_unregistered_diagnostics_test() -> Nil {
  let assert Ok([cache]) =
    status.parse_cache(
      "cache;hit;key=\"private-key\";detail=INTERNAL;vendor=secret",
    )
  assert status.public_cache(cache)
    == status.CacheStatus(..cache, key: None, detail: None, extensions: [])

  let assert Ok([proxy]) =
    status.parse_proxy(
      "edge;error=connection_timeout;next-hop=internal;details=\"secret\";trace=private",
    )
  assert status.public_proxy(proxy)
    == status.ProxyStatus(
      ..proxy,
      next_hop: None,
      details: None,
      extensions: [],
    )
}

pub fn pinned_ratelimit_policy_round_trips_registered_values_test() -> Nil {
  let input = "\"burst\";q=100;qu=\"requests\";w=60;pk=:AQI=:;acme-burst=10"
  let assert Ok(parsed) = status.parse_rate_limit_policy(input)
  assert parsed
    == [
      status.RateLimitPolicy(
        policy: "burst",
        quota: 100,
        quota_unit: Some("requests"),
        window_seconds: Some(60),
        partition_key: Some(<<1, 2>>),
        extensions: [
          structured_fields.Parameter(
            "acme-burst",
            structured_fields.Integer(10),
          ),
        ],
      ),
    ]
  assert status.serialize_rate_limit_policy(parsed) == Ok(input)
}

pub fn pinned_ratelimit_policy_rejects_invalid_required_values_test() -> Nil {
  assert status.parse_rate_limit_policy("") == Error(status.Invalid)
  assert status.parse_rate_limit_policy("burst;q=100") == Error(status.Invalid)
  assert status.parse_rate_limit_policy("\"burst\"") == Error(status.Invalid)
  assert status.parse_rate_limit_policy("\"burst\";q=-1")
    == Error(status.Invalid)
  assert status.parse_rate_limit_policy("\"burst\";q=1;w=0")
    == Error(status.Invalid)
  assert status.parse_rate_limit_policy("\"burst\";q=1;qu=requests")
    == Error(status.Invalid)
  assert status.parse_rate_limit_policy("\"burst\";q=1;pk=opaque")
    == Error(status.Invalid)
  assert status.parse_rate_limit_policy("(\"burst\");q=1")
    == Error(status.Invalid)

  let assert Ok(with_future_extension) =
    status.parse_rate_limit_policy("\"burst\";q=1;future=2")
  assert status.serialize_rate_limit_policy(with_future_extension)
    == Ok("\"burst\";q=1;future=2")
  assert status.serialize_rate_limit_policy([]) == Error(status.Invalid)
}

pub fn pinned_ratelimit_service_limit_round_trips_and_validates_test() -> Nil {
  let input = "\"default\";r=50;t=30;pk=:dXNlcg==:;acme-note=ok"
  let assert Ok(parsed) = status.parse_rate_limit(input)
  assert parsed
    == [
      status.ServiceLimit(
        policy: "default",
        remaining: 50,
        window_seconds: Some(30),
        partition_key: Some(<<"user":utf8>>),
        extensions: [
          structured_fields.Parameter(
            "acme-note",
            structured_fields.Token("ok"),
          ),
        ],
      ),
    ]
  assert status.serialize_rate_limit(parsed) == Ok(input)

  assert status.parse_rate_limit("") == Error(status.Invalid)
  assert status.parse_rate_limit("default;r=1") == Error(status.Invalid)
  assert status.parse_rate_limit("\"default\"") == Error(status.Invalid)
  assert status.parse_rate_limit("\"default\";r=-1") == Error(status.Invalid)
  assert status.parse_rate_limit("\"default\";r=1;t=-1")
    == Error(status.Invalid)
  assert status.parse_rate_limit("\"default\";r=1;pk=user")
    == Error(status.Invalid)
  assert status.parse_rate_limit("(\"default\");r=1") == Error(status.Invalid)
}

pub fn pinned_ratelimit_generation_is_header_only_namespaced_and_capped_test() -> Nil {
  assert status.rate_limit_caps(
      maximum_quota: 0,
      maximum_window_seconds: 3600,
      maximum_units_per_second: 100,
    )
    == Error(status.Invalid)
  assert status.rate_limit_caps(
      maximum_quota: 1000,
      maximum_window_seconds: 3600,
      maximum_units_per_second: 1_000_000_000_000_000,
    )
    == Error(status.Invalid)
  let assert Ok(caps) =
    status.rate_limit_caps(
      maximum_quota: 1000,
      maximum_window_seconds: 3600,
      maximum_units_per_second: 100,
    )
  let policy =
    rate_limit_policy(quota: 100, window_seconds: Some(60), extensions: [])
  let limit =
    service_limit(remaining: 50, window_seconds: Some(30), extensions: [])
  assert status.serialize_rate_limit_policy_for(status.RateLimitHeader, caps, [
      policy,
    ])
    == Ok("\"default\";q=100;w=60")
  assert status.serialize_rate_limit_for(
      status.RateLimitHeader,
      caps,
      [limit],
      retry_after_seconds: Some(30),
    )
    == Ok("\"default\";r=50;t=30")
  assert status.serialize_rate_limit_policy_for(status.RateLimitTrailer, caps, [
      policy,
    ])
    == Error(status.Invalid)
  assert status.serialize_rate_limit_policy([
      rate_limit_policy(quota: 100, window_seconds: None, extensions: [
        structured_fields.Parameter("q", structured_fields.Integer(200)),
      ]),
    ])
    == Error(status.Invalid)
  assert status.serialize_rate_limit_for(
      status.RateLimitTrailer,
      caps,
      [limit],
      retry_after_seconds: None,
    )
    == Error(status.Invalid)

  assert status.serialize_rate_limit_for(
      status.RateLimitHeader,
      caps,
      [limit],
      retry_after_seconds: Some(29),
    )
    == Error(status.Invalid)
  assert status.serialize_rate_limit_for(
      status.RateLimitHeader,
      caps,
      [service_limit(remaining: 3001, window_seconds: Some(30), extensions: [])],
      retry_after_seconds: None,
    )
    == Error(status.Invalid)
  assert status.serialize_rate_limit_policy_for(status.RateLimitHeader, caps, [
      rate_limit_policy(quota: 100, window_seconds: Some(60), extensions: [
        structured_fields.Parameter("private", structured_fields.Integer(1)),
      ]),
    ])
    == Error(status.Invalid)
}

pub fn pinned_ratelimit_client_advice_ignores_untrusted_values_test() -> Nil {
  let assert Ok(caps) =
    status.rate_limit_caps(
      maximum_quota: 1000,
      maximum_window_seconds: 3600,
      maximum_units_per_second: 100,
    )
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "malformed",
      caps,
      retry_after_seconds: None,
    )
    == status.IgnoreRateLimit
  assert status.client_rate_limit_advice(
      status.CachedRateLimitResponse(current_age_seconds: 0),
      "\"default\";r=0;t=6",
      caps,
      retry_after_seconds: None,
    )
    == status.HonorRateLimit([
      status.RateLimitHint(
        limit: service_limit(
          remaining: 0,
          window_seconds: Some(6),
          extensions: [],
        ),
        minimum_spacing_milliseconds: Some(6000),
      ),
    ])
  assert status.client_rate_limit_advice(
      status.CachedRateLimitResponse(current_age_seconds: 1),
      "\"default\";r=10;t=6",
      caps,
      retry_after_seconds: None,
    )
    == status.IgnoreRateLimit
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "\"default\";r=10;t=6",
      caps,
      retry_after_seconds: Some(12),
    )
    == status.HonorRetryAfter(seconds: 12)
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "\"default\";r=10;t=6",
      caps,
      retry_after_seconds: None,
    )
    == status.HonorRateLimit([
      status.RateLimitHint(
        limit: service_limit(
          remaining: 10,
          window_seconds: Some(6),
          extensions: [],
        ),
        minimum_spacing_milliseconds: Some(600),
      ),
    ])
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "\"default\";r=1001;t=1",
      caps,
      retry_after_seconds: None,
    )
    == status.IgnoreRateLimit
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "\"default\";r=10;t=6",
      caps,
      retry_after_seconds: Some(-1),
    )
    == status.IgnoreRateLimit
  // Advice is deliberately per-response; a missing later field never reuses
  // a previous response's quota or inferred restoration state.
  assert status.client_rate_limit_advice(
      status.LiveRateLimitResponse,
      "",
      caps,
      retry_after_seconds: None,
    )
    == status.IgnoreRateLimit
}

pub fn pinned_ratelimit_intermediary_cannot_make_quota_more_permissive_test() -> Nil {
  let upstream =
    service_limit(remaining: 50, window_seconds: Some(30), extensions: [])
  let stricter =
    service_limit(remaining: 40, window_seconds: Some(60), extensions: [])
  assert status.restrict_rate_limit(upstream, stricter) == Ok(stricter)
  assert status.restrict_rate_limit(
      upstream,
      service_limit(remaining: 51, window_seconds: Some(60), extensions: []),
    )
    == Error(status.Invalid)
  assert status.restrict_rate_limit(
      upstream,
      service_limit(remaining: 40, window_seconds: Some(29), extensions: []),
    )
    == Error(status.Invalid)
  assert status.restrict_rate_limit(
      upstream,
      status.ServiceLimit(..stricter, policy: "other"),
    )
    == Error(status.Invalid)
}

fn proxy_entry(identifier: String) -> status.ProxyStatus {
  status.ProxyStatus(
    proxy: status.TokenIdentifier(identifier),
    error: None,
    next_hop: None,
    next_protocol: None,
    received_status: None,
    details: None,
    extensions: [],
  )
}

fn cache_entry(identifier: String) -> status.CacheStatus {
  status.CacheStatus(
    cache: status.TokenIdentifier(identifier),
    hit: Some(True),
    forwarded: None,
    forward_status: None,
    ttl: None,
    stored: None,
    collapsed: None,
    key: None,
    detail: None,
    extensions: [],
  )
}

fn rate_limit_policy(
  quota quota: Int,
  window_seconds window_seconds: Option(Int),
  extensions extensions: List(structured_fields.Parameter),
) -> status.RateLimitPolicy {
  status.RateLimitPolicy(
    policy: "default",
    quota: quota,
    quota_unit: None,
    window_seconds: window_seconds,
    partition_key: None,
    extensions: extensions,
  )
}

fn service_limit(
  remaining remaining: Int,
  window_seconds window_seconds: Option(Int),
  extensions extensions: List(structured_fields.Parameter),
) -> status.ServiceLimit {
  status.ServiceLimit(
    policy: "default",
    remaining: remaining,
    window_seconds: window_seconds,
    partition_key: None,
    extensions: extensions,
  )
}
