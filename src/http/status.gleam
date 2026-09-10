//// Typed, bounded Cache-Status, Proxy-Status, and RateLimit fields.
////
//// Registered parameters are validated according to RFC 9211 and RFC 9209.
//// Unknown parameters are retained for intermediaries that understand an
//// extension, but `public_cache` and `public_proxy` remove them together with
//// deployment-sensitive diagnostics by default.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/structured_fields

const maximum_structured_integer = 999_999_999_999_999

/// A field member identifier whose String/Token wire distinction is retained.
pub type Identifier {
  TokenIdentifier(value: String)
  StringIdentifier(value: String)
}

/// The RFC 9211 detail parameter retains its String/Token wire distinction.
pub type CacheDetail {
  DetailToken(value: String)
  DetailString(value: String)
}

/// An ALPN protocol identifier in its preferred Token or binary form.
pub type ProtocolIdentifier {
  ProtocolToken(value: String)
  ProtocolBytes(value: BitArray)
}

/// One cache, ordered from the origin towards the user agent.
pub type CacheStatus {
  CacheStatus(
    cache: Identifier,
    hit: Option(Bool),
    forwarded: Option(String),
    forward_status: Option(Int),
    ttl: Option(Int),
    stored: Option(Bool),
    collapsed: Option(Bool),
    key: Option(String),
    detail: Option(CacheDetail),
    extensions: List(structured_fields.Parameter),
  )
}

/// How the response carrying Cache-Status was produced.
pub type CacheResponseSource {
  ForwardedResponse
  LocallyGeneratedResponse(based_on_stored_response: Bool)
}

/// One intermediary, ordered from the origin towards the user agent.
pub type ProxyStatus {
  ProxyStatus(
    proxy: Identifier,
    error: Option(String),
    next_hop: Option(Identifier),
    next_protocol: Option(ProtocolIdentifier),
    received_status: Option(Int),
    details: Option(String),
    extensions: List(structured_fields.Parameter),
  )
}

/// The HTTP role attempting to generate a Proxy-Status field.
pub type ProxyProducer {
  OriginServer
  Intermediary
}

/// Where an intermediary will place a Proxy-Status value.
///
/// A trailer identifies the members announced in the header section and
/// whether that section was still writable when the diagnostic became known.
pub type ProxyPlacement {
  ProxyHeader
  ProxyTrailer(announced: List(Identifier), header_was_available: Bool)
}

/// One quota policy from the revision-pinned
/// draft-ietf-httpapi-ratelimit-headers-11 field definition.
///
/// The API is stable, but the cited specification is still an Internet-Draft,
/// not RFC 9331. Unknown parameters are retained for forward compatibility.
pub type RateLimitPolicy {
  RateLimitPolicy(
    policy: String,
    quota: Int,
    quota_unit: Option(String),
    window_seconds: Option(Int),
    partition_key: Option(BitArray),
    extensions: List(structured_fields.Parameter),
  )
}

/// One current service limit associated with a quota policy.
/// Positive remaining quota is only a hint and is never a service guarantee.
pub type ServiceLimit {
  ServiceLimit(
    policy: String,
    remaining: Int,
    window_seconds: Option(Int),
    partition_key: Option(BitArray),
    extensions: List(structured_fields.Parameter),
  )
}

/// RateLimit fields are forbidden in trailers by the pinned draft revision.
pub type RateLimitPlacement {
  RateLimitHeader
  RateLimitTrailer
}

/// Whether a client received a live or stored response.
pub type RateLimitResponseSource {
  LiveRateLimitResponse
  CachedRateLimitResponse(current_age_seconds: Int)
}

/// Finite application policy for accepting or generating quota hints.
pub opaque type RateLimitCaps {
  RateLimitCaps(
    maximum_quota: Int,
    maximum_window_seconds: Int,
    maximum_units_per_second: Int,
  )
}

/// A bounded pacing hint derived from one untrusted service-limit item.
pub type RateLimitHint {
  RateLimitHint(limit: ServiceLimit, minimum_spacing_milliseconds: Option(Int))
}

/// Fail-closed client interpretation of RateLimit and Retry-After.
pub type RateLimitAdvice {
  IgnoreRateLimit
  HonorRetryAfter(seconds: Int)
  HonorRateLimit(hints: List(RateLimitHint))
}

/// A syntax, registered-parameter, or finite-resource failure.
pub type Error {
  Invalid
  LimitExceeded
}

type CacheParts {
  CacheParts(
    hit: Option(Bool),
    forwarded: Option(String),
    forward_status: Option(Int),
    ttl: Option(Int),
    stored: Option(Bool),
    collapsed: Option(Bool),
    key: Option(String),
    detail: Option(CacheDetail),
    extensions: List(structured_fields.Parameter),
  )
}

type ProxyParts {
  ProxyParts(
    error: Option(String),
    next_hop: Option(Identifier),
    next_protocol: Option(ProtocolIdentifier),
    received_status: Option(Int),
    details: Option(String),
    extensions: List(structured_fields.Parameter),
  )
}

type RateLimitPolicyParts {
  RateLimitPolicyParts(
    quota: Option(Int),
    quota_unit: Option(String),
    window_seconds: Option(Int),
    partition_key: Option(BitArray),
    extensions: List(structured_fields.Parameter),
  )
}

type ServiceLimitParts {
  ServiceLimitParts(
    remaining: Option(Int),
    window_seconds: Option(Int),
    partition_key: Option(BitArray),
    extensions: List(structured_fields.Parameter),
  )
}

/// Parse a complete Cache-Status field under the Structured Fields ceilings.
pub fn parse_cache(input: String) -> Result(List(CacheStatus), Error) {
  use members <- result.try(
    structured_fields.parse_list(input)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, parse_cache_member)
}

/// Serialize Cache-Status in deterministic registered-parameter order.
///
/// This is the low-level value codec. Caches generating an actual field should
/// use `serialize_cache_for` to enforce response-source policy.
pub fn serialize_cache(entries: List(CacheStatus)) -> Result(String, Error) {
  use members <- result.try(list.try_map(entries, cache_member))
  structured_fields.serialize_list(members)
  |> result.map_error(from_structured_error)
}

/// Serialize a Cache-Status value under RFC 9211's response-source rule.
/// A locally generated response is accepted only when it is based on a stored
/// response, such as a cache-generated 304 or 206.
pub fn serialize_cache_for(
  source: CacheResponseSource,
  entries: List(CacheStatus),
) -> Result(String, Error) {
  use _ <- result.try(case source {
    ForwardedResponse -> Ok(Nil)
    LocallyGeneratedResponse(based_on_stored_response) ->
      ensure(based_on_stored_response)
  })
  serialize_cache(entries)
}

/// Append one cache member without disturbing the origin-to-user ordering of
/// members already received.
pub fn append_cache(
  existing: List(CacheStatus),
  cache: CacheStatus,
) -> List(CacheStatus) {
  list.append(existing, [cache])
}

/// Parse a complete Proxy-Status field under the Structured Fields ceilings.
pub fn parse_proxy(input: String) -> Result(List(ProxyStatus), Error) {
  use members <- result.try(
    structured_fields.parse_list(input)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, parse_proxy_member)
}

/// Serialize Proxy-Status in deterministic registered-parameter order.
///
/// This is the low-level value codec. Intermediaries generating an actual
/// field should use `serialize_proxy_for` to enforce role and trailer policy.
pub fn serialize_proxy(entries: List(ProxyStatus)) -> Result(String, Error) {
  use members <- result.try(list.try_map(entries, proxy_member))
  structured_fields.serialize_list(members)
  |> result.map_error(from_structured_error)
}

/// Serialize a Proxy-Status value under RFC 9209's producer and placement
/// rules. Origin servers are rejected. Trailer values require an earlier
/// header member with the same identifier and are rejected when the header
/// section was still available.
pub fn serialize_proxy_for(
  producer: ProxyProducer,
  placement: ProxyPlacement,
  entries: List(ProxyStatus),
) -> Result(String, Error) {
  case producer {
    OriginServer -> Error(Invalid)
    Intermediary -> {
      use _ <- result.try(case placement {
        ProxyHeader -> Ok(Nil)
        ProxyTrailer(announced, header_was_available) ->
          ensure(
            !header_was_available
            && list.all(entries, fn(entry) {
              identifier_announced(entry.proxy, announced)
            }),
          )
      })
      serialize_proxy(entries)
    }
  }
}

/// Append one intermediary member without disturbing the origin-to-client
/// ordering of members already received.
pub fn append_proxy(
  existing: List(ProxyStatus),
  intermediary: ProxyStatus,
) -> List(ProxyStatus) {
  list.append(existing, [intermediary])
}

/// Construct finite RateLimit ceilings.
///
/// All values are positive and no larger than a Structured Fields Integer.
/// Callers choose values appropriate for their capacity; the library does not
/// hide a universal throughput limit in an unsafe default.
pub fn rate_limit_caps(
  maximum_quota maximum_quota: Int,
  maximum_window_seconds maximum_window_seconds: Int,
  maximum_units_per_second maximum_units_per_second: Int,
) -> Result(RateLimitCaps, Error) {
  use _ <- result.try(ensure(
    valid_ceiling(maximum_quota)
    && valid_ceiling(maximum_window_seconds)
    && valid_ceiling(maximum_units_per_second),
  ))
  Ok(RateLimitCaps(
    maximum_quota: maximum_quota,
    maximum_window_seconds: maximum_window_seconds,
    maximum_units_per_second: maximum_units_per_second,
  ))
}

/// Parse a complete, non-empty RateLimit-Policy field.
pub fn parse_rate_limit_policy(
  input: String,
) -> Result(List(RateLimitPolicy), Error) {
  use members <- result.try(
    structured_fields.parse_list(input)
    |> result.map_error(from_structured_error),
  )
  use _ <- result.try(ensure(members != []))
  list.try_map(members, parse_rate_limit_policy_member)
}

/// Serialize a RateLimit-Policy value without deployment policy checks.
/// Use `serialize_rate_limit_policy_for` for a generated response field.
pub fn serialize_rate_limit_policy(
  entries: List(RateLimitPolicy),
) -> Result(String, Error) {
  use _ <- result.try(ensure(entries != []))
  use members <- result.try(list.try_map(entries, rate_limit_policy_member))
  structured_fields.serialize_list(members)
  |> result.map_error(from_structured_error)
}

/// Generate a header-only, finite RateLimit-Policy value.
/// Implementation-specific extensions must use a vendor-prefixed key.
pub fn serialize_rate_limit_policy_for(
  placement: RateLimitPlacement,
  caps: RateLimitCaps,
  entries: List(RateLimitPolicy),
) -> Result(String, Error) {
  use _ <- result.try(ensure(placement == RateLimitHeader))
  use _ <- result.try(
    ensure(
      list.all(entries, fn(entry) {
        policy_within_caps(entry, caps)
        && generation_extensions_valid(entry.extensions, ["q", "qu", "w", "pk"])
      }),
    ),
  )
  serialize_rate_limit_policy(entries)
}

/// Parse a complete, non-empty RateLimit field.
pub fn parse_rate_limit(input: String) -> Result(List(ServiceLimit), Error) {
  use members <- result.try(
    structured_fields.parse_list(input)
    |> result.map_error(from_structured_error),
  )
  use _ <- result.try(ensure(members != []))
  list.try_map(members, parse_service_limit_member)
}

/// Serialize a RateLimit value without deployment policy checks.
/// Use `serialize_rate_limit_for` for a generated response field.
pub fn serialize_rate_limit(
  entries: List(ServiceLimit),
) -> Result(String, Error) {
  use _ <- result.try(ensure(entries != []))
  use members <- result.try(list.try_map(entries, service_limit_member))
  structured_fields.serialize_list(members)
  |> result.map_error(from_structured_error)
}

/// Generate a header-only, finite RateLimit value.
///
/// A normalized Retry-After delay, when present, must not end before any
/// advertised effective window. Implementation-specific extensions must use
/// a vendor-prefixed key.
pub fn serialize_rate_limit_for(
  placement: RateLimitPlacement,
  caps: RateLimitCaps,
  entries: List(ServiceLimit),
  retry_after_seconds retry_after_seconds: Option(Int),
) -> Result(String, Error) {
  use _ <- result.try(ensure(placement == RateLimitHeader))
  use _ <- result.try(
    ensure(retry_after_covers_windows(retry_after_seconds, entries)),
  )
  use _ <- result.try(
    ensure(
      list.all(entries, fn(entry) {
        service_limit_within_caps(entry, caps)
        && generation_extensions_valid(entry.extensions, ["r", "t", "pk"])
      }),
    ),
  )
  serialize_rate_limit(entries)
}

/// Interpret untrusted response fields without treating them as a service
/// guarantee. Valid Retry-After takes precedence. Malformed, stale cached, or
/// over-ceiling RateLimit values are ignored rather than partially applied.
pub fn client_rate_limit_advice(
  source: RateLimitResponseSource,
  input: String,
  caps: RateLimitCaps,
  retry_after_seconds retry_after_seconds: Option(Int),
) -> RateLimitAdvice {
  case retry_after_seconds {
    Some(seconds) if seconds >= 0 -> HonorRetryAfter(seconds: seconds)
    Some(_) -> IgnoreRateLimit
    None ->
      case source {
        CachedRateLimitResponse(current_age_seconds)
          if current_age_seconds != 0
        -> IgnoreRateLimit
        _ -> fresh_rate_limit_advice(input, caps)
      }
  }
}

fn fresh_rate_limit_advice(
  input: String,
  caps: RateLimitCaps,
) -> RateLimitAdvice {
  parse_rate_limit(input)
  |> result.map(fn(limits) {
    case
      list.all(limits, fn(limit) { service_limit_within_caps(limit, caps) })
    {
      True -> HonorRateLimit(list.map(limits, rate_limit_hint))
      False -> IgnoreRateLimit
    }
  })
  |> result.unwrap(IgnoreRateLimit)
}

/// Accept an intermediary replacement only when it identifies the same quota
/// partition and is provably no more permissive than the upstream value.
pub fn restrict_rate_limit(
  upstream: ServiceLimit,
  replacement: ServiceLimit,
) -> Result(ServiceLimit, Error) {
  use _ <- result.try(ensure(
    upstream.policy == replacement.policy
    && upstream.partition_key == replacement.partition_key
    && replacement.remaining <= upstream.remaining
    && window_is_no_more_permissive(
      upstream.window_seconds,
      replacement.window_seconds,
    ),
  ))
  Ok(replacement)
}

/// Remove cache-key, implementation detail, and all unregistered parameters.
/// Applications must explicitly use the original value to expose them.
pub fn public_cache(entry: CacheStatus) -> CacheStatus {
  CacheStatus(..entry, key: None, detail: None, extensions: [])
}

/// Remove next-hop, free-form details, and all unregistered parameters.
/// Applications must explicitly use the original value to expose them.
pub fn public_proxy(entry: ProxyStatus) -> ProxyStatus {
  ProxyStatus(..entry, next_hop: None, details: None, extensions: [])
}

fn parse_rate_limit_policy_member(
  member: structured_fields.ListMember,
) -> Result(RateLimitPolicy, Error) {
  case member {
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.StringValue(policy),
      parameters,
    )) -> {
      use parts <- result.try(parse_rate_limit_policy_parameters(
        parameters,
        RateLimitPolicyParts(None, None, None, None, []),
      ))
      case parts.quota {
        None -> Error(Invalid)
        Some(quota) ->
          Ok(RateLimitPolicy(
            policy: policy,
            quota: quota,
            quota_unit: parts.quota_unit,
            window_seconds: parts.window_seconds,
            partition_key: parts.partition_key,
            extensions: list.reverse(parts.extensions),
          ))
      }
    }
    _ -> Error(Invalid)
  }
}

fn parse_rate_limit_policy_parameters(
  parameters: List(structured_fields.Parameter),
  parts: RateLimitPolicyParts,
) -> Result(RateLimitPolicyParts, Error) {
  case parameters {
    [] -> Ok(parts)
    [parameter, ..rest] -> {
      use parts <- result.try(parse_rate_limit_policy_parameter(
        parameter,
        parts,
      ))
      parse_rate_limit_policy_parameters(rest, parts)
    }
  }
}

fn parse_rate_limit_policy_parameter(
  parameter: structured_fields.Parameter,
  parts: RateLimitPolicyParts,
) -> Result(RateLimitPolicyParts, Error) {
  let structured_fields.Parameter(name, value) = parameter
  case name, value {
    "q", structured_fields.Integer(value) if value >= 0 ->
      Ok(RateLimitPolicyParts(..parts, quota: Some(value)))
    "qu", structured_fields.StringValue(value) ->
      Ok(RateLimitPolicyParts(..parts, quota_unit: Some(value)))
    "w", structured_fields.Integer(value) if value > 0 ->
      Ok(RateLimitPolicyParts(..parts, window_seconds: Some(value)))
    "pk", structured_fields.ByteSequence(value) ->
      Ok(RateLimitPolicyParts(..parts, partition_key: Some(value)))
    name, _ ->
      case rate_limit_policy_registered(name) {
        True -> Error(Invalid)
        False ->
          Ok(
            RateLimitPolicyParts(..parts, extensions: [
              parameter,
              ..parts.extensions
            ]),
          )
      }
  }
}

fn rate_limit_policy_member(
  entry: RateLimitPolicy,
) -> Result(structured_fields.ListMember, Error) {
  use _ <- result.try(ensure(
    entry.quota >= 0
    && optional_positive(entry.window_seconds)
    && extensions_registered_free(entry.extensions, ["q", "qu", "w", "pk"]),
  ))
  let parameters =
    []
    |> add_optional_integer("q", Some(entry.quota))
    |> add_optional_string("qu", entry.quota_unit)
    |> add_optional_integer("w", entry.window_seconds)
    |> add_optional_bytes("pk", entry.partition_key)
    |> list.append(entry.extensions)
  Ok(
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.StringValue(entry.policy),
      parameters,
    )),
  )
}

fn parse_service_limit_member(
  member: structured_fields.ListMember,
) -> Result(ServiceLimit, Error) {
  case member {
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.StringValue(policy),
      parameters,
    )) -> {
      use parts <- result.try(parse_service_limit_parameters(
        parameters,
        ServiceLimitParts(None, None, None, []),
      ))
      case parts.remaining {
        None -> Error(Invalid)
        Some(remaining) ->
          Ok(ServiceLimit(
            policy: policy,
            remaining: remaining,
            window_seconds: parts.window_seconds,
            partition_key: parts.partition_key,
            extensions: list.reverse(parts.extensions),
          ))
      }
    }
    _ -> Error(Invalid)
  }
}

fn parse_service_limit_parameters(
  parameters: List(structured_fields.Parameter),
  parts: ServiceLimitParts,
) -> Result(ServiceLimitParts, Error) {
  case parameters {
    [] -> Ok(parts)
    [parameter, ..rest] -> {
      use parts <- result.try(parse_service_limit_parameter(parameter, parts))
      parse_service_limit_parameters(rest, parts)
    }
  }
}

fn parse_service_limit_parameter(
  parameter: structured_fields.Parameter,
  parts: ServiceLimitParts,
) -> Result(ServiceLimitParts, Error) {
  let structured_fields.Parameter(name, value) = parameter
  case name, value {
    "r", structured_fields.Integer(value) if value >= 0 ->
      Ok(ServiceLimitParts(..parts, remaining: Some(value)))
    "t", structured_fields.Integer(value) if value >= 0 ->
      Ok(ServiceLimitParts(..parts, window_seconds: Some(value)))
    "pk", structured_fields.ByteSequence(value) ->
      Ok(ServiceLimitParts(..parts, partition_key: Some(value)))
    name, _ ->
      case service_limit_registered(name) {
        True -> Error(Invalid)
        False ->
          Ok(
            ServiceLimitParts(..parts, extensions: [
              parameter,
              ..parts.extensions
            ]),
          )
      }
  }
}

fn service_limit_member(
  entry: ServiceLimit,
) -> Result(structured_fields.ListMember, Error) {
  use _ <- result.try(ensure(
    entry.remaining >= 0
    && optional_non_negative(entry.window_seconds)
    && extensions_registered_free(entry.extensions, ["r", "t", "pk"]),
  ))
  let parameters =
    []
    |> add_optional_integer("r", Some(entry.remaining))
    |> add_optional_integer("t", entry.window_seconds)
    |> add_optional_bytes("pk", entry.partition_key)
    |> list.append(entry.extensions)
  Ok(
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.StringValue(entry.policy),
      parameters,
    )),
  )
}

fn parse_cache_member(
  member: structured_fields.ListMember,
) -> Result(CacheStatus, Error) {
  case member {
    structured_fields.ListItem(structured_fields.Item(value, parameters)) -> {
      use cache <- result.try(identifier(value))
      use parts <- result.try(parse_cache_parameters(
        parameters,
        CacheParts(None, None, None, None, None, None, None, None, []),
      ))
      use _ <- result.try(ensure(not_both_some(parts.hit, parts.forwarded)))
      Ok(CacheStatus(
        cache: cache,
        hit: parts.hit,
        forwarded: parts.forwarded,
        forward_status: parts.forward_status,
        ttl: parts.ttl,
        stored: parts.stored,
        collapsed: parts.collapsed,
        key: parts.key,
        detail: parts.detail,
        extensions: list.reverse(parts.extensions),
      ))
    }
    structured_fields.InnerList(_, _) -> Error(Invalid)
  }
}

fn parse_cache_parameters(
  parameters: List(structured_fields.Parameter),
  parts: CacheParts,
) -> Result(CacheParts, Error) {
  case parameters {
    [] -> Ok(parts)
    [parameter, ..rest] -> {
      use parts <- result.try(parse_cache_parameter(parameter, parts))
      parse_cache_parameters(rest, parts)
    }
  }
}

fn parse_cache_parameter(
  parameter: structured_fields.Parameter,
  parts: CacheParts,
) -> Result(CacheParts, Error) {
  let structured_fields.Parameter(name, value) = parameter
  case name, value {
    "hit", structured_fields.Boolean(value) ->
      Ok(CacheParts(..parts, hit: Some(value)))
    "fwd", structured_fields.Token(value) ->
      Ok(CacheParts(..parts, forwarded: Some(value)))
    "fwd-status", structured_fields.Integer(value) ->
      case valid_status(value) {
        True -> Ok(CacheParts(..parts, forward_status: Some(value)))
        False -> Error(Invalid)
      }
    "ttl", structured_fields.Integer(value) ->
      Ok(CacheParts(..parts, ttl: Some(value)))
    "stored", structured_fields.Boolean(value) ->
      Ok(CacheParts(..parts, stored: Some(value)))
    "collapsed", structured_fields.Boolean(value) ->
      Ok(CacheParts(..parts, collapsed: Some(value)))
    "key", structured_fields.StringValue(value) ->
      Ok(CacheParts(..parts, key: Some(value)))
    "detail", structured_fields.Token(value) ->
      Ok(CacheParts(..parts, detail: Some(DetailToken(value))))
    "detail", structured_fields.StringValue(value) ->
      Ok(CacheParts(..parts, detail: Some(DetailString(value))))
    name, _ ->
      case cache_registered(name) {
        True -> Error(Invalid)
        False ->
          Ok(CacheParts(..parts, extensions: [parameter, ..parts.extensions]))
      }
  }
}

fn cache_member(
  entry: CacheStatus,
) -> Result(structured_fields.ListMember, Error) {
  use _ <- result.try(ensure(not_both_some(entry.hit, entry.forwarded)))
  use _ <- result.try(ensure(optional_status_valid(entry.forward_status)))
  let parameters = cache_parameters(entry)
  Ok(
    structured_fields.ListItem(structured_fields.Item(
      identifier_bare(entry.cache),
      parameters,
    )),
  )
}

fn cache_parameters(entry: CacheStatus) -> List(structured_fields.Parameter) {
  []
  |> add_optional_bool("hit", entry.hit)
  |> add_optional_token("fwd", entry.forwarded)
  |> add_optional_integer("fwd-status", entry.forward_status)
  |> add_optional_integer("ttl", entry.ttl)
  |> add_optional_bool("stored", entry.stored)
  |> add_optional_bool("collapsed", entry.collapsed)
  |> add_optional_string("key", entry.key)
  |> add_optional_cache_detail(entry.detail)
  |> list.append(entry.extensions)
}

fn parse_proxy_member(
  member: structured_fields.ListMember,
) -> Result(ProxyStatus, Error) {
  case member {
    structured_fields.ListItem(structured_fields.Item(value, parameters)) -> {
      use proxy <- result.try(identifier(value))
      use parts <- result.try(parse_proxy_parameters(
        parameters,
        ProxyParts(None, None, None, None, None, []),
      ))
      Ok(ProxyStatus(
        proxy: proxy,
        error: parts.error,
        next_hop: parts.next_hop,
        next_protocol: parts.next_protocol,
        received_status: parts.received_status,
        details: parts.details,
        extensions: list.reverse(parts.extensions),
      ))
    }
    structured_fields.InnerList(_, _) -> Error(Invalid)
  }
}

fn parse_proxy_parameters(
  parameters: List(structured_fields.Parameter),
  parts: ProxyParts,
) -> Result(ProxyParts, Error) {
  case parameters {
    [] -> Ok(parts)
    [parameter, ..rest] -> {
      use parts <- result.try(parse_proxy_parameter(parameter, parts))
      parse_proxy_parameters(rest, parts)
    }
  }
}

fn parse_proxy_parameter(
  parameter: structured_fields.Parameter,
  parts: ProxyParts,
) -> Result(ProxyParts, Error) {
  let structured_fields.Parameter(name, value) = parameter
  case name, value {
    "error", structured_fields.Token(value) ->
      Ok(ProxyParts(..parts, error: Some(value)))
    "next-hop", value -> {
      use value <- result.try(identifier(value))
      Ok(ProxyParts(..parts, next_hop: Some(value)))
    }
    "next-protocol", structured_fields.Token(value) -> {
      let protocol = ProtocolToken(value)
      use _ <- result.try(validate_protocol_identifier(Some(protocol)))
      Ok(ProxyParts(..parts, next_protocol: Some(protocol)))
    }
    "next-protocol", structured_fields.ByteSequence(value) -> {
      let protocol = ProtocolBytes(value)
      use _ <- result.try(validate_protocol_identifier(Some(protocol)))
      Ok(ProxyParts(..parts, next_protocol: Some(protocol)))
    }
    "received-status", structured_fields.Integer(value) ->
      case valid_status(value) {
        True -> Ok(ProxyParts(..parts, received_status: Some(value)))
        False -> Error(Invalid)
      }
    "details", structured_fields.StringValue(value) ->
      Ok(ProxyParts(..parts, details: Some(value)))
    name, _ ->
      case proxy_registered(name) {
        True -> Error(Invalid)
        False ->
          Ok(ProxyParts(..parts, extensions: [parameter, ..parts.extensions]))
      }
  }
}

fn proxy_member(
  entry: ProxyStatus,
) -> Result(structured_fields.ListMember, Error) {
  use _ <- result.try(ensure(optional_status_valid(entry.received_status)))
  use _ <- result.try(validate_protocol_identifier(entry.next_protocol))
  let parameters = proxy_parameters(entry)
  Ok(
    structured_fields.ListItem(structured_fields.Item(
      identifier_bare(entry.proxy),
      parameters,
    )),
  )
}

fn proxy_parameters(entry: ProxyStatus) -> List(structured_fields.Parameter) {
  []
  |> add_optional_token("error", entry.error)
  |> add_optional_identifier("next-hop", entry.next_hop)
  |> add_optional_protocol(entry.next_protocol)
  |> add_optional_integer("received-status", entry.received_status)
  |> add_optional_string("details", entry.details)
  |> list.append(entry.extensions)
}

fn identifier(value: structured_fields.BareItem) -> Result(Identifier, Error) {
  case value {
    structured_fields.Token(value) -> Ok(TokenIdentifier(value))
    structured_fields.StringValue(value) -> Ok(StringIdentifier(value))
    _ -> Error(Invalid)
  }
}

fn identifier_bare(value: Identifier) -> structured_fields.BareItem {
  case value {
    TokenIdentifier(value) -> structured_fields.Token(value)
    StringIdentifier(value) -> structured_fields.StringValue(value)
  }
}

fn identifier_announced(
  identifier: Identifier,
  announced: List(Identifier),
) -> Bool {
  let expected = identifier_value(identifier)
  list.any(announced, fn(value) { identifier_value(value) == expected })
}

fn identifier_value(identifier: Identifier) -> String {
  case identifier {
    TokenIdentifier(value) -> value
    StringIdentifier(value) -> value
  }
}

fn validate_protocol_identifier(
  identifier: Option(ProtocolIdentifier),
) -> Result(Nil, Error) {
  case identifier {
    None -> Ok(Nil)
    Some(ProtocolToken(value)) ->
      ensure(string.byte_size(value) > 0 && string.byte_size(value) <= 255)
    Some(ProtocolBytes(value)) ->
      ensure(
        bit_array.bit_size(value) % 8 == 0
        && bit_array.byte_size(value) > 0
        && bit_array.byte_size(value) <= 255
        && !protocol_bytes_have_token_form(value),
      )
  }
}

fn protocol_bytes_have_token_form(value: BitArray) -> Bool {
  case value {
    <<first, rest:bits>> ->
      case token_first_byte(first) {
        True -> all_token_bytes(rest)
        False -> False
      }
    _ -> False
  }
}

fn all_token_bytes(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> -> token_byte(byte) && all_token_bytes(rest)
    _ -> False
  }
}

fn token_first_byte(byte: Int) -> Bool {
  byte >= 0x61 && byte <= 0x7a || byte >= 0x41 && byte <= 0x5a || byte == 0x2a
}

fn token_byte(byte: Int) -> Bool {
  token_first_byte(byte)
  || byte >= 0x30
  && byte <= 0x39
  || byte == 0x21
  || byte == 0x23
  || byte == 0x24
  || byte == 0x25
  || byte == 0x26
  || byte == 0x27
  || byte == 0x2b
  || byte == 0x2d
  || byte == 0x2e
  || byte == 0x3a
  || byte == 0x2f
  || byte == 0x5e
  || byte == 0x5f
  || byte == 0x60
  || byte == 0x7c
  || byte == 0x7e
}

fn add_optional_bool(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(Bool),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, structured_fields.Boolean(value)),
      ])
  }
}

fn add_optional_token(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(String),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, structured_fields.Token(value)),
      ])
  }
}

fn add_optional_integer(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(Int),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, structured_fields.Integer(value)),
      ])
  }
}

fn add_optional_string(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(String),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, structured_fields.StringValue(value)),
      ])
  }
}

fn add_optional_bytes(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(BitArray),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, structured_fields.ByteSequence(value)),
      ])
  }
}

fn add_optional_identifier(
  parameters: List(structured_fields.Parameter),
  name: String,
  value: Option(Identifier),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(value) ->
      list.append(parameters, [
        structured_fields.Parameter(name, identifier_bare(value)),
      ])
  }
}

fn add_optional_cache_detail(
  parameters: List(structured_fields.Parameter),
  value: Option(CacheDetail),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(DetailToken(value)) ->
      list.append(parameters, [
        structured_fields.Parameter("detail", structured_fields.Token(value)),
      ])
    Some(DetailString(value)) ->
      list.append(parameters, [
        structured_fields.Parameter(
          "detail",
          structured_fields.StringValue(value),
        ),
      ])
  }
}

fn add_optional_protocol(
  parameters: List(structured_fields.Parameter),
  value: Option(ProtocolIdentifier),
) -> List(structured_fields.Parameter) {
  case value {
    None -> parameters
    Some(ProtocolToken(value)) ->
      list.append(parameters, [
        structured_fields.Parameter(
          "next-protocol",
          structured_fields.Token(value),
        ),
      ])
    Some(ProtocolBytes(value)) ->
      list.append(parameters, [
        structured_fields.Parameter(
          "next-protocol",
          structured_fields.ByteSequence(value),
        ),
      ])
  }
}

fn valid_status(value: Int) -> Bool {
  value >= 100 && value <= 599
}

fn optional_status_valid(value: Option(Int)) -> Bool {
  case value {
    None -> True
    Some(value) -> valid_status(value)
  }
}

fn not_both_some(first: Option(a), second: Option(b)) -> Bool {
  case first, second {
    Some(_), Some(_) -> False
    _, _ -> True
  }
}

fn cache_registered(name: String) -> Bool {
  list.contains(
    [
      "hit",
      "fwd",
      "fwd-status",
      "ttl",
      "stored",
      "collapsed",
      "key",
      "detail",
    ],
    name,
  )
}

fn proxy_registered(name: String) -> Bool {
  list.contains(
    ["error", "next-hop", "next-protocol", "received-status", "details"],
    name,
  )
}

fn rate_limit_policy_registered(name: String) -> Bool {
  list.contains(["q", "qu", "w", "pk"], name)
}

fn service_limit_registered(name: String) -> Bool {
  list.contains(["r", "t", "pk"], name)
}

fn extensions_registered_free(
  extensions: List(structured_fields.Parameter),
  registered: List(String),
) -> Bool {
  list.all(extensions, fn(parameter) {
    let structured_fields.Parameter(name, _) = parameter
    !list.contains(registered, name)
  })
}

fn generation_extensions_valid(
  extensions: List(structured_fields.Parameter),
  registered: List(String),
) -> Bool {
  list.all(extensions, fn(parameter) {
    let structured_fields.Parameter(name, _) = parameter
    !list.contains(registered, name)
    && string.contains(name, "-")
    && !string.starts_with(name, "-")
    && !string.ends_with(name, "-")
  })
}

fn valid_ceiling(value: Int) -> Bool {
  value > 0 && value <= maximum_structured_integer
}

fn optional_positive(value: Option(Int)) -> Bool {
  case value {
    None -> True
    Some(value) -> value > 0
  }
}

fn optional_non_negative(value: Option(Int)) -> Bool {
  case value {
    None -> True
    Some(value) -> value >= 0
  }
}

fn policy_within_caps(entry: RateLimitPolicy, caps: RateLimitCaps) -> Bool {
  quota_within_caps(entry.quota, entry.window_seconds, caps)
}

fn service_limit_within_caps(entry: ServiceLimit, caps: RateLimitCaps) -> Bool {
  quota_within_caps(entry.remaining, entry.window_seconds, caps)
}

fn quota_within_caps(
  quota: Int,
  window_seconds: Option(Int),
  caps: RateLimitCaps,
) -> Bool {
  let RateLimitCaps(
    maximum_quota,
    maximum_window_seconds,
    maximum_units_per_second,
  ) = caps
  quota >= 0
  && quota <= maximum_quota
  && case window_seconds {
    None -> True
    Some(seconds) ->
      seconds >= 0
      && seconds <= maximum_window_seconds
      && quota <= maximum_units_per_second * seconds
  }
}

fn retry_after_covers_windows(
  retry_after_seconds: Option(Int),
  entries: List(ServiceLimit),
) -> Bool {
  case retry_after_seconds {
    None -> True
    Some(seconds) if seconds < 0 -> False
    Some(seconds) ->
      list.all(entries, fn(entry) {
        case entry.window_seconds {
          None -> True
          Some(window) -> seconds >= window
        }
      })
  }
}

fn rate_limit_hint(limit: ServiceLimit) -> RateLimitHint {
  let spacing = case limit.window_seconds {
    None -> None
    Some(window) if limit.remaining == 0 -> Some(window * 1000)
    Some(window) ->
      Some({ window * 1000 + limit.remaining - 1 } / limit.remaining)
  }
  RateLimitHint(limit: limit, minimum_spacing_milliseconds: spacing)
}

fn window_is_no_more_permissive(
  upstream: Option(Int),
  replacement: Option(Int),
) -> Bool {
  case upstream, replacement {
    None, None -> True
    Some(upstream), Some(replacement) -> replacement >= upstream
    _, _ -> False
  }
}

fn ensure(condition: Bool) -> Result(Nil, Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(Invalid)
  }
}

fn from_structured_error(error: structured_fields.Error) -> Error {
  case error {
    structured_fields.Invalid -> Invalid
    structured_fields.LimitExceeded -> LimitExceeded
  }
}
