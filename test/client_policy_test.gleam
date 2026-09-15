import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleeunit
import http/internal/alt_svc
import http/internal/cache
import http/internal/cookie
import http/internal/hsts

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn alt_svc_clear_produces_an_exact_origin_expiry_test() -> Nil {
  let assert Some(entry) = alt_svc.parse("clear", "Example.COM", 443, 10_000)
  assert entry.origin_host == "example.com"
  assert entry.origin_port == 443
  assert entry.expires_at == 10_000
  assert !alt_svc.supports_same_port([entry], "example.com", 443, 10_000)
}

pub fn cache_subtracts_a_valid_age_from_explicit_freshness_test() -> Nil {
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: Nil,
      scheme: gleam_http.Https,
      host: "example.com",
      port: None,
      path: "/resource",
      query: None,
    )
  let incoming =
    response.Response(
      status: 200,
      headers: [#("cache-control", "max-age=60"), #("age", "60")],
      body: Nil,
    )

  assert cache.entry(outgoing, incoming, <<"stale":utf8>>, [], 1000) == None
}

pub fn ip_origins_reject_suffix_domain_cookies_test() -> Nil {
  assert cookie.parse(
      "sid=secret; Domain=0.0.1; Path=/; Max-Age=60",
      gleam_http.Https,
      "127.0.0.1",
      "/",
      1000,
    )
    == None
}

pub fn host_only_cookies_never_escape_to_a_subdomain_test() -> Nil {
  let assert Some(host_only) =
    cookie.parse(
      "sid=host; Path=/; Max-Age=60",
      gleam_http.Https,
      "example.com",
      "/",
      1000,
    )
  let assert Some(domain) =
    cookie.parse(
      "sid=domain; Domain=example.com; Path=/; Max-Age=60",
      gleam_http.Https,
      "example.com",
      "/",
      1000,
    )

  assert cookie.request_header(
      [host_only],
      gleam_http.Https,
      "sub.example.com",
      "/",
      2000,
    )
    == None
  assert cookie.request_header(
      [domain],
      gleam_http.Https,
      "sub.example.com",
      "/",
      2000,
    )
    == Some("sid=domain")
}

pub fn a_strict_transport_security_directive_may_appear_only_once_test() -> Nil {
  // RFC 6797 section 6.1: all directives appear only once, and a field that
  // does not conform to the syntax is ignored rather than partly believed.
  let assert Some(entry) =
    hsts.parse("max-age=60; includeSubDomains", "example.com", 0)
  assert entry.include_subdomains
  assert entry.expires_at == 60_000

  assert hsts.parse("max-age=60; max-age=120", "example.com", 0) == None
  assert hsts.parse(
      "max-age=60; includeSubDomains; includeSubDomains",
      "example.com",
      0,
    )
    == None
  assert hsts.parse("max-age=60; extra; extra", "example.com", 0) == None

  // An omitted directive is admissible in every position, so the empty spans a
  // trailing or doubled separator leaves are not repeats of one another.
  let assert Some(trailing) = hsts.parse("max-age=60;;", "example.com", 0)
  assert trailing.expires_at == 60_000

  // The field still has to carry max-age, and an unrecognised directive on its
  // own is still ignored rather than refusing the field.
  assert hsts.parse("includeSubDomains", "example.com", 0) == None
  let assert Some(unknown) = hsts.parse("max-age=60; extra=1", "example.com", 0)
  assert !unknown.include_subdomains

  // A recognised name carrying the wrong shape conveys nothing, so it is
  // ignored the way an unrecognised one is. Subdomains are not covered on an
  // `includeSubDomains` that came with a value, and a bare `max-age` leaves the
  // field without the directive it has to carry.
  let assert Some(valued) =
    hsts.parse("max-age=60; includeSubDomains=1", "example.com", 0)
  assert !valued.include_subdomains
  assert hsts.parse("max-age; includeSubDomains", "example.com", 0) == None
}
