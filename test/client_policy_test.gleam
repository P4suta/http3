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

pub fn an_ip_literal_host_is_never_noted_as_an_hsts_host_test() -> Nil {
  // RFC 6797 section 8.1.1: an address is not a name, so a policy keyed on one
  // would outlive whatever answers at that address. Both literal forms and the
  // bracketed IPv6 form are refused before an entry exists.
  assert hsts.parse("max-age=60", "192.0.2.1", 0) == None
  assert hsts.parse("max-age=60", "[2001:db8::1]", 0) == None
  assert hsts.parse("max-age=60", "2001:db8::1", 0) == None
  assert hsts.parse("max-age=60", "255.255.255.255", 0) == None

  // A name that merely looks numeric in one label is still a name.
  let assert Some(named) = hsts.parse("max-age=60", "192.0.2.example", 0)
  assert named.host == "192.0.2.example"
  let assert Some(short) = hsts.parse("max-age=60", "1.2.3", 0)
  assert short.host == "1.2.3"

  // The persisted path refuses the same hosts, so a store written by an older
  // build cannot reintroduce one.
  assert hsts.from_persisted("192.0.2.1", False, 60_000, 0) == None
  assert hsts.from_persisted("[2001:db8::1]", False, 60_000, 0) == None
}

pub fn an_alt_svc_parameter_may_be_quoted_and_carry_delimiters_test() -> Nil {
  // RFC 7838 section 3: every field element that allows quoted-string syntax is
  // processed per RFC 7230 section 3.2.6. A parameter value may be a
  // quoted-string, so `,` and `;` inside one end neither the alt-value nor the
  // parameter list, and `ma` may be sent quoted.
  let assert Some(plain) =
    alt_svc.parse("h3=\":443\"; ma=3600", "Example.COM", 443, 0)
  assert plain.alternative_port == 443
  assert plain.expires_at == 3_600_000

  let assert Some(comma) =
    alt_svc.parse(
      "h3=\":443\"; persist=\"a,b\"; ma=3600",
      "example.com",
      443,
      0,
    )
  assert comma.alternative_port == 443
  assert comma.expires_at == 3_600_000

  let assert Some(semicolon) =
    alt_svc.parse("h3=\":443\"; note=\"x;y\"; ma=60", "example.com", 443, 0)
  assert semicolon.expires_at == 60_000

  let assert Some(quoted_age) =
    alt_svc.parse("h3=\":443\"; ma=\"3600\"", "example.com", 443, 0)
  assert quoted_age.expires_at == 3_600_000

  // A parameter this module does not read still ends where its quote does, so
  // an `ma` written inside one is text rather than a maximum age.
  assert alt_svc.parse("h3=\":443\"; note=\"; ma=99; \"", "example.com", 443, 0)
    == None

  // An unterminated quote is still refused rather than read to the end of the
  // field, and a second alternative is still reached when the first is not h3.
  assert alt_svc.parse("h3=\":443", "example.com", 443, 0) == None
  assert alt_svc.parse("h3=\":443; ma=60", "example.com", 443, 0) == None
  let assert Some(second) =
    alt_svc.parse(
      "h2=\":443\"; ma=60, h3=\":8443\"; ma=120",
      "example.com",
      443,
      0,
    )
  assert second.alternative_port == 8443
  assert second.expires_at == 120_000
}
