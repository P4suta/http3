import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/list
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

  // RFC 6797 section 13 asks a user agent to implement IDNA. Nothing here
  // does, so a host still carrying a U-label is refused rather than stored
  // under a name that would never match the A-label a request resolves.
  assert hsts.parse("max-age=60", "bücher.example", 0) == None
  assert hsts.from_persisted("bücher.example", False, 60_000, 0) == None
  let assert Some(a_label) =
    hsts.parse("max-age=60", "xn--bcher-kva.example", 0)
  assert a_label.host == "xn--bcher-kva.example"
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

pub fn a_cached_response_carries_the_age_it_has_accumulated_test() -> Nil {
  // RFC 9111 section 4: a stored response served without validation carries an
  // Age header field giving how long it has been held, counted from the age it
  // already had when it arrived.
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
      headers: [#("cache-control", "max-age=600"), #("age", "30")],
      body: Nil,
    )
  let assert Some(entry) =
    cache.entry(outgoing, incoming, <<"body":utf8>>, [], 1000)

  // Served the instant it was stored, the age is the one it arrived with.
  let fresh = cache.response(entry, 1000)
  assert list.key_find(fresh.headers, "age") == Ok("30")

  // Ninety seconds later it is thirty plus ninety, and the field replaces the
  // stored one rather than joining it.
  let held = cache.response(entry, 91_000)
  assert list.key_find(held.headers, "age") == Ok("120")
  assert list.filter(held.headers, fn(pair) { pair.0 == "age" })
    == [#("age", "120")]

  // A response that arrived without an Age counts from zero.
  let plain =
    response.Response(
      status: 200,
      headers: [#("cache-control", "max-age=600")],
      body: Nil,
    )
  let assert Some(entry) =
    cache.entry(outgoing, plain, <<"body":utf8>>, [], 1000)
  assert list.key_find(cache.response(entry, 46_000).headers, "age") == Ok("45")
}

pub fn a_request_that_forbids_storage_is_not_stored_test() -> Nil {
  // RFC 9111 section 5.2.1.5: a request carrying no-store means no part of it
  // or of any response to it is stored, in a private cache as much as a shared
  // one.
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [#("cache-control", "no-store")],
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
      headers: [#("cache-control", "max-age=600")],
      body: Nil,
    )
  assert cache.key(outgoing) == None
  assert cache.entry(outgoing, incoming, <<"body":utf8>>, [], 1000) == None

  // The same request without the directive is cacheable, so the refusal is the
  // directive's doing and not the request's shape.
  let storable = request.Request(..outgoing, headers: [])
  assert cache.key(storable) != None
  assert cache.entry(storable, incoming, <<"body":utf8>>, [], 1000) != None

  // A no-cache request still stores; it governs reuse, not storage.
  let revalidating =
    request.Request(..outgoing, headers: [#("cache-control", "no-cache")])
  assert cache.entry(revalidating, incoming, <<"body":utf8>>, [], 1000) != None
}

pub fn an_unsafe_method_invalidates_the_stored_response_test() -> Nil {
  // RFC 9111 section 4.4: a non-error answer to an unsafe request invalidates
  // the target URI, so the next read does not serve what the write replaced.
  let read =
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
  let write = request.Request(..read, method: gleam_http.Post)

  let assert Some(key) = cache.key(read)
  assert cache.invalidated_key(write, 200) == Some(key)
  assert cache.invalidated_key(write, 204) == Some(key)

  // An error answer changes nothing, so it invalidates nothing.
  assert cache.invalidated_key(write, 500) == None
  assert cache.invalidated_key(write, 404) == None

  // A safe method invalidates nothing either, whatever it answered.
  assert cache.invalidated_key(read, 200) == None

  // The key is the exact origin and target, so one origin's write cannot
  // invalidate another's entry.
  let elsewhere = request.Request(..write, host: "other.example")
  assert cache.invalidated_key(elsewhere, 200) != Some(key)
}
