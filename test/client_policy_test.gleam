import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleeunit
import http/internal/alt_svc
import http/internal/cache
import http/internal/cookie

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
