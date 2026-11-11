//// Complete HTTP URL components are checked against independent URL parsers.

import gleam/result
import http/internal/url_pattern/component
import http/internal/url_pattern/url

pub fn case_default_port_and_dot_segments_are_canonical_test() -> Nil {
  assert url.parse("HTTPS://EXAMPLE.COM:0443/a/../b?q=a b#x y")
    == Ok(url.Url(
      "https",
      "",
      "",
      "example.com",
      "",
      "/b",
      "q=a%20b",
      "x%20y",
      True,
      True,
      False,
    ))
}

pub fn reverse_solidus_and_missing_authority_slashes_are_special_urls_test() -> Nil {
  assert url.parse("https:example.com\\a\\..\\b")
    == Ok(url.Url(
      "https",
      "",
      "",
      "example.com",
      "",
      "/b",
      "",
      "",
      False,
      False,
      False,
    ))
}

pub fn credentials_multiple_at_signs_and_opaque_percent_are_preserved_test() -> Nil {
  assert url.parse("https://a:b@c@EXAMPLE.com/%2f?q=%2f")
    == Ok(url.Url(
      "https",
      "a",
      "b%40c",
      "example.com",
      "",
      "/%2f",
      "q=%2f",
      "",
      True,
      False,
      True,
    ))
}

pub fn empty_query_and_fragment_are_distinct_from_absence_test() -> Nil {
  assert url.parse("https://example.com?#")
    == Ok(url.Url(
      "https",
      "",
      "",
      "example.com",
      "",
      "/",
      "",
      "",
      True,
      True,
      False,
    ))
}

pub fn numeric_hosts_and_bracketed_ipv6_have_one_serialization_test() -> Nil {
  assert url.parse("https://0x7f.1:443/") |> result.map(url.origin)
    == Ok("https://127.0.0.1")
  assert url.parse("https://[0:0:0:0:0:0:0:1]:8443/") |> result.map(url.origin)
    == Ok("https://[::1]:8443")
}

pub fn malformed_authority_and_non_http_context_are_rejected_test() -> Nil {
  assert url.parse("https://example.com:80abc/") |> result.replace(Nil)
    == Error(component.InvalidPattern)
  assert url.parse("https://[::1]extra/") |> result.replace(Nil)
    == Error(component.InvalidPattern)
  assert url.parse("https:///path@/") |> result.replace(Nil)
    == Error(component.InvalidPattern)
  assert url.parse("file:///path") |> result.replace(Nil)
    == Error(component.InvalidPattern)
}

pub fn leading_control_space_and_internal_tabs_follow_url_preprocessing_test() -> Nil {
  assert url.parse(" \tHTTPS://exa\nmple.com/a\tb \r")
    == Ok(url.Url(
      "https",
      "",
      "",
      "example.com",
      "",
      "/ab",
      "",
      "",
      False,
      False,
      False,
    ))
}
