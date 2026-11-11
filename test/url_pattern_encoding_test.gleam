//// Canonicalization controls independently observed in Node 26.8.2.

import http/internal/url_pattern/component
import http/internal/url_pattern/encoding

pub fn protocol_case_and_empty_value_are_canonical_test() -> Nil {
  assert encoding.encode(kind: encoding.Protocol, value: "HTTPS") == Ok("https")
  assert encoding.encode(kind: encoding.Protocol, value: "") == Ok("")
  assert encoding.encode(kind: encoding.Protocol, value: "1https")
    == Error(component.InvalidPattern)
}

pub fn credentials_percent_encode_reserved_and_utf8_bytes_test() -> Nil {
  assert encoding.encode(kind: encoding.Userinfo, value: "a:b@c /é")
    == Ok("a%3Ab%40c%20%2F%C3%A9")
  assert encoding.encode(kind: encoding.Userinfo, value: "%2f") == Ok("%2f")
}

pub fn query_and_fragment_have_different_encode_sets_test() -> Nil {
  assert encoding.encode(kind: encoding.Search, value: "a b'`?#é")
    == Ok("a%20b%27`?%23%C3%A9")
  assert encoding.encode(kind: encoding.Hash, value: "a b'`?#é")
    == Ok("a%20b'%60?#%C3%A9")
}

pub fn port_setter_parses_numeric_prefix_without_an_implied_scheme_test() -> Nil {
  assert encoding.encode(kind: encoding.Port, value: "00443") == Ok("443")
  assert encoding.encode(kind: encoding.Port, value: "80abc") == Ok("80")
  assert encoding.encode(kind: encoding.Port, value: "abc")
    == Error(component.InvalidPattern)
  assert encoding.encode(kind: encoding.Port, value: "65536")
    == Error(component.InvalidPattern)
}

pub fn opaque_path_preserves_slashes_and_dots_test() -> Nil {
  assert encoding.encode(kind: encoding.OpaquePath, value: "a/../b é")
    == Ok("a/../b %C3%A9")
}

pub fn opaque_path_state_separates_query_and_fragment_delimiters_test() -> Nil {
  // URLPattern invokes the URL opaque-path state, including its delimiter transitions.
  // Chromium's contrary component-setter observation is retained as a reference disagreement rather than a normative expected result.
  assert encoding.encode(kind: encoding.OpaquePath, value: "a?b") == Ok("a")
  assert encoding.encode(kind: encoding.OpaquePath, value: "a#b ") == Ok("a")
  assert encoding.encode(kind: encoding.OpaquePath, value: "a #b") == Ok("a%20")
  assert encoding.encode(kind: encoding.OpaquePath, value: "a ") == Ok("a ")
}

pub fn ipv6_pattern_pieces_are_not_complete_address_parses_test() -> Nil {
  assert encoding.encode(kind: encoding.Ipv6Pattern, value: "[ABCD:")
    == Ok("[abcd:")
  assert encoding.encode(kind: encoding.Ipv6Pattern, value: ".1]")
    == Error(component.InvalidPattern)
}
