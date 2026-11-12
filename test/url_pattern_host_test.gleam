//// Fixed scalar assertions keep prospective host inputs out of failure output.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/dynamic
import gleam/list
import gleam/string
import http/internal/url_pattern/host
import http/internal/url_pattern/host_data
import http/internal/url_pattern/host_nfc

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_host_test", "reference_contracts")
pub fn unicode_and_host_reference_test_() -> dynamic.Dynamic

pub fn special_domain_case_and_percent_decoding_test() -> Nil {
  assert canonical("EX%41MPLE.com.", "example.com.")
  assert canonical("foo_bar.example", "foo_bar.example")
  assert canonical("-a..b-", "-a..b-")
}

pub fn numeric_ipv4_radices_and_short_forms_test() -> Nil {
  assert canonical("127.1", "127.0.0.1")
  assert canonical("0x7f000001", "127.0.0.1")
  assert canonical("0177.0.0.01.", "127.0.0.1")
  assert canonical("1.2.65535", "1.2.255.255")
  assert canonical("4294967295", "255.255.255.255")
}

pub fn numeric_domain_tail_requires_valid_ipv4_test() -> Nil {
  assert rejected(["example.12", "1.2.65536", "4294967296", "09", "1.2.3.4.5"])
  assert canonical("0x", "0.0.0.0")
  assert canonical("09x", "09x")
}

pub fn overflowing_hex_ipv4_is_not_reclassified_as_a_domain_test() -> Nil {
  assert rejected(["0x100000000", "0x" <> string.repeat("f", 2046)])
  assert canonical("0x100000000z", "0x100000000z")
}

pub fn domain_ending_in_overflowing_hex_still_requires_ipv4_test() -> Nil {
  assert rejected(["example.0x100000000", "1.2.3.0x100000000"])
}

pub fn ipv6_compression_and_ipv4_tail_test() -> Nil {
  assert canonical("[0:0:0:0:0:0:0:1]", "[::1]")
  assert canonical("[2001:0DB8:0:0:1:0:0:1]", "[2001:db8::1:0:0:1]")
  assert canonical("[::ffff:192.0.2.128]", "[::ffff:c000:280]")
  assert canonical("[0:0:0:0:0:0:0:0]", "[::]")
}

pub fn ipv6_malformed_components_are_rejected_test() -> Nil {
  assert rejected([
    "[::1", "::1", "[1::2::3]", "[1:2:3:4:5:6:7]", "[1:2:3:4:5:6:7:8:9]",
    "[::ffff:192.00.2.1]", "[::ffff:192.0.2]", "[fe80::1%25eth0]", "[::]:80",
  ])
}

pub fn unicode_mapping_and_nontransitional_sharp_s_test() -> Nil {
  assert canonical("ＦＡＳＳ。de", "fass.de")
  assert canonical("faß.de", "xn--fa-hia.de")
  assert canonical("bücher.example", "xn--bcher-kva.example")
  assert canonical("①.②.③.④", "1.2.3.4")
  assert canonical("a\u{ad}b.example", "ab.example")
}

pub fn canonical_composition_and_hangul_test() -> Nil {
  assert canonical("e\u{301}.example", "xn--9ca.example")
  assert canonical("é.example", "xn--9ca.example")
  assert canonical("\u{1100}\u{1161}.example", "xn--o39a.example")
  assert canonical("가.example", "xn--o39a.example")
}

pub fn unicode_bidi_and_joiner_contexts_are_enforced_test() -> Nil {
  assert canonical("مثال.إختبار", "xn--mgbh0fb.xn--kgbechtv")
  assert rejected([
    "a\u{200d}b.example",
    "a\u{200c}b.example",
    "\u{301}a.example",
    "aא.example",
    "אa.example",
  ])
}

pub fn invalid_encoded_utf8_and_forbidden_domain_bytes_test() -> Nil {
  assert rejected([
    "",
    "%",
    "%ff",
    "%c0%af",
    "x%23y",
    "a b",
    "a/b",
    "a:b",
    "a@b",
    "a\\b",
    "a%00b",
  ])
}

pub fn input_and_output_bounds_are_bytes_test() -> Nil {
  let largest = string.repeat("a", 2048)
  assert canonical(largest, largest)
  assert rejected([largest <> "a", string.repeat("é", 1025)])
  assert rejected([string.repeat("a", 2046) <> "é"])
}

pub fn maximum_mapping_expansion_has_a_finite_scalar_bound_test() -> Nil {
  let input = string.repeat("\u{fdfa}", 682)
  assert string.byte_size(input) == 2046
  let mapping = host_data.mapping(65_018).1
  assert list.length(mapping) == 18
  let normalized =
    list.repeat(mapping, 682) |> list.flatten |> host_nfc.normalize
  assert list.length(normalized) == 12_276
  assert host.canonicalize(input) == Error(Nil)
}

fn canonical(input: String, expected: String) -> Bool {
  host.canonicalize(input) == Ok(expected)
}

fn rejected(inputs: List(String)) -> Bool {
  list.all(inputs, fn(input) { host.canonicalize(input) == Error(Nil) })
}
