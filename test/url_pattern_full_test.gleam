//// Full constructor/matching cases checked with independent Node/Chromium.

import gleam/dynamic
import gleam/result
import gleam/string
import http/internal/url_pattern/component
import http/internal/url_pattern/pattern
import http/internal/url_pattern/url

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_pattern_test", "full_reference_contracts")
pub fn urlpattern_constructor_wpt_test_() -> dynamic.Dynamic

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_pattern_test", "independent_contracts")
pub fn urlpattern_independent_full_test_() -> dynamic.Dynamic

pub fn absolute_patterns_match_all_url_components_test() -> Nil {
  assert matches(
      input: "https://:sub.example.com:8443/app/:name?view=1#top",
      base: "https://base.example/dictionary",
      candidate: "https://cdn.example.com:8443/app/fileview=1#top",
    )
    == Ok(True)
  assert matches(
      input: "https://:sub.example.com:8443/app/:name?view=1#top",
      base: "https://base.example/dictionary",
      candidate: "https://cdn.example.com:8443/app/file?view=1#top",
    )
    == Ok(False)
}

pub fn relative_patterns_resolve_against_the_base_directory_test() -> Nil {
  assert matches(
      input: "../scripts/*",
      base: "https://example.com/dicts/current/dict",
      candidate: "https://example.com/dicts/scripts/main.js",
    )
    == Ok(True)
  assert matches(
      input: "../scripts/*",
      base: "https://example.com/dicts/current/dict",
      candidate: "https://example.com/scripts/main.js",
    )
    == Ok(False)
}

pub fn inherited_base_components_escape_pattern_metacharacters_test() -> Nil {
  assert matches(
      input: "file",
      base: "https://example.com/a*/(fixed)/base",
      candidate: "https://example.com/a*/(fixed)/file",
    )
    == Ok(True)
  assert matches(
      input: "file",
      base: "https://example.com/a*/(fixed)/base",
      candidate: "https://example.com/anything/(fixed)/file",
    )
    == Ok(False)
}

pub fn search_and_hash_only_patterns_inherit_the_right_prefix_test() -> Nil {
  assert matches(
      input: "#new",
      base: "https://example.com/dir/page?old#before",
      candidate: "https://example.com/dir/page?old#new",
    )
    == Ok(True)
  assert matches(
      input: "?new",
      base: "https://example.com/dir/page?old#before",
      candidate: "https://example.com/dir/page?new#anything",
    )
    == Ok(True)
}

pub fn explicit_default_port_and_credentials_are_canonical_test() -> Nil {
  assert matches(
      input: "http://example.com:80/*",
      base: "https://base.example/dict",
      candidate: "http://example.com:080/path",
    )
    == Ok(True)
  assert matches(
      input: "https://example.com/*",
      base: "https://base.example/dict",
      candidate: "https://user:password@example.com/path",
    )
    == Ok(True)
  assert matches(
      input: "https://example.com/*",
      base: "https://base.example/dict",
      candidate: "https://example.com:8443/path",
    )
    == Ok(False)
}

pub fn default_port_removal_precedes_component_canonicalization_test() -> Nil {
  assert matches(
      input: "{https}://example.com:443/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
  assert matches(
      input: "HTTPS://example.com:443/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
  assert matches(
      input: "https://example.com:{443}/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
  assert matches(
      input: "https://example.com:443abc/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
  assert matches(
      input: "https://example.com:443/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(True)
}

pub fn query_apostrophe_matches_whatwg_url_serialization_test() -> Nil {
  assert matches(
      input: "/path?q=a b'",
      base: "https://example.com/dict",
      candidate: "https://example.com/path?q=a%20b%27",
    )
    == Ok(True)
}

pub fn arbitrary_regexp_groups_are_rejected_in_every_component_test() -> Nil {
  assert matches(
      input: "https://(evil|good).example/*",
      base: "https://example.com/dict",
      candidate: "https://good.example/path",
    )
    == Error(component.InvalidPattern)
  assert matches(
      input: "/path?query=(.+)",
      base: "https://example.com/dict",
      candidate: "https://example.com/path?query=abc",
    )
    == Error(component.InvalidPattern)
}

pub fn construction_and_matching_share_one_finite_budget_test() -> Nil {
  let result =
    url.parse("https://example.com/base")
    |> result.try(fn(base) { pattern.compile(input: "/*", base: base, work: 0) })
    |> result.replace(Nil)
  assert result == Error(component.WorkLimitExceeded)
}

pub fn inherited_maximum_path_keeps_escaped_literals_bounded_test() -> Nil {
  let prefix = "https://example.com/" <> string.repeat("(", 8186) <> "/"
  assert matches(
      input: "file",
      base: prefix <> "base",
      candidate: prefix <> "file",
    )
    == Ok(True)
  assert matches(
      input: "file",
      base: prefix <> "base",
      candidate: prefix <> "nope",
    )
    == Ok(False)
}

pub fn expanded_graph_admission_fails_before_building_the_graph_test() -> Nil {
  let result =
    component.compile_component(
      pattern: string.repeat("{xxxx}?", 3400),
      options: component.Options(-1, -1, Ok),
    )
    |> result.replace(Nil)
  assert result == Error(component.WorkLimitExceeded)
}

pub fn negative_construction_credit_cannot_accept_an_empty_pattern_test() -> Nil {
  let result =
    url.parse("https://example.com/base")
    |> result.try(fn(base) { pattern.compile(input: "", base: base, work: -1) })
    |> result.replace(Nil)
  assert result == Error(component.WorkLimitExceeded)
}

pub fn ipv6_pattern_against_a_domain_is_a_clean_non_match_test() -> Nil {
  assert matches(
      input: "https://[\\:\\:1]/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
}

pub fn unmodified_fixed_groups_merge_before_path_canonicalization_test() -> Nil {
  assert matches(
      input: "/{a}/../b",
      base: "https://example.com/dict",
      candidate: "https://example.com/b",
    )
    == Ok(True)
  assert matches(
      input: "/{a}/../b",
      base: "https://example.com/dict",
      candidate: "https://example.com/a/b",
    )
    == Ok(False)
}

pub fn unmodified_fixed_groups_merge_before_ipv4_parsing_test() -> Nil {
  assert matches(
      input: "https://{127}.0.0.1/*",
      base: "https://example.com/dict",
      candidate: "https://127.0.0.1/a",
    )
    == Ok(True)
}

pub fn unmodified_fixed_groups_merge_before_unicode_host_normalization_test() -> Nil {
  assert matches(
      input: "https://{a}\u{0301}.example/*",
      base: "https://example.com/dict",
      candidate: "https://á.example/a",
    )
    == Ok(True)
}

pub fn hostname_fixed_pieces_use_url_hostname_state_preprocessing_test() -> Nil {
  assert matches(
      input: "https://ex\tample.com/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(True)
  assert matches(
      input: "https://ex\nample.com/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(True)
}

pub fn hostname_fixed_pieces_end_at_url_delimiters_test() -> Nil {
  assert matches(
      input: "https://{sub.}?example{.com/}foo/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(True)
  assert matches(
      input: "https://{exam#ignored}ple.com/*",
      base: "https://example.com/dict",
      candidate: "https://exam/a",
    )
    == Ok(True)
  assert matches(
      input: "https://{exam#ignored}ple.com/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Ok(False)
}

pub fn hostname_empty_prefix_and_port_inside_a_fixed_piece_are_invalid_test() -> Nil {
  assert matches(
      input: "https://{/#ignored}/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Error(component.InvalidPattern)
  assert matches(
      input: "https://{example.com\\:443}/*",
      base: "https://example.com/dict",
      candidate: "https://example.com/a",
    )
    == Error(component.InvalidPattern)
}

fn matches(
  input input: String,
  base base: String,
  candidate candidate: String,
) -> Result(Bool, component.Error) {
  use base <- result.try(url.parse(base))
  use candidate <- result.try(url.parse(candidate))
  use #(compiled, work) <- result.try(pattern.compile(
    input: input,
    base: base,
    work: 1_048_576,
  ))
  pattern.matches(compiled: compiled, input: candidate, work: work)
  |> result.map(fn(result) { result.0 })
}
