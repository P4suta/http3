//// URLPattern component contracts independently checked with Node 26.8.2.
//// The RFC pins WHATWG commit 696b4029d52e5854044bac6b72cdb198cb962ed0.

import gleam/dynamic
import gleam/list
import gleam/result
import http/compression
import http/internal/url_pattern/component

// nolint: trailing_underscore -- EUnit requires the descriptor generator suffix.
@external(erlang, "http_url_pattern_test", "reference_contracts")
pub fn urlpattern_wpt_test_() -> dynamic.Dynamic

pub fn matching_work_exhaustion_is_an_error_test() -> Nil {
  let result =
    component.compile_path("/*")
    |> result.try(fn(compiled) {
      component.matches(compiled:, input: "/input", work: 0)
    })
  assert result == Error(component.WorkLimitExceeded)
}

pub fn unicode_identifiers_obey_start_and_continue_properties_test() -> Nil {
  assert matches("/:café", "/value") == Ok(True)
  assert matches("/:℘", "/value") == Ok(True)
  assert matches("/:㐀", "/value") == Ok(True)
  assert accepted("/:🙂") == Error(compression.InvalidDictionary)
  assert accepted("/:1name") == Error(compression.InvalidDictionary)
}

pub fn named_segments_match_exactly_one_path_segment_test() -> Nil {
  assert matches("/app/:version/main.js", "/app/v2/main.js") == Ok(True)
  assert matches("/app/:version/main.js", "/app/v2/sub/main.js") == Ok(False)
  assert matches("/app/:version/main.js", "/app//main.js") == Ok(False)
}

pub fn optional_groups_include_their_fixed_prefix_test() -> Nil {
  assert matches("/app{/v2}?/main.js", "/app/main.js") == Ok(True)
  assert matches("/app{/v2}?/main.js", "/app/v2/main.js") == Ok(True)
  assert matches("/app{/v2}?/main.js", "/app/v3/main.js") == Ok(False)
}

pub fn repeated_segments_and_fixed_groups_have_distinct_minima_test() -> Nil {
  assert matches("/app/:version+/main.js", "/app/v2/sub/main.js") == Ok(True)
  assert matches("/app/:version+/main.js", "/app/main.js") == Ok(False)
  assert matches("/app/:version*/main.js", "/app/main.js") == Ok(True)
  assert matches("/app/{x}+", "/app/xxx") == Ok(True)
  assert matches("/app/{x}+", "/app/") == Ok(False)
  assert matches("/app/{x}*", "/app/") == Ok(True)
}

pub fn escaped_pattern_syntax_is_literal_text_test() -> Nil {
  assert matches("/app/\\(name\\).js", "/app/(name).js") == Ok(True)
  assert matches("/app/\\*", "/app/*") == Ok(True)
  assert matches("/app/\\*", "/app/anything") == Ok(False)
}

pub fn unmatched_or_nested_groups_are_invalid_test() -> Nil {
  assert list.all(["/app/{segment", "/app/segment}", "/app/{{x}}"], fn(pattern) {
    accepted(pattern) == Error(compression.InvalidDictionary)
  })
}

pub fn duplicate_capture_names_are_invalid_test() -> Nil {
  assert accepted("/:name/:name") == Error(compression.InvalidDictionary)
  assert accepted("/{:name}/{:name}") == Error(compression.InvalidDictionary)
}

pub fn canonical_wildcard_groups_are_not_regexp_groups_test() -> Nil {
  assert matches("/app/(.*)", "/app/v2/main.js") == Ok(True)
  assert matches("/app/([^\\/]+?)", "/app/main.js") == Ok(True)
  assert matches("/app/([^\\/]+?)", "/app/v2/main.js") == Ok(False)
  assert accepted("/app/(.+)") == Error(compression.InvalidDictionary)
}

pub fn missing_names_and_dangling_escapes_are_invalid_test() -> Nil {
  assert accepted("/app/:") == Error(compression.InvalidDictionary)
  assert accepted("/app/\\") == Error(compression.InvalidDictionary)
}

fn accepted(pattern: String) -> Result(Nil, compression.Error) {
  stored(pattern) |> result.replace(Nil)
}

fn matches(pattern: String, path: String) -> Result(Bool, compression.Error) {
  use store <- result.try(stored(pattern))
  case
    compression.select_dictionary_for_request(
      store,
      compression.IsolationKey("top", "profile"),
      origin: "https://example.com",
      path:,
      destination: compression.DestinationsUnsupported,
      now: 150,
    )
  {
    Ok(_) -> Ok(True)
    Error(compression.NoMatchingDictionary) -> Ok(False)
    Error(error) -> Error(error)
  }
}

fn stored(pattern: String) -> Result(compression.Store, compression.Error) {
  use store <- result.try(compression.store(1, 4096))
  compression.insert_dictionary(
    store,
    compression.IsolationKey("top", "profile"),
    origin: "https://example.com",
    directive: compression.UseAsDictionary(
      pattern,
      [],
      "pattern",
      compression.Raw,
      [],
    ),
    content: <<"dictionary":utf8>>,
    fresh_until: 200,
    fetched_at: 100,
  )
}
