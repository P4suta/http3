//// An origin argument cannot silently carry URL credentials, paths or ports.

import gleam/result
import gleam/string
import http/compression

pub fn malformed_port_is_not_a_dictionary_origin_test() -> Nil {
  assert stored("https://trusted.example:bad")
    == Error(compression.InvalidDictionary)
}

pub fn origin_parameter_does_not_accept_userinfo_test() -> Nil {
  assert stored("https://trusted.example@evil.example")
    == Error(compression.InvalidDictionary)
}

pub fn origin_parameter_does_not_accept_path_or_query_test() -> Nil {
  assert stored("https://trusted.example/path")
    == Error(compression.InvalidDictionary)
  assert stored("https://trusted.example?query")
    == Error(compression.InvalidDictionary)
}

pub fn absolute_url_patterns_match_the_existing_request_api_test() -> Nil {
  assert selected("https://trusted.example/app/*", "/app/main.js") == Ok(True)
}

pub fn relative_patterns_use_the_outgoing_request_directory_test() -> Nil {
  assert selected("main.js", "/app/main.js") == Ok(True)
  assert selected("main.js", "/app/other.js") == Ok(False)
}

pub fn query_only_patterns_use_the_outgoing_request_url_test() -> Nil {
  assert selected("?view=1", "/app/main.js?view=1") == Ok(True)
  assert selected("?view=1", "/app/main.js?view=2") == Ok(False)
}

pub fn full_url_matching_does_not_treat_query_as_path_text_test() -> Nil {
  assert selected("/app/main.js?view=1", "/app/main.js?view=2") == Ok(False)
  assert selected("/app/main.js", "/app/main.js?view=2") == Ok(True)
}

pub fn default_ports_and_host_case_share_one_origin_test() -> Nil {
  assert canonical_origin_selection() == Ok(Nil)
}

pub fn full_url_api_resolves_match_against_the_outgoing_url_test() -> Nil {
  assert selected_url(
      pattern: "main.js",
      dictionary_url: "https://trusted.example/dicts/dictionary",
      request_url: "https://trusted.example/app/main.js",
    )
    == Ok(True)
  assert selected_url(
      pattern: "main.js",
      dictionary_url: "https://trusted.example/dicts/dictionary",
      request_url: "https://trusted.example/app/other.js",
    )
    == Ok(False)
}

pub fn full_url_api_checks_query_and_fragment_independently_test() -> Nil {
  assert selected_url(
      pattern: "?view=1#top",
      dictionary_url: "https://trusted.example/dicts/dictionary",
      request_url: "https://trusted.example/app/main.js?view=1#top",
    )
    == Ok(True)
  assert selected_url(
      pattern: "?view=1#top",
      dictionary_url: "https://trusted.example/dicts/dictionary",
      request_url: "https://trusted.example/app/main.js?view=1#other",
    )
    == Ok(False)
}

pub fn full_url_api_rejects_cross_origin_even_with_a_wildcard_host_test() -> Nil {
  assert selected_url(
      pattern: "https://*.example/*",
      dictionary_url: "https://trusted.example/dict",
      request_url: "https://other.example/app",
    )
    == Ok(False)
  assert selected_url(
      pattern: "https://*.example/*",
      dictionary_url: "https://trusted.example/dict",
      request_url: "https://trusted.example:8443/app",
    )
    == Ok(False)
}

pub fn full_url_api_uses_canonical_unicode_and_ipv6_origins_test() -> Nil {
  assert selected_url(
      pattern: "/*",
      dictionary_url: "https://BÜCHER.example:443/dict",
      request_url: "https://xn--bcher-kva.example/app",
    )
    == Ok(True)
  assert selected_url(
      pattern: "/*",
      dictionary_url: "https://[0:0:0:0:0:0:0:1]:443/dict",
      request_url: "https://[::1]/app",
    )
    == Ok(True)
}

pub fn unrelated_ipv6_pattern_does_not_poison_domain_selection_test() -> Nil {
  assert selected_url(
      pattern: "https://[\\:\\:1]/*",
      dictionary_url: "https://trusted.example/dict",
      request_url: "https://trusted.example/app",
    )
    == Ok(False)
  assert selected_after_irrelevant_pattern() == Ok(<<1>>)
}

fn selected_after_irrelevant_pattern() -> Result(BitArray, compression.Error) {
  use store <- result.try(stored_url(
    pattern: "/*",
    dictionary_url: "https://trusted.example/dict",
    maximum_bytes: 8192,
  ))
  use store <- result.try(compression.insert_dictionary_from_url(
    store:,
    isolation_key: compression.IsolationKey("top", "profile"),
    dictionary_url: "https://trusted.example/ipv6-dict",
    directive: compression.UseAsDictionary(
      "https://[\\:\\:1]/*",
      [],
      "",
      compression.Raw,
      [],
    ),
    content: <<2>>,
    fresh_until: 1000,
    fetched_at: 1,
  ))
  compression.select_dictionary_for_url(
    store,
    compression.IsolationKey("top", "profile"),
    request_url: "https://trusted.example/app",
    destination: compression.DestinationsUnsupported,
    now: 2,
  )
  |> result.map(fn(dictionary) { dictionary.content })
}

pub fn full_url_api_preserves_secure_context_and_partition_rules_test() -> Nil {
  assert selected_url(
      pattern: "/*",
      dictionary_url: "http://trusted.example/dict",
      request_url: "https://trusted.example/app",
    )
    == Error(compression.InvalidDictionary)
  assert selected_url(
      pattern: "/*",
      dictionary_url: "https://trusted.example/dict",
      request_url: "http://trusted.example/app",
    )
    == Error(compression.InvalidDictionary)
  assert other_partition_selection() == Error(compression.NoMatchingDictionary)
}

pub fn full_url_api_has_finite_input_and_existing_admission_bounds_test() -> Nil {
  assert selected_url(
      pattern: "/*",
      dictionary_url: "https://trusted.example/" <> string.repeat("a", 10_240),
      request_url: "https://trusted.example/app",
    )
    == Error(compression.InvalidDictionary)
  assert tiny_store_admission() == Error(compression.LimitExceeded)
}

fn other_partition_selection() -> Result(Nil, compression.Error) {
  use store <- result.try(stored_url(
    pattern: "/*",
    dictionary_url: "https://trusted.example/dict",
    maximum_bytes: 8192,
  ))
  compression.select_dictionary_for_url(
    store,
    compression.IsolationKey("other", "profile"),
    request_url: "https://trusted.example/app",
    destination: compression.DestinationsUnsupported,
    now: 1,
  )
  |> result.replace(Nil)
}

fn tiny_store_admission() -> Result(Nil, compression.Error) {
  stored_url(
    pattern: "/*",
    dictionary_url: "https://trusted.example/dict",
    maximum_bytes: 1024,
  )
  |> result.replace(Nil)
}

fn selected_url(
  pattern pattern: String,
  dictionary_url dictionary_url: String,
  request_url request_url: String,
) -> Result(Bool, compression.Error) {
  use store <- result.try(stored_url(
    pattern: pattern,
    dictionary_url: dictionary_url,
    maximum_bytes: 8192,
  ))
  case
    compression.select_dictionary_for_url(
      store,
      compression.IsolationKey("top", "profile"),
      request_url:,
      destination: compression.DestinationsUnsupported,
      now: 1,
    )
  {
    Ok(_) -> Ok(True)
    Error(compression.NoMatchingDictionary) -> Ok(False)
    Error(error) -> Error(error)
  }
}

fn stored_url(
  pattern pattern: String,
  dictionary_url dictionary_url: String,
  maximum_bytes maximum_bytes: Int,
) -> Result(compression.Store, compression.Error) {
  use store <- result.try(compression.store(4, maximum_bytes))
  compression.insert_dictionary_from_url(
    store:,
    isolation_key: compression.IsolationKey("top", "profile"),
    dictionary_url:,
    directive: compression.UseAsDictionary(pattern, [], "", compression.Raw, []),
    content: <<1>>,
    fresh_until: 1000,
    fetched_at: 0,
  )
}

fn canonical_origin_selection() -> Result(Nil, compression.Error) {
  use store <- result.try(make_store("https://TRUSTED.example:443", "/*"))
  compression.select_dictionary(
    store,
    compression.IsolationKey("top", "profile"),
    origin: "https://trusted.example",
    path: "/app/main.js",
    destination: "",
    now: 1,
  )
  |> result.replace(Nil)
}

fn selected(pattern: String, path: String) -> Result(Bool, compression.Error) {
  use store <- result.try(make_store("https://trusted.example", pattern))
  case
    compression.select_dictionary(
      store,
      compression.IsolationKey("top", "profile"),
      origin: "https://trusted.example",
      path:,
      destination: "",
      now: 1,
    )
  {
    Ok(_) -> Ok(True)
    Error(compression.NoMatchingDictionary) -> Ok(False)
    Error(error) -> Error(error)
  }
}

fn stored(origin: String) -> Result(Nil, compression.Error) {
  make_store(origin, "/*") |> result.replace(Nil)
}

fn make_store(
  origin: String,
  pattern: String,
) -> Result(compression.Store, compression.Error) {
  use store <- result.try(compression.store(
    maximum_entries: 4,
    maximum_bytes: 8192,
  ))
  compression.insert_dictionary(
    store:,
    isolation_key: compression.IsolationKey("top", "profile"),
    origin:,
    directive: compression.UseAsDictionary(pattern, [], "", compression.Raw, []),
    content: <<1>>,
    fresh_until: 1000,
    fetched_at: 0,
  )
}
