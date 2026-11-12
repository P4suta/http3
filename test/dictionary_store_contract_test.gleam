//// Exact dictionary-selection contracts for RFC 9842.

import gleam/bit_array
import gleam/result
import http/compression

pub fn dictionary_expires_at_its_exact_freshness_deadline_test() -> Nil {
  let stored =
    add(
      stored: empty(),
      id: "v1",
      pattern: "/app/main.js",
      destinations: [],
      fetched_at: 100,
    )
  assert result.is_ok(select(stored:, destination: "script", now: 199))
  assert select(stored:, destination: "script", now: 200)
    == Error(compression.NoMatchingDictionary)
  assert select(stored:, destination: "script", now: 201)
    == Error(compression.NoMatchingDictionary)
}

pub fn empty_destination_matches_all_destinations_test() -> Nil {
  let stored =
    add(
      stored: empty(),
      id: "v1",
      pattern: "/app/*",
      destinations: [],
      fetched_at: 100,
    )
  assert result.is_ok(select(stored:, destination: "script", now: 150))
  assert result.is_ok(select(stored:, destination: "document", now: 150))
  assert result.is_ok(select(stored:, destination: "", now: 150))
}

pub fn trailing_wildcards_match_remaining_path_bytes_test() -> Nil {
  let stored =
    add(
      stored: empty(),
      id: "v1",
      pattern: "/app/*",
      destinations: [],
      fetched_at: 100,
    )
  assert result.is_ok(select(stored:, destination: "script", now: 150))
  let stored =
    add(
      stored: empty(),
      id: "v2",
      pattern: "/app/*main*",
      destinations: [],
      fetched_at: 100,
    )
  assert result.is_ok(select(stored:, destination: "script", now: 150))
  let stored =
    add(
      stored: empty(),
      id: "wrong-suffix",
      pattern: "/app/*main",
      destinations: [],
      fetched_at: 100,
    )
  assert select(stored:, destination: "script", now: 150)
    == Error(compression.NoMatchingDictionary)
}

pub fn dictionary_selection_uses_all_three_precedence_rules_test() -> Nil {
  let stored =
    empty()
    |> add(
      id: "long-general",
      pattern: "/app/main.js",
      destinations: [],
      fetched_at: 130,
    )
    |> add(
      id: "specific-old",
      pattern: "/app/*",
      destinations: ["script"],
      fetched_at: 100,
    )
    |> add(
      id: "specific-new",
      pattern: "/app/*",
      destinations: ["script"],
      fetched_at: 120,
    )
  let assert Ok(specific) = select(stored:, destination: "script", now: 150)
  assert specific.identifier == "specific-new"
  let stored =
    add(
      stored: stored,
      id: "long-specific",
      pattern: "/app/main.js",
      destinations: ["script"],
      fetched_at: 90,
    )
  let assert Ok(longer) = select(stored:, destination: "script", now: 150)
  assert longer.identifier == "long-specific"
  let assert Ok(general) = select(stored:, destination: "document", now: 150)
  assert general.identifier == "long-general"
}

pub fn unknown_dictionary_types_and_missing_match_are_rejected_test() -> Nil {
  assert compression.parse_use_as_dictionary("id=\"unusable\"")
    == Error(compression.InvalidDictionary)
  let assert Ok(unknown) =
    compression.parse_use_as_dictionary("match=\"/app/*\", type=future")
  assert compression.insert_dictionary(
      empty(),
      isolation(),
      origin: "https://example.com",
      directive: unknown,
      content: <<"dictionary":utf8>>,
      fresh_until: 200,
      fetched_at: 100,
    )
    == Error(compression.UnsupportedAlgorithm)
}

pub fn isolation_key_and_insecure_origins_cannot_select_a_dictionary_test() -> Nil {
  let stored =
    add(
      stored: empty(),
      id: "v1",
      pattern: "/app/*",
      destinations: [],
      fetched_at: 100,
    )
  assert result.is_ok(select(stored:, destination: "script", now: 150))
  assert compression.select_dictionary(
      stored,
      compression.IsolationKey("other.example", "profile"),
      origin: "https://example.com",
      path: "/app/main.js",
      destination: "script",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert compression.select_dictionary(
      stored,
      compression.IsolationKey("top.example", "other-profile"),
      origin: "https://example.com",
      path: "/app/main.js",
      destination: "script",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert compression.select_dictionary(
      stored,
      isolation(),
      origin: "http://example.com",
      path: "/app/main.js",
      destination: "script",
      now: 150,
    )
    == Error(compression.InvalidDictionary)
}

fn isolation() -> compression.IsolationKey {
  compression.IsolationKey("top.example", "profile")
}

fn empty() -> compression.Store {
  let assert Ok(stored) = compression.store(8, 16_384)
  stored
}

fn add(
  stored stored: compression.Store,
  id id: String,
  pattern pattern: String,
  destinations destinations: List(String),
  fetched_at fetched_at: Int,
) -> compression.Store {
  let directive =
    compression.UseAsDictionary(pattern, destinations, id, compression.Raw, [])
  let assert Ok(stored) =
    compression.insert_dictionary(
      stored,
      isolation(),
      origin: "https://example.com",
      directive: directive,
      content: bit_array.from_string(id),
      fresh_until: 200,
      fetched_at: fetched_at,
    )
  stored
}

fn select(
  stored stored: compression.Store,
  destination destination: String,
  now now: Int,
) -> Result(compression.Dictionary, compression.Error) {
  compression.select_dictionary(
    stored,
    isolation(),
    origin: "https://example.com",
    path: "/app/main.js",
    destination: destination,
    now: now,
  )
}
