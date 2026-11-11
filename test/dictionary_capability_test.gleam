//// Request-destination capability and explicit dictionary-store clearing.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import http/compression

pub fn unsupported_destinations_ignore_restrictive_match_lists_test() -> Nil {
  let stored =
    add(
      store: empty(),
      key: key(),
      id: "restricted",
      pattern: "/app/*",
      destinations: ["image"],
      fetched: 100,
    )
  assert selected(stored, compression.DestinationsUnsupported)
    == Ok("restricted")
  assert selected(stored, compression.SupportedDestination("script"))
    == Error(compression.NoMatchingDictionary)
}

pub fn unsupported_destinations_remove_specificity_before_path_order_test() -> Nil {
  let stored =
    empty()
    |> add(
      key: key(),
      id: "general",
      pattern: "/app/main.js",
      destinations: [],
      fetched: 100,
    )
    |> add(
      key: key(),
      id: "restricted",
      pattern: "/app/*",
      destinations: ["script"],
      fetched: 120,
    )
  assert selected(stored, compression.DestinationsUnsupported) == Ok("general")
  assert selected(stored, compression.SupportedDestination("script"))
    == Ok("restricted")
}

pub fn unsupported_destinations_use_recency_for_equal_paths_test() -> Nil {
  let stored =
    empty()
    |> add(
      key: key(),
      id: "restricted-old",
      pattern: "/app/*",
      destinations: ["script"],
      fetched: 100,
    )
    |> add(
      key: key(),
      id: "general-new",
      pattern: "/app/*",
      destinations: [],
      fetched: 120,
    )
  assert selected(stored, compression.DestinationsUnsupported)
    == Ok("general-new")
  assert selected(stored, compression.SupportedDestination("script"))
    == Ok("restricted-old")
}

pub fn supported_empty_fetch_destination_is_not_unsupported_test() -> Nil {
  let stored =
    add(
      store: empty(),
      key: key(),
      id: "restricted",
      pattern: "/app/*",
      destinations: ["script"],
      fetched: 100,
    )
  assert selected(stored, compression.DestinationsUnsupported)
    == Ok("restricted")
  assert selected(stored, compression.SupportedDestination(""))
    == Error(compression.NoMatchingDictionary)
  assert old_selected(stored, "") == Error(compression.NoMatchingDictionary)
}

pub fn match_dest_can_name_the_empty_fetch_destination_test() -> Nil {
  let parsed =
    compression.parse_use_as_dictionary("match=\"/app/*\", match-dest=(\"\")")
    |> result.map(fn(value) { value.destinations })
  assert parsed == Ok([""])
  let stored =
    add(
      store: empty(),
      key: key(),
      id: "empty-only",
      pattern: "/app/*",
      destinations: [""],
      fetched: 100,
    )
  assert selected(stored, compression.SupportedDestination(""))
    == Ok("empty-only")
  assert selected(stored, compression.SupportedDestination("script"))
    == Error(compression.NoMatchingDictionary)
  assert old_selected(stored, "") == Ok("empty-only")
}

pub fn supported_empty_destination_preserves_specificity_test() -> Nil {
  let stored =
    empty()
    |> add(
      key: key(),
      id: "general-longer",
      pattern: "/app/main.js",
      destinations: [],
      fetched: 120,
    )
    |> add(
      key: key(),
      id: "empty-specific",
      pattern: "/app/*",
      destinations: [""],
      fetched: 100,
    )
  assert selected(stored, compression.SupportedDestination(""))
    == Ok("empty-specific")
  assert selected(stored, compression.DestinationsUnsupported)
    == Ok("general-longer")
  assert old_selected(stored, "") == Ok("empty-specific")
}

pub fn existing_selection_preserves_supported_destination_semantics_test() -> Nil {
  let stored =
    empty()
    |> add(
      key: key(),
      id: "general",
      pattern: "/app/main.js",
      destinations: [],
      fetched: 110,
    )
    |> add(
      key: key(),
      id: "script",
      pattern: "/app/*",
      destinations: ["script"],
      fetched: 100,
    )
  assert list.all(
    ["", "script", "image", "future-destination"],
    fn(destination) {
      old_selected(stored, destination)
      == selected(stored, compression.SupportedDestination(destination))
    },
  )
  assert selected(stored, compression.SupportedDestination("script\r\n"))
    == Error(compression.InvalidDictionary)
}

pub fn unsupported_destinations_preserve_origin_partition_and_freshness_test() -> Nil {
  let stored =
    add(
      store: empty(),
      key: key(),
      id: "restricted",
      pattern: "/app/*",
      destinations: ["script"],
      fetched: 100,
    )
  assert select_at(
      store: stored,
      key: compression.IsolationKey("other", "profile"),
      origin: "https://example.com",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert select_at(
      store: stored,
      key: key(),
      origin: "https://other.example",
      now: 150,
    )
    == Error(compression.NoMatchingDictionary)
  assert select_at(
      store: stored,
      key: key(),
      origin: "https://example.com",
      now: 200,
    )
    == Error(compression.NoMatchingDictionary)
  assert select_at(
      store: stored,
      key: key(),
      origin: "http://example.com",
      now: 150,
    )
    == Error(compression.InvalidDictionary)
}

pub fn clearing_partition_preserves_other_sites_profiles_and_accounting_test() -> Nil {
  let other_site = compression.IsolationKey("other", "profile")
  let other_profile = compression.IsolationKey("top", "other")
  let surviving =
    empty()
    |> add(
      key: other_site,
      id: "site",
      pattern: "/app/*",
      destinations: [],
      fetched: 110,
    )
    |> add(
      key: other_profile,
      id: "profile",
      pattern: "/app/*",
      destinations: [],
      fetched: 120,
    )
  let stored =
    add(
      store: surviving,
      key: key(),
      id: "removed",
      pattern: "/app/*",
      destinations: [],
      fetched: 130,
    )
  let cleared =
    compression.clear_dictionaries(
      stored,
      compression.PartitionDictionaries(key()),
    )
  assert cleared == Ok(surviving)
  // Previous immutable values remain owned by their caller.
  assert old_selected(stored, "script") == Ok("removed")
}

pub fn clearing_profile_removes_all_its_partitions_only_test() -> Nil {
  let other = compression.IsolationKey("top", "profile-other")
  let surviving =
    add(
      store: empty(),
      key: other,
      id: "other-profile",
      pattern: "/app/*",
      destinations: [],
      fetched: 100,
    )
  let stored =
    surviving
    |> add(
      key: key(),
      id: "same-site",
      pattern: "/app/*",
      destinations: [],
      fetched: 110,
    )
    |> add(
      key: compression.IsolationKey("other-site", "profile"),
      id: "other-site",
      pattern: "/app/*",
      destinations: [],
      fetched: 120,
    )
  assert compression.clear_dictionaries(
      stored,
      compression.ProfileDictionaries("profile"),
    )
    == Ok(surviving)
}

// nolint: assert_ok_pattern -- Test prerequisites must fail immediately.
pub fn clearing_partition_removes_every_origin_in_that_partition_test() -> Nil {
  let initial = empty()
  let stored =
    add(
      store: initial,
      key: key(),
      id: "first-origin",
      pattern: "/app/*",
      destinations: [],
      fetched: 100,
    )
  let assert Ok(stored) =
    compression.insert_dictionary(
      stored,
      key(),
      origin: "https://second.example",
      directive: compression.UseAsDictionary(
        "/*",
        [],
        "second",
        compression.Raw,
        [],
      ),
      content: <<"second-origin":utf8>>,
      fresh_until: 200,
      fetched_at: 110,
    )
  assert compression.clear_dictionaries(
      stored,
      compression.PartitionDictionaries(key()),
    )
    == Ok(initial)
}

// nolint: assert_ok_pattern -- These are assertions of the expected successful API results.
pub fn clearing_all_and_repeated_clearing_preserve_finite_admission_test() -> Nil {
  let assert Ok(initial) = compression.store(1, 2048)
  let stored =
    add(
      store: initial,
      key: key(),
      id: "first",
      pattern: "/app/*",
      destinations: [],
      fetched: 100,
    )
  let assert Ok(cleared) =
    compression.clear_dictionaries(stored, compression.AllDictionaries)
  assert cleared == initial
  assert compression.clear_dictionaries(cleared, compression.AllDictionaries)
    == Ok(initial)
  let after_first =
    add(
      store: cleared,
      key: key(),
      id: "first",
      pattern: "/app/*",
      destinations: [],
      fetched: 100,
    )
  let after_second =
    add(
      store: after_first,
      key: key(),
      id: "second",
      pattern: "/app/*",
      destinations: [],
      fetched: 110,
    )
  assert after_second
    == add(
      store: initial,
      key: key(),
      id: "second",
      pattern: "/app/*",
      destinations: [],
      fetched: 110,
    )
  let too_large =
    compression.insert_dictionary(
      cleared,
      key(),
      origin: "https://example.com",
      directive: compression.UseAsDictionary(
        "/app/*",
        [],
        "",
        compression.Raw,
        [],
      ),
      content: bit_array.from_string(string.repeat("x", 2048)),
      fresh_until: 200,
      fetched_at: 100,
    )
    |> result.replace(Nil)
  assert too_large == Error(compression.LimitExceeded)
}

pub fn clearing_unknown_partitions_is_idempotent_and_invalid_scopes_fail_test() -> Nil {
  let stored =
    add(
      store: empty(),
      key: key(),
      id: "retained",
      pattern: "/app/*",
      destinations: [],
      fetched: 100,
    )
  assert compression.clear_dictionaries(
      stored,
      compression.ProfileDictionaries("absent"),
    )
    == Ok(stored)
  assert compression.clear_dictionaries(
      stored,
      compression.PartitionDictionaries(compression.IsolationKey(
        "absent",
        "profile",
      )),
    )
    == Ok(stored)
  assert compression.clear_dictionaries(
      stored,
      compression.ProfileDictionaries(""),
    )
    == Error(compression.InvalidDictionary)
  assert compression.clear_dictionaries(
      stored,
      compression.ProfileDictionaries("profile\n"),
    )
    == Error(compression.InvalidDictionary)
  assert compression.clear_dictionaries(
      stored,
      compression.PartitionDictionaries(compression.IsolationKey("", "profile")),
    )
    == Error(compression.InvalidDictionary)
}

fn key() -> compression.IsolationKey {
  compression.IsolationKey("top", "profile")
}

// nolint: assert_ok_pattern -- A failed fixture store is a test failure.
fn empty() -> compression.Store {
  let assert Ok(stored) = compression.store(8, 16_384)
  stored
}

// nolint: assert_ok_pattern -- A failed fixture insertion is a test failure.
fn add(
  store store: compression.Store,
  key key: compression.IsolationKey,
  id id: String,
  pattern pattern: String,
  destinations destinations: List(String),
  fetched fetched: Int,
) -> compression.Store {
  let assert Ok(stored) =
    compression.insert_dictionary(
      store,
      key,
      origin: "https://example.com",
      directive: compression.UseAsDictionary(
        pattern,
        destinations,
        id,
        compression.Raw,
        [],
      ),
      content: bit_array.from_string(id),
      fresh_until: 200,
      fetched_at: fetched,
    )
  stored
}

fn selected(
  store: compression.Store,
  capability: compression.DestinationCapability,
) -> Result(String, compression.Error) {
  compression.select_dictionary_for_request(
    store,
    key(),
    origin: "https://example.com",
    path: "/app/main.js",
    destination: capability,
    now: 150,
  )
  |> result.map(fn(entry) { entry.identifier })
}

fn old_selected(
  store: compression.Store,
  destination: String,
) -> Result(String, compression.Error) {
  compression.select_dictionary(
    store,
    key(),
    origin: "https://example.com",
    path: "/app/main.js",
    destination:,
    now: 150,
  )
  |> result.map(fn(entry) { entry.identifier })
}

fn select_at(
  store store: compression.Store,
  key key: compression.IsolationKey,
  origin origin: String,
  now now: Int,
) -> Result(String, compression.Error) {
  compression.select_dictionary_for_request(
    store,
    key,
    origin:,
    path: "/app/main.js",
    destination: compression.DestinationsUnsupported,
    now:,
  )
  |> result.map(fn(entry) { entry.identifier })
}
