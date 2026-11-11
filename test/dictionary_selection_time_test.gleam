//// Selection uses the caller's one signed 64-bit clock domain.
//// These checks do not claim to derive an RFC 9111 age from unconnected cache headers.

import gleam/bit_array
import gleam/list
import gleam/result
import http/compression

pub fn a_dictionary_not_yet_fetched_is_not_eligible_test() -> Nil {
  let stored =
    add(stored: empty(), id: "future", fetched: 200, fresh_until: 300)
  assert select(stored, now: 199) == Error(compression.NoMatchingDictionary)
  assert select(stored, now: 200) == Ok("future")
}

pub fn a_future_record_cannot_displace_an_eligible_record_test() -> Nil {
  let stored =
    empty()
    |> add(id: "available", fetched: 100, fresh_until: 400)
    |> add(id: "future", fetched: 200, fresh_until: 400)
  assert select(stored, now: 150) == Ok("available")
  assert select(stored, now: 200) == Ok("future")
}

pub fn selection_clock_must_fit_the_record_clock_domain_test() -> Nil {
  let stored =
    add(stored: empty(), id: "available", fetched: 100, fresh_until: 200)
  assert list.all(
    [-9_223_372_036_854_775_809, 9_223_372_036_854_775_808],
    fn(now) {
      select(stored, now:) == Error(compression.InvalidDictionary)
      && select(empty(), now:) == Error(compression.InvalidDictionary)
    },
  )
}

pub fn signed_clock_endpoints_and_exclusive_expiry_are_preserved_test() -> Nil {
  let early =
    add(
      stored: empty(),
      id: "early",
      fetched: -9_223_372_036_854_775_808,
      fresh_until: -9_223_372_036_854_775_807,
    )
  assert select(early, now: -9_223_372_036_854_775_808) == Ok("early")
  assert select(early, now: -9_223_372_036_854_775_807)
    == Error(compression.NoMatchingDictionary)
  let late =
    add(
      stored: empty(),
      id: "late",
      fetched: 9_223_372_036_854_775_806,
      fresh_until: 9_223_372_036_854_775_807,
    )
  assert select(late, now: 9_223_372_036_854_775_806) == Ok("late")
  assert select(late, now: 9_223_372_036_854_775_807)
    == Error(compression.NoMatchingDictionary)
}

pub fn canonical_origin_and_partition_still_gate_fresh_records_test() -> Nil {
  let stored =
    add(stored: empty(), id: "available", fetched: 100, fresh_until: 200)
  assert result.is_ok(compression.select_dictionary_for_url(
    stored,
    key(),
    request_url: "https://EXAMPLE.com:443/app/file",
    destination: compression.DestinationsUnsupported,
    now: 150,
  ))
  assert list.all(
    ["https://other.example/app/file", "https://example.com:444/app/file"],
    fn(request_url) {
      compression.select_dictionary_for_url(
        stored,
        key(),
        request_url:,
        destination: compression.DestinationsUnsupported,
        now: 150,
      )
      |> result.map(fn(_) { Nil })
      == Error(compression.NoMatchingDictionary)
    },
  )
  assert compression.select_dictionary_for_url(
      stored,
      compression.IsolationKey("another", "profile"),
      request_url: "https://example.com/app/file",
      destination: compression.DestinationsUnsupported,
      now: 150,
    )
    |> result.map(fn(_) { Nil })
    == Error(compression.NoMatchingDictionary)
}

fn key() -> compression.IsolationKey {
  compression.IsolationKey("site", "profile")
}

fn empty() -> compression.Store {
  let assert Ok(stored) =
    compression.store(maximum_entries: 4, maximum_bytes: 16_384)
  stored
}

fn add(
  stored stored: compression.Store,
  id id: String,
  fetched fetched: Int,
  fresh_until fresh_until: Int,
) -> compression.Store {
  let assert Ok(directive) =
    compression.parse_use_as_dictionary("match=\"/app/*\"")
  let assert Ok(stored) =
    compression.insert_dictionary_from_url(
      store: stored,
      isolation_key: key(),
      dictionary_url: "https://example.com/dict",
      directive: compression.UseAsDictionary(..directive, identifier: id),
      content: bit_array.from_string(id),
      fresh_until:,
      fetched_at: fetched,
    )
  stored
}

fn select(
  stored: compression.Store,
  now now: Int,
) -> Result(String, compression.Error) {
  compression.select_dictionary_for_url(
    stored,
    key(),
    request_url: "https://example.com/app/file",
    destination: compression.DestinationsUnsupported,
    now:,
  )
  |> result.map(fn(selected) { selected.identifier })
}
