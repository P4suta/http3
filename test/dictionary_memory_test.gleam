//// Retained dictionary metadata and binary backing allocations are bounded.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import http/compression

@external(erlang, "http_dictionary_memory_test_ffi", "sub_binary")
fn sub_string(value: String) -> String

@external(erlang, "http_dictionary_memory_test_ffi", "sub_binary")
fn sub_bytes(value: BitArray) -> BitArray

@external(erlang, "http_dictionary_memory_test_ffi", "referenced_bytes")
fn string_allocation(value: String) -> Int

@external(erlang, "http_dictionary_memory_test_ffi", "referenced_bytes")
fn bytes_allocation(value: BitArray) -> Int

@external(erlang, "http_dictionary_memory_test_ffi", "retained_upper_bound")
fn measured_record(value: compression.Dictionary) -> Int

// nolint: avoid_panic, thrown_away_error -- Setup failures expose only a fixed label.
fn require_ok(value: Result(a, compression.Error)) -> a {
  case value {
    Ok(value) -> value
    Error(_) -> panic as "dictionary memory fixture setup failed"
  }
}

fn directive() -> compression.UseAsDictionary {
  compression.UseAsDictionary("/*", [], "", compression.Raw, [])
}

fn insert(
  store: compression.Store,
  key: compression.IsolationKey,
) -> Result(compression.Store, compression.Error) {
  compression.insert_dictionary(
    store,
    key,
    origin: "https://example.com",
    directive: directive(),
    content: <<1>>,
    fresh_until: 200,
    fetched_at: 100,
  )
}

pub fn isolation_key_bytes_are_charged_before_dictionary_admission_test() -> Nil {
  let store = compression.store(4, 256) |> require_ok
  let key =
    compression.IsolationKey(string.repeat("s", 256), string.repeat("p", 256))
  let observed = insert(store, key) |> result.replace(Nil)
  assert observed == Error(compression.LimitExceeded)
}

pub fn measured_record_storage_fits_its_reported_retained_charge_test() -> Nil {
  let store = compression.store(4, 65_536) |> require_ok
  let key =
    compression.IsolationKey(string.repeat("s", 1024), string.repeat("p", 1024))
  let destinations =
    int.range(1, 64, with: [], run: fn(values, index) {
      [string.repeat("d", 60) <> int.to_string(index), ..values]
    })
  let directive =
    compression.UseAsDictionary(
      "/*",
      destinations,
      string.repeat("i", 1024),
      compression.Raw,
      [],
    )
  let store =
    compression.insert_dictionary(
      store,
      key,
      origin: "https://example.com",
      directive: directive,
      content: bit_array.from_string(string.repeat("c", 256)),
      fresh_until: 200,
      fetched_at: 100,
    )
    |> require_ok
  let selected =
    compression.select_dictionary(
      store,
      key,
      origin: "https://example.com",
      path: "/asset",
      destination: string.repeat("d", 60) <> "1",
      now: 150,
    )
    |> require_ok
  assert measured_record(selected) <= selected.retained_bytes
}

pub fn stored_binary_slices_do_not_pin_large_caller_allocations_test() -> Nil {
  let key =
    compression.IsolationKey(
      sub_string(string.repeat("s", 96)),
      sub_string(string.repeat("p", 96)),
    )
  let origin = sub_string("https://" <> string.repeat("a", 60) <> ".example")
  let pattern = sub_string("/" <> string.repeat("p", 80) <> "*")
  let identifier = sub_string(string.repeat("i", 96))
  let content = sub_bytes(bit_array.from_string(string.repeat("c", 128)))
  assert string_allocation(origin) > 1_000_000
  assert bytes_allocation(content) > 1_000_000
  let store = compression.store(4, 32_768) |> require_ok
  let directive =
    compression.UseAsDictionary(pattern, [], identifier, compression.Raw, [])
  let store =
    compression.insert_dictionary(
      store,
      key,
      origin: origin,
      directive: directive,
      content: content,
      fresh_until: 200,
      fetched_at: 100,
    )
    |> require_ok
  let selected =
    compression.select_dictionary(
      store,
      key,
      origin: origin,
      path: "/" <> string.repeat("p", 80) <> "/asset",
      destination: "script",
      now: 150,
    )
    |> require_ok
  let text = [
    selected.origin,
    selected.match,
    selected.identifier,
    selected.isolation_key.top_level_site,
    selected.isolation_key.profile,
  ]
  assert list.all(text, fn(value) {
    string_allocation(value) == string.byte_size(value)
  })
  assert bytes_allocation(selected.content)
    == bit_array.byte_size(selected.content)
  assert measured_record(selected) <= selected.retained_bytes
}

pub fn metadata_pressure_evicts_the_oldest_isolation_partition_test() -> Nil {
  let store = compression.store(4, 4096) |> require_ok
  let first =
    compression.IsolationKey(string.repeat("s", 1024), string.repeat("a", 1024))
  let second =
    compression.IsolationKey(string.repeat("s", 1024), string.repeat("b", 1024))
  let store = insert(store, first) |> require_ok
  let store = insert(store, second) |> require_ok
  let old =
    compression.select_dictionary(
      store,
      first,
      origin: "https://example.com",
      path: "/asset",
      destination: "script",
      now: 150,
    )
    |> result.replace(Nil)
  let current =
    compression.select_dictionary(
      store,
      second,
      origin: "https://example.com",
      path: "/asset",
      destination: "script",
      now: 150,
    )
    |> result.replace(Nil)
  assert old == Error(compression.NoMatchingDictionary)
  assert current == Ok(Nil)
}

pub fn stored_clock_values_have_a_finite_integer_representation_test() -> Nil {
  let store = compression.store(4, 4096) |> require_ok
  let key = compression.IsolationKey("site", "profile")
  let too_late =
    compression.insert_dictionary(
      store,
      key,
      origin: "https://example.com",
      directive: directive(),
      content: <<1>>,
      fetched_at: 100,
      fresh_until: 9_223_372_036_854_775_808,
    )
    |> result.replace(Nil)
  let too_early =
    compression.insert_dictionary(
      store,
      key,
      origin: "https://example.com",
      directive: directive(),
      content: <<1>>,
      fetched_at: -9_223_372_036_854_775_809,
      fresh_until: 100,
    )
    |> result.replace(Nil)
  assert too_late == Error(compression.InvalidDictionary)
  assert too_early == Error(compression.InvalidDictionary)
  let boundary =
    compression.insert_dictionary(
      store,
      key,
      origin: "https://example.com",
      directive: directive(),
      content: <<1>>,
      fetched_at: -9_223_372_036_854_775_808,
      fresh_until: 9_223_372_036_854_775_807,
    )
    |> require_ok
  let selected =
    compression.select_dictionary(
      boundary,
      key,
      origin: "https://example.com",
      path: "/asset",
      destination: "script",
      now: 0,
    )
    |> require_ok
  assert measured_record(selected) <= selected.retained_bytes
}
