import gleam/dict
import gleeunit/should
import http3/internal/native/terminal_registry

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retains_only_the_most_recent_terminal_entries_test() -> Nil {
  let registry =
    terminal_registry.new(3)
    |> terminal_registry.insert(4, "four")
    |> terminal_registry.insert(8, "eight")
    |> terminal_registry.insert(12, "twelve")

  assert terminal_registry.size(registry) == 3
  assert terminal_registry.get(registry, 4) == Ok("four")

  let #(registry, evicted) =
    terminal_registry.insert_with_evictions(registry, 16, "sixteen")

  assert evicted == [#(4, "four")]
  assert terminal_registry.size(registry) == 3
  terminal_registry.get(registry, 4) |> should.be_error
  assert terminal_registry.get(registry, 8) == Ok("eight")
  assert terminal_registry.get(registry, 16) == Ok("sixteen")
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn updating_a_terminal_entry_does_not_change_fifo_order_test() -> Nil {
  let registry =
    terminal_registry.new(2)
    |> terminal_registry.insert(1, "original")
    |> terminal_registry.insert(2, "second")
    |> terminal_registry.insert(1, "updated")

  let #(registry, evicted) =
    terminal_registry.insert_with_evictions(registry, 3, "third")

  assert evicted == [#(1, "updated")]
  assert terminal_registry.get(registry, 2) == Ok("second")
  assert terminal_registry.get(registry, 3) == Ok("third")
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn zero_capacity_immediately_evicts_without_retention_test() -> Nil {
  let #(registry, evicted) =
    terminal_registry.new(0)
    |> terminal_registry.insert_with_evictions(1, "terminal")

  assert terminal_registry.size(registry) == 0
  assert evicted == [#(1, "terminal")]
  assert terminal_registry.entries(registry) == dict.new()
}
