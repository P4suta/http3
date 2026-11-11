import gleam/int
import gleam/list
import http3/internal/native/server_worker
import http3/internal/native/terminal_event_store

fn only_eviction(
  evictions: List(terminal_event_store.Eviction(value)),
) -> terminal_event_store.Eviction(value) {
  let assert [eviction] = evictions
  eviction
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_thousand_terminal_payloads_remain_inside_one_connection_budget_test() -> Nil {
  let #(store, evictions) =
    int.range(
      0,
      1024,
      #(terminal_event_store.new(1024, 3, 16), 0),
      fn(state, identifier) {
        let #(store, evictions) = state
        let #(store, removed) =
          terminal_event_store.insert_with_evictions(
            store,
            identifier,
            identifier,
            2,
            8,
          )
        #(store, evictions + list.length(removed))
      },
    )
  assert terminal_event_store.stats(store) == #(1, 2, 8, 1024, 3, 16)
  assert evictions == 1023
  assert terminal_event_store.get(store, 1023)
    == Ok(terminal_event_store.Entry(1023, 2, 8))
  assert terminal_event_store.stats(terminal_event_store.delete(store, 1023))
    == #(0, 0, 0, 1024, 3, 16)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn one_entry_over_the_byte_ceiling_reports_bytes_test() -> Nil {
  let #(store, evictions) =
    terminal_event_store.new(4, 4, 7)
    |> terminal_event_store.insert_with_evictions(1, "oversized", 1, 8)
  assert terminal_event_store.stats(store) == #(0, 0, 0, 4, 4, 7)
  assert only_eviction(evictions)
    == terminal_event_store.Eviction(
      1,
      terminal_event_store.Entry("oversized", 1, 8),
      terminal_event_store.Bytes,
    )
  assert server_worker.terminal_event_limit_failure(
      terminal_event_store.Bytes,
      4,
      7,
    )
    == server_worker.ConsumerTooSlow(7)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn aggregate_bytes_evict_the_oldest_entry_with_byte_cause_test() -> Nil {
  let store = terminal_event_store.new(4, 4, 10)
  let store = terminal_event_store.insert(store, 1, "oldest", 1, 6)
  let #(store, evictions) =
    terminal_event_store.insert_with_evictions(store, 2, "newest", 1, 5)
  assert terminal_event_store.stats(store) == #(1, 1, 5, 4, 4, 10)
  assert only_eviction(evictions)
    == terminal_event_store.Eviction(
      1,
      terminal_event_store.Entry("oldest", 1, 6),
      terminal_event_store.Bytes,
    )
  assert server_worker.terminal_event_limit_failure(
      terminal_event_store.Bytes,
      4,
      10,
    )
    == server_worker.ConsumerTooSlow(10)
  assert terminal_event_store.stats(terminal_event_store.delete(store, 2))
    == #(0, 0, 0, 4, 4, 10)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn event_ceiling_reports_events_test() -> Nil {
  let store = terminal_event_store.new(4, 1, 10)
  let store = terminal_event_store.insert(store, 1, "oldest", 1, 1)
  let #(store, evictions) =
    terminal_event_store.insert_with_evictions(store, 2, "newest", 1, 1)
  assert terminal_event_store.stats(store) == #(1, 1, 1, 4, 1, 10)
  assert only_eviction(evictions)
    == terminal_event_store.Eviction(
      1,
      terminal_event_store.Entry("oldest", 1, 1),
      terminal_event_store.Events,
    )
  assert server_worker.terminal_event_limit_failure(
      terminal_event_store.Events,
      1,
      10,
    )
    == server_worker.RequestEventQueueExceeded(1)
  assert terminal_event_store.stats(terminal_event_store.delete(store, 2))
    == #(0, 0, 0, 4, 1, 10)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn entry_ceiling_reports_entries_test() -> Nil {
  let store = terminal_event_store.new(1, 4, 10)
  let store = terminal_event_store.insert(store, 1, "oldest", 1, 1)
  let #(store, evictions) =
    terminal_event_store.insert_with_evictions(store, 2, "newest", 1, 1)
  assert terminal_event_store.stats(store) == #(1, 1, 1, 1, 4, 10)
  assert only_eviction(evictions)
    == terminal_event_store.Eviction(
      1,
      terminal_event_store.Entry("oldest", 1, 1),
      terminal_event_store.Entries,
    )
  assert server_worker.terminal_event_limit_failure(
      terminal_event_store.Entries,
      1,
      10,
    )
    == server_worker.RequestEventQueueExceeded(1)
  assert terminal_event_store.stats(terminal_event_store.delete(store, 2))
    == #(0, 0, 0, 1, 4, 10)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn simultaneous_ceiling_failure_uses_bytes_events_entries_precedence_test() -> Nil {
  let #(store, evictions) =
    terminal_event_store.new(0, 0, 0)
    |> terminal_event_store.insert_with_evictions(1, "all", 1, 1)
  assert terminal_event_store.stats(store) == #(0, 0, 0, 0, 0, 0)
  assert only_eviction(evictions)
    == terminal_event_store.Eviction(
      1,
      terminal_event_store.Entry("all", 1, 1),
      terminal_event_store.Bytes,
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn replacing_and_deleting_an_entry_releases_its_exact_accounting_test() -> Nil {
  let store = terminal_event_store.new(2, 4, 16)
  let store = terminal_event_store.insert(store, 1, True, 2, 12)
  let store = terminal_event_store.insert(store, 1, False, 1, 3)
  assert terminal_event_store.stats(store) == #(1, 1, 3, 2, 4, 16)
  let store = terminal_event_store.delete(store, 1)
  assert terminal_event_store.stats(store) == #(0, 0, 0, 2, 4, 16)
}
