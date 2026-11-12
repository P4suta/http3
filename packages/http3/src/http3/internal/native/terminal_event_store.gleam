//// Connection-wide bounded ownership for terminal application deliveries.
////
//// Unlike the lightweight terminal-result registry, values here may own payload bytes.
//// Admission therefore checks entry, event, and byte ceilings before publishing the new store.
//// Oldest entries are returned explicitly so the caller can replace silent payload loss with a typed terminal failure.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}

pub type Entry(value) {
  Entry(value: value, events: Int, bytes: Int)
}

/// The first connection-wide ceiling that forced an entry to be evicted.
///
/// Multiple ceilings can be exceeded by one insert.
/// Bytes has precedence over Events, which has precedence over Entries, so payload pressure is never reported as an ordinary queue-capacity failure.
pub type Limit {
  Entries
  Events
  Bytes
}

pub type Eviction(value) {
  Eviction(identifier: Int, entry: Entry(value), limit: Limit)
}

pub opaque type Store(value) {
  Store(
    maximum_entries: Int,
    maximum_events: Int,
    maximum_bytes: Int,
    values: Dict(Int, Entry(value)),
    oldest: List(Int),
    newest: List(Int),
    entries: Int,
    events: Int,
    bytes: Int,
  )
}

pub fn new(
  maximum_entries: Int,
  maximum_events: Int,
  maximum_bytes: Int,
) -> Store(value) {
  Store(
    int.max(maximum_entries, 0),
    int.max(maximum_events, 0),
    int.max(maximum_bytes, 0),
    dict.new(),
    [],
    [],
    0,
    0,
    0,
  )
}

pub fn get(store: Store(value), identifier: Int) -> Result(Entry(value), Nil) {
  dict.get(store.values, identifier)
}

pub fn insert_with_evictions(
  store: Store(value),
  identifier: Int,
  value: value,
  events: Int,
  bytes: Int,
) -> #(Store(value), List(Eviction(value))) {
  let entry = Entry(value, int.max(events, 0), int.max(bytes, 0))
  let store = case dict.get(store.values, identifier) {
    Ok(Entry(events: previous_events, bytes: previous_bytes, ..)) ->
      Store(
        ..store,
        values: dict.insert(store.values, identifier, entry),
        events: store.events - previous_events + entry.events,
        bytes: store.bytes - previous_bytes + entry.bytes,
      )
    Error(Nil) ->
      Store(
        ..store,
        values: dict.insert(store.values, identifier, entry),
        newest: [identifier, ..store.newest],
        entries: store.entries + 1,
        events: store.events + entry.events,
        bytes: store.bytes + entry.bytes,
      )
  }
  evict_excess(store, [])
}

pub fn insert(
  store: Store(value),
  identifier: Int,
  value: value,
  events: Int,
  bytes: Int,
) -> Store(value) {
  insert_with_evictions(store, identifier, value, events, bytes).0
}

pub fn delete(store: Store(value), identifier: Int) -> Store(value) {
  case dict.get(store.values, identifier) {
    Error(Nil) -> store
    Ok(entry) ->
      Store(
        ..store,
        values: dict.delete(store.values, identifier),
        oldest: list.filter(store.oldest, fn(value) { value != identifier }),
        newest: list.filter(store.newest, fn(value) { value != identifier }),
        entries: int.max(0, store.entries - 1),
        events: int.max(0, store.events - entry.events),
        bytes: int.max(0, store.bytes - entry.bytes),
      )
  }
}

/// Current ownership followed by its configured ceilings.
pub fn stats(store: Store(value)) -> #(Int, Int, Int, Int, Int, Int) {
  #(
    store.entries,
    store.events,
    store.bytes,
    store.maximum_entries,
    store.maximum_events,
    store.maximum_bytes,
  )
}

fn evict_excess(
  store: Store(value),
  evicted: List(Eviction(value)),
) -> #(Store(value), List(Eviction(value))) {
  case excess_limit(store) {
    None -> #(store, list.reverse(evicted))
    Some(limit) ->
      case take_oldest(store) {
        None -> #(store, list.reverse(evicted))
        Some(#(store, identifier)) ->
          case dict.get(store.values, identifier) {
            Error(Nil) -> evict_excess(store, evicted)
            Ok(entry) ->
              evict_excess(
                Store(
                  ..store,
                  values: dict.delete(store.values, identifier),
                  entries: int.max(0, store.entries - 1),
                  events: int.max(0, store.events - entry.events),
                  bytes: int.max(0, store.bytes - entry.bytes),
                ),
                [Eviction(identifier, entry, limit), ..evicted],
              )
          }
      }
  }
}

fn excess_limit(store: Store(value)) -> Option(Limit) {
  case store.bytes > store.maximum_bytes {
    True -> Some(Bytes)
    False ->
      case store.events > store.maximum_events {
        True -> Some(Events)
        False ->
          case store.entries > store.maximum_entries {
            True -> Some(Entries)
            False -> None
          }
      }
  }
}

fn take_oldest(store: Store(value)) -> Option(#(Store(value), Int)) {
  case store.oldest {
    [identifier, ..rest] -> Some(#(Store(..store, oldest: rest), identifier))
    [] ->
      case list.reverse(store.newest) {
        [] -> None
        [identifier, ..rest] ->
          Some(#(Store(..store, oldest: rest, newest: []), identifier))
      }
  }
}
