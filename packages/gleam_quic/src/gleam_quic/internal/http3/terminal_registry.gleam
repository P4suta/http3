//// Bounded FIFO retention for lightweight terminal handle state.
////
//// Active HTTP/3 stream state is held elsewhere. This registry remembers only
//// the most recent terminal outcomes so idempotent handle operations retain
//// useful semantics without memory growing with the lifetime stream count.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}

pub opaque type Registry(value) {
  Registry(
    maximum: Int,
    values: Dict(Int, value),
    oldest: List(Int),
    newest: List(Int),
    count: Int,
  )
}

/// Create a registry retaining at most `maximum` entries.
pub fn new(maximum: Int) -> Registry(value) {
  Registry(int.max(maximum, 0), dict.new(), [], [], 0)
}

/// Insert or update one entry, discarding any evicted values.
pub fn insert(
  registry: Registry(value),
  identifier: Int,
  value: value,
) -> Registry(value) {
  let #(registry, _) = insert_with_evictions(registry, identifier, value)
  registry
}

/// Insert or update one entry and return evictions from oldest to newest.
pub fn insert_with_evictions(
  registry: Registry(value),
  identifier: Int,
  value: value,
) -> #(Registry(value), List(#(Int, value))) {
  let registry = case dict.has_key(registry.values, identifier) {
    True ->
      Registry(
        ..registry,
        values: dict.insert(registry.values, identifier, value),
      )
    False ->
      Registry(
        ..registry,
        values: dict.insert(registry.values, identifier, value),
        newest: [identifier, ..registry.newest],
        count: registry.count + 1,
      )
  }
  evict_excess(registry, [])
}

/// Look up one retained terminal value.
pub fn get(registry: Registry(value), identifier: Int) -> Result(value, Nil) {
  dict.get(registry.values, identifier)
}

/// Return the number of retained entries.
pub fn size(registry: Registry(value)) -> Int {
  registry.count
}

/// Return all retained entries without ordering guarantees.
pub fn entries(registry: Registry(value)) -> Dict(Int, value) {
  registry.values
}

fn evict_excess(
  registry: Registry(value),
  evicted: List(#(Int, value)),
) -> #(Registry(value), List(#(Int, value))) {
  case registry.count > registry.maximum {
    False -> #(registry, list.reverse(evicted))
    True ->
      case take_oldest(registry) {
        None -> #(
          Registry(..registry, count: dict.size(registry.values)),
          list.reverse(evicted),
        )
        Some(#(registry, identifier)) ->
          case dict.get(registry.values, identifier) {
            Error(Nil) ->
              evict_excess(
                Registry(..registry, count: registry.count - 1),
                evicted,
              )
            Ok(value) ->
              evict_excess(
                Registry(
                  ..registry,
                  values: dict.delete(registry.values, identifier),
                  count: registry.count - 1,
                ),
                [#(identifier, value), ..evicted],
              )
          }
      }
  }
}

fn take_oldest(registry: Registry(value)) -> Option(#(Registry(value), Int)) {
  case registry.oldest {
    [identifier, ..rest] ->
      Some(#(Registry(..registry, oldest: rest), identifier))
    [] ->
      case list.reverse(registry.newest) {
        [] -> None
        [identifier, ..rest] ->
          Some(#(Registry(..registry, oldest: rest, newest: []), identifier))
      }
  }
}
