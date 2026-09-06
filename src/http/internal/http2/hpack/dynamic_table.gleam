//// Bounded RFC 7541 dynamic table with oldest-first eviction.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

const entry_overhead = 32

const maximum_wire_capacity = 0xffff_ffff

/// One dynamic-table field.
pub type Field {
  Field(name: BitArray, value: BitArray)
}

type StoredField {
  StoredField(field: Field, size: Int)
}

/// Entries are retained newest first and never exceed `capacity` bytes.
pub opaque type State {
  State(
    maximum_allowed_capacity: Int,
    capacity: Int,
    current_size: Int,
    entries: List(StoredField),
  )
}

/// Capacity or field-shape failure.
pub type Error {
  InvalidCapacity
  CapacityExceeded(maximum: Int)
  InvalidField
}

/// Start with the negotiated maximum as the current capacity.
pub fn new(maximum_allowed_capacity: Int) -> Result(State, Error) {
  case
    maximum_allowed_capacity >= 0
    && maximum_allowed_capacity <= maximum_wire_capacity
  {
    True ->
      Ok(
        State(
          maximum_allowed_capacity:,
          capacity: maximum_allowed_capacity,
          current_size: 0,
          entries: [],
        ),
      )
    False -> Error(InvalidCapacity)
  }
}

/// Apply a header-block table-size update and evict oldest entries as needed.
pub fn set_capacity(state: State, capacity: Int) -> Result(State, Error) {
  case capacity >= 0 && capacity <= state.maximum_allowed_capacity {
    False -> Error(CapacityExceeded(state.maximum_allowed_capacity))
    True -> {
      let #(entries, current_size) =
        evict_until(state.entries, state.current_size, capacity)
      Ok(State(..state, capacity:, current_size:, entries:))
    }
  }
}

/// Insert a field. A field larger than the current capacity empties the table
/// and is not inserted, as required by RFC 7541 section 4.4.
pub fn insert(state: State, field: Field) -> Result(#(State, Bool), Error) {
  use entry_size <- result.try(field_size(field))
  case entry_size > state.capacity {
    True -> Ok(#(State(..state, current_size: 0, entries: []), False))
    False -> {
      let #(entries, current_size) =
        evict_until(
          state.entries,
          state.current_size,
          state.capacity - entry_size,
        )
      Ok(#(
        State(..state, current_size: current_size + entry_size, entries: [
          StoredField(field, entry_size),
          ..entries
        ]),
        True,
      ))
    }
  }
}

/// Resolve relative index zero as the newest resident field.
pub fn get_relative(state: State, index: Int) -> Option(Field) {
  get_at(state.entries, index)
}

/// Find the newest exact dynamic entry and return its relative index.
pub fn find(state: State, field: Field) -> Option(Int) {
  find_exact(state.entries, field, 0)
}

/// Find the newest entry carrying `name` and return its relative index.
pub fn find_name(state: State, name: BitArray) -> Option(Int) {
  find_named(state.entries, name, 0)
}

/// Current resident byte size.
pub fn size(state: State) -> Int {
  state.current_size
}

/// Current encoder-selected capacity.
pub fn capacity(state: State) -> Int {
  state.capacity
}

/// Current number of resident entries.
pub fn length(state: State) -> Int {
  list.length(state.entries)
}

fn field_size(field: Field) -> Result(Int, Error) {
  let Field(name, value) = field
  case
    bit_array.bit_size(name) % 8 == 0
    && bit_array.bit_size(value) % 8 == 0
    && bit_array.byte_size(name) > 0
  {
    True ->
      Ok(
        bit_array.byte_size(name) + bit_array.byte_size(value) + entry_overhead,
      )
    False -> Error(InvalidField)
  }
}

fn evict_until(
  entries: List(StoredField),
  current_size: Int,
  target_size: Int,
) -> #(List(StoredField), Int) {
  case current_size <= target_size {
    True -> #(entries, current_size)
    False -> {
      let #(entries, removed_size) = remove_oldest(entries)
      evict_until(entries, current_size - removed_size, target_size)
    }
  }
}

fn remove_oldest(entries: List(StoredField)) -> #(List(StoredField), Int) {
  case entries {
    [] -> #([], 0)
    [StoredField(_, size)] -> #([], size)
    [newest, ..rest] -> {
      let #(rest, removed_size) = remove_oldest(rest)
      #([newest, ..rest], removed_size)
    }
  }
}

fn get_at(entries: List(StoredField), index: Int) -> Option(Field) {
  case entries, index {
    _, value if value < 0 -> None
    [], _ -> None
    [StoredField(field, _), ..], 0 -> Some(field)
    [_, ..rest], remaining -> get_at(rest, remaining - 1)
  }
}

fn find_exact(
  entries: List(StoredField),
  wanted: Field,
  index: Int,
) -> Option(Int) {
  case entries {
    [] -> None
    [StoredField(field, _), ..rest] ->
      case field == wanted {
        True -> Some(index)
        False -> find_exact(rest, wanted, index + 1)
      }
  }
}

fn find_named(
  entries: List(StoredField),
  wanted: BitArray,
  index: Int,
) -> Option(Int) {
  case entries {
    [] -> None
    [StoredField(Field(name, _), _), ..rest] ->
      case name == wanted {
        True -> Some(index)
        False -> find_named(rest, wanted, index + 1)
      }
  }
}
