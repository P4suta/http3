//// Bounded RFC 9204 dynamic table with reference-safe eviction.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/varint

const entry_overhead = 32

/// One dynamic-table field.
pub type Field {
  Field(name: BitArray, value: BitArray)
}

/// One absolute entry snapshot without internal reference counters.
pub type Entry {
  Entry(absolute_index: Int, field: Field)
}

type StoredEntry {
  StoredEntry(absolute_index: Int, field: Field, size: Int, references: Int)
}

/// Encoder/decoder table state. Entries are newest first.
pub opaque type State {
  State(
    maximum_allowed_capacity: Int,
    capacity: Int,
    current_size: Int,
    entries: List(StoredEntry),
    insert_count: Int,
    dropped_count: Int,
  )
}

/// Capacity, index, memory, alignment, or blocked-eviction failure.
pub type Error {
  InvalidCapacity
  CapacityExceeded(Int)
  InvalidField
  EntryTooLarge(Int)
  MissingRelativeIndex(Int)
  MissingAbsoluteIndex(Int)
  ReferencedEntryCannotBeEvicted(Int)
  InvalidReferenceCount
  RequiredInsertCountFailure
  InsertCountExhausted
}

/// Start at zero capacity below a negotiated ceiling.
pub fn new(maximum_allowed_capacity: Int) -> Result(State, Error) {
  case
    maximum_allowed_capacity >= 0 && maximum_allowed_capacity <= varint.maximum
  {
    True -> Ok(State(maximum_allowed_capacity, 0, 0, [], 0, 0))
    False -> Error(InvalidCapacity)
  }
}

/// Apply a dynamic table capacity instruction and evict only unreferenced
/// oldest entries.
pub fn set_capacity(state: State, capacity: Int) -> Result(State, Error) {
  case capacity < 0 || capacity > state.maximum_allowed_capacity {
    True -> Error(CapacityExceeded(state.maximum_allowed_capacity))
    False -> {
      use #(entries, size, dropped) <- result.try(evict_until(
        state.entries,
        state.current_size,
        capacity,
        0,
      ))
      Ok(
        State(
          ..state,
          capacity: capacity,
          current_size: size,
          entries: entries,
          dropped_count: state.dropped_count + dropped,
        ),
      )
    }
  }
}

/// Insert a literal field and return its absolute index.
pub fn insert(state: State, field: Field) -> Result(#(State, Int), Error) {
  use entry_size <- result.try(field_size(field))
  case entry_size > state.capacity, state.insert_count >= varint.maximum {
    True, _ -> Error(EntryTooLarge(state.capacity))
    _, True -> Error(InsertCountExhausted)
    False, False -> insert_sized(state, field, entry_size)
  }
}

/// Duplicate a relative entry as a new insertion.
pub fn duplicate(
  state: State,
  relative_index: Int,
) -> Result(#(State, Int), Error) {
  use Entry(_, field) <- result.try(get_relative(state, relative_index))
  insert(state, field)
}

/// Resolve relative index zero as the newest entry.
pub fn get_relative(state: State, relative_index: Int) -> Result(Entry, Error) {
  case get_at(state.entries, relative_index) {
    Some(StoredEntry(index, field, _, _)) -> Ok(Entry(index, field))
    None -> Error(MissingRelativeIndex(relative_index))
  }
}

/// Resolve an absolute insertion index while it remains resident.
pub fn get_absolute(state: State, absolute_index: Int) -> Result(Entry, Error) {
  case find_absolute(state.entries, absolute_index) {
    Some(StoredEntry(index, field, _, _)) -> Ok(Entry(index, field))
    None -> Error(MissingAbsoluteIndex(absolute_index))
  }
}

/// Hold referenced entries until the associated field section is acknowledged
/// or cancelled.
pub fn acquire(
  state: State,
  absolute_indices: List(Int),
) -> Result(State, Error) {
  use _ <- result.try(validate_distinct_indices(absolute_indices, []))
  use entries <- result.try(adjust_references(
    state.entries,
    absolute_indices,
    1,
  ))
  Ok(State(..state, entries: entries))
}

/// Release a previously acquired field section reference set.
pub fn release(
  state: State,
  absolute_indices: List(Int),
) -> Result(State, Error) {
  use _ <- result.try(validate_distinct_indices(absolute_indices, []))
  use entries <- result.try(adjust_references(
    state.entries,
    absolute_indices,
    -1,
  ))
  Ok(State(..state, entries: entries))
}

/// Encode Required Insert Count modulo twice the maximum entry count.
pub fn encode_required_insert_count(
  required_insert_count: Int,
  maximum_capacity: Int,
) -> Result(Int, Error) {
  let maximum_entries = maximum_capacity / entry_overhead
  case required_insert_count, maximum_entries {
    0, _ -> Ok(0)
    value, 0 if value > 0 -> Error(RequiredInsertCountFailure)
    value, _ if value < 0 || value > varint.maximum ->
      Error(RequiredInsertCountFailure)
    value, entries -> Ok(value % { 2 * entries } + 1)
  }
}

/// Reconstruct Required Insert Count from the encoded modulo value.
pub fn decode_required_insert_count(
  encoded: Int,
  maximum_capacity: Int,
  total_insert_count: Int,
) -> Result(Int, Error) {
  let maximum_entries = maximum_capacity / entry_overhead
  case encoded, maximum_entries {
    0, _ -> Ok(0)
    _, 0 -> Error(RequiredInsertCountFailure)
    value, _ if value < 0 || total_insert_count < 0 ->
      Error(RequiredInsertCountFailure)
    value, entries ->
      reconstruct_required_insert_count(value, entries, total_insert_count)
  }
}

/// Current insertion count, one greater than the newest absolute index.
pub fn insert_count(state: State) -> Int {
  state.insert_count
}

/// Current resident byte size.
pub fn size(state: State) -> Int {
  state.current_size
}

/// Current capacity selected by the encoder stream.
pub fn capacity(state: State) -> Int {
  state.capacity
}

/// Negotiated upper bound used for Required Insert Count reconstruction.
pub fn maximum_allowed_capacity(state: State) -> Int {
  state.maximum_allowed_capacity
}

/// Find the newest resident exact field.
pub fn find(state: State, field: Field) -> Option(Entry) {
  find_field(state.entries, field)
}

/// Find the newest resident field carrying a name.
pub fn find_name(state: State, name: BitArray) -> Option(Entry) {
  find_field_name(state.entries, name)
}

fn insert_sized(
  state: State,
  field: Field,
  entry_size: Int,
) -> Result(#(State, Int), Error) {
  use #(entries, size, dropped) <- result.try(evict_until(
    state.entries,
    state.current_size,
    state.capacity - entry_size,
    0,
  ))
  let absolute_index = state.insert_count
  let inserted = StoredEntry(absolute_index, field, entry_size, 0)
  Ok(#(
    State(
      ..state,
      current_size: size + entry_size,
      entries: [inserted, ..entries],
      insert_count: state.insert_count + 1,
      dropped_count: state.dropped_count + dropped,
    ),
    absolute_index,
  ))
}

fn field_size(field: Field) -> Result(Int, Error) {
  let Field(name, value) = field
  case
    bit_array.bit_size(name) % 8 == 0,
    bit_array.bit_size(value) % 8 == 0,
    bit_array.byte_size(name) > 0
  {
    True, True, True ->
      Ok(
        bit_array.byte_size(name) + bit_array.byte_size(value) + entry_overhead,
      )
    _, _, _ -> Error(InvalidField)
  }
}

fn evict_until(
  entries: List(StoredEntry),
  current_size: Int,
  target_size: Int,
  dropped: Int,
) -> Result(#(List(StoredEntry), Int, Int), Error) {
  case current_size <= target_size {
    True -> Ok(#(entries, current_size, dropped))
    False -> evict_oldest(entries, current_size, target_size, dropped)
  }
}

fn evict_oldest(
  entries: List(StoredEntry),
  current_size: Int,
  target_size: Int,
  dropped: Int,
) -> Result(#(List(StoredEntry), Int, Int), Error) {
  case list.reverse(entries) {
    [] -> Error(InvalidCapacity)
    [StoredEntry(index, _, _, references), ..] if references > 0 ->
      Error(ReferencedEntryCannotBeEvicted(index))
    [StoredEntry(_, _, entry_size, _), ..remaining_reversed] ->
      evict_until(
        list.reverse(remaining_reversed),
        current_size - entry_size,
        target_size,
        dropped + 1,
      )
  }
}

fn get_at(entries: List(StoredEntry), index: Int) -> Option(StoredEntry) {
  case entries, index {
    _, value if value < 0 -> None
    [], _ -> None
    [entry, ..], 0 -> Some(entry)
    [_, ..rest], remaining -> get_at(rest, remaining - 1)
  }
}

fn find_absolute(
  entries: List(StoredEntry),
  absolute_index: Int,
) -> Option(StoredEntry) {
  case entries {
    [] -> None
    [StoredEntry(index, _, _, _) as entry, ..rest] ->
      case index == absolute_index {
        True -> Some(entry)
        False -> find_absolute(rest, absolute_index)
      }
  }
}

fn find_field(entries: List(StoredEntry), field: Field) -> Option(Entry) {
  case entries {
    [] -> None
    [StoredEntry(index, current, _, _), ..rest] ->
      case current == field {
        True -> Some(Entry(index, current))
        False -> find_field(rest, field)
      }
  }
}

fn find_field_name(
  entries: List(StoredEntry),
  name: BitArray,
) -> Option(Entry) {
  case entries {
    [] -> None
    [StoredEntry(index, Field(current_name, _) as field, _, _), ..rest] ->
      case current_name == name {
        True -> Some(Entry(index, field))
        False -> find_field_name(rest, name)
      }
  }
}

fn validate_distinct_indices(
  indices: List(Int),
  seen: List(Int),
) -> Result(Nil, Error) {
  case indices {
    [] -> Ok(Nil)
    [index, ..rest] ->
      case index < 0 || list.contains(seen, index) {
        True -> Error(InvalidReferenceCount)
        False -> validate_distinct_indices(rest, [index, ..seen])
      }
  }
}

fn adjust_references(
  entries: List(StoredEntry),
  indices: List(Int),
  delta: Int,
) -> Result(List(StoredEntry), Error) {
  case indices {
    [] -> Ok(entries)
    [index, ..rest] -> {
      use entries <- result.try(adjust_reference(entries, index, delta, []))
      adjust_references(entries, rest, delta)
    }
  }
}

fn adjust_reference(
  entries: List(StoredEntry),
  absolute_index: Int,
  delta: Int,
  reversed: List(StoredEntry),
) -> Result(List(StoredEntry), Error) {
  case entries {
    [] -> Error(MissingAbsoluteIndex(absolute_index))
    [StoredEntry(index, field, size, references) as entry, ..rest] ->
      case index == absolute_index, references + delta >= 0 {
        True, False -> Error(InvalidReferenceCount)
        True, True ->
          Ok(
            list.append(list.reverse(reversed), [
              StoredEntry(index, field, size, references + delta),
              ..rest
            ]),
          )
        False, _ ->
          adjust_reference(rest, absolute_index, delta, [entry, ..reversed])
      }
  }
}

fn reconstruct_required_insert_count(
  encoded: Int,
  maximum_entries: Int,
  total_insert_count: Int,
) -> Result(Int, Error) {
  let full_range = 2 * maximum_entries
  case encoded > full_range {
    True -> Error(RequiredInsertCountFailure)
    False -> {
      let maximum_value = total_insert_count + maximum_entries
      let maximum_wrapped = maximum_value / full_range * full_range
      let candidate = maximum_wrapped + encoded - 1
      let candidate = case candidate > maximum_value {
        True ->
          case candidate <= full_range {
            True -> -1
            False -> candidate - full_range
          }
        False -> candidate
      }
      case candidate <= 0 {
        True -> Error(RequiredInsertCountFailure)
        False -> Ok(candidate)
      }
    }
  }
}
