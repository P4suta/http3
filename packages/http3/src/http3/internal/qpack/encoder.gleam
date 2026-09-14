//// Stateful bounded QPACK encoder and decoder-stream consumer.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/qpack/dynamic_table
import http3/internal/qpack/field_section
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction
import http3/internal/qpack/static_table
import http3/internal/varint

type Outstanding {
  Outstanding(references: List(Int), required_insert_count: Int)
}

/// Encoder table, peer knowledge, outstanding references, and instructions.
pub opaque type State {
  State(
    table: dynamic_table.State,
    known_received_count: Int,
    maximum_blocked_streams: Int,
    outstanding: Dict(Int, List(Outstanding)),
    insertion_holds: List(Int),
    maximum_fields: Int,
    maximum_field_section_size: Int,
    pending_instructions: List(instruction.EncoderInstruction),
  )
}

/// Configuration, table, field-section, blocking, or feedback failure.
pub type Error {
  InvalidConfiguration
  InvalidStreamId(Int)
  InvalidHeader
  SensitiveFieldCannotBeInserted
  FieldLimitExceeded(Int)
  FieldSectionSizeExceeded(Int)
  DynamicTableFailure(dynamic_table.Error)
  FieldSectionFailure(field_section.Error)
  InvalidRequiredInsertCount
  InvalidInsertCountIncrement
  MissingOutstandingSection(Int)
}

/// Configure the peer decoder's dynamic-table and blocked-stream limits.
pub fn new(
  maximum_table_capacity: Int,
  initial_table_capacity: Int,
  maximum_blocked_streams: Int,
  maximum_fields: Int,
  maximum_field_section_size: Int,
) -> Result(State, Error) {
  case
    maximum_blocked_streams >= 0
    && maximum_fields > 0
    && maximum_field_section_size >= 0
  {
    False -> Error(InvalidConfiguration)
    True -> {
      use table <- result.try(
        dynamic_table.new(maximum_table_capacity) |> map_table_result,
      )
      use table <- result.try(
        dynamic_table.set_capacity(table, initial_table_capacity)
        |> map_table_result,
      )
      let pending = case initial_table_capacity > 0 {
        True -> [instruction.SetDynamicTableCapacity(initial_table_capacity)]
        False -> []
      }
      Ok(State(
        table,
        0,
        maximum_blocked_streams,
        dict.new(),
        [],
        maximum_fields,
        maximum_field_section_size,
        pending,
      ))
    }
  }
}

/// Change the active table capacity and queue the corresponding instruction.
pub fn set_capacity(state: State, capacity: Int) -> Result(State, Error) {
  use table <- result.try(
    dynamic_table.set_capacity(state.table, capacity) |> map_table_result,
  )
  Ok(queue_instruction(
    State(..state, table: table),
    instruction.SetDynamicTableCapacity(capacity),
  ))
}

/// Insert one reusable field and hold it until the decoder acknowledges it.
pub fn insert(state: State, field: Header) -> Result(State, Error) {
  let Header(name, value, never_index) = field
  use _ <- result.try(validate_header(field))
  case never_index {
    True -> Error(SensitiveFieldCannotBeInserted)
    False -> {
      let outgoing = insertion_instruction(state.table, name, value)
      use #(table, absolute_index) <- result.try(
        dynamic_table.insert(state.table, dynamic_table.Field(name, value))
        |> map_table_result,
      )
      use table <- result.try(
        dynamic_table.acquire(table, [absolute_index]) |> map_table_result,
      )
      Ok(queue_instruction(
        State(..state, table: table, insertion_holds: [
          absolute_index,
          ..state.insertion_holds
        ]),
        outgoing,
      ))
    }
  }
}

/// Duplicate one resident entry addressed by absolute index.
pub fn duplicate(state: State, absolute_index: Int) -> Result(State, Error) {
  let relative_index =
    dynamic_table.insert_count(state.table) - absolute_index - 1
  use #(table, inserted_index) <- result.try(
    dynamic_table.duplicate(state.table, relative_index) |> map_table_result,
  )
  use table <- result.try(
    dynamic_table.acquire(table, [inserted_index]) |> map_table_result,
  )
  Ok(queue_instruction(
    State(..state, table: table, insertion_holds: [
      inserted_index,
      ..state.insertion_holds
    ]),
    instruction.Duplicate(relative_index),
  ))
}

/// Encode an ordered field section without exceeding the peer's blocked-stream
/// promise. Unacknowledged dynamic entries are used only when `allow_blocking`
/// is true and a blocked-stream slot is available for this stream.
pub fn encode(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_blocking: Bool,
  prefer_huffman: Bool,
) -> Result(#(State, BitArray), Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  use _ <- result.try(validate_fields(state, fields))
  let base = dynamic_table.insert_count(state.table)
  let may_risk_blocking =
    allow_blocking
    && {
      stream_might_block(state, stream_id)
      || blocked_stream_count(state) < state.maximum_blocked_streams
    }
  use #(representations, references) <- result.try(
    encode_fields(
      state.table,
      fields,
      base,
      state.known_received_count,
      may_risk_blocking,
      [],
      [],
    ),
  )
  let references = distinct(references, [])
  let required_insert_count = largest(references, -1) + 1
  use encoded_required <- result.try(
    dynamic_table.encode_required_insert_count(
      required_insert_count,
      dynamic_table.maximum_allowed_capacity(state.table),
    )
    |> map_required_result,
  )
  let prefix = case required_insert_count {
    0 -> field_section.Prefix(0, False, 0)
    required -> field_section.Prefix(encoded_required, False, base - required)
  }
  use encoded <- result.try(
    field_section.encode(
      field_section.Section(prefix, representations),
      prefer_huffman,
    )
    |> map_field_section_result,
  )
  case references {
    [] -> Ok(#(state, encoded))
    _ -> {
      use table <- result.try(
        dynamic_table.acquire(state.table, references) |> map_table_result,
      )
      let sections = dict.get(state.outstanding, stream_id) |> result.unwrap([])
      let outstanding =
        dict.insert(
          state.outstanding,
          stream_id,
          list.append(sections, [
            Outstanding(references, required_insert_count),
          ]),
        )
      Ok(#(State(..state, table: table, outstanding: outstanding), encoded))
    }
  }
}

/// Apply peer feedback from the critical QPACK decoder stream.
pub fn apply_decoder_instruction(
  state: State,
  incoming: instruction.DecoderInstruction,
) -> Result(State, Error) {
  case incoming {
    instruction.InsertCountIncrement(increment) ->
      apply_insert_count_increment(state, increment)
    instruction.SectionAcknowledgement(stream_id) ->
      acknowledge_section(state, stream_id)
    instruction.StreamCancellation(stream_id) -> cancel_stream(state, stream_id)
  }
}

/// Pull and clear ordered instructions for the local QPACK encoder stream.
pub fn take_instructions(
  state: State,
) -> #(State, List(instruction.EncoderInstruction)) {
  #(State(..state, pending_instructions: []), state.pending_instructions)
}

/// Number of insertions the peer has confirmed receiving.
pub fn known_received_count(state: State) -> Int {
  state.known_received_count
}

/// Number of streams whose outstanding sections could currently block.
pub fn blocked_stream_count(state: State) -> Int {
  count_blocked(dict.to_list(state.outstanding), state.known_received_count, 0)
}

fn insertion_instruction(
  table: dynamic_table.State,
  name: BitArray,
  value: BitArray,
) -> instruction.EncoderInstruction {
  case
    static_table.find_name_bytes(name),
    dynamic_table.find_name(table, name)
  {
    Some(index), _ -> instruction.InsertWithNameReference(True, index, value)
    None, Some(dynamic_table.Entry(index, _)) ->
      instruction.InsertWithNameReference(
        False,
        dynamic_table.insert_count(table) - index - 1,
        value,
      )
    None, None -> instruction.InsertWithLiteralName(name, value)
  }
}

fn encode_fields(
  table: dynamic_table.State,
  fields: List(Header),
  base: Int,
  known_received_count: Int,
  may_risk_blocking: Bool,
  representations_reversed: List(field_section.Representation),
  references: List(Int),
) -> Result(#(List(field_section.Representation), List(Int)), Error) {
  case fields {
    [] -> Ok(#(list.reverse(representations_reversed), references))
    [field, ..rest] -> {
      use #(representation, reference) <- result.try(encode_field(
        table,
        field,
        base,
        known_received_count,
        may_risk_blocking,
      ))
      let references = case reference {
        None -> references
        Some(index) -> [index, ..references]
      }
      encode_fields(
        table,
        rest,
        base,
        known_received_count,
        may_risk_blocking,
        [representation, ..representations_reversed],
        references,
      )
    }
  }
}

fn encode_field(
  table: dynamic_table.State,
  field: Header,
  base: Int,
  known_received_count: Int,
  may_risk_blocking: Bool,
) -> Result(#(field_section.Representation, Option(Int)), Error) {
  let Header(name, value, never_index) = field
  case never_index, static_table.find_bytes(name, value) {
    False, Some(index) -> Ok(#(field_section.Indexed(True, index), None))
    _, _ ->
      encode_non_static_field(
        table,
        name,
        value,
        never_index,
        base,
        known_received_count,
        may_risk_blocking,
      )
  }
}

fn encode_non_static_field(
  table: dynamic_table.State,
  name: BitArray,
  value: BitArray,
  never_index: Bool,
  base: Int,
  known_received_count: Int,
  may_risk_blocking: Bool,
) -> Result(#(field_section.Representation, Option(Int)), Error) {
  let exact = case never_index {
    True -> None
    False -> dynamic_table.find(table, dynamic_table.Field(name, value))
  }
  case usable_dynamic_entry(exact, known_received_count, may_risk_blocking) {
    Some(dynamic_table.Entry(index, _)) ->
      Ok(#(field_section.Indexed(False, base - index - 1), Some(index)))
    None ->
      encode_literal(
        table,
        name,
        value,
        never_index,
        base,
        known_received_count,
        may_risk_blocking,
      )
  }
}

fn encode_literal(
  table: dynamic_table.State,
  name: BitArray,
  value: BitArray,
  never_index: Bool,
  base: Int,
  known_received_count: Int,
  may_risk_blocking: Bool,
) -> Result(#(field_section.Representation, Option(Int)), Error) {
  case static_table.find_name_bytes(name) {
    Some(index) ->
      Ok(#(
        field_section.LiteralNameReference(never_index, True, index, value),
        None,
      ))
    None -> {
      let named =
        dynamic_table.find_name(table, name)
        |> usable_dynamic_entry(known_received_count, may_risk_blocking)
      case named {
        Some(dynamic_table.Entry(index, _)) ->
          Ok(#(
            field_section.LiteralNameReference(
              never_index,
              False,
              base - index - 1,
              value,
            ),
            Some(index),
          ))
        None ->
          Ok(#(field_section.LiteralLiteralName(never_index, name, value), None))
      }
    }
  }
}

fn usable_dynamic_entry(
  entry: Option(dynamic_table.Entry),
  known_received_count: Int,
  may_risk_blocking: Bool,
) -> Option(dynamic_table.Entry) {
  case entry {
    Some(dynamic_table.Entry(index, _) as found)
      if index < known_received_count || may_risk_blocking
    -> Some(found)
    _ -> None
  }
}

fn apply_insert_count_increment(
  state: State,
  increment: Int,
) -> Result(State, Error) {
  let updated = state.known_received_count + increment
  case
    increment > 0
    && updated <= dynamic_table.insert_count(state.table)
    && updated <= varint.maximum
  {
    False -> Error(InvalidInsertCountIncrement)
    True -> advance_known_received_count(state, updated)
  }
}

fn acknowledge_section(state: State, stream_id: Int) -> Result(State, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  case dict.get(state.outstanding, stream_id) {
    Error(_) -> Error(MissingOutstandingSection(stream_id))
    Ok([]) -> Error(MissingOutstandingSection(stream_id))
    Ok([Outstanding(references, required), ..remaining]) -> {
      use table <- result.try(
        dynamic_table.release(state.table, references) |> map_table_result,
      )
      let outstanding = case remaining {
        [] -> dict.delete(state.outstanding, stream_id)
        _ -> dict.insert(state.outstanding, stream_id, remaining)
      }
      let state = State(..state, table: table, outstanding: outstanding)
      case required > state.known_received_count {
        True -> advance_known_received_count(state, required)
        False -> Ok(state)
      }
    }
  }
}

fn cancel_stream(state: State, stream_id: Int) -> Result(State, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  case
    dict.get(state.outstanding, stream_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> Ok(state)
    Some(sections) -> {
      use table <- result.try(release_sections(state.table, sections))
      Ok(
        State(
          ..state,
          table: table,
          outstanding: dict.delete(state.outstanding, stream_id),
        ),
      )
    }
  }
}

fn release_sections(
  table: dynamic_table.State,
  sections: List(Outstanding),
) -> Result(dynamic_table.State, Error) {
  case sections {
    [] -> Ok(table)
    [Outstanding(references, _), ..rest] -> {
      use table <- result.try(
        dynamic_table.release(table, references) |> map_table_result,
      )
      release_sections(table, rest)
    }
  }
}

fn advance_known_received_count(
  state: State,
  updated_count: Int,
) -> Result(State, Error) {
  use #(table, remaining_holds) <- result.try(
    release_known_holds(state.table, state.insertion_holds, updated_count, []),
  )
  Ok(
    State(
      ..state,
      table: table,
      known_received_count: updated_count,
      insertion_holds: remaining_holds,
    ),
  )
}

fn release_known_holds(
  table: dynamic_table.State,
  holds: List(Int),
  known_received_count: Int,
  remaining_reversed: List(Int),
) -> Result(#(dynamic_table.State, List(Int)), Error) {
  case holds {
    [] -> Ok(#(table, list.reverse(remaining_reversed)))
    [index, ..rest] if index < known_received_count -> {
      use table <- result.try(
        dynamic_table.release(table, [index]) |> map_table_result,
      )
      release_known_holds(table, rest, known_received_count, remaining_reversed)
    }
    [index, ..rest] ->
      release_known_holds(table, rest, known_received_count, [
        index,
        ..remaining_reversed
      ])
  }
}

fn validate_fields(state: State, fields: List(Header)) -> Result(Nil, Error) {
  case list.length(fields) > state.maximum_fields {
    True -> Error(FieldLimitExceeded(state.maximum_fields))
    False -> validate_field_sizes(fields, state.maximum_field_section_size, 0)
  }
}

fn validate_field_sizes(
  fields: List(Header),
  maximum_size: Int,
  size: Int,
) -> Result(Nil, Error) {
  case fields {
    [] -> Ok(Nil)
    [field, ..rest] -> {
      use _ <- result.try(validate_header(field))
      let updated_size = size + header_size(field)
      case updated_size > maximum_size {
        True -> Error(FieldSectionSizeExceeded(maximum_size))
        False -> validate_field_sizes(rest, maximum_size, updated_size)
      }
    }
  }
}

fn validate_header(field: Header) -> Result(Nil, Error) {
  let Header(name, value, _) = field
  case
    bit_array.bit_size(name) % 8 == 0
    && bit_array.bit_size(value) % 8 == 0
    && bit_array.byte_size(name) > 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidHeader)
  }
}

fn header_size(field: Header) -> Int {
  let Header(name, value, _) = field
  bit_array.byte_size(name) + bit_array.byte_size(value) + 32
}

fn validate_stream_id(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= varint.maximum {
    True -> Ok(Nil)
    False -> Error(InvalidStreamId(stream_id))
  }
}

fn stream_might_block(state: State, stream_id: Int) -> Bool {
  dict.get(state.outstanding, stream_id)
  |> result.map(fn(sections) {
    sections_might_block(sections, state.known_received_count)
  })
  |> result.unwrap(False)
}

fn count_blocked(
  streams: List(#(Int, List(Outstanding))),
  known_received_count: Int,
  count: Int,
) -> Int {
  case streams {
    [] -> count
    [#(_, sections), ..rest] ->
      count_blocked(
        rest,
        known_received_count,
        case sections_might_block(sections, known_received_count) {
          True -> count + 1
          False -> count
        },
      )
  }
}

fn sections_might_block(
  sections: List(Outstanding),
  known_received_count: Int,
) -> Bool {
  case sections {
    [] -> False
    [Outstanding(_, required), ..] if required > known_received_count -> True
    [_, ..rest] -> sections_might_block(rest, known_received_count)
  }
}

fn distinct(values: List(Int), accumulator: List(Int)) -> List(Int) {
  case values {
    [] -> accumulator
    [value, ..rest] ->
      distinct(rest, case list.contains(accumulator, value) {
        True -> accumulator
        False -> [value, ..accumulator]
      })
  }
}

fn largest(values: List(Int), current: Int) -> Int {
  case values {
    [] -> current
    [value, ..rest] ->
      largest(rest, case value > current {
        True -> value
        False -> current
      })
  }
}

fn queue_instruction(
  state: State,
  outgoing: instruction.EncoderInstruction,
) -> State {
  State(
    ..state,
    pending_instructions: list.append(state.pending_instructions, [outgoing]),
  )
}

fn map_table_result(
  value: Result(value, dynamic_table.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(DynamicTableFailure(error))
  }
}

fn map_field_section_result(
  value: Result(value, field_section.Error),
) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(FieldSectionFailure(error))
  }
}

fn map_required_result(
  value: Result(Int, dynamic_table.Error),
) -> Result(Int, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidRequiredInsertCount)
  }
}
