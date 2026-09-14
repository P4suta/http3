//// Stateful bounded QPACK decoder, encoder-stream consumer, and blocking.

import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/qpack/dynamic_table
import http3/internal/qpack/field_section
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction
import http3/internal/qpack/static_table

type BlockedSection {
  BlockedSection(BitArray)
}

/// Decoded immediately or retained within the negotiated blocked-stream bound.
pub type Outcome {
  Decoded(State, List(Header))
  Blocked(State, required_insert_count: Int)
}

/// Decoder table, blocked sections, and pending decoder-stream feedback.
pub opaque type State {
  State(
    table: dynamic_table.State,
    maximum_blocked_streams: Int,
    blocked: Dict(Int, BlockedSection),
    maximum_fields: Int,
    maximum_field_section_size: Int,
    pending_instructions: List(instruction.DecoderInstruction),
  )
}

/// Encoder-stream, field-section, index, blocking, or size failure.
pub type Error {
  InvalidConfiguration
  EncoderInstructionFailure
  DynamicTableFailure(dynamic_table.Error)
  FieldSectionFailure(field_section.Error)
  MissingStaticIndex(Int)
  InvalidDynamicReference(Int)
  InvalidRequiredInsertCount
  InvalidBase
  BlockedStreamLimitExceeded(Int)
  StreamAlreadyBlocked(Int)
  StreamNotBlocked(Int)
  FieldSectionSizeExceeded(Int)
}

/// Configure the peer encoder's capacity and blocked-stream ceilings.
pub fn new(
  maximum_table_capacity: Int,
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
      Ok(
        State(
          table,
          maximum_blocked_streams,
          dict.new(),
          maximum_fields,
          maximum_field_section_size,
          [],
        ),
      )
    }
  }
}

/// Apply one instruction received on the peer's critical encoder stream.
pub fn apply_encoder_instruction(
  state: State,
  incoming: instruction.EncoderInstruction,
) -> Result(State, Error) {
  case incoming {
    instruction.SetDynamicTableCapacity(capacity) -> {
      use table <- result.try(
        dynamic_table.set_capacity(state.table, capacity) |> map_table_result,
      )
      Ok(State(..state, table: table))
    }
    instruction.InsertWithLiteralName(name, value) ->
      insert_field(state, dynamic_table.Field(name, value))
    instruction.InsertWithNameReference(is_static, index, value) -> {
      use name <- result.try(resolve_insert_name(state.table, is_static, index))
      insert_field(state, dynamic_table.Field(name, value))
    }
    instruction.Duplicate(relative_index) -> {
      use #(table, _) <- result.try(
        dynamic_table.duplicate(state.table, relative_index) |> map_table_result,
      )
      Ok(record_insert(State(..state, table: table)))
    }
  }
}

/// Decode or block one field section on a request/push stream.
pub fn decode(
  state: State,
  stream_id: Int,
  encoded: BitArray,
) -> Result(Outcome, Error) {
  use section <- result.try(decode_wire_section(state, encoded))
  let field_section.Section(prefix, _) = section
  use #(required, base) <- result.try(resolve_prefix(state, prefix))
  case required > dynamic_table.insert_count(state.table) {
    True -> block_section(state, stream_id, encoded, required)
    False -> decode_available(state, stream_id, section, required, base)
  }
}

/// Retry one retained section after processing encoder-stream insertions.
pub fn retry_blocked(state: State, stream_id: Int) -> Result(Outcome, Error) {
  case dict.get(state.blocked, stream_id) {
    Error(_) -> Error(StreamNotBlocked(stream_id))
    Ok(BlockedSection(encoded)) ->
      decode(
        State(..state, blocked: dict.delete(state.blocked, stream_id)),
        stream_id,
        encoded,
      )
  }
}

/// Pull and clear ordered feedback for the local QPACK decoder stream.
pub fn take_instructions(
  state: State,
) -> #(State, List(instruction.DecoderInstruction)) {
  #(State(..state, pending_instructions: []), state.pending_instructions)
}

/// Stream IDs currently flow-control blocked on missing dynamic insertions.
pub fn blocked_streams(state: State) -> List(Int) {
  dict.keys(state.blocked)
}

/// Abandon one blocked field section and notify the peer encoder to release
/// every outstanding reference associated with the request stream.
pub fn cancel_stream(state: State, stream_id: Int) -> State {
  case dict.has_key(state.blocked, stream_id) {
    False -> state
    True ->
      queue_instruction(
        State(..state, blocked: dict.delete(state.blocked, stream_id)),
        instruction.StreamCancellation(stream_id),
      )
  }
}

fn insert_field(
  state: State,
  field: dynamic_table.Field,
) -> Result(State, Error) {
  use #(table, _) <- result.try(
    dynamic_table.insert(state.table, field) |> map_table_result,
  )
  Ok(record_insert(State(..state, table: table)))
}

fn record_insert(state: State) -> State {
  State(
    ..state,
    pending_instructions: list.append(state.pending_instructions, [
      instruction.InsertCountIncrement(1),
    ]),
  )
}

fn resolve_insert_name(
  table: dynamic_table.State,
  is_static: Bool,
  index: Int,
) -> Result(BitArray, Error) {
  case is_static {
    True ->
      case static_table.get(index) {
        Some(static_table.Field(name, _)) -> Ok(<<name:utf8>>)
        None -> Error(MissingStaticIndex(index))
      }
    False ->
      case dynamic_table.get_relative(table, index) {
        Ok(dynamic_table.Entry(_, dynamic_table.Field(name, _))) -> Ok(name)
        Error(error) -> Error(DynamicTableFailure(error))
      }
  }
}

fn decode_wire_section(
  state: State,
  encoded: BitArray,
) -> Result(field_section.Section, Error) {
  field_section.decode(
    encoded,
    field_section.Limits(
      state.maximum_fields,
      state.maximum_field_section_size,
      state.maximum_field_section_size,
    ),
  )
  |> map_field_section_result
}

fn resolve_prefix(
  state: State,
  prefix: field_section.Prefix,
) -> Result(#(Int, Int), Error) {
  let field_section.Prefix(encoded_required, sign, delta) = prefix
  use required <- result.try(
    dynamic_table.decode_required_insert_count(
      encoded_required,
      dynamic_table.maximum_allowed_capacity(state.table),
      dynamic_table.insert_count(state.table),
    )
    |> map_required_insert_count_result,
  )
  let base = case sign {
    False -> required + delta
    True -> required - delta - 1
  }
  case base >= 0 {
    True -> Ok(#(required, base))
    False -> Error(InvalidBase)
  }
}

fn block_section(
  state: State,
  stream_id: Int,
  encoded: BitArray,
  required: Int,
) -> Result(Outcome, Error) {
  case dict.has_key(state.blocked, stream_id), dict.size(state.blocked) {
    True, _ -> Error(StreamAlreadyBlocked(stream_id))
    False, count if count >= state.maximum_blocked_streams ->
      Error(BlockedStreamLimitExceeded(state.maximum_blocked_streams))
    False, _ ->
      Ok(Blocked(
        State(
          ..state,
          blocked: dict.insert(
            state.blocked,
            stream_id,
            BlockedSection(encoded),
          ),
        ),
        required,
      ))
  }
}

fn decode_available(
  state: State,
  stream_id: Int,
  section: field_section.Section,
  required: Int,
  base: Int,
) -> Result(Outcome, Error) {
  let field_section.Section(_, representations) = section
  use #(headers, references, field_size) <- result.try(resolve_representations(
    state.table,
    representations,
    base,
    [],
    [],
    0,
  ))
  use _ <- result.try(validate_required_count(required, references))
  case field_size > state.maximum_field_section_size {
    True -> Error(FieldSectionSizeExceeded(state.maximum_field_section_size))
    False -> {
      let state = case required > 0 {
        True ->
          queue_instruction(
            state,
            instruction.SectionAcknowledgement(stream_id),
          )
        False -> state
      }
      Ok(Decoded(state, headers))
    }
  }
}

fn resolve_representations(
  table: dynamic_table.State,
  representations: List(field_section.Representation),
  base: Int,
  headers_reversed: List(Header),
  references: List(Int),
  size: Int,
) -> Result(#(List(Header), List(Int), Int), Error) {
  case representations {
    [] -> Ok(#(list.reverse(headers_reversed), references, size))
    [representation, ..rest] -> {
      use #(decoded_header, reference) <- result.try(resolve_representation(
        table,
        representation,
        base,
      ))
      let references = case reference {
        None -> references
        Some(index) -> [index, ..references]
      }
      resolve_representations(
        table,
        rest,
        base,
        [decoded_header, ..headers_reversed],
        references,
        size + header.size(decoded_header),
      )
    }
  }
}

fn resolve_representation(
  table: dynamic_table.State,
  representation: field_section.Representation,
  base: Int,
) -> Result(#(Header, Option(Int)), Error) {
  case representation {
    field_section.Indexed(True, index) -> {
      use field <- result.try(static_field(index))
      Ok(#(field_to_header(field, False), None))
    }
    field_section.Indexed(False, index) ->
      dynamic_field(table, base - index - 1, False)
    field_section.IndexedPostBase(index) ->
      dynamic_field(table, base + index, False)
    field_section.LiteralNameReference(never, True, index, value) -> {
      use static_table.Field(name, _) <- result.try(static_field(index))
      Ok(#(Header(<<name:utf8>>, value, never), None))
    }
    field_section.LiteralNameReference(never, False, index, value) ->
      dynamic_name(table, base - index - 1, value, never)
    field_section.LiteralPostBaseNameReference(never, index, value) ->
      dynamic_name(table, base + index, value, never)
    field_section.LiteralLiteralName(never, name, value) ->
      Ok(#(Header(name, value, never), None))
  }
}

fn static_field(index: Int) -> Result(static_table.Field, Error) {
  case static_table.get(index) {
    Some(field) -> Ok(field)
    None -> Error(MissingStaticIndex(index))
  }
}

fn field_to_header(field: static_table.Field, never: Bool) -> Header {
  let static_table.Field(name, value) = field
  Header(<<name:utf8>>, <<value:utf8>>, never)
}

fn dynamic_field(
  table: dynamic_table.State,
  absolute_index: Int,
  never: Bool,
) -> Result(#(Header, Option(Int)), Error) {
  case dynamic_table.get_absolute(table, absolute_index) {
    Ok(dynamic_table.Entry(index, dynamic_table.Field(name, value))) ->
      Ok(#(Header(name, value, never), Some(index)))
    Error(_) -> Error(InvalidDynamicReference(absolute_index))
  }
}

fn dynamic_name(
  table: dynamic_table.State,
  absolute_index: Int,
  value: BitArray,
  never: Bool,
) -> Result(#(Header, Option(Int)), Error) {
  case dynamic_table.get_absolute(table, absolute_index) {
    Ok(dynamic_table.Entry(index, dynamic_table.Field(name, _))) ->
      Ok(#(Header(name, value, never), Some(index)))
    Error(_) -> Error(InvalidDynamicReference(absolute_index))
  }
}

fn validate_required_count(
  required: Int,
  references: List(Int),
) -> Result(Nil, Error) {
  let actual = largest_reference(references, -1) + 1
  case actual == required {
    True -> Ok(Nil)
    False -> Error(InvalidRequiredInsertCount)
  }
}

fn largest_reference(references: List(Int), largest: Int) -> Int {
  case references {
    [] -> largest
    [value, ..rest] ->
      largest_reference(rest, case value > largest {
        True -> value
        False -> largest
      })
  }
}

fn queue_instruction(
  state: State,
  outgoing: instruction.DecoderInstruction,
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
    Ok(decoded) -> Ok(decoded)
    Error(error) -> Error(FieldSectionFailure(error))
  }
}

fn map_required_insert_count_result(
  value: Result(Int, dynamic_table.Error),
) -> Result(Int, Error) {
  case value {
    Ok(required) -> Ok(required)
    Error(_) -> Error(InvalidRequiredInsertCount)
  }
}
