import gleam/result
import gleam_quic/internal/qpack/decoder
import gleam_quic/internal/qpack/dynamic_table
import gleam_quic/internal/qpack/encoder
import gleam_quic/internal/qpack/field_section
import gleam_quic/internal/qpack/header
import gleam_quic/internal/qpack/instruction

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn static_and_never_indexed_fields_round_trip_without_state_test() -> Nil {
  let assert Ok(encoder_state) = encoder.new(0, 0, 0, 16, 4096)
  let fields = [
    header.Header(<<":method">>, <<"GET">>, False),
    header.Header(<<"authorization">>, <<"secret">>, True),
  ]
  let assert Ok(#(encoder_state, encoded)) =
    encoder.encode(encoder_state, 0, fields, False, True)
  let assert Ok(decoder_state) = decoder.new(0, 0, 16, 4096)
  assert decoder.decode(decoder_state, 0, encoded)
    == Ok(decoder.Decoded(decoder_state, fields))
  assert encoder.blocked_stream_count(encoder_state) == 0
  let #(_, instructions) = encoder.take_instructions(encoder_state)
  assert instructions == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dynamic_entry_feedback_releases_insertion_and_section_holds_test() -> Nil {
  let assert Ok(encoder_state) = encoder.new(128, 128, 1, 16, 4096)
  let assert #(encoder_state, [instruction.SetDynamicTableCapacity(128)]) =
    encoder.take_instructions(encoder_state)
  let field = header.Header(<<"custom-key">>, <<"custom-value">>, False)
  let assert Ok(encoder_state) = encoder.insert(encoder_state, field)
  let assert #(
    encoder_state,
    [instruction.InsertWithLiteralName(<<"custom-key">>, <<"custom-value">>)],
  ) = encoder.take_instructions(encoder_state)

  let assert Ok(#(encoder_state, encoded)) =
    encoder.encode(encoder_state, 4, [field], True, False)
  assert encoder.blocked_stream_count(encoder_state) == 1

  let assert Ok(decoder_state) = decoder.new(128, 1, 16, 4096)
  let assert Ok(decoder_state) =
    decoder.apply_encoder_instruction(
      decoder_state,
      instruction.SetDynamicTableCapacity(128),
    )
  let assert Ok(decoder_state) =
    decoder.apply_encoder_instruction(
      decoder_state,
      instruction.InsertWithLiteralName(<<"custom-key">>, <<"custom-value">>),
    )
  let assert Ok(decoder.Decoded(decoder_state, [decoded])) =
    decoder.decode(decoder_state, 4, encoded)
  assert decoded == field
  let assert #(
    _,
    [instruction.InsertCountIncrement(1), instruction.SectionAcknowledgement(4)],
  ) = decoder.take_instructions(decoder_state)

  let assert Ok(encoder_state) =
    encoder.apply_decoder_instruction(
      encoder_state,
      instruction.InsertCountIncrement(1),
    )
  assert encoder.known_received_count(encoder_state) == 1
  assert encoder.blocked_stream_count(encoder_state) == 0
  let assert Ok(encoder_state) =
    encoder.apply_decoder_instruction(
      encoder_state,
      instruction.SectionAcknowledgement(4),
    )
  assert encoder.blocked_stream_count(encoder_state) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn avoids_exceeding_the_peer_blocked_stream_limit_test() -> Nil {
  let assert Ok(state) = encoder.new(256, 256, 1, 16, 4096)
  let first = header.Header(<<"x-first">>, <<"one">>, False)
  let second = header.Header(<<"x-second">>, <<"two">>, False)
  let assert Ok(state) = encoder.insert(state, first)
  let assert Ok(state) = encoder.insert(state, second)
  let assert Ok(#(state, _)) = encoder.encode(state, 0, [first], True, False)
  assert encoder.blocked_stream_count(state) == 1

  let assert Ok(#(state, encoded)) =
    encoder.encode(state, 4, [second], True, False)
  assert encoder.blocked_stream_count(state) == 1
  let assert Ok(field_section.Section(
    field_section.Prefix(0, False, 0),
    [field_section.LiteralLiteralName(False, <<"x-second">>, <<"two">>)],
  )) = field_section.decode(encoded, field_section.default_limits())

  let assert Ok(#(state, _)) = encoder.encode(state, 0, [second], True, False)
  assert encoder.blocked_stream_count(state) == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unacknowledged_insertions_cannot_be_evicted_test() -> Nil {
  let assert Ok(state) = encoder.new(34, 34, 0, 16, 4096)
  let assert Ok(state) =
    encoder.insert(state, header.Header(<<"a">>, <<"1">>, False))
  assert encoder.insert(state, header.Header(<<"b">>, <<"2">>, False))
    == Error(
      encoder.DynamicTableFailure(dynamic_table.ReferencedEntryCannotBeEvicted(
        0,
      )),
    )
  let assert Ok(state) =
    encoder.apply_decoder_instruction(
      state,
      instruction.InsertCountIncrement(1),
    )
  assert encoder.insert(state, header.Header(<<"b">>, <<"2">>, False))
    |> result.is_ok
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cancellation_releases_all_sections_on_the_stream_test() -> Nil {
  let assert Ok(state) = encoder.new(128, 128, 1, 16, 4096)
  let field = header.Header(<<"a">>, <<"1">>, False)
  let assert Ok(state) = encoder.insert(state, field)
  let assert Ok(state) =
    encoder.apply_decoder_instruction(
      state,
      instruction.InsertCountIncrement(1),
    )
  let assert Ok(#(state, _)) = encoder.encode(state, 0, [field], False, False)
  let assert Ok(#(state, _)) = encoder.encode(state, 0, [field], False, False)
  let assert Ok(state) =
    encoder.apply_decoder_instruction(state, instruction.StreamCancellation(0))
  assert encoder.set_capacity(state, 0) |> result.is_ok
  assert encoder.apply_decoder_instruction(
      state,
      instruction.SectionAcknowledgement(0),
    )
    == Error(encoder.MissingOutstandingSection(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn duplicates_a_resident_entry_and_queues_the_instruction_test() -> Nil {
  let assert Ok(state) = encoder.new(128, 128, 1, 16, 4096)
  let #(state, _) = encoder.take_instructions(state)
  let assert Ok(state) =
    encoder.insert(state, header.Header(<<"a">>, <<"1">>, False))
  let #(state, _) = encoder.take_instructions(state)
  let assert Ok(state) = encoder.duplicate(state, 0)
  let #(_, instructions) = encoder.take_instructions(state)
  assert instructions == [instruction.Duplicate(0)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_feedback_and_field_bounds_test() -> Nil {
  let assert Ok(state) = encoder.new(64, 64, 0, 1, 34)
  assert encoder.apply_decoder_instruction(
      state,
      instruction.InsertCountIncrement(0),
    )
    == Error(encoder.InvalidInsertCountIncrement)
  assert encoder.apply_decoder_instruction(
      state,
      instruction.InsertCountIncrement(1),
    )
    == Error(encoder.InvalidInsertCountIncrement)
  assert encoder.encode(
      state,
      0,
      [
        header.Header(<<"a">>, <<"1">>, False),
        header.Header(<<"b">>, <<"2">>, False),
      ],
      False,
      False,
    )
    == Error(encoder.FieldLimitExceeded(1))
  assert encoder.encode(
      state,
      0,
      [header.Header(<<"aa">>, <<"1">>, False)],
      False,
      False,
    )
    == Error(encoder.FieldSectionSizeExceeded(34))
  assert encoder.insert(
      state,
      header.Header(<<"authorization">>, <<"secret">>, True),
    )
    == Error(encoder.SensitiveFieldCannotBeInserted)
}
