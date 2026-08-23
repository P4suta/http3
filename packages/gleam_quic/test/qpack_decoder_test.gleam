import gleam_quic/internal/qpack/decoder
import gleam_quic/internal/qpack/field_section
import gleam_quic/internal/qpack/header
import gleam_quic/internal/qpack/instruction

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn decodes_static_and_literal_field_sections_test() -> Nil {
  let assert Ok(state) = decoder.new(0, 0, 16, 4096)
  let section =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 17),
      field_section.LiteralNameReference(False, True, 4, <<"42">>),
      field_section.LiteralLiteralName(True, <<"authorization">>, <<"x">>),
    ])
  let assert Ok(encoded) = field_section.encode(section, True)
  assert decoder.decode(state, 0, encoded)
    == Ok(
      decoder.Decoded(state, [
        header.Header(<<":method">>, <<"GET">>, False),
        header.Header(<<"content-length">>, <<"42">>, False),
        header.Header(<<"authorization">>, <<"x">>, True),
      ]),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn blocks_then_resumes_dynamic_references_and_emits_feedback_test() -> Nil {
  let assert Ok(state) = decoder.new(128, 1, 16, 4096)
  let section =
    field_section.Section(field_section.Prefix(2, False, 0), [
      field_section.Indexed(False, 0),
    ])
  let assert Ok(encoded) = field_section.encode(section, False)
  let assert Ok(decoder.Blocked(state, 1)) = decoder.decode(state, 4, encoded)
  let cancelled = decoder.cancel_stream(state, 4)
  let #(_, cancelled_feedback) = decoder.take_instructions(cancelled)
  assert cancelled_feedback == [instruction.StreamCancellation(4)]
  let assert Ok(state) =
    decoder.apply_encoder_instruction(
      state,
      instruction.SetDynamicTableCapacity(128),
    )
  let assert Ok(state) =
    decoder.apply_encoder_instruction(
      state,
      instruction.InsertWithLiteralName(<<"a">>, <<"1">>),
    )
  let assert Ok(decoder.Decoded(state, [header.Header(<<"a">>, <<"1">>, False)])) =
    decoder.retry_blocked(state, 4)
  let #(_, feedback) = decoder.take_instructions(state)
  assert feedback
    == [
      instruction.InsertCountIncrement(1),
      instruction.SectionAcknowledgement(4),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_blocked_stream_and_required_insert_count_rules_test() -> Nil {
  let assert Ok(state) = decoder.new(128, 0, 16, 4096)
  let section =
    field_section.Section(field_section.Prefix(2, False, 0), [
      field_section.Indexed(False, 0),
    ])
  let assert Ok(encoded) = field_section.encode(section, False)
  assert decoder.decode(state, 0, encoded)
    == Error(decoder.BlockedStreamLimitExceeded(0))

  let invalid =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 17),
    ])
  let assert Ok(invalid) = field_section.encode(invalid, False)
  assert decoder.decode(state, 0, invalid)
    == Ok(
      decoder.Decoded(state, [
        header.Header(<<":method">>, <<"GET">>, False),
      ]),
    )
}
