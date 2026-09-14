import http3/internal/qpack/instruction
import http3/internal/qpack/instruction_stream
import http3/internal/qpack/string_literal

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn incrementally_parses_encoder_and_decoder_streams_test() -> Nil {
  let limits = instruction.Limits(16, 16)
  let assert Ok(state) =
    instruction_stream.new(instruction_stream.EncoderStream, limits, 32)
  let assert Ok(encoded) =
    instruction.encode_encoder(
      instruction.InsertWithLiteralName(<<"name">>, <<"value">>),
      False,
    )
  let assert <<first, rest:bits>> = encoded
  let assert Ok(state) = instruction_stream.push(state, <<first>>)
  assert instruction_stream.next(state)
    == Ok(instruction_stream.NeedMore(state))
  let assert Ok(state) = instruction_stream.push(state, rest)
  let assert Ok(instruction_stream.InstructionReady(
    _,
    instruction_stream.EncoderInstruction(decoded),
  )) = instruction_stream.next(state)
  assert decoded == instruction.InsertWithLiteralName(<<"name">>, <<"value">>)

  let assert Ok(state) =
    instruction_stream.new(instruction_stream.DecoderStream, limits, 32)
  let assert Ok(encoded) =
    instruction.encode_decoder(instruction.SectionAcknowledgement(64))
  let assert Ok(state) = instruction_stream.push(state, encoded)
  let assert Ok(instruction_stream.InstructionReady(
    state,
    instruction_stream.DecoderInstruction(instruction.SectionAcknowledgement(64)),
  )) = instruction_stream.next(state)
  assert instruction_stream.finish(state)
    == Error(instruction_stream.ClosedCriticalStream)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_instruction_and_buffer_limits_test() -> Nil {
  let limits = instruction.Limits(4, 4)
  let assert Ok(state) =
    instruction_stream.new(instruction_stream.EncoderStream, limits, 20)
  assert instruction_stream.push(state, <<0:168>>)
    == Error(instruction_stream.BufferLimitExceeded(20))
  assert instruction_stream.push(state, <<0:1>>)
    == Error(instruction_stream.NonByteAligned)

  let assert Ok(oversized) =
    instruction.encode_encoder(
      instruction.InsertWithLiteralName(<<"12345">>, <<"v">>),
      False,
    )
  let assert Ok(state) = instruction_stream.push(state, oversized)
  assert instruction_stream.next(state)
    == Error(
      instruction_stream.InstructionFailure(
        instruction.StringFailure(string_literal.EncodedLengthLimitExceeded(4)),
      ),
    )
}
