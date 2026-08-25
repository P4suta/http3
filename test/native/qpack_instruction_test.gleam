import http3/internal/qpack/instruction

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_encoder_stream_instructions_test() -> Nil {
  let limits = instruction.default_limits()
  let instructions = [
    instruction.SetDynamicTableCapacity(220),
    instruction.InsertWithNameReference(True, 17, <<"GET">>),
    instruction.InsertWithNameReference(False, 0, <<"value">>),
    instruction.InsertWithLiteralName(<<"custom-key">>, <<"custom-value">>),
    instruction.Duplicate(5),
  ]
  check_encoder_round_trips(instructions, limits)
  assert instruction.encode_encoder(
      instruction.SetDynamicTableCapacity(220),
      False,
    )
    == Ok(<<0x3f, 0xbd, 0x01>>)
  assert instruction.encode_encoder(
      instruction.InsertWithNameReference(True, 17, <<"GET">>),
      False,
    )
    == Ok(<<0xd1, 3, "GET">>)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_decoder_stream_instructions_and_rejects_zero_increment_test() -> Nil {
  let instructions = [
    instruction.SectionAcknowledgement(10),
    instruction.StreamCancellation(10),
    instruction.InsertCountIncrement(10),
  ]
  check_decoder_round_trips(instructions)
  assert instruction.encode_decoder(instruction.SectionAcknowledgement(10))
    == Ok(<<0x8a>>)
  assert instruction.encode_decoder(instruction.StreamCancellation(10))
    == Ok(<<0x4a>>)
  assert instruction.encode_decoder(instruction.InsertCountIncrement(10))
    == Ok(<<0x0a>>)
  assert instruction.decode_decoder(<<0>>)
    == Error(instruction.InvalidInstruction)
}

fn check_encoder_round_trips(
  instructions: List(instruction.EncoderInstruction),
  limits: instruction.Limits,
) -> Nil {
  case instructions {
    [] -> Nil
    [value, ..rest] -> {
      let assert Ok(encoded) = instruction.encode_encoder(value, True)
      assert instruction.decode_encoder(encoded, limits) == Ok(#(value, <<>>))
      check_encoder_round_trips(rest, limits)
    }
  }
}

fn check_decoder_round_trips(
  instructions: List(instruction.DecoderInstruction),
) -> Nil {
  case instructions {
    [] -> Nil
    [value, ..rest] -> {
      let assert Ok(encoded) = instruction.encode_decoder(value)
      assert instruction.decode_decoder(encoded) == Ok(#(value, <<>>))
      check_decoder_round_trips(rest)
    }
  }
}
