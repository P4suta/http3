//// Bounded incremental parser for critical QPACK instruction streams.

import gleam/bit_array
import http3/internal/qpack/instruction

/// Which peer critical stream is being parsed.
pub type Kind {
  EncoderStream
  DecoderStream
}

/// One decoded instruction from either direction.
pub type Decoded {
  EncoderInstruction(instruction.EncoderInstruction)
  DecoderInstruction(instruction.DecoderInstruction)
}

/// Incremental parser buffer and string allocation bounds.
pub opaque type State {
  State(
    kind: Kind,
    buffered: BitArray,
    limits: instruction.Limits,
    maximum_buffered_bytes: Int,
  )
}

/// Parser needs more bytes or produced one instruction.
pub type Outcome {
  NeedMore(State)
  InstructionReady(State, Decoded)
}

/// Invalid configuration, alignment, bounds, instruction, or critical FIN.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  BufferLimitExceeded(Int)
  ClosedCriticalStream
  InstructionFailure(instruction.Error)
}

/// Create a parser for one peer encoder or decoder stream.
pub fn new(
  kind: Kind,
  limits: instruction.Limits,
  maximum_buffered_bytes: Int,
) -> Result(State, Error) {
  case limits, maximum_buffered_bytes {
    instruction.Limits(maximum_encoded, maximum_decoded), maximum
      if maximum_encoded >= 0
      && maximum_decoded >= 0
      && maximum >= maximum_encoded + 16
    -> Ok(State(kind, <<>>, limits, maximum))
    _, _ -> Error(InvalidConfiguration)
  }
}

/// Append in-order critical-stream bytes.
pub fn push(state: State, bytes: BitArray) -> Result(State, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let size =
        bit_array.byte_size(state.buffered) + bit_array.byte_size(bytes)
      case size > state.maximum_buffered_bytes {
        True -> Error(BufferLimitExceeded(state.maximum_buffered_bytes))
        False ->
          Ok(State(..state, buffered: <<state.buffered:bits, bytes:bits>>))
      }
    }
  }
}

/// Parse at most one instruction.
pub fn next(state: State) -> Result(Outcome, Error) {
  case state.buffered {
    <<>> -> Ok(NeedMore(state))
    _ ->
      case state.kind {
        EncoderStream -> decode_encoder(state)
        DecoderStream -> decode_decoder(state)
      }
  }
}

/// QPACK critical streams are never permitted to close, even on an
/// instruction boundary.
pub fn finish(_state: State) -> Result(Nil, Error) {
  Error(ClosedCriticalStream)
}

fn decode_encoder(state: State) -> Result(Outcome, Error) {
  case instruction.decode_encoder(state.buffered, state.limits) {
    Ok(#(decoded, rest)) ->
      Ok(InstructionReady(
        State(..state, buffered: rest),
        EncoderInstruction(decoded),
      ))
    Error(instruction.Truncated) -> Ok(NeedMore(state))
    Error(error) -> Error(InstructionFailure(error))
  }
}

fn decode_decoder(state: State) -> Result(Outcome, Error) {
  case instruction.decode_decoder(state.buffered) {
    Ok(#(decoded, rest)) ->
      Ok(InstructionReady(
        State(..state, buffered: rest),
        DecoderInstruction(decoded),
      ))
    Error(instruction.Truncated) -> Ok(NeedMore(state))
    Error(error) -> Error(InstructionFailure(error))
  }
}
