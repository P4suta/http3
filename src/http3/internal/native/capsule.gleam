//// Bounded incremental RFC 9297 Capsule Protocol parser and encoder.

import gleam/bit_array
import gleam/result
import gleam_quic/varint

/// One known or extension capsule. Unknown types remain available to the
/// negotiated HTTP extension that owns the data stream.
pub type Capsule {
  Datagram(BitArray)
  Unknown(capsule_type: Int, value: BitArray)
}

/// Incremental parser with unread stream bytes retained within a fixed bound.
pub opaque type State {
  State(
    buffered: BitArray,
    maximum_capsule_value_bytes: Int,
    maximum_buffered_bytes: Int,
  )
}

/// Parser needs more data or produced exactly one capsule.
pub type Outcome {
  NeedMore(State)
  CapsuleReady(State, Capsule)
}

/// Invalid configuration, alignment, integer, size, or clean-end failure.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  BufferLimitExceeded(Int)
  CapsuleLimitExceeded(Int)
  TruncatedCapsule
  IntegerFailure(varint.Error)
}

/// Start one bounded parser for a negotiated Capsule Protocol data stream.
pub fn new(
  maximum_capsule_value_bytes: Int,
  maximum_buffered_bytes: Int,
) -> Result(State, Error) {
  case
    maximum_capsule_value_bytes >= 0
    && maximum_buffered_bytes >= maximum_capsule_value_bytes
  {
    True -> Ok(State(<<>>, maximum_capsule_value_bytes, maximum_buffered_bytes))
    False -> Error(InvalidConfiguration)
  }
}

/// Append an in-order DATA payload without exceeding retained-memory limits.
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

/// Parse at most one capsule, preserving incomplete or following bytes.
pub fn next(state: State) -> Result(Outcome, Error) {
  case state.buffered {
    <<>> -> Ok(NeedMore(state))
    _ -> decode_type(state)
  }
}

/// A clean FIN is valid only on a capsule boundary.
pub fn finish(state: State) -> Result(Nil, Error) {
  case state.buffered {
    <<>> -> Ok(Nil)
    _ -> Error(TruncatedCapsule)
  }
}

/// Encode one complete capsule.
pub fn encode(value: Capsule) -> Result(BitArray, Error) {
  let #(capsule_type, payload) = case value {
    Datagram(payload) -> #(0, payload)
    Unknown(capsule_type, payload) -> #(capsule_type, payload)
  }
  case bit_array.bit_size(payload) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      use capsule_type <- result.try(encode_integer(capsule_type))
      use length <- result.try(encode_integer(bit_array.byte_size(payload)))
      Ok(<<capsule_type:bits, length:bits, payload:bits>>)
    }
  }
}

/// Bytes currently retained for a partial or following capsule.
pub fn buffered_bytes(state: State) -> Int {
  bit_array.byte_size(state.buffered)
}

fn decode_type(state: State) -> Result(Outcome, Error) {
  case varint.decode(state.buffered) {
    Error(varint.Truncated) -> Ok(NeedMore(state))
    Error(error) -> Error(IntegerFailure(error))
    Ok(#(capsule_type, rest)) -> decode_length(state, capsule_type, rest)
  }
}

fn decode_length(
  state: State,
  capsule_type: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  case varint.decode(bytes) {
    Error(varint.Truncated) -> Ok(NeedMore(state))
    Error(error) -> Error(IntegerFailure(error))
    Ok(#(length, payload_and_rest)) ->
      case length > state.maximum_capsule_value_bytes {
        True -> Error(CapsuleLimitExceeded(state.maximum_capsule_value_bytes))
        False -> take_capsule(state, capsule_type, length, payload_and_rest)
      }
  }
}

// nolint: deep_nesting -- the bounded payload slice is validated without partial allocation.
fn take_capsule(
  state: State,
  capsule_type: Int,
  length: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  case bit_array.byte_size(bytes) < length {
    True -> Ok(NeedMore(state))
    False -> {
      let bits = length * 8
      case bytes {
        <<payload:bits-size(bits), rest:bits>> -> {
          let decoded = case capsule_type {
            0 -> Datagram(payload)
            value -> Unknown(value, payload)
          }
          Ok(CapsuleReady(State(..state, buffered: rest), decoded))
        }
        _ -> Ok(NeedMore(state))
      }
    }
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case varint.encode(value) {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(IntegerFailure(error))
  }
}
