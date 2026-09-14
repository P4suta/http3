//// Bounded RFC 9297 Capsule Protocol codec for Extended CONNECT streams.
////
//// Capsule and QUIC variable-length integer ownership lives in the `http3`
//// package; no raw transport codec crosses the package boundary.

import gleam/bit_array
import gleam/bool
import gleam/result

const maximum_integer = 4_611_686_018_427_387_903

/// One standard DATAGRAM Capsule or an extension capsule.
pub type Capsule {
  Datagram(BitArray)
  Extension(capsule_type: Int, value: BitArray)
}

/// Incremental decoder retaining at most its configured byte limit.
pub opaque type Decoder {
  Decoder(
    buffered: BitArray,
    maximum_capsule_bytes: Int,
    maximum_buffered_bytes: Int,
  )
}

/// Result of parsing at most one capsule.
pub type Outcome {
  NeedMore(Decoder)
  Ready(decoder: Decoder, capsule: Capsule)
}

/// Invalid configuration, wire input, bound, or clean stream end.
pub type Error {
  InvalidConfiguration
  NonByteAligned
  BufferLimitExceeded(limit: Int)
  CapsuleLimitExceeded(limit: Int)
  Truncated
  InvalidCapsuleType
}

/// Create a bounded incremental decoder.
pub fn decoder(
  maximum_capsule_bytes maximum_capsule_bytes: Int,
  maximum_buffered_bytes maximum_buffered_bytes: Int,
) -> Result(Decoder, Error) {
  use <- bool.guard(
    when: maximum_capsule_bytes < 0
      || maximum_buffered_bytes < maximum_capsule_bytes,
    return: Error(InvalidConfiguration),
  )
  Ok(Decoder(<<>>, maximum_capsule_bytes, maximum_buffered_bytes))
}

/// Append one byte-aligned HTTP DATA fragment.
pub fn push(
  decoder decoder: Decoder,
  bytes bytes: BitArray,
) -> Result(Decoder, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let size =
        bit_array.byte_size(decoder.buffered) + bit_array.byte_size(bytes)
      case size > decoder.maximum_buffered_bytes {
        True -> Error(BufferLimitExceeded(decoder.maximum_buffered_bytes))
        False ->
          Ok(
            Decoder(..decoder, buffered: <<decoder.buffered:bits, bytes:bits>>),
          )
      }
    }
  }
}

/// Parse at most one capsule while preserving following bytes.
pub fn next(decoder: Decoder) -> Result(Outcome, Error) {
  case decoder.buffered {
    <<>> -> Ok(NeedMore(decoder))
    bytes -> decode_type(decoder, bytes)
  }
}

/// Validate that stream FIN arrived exactly on a capsule boundary.
pub fn finish(decoder: Decoder) -> Result(Nil, Error) {
  case decoder.buffered {
    <<>> -> Ok(Nil)
    _ -> Error(Truncated)
  }
}

/// Encode one complete capsule.
pub fn encode(capsule: Capsule) -> Result(BitArray, Error) {
  let #(capsule_type, payload) = case capsule {
    Datagram(payload) -> #(0, payload)
    Extension(capsule_type, payload) -> #(capsule_type, payload)
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

/// Return bytes retained for an incomplete or following capsule.
pub fn buffered_bytes(decoder: Decoder) -> Int {
  bit_array.byte_size(decoder.buffered)
}

fn decode_type(decoder: Decoder, bytes: BitArray) -> Result(Outcome, Error) {
  case decode_integer(bytes) {
    Error(Nil) -> Ok(NeedMore(decoder))
    Ok(#(capsule_type, rest)) -> decode_length(decoder, capsule_type, rest)
  }
}

// nolint: label_possible -- private parser helpers read clearly in wire order.
fn decode_length(
  decoder: Decoder,
  capsule_type: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  case decode_integer(bytes) {
    Error(Nil) -> Ok(NeedMore(decoder))
    Ok(#(length, payload_and_rest)) ->
      case length > decoder.maximum_capsule_bytes {
        True -> Error(CapsuleLimitExceeded(decoder.maximum_capsule_bytes))
        False -> take_capsule(decoder, capsule_type, length, payload_and_rest)
      }
  }
}

// nolint: label_possible -- private parser helpers read clearly in wire order.
fn take_capsule(
  decoder: Decoder,
  capsule_type: Int,
  length: Int,
  bytes: BitArray,
) -> Result(Outcome, Error) {
  use <- bool.guard(
    when: bit_array.byte_size(bytes) < length,
    return: Ok(NeedMore(decoder)),
  )
  let bits = length * 8
  case bytes {
    <<payload:bits-size(bits), rest:bits>> -> {
      let capsule = case capsule_type {
        0 -> Datagram(payload)
        extension -> Extension(extension, payload)
      }
      Ok(Ready(Decoder(..decoder, buffered: rest), capsule))
    }
    _ -> Ok(NeedMore(decoder))
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Nil) {
  case bytes {
    <<0:2, value:6, rest:bits>> -> Ok(#(value, rest))
    <<1:2, value:14, rest:bits>> -> Ok(#(value, rest))
    <<2:2, value:30, rest:bits>> -> Ok(#(value, rest))
    <<3:2, value:62, rest:bits>> -> Ok(#(value, rest))
    _ -> Error(Nil)
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  use <- bool.guard(
    when: value < 0 || value > maximum_integer,
    return: Error(InvalidCapsuleType),
  )
  case value {
    value if value <= 63 -> Ok(<<0:2, value:6>>)
    value if value <= 16_383 -> Ok(<<1:2, value:14>>)
    value if value <= 1_073_741_823 -> Ok(<<2:2, value:30>>)
    value -> Ok(<<3:2, value:62>>)
  }
}
