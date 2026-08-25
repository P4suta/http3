//// Reproducible generated round-trip properties for core wire codecs.

import gleam/bit_array
import gleam_quic/frame as transport_frame
import gleam_quic/varint
import http3/internal/native/frame as http3_frame
import http3/internal/qpack/integer as qpack_integer

const generator_modulus = 2_147_483_647

/// Check generated varint, transport-frame, HTTP/3-frame, and QPACK integer
/// round trips.
pub fn exercise(cases: Int) -> Int {
  exercise_cases(982_451_653, cases)
  cases
}

fn exercise_cases(seed: Int, remaining: Int) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let first = next_seed(seed)
      let second = next_seed(first)
      let value = { first * second } % { varint.maximum + 1 }
      assert_varint_round_trip(value)
      assert_qpack_integer_round_trip(value, 1 + first % 8)

      let length = second % 65
      let #(seed, payload) = generate_bytes(second, length, <<>>)
      assert_transport_frame_round_trip(transport_frame.Stream(
        first % 1024,
        second % 65_536,
        payload,
        first % 2 == 0,
      ))
      assert_http3_frame_round_trip(http3_frame.Unknown(
        14 + second % 4096,
        payload,
      ))
      exercise_cases(seed, remaining - 1)
    }
  }
}

fn assert_varint_round_trip(value: Int) -> Nil {
  let assert Ok(encoded) = varint.encode(value)
  let assert Ok(#(decoded, <<>>)) = varint.decode(encoded)
  let assert Ok(size) = varint.encoded_size(value)
  assert decoded == value
  assert bit_array.byte_size(encoded) == size
}

fn assert_qpack_integer_round_trip(value: Int, prefix_bits: Int) -> Nil {
  let assert Ok(encoded) = qpack_integer.encode(value, prefix_bits, 0)
  let assert Ok(qpack_integer.Decoded(decoded, <<>>)) =
    qpack_integer.decode(encoded, prefix_bits)
  assert decoded == value
}

fn assert_transport_frame_round_trip(value: transport_frame.Frame) -> Nil {
  let assert Ok(encoded) = transport_frame.encode(value)
  assert transport_frame.decode_all(encoded, transport_frame.default_limits())
    == Ok([value])
}

fn assert_http3_frame_round_trip(value: http3_frame.Frame) -> Nil {
  let assert Ok(encoded) = http3_frame.encode(value)
  assert http3_frame.decode(encoded, http3_frame.default_limits())
    == Ok(#(value, <<>>))
}

fn generate_bytes(
  seed: Int,
  remaining: Int,
  accumulator: BitArray,
) -> #(Int, BitArray) {
  case remaining {
    0 -> #(seed, accumulator)
    _ -> {
      let seed = next_seed(seed)
      let byte = seed % 256
      generate_bytes(seed, remaining - 1, <<accumulator:bits, byte>>)
    }
  }
}

fn next_seed(seed: Int) -> Int {
  { seed * 48_271 + 1 } % generator_modulus
}
