//// Deterministic retained-seed corpus for every unauthenticated QUIC parser.

import gleam/list
import gleam/result
import gleam_quic/frame as transport_frame
import gleam_quic/internal/tls/handshake
import gleam_quic/packet
import gleam_quic/transport_parameter
import gleam_quic/varint

const generator_modulus = 2_147_483_647

/// Exercise retained regressions and a reproducible generated corpus.
pub fn exercise(generated_cases: Int) -> Int {
  let retained = retained_inputs()
  list.each(retained, exercise_one)
  exercise_generated(1_597_463_007, generated_cases)
  list.length(retained) + generated_cases
}

fn exercise_generated(seed: Int, remaining: Int) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let seed = next_seed(seed)
      let length = seed % 257
      let #(seed, bytes) = generate_bytes(seed, length, <<>>)
      exercise_one(bytes)
      exercise_generated(seed, remaining - 1)
    }
  }
}

fn exercise_one(bytes: BitArray) -> Nil {
  assert observe_result(varint.decode(bytes))
  assert observe_result(transport_frame.decode_all(
    bytes,
    transport_frame.default_limits(),
  ))
  assert observe_result(transport_parameter.decode_all(
    bytes,
    transport_parameter.Client,
    transport_parameter.default_limits(),
  ))
  assert observe_result(transport_parameter.decode_all(
    bytes,
    transport_parameter.Server,
    transport_parameter.default_limits(),
  ))
  assert observe_result(packet.parse_long(bytes))
  assert observe_result(packet.parse_short(bytes, first_byte(bytes) % 21))
  assert observe_result(handshake.decode_next(bytes, handshake.default_limits()))
}

fn retained_inputs() -> List(BitArray) {
  [
    <<>>,
    <<0>>,
    <<0x3f>>,
    <<0x40>>,
    <<0x7f>>,
    <<0x80>>,
    <<0xc0>>,
    <<0xff>>,
    <<0x40, 0>>,
    <<0x80, 0, 0, 0, 0, 0, 0>>,
    <<0xc0, 0, 0, 0, 1, 21, 0:168, 0>>,
    <<0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>,
    <<0x04, 0x01, 0x00, 0x04, 0x01, 0x00>>,
    <<0x1c, 0x3f, 0x3f, 0x3f>>,
    <<0x31, 0x40, 0x00>>,
    <<0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>,
  ]
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

fn first_byte(bytes: BitArray) -> Int {
  case bytes {
    <<first, _:bits>> -> first
    <<>> -> 0
    _ -> 0
  }
}

fn observe_result(outcome: Result(value, error)) -> Bool {
  result.is_ok(outcome) || result.is_error(outcome)
}
