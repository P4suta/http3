//// QUIC packet number reconstruction from RFC 9000 appendix A.3.

import gleam/int
import gleam/option.{type Option, None, Some}

const maximum = 4_611_686_018_427_387_903

/// A packet number reconstruction failure.
pub type Error {
  InvalidWidth
  OutOfRange
  EncodingRangeTooLarge
}

/// Encode the shortest packet number that a peer can reconstruct safely.
pub fn encode(
  packet_number packet_number: Int,
  largest_acknowledged largest_acknowledged: Option(Int),
) -> Result(BitArray, Error) {
  case packet_number < 0 || packet_number > maximum {
    True -> Error(OutOfRange)
    False ->
      case largest_acknowledged {
        None -> encode_after_acknowledged(packet_number, -1)
        Some(largest) ->
          case largest < 0 || largest >= packet_number {
            True -> Error(OutOfRange)
            False -> encode_after_acknowledged(packet_number, largest)
          }
      }
  }
}

fn encode_after_acknowledged(
  packet_number: Int,
  largest_acknowledged: Int,
) -> Result(BitArray, Error) {
  let unacknowledged = packet_number - largest_acknowledged
  case unacknowledged {
    value if value <= 128 -> Ok(encode_low_bits(packet_number, 8))
    value if value <= 32_768 -> Ok(encode_low_bits(packet_number, 16))
    value if value <= 8_388_608 -> Ok(encode_low_bits(packet_number, 24))
    value if value <= 2_147_483_648 -> Ok(encode_low_bits(packet_number, 32))
    _ -> Error(EncodingRangeTooLarge)
  }
}

fn encode_low_bits(packet_number: Int, encoded_bits: Int) -> BitArray {
  let mask = int.bitwise_shift_left(1, encoded_bits) - 1
  let truncated = int.bitwise_and(packet_number, mask)
  case encoded_bits {
    8 -> <<truncated>>
    16 -> <<truncated:size(16)>>
    24 -> <<truncated:size(24)>>
    _ -> <<truncated:size(32)>>
  }
}

/// Reconstruct a full packet number from the protected truncated value.
pub fn reconstruct(
  truncated truncated: Int,
  encoded_bits encoded_bits: Int,
  expected expected: Int,
) -> Result(Int, Error) {
  case encoded_bits {
    8 | 16 | 24 | 32 ->
      reconstruct_with_valid_width(truncated:, encoded_bits:, expected:)
    _ -> Error(InvalidWidth)
  }
}

fn reconstruct_with_valid_width(
  truncated truncated: Int,
  encoded_bits encoded_bits: Int,
  expected expected: Int,
) -> Result(Int, Error) {
  let window = int.bitwise_shift_left(1, encoded_bits)
  let half_window = window / 2
  let mask = window - 1

  case truncated < 0 || truncated > mask || expected < 0 || expected > maximum {
    True -> Error(OutOfRange)
    False -> {
      let candidate =
        expected
        |> int.bitwise_and(int.bitwise_not(mask))
        |> int.bitwise_or(truncated)

      case
        candidate <= expected - half_window && candidate < maximum - window + 1,
        candidate > expected + half_window && candidate >= window
      {
        True, _ -> Ok(candidate + window)
        _, True -> Ok(candidate - window)
        _, _ -> Ok(candidate)
      }
    }
  }
}
