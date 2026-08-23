//// QUIC packet number reconstruction from RFC 9000 appendix A.3.

import gleam/int

const maximum = 4_611_686_018_427_387_903

/// A packet number reconstruction failure.
pub type Error {
  InvalidWidth
  OutOfRange
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
