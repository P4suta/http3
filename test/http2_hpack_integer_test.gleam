import gleeunit
import http/internal/http2/hpack/integer

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn rfc_examples_round_trip_and_leave_following_bytes_test() -> Nil {
  let limits = integer.limits(0xffff_ffff, 6)
  let assert Ok(limits) = limits

  assert integer.encode(10, 5, 0, limits) == Ok(<<10>>)
  assert integer.encode(1337, 5, 0, limits) == Ok(<<31, 154, 10>>)
  assert integer.decode(<<31, 154, 10, 9>>, 5, limits)
    == Ok(integer.Decoded(1337, rest: <<9>>))
}

pub fn representation_bits_are_preserved_outside_the_prefix_test() -> Nil {
  let assert Ok(limits) = integer.limits(1024, 4)

  assert integer.encode(10, 5, 0x40, limits) == Ok(<<0x4a>>)
  assert integer.decode(<<0x4a>>, 5, limits)
    == Ok(integer.Decoded(10, rest: <<>>))
}

pub fn limits_are_finite_and_enforced_on_encode_and_decode_test() -> Nil {
  assert integer.limits(-1, 2) == Error(integer.InvalidLimits)
  assert integer.limits(10, 0) == Error(integer.InvalidLimits)
  assert integer.limits(0x1_0000_0000, 6) == Error(integer.InvalidLimits)
  assert integer.limits(10, 7) == Error(integer.InvalidLimits)

  let assert Ok(value_limit) = integer.limits(32, 3)
  assert integer.encode(33, 5, 0, value_limit)
    == Error(integer.ValueOutOfRange(maximum: 32))
  assert integer.decode(<<31, 2>>, 5, value_limit)
    == Error(integer.ValueOutOfRange(maximum: 32))

  let assert Ok(octet_limit) = integer.limits(0xffff_ffff, 2)
  assert integer.encode(1337, 5, 0, octet_limit)
    == Error(integer.IntegerTooLong(maximum_bytes: 2))
  assert integer.decode(<<31, 128, 0>>, 5, octet_limit)
    == Error(integer.IntegerTooLong(maximum_bytes: 2))
}

pub fn malformed_input_is_rejected_without_partial_success_test() -> Nil {
  let assert Ok(limits) = integer.limits(1024, 4)

  assert integer.decode(<<31>>, 5, limits) == Error(integer.Truncated)
  assert integer.decode(<<1:size(1)>>, 5, limits)
    == Error(integer.NonByteAligned)
  assert integer.decode(<<0>>, 0, limits) == Error(integer.InvalidPrefix)
  assert integer.encode(1, 9, 0, limits) == Error(integer.InvalidPrefix)
  assert integer.encode(1, 5, 1, limits) == Error(integer.InvalidHighBits)
}
