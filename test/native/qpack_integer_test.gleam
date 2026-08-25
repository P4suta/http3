import http3/internal/qpack/integer

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matches_prefixed_integer_examples_and_preserves_rest_test() -> Nil {
  assert integer.encode(10, 5, 0) == Ok(<<10>>)
  assert integer.encode(1337, 5, 0) == Ok(<<31, 154, 10>>)
  assert integer.encode(42, 8, 0) == Ok(<<42>>)
  assert integer.encode(10, 5, 0x40) == Ok(<<0x4a>>)
  assert integer.decode(<<31, 154, 10, 9>>, 5)
    == Ok(integer.Decoded(1337, <<9>>))
  assert integer.decode(<<0x4a>>, 5) == Ok(integer.Decoded(10, <<>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_prefix_truncation_and_overlong_values_test() -> Nil {
  assert integer.encode(1, 0, 0) == Error(integer.InvalidPrefix)
  assert integer.encode(1, 5, 1) == Error(integer.InvalidHighBits)
  assert integer.decode(<<31>>, 5) == Error(integer.Truncated)
  assert integer.decode(
      <<
        31,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0x80,
        0,
      >>,
      5,
    )
    == Error(integer.IntegerTooLong)
}
