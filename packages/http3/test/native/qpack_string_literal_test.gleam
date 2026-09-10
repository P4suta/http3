import http3/internal/qpack/string_literal

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_raw_huffman_and_embedded_prefixes_test() -> Nil {
  assert string_literal.encode(<<"a">>, False) == Ok(<<1, "a">>)
  let assert Ok(encoded) = string_literal.encode(<<"www.example.com">>, True)
  let assert <<first, _:bits>> = encoded
  assert first >= 0x80
  assert string_literal.decode(encoded, 64, 64)
    == Ok(string_literal.Decoded(<<"www.example.com">>, <<>>, True))

  let assert Ok(embedded) =
    string_literal.encode_prefixed(<<"custom-key">>, 3, 0x08, 0x20, True)
  let assert Ok(string_literal.Decoded(<<"custom-key">>, <<>>, _)) =
    string_literal.decode_prefixed(embedded, 3, 0x08, 64, 64)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_encoded_and_decoded_limits_test() -> Nil {
  assert string_literal.decode(<<3, "abc">>, 2, 8)
    == Error(string_literal.EncodedLengthLimitExceeded(2))
  assert string_literal.decode(<<3, "abc">>, 8, 2)
    == Error(string_literal.DecodedLengthLimitExceeded(2))
  assert string_literal.decode(<<3, "ab">>, 8, 8)
    == Error(string_literal.Truncated)
}
