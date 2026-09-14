import gleam/bit_array
import gleam/string
import gleeunit
import http/internal/http2/hpack/huffman
import http/internal/http2/hpack/integer
import http/internal/http2/hpack/string_literal

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn uncompressed_literal_round_trips_and_preserves_following_bytes_test() -> Nil {
  let assert Ok(encoded) = string_literal.encode(<<"custom-key":utf8>>, False)
  assert encoded == <<10, "custom-key":utf8>>
  assert string_literal.decode(<<encoded:bits, 9>>, 64)
    == Ok(string_literal.Decoded(
      value: <<"custom-key":utf8>>,
      rest: <<9>>,
      huffman: False,
    ))
}

pub fn huffman_flag_and_continued_length_are_losslessly_preserved_test() -> Nil {
  let encoded_value =
    string.repeat("x", times: 127)
    |> bit_array.from_string
  let assert Ok(encoded) = string_literal.encode(encoded_value, True)
  assert encoded == <<0xff, 0, encoded_value:bits>>
  assert string_literal.decode(encoded, 127)
    == Ok(string_literal.Decoded(encoded_value, <<>>, True))
}

pub fn encoded_length_is_bounded_before_payload_extraction_test() -> Nil {
  assert string_literal.decode(<<3, "abc":utf8>>, 2)
    == Error(string_literal.EncodedLengthLimitExceeded(maximum: 2))
  assert string_literal.decode(<<3, "ab":utf8>>, 8)
    == Error(string_literal.Truncated)
  assert string_literal.decode(<<1:size(1)>>, 8)
    == Error(string_literal.NonByteAligned)
  assert string_literal.decode(<<>>, 8) == Error(string_literal.Truncated)
}

pub fn invalid_limits_and_integer_failures_are_typed_test() -> Nil {
  assert string_literal.decode(<<0>>, -1) == Error(string_literal.InvalidLimit)
  assert string_literal.decode(<<0>>, 0x1_0000_0000)
    == Error(string_literal.InvalidLimit)
  assert string_literal.decode(<<0x7f>>, 1024)
    == Error(string_literal.IntegerFailure(integer.Truncated))
}

pub fn selected_huffman_encoding_is_strictly_decoded_test() -> Nil {
  let assert Ok(encoded) =
    string_literal.encode_value(<<"www.example.com":utf8>>, True)
  assert encoded
    == <<
      0x8c,
      0xf1,
      0xe3,
      0xc2,
      0xe5,
      0xf2,
      0x3a,
      0x6b,
      0xa0,
      0xab,
      0x90,
      0xf4,
      0xff,
    >>
  assert string_literal.decode_value(encoded, 64, 64)
    == Ok(string_literal.Decoded(
      value: <<"www.example.com":utf8>>,
      rest: <<>>,
      huffman: True,
    ))
}

pub fn huffman_is_not_selected_when_it_would_expand_the_value_test() -> Nil {
  let assert Ok(encoded) = string_literal.encode_value(<<255>>, True)
  assert encoded == <<1, 255>>
  assert string_literal.decode_value(encoded, 1, 1)
    == Ok(string_literal.Decoded(<<255>>, <<>>, False))
}

pub fn decoded_size_and_malformed_huffman_are_typed_test() -> Nil {
  let assert Ok(encoded) = string_literal.encode_value(<<"aaaa":utf8>>, True)
  assert string_literal.decode_value(encoded, 8, 3)
    == Error(
      string_literal.HuffmanFailure(huffman.OutputLimitExceeded(maximum: 3)),
    )
  assert string_literal.decode_value(<<0x81, 0>>, 8, 8)
    == Error(string_literal.HuffmanFailure(huffman.InvalidPadding))
  assert string_literal.decode_value(<<3, "abc":utf8>>, 8, 2)
    == Error(string_literal.DecodedLengthLimitExceeded(maximum: 2))
}
