import gleeunit
import http/internal/http2/hpack/huffman

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn rfc_appendix_vectors_encode_decode_and_size_test() -> Nil {
  assert huffman.encode(<<"www.example.com":utf8>>)
    == Ok(<<
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
    >>)
  assert huffman.decode(<<0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f>>, 32)
    == Ok(<<"custom-key":utf8>>)
  assert huffman.decode(
      <<0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf>>,
      32,
    )
    == Ok(<<"custom-value":utf8>>)
  assert huffman.encoded_size(<<"www.example.com":utf8>>) == Ok(12)
}

pub fn eos_invalid_padding_and_output_expansion_are_rejected_test() -> Nil {
  assert huffman.decode(<<0xff, 0xff, 0xff, 0xff>>, 32)
    == Error(huffman.EosSymbol)
  assert huffman.decode(<<0>>, 32) == Error(huffman.InvalidPadding)
  let assert Ok(encoded) = huffman.encode(<<"aaaa":utf8>>)
  assert huffman.decode(encoded, 3)
    == Error(huffman.OutputLimitExceeded(maximum: 3))
  assert huffman.decode(encoded, -1)
    == Error(huffman.OutputLimitExceeded(maximum: -1))
}

pub fn byte_alignment_and_empty_input_are_handled_test() -> Nil {
  assert huffman.encode(<<1:size(1)>>) == Error(huffman.NonByteAligned)
  assert huffman.decode(<<1:size(1)>>, 8) == Error(huffman.NonByteAligned)
  assert huffman.encode(<<>>) == Ok(<<>>)
  assert huffman.decode(<<>>, 0) == Ok(<<>>)
}
