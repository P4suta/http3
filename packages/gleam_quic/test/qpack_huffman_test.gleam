import gleam_quic/internal/qpack/huffman

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn matches_rfc_huffman_vectors_test() -> Nil {
  assert huffman.encode(<<"www.example.com">>)
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
  assert huffman.encode(<<"no-cache">>)
    == Ok(<<0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf>>)
  assert huffman.decode(<<0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f>>, 32)
    == Ok(<<"custom-key">>)
  assert huffman.decode(
      <<0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf>>,
      32,
    )
    == Ok(<<"custom-value">>)
  assert huffman.encoded_size(<<"www.example.com">>) == Ok(12)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_eos_padding_and_decompression_expansion_test() -> Nil {
  assert huffman.decode(<<0xff, 0xff, 0xff, 0xff>>, 32)
    == Error(huffman.EosSymbol)
  assert huffman.decode(<<0>>, 32) == Error(huffman.InvalidPadding)
  let assert Ok(encoded) = huffman.encode(<<"aaaa">>)
  assert huffman.decode(encoded, 3) == Error(huffman.OutputLimitExceeded(3))
}
