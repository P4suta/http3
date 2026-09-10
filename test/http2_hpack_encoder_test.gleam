import gleeunit
import http/internal/http2/hpack/decoder
import http/internal/http2/hpack/encoder

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn consecutive_rfc_requests_share_encoder_state_test() -> Nil {
  let assert Ok(state) = encoder.new(4096, 8192, False)
  let first_headers = [
    header(":method", "GET", False),
    header(":scheme", "http", False),
    header(":path", "/", False),
    header(":authority", "www.example.com", False),
  ]
  let assert Ok(encoder.Encoded(state, first)) =
    encoder.encode(state, first_headers)
  assert first == <<0x82, 0x86, 0x84, 0x41, 0x0f, "www.example.com":utf8>>

  let second_headers = [
    header(":method", "GET", False),
    header(":scheme", "http", False),
    header(":path", "/", False),
    header(":authority", "www.example.com", False),
    header("cache-control", "no-cache", False),
  ]
  let assert Ok(encoder.Encoded(state, second)) =
    encoder.encode(state, second_headers)
  assert second == <<0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, "no-cache":utf8>>
  assert encoder.dynamic_table_size(state) == 110
}

pub fn huffman_preference_matches_the_rfc_request_vector_test() -> Nil {
  let assert Ok(state) = encoder.new(4096, 8192, True)
  let headers = [
    header(":method", "GET", False),
    header(":scheme", "http", False),
    header(":path", "/", False),
    header(":authority", "www.example.com", False),
  ]
  let assert Ok(encoder.Encoded(_, block)) = encoder.encode(state, headers)
  assert block
    == <<
      0x82,
      0x86,
      0x84,
      0x41,
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
}

pub fn never_index_is_preserved_and_does_not_modify_the_table_test() -> Nil {
  let assert Ok(encoder_state) = encoder.new(128, 1024, False)
  let assert Ok(encoder.Encoded(encoder_state, block)) =
    encoder.encode(encoder_state, [header("authorization", "secret", True)])
  assert block == <<0x1f, 0x08, 0x06, "secret":utf8>>
  assert encoder.dynamic_table_size(encoder_state) == 0

  let assert Ok(decoder_state) = decoder.new(128, 1024)
  let assert Ok(decoder.Decoded(_, headers)) =
    decoder.decode(decoder_state, block)
  assert headers == [header("authorization", "secret", True)]
}

pub fn pending_capacity_updates_emit_minimum_then_final_before_fields_test() -> Nil {
  let assert Ok(state) = encoder.new(128, 1024, False)
  let assert Ok(state) = encoder.set_capacity(state, 32)
  let assert Ok(state) = encoder.set_capacity(state, 64)
  let assert Ok(encoder.Encoded(_, block)) =
    encoder.encode(state, [header(":method", "GET", False)])

  assert block == <<0x3f, 0x01, 0x3f, 0x21, 0x82>>
}

pub fn capacity_header_limit_and_name_validation_are_typed_test() -> Nil {
  let assert Ok(state) = encoder.new(64, 41, False)
  assert encoder.set_capacity(state, 65)
    == Error(encoder.TableSizeExceeded(maximum: 64))
  assert encoder.encode(state, [header(":method", "GET", False)])
    == Error(encoder.HeaderListTooLarge(maximum: 41))
  assert encoder.encode(state, [decoder.Header(<<>>, <<>>, False)])
    == Error(encoder.InvalidHeaderName)
}

fn header(name: String, value: String, never_index: Bool) -> decoder.Header {
  decoder.Header(<<name:utf8>>, <<value:utf8>>, never_index)
}
