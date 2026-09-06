import gleeunit
import http/internal/http2/hpack/decoder

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn consecutive_rfc_requests_share_the_dynamic_table_test() -> Nil {
  let assert Ok(state) = decoder.new(4096, 8192)
  let first = <<
    0x82,
    0x86,
    0x84,
    0x41,
    0x0f,
    "www.example.com":utf8,
  >>
  let assert Ok(decoder.Decoded(state, first_headers)) =
    decoder.decode(state, first)
  assert first_headers
    == [
      header(":method", "GET", False),
      header(":scheme", "http", False),
      header(":path", "/", False),
      header(":authority", "www.example.com", False),
    ]

  let second = <<
    0x82,
    0x86,
    0x84,
    0xbe,
    0x58,
    0x08,
    "no-cache":utf8,
  >>
  let assert Ok(decoder.Decoded(state, second_headers)) =
    decoder.decode(state, second)
  assert second_headers
    == [
      header(":method", "GET", False),
      header(":scheme", "http", False),
      header(":path", "/", False),
      header(":authority", "www.example.com", False),
      header("cache-control", "no-cache", False),
    ]
  assert decoder.dynamic_table_size(state) == 110
}

pub fn huffman_rfc_request_is_strictly_expanded_test() -> Nil {
  let assert Ok(state) = decoder.new(4096, 8192)
  let block = <<
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
  let assert Ok(decoder.Decoded(_, headers)) = decoder.decode(state, block)
  assert headers
    == [
      header(":method", "GET", False),
      header(":scheme", "http", False),
      header(":path", "/", False),
      header(":authority", "www.example.com", False),
    ]
}

pub fn literal_modes_preserve_never_index_and_only_index_when_requested_test() -> Nil {
  let assert Ok(state) = decoder.new(128, 1024)
  let block = <<
    0x10,
    0x06,
    "secret":utf8,
    0x05,
    "value":utf8,
    0x00,
    0x05,
    "plain":utf8,
    0x01,
    "x":utf8,
  >>
  let assert Ok(decoder.Decoded(state, headers)) = decoder.decode(state, block)
  assert headers
    == [
      header("secret", "value", True),
      header("plain", "x", False),
    ]
  assert decoder.dynamic_table_size(state) == 0
}

pub fn table_size_updates_are_bounded_and_only_allowed_at_the_start_test() -> Nil {
  let assert Ok(state) = decoder.new(128, 1024)
  let assert Ok(decoder.Decoded(state, [method])) =
    decoder.decode(state, <<0x3f, 0x21, 0x82>>)
  assert method == header(":method", "GET", False)
  assert decoder.dynamic_table_capacity(state) == 64

  let assert Error(late) = decoder.decode(state, <<0x82, 0x20>>)
  assert late == decoder.LateTableSizeUpdate
  let assert Error(large) = decoder.decode(state, <<0x3f, 0x62>>)
  assert large == decoder.TableSizeExceeded(maximum: 128)
}

pub fn invalid_indices_truncation_and_header_list_limits_are_typed_test() -> Nil {
  let assert Ok(state) = decoder.new(64, 64)
  assert decoder.decode(state, <<0x80>>) == Error(decoder.InvalidIndex(0))
  assert decoder.decode(state, <<0xbe>>) == Error(decoder.InvalidIndex(62))
  assert decoder.decode(state, <<0x40>>) == Error(decoder.Truncated)

  let assert Ok(tiny) = decoder.new(64, 33)
  assert decoder.decode(tiny, <<0x82>>)
    == Error(decoder.HeaderListTooLarge(maximum: 33))
}

pub fn malformed_or_empty_literal_names_are_rejected_transactionally_test() -> Nil {
  let assert Ok(state) = decoder.new(128, 1024)
  assert decoder.decode(state, <<0x40, 0, 0>>)
    == Error(decoder.InvalidHeaderName)
  assert decoder.dynamic_table_size(state) == 0
}

fn header(name: String, value: String, never_index: Bool) -> decoder.Header {
  decoder.Header(<<name:utf8>>, <<value:utf8>>, never_index)
}
