import gleam/list
import gleeunit
import http/internal/http2/frame
import http/internal/http2/header_writer
import http/internal/http2/hpack/decoder

pub fn main() -> Nil {
  gleeunit.main()
}

fn header(name: String, value: String, never_index: Bool) -> decoder.Header {
  decoder.Header(<<name:utf8>>, <<value:utf8>>, never_index)
}

fn writer() -> header_writer.State {
  let assert Ok(state) =
    header_writer.new(
      maximum_table_capacity: 4096,
      maximum_header_list_bytes: 4096,
      prefer_huffman: False,
    )
  state
}

pub fn field_block_is_split_into_headers_and_continuations_test() -> Nil {
  let headers = [
    header(":method", "GET", False),
    header(":scheme", "https", False),
    header(":path", "/", False),
    header(":authority", "example.com", False),
  ]
  let assert Ok(header_writer.Encoded(_, frames)) =
    header_writer.encode(
      writer(),
      stream_id: 1,
      headers: headers,
      end_stream: True,
      maximum_frame_bytes: 5,
    )
  assert list.length(frames) == 4
  let assert [first, second, third, fourth] = frames
  assert first == <<0, 0, 5, 1, 1, 0, 0, 0, 1, 0x82, 0x87, 0x84, 0x41, 11>>
  assert second == <<0, 0, 5, 9, 0, 0, 0, 0, 1, "examp":utf8>>
  assert third == <<0, 0, 5, 9, 0, 0, 0, 0, 1, "le.co":utf8>>
  assert fourth == <<0, 0, 1, 9, 4, 0, 0, 0, 1, "m":utf8>>
}

pub fn a_single_fragment_sets_end_headers_and_preserves_end_stream_test() -> Nil {
  let assert Ok(header_writer.Encoded(_, [encoded])) =
    header_writer.encode(
      writer(),
      stream_id: 3,
      headers: [header(":status", "204", False)],
      end_stream: True,
      maximum_frame_bytes: 16_384,
    )
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(header, <<0x89>>, <<>>)) =
    frame.feed(decoder, encoded)
  assert header == frame.Header(1, frame.Headers, 0x5, 3)
}

pub fn an_empty_field_block_still_emits_one_headers_frame_test() -> Nil {
  let assert Ok(header_writer.Encoded(_, [encoded])) =
    header_writer.encode(
      writer(),
      stream_id: 1,
      headers: [],
      end_stream: False,
      maximum_frame_bytes: 16_384,
    )
  assert encoded == <<0, 0, 0, 1, 4, 0, 0, 0, 1>>
}

pub fn invalid_writer_configuration_and_frame_limits_are_typed_test() -> Nil {
  assert header_writer.new(
      maximum_table_capacity: -1,
      maximum_header_list_bytes: 1,
      prefer_huffman: False,
    )
    == Error(header_writer.InvalidConfiguration)
  assert header_writer.encode(
      writer(),
      stream_id: 1,
      headers: [],
      end_stream: False,
      maximum_frame_bytes: 0,
    )
    == Error(header_writer.InvalidFrameLimit)
}
