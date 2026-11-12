import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_truncated_payload_in_a_complete_frame_test() -> Nil {
  let limits = frame.Limits(4, 4, 2, 2)
  let assert Ok(empty) = frame_parser.new(limits, 20)
  let assert Ok(malformed) = frame_parser.push(empty, <<7, 1, 0x40>>)
  assert frame_parser.next(malformed)
    == Error(frame_parser.FrameFailure(frame.Truncated))

  let assert Ok(incomplete) = frame_parser.push(empty, <<7, 2, 0x40>>)
  assert frame_parser.next(incomplete) == Ok(frame_parser.NeedMore(incomplete))
  let assert Ok(complete) = frame_parser.push(incomplete, <<0>>)
  let assert Ok(frame_parser.FrameReady(_, decoded)) =
    frame_parser.next(complete)
  assert decoded == frame.GoAway(0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_fragmented_and_coalesced_frames_incrementally_test() -> Nil {
  let limits = frame.Limits(16, 16, 4, 4)
  let assert Ok(state) = frame_parser.new(limits, 32)
  let assert Ok(state) = frame_parser.push(state, <<0, 3, "a">>)
  assert frame_parser.next(state) == Ok(frame_parser.NeedMore(state))
  let assert Ok(state) = frame_parser.push(state, <<"bc", 1, 0>>)
  let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"abc">>))) =
    frame_parser.next(state)
  assert frame_parser.buffered_bytes(state) == 2
  let assert Ok(frame_parser.FrameReady(state, frame.Headers(<<>>))) =
    frame_parser.next(state)
  assert frame_parser.finish(state) == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_oversized_buffers_frames_and_truncated_fin_test() -> Nil {
  let limits = frame.Limits(4, 4, 2, 2)
  let assert Ok(state) = frame_parser.new(limits, 20)
  let assert Ok(state) = frame_parser.push(state, <<0, 5>>)
  assert frame_parser.next(state)
    == Error(frame_parser.FrameFailure(frame.PayloadLimitExceeded(4)))
  assert frame_parser.finish(state) == Error(frame_parser.TruncatedFrame)
  let assert Ok(empty) = frame_parser.new(limits, 20)
  assert frame_parser.push(empty, <<0:size(168)>>)
    == Error(frame_parser.BufferLimitExceeded(20))
  assert frame_parser.new(limits, 19)
    == Error(frame_parser.InvalidConfiguration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_data_preserves_every_fragmented_varint_boundary_test() -> Nil {
  // Both type and length use their legal non-minimal eight-byte encoding.
  let header = <<3:size(2), 0:size(62), 3:size(2), 7:size(62)>>
  list.each([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], fn(cut) {
    let assert <<prefix:bytes-size(cut), suffix:bits>> = header
    let assert Ok(state) =
      frame_parser.new_streaming(frame.Limits(4, 4, 2, 2), 32, 3)
    let assert Ok(state) = frame_parser.push(state, prefix)
    let assert Ok(frame_parser.NeedMore(state)) = frame_parser.next(state)
    assert frame_parser.completed_data_frame(state) == None
    let assert Ok(state) =
      frame_parser.push(state, <<suffix:bits, "abcdefg", 1, 0>>)
    let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"abc">>))) =
      frame_parser.next(state)
    assert frame_parser.completed_data_frame(state) == None
    let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"def">>))) =
      frame_parser.next(state)
    assert frame_parser.completed_data_frame(state) == None
    let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"g">>))) =
      frame_parser.next(state)
    assert frame_parser.completed_data_frame(state) == Some(7)
    assert frame_parser.buffered_bytes(state) == 2
    let assert Ok(frame_parser.FrameReady(state, frame.Headers(<<>>))) =
      frame_parser.next(state)
    assert frame_parser.completed_data_frame(state) == None
    assert frame_parser.finish(state) == Ok(Nil)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_huge_declared_length_retains_no_unreceived_payload_test() -> Nil {
  let assert Ok(length) = varint.encode(varint.maximum)
  let assert Ok(state) =
    frame_parser.new_streaming(frame.Limits(4, 4, 2, 2), 20, 3)
  let assert Ok(state) = frame_parser.push(state, <<0, length:bits, "a">>)
  let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"a">>))) =
    frame_parser.next(state)
  assert frame_parser.buffered_bytes(state) == 0
  assert frame_parser.completed_data_frame(state) == None
  assert frame_parser.finish(state) == Error(frame_parser.TruncatedFrame)
  let assert Ok(frame_parser.NeedMore(waiting)) = frame_parser.next(state)
  assert frame_parser.buffered_bytes(waiting) == 0
  assert frame_parser.push(waiting, <<1:size(1)>>)
    == Error(frame_parser.NonByteAligned)
  assert frame_parser.push(waiting, <<0:size(21)-unit(8)>>)
    == Error(frame_parser.BufferLimitExceeded(20))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_data_keeps_empty_frame_and_truncated_fin_distinct_test() -> Nil {
  let assert Ok(state) =
    frame_parser.new_streaming(frame.Limits(4, 4, 2, 2), 20, 3)
  let assert Ok(state) = frame_parser.push(state, <<0, 0, 0, 2, "a">>)
  let assert Ok(frame_parser.FrameReady(state, frame.Data(<<>>))) =
    frame_parser.next(state)
  assert frame_parser.completed_data_frame(state) == Some(0)
  let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"a">>))) =
    frame_parser.next(state)
  assert frame_parser.completed_data_frame(state) == None
  assert frame_parser.finish(state) == Error(frame_parser.TruncatedFrame)
  let assert Ok(state) = frame_parser.push(state, <<"b">>)
  let assert Ok(frame_parser.FrameReady(state, frame.Data(<<"b">>))) =
    frame_parser.next(state)
  assert frame_parser.completed_data_frame(state) == Some(2)
  assert frame_parser.finish(state) == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_data_preserves_header_control_and_unknown_frame_limits_test() -> Nil {
  list.each([1, 4, 0x21], fn(kind) {
    let assert Ok(state) =
      frame_parser.new_streaming(frame.Limits(4, 2, 2, 2), 20, 3)
    let assert Ok(state) = frame_parser.push(state, <<kind, 5>>)
    assert frame_parser.next(state)
      == Error(frame_parser.FrameFailure(frame.PayloadLimitExceeded(4)))
  })
  let assert Ok(state) =
    frame_parser.new_streaming(frame.Limits(4, 2, 2, 2), 20, 3)
  let assert Ok(state) = frame_parser.push(state, <<1, 3, "abc">>)
  assert frame_parser.next(state)
    == Error(frame_parser.FrameFailure(frame.FieldSectionLimitExceeded(2)))
  assert frame_parser.new_streaming(frame.Limits(4, 2, 2, 2), 20, 0)
    == Error(frame_parser.InvalidConfiguration)
  assert frame_parser.new_streaming(frame.Limits(4, 2, 2, 2), 20, 21)
    == Error(frame_parser.InvalidConfiguration)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_single_read_deliveries_respect_chunk_cap_test() -> Nil {
  let assert Ok(state) =
    frame_parser.new_streaming(frame.Limits(4, 4, 2, 2), 32, 3)
  let assert Ok(state) = frame_parser.push(state, <<0, 10, "abcdefghij">>)
  let #(state, chunks) = data_chunks(state, [])
  assert chunks == [<<"abc">>, <<"def">>, <<"ghi">>, <<"j">>]
  assert bit_array.byte_size(bit_array.concat(chunks)) == 10
  assert frame_parser.buffered_bytes(state) == 0
  assert frame_parser.finish(state) == Ok(Nil)
}

fn data_chunks(
  state: frame_parser.State,
  chunks: List(BitArray),
) -> #(frame_parser.State, List(BitArray)) {
  case frame_parser.next(state) {
    Ok(frame_parser.FrameReady(state, frame.Data(bytes))) ->
      data_chunks(state, [bytes, ..chunks])
    result -> {
      let assert Ok(frame_parser.NeedMore(state)) = result
      #(state, list.reverse(chunks))
    }
  }
}

import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
