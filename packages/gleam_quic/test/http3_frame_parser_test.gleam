import gleam_quic/internal/http3/frame
import gleam_quic/internal/http3/frame_parser

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn parses_fragmented_and_coalesced_frames_incrementally_test() -> Nil {
  let limits = frame.Limits(16, 16, 4)
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
  let limits = frame.Limits(4, 4, 2)
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
