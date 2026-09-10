import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/frame
import http/internal/http2/header_block

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn headers_and_continuation_fragments_are_joined_on_one_stream_test() -> Nil {
  let assert Ok(state) = header_block.new(16)
  let first = frame.Header(2, frame.Headers, 0, 1)
  let assert Ok(header_block.Waiting(state)) =
    header_block.accept(state, first, <<"ab":utf8>>)
  let last = frame.Header(2, frame.Continuation, 0x4, 1)
  let assert Ok(header_block.Complete(state, completed)) =
    header_block.accept(state, last, <<"cd":utf8>>)

  assert completed
    == header_block.Block(
      stream_id: 1,
      fragment: <<"abcd":utf8>>,
      end_stream: False,
      priority: None,
    )
  assert header_block.is_idle(state)
}

pub fn padded_priority_headers_are_parsed_before_hpack_test() -> Nil {
  let assert Ok(state) = header_block.new(32)
  let payload = <<2, 1:size(1), 3:size(31), 15, "abc":utf8, 0, 0>>
  let header = frame.Header(11, frame.Headers, 0x2d, 5)
  let assert Ok(header_block.Complete(_, completed)) =
    header_block.accept(state, header, payload)

  assert completed
    == header_block.Block(
      stream_id: 5,
      fragment: <<"abc":utf8>>,
      end_stream: True,
      priority: Some(header_block.Priority(
        exclusive: True,
        dependency: 3,
        weight: 16,
      )),
    )
}

pub fn continuation_interleaving_and_wrong_stream_are_rejected_test() -> Nil {
  let assert Ok(state) = header_block.new(16)
  let assert Ok(header_block.Waiting(state)) =
    header_block.accept(state, frame.Header(1, frame.Headers, 0, 1), <<
      "a":utf8,
    >>)
  assert header_block.accept(state, frame.Header(0, frame.Settings, 0, 0), <<>>)
    == Error(header_block.ExpectedContinuation(stream_id: 1))
  assert header_block.accept(
      state,
      frame.Header(1, frame.Continuation, 0x4, 3),
      <<"b":utf8>>,
    )
    == Error(header_block.WrongContinuationStream(expected: 1, received: 3))
}

pub fn invalid_padding_dependency_and_resource_bounds_are_typed_test() -> Nil {
  assert header_block.new(0) == Error(header_block.InvalidLimit)
  let assert Ok(state) = header_block.new(2)
  assert header_block.accept(
      state,
      frame.Header(0, frame.Continuation, 0x4, 1),
      <<>>,
    )
    == Error(header_block.UnexpectedContinuation)
  assert header_block.accept(state, frame.Header(2, frame.Headers, 0x0c, 1), <<
      5,
      "x":utf8,
    >>)
    == Error(header_block.InvalidPadding)
  assert header_block.accept(state, frame.Header(5, frame.Headers, 0x24, 1), <<
      0:size(1),
      1:size(31),
      0,
    >>)
    == Error(header_block.SelfDependency)
  assert header_block.accept(state, frame.Header(3, frame.Headers, 0x4, 1), <<
      "abc":utf8,
    >>)
    == Error(header_block.BlockTooLarge(maximum: 2))
  assert header_block.accept(state, frame.Header(0, frame.Headers, 0x4, 1), <<
      1:size(1),
    >>)
    == Error(header_block.NonByteAligned)
}
