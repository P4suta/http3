//// Bounded HEADERS/CONTINUATION block assembly.

import gleam/bit_array
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/frame

const maximum_wire_block_bytes = 0xffff_ffff

/// Optional priority information carried by the initial HEADERS frame.
pub type Priority {
  Priority(exclusive: Bool, dependency: Int, weight: Int)
}

/// One complete compressed field block and its stream metadata.
pub type Block {
  Block(
    stream_id: Int,
    fragment: BitArray,
    end_stream: Bool,
    priority: Option(Priority),
  )
}

type Pending {
  Pending(
    stream_id: Int,
    fragment: BitArray,
    end_stream: Bool,
    priority: Option(Priority),
  )
}

/// Connection-scoped assembler state.
pub opaque type State {
  State(maximum_block_bytes: Int, pending: Option(Pending))
}

/// Assembly progress after one frame.
pub type Outcome {
  Waiting(State)
  Complete(State, Block)
}

/// Envelope, sequencing, priority, or finite-resource failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  InvalidPayloadLength
  UnexpectedFrame
  UnexpectedContinuation
  ExpectedContinuation(stream_id: Int)
  WrongContinuationStream(expected: Int, received: Int)
  InvalidPadding
  InvalidPriority
  SelfDependency
  BlockTooLarge(maximum: Int)
}

/// Construct an idle assembler with a finite compressed-block limit.
pub fn new(maximum_block_bytes: Int) -> Result(State, Error) {
  case
    maximum_block_bytes > 0 && maximum_block_bytes <= maximum_wire_block_bytes
  {
    True -> Ok(State(maximum_block_bytes, None))
    False -> Error(InvalidLimit)
  }
}

/// Accept one decoded frame envelope and its payload.
pub fn accept(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Outcome, Error) {
  use _ <- result.try(validate_payload(header, payload))
  case state.pending {
    Some(pending) -> accept_continuation(state, pending, header, payload)
    None -> accept_initial(state, header, payload)
  }
}

/// Whether no continuation sequence is in progress.
pub fn is_idle(state: State) -> Bool {
  state.pending == None
}

fn accept_initial(
  state: State,
  header: frame.Header,
  payload: BitArray,
) -> Result(Outcome, Error) {
  let frame.Header(_, frame_type, flags, stream_id) = header
  case frame_type {
    frame.Continuation -> Error(UnexpectedContinuation)
    frame.Headers -> {
      use #(fragment, priority) <- result.try(parse_headers_payload(
        payload,
        flags,
        stream_id,
      ))
      use fragment <- result.try(require_capacity(state, <<>>, fragment))
      let end_stream = int.bitwise_and(flags, 0x1) != 0
      case int.bitwise_and(flags, 0x4) != 0 {
        True ->
          Ok(Complete(
            State(..state, pending: None),
            Block(stream_id, fragment, end_stream, priority),
          ))
        False ->
          Ok(Waiting(
            State(
              ..state,
              pending: Some(Pending(stream_id, fragment, end_stream, priority)),
            ),
          ))
      }
    }
    _ -> Error(UnexpectedFrame)
  }
}

fn accept_continuation(
  state: State,
  pending: Pending,
  header: frame.Header,
  payload: BitArray,
) -> Result(Outcome, Error) {
  let Pending(stream_id, fragment, end_stream, priority) = pending
  let frame.Header(_, frame_type, flags, received_stream) = header
  case frame_type {
    frame.Continuation ->
      case received_stream == stream_id {
        False -> Error(WrongContinuationStream(stream_id, received_stream))
        True -> {
          use fragment <- result.try(require_capacity(state, fragment, payload))
          case int.bitwise_and(flags, 0x4) != 0 {
            True ->
              Ok(Complete(
                State(..state, pending: None),
                Block(stream_id, fragment, end_stream, priority),
              ))
            False ->
              Ok(Waiting(
                State(
                  ..state,
                  pending: Some(Pending(
                    stream_id,
                    fragment,
                    end_stream,
                    priority,
                  )),
                ),
              ))
          }
        }
      }
    _ -> Error(ExpectedContinuation(stream_id))
  }
}

fn parse_headers_payload(
  payload: BitArray,
  flags: Int,
  stream_id: Int,
) -> Result(#(BitArray, Option(Priority)), Error) {
  use #(padding, after_padding_length) <- result.try(take_padding_length(
    payload,
    int.bitwise_and(flags, 0x8) != 0,
  ))
  use #(priority, fragment_and_padding) <- result.try(take_priority(
    after_padding_length,
    int.bitwise_and(flags, 0x20) != 0,
    stream_id,
  ))
  use fragment <- result.try(remove_padding(fragment_and_padding, padding))
  Ok(#(fragment, priority))
}

fn take_padding_length(
  payload: BitArray,
  padded: Bool,
) -> Result(#(Int, BitArray), Error) {
  case padded, payload {
    False, _ -> Ok(#(0, payload))
    True, <<padding, rest:bytes>> -> Ok(#(padding, rest))
    True, _ -> Error(InvalidPadding)
  }
}

fn take_priority(
  payload: BitArray,
  prioritized: Bool,
  stream_id: Int,
) -> Result(#(Option(Priority), BitArray), Error) {
  case prioritized, payload {
    False, _ -> Ok(#(None, payload))
    True, <<exclusive:size(1), dependency:size(31), weight, rest:bytes>> ->
      case dependency == stream_id {
        True -> Error(SelfDependency)
        False ->
          Ok(#(Some(Priority(exclusive == 1, dependency, weight + 1)), rest))
      }
    True, _ -> Error(InvalidPriority)
  }
}

fn remove_padding(payload: BitArray, padding: Int) -> Result(BitArray, Error) {
  let payload_bytes = bit_array.byte_size(payload)
  case padding > payload_bytes {
    True -> Error(InvalidPadding)
    False -> {
      let fragment_bytes = payload_bytes - padding
      case payload {
        <<fragment:bytes-size(fragment_bytes), _:bytes-size(padding)>> ->
          Ok(fragment)
        _ -> Error(InvalidPadding)
      }
    }
  }
}

fn require_capacity(
  state: State,
  accumulated: BitArray,
  fragment: BitArray,
) -> Result(BitArray, Error) {
  case
    bit_array.byte_size(fragment)
    > state.maximum_block_bytes - bit_array.byte_size(accumulated)
  {
    True -> Error(BlockTooLarge(state.maximum_block_bytes))
    False -> Ok(<<accumulated:bits, fragment:bits>>)
  }
}

fn validate_payload(
  header: frame.Header,
  payload: BitArray,
) -> Result(Nil, Error) {
  let frame.Header(length, _, _, _) = header
  case bit_array.bit_size(payload) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case bit_array.byte_size(payload) == length {
        True -> Ok(Nil)
        False -> Error(InvalidPayloadLength)
      }
  }
}
