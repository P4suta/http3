//// Finite per-stream HTTP/2 message body length accounting.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result

const maximum_stream_id = 0x7fff_ffff

type Progress {
  Progress(expected: Option(Int), received: Int)
}

/// Updated accounting state and remaining exact bytes, or -1 when unknown.
pub type Updated {
  Updated(state: State, remaining: Int)
}

/// Configuration, stream, admission, or declared-length failure.
pub type Error {
  InvalidLimit
  InvalidStreamIdentifier
  InvalidLength
  AlreadyTracked(stream_id: Int)
  UnknownStream(stream_id: Int)
  TooManyTracked(maximum: Int)
  BodyTooLong(expected: Int, received: Int)
  LengthMismatch(expected: Int, received: Int)
}

/// Opaque bounded message accounting state.
pub opaque type State {
  State(maximum_tracked: Int, messages: Dict(Int, Progress))
}

/// Construct an empty tracker with finite stream admission.
pub fn new(maximum_tracked: Int) -> Result(State, Error) {
  case maximum_tracked > 0 {
    True -> Ok(State(maximum_tracked, dict.new()))
    False -> Error(InvalidLimit)
  }
}

/// Begin one initial request or final-response field section.
pub fn start(
  state: State,
  stream_id stream_id: Int,
  expected expected: Option(Int),
  end_stream end_stream: Bool,
) -> Result(State, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  use _ <- result.try(validate_expected(expected))
  case dict.has_key(state.messages, stream_id) {
    True -> Error(AlreadyTracked(stream_id: stream_id))
    False -> start_new(state, stream_id, expected, end_stream)
  }
}

/// Account flow-decoded DATA octets before committing connection windows.
pub fn receive_data(
  state: State,
  stream_id stream_id: Int,
  octets octets: Int,
  end_stream end_stream: Bool,
) -> Result(Updated, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  case octets >= 0, dict.get(state.messages, stream_id) {
    False, _ -> Error(InvalidLength)
    True, Error(Nil) -> Error(UnknownStream(stream_id: stream_id))
    True, Ok(progress) ->
      advance(state, stream_id, progress, octets, end_stream)
  }
}

/// Finish a message with a trailer field section.
pub fn receive_trailers(
  state: State,
  stream_id stream_id: Int,
) -> Result(State, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  use progress <- result.try(lookup(state, stream_id))
  use _ <- result.try(require_complete(progress))
  Ok(State(..state, messages: dict.delete(state.messages, stream_id)))
}

/// Release accounting after RST_STREAM. Repeated resets are harmless.
pub fn reset(state: State, stream_id stream_id: Int) -> State {
  State(..state, messages: dict.delete(state.messages, stream_id))
}

/// Number of live message records retained.
pub fn tracked(state: State) -> Int {
  dict.size(state.messages)
}

fn start_new(
  state: State,
  stream_id: Int,
  expected: Option(Int),
  end_stream: Bool,
) -> Result(State, Error) {
  let progress = Progress(expected, 0)
  case end_stream {
    True -> {
      use _ <- result.try(require_complete(progress))
      Ok(state)
    }
    False ->
      case dict.size(state.messages) < state.maximum_tracked {
        True ->
          Ok(
            State(
              ..state,
              messages: dict.insert(state.messages, stream_id, progress),
            ),
          )
        False -> Error(TooManyTracked(maximum: state.maximum_tracked))
      }
  }
}

fn advance(
  state: State,
  stream_id: Int,
  progress: Progress,
  octets: Int,
  end_stream: Bool,
) -> Result(Updated, Error) {
  let Progress(expected, received) = progress
  let received = received + octets
  use _ <- result.try(require_not_overrun(expected, received))
  let progress = Progress(expected, received)
  case end_stream {
    True -> {
      use _ <- result.try(require_complete(progress))
      Ok(Updated(
        State(..state, messages: dict.delete(state.messages, stream_id)),
        remaining(expected, received),
      ))
    }
    False ->
      Ok(Updated(
        State(
          ..state,
          messages: dict.insert(state.messages, stream_id, progress),
        ),
        remaining(expected, received),
      ))
  }
}

fn lookup(state: State, stream_id: Int) -> Result(Progress, Error) {
  case dict.get(state.messages, stream_id) {
    Ok(progress) -> Ok(progress)
    Error(Nil) -> Error(UnknownStream(stream_id: stream_id))
  }
}

fn require_not_overrun(
  expected: Option(Int),
  received: Int,
) -> Result(Nil, Error) {
  case expected {
    Some(expected) if received > expected ->
      Error(BodyTooLong(expected: expected, received: received))
    _ -> Ok(Nil)
  }
}

fn require_complete(progress: Progress) -> Result(Nil, Error) {
  let Progress(expected, received) = progress
  case expected {
    Some(expected) if received != expected ->
      Error(LengthMismatch(expected: expected, received: received))
    _ -> Ok(Nil)
  }
}

fn remaining(expected: Option(Int), received: Int) -> Int {
  case expected {
    None -> -1
    Some(expected) -> expected - received
  }
}

fn validate_stream_id(stream_id: Int) -> Result(Nil, Error) {
  case stream_id > 0 && stream_id <= maximum_stream_id {
    True -> Ok(Nil)
    False -> Error(InvalidStreamIdentifier)
  }
}

fn validate_expected(expected: Option(Int)) -> Result(Nil, Error) {
  case expected {
    Some(value) if value < 0 -> Error(InvalidLength)
    _ -> Ok(Nil)
  }
}
