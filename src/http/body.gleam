//// Opaque, bounded, pull-based HTTP bodies.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import http/error

/// HTTP trailers represented with the same lossless name/value shape used by
/// `gleam_http` requests and responses.
pub type Headers =
  List(#(String, String))

/// The result of invoking an advanced pull source.
pub type PullEvent {
  PullData(bytes: BitArray, next: Pull)
  PullEnd(trailers: Headers)
}

/// An opaque pull source. Each successful data event supplies the source for
/// the following pull, keeping cursor state explicit and free of globals.
pub opaque type Pull {
  PullSource(next: fn(Int) -> Result(PullEvent, error.Error))
}

/// One bounded read from a body.
pub type Read {
  Data(bytes: BitArray, next: Body)
  Done(completed: Body)
}

type Source {
  EmptySource
  BytesSource(bytes: BitArray, offset: Int, completion_trailers: Headers)
  FileSource(path: String, offset: Int)
  AdvancedSource(source: Pull)
  InvalidSource
}

type CancelHandle

/// A body cursor. Its source, file path, callbacks, cancellation token, and
/// replay factory are private.
pub opaque type Body {
  BodyState(
    source: Source,
    total_length: Option(Int),
    consumed: Int,
    replay_factory: Option(fn() -> Result(Body, error.Error)),
    cancel_handle: CancelHandle,
    on_cancel: fn() -> Nil,
    trailers: Option(Headers),
  )
}

@external(erlang, "http_body_ffi", "new_cancel_handle")
fn new_cancel_handle() -> CancelHandle

@external(erlang, "http_body_ffi", "mark_cancelled")
fn mark_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_body_ffi", "is_cancelled")
fn is_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_body_ffi", "file_size")
fn file_size(path: String) -> Result(Int, Nil)

@external(erlang, "http_body_ffi", "read_file_chunk")
fn read_file_chunk(
  path: String,
  offset: Int,
  maximum: Int,
) -> Result(BitArray, Nil)

/// Construct an empty replayable body.
pub fn empty() -> Body {
  BodyState(
    source: EmptySource,
    total_length: Some(0),
    consumed: 0,
    replay_factory: Some(fn() { Ok(empty()) }),
    cancel_handle: new_cancel_handle(),
    on_cancel: fn() { Nil },
    trailers: Some([]),
  )
}

/// Construct a replayable in-memory body.
///
/// A non-byte-aligned bit array is retained as an invalid source and produces
/// a typed `InvalidChunk` error when read; it never reaches a protocol writer.
pub fn from_bytes(bytes: BitArray) -> Body {
  from_bytes_with_trailers(bytes, [])
}

/// Construct a replayable in-memory body with completion trailers.
///
/// Trailers remain unavailable through `trailers` until the body is fully
/// consumed. A replay preserves both the bytes and the trailers.
pub fn from_bytes_with_trailers(bytes: BitArray, trailers: Headers) -> Body {
  case bit_array.bit_size(bytes) % 8 {
    0 -> bytes_body(bytes, trailers)
    _ ->
      BodyState(
        source: InvalidSource,
        total_length: None,
        consumed: 0,
        replay_factory: Some(fn() {
          Ok(from_bytes_with_trailers(bytes, trailers))
        }),
        cancel_handle: new_cancel_handle(),
        on_cancel: fn() { Nil },
        trailers: None,
      )
  }
}

/// Construct a replayable UTF-8 body.
pub fn from_text(text: String) -> Body {
  text |> bit_array.from_string |> from_bytes
}

/// Construct a replayable file body after checking that the file can be
/// opened and measuring its current size. File paths never appear in errors.
pub fn from_file(path: String) -> Result(Body, error.Error) {
  case file_size(path) {
    Error(_) -> Error(body_error(error.ReadFailed))
    Ok(size) -> Ok(file_body(path, size))
  }
}

/// Wrap an advanced pull callback.
pub fn pull(next: fn(Int) -> Result(PullEvent, error.Error)) -> Pull {
  PullSource(next)
}

/// Construct a pull-stream body.
///
/// `known_length` must be non-negative when present. Supplying `replay`
/// allows redirects, retries, and explicit replay to create a fresh source.
pub fn from_pull(
  source: Pull,
  known_length: Option(Int),
  replay: Option(fn() -> Pull),
  on_cancel: fn() -> Nil,
) -> Result(Body, error.Error) {
  case known_length {
    Some(length) ->
      case length < 0 {
        True -> Error(body_error(error.InvalidLimit))
        False -> Ok(pull_body(source, known_length, replay, on_cancel))
      }
    None -> Ok(pull_body(source, known_length, replay, on_cancel))
  }
}

/// Return the body's declared total byte length, when known.
pub fn known_length(body: Body) -> Option(Int) {
  body.total_length
}

/// Return whether a fresh body can be generated safely.
pub fn is_replayable(body: Body) -> Bool {
  case body.replay_factory {
    Some(_) -> True
    None -> False
  }
}

/// Generate a fresh body or return a typed policy-safe body error.
pub fn replay(body: Body) -> Result(Body, error.Error) {
  case body.replay_factory {
    Some(factory) -> factory()
    None -> Error(body_error(error.NotReplayable))
  }
}

/// Cancel this body and every cursor already derived from it.
///
/// The source cancellation callback is invoked at most once.
pub fn cancel(body: Body) -> Nil {
  case mark_cancelled(body.cancel_handle) {
    True -> body.on_cancel()
    False -> Nil
  }
}

/// Return trailers only after the body has completed.
pub fn trailers(body: Body) -> Option(Headers) {
  body.trailers
}

/// Pull at most `maximum_bytes` from a body.
pub fn read(body: Body, maximum_bytes: Int) -> Result(Read, error.Error) {
  case maximum_bytes <= 0, is_cancelled(body.cancel_handle) {
    True, _ -> Error(body_error(error.InvalidLimit))
    _, True -> Error(error.new(error.Cancelled))
    False, False -> read_source(body, maximum_bytes)
  }
}

/// Collect a body up to a finite byte limit and return its trailers.
pub fn read_all(
  body: Body,
  maximum_bytes: Int,
) -> Result(#(BitArray, Headers), error.Error) {
  case maximum_bytes < 0 {
    True -> Error(body_error(error.InvalidLimit))
    False ->
      case body.total_length {
        Some(length) if length > maximum_bytes ->
          Error(body_error(error.TooLarge(maximum_bytes)))
        _ -> read_all_loop(body, maximum_bytes, 0, [])
      }
  }
}

fn bytes_body(bytes: BitArray, completion_trailers: Headers) -> Body {
  let length = bit_array.byte_size(bytes)
  BodyState(
    source: BytesSource(bytes, 0, completion_trailers),
    total_length: Some(length),
    consumed: 0,
    replay_factory: Some(fn() {
      Ok(from_bytes_with_trailers(bytes, completion_trailers))
    }),
    cancel_handle: new_cancel_handle(),
    on_cancel: fn() { Nil },
    trailers: None,
  )
}

fn file_body(path: String, size: Int) -> Body {
  BodyState(
    source: FileSource(path, 0),
    total_length: Some(size),
    consumed: 0,
    replay_factory: Some(fn() { from_file(path) }),
    cancel_handle: new_cancel_handle(),
    on_cancel: fn() { Nil },
    trailers: None,
  )
}

fn pull_body(
  source: Pull,
  known_length: Option(Int),
  replay_source: Option(fn() -> Pull),
  on_cancel: fn() -> Nil,
) -> Body {
  let replay_factory = case replay_source {
    None -> None
    Some(factory) ->
      Some(fn() { from_pull(factory(), known_length, replay_source, on_cancel) })
  }
  BodyState(
    source: AdvancedSource(source),
    total_length: known_length,
    consumed: 0,
    replay_factory: replay_factory,
    cancel_handle: new_cancel_handle(),
    on_cancel: on_cancel,
    trailers: None,
  )
}

fn read_source(body: Body, maximum_bytes: Int) -> Result(Read, error.Error) {
  case body.source {
    EmptySource -> Ok(Done(complete(body, body.trailers)))
    InvalidSource -> Error(body_error(error.InvalidChunk))
    BytesSource(bytes, offset, completion_trailers) ->
      read_bytes(body, bytes, offset, completion_trailers, maximum_bytes)
    FileSource(path, offset) -> read_file(body, path, offset, maximum_bytes)
    AdvancedSource(source) -> read_pull(body, source, maximum_bytes)
  }
}

fn read_bytes(
  body: Body,
  bytes: BitArray,
  offset: Int,
  completion_trailers: Headers,
  maximum_bytes: Int,
) -> Result(Read, error.Error) {
  let size = bit_array.byte_size(bytes)
  case offset >= size {
    True -> finish_with(body, completion_trailers)
    False -> {
      let count = smallest(maximum_bytes, size - offset)
      case bit_array.slice(bytes, at: offset, take: count) {
        Error(_) -> Error(body_error(error.InvalidChunk))
        Ok(chunk) ->
          data(
            body,
            chunk,
            BytesSource(bytes, offset + count, completion_trailers),
          )
      }
    }
  }
}

fn read_file(
  body: Body,
  path: String,
  offset: Int,
  maximum_bytes: Int,
) -> Result(Read, error.Error) {
  let remaining = remaining_bytes(body)
  case remaining {
    Some(0) -> finish_with(body, [])
    _ -> {
      let count = case remaining {
        Some(bytes) -> smallest(maximum_bytes, bytes)
        None -> maximum_bytes
      }
      case read_file_chunk(path, offset, count) {
        Error(_) -> Error(body_error(error.ReadFailed))
        Ok(<<>>) -> finish_with(body, [])
        Ok(chunk) ->
          data(
            body,
            chunk,
            FileSource(path, offset + bit_array.byte_size(chunk)),
          )
      }
    }
  }
}

fn read_pull(
  body: Body,
  source: Pull,
  maximum_bytes: Int,
) -> Result(Read, error.Error) {
  let PullSource(next) = source
  case next(maximum_bytes) {
    Error(failure) -> Error(failure)
    Ok(PullEnd(trailers)) -> finish_with(body, trailers)
    Ok(PullData(bytes, next)) ->
      case bit_array.bit_size(bytes) % 8, bit_array.bit_size(bytes) {
        0, size if size > 0 ->
          case size / 8 <= maximum_bytes {
            True -> data(body, bytes, AdvancedSource(next))
            False -> Error(body_error(error.InvalidChunk))
          }
        _, _ -> Error(body_error(error.InvalidChunk))
      }
  }
}

fn data(
  body: Body,
  bytes: BitArray,
  source: Source,
) -> Result(Read, error.Error) {
  let count = bit_array.byte_size(bytes)
  let received = body.consumed + count
  case body.total_length {
    Some(expected) if received > expected ->
      Error(body_error(error.LengthMismatch(expected, received)))
    _ ->
      Ok(Data(
        bytes,
        BodyState(..body, source: source, consumed: received, trailers: None),
      ))
  }
}

fn finish_with(body: Body, trailers: Headers) -> Result(Read, error.Error) {
  case body.total_length {
    Some(expected) if body.consumed != expected ->
      Error(body_error(error.LengthMismatch(expected, body.consumed)))
    _ -> Ok(Done(complete(body, Some(trailers))))
  }
}

fn complete(body: Body, trailers: Option(Headers)) -> Body {
  BodyState(..body, source: EmptySource, trailers: trailers)
}

fn remaining_bytes(body: Body) -> Option(Int) {
  case body.total_length {
    Some(length) -> Some(length - body.consumed)
    None -> None
  }
}

fn read_all_loop(
  body: Body,
  maximum_bytes: Int,
  collected_bytes: Int,
  chunks: List(BitArray),
) -> Result(#(BitArray, Headers), error.Error) {
  let maximum_chunk = smallest(65_536, maximum_bytes - collected_bytes + 1)
  case read(body, largest(1, maximum_chunk)) {
    Error(failure) -> Error(failure)
    Ok(Done(completed)) ->
      Ok(#(
        bit_array.concat(list.reverse(chunks)),
        completed_trailers(completed),
      ))
    Ok(Data(bytes, next)) -> {
      let total = collected_bytes + bit_array.byte_size(bytes)
      case total > maximum_bytes {
        True -> Error(body_error(error.TooLarge(maximum_bytes)))
        False -> read_all_loop(next, maximum_bytes, total, [bytes, ..chunks])
      }
    }
  }
}

fn completed_trailers(body: Body) -> Headers {
  case body.trailers {
    Some(trailers) -> trailers
    None -> []
  }
}

fn smallest(first: Int, second: Int) -> Int {
  case first < second {
    True -> first
    False -> second
  }
}

fn largest(first: Int, second: Int) -> Int {
  case first > second {
    True -> first
    False -> second
  }
}

fn body_error(kind: error.BodyErrorKind) -> error.Error {
  error.new(error.Body(kind))
}
