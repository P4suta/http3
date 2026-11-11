//// Opaque, bounded, pull-based HTTP bodies.

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/error

/// HTTP trailers represented with the same lossless name/value shape used by `gleam_http` requests and responses.
pub type Headers =
  List(#(String, String))

/// The result of invoking an advanced pull source.
pub type PullEvent {
  PullData(bytes: BitArray, next: Pull)
  PullEnd(trailers: Headers)
}

/// An opaque pull source.
/// Each successful data event supplies the source for the following pull, keeping cursor state explicit and free of globals.
pub opaque type Pull {
  PullSource(next: fn(Int) -> Result(PullEvent, error.Error))
}

/// One bounded read from a body.
pub type Read {
  Data(bytes: BitArray, next: Body)
  Done(completed: Body)
}

/// Shared source cleanup state.
/// Exhausting a wait does not certify release.
@internal
pub type ReleaseState {
  ReleasePending
  Released(outcome: Result(Nil, error.Error))
}

type Source {
  EmptySource
  BytesSource(bytes: BitArray, offset: Int, completion_trailers: Headers)
  FileSource(path: String, offset: Int)
  AdvancedSource(source: Pull)
  InvalidSource
}

type CancelHandle

type TransferObserver {
  TransferObserver(
    read_complete: CancelHandle,
    terminal: CancelHandle,
    previous: Option(TransferObserver),
    on_read_complete: fn() -> Nil,
    on_transfer_complete: fn(Result(Nil, error.Error)) -> Nil,
  )
}

type CleanupCallback {
  InfallibleCleanup(fn() -> Nil)
  FallibleCleanup(fn() -> Result(Nil, Int))
}

/// A body cursor.
/// Its source, file path, callbacks, cancellation token, and replay factory are private.
pub opaque type Body {
  BodyState(
    source: Source,
    total_length: Option(Int),
    consumed: Int,
    replay_factory: Option(fn() -> Result(Body, error.Error)),
    cancel_handle: CancelHandle,
    on_cancel: Option(CleanupCallback),
    on_released: Option(fn(Result(Nil, error.Error)) -> Nil),
    trailers: Option(Headers),
    observer: Option(TransferObserver),
  )
}

@external(erlang, "http_body_ffi", "new_cancel_handle")
fn new_cancel_handle() -> CancelHandle

@external(erlang, "http_body_ffi", "mark_cancelled")
fn mark_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_body_ffi", "is_cancelled")
fn is_cancelled(handle: CancelHandle) -> Bool

@external(erlang, "http_body_ffi", "cancel_once")
fn cancel_once(
  handle: CancelHandle,
  callback: Option(CleanupCallback),
  on_released: Option(fn(Result(Nil, Int)) -> Nil),
  milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_body_ffi", "run_cancel_callback")
fn run_transfer_observer(
  callback: fn() -> Nil,
  timeout_milliseconds: Int,
) -> Result(Nil, Int)

@external(erlang, "http_body_ffi", "await_release")
fn await_release_state(
  handle: CancelHandle,
  milliseconds: Int,
) -> Option(Result(Nil, Int))

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
    on_cancel: None,
    on_released: None,
    trailers: Some([]),
    observer: None,
  )
}

/// Construct a replayable in-memory body.
///
/// A non-byte-aligned bit array is retained as an invalid source and produces a typed `InvalidChunk` error when read; it never reaches a protocol writer.
pub fn from_bytes(bytes: BitArray) -> Body {
  from_bytes_with_trailers(bytes, [])
}

/// Construct a replayable in-memory body with completion trailers.
///
/// Trailers remain unavailable through `trailers` until the body is fully consumed.
/// A replay preserves both the bytes and the trailers.
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
        on_cancel: None,
        on_released: None,
        trailers: None,
        observer: None,
      )
  }
}

/// Construct a replayable UTF-8 body.
pub fn from_text(text: String) -> Body {
  text |> bit_array.from_string |> from_bytes
}

/// Construct a replayable file body after checking that the file can be opened and measuring its current size.
/// File paths never appear in errors.
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
/// `known_length` must be non-negative when present.
/// Supplying `replay` allows redirects, retries, and explicit replay to create a fresh source.
pub fn from_pull(
  source: Pull,
  known_length: Option(Int),
  replay: Option(fn() -> Pull),
  on_cancel: fn() -> Nil,
) -> Result(Body, error.Error) {
  from_pull_callback(source, known_length, replay, InfallibleCleanup(on_cancel))
}

/// Construct a protocol-owned stream with a redacted cleanup result.
@internal
pub fn from_pull_with_cleanup(
  source: Pull,
  known_length: Option(Int),
  replay: Option(fn() -> Pull),
  on_cancel: fn() -> Result(Nil, error.Error),
) -> Result(Body, error.Error) {
  from_pull_callback(
    source,
    known_length,
    replay,
    FallibleCleanup(fn() {
      on_cancel() |> result.map_error(cleanup_failure_code)
    }),
  )
}

fn cleanup_failure_code(failure: error.Error) -> Int {
  case error.kind(failure) {
    error.Timeout(_) -> 2
    error.Cancelled -> 3
    _ -> 1
  }
}

fn from_pull_callback(
  source: Pull,
  known_length: Option(Int),
  replay: Option(fn() -> Pull),
  on_cancel: CleanupCallback,
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

/// Whether a protocol writer must leave room for completion trailers.
/// Known byte length does not rule out trailers.
/// Advanced sources are treated conservatively without calling their producer or consuming any body data.
@internal
pub fn may_have_trailers(body: Body) -> Bool {
  case body.trailers {
    Some(fields) -> fields != []
    None ->
      case body.source {
        BytesSource(_, _, fields) -> fields != []
        AdvancedSource(_) -> True
        EmptySource | FileSource(_, _) | InvalidSource -> False
      }
  }
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
/// It runs under supervision with a one-second cleanup deadline; callback exceptions and stalls cannot escape into the cancelling application.
pub fn cancel(body: Body) -> Nil {
  let _cleanup = cancel_within(body, 1000)
  Nil
}

/// Dispose a source under a finite cleanup budget and preserve a redacted cleanup outcome separately from its already-recorded transfer outcome.
@internal
pub fn cancel_within(
  body: Body,
  milliseconds: Int,
) -> Result(Nil, error.Error) {
  transfer_finished(body, Error(error.new(error.Cancelled)))
  let released = case body.on_released {
    None -> None
    Some(observe) -> Some(fn(outcome) { observe(cleanup_outcome(outcome)) })
  }
  cancel_once(body.cancel_handle, body.on_cancel, released, milliseconds)
  |> cleanup_outcome
}

fn cleanup_outcome(outcome: Result(Nil, Int)) -> Result(Nil, error.Error) {
  case outcome {
    Ok(Nil) -> Ok(Nil)
    Error(2) -> Error(error.new(error.Timeout(error.Operation)))
    Error(3) -> Error(error.new(error.Cancelled))
    Error(_) -> Error(error.new(error.Service))
  }
}

/// Wait for confirmed cleanup without confusing a waiting caller's deadline with a source callback that has already been stopped at its own deadline.
/// A zero budget is an immediate snapshot and never starts cancellation.
@internal
pub fn await_release(body: Body, within_milliseconds: Int) -> ReleaseState {
  case await_release_state(body.cancel_handle, within_milliseconds) {
    None -> ReleasePending
    Some(outcome) -> Released(cleanup_outcome(outcome))
  }
}

/// Observe the completed cleanup independently from the transfer result.
/// Every cursor shares the same cancellation claim and terminal result.
@internal
pub fn observe_release(
  body: Body,
  on_released: fn(Result(Nil, error.Error)) -> Nil,
) -> Body {
  let previous = body.on_released
  BodyState(
    ..body,
    on_released: Some(fn(outcome) {
      case previous {
        Some(observe) -> observe(outcome)
        None -> Nil
      }
      on_released(outcome)
    }),
  )
}

/// Return trailers only after the body has completed.
pub fn trailers(body: Body) -> Option(Headers) {
  body.trailers
}

/// Pull at most `maximum_bytes` from a body.
pub fn read(body: Body, maximum_bytes: Int) -> Result(Read, error.Error) {
  case maximum_bytes <= 0 {
    True -> Error(body_error(error.InvalidLimit))
    False -> read_valid_limit(body, maximum_bytes)
  }
}

fn read_valid_limit(
  body: Body,
  maximum_bytes: Int,
) -> Result(Read, error.Error) {
  let outcome = case is_cancelled(body.cancel_handle) {
    True -> Error(error.new(error.Cancelled))
    False -> read_source(body, maximum_bytes)
  }
  case outcome {
    Ok(Done(_)) -> observe_read_completion(body)
    Error(failure) -> transfer_finished(body, Error(failure))
    Ok(Data(..)) -> Nil
  }
  outcome
}

/// Attach payload-free transfer observers shared by every derived cursor.
/// Existing observers retain their own shared notification claims and are attempted before the newly attached callbacks.
/// Each callback runs in its own bounded guardian, so an exception or stall cannot suppress the next observer in the chain.
/// Attaching never replays prior events.
/// Reading EOF does not imply that a protocol's final write succeeded.
@internal
pub fn observe_transfer(
  body: Body,
  on_read_complete: fn() -> Nil,
  on_transfer_complete: fn(Result(Nil, error.Error)) -> Nil,
) -> Body {
  // Capture only the previous observer, never the source or replay payload.
  let previous = body.observer
  BodyState(
    ..body,
    observer: Some(TransferObserver(
      read_complete: new_cancel_handle(),
      terminal: new_cancel_handle(),
      previous:,
      on_read_complete:,
      on_transfer_complete:,
    )),
  )
}

/// Record the actual protocol outcome exactly once, including failed final writes after EOF.
/// Adapters call this before disposing a suppressed body.
@internal
pub fn transfer_finished(body: Body, outcome: Result(Nil, error.Error)) -> Nil {
  notify_transfer_completion(body.observer, outcome)
}

fn notify_transfer_completion(
  observer: Option(TransferObserver),
  outcome: Result(Nil, error.Error),
) -> Nil {
  case observer {
    None -> Nil
    Some(observer) -> {
      let _previous_notified =
        notify_transfer_completion(observer.previous, outcome)
      use <- bool.guard(when: !mark_cancelled(observer.terminal), return: Nil)
      let _observed =
        run_transfer_observer(
          fn() { observer.on_transfer_complete(outcome) },
          100,
        )
      Nil
    }
  }
}

fn observe_read_completion(body: Body) -> Nil {
  notify_read_completion(body.observer)
}

fn notify_read_completion(observer: Option(TransferObserver)) -> Nil {
  case observer {
    None -> Nil
    Some(observer) -> {
      let _previous_notified = notify_read_completion(observer.previous)
      use <- bool.guard(
        when: !mark_cancelled(observer.read_complete),
        return: Nil,
      )
      let _observed = run_transfer_observer(observer.on_read_complete, 100)
      Nil
    }
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
    on_cancel: None,
    trailers: None,
    on_released: None,
    observer: None,
  )
}

fn file_body(path: String, size: Int) -> Body {
  BodyState(
    source: FileSource(path, 0),
    total_length: Some(size),
    consumed: 0,
    replay_factory: Some(fn() { from_file(path) }),
    cancel_handle: new_cancel_handle(),
    on_cancel: None,
    trailers: None,
    on_released: None,
    observer: None,
  )
}

fn pull_body(
  source: Pull,
  known_length: Option(Int),
  replay_source: Option(fn() -> Pull),
  on_cancel: CleanupCallback,
) -> Body {
  let replay_factory = case replay_source {
    None -> None
    Some(factory) ->
      Some(fn() {
        Ok(pull_body(factory(), known_length, replay_source, on_cancel))
      })
  }
  BodyState(
    source: AdvancedSource(source),
    total_length: known_length,
    consumed: 0,
    replay_factory: replay_factory,
    cancel_handle: new_cancel_handle(),
    on_cancel: Some(on_cancel),
    on_released: None,
    trailers: None,
    observer: None,
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
