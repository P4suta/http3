import gleam/bit_array
import gleam/option.{None, Some}
import gleeunit
import http/body
import http/error

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn empty_body_is_known_replayable_and_complete_test() -> Nil {
  let value = body.empty()

  assert body.known_length(value) == Some(0)
  assert body.is_replayable(value)
  let assert Ok(body.Done(completed)) = body.read(value, 16)
  assert body.trailers(completed) == Some([])
}

pub fn bytes_are_pulled_in_bounded_chunks_and_replayed_test() -> Nil {
  let value = body.from_bytes(<<1, 2, 3, 4, 5>>)

  let assert Ok(body.Data(<<1, 2>>, second)) = body.read(value, 2)
  let assert Ok(body.Data(<<3, 4>>, third)) = body.read(second, 2)
  let assert Ok(body.Data(<<5>>, final)) = body.read(third, 2)
  let assert Ok(body.Done(completed)) = body.read(final, 2)
  assert body.trailers(completed) == Some([])

  let assert Ok(replayed) = body.replay(value)
  let assert Ok(#(bytes, [])) = body.read_all(replayed, 5)
  assert bytes == <<1, 2, 3, 4, 5>>
}

pub fn in_memory_body_preserves_trailers_across_replay_test() -> Nil {
  let value =
    body.from_bytes_with_trailers(<<"complete":utf8>>, [
      #("digest", "sha-256=:example:"),
    ])

  assert body.trailers(value) == None
  assert body.known_length(value) == Some(8)
  assert body.is_replayable(value)
  let assert Ok(#(<<"complete":utf8>>, trailers)) = body.read_all(value, 8)
  assert trailers == [#("digest", "sha-256=:example:")]

  let assert Ok(replayed) = body.replay(value)
  let assert Ok(#(<<"complete":utf8>>, replayed_trailers)) =
    body.read_all(replayed, 8)
  assert replayed_trailers == trailers
}

pub fn text_uses_its_utf8_byte_length_test() -> Nil {
  let value = body.from_text("日本")

  assert body.known_length(value) == Some(6)
  let assert Ok(#(bytes, [])) = body.read_all(value, 6)
  assert bit_array.to_string(bytes) == Ok("日本")
}

pub fn bounded_collection_rejects_expansion_past_the_limit_test() -> Nil {
  let result = body.read_all(body.from_bytes(<<1, 2, 3>>), 2)

  let assert Error(failure) = result
  assert error.kind(failure) == error.Body(error.TooLarge(2))
}

pub fn invalid_read_limit_is_typed_test() -> Nil {
  let result = body.read(body.empty(), 0)

  let assert Error(failure) = result
  assert error.kind(failure) == error.Body(error.InvalidLimit)
}

pub fn cancellation_is_shared_by_every_cursor_test() -> Nil {
  let value = body.from_bytes(<<1, 2, 3>>)
  let assert Ok(body.Data(_, next)) = body.read(value, 1)

  body.cancel(value)
  body.cancel(value)

  let assert Error(failure) = body.read(next, 1)
  assert error.kind(failure) == error.Cancelled
}

pub fn pull_stream_preserves_trailers_and_known_length_test() -> Nil {
  let assert Ok(value) =
    body.from_pull(
      chunks([<<"ab":utf8>>, <<"cd":utf8>>], [#("digest", "ok")]),
      Some(4),
      Some(fn() { chunks([<<"ab":utf8>>, <<"cd":utf8>>], []) }),
      fn() { Nil },
    )

  assert body.known_length(value) == Some(4)
  assert body.is_replayable(value)
  let assert Ok(#(bytes, trailers)) = body.read_all(value, 4)
  assert bytes == <<"abcd":utf8>>
  assert trailers == [#("digest", "ok")]
}

pub fn pull_stream_rejects_empty_progress_chunks_test() -> Nil {
  let source =
    body.pull(fn(_) {
      Ok(body.PullData(<<>>, body.pull(fn(_) { Ok(body.PullEnd([])) })))
    })
  let assert Ok(value) = body.from_pull(source, None, None, fn() { Nil })

  let assert Error(failure) = body.read(value, 16)
  assert error.kind(failure) == error.Body(error.InvalidChunk)
}

pub fn pull_stream_cannot_exceed_the_requested_chunk_budget_test() -> Nil {
  let source =
    body.pull(fn(_) {
      Ok(body.PullData(<<1, 2>>, body.pull(fn(_) { Ok(body.PullEnd([])) })))
    })
  let assert Ok(value) = body.from_pull(source, None, None, fn() { Nil })

  let assert Error(failure) = body.read(value, 1)
  assert error.kind(failure) == error.Body(error.InvalidChunk)
}

pub fn pull_stream_enforces_declared_length_test() -> Nil {
  let assert Ok(value) =
    body.from_pull(chunks([<<1, 2>>], []), Some(1), None, fn() { Nil })

  let assert Error(failure) = body.read(value, 16)
  assert error.kind(failure) == error.Body(error.LengthMismatch(1, 2))
}

pub fn file_body_is_bounded_and_replayable_test() -> Nil {
  let assert Ok(value) = body.from_file("test/fixtures/body.txt")

  assert body.known_length(value) == Some(10)
  assert body.is_replayable(value)
  let assert Ok(#(bytes, [])) = body.read_all(value, 10)
  assert bytes == <<"file body\n":utf8>>
}

pub fn missing_file_error_does_not_expose_its_path_test() -> Nil {
  let result = body.from_file("test/fixtures/private-secret-name.txt")

  let assert Error(failure) = result
  assert error.kind(failure) == error.Body(error.ReadFailed)
  assert error.message(failure) == "HTTP body source could not be read"
}

fn chunks(values: List(BitArray), trailers: body.Headers) -> body.Pull {
  body.pull(fn(_) {
    case values {
      [] -> Ok(body.PullEnd(trailers))
      [first, ..rest] -> Ok(body.PullData(first, chunks(rest, trailers)))
    }
  })
}
