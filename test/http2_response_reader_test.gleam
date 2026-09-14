import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder
import http/internal/http2/response_reader

pub fn main() -> Nil {
  gleeunit.main()
}

fn response_section(
  status: BitArray,
  headers: List(decoder.Header),
  end_stream: Bool,
) -> header_codec.HeaderSection {
  let assert Ok(validated) =
    header_semantics.validate(
      [decoder.Header(<<":status">>, status, False), ..headers],
      header_semantics.ResponseSection,
      False,
    )
  header_codec.HeaderSection(1, end_stream, validated, None)
}

fn trailers_section(
  headers: List(decoder.Header),
) -> header_codec.HeaderSection {
  let assert Ok(validated) =
    header_semantics.validate(headers, header_semantics.TrailerSection, False)
  header_codec.HeaderSection(1, True, validated, None)
}

fn new_reader(maximum_body_bytes: Int) -> response_reader.State {
  let assert Ok(state) =
    response_reader.new(
      stream_id: 1,
      maximum_body_bytes: maximum_body_bytes,
      maximum_informational: 2,
    )
  state
}

pub fn final_head_and_data_are_emitted_without_accumulating_the_body_test() -> Nil {
  let state = new_reader(8)
  let assert Ok(response_reader.Progress(
    state,
    Some(response_reader.Head(incoming, Some(4))),
    [response_reader.Chunk(<<"body">>, 5)],
    Some([]),
  )) =
    response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"103">>, [], False)),
      connection.HeadersReceived(response_section(
        <<"200">>,
        [decoder.Header(<<"content-length">>, <<"4">>, False)],
        False,
      )),
      connection.DataReceived(1, <<"body">>, True, 5),
    ])

  assert incoming.status == 200
  assert response_reader.body_bytes_received(state) == 4
  assert response_reader.finished(state)
}

pub fn trailers_complete_the_stream_without_losing_fields_test() -> Nil {
  let state = new_reader(8)
  let assert Ok(response_reader.Progress(state, Some(_), [], None)) =
    response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"200">>, [], False)),
    ])
  let assert Ok(response_reader.Progress(
    state,
    None,
    [response_reader.Chunk(<<"ok">>, 2)],
    None,
  )) =
    response_reader.accept(state, [
      connection.DataReceived(1, <<"ok">>, False, 2),
    ])
  let assert Ok(response_reader.Progress(
    _,
    None,
    [],
    Some([#("checksum", "yes")]),
  )) =
    response_reader.accept(state, [
      connection.HeadersReceived(
        trailers_section([
          decoder.Header(<<"checksum">>, <<"yes">>, False),
        ]),
      ),
    ])
  Nil
}

pub fn body_limit_and_post_completion_data_are_rejected_test() -> Nil {
  let state = new_reader(3)
  let assert Ok(response_reader.Progress(state, Some(_), [], None)) =
    response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"200">>, [], False)),
    ])
  assert response_reader.accept(state, [
      connection.DataReceived(1, <<"four">>, True, 4),
    ])
    == Error(response_reader.BodyTooLarge(maximum: 3))

  let state = new_reader(3)
  let assert Ok(response_reader.Progress(state, Some(_), [], Some([]))) =
    response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"204">>, [], True)),
    ])
  assert response_reader.accept(state, [
      connection.DataReceived(1, <<"x">>, True, 1),
    ])
    == Error(response_reader.DataAfterCompletion)
}

pub fn reset_goaway_and_informational_limits_are_typed_test() -> Nil {
  let state = new_reader(8)
  assert response_reader.accept(state, [connection.StreamReset(1, 8)])
    == Error(response_reader.StreamReset(error_code: 8))
  assert response_reader.accept(state, [connection.PeerGoAway(0, 0, <<>>)])
    == Error(response_reader.StreamRefused)
  let assert Ok(response_reader.Progress(state, None, [], None)) =
    response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"103">>, [], False)),
      connection.HeadersReceived(response_section(<<"102">>, [], False)),
    ])
  assert response_reader.accept(state, [
      connection.HeadersReceived(response_section(<<"100">>, [], False)),
    ])
    == Error(response_reader.TooManyInformational(maximum: 2))
}

pub fn receive_credit_is_released_only_after_a_chunk_is_fully_consumed_test() -> Nil {
  let chunk = response_reader.Chunk(<<"body">>, 5)
  let assert Ok(response_reader.ChunkPart(
    <<"bo">>,
    Some(remaining),
    released_credit: 0,
  )) = response_reader.read_chunk(chunk, 2)
  assert remaining == response_reader.Chunk(<<"dy">>, 5)
  assert response_reader.read_chunk(remaining, 2)
    == Ok(response_reader.ChunkPart(<<"dy">>, None, released_credit: 5))
  assert response_reader.read_chunk(response_reader.Chunk(<<>>, 7), 1)
    == Ok(response_reader.ChunkPart(<<>>, None, released_credit: 7))
  assert response_reader.read_chunk(chunk, 0)
    == Error(response_reader.InvalidReadLimit)
}
