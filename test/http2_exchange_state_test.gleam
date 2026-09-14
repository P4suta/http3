import gleam/option
import gleeunit
import http/body
import http/internal/http2/connection
import http/internal/http2/exchange_state
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder

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
  header_codec.HeaderSection(1, end_stream, validated, option.None)
}

fn trailers_section(
  headers: List(decoder.Header),
) -> header_codec.HeaderSection {
  let assert Ok(validated) =
    header_semantics.validate(headers, header_semantics.TrailerSection, False)
  header_codec.HeaderSection(1, True, validated, option.None)
}

pub fn informational_final_and_data_complete_one_bounded_response_test() -> Nil {
  let assert Ok(state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 8,
      maximum_informational: 2,
    )
  let assert Ok(exchange_state.Waiting(state, [])) =
    exchange_state.accept(state, [
      connection.HeadersReceived(response_section(<<"103">>, [], False)),
      connection.HeadersReceived(response_section(
        <<"200">>,
        [decoder.Header(<<"x-result">>, <<"yes">>, False)],
        False,
      )),
    ])

  let assert Ok(exchange_state.Complete(
    _,
    incoming,
    [exchange_state.Credit(stream_id: 1, octets: 5)],
  )) =
    exchange_state.accept(state, [
      connection.DataReceived(
        stream_id: 1,
        bytes: <<"done">>,
        end_stream: True,
        flow_controlled_bytes: 5,
      ),
    ])

  assert incoming.status == 200
  assert incoming.headers == [#("x-result", "yes")]
  let assert Ok(#(<<"done">>, [])) = body.read_all(incoming.body, 8)
  Nil
}

pub fn trailers_are_retained_on_the_completed_body_test() -> Nil {
  let assert Ok(state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 8,
      maximum_informational: 1,
    )
  let assert Ok(exchange_state.Waiting(
    state,
    [exchange_state.Credit(stream_id: 1, octets: 2)],
  )) =
    exchange_state.accept(state, [
      connection.HeadersReceived(response_section(<<"200">>, [], False)),
      connection.DataReceived(1, <<"ok">>, False, 2),
    ])
  let assert Ok(exchange_state.Complete(_, incoming, [])) =
    exchange_state.accept(state, [
      connection.HeadersReceived(
        trailers_section([
          decoder.Header(<<"checksum">>, <<"yes">>, False),
        ]),
      ),
    ])

  let assert Ok(#(<<"ok">>, [#("checksum", "yes")])) =
    body.read_all(incoming.body, 8)
  Nil
}

pub fn body_limit_is_checked_before_retaining_peer_data_test() -> Nil {
  let assert Ok(state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 4,
      maximum_informational: 1,
    )
  let assert Ok(exchange_state.Waiting(state, [])) =
    exchange_state.accept(state, [
      connection.HeadersReceived(response_section(<<"200">>, [], False)),
    ])

  assert exchange_state.accept(state, [
      connection.DataReceived(1, <<"abcde">>, True, 5),
    ])
    == Error(exchange_state.BodyTooLarge(maximum: 4))
}

pub fn invalid_response_sequence_and_peer_abort_are_typed_test() -> Nil {
  let assert Ok(state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 8,
      maximum_informational: 1,
    )
  assert exchange_state.accept(state, [
      connection.DataReceived(1, <<"x">>, True, 1),
    ])
    == Error(exchange_state.DataBeforeFinalHeaders)
  assert exchange_state.accept(state, [connection.StreamReset(1, 8)])
    == Error(exchange_state.StreamReset(error_code: 8))
  assert exchange_state.accept(state, [connection.PeerGoAway(0, 0, <<>>)])
    == Error(exchange_state.StreamRefused)
}

pub fn informational_responses_are_finitely_bounded_test() -> Nil {
  let assert Ok(state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 8,
      maximum_informational: 1,
    )
  let assert Ok(exchange_state.Waiting(state, [])) =
    exchange_state.accept(state, [
      connection.HeadersReceived(response_section(<<"103">>, [], False)),
    ])

  assert exchange_state.accept(state, [
      connection.HeadersReceived(response_section(<<"102">>, [], False)),
    ])
    == Error(exchange_state.TooManyInformational(maximum: 1))
}
