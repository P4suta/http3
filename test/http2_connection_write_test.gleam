import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{type Option, None, Some}
import gleeunit
import http/internal/http2/body_length
import http/internal/http2/connection
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder
import http/internal/http2/hpack/encoder
import http/internal/http2/message
import http/internal/http2/origin
import http/internal/http2/settings
import http/internal/http2/stream_state

pub fn main() -> Nil {
  gleeunit.main()
}

fn limits() -> connection.Limits {
  limits_with_tracked_streams(4)
}

fn limits_with_tracked_streams(
  maximum_tracked_streams: Int,
) -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 64,
    maximum_active_streams: 4,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 1024,
      maximum_header_list_bytes: 4096,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: maximum_tracked_streams,
    ),
  )
}

fn ready_with_limits(
  role: connection.Role,
  limits: connection.Limits,
) -> connection.State {
  let assert Ok(state) = connection.new(role, limits)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(0, frame.Settings, 0, 0), <<>>)
  state
}

fn ready(role: connection.Role) -> connection.State {
  let assert Ok(state) = connection.new(role, limits())
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(0, frame.Settings, 0, 0), <<>>)
  state
}

fn get_request() -> request.Request(Nil) {
  request.Request(
    method: gleam_http.Get,
    headers: [],
    body: Nil,
    scheme: gleam_http.Https,
    host: "example.com",
    port: None,
    path: "/",
    query: None,
  )
}

fn extended_connect_request() -> request.Request(Nil) {
  request.Request(
    method: gleam_http.Connect,
    headers: [#("sec-websocket-version", "13")],
    body: Nil,
    scheme: gleam_http.Https,
    host: "example.com",
    port: None,
    path: "/chat",
    query: None,
  )
}

pub fn server_origin_frame_is_always_emitted_on_stream_zero_without_flags_test() -> Nil {
  let server = ready(connection.Server)
  let origins = [origin.Origin("https", "example.com", None)]
  let assert Ok(connection.ControlWritten(_, [wire])) =
    connection.send_origins(server, origins)
  assert wire
    == <<
      0,
      0,
      21,
      0x0c,
      0,
      0,
      0,
      0,
      0,
      19:size(16),
      "https://example.com":utf8,
    >>
  assert connection.send_origins(ready(connection.Client), origins)
    == Error(connection.WrongRole)
}

fn response_block(status: String, content_length: Option(String)) -> BitArray {
  let fields = case content_length {
    None -> [decoder.Header(<<":status">>, <<status:utf8>>, False)]
    Some(length) -> [
      decoder.Header(<<":status">>, <<status:utf8>>, False),
      decoder.Header(<<"content-length">>, <<length:utf8>>, False),
    ]
  }
  let assert Ok(state) = encoder.new(4096, 4096, False)
  let assert Ok(encoder.Encoded(_, block)) = encoder.encode(state, fields)
  block
}

fn request_block(method: String) -> BitArray {
  let fields = [
    decoder.Header(<<":method">>, <<method:utf8>>, False),
    decoder.Header(<<":scheme">>, <<"https">>, False),
    decoder.Header(<<":authority">>, <<"example.com">>, False),
    decoder.Header(<<":path">>, <<"/">>, False),
  ]
  let assert Ok(state) = encoder.new(4096, 4096, False)
  let assert Ok(encoder.Encoded(_, block)) = encoder.encode(state, fields)
  block
}

fn server_with_request(method: String) -> connection.State {
  let state = ready(connection.Server)
  let block = request_block(method)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 1),
      block,
    )
  state
}

pub fn a_standard_request_allocates_a_client_stream_and_writes_headers_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, [wire])) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  assert connection.stream_state(state, 1) == stream_state.HalfClosedLocal

  let assert Ok(frame_decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(
    frame.Header(_, frame.Headers, 0x5, 1),
    block,
    <<>>,
  )) = frame.feed(frame_decoder, wire)
  let assert Ok(hpack) = decoder.new(4096, 4096)
  let assert Ok(decoder.Decoded(_, fields)) = decoder.decode(hpack, block)
  assert list.length(fields) == 4

  let assert Ok(connection.HeadersWritten(_, 3, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  Nil
}

pub fn rfc8441_client_requires_peer_opt_in_before_writing_extended_connect_test() -> Nil {
  let state = ready(connection.Client)
  assert connection.send_extended_connect_headers(
      state,
      extended_connect_request(),
      protocol: "websocket",
    )
    == Error(connection.ExtendedConnectNotEnabled)

  let assert Ok(payload) =
    settings.encode([settings.EnableConnectProtocol(True)])
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(payload), frame.Settings, 0, 0),
      payload,
    )
  let assert Ok(connection.HeadersWritten(state, 1, [encoded])) =
    connection.send_extended_connect_headers(
      state,
      extended_connect_request(),
      protocol: "websocket",
    )
  assert connection.stream_state(state, 1) == stream_state.Open

  let assert Ok(frame_decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(
    frame.Header(_, frame.Headers, 0x4, 1),
    block,
    <<>>,
  )) = frame.feed(frame_decoder, encoded)
  let assert Ok(hpack) = decoder.new(4096, 4096)
  let assert Ok(decoder.Decoded(_, fields)) = decoder.decode(hpack, block)
  assert fields
    == [
      decoder.Header(<<":method">>, <<"CONNECT">>, False),
      decoder.Header(<<":protocol">>, <<"websocket">>, False),
      decoder.Header(<<":scheme">>, <<"https">>, False),
      decoder.Header(<<":authority">>, <<"example.com">>, False),
      decoder.Header(<<":path">>, <<"/chat">>, False),
      decoder.Header(<<"sec-websocket-version">>, <<"13">>, False),
    ]
}

pub fn a_server_writes_a_standard_response_on_an_existing_request_stream_test() -> Nil {
  let state = ready(connection.Server)
  let request_block = <<0x82, 0x87, 0x84, 0x01, 11, "example.com":utf8>>
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(16, frame.Headers, 0x5, 1),
      request_block,
    )
  let outgoing = response.Response(status: 200, headers: [], body: Nil)
  let assert Ok(connection.HeadersWritten(state, 1, [wire])) =
    connection.send_response_headers(state, 1, outgoing, end_stream: True)
  assert wire == <<0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88>>
  assert connection.stream_state(state, 1) == stream_state.Closed
}

pub fn late_window_update_on_a_closed_stream_is_ignored_test() -> Nil {
  let state = server_with_request("GET")
  let outgoing = response.Response(status: 200, headers: [], body: Nil)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_response_headers(state, 1, outgoing, end_stream: True)
  assert connection.stream_state(state, 1) == stream_state.Closed

  let assert Ok(connection.Transition(unchanged, [])) =
    connection.receive_frame(state, frame.Header(4, frame.WindowUpdate, 0, 1), <<
      0:size(1),
      16_384:size(31),
    >>)
  assert connection.stream_state(unchanged, 1) == stream_state.Closed
}

pub fn outbound_reset_closes_only_the_selected_stream_test() -> Nil {
  let state = server_with_request("GET")
  let block = request_block("GET")
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 3),
      block,
    )
  let assert Ok(connection.ControlWritten(state, [wire])) =
    connection.reset_stream(state, stream_id: 1, error_code: 0x2)

  assert wire == <<0, 0, 4, 3, 0, 0, 0, 0, 1, 0, 0, 0, 2>>
  assert connection.stream_state(state, 1) == stream_state.Closed
  assert connection.stream_state(state, 3) == stream_state.HalfClosedRemote
}

pub fn trailers_end_an_existing_outbound_stream_and_reuse_hpack_state_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: False)
  let assert Ok(connection.DataWritten(open_state, _, <<>>, False)) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"body">>,
      end_stream: False,
    )

  let assert Ok(connection.HeadersWritten(state, 1, [wire])) =
    connection.send_trailers(open_state, 1, [#("checksum", "yes")])

  assert connection.stream_state(state, 1) == stream_state.HalfClosedLocal
  let assert Ok(frame_decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(
    frame.Header(_, frame.Headers, 0x5, 1),
    block,
    <<>>,
  )) = frame.feed(frame_decoder, wire)
  let assert Ok(hpack) = decoder.new(4096, 4096)
  let assert Ok(decoder.Decoded(_, [decoded])) = decoder.decode(hpack, block)
  assert decoded == decoder.Header(<<"checksum">>, <<"yes">>, False)

  assert connection.send_trailers(open_state, 1, [#("content-length", "4")])
    == Error(
      connection.MessageFailure(
        message.SemanticsFailure(
          header_semantics.ForbiddenTrailerField(<<"content-length">>),
        ),
      ),
    )
}

pub fn outbound_request_content_length_is_transactionally_enforced_test() -> Nil {
  let outgoing =
    request.Request(..get_request(), method: gleam_http.Post, headers: [
      #("content-length", "3"),
    ])
  let state = ready(connection.Client)
  assert connection.send_request_headers(state, outgoing, end_stream: True)
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 0,
      )),
    )

  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, outgoing, end_stream: False)
  assert connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"ab">>,
      end_stream: True,
    )
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 2,
      )),
    )

  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, outgoing, end_stream: False)
  let assert Ok(connection.DataWritten(_, _, <<>>, True)) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"abc">>,
      end_stream: True,
    )
  Nil
}

pub fn outbound_response_content_length_uses_request_semantics_test() -> Nil {
  let outgoing =
    response.Response(
      status: 200,
      headers: [
        #("content-length", "3"),
      ],
      body: Nil,
    )
  let state = server_with_request("GET")
  assert connection.send_response_headers(state, 1, outgoing, end_stream: True)
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 0,
      )),
    )

  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_response_headers(state, 1, outgoing, end_stream: False)
  assert connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"ab">>,
      end_stream: True,
    )
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 2,
      )),
    )

  let state = server_with_request("GET")
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_response_headers(state, 1, outgoing, end_stream: False)
  let assert Ok(connection.DataWritten(_, _, <<>>, True)) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"abc">>,
      end_stream: True,
    )
  Nil
}

pub fn outbound_head_and_304_content_lengths_are_metadata_test() -> Nil {
  let outgoing =
    response.Response(
      status: 200,
      headers: [
        #("content-length", "42"),
      ],
      body: Nil,
    )
  let state = server_with_request("HEAD")
  let assert Ok(connection.HeadersWritten(_, 1, _)) =
    connection.send_response_headers(state, 1, outgoing, end_stream: True)
  assert connection.send_response_headers(state, 1, outgoing, end_stream: False)
    == Error(connection.ResponseMustEndStream(status: 200))

  let outgoing = response.Response(..outgoing, status: 304)
  let state = server_with_request("GET")
  let assert Ok(connection.HeadersWritten(_, 1, _)) =
    connection.send_response_headers(state, 1, outgoing, end_stream: True)
  assert connection.send_response_headers(state, 1, outgoing, end_stream: False)
    == Error(connection.ResponseMustEndStream(status: 304))
  Nil
}

pub fn data_writes_resume_after_stream_window_update_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: False)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(6, frame.Settings, 0, 0), <<
      0,
      4,
      0,
      0,
      0,
      3,
    >>)

  let assert Ok(connection.DataWritten(
    state,
    [first],
    remaining: <<"def":utf8>>,
    end_stream_sent: False,
  )) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"abcdef":utf8>>,
      end_stream: True,
    )
  assert first == <<0, 0, 3, 0, 0, 0, 0, 0, 1, "abc":utf8>>
  assert connection.stream_send_window(state, 1) == Ok(0)
  let assert Ok(connection.DataBlocked(_)) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"def":utf8>>,
      end_stream: True,
    )

  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(4, frame.WindowUpdate, 0, 1), <<
      0:size(1),
      3:size(31),
    >>)
  let assert Ok(connection.DataWritten(
    state,
    [last],
    remaining: <<>>,
    end_stream_sent: True,
  )) =
    connection.send_data(
      state,
      stream_id: 1,
      bytes: <<"def":utf8>>,
      end_stream: True,
    )
  assert last == <<0, 0, 3, 0, 1, 0, 0, 0, 1, "def":utf8>>
  assert connection.stream_state(state, 1) == stream_state.HalfClosedLocal
}

pub fn request_and_response_writers_are_role_checked_test() -> Nil {
  let server = ready(connection.Server)
  assert connection.send_request_headers(
      server,
      get_request(),
      end_stream: True,
    )
    == Error(connection.WrongRole)

  let client = ready(connection.Client)
  let outgoing = response.Response(status: 200, headers: [], body: Nil)
  assert connection.send_response_headers(client, 1, outgoing, end_stream: True)
    == Error(connection.WrongRole)
}

pub fn peer_concurrency_limit_is_released_by_reset_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(6, frame.Settings, 0, 0), <<
      0,
      3,
      0,
      0,
      0,
      1,
    >>)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  assert connection.send_request_headers(state, get_request(), end_stream: True)
    == Error(connection.PeerConcurrentStreamLimit(maximum: 1))

  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(4, frame.RstStream, 0, 1), <<
      0,
      0,
      0,
      8,
    >>)
  assert actions == [connection.StreamReset(stream_id: 1, error_code: 8)]
  assert connection.stream_state(state, 1) == stream_state.Closed
  let assert Ok(connection.HeadersWritten(_, 3, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  Nil
}

pub fn peer_header_table_limit_is_applied_to_the_next_header_block_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(6, frame.Settings, 0, 0), <<
      0,
      1,
      0,
      0,
      0,
      0,
    >>)
  let assert Ok(connection.HeadersWritten(_, 1, [wire])) =
    connection.send_request_headers(state, get_request(), end_stream: True)

  let assert Ok(frame_decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(
    frame.Header(_, frame.Headers, _, 1),
    block,
    <<>>,
  )) = frame.feed(frame_decoder, wire)
  let assert <<0x20, fields:bits>> = block
  assert bit_array.byte_size(fields) > 0
}

pub fn closed_response_headers_release_bounded_phase_metadata_test() -> Nil {
  let state =
    ready_with_limits(connection.Client, limits_with_tracked_streams(1))
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x5, 1), <<
      0x88,
    >>)

  let assert Ok(connection.HeadersWritten(state, 3, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(_, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x5, 3), <<
      0x88,
    >>)
  Nil
}

pub fn closed_response_data_releases_bounded_phase_metadata_test() -> Nil {
  let state =
    ready_with_limits(connection.Client, limits_with_tracked_streams(1))
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x4, 1), <<
      0x88,
    >>)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(0, frame.Data, 0x1, 1), <<>>)

  let assert Ok(connection.HeadersWritten(state, 3, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(_, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x5, 3), <<
      0x88,
    >>)
  Nil
}

pub fn processed_data_restores_connection_and_active_stream_credit_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x4, 1), <<
      0x88,
    >>)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(3, frame.Data, 0, 1), <<
      "abc":utf8,
    >>)
  assert connection.connection_receive_window(state) == 65_532
  assert connection.stream_receive_window(state, 1) == Ok(65_532)

  let assert Ok(connection.ReceiveCreditReleased(state, frames)) =
    connection.release_receive_credit(state, stream_id: 1, octets: 3)
  assert frames
    == [
      <<0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 3>>,
      <<0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 3>>,
    ]
  assert connection.connection_receive_window(state) == 65_535
  assert connection.stream_receive_window(state, 1) == Ok(65_535)
}

pub fn processed_final_data_only_restores_connection_credit_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(1, frame.Headers, 0x4, 1), <<
      0x88,
    >>)
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(3, frame.Data, 0x1, 1), <<
      "abc":utf8,
    >>)
  assert connection.stream_state(state, 1) == stream_state.Closed

  let assert Ok(connection.ReceiveCreditReleased(state, [wire])) =
    connection.release_receive_credit(state, stream_id: 1, octets: 3)
  assert wire == <<0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 3>>
  assert connection.connection_receive_window(state) == 65_535
}

pub fn response_content_length_is_checked_against_data_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let block = response_block("200", Some("3"))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
  assert connection.receive_frame(state, frame.Header(2, frame.Data, 0x1, 1), <<
      "ab":utf8,
    >>)
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 2,
      )),
    )
}

pub fn head_content_length_is_metadata_and_the_headers_end_the_stream_test() -> Nil {
  let state = ready(connection.Client)
  let outgoing = request.Request(..get_request(), method: gleam_http.Head)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, outgoing, end_stream: True)
  let block = response_block("200", Some("42"))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 1),
      block,
    )
  assert connection.stream_state(state, 1) == stream_state.Closed
}

pub fn bodyless_response_status_must_end_on_the_header_section_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.HeadersWritten(state, 1, _)) =
    connection.send_request_headers(state, get_request(), end_stream: True)
  let block = response_block("204", None)
  assert connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
    == Error(connection.ResponseMustEndStream(status: 204))
}
