import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleeunit
import http/body
import http/internal/http2/connection
import http/internal/http2/control
import http/internal/http2/exchange_state
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/hpack/decoder
import http/internal/http2/hpack/encoder
import http/internal/http2/origin
import http/internal/http2/preface
import http/internal/http2/settings
import http/internal/http2/stream_state
import http/internal/http2/wire

pub fn main() -> Nil {
  gleeunit.main()
}

fn connection_limits() -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 64,
    maximum_active_streams: 16,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 4096,
      maximum_header_list_bytes: 8192,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: 16,
    ),
  )
}

fn wire_limits(maximum_frames_per_feed: Int) -> wire.Limits {
  wire.Limits(
    maximum_frame_bytes: 16_384,
    maximum_feed_bytes: 65_536,
    maximum_frames_per_feed: maximum_frames_per_feed,
  )
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

fn extended_connect_block() -> BitArray {
  let assert Ok(state) = encoder.new(4096, 8192, False)
  let assert Ok(encoder.Encoded(_, block)) =
    encoder.encode(state, [
      decoder.Header(<<":method">>, <<"CONNECT">>, False),
      decoder.Header(<<":scheme">>, <<"https">>, False),
      decoder.Header(<<":path">>, <<"/chat">>, False),
      decoder.Header(<<":authority">>, <<"example.com">>, False),
      decoder.Header(<<":protocol">>, <<"websocket">>, False),
    ])
  block
}

pub fn server_preface_and_multiple_frames_are_incremental_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Server, connection_limits(), wire_limits(8))
  let assert Ok(initial) = preface.client_initial_bytes([], 16_384)
  let assert Ok(ping) =
    control.encode(control.PingFrame(False, <<"12345678":utf8>>), 0, 16_384)
  let bytes = <<initial:bits, ping:bits>>
  let assert Ok(first) = bit_array.slice(bytes, at: 0, take: 10)
  let assert Ok(rest) =
    bit_array.slice(bytes, at: 10, take: bit_array.byte_size(bytes) - 10)

  let assert Ok(wire.Fed(state, [])) = wire.feed(state, first)
  let assert Ok(wire.Fed(_, actions)) = wire.feed(state, rest)
  assert actions
    == [
      connection.SendSettingsAcknowledgement,
      connection.PeerSettingsChanged(initial_window_delta: 0),
      connection.SendPingAcknowledgement(<<"12345678":utf8>>),
    ]
}

pub fn client_initial_bytes_are_sent_once_and_record_settings_ack_debt_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let local_settings = [settings.MaxConcurrentStreams(16)]
  let assert Ok(expected) = preface.client_initial_bytes(local_settings, 16_384)
  let assert Ok(wire.Started(state, bytes)) =
    wire.initial_bytes(state, local_settings)
  assert bytes == expected
  assert connection.outstanding_settings(wire.connection_state(state)) == 1
  assert wire.initial_bytes(state, []) == Error(wire.AlreadyStarted)
}

pub fn incomplete_frame_is_retained_until_the_next_feed_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(settings_frame) = preface.server_initial_bytes([], 16_384)
  let assert Ok(first) = bit_array.slice(settings_frame, at: 0, take: 4)
  let assert Ok(rest) = bit_array.slice(settings_frame, at: 4, take: 5)

  let assert Ok(wire.Fed(state, [])) = wire.feed(state, first)
  let assert Ok(wire.Fed(_, actions)) = wire.feed(state, rest)
  assert actions
    == [
      connection.SendSettingsAcknowledgement,
      connection.PeerSettingsChanged(initial_window_delta: 0),
    ]
}

pub fn feed_bytes_and_frame_count_are_strictly_bounded_test() -> Nil {
  let assert Ok(tiny) =
    wire.new(connection.Client, connection_limits(), wire.Limits(16_384, 8, 1))
  assert wire.feed(tiny, <<0, 0, 0, 0, 0, 0, 0, 0, 0>>)
    == Error(wire.ChunkTooLarge(maximum: 8))

  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(1))
  let assert Ok(settings_frame) = preface.server_initial_bytes([], 16_384)
  let assert Ok(ping) =
    frame.encode(frame.Ping, 0, 0, <<"12345678":utf8>>, 16_384)
  assert wire.feed(state, <<settings_frame:bits, ping:bits>>)
    == Error(wire.TooManyFrames(maximum: 1))
}

pub fn automatic_control_actions_encode_only_required_acknowledgements_test() -> Nil {
  let actions = [
    connection.SendSettingsAcknowledgement,
    connection.PeerSettingsChanged(initial_window_delta: 0),
    connection.SendPingAcknowledgement(<<"12345678":utf8>>),
    connection.PingAcknowledged(<<"abcdefgh":utf8>>),
  ]
  let assert Ok(writes) = wire.automatic_writes(actions, 16_384)
  assert writes
    == [
      <<0, 0, 0, 4, 1, 0, 0, 0, 0>>,
      <<0, 0, 8, 6, 1, 0, 0, 0, 0, "12345678":utf8>>,
    ]
}

pub fn server_wire_origin_control_write_preserves_typed_state_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Server, connection_limits(), wire_limits(8))
  let origins = [origin.Origin("https", "example.com", None)]
  let assert Ok(wire.ControlWritten(_, [encoded])) =
    wire.send_origins(state, origins)
  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(frame.Header(21, frame.Origin, 0, 0), _, <<>>)) =
    frame.feed(decoder, encoded)
  Nil
}

pub fn outbound_request_state_continues_into_inbound_response_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(wire.Started(state, _)) = wire.initial_bytes(state, [])
  let assert Ok(peer_settings) = preface.server_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, peer_settings)

  let assert Ok(wire.HeadersWritten(state, 1, request_frames)) =
    wire.send_request_headers(state, get_request(), end_stream: True)
  assert request_frames != []
  let assert Ok(response) =
    frame.encode(frame.Headers, 0x5, 1, <<0x88>>, 16_384)
  let assert Ok(wire.Fed(_, [connection.HeadersReceived(_)])) =
    wire.feed(state, response)
  Nil
}

pub fn rfc8441_outbound_extended_connect_is_observable_at_the_wire_boundary_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(peer_settings) =
    preface.server_initial_bytes([settings.EnableConnectProtocol(True)], 16_384)
  let assert Ok(wire.Fed(state, actions)) = wire.feed(state, peer_settings)
  assert actions
    == [
      connection.SendSettingsAcknowledgement,
      connection.PeerSettingsChanged(initial_window_delta: 0),
    ]

  let assert Ok(wire.HeadersWritten(state, 1, frames)) =
    wire.send_extended_connect_headers(
      state,
      extended_connect_request(),
      protocol: "websocket",
    )
  assert !list.is_empty(frames)
  assert connection.stream_state(wire.connection_state(state), 1)
    == stream_state.Open
}

pub fn outbound_data_advances_the_opaque_wire_state_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(peer_settings) = preface.server_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, peer_settings)
  let assert Ok(wire.HeadersWritten(state, 1, _)) =
    wire.send_request_headers(state, get_request(), end_stream: False)
  let assert Ok(wire.DataWritten(
    state,
    [data_frame],
    remaining: <<>>,
    end_stream_sent: True,
  )) =
    wire.send_data(state, stream_id: 1, bytes: <<"abc":utf8>>, end_stream: True)
  assert data_frame == <<0, 0, 3, 0, 1, 0, 0, 0, 1, "abc":utf8>>
  assert connection.stream_state(wire.connection_state(state), 1)
    == stream_state.HalfClosedLocal
}

pub fn outbound_trailers_advance_the_opaque_wire_state_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(peer_settings) = preface.server_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, peer_settings)
  let assert Ok(wire.HeadersWritten(state, 1, _)) =
    wire.send_request_headers(state, get_request(), end_stream: False)
  let assert Ok(wire.DataWritten(state, _, <<>>, False)) =
    wire.send_data(state, stream_id: 1, bytes: <<"body">>, end_stream: False)

  let assert Ok(wire.HeadersWritten(state, 1, [trailer_frame])) =
    wire.send_trailers(state, 1, [#("checksum", "yes")])

  let assert Ok(decoder) = frame.decoder(16_384)
  let assert Ok(frame.FrameReady(
    frame.Header(_, frame.Headers, 0x5, 1),
    _,
    <<>>,
  )) = frame.feed(decoder, trailer_frame)
  assert connection.stream_state(wire.connection_state(state), 1)
    == stream_state.HalfClosedLocal
}

pub fn server_response_headers_advance_the_opaque_wire_state_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Server, connection_limits(), wire_limits(8))
  let assert Ok(initial) = preface.client_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, initial)
  let request_block = <<0x82, 0x87, 0x84, 0x01, 11, "example.com":utf8>>
  let assert Ok(request_frame) =
    frame.encode(frame.Headers, 0x5, 1, request_block, 16_384)
  let assert Ok(wire.Fed(state, [connection.HeadersReceived(_)])) =
    wire.feed(state, request_frame)
  let outgoing = response.Response(status: 200, headers: [], body: Nil)

  let assert Ok(wire.HeadersWritten(state, 1, [response_frame])) =
    wire.send_response_headers(state, 1, outgoing, end_stream: True)

  assert response_frame == <<0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88>>
  assert connection.stream_state(wire.connection_state(state), 1)
    == stream_state.Closed
}

pub fn processed_data_releases_credit_through_the_opaque_wire_state_test() -> Nil {
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits(8))
  let assert Ok(peer_settings) = preface.server_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, peer_settings)
  let assert Ok(wire.HeadersWritten(state, 1, _)) =
    wire.send_request_headers(state, get_request(), end_stream: True)
  let assert Ok(response_headers) =
    frame.encode(frame.Headers, 0x4, 1, <<0x88>>, 16_384)
  let assert Ok(response_data) =
    frame.encode(frame.Data, 0, 1, <<"abc":utf8>>, 16_384)
  let assert Ok(wire.Fed(state, _)) =
    wire.feed(state, <<response_headers:bits, response_data:bits>>)

  let assert Ok(wire.ReceiveCreditReleased(state, frames)) =
    wire.release_receive_credit(state, stream_id: 1, octets: 3)

  assert frames
    == [
      <<0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 3>>,
      <<0, 0, 4, 8, 0, 0, 0, 0, 1, 0, 0, 0, 3>>,
    ]
  assert connection.connection_receive_window(wire.connection_state(state))
    == 65_535
}

pub fn extended_connect_is_available_only_through_explicit_wire_capability_test() -> Nil {
  let assert Ok(state) =
    wire.new_with_capabilities(
      connection.Server,
      connection_limits(),
      connection.Capabilities(extended_connect_enabled: True),
      wire_limits(8),
    )
  let assert Ok(initial) = preface.client_initial_bytes([], 16_384)
  let assert Ok(wire.Fed(state, _)) = wire.feed(state, initial)
  let block = extended_connect_block()
  let assert Ok(headers) = frame.encode(frame.Headers, 0x5, 1, block, 16_384)

  let assert Ok(wire.Fed(_, [connection.HeadersReceived(_)])) =
    wire.feed(state, headers)
  Nil
}

pub fn pure_client_and_server_wire_states_complete_one_exchange_test() -> Nil {
  let assert Ok(client) =
    wire.new(connection.Client, connection_limits(), wire_limits(32))
  let assert Ok(server) =
    wire.new(connection.Server, connection_limits(), wire_limits(32))
  let assert Ok(wire.Started(client, client_initial)) =
    wire.initial_bytes(client, [])
  let assert Ok(wire.Started(server, server_initial)) =
    wire.initial_bytes(server, [])
  let assert Ok(wire.Fed(client, _)) = wire.feed(client, server_initial)
  let assert Ok(wire.Fed(server, _)) = wire.feed(server, client_initial)
  let assert Ok(wire.HeadersWritten(client, 1, request_frames)) =
    wire.send_request_headers(client, get_request(), end_stream: True)
  let assert Ok(wire.Fed(server, [connection.HeadersReceived(_)])) =
    wire.feed(server, bit_array.concat(request_frames))
  let outgoing =
    response.Response(status: 200, headers: [#("x-server", "h2")], body: Nil)
  let assert Ok(wire.HeadersWritten(server, 1, response_frames)) =
    wire.send_response_headers(server, 1, outgoing, end_stream: False)
  let assert Ok(wire.DataWritten(_, data_frames, <<>>, True)) =
    wire.send_data(server, stream_id: 1, bytes: <<"hello">>, end_stream: True)
  let assert Ok(wire.Fed(_, actions)) =
    wire.feed(
      client,
      list.append(response_frames, data_frames) |> bit_array.concat,
    )
  let assert Ok(response_state) =
    exchange_state.new(
      stream_id: 1,
      maximum_body_bytes: 16,
      maximum_informational: 1,
    )
  let assert Ok(exchange_state.Complete(_, incoming, [_])) =
    exchange_state.accept(response_state, actions)
  let assert Ok(#(<<"hello">>, [])) = body.read_all(incoming.body, 16)
  Nil
}
