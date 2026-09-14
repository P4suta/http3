import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/body_length
import http/internal/http2/connection
import http/internal/http2/flow_control
import http/internal/http2/frame
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder
import http/internal/http2/hpack/encoder
import http/internal/http2/origin
import http/internal/http2/peer_settings
import http/internal/http2/priority
import http/internal/http2/stream_registry
import http/internal/http2/stream_state

pub fn main() -> Nil {
  gleeunit.main()
}

fn limits(
  maximum_outstanding_settings: Int,
  maximum_debug_bytes: Int,
  maximum_active_streams: Int,
) -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings:,
    maximum_debug_bytes:,
    maximum_active_streams:,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 1024,
      maximum_header_list_bytes: 4096,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: maximum_active_streams,
    ),
  )
}

fn request_block() -> BitArray {
  <<0x82, 0x87, 0x84, 0x01, 11, "example.com":utf8>>
}

fn request_block_with_content_length(length: String) -> BitArray {
  encode_fields([
    decoder.Header(<<":method">>, <<"POST">>, False),
    decoder.Header(<<":scheme">>, <<"https">>, False),
    decoder.Header(<<":path">>, <<"/upload">>, False),
    decoder.Header(<<":authority">>, <<"example.com">>, False),
    decoder.Header(<<"content-length">>, <<length:utf8>>, False),
  ])
}

fn request_block_with_priority(values: List(BitArray)) -> BitArray {
  let priority_fields =
    values
    |> list.map(fn(value) { decoder.Header(<<"priority">>, value, False) })
  encode_fields(list.append(
    [
      decoder.Header(<<":method">>, <<"GET">>, False),
      decoder.Header(<<":scheme">>, <<"https">>, False),
      decoder.Header(<<":path">>, <<"/asset">>, False),
      decoder.Header(<<":authority">>, <<"example.com">>, False),
    ],
    priority_fields,
  ))
}

fn trailer_block() -> BitArray {
  encode_fields([decoder.Header(<<"checksum">>, <<"ok">>, False)])
}

fn extended_connect_block() -> BitArray {
  encode_fields([
    decoder.Header(<<":method">>, <<"CONNECT">>, False),
    decoder.Header(<<":scheme">>, <<"https">>, False),
    decoder.Header(<<":path">>, <<"/chat">>, False),
    decoder.Header(<<":authority">>, <<"example.com">>, False),
    decoder.Header(<<":protocol">>, <<"websocket">>, False),
  ])
}

fn encode_fields(fields: List(decoder.Header)) -> BitArray {
  let assert Ok(state) = encoder.new(4096, 8192, False)
  let assert Ok(encoder.Encoded(_, block)) = encoder.encode(state, fields)
  block
}

pub fn first_peer_frame_must_be_non_ack_settings_test() -> Nil {
  let assert Ok(state) = connection.new(connection.Client, limits(4, 1024, 16))

  assert connection.receive_frame(state, frame.Header(8, frame.Ping, 0, 0), <<
      "12345678":utf8,
    >>)
    == Error(connection.ExpectedInitialSettings)
  assert connection.receive_frame(
      state,
      frame.Header(0, frame.Settings, 1, 0),
      <<>>,
    )
    == Error(connection.ExpectedInitialSettings)
}

pub fn initial_settings_are_applied_and_acknowledged_test() -> Nil {
  let assert Ok(state) = connection.new(connection.Client, limits(4, 1024, 16))
  let payload = <<0, 3, 0, 0, 0, 7, 0, 5, 0, 0, 128, 0>>
  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(
      state,
      frame.Header(12, frame.Settings, 0, 0),
      payload,
    )

  assert connection.received_initial_settings(state)
  assert peer_settings.maximum_concurrent_streams(connection.peer_settings(
      state,
    ))
    == Some(7)
  assert peer_settings.maximum_frame_size(connection.peer_settings(state))
    == 32_768
  assert actions
    == [
      connection.SendSettingsAcknowledgement,
      connection.PeerSettingsChanged(initial_window_delta: 0),
    ]
}

pub fn no_rfc7540_priorities_is_initial_only_and_value_is_pinned_test() -> Nil {
  let setting = <<0, 9, 0, 0, 0, 1>>
  let assert Ok(state) = connection.new(connection.Server, limits(4, 1024, 16))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(6, frame.Settings, 0, 0),
      setting,
    )
  assert peer_settings.rfc7540_priorities_disabled(connection.peer_settings(
    state,
  ))

  let assert Ok(connection.Transition(_, _)) =
    connection.receive_frame(
      state,
      frame.Header(6, frame.Settings, 0, 0),
      setting,
    )
  assert connection.receive_frame(state, frame.Header(6, frame.Settings, 0, 0), <<
      0,
      9,
      0,
      0,
      0,
      0,
    >>)
    == Error(connection.NoRfc7540PrioritiesChanged(
      previous: True,
      received: False,
    ))

  let state = ready(connection.Server)
  assert connection.receive_frame(
      state,
      frame.Header(6, frame.Settings, 0, 0),
      setting,
    )
    == Error(connection.NoRfc7540PrioritiesNotInitial)
}

pub fn disabled_legacy_priority_signals_are_ignored_test() -> Nil {
  let assert Ok(state) = connection.new(connection.Server, limits(4, 1024, 16))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(6, frame.Settings, 0, 0), <<
      0,
      9,
      0,
      0,
      0,
      1,
    >>)
  let assert Ok(connection.Transition(state, [])) =
    connection.receive_frame(state, frame.Header(5, frame.Priority, 0, 3), <<
      0:size(1),
      1:size(31),
      15,
    >>)

  let block = request_block()
  let prioritized = <<0:size(1), 0:size(31), 15, block:bits>>
  let assert Ok(connection.Transition(_, [connection.HeadersReceived(section)])) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(prioritized), frame.Headers, 0x24, 1),
      prioritized,
    )
  let assert header_codec.HeaderSection(_, _, _, None) = section
  Nil
}

pub fn settings_ack_must_match_a_locally_sent_settings_frame_test() -> Nil {
  let assert Ok(state) = connection.new(connection.Server, limits(1, 1024, 16))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(0, frame.Settings, 0, 0), <<>>)

  assert connection.receive_frame(
      state,
      frame.Header(0, frame.Settings, 1, 0),
      <<>>,
    )
    == Error(connection.UnexpectedSettingsAcknowledgement)

  let assert Ok(state) = connection.record_settings_sent(state)
  assert connection.outstanding_settings(state) == 1
  assert connection.record_settings_sent(state)
    == Error(connection.TooManyOutstandingSettings(maximum: 1))

  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(0, frame.Settings, 1, 0), <<>>)
  assert connection.outstanding_settings(state) == 0
  assert actions == [connection.SettingsAcknowledged]
}

pub fn invalid_connection_limits_are_rejected_test() -> Nil {
  assert connection.new(connection.Client, limits(0, 1, 16))
    == Error(connection.InvalidLimits)
  assert connection.new(connection.Client, limits(1, -1, 16))
    == Error(connection.InvalidLimits)
  assert connection.new(connection.Client, limits(1, 1, 0))
    == Error(connection.InvalidLimits)
}

fn ready(role: connection.Role) -> connection.State {
  let assert Ok(state) = connection.new(role, limits(4, 4, 16))
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(0, frame.Settings, 0, 0), <<>>)
  state
}

pub fn ping_is_acknowledged_without_echoing_an_ack_test() -> Nil {
  let state = ready(connection.Client)
  let data = <<"12345678":utf8>>
  let assert Ok(connection.Transition(_, actions)) =
    connection.receive_frame(state, frame.Header(8, frame.Ping, 0, 0), data)
  assert actions == [connection.SendPingAcknowledgement(data)]

  let assert Ok(connection.Transition(_, actions)) =
    connection.receive_frame(state, frame.Header(8, frame.Ping, 1, 0), data)
  assert actions == [connection.PingAcknowledged(data)]
}

pub fn origin_frames_are_typed_for_clients_and_ignored_when_inapplicable_test() -> Nil {
  let payload = <<19:size(16), "https://example.com":utf8>>
  let client = ready(connection.Client)
  let assert Ok(connection.Transition(_, actions)) =
    connection.receive_frame(
      client,
      frame.Header(21, frame.Origin, 0, 0),
      payload,
    )
  assert actions
    == [
      connection.OriginsReceived([
        origin.Origin("https", "example.com", None),
      ]),
    ]

  let assert Ok(connection.Transition(_, [])) =
    connection.receive_frame(
      client,
      frame.Header(21, frame.Origin, 0, 1),
      payload,
    )
  let assert Ok(connection.Transition(_, [])) =
    connection.receive_frame(
      client,
      frame.Header(21, frame.Origin, 0x1, 0),
      payload,
    )
  let assert Ok(connection.Transition(_, [connection.OriginsReceived(_)])) =
    connection.receive_frame(
      client,
      frame.Header(21, frame.Origin, 0x10, 0),
      payload,
    )
  let server = ready(connection.Server)
  let assert Ok(connection.Transition(_, [])) =
    connection.receive_frame(
      server,
      frame.Header(21, frame.Origin, 0, 0),
      payload,
    )
  Nil
}

pub fn priority_updates_are_server_only_latest_and_bounded_test() -> Nil {
  let update = <<0:size(1), 1:size(31), "u=0, i":utf8>>
  let server = ready(connection.Server)
  let assert Ok(connection.Transition(server, actions)) =
    connection.receive_frame(
      server,
      frame.Header(10, frame.PriorityUpdate, 0, 0),
      update,
    )
  assert actions
    == [
      connection.PriorityUpdated(
        stream_id: 1,
        priority: priority.Priority(0, True),
      ),
    ]
  assert connection.stream_priority(server, 1)
    == Some(priority.Priority(0, True))

  let replacement = <<0:size(1), 1:size(31), "u=6":utf8>>
  let assert Ok(connection.Transition(server, _)) =
    connection.receive_frame(
      server,
      frame.Header(7, frame.PriorityUpdate, 0, 0),
      replacement,
    )
  assert connection.stream_priority(server, 1)
    == Some(priority.Priority(6, False))

  let client = ready(connection.Client)
  assert connection.receive_frame(
      client,
      frame.Header(10, frame.PriorityUpdate, 0, 0),
      update,
    )
    == Error(connection.PriorityUpdateForbidden)

  let assert Ok(limited) = connection.new(connection.Server, limits(4, 4, 1))
  let assert Ok(connection.Transition(limited, _)) =
    connection.receive_frame(
      limited,
      frame.Header(0, frame.Settings, 0, 0),
      <<>>,
    )
  let assert Ok(connection.Transition(limited, _)) =
    connection.receive_frame(
      limited,
      frame.Header(10, frame.PriorityUpdate, 0, 0),
      update,
    )
  assert connection.receive_frame(
      limited,
      frame.Header(7, frame.PriorityUpdate, 0, 0),
      <<0:size(1), 3:size(31), "u=2":utf8>>,
    )
    == Error(connection.TooManyPrioritizedStreams(maximum: 1))

  // Even-numbered targets are server push streams. A client is not allowed to
  // create priority state for an idle push stream that was never reserved.
  assert connection.receive_frame(
      server,
      frame.Header(7, frame.PriorityUpdate, 0, 0),
      <<0:size(1), 2:size(31), "u=1":utf8>>,
    )
    == Error(connection.InvalidPriorityTarget(stream_id: 2))
  Nil
}

pub fn request_priority_fields_apply_unless_a_newer_update_exists_test() -> Nil {
  let block = request_block_with_priority([<<"u=6">>, <<"i">>])
  let server = ready(connection.Server)
  let assert Ok(connection.Transition(server, actions)) =
    connection.receive_frame(
      server,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 1),
      block,
    )
  let assert [
    connection.PriorityUpdated(
      stream_id: 1,
      priority: priority.Priority(6, True),
    ),
    connection.HeadersReceived(_),
  ] = actions
  assert connection.stream_priority(server, 1)
    == Some(priority.Priority(6, True))

  let preupdated = ready(connection.Server)
  let update = <<0:size(1), 1:size(31), "u=0":utf8>>
  let assert Ok(connection.Transition(preupdated, _)) =
    connection.receive_frame(
      preupdated,
      frame.Header(7, frame.PriorityUpdate, 0, 0),
      update,
    )
  let block = request_block_with_priority([<<"u=7">>])
  let assert Ok(connection.Transition(preupdated, [_])) =
    connection.receive_frame(
      preupdated,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 1),
      block,
    )
  assert connection.stream_priority(preupdated, 1)
    == Some(priority.Priority(0, False))

  let malformed = request_block_with_priority([<<"u=1,">>])
  let assert Ok(connection.Transition(malformed_state, [_])) =
    connection.receive_frame(
      ready(connection.Server),
      frame.Header(bit_array.byte_size(malformed), frame.Headers, 0x5, 1),
      malformed,
    )
  assert connection.stream_priority(malformed_state, 1) == None
}

pub fn connection_window_update_is_bounded_test() -> Nil {
  let state = ready(connection.Server)
  assert connection.connection_send_window(state) == 65_535

  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(4, frame.WindowUpdate, 0, 0), <<
      0:size(1),
      10:size(31),
    >>)
  assert connection.connection_send_window(state) == 65_545
  assert actions == [connection.ConnectionWindowIncreased(available: 65_545)]

  assert connection.receive_frame(
      state,
      frame.Header(4, frame.WindowUpdate, 0, 0),
      <<0:size(1), 0x7fff_ffff:size(31)>>,
    )
    == Error(connection.FlowControlFailure(flow_control.WindowOverflow))
}

pub fn goaway_enters_drain_and_last_stream_id_cannot_increase_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(11, frame.GoAway, 0, 0), <<
      0:size(1),
      9:size(31),
      0:size(32),
      "bye":utf8,
    >>)
  assert connection.draining(state)
  assert connection.peer_last_stream_id(state) == Some(9)
  assert actions
    == [
      connection.PeerGoAway(last_stream_id: 9, error_code: 0, debug_data: <<
        "bye":utf8,
      >>),
    ]

  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(8, frame.GoAway, 0, 0), <<
      0:size(1),
      7:size(31),
      0:size(32),
    >>)
  assert connection.peer_last_stream_id(state) == Some(7)
  assert connection.receive_frame(state, frame.Header(8, frame.GoAway, 0, 0), <<
      0:size(1),
      8:size(31),
      0:size(32),
    >>)
    == Error(connection.IncreasingGoAwayLastStreamId(previous: 7, received: 8))
}

pub fn unknown_frame_types_are_ignored_after_initial_settings_test() -> Nil {
  let state = ready(connection.Server)
  let assert Ok(connection.Transition(_, actions)) =
    connection.receive_frame(
      state,
      frame.Header(3, frame.Unknown(42), 0xff, 99),
      <<1, 2, 3>>,
    )
  assert actions == [connection.IgnoredUnknownFrame(frame_type: 42)]
}

pub fn server_headers_and_data_advance_stream_and_both_receive_windows_test() -> Nil {
  let state = ready(connection.Server)
  let block = request_block()
  let assert Ok(connection.Transition(
    state,
    [connection.HeadersReceived(section)],
  )) =
    connection.receive_frame(
      state,
      frame.Header(16, frame.Headers, 0x4, 1),
      block,
    )
  let assert header_codec.HeaderSection(
    1,
    False,
    header_semantics.Validated(
      header_semantics.RequestControlData(control),
      [],
      _,
    ),
    _,
  ) = section
  assert control.method == <<"GET">>
  assert connection.stream_state(state, 1) == stream_state.Open

  let payload = <<2, "abc":utf8, 0, 0>>
  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(
      state,
      frame.Header(6, frame.Data, 0x9, 1),
      payload,
    )
  assert actions
    == [
      connection.DataReceived(
        stream_id: 1,
        bytes: <<"abc":utf8>>,
        end_stream: True,
        flow_controlled_bytes: 6,
      ),
    ]
  assert connection.connection_receive_window(state) == 65_529
  assert connection.stream_receive_window(state, 1) == Ok(65_529)
  assert connection.stream_state(state, 1) == stream_state.HalfClosedRemote
}

pub fn local_streams_obey_goaway_and_peer_initial_window_changes_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.StreamOpened(state, 1)) =
    connection.open_local_stream(state, end_stream: False)
  assert connection.stream_send_window(state, 1) == Ok(65_535)

  let let_initial_window_zero = <<0, 4, 0, 0, 0, 0>>
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(6, frame.Settings, 0, 0),
      let_initial_window_zero,
    )
  assert connection.stream_send_window(state, 1) == Ok(0)

  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(8, frame.GoAway, 0, 0), <<
      0:size(1),
      1:size(31),
      0:size(32),
    >>)
  assert connection.open_local_stream(state, end_stream: False)
    == Error(connection.ConnectionDraining)
}

pub fn stream_window_updates_are_applied_only_to_active_streams_test() -> Nil {
  let state = ready(connection.Client)
  let assert Ok(connection.StreamOpened(state, 1)) =
    connection.open_local_stream(state, end_stream: False)
  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(4, frame.WindowUpdate, 0, 1), <<
      0:size(1),
      10:size(31),
    >>)
  assert connection.stream_send_window(state, 1) == Ok(65_545)
  assert actions
    == [connection.StreamWindowIncreased(stream_id: 1, available: 65_545)]
  assert connection.receive_frame(
      state,
      frame.Header(4, frame.WindowUpdate, 0, 3),
      <<0:size(1), 1:size(31)>>,
    )
    == Error(
      connection.StreamFailure(stream_registry.UnknownStream(stream_id: 3)),
    )
}

pub fn legacy_priority_is_observed_without_opening_an_idle_stream_test() -> Nil {
  let state = ready(connection.Server)
  let assert Ok(connection.Transition(state, actions)) =
    connection.receive_frame(state, frame.Header(5, frame.Priority, 0, 3), <<
      1:size(1),
      1:size(31),
      255,
    >>)
  assert actions
    == [
      connection.LegacyPriorityReceived(
        stream_id: 3,
        exclusive: True,
        dependency: 1,
        weight: 256,
      ),
    ]
  assert connection.stream_state(state, 3) == stream_state.Idle
}

pub fn request_content_length_overrun_and_early_end_are_rejected_test() -> Nil {
  let state = ready(connection.Server)
  let block = request_block_with_content_length("3")
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
  assert connection.receive_frame(state, frame.Header(4, frame.Data, 0, 1), <<
      "abcd":utf8,
    >>)
    == Error(
      connection.BodyLengthFailure(body_length.BodyTooLong(
        expected: 3,
        received: 4,
      )),
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

  let fresh = ready(connection.Server)
  assert connection.receive_frame(
      fresh,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x5, 1),
      block,
    )
    == Error(
      connection.BodyLengthFailure(body_length.LengthMismatch(
        expected: 3,
        received: 0,
      )),
    )
}

pub fn exact_request_content_length_can_finish_with_trailers_test() -> Nil {
  let state = ready(connection.Server)
  let block = request_block_with_content_length("3")
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(state, frame.Header(3, frame.Data, 0, 1), <<
      "abc":utf8,
    >>)
  let trailers = trailer_block()
  let assert Ok(connection.Transition(state, _)) =
    connection.receive_frame(
      state,
      frame.Header(bit_array.byte_size(trailers), frame.Headers, 0x5, 1),
      trailers,
    )
  assert connection.stream_state(state, 1) == stream_state.HalfClosedRemote
}

pub fn extended_connect_requires_an_explicit_server_capability_test() -> Nil {
  let block = extended_connect_block()
  let default = ready(connection.Server)
  assert connection.receive_frame(
      default,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
    == Error(
      connection.HeaderFailure(header_codec.SemanticsFailure(
        header_semantics.ExtendedConnectNotEnabled,
      )),
    )

  let assert Ok(enabled) =
    connection.new_with_capabilities(
      connection.Server,
      limits(4, 4, 16),
      connection.Capabilities(extended_connect_enabled: True),
    )
  let assert Ok(connection.Transition(enabled, _)) =
    connection.receive_frame(
      enabled,
      frame.Header(0, frame.Settings, 0, 0),
      <<>>,
    )
  let assert Ok(connection.Transition(_, [connection.HeadersReceived(section)])) =
    connection.receive_frame(
      enabled,
      frame.Header(bit_array.byte_size(block), frame.Headers, 0x4, 1),
      block,
    )
  let assert header_codec.HeaderSection(
    _,
    _,
    header_semantics.Validated(
      header_semantics.RequestControlData(control),
      _,
      _,
    ),
    _,
  ) = section
  assert control.protocol == Some(<<"websocket">>)
}
