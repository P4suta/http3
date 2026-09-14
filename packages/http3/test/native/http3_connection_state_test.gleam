import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleeunit/should
import http3/internal/native/capsule
import http3/internal/native/connection_state
import http3/internal/native/datagram
import http3/internal/native/drain
import http3/internal/native/frame
import http3/internal/native/message_stream
import http3/internal/native/origin
import http3/internal/native/priority
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction
import http3/internal/varint

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bootstraps_unique_critical_streams_with_settings_first_test() -> Nil {
  let assert Ok(state) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      False,
    )
  assert connection_state.bootstrap(state, 2, 2, 10)
    == Error(connection_state.DuplicateCriticalStreamId)
  assert connection_state.bootstrap(state, 3, 6, 10)
    == Error(connection_state.InvalidStreamId(3))

  let assert Ok(#(
    _,
    [
      connection_state.StreamBytes(2, control_bytes),
      connection_state.StreamBytes(6, encoder_bytes),
      connection_state.StreamBytes(10, decoder_bytes),
    ],
  )) = connection_state.bootstrap(state, 2, 6, 10)
  let assert Ok(#(0, settings_bytes)) = varint.decode(control_bytes)
  let assert Ok(#(frame.Settings(settings), <<>>)) =
    frame.decode(settings_bytes, frame.default_limits())
  assert settings
    == [
      frame.Setting(1, 4096),
      frame.Setting(6, 65_536),
      frame.Setting(7, 16),
      frame.Setting(8, 1),
      frame.Setting(0x33, 0),
      frame.Setting(0x21, 0),
    ]
  assert varint.decode(encoder_bytes) == Ok(#(2, <<>>))
  assert varint.decode(decoder_bytes) == Ok(#(3, <<>>))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn advertises_configured_qpack_limits_in_settings_test() -> Nil {
  let defaults = connection_state.default_config(connection_state.Client)
  let configured =
    connection_state.Config(
      ..defaults,
      settings: connection_state.Settings(
        ..defaults.settings,
        qpack_max_table_capacity: 1234,
        qpack_blocked_streams: 7,
      ),
      preferred_qpack_table_capacity: 1234,
    )
  let assert Ok(state) = connection_state.new(configured, False)
  let assert Ok(#(_, [connection_state.StreamBytes(2, control_bytes), ..])) =
    connection_state.bootstrap(state, 2, 6, 10)
  let assert Ok(#(0, settings_bytes)) = varint.decode(control_bytes)
  let assert Ok(#(frame.Settings(settings), <<>>)) =
    frame.decode(settings_bytes, frame.default_limits())
  assert list.contains(settings, frame.Setting(1, 1234))
  assert list.contains(settings, frame.Setting(7, 7))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_observes_typed_origin_set_from_server_control_stream_test() -> Nil {
  let #(client, _) = ready_pair()
  let origins = [origin.Origin("https", "example.com", None)]
  let assert Ok(#(_, [connection_state.OriginsReceived(received)])) =
    connection_state.receive_control_frame(client, frame.Origin(origins))
  assert received == origins
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn static_request_response_round_trip_cleans_transaction_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, [connection_state.RequestHeaders(0, _)])) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(client) = connection_state.finish_send(client, 0)
  let assert Ok(#(server, [connection_state.StreamFinished(0)])) =
    connection_state.receive_request_finish(server, 0)

  let assert Ok(#(server, response_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      response_headers(200, 3),
      False,
    )
  let assert Ok(#(server, data_bytes)) =
    connection_state.send_data(server, 0, <<"abc">>)
  let assert Ok(#(server, trailer_bytes)) =
    connection_state.send_trailers(
      server,
      0,
      [Header(<<"x-checksum">>, <<"ok">>, False)],
      False,
    )
  let assert Ok(_) = connection_state.finish_send(server, 0)

  let assert Ok(#(client, [connection_state.ResponseHeaders(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(response_bytes),
    )
  let assert Ok(#(client, [connection_state.Data(0, <<"abc">>)])) =
    connection_state.receive_request_frame(client, 0, decode_frame(data_bytes))
  let assert Ok(#(client, [connection_state.Trailers(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(trailer_bytes),
    )
  let assert Ok(#(client, [connection_state.StreamFinished(0)])) =
    connection_state.receive_request_finish(client, 0)
  assert connection_state.receive_request_finish(client, 0)
    == Error(connection_state.MissingTransaction(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn informational_final_body_and_trailers_are_ordered_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )

  let informational = [
    Header(<<":status">>, <<"103">>, False),
    Header(<<"link">>, <<"</style.css>">>, False),
  ]
  let assert Ok(#(server, informational_bytes)) =
    connection_state.send_response_headers(server, 0, informational, False)
  let assert Ok(#(server, final_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      [Header(<<":status">>, <<"200">>, False)],
      False,
    )
  let assert Ok(#(server, data_bytes)) =
    connection_state.send_data(server, 0, <<"response">>)
  let assert Ok(#(server, trailer_bytes)) =
    connection_state.send_trailers(
      server,
      0,
      [Header(<<"digest">>, <<"response-digest">>, False)],
      False,
    )
  let assert Ok(_) = connection_state.finish_send(server, 0)

  let assert Ok(#(client, [connection_state.InformationalResponse(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(informational_bytes),
    )
  let assert Ok(#(client, [connection_state.ResponseHeaders(0, _)])) =
    connection_state.receive_request_frame(client, 0, decode_frame(final_bytes))
  let assert Ok(#(client, [connection_state.Data(0, <<"response">>)])) =
    connection_state.receive_request_frame(client, 0, decode_frame(data_bytes))
  let assert Ok(#(_client, [connection_state.Trailers(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(trailer_bytes),
    )
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_blocking_resumes_after_ordered_encoder_instructions_test() -> Nil {
  let #(client, server) = ready_pair()
  let dynamic = Header(<<"x-dynamic">>, <<"indexed">>, False)
  let assert Ok(client) = connection_state.index_field(client, dynamic)
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(
      client,
      0,
      list.append(get_headers(), [dynamic]),
      True,
    )
  let assert Ok(#(client, Some(connection_state.StreamBytes(6, instructions)))) =
    connection_state.take_qpack_encoder_bytes(client)
  let assert Ok(#(instruction.SetDynamicTableCapacity(4096), instructions)) =
    instruction.decode_encoder(instructions, instruction.default_limits())
  let assert Ok(#(
    instruction.InsertWithLiteralName(<<"x-dynamic">>, <<"indexed">>),
    <<>>,
  )) = instruction.decode_encoder(instructions, instruction.default_limits())

  let assert Ok(#(server, [connection_state.HeadersBlocked(0, 1)])) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  // Reader actors for the request and QPACK encoder streams are independent.
  // DATA and FIN can therefore arrive while the field section is blocked;
  // retain them within the configured finite bound and replay in stream order.
  let assert Ok(#(server, [])) =
    connection_state.receive_request_frame(
      server,
      0,
      frame.Data(<<"queued":utf8>>),
    )
  let assert Ok(#(server, [])) =
    connection_state.receive_request_finish(server, 0)
  let assert Ok(#(server, [])) =
    connection_state.receive_qpack_encoder_instruction(
      server,
      instruction.SetDynamicTableCapacity(4096),
    )
  let assert Ok(#(
    server,
    [
      connection_state.RequestHeaders(0, _),
      connection_state.Data(0, <<"queued":utf8>>),
      connection_state.StreamFinished(0),
    ],
  )) =
    connection_state.receive_qpack_encoder_instruction(
      server,
      instruction.InsertWithLiteralName(<<"x-dynamic">>, <<"indexed">>),
    )

  let assert Ok(#(_, Some(connection_state.StreamBytes(11, feedback)))) =
    connection_state.take_qpack_decoder_bytes(server)
  let assert Ok(#(instruction.InsertCountIncrement(1), feedback)) =
    instruction.decode_decoder(feedback)
  let assert Ok(#(instruction.SectionAcknowledgement(0), <<>>)) =
    instruction.decode_decoder(feedback)
  let assert Ok(client) =
    connection_state.receive_qpack_decoder_instruction(
      client,
      instruction.InsertCountIncrement(1),
    )
  let assert Ok(_) =
    connection_state.receive_qpack_decoder_instruction(
      client,
      instruction.SectionAcknowledgement(0),
    )
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_blocked_frame_backlog_is_bounded_without_partial_growth_test() -> Nil {
  let client_config = connection_state.default_config(connection_state.Client)
  let server_config =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Server),
      maximum_frame_payload_bytes: 8,
    )
  let #(client, server) = ready_pair_with_configs(client_config, server_config)
  let dynamic = Header(<<"x-dynamic">>, <<"bounded">>, False)
  let assert Ok(client) = connection_state.index_field(client, dynamic)
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(
      client,
      0,
      list.append(get_headers(), [dynamic]),
      True,
    )
  let assert Ok(#(_client, Some(connection_state.StreamBytes(6, instructions)))) =
    connection_state.take_qpack_encoder_bytes(client)
  let assert Ok(#(capacity, instructions)) =
    instruction.decode_encoder(instructions, instruction.default_limits())
  let assert instruction.SetDynamicTableCapacity(4096) = capacity
  let assert Ok(#(insert, <<>>)) =
    instruction.decode_encoder(instructions, instruction.default_limits())
  let assert instruction.InsertWithLiteralName(_, _) = insert
  let assert Ok(#(server, [connection_state.HeadersBlocked(0, 1)])) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )

  let queued = frame.Data(<<1, 2, 3, 4>>)
  let assert Ok(queued_bytes) = frame.encode(queued)
  let retained = bit_array.byte_size(queued_bytes)
  let assert Ok(#(server, [])) =
    connection_state.receive_request_frame(server, 0, queued)
  assert connection_state.blocked_stream_bytes(server, 0) == retained
  assert connection_state.receive_request_frame(server, 0, frame.Data(<<5>>))
    == Error(connection_state.BlockedStreamBufferExceeded(8))
  // An admission failure returns no mutated State; callers retain the exact
  // previously-accounted value.
  assert connection_state.blocked_stream_bytes(server, 0) == retained

  let assert Ok(#(server, [])) =
    connection_state.receive_qpack_encoder_instruction(server, capacity)
  let assert Ok(#(
    server,
    [
      connection_state.RequestHeaders(0, _),
      connection_state.Data(0, <<1, 2, 3, 4>>),
    ],
  )) = connection_state.receive_qpack_encoder_instruction(server, insert)
  assert connection_state.blocked_stream_bytes(server, 0) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_blocked_backlogs_share_one_connection_byte_ceiling_test() -> Nil {
  let client_config = connection_state.default_config(connection_state.Client)
  let server_config =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Server),
      maximum_frame_payload_bytes: 8,
    )
  let #(client, server) = ready_pair_with_configs(client_config, server_config)
  let dynamic = Header(<<"x-dynamic">>, <<"aggregate">>, False)
  let assert Ok(client) = connection_state.index_field(client, dynamic)
  let fields = list.append(get_headers(), [dynamic])
  let assert Ok(#(client, first_request)) =
    connection_state.open_request(client, 0, fields, True)
  let assert Ok(#(_client, second_request)) =
    connection_state.open_request(client, 4, fields, True)
  let assert Ok(#(server, [connection_state.HeadersBlocked(0, 1)])) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(first_request),
    )
  let assert Ok(#(server, [connection_state.HeadersBlocked(4, 1)])) =
    connection_state.receive_request_frame(
      server,
      4,
      decode_frame(second_request),
    )
  let first = frame.Data(<<1, 2, 3, 4>>)
  let assert Ok(first_bytes) = frame.encode(first)
  let retained = bit_array.byte_size(first_bytes)
  let assert Ok(#(server, [])) =
    connection_state.receive_request_frame(server, 0, first)
  assert connection_state.blocked_connection_bytes(server) == retained
  assert connection_state.receive_request_frame(server, 4, frame.Data(<<5>>))
    == Error(connection_state.BlockedConnectionBufferExceeded(8))
  assert connection_state.blocked_stream_bytes(server, 4) == 0
  assert connection_state.blocked_connection_bytes(server) == retained
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resetting_qpack_blocked_stream_releases_backlog_and_references_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(client) = connection_state.finish_send(client, 0)

  let dynamic = Header(<<"x-reset-dynamic">>, <<"indexed">>, False)
  let assert Ok(server) = connection_state.index_field(server, dynamic)
  let assert Ok(#(server, response_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      list.append(response_headers(200, 3), [dynamic]),
      True,
    )
  let assert Ok(#(_server, Some(_instructions))) =
    connection_state.take_qpack_encoder_bytes(server)
  let assert Ok(#(client, [connection_state.HeadersBlocked(0, 1)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(response_bytes),
    )
  let assert Ok(#(client, [])) =
    connection_state.receive_request_frame(client, 0, frame.Data(<<"abc">>))
  assert connection_state.blocked_connection_bytes(client) > 0

  let assert Ok(client) = connection_state.receive_stream_reset(client, 0)
  assert connection_state.blocked_connection_bytes(client) == 0
  assert connection_state.receive_request_finish(client, 0)
    == Error(connection_state.MissingTransaction(0))
  let assert Ok(#(_, Some(connection_state.StreamBytes(10, feedback)))) =
    connection_state.take_qpack_decoder_bytes(client)
  let assert Ok(#(instruction.StreamCancellation(0), <<>>)) =
    instruction.decode_decoder(feedback)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_blocked_push_replays_data_and_fin_in_stream_order_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, maximum_push_id)) =
    connection_state.permit_pushes(client, 0)
  let assert Ok(#(server, [])) =
    connection_state.receive_control_frame(
      server,
      decode_frame(maximum_push_id),
    )
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(server, 0, promise_bytes)) =
    connection_state.promise_push(server, 0, get_headers(), False)
  let assert Ok(#(client, [connection_state.PushPromised(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(promise_bytes),
    )
  let assert Ok(#(server, preface)) =
    connection_state.open_push_stream(server, 15, 0, 10)
  let assert Ok(#(client, _, <<>>)) =
    connection_state.open_peer_unidirectional_stream(client, 15, preface, 10)

  let dynamic = Header(<<"x-push-dynamic">>, <<"indexed">>, False)
  let assert Ok(server) = connection_state.index_field(server, dynamic)
  let assert Ok(#(server, headers_bytes)) =
    connection_state.send_push_response_headers(
      server,
      15,
      list.append(response_headers(200, 3), [dynamic]),
      True,
    )
  let assert Ok(#(server, Some(connection_state.StreamBytes(7, instructions)))) =
    connection_state.take_qpack_encoder_bytes(server)
  let assert Ok(#(capacity, instructions)) =
    instruction.decode_encoder(instructions, instruction.default_limits())
  let assert instruction.SetDynamicTableCapacity(4096) = capacity
  let assert Ok(#(insert, <<>>)) =
    instruction.decode_encoder(instructions, instruction.default_limits())
  let assert instruction.InsertWithLiteralName(_, _) = insert
  let assert Ok(#(client, [connection_state.HeadersBlocked(15, 1)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(headers_bytes),
    )
  let assert Ok(#(_server, data_bytes)) =
    connection_state.send_push_data(server, 15, <<"css">>)
  let assert Ok(#(client, [])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(data_bytes),
    )
  let assert Ok(#(client, [])) =
    connection_state.close_peer_unidirectional_stream(client, 15)
  let assert Ok(#(client, [])) =
    connection_state.receive_qpack_encoder_instruction(client, capacity)
  let assert Ok(#(
    client,
    [
      connection_state.PushResponseHeaders(0, 15, _),
      connection_state.PushData(0, 15, <<"css">>),
      connection_state.PushFinished(0, 15),
    ],
  )) = connection_state.receive_qpack_encoder_instruction(client, insert)
  assert connection_state.blocked_stream_bytes(client, 15) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resetting_qpack_blocked_push_releases_lifecycle_and_references_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, maximum_push_id)) =
    connection_state.permit_pushes(client, 0)
  let assert Ok(#(server, [])) =
    connection_state.receive_control_frame(
      server,
      decode_frame(maximum_push_id),
    )
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(server, 0, promise_bytes)) =
    connection_state.promise_push(server, 0, get_headers(), False)
  let assert Ok(#(client, [connection_state.PushPromised(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(promise_bytes),
    )
  let assert Ok(#(server, preface)) =
    connection_state.open_push_stream(server, 15, 0, 10)
  let assert Ok(#(client, _, <<>>)) =
    connection_state.open_peer_unidirectional_stream(client, 15, preface, 10)

  let dynamic = Header(<<"x-reset-push">>, <<"indexed">>, False)
  let assert Ok(server) = connection_state.index_field(server, dynamic)
  let assert Ok(#(server, headers_bytes)) =
    connection_state.send_push_response_headers(
      server,
      15,
      list.append(response_headers(200, 3), [dynamic]),
      True,
    )
  let assert Ok(#(_server, Some(_instructions))) =
    connection_state.take_qpack_encoder_bytes(server)
  let assert Ok(#(client, [connection_state.HeadersBlocked(15, 1)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(headers_bytes),
    )
  let assert Ok(#(client, [])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      frame.Data(<<"css">>),
    )
  assert connection_state.blocked_connection_bytes(client) > 0

  let assert Ok(client) = connection_state.receive_stream_reset(client, 15)
  assert connection_state.blocked_connection_bytes(client) == 0
  assert connection_state.receive_push_stream_frame(
      client,
      15,
      frame.Data(<<>>),
    )
    == Error(connection_state.MissingTransaction(15))
  let assert Ok(#(_, Some(connection_state.StreamBytes(10, feedback)))) =
    connection_state.take_qpack_decoder_bytes(client)
  let assert Ok(#(instruction.StreamCancellation(15), <<>>)) =
    instruction.decode_decoder(feedback)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_response_body_overrun_before_stream_finish_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(server, response_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      response_headers(200, 3),
      False,
    )
  let assert Ok(#(_, data_bytes)) =
    connection_state.send_data(server, 0, <<"abc">>)
  let assert Ok(#(client, _)) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(response_bytes),
    )
  let assert frame.Data(_) = decode_frame(data_bytes)
  assert connection_state.receive_request_frame(
      client,
      0,
      frame.Data(<<"four">>),
    )
    == Error(
      connection_state.MessageFailure(message_stream.ContentLengthExceeded(3, 4)),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn head_response_reports_length_but_rejects_data_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, head_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(_, response_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      response_headers(200, 999),
      False,
    )
  let assert Ok(#(client, _)) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(response_bytes),
    )
  assert connection_state.receive_request_frame(client, 0, frame.Data(<<1>>))
    == Error(
      connection_state.MessageFailure(message_stream.ContentLengthExceeded(0, 1)),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_push_round_trip_uses_a_bounded_unidirectional_stream_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, maximum_push_id)) =
    connection_state.permit_pushes(client, 0)
  let assert Ok(#(server, [])) =
    connection_state.receive_control_frame(
      server,
      decode_frame(maximum_push_id),
    )
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )

  let promised = request_headers_for_path(<<"GET">>, <<"/asset.css">>)
  let assert Ok(#(server, 0, promise_bytes)) =
    connection_state.promise_push(server, 0, promised, False)
  let assert Ok(#(client, [connection_state.PushPromised(0, _)])) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(promise_bytes),
    )
  let assert Ok(#(server, preface)) =
    connection_state.open_push_stream(server, 15, 0, 10)
  let assert Ok(#(client, _, <<>>)) =
    connection_state.open_peer_unidirectional_stream(client, 15, preface, 10)

  let misplaced_priority =
    priority.to_frame(priority.PushUpdate(0, priority.Priority(0, True)))
    |> should.be_ok
  assert connection_state.receive_push_stream_frame(
      client,
      15,
      misplaced_priority,
    )
    == Error(connection_state.FrameUnexpected)

  let assert Ok(#(server, headers_bytes)) =
    connection_state.send_push_response_headers(
      server,
      15,
      response_headers(200, 3),
      False,
    )
  let assert Ok(#(server, data_bytes)) =
    connection_state.send_push_data(server, 15, <<"css">>)
  let assert Ok(#(server, trailer_bytes)) =
    connection_state.send_push_trailers(
      server,
      15,
      [Header(<<"x-push">>, <<"done">>, False)],
      False,
    )
  let assert Ok(_) = connection_state.finish_push_send(server, 15)
  let assert Ok(#(client, [connection_state.PushResponseHeaders(0, 15, _)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(headers_bytes),
    )
  let assert Ok(#(client, [connection_state.PushData(0, 15, <<"css">>)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(data_bytes),
    )
  let assert Ok(#(client, [connection_state.PushTrailers(0, 15, _)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(trailer_bytes),
    )
  let assert Ok(#(client, [connection_state.PushFinished(0, 15)])) =
    connection_state.close_peer_unidirectional_stream(client, 15)
  assert connection_state.receive_push_stream_frame(
      client,
      15,
      frame.Data(<<>>),
    )
    == Error(connection_state.MissingTransaction(15))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reordered_push_stream_waits_for_promise_and_pending_fin_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, maximum_push_id)) =
    connection_state.permit_pushes(client, 0)
  let assert Ok(#(server, [])) =
    connection_state.receive_control_frame(
      server,
      decode_frame(maximum_push_id),
    )
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let promised = request_headers_for_path(<<"GET">>, <<"/early">>)
  let assert Ok(#(server, 0, promise_bytes)) =
    connection_state.promise_push(server, 0, promised, False)
  let assert Ok(#(server, preface)) =
    connection_state.open_push_stream(server, 15, 0, 10)
  let assert Ok(#(client, _, <<>>)) =
    connection_state.open_peer_unidirectional_stream(client, 15, preface, 10)
  let assert Ok(#(_, headers_bytes)) =
    connection_state.send_push_response_headers(
      server,
      15,
      response_headers(200, 0),
      False,
    )

  let assert Ok(#(client, [connection_state.PushAwaitingPromise(0, 15)])) =
    connection_state.receive_push_stream_frame(
      client,
      15,
      decode_frame(headers_bytes),
    )
  let assert Ok(#(client, [])) =
    connection_state.close_peer_unidirectional_stream(client, 15)
  let assert Ok(#(
    _,
    [
      connection_state.PushPromised(0, _),
      connection_state.PushResponseHeaders(0, 15, _),
      connection_state.PushFinished(0, 15),
    ],
  )) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(promise_bytes),
    )
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cancels_and_expires_push_streams_deterministically_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, maximum_push_id)) =
    connection_state.permit_pushes(client, 1)
  let assert Ok(#(server, [])) =
    connection_state.receive_control_frame(
      server,
      decode_frame(maximum_push_id),
    )
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(server, 0, promise_bytes)) =
    connection_state.promise_push(server, 0, get_headers(), False)
  let assert Ok(#(client, _)) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(promise_bytes),
    )
  let assert Ok(#(server, preface)) =
    connection_state.open_push_stream(server, 15, 0, 10)
  let assert Ok(#(client, _, _)) =
    connection_state.open_peer_unidirectional_stream(client, 15, preface, 10)
  let assert Ok(#(client, cancel_bytes, Some(15))) =
    connection_state.cancel_push(client, 0)
  let assert Ok(#(
    _,
    [
      connection_state.PushCancelled(0),
      connection_state.PushStreamCancellationRequested(0, 15),
    ],
  )) =
    connection_state.receive_control_frame(server, decode_frame(cancel_bytes))

  let assert Ok(#(client, _, _)) =
    connection_state.open_peer_unidirectional_stream(client, 19, <<1, 1>>, 20)
  let assert Ok(#(client, [])) =
    connection_state.expire_pending_pushes(client, 10_019)
  let assert Ok(#(_, [19])) =
    connection_state.expire_pending_pushes(client, 10_020)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn binds_http_datagrams_to_an_explicit_extension_test() -> Nil {
  let #(client, server, extension) = open_datagram_tunnel()
  let assert Ok(encoded) = connection_state.send_datagram(client, 0, <<"udp">>)
  assert connection_state.receive_datagram(server, encoded)
    == Ok(
      connection_state.DatagramDelivered(
        datagram.Received(0, extension, <<"udp">>),
      ),
    )
  assert connection_state.receive_capsule(
      server,
      0,
      capsule.Datagram(<<"reliable">>),
    )
    == Ok(
      datagram.DatagramReceived(datagram.Received(0, extension, <<"reliable">>)),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_http_datagram_stream_lifecycle_test() -> Nil {
  let #(client, server, _) = open_datagram_tunnel()
  let assert Ok(encoded) =
    connection_state.send_datagram(client, 0, <<"before-fin">>)

  let assert Ok(client) = connection_state.finish_send(client, 0)
  assert connection_state.send_datagram(client, 0, <<"after-fin">>)
    == Error(connection_state.DatagramFailure(datagram.SendSideClosed(0)))

  let assert Ok(#(server, [connection_state.StreamFinished(0)])) =
    connection_state.receive_request_finish(server, 0)
  assert connection_state.receive_datagram(server, encoded)
    == Ok(connection_state.DatagramDropped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn distinguishes_future_and_semantically_unassociated_datagrams_test() -> Nil {
  let #(client, server) = datagram_ready_pair()
  assert connection_state.receive_datagram(server, <<1, "future">>)
    == Ok(connection_state.DatagramDropped)

  let assert Ok(#(_, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  assert connection_state.receive_datagram(server, <<0, "forbidden">>)
    == Ok(connection_state.DatagramRequestRejected(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn schedules_responses_and_times_out_graceful_drain_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(client, first)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(_, second)) =
    connection_state.open_request(client, 4, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(server, 0, decode_frame(first))
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(server, 4, decode_frame(second))
  let assert Ok(server) = connection_state.set_response_ready(server, 0, True)
  let assert Ok(server) = connection_state.set_response_ready(server, 4, True)
  let assert Some(#(server, 0)) = connection_state.next_response_stream(server)
  let assert Ok(#(server, _)) = connection_state.start_drain(server, 0)
  assert connection_state.drain_phase(server) == drain.LocalGoAway
  let assert Ok(#(server, _, [4])) = connection_state.refine_drain(server, 4)
  let assert Ok(#(server, [0])) =
    connection_state.on_drain_timer(server, 30_000)
  let assert Ok(server) = connection_state.close_drained(server)
  assert connection_state.drain_phase(server) == drain.Closed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc9218_priority_updates_reject_unadmitted_request_and_push_ids_test() -> Nil {
  let client_config = connection_state.default_config(connection_state.Client)
  let server_defaults = connection_state.default_config(connection_state.Server)
  let server_config =
    connection_state.Config(
      ..server_defaults,
      maximum_transactions: 2,
      maximum_pushes: 2,
    )
  let #(client, server) = ready_pair_with_configs(client_config, server_config)
  assert connection_state.pending_priority_count(server) == 0
  assert connection_state.maximum_retained_priority_stream_id(server) == 4

  let accepted_future =
    priority.to_frame(priority.RequestUpdate(4, priority.Priority(0, True)))
    |> should.be_ok
  let assert Ok(#(server, [_])) =
    connection_state.receive_control_frame(server, accepted_future)
  assert connection_state.pending_priority_count(server) == 1

  // With a two-request admission window, request stream IDs 0 and 4 are the
  // only future IDs whose priority can be retained. A peer cannot use a
  // priority update to allocate state for stream 8.
  let beyond_stream_limit =
    priority.to_frame(priority.RequestUpdate(8, priority.Priority(1, False)))
    |> should.be_ok
  assert connection_state.receive_control_frame(server, beyond_stream_limit)
    == Error(connection_state.PriorityFailure(priority.InvalidElementId(8)))
  assert connection_state.pending_priority_count(server) == 1

  // Push updates are meaningful only for a Push ID this server promised.
  let unpromised_push =
    priority.to_frame(priority.PushUpdate(0, priority.Priority(2, True)))
    |> should.be_ok
  assert connection_state.receive_control_frame(server, unpromised_push)
    == Error(connection_state.PriorityFailure(priority.InvalidElementId(0)))

  // A server is forbidden from sending either PRIORITY_UPDATE variant.
  let forbidden_server_update =
    priority.to_frame(priority.RequestUpdate(0, priority.Priority(3, False)))
    |> should.be_ok
  assert connection_state.receive_control_frame(client, forbidden_server_update)
    == Error(connection_state.FrameUnexpected)

  // Opening the prioritized stream consumes the pending value and slides the
  // finite future window without tying it to absolute stream IDs forever.
  let assert Ok(#(client, first_request)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(_client, second_request)) =
    connection_state.open_request(client, 4, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(first_request),
    )
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      4,
      decode_frame(second_request),
    )
  assert connection_state.pending_priority_count(server) == 0
  assert connection_state.maximum_retained_priority_stream_id(server) == 12
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc9218_priority_update_on_request_stream_is_frame_unexpected_test() -> Nil {
  let #(client, server) = ready_pair()
  let assert Ok(#(_, request_bytes)) =
    connection_state.open_request(client, 0, get_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let misplaced =
    priority.to_frame(priority.RequestUpdate(0, priority.Priority(0, True)))
    |> should.be_ok

  assert connection_state.receive_request_frame(server, 0, misplaced)
    == Error(connection_state.FrameUnexpected)
}

fn ready_pair() -> #(connection_state.State, connection_state.State) {
  ready_pair_with_configs(
    connection_state.default_config(connection_state.Client),
    connection_state.default_config(connection_state.Server),
  )
}

fn datagram_ready_pair() -> #(connection_state.State, connection_state.State) {
  let client_defaults = connection_state.default_config(connection_state.Client)
  let server_defaults = connection_state.default_config(connection_state.Server)
  let client_config =
    connection_state.Config(
      ..client_defaults,
      settings: connection_state.Settings(
        ..client_defaults.settings,
        h3_datagram: True,
      ),
    )
  let server_config =
    connection_state.Config(
      ..server_defaults,
      settings: connection_state.Settings(
        ..server_defaults.settings,
        h3_datagram: True,
      ),
    )
  let assert Ok(client) = connection_state.new(client_config, True)
  let assert Ok(server) = connection_state.new(server_config, True)
  let assert Ok(#(client, _)) = connection_state.bootstrap(client, 2, 6, 10)
  let assert Ok(#(server, _)) = connection_state.bootstrap(server, 3, 7, 11)
  let settings = frame.Settings([frame.Setting(8, 1), frame.Setting(0x33, 1)])
  let assert Ok(#(client, [_])) =
    connection_state.receive_control_frame(client, settings)
  let assert Ok(#(server, [_])) =
    connection_state.receive_control_frame(server, settings)
  #(client, server)
}

fn open_datagram_tunnel() -> #(
  connection_state.State,
  connection_state.State,
  datagram.Extension,
) {
  let #(client, server) = datagram_ready_pair()
  let assert Ok(#(client, request_bytes)) =
    connection_state.open_request(client, 0, connect_headers(), False)
  let assert Ok(#(server, _)) =
    connection_state.receive_request_frame(
      server,
      0,
      decode_frame(request_bytes),
    )
  let assert Ok(#(server, response_bytes)) =
    connection_state.send_response_headers(
      server,
      0,
      connect_response_headers(),
      False,
    )
  let assert Ok(#(client, _)) =
    connection_state.receive_request_frame(
      client,
      0,
      decode_frame(response_bytes),
    )
  let assert Ok(extension) = datagram.extension(<<"connect-udp">>)
  #(client, server, extension)
}

fn ready_pair_with_configs(
  client_config: connection_state.Config,
  server_config: connection_state.Config,
) -> #(connection_state.State, connection_state.State) {
  let assert Ok(client) = connection_state.new(client_config, False)
  let assert Ok(server) = connection_state.new(server_config, False)
  let assert Ok(#(client, _)) = connection_state.bootstrap(client, 2, 6, 10)
  let assert Ok(#(server, _)) = connection_state.bootstrap(server, 3, 7, 11)
  let settings =
    frame.Settings([
      frame.Setting(1, 4096),
      frame.Setting(6, 65_536),
      frame.Setting(7, 16),
      frame.Setting(8, 1),
      frame.Setting(0x33, 0),
    ])
  let assert Ok(#(client, [_])) =
    connection_state.receive_control_frame(client, settings)
  let assert Ok(#(server, [_])) =
    connection_state.receive_control_frame(server, settings)
  #(client, server)
}

fn get_headers() -> List(Header) {
  request_headers(<<"GET">>)
}

fn connect_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"CONNECT">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"example.test">>, False),
    Header(<<":path">>, <<"/masque">>, False),
    Header(<<":protocol">>, <<"connect-udp">>, False),
  ]
}

fn connect_response_headers() -> List(Header) {
  [Header(<<":status">>, <<"200">>, False)]
}

fn head_headers() -> List(Header) {
  request_headers(<<"HEAD">>)
}

fn request_headers(method: BitArray) -> List(Header) {
  request_headers_for_path(method, <<"/">>)
}

fn request_headers_for_path(method: BitArray, path: BitArray) -> List(Header) {
  [
    Header(<<":method">>, method, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"example.test">>, False),
    Header(<<":path">>, path, False),
  ]
}

fn response_headers(status: Int, content_length: Int) -> List(Header) {
  [
    Header(<<":status">>, int_bytes(status), False),
    Header(<<"content-length">>, int_bytes(content_length), False),
  ]
}

fn int_bytes(value: Int) -> BitArray {
  case value {
    3 -> <<"3">>
    200 -> <<"200">>
    999 -> <<"999">>
    _ -> <<"0">>
  }
}

fn decode_frame(bytes: BitArray) -> frame.Frame {
  let assert Ok(#(decoded, <<>>)) = frame.decode(bytes, frame.default_limits())
  decoded
}
