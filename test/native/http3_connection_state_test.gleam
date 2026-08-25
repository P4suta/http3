import gleam/list
import gleam/option.{Some}
import gleam_quic/varint
import http3/internal/native/capsule
import http3/internal/native/connection_state
import http3/internal/native/datagram
import http3/internal/native/drain
import http3/internal/native/frame
import http3/internal/native/message_stream
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction

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
  let assert Ok(#(server, [])) =
    connection_state.receive_qpack_encoder_instruction(
      server,
      instruction.SetDynamicTableCapacity(4096),
    )
  let assert Ok(#(server, [connection_state.RequestHeaders(0, _)])) =
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
  let config =
    connection_state.Config(
      ..connection_state.default_config(connection_state.Client),
      settings: connection_state.Settings(4096, 65_536, 16, True, True, True),
    )
  let assert Ok(state) = connection_state.new(config, True)
  let assert Ok(#(state, _)) = connection_state.bootstrap(state, 2, 6, 10)
  let assert Ok(#(state, _)) =
    connection_state.receive_control_frame(
      state,
      frame.Settings([
        frame.Setting(0x33, 1),
      ]),
    )
  let assert Ok(extension) = datagram.extension(<<"connect-udp">>)
  let assert Ok(state) =
    connection_state.associate_datagrams(
      state,
      0,
      extension,
      datagram.UnreliableAndCapsules,
    )
  let assert Ok(encoded) = connection_state.send_datagram(state, 0, <<"udp">>)
  assert connection_state.receive_datagram(state, encoded)
    == Ok(datagram.Received(0, extension, <<"udp">>))
  assert connection_state.receive_capsule(
      state,
      0,
      capsule.Datagram(<<"reliable">>),
    )
    == Ok(
      datagram.DatagramReceived(datagram.Received(0, extension, <<"reliable">>)),
    )
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

fn ready_pair() -> #(connection_state.State, connection_state.State) {
  let assert Ok(client) =
    connection_state.new(
      connection_state.default_config(connection_state.Client),
      False,
    )
  let assert Ok(server) =
    connection_state.new(
      connection_state.default_config(connection_state.Server),
      False,
    )
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
