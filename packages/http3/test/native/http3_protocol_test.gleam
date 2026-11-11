import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit/should
import http3/internal/native/connection_state as http3_state
import http3/internal/native/control
import http3/internal/native/datagram
import http3/internal/native/drain
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/header_semantics
import http3/internal/native/message_stream
import http3/internal/native/priority
import http3/internal/native/protocol
import http3/internal/native/push
import http3/internal/native/settings_memory
import http3/internal/native/stream_registry
import http3/internal/qpack/decoder
import http3/internal/qpack/encoder
import http3/internal/qpack/field_section
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction
import http3/internal/varint

type Write {
  Write(identifier: Int, bytes: BitArray, finished: Bool)
}

type ResourceOperation {
  ResourceWrite(Write)
  ResourceAbort(identifier: Int, application_error_code: Int)
}

type FakeConnection {
  FakeConnection(
    next_bidirectional: Int,
    next_unidirectional: Int,
    writes: List(Write),
    registered: Dict(Int, Nil),
    datagrams: List(BitArray),
    aborts: List(#(Int, Int)),
    operations: List(ResourceOperation),
  )
}

fn resource() -> protocol.Resource(FakeConnection) {
  protocol.Resource(
    open_bidirectional: fn(connection) {
      Ok(#(
        FakeConnection(
          ..connection,
          next_bidirectional: connection.next_bidirectional + 4,
        ),
        connection.next_bidirectional,
      ))
    },
    open_unidirectional: fn(connection) {
      Ok(#(
        FakeConnection(
          ..connection,
          next_unidirectional: connection.next_unidirectional + 4,
        ),
        connection.next_unidirectional,
      ))
    },
    write: fn(connection, identifier, bytes, finished) {
      let recorded_write = Write(identifier, bytes, finished)
      Ok(
        FakeConnection(
          ..connection,
          writes: list.append(connection.writes, [recorded_write]),
          operations: list.append(connection.operations, [
            ResourceWrite(recorded_write),
          ]),
        ),
      )
    },
    abort: fn(connection, identifier, application_error_code) {
      Ok(
        FakeConnection(
          ..connection,
          aborts: list.append(connection.aborts, [
            #(identifier, application_error_code),
          ]),
          operations: list.append(connection.operations, [
            ResourceAbort(identifier, application_error_code),
          ]),
        ),
      )
    },
    send_datagram: fn(connection, bytes) {
      Ok(
        FakeConnection(..connection, datagrams: [bytes, ..connection.datagrams]),
      )
    },
    maximum_datagram_size: fn(_) { Ok(1200) },
    guaranteed_datagram_size: fn(_) { Ok(600) },
  )
}

fn connection(role: http3_state.Role) -> FakeConnection {
  case role {
    http3_state.Client -> FakeConnection(0, 2, [], dict.new(), [], [], [])
    http3_state.Server -> FakeConnection(1, 3, [], dict.new(), [], [], [])
  }
}

fn start(role: http3_state.Role) -> protocol.State(FakeConnection) {
  protocol.start(
    resource(),
    connection(role),
    http3_state.default_config(role),
    False,
  )
  |> should.be_ok
}

fn start_datagrams(role: http3_state.Role) -> protocol.State(FakeConnection) {
  let defaults = http3_state.default_config(role)
  protocol.start(
    resource(),
    connection(role),
    http3_state.Config(
      ..defaults,
      settings: http3_state.Settings(..defaults.settings, h3_datagram: True),
    ),
    True,
  )
  |> should.be_ok
}

fn transfer(
  source: protocol.State(FakeConnection),
  target: protocol.State(FakeConnection),
) -> Result(
  #(protocol.State(FakeConnection), protocol.State(FakeConnection)),
  protocol.Error,
) {
  let source_connection = protocol.connection(source)
  let source =
    protocol.with_connection(
      source,
      FakeConnection(..source_connection, writes: [], operations: []),
    )
  use target <- result.try(transfer_writes(target, source_connection.writes))
  Ok(#(source, target))
}

fn transfer_writes(
  target: protocol.State(FakeConnection),
  writes: List(Write),
) -> Result(protocol.State(FakeConnection), protocol.Error) {
  case writes {
    [] -> Ok(target)
    [Write(identifier, bytes, finished), ..rest] -> {
      let connection = protocol.connection(target)
      use target <- result.try(
        case dict.has_key(connection.registered, identifier) {
          True -> Ok(target)
          False -> {
            let connection =
              FakeConnection(
                ..connection,
                registered: dict.insert(connection.registered, identifier, Nil),
              )
            protocol.register_peer_stream(
              protocol.with_connection(target, connection),
              identifier,
            )
          }
        },
      )
      use target <- result.try(protocol.receive_stream(
        target,
        identifier,
        bytes,
        finished,
        1,
      ))
      transfer_writes(target, rest)
    }
  }
}

fn request_headers() -> List(Header) {
  [
    Header(<<":method":utf8>>, <<"POST":utf8>>, False),
    Header(<<":scheme":utf8>>, <<"https":utf8>>, False),
    Header(<<":authority":utf8>>, <<"localhost":utf8>>, False),
    Header(<<":path":utf8>>, <<"/public-core":utf8>>, False),
    Header(<<"content-length":utf8>>, <<"4":utf8>>, False),
  ]
}

fn push_associated_request_headers() -> List(Header) {
  [
    Header(<<":method">>, <<"GET">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/index">>, False),
  ]
}

fn promised_request(
  method: BitArray,
  scheme: BitArray,
  authority: BitArray,
  extra: List(Header),
) -> List(Header) {
  list.append(
    [
      Header(<<":method">>, method, False),
      Header(<<":scheme">>, scheme, False),
      Header(<<":authority">>, authority, False),
      Header(<<":path">>, <<"/asset">>, False),
    ],
    extra,
  )
}

fn encoded_push_promise(push_id: Int, fields: List(Header)) -> BitArray {
  let encoder_state = encoder.new(0, 0, 0, 256, 65_536) |> should.be_ok
  let #(_, field_section) =
    encoder.encode(encoder_state, 0, fields, False, True) |> should.be_ok
  frame.encode(frame.PushPromise(push_id, field_section)) |> should.be_ok
}

fn encoded_headers_frame(stream_id: Int, fields: List(Header)) -> BitArray {
  let encoder_state = encoder.new(0, 0, 0, 256, 65_536) |> should.be_ok
  let #(_, field_section) =
    encoder.encode(encoder_state, stream_id, fields, False, True)
    |> should.be_ok
  frame.encode(frame.Headers(field_section)) |> should.be_ok
}

fn qpack_blocked_headers_and_instructions(
  stream_id: Int,
  fields: List(Header),
  dynamic: Header,
) -> #(BitArray, BitArray) {
  let encoder_state = encoder.new(4096, 4096, 16, 256, 65_536) |> should.be_ok
  let encoder_state = encoder.insert(encoder_state, dynamic) |> should.be_ok
  let #(encoder_state, field_section) =
    encoder.encode(encoder_state, stream_id, fields, True, True)
    |> should.be_ok
  let #(_, pending) = encoder.take_instructions(encoder_state)
  let instructions =
    pending
    |> list.map(fn(value) {
      instruction.encode_encoder(value, True) |> should.be_ok
    })
    |> bit_array.concat
  let headers = frame.encode(frame.Headers(field_section)) |> should.be_ok
  #(headers, instructions)
}

fn decode_single_frame(bytes: BitArray) -> frame.Frame {
  let assert #(decoded, <<>>) =
    frame.decode(bytes, frame.default_limits()) |> should.be_ok
  decoded
}

fn response_headers() -> List(Header) {
  [
    Header(<<":status":utf8>>, <<"200":utf8>>, False),
    Header(<<"content-length":utf8>>, <<"2":utf8>>, False),
  ]
}

fn start_bounded_data(
  role: http3_state.Role,
) -> protocol.State(FakeConnection) {
  let defaults = http3_state.default_config(role)
  protocol.start(
    resource(),
    connection(role),
    http3_state.Config(..defaults, maximum_frame_payload_bytes: 65_536),
    False,
  )
  |> should.be_ok
}

fn receive_large_data(target: protocol.State(FakeConnection)) -> Nil {
  let #(target, _) = protocol.take_events(target)
  let length = varint.encode(66_000) |> should.be_ok
  let target =
    protocol.receive_stream(target, 0, <<0, length:bits>>, False, 1)
    |> should.be_ok
  let chunk = <<7:size(32_768)-unit(8)>>
  // Deliver body bytes before the complete DATA frame exists.
  // An application can consume this event and return stream credit to the independent peer.
  let target =
    protocol.receive_stream(target, 0, chunk, False, 2) |> should.be_ok
  let #(target, events) = protocol.take_events(target)
  assert events == [protocol.Http3Event(http3_state.Data(0, chunk))]
  let target =
    protocol.receive_stream(target, 0, chunk, False, 3) |> should.be_ok
  let #(target, events) = protocol.take_events(target)
  assert events == [protocol.Http3Event(http3_state.Data(0, chunk))]
  let last = <<9:size(464)-unit(8)>>
  let target = protocol.receive_stream(target, 0, last, True, 4) |> should.be_ok
  let #(_, events) = protocol.take_events(target)
  assert events
    == [
      protocol.Http3Event(http3_state.Data(0, last)),
      protocol.DataFrameParsed(0, 66_000),
      protocol.Http3Event(http3_state.StreamFinished(0)),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn startup_writes_settings_as_first_control_stream_frame_test() -> Nil {
  list.each([http3_state.Client, http3_state.Server], fn(role) {
    let state = start(role)
    let FakeConnection(writes: writes, ..) = protocol.connection(state)
    let assert [Write(control_id, control_bytes, False), ..] = writes
    let expected_control_id = case role {
      http3_state.Client -> 2
      http3_state.Server -> 3
    }
    assert control_id == expected_control_id
    let assert Ok(#(0, encoded_settings)) = varint.decode(control_bytes)
    let assert Ok(#(frame.Settings(_), <<>>)) =
      frame.decode(encoded_settings, frame.default_limits())
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn request_and_response_fin_are_queued_without_peer_progress_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  // Finish the initial QPACK-capacity exchange so the following write log is scoped to this request/response exchange.
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)

  let #(client, stream_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let client = protocol.finish_stream(client, stream_id) |> should.be_ok
  // Inspect before transferring any request bytes.
  // The peer has had no chance to respond, so this FIN cannot depend on response progress.
  let FakeConnection(writes: request_writes, ..) = protocol.connection(client)
  let assert [
    Write(headers_stream_id, _, False),
    Write(fin_stream_id, <<>>, True),
  ] = request_writes
  assert headers_stream_id == stream_id
  assert fin_stream_id == stream_id

  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, request_events) = protocol.take_events(server)
  let assert [
    protocol.Http3Event(http3_state.RequestHeaders(request_stream_id, _)),
    protocol.Http3Event(http3_state.StreamFinished(finished_request_id)),
  ] = request_events
  assert request_stream_id == stream_id
  assert finished_request_id == stream_id

  let server =
    protocol.send_response_headers(
      server,
      stream_id,
      [Header(<<":status">>, <<"200">>, False)],
      False,
    )
    |> should.be_ok
  let server = protocol.finish_stream(server, stream_id) |> should.be_ok
  // The final response HEADERS and FIN are adjacent local writes, before any additional peer input is delivered.
  let FakeConnection(writes: response_writes, ..) = protocol.connection(server)
  let assert [
    Write(response_stream_id, _, False),
    Write(response_fin_id, <<>>, True),
  ] = response_writes
  assert response_stream_id == stream_id
  assert response_fin_id == stream_id

  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, response_events) = protocol.take_events(client)
  let assert [
    protocol.Http3Event(http3_state.ResponseHeaders(response_event_id, _)),
    protocol.Http3Event(http3_state.StreamFinished(finished_response_id)),
  ] = response_events
  assert response_event_id == stream_id
  assert finished_response_id == stream_id
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn repeated_peer_stream_registration_preserves_control_frames_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let bytes = frame.encode(frame.GoAway(0)) |> should.be_ok
  let original =
    protocol.receive_stream(client, 3, bytes, False, 1) |> should.be_ok
  let repeated = protocol.register_peer_stream(client, 3) |> should.be_ok
  let repeated =
    protocol.receive_stream(repeated, 3, bytes, False, 1) |> should.be_ok
  let #(_, original_events) = protocol.take_events(original)
  let #(_, repeated_events) = protocol.take_events(repeated)
  assert original_events != []
  assert repeated_events == original_events
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn inconsistent_redundant_frame_lengths_are_h3_frame_error_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_, server) = transfer(client, server) |> should.be_ok
  let malformed = [
    // The frame length leaves a surplus byte after the one-byte GOAWAY ID.
    #(<<7, 2, 0, 0>>, frame.InvalidFrame),
    // The frame length ends before the two-byte GOAWAY ID is complete.
    #(<<7, 1, 0x40>>, frame.Truncated),
  ]
  list.each(malformed, fn(example) {
    let #(bytes, expected) = example
    let assert Error(error) =
      protocol.receive_stream(server, 2, bytes, False, 1)
    assert error
      == protocol.FrameParserFailure(frame_parser.FrameFailure(expected))
    assert protocol.peer_application_error_code(error) == Some(0x106)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn data_and_headers_on_control_are_h3_frame_unexpected_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_, server) = transfer(client, server) |> should.be_ok
  list.each([frame.Data(<<"body">>), frame.Headers(<<>>)], fn(incoming) {
    let bytes = frame.encode(incoming) |> should.be_ok
    let assert Error(error) =
      protocol.receive_stream(server, 2, bytes, False, 1)
    assert error
      == protocol.Http3Failure(http3_state.ControlFailure(
        control.FrameUnexpected,
      ))
    assert protocol.peer_application_error_code(error) == Some(0x105)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn request_data_larger_than_frame_buffer_is_delivered_before_fin_test() -> Nil {
  let client = start_bounded_data(http3_state.Client)
  let server = start_bounded_data(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let headers =
    list.filter(request_headers(), fn(header) {
      header.name != <<"content-length">>
    })
  let #(client, _) =
    protocol.open_request(client, headers, False) |> should.be_ok
  let #(_, server) = transfer(client, server) |> should.be_ok
  receive_large_data(server)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn response_data_larger_than_frame_buffer_is_delivered_before_fin_test() -> Nil {
  let client = start_bounded_data(http3_state.Client)
  let server = start_bounded_data(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let headers =
    list.filter(request_headers(), fn(header) {
      header.name != <<"content-length">>
    })
  let #(client, _) =
    protocol.open_request(client, headers, True) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let server =
    protocol.send_response_headers(
      server,
      0,
      [Header(<<":status">>, <<"200">>, False)],
      False,
    )
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  receive_large_data(client)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_data_preserves_body_limit_order_truncation_and_cancel_test() -> Nil {
  let client = start_bounded_data(http3_state.Client)
  let defaults = http3_state.default_config(http3_state.Server)
  let server =
    protocol.start(
      resource(),
      connection(http3_state.Server),
      http3_state.Config(
        ..defaults,
        maximum_frame_payload_bytes: 65_536,
        maximum_body_bytes: 2,
      ),
      False,
    )
    |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let length = varint.encode(66_000) |> should.be_ok
  let prefix = <<0, length:bits, "ab">>
  let unopened = protocol.register_peer_stream(server, 4) |> should.be_ok
  assert protocol.receive_stream(unopened, 4, prefix, False, 1)
    == Error(protocol.Http3Failure(http3_state.FrameUnexpected))
  assert protocol.receive_stream(server, 2, prefix, False, 1)
    == Error(
      protocol.Http3Failure(http3_state.ControlFailure(control.FrameUnexpected)),
    )
  let headers =
    list.filter(request_headers(), fn(header) {
      header.name != <<"content-length">>
    })
  let #(client, _) =
    protocol.open_request(client, headers, False) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, _) = protocol.take_events(server)
  let partial =
    protocol.receive_stream(server, 0, prefix, False, 2) |> should.be_ok
  let #(partial, events) = protocol.take_events(partial)
  assert events == [protocol.Http3Event(http3_state.Data(0, <<"ab">>))]
  assert protocol.receive_stream(partial, 0, <<"c">>, False, 3)
    == Error(
      protocol.Http3Failure(
        http3_state.MessageFailure(message_stream.BodyLimitExceeded(2)),
      ),
    )
  assert protocol.receive_stream(partial, 0, <<>>, True, 3)
    == Error(protocol.FrameParserFailure(frame_parser.TruncatedFrame))
  let cancelled = protocol.abort_stream(partial, 0, 0x10c) |> should.be_ok
  let cancelled =
    protocol.receive_stream(cancelled, 0, <<"discarded">>, True, 4)
    |> should.be_ok
  let #(_, events) = protocol.take_events(cancelled)
  assert events == []
  let client =
    protocol.send_trailers(
      client,
      0,
      [Header(<<"x-finished">>, <<"yes">>, False)],
      False,
    )
    |> should.be_ok
  let #(_, server) = transfer(client, server) |> should.be_ok
  assert protocol.receive_stream(server, 0, prefix, False, 5)
    == Error(
      protocol.Http3Failure(http3_state.MessageFailure(
        message_stream.DataAfterTrailers,
      )),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn empty_unidirectional_stream_fin_is_unused_but_partial_preface_is_rejected_test() -> Nil {
  let server = start(http3_state.Server)
  // Client-initiated unidirectional stream 2 has not supplied a type.
  // A clean FIN means it was unused and must not poison the connection.
  let unused = protocol.register_peer_stream(server, 2) |> should.be_ok
  let unused = protocol.receive_stream(unused, 2, <<>>, True, 1) |> should.be_ok
  assert protocol.receive_stream(unused, 2, <<>>, False, 2)
    == Error(protocol.MissingInput(2))

  // One leading byte of an eight-byte QUIC varint is an actual truncated preface.
  // It remains an error rather than being treated as an unused stream.
  let partial = protocol.register_peer_stream(server, 6) |> should.be_ok
  let partial =
    protocol.receive_stream(partial, 6, <<0xC0>>, False, 3)
    |> should.be_ok
  assert protocol.receive_stream(partial, 6, <<>>, True, 4)
    == Error(protocol.PrefaceLimitExceeded)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn pushed_stream_data_preserves_incremental_order_and_cancellation_test() -> Nil {
  let client = start_bounded_data(http3_state.Client)
  let server = start_bounded_data(http3_state.Server)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let fields = [
    Header(<<":method">>, <<"GET">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/asset">>, False),
  ]
  let #(client, _) = protocol.open_request(client, fields, True) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, push_id, stream_id) =
    protocol.promise_push(server, 0, fields, 1) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let length = varint.encode(66_000) |> should.be_ok
  let prefix = <<0, length:bits, "ab">>
  assert protocol.receive_stream(client, stream_id, prefix, False, 2)
    == Error(
      protocol.Http3Failure(http3_state.MessageFailure(
        message_stream.DataBeforeFinalHeaders,
      )),
    )
  let server =
    protocol.send_push_response_headers(server, stream_id, [
      Header(<<":status">>, <<"200">>, False),
    ])
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let client =
    protocol.receive_stream(client, stream_id, prefix, False, 3)
    |> should.be_ok
  let #(client, events) = protocol.take_events(client)
  assert events
    == [protocol.Http3Event(http3_state.PushData(push_id, stream_id, <<"ab">>))]
  assert protocol.receive_stream(client, stream_id, <<>>, True, 4)
    == Error(protocol.FrameParserFailure(frame_parser.TruncatedFrame))
  let client = protocol.cancel_push(client, push_id) |> should.be_ok
  let client =
    protocol.receive_stream(client, stream_id, <<"discarded">>, True, 4)
    |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert events == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn push_promise_on_push_stream_is_h3_frame_unexpected_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let fields = push_associated_request_headers()
  let #(client, _) =
    protocol.open_request(client, fields, False)
    |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, _, push_stream_id) =
    protocol.promise_push(server, 0, fields, 1) |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok

  let misplaced = frame.encode(frame.PushPromise(0, <<>>)) |> should.be_ok
  let assert Error(error) =
    protocol.receive_stream(client, push_stream_id, misplaced, False, 2)
  assert error == protocol.Http3Failure(http3_state.FrameUnexpected)
  assert protocol.peer_application_error_code(error) == Some(0x105)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejected_push_promises_emit_cancel_and_never_deliver_response_data_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let client = protocol.permit_pushes(client, 3) |> should.be_ok
  let assert #(client, 0) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let client_connection = protocol.connection(client)
  let client =
    protocol.with_connection(
      client,
      FakeConnection(
        ..client_connection,
        writes: [],
        aborts: [],
        operations: [],
      ),
    )

  let rejected = [
    #(0, promised_request(<<"POST">>, <<"https">>, <<"localhost">>, [])),
    #(
      1,
      promised_request(<<"GET">>, <<"https">>, <<"localhost">>, [
        Header(<<"content-length">>, <<"1">>, False),
      ]),
    ),
    #(
      2,
      promised_request(<<"GET">>, <<"https">>, <<"localhost">>, [
        Header(<<"cookie">>, <<"private">>, True),
      ]),
    ),
    #(3, promised_request(<<"GET">>, <<"https">>, <<"other.example">>, [])),
  ]
  let client =
    list.fold(rejected, client, fn(client, item) {
      let #(push_id, fields) = item
      protocol.receive_stream(
        client,
        0,
        encoded_push_promise(push_id, fields),
        False,
        push_id + 1,
      )
      |> should.be_ok
    })
  let #(client, events) = protocol.take_events(client)
  assert events
    == [
      protocol.Http3Event(http3_state.PushPromiseRejected(
        0,
        push.MethodNotKnownSafe,
      )),
      protocol.Http3Event(http3_state.PushPromiseRejected(
        1,
        push.RequestContentIndicated,
      )),
      protocol.Http3Event(http3_state.PushPromiseRejected(
        2,
        push.RequestNotConservativelyCacheable,
      )),
      protocol.Http3Event(http3_state.PushPromiseRejected(
        3,
        push.OriginNotAuthorized,
      )),
    ]
  let FakeConnection(writes: writes, ..) = protocol.connection(client)
  let cancellations =
    list.filter_map(writes, fn(write) {
      case write {
        Write(2, bytes, False) -> Ok(decode_single_frame(bytes))
        _ -> Error(Nil)
      }
    })
  assert cancellations
    == [
      frame.CancelPush(0),
      frame.CancelPush(1),
      frame.CancelPush(2),
      frame.CancelPush(3),
    ]

  // A stream that races behind CANCEL_PUSH is stopped and all of its already pulled bytes are discarded without producing a push handle or body event.
  let FakeConnection(next_unidirectional: push_stream_id, ..) =
    protocol.connection(server)
  let client =
    protocol.register_peer_stream(client, push_stream_id) |> should.be_ok
  let client =
    protocol.receive_stream(
      client,
      push_stream_id,
      <<1, 0, "untrusted">>,
      False,
      10,
    )
    |> should.be_ok
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(push_stream_id, 0x10c)]
  let client =
    protocol.receive_stream(client, push_stream_id, <<"discarded">>, True, 11)
    |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert events == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn buffered_push_response_is_discarded_when_its_later_promise_is_rejected_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let assert #(client, 0) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let client_connection = protocol.connection(client)
  let client =
    protocol.with_connection(
      client,
      FakeConnection(
        ..client_connection,
        writes: [],
        aborts: [],
        operations: [],
      ),
    )

  let FakeConnection(next_unidirectional: push_stream_id, ..) =
    protocol.connection(server)
  let client =
    protocol.register_peer_stream(client, push_stream_id) |> should.be_ok
  let data = frame.encode(frame.Data(<<"ok">>)) |> should.be_ok
  let response =
    bit_array.concat([
      <<1, 0>>,
      encoded_headers_frame(push_stream_id, response_headers()),
      data,
    ])
  let client =
    protocol.receive_stream(client, push_stream_id, response, False, 1)
    |> should.be_ok
  let #(client, events) = protocol.take_events(client)
  assert events
    == [
      protocol.Http3Event(http3_state.PushAwaitingPromise(0, push_stream_id)),
      protocol.DataFrameParsed(push_stream_id, 2),
    ]

  let rejected =
    promised_request(<<"GET">>, <<"https">>, <<"unauthorized.example">>, [])
  let client =
    protocol.receive_stream(
      client,
      0,
      encoded_push_promise(0, rejected),
      False,
      2,
    )
    |> should.be_ok
  let #(client, events) = protocol.take_events(client)
  assert events
    == [
      protocol.Http3Event(http3_state.PushPromiseRejected(
        0,
        push.OriginNotAuthorized,
      )),
    ]
  let FakeConnection(aborts: aborts, operations: operations, ..) =
    protocol.connection(client)
  assert aborts == [#(push_stream_id, 0x10c)]
  let assert [
    ResourceWrite(Write(control_stream, cancel_bytes, False)),
    ResourceAbort(aborted_stream, 0x10c),
  ] = operations
  assert aborted_stream == push_stream_id
  assert control_stream == 2
  assert decode_single_frame(cancel_bytes) == frame.CancelPush(0)

  let client =
    protocol.receive_stream(
      client,
      push_stream_id,
      <<"never-delivered">>,
      True,
      3,
    )
    |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert events == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn promise_is_written_before_the_promised_response_headers_and_data_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let fields = push_associated_request_headers()
  let assert #(client, 0) =
    protocol.open_request(client, fields, False) |> should.be_ok
  let #(_, server) = transfer(client, server) |> should.be_ok
  let #(server, _) = protocol.take_events(server)
  let server_connection = protocol.connection(server)
  let server =
    protocol.with_connection(
      server,
      FakeConnection(..server_connection, writes: [], operations: []),
    )

  let #(server, push_id, push_stream_id) =
    protocol.promise_push(server, 0, fields, 1) |> should.be_ok
  let server =
    protocol.send_push_response_headers(
      server,
      push_stream_id,
      response_headers(),
    )
    |> should.be_ok
  let server =
    protocol.send_push_data(server, push_stream_id, <<"ok">>)
    |> should.be_ok
  let FakeConnection(writes: writes, ..) = protocol.connection(server)
  let assert [
    Write(0, promise_bytes, False),
    Write(preface_stream, preface, False),
    Write(response_head_stream, response_head, False),
    Write(response_data_stream, response_data, False),
  ] = writes
  assert [preface_stream, response_head_stream, response_data_stream]
    == list.repeat(push_stream_id, 3)
  let assert frame.PushPromise(promised_id, _) =
    decode_single_frame(promise_bytes)
  assert promised_id == push_id
  assert preface == <<1, push_id>>
  let assert frame.Headers(_) = decode_single_frame(response_head)
  assert decode_single_frame(response_data) == frame.Data(<<"ok">>)

  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  let assert [
    protocol.Http3Event(http3_state.PushPromised(event_promised_id, _)),
    protocol.Http3Event(http3_state.PushResponseHeaders(
      response_id,
      response_stream,
      _,
    )),
    protocol.Http3Event(http3_state.PushData(data_id, data_stream, <<"ok">>)),
    protocol.DataFrameParsed(parsed_stream, 2),
  ] = events
  assert [event_promised_id, response_id, data_id] == list.repeat(push_id, 3)
  assert [response_stream, data_stream, parsed_stream]
    == list.repeat(push_stream_id, 3)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn maps_http_datagram_wire_and_setting_errors_to_registered_codes_test() -> Nil {
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(http3_state.DatagramFailure(datagram.Truncated)),
    )
    == Some(0x33)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        http3_state.DatagramFailure(datagram.InvalidQuarterStreamId(
          1_152_921_504_606_846_976,
        )),
      ),
    )
    == Some(0x33)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        http3_state.ControlFailure(control.InvalidSetting(0x33)),
      ),
    )
    == Some(0x109)
  assert protocol.peer_application_error_code(protocol.Http3Failure(
      http3_state.ZeroRttSettingsIncompatible,
    ))
    == Some(0x109)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(http3_state.SettingsMemoryFailure(
        settings_memory.InvalidEncoding,
      )),
    )
    == Some(0x109)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc9114_control_failures_use_their_specific_peer_codes_test() -> Nil {
  let cases = [
    #(control.MissingSettings, 0x10a),
    #(control.DuplicateSettings, 0x105),
    #(control.FrameUnexpected, 0x105),
    #(control.InvalidSetting(0x33), 0x109),
    #(control.InvalidGoAwayIdentifier(3), 0x108),
    #(control.IncreasingGoAwayIdentifier, 0x108),
    #(control.PushControlFromServer, 0x108),
    #(control.PushIdDecreased, 0x108),
  ]
  list.each(cases, fn(pair) {
    let #(failure, expected) = pair
    assert protocol.peer_application_error_code(
        protocol.Http3Failure(http3_state.ControlFailure(failure)),
      )
      == Some(expected)
  })

  assert protocol.peer_application_error_code(
      protocol.Http3Failure(http3_state.InvalidStreamId(3)),
    )
    == Some(0x108)
  let push_identifier_cases = [
    push.PushIdDecreased,
    push.PushIdNotAllowed(7),
    push.InvalidRequestStream(3),
    push.InvalidPushStream(4),
    push.DuplicatePushStream(3),
  ]
  list.each(push_identifier_cases, fn(failure) {
    assert protocol.peer_application_error_code(
        protocol.Http3Failure(http3_state.PushFailure(failure)),
      )
      == Some(0x108)
  })
  let drain_identifier_cases = [
    drain.InvalidRequestId(3),
    drain.InvalidPushId(-1),
    drain.IncreasingGoAwayIdentifier,
    drain.DuplicateIdentifier(4),
  ]
  list.each(drain_identifier_cases, fn(failure) {
    assert protocol.peer_application_error_code(
        protocol.Http3Failure(http3_state.DrainFailure(failure)),
      )
      == Some(0x108)
  })
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        http3_state.StreamRegistryFailure(stream_registry.PushIdNotAllowed(1)),
      ),
    )
    == Some(0x108)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        http3_state.StreamRegistryFailure(stream_registry.DuplicatePushId(1)),
      ),
    )
    == Some(0x108)
  assert protocol.peer_application_error_code(
      protocol.FrameParserFailure(
        frame_parser.FrameFailure(frame.DuplicateSetting(1)),
      ),
    )
    == Some(0x109)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn duplicate_push_promise_mismatch_uses_general_protocol_error_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(_server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, request_stream) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  let first =
    encoded_push_promise(
      0,
      promised_request(<<"GET">>, <<"https">>, <<"localhost">>, [
        Header(<<"x-variant">>, <<"first">>, False),
      ]),
    )
  let second =
    encoded_push_promise(
      0,
      promised_request(<<"GET">>, <<"https">>, <<"localhost">>, [
        Header(<<"x-variant">>, <<"second">>, False),
      ]),
    )
  let client =
    protocol.receive_stream(client, request_stream, first, False, 1)
    |> should.be_ok
  let assert Error(error) =
    protocol.receive_stream(client, request_stream, second, False, 2)
  assert protocol.peer_application_error_code(error) == Some(0x101)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc9114_message_rejection_and_incomplete_request_codes_are_specific_test() -> Nil {
  assert protocol.peer_stream_application_error_code(
      protocol.Http3Failure(http3_state.HeaderFailure(
        header_semantics.InvalidFieldName,
      )),
    )
    == Some(0x10e)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(http3_state.HeaderFailure(
        header_semantics.InvalidFieldName,
      )),
    )
    == None
  assert protocol.peer_stream_application_error_code(protocol.Http3Failure(
      http3_state.InvalidMessageFraming,
    ))
    == Some(0x10e)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(http3_state.RequestRejected(4)),
    )
    == Some(0x10b)
  assert protocol.peer_stream_application_error_code(
      protocol.Http3Failure(
        http3_state.PushFailure(push.InvalidPromisedRequest(
          header_semantics.InvalidFieldName,
        )),
      ),
    )
    == Some(0x10e)
  assert protocol.peer_stream_application_error_code(
      protocol.Http3Failure(http3_state.PushFailure(push.UnsafePromisedRequest)),
    )
    == Some(0x10e)
  assert protocol.peer_stream_application_error_code(
      protocol.Http3Failure(
        http3_state.PushFailure(push.PromisedRequestRejected(
          push.OriginNotAuthorized,
        )),
      ),
    )
    == Some(0x10e)
  let cases = [
    #(message_stream.DataBeforeFinalHeaders, 0x105),
    #(message_stream.HeadersAfterTrailers, 0x105),
    #(message_stream.BodyLimitExceeded(1024), 0x107),
    // Any Content-Length/DATA length disagreement is a malformed message.
    #(message_stream.ContentLengthExceeded(3, 5), 0x10e),
    #(message_stream.ContentLengthMismatch(5, 3), 0x10e),
    #(message_stream.NonByteAligned, 0x101),
  ]
  list.each(cases, fn(pair) {
    let #(failure, expected) = pair
    let error = protocol.Http3Failure(http3_state.MessageFailure(failure))
    case expected {
      0x10e -> {
        assert protocol.peer_application_error_code(error) == None
        assert protocol.peer_stream_application_error_code(error)
          == Some(expected)
      }
      _ -> {
        assert protocol.peer_application_error_code(error) == Some(expected)
        assert protocol.peer_stream_application_error_code(error) == None
      }
    }
  })
  // The stream-level code for this failure needs the receiving role and stream kind, so neither role-neutral classifier may guess it.
  let missing =
    protocol.Http3Failure(http3_state.MessageFailure(
      message_stream.MissingFinalHeaders,
    ))
  assert protocol.peer_application_error_code(missing) == None
  assert protocol.peer_stream_application_error_code(missing) == None
  assert protocol.peer_application_error_code(protocol.ResourceFailure(
      protocol.ResourceClosed,
    ))
    == None
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn malformed_request_aborts_only_its_stream_and_next_request_continues_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, _) = protocol.take_events(server)

  // Advance the client allocator without delivering its valid stream-0 HEADERS.
  // The injected field section has authenticated QPACK syntax but an invalid uppercase HTTP field name.
  let #(client, malformed_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  assert malformed_id == 0
  let client_connection = protocol.connection(client)
  let client =
    protocol.with_connection(
      client,
      FakeConnection(..client_connection, writes: [], operations: []),
    )
  let server =
    protocol.register_peer_stream(server, malformed_id)
    |> should.be_ok
  let malformed =
    encoded_headers_frame(malformed_id, [
      Header(<<":method">>, <<"GET">>, False),
      Header(<<":scheme">>, <<"https">>, False),
      Header(<<":authority">>, <<"localhost">>, False),
      Header(<<":path">>, <<"/malformed">>, False),
      Header(<<"X-Invalid">>, <<"redacted">>, False),
    ])
  let assert Ok(protocol.MessageStreamAborted(
    server,
    protocol.RequestStream,
    0x10e,
  )) = protocol.receive_active_stream(server, malformed_id, malformed, True, 1)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(server)
  assert aborts == [#(malformed_id, 0x10e)]
  let #(server, malformed_events) = protocol.take_events(server)
  assert malformed_events == []

  let #(client, next_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  assert next_id == 4
  let #(_, server) = transfer(client, server) |> should.be_ok
  let #(_, events) = protocol.take_events(server)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.RequestHeaders(identifier, _)) ->
        identifier == next_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn malformed_response_aborts_only_its_stream_and_next_response_continues_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(client, first_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let #(client, next_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  // A 204 response cannot carry Content-Length.
  // This is message framing, not a frame-placement failure, and therefore has stream scope.
  let malformed =
    encoded_headers_frame(first_id, [
      Header(<<":status">>, <<"204">>, False),
      Header(<<"content-length">>, <<"1">>, False),
    ])
  let assert Ok(protocol.MessageStreamAborted(
    client,
    protocol.RequestStream,
    0x10e,
  )) = protocol.receive_active_stream(client, first_id, malformed, True, 2)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(first_id, 0x10e)]
  let #(client, malformed_events) = protocol.take_events(client)
  assert malformed_events == []

  let server =
    protocol.send_response_headers(server, next_id, response_headers(), False)
    |> should.be_ok
  let server = protocol.send_data(server, next_id, <<"ok">>) |> should.be_ok
  let server = protocol.finish_stream(server, next_id) |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == next_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn oversized_pushed_response_aborts_only_its_push_stream_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let fields = push_associated_request_headers()
  let #(client, request_id) =
    protocol.open_request(client, fields, False) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, push_id, push_stream_id) =
    protocol.promise_push(server, request_id, fields, 1) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  let pushed_headers =
    encoded_headers_frame(push_stream_id, [
      Header(<<":status">>, <<"200">>, False),
      Header(<<"content-length">>, <<"1">>, False),
    ])
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(
      client,
      push_stream_id,
      pushed_headers,
      False,
      2,
    )
  let #(client, _) = protocol.take_events(client)
  let oversized = frame.encode(frame.Data(<<"xx">>)) |> should.be_ok
  let assert Ok(protocol.MessageStreamAborted(
    client,
    protocol.PushStream(aborted_push_id),
    0x10e,
  )) =
    protocol.receive_active_stream(client, push_stream_id, oversized, True, 3)
  assert aborted_push_id == push_id
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(push_stream_id, 0x10e)]
  let #(client, malformed_events) = protocol.take_events(client)
  assert malformed_events == []

  // The request stream on the same connection remains usable.
  let server =
    protocol.send_response_headers(
      server,
      request_id,
      response_headers(),
      False,
    )
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == request_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_incomplete_push_response_uses_h3_message_error_and_keeps_request_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)
  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let request_fields = push_associated_request_headers()
  let #(client, request_id) =
    protocol.open_request(client, request_fields, False) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, push_id, push_stream_id) =
    protocol.promise_push(server, request_id, request_fields, 1) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  let assert Ok(protocol.MessageStreamAborted(
    client,
    protocol.PushStream(aborted_push_id),
    0x10e,
  )) = protocol.receive_active_stream(client, push_stream_id, <<>>, True, 2)
  assert aborted_push_id == push_id
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(push_stream_id, 0x10e)]

  let server =
    protocol.send_response_headers(
      server,
      request_id,
      response_headers(),
      False,
    )
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == request_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_incomplete_response_aborts_only_stream_with_h3_message_error_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, incomplete_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let #(client, next_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  let assert Ok(protocol.MessageStreamAborted(
    client,
    protocol.RequestStream,
    0x10e,
  )) = protocol.receive_active_stream(client, incomplete_id, <<>>, True, 3)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(incomplete_id, 0x10e)]

  let server =
    protocol.send_response_headers(server, next_id, response_headers(), False)
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == next_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_incomplete_request_aborts_only_stream_with_h3_request_incomplete_test() -> Nil {
  let server = start(http3_state.Server)
  let server = protocol.register_peer_stream(server, 0) |> should.be_ok
  let assert Ok(protocol.MessageStreamAborted(
    server,
    protocol.RequestStream,
    0x10d,
  )) = protocol.receive_active_stream(server, 0, <<>>, True, 1)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(server)
  assert aborts == [#(0, 0x10d)]

  let server = protocol.register_peer_stream(server, 4) |> should.be_ok
  let valid = encoded_headers_frame(4, push_associated_request_headers())
  let assert Ok(protocol.StreamReceived(server)) =
    protocol.receive_active_stream(server, 4, valid, False, 2)
  let #(_, events) = protocol.take_events(server)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.RequestHeaders(4, _)) -> True
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn data_before_headers_remains_h3_frame_unexpected_connection_error_test() -> Nil {
  let server = start(http3_state.Server)
  let server = protocol.register_peer_stream(server, 0) |> should.be_ok
  let data = frame.encode(frame.Data(<<"x">>)) |> should.be_ok
  let assert Error(error) =
    protocol.receive_active_stream(server, 0, data, False, 1)
  assert protocol.peer_stream_application_error_code(error) == None
  assert protocol.peer_application_error_code(error) == Some(0x105)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(server)
  assert aborts == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_unblock_malformed_request_aborts_only_original_stream_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(_, server) = transfer(client, server) |> should.be_ok
  let #(server, _) = protocol.take_events(server)
  let server = protocol.register_peer_stream(server, 0) |> should.be_ok
  let dynamic = Header(<<"X-Qpack-Invalid">>, <<"redacted">>, False)
  let #(headers, instructions) =
    qpack_blocked_headers_and_instructions(
      0,
      [
        Header(<<":method">>, <<"GET">>, False),
        Header(<<":scheme">>, <<"https">>, False),
        Header(<<":authority">>, <<"localhost">>, False),
        Header(<<":path">>, <<"/blocked">>, False),
        dynamic,
      ],
      dynamic,
    )
  let assert Ok(protocol.StreamReceived(server)) =
    protocol.receive_active_stream(server, 0, headers, False, 1)
  let #(server, blocked_events) = protocol.take_events(server)
  assert list.any(blocked_events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.HeadersBlocked(0, 1)) -> True
      _ -> False
    }
  })
  let assert Ok(protocol.StreamReceived(server)) =
    protocol.receive_active_stream(server, 6, instructions, False, 2)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(server)
  assert aborts == [#(0, 0x10e)]
  let #(server, rejected) = protocol.take_events(server)
  assert rejected
    == [
      protocol.MessageStreamWasRejected(protocol.RequestStream, 0, 0x10e),
    ]

  // The QPACK encoder stream and connection remain usable for stream 4.
  let server = protocol.register_peer_stream(server, 4) |> should.be_ok
  let valid = encoded_headers_frame(4, push_associated_request_headers())
  let assert Ok(protocol.StreamReceived(server)) =
    protocol.receive_active_stream(server, 4, valid, False, 3)
  let #(_, events) = protocol.take_events(server)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.RequestHeaders(4, _)) -> True
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_unblock_incomplete_response_uses_h3_message_error_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(_server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(client, stream_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let dynamic = Header(<<"x-qpack-info">>, <<"blocked">>, False)
  let #(headers, instructions) =
    qpack_blocked_headers_and_instructions(
      stream_id,
      [Header(<<":status">>, <<"103">>, False), dynamic],
      dynamic,
    )
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(client, stream_id, headers, True, 1)
  let #(client, blocked_events) = protocol.take_events(client)
  assert list.any(blocked_events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.HeadersBlocked(identifier, 1)) ->
        identifier == stream_id
      _ -> False
    }
  })
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(client, 7, instructions, False, 2)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(stream_id, 0x10e)]
  let #(client, rejected) = protocol.take_events(client)
  assert rejected
    == [
      protocol.MessageStreamWasRejected(
        protocol.RequestStream,
        stream_id,
        0x10e,
      ),
    ]

  let #(client, next_id) =
    protocol.open_request(client, push_associated_request_headers(), False)
    |> should.be_ok
  let valid = encoded_headers_frame(next_id, response_headers())
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(client, next_id, valid, False, 3)
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == next_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qpack_unblock_incomplete_push_response_aborts_only_push_stream_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)

  let client = protocol.permit_pushes(client, 0) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let request_fields = push_associated_request_headers()
  let #(client, request_id) =
    protocol.open_request(client, request_fields, False) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, push_id, push_stream_id) =
    protocol.promise_push(server, request_id, request_fields, 1) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  let dynamic = Header(<<"x-qpack-push-info">>, <<"blocked">>, False)
  let #(headers, instructions) =
    qpack_blocked_headers_and_instructions(
      push_stream_id,
      [Header(<<":status">>, <<"103">>, False), dynamic],
      dynamic,
    )
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(client, push_stream_id, headers, True, 2)
  let #(client, blocked_events) = protocol.take_events(client)
  assert list.any(blocked_events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.HeadersBlocked(identifier, 1)) ->
        identifier == push_stream_id
      _ -> False
    }
  })
  let assert Ok(protocol.StreamReceived(client)) =
    protocol.receive_active_stream(client, 7, instructions, False, 3)
  let FakeConnection(aborts: aborts, ..) = protocol.connection(client)
  assert aborts == [#(push_stream_id, 0x10e)]
  let #(client, rejected) = protocol.take_events(client)
  assert rejected
    == [
      protocol.MessageStreamWasRejected(
        protocol.PushStream(push_id),
        push_stream_id,
        0x10e,
      ),
    ]

  // An incomplete pushed response cannot consume the request stream or close its connection.
  // The associated request still receives a final response.
  let server =
    protocol.send_response_headers(
      server,
      request_id,
      response_headers(),
      False,
    )
    |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert list.any(events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(identifier, _)) ->
        identifier == request_id
      _ -> False
    }
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rfc9218_priority_failures_keep_their_registered_h3_codes_test() -> Nil {
  assert protocol.peer_application_error_code(protocol.Http3Failure(
      http3_state.FrameUnexpected,
    ))
    == Some(0x105)
  assert protocol.peer_application_error_code(
      protocol.Http3Failure(
        http3_state.PriorityFailure(priority.InvalidElementId(8)),
      ),
    )
    == Some(0x108)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn fragmented_grease_before_headers_preserves_message_and_fin_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(_server, client) = transfer(server, client) |> should.be_ok
  let #(server, _) = protocol.take_events(server)
  let server = protocol.register_peer_stream(server, 0) |> should.be_ok
  let #(client, _) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  let assert [Write(0, headers, False)] =
    list.filter(protocol.connection(client).writes, fn(write) {
      write.identifier == 0
    })
  let first = frame.encode(frame.Unknown(0x21, <<>>)) |> should.be_ok
  let second =
    frame.encode(frame.Unknown(0x40, <<"123456789012345678">>)) |> should.be_ok
  let data = frame.encode(frame.Data(<<"body">>)) |> should.be_ok
  let assert <<prefix:bytes-size(1), remaining:bits>> = first
  let server =
    protocol.receive_stream(server, 0, prefix, False, 1) |> should.be_ok
  let server =
    protocol.receive_stream(
      server,
      0,
      bit_array.concat([remaining, second, headers, first, data]),
      True,
      2,
    )
    |> should.be_ok
  let #(_, events) = protocol.take_events(server)
  let assert [
    protocol.Http3Event(http3_state.ExtensionFrameIgnored(0x21)),
    protocol.Http3Event(http3_state.ExtensionFrameIgnored(0x40)),
    protocol.Http3Event(http3_state.RequestHeaders(0, _)),
    protocol.Http3Event(http3_state.ExtensionFrameIgnored(0x21)),
    protocol.Http3Event(http3_state.Data(0, <<"body">>)),
    protocol.DataFrameParsed(0, 4),
    protocol.Http3Event(http3_state.StreamFinished(0)),
  ] = events
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn aborts_only_an_existing_unassociated_datagram_request_test() -> Nil {
  let client = start_datagrams(http3_state.Client)
  let server = start_datagrams(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok

  let #(client, request_id) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  assert request_id == 0
  let #(_client, server) = transfer(client, server) |> should.be_ok

  let server =
    protocol.receive_datagram(server, <<0, "forbidden">>)
    |> should.be_ok
  let server_connection = protocol.connection(server)
  assert server_connection.aborts == [#(0, 0x33)]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn role_neutral_public_resource_adapter_round_trips_http3_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok

  let #(client, request_id) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  assert request_id == 0
  let client =
    protocol.send_data(client, request_id, <<"body":utf8>>)
    |> should.be_ok
  let client = protocol.finish_stream(client, request_id) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, request_events) = protocol.take_events(server)
  assert list.any(request_events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.RequestHeaders(0, _)) -> True
      _ -> False
    }
  })
  assert list.any(request_events, fn(event) {
    event == protocol.Http3Event(http3_state.Data(0, <<"body":utf8>>))
  })
  assert list.any(request_events, fn(event) {
    event == protocol.Http3Event(http3_state.StreamFinished(0))
  })

  let server =
    protocol.send_response_headers(server, 0, response_headers(), False)
    |> should.be_ok
  let server = protocol.send_data(server, 0, <<"ok":utf8>>) |> should.be_ok
  let server = protocol.finish_stream(server, 0) |> should.be_ok
  let #(_server, client) = transfer(server, client) |> should.be_ok
  let #(_, response_events) = protocol.take_events(client)
  assert list.any(response_events, fn(event) {
    case event {
      protocol.Http3Event(http3_state.ResponseHeaders(0, _)) -> True
      _ -> False
    }
  })
  assert list.any(response_events, fn(event) {
    event == protocol.Http3Event(http3_state.Data(0, <<"ok":utf8>>))
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn locally_aborted_stream_discards_already_pulled_peer_bytes_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, client) = transfer(server, client) |> should.be_ok
  let #(client, _) = protocol.take_events(client)

  let #(client, request_id) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  let client =
    protocol.send_data(client, request_id, <<"body":utf8>>)
    |> should.be_ok
  let client = protocol.finish_stream(client, request_id) |> should.be_ok
  let #(client, server) = transfer(client, server) |> should.be_ok

  let server =
    protocol.send_response_headers(
      server,
      request_id,
      response_headers(),
      False,
    )
    |> should.be_ok
  let server =
    protocol.send_data(server, request_id, <<"ok":utf8>>)
    |> should.be_ok
  let server = protocol.finish_stream(server, request_id) |> should.be_ok

  // Public-core read tasks can already have pulled the response bytes when an application queue limit aborts the stream.
  // Those ordered late deliveries are stream-local discard, never a connection protocol failure.
  let client = protocol.abort_stream(client, request_id, 0x107) |> should.be_ok
  let #(_, client) = transfer(server, client) |> should.be_ok
  let #(_, events) = protocol.take_events(client)
  assert events == []
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_reset_removes_request_input_through_http3_cleanup_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(client, server) = transfer(client, server) |> should.be_ok
  let #(server, _client) = transfer(server, client) |> should.be_ok
  let #(client, request_id) =
    protocol.open_request(client, request_headers(), False) |> should.be_ok
  let #(_client, server) = transfer(client, server) |> should.be_ok

  let server = protocol.receive_reset(server, request_id) |> should.be_ok
  assert protocol.receive_stream(server, request_id, <<>>, False, 2)
    == Error(protocol.MissingInput(request_id))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_reset_of_critical_stream_is_connection_error_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_client, server) = transfer(client, server) |> should.be_ok

  assert protocol.receive_reset(server, 2)
    == Error(
      protocol.Http3Failure(
        http3_state.StreamRegistryFailure(stream_registry.ClosedCriticalStream(
          2,
        )),
      ),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_qpack_failures_keep_their_wire_context_through_protocol_parsing_test() -> Nil {
  let client = start(http3_state.Client)
  let server = start(http3_state.Server)
  let #(_client, server) = transfer(client, server) |> should.be_ok

  let invalid_encoder =
    instruction.encode_encoder(
      instruction.InsertWithNameReference(True, 1000, <<"value">>),
      False,
    )
    |> should.be_ok
  let encoder_error =
    protocol.receive_stream(server, 6, invalid_encoder, False, 1)
    |> result.unwrap_error(protocol.MissingInput(6))
  assert encoder_error
    == protocol.Http3Failure(
      http3_state.QpackEncoderStreamFailure(decoder.MissingStaticIndex(1000)),
    )
  assert protocol.peer_application_error_code(encoder_error) == Some(0x201)

  // Zero is syntactically a decoder-stream increment, but semantically invalid because it cannot advance the peer's Known Received Count.
  let decoder_error =
    protocol.receive_stream(server, 10, <<0>>, False, 1)
    |> result.unwrap_error(protocol.MissingInput(10))
  assert protocol.peer_application_error_code(decoder_error) == Some(0x202)

  let invalid_section =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 99),
    ])
    |> field_section.encode(False)
    |> should.be_ok
    |> frame.Headers
    |> frame.encode
    |> should.be_ok
  let server = protocol.register_peer_stream(server, 0) |> should.be_ok
  let decompression_error =
    protocol.receive_stream(server, 0, invalid_section, False, 1)
    |> result.unwrap_error(protocol.MissingInput(0))
  assert decompression_error
    == protocol.Http3Failure(
      http3_state.QpackDecompressionFailure(decoder.MissingStaticIndex(99)),
    )
  assert protocol.peer_application_error_code(decompression_error)
    == Some(0x200)
}
