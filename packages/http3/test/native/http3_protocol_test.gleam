import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{Some}
import gleam/result
import gleeunit/should
import http3/internal/native/connection_state as http3_state
import http3/internal/native/control
import http3/internal/native/datagram
import http3/internal/native/frame
import http3/internal/native/priority
import http3/internal/native/protocol
import http3/internal/native/stream_registry
import http3/internal/qpack/decoder
import http3/internal/qpack/field_section
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction

type Write {
  Write(identifier: Int, bytes: BitArray, finished: Bool)
}

type FakeConnection {
  FakeConnection(
    next_bidirectional: Int,
    next_unidirectional: Int,
    writes: List(Write),
    registered: Dict(Int, Nil),
    datagrams: List(BitArray),
    aborts: List(#(Int, Int)),
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
      Ok(
        FakeConnection(
          ..connection,
          writes: list.append(connection.writes, [
            Write(identifier, bytes, finished),
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
    http3_state.Client -> FakeConnection(0, 2, [], dict.new(), [], [])
    http3_state.Server -> FakeConnection(1, 3, [], dict.new(), [], [])
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
      FakeConnection(..source_connection, writes: []),
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

fn response_headers() -> List(Header) {
  [
    Header(<<":status":utf8>>, <<"200":utf8>>, False),
    Header(<<"content-length":utf8>>, <<"2":utf8>>, False),
  ]
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

  // Public-core read tasks can already have pulled the response bytes when an
  // application queue limit aborts the stream. Those ordered late deliveries
  // are stream-local discard, never a connection protocol failure.
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

  // Zero is syntactically a decoder-stream increment, but semantically
  // invalid because it cannot advance the peer's Known Received Count.
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
