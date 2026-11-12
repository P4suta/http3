import gleam/bit_array
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleeunit/should
import http3/client
import http3/config
import http3/failure
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/native/grease
import http3/internal/native/origin
import http3/internal/native/protocol
import http3/internal/qpack/field_section
import http3/internal/varint
import http3/server
import http3/transport
import http3_test_support
import quic_core
import quic_core/client as core_client
import quic_core/failure as core_failure
import quic_core/server as core_server

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn truncated_frames_and_resource_limits_have_distinct_wire_codes_test() -> Nil {
  assert protocol.peer_application_error_code(protocol.FrameParserFailure(
      frame_parser.TruncatedFrame,
    ))
    == Some(0x106)
  assert protocol.peer_application_error_code(
      protocol.FrameParserFailure(frame_parser.BufferLimitExceeded(16)),
    )
    == Some(0x107)
  assert protocol.peer_application_error_code(
      protocol.FrameParserFailure(
        frame_parser.FrameFailure(frame.PayloadLimitExceeded(16)),
      ),
    )
    == Some(0x107)
  assert protocol.peer_application_error_code(protocol.FrameParserFailure(
      frame_parser.InvalidConfiguration,
    ))
    == None
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn frame_runtime_mapping_preserves_resource_bounds_and_local_origin_test() -> Nil {
  let cases = [
    #(frame_parser.BufferLimitExceeded(17), failure.Limit(failure.Buffer, 17)),
    #(
      frame_parser.FrameFailure(frame.PayloadLimitExceeded(18)),
      failure.Limit(failure.Frame, 18),
    ),
    #(
      frame_parser.FrameFailure(frame.FieldSectionLimitExceeded(19)),
      failure.Limit(failure.Frame, 19),
    ),
    #(
      frame_parser.FrameFailure(frame.SettingsLimitExceeded(20)),
      failure.Limit(failure.Queue, 20),
    ),
    #(
      frame_parser.FrameFailure(frame.OriginFailure(origin.OriginTooLong(21))),
      failure.Limit(failure.Frame, 21),
    ),
    #(
      frame_parser.FrameFailure(frame.OriginFailure(origin.TooManyOrigins(22))),
      failure.Limit(failure.Queue, 22),
    ),
    #(frame_parser.InvalidConfiguration, failure.Http3(failure.Local, None)),
    #(frame_parser.NonByteAligned, failure.Http3(failure.Local, None)),
    #(
      frame_parser.FrameFailure(frame.InvalidLimits),
      failure.Http3(failure.Local, None),
    ),
    #(
      frame_parser.FrameFailure(frame.ProhibitedHttp2FrameType(2)),
      failure.Http3(failure.Peer, Some(0x105)),
    ),
    #(
      frame_parser.FrameFailure(frame.DuplicateSetting(1)),
      failure.Http3(failure.Peer, Some(0x109)),
    ),
    #(
      frame_parser.FrameFailure(frame.InvalidFrame),
      failure.Http3(failure.Peer, Some(0x106)),
    ),
  ]
  list.each(cases, fn(pair) {
    let #(incoming, expected) = pair
    assert protocol.frame_parser_runtime_failure(incoming) == expected
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn buffered_client_preserves_frame_limit_and_sends_excessive_load_test() -> Nil {
  let length = varint.encode(65_537) |> should.be_ok
  let observed =
    with_raw_response(<<1, length:bits>>, False, fn(port, ca) {
      let configured =
        client.with_ca_certificate(client.new(), ca) |> should.be_ok
      client.send(
        configured,
        request.new()
          |> request.set_host("localhost")
          |> request.set_port(port)
          |> request.set_body(<<>>),
      )
      |> result.replace(Nil)
    })
  assert observed
    == #(
      Error(client.Failure(failure.Limit(failure.Frame, 65_536))),
      Some(0x107),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reusable_client_preserves_truncated_headers_and_sends_frame_error_test() -> Nil {
  let observed = with_raw_response(<<1, 3, 0>>, True, reusable_request)
  assert observed
    == #(
      Error(client.Failure(failure.Http3(failure.Peer, Some(0x106)))),
      Some(0x106),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reusable_client_preserves_truncated_data_and_sends_frame_error_test() -> Nil {
  // RFC9204 static table index25 is :status200; DATA promises four bytes but the peer cleanly finishes after two.
  // No header, body, or failure text is retained by this fixture's observation.
  let bytes = <<1, 3, 0, 0, 0xd9, 0, 4, "ab">>
  let observed = with_raw_response(bytes, True, reusable_request)
  assert observed
    == #(
      Error(client.Failure(failure.Http3(failure.Peer, Some(0x106)))),
      Some(0x106),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn buffered_client_counts_one_wire_data_frame_across_multiple_chunks_test() -> Nil {
  let payload = http3_test_support.repeated_bytes(66_000)
  let length = varint.encode(66_000) |> should.be_ok
  let bytes = <<1, 3, 0, 0, 0xd9, 0, length:bits, payload:bits>>
  let #(frames, files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      let observed =
        with_raw_response(bytes, True, fn(port, ca) {
          let qlog = transport.qlog(directory) |> should.be_ok
          let configured =
            client.new()
            |> client.with_ca_certificate(ca)
            |> should.be_ok
            |> client.with_qlog(qlog)
          client.send(
            configured,
            request.new()
              |> request.set_host("localhost")
              |> request.set_port(port)
              |> request.set_body(<<>>),
          )
          |> result.map(fn(reply) { bit_array.byte_size(reply.body) })
        })
      let #(response, close_code) = observed
      assert response == Ok(66_000)
      let assert Some(close_code) = close_code
      assert close_code == 0x100 || grease.is_reserved(close_code)
      http3_test_support.qlog_event_count(directory, "http3:frame_parsed")
    })
  assert #(frames, files) == #(3, 1)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_preserves_truncated_request_data_and_frame_error_test() -> Nil {
  assert with_raw_request_tail(<<0, 4, "ab">>, True)
    == #(
      Error(server.Failure(failure.Http3(failure.Peer, Some(0x106)))),
      Some(0x106),
    )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn buffered_client_records_primary_and_bounded_parser_cause_test() -> Nil {
  let #(errors, files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      let observed =
        with_raw_response(<<1, 3, 0>>, True, fn(port, ca) {
          let qlog = transport.qlog(directory) |> should.be_ok
          let configured =
            client.new()
            |> client.with_ca_certificate(ca)
            |> should.be_ok
            |> client.with_qlog(qlog)
          client.send(
            configured,
            request.new()
              |> request.set_host("localhost")
              |> request.set_port(port)
              |> request.set_body(<<>>),
          )
          |> result.replace(Nil)
        })
      assert observed
        == #(
          Error(client.Failure(failure.Http3(failure.Peer, Some(0x106)))),
          Some(0x106),
        )
      http3_test_support.qlog_event_count(directory, "loglevel:error")
    })
  assert #(errors, files) == #(2, 1)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reusable_client_records_parser_cause_before_closing_trace_test() -> Nil {
  let #(errors, files) =
    http3_test_support.with_qlog_directory(fn(directory) {
      let observed =
        with_raw_response(<<1, 3, 0>>, True, fn(port, ca) {
          let configured =
            client.with_ca_certificate(client.new(), ca)
            |> should.be_ok
            |> client.with_qlog(transport.qlog(directory) |> should.be_ok)
          reusable_request_with_config(port, configured)
        })
      assert observed
        == #(
          Error(client.Failure(failure.Http3(failure.Peer, Some(0x106)))),
          Some(0x106),
        )
      http3_test_support.qlog_event_count(directory, "loglevel:error")
    })
  assert #(errors, files) == #(2, 1)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_preserves_oversized_trailers_and_excessive_load_test() -> Nil {
  let length = varint.encode(65_537) |> should.be_ok
  assert with_raw_request_tail(<<1, length:bits>>, False)
    == #(
      Error(server.Failure(failure.Limit(failure.Frame, 65_536))),
      Some(0x107),
    )
}

fn with_raw_request_tail(
  bytes: BitArray,
  finished: Bool,
) -> #(Result(Nil, server.Error), Option(Int)) {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let listener =
    server.new(certificate, key)
    |> should.be_ok
    |> server.with_address_family(config.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let accepted = http3_test_support.new_signal()
  let task =
    http3_test_support.start_task(fn() {
      let connection =
        core_client.new_with_ca_certificates_der("localhost", port, "h3", [ca])
        |> should.be_ok
        |> core_client.with_address_family(quic_core.Ipv4)
        |> core_client.connect
        |> should.be_ok
      let control = core_client.open_unidirectional(connection) |> should.be_ok
      core_client.send(control, <<0, 4, 0>>) |> should.be_ok
      let encoder = core_client.open_unidirectional(connection) |> should.be_ok
      core_client.send(encoder, <<2>>) |> should.be_ok
      let decoder = core_client.open_unidirectional(connection) |> should.be_ok
      core_client.send(decoder, <<3>>) |> should.be_ok
      let stream = core_client.open_bidirectional(connection) |> should.be_ok
      let fields =
        field_section.Section(field_section.Prefix(0, False, 0), [
          field_section.Indexed(True, 17),
          field_section.Indexed(True, 23),
          field_section.Indexed(True, 1),
          field_section.LiteralNameReference(
            False,
            True,
            0,
            bit_array.from_string("localhost:" <> int.to_string(port)),
          ),
        ])
        |> field_section.encode(False)
        |> should.be_ok
      let headers = frame.encode(frame.Headers(fields)) |> should.be_ok
      core_client.send(stream, headers) |> should.be_ok
      http3_test_support.checkpoint(accepted)
      case finished {
        True -> core_client.send_and_finish(stream, bytes) |> should.be_ok
        False -> core_client.send(stream, bytes) |> should.be_ok
      }
      let observed = case core_client.receive_datagram(connection) {
        Error(core_client.Failure(core_failure.Closed(core_failure.Peer, code))) ->
          code
        error -> http3_test_support.fail(error)
      }
      let _closed = core_client.close(connection)
      observed
    })
  let incoming = server.accept(listener) |> should.be_ok
  http3_test_support.release_signal(accepted)
  let outcome = server.read_body(incoming) |> result.replace(Nil)
  let code = http3_test_support.await_task(task)
  server.stop(listener) |> should.be_ok
  #(outcome, code)
}

fn reusable_request(port: Int, ca: BitArray) -> Result(Nil, client.Error) {
  let configured = client.with_ca_certificate(client.new(), ca) |> should.be_ok
  reusable_request_with_config(port, configured)
}

fn reusable_request_with_config(
  port: Int,
  configured: client.Client,
) -> Result(Nil, client.Error) {
  use connection <- result.try(client.connect(configured, "localhost", port))
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let outcome = {
    use stream <- result.try(client.open_stream(connection, outgoing))
    use Nil <- result.try(client.finish(stream))
    consume(stream, 8)
  }
  let _closed = client.close_within(connection, 5000)
  outcome
}

fn consume(stream: client.Stream, remaining: Int) -> Result(Nil, client.Error) {
  case remaining {
    0 -> Ok(Nil)
    _ ->
      case client.next_event(stream) {
        Error(error) -> Error(error)
        Ok(client.End) -> Ok(Nil)
        Ok(_) -> consume(stream, remaining - 1)
      }
  }
}

fn with_raw_response(
  bytes: BitArray,
  finished: Bool,
  run: fn(Int, BitArray) -> value,
) -> #(value, Option(Int)) {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let configured = core_server.new(certificate, key, "h3") |> should.be_ok
  let listener =
    configured
    |> core_server.with_address_family(quic_core.Ipv4)
    |> core_server.start
    |> should.be_ok
  let port = core_server.port(listener) |> should.be_ok
  let task =
    http3_test_support.start_task(fn() {
      let connection = core_server.accept(listener) |> should.be_ok
      let control = core_server.open_unidirectional(connection) |> should.be_ok
      core_server.send(control, <<0, 4, 0>>) |> should.be_ok
      let encoder = core_server.open_unidirectional(connection) |> should.be_ok
      core_server.send(encoder, <<2>>) |> should.be_ok
      let decoder = core_server.open_unidirectional(connection) |> should.be_ok
      core_server.send(decoder, <<3>>) |> should.be_ok
      let stream = accept_request(connection, 4)
      let _request = core_server.receive_next(stream, 65_536) |> should.be_ok
      case finished {
        True -> core_server.send_and_finish(stream, bytes) |> should.be_ok
        False -> core_server.send(stream, bytes) |> should.be_ok
      }
      let observed = await_peer_close(connection, 4)
      let _closed = core_server.close(connection)
      observed
    })
  let result = run(port, ca)
  let observed = http3_test_support.await_task(task)
  let _stopped = core_server.stop(listener)
  #(result, observed)
}

fn accept_request(
  connection: core_server.Connection,
  remaining: Int,
) -> core_server.Stream {
  assert remaining > 0
  let incoming = core_server.accept_stream_next(connection) |> should.be_ok
  case incoming {
    core_server.IncomingStream(stream, core_server.Bidirectional) -> stream
    _ -> accept_request(connection, remaining - 1)
  }
}

fn await_peer_close(
  connection: core_server.Connection,
  remaining: Int,
) -> Option(Int) {
  case remaining {
    0 -> None
    _ ->
      case core_server.accept_stream_next(connection) {
        Error(core_server.Failure(core_failure.Closed(core_failure.Peer, code))) ->
          code
        Error(error) -> http3_test_support.fail(error)
        Ok(_) -> await_peer_close(connection, remaining - 1)
      }
  }
}
