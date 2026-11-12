import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, Some}
import gleeunit/should
import http3/client
import http3/config
import http3/internal/native/frame
import http3/internal/native/frame_parser
import http3/internal/qpack/field_section
import http3/internal/varint
import http3/server
import http3_test_support
import quic_core
import quic_core/client as core_client
import quic_core/failure as core_failure
import quic_core/server as core_server

type Observation {
  Observation(goaway_identifiers: List(Int), close_code: Option(Int))
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn client_close_is_peer_observed_as_two_goaways_then_no_error_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let raw_listener =
    core_server.new(certificate, private_key, "h3")
    |> should.be_ok
    |> core_server.with_address_family(quic_core.Ipv4)
    |> core_server.start
    |> should.be_ok
  let port = core_server.port(raw_listener) |> should.be_ok
  let peer =
    http3_test_support.start_task(fn() {
      let connection = core_server.accept(raw_listener) |> should.be_ok
      send_server_critical_streams(connection)
      let #(control, buffered) =
        accept_client_control_stream(connection, 4) |> should.be_ok
      let observation = observe_client_control(control, buffered)
      let _closed = core_server.close(connection)
      observation
    })

  let configured =
    client.new()
    |> client.with_address_family(config.Ipv4)
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
  let connection = client.connect(configured, "localhost", port) |> should.be_ok
  assert client.close(connection) == Ok(client.Closed)
  let observation = http3_test_support.await_task(peer)
  let _stopped = core_server.stop(raw_listener)

  assert observation == Observation([varint.maximum, 0], Some(0x100))
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn server_stop_is_peer_observed_as_two_goaways_then_no_error_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configured =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_address_family(config.Ipv4)
  let listener = server.start(configured) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let peer =
    http3_test_support.start_task(fn() {
      let connection =
        core_client.new_with_ca_certificates_der("localhost", port, "h3", [
          ca_certificate,
        ])
        |> should.be_ok
        |> core_client.with_address_family(quic_core.Ipv4)
        |> core_client.connect
        |> should.be_ok
      send_client_critical_streams(connection)
      send_raw_request(connection, port, "/orderly-stop")
      let #(control, buffered) =
        accept_server_control_stream(connection, 4) |> should.be_ok
      let observation =
        observe_server_control_after_late_request(
          connection,
          control,
          buffered,
          port,
        )
      let _closed = core_client.close(connection)
      observation
    })

  let accepted = server.accept(listener) |> should.be_ok
  assert server.path(accepted) == "/orderly-stop"
  assert server.stop(listener) == Ok(server.Stopped)
  let observation = http3_test_support.await_task(peer)

  assert observation == Observation([varint.maximum - 3, 8], Some(0x100))
}

// nolint: unused_exports -- gleeunit discovers public tests by suffix.
pub fn graceful_server_drain_is_peer_observed_before_no_error_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configured =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_address_family(config.Ipv4)
  let listener = server.start(configured) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let peer =
    http3_test_support.start_task(fn() {
      let connection =
        core_client.new_with_ca_certificates_der("localhost", port, "h3", [
          ca_certificate,
        ])
        |> should.be_ok
        |> core_client.with_address_family(quic_core.Ipv4)
        |> core_client.connect
        |> should.be_ok
      send_client_critical_streams(connection)
      send_raw_request(connection, port, "/orderly-drain")
      let #(control, buffered) =
        accept_server_control_stream(connection, 4) |> should.be_ok
      let observation = observe_server_control(control, buffered)
      let _closed = core_client.close(connection)
      observation
    })

  let accepted = server.accept(listener) |> should.be_ok
  assert server.path(accepted) == "/orderly-drain"
  server.respond(accepted, 204, [], <<>>) |> should.be_ok
  assert server.graceful_stop(listener) == Ok(server.Drained)
  let observation = http3_test_support.await_task(peer)

  assert observation == Observation([varint.maximum - 3, 4], Some(0x100))
}

fn send_server_critical_streams(connection: core_server.Connection) -> Nil {
  list.each([<<0, 4, 0>>, <<2>>, <<3>>], fn(preface) {
    let stream = core_server.open_unidirectional(connection) |> should.be_ok
    core_server.send(stream, preface) |> should.be_ok
  })
}

fn send_client_critical_streams(connection: core_client.Connection) -> Nil {
  list.each([<<0, 4, 0>>, <<2>>, <<3>>], fn(preface) {
    let stream = core_client.open_unidirectional(connection) |> should.be_ok
    core_client.send(stream, preface) |> should.be_ok
  })
}

fn send_raw_request(
  connection: core_client.Connection,
  port: Int,
  path: String,
) -> core_client.Stream {
  let encoder =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 17),
      field_section.Indexed(True, 23),
      field_section.LiteralNameReference(
        False,
        True,
        0,
        bit_array.from_string("localhost:" <> int.to_string(port)),
      ),
      field_section.LiteralNameReference(
        False,
        True,
        1,
        bit_array.from_string(path),
      ),
    ])
    |> field_section.encode(False)
    |> should.be_ok
  let headers = frame.encode(frame.Headers(encoder)) |> should.be_ok
  let stream = core_client.open_bidirectional(connection) |> should.be_ok
  core_client.send_and_finish(stream, headers) |> should.be_ok
  stream
}

fn accept_client_control_stream(
  connection: core_server.Connection,
  remaining: Int,
) -> Result(#(core_server.Stream, BitArray), Nil) {
  case remaining {
    0 -> Error(Nil)
    _ -> {
      let incoming = core_server.accept_stream_next(connection) |> should.be_ok
      let core_server.IncomingStream(stream, kind) = incoming
      case kind, core_server.receive_next(stream, 65_536) {
        core_server.Unidirectional, Ok(core_server.Data(<<0, rest:bits>>, _)) ->
          Ok(#(stream, rest))
        _, _ -> accept_client_control_stream(connection, remaining - 1)
      }
    }
  }
}

fn accept_server_control_stream(
  connection: core_client.Connection,
  remaining: Int,
) -> Result(#(core_client.Stream, BitArray), Nil) {
  case remaining {
    0 -> Error(Nil)
    _ -> {
      let incoming = core_client.accept_stream_next(connection) |> should.be_ok
      let core_client.IncomingStream(stream, kind) = incoming
      case kind, core_client.receive_next(stream, 65_536) {
        core_client.Unidirectional, Ok(core_client.Data(<<0, rest:bits>>, _)) ->
          Ok(#(stream, rest))
        _, _ -> accept_server_control_stream(connection, remaining - 1)
      }
    }
  }
}

fn observe_client_control(
  stream: core_server.Stream,
  buffered: BitArray,
) -> Observation {
  let parser = new_control_parser(buffered)
  observe_client_frames(stream, parser, [], 8)
}

fn observe_client_frames(
  stream: core_server.Stream,
  parser: frame_parser.State,
  goaways: List(Int),
  remaining_frames: Int,
) -> Observation {
  case remaining_frames, frame_parser.next(parser) {
    0, _ ->
      http3_test_support.fail(#("missing orderly close", list.length(goaways)))
    _, Ok(frame_parser.FrameReady(parser, frame.GoAway(identifier))) -> {
      let goaways = list.append(goaways, [identifier])
      case list.length(goaways) {
        2 -> Observation(goaways, await_client_close(stream, 2))
        _ ->
          observe_client_frames(stream, parser, goaways, remaining_frames - 1)
      }
    }
    _, Ok(frame_parser.FrameReady(parser, _)) ->
      observe_client_frames(stream, parser, goaways, remaining_frames - 1)
    _, Ok(frame_parser.NeedMore(parser)) ->
      case core_server.receive_next(stream, 65_536) {
        Ok(core_server.Data(bytes, _)) -> {
          let parser = frame_parser.push(parser, bytes) |> should.be_ok
          observe_client_frames(stream, parser, goaways, remaining_frames)
        }
        outcome -> http3_test_support.fail(outcome)
      }
    _, Error(error) -> http3_test_support.fail(error)
  }
}

fn observe_server_control(
  stream: core_client.Stream,
  buffered: BitArray,
) -> Observation {
  let parser = new_control_parser(buffered)
  observe_server_frames(stream, parser, [], 8)
}

fn observe_server_control_after_late_request(
  connection: core_client.Connection,
  stream: core_client.Stream,
  buffered: BitArray,
  port: Int,
) -> Observation {
  let parser = new_control_parser(buffered)
  observe_first_server_goaway_then_send_request(
    connection,
    stream,
    parser,
    port,
    8,
  )
}

fn observe_first_server_goaway_then_send_request(
  connection: core_client.Connection,
  stream: core_client.Stream,
  parser: frame_parser.State,
  port: Int,
  remaining_frames: Int,
) -> Observation {
  case remaining_frames, frame_parser.next(parser) {
    0, _ -> http3_test_support.fail(#("missing initial GOAWAY", 0))
    _, Ok(frame_parser.FrameReady(parser, frame.GoAway(identifier))) -> {
      // Receipt of the initial GOAWAY is the synchronization point.
      // No sleep or scheduler timing is used to place this request in the refinement interval.
      let late =
        send_raw_request(connection, port, "/arrived-before-final-goaway")
      await_request_rejection(late, 4)
      observe_server_frames(stream, parser, [identifier], remaining_frames - 1)
    }
    _, Ok(frame_parser.FrameReady(parser, _)) ->
      observe_first_server_goaway_then_send_request(
        connection,
        stream,
        parser,
        port,
        remaining_frames - 1,
      )
    _, Ok(frame_parser.NeedMore(parser)) ->
      case core_client.receive_next(stream, 65_536) {
        Ok(core_client.Data(bytes, _)) -> {
          let parser = frame_parser.push(parser, bytes) |> should.be_ok
          observe_first_server_goaway_then_send_request(
            connection,
            stream,
            parser,
            port,
            remaining_frames,
          )
        }
        outcome -> http3_test_support.fail(outcome)
      }
    _, Error(error) -> http3_test_support.fail(error)
  }
}

fn await_request_rejection(
  stream: core_client.Stream,
  remaining_events: Int,
) -> Nil {
  case remaining_events, core_client.receive_next(stream, 65_536) {
    _, Ok(core_client.Reset(0x10b))
    | _, Error(core_client.StreamReset(0x10b))
    -> Nil
    0, outcome -> http3_test_support.fail(outcome)
    _, Ok(core_client.Data(_, _)) ->
      await_request_rejection(stream, remaining_events - 1)
    _, outcome -> http3_test_support.fail(outcome)
  }
}

fn observe_server_frames(
  stream: core_client.Stream,
  parser: frame_parser.State,
  goaways: List(Int),
  remaining_frames: Int,
) -> Observation {
  case remaining_frames, frame_parser.next(parser) {
    0, _ ->
      http3_test_support.fail(#("missing orderly close", list.length(goaways)))
    _, Ok(frame_parser.FrameReady(parser, frame.GoAway(identifier))) -> {
      let goaways = list.append(goaways, [identifier])
      case list.length(goaways) {
        2 -> Observation(goaways, await_server_close(stream, 2))
        _ ->
          observe_server_frames(stream, parser, goaways, remaining_frames - 1)
      }
    }
    _, Ok(frame_parser.FrameReady(parser, _)) ->
      observe_server_frames(stream, parser, goaways, remaining_frames - 1)
    _, Ok(frame_parser.NeedMore(parser)) ->
      case core_client.receive_next(stream, 65_536) {
        Ok(core_client.Data(bytes, _)) -> {
          let parser = frame_parser.push(parser, bytes) |> should.be_ok
          observe_server_frames(stream, parser, goaways, remaining_frames)
        }
        outcome -> http3_test_support.fail(outcome)
      }
    _, Error(error) -> http3_test_support.fail(error)
  }
}

fn new_control_parser(buffered: BitArray) -> frame_parser.State {
  frame_parser.new(frame.Limits(1024, 1024, 256, 256), 1040)
  |> should.be_ok
  |> frame_parser.push(buffered)
  |> should.be_ok
}

fn await_client_close(
  stream: core_server.Stream,
  remaining: Int,
) -> Option(Int) {
  case remaining, core_server.receive_next(stream, 65_536) {
    _, Error(core_server.Failure(core_failure.Closed(core_failure.Peer, code)))
    -> code
    0, outcome -> http3_test_support.fail(outcome)
    _, Ok(core_server.Data(_, _)) -> await_client_close(stream, remaining - 1)
    _, outcome -> http3_test_support.fail(outcome)
  }
}

fn await_server_close(
  stream: core_client.Stream,
  remaining: Int,
) -> Option(Int) {
  case remaining, core_client.receive_next(stream, 65_536) {
    _, Error(core_client.Failure(core_failure.Closed(core_failure.Peer, code)))
    -> code
    0, outcome -> http3_test_support.fail(outcome)
    _, Ok(core_client.Data(_, _)) -> await_server_close(stream, remaining - 1)
    _, outcome -> http3_test_support.fail(outcome)
  }
}
