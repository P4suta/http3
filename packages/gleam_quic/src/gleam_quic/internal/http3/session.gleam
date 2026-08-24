//// Live HTTP/3 orchestration over the native QUIC datagram driver.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/datagram
import gleam_quic/internal/http3/drain
import gleam_quic/internal/http3/frame
import gleam_quic/internal/http3/frame_parser
import gleam_quic/internal/http3/stream_registry
import gleam_quic/internal/packet_space
import gleam_quic/internal/qpack/header.{type Header}
import gleam_quic/internal/qpack/instruction
import gleam_quic/internal/qpack/instruction_stream
import gleam_quic/internal/stream_state
import gleam_quic/internal/tls/anti_replay
import gleam_quic/stream_id
import gleam_quic/varint

const maximum_stream_read_bytes = 65_536

const maximum_preface_bytes = 16

const maximum_frame_parser_bytes = 16_777_232

const maximum_instruction_parser_bytes = 65_552

type FrameKind {
  ControlFrames
  RequestFrames
  PushFrames
}

type Input {
  AwaitingPreface(BitArray)
  Framed(FrameKind, frame_parser.State)
  Instructions(instruction_stream.State)
  Ignored
}

/// Semantic HTTP/3 events and non-stream transport notifications.
pub type Event {
  Http3Event(http3_state.Event)
  TransportEvent(transport.Event)
}

/// QUIC, HTTP/3, incremental parser, or orchestration failure.
pub type Error {
  ConnectionNotEstablished
  InvalidPeerStream(Int)
  MissingInput(Int)
  PrefaceLimitExceeded
  DriverFailure(driver.Error)
  TransportFailure(transport.Error)
  Http3Failure(http3_state.Error)
  FrameParserFailure(frame_parser.Error)
  InstructionParserFailure(instruction_stream.Error)
}

/// HTTP/3, stream parsers, and one native QUIC connection.
pub opaque type State {
  State(
    quic: driver.State,
    http3: http3_state.State,
    inputs: Dict(Int, Input),
    events: List(Event),
  )
}

/// A protected datagram whose QUIC send transition is not yet committed.
pub opaque type PreparedDatagram {
  PreparedDatagram(state: State, prepared: driver.PreparedDatagram)
}

/// Bootstrap the mandatory control and QPACK streams on an established QUIC
/// connection and queue SETTINGS before returning.
pub fn start(
  quic: driver.State,
  config: http3_state.Config,
  quic_datagram_negotiated: Bool,
) -> Result(State, Error) {
  case driver.phase(quic) {
    transport.Established ->
      start_established(quic, config, quic_datagram_negotiated)
    _ -> Error(ConnectionNotEstablished)
  }
}

/// Return the stable transport phase.
pub fn phase(state: State) -> transport.Phase {
  driver.phase(state.quic)
}

/// Pull and clear ordered HTTP/3 and transport events.
pub fn take_events(state: State) -> #(State, List(Event)) {
  #(State(..state, events: []), state.events)
}

/// Open a client request stream and queue its initial HEADERS frame.
pub fn open_request(
  state: State,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, Int), Error) {
  use #(connection, identifier) <- result.try(
    transport.open_stream(
      driver.connection(state.quic),
      stream_id.Bidirectional,
    )
    |> map_transport_result,
  )
  use #(http3, bytes) <- result.try(
    http3_state.open_request(
      state.http3,
      identifier,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use connection <- result.try(
    transport.queue_stream(connection, identifier, bytes, False)
    |> map_transport_result,
  )
  use parser <- result.try(new_frame_parser())
  flush_qpack(
    State(
      ..state,
      quic: driver.put_connection(state.quic, connection),
      http3: http3,
      inputs: dict.insert(
        state.inputs,
        identifier,
        Framed(RequestFrames, parser),
      ),
    ),
  )
  |> result.map(fn(state) { #(state, identifier) })
}

/// Queue server response HEADERS on an existing request stream.
pub fn send_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State, Error) {
  use #(http3, bytes) <- result.try(
    http3_state.send_response_headers(
      state.http3,
      stream_id,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    bytes,
    False,
  ))
  flush_qpack(state)
}

/// Queue one bounded HTTP DATA frame on a request or response stream.
pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_data(state.http3, stream_id, bytes) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, encoded, False)
}

/// Queue one HTTP trailer section.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(State, Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_trailers(
      state.http3,
      stream_id,
      fields,
      allow_qpack_blocking,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    encoded,
    False,
  ))
  flush_qpack(state)
}

/// Validate local HTTP message framing and queue a QUIC FIN.
pub fn finish_stream(state: State, stream_id: Int) -> Result(State, Error) {
  use http3 <- result.try(
    http3_state.finish_send(state.http3, stream_id) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, <<>>, True)
}

/// Grant the peer a bounded inclusive server Push ID.
pub fn permit_pushes(
  state: State,
  maximum_push_id: Int,
) -> Result(State, Error) {
  use #(http3, bytes) <- result.try(
    http3_state.permit_pushes(state.http3, maximum_push_id)
    |> map_http3_result,
  )
  use control_stream <- result.try(
    http3_state.control_stream_id(http3) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), control_stream, bytes, False)
}

/// Promise a push and open its server-initiated unidirectional stream.
pub fn promise_push(
  state: State,
  request_stream_id: Int,
  fields: List(Header),
  now_ms: Int,
) -> Result(#(State, Int, Int), Error) {
  use #(http3, push_id, promise_bytes) <- result.try(
    http3_state.promise_push(state.http3, request_stream_id, fields, False)
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    request_stream_id,
    promise_bytes,
    False,
  ))
  use #(connection, push_stream_id) <- result.try(
    transport.open_stream(
      driver.connection(state.quic),
      stream_id.Unidirectional,
    )
    |> map_transport_result,
  )
  use #(http3, preface) <- result.try(
    http3_state.open_push_stream(state.http3, push_stream_id, push_id, now_ms)
    |> map_http3_result,
  )
  use connection <- result.try(
    transport.queue_stream(connection, push_stream_id, preface, False)
    |> map_transport_result,
  )
  flush_qpack(
    State(
      ..state,
      quic: driver.put_connection(state.quic, connection),
      http3: http3,
    ),
  )
  |> result.map(fn(state) { #(state, push_id, push_stream_id) })
}

/// Queue pushed response HEADERS.
pub fn send_push_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  use #(http3, bytes) <- result.try(
    http3_state.send_push_response_headers(
      state.http3,
      stream_id,
      fields,
      False,
    )
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    bytes,
    False,
  ))
  flush_qpack(state)
}

/// Queue pushed response DATA.
pub fn send_push_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_push_data(state.http3, stream_id, bytes)
    |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, encoded, False)
}

/// Queue pushed response trailers.
pub fn send_push_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  use #(http3, encoded) <- result.try(
    http3_state.send_push_trailers(state.http3, stream_id, fields, False)
    |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    stream_id,
    encoded,
    False,
  ))
  flush_qpack(state)
}

/// Finish one pushed response stream.
pub fn finish_push(state: State, stream_id: Int) -> Result(State, Error) {
  use http3 <- result.try(
    http3_state.finish_push_send(state.http3, stream_id) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), stream_id, <<>>, True)
}

/// Cancel one promised push and abort its stream when already opened.
pub fn cancel_push(state: State, push_id: Int) -> Result(State, Error) {
  use #(http3, bytes, push_stream_id) <- result.try(
    http3_state.cancel_push(state.http3, push_id) |> map_http3_result,
  )
  use control_stream <- result.try(
    http3_state.control_stream_id(http3) |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    control_stream,
    bytes,
    False,
  ))
  case push_stream_id {
    None -> Ok(state)
    Some(identifier) -> {
      use connection <- result.try(
        transport.abort_stream(driver.connection(state.quic), identifier, 0x10c)
        |> map_transport_result,
      )
      Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
    }
  }
}

/// Abort both directions of one HTTP request stream with an application code.
pub fn abort_stream(
  state state: State,
  stream_id stream_id: Int,
  application_error_code application_error_code: Int,
) -> Result(State, Error) {
  use connection <- result.try(
    transport.abort_stream(
      driver.connection(state.quic),
      stream_id,
      application_error_code,
    )
    |> map_transport_result,
  )
  Ok(
    State(
      ..state,
      quic: driver.put_connection(state.quic, connection),
      inputs: dict.delete(state.inputs, stream_id),
    ),
  )
}

/// Return whether both QUIC and HTTP/3 Datagram settings were negotiated.
pub fn datagrams_available(state: State) -> Bool {
  http3_state.datagrams_available(state.http3)
}

/// Return whether the peer's mandatory SETTINGS frame has arrived.
pub fn peer_settings_received(state: State) -> Bool {
  http3_state.peer_settings_received(state.http3)
}

/// Return the largest HTTP Datagram application payload for a request stream.
pub fn maximum_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  use _ <- result.try(
    http3_state.send_datagram(state.http3, stream_id, <<>>)
    |> map_http3_result,
  )
  use _ <- result.try(case http3_state.datagrams_available(state.http3) {
    True -> Ok(Nil)
    False -> Error(TransportFailure(transport.DatagramNotNegotiated))
  })
  use raw_limit <- result.try(
    transport.maximum_datagram_data_size(driver.connection(state.quic))
    |> map_transport_result,
  )
  use quarter_bytes <- result.try(
    varint.encoded_size(stream_id / 4)
    |> result.map_error(fn(_) {
      Http3Failure(http3_state.InvalidStreamId(stream_id))
    }),
  )
  let maximum = raw_limit - quarter_bytes
  case stream_id >= 0 && stream_id % 4 == 0 && maximum >= 0 {
    True -> Ok(maximum)
    False -> Error(Http3Failure(http3_state.InvalidStreamId(stream_id)))
  }
}

/// Queue one RFC 9297 quarter-stream-prefixed QUIC DATAGRAM.
pub fn send_http_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(State, Error) {
  use _ <- result.try(maximum_http_datagram_size(state, stream_id))
  use encoded <- result.try(
    http3_state.send_datagram(state.http3, stream_id, payload)
    |> map_http3_result,
  )
  use connection <- result.try(
    transport.queue_datagram(driver.connection(state.quic), encoded)
    |> map_transport_result,
  )
  Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
}

/// Queue a request PRIORITY_UPDATE on the local control stream.
pub fn set_request_priority(
  state: State,
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(State, Error) {
  use http3_state.StreamBytes(identifier, bytes) <- result.try(
    http3_state.request_priority_update(
      state.http3,
      stream_id,
      urgency,
      incremental,
    )
    |> map_http3_result,
  )
  queue_bytes(state, identifier, bytes, False)
}

/// Begin two-stage graceful drain and queue the initial GOAWAY.
pub fn start_drain(state: State, now_ms: Int) -> Result(State, Error) {
  use #(http3, http3_state.StreamBytes(identifier, bytes)) <- result.try(
    http3_state.start_drain(state.http3, now_ms) |> map_http3_result,
  )
  queue_bytes(State(..state, http3: http3), identifier, bytes, False)
}

/// Queue the final GOAWAY cutoff and return request identifiers it rejects.
pub fn refine_drain(
  state: State,
  identifier: Int,
) -> Result(#(State, List(Int)), Error) {
  use #(http3, http3_state.StreamBytes(control_stream, bytes), rejected) <- result.try(
    http3_state.refine_drain(state.http3, identifier) |> map_http3_result,
  )
  use state <- result.try(queue_bytes(
    State(..state, http3: http3),
    control_stream,
    bytes,
    False,
  ))
  Ok(#(state, rejected))
}

/// Advance graceful-drain state and return transport streams to abort.
pub fn on_drain_timer(
  state: State,
  now_ms: Int,
) -> Result(#(State, List(Int)), Error) {
  use #(http3, cancelled) <- result.try(
    http3_state.on_drain_timer(state.http3, now_ms) |> map_http3_result,
  )
  Ok(#(State(..state, http3: http3), cancelled))
}

/// Return the HTTP/3 graceful-drain phase.
pub fn drain_phase(state: State) -> drain.Phase {
  http3_state.drain_phase(state.http3)
}

/// Mark graceful drain closed after QUIC close is queued.
pub fn close_drained(state: State) -> Result(State, Error) {
  use http3 <- result.try(
    http3_state.close_drained(state.http3) |> map_http3_result,
  )
  Ok(State(..state, http3: http3))
}

/// Queue one QUIC PING.
pub fn ping(state: State) -> Result(State, Error) {
  use connection <- result.try(
    transport.queue_ping(driver.connection(state.quic))
    |> map_transport_result,
  )
  Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
}

/// Change the live congestion controller.
pub fn set_congestion_algorithm(
  state: State,
  algorithm: transport.CongestionAlgorithm,
) -> Result(State, Error) {
  use connection <- result.try(
    transport.set_congestion_algorithm(driver.connection(state.quic), algorithm)
    |> map_transport_result,
  )
  Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
}

/// Begin validation for a newly selected local path.
pub fn begin_path_validation(
  state: State,
  challenge: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  use connection <- result.try(
    transport.begin_path_validation(
      driver.connection(state.quic),
      challenge,
      True,
      now_ms,
    )
    |> map_transport_result,
  )
  Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
}

/// Return whether active migration is currently permitted.
pub fn active_migration_available(state: State) -> Bool {
  transport.active_migration_available(driver.connection(state.quic))
}

/// Return the current path MTU.
pub fn path_mtu(state: State) -> Int {
  transport.path_mtu(driver.connection(state.quic))
}

/// Snapshot the current path.
pub fn path_snapshot(state: State) -> transport.PathSnapshot {
  transport.path_snapshot(driver.connection(state.quic))
}

/// Poll and protect at most one UDP datagram.
pub fn prepare_datagram(
  state: State,
  maximum_frame_data_bytes: Int,
  now_ms: Int,
) -> Result(Option(PreparedDatagram), Error) {
  case driver.prepare_datagram(state.quic, maximum_frame_data_bytes, now_ms) {
    Error(error) -> Error(DriverFailure(error))
    Ok(None) -> Ok(None)
    Ok(Some(prepared)) -> Ok(Some(PreparedDatagram(state, prepared)))
  }
}

/// Bytes for one UDP send operation.
pub fn prepared_bytes(prepared: PreparedDatagram) -> BitArray {
  driver.prepared_bytes(prepared.prepared)
}

/// Commit a datagram only after UDP reports a successful send.
pub fn commit_datagram(
  prepared: PreparedDatagram,
  codepoint: ecn.Codepoint,
  now_ms: Int,
) -> Result(State, Error) {
  use quic <- result.try(
    driver.commit_datagram_with_ecn(prepared.prepared, codepoint, now_ms)
    |> map_driver_result,
  )
  Ok(State(..prepared.state, quic: quic))
}

/// Authenticate and process one received UDP datagram through QUIC and HTTP/3.
pub fn receive_datagram(
  state: State,
  datagram: BitArray,
  codepoint: packet_space.ReceivedCodepoint,
  now_ms: Int,
) -> Result(State, Error) {
  use quic <- result.try(
    driver.receive_datagram_with_ecn(state.quic, datagram, codepoint, now_ms)
    |> map_driver_result,
  )
  process_transport_events(State(..state, quic: quic), now_ms)
}

/// Advance QUIC timers using a caller-supplied monotonic timestamp.
pub fn tick(state: State, now_ms: Int) -> Result(State, Error) {
  use quic <- result.try(driver.tick(state.quic, now_ms) |> map_driver_result)
  Ok(State(..state, quic: quic))
}

/// Enter QUIC application closing while retaining HTTP/3 orchestration state.
pub fn close(
  state state: State,
  application_error_code application_error_code: Int,
  reason reason: String,
  now_ms now_ms: Int,
) -> Result(State, Error) {
  use quic <- result.try(
    driver.update_connection(state.quic, fn(connection) {
      transport.close(connection, application_error_code, reason, now_ms)
    })
    |> map_driver_result,
  )
  Ok(State(..state, quic: quic))
}

/// Queue one encrypted post-handshake session ticket on a server connection.
pub fn issue_session_ticket(
  state: State,
  ticket_key: BitArray,
  now_ms: Int,
  lifetime_seconds: Int,
  permit_early_data: Bool,
) -> Result(State, Error) {
  use quic <- result.try(
    driver.update_connection(state.quic, fn(connection) {
      transport.issue_session_ticket(
        connection,
        ticket_key,
        now_ms,
        lifetime_seconds,
        permit_early_data,
      )
    })
    |> map_driver_result,
  )
  Ok(State(..state, quic: quic))
}

/// Return the connected server TLS anti-replay cache without ticket secrets.
pub fn server_replay_cache(state: State) -> Option(anti_replay.Cache) {
  transport.server_replay_cache(driver.connection(state.quic))
}

fn start_established(
  quic: driver.State,
  config: http3_state.Config,
  quic_datagram_negotiated: Bool,
) -> Result(State, Error) {
  use http3 <- result.try(
    http3_state.new(config, quic_datagram_negotiated) |> map_http3_result,
  )
  use #(connection, control_id) <- result.try(
    open_unidirectional(driver.connection(quic)),
  )
  use #(connection, encoder_id) <- result.try(open_unidirectional(connection))
  use #(connection, decoder_id) <- result.try(open_unidirectional(connection))
  use #(http3, bootstrap) <- result.try(
    http3_state.bootstrap(http3, control_id, encoder_id, decoder_id)
    |> map_http3_result,
  )
  use connection <- result.try(queue_stream_bytes(connection, bootstrap))
  process_transport_events(
    State(driver.put_connection(quic, connection), http3, dict.new(), []),
    0,
  )
}

fn open_unidirectional(
  connection: transport.State,
) -> Result(#(transport.State, Int), Error) {
  transport.open_stream(connection, stream_id.Unidirectional)
  |> map_transport_result
}

fn queue_stream_bytes(
  connection: transport.State,
  outputs: List(http3_state.StreamBytes),
) -> Result(transport.State, Error) {
  case outputs {
    [] -> Ok(connection)
    [http3_state.StreamBytes(identifier, bytes), ..rest] -> {
      use connection <- result.try(
        transport.queue_stream(connection, identifier, bytes, False)
        |> map_transport_result,
      )
      queue_stream_bytes(connection, rest)
    }
  }
}

fn queue_bytes(
  state: State,
  identifier: Int,
  bytes: BitArray,
  fin: Bool,
) -> Result(State, Error) {
  use connection <- result.try(
    transport.queue_stream(
      driver.connection(state.quic),
      identifier,
      bytes,
      fin,
    )
    |> map_transport_result,
  )
  Ok(State(..state, quic: driver.put_connection(state.quic, connection)))
}

fn flush_qpack(state: State) -> Result(State, Error) {
  use #(http3, encoder_output) <- result.try(
    http3_state.take_qpack_encoder_bytes(state.http3) |> map_http3_result,
  )
  use #(http3, decoder_output) <- result.try(
    http3_state.take_qpack_decoder_bytes(http3) |> map_http3_result,
  )
  use state <- result.try(queue_optional_stream_bytes(
    State(..state, http3: http3),
    encoder_output,
  ))
  queue_optional_stream_bytes(state, decoder_output)
}

fn queue_optional_stream_bytes(
  state: State,
  output: Option(http3_state.StreamBytes),
) -> Result(State, Error) {
  case output {
    None -> Ok(state)
    Some(http3_state.StreamBytes(identifier, bytes)) ->
      queue_bytes(state, identifier, bytes, False)
  }
}

fn process_transport_events(state: State, now_ms: Int) -> Result(State, Error) {
  let #(quic, events) = driver.take_events(state.quic)
  process_transport_event_list(State(..state, quic: quic), events, now_ms)
}

fn process_transport_event_list(
  state: State,
  events: List(transport.Event),
  now_ms: Int,
) -> Result(State, Error) {
  case events {
    [] -> Ok(state)
    [transport.StreamOpened(identifier), ..rest] -> {
      use state <- result.try(register_input(state, identifier))
      process_transport_event_list(state, rest, now_ms)
    }
    [transport.StreamReadable(identifier), ..rest] -> {
      case dict.has_key(state.inputs, identifier) {
        False -> process_transport_event_list(state, rest, now_ms)
        True -> {
          use state <- result.try(drain_stream(state, identifier, now_ms))
          process_transport_event_list(state, rest, now_ms)
        }
      }
    }
    [transport.DatagramReceived(encoded), ..rest] -> {
      use datagram.Received(identifier, _, payload) <- result.try(
        http3_state.receive_datagram(state.http3, encoded) |> map_http3_result,
      )
      process_transport_event_list(
        add_events(state, [
          Http3Event(http3_state.HttpDatagram(identifier, payload)),
        ]),
        rest,
        now_ms,
      )
    }
    [event, ..rest] ->
      process_transport_event_list(
        add_events(state, [TransportEvent(event)]),
        rest,
        now_ms,
      )
  }
}

fn register_input(state: State, identifier: Int) -> Result(State, Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(InvalidPeerStream(identifier))
    Ok(stream_id.StreamId(_, initiator, direction)) ->
      register_decoded_input(state, identifier, initiator, direction)
  }
}

fn register_decoded_input(
  state: State,
  identifier: Int,
  initiator: stream_id.Initiator,
  direction: stream_id.Direction,
) -> Result(State, Error) {
  let local = case http3_state.role(state.http3) {
    http3_state.Client -> stream_id.Client
    http3_state.Server -> stream_id.Server
  }
  case initiator == local, direction, dict.has_key(state.inputs, identifier) {
    True, _, _ -> Ok(state)
    False, stream_id.Unidirectional, _ ->
      Ok(put_input(state, identifier, AwaitingPreface(<<>>)))
    False, stream_id.Bidirectional, True -> Ok(state)
    False, stream_id.Bidirectional, False ->
      case http3_state.role(state.http3), initiator {
        http3_state.Server, stream_id.Client -> {
          use parser <- result.try(new_frame_parser())
          Ok(put_input(state, identifier, Framed(RequestFrames, parser)))
        }
        _, _ -> Error(InvalidPeerStream(identifier))
      }
  }
}

fn drain_stream(
  state: State,
  identifier: Int,
  now_ms: Int,
) -> Result(State, Error) {
  case dict.get(state.inputs, identifier) {
    Error(_) -> Error(MissingInput(identifier))
    Ok(input) -> {
      use #(connection, outcome) <- result.try(
        transport.read_stream(
          driver.connection(state.quic),
          identifier,
          maximum_stream_read_bytes,
        )
        |> map_transport_result,
      )
      let state =
        State(..state, quic: driver.put_connection(state.quic, connection))
      case outcome {
        stream_state.ReadPending(_) -> Ok(state)
        stream_state.ReadFinished(_) -> finish_input(state, identifier, input)
        stream_state.ReadReset(_, _, _, _) ->
          Ok(State(..state, inputs: dict.delete(state.inputs, identifier)))
        stream_state.ReadData(_, bytes, finished, _) ->
          handle_stream_data(state, identifier, input, bytes, finished, now_ms)
      }
    }
  }
}

fn handle_stream_data(
  state: State,
  identifier: Int,
  input: Input,
  bytes: BitArray,
  finished: Bool,
  now_ms: Int,
) -> Result(State, Error) {
  use state <- result.try(feed_input(state, identifier, input, bytes, now_ms))
  case finished {
    True -> finish_current_input(state, identifier)
    False -> drain_stream(state, identifier, now_ms)
  }
}

fn feed_input(
  state: State,
  identifier: Int,
  input: Input,
  bytes: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  case input {
    AwaitingPreface(buffered) ->
      feed_preface(state, identifier, buffered, bytes, now_ms)
    Framed(kind, parser) -> feed_frames(state, identifier, kind, parser, bytes)
    Instructions(parser) -> feed_instructions(state, identifier, parser, bytes)
    Ignored -> Ok(state)
  }
}

fn feed_preface(
  state: State,
  identifier: Int,
  buffered: BitArray,
  bytes: BitArray,
  now_ms: Int,
) -> Result(State, Error) {
  let combined = <<buffered:bits, bytes:bits>>
  case
    http3_state.open_peer_unidirectional_stream(
      state.http3,
      identifier,
      combined,
      now_ms,
    )
  {
    Error(http3_state.StreamRegistryFailure(stream_registry.TruncatedPreface)) ->
      case bit_array.byte_size(combined) > maximum_preface_bytes {
        True -> Error(PrefaceLimitExceeded)
        False -> Ok(put_input(state, identifier, AwaitingPreface(combined)))
      }
    Error(error) -> Error(Http3Failure(error))
    Ok(#(http3, kind, remaining)) -> {
      use input <- result.try(input_for_kind(kind))
      feed_input(
        put_input(State(..state, http3: http3), identifier, input),
        identifier,
        input,
        remaining,
        now_ms,
      )
    }
  }
}

fn input_for_kind(kind: stream_registry.Kind) -> Result(Input, Error) {
  case kind {
    stream_registry.Control ->
      new_frame_parser()
      |> result.map(fn(parser) { Framed(ControlFrames, parser) })
    stream_registry.Push(_) ->
      new_frame_parser()
      |> result.map(fn(parser) { Framed(PushFrames, parser) })
    stream_registry.QpackEncoder ->
      new_instruction_parser(instruction_stream.EncoderStream)
      |> result.map(Instructions)
    stream_registry.QpackDecoder ->
      new_instruction_parser(instruction_stream.DecoderStream)
      |> result.map(Instructions)
    stream_registry.Unknown(_) -> Ok(Ignored)
  }
}

fn feed_frames(
  state: State,
  identifier: Int,
  kind: FrameKind,
  parser: frame_parser.State,
  bytes: BitArray,
) -> Result(State, Error) {
  use parser <- result.try(
    frame_parser.push(parser, bytes) |> map_frame_parser_result,
  )
  parse_frames(state, identifier, kind, parser)
}

fn parse_frames(
  state: State,
  identifier: Int,
  kind: FrameKind,
  parser: frame_parser.State,
) -> Result(State, Error) {
  case frame_parser.next(parser) {
    Error(error) -> Error(FrameParserFailure(error))
    Ok(frame_parser.NeedMore(parser)) ->
      Ok(put_input(state, identifier, Framed(kind, parser)))
    Ok(frame_parser.FrameReady(parser, incoming)) -> {
      use #(http3, events) <- result.try(receive_http3_frame(
        state.http3,
        identifier,
        kind,
        incoming,
      ))
      use state <- result.try(
        flush_qpack(add_http3_events(State(..state, http3: http3), events)),
      )
      parse_frames(state, identifier, kind, parser)
    }
  }
}

fn receive_http3_frame(
  state: http3_state.State,
  identifier: Int,
  kind: FrameKind,
  incoming: frame.Frame,
) -> Result(#(http3_state.State, List(http3_state.Event)), Error) {
  case kind {
    ControlFrames ->
      http3_state.receive_control_frame(state, incoming) |> map_http3_result
    RequestFrames ->
      http3_state.receive_request_frame(state, identifier, incoming)
      |> map_http3_result
    PushFrames ->
      http3_state.receive_push_stream_frame(state, identifier, incoming)
      |> map_http3_result
  }
}

fn feed_instructions(
  state: State,
  identifier: Int,
  parser: instruction_stream.State,
  bytes: BitArray,
) -> Result(State, Error) {
  use parser <- result.try(
    instruction_stream.push(parser, bytes) |> map_instruction_parser_result,
  )
  parse_instructions(state, identifier, parser)
}

fn parse_instructions(
  state: State,
  identifier: Int,
  parser: instruction_stream.State,
) -> Result(State, Error) {
  case instruction_stream.next(parser) {
    Error(error) -> Error(InstructionParserFailure(error))
    Ok(instruction_stream.NeedMore(parser)) ->
      Ok(put_input(state, identifier, Instructions(parser)))
    Ok(instruction_stream.InstructionReady(parser, decoded)) -> {
      use state <- result.try(apply_instruction(state, decoded))
      parse_instructions(state, identifier, parser)
    }
  }
}

fn apply_instruction(
  state: State,
  decoded: instruction_stream.Decoded,
) -> Result(State, Error) {
  case decoded {
    instruction_stream.EncoderInstruction(incoming) -> {
      use #(http3, events) <- result.try(
        http3_state.receive_qpack_encoder_instruction(state.http3, incoming)
        |> map_http3_result,
      )
      flush_qpack(add_http3_events(State(..state, http3: http3), events))
    }
    instruction_stream.DecoderInstruction(incoming) -> {
      use http3 <- result.try(
        http3_state.receive_qpack_decoder_instruction(state.http3, incoming)
        |> map_http3_result,
      )
      Ok(State(..state, http3: http3))
    }
  }
}

fn finish_current_input(state: State, identifier: Int) -> Result(State, Error) {
  case dict.get(state.inputs, identifier) {
    Error(_) -> Error(MissingInput(identifier))
    Ok(input) -> finish_input(state, identifier, input)
  }
}

fn finish_input(
  state: State,
  identifier: Int,
  input: Input,
) -> Result(State, Error) {
  case input {
    AwaitingPreface(_) -> Error(PrefaceLimitExceeded)
    Instructions(parser) ->
      instruction_stream.finish(parser)
      |> map_instruction_parser_result
      |> result.map(fn(_) { state })
    Ignored -> close_unidirectional(state, identifier)
    Framed(kind, parser) -> {
      use Nil <- result.try(
        frame_parser.finish(parser) |> map_frame_parser_result,
      )
      finish_framed(state, identifier, kind)
    }
  }
}

fn finish_framed(
  state: State,
  identifier: Int,
  kind: FrameKind,
) -> Result(State, Error) {
  case kind {
    RequestFrames -> {
      use #(http3, events) <- result.try(
        http3_state.receive_request_finish(state.http3, identifier)
        |> map_http3_result,
      )
      flush_qpack(add_http3_events(
        State(
          ..state,
          http3: http3,
          inputs: dict.delete(state.inputs, identifier),
        ),
        events,
      ))
    }
    ControlFrames | PushFrames -> close_unidirectional(state, identifier)
  }
}

fn close_unidirectional(state: State, identifier: Int) -> Result(State, Error) {
  use #(http3, events) <- result.try(
    http3_state.close_peer_unidirectional_stream(state.http3, identifier)
    |> map_http3_result,
  )
  Ok(add_http3_events(
    State(..state, http3: http3, inputs: dict.delete(state.inputs, identifier)),
    events,
  ))
}

fn new_frame_parser() -> Result(frame_parser.State, Error) {
  frame_parser.new(frame.default_limits(), maximum_frame_parser_bytes)
  |> map_frame_parser_result
}

fn new_instruction_parser(
  kind: instruction_stream.Kind,
) -> Result(instruction_stream.State, Error) {
  instruction_stream.new(
    kind,
    instruction.default_limits(),
    maximum_instruction_parser_bytes,
  )
  |> map_instruction_parser_result
}

fn put_input(state: State, identifier: Int, input: Input) -> State {
  State(..state, inputs: dict.insert(state.inputs, identifier, input))
}

fn add_http3_events(state: State, events: List(http3_state.Event)) -> State {
  add_events(state, list.map(events, fn(event) { Http3Event(event) }))
}

fn add_events(state: State, events: List(Event)) -> State {
  State(..state, events: list.append(state.events, events))
}

fn map_driver_result(
  value: Result(value, driver.Error),
) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(DriverFailure(error))
  }
}

fn map_transport_result(
  value: Result(value, transport.Error),
) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TransportFailure(error))
  }
}

fn map_http3_result(
  value: Result(value, http3_state.Error),
) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(Http3Failure(error))
  }
}

fn map_frame_parser_result(
  value: Result(value, frame_parser.Error),
) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(FrameParserFailure(error))
  }
}

fn map_instruction_parser_result(
  value: Result(value, instruction_stream.Error),
) -> Result(value, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(InstructionParserFailure(error))
  }
}
