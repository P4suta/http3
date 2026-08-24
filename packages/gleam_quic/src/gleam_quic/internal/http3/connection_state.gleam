//// Pure RFC 9114 connection semantics over an established QUIC transport.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/http3/capsule
import gleam_quic/internal/http3/control
import gleam_quic/internal/http3/datagram
import gleam_quic/internal/http3/drain
import gleam_quic/internal/http3/frame
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/http3/message_stream
import gleam_quic/internal/http3/priority
import gleam_quic/internal/http3/priority_scheduler
import gleam_quic/internal/http3/push
import gleam_quic/internal/http3/stream_registry
import gleam_quic/internal/qpack/decoder
import gleam_quic/internal/qpack/encoder
import gleam_quic/internal/qpack/header.{type Header}
import gleam_quic/internal/qpack/instruction
import gleam_quic/stream_id
import gleam_quic/varint

/// Role of this endpoint.
pub type Role {
  Client
  Server
}

/// SETTINGS advertised on the local control stream.
pub type Settings {
  Settings(
    qpack_max_table_capacity: Int,
    maximum_field_section_size: Int,
    qpack_blocked_streams: Int,
    enable_connect_protocol: Bool,
    h3_datagram: Bool,
    grease: Bool,
  )
}

/// Fixed resource and behavior policy for one connection.
pub type Config {
  Config(
    role: Role,
    settings: Settings,
    preferred_qpack_table_capacity: Int,
    maximum_fields: Int,
    maximum_body_bytes: Int,
    maximum_transactions: Int,
    maximum_pushes: Int,
    push_promise_timeout_ms: Int,
    maximum_datagram_payload_bytes: Int,
    maximum_priority_field_bytes: Int,
    drain_timeout_ms: Int,
  )
}

/// Bytes that must be written in order to one QUIC stream.
pub type StreamBytes {
  StreamBytes(stream_id: Int, bytes: BitArray)
}

/// Semantic events delivered only after QPACK and HTTP validation.
pub type Event {
  PeerSettings(control.Settings)
  RequestHeaders(stream_id: Int, headers: header_semantics.Validated)
  InformationalResponse(stream_id: Int, headers: header_semantics.Validated)
  ResponseHeaders(stream_id: Int, headers: header_semantics.Validated)
  Trailers(stream_id: Int, headers: header_semantics.Validated)
  Data(stream_id: Int, bytes: BitArray)
  HttpDatagram(stream_id: Int, payload: BitArray)
  StreamFinished(stream_id: Int)
  HeadersBlocked(stream_id: Int, required_insert_count: Int)
  PushPromised(push_id: Int, headers: header_semantics.Validated)
  PushAwaitingPromise(push_id: Int, stream_id: Int)
  PushInformationalResponse(
    push_id: Int,
    stream_id: Int,
    headers: header_semantics.Validated,
  )
  PushResponseHeaders(
    push_id: Int,
    stream_id: Int,
    headers: header_semantics.Validated,
  )
  PushData(push_id: Int, stream_id: Int, bytes: BitArray)
  PushTrailers(
    push_id: Int,
    stream_id: Int,
    headers: header_semantics.Validated,
  )
  PushFinished(push_id: Int, stream_id: Int)
  PushCancelled(push_id: Int)
  PushStreamCancellationRequested(push_id: Int, stream_id: Int)
  GoAwayReceived(identifier: Int, rejected: List(Int))
  PriorityChanged(priority.Update)
  ExtensionFrameIgnored(frame_type: Int)
}

type BlockedKind {
  BlockedHeaders
  BlockedPushPromise(push_id: Int)
}

type Transaction {
  Transaction(
    inbound: message_stream.State,
    outbound: message_stream.State,
    inbound_final_headers: Bool,
    outbound_final_headers: Bool,
    inbound_finished: Bool,
    outbound_finished: Bool,
    inbound_fin_pending: Bool,
    request_control: Option(header_semantics.RequestControl),
    blocked: Option(BlockedKind),
  )
}

type PushBlock {
  PushQpackBlocked
  PushPromiseBlocked(List(Header))
}

type PushTransaction {
  PushTransaction(
    push_id: Int,
    message: message_stream.State,
    final_headers: Bool,
    finished: Bool,
    fin_pending: Bool,
    request_control: Option(header_semantics.RequestControl),
    blocked: Option(PushBlock),
  )
}

type CriticalStreams {
  CriticalStreams(control: Int, qpack_encoder: Int, qpack_decoder: Int)
}

/// All HTTP/3 state above a single native QUIC connection.
pub opaque type State {
  State(
    config: Config,
    quic_datagram_negotiated: Bool,
    peer_control: control.State,
    peer_settings: Option(control.Settings),
    peer_streams: stream_registry.State,
    qpack_encoder: encoder.State,
    qpack_decoder: decoder.State,
    pushes: push.State,
    drain: drain.State,
    datagrams: datagram.State,
    scheduler: priority_scheduler.State,
    pending_priorities: Dict(Int, priority.Priority),
    transactions: Dict(Int, Transaction),
    push_transactions: Dict(Int, PushTransaction),
    critical_streams: Option(CriticalStreams),
  )
}

/// Typed connection, QPACK, HTTP, stream, extension, or resource failure.
pub type Error {
  InvalidConfiguration
  WrongRole
  InvalidStreamId(Int)
  DuplicateCriticalStreamId
  CriticalStreamsAlreadyInstalled
  CriticalStreamsNotInstalled
  TransactionLimitExceeded(Int)
  DuplicateTransaction(Int)
  MissingTransaction(Int)
  StreamBlocked(Int)
  FrameUnexpected
  RequestRejected(Int)
  PushRejected(Int)
  MissingPushPromise(Int)
  InvalidMessageFraming
  ControlFailure(control.Error)
  FrameFailure(frame.Error)
  HeaderFailure(header_semantics.Error)
  MessageFailure(message_stream.Error)
  EncoderFailure(encoder.Error)
  DecoderFailure(decoder.Error)
  InstructionFailure(instruction.Error)
  PushFailure(push.Error)
  DrainFailure(drain.Error)
  DatagramFailure(datagram.Error)
  StreamRegistryFailure(stream_registry.Error)
  PriorityFailure(priority.Error)
  SchedulerFailure(priority_scheduler.Error)
  IntegerFailure(varint.Error)
}

/// Conservative bounded defaults suitable for a general endpoint.
pub fn default_config(role: Role) -> Config {
  Config(
    role,
    Settings(4096, 65_536, 16, True, False, True),
    4096,
    256,
    16_777_216,
    1024,
    128,
    10_000,
    65_535,
    4096,
    30_000,
  )
}

/// Create HTTP/3 state after QUIC has negotiated ALPN `h3` and transport
/// parameters, but before critical streams are opened.
pub fn new(
  config: Config,
  quic_datagram_negotiated: Bool,
) -> Result(State, Error) {
  use _ <- result.try(validate_config(config, quic_datagram_negotiated))
  let peer_role = case config.role {
    Client -> control.Server
    Server -> control.Client
  }
  let registry_role = case config.role {
    Client -> stream_registry.Server
    Server -> stream_registry.Client
  }
  use peer_streams <- result.try(
    stream_registry.new(registry_role, config.maximum_pushes)
    |> map_registry_result,
  )
  use qpack_encoder <- result.try(
    encoder.new(
      0,
      0,
      0,
      config.maximum_fields,
      config.settings.maximum_field_section_size,
    )
    |> map_encoder_result,
  )
  use qpack_decoder <- result.try(
    decoder.new(
      config.settings.qpack_max_table_capacity,
      config.settings.qpack_blocked_streams,
      config.maximum_fields,
      config.settings.maximum_field_section_size,
    )
    |> map_decoder_result,
  )
  use pushes <- result.try(
    push.new(config.maximum_pushes, config.push_promise_timeout_ms)
    |> map_push_result,
  )
  let drain_role = case config.role {
    Client -> drain.Client
    Server -> drain.Server
  }
  use drain_state <- result.try(
    drain.new(drain_role, config.maximum_transactions, config.drain_timeout_ms)
    |> map_drain_result,
  )
  use datagrams <- result.try(
    datagram.new(
      quic_datagram_negotiated,
      False,
      config.maximum_transactions,
      config.maximum_datagram_payload_bytes,
    )
    |> map_datagram_result,
  )
  use scheduler <- result.try(
    priority_scheduler.new(config.maximum_transactions, 64, 16)
    |> map_scheduler_result,
  )
  Ok(State(
    config,
    quic_datagram_negotiated,
    control.new(peer_role),
    None,
    peer_streams,
    qpack_encoder,
    qpack_decoder,
    pushes,
    drain_state,
    datagrams,
    scheduler,
    dict.new(),
    dict.new(),
    dict.new(),
    None,
  ))
}

/// Return the endpoint role fixed by this HTTP/3 connection.
pub fn role(state: State) -> Role {
  state.config.role
}

/// Return whether both endpoints enabled RFC 9297 over QUIC DATAGRAM.
pub fn datagrams_available(state: State) -> Bool {
  case state.peer_settings {
    Some(settings) ->
      state.quic_datagram_negotiated
      && state.config.settings.h3_datagram
      && settings.h3_datagram
    None -> False
  }
}

/// Return whether the peer's mandatory SETTINGS frame has been installed.
pub fn peer_settings_received(state: State) -> Bool {
  option.is_some(state.peer_settings)
}

/// Install the three local critical streams and produce their mandatory
/// ordered prefaces. SETTINGS is the first control-stream frame.
pub fn bootstrap(
  state: State,
  control_stream_id: Int,
  qpack_encoder_stream_id: Int,
  qpack_decoder_stream_id: Int,
) -> Result(#(State, List(StreamBytes)), Error) {
  case state.critical_streams {
    Some(_) -> Error(CriticalStreamsAlreadyInstalled)
    None -> {
      use _ <- result.try(validate_local_unidirectional(
        state.config.role,
        control_stream_id,
      ))
      use _ <- result.try(validate_local_unidirectional(
        state.config.role,
        qpack_encoder_stream_id,
      ))
      use _ <- result.try(validate_local_unidirectional(
        state.config.role,
        qpack_decoder_stream_id,
      ))
      use _ <- result.try(
        case
          control_stream_id == qpack_encoder_stream_id
          || control_stream_id == qpack_decoder_stream_id
          || qpack_encoder_stream_id == qpack_decoder_stream_id
        {
          True -> Error(DuplicateCriticalStreamId)
          False -> Ok(Nil)
        },
      )
      use settings <- result.try(
        frame.encode(local_settings_frame(state.config.settings))
        |> map_frame_result,
      )
      use control_type <- result.try(encode_integer(0))
      use encoder_type <- result.try(encode_integer(2))
      use decoder_type <- result.try(encode_integer(3))
      let critical =
        CriticalStreams(
          control_stream_id,
          qpack_encoder_stream_id,
          qpack_decoder_stream_id,
        )
      Ok(
        #(State(..state, critical_streams: Some(critical)), [
          StreamBytes(control_stream_id, <<control_type:bits, settings:bits>>),
          StreamBytes(qpack_encoder_stream_id, encoder_type),
          StreamBytes(qpack_decoder_stream_id, decoder_type),
        ]),
      )
    }
  }
}

/// Classify and register one peer-initiated unidirectional stream. The caller
/// retains `remaining` and routes it according to the returned stream kind.
pub fn open_peer_unidirectional_stream(
  state: State,
  stream_id: Int,
  preface: BitArray,
  now_ms: Int,
) -> Result(#(State, stream_registry.Kind, BitArray), Error) {
  use stream_registry.Preface(kind, remaining) <- result.try(
    stream_registry.decode_preface(preface) |> map_registry_result,
  )
  use peer_streams <- result.try(
    stream_registry.open(state.peer_streams, stream_id, kind)
    |> map_registry_result,
  )
  let state = State(..state, peer_streams: peer_streams)
  case kind {
    stream_registry.Push(push_id) ->
      open_inbound_push(state, stream_id, push_id, now_ms, remaining)
    _ -> Ok(#(state, kind, remaining))
  }
}

/// Observe FIN or reset on a peer unidirectional stream. Closing a control or
/// QPACK stream is a connection error; a completed push releases all bounds.
pub fn close_peer_unidirectional_stream(
  state: State,
  stream_id: Int,
) -> Result(#(State, List(Event)), Error) {
  case
    dict.get(state.push_transactions, stream_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> {
      use peer_streams <- result.try(
        stream_registry.close(state.peer_streams, stream_id)
        |> map_registry_result,
      )
      Ok(#(State(..state, peer_streams: peer_streams), []))
    }
    Some(transaction) -> finish_inbound_push(state, stream_id, transaction)
  }
}

/// Apply one frame from a registered server push stream.
pub fn receive_push_stream_frame(
  state: State,
  stream_id: Int,
  incoming: frame.Frame,
) -> Result(#(State, List(Event)), Error) {
  use transaction <- result.try(get_push_transaction(state, stream_id))
  case transaction.blocked {
    Some(_) -> Error(StreamBlocked(stream_id))
    None -> receive_push_frame(state, stream_id, transaction, incoming)
  }
}

/// Apply one frame from the unique peer control stream.
pub fn receive_control_frame(
  state: State,
  incoming: frame.Frame,
) -> Result(#(State, List(Event)), Error) {
  use #(peer_control, event) <- result.try(
    control.receive(
      state.peer_control,
      incoming,
      state.quic_datagram_negotiated,
    )
    |> map_control_result,
  )
  let state = State(..state, peer_control: peer_control)
  case event {
    control.SettingsReceived(settings) -> install_peer_settings(state, settings)
    control.GoAwayReceived(identifier) -> {
      use drain.GoAwayOutcome(drain_state, rejected) <- result.try(
        drain.receive_goaway(state.drain, identifier) |> map_drain_result,
      )
      use #(state, push_events) <- result.try(case state.config.role {
        Server -> {
          use pushes <- result.try(
            push.apply_goaway(state.pushes, identifier) |> map_push_result,
          )
          cancel_push_transactions(
            State(..state, pushes: pushes, drain: drain_state),
            rejected,
            [],
          )
        }
        Client -> Ok(#(State(..state, drain: drain_state), []))
      })
      Ok(#(state, [GoAwayReceived(identifier, rejected), ..push_events]))
    }
    control.PushCancelled(push_id) -> {
      use pushes <- result.try(
        push.announce_cancellation(state.pushes, push_id) |> map_push_result,
      )
      use #(state, events) <- result.try(
        cancel_push_transactions(State(..state, pushes: pushes), [push_id], []),
      )
      Ok(#(state, [PushCancelled(push_id), ..events]))
    }
    control.MaximumPushIdReceived(push_id) -> {
      use pushes <- result.try(
        push.permit_through(state.pushes, push_id) |> map_push_result,
      )
      Ok(#(State(..state, pushes: pushes), []))
    }
    control.ExtensionIgnored(frame_type) ->
      receive_control_extension(state, incoming, frame_type)
  }
}

/// Open and encode the initial request HEADERS on a client request stream.
pub fn open_request(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use _ <- result.try(validate_request_stream(stream_id))
  use _ <- result.try(ensure_transaction_capacity(state, stream_id))
  use drain_state <- result.try(
    drain.open_request(state.drain, stream_id) |> map_drain_result,
  )
  use validated <- result.try(
    header_semantics.validate(
      fields,
      header_semantics.RequestSection,
      peer_connect_enabled(state),
    )
    |> map_header_result,
  )
  use #(request_control, content_length) <- result.try(request_metadata(
    validated,
  ))
  use #(qpack_encoder, encoded) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      stream_id,
      fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.Headers(encoded)) |> map_frame_result,
  )
  let outbound = message_stream.new(message_stream.Request)
  use outbound <- result.try(
    message_stream.receive_headers_with_length(
      outbound,
      message_stream.Final,
      content_length,
    )
    |> map_message_result,
  )
  let transaction =
    Transaction(
      message_stream.new(message_stream.Response),
      outbound,
      False,
      True,
      False,
      False,
      False,
      Some(request_control),
      None,
    )
  Ok(#(
    State(
      ..state,
      drain: drain_state,
      qpack_encoder: qpack_encoder,
      transactions: dict.insert(state.transactions, stream_id, transaction),
    ),
    encoded,
  ))
}

/// Apply one HTTP frame from a request stream. Server-side transactions are
/// created only by their first HEADERS frame.
pub fn receive_request_frame(
  state: State,
  stream_id: Int,
  incoming: frame.Frame,
) -> Result(#(State, List(Event)), Error) {
  use _ <- result.try(validate_request_stream(stream_id))
  use state <- result.try(ensure_inbound_transaction(state, stream_id, incoming))
  use transaction <- result.try(get_transaction(state, stream_id))
  case transaction.blocked {
    Some(_) -> Error(StreamBlocked(stream_id))
    None -> receive_transaction_frame(state, stream_id, transaction, incoming)
  }
}

/// Observe the clean FIN of a request stream.
pub fn receive_request_finish(
  state: State,
  stream_id: Int,
) -> Result(#(State, List(Event)), Error) {
  use transaction <- result.try(get_transaction(state, stream_id))
  case transaction.blocked {
    Some(_) -> {
      let transaction = Transaction(..transaction, inbound_fin_pending: True)
      Ok(#(put_transaction(state, stream_id, transaction), []))
    }
    None -> finish_inbound(state, stream_id, transaction)
  }
}

/// Encode response HEADERS. Informational responses can precede one final
/// response; CONNECT success changes the stream to data-only tunnel mode.
pub fn send_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use transaction <- result.try(get_transaction(state, stream_id))
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
    |> map_header_result,
  )
  use #(status, content_length) <- result.try(response_metadata(validated))
  let informational = header_semantics.is_informational_status(status)
  use content_length <- result.try(response_content_length(
    transaction.request_control,
    status,
    content_length,
  ))
  let kind = case informational {
    True -> message_stream.Informational
    False -> message_stream.Final
  }
  use outbound <- result.try(
    message_stream.receive_headers_with_length(
      transaction.outbound,
      kind,
      content_length,
    )
    |> map_message_result,
  )
  use outbound <- result.try(maybe_establish_connect(
    outbound,
    transaction.request_control,
    status,
  ))
  use inbound <- result.try(maybe_establish_connect(
    transaction.inbound,
    transaction.request_control,
    status,
  ))
  use datagrams <- result.try(associate_response_datagrams(
    state.datagrams,
    stream_id,
    transaction.request_control,
    status,
  ))
  use #(qpack_encoder, encoded) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      stream_id,
      fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.Headers(encoded)) |> map_frame_result,
  )
  let transaction =
    Transaction(
      ..transaction,
      inbound: inbound,
      outbound: outbound,
      outbound_final_headers: transaction.outbound_final_headers
        || !informational,
    )
  Ok(#(
    put_transaction(
      State(..state, qpack_encoder: qpack_encoder, datagrams: datagrams),
      stream_id,
      transaction,
    ),
    encoded,
  ))
}

/// Encode a bounded DATA frame and advance outbound message framing.
pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(#(State, BitArray), Error) {
  use transaction <- result.try(get_transaction(state, stream_id))
  use outbound <- result.try(
    message_stream.receive_data(
      transaction.outbound,
      bytes,
      state.config.maximum_body_bytes,
    )
    |> map_message_result,
  )
  use encoded <- result.try(frame.encode(frame.Data(bytes)) |> map_frame_result)
  Ok(#(
    put_transaction(
      state,
      stream_id,
      Transaction(..transaction, outbound: outbound),
    ),
    encoded,
  ))
}

/// Encode one trailer section after final headers and body data.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, BitArray), Error) {
  use transaction <- result.try(get_transaction(state, stream_id))
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.TrailerSection, False)
    |> map_header_result,
  )
  use outbound <- result.try(
    message_stream.receive_headers(
      transaction.outbound,
      message_stream.Trailers,
    )
    |> map_message_result,
  )
  use #(qpack_encoder, encoded) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      stream_id,
      fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.Headers(encoded)) |> map_frame_result,
  )
  Ok(#(
    put_transaction(
      State(..state, qpack_encoder: qpack_encoder),
      stream_id,
      Transaction(..transaction, outbound: outbound),
    ),
    encoded,
  ))
}

/// Validate the local message before the transport sets FIN.
pub fn finish_send(state: State, stream_id: Int) -> Result(State, Error) {
  use transaction <- result.try(get_transaction(state, stream_id))
  use outbound <- result.try(
    message_stream.finish(transaction.outbound) |> map_message_result,
  )
  let state =
    put_transaction(
      state,
      stream_id,
      Transaction(..transaction, outbound: outbound, outbound_finished: True),
    )
  let state = case state.config.role {
    Server -> complete_drain_work(state, stream_id)
    Client -> state
  }
  Ok(cleanup_if_complete(state, stream_id))
}

/// Apply one peer QPACK encoder-stream instruction, retrying any newly
/// unblocked field sections in deterministic stream-ID list order.
pub fn receive_qpack_encoder_instruction(
  state: State,
  incoming: instruction.EncoderInstruction,
) -> Result(#(State, List(Event)), Error) {
  use qpack_decoder <- result.try(
    decoder.apply_encoder_instruction(state.qpack_decoder, incoming)
    |> map_decoder_result,
  )
  retry_blocked(
    State(..state, qpack_decoder: qpack_decoder),
    decoder.blocked_streams(qpack_decoder) |> list.sort(int.compare),
    [],
  )
}

/// Apply peer QPACK decoder feedback and release encoder references.
pub fn receive_qpack_decoder_instruction(
  state: State,
  incoming: instruction.DecoderInstruction,
) -> Result(State, Error) {
  use qpack_encoder <- result.try(
    encoder.apply_decoder_instruction(state.qpack_encoder, incoming)
    |> map_encoder_result,
  )
  Ok(State(..state, qpack_encoder: qpack_encoder))
}

/// Pull ordered bytes for the local critical QPACK encoder stream.
pub fn take_qpack_encoder_bytes(
  state: State,
) -> Result(#(State, Option(StreamBytes)), Error) {
  use critical <- result.try(require_critical_streams(state))
  let #(qpack_encoder, instructions) =
    encoder.take_instructions(state.qpack_encoder)
  use bytes <- result.try(encode_encoder_instructions(instructions, <<>>))
  let output = case bytes {
    <<>> -> None
    _ -> Some(StreamBytes(critical.qpack_encoder, bytes))
  }
  Ok(#(State(..state, qpack_encoder: qpack_encoder), output))
}

/// Pull ordered bytes for the local critical QPACK decoder stream.
pub fn take_qpack_decoder_bytes(
  state: State,
) -> Result(#(State, Option(StreamBytes)), Error) {
  use critical <- result.try(require_critical_streams(state))
  let #(qpack_decoder, instructions) =
    decoder.take_instructions(state.qpack_decoder)
  use bytes <- result.try(encode_decoder_instructions(instructions, <<>>))
  let output = case bytes {
    <<>> -> None
    _ -> Some(StreamBytes(critical.qpack_decoder, bytes))
  }
  Ok(#(State(..state, qpack_decoder: qpack_decoder), output))
}

/// Return the installed local control-stream identifier.
pub fn control_stream_id(state: State) -> Result(Int, Error) {
  use CriticalStreams(identifier, _, _) <- result.try(require_critical_streams(
    state,
  ))
  Ok(identifier)
}

/// Insert one local field into QPACK after peer SETTINGS established capacity.
pub fn index_field(state: State, field: Header) -> Result(State, Error) {
  use qpack_encoder <- result.try(
    encoder.insert(state.qpack_encoder, field) |> map_encoder_result,
  )
  Ok(State(..state, qpack_encoder: qpack_encoder))
}

/// Client grants server push IDs and updates its incoming push-stream registry.
pub fn permit_pushes(
  state: State,
  maximum_push_id: Int,
) -> Result(#(State, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use pushes <- result.try(
    push.permit_through(state.pushes, maximum_push_id) |> map_push_result,
  )
  use peer_streams <- result.try(
    stream_registry.permit_pushes_through(state.peer_streams, maximum_push_id)
    |> map_registry_result,
  )
  use encoded <- result.try(
    frame.encode(frame.MaxPushId(maximum_push_id)) |> map_frame_result,
  )
  Ok(#(State(..state, pushes: pushes, peer_streams: peer_streams), encoded))
}

/// Allocate a server Push ID and encode its PUSH_PROMISE on an active request.
pub fn promise_push(
  state: State,
  request_stream_id: Int,
  request_fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, Int, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use _ <- result.try(get_transaction(state, request_stream_id))
  use #(pushes, push_id) <- result.try(
    push.allocate_promise(state.pushes, request_stream_id, request_fields)
    |> map_push_result,
  )
  use drain_state <- result.try(
    drain.promise_push(state.drain, push_id) |> map_drain_result,
  )
  use #(qpack_encoder, field_section) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      request_stream_id,
      request_fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.PushPromise(push_id, field_section))
    |> map_frame_result,
  )
  Ok(#(
    State(
      ..state,
      pushes: pushes,
      drain: drain_state,
      qpack_encoder: qpack_encoder,
    ),
    push_id,
    encoded,
  ))
}

/// Open the server push stream and return its type and Push-ID preface.
pub fn open_push_stream(
  state: State,
  stream_id: Int,
  push_id: Int,
  now_ms: Int,
) -> Result(#(State, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use _ <- result.try(validate_local_unidirectional(Server, stream_id))
  use _ <- result.try(ensure_push_transaction_capacity(state, stream_id))
  use request_control <- result.try(require_push_request_control(
    state.pushes,
    push_id,
  ))
  use pushes <- result.try(
    push.open_stream(state.pushes, push_id, stream_id, now_ms)
    |> map_push_result,
  )
  use stream_type <- result.try(encode_integer(1))
  use encoded_push_id <- result.try(encode_integer(push_id))
  let transaction =
    PushTransaction(
      push_id,
      message_stream.new(message_stream.Response),
      False,
      False,
      False,
      Some(request_control),
      None,
    )
  Ok(
    #(
      State(
        ..state,
        pushes: pushes,
        push_transactions: dict.insert(
          state.push_transactions,
          stream_id,
          transaction,
        ),
      ),
      <<stream_type:bits, encoded_push_id:bits>>,
    ),
  )
}

/// Encode pushed response HEADERS, including informational stages.
pub fn send_push_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, BitArray), Error) {
  use transaction <- result.try(get_push_transaction(state, stream_id))
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
    |> map_header_result,
  )
  use #(status, content_length) <- result.try(response_metadata(validated))
  let informational = header_semantics.is_informational_status(status)
  use content_length <- result.try(response_content_length(
    transaction.request_control,
    status,
    content_length,
  ))
  let kind = case informational {
    True -> message_stream.Informational
    False -> message_stream.Final
  }
  use message <- result.try(
    message_stream.receive_headers_with_length(
      transaction.message,
      kind,
      content_length,
    )
    |> map_message_result,
  )
  use #(qpack_encoder, field_section) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      stream_id,
      fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.Headers(field_section)) |> map_frame_result,
  )
  let transaction =
    PushTransaction(
      ..transaction,
      message: message,
      final_headers: transaction.final_headers || !informational,
    )
  Ok(#(
    put_push_transaction(
      State(..state, qpack_encoder: qpack_encoder),
      stream_id,
      transaction,
    ),
    encoded,
  ))
}

/// Encode one bounded DATA frame on a server push stream.
pub fn send_push_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(#(State, BitArray), Error) {
  use transaction <- result.try(get_push_transaction(state, stream_id))
  use message <- result.try(
    message_stream.receive_data(
      transaction.message,
      bytes,
      state.config.maximum_body_bytes,
    )
    |> map_message_result,
  )
  use encoded <- result.try(frame.encode(frame.Data(bytes)) |> map_frame_result)
  Ok(#(
    put_push_transaction(
      state,
      stream_id,
      PushTransaction(..transaction, message: message),
    ),
    encoded,
  ))
}

/// Encode pushed response trailers.
pub fn send_push_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
  allow_qpack_blocking: Bool,
) -> Result(#(State, BitArray), Error) {
  use transaction <- result.try(get_push_transaction(state, stream_id))
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.TrailerSection, False)
    |> map_header_result,
  )
  use message <- result.try(
    message_stream.receive_headers(transaction.message, message_stream.Trailers)
    |> map_message_result,
  )
  use #(qpack_encoder, field_section) <- result.try(
    encoder.encode(
      state.qpack_encoder,
      stream_id,
      fields,
      allow_qpack_blocking,
      True,
    )
    |> map_encoder_result,
  )
  use encoded <- result.try(
    frame.encode(frame.Headers(field_section)) |> map_frame_result,
  )
  Ok(#(
    put_push_transaction(
      State(..state, qpack_encoder: qpack_encoder),
      stream_id,
      PushTransaction(..transaction, message: message),
    ),
    encoded,
  ))
}

/// Validate and release a locally completed server push stream.
pub fn finish_push_send(state: State, stream_id: Int) -> Result(State, Error) {
  use transaction <- result.try(get_push_transaction(state, stream_id))
  use _ <- result.try(
    message_stream.finish(transaction.message) |> map_message_result,
  )
  finish_push_lifecycle(state, stream_id, transaction.push_id)
}

/// Cancel an accepted push and return a stream ID that the transport should
/// STOP_SENDING, when its stream has already arrived.
pub fn cancel_push(
  state: State,
  push_id: Int,
) -> Result(#(State, BitArray, Option(Int)), Error) {
  use _ <- result.try(case state.config.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use tracked <- result.try(case push.get(state.pushes, push_id) {
    Some(value) -> Ok(value)
    None -> Error(MissingPushPromise(push_id))
  })
  use pushes <- result.try(
    push.cancel(state.pushes, push_id) |> map_push_result,
  )
  use encoded <- result.try(
    frame.encode(frame.CancelPush(push_id)) |> map_frame_result,
  )
  let push.Push(_, _, _, push_stream_id, _) = tracked
  let state =
    remove_push_transaction_by_id(State(..state, pushes: pushes), push_id)
    |> complete_push_drain(push_id)
  use state <- result.try(case push_stream_id {
    None -> Ok(state)
    Some(identifier) -> {
      use peer_streams <- result.try(
        stream_registry.close(state.peer_streams, identifier)
        |> map_registry_result,
      )
      Ok(State(..state, peer_streams: peer_streams))
    }
  })
  Ok(#(state, encoded, push_stream_id))
}

/// Expire push streams which arrived without a matching promise. Returned
/// stream IDs must be stopped by the transport.
pub fn expire_pending_pushes(
  state: State,
  now_ms: Int,
) -> Result(#(State, List(Int)), Error) {
  use #(pushes, expired) <- result.try(
    push.expire_pending(state.pushes, now_ms) |> map_push_result,
  )
  expire_push_streams(State(..state, pushes: pushes), expired)
}

/// Create a semantics-bound HTTP Datagram association after Extended CONNECT
/// or another extension has negotiated its use.
pub fn associate_datagrams(
  state: State,
  stream_id: Int,
  extension: datagram.Extension,
  delivery: datagram.Delivery,
) -> Result(State, Error) {
  use datagrams <- result.try(
    datagram.associate(state.datagrams, stream_id, extension, delivery)
    |> map_datagram_result,
  )
  Ok(State(..state, datagrams: datagrams))
}

/// Encode an associated QUIC DATAGRAM payload.
pub fn send_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(BitArray, Error) {
  datagram.encode_unreliable(state.datagrams, stream_id, payload)
  |> map_datagram_result
}

/// Decode an associated QUIC DATAGRAM payload.
pub fn receive_datagram(
  state: State,
  payload: BitArray,
) -> Result(datagram.Received, Error) {
  datagram.decode_unreliable(state.datagrams, payload) |> map_datagram_result
}

/// Validate an associated capsule from request DATA.
pub fn receive_capsule(
  state: State,
  stream_id: Int,
  incoming: capsule.Capsule,
) -> Result(datagram.CapsuleOutcome, Error) {
  datagram.receive_capsule(state.datagrams, stream_id, incoming)
  |> map_datagram_result
}

/// Encode one client request PRIORITY_UPDATE on the local control stream.
pub fn request_priority_update(
  state: State,
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(StreamBytes, Error) {
  use _ <- result.try(case state.config.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use _ <- result.try(validate_request_stream(stream_id))
  use CriticalStreams(control_stream, _, _) <- result.try(
    require_critical_streams(state),
  )
  use encoded <- result.try(
    priority.encode_update(priority.RequestUpdate(
      stream_id,
      priority.Priority(urgency, incremental),
    ))
    |> map_priority_result,
  )
  Ok(StreamBytes(control_stream, encoded))
}

/// Begin two-stage graceful drain and encode the initial GOAWAY frame.
pub fn start_drain(
  state: State,
  now_ms: Int,
) -> Result(#(State, StreamBytes), Error) {
  use CriticalStreams(control_stream, _, _) <- result.try(
    require_critical_streams(state),
  )
  use #(drain_state, identifier) <- result.try(
    drain.start(state.drain, now_ms) |> map_drain_result,
  )
  use encoded <- result.try(
    frame.encode(frame.GoAway(identifier)) |> map_frame_result,
  )
  Ok(#(State(..state, drain: drain_state), StreamBytes(control_stream, encoded)))
}

/// Refine graceful drain to the first identifier this endpoint will reject.
pub fn refine_drain(
  state: State,
  identifier: Int,
) -> Result(#(State, StreamBytes, List(Int)), Error) {
  use CriticalStreams(control_stream, _, _) <- result.try(
    require_critical_streams(state),
  )
  use drain.GoAwayOutcome(drain_state, rejected) <- result.try(
    drain.refine(state.drain, identifier) |> map_drain_result,
  )
  use encoded <- result.try(
    frame.encode(frame.GoAway(identifier)) |> map_frame_result,
  )
  Ok(#(
    State(..state, drain: drain_state),
    StreamBytes(control_stream, encoded),
    rejected,
  ))
}

/// Current graceful-shutdown phase.
pub fn drain_phase(state: State) -> drain.Phase {
  drain.phase(state.drain)
}

/// Mark whether a server response currently has a bounded write quantum.
pub fn set_response_ready(
  state: State,
  stream_id: Int,
  ready: Bool,
) -> Result(State, Error) {
  use _ <- result.try(case state.config.role {
    Server -> Ok(Nil)
    Client -> Error(WrongRole)
  })
  use scheduler <- result.try(
    priority_scheduler.set_ready(state.scheduler, stream_id, ready)
    |> map_scheduler_result,
  )
  Ok(State(..state, scheduler: scheduler))
}

/// Select the next response write quantum using RFC 9218 priority and bounded
/// starvation. The returned state advances the fairness cursors.
pub fn next_response_stream(state: State) -> Option(#(State, Int)) {
  case priority_scheduler.next(state.scheduler) {
    None -> None
    Some(priority_scheduler.Selection(scheduler, stream_id)) ->
      Some(#(State(..state, scheduler: scheduler), stream_id))
  }
}

/// Advance a fixed graceful-drain deadline. Timed-out identifiers must be
/// cancelled at the QUIC layer before closing the connection.
pub fn on_drain_timer(
  state: State,
  now_ms: Int,
) -> Result(#(State, List(Int)), Error) {
  use outcome <- result.try(
    drain.on_timer(state.drain, now_ms) |> map_drain_result,
  )
  case outcome {
    drain.Draining(drain_state) | drain.DrainReady(drain_state) ->
      Ok(#(State(..state, drain: drain_state), []))
    drain.DrainTimedOut(drain_state, cancelled) ->
      Ok(#(State(..state, drain: drain_state), cancelled))
  }
}

/// Record that the QUIC application close was sent after drain convergence.
pub fn close_drained(state: State) -> Result(State, Error) {
  use drain_state <- result.try(drain.close(state.drain) |> map_drain_result)
  Ok(State(..state, drain: drain_state))
}

fn install_peer_settings(
  state: State,
  settings: control.Settings,
) -> Result(#(State, List(Event)), Error) {
  let capacity =
    minimum(
      settings.qpack_max_table_capacity,
      state.config.preferred_qpack_table_capacity,
    )
  let field_limit =
    minimum(
      settings.maximum_field_section_size,
      state.config.settings.maximum_field_section_size,
    )
  use qpack_encoder <- result.try(
    encoder.new(
      settings.qpack_max_table_capacity,
      capacity,
      settings.qpack_blocked_streams,
      state.config.maximum_fields,
      field_limit,
    )
    |> map_encoder_result,
  )
  use datagrams <- result.try(
    datagram.new(
      state.quic_datagram_negotiated,
      state.config.settings.h3_datagram && settings.h3_datagram,
      state.config.maximum_transactions,
      state.config.maximum_datagram_payload_bytes,
    )
    |> map_datagram_result,
  )
  Ok(
    #(
      State(
        ..state,
        peer_settings: Some(settings),
        qpack_encoder: qpack_encoder,
        datagrams: datagrams,
      ),
      [PeerSettings(settings)],
    ),
  )
}

fn receive_control_extension(
  state: State,
  incoming: frame.Frame,
  frame_type: Int,
) -> Result(#(State, List(Event)), Error) {
  case
    priority.from_frame(incoming, state.config.maximum_priority_field_bytes)
  {
    Error(priority.NotPriorityUpdate) ->
      Ok(#(state, [ExtensionFrameIgnored(frame_type)]))
    Error(error) -> Error(PriorityFailure(error))
    Ok(update) ->
      case state.config.role, update {
        Client, _ -> Error(FrameUnexpected)
        Server, priority.RequestUpdate(stream_id, value) -> {
          use state <- result.try(apply_request_priority(
            state,
            stream_id,
            value,
          ))
          Ok(#(state, [PriorityChanged(update)]))
        }
        Server, priority.PushUpdate(_, _) ->
          Ok(#(state, [PriorityChanged(update)]))
      }
  }
}

fn apply_request_priority(
  state: State,
  stream_id: Int,
  value: priority.Priority,
) -> Result(State, Error) {
  case priority_scheduler.update(state.scheduler, stream_id, value) {
    Ok(scheduler) -> Ok(State(..state, scheduler: scheduler))
    Error(priority_scheduler.MissingStream(_)) ->
      case
        dict.has_key(state.pending_priorities, stream_id),
        dict.size(state.pending_priorities) >= state.config.maximum_transactions
      {
        True, _ ->
          Ok(
            State(
              ..state,
              pending_priorities: dict.insert(
                state.pending_priorities,
                stream_id,
                value,
              ),
            ),
          )
        False, True ->
          Error(TransactionLimitExceeded(state.config.maximum_transactions))
        False, False ->
          Ok(
            State(
              ..state,
              pending_priorities: dict.insert(
                state.pending_priorities,
                stream_id,
                value,
              ),
            ),
          )
      }
    Error(error) -> Error(SchedulerFailure(error))
  }
}

fn ensure_inbound_transaction(
  state: State,
  stream_id: Int,
  incoming: frame.Frame,
) -> Result(State, Error) {
  case
    dict.has_key(state.transactions, stream_id),
    state.config.role,
    incoming
  {
    True, _, _ -> Ok(state)
    False, Client, _ -> Error(MissingTransaction(stream_id))
    False, Server, frame.Headers(_) -> {
      use _ <- result.try(ensure_transaction_capacity(state, stream_id))
      use acceptance <- result.try(
        drain.receive_request(state.drain, stream_id) |> map_drain_result,
      )
      case acceptance {
        drain.Rejected(_, _) -> Error(RequestRejected(stream_id))
        drain.Accepted(drain_state) -> {
          let priority =
            dict.get(state.pending_priorities, stream_id)
            |> result.unwrap(priority.default())
          use scheduler <- result.try(
            priority_scheduler.register(state.scheduler, stream_id, priority)
            |> map_scheduler_result,
          )
          let transaction =
            Transaction(
              message_stream.new(message_stream.Request),
              message_stream.new(message_stream.Response),
              False,
              False,
              False,
              False,
              False,
              None,
              None,
            )
          Ok(
            State(
              ..state,
              drain: drain_state,
              scheduler: scheduler,
              pending_priorities: dict.delete(
                state.pending_priorities,
                stream_id,
              ),
              transactions: dict.insert(
                state.transactions,
                stream_id,
                transaction,
              ),
            ),
          )
        }
      }
    }
    False, Server, _ -> Error(FrameUnexpected)
  }
}

fn receive_transaction_frame(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  incoming: frame.Frame,
) -> Result(#(State, List(Event)), Error) {
  case incoming {
    frame.Headers(encoded) ->
      decode_headers(state, stream_id, transaction, encoded, BlockedHeaders)
    frame.Data(bytes) -> {
      use inbound <- result.try(
        message_stream.receive_data(
          transaction.inbound,
          bytes,
          state.config.maximum_body_bytes,
        )
        |> map_message_result,
      )
      Ok(
        #(
          put_transaction(
            state,
            stream_id,
            Transaction(..transaction, inbound: inbound),
          ),
          [Data(stream_id, bytes)],
        ),
      )
    }
    frame.PushPromise(push_id, encoded) ->
      case state.config.role {
        Server -> Error(FrameUnexpected)
        Client ->
          decode_headers(
            state,
            stream_id,
            transaction,
            encoded,
            BlockedPushPromise(push_id),
          )
      }
    frame.Unknown(frame_type, _) ->
      Ok(#(state, [ExtensionFrameIgnored(frame_type)]))
    _ -> Error(FrameUnexpected)
  }
}

fn decode_headers(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  encoded: BitArray,
  blocked_kind: BlockedKind,
) -> Result(#(State, List(Event)), Error) {
  use outcome <- result.try(
    decoder.decode(state.qpack_decoder, stream_id, encoded)
    |> map_decoder_result,
  )
  case outcome {
    decoder.Blocked(qpack_decoder, required) -> {
      let transaction = Transaction(..transaction, blocked: Some(blocked_kind))
      Ok(
        #(
          put_transaction(
            State(..state, qpack_decoder: qpack_decoder),
            stream_id,
            transaction,
          ),
          [HeadersBlocked(stream_id, required)],
        ),
      )
    }
    decoder.Decoded(qpack_decoder, fields) ->
      process_decoded(
        State(..state, qpack_decoder: qpack_decoder),
        stream_id,
        transaction,
        blocked_kind,
        fields,
      )
  }
}

fn process_decoded(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  kind: BlockedKind,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  case kind {
    BlockedHeaders ->
      process_message_headers(state, stream_id, transaction, fields)
    BlockedPushPromise(push_id) ->
      process_push_promise(state, stream_id, transaction, push_id, fields)
  }
}

fn process_message_headers(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  case state.config.role, transaction.inbound_final_headers {
    Server, False -> {
      use validated <- result.try(
        header_semantics.validate(
          fields,
          header_semantics.RequestSection,
          state.config.settings.enable_connect_protocol,
        )
        |> map_header_result,
      )
      use #(request_control, content_length) <- result.try(request_metadata(
        validated,
      ))
      use inbound <- result.try(
        message_stream.receive_headers_with_length(
          transaction.inbound,
          message_stream.Final,
          content_length,
        )
        |> map_message_result,
      )
      let transaction =
        Transaction(
          ..transaction,
          inbound: inbound,
          inbound_final_headers: True,
          request_control: Some(request_control),
          blocked: None,
        )
      finish_after_unblock(
        put_transaction(state, stream_id, transaction),
        stream_id,
        transaction,
        [RequestHeaders(stream_id, validated)],
      )
    }
    Server, True -> process_trailers(state, stream_id, transaction, fields)
    Client, False ->
      process_response_headers(state, stream_id, transaction, fields)
    Client, True -> process_trailers(state, stream_id, transaction, fields)
  }
}

fn process_response_headers(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
    |> map_header_result,
  )
  use #(status, content_length) <- result.try(response_metadata(validated))
  let informational = header_semantics.is_informational_status(status)
  use content_length <- result.try(response_content_length(
    transaction.request_control,
    status,
    content_length,
  ))
  let kind = case informational {
    True -> message_stream.Informational
    False -> message_stream.Final
  }
  use inbound <- result.try(
    message_stream.receive_headers_with_length(
      transaction.inbound,
      kind,
      content_length,
    )
    |> map_message_result,
  )
  use inbound <- result.try(maybe_establish_connect(
    inbound,
    transaction.request_control,
    status,
  ))
  use outbound <- result.try(maybe_establish_connect(
    transaction.outbound,
    transaction.request_control,
    status,
  ))
  use datagrams <- result.try(associate_response_datagrams(
    state.datagrams,
    stream_id,
    transaction.request_control,
    status,
  ))
  let transaction =
    Transaction(
      ..transaction,
      inbound: inbound,
      outbound: outbound,
      inbound_final_headers: transaction.inbound_final_headers || !informational,
      blocked: None,
    )
  let event = case informational {
    True -> InformationalResponse(stream_id, validated)
    False -> ResponseHeaders(stream_id, validated)
  }
  finish_after_unblock(
    put_transaction(
      State(..state, datagrams: datagrams),
      stream_id,
      transaction,
    ),
    stream_id,
    transaction,
    [event],
  )
}

fn process_trailers(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.TrailerSection, False)
    |> map_header_result,
  )
  use inbound <- result.try(
    message_stream.receive_headers(transaction.inbound, message_stream.Trailers)
    |> map_message_result,
  )
  let transaction = Transaction(..transaction, inbound: inbound, blocked: None)
  finish_after_unblock(
    put_transaction(state, stream_id, transaction),
    stream_id,
    transaction,
    [Trailers(stream_id, validated)],
  )
}

fn process_push_promise(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  push_id: Int,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.RequestSection, False)
    |> map_header_result,
  )
  use pushes <- result.try(
    push.promise(state.pushes, push_id, stream_id, fields) |> map_push_result,
  )
  let transaction = Transaction(..transaction, blocked: None)
  use #(state, push_events) <- result.try(resume_push_after_promise(
    put_transaction(State(..state, pushes: pushes), stream_id, transaction),
    push_id,
  ))
  use #(state, request_events) <- result.try(
    finish_after_unblock(state, stream_id, transaction, []),
  )
  Ok(
    #(state, [
      PushPromised(push_id, validated),
      ..list.append(push_events, request_events)
    ]),
  )
}

fn open_inbound_push(
  state: State,
  stream_id: Int,
  push_id: Int,
  now_ms: Int,
  remaining: BitArray,
) -> Result(#(State, stream_registry.Kind, BitArray), Error) {
  use _ <- result.try(case state.config.role {
    Client -> Ok(Nil)
    Server -> Error(WrongRole)
  })
  use _ <- result.try(ensure_push_transaction_capacity(state, stream_id))
  use acceptance <- result.try(
    drain.receive_push(state.drain, push_id) |> map_drain_result,
  )
  use drain_state <- result.try(case acceptance {
    drain.Accepted(drain_state) -> Ok(drain_state)
    drain.Rejected(_, _) -> Error(PushRejected(push_id))
  })
  use pushes <- result.try(
    push.open_stream(state.pushes, push_id, stream_id, now_ms)
    |> map_push_result,
  )
  use request_control <- result.try(push_request_control(pushes, push_id))
  let transaction =
    PushTransaction(
      push_id,
      message_stream.new(message_stream.Response),
      False,
      False,
      False,
      request_control,
      None,
    )
  Ok(#(
    State(
      ..state,
      drain: drain_state,
      pushes: pushes,
      push_transactions: dict.insert(
        state.push_transactions,
        stream_id,
        transaction,
      ),
    ),
    stream_registry.Push(push_id),
    remaining,
  ))
}

fn receive_push_frame(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  incoming: frame.Frame,
) -> Result(#(State, List(Event)), Error) {
  case incoming {
    frame.Headers(field_section) ->
      decode_push_headers(state, stream_id, transaction, field_section)
    frame.Data(bytes) -> {
      use message <- result.try(
        message_stream.receive_data(
          transaction.message,
          bytes,
          state.config.maximum_body_bytes,
        )
        |> map_message_result,
      )
      Ok(
        #(
          put_push_transaction(
            state,
            stream_id,
            PushTransaction(..transaction, message: message),
          ),
          [PushData(transaction.push_id, stream_id, bytes)],
        ),
      )
    }
    frame.Unknown(frame_type, _) ->
      Ok(#(state, [ExtensionFrameIgnored(frame_type)]))
    _ -> Error(FrameUnexpected)
  }
}

fn decode_push_headers(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  field_section: BitArray,
) -> Result(#(State, List(Event)), Error) {
  use outcome <- result.try(
    decoder.decode(state.qpack_decoder, stream_id, field_section)
    |> map_decoder_result,
  )
  case outcome {
    decoder.Blocked(qpack_decoder, required) ->
      Ok(
        #(
          put_push_transaction(
            State(..state, qpack_decoder: qpack_decoder),
            stream_id,
            PushTransaction(..transaction, blocked: Some(PushQpackBlocked)),
          ),
          [HeadersBlocked(stream_id, required)],
        ),
      )
    decoder.Decoded(qpack_decoder, fields) ->
      process_inbound_push_headers(
        State(..state, qpack_decoder: qpack_decoder),
        stream_id,
        transaction,
        fields,
      )
  }
}

fn process_inbound_push_headers(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  case transaction.request_control {
    None ->
      Ok(
        #(
          put_push_transaction(
            state,
            stream_id,
            PushTransaction(
              ..transaction,
              blocked: Some(PushPromiseBlocked(fields)),
            ),
          ),
          [PushAwaitingPromise(transaction.push_id, stream_id)],
        ),
      )
    Some(request_control) ->
      process_inbound_push_headers_with_request(
        state,
        stream_id,
        transaction,
        request_control,
        fields,
      )
  }
}

fn process_inbound_push_headers_with_request(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  request_control: header_semantics.RequestControl,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  case transaction.final_headers {
    True -> process_inbound_push_trailers(state, stream_id, transaction, fields)
    False -> {
      use validated <- result.try(
        header_semantics.validate(
          fields,
          header_semantics.ResponseSection,
          False,
        )
        |> map_header_result,
      )
      use #(status, content_length) <- result.try(response_metadata(validated))
      let informational = header_semantics.is_informational_status(status)
      use content_length <- result.try(response_content_length(
        Some(request_control),
        status,
        content_length,
      ))
      let kind = case informational {
        True -> message_stream.Informational
        False -> message_stream.Final
      }
      use message <- result.try(
        message_stream.receive_headers_with_length(
          transaction.message,
          kind,
          content_length,
        )
        |> map_message_result,
      )
      let transaction =
        PushTransaction(
          ..transaction,
          message: message,
          final_headers: transaction.final_headers || !informational,
          blocked: None,
        )
      let event = case informational {
        True ->
          PushInformationalResponse(transaction.push_id, stream_id, validated)
        False -> PushResponseHeaders(transaction.push_id, stream_id, validated)
      }
      finish_push_after_unblock(
        put_push_transaction(state, stream_id, transaction),
        stream_id,
        transaction,
        [event],
      )
    }
  }
}

fn process_inbound_push_trailers(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  fields: List(Header),
) -> Result(#(State, List(Event)), Error) {
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.TrailerSection, False)
    |> map_header_result,
  )
  use message <- result.try(
    message_stream.receive_headers(transaction.message, message_stream.Trailers)
    |> map_message_result,
  )
  let transaction =
    PushTransaction(..transaction, message: message, blocked: None)
  finish_push_after_unblock(
    put_push_transaction(state, stream_id, transaction),
    stream_id,
    transaction,
    [PushTrailers(transaction.push_id, stream_id, validated)],
  )
}

fn finish_push_after_unblock(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
  events: List(Event),
) -> Result(#(State, List(Event)), Error) {
  case transaction.fin_pending {
    False -> Ok(#(state, events))
    True -> {
      use #(state, finished) <- result.try(finish_inbound_push(
        state,
        stream_id,
        PushTransaction(..transaction, fin_pending: False),
      ))
      Ok(#(state, list.append(events, finished)))
    }
  }
}

fn finish_inbound_push(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
) -> Result(#(State, List(Event)), Error) {
  case transaction.blocked {
    Some(_) ->
      Ok(
        #(
          put_push_transaction(
            state,
            stream_id,
            PushTransaction(..transaction, fin_pending: True),
          ),
          [],
        ),
      )
    None -> {
      use _ <- result.try(
        message_stream.finish(transaction.message) |> map_message_result,
      )
      use peer_streams <- result.try(
        stream_registry.close(state.peer_streams, stream_id)
        |> map_registry_result,
      )
      use state <- result.try(finish_push_lifecycle(
        State(..state, peer_streams: peer_streams),
        stream_id,
        transaction.push_id,
      ))
      Ok(#(state, [PushFinished(transaction.push_id, stream_id)]))
    }
  }
}

fn resume_push_after_promise(
  state: State,
  push_id: Int,
) -> Result(#(State, List(Event)), Error) {
  resume_push_entries(state, push_id, dict.to_list(state.push_transactions))
}

fn resume_push_entries(
  state: State,
  push_id: Int,
  entries: List(#(Int, PushTransaction)),
) -> Result(#(State, List(Event)), Error) {
  case entries {
    [] -> Ok(#(state, []))
    [#(stream_id, transaction), ..] if transaction.push_id == push_id -> {
      use request_control <- result.try(require_push_request_control(
        state.pushes,
        push_id,
      ))
      let transaction =
        PushTransaction(..transaction, request_control: Some(request_control))
      case transaction.blocked {
        Some(PushPromiseBlocked(fields)) ->
          process_inbound_push_headers(
            state,
            stream_id,
            PushTransaction(..transaction, blocked: None),
            fields,
          )
        _ -> Ok(#(put_push_transaction(state, stream_id, transaction), []))
      }
    }
    [_, ..rest] -> resume_push_entries(state, push_id, rest)
  }
}

// nolint: deep_nesting -- each branch preserves ordered QPACK retry state and events.
fn retry_blocked(
  state: State,
  stream_ids: List(Int),
  events_reversed: List(Event),
) -> Result(#(State, List(Event)), Error) {
  case stream_ids {
    [] -> Ok(#(state, list.reverse(events_reversed)))
    [stream_id, ..rest] ->
      case
        dict.get(state.transactions, stream_id)
        |> result.map(Some)
        |> result.unwrap(None)
      {
        None -> retry_blocked_push(state, stream_id, rest, events_reversed)
        Some(transaction) ->
          case transaction.blocked {
            None -> retry_blocked(state, rest, events_reversed)
            Some(kind) -> {
              use outcome <- result.try(
                decoder.retry_blocked(state.qpack_decoder, stream_id)
                |> map_decoder_result,
              )
              case outcome {
                decoder.Blocked(qpack_decoder, _) ->
                  retry_blocked(
                    State(..state, qpack_decoder: qpack_decoder),
                    rest,
                    events_reversed,
                  )
                decoder.Decoded(qpack_decoder, fields) -> {
                  use #(state, events) <- result.try(process_decoded(
                    State(..state, qpack_decoder: qpack_decoder),
                    stream_id,
                    transaction,
                    kind,
                    fields,
                  ))
                  retry_blocked(
                    state,
                    rest,
                    list.append(list.reverse(events), events_reversed),
                  )
                }
              }
            }
          }
      }
  }
}

// nolint: deep_nesting -- each branch preserves ordered QPACK retry state and events.
fn retry_blocked_push(
  state: State,
  stream_id: Int,
  remaining_streams: List(Int),
  events_reversed: List(Event),
) -> Result(#(State, List(Event)), Error) {
  case
    dict.get(state.push_transactions, stream_id)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> retry_blocked(state, remaining_streams, events_reversed)
    Some(transaction) ->
      case transaction.blocked {
        Some(PushQpackBlocked) -> {
          use outcome <- result.try(
            decoder.retry_blocked(state.qpack_decoder, stream_id)
            |> map_decoder_result,
          )
          case outcome {
            decoder.Blocked(qpack_decoder, _) ->
              retry_blocked(
                State(..state, qpack_decoder: qpack_decoder),
                remaining_streams,
                events_reversed,
              )
            decoder.Decoded(qpack_decoder, fields) -> {
              use #(state, events) <- result.try(process_inbound_push_headers(
                State(..state, qpack_decoder: qpack_decoder),
                stream_id,
                PushTransaction(..transaction, blocked: None),
                fields,
              ))
              retry_blocked(
                state,
                remaining_streams,
                list.append(list.reverse(events), events_reversed),
              )
            }
          }
        }
        _ -> retry_blocked(state, remaining_streams, events_reversed)
      }
  }
}

fn finish_after_unblock(
  state: State,
  stream_id: Int,
  transaction: Transaction,
  events: List(Event),
) -> Result(#(State, List(Event)), Error) {
  case transaction.inbound_fin_pending {
    False -> Ok(#(state, events))
    True -> {
      use #(state, finished) <- result.try(finish_inbound(
        state,
        stream_id,
        Transaction(..transaction, inbound_fin_pending: False),
      ))
      Ok(#(state, list.append(events, finished)))
    }
  }
}

fn finish_inbound(
  state: State,
  stream_id: Int,
  transaction: Transaction,
) -> Result(#(State, List(Event)), Error) {
  use inbound <- result.try(
    message_stream.finish(transaction.inbound) |> map_message_result,
  )
  let transaction =
    Transaction(
      ..transaction,
      inbound: inbound,
      inbound_finished: True,
      inbound_fin_pending: False,
    )
  let state = put_transaction(state, stream_id, transaction)
  let state = case state.config.role {
    Client -> complete_drain_work(state, stream_id)
    Server -> state
  }
  Ok(#(cleanup_if_complete(state, stream_id), [StreamFinished(stream_id)]))
}

fn complete_drain_work(state: State, stream_id: Int) -> State {
  drain.complete_request(state.drain, stream_id)
  |> result.map(fn(drain_state) { State(..state, drain: drain_state) })
  |> result.unwrap(state)
}

fn response_content_length(
  request: Option(header_semantics.RequestControl),
  status: Int,
  content_length: Option(Int),
) -> Result(Option(Int), Error) {
  let method = request_method(request)
  case status, method, content_length {
    value, _, Some(_) if value >= 100 && value < 200 ->
      Error(InvalidMessageFraming)
    204, _, Some(_) -> Error(InvalidMessageFraming)
    value, Some(<<"CONNECT">>), Some(_) if value >= 200 && value < 300 ->
      Error(InvalidMessageFraming)
    204, _, None -> Ok(Some(0))
    205, _, Some(value) if value != 0 -> Error(InvalidMessageFraming)
    205, _, _ -> Ok(Some(0))
    304, _, _ -> Ok(Some(0))
    _, Some(<<"HEAD">>), _ -> Ok(Some(0))
    value, Some(<<"CONNECT">>), _ if value >= 200 && value < 300 -> Ok(None)
    _, _, value -> Ok(value)
  }
}

fn request_metadata(
  validated: header_semantics.Validated,
) -> Result(#(header_semantics.RequestControl, Option(Int)), Error) {
  case validated {
    header_semantics.Validated(
      header_semantics.RequestControlData(control),
      _,
      content_length,
    ) -> Ok(#(control, content_length))
    _ -> Error(InvalidMessageFraming)
  }
}

fn response_metadata(
  validated: header_semantics.Validated,
) -> Result(#(Int, Option(Int)), Error) {
  case validated {
    header_semantics.Validated(
      header_semantics.ResponseControlData(status),
      _,
      content_length,
    ) -> Ok(#(status, content_length))
    _ -> Error(InvalidMessageFraming)
  }
}

fn maybe_establish_connect(
  stream: message_stream.State,
  request: Option(header_semantics.RequestControl),
  status: Int,
) -> Result(message_stream.State, Error) {
  case request_method(request), status >= 200 && status < 300 {
    Some(<<"CONNECT">>), True ->
      message_stream.establish_connect(stream) |> map_message_result
    _, _ -> Ok(stream)
  }
}

fn request_method(
  request: Option(header_semantics.RequestControl),
) -> Option(BitArray) {
  case request {
    Some(header_semantics.RequestControl(method, _, _, _, _)) -> Some(method)
    None -> None
  }
}

fn associate_response_datagrams(
  datagrams: datagram.State,
  stream_id: Int,
  request: Option(header_semantics.RequestControl),
  status: Int,
) -> Result(datagram.State, Error) {
  let protocol = case request {
    Some(header_semantics.RequestControl(<<"CONNECT">>, _, _, _, protocol))
      if status >= 200 && status < 300
    -> protocol
    _ -> None
  }
  case protocol {
    None -> Ok(datagrams)
    Some(protocol) -> {
      use extension <- result.try(
        datagram.extension(protocol) |> map_datagram_result,
      )
      case
        datagram.associate(
          datagrams,
          stream_id,
          extension,
          datagram.UnreliableAndCapsules,
        )
      {
        Ok(datagrams) -> Ok(datagrams)
        Error(datagram.UnreliableDatagramNotNegotiated) ->
          datagram.associate(datagrams, stream_id, extension, datagram.Capsules)
          |> map_datagram_result
        Error(error) -> Error(DatagramFailure(error))
      }
    }
  }
}

fn local_settings_frame(settings: Settings) -> frame.Frame {
  let settings_list = [
    frame.Setting(1, settings.qpack_max_table_capacity),
    frame.Setting(6, settings.maximum_field_section_size),
    frame.Setting(7, settings.qpack_blocked_streams),
    frame.Setting(8, bool_int(settings.enable_connect_protocol)),
    frame.Setting(0x33, bool_int(settings.h3_datagram)),
  ]
  let settings_list = case settings.grease {
    True -> list.append(settings_list, [frame.Setting(0x21, 0)])
    False -> settings_list
  }
  frame.Settings(settings_list)
}

fn encode_encoder_instructions(
  instructions: List(instruction.EncoderInstruction),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case instructions {
    [] -> Ok(accumulator)
    [next, ..rest] -> {
      use encoded <- result.try(
        instruction.encode_encoder(next, True) |> map_instruction_result,
      )
      encode_encoder_instructions(rest, <<accumulator:bits, encoded:bits>>)
    }
  }
}

fn encode_decoder_instructions(
  instructions: List(instruction.DecoderInstruction),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case instructions {
    [] -> Ok(accumulator)
    [next, ..rest] -> {
      use encoded <- result.try(
        instruction.encode_decoder(next) |> map_instruction_result,
      )
      encode_decoder_instructions(rest, <<accumulator:bits, encoded:bits>>)
    }
  }
}

fn peer_connect_enabled(state: State) -> Bool {
  case state.peer_settings {
    Some(settings) -> settings.enable_connect_protocol
    None -> False
  }
}

fn get_transaction(state: State, stream_id: Int) -> Result(Transaction, Error) {
  case dict.get(state.transactions, stream_id) {
    Ok(transaction) -> Ok(transaction)
    Error(_) -> Error(MissingTransaction(stream_id))
  }
}

fn get_push_transaction(
  state: State,
  stream_id: Int,
) -> Result(PushTransaction, Error) {
  case dict.get(state.push_transactions, stream_id) {
    Ok(transaction) -> Ok(transaction)
    Error(_) -> Error(MissingTransaction(stream_id))
  }
}

fn put_push_transaction(
  state: State,
  stream_id: Int,
  transaction: PushTransaction,
) -> State {
  State(
    ..state,
    push_transactions: dict.insert(
      state.push_transactions,
      stream_id,
      transaction,
    ),
  )
}

fn ensure_push_transaction_capacity(
  state: State,
  stream_id: Int,
) -> Result(Nil, Error) {
  case
    dict.has_key(state.push_transactions, stream_id),
    dict.size(state.push_transactions)
  {
    True, _ -> Error(DuplicateTransaction(stream_id))
    False, count if count >= state.config.maximum_pushes ->
      Error(TransactionLimitExceeded(state.config.maximum_pushes))
    False, _ -> Ok(Nil)
  }
}

fn push_request_control(
  pushes: push.State,
  push_id: Int,
) -> Result(Option(header_semantics.RequestControl), Error) {
  case push.get(pushes, push_id) {
    None -> Error(MissingPushPromise(push_id))
    Some(push.Push(_, None, _, _, _)) -> Ok(None)
    Some(push.Push(_, Some(fields), _, _, _)) -> {
      use validated <- result.try(
        header_semantics.validate(
          fields,
          header_semantics.RequestSection,
          False,
        )
        |> map_header_result,
      )
      use #(control, _) <- result.try(request_metadata(validated))
      Ok(Some(control))
    }
  }
}

fn require_push_request_control(
  pushes: push.State,
  push_id: Int,
) -> Result(header_semantics.RequestControl, Error) {
  use control <- result.try(push_request_control(pushes, push_id))
  case control {
    Some(value) -> Ok(value)
    None -> Error(MissingPushPromise(push_id))
  }
}

fn finish_push_lifecycle(
  state: State,
  stream_id: Int,
  push_id: Int,
) -> Result(State, Error) {
  use pushes <- result.try(
    push.complete(state.pushes, push_id) |> map_push_result,
  )
  use pushes <- result.try(push.release(pushes, push_id) |> map_push_result)
  use drain_state <- result.try(
    drain.complete_push(state.drain, push_id) |> map_drain_result,
  )
  Ok(
    State(
      ..state,
      pushes: pushes,
      drain: drain_state,
      push_transactions: dict.delete(state.push_transactions, stream_id),
    ),
  )
}

fn cancel_push_transactions(
  state: State,
  push_ids: List(Int),
  events_reversed: List(Event),
) -> Result(#(State, List(Event)), Error) {
  case push_ids {
    [] -> Ok(#(state, list.reverse(events_reversed)))
    [push_id, ..rest] -> {
      let stream_id =
        push_transaction_stream_id(
          dict.to_list(state.push_transactions),
          push_id,
        )
      let state = remove_push_transaction_by_id(state, push_id)
      let state = complete_push_drain(state, push_id)
      let state = case state.config.role {
        Server -> release_terminal_push(state, push_id)
        Client -> state
      }
      let events = case stream_id {
        Some(identifier) -> [
          PushStreamCancellationRequested(push_id, identifier),
          ..events_reversed
        ]
        None -> events_reversed
      }
      cancel_push_transactions(state, rest, events)
    }
  }
}

fn push_transaction_stream_id(
  entries: List(#(Int, PushTransaction)),
  push_id: Int,
) -> Option(Int) {
  case entries {
    [] -> None
    [#(stream_id, transaction), ..] if transaction.push_id == push_id ->
      Some(stream_id)
    [_, ..rest] -> push_transaction_stream_id(rest, push_id)
  }
}

fn remove_push_transaction_by_id(state: State, push_id: Int) -> State {
  case
    push_transaction_stream_id(dict.to_list(state.push_transactions), push_id)
  {
    None -> state
    Some(stream_id) ->
      State(
        ..state,
        push_transactions: dict.delete(state.push_transactions, stream_id),
      )
  }
}

fn complete_push_drain(state: State, push_id: Int) -> State {
  drain.complete_push(state.drain, push_id)
  |> result.map(fn(drain_state) { State(..state, drain: drain_state) })
  |> result.unwrap(state)
}

fn release_terminal_push(state: State, push_id: Int) -> State {
  push.release(state.pushes, push_id)
  |> result.map(fn(pushes) { State(..state, pushes: pushes) })
  |> result.unwrap(state)
}

fn expire_push_streams(
  state: State,
  stream_ids: List(Int),
) -> Result(#(State, List(Int)), Error) {
  case stream_ids {
    [] -> Ok(#(state, []))
    [stream_id, ..rest] -> {
      let push_id =
        dict.get(state.push_transactions, stream_id)
        |> result.map(fn(transaction) { Some(transaction.push_id) })
        |> result.unwrap(None)
      use peer_streams <- result.try(
        stream_registry.close(state.peer_streams, stream_id)
        |> map_registry_result,
      )
      let state =
        State(
          ..state,
          peer_streams: peer_streams,
          push_transactions: dict.delete(state.push_transactions, stream_id),
        )
      let state = case push_id {
        Some(value) -> complete_push_drain(state, value)
        None -> state
      }
      use #(state, expired) <- result.try(expire_push_streams(state, rest))
      Ok(#(state, [stream_id, ..expired]))
    }
  }
}

fn cleanup_if_complete(state: State, stream_id: Int) -> State {
  case dict.get(state.transactions, stream_id) {
    Ok(Transaction(_, _, _, _, True, True, _, _, _)) ->
      State(
        ..state,
        transactions: dict.delete(state.transactions, stream_id),
        scheduler: priority_scheduler.remove(state.scheduler, stream_id),
        datagrams: datagram.remove(state.datagrams, stream_id),
      )
    _ -> state
  }
}

fn put_transaction(
  state: State,
  stream_id: Int,
  transaction: Transaction,
) -> State {
  State(
    ..state,
    transactions: dict.insert(state.transactions, stream_id, transaction),
  )
}

fn ensure_transaction_capacity(
  state: State,
  stream_id: Int,
) -> Result(Nil, Error) {
  case
    dict.has_key(state.transactions, stream_id),
    dict.size(state.transactions)
  {
    True, _ -> Error(DuplicateTransaction(stream_id))
    False, count if count >= state.config.maximum_transactions ->
      Error(TransactionLimitExceeded(state.config.maximum_transactions))
    False, _ -> Ok(Nil)
  }
}

fn require_critical_streams(state: State) -> Result(CriticalStreams, Error) {
  case state.critical_streams {
    Some(streams) -> Ok(streams)
    None -> Error(CriticalStreamsNotInstalled)
  }
}

fn validate_config(
  config: Config,
  quic_datagram_negotiated: Bool,
) -> Result(Nil, Error) {
  let settings = config.settings
  case
    settings.qpack_max_table_capacity >= 0
    && settings.qpack_max_table_capacity <= varint.maximum
    && settings.maximum_field_section_size >= 0
    && settings.maximum_field_section_size <= varint.maximum
    && settings.qpack_blocked_streams >= 0
    && settings.qpack_blocked_streams <= varint.maximum
    && { !settings.h3_datagram || quic_datagram_negotiated }
    && config.preferred_qpack_table_capacity >= 0
    && config.maximum_fields > 0
    && config.maximum_body_bytes >= 0
    && config.maximum_transactions > 0
    && config.maximum_pushes >= 0
    && config.push_promise_timeout_ms > 0
    && config.maximum_datagram_payload_bytes >= 0
    && config.maximum_priority_field_bytes > 0
    && config.drain_timeout_ms > 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  }
}

fn validate_local_unidirectional(
  role: Role,
  identifier: Int,
) -> Result(Nil, Error) {
  case stream_id.decode(identifier), role {
    Ok(stream_id.StreamId(_, stream_id.Client, stream_id.Unidirectional)),
      Client
    -> Ok(Nil)
    Ok(stream_id.StreamId(_, stream_id.Server, stream_id.Unidirectional)),
      Server
    -> Ok(Nil)
    _, _ -> Error(InvalidStreamId(identifier))
  }
}

fn validate_request_stream(identifier: Int) -> Result(Nil, Error) {
  case identifier >= 0 && identifier <= varint.maximum && identifier % 4 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidStreamId(identifier))
  }
}

fn minimum(first: Int, second: Int) -> Int {
  case first < second {
    True -> first
    False -> second
  }
}

fn bool_int(value: Bool) -> Int {
  case value {
    True -> 1
    False -> 0
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case varint.encode(value) {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_control_result(
  value: Result(value, control.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(ControlFailure(error))
  }
}

fn map_frame_result(value: Result(value, frame.Error)) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(FrameFailure(error))
  }
}

fn map_header_result(
  value: Result(value, header_semantics.Error),
) -> Result(value, Error) {
  case value {
    Ok(validated) -> Ok(validated)
    Error(error) -> Error(HeaderFailure(error))
  }
}

fn map_message_result(
  value: Result(value, message_stream.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(MessageFailure(error))
  }
}

fn map_encoder_result(
  value: Result(value, encoder.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(EncoderFailure(error))
  }
}

fn map_decoder_result(
  value: Result(value, decoder.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(DecoderFailure(error))
  }
}

fn map_instruction_result(
  value: Result(value, instruction.Error),
) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(InstructionFailure(error))
  }
}

fn map_push_result(value: Result(value, push.Error)) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(PushFailure(error))
  }
}

fn map_drain_result(value: Result(value, drain.Error)) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(DrainFailure(error))
  }
}

fn map_datagram_result(
  value: Result(value, datagram.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(DatagramFailure(error))
  }
}

fn map_registry_result(
  value: Result(value, stream_registry.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(StreamRegistryFailure(error))
  }
}

fn map_scheduler_result(
  value: Result(value, priority_scheduler.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(SchedulerFailure(error))
  }
}

fn map_priority_result(
  value: Result(value, priority.Error),
) -> Result(value, Error) {
  case value {
    Ok(updated) -> Ok(updated)
    Error(error) -> Error(PriorityFailure(error))
  }
}
