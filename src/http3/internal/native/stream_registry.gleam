//// HTTP/3 unidirectional stream classification and critical-stream lifetime.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/stream_id
import gleam_quic/varint

/// Role of the peer that opens the streams tracked by this registry.
pub type PeerRole {
  Client
  Server
}

/// Decoded HTTP/3 unidirectional stream purpose.
pub type Kind {
  Control
  Push(push_id: Int)
  QpackEncoder
  QpackDecoder
  Unknown(stream_type: Int)
}

/// Parsed stream prefix with application bytes left untouched.
pub type Preface {
  Preface(kind: Kind, remaining: BitArray)
}

/// Peer critical streams and active push-stream identifiers.
pub opaque type State {
  State(
    peer_role: PeerRole,
    control_stream: Option(Int),
    qpack_encoder_stream: Option(Int),
    qpack_decoder_stream: Option(Int),
    maximum_push_id: Option(Int),
    push_streams: Dict(Int, Int),
    maximum_active_push_streams: Int,
  )
}

/// Invalid, duplicated, prohibited, truncated, or prematurely closed stream.
pub type Error {
  InvalidConfiguration
  InvalidStreamId(Int)
  InvalidStreamType(Int)
  TruncatedPreface
  DuplicateControlStream
  DuplicateQpackEncoderStream
  DuplicateQpackDecoderStream
  PushStreamFromClient
  MissingPushId
  UnexpectedPushId
  PushIdNotAllowed(Int)
  DuplicatePushId(Int)
  PushStreamLimitExceeded(Int)
  ClosedCriticalStream(Int)
  IntegerFailure(varint.Error)
}

/// Start a bounded registry for streams initiated by one peer.
pub fn new(
  peer_role: PeerRole,
  maximum_active_push_streams: Int,
) -> Result(State, Error) {
  case maximum_active_push_streams >= 0 {
    True ->
      Ok(State(
        peer_role,
        None,
        None,
        None,
        None,
        dict.new(),
        maximum_active_push_streams,
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Update the largest push ID this endpoint has permitted its server peer to
/// use. The limit can only increase.
pub fn permit_pushes_through(
  state: State,
  maximum_push_id: Int,
) -> Result(State, Error) {
  case
    state.peer_role,
    maximum_push_id >= 0 && maximum_push_id <= varint.maximum,
    state.maximum_push_id
  {
    Client, _, _ -> Error(PushStreamFromClient)
    _, False, _ -> Error(PushIdNotAllowed(maximum_push_id))
    Server, True, Some(previous) if maximum_push_id < previous ->
      Error(PushIdNotAllowed(maximum_push_id))
    Server, True, _ ->
      Ok(State(..state, maximum_push_id: Some(maximum_push_id)))
  }
}

/// Parse a complete available stream preface. Unknown stream types consume
/// only their type; push streams additionally consume the Push ID.
pub fn decode_preface(bytes: BitArray) -> Result(Preface, Error) {
  use #(stream_type, remaining) <- result.try(decode_integer(bytes))
  case stream_type {
    0 -> Ok(Preface(Control, remaining))
    1 -> {
      use #(push_id, remaining) <- result.try(decode_integer(remaining))
      Ok(Preface(Push(push_id), remaining))
    }
    2 -> Ok(Preface(QpackEncoder, remaining))
    3 -> Ok(Preface(QpackDecoder, remaining))
    value -> Ok(Preface(Unknown(value), remaining))
  }
}

/// Register one classified peer-initiated unidirectional stream.
pub fn open(state: State, identifier: Int, kind: Kind) -> Result(State, Error) {
  use _ <- result.try(validate_peer_stream(state.peer_role, identifier))
  case kind {
    Control -> register_control(state, identifier)
    QpackEncoder -> register_qpack_encoder(state, identifier)
    QpackDecoder -> register_qpack_decoder(state, identifier)
    Push(push_id) -> register_push(state, identifier, push_id)
    Unknown(stream_type) ->
      case stream_type >= 0 && stream_type <= varint.maximum {
        True -> Ok(state)
        False -> Error(InvalidStreamType(stream_type))
      }
  }
}

/// Observe a FIN or reset. Ending a control or QPACK stream is fatal; ending a
/// push or unknown stream is allowed and releases its registry slot.
pub fn close(state: State, identifier: Int) -> Result(State, Error) {
  case
    state.control_stream == Some(identifier)
    || state.qpack_encoder_stream == Some(identifier)
    || state.qpack_decoder_stream == Some(identifier)
  {
    True -> Error(ClosedCriticalStream(identifier))
    False ->
      Ok(
        State(
          ..state,
          push_streams: delete_stream(state.push_streams, identifier),
        ),
      )
  }
}

/// Active registered server push streams.
pub fn active_push_streams(state: State) -> Int {
  dict.size(state.push_streams)
}

fn register_control(state: State, identifier: Int) -> Result(State, Error) {
  case state.control_stream {
    Some(_) -> Error(DuplicateControlStream)
    None -> Ok(State(..state, control_stream: Some(identifier)))
  }
}

fn register_qpack_encoder(
  state: State,
  identifier: Int,
) -> Result(State, Error) {
  case state.qpack_encoder_stream {
    Some(_) -> Error(DuplicateQpackEncoderStream)
    None -> Ok(State(..state, qpack_encoder_stream: Some(identifier)))
  }
}

fn register_qpack_decoder(
  state: State,
  identifier: Int,
) -> Result(State, Error) {
  case state.qpack_decoder_stream {
    Some(_) -> Error(DuplicateQpackDecoderStream)
    None -> Ok(State(..state, qpack_decoder_stream: Some(identifier)))
  }
}

fn register_push(
  state: State,
  identifier: Int,
  push_id: Int,
) -> Result(State, Error) {
  case state.peer_role, state.maximum_push_id {
    Client, _ -> Error(PushStreamFromClient)
    Server, None -> Error(PushIdNotAllowed(push_id))
    Server, Some(maximum) if push_id < 0 || push_id > maximum ->
      Error(PushIdNotAllowed(push_id))
    Server, Some(_) ->
      case
        dict.has_key(state.push_streams, push_id),
        dict.size(state.push_streams)
      {
        True, _ -> Error(DuplicatePushId(push_id))
        False, count if count >= state.maximum_active_push_streams ->
          Error(PushStreamLimitExceeded(state.maximum_active_push_streams))
        False, _ ->
          Ok(
            State(
              ..state,
              push_streams: dict.insert(state.push_streams, push_id, identifier),
            ),
          )
      }
  }
}

fn validate_peer_stream(
  peer_role: PeerRole,
  identifier: Int,
) -> Result(Nil, Error) {
  case stream_id.decode(identifier) {
    Ok(stream_id.StreamId(_, initiator, stream_id.Unidirectional)) -> {
      let expected = case peer_role {
        Client -> stream_id.Client
        Server -> stream_id.Server
      }
      case initiator == expected {
        True -> Ok(Nil)
        False -> Error(InvalidStreamId(identifier))
      }
    }
    _ -> Error(InvalidStreamId(identifier))
  }
}

fn delete_stream(streams: Dict(Int, Int), identifier: Int) -> Dict(Int, Int) {
  delete_stream_entries(dict.to_list(streams), streams, identifier)
}

fn delete_stream_entries(
  entries: List(#(Int, Int)),
  streams: Dict(Int, Int),
  identifier: Int,
) -> Dict(Int, Int) {
  case entries {
    [] -> streams
    [#(push_id, current), ..rest] if current == identifier ->
      delete_stream_entries(rest, dict.delete(streams, push_id), identifier)
    [_, ..rest] -> delete_stream_entries(rest, streams, identifier)
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(varint.Truncated) -> Error(TruncatedPreface)
    Error(error) -> Error(IntegerFailure(error))
  }
}
