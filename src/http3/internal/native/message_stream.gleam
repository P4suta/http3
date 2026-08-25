//// HTTP/3 request/response field-section, body, and trailer sequencing.

import gleam/bit_array
import gleam/option.{type Option, None, Some}

/// Semantics carried by one bidirectional request stream.
pub type MessageKind {
  Request
  Response
}

/// Classification produced after QPACK and pseudo-header validation.
pub type HeaderKind {
  Informational
  Final
  Trailers
}

/// One bounded message-stream state.
pub opaque type State {
  State(
    message_kind: MessageKind,
    final_headers_received: Bool,
    trailers_received: Bool,
    body_bytes: Int,
    content_length: Option(Int),
    connect_established: Bool,
    finished: Bool,
  )
}

/// Invalid HTTP message frame ordering.
pub type Error {
  InformationalRequestHeaders
  DataBeforeFinalHeaders
  DuplicateFinalHeaders
  TrailersBeforeFinalHeaders
  DuplicateTrailers
  HeadersAfterTrailers
  DataAfterTrailers
  FrameAfterFinished
  MissingFinalHeaders
  BodyLimitExceeded(Int)
  ContentLengthExceeded(expected: Int, attempted: Int)
  ContentLengthMismatch(expected: Int, actual: Int)
  ConnectBeforeFinalHeaders
  HeadersAfterConnect
  NonByteAligned
}

/// Start one inbound request or response with a fixed body bound.
pub fn new(message_kind: MessageKind) -> State {
  State(message_kind, False, False, 0, None, False, False)
}

/// Accept one classified HEADERS field section.
pub fn receive_headers(
  state: State,
  header_kind: HeaderKind,
) -> Result(State, Error) {
  receive_headers_with_length(state, header_kind, None)
}

/// Accept classified HEADERS and retain the validated Content-Length on the
/// final header section. Trailers cannot replace message framing metadata.
pub fn receive_headers_with_length(
  state: State,
  header_kind: HeaderKind,
  content_length: Option(Int),
) -> Result(State, Error) {
  case state.finished, state.connect_established, state.trailers_received {
    True, _, _ -> Error(FrameAfterFinished)
    _, True, _ -> Error(HeadersAfterConnect)
    _, _, True -> Error(HeadersAfterTrailers)
    False, False, False ->
      receive_open_headers(state, header_kind, content_length)
  }
}

/// Account a DATA frame without retaining its bytes.
pub fn receive_data(
  state: State,
  data: BitArray,
  maximum_body_bytes: Int,
) -> Result(State, Error) {
  case bit_array.bit_size(data) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      receive_aligned_data(state, bit_array.byte_size(data), maximum_body_bytes)
  }
}

/// Finish the QUIC stream only after final headers have arrived.
pub fn finish(state: State) -> Result(State, Error) {
  case state.finished, state.final_headers_received {
    True, _ -> Ok(state)
    False, False -> Error(MissingFinalHeaders)
    False, True ->
      case state.content_length {
        Some(expected) if expected != state.body_bytes ->
          Error(ContentLengthMismatch(expected, state.body_bytes))
        _ -> Ok(State(..state, finished: True))
      }
  }
}

/// Enter tunnel/capsule data mode after successful CONNECT response handling.
/// Once established, ordinary HEADERS are prohibited on the stream.
pub fn establish_connect(state: State) -> Result(State, Error) {
  case state.finished, state.final_headers_received, state.trailers_received {
    True, _, _ -> Error(FrameAfterFinished)
    _, False, _ -> Error(ConnectBeforeFinalHeaders)
    _, _, True -> Error(HeadersAfterTrailers)
    False, True, False -> Ok(State(..state, connect_established: True))
  }
}

/// Return body bytes accepted across DATA frames.
pub fn body_bytes(state: State) -> Int {
  state.body_bytes
}

fn receive_open_headers(
  state: State,
  header_kind: HeaderKind,
  content_length: Option(Int),
) -> Result(State, Error) {
  case state.message_kind, header_kind, state.final_headers_received {
    Request, Informational, _ -> Error(InformationalRequestHeaders)
    _, Informational, True -> Error(DuplicateFinalHeaders)
    Response, Informational, False -> Ok(state)
    _, Final, True -> Error(DuplicateFinalHeaders)
    _, Final, False ->
      Ok(
        State(
          ..state,
          final_headers_received: True,
          content_length: content_length,
        ),
      )
    _, Trailers, False -> Error(TrailersBeforeFinalHeaders)
    _, Trailers, True -> Ok(State(..state, trailers_received: True))
  }
}

fn receive_aligned_data(
  state: State,
  length: Int,
  maximum_body_bytes: Int,
) -> Result(State, Error) {
  let updated_body_bytes = state.body_bytes + length
  case
    state.finished,
    state.final_headers_received,
    state.trailers_received,
    maximum_body_bytes >= 0 && updated_body_bytes <= maximum_body_bytes,
    state.content_length
  {
    True, _, _, _, _ -> Error(FrameAfterFinished)
    _, False, _, _, _ -> Error(DataBeforeFinalHeaders)
    _, _, True, _, _ -> Error(DataAfterTrailers)
    _, _, _, False, _ -> Error(BodyLimitExceeded(maximum_body_bytes))
    _, _, _, _, Some(expected) if updated_body_bytes > expected ->
      Error(ContentLengthExceeded(expected, updated_body_bytes))
    False, True, False, True, _ ->
      Ok(State(..state, body_bytes: updated_body_bytes))
  }
}
