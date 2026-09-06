//// Protocol-neutral RFC 6455 WebSocket handshakes and bounded framing.
////
//// HTTP/1.1 uses Upgrade while HTTP/2 and HTTP/3 use Extended CONNECT.
//// Compression is default-deny. The pure session owns masking, fragmented
//// message reassembly, control-frame rules, UTF-8 validation, and close state;
//// protocol adapters only have to move the returned bytes.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

const frame_overhead_bytes = 14

/// HTTP mapping used for a WebSocket handshake.
pub type Protocol {
  Http1
  Http2
  Http3
}

/// Which endpoint owns a framing session.
pub type Role {
  Client
  Server
}

/// Finite complete-message and retained-wire limits.
pub type Limits {
  Limits(maximum_message_bytes: Int, maximum_buffered_bytes: Int)
}

/// RFC 6455 opcodes supported when no extension is negotiated.
pub type Opcode {
  Continuation
  Text
  Binary
  Close
  PingFrame
  PongFrame
}

/// One decoded or to-be-encoded RFC 6455 frame.
pub type Frame {
  Frame(fin: Bool, opcode: Opcode, payload: BitArray)
}

/// One complete message or control event.
pub type Event {
  TextMessage(String)
  BinaryMessage(BitArray)
  Ping(BitArray)
  Pong(BitArray)
  CloseReceived(status: Option(Int), reason: String)
}

/// Result of pulling one application event from a session.
///
/// `outbound` contains automatic Pong or Close replies, already framed for
/// the local role. It is empty for data and Pong events.
pub type Progress {
  EventReady(session: Session, event: Event, outbound: List(BitArray))
  NeedMore(Session)
}

/// Strict handshake, framing, state, and finite-resource failures.
pub type Error {
  InvalidHandshake
  UnsupportedVersion
  InvalidKey
  InvalidSubprotocol
  SubprotocolMismatch
  ExtensionsForbidden
  UnexpectedStatus(Int)
  AcceptMismatch
  InvalidLimit
  NonByteAligned
  BufferLimitExceeded(Int)
  PayloadLimitExceeded(Int)
  ReservedBits
  ReservedOpcode(Int)
  MaskRequired
  MaskForbidden
  InvalidLength
  FragmentedControl
  ControlPayloadTooLarge
  InvalidMask
  InvalidUtf8
  ProtocolViolation
  InvalidClose
  AlreadyClosed
}

/// Client handshake state binds response validation to its nonce and offered
/// subprotocols.
pub opaque type ClientHandshake {
  ClientHandshake(
    protocol: Protocol,
    key: String,
    subprotocols: List(String),
    headers: List(#(String, String)),
  )
}

/// A validated server handshake response.
pub opaque type HandshakeResponse {
  HandshakeResponse(
    status: Int,
    headers: List(#(String, String)),
    selected_protocol: Option(String),
  )
}

/// A finite, transport-independent WebSocket state machine.
pub opaque type Session {
  Session(
    role: Role,
    limits: Limits,
    buffered: BitArray,
    fragment: Option(Fragment),
    close_sent: Bool,
    close_received: Bool,
  )
}

type Fragment {
  Fragment(opcode: Opcode, payload: BitArray)
}

type ParseProgress {
  Parsed(Session, Frame)
  FrameNeedMore(Session)
}

type LengthProgress {
  LengthReady(Int, BitArray)
  LengthNeedMore
  LengthError
}

@external(erlang, "http_websocket_ffi", "client_key")
fn client_key() -> Result(String, Nil)

@external(erlang, "http_websocket_ffi", "accept")
fn accept_value(key: String) -> Result(String, Nil)

@external(erlang, "http_websocket_ffi", "mask")
fn apply_mask(payload: BitArray, key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "http_websocket_ffi", "random_mask")
fn random_mask() -> Result(BitArray, Nil)

/// Create a client handshake with a cryptographically random 16-byte nonce.
pub fn client_handshake(
  protocol: Protocol,
  subprotocols: List(String),
) -> Result(ClientHandshake, Error) {
  case protocol {
    Http1 -> {
      use key <- result.try(client_key() |> result.replace_error(InvalidKey))
      client_handshake_with_key(protocol, key, subprotocols)
    }
    Http2 | Http3 -> build_client_handshake(protocol, "", subprotocols)
  }
}

/// Create a client handshake using an explicit key for protocol vectors.
///
/// The key still has to be canonical base64 for exactly 16 decoded bytes.
pub fn client_handshake_with_key(
  protocol: Protocol,
  key: String,
  subprotocols: List(String),
) -> Result(ClientHandshake, Error) {
  use _ <- result.try(accept_value(key) |> result.replace_error(InvalidKey))
  build_client_handshake(protocol, key, subprotocols)
}

fn build_client_handshake(
  protocol: Protocol,
  key: String,
  subprotocols: List(String),
) -> Result(ClientHandshake, Error) {
  use _ <- result.try(validate_subprotocols(subprotocols))
  let headers = case protocol {
    Http1 -> [
      #("connection", "Upgrade"),
      #("upgrade", "websocket"),
      #("sec-websocket-version", "13"),
      #("sec-websocket-key", key),
    ]
    Http2 | Http3 -> [#("sec-websocket-version", "13")]
  }
  let headers = case subprotocols {
    [] -> headers
    values ->
      list.append(headers, [
        #("sec-websocket-protocol", string.join(values, with: ", ")),
      ])
  }
  Ok(ClientHandshake(protocol, key, subprotocols, headers))
}

/// Return the transport headers for a client handshake.
pub fn request_headers(handshake: ClientHandshake) -> List(#(String, String)) {
  handshake.headers
}

/// Validate an HTTP response against a client handshake.
pub fn validate_response(
  handshake: ClientHandshake,
  status: Int,
  headers: List(#(String, String)),
) -> Result(Option(String), Error) {
  let expected_status = case handshake.protocol {
    Http1 -> 101
    Http2 | Http3 -> 200
  }
  use <- bool.guard(
    when: status != expected_status,
    return: Error(UnexpectedStatus(status)),
  )
  use _ <- result.try(validate_response_mapping(handshake.protocol, headers))
  use <- bool.guard(
    when: has_header(headers, "sec-websocket-extensions"),
    return: Error(ExtensionsForbidden),
  )
  case handshake.protocol {
    Http1 -> {
      use actual <- result.try(single_header(headers, "sec-websocket-accept"))
      use expected <- result.try(
        accept_value(handshake.key) |> result.replace_error(InvalidKey),
      )
      use <- bool.guard(when: actual != expected, return: Error(AcceptMismatch))
      validate_selected_protocol(headers, handshake.subprotocols)
    }
    Http2 | Http3 -> validate_selected_protocol(headers, handshake.subprotocols)
  }
}

/// Validate a server-side H1 Upgrade or H2/H3 Extended CONNECT handshake.
///
/// Extensions are not accepted. `supported_subprotocols` is server preference
/// order; an offered value is selected only when it is present in this list.
pub fn accept_handshake(
  protocol: Protocol,
  method: http.Method,
  scheme: String,
  authority: String,
  extended_protocol: Option(String),
  headers: List(#(String, String)),
  supported_subprotocols: List(String),
) -> Result(HandshakeResponse, Error) {
  use _ <- result.try(validate_subprotocols(supported_subprotocols))
  use _ <- result.try(validate_request_mapping(
    protocol,
    method,
    scheme,
    authority,
    extended_protocol,
    headers,
  ))
  use <- bool.guard(
    when: has_header(headers, "sec-websocket-extensions"),
    return: Error(ExtensionsForbidden),
  )
  use version <- result.try(single_header(headers, "sec-websocket-version"))
  use <- bool.guard(when: version != "13", return: Error(UnsupportedVersion))
  use offered <- result.try(requested_subprotocols(headers))
  let selected = select_subprotocol(supported_subprotocols, offered)
  use status_and_headers <- result.try(case protocol {
    Http1 -> {
      use key <- result.try(single_header(headers, "sec-websocket-key"))
      use accepted <- result.try(
        accept_value(key) |> result.replace_error(InvalidKey),
      )
      Ok(
        #(101, [
          #("connection", "Upgrade"),
          #("upgrade", "websocket"),
          #("sec-websocket-accept", accepted),
        ]),
      )
    }
    Http2 | Http3 -> Ok(#(200, []))
  })
  let #(status, response_headers) = status_and_headers
  let response_headers = case selected {
    None -> response_headers
    Some(value) ->
      list.append(response_headers, [
        #("sec-websocket-protocol", value),
      ])
  }
  Ok(HandshakeResponse(status, response_headers, selected))
}

/// Return a validated handshake's response status.
pub fn response_status(response: HandshakeResponse) -> Int {
  response.status
}

/// Return a validated handshake's response headers.
pub fn response_headers(
  response: HandshakeResponse,
) -> List(#(String, String)) {
  response.headers
}

/// Return the negotiated subprotocol, if any.
pub fn selected_protocol(response: HandshakeResponse) -> Option(String) {
  response.selected_protocol
}

fn validate_request_mapping(
  protocol: Protocol,
  method: http.Method,
  scheme: String,
  authority: String,
  extended_protocol: Option(String),
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  use <- bool.guard(
    when: string.is_empty(authority),
    return: Error(InvalidHandshake),
  )
  case protocol {
    Http1 -> {
      use <- bool.guard(
        when: method != http.Get
          || { scheme != "http" && scheme != "https" }
          || extended_protocol != None
          || !headers_contain_token(headers, "connection", "upgrade")
          || !single_token_header(headers, "upgrade", "websocket"),
        return: Error(InvalidHandshake),
      )
      Ok(Nil)
    }
    Http2 -> {
      use <- bool.guard(
        when: method != http.Connect
          || { scheme != "http" && scheme != "https" }
          || extended_protocol != Some("websocket")
          || has_header(headers, "connection")
          || has_header(headers, "upgrade"),
        return: Error(InvalidHandshake),
      )
      Ok(Nil)
    }
    Http3 -> {
      use <- bool.guard(
        when: method != http.Connect
          || scheme != "https"
          || extended_protocol != Some("websocket")
          || has_header(headers, "connection")
          || has_header(headers, "upgrade"),
        return: Error(InvalidHandshake),
      )
      Ok(Nil)
    }
  }
}

fn validate_response_mapping(
  protocol: Protocol,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  case protocol {
    Http1 ->
      case
        headers_contain_token(headers, "connection", "upgrade")
        && single_token_header(headers, "upgrade", "websocket")
      {
        True -> Ok(Nil)
        False -> Error(InvalidHandshake)
      }
    Http2 | Http3 ->
      case has_header(headers, "connection") || has_header(headers, "upgrade") {
        True -> Error(InvalidHandshake)
        False -> Ok(Nil)
      }
  }
}

fn requested_subprotocols(
  headers: List(#(String, String)),
) -> Result(List(String), Error) {
  case header_values(headers, "sec-websocket-protocol") {
    [] -> Ok([])
    [value] -> {
      let values =
        value
        |> string.split(on: ",")
        |> list.map(string.trim)
      use _ <- result.try(validate_subprotocols(values))
      Ok(values)
    }
    _ -> Error(InvalidSubprotocol)
  }
}

fn validate_selected_protocol(
  headers: List(#(String, String)),
  offered: List(String),
) -> Result(Option(String), Error) {
  case header_values(headers, "sec-websocket-protocol") {
    [] -> Ok(None)
    [value] -> {
      let value = string.trim(value)
      case valid_token(value) && list.contains(offered, value) {
        True -> Ok(Some(value))
        False -> Error(SubprotocolMismatch)
      }
    }
    _ -> Error(SubprotocolMismatch)
  }
}

fn validate_subprotocols(values: List(String)) -> Result(Nil, Error) {
  case list.all(values, valid_token) && list.unique(values) == values {
    True -> Ok(Nil)
    False -> Error(InvalidSubprotocol)
  }
}

fn select_subprotocol(
  supported: List(String),
  offered: List(String),
) -> Option(String) {
  case supported {
    [] -> None
    [candidate, ..rest] ->
      case list.contains(offered, candidate) {
        True -> Some(candidate)
        False -> select_subprotocol(rest, offered)
      }
  }
}

/// Construct a finite framing session.
pub fn session(role: Role, limits: Limits) -> Result(Session, Error) {
  let Limits(maximum_message_bytes, maximum_buffered_bytes) = limits
  case
    maximum_message_bytes > 0
    && maximum_buffered_bytes >= maximum_message_bytes + frame_overhead_bytes
  {
    True -> Ok(Session(role, limits, <<>>, None, False, False))
    False -> Error(InvalidLimit)
  }
}

/// Append one byte-aligned transport chunk without exceeding retained memory.
pub fn push(session: Session, bytes: BitArray) -> Result(Session, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(bytes) % 8 != 0,
    return: Error(NonByteAligned),
  )
  let Limits(_, maximum_buffered_bytes) = session.limits
  let total = bit_array.byte_size(session.buffered) + bit_array.byte_size(bytes)
  use <- bool.guard(
    when: total > maximum_buffered_bytes,
    return: Error(BufferLimitExceeded(maximum_buffered_bytes)),
  )
  Ok(Session(..session, buffered: <<session.buffered:bits, bytes:bits>>))
}

/// Return retained transport bytes, excluding fragmented application payload.
pub fn buffered_bytes(session: Session) -> Int {
  bit_array.byte_size(session.buffered)
}

/// Pull one complete event, retaining incomplete framing and message state.
pub fn next(session: Session) -> Result(Progress, Error) {
  use <- bool.guard(when: session.close_received, return: Error(AlreadyClosed))
  case parse_frame(session) {
    Error(error) -> Error(error)
    Ok(FrameNeedMore(session)) -> Ok(NeedMore(session))
    Ok(Parsed(session, frame)) -> handle_frame(session, frame)
  }
}

/// Encode one frame, using a cryptographically random mask for a client.
pub fn encode(role: Role, frame: Frame) -> Result(BitArray, Error) {
  case role {
    Server -> encode_with_mask(frame, None)
    Client -> {
      use mask <- result.try(random_mask() |> result.replace_error(InvalidMask))
      encode_with_mask(frame, Some(mask))
    }
  }
}

/// Encode one frame with an explicit four-byte mask for deterministic vectors.
pub fn encode_with_mask(
  frame: Frame,
  mask: Option(BitArray),
) -> Result(BitArray, Error) {
  let Frame(fin, opcode, payload) = frame
  use <- bool.guard(
    when: bit_array.bit_size(payload) % 8 != 0,
    return: Error(NonByteAligned),
  )
  use _ <- result.try(validate_control(
    opcode,
    fin,
    bit_array.byte_size(payload),
  ))
  use <- bool.guard(
    when: case mask {
      Some(value) -> bit_array.byte_size(value) != 4
      None -> False
    },
    return: Error(InvalidMask),
  )
  let first = case fin {
    True -> 128 + opcode_value(opcode)
    False -> opcode_value(opcode)
  }
  let length = bit_array.byte_size(payload)
  let #(marker, extended) = encoded_length(length)
  case mask {
    None -> Ok(<<first, marker, extended:bits, payload:bits>>)
    Some(key) -> {
      use masked <- result.try(
        apply_mask(payload, key) |> result.replace_error(InvalidMask),
      )
      let second = 128 + marker
      Ok(<<first, second, extended:bits, key:bits, masked:bits>>)
    }
  }
}

/// Encode and account for one complete outbound UTF-8 text message.
pub fn send_text(
  session: Session,
  message: String,
) -> Result(#(Session, BitArray), Error) {
  send_data(session, Text, <<message:utf8>>)
}

/// Encode and account for one complete outbound binary message.
pub fn send_binary(
  session: Session,
  message: BitArray,
) -> Result(#(Session, BitArray), Error) {
  use <- bool.guard(
    when: bit_array.bit_size(message) % 8 != 0,
    return: Error(NonByteAligned),
  )
  send_data(session, Binary, message)
}

/// Encode an outbound Ping with at most 125 bytes.
pub fn ping_frame(
  session: Session,
  payload: BitArray,
) -> Result(#(Session, BitArray), Error) {
  use <- bool.guard(when: session.close_sent, return: Error(AlreadyClosed))
  use bytes <- result.try(encode(session.role, Frame(True, PingFrame, payload)))
  Ok(#(session, bytes))
}

/// Encode an outbound Close without session state, useful for adapters.
pub fn close_frame(
  role: Role,
  status: Option(Int),
  reason: String,
) -> Result(BitArray, Error) {
  use payload <- result.try(close_payload(status, reason))
  encode(role, Frame(True, Close, payload))
}

/// Encode an outbound Close and prevent further data sends.
pub fn close(
  session: Session,
  status: Option(Int),
  reason: String,
) -> Result(#(Session, BitArray), Error) {
  use <- bool.guard(when: session.close_sent, return: Error(AlreadyClosed))
  use bytes <- result.try(close_frame(session.role, status, reason))
  Ok(#(Session(..session, close_sent: True), bytes))
}

fn send_data(
  session: Session,
  opcode: Opcode,
  payload: BitArray,
) -> Result(#(Session, BitArray), Error) {
  use <- bool.guard(when: session.close_sent, return: Error(AlreadyClosed))
  let Limits(maximum_message_bytes, _) = session.limits
  use <- bool.guard(
    when: bit_array.byte_size(payload) > maximum_message_bytes,
    return: Error(PayloadLimitExceeded(maximum_message_bytes)),
  )
  use bytes <- result.try(encode(session.role, Frame(True, opcode, payload)))
  Ok(#(session, bytes))
}

fn parse_frame(session: Session) -> Result(ParseProgress, Error) {
  case session.buffered {
    <<fin:1, reserved:3, opcode_value:4, masked:1, marker:7, rest:bits>> -> {
      use <- bool.guard(when: reserved != 0, return: Error(ReservedBits))
      use opcode <- result.try(decode_opcode(opcode_value))
      case parse_length(marker, rest) {
        LengthNeedMore -> Ok(FrameNeedMore(session))
        LengthError -> Error(InvalidLength)
        LengthReady(length, payload_and_mask) ->
          decode_payload(session, fin, opcode, masked, length, payload_and_mask)
      }
    }
    _ -> Ok(FrameNeedMore(session))
  }
}

fn decode_payload(
  session: Session,
  fin: Int,
  opcode: Opcode,
  masked: Int,
  length: Int,
  payload_and_mask: BitArray,
) -> Result(ParseProgress, Error) {
  let Limits(maximum_message_bytes, _) = session.limits
  use <- bool.guard(
    when: length > maximum_message_bytes,
    return: Error(PayloadLimitExceeded(maximum_message_bytes)),
  )
  use _ <- result.try(validate_control(opcode, fin == 1, length))
  use _ <- result.try(validate_mask(session.role, masked == 1))
  let mask_bytes = case masked {
    1 -> 4
    _ -> 0
  }
  case take(payload_and_mask, mask_bytes + length) {
    None -> Ok(FrameNeedMore(session))
    Some(#(encoded, remaining)) -> {
      use payload <- result.try(case masked {
        0 -> Ok(encoded)
        _ -> unmask(encoded, length)
      })
      Ok(Parsed(
        Session(..session, buffered: remaining),
        Frame(fin == 1, opcode, payload),
      ))
    }
  }
}

fn handle_frame(session: Session, frame: Frame) -> Result(Progress, Error) {
  let Frame(fin, opcode, payload) = frame
  case opcode {
    PingFrame -> {
      use reply <- result.try(encode(
        session.role,
        Frame(True, PongFrame, payload),
      ))
      Ok(EventReady(session, Ping(payload), [reply]))
    }
    PongFrame -> Ok(EventReady(session, Pong(payload), []))
    Close -> handle_close(session, payload)
    Continuation -> continue_fragment(session, fin, payload)
    Text | Binary -> start_message(session, fin, opcode, payload)
  }
}

fn start_message(
  session: Session,
  fin: Bool,
  opcode: Opcode,
  payload: BitArray,
) -> Result(Progress, Error) {
  use <- bool.guard(
    when: session.fragment != None,
    return: Error(ProtocolViolation),
  )
  case fin {
    True -> complete_message(session, opcode, payload)
    False -> next(Session(..session, fragment: Some(Fragment(opcode, payload))))
  }
}

fn continue_fragment(
  session: Session,
  fin: Bool,
  payload: BitArray,
) -> Result(Progress, Error) {
  case session.fragment {
    None -> Error(ProtocolViolation)
    Some(Fragment(opcode, retained)) -> {
      let Limits(maximum_message_bytes, _) = session.limits
      let total = bit_array.byte_size(retained) + bit_array.byte_size(payload)
      use <- bool.guard(
        when: total > maximum_message_bytes,
        return: Error(PayloadLimitExceeded(maximum_message_bytes)),
      )
      let combined = <<retained:bits, payload:bits>>
      case fin {
        True ->
          complete_message(Session(..session, fragment: None), opcode, combined)
        False ->
          next(Session(..session, fragment: Some(Fragment(opcode, combined))))
      }
    }
  }
}

fn complete_message(
  session: Session,
  opcode: Opcode,
  payload: BitArray,
) -> Result(Progress, Error) {
  case opcode {
    Text ->
      bit_array.to_string(payload)
      |> result.map(fn(message) {
        EventReady(session, TextMessage(message), [])
      })
      |> result.replace_error(InvalidUtf8)
    Binary -> Ok(EventReady(session, BinaryMessage(payload), []))
    _ -> Error(ProtocolViolation)
  }
}

fn handle_close(
  session: Session,
  payload: BitArray,
) -> Result(Progress, Error) {
  use #(status, reason) <- result.try(parse_close_payload(payload))
  let received = Session(..session, close_received: True)
  case session.close_sent {
    True -> Ok(EventReady(received, CloseReceived(status, reason), []))
    False -> {
      use reply <- result.try(close_frame(session.role, status, reason))
      Ok(
        EventReady(
          Session(..received, close_sent: True),
          CloseReceived(status, reason),
          [reply],
        ),
      )
    }
  }
}

fn close_payload(
  status: Option(Int),
  reason: String,
) -> Result(BitArray, Error) {
  case status {
    None ->
      case string.is_empty(reason) {
        True -> Ok(<<>>)
        False -> Error(InvalidClose)
      }
    Some(code) -> {
      use <- bool.guard(
        when: !valid_close_code(code)
          || bit_array.byte_size(<<reason:utf8>>) > 123,
        return: Error(InvalidClose),
      )
      Ok(<<code:size(16), reason:utf8>>)
    }
  }
}

fn parse_close_payload(
  payload: BitArray,
) -> Result(#(Option(Int), String), Error) {
  case payload {
    <<>> -> Ok(#(None, ""))
    <<_:size(8)>> -> Error(InvalidClose)
    <<code:size(16), reason:bits>> -> {
      use <- bool.guard(
        when: !valid_close_code(code),
        return: Error(InvalidClose),
      )
      bit_array.to_string(reason)
      |> result.map(fn(reason) { #(Some(code), reason) })
      |> result.replace_error(InvalidUtf8)
    }
    _ -> Error(InvalidClose)
  }
}

fn valid_close_code(code: Int) -> Bool {
  list.contains(
    [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014],
    code,
  )
  || { code >= 3000 && code <= 4999 }
}

fn unmask(encoded: BitArray, length: Int) -> Result(BitArray, Error) {
  case encoded {
    <<key:bits-size(32), payload:bits>> ->
      case bit_array.byte_size(payload) == length {
        True -> apply_mask(payload, key) |> result.replace_error(InvalidMask)
        False -> Error(InvalidMask)
      }
    _ -> Error(InvalidMask)
  }
}

fn validate_mask(role: Role, masked: Bool) -> Result(Nil, Error) {
  case role, masked {
    Server, False -> Error(MaskRequired)
    Client, True -> Error(MaskForbidden)
    _, _ -> Ok(Nil)
  }
}

fn validate_control(
  opcode: Opcode,
  fin: Bool,
  length: Int,
) -> Result(Nil, Error) {
  case is_control(opcode), fin, length > 125 {
    True, False, _ -> Error(FragmentedControl)
    True, _, True -> Error(ControlPayloadTooLarge)
    _, _, _ -> Ok(Nil)
  }
}

fn parse_length(marker: Int, bytes: BitArray) -> LengthProgress {
  case marker {
    126 ->
      case bytes {
        <<length:size(16), rest:bits>> if length >= 126 ->
          LengthReady(length, rest)
        <<_:size(16), _rest:bits>> -> LengthError
        _ -> LengthNeedMore
      }
    127 ->
      case bytes {
        <<0:1, length:size(63), rest:bits>> if length >= 65_536 ->
          LengthReady(length, rest)
        <<_:size(64), _rest:bits>> -> LengthError
        _ -> LengthNeedMore
      }
    length -> LengthReady(length, bytes)
  }
}

fn decode_opcode(value: Int) -> Result(Opcode, Error) {
  case value {
    0 -> Ok(Continuation)
    1 -> Ok(Text)
    2 -> Ok(Binary)
    8 -> Ok(Close)
    9 -> Ok(PingFrame)
    10 -> Ok(PongFrame)
    value -> Error(ReservedOpcode(value))
  }
}

fn opcode_value(opcode: Opcode) -> Int {
  case opcode {
    Continuation -> 0
    Text -> 1
    Binary -> 2
    Close -> 8
    PingFrame -> 9
    PongFrame -> 10
  }
}

fn is_control(opcode: Opcode) -> Bool {
  case opcode {
    Close | PingFrame | PongFrame -> True
    Continuation | Text | Binary -> False
  }
}

fn encoded_length(length: Int) -> #(Int, BitArray) {
  case length {
    value if value <= 125 -> #(value, <<>>)
    value if value <= 65_535 -> #(126, <<value:size(16)>>)
    value -> #(127, <<value:size(64)>>)
  }
}

fn take(bytes: BitArray, length: Int) -> Option(#(BitArray, BitArray)) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> None
    False -> {
      let bit_length = length * 8
      case bytes {
        <<value:bits-size(bit_length), rest:bits>> -> Some(#(value, rest))
        _ -> None
      }
    }
  }
}

fn single_header(
  headers: List(#(String, String)),
  name: String,
) -> Result(String, Error) {
  case header_values(headers, name) {
    [value] -> {
      let value = string.trim(value)
      case string.is_empty(value) {
        True -> Error(InvalidHandshake)
        False -> Ok(value)
      }
    }
    _ -> Error(InvalidHandshake)
  }
}

fn single_token_header(
  headers: List(#(String, String)),
  name: String,
  expected: String,
) -> Bool {
  case header_values(headers, name) {
    [value] -> string.lowercase(string.trim(value)) == expected
    _ -> False
  }
}

fn headers_contain_token(
  headers: List(#(String, String)),
  name: String,
  expected: String,
) -> Bool {
  headers
  |> header_values(name)
  |> list.flat_map(fn(value) { string.split(value, on: ",") })
  |> list.any(fn(value) { string.lowercase(string.trim(value)) == expected })
}

fn has_header(headers: List(#(String, String)), name: String) -> Bool {
  header_values(headers, name) != []
}

fn header_values(
  headers: List(#(String, String)),
  name: String,
) -> List(String) {
  headers
  |> list.filter(fn(header) {
    let #(header_name, _) = header
    string.lowercase(header_name) == name
  })
  |> list.map(fn(header) {
    let #(_, value) = header
    value
  })
}

fn valid_token(value: String) -> Bool {
  !string.is_empty(value)
  && list.all(string.to_utf_codepoints(value), fn(character) {
    token_character(string.utf_codepoint_to_int(character))
  })
}

fn token_character(character: Int) -> Bool {
  character >= 48
  && character <= 57
  || character >= 65
  && character <= 90
  || character >= 97
  && character <= 122
  || list.contains(
    [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126],
    character,
  )
}
