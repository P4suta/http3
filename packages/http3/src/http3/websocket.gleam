//// RFC 9220 WebSockets over HTTP/3 with bounded RFC 6455 framing.
////
//// Compression is intentionally not negotiated.
//// Client frames are masked,
//// server frames are not, fragmented messages are reassembled within a finite message limit, and transport reads retain at most the configured finite buffer.

import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/http
import gleam/http/request.{type Request}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http3/client
import http3/failure as runtime_failure
import http3/internal/clock
import http3/internal/native/diagnostic_code
import http3/internal/websocket_frame as frame
import http3/server

const default_message_bytes = 1_048_576

const frame_overhead_bytes = 14

// Bound subprotocol parsing independently of application message framing.
// Each repeated field also consumes one byte of this work allowance.
const maximum_subprotocol_bytes = 65_536

/// Finite message and retained-frame limits.
pub opaque type Configuration {
  Configuration(maximum_message_bytes: Int, maximum_buffered_bytes: Int)
}

/// A connected client or accepted server WebSocket.
pub opaque type Socket {
  Socket(
    transport: Transport,
    configuration: Configuration,
    decoder: frame.Decoder,
    fragment: Option(Fragment),
    close_sent: Bool,
    close_received: Bool,
  )
}

type Transport {
  ClientTransport(client.Stream)
  ServerTransport(server.Request)
}

type Fragment {
  Fragment(opcode: frame.Opcode, payload: BitArray)
}

type ReceiveBudget {
  ReceiveBudget(deadline: Int, now: fn() -> Int)
}

/// One complete message or control-frame event.
pub type Event {
  TextMessage(String)
  BinaryMessage(BitArray)
  Ping(BitArray)
  Pong(BitArray)
  CloseReceived(status: Option(Int), reason: String)
}

/// Invalid finite WebSocket configuration.
pub type ConfigurationError {
  InvalidMessageLimit
  InvalidBufferLimit
}

/// Handshake, framing, UTF-8, state, or HTTP/3 transport failure.
pub type Error {
  InvalidHandshake
  UnsupportedVersion
  InvalidKey
  UnexpectedStatus(Int)
  AcceptMismatch
  FrameError
  InvalidUtf8
  MessageTooLarge(Int)
  ProtocolViolation
  InvalidClose
  AlreadyClosed
  ServerFailure(server.Error)
  ClientFailure(client.Error)
}

/// Construct immediately usable finite WebSocket limits.
pub fn new() -> Configuration {
  Configuration(
    maximum_message_bytes: default_message_bytes,
    maximum_buffered_bytes: default_message_bytes + frame_overhead_bytes,
  )
}

/// Replace both finite limits atomically.
///
/// The frame buffer must accommodate the largest message or the independent 125-byte control-frame limit, plus its RFC 6455 header.
/// Fragment reassembly is separately bounded by the message limit.
pub fn with_limits(
  _configuration: Configuration,
  maximum_message_bytes: Int,
  maximum_buffered_bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  case
    maximum_message_bytes > 0,
    maximum_buffered_bytes
    >= int.max(maximum_message_bytes, 125) + frame_overhead_bytes
  {
    False, _ -> Error(InvalidMessageLimit)
    _, False -> Error(InvalidBufferLimit)
    True, True ->
      Ok(Configuration(
        maximum_message_bytes: maximum_message_bytes,
        maximum_buffered_bytes: maximum_buffered_bytes,
      ))
  }
}

/// Return the configured maximum complete message size.
pub fn maximum_message_bytes(configuration: Configuration) -> Int {
  configuration.maximum_message_bytes
}

/// Return the configured maximum retained frame-buffer size.
pub fn maximum_buffered_bytes(configuration: Configuration) -> Int {
  configuration.maximum_buffered_bytes
}

/// Accept an RFC 9220 Extended CONNECT request and send its HTTP/3 200.
pub fn accept(
  configuration: Configuration,
  request: server.Request,
) -> Result(Socket, Error) {
  accept_with_headers(configuration, request, [])
}

/// Accept an RFC 9220 Extended CONNECT request with application headers.
///
/// RFC 8441 retains the version and subprotocol negotiation rules.
/// This API profile rejects HTTP/1.1 nonce fields and does not negotiate extensions.
/// Connection-specific headers remain rejected by the HTTP/3 validator.
/// A selected subprotocol must be one token offered by the client.
/// Parsing all offered subprotocol fields is limited to 65,536 bytes, including one byte per field.
/// Invalid application response headers commit no response.
/// An unsupported version sends HTTP 400 with the supported version, awaits response acknowledgement, and cancels the unfinished request direction.
/// Transport failure during this refusal is returned as `ServerFailure`.
pub fn accept_with_headers(
  configuration: Configuration,
  request: server.Request,
  response_headers: List(#(String, String)),
) -> Result(Socket, Error) {
  use <- bool.guard(
    when: has_header(response_headers, "sec-websocket-key")
      || has_header(response_headers, "sec-websocket-accept")
      || has_header(response_headers, "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  use _ <- result.try(require_supported_protocol(request))
  use _ <- result.try(validate_or_reject_server_handshake(request))
  use offered <- result.try(validate_or_reject_requested_subprotocols(request))
  use _ <- result.try(validate_selected_subprotocol(response_headers, offered))
  use _ <- result.try(
    server.send_response(request, 200, response_headers)
    |> result.map_error(ServerFailure),
  )
  socket(ServerTransport(request), frame.Server, configuration)
}

fn require_supported_protocol(request: server.Request) -> Result(Nil, Error) {
  case server.method(request), server.protocol(request) {
    http.Connect, Some("websocket") -> Ok(Nil)
    http.Connect, Some(_) ->
      reject_handshake(request, 501, [], InvalidHandshake)
    _, _ -> reject_handshake(request, 400, [], InvalidHandshake)
  }
}

/// Open and validate an RFC 9220 Extended CONNECT client handshake.
///
/// The request supplies the HTTPS origin, path, query, cookies,
/// authorization, and any requested subprotocol header.
/// The mandatory version is supplied by this API; HTTP/1.1 key and accept fields are rejected.
/// Offered subprotocols must be distinct HTTP tokens.
/// Their fields share a 65,536-byte parsing allowance, including one byte per repeated field.
/// After stream admission, response reads share one operation deadline across informational responses.
/// Admission and failed-handshake cancellation keep their separate configured operation budgets.
pub fn connect(
  configuration: Configuration,
  connection: client.Connection,
  request: Request(Nil),
) -> Result(Socket, Error) {
  connect_with_clock(
    configuration,
    connection,
    request,
    clock.monotonic_milliseconds,
  )
}

/// Internal deterministic clock seam for one client handshake read chain.
@internal
pub fn connect_with_clock(
  configuration: Configuration,
  connection: client.Connection,
  request: Request(Nil),
  now: fn() -> Int,
) -> Result(Socket, Error) {
  use <- bool.guard(
    when: has_header(request.headers, "sec-websocket-key")
      || has_header(request.headers, "sec-websocket-accept")
      || has_header(request.headers, "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  use offered <- result.try(requested_subprotocols(request.headers))
  let outbound =
    request.Request(
      ..request,
      headers: list.filter(request.headers, fn(header) {
        string.lowercase(header.0) != "sec-websocket-version"
      }),
    )
    |> request.set_header("sec-websocket-version", "13")
  use stream <- result.try(
    client.open_extended_connect(connection, outbound, "websocket")
    |> result.map_error(ClientFailure),
  )
  let deadline = now() + client.operation_timeout_milliseconds(stream)
  case validate_client_handshake(stream, offered, deadline, now) {
    Error(failure) -> cancel_failed_handshake(stream, failure)
    Ok(Nil) ->
      case socket(ClientTransport(stream), frame.Client, configuration) {
        Ok(socket) -> Ok(socket)
        Error(failure) -> cancel_failed_handshake(stream, failure)
      }
  }
}

fn validate_client_handshake(
  stream: client.Stream,
  offered: Dict(String, Nil),
  deadline: Int,
  now: fn() -> Int,
) -> Result(Nil, Error) {
  use headers <- result.try(await_client_handshake(stream, deadline, now))
  use <- bool.guard(
    when: has_header(headers, "sec-websocket-key")
      || has_header(headers, "sec-websocket-accept")
      || has_header(headers, "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  validate_selected_subprotocol(headers, offered)
}

fn requested_subprotocols(
  headers: List(#(String, String)),
) -> Result(Dict(String, Nil), Error) {
  case header_values(headers, "sec-websocket-protocol") {
    [] -> Ok(dict.new())
    values -> {
      use #(offered, _) <- result.try(list.try_fold(
        values,
        #(dict.new(), maximum_subprotocol_bytes),
        parse_subprotocol_field,
      ))
      case dict.size(offered) {
        0 -> Error(InvalidHandshake)
        _ -> Ok(offered)
      }
    }
  }
}

fn parse_subprotocol_field(
  state: #(Dict(String, Nil), Int),
  value: String,
) -> Result(#(Dict(String, Nil), Int), Error) {
  let #(offered, remaining) = state
  let charged = string.byte_size(value) + 1
  use <- bool.guard(
    when: charged > remaining || !subprotocol_field_characters(value),
    return: Error(InvalidHandshake),
  )
  // RFC 2616's #list permits empty list members; they do not count as subprotocols.
  // At least one nonempty token is required across all fields.
  use offered <- result.try(list.try_fold(
    string.split(value, ","),
    offered,
    insert_subprotocol,
  ))
  Ok(#(offered, remaining - charged))
}

fn insert_subprotocol(
  offered: Dict(String, Nil),
  member: String,
) -> Result(Dict(String, Nil), Error) {
  let token = string.trim(member)
  use <- bool.guard(when: token == "", return: Ok(offered))
  use <- bool.guard(
    when: !subprotocol_token(token) || dict.has_key(offered, token),
    return: Error(InvalidHandshake),
  )
  Ok(dict.insert(offered, token, Nil))
}

fn validate_selected_subprotocol(
  headers: List(#(String, String)),
  offered: Dict(String, Nil),
) -> Result(Nil, Error) {
  case header_values(headers, "sec-websocket-protocol") {
    [] -> Ok(Nil)
    [value] -> {
      use <- bool.guard(
        when: string.byte_size(value) >= maximum_subprotocol_bytes
          || !subprotocol_field_characters(value),
        return: Error(InvalidHandshake),
      )
      let token = string.trim(value)
      case subprotocol_token(token) && dict.has_key(offered, token) {
        True -> Ok(Nil)
        False -> Error(InvalidHandshake)
      }
    }
    _ -> Error(InvalidHandshake)
  }
}

fn subprotocol_field_characters(value: String) -> Bool {
  list.all(string.to_utf_codepoints(value), fn(character) {
    let codepoint = string.utf_codepoint_to_int(character)
    codepoint == 9 || codepoint >= 32 && codepoint <= 126
  })
}

fn subprotocol_token(value: String) -> Bool {
  value != ""
  && list.all(string.to_utf_codepoints(value), fn(character) {
    let codepoint = string.utf_codepoint_to_int(character)
    codepoint >= 48
    && codepoint <= 57
    || codepoint >= 65
    && codepoint <= 90
    || codepoint >= 97
    && codepoint <= 122
    || list.contains(
      [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126],
      codepoint,
    )
  })
}

fn cancel_failed_handshake(
  stream: client.Stream,
  failure: Error,
) -> Result(value, Error) {
  case client.cancel(stream) {
    Ok(_) | Error(_) -> Error(failure)
  }
}

fn socket(
  transport: Transport,
  role: frame.Role,
  configuration: Configuration,
) -> Result(Socket, Error) {
  frame.decoder(
    role,
    // RFC 6455 control payloads have their own 125-byte limit.
    // A smaller application message limit must not reject an otherwise bounded Ping.
    int.max(configuration.maximum_message_bytes, 125),
    configuration.maximum_buffered_bytes,
  )
  |> result.map(fn(decoder) {
    Socket(transport, configuration, decoder, None, False, False)
  })
  |> result.replace_error(FrameError)
}

fn validate_server_handshake(request: server.Request) -> Result(Nil, Error) {
  use <- bool.guard(
    when: server.scheme(request) != "https"
      || string.is_empty(server.authority(request)),
    return: Error(InvalidHandshake),
  )
  use version <- result.try(
    single_header(server.headers(request), "sec-websocket-version")
    |> result.replace_error(UnsupportedVersion),
  )
  use <- bool.guard(when: version != "13", return: Error(UnsupportedVersion))
  use <- bool.guard(
    when: has_header(server.headers(request), "sec-websocket-key")
      || has_header(server.headers(request), "sec-websocket-accept")
      || has_header(server.headers(request), "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  Ok(Nil)
}

fn validate_or_reject_server_handshake(
  request: server.Request,
) -> Result(Nil, Error) {
  case validate_server_handshake(request) {
    Error(UnsupportedVersion) -> reject_unsupported_version(request)
    Error(failure) -> reject_handshake(request, 400, [], failure)
    Ok(Nil) -> Ok(Nil)
  }
}

fn validate_or_reject_requested_subprotocols(
  request: server.Request,
) -> Result(Dict(String, Nil), Error) {
  case requested_subprotocols(server.headers(request)) {
    Error(failure) -> reject_handshake(request, 400, [], failure)
    Ok(offered) -> Ok(offered)
  }
}

fn reject_unsupported_version(request: server.Request) -> Result(value, Error) {
  reject_handshake(
    request,
    400,
    [#("sec-websocket-version", "13")],
    UnsupportedVersion,
  )
}

fn reject_handshake(
  request: server.Request,
  status: Int,
  headers: List(#(String, String)),
  failure: Error,
) -> Result(value, Error) {
  record_server_failure(request, failure)
  let transmitted = {
    use _ <- result.try(server.respond(request, status, headers, <<>>))
    // Confirm the response send direction before cancelling the unread request direction, so rejection cannot discard an unacknowledged head.
    server.await_response_completion(request)
  }
  let cancelled = server.cancel(request)
  case transmitted, cancelled {
    Error(error), _ | _, Error(error) -> Error(ServerFailure(error))
    Ok(_), Ok(_) -> Error(failure)
  }
}

fn record_server_failure(request: server.Request, failure: Error) -> Nil {
  case websocket_failure(failure) {
    Some(kind) ->
      server.record_application_error(
        request: request,
        code: diagnostic_code.websocket_failure(kind),
      )
    None -> Nil
  }
}

fn websocket_failure(
  failure: Error,
) -> Option(diagnostic_code.WebsocketFailure) {
  case failure {
    FrameError -> Some(diagnostic_code.WebsocketFrameSyntax)
    InvalidUtf8 -> Some(diagnostic_code.WebsocketInvalidUtf8)
    MessageTooLarge(_) -> Some(diagnostic_code.WebsocketMessageLimit)
    ProtocolViolation -> Some(diagnostic_code.WebsocketProtocolState)
    InvalidClose -> Some(diagnostic_code.WebsocketInvalidClose)
    InvalidHandshake -> Some(diagnostic_code.WebsocketInvalidHandshake)
    UnsupportedVersion -> Some(diagnostic_code.WebsocketUnsupportedVersion)
    AlreadyClosed
    | InvalidKey
    | UnexpectedStatus(_)
    | AcceptMismatch
    | ServerFailure(_)
    | ClientFailure(_) -> None
  }
}

fn await_client_handshake(
  stream: client.Stream,
  deadline: Int,
  now: fn() -> Int,
) -> Result(List(#(String, String)), Error) {
  use _ <- result.try(require_handshake_time(deadline, now))
  use event <- result.try(
    client.next_event_until(stream, deadline) |> result.map_error(ClientFailure),
  )
  use _ <- result.try(require_handshake_time(deadline, now))
  case event {
    client.InformationalResponse(_, _) ->
      await_client_handshake(stream, deadline, now)
    client.Response(status, headers) if status >= 200 && status < 300 ->
      Ok(headers)
    client.Response(status, _) -> Error(UnexpectedStatus(status))
    client.Data(_) | client.Trailers(_) | client.End -> Error(InvalidHandshake)
  }
}

fn require_handshake_time(
  deadline: Int,
  now: fn() -> Int,
) -> Result(Nil, Error) {
  use <- bool.guard(when: now() < deadline, return: Ok(Nil))
  Error(
    ClientFailure(
      client.Failure(runtime_failure.Timeout(runtime_failure.Operation)),
    ),
  )
}

/// Send one complete UTF-8 text message.
pub fn send_text(socket: Socket, message: String) -> Result(Socket, Error) {
  send_data(socket, frame.Text, <<message:utf8>>)
}

/// Send one complete byte-aligned binary message.
pub fn send_binary(socket: Socket, message: BitArray) -> Result(Socket, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(message) % 8 != 0,
    return: Error(ProtocolViolation),
  )
  send_data(socket, frame.Binary, message)
}

fn send_data(
  socket: Socket,
  opcode: frame.Opcode,
  payload: BitArray,
) -> Result(Socket, Error) {
  use <- bool.guard(when: socket.close_sent, return: Error(AlreadyClosed))
  use <- bool.guard(
    when: bit_array.byte_size(payload)
      > socket.configuration.maximum_message_bytes,
    return: Error(MessageTooLarge(socket.configuration.maximum_message_bytes)),
  )
  send_frame(socket, frame.Frame(True, opcode, payload))
}

/// Send one Ping control frame.
/// The payload may contain at most 125 bytes.
pub fn ping(socket: Socket, payload: BitArray) -> Result(Socket, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(payload) % 8 != 0
      || bit_array.byte_size(payload) > 125,
    return: Error(ProtocolViolation),
  )
  use <- bool.guard(when: socket.close_sent, return: Error(AlreadyClosed))
  send_frame(socket, frame.Frame(True, frame.Ping, payload))
}

/// Send one Close frame.
///
/// Omit the status only with an empty reason.
/// A reason is UTF-8 by type and may occupy at most 123 bytes after the two-byte status code.
pub fn close(
  socket: Socket,
  status: Option(Int),
  reason: String,
) -> Result(Socket, Error) {
  use <- bool.guard(when: socket.close_sent, return: Error(AlreadyClosed))
  use payload <- result.try(close_payload(status, reason))
  send_frame(socket, frame.Frame(True, frame.Close, payload))
  |> result.map(fn(socket) { Socket(..socket, close_sent: True) })
}

/// Abort the HTTP/3 stream and mark this local WebSocket closed.
pub fn cancel(socket: Socket) -> Result(Socket, Error) {
  case socket.transport {
    ClientTransport(stream) ->
      client.cancel(stream)
      |> result.map(fn(_) { discard_closed_input(socket) })
      |> result.map_error(ClientFailure)
    ServerTransport(request) ->
      server.cancel(request)
      |> result.map(fn(_) { discard_closed_input(socket) })
      |> result.map_error(ServerFailure)
  }
}

fn discard_closed_input(socket: Socket) -> Socket {
  Socket(
    ..socket,
    close_sent: True,
    close_received: True,
    fragment: None,
    decoder: frame.clear(socket.decoder),
  )
}

/// Pull the next complete message or control frame.
///
/// Ping is answered with Pong before the event is returned.
/// A received Close is echoed once when necessary and then makes subsequent reads return `AlreadyClosed`.
/// Both Close frames finish the local HTTP/3 send direction.
/// A receive failure aborts the stream and preserves its original error.
/// When the server can still write an established stream, a protocol failure first sends the applicable RFC 6455 Close code and awaits its HTTP/3 send acknowledgement.
/// Cleanup remains bounded even when that attempt fails.
/// Fragment and transport reads share one operation deadline.
/// Automatic Pong,
/// Close, FIN and failure cancellation retain their own bounded operation budgets.
pub fn receive(socket: Socket) -> Result(#(Socket, Event), Error) {
  receive_with_clock(socket, clock.monotonic_milliseconds)
}

/// Internal deterministic clock seam for one receive operation.
@internal
pub fn receive_with_clock(
  socket: Socket,
  now: fn() -> Int,
) -> Result(#(Socket, Event), Error) {
  use <- bool.guard(when: socket.close_received, return: Error(AlreadyClosed))
  let duration = case socket.transport {
    ClientTransport(stream) -> client.operation_timeout_milliseconds(stream)
    ServerTransport(request) -> server.operation_timeout_milliseconds(request)
  }
  let budget = ReceiveBudget(now() + duration, now)
  let outcome = {
    use event <- result.try(receive_buffered(socket, budget))
    use _ <- result.try(require_receive_time(socket.transport, budget))
    Ok(event)
  }
  case outcome {
    Ok(event) -> Ok(event)
    Error(failure) -> fail_receive(socket, failure)
  }
}

fn fail_receive(socket: Socket, failure: Error) -> Result(value, Error) {
  case socket.transport, failure_close_code(failure) {
    ClientTransport(stream), Some(status) -> {
      record_client_failure(stream, failure)
      try_client_failure_close(socket, stream, status)
    }
    ServerTransport(request), Some(status) -> {
      record_server_failure(request, failure)
      try_server_failure_close(socket, request, status)
    }
    _, _ -> Nil
  }
  // A failed WebSocket must not leave its HTTP/3 stream open.
  // Preserve the framing/transport cause if Close transmission or cancellation also fails.
  case cancel(socket) {
    Ok(_) | Error(_) -> Error(failure)
  }
}

fn record_client_failure(stream: client.Stream, failure: Error) -> Nil {
  case websocket_failure(failure) {
    Some(kind) ->
      client.record_application_error(
        stream: stream,
        code: diagnostic_code.websocket_failure(kind),
      )
    None -> Nil
  }
}

fn failure_close_code(failure: Error) -> Option(Int) {
  case failure {
    FrameError | ProtocolViolation | InvalidClose -> Some(1002)
    InvalidUtf8 -> Some(1007)
    MessageTooLarge(_) -> Some(1009)
    InvalidHandshake
    | UnsupportedVersion
    | InvalidKey
    | UnexpectedStatus(_)
    | AcceptMismatch
    | AlreadyClosed
    | ServerFailure(_)
    | ClientFailure(_) -> None
  }
}

fn try_server_failure_close(
  socket: Socket,
  request: server.Request,
  status: Int,
) -> Nil {
  let closed = case socket.close_sent {
    True -> Ok(socket)
    False -> close(socket, Some(status), "")
  }
  let _close_attempt = {
    use closed <- result.try(closed)
    use _ <- result.try(finish_transport(closed.transport))
    server.await_response_completion(request) |> result.map_error(ServerFailure)
  }
  Nil
}

fn try_client_failure_close(
  socket: Socket,
  stream: client.Stream,
  status: Int,
) -> Nil {
  let closed = case socket.close_sent {
    True -> Ok(socket)
    False -> close(socket, Some(status), "")
  }
  let _close_attempt = {
    use closed <- result.try(closed)
    use _ <- result.try(finish_transport(closed.transport))
    client.await_request_completion(stream) |> result.map_error(ClientFailure)
  }
  Nil
}

fn require_receive_time(
  transport: Transport,
  budget: ReceiveBudget,
) -> Result(Nil, Error) {
  use <- bool.guard(when: budget.now() < budget.deadline, return: Ok(Nil))
  let timeout = runtime_failure.Timeout(runtime_failure.Operation)
  case transport {
    ClientTransport(_) -> Error(ClientFailure(client.Failure(timeout)))
    ServerTransport(_) -> Error(ServerFailure(server.Failure(timeout)))
  }
}

fn receive_buffered(
  socket: Socket,
  budget: ReceiveBudget,
) -> Result(#(Socket, Event), Error) {
  use _ <- result.try(require_receive_time(socket.transport, budget))
  case frame.next(socket.decoder) {
    Error(_) -> Error(FrameError)
    Ok(frame.NeedMore(_)) -> read_transport(socket, budget)
    Ok(frame.Ready(decoder, incoming)) ->
      handle_frame(Socket(..socket, decoder: decoder), incoming, budget)
  }
}

fn read_transport(
  socket: Socket,
  budget: ReceiveBudget,
) -> Result(#(Socket, Event), Error) {
  case next_transport_event(socket.transport, budget.deadline) {
    Ok(bytes) -> {
      use decoder <- result.try(
        frame.push(socket.decoder, bytes)
        |> result.replace_error(FrameError),
      )
      receive_buffered(Socket(..socket, decoder: decoder), budget)
    }
    Error(error) -> Error(error)
  }
}

fn next_transport_event(
  transport: Transport,
  deadline: Int,
) -> Result(BitArray, Error) {
  case transport {
    ServerTransport(request) ->
      case server.next_event_until(request, deadline) {
        Ok(server.Data(bytes)) -> Ok(bytes)
        Ok(server.Trailers(_)) | Ok(server.End) -> Error(ProtocolViolation)
        Error(error) -> Error(ServerFailure(error))
      }
    ClientTransport(stream) ->
      case client.next_event_until(stream, deadline) {
        Ok(client.Data(bytes)) -> Ok(bytes)
        Ok(client.InformationalResponse(_, _))
        | Ok(client.Response(_, _))
        | Ok(client.Trailers(_))
        | Ok(client.End) -> Error(ProtocolViolation)
        Error(error) -> Error(ClientFailure(error))
      }
  }
}

fn handle_frame(
  socket: Socket,
  incoming: frame.Frame,
  budget: ReceiveBudget,
) -> Result(#(Socket, Event), Error) {
  let frame.Frame(fin, opcode, payload) = incoming
  case opcode {
    frame.Ping -> {
      use socket <- result.try(send_frame(
        socket,
        frame.Frame(True, frame.Pong, payload),
      ))
      Ok(#(socket, Ping(payload)))
    }
    frame.Pong -> Ok(#(socket, Pong(payload)))
    frame.Close -> handle_close(socket, payload)
    frame.Continuation -> continue_fragment(socket, fin, payload, budget)
    frame.Text | frame.Binary ->
      start_message(socket, fin, opcode, payload, budget)
  }
}

fn start_message(
  socket: Socket,
  fin: Bool,
  opcode: frame.Opcode,
  payload: BitArray,
  budget: ReceiveBudget,
) -> Result(#(Socket, Event), Error) {
  use <- bool.guard(
    when: socket.fragment != None,
    return: Error(ProtocolViolation),
  )
  // Account for the first fragment before retaining it or processing a following control frame.
  // The frame decoder's separate control allowance may be larger than this application's complete-message limit.
  use <- bool.guard(
    when: bit_array.byte_size(payload)
      > socket.configuration.maximum_message_bytes,
    return: Error(MessageTooLarge(socket.configuration.maximum_message_bytes)),
  )
  case fin {
    True -> complete_message(socket, opcode, payload)
    False ->
      receive_buffered(
        Socket(..socket, fragment: Some(Fragment(opcode, payload))),
        budget,
      )
  }
}

fn continue_fragment(
  socket: Socket,
  fin: Bool,
  payload: BitArray,
  budget: ReceiveBudget,
) -> Result(#(Socket, Event), Error) {
  case socket.fragment {
    None -> Error(ProtocolViolation)
    Some(Fragment(opcode, retained)) -> {
      let total = bit_array.byte_size(retained) + bit_array.byte_size(payload)
      use <- bool.guard(
        when: total > socket.configuration.maximum_message_bytes,
        return: Error(MessageTooLarge(
          socket.configuration.maximum_message_bytes,
        )),
      )
      let combined = <<retained:bits, payload:bits>>
      case fin {
        True ->
          complete_message(Socket(..socket, fragment: None), opcode, combined)
        False ->
          receive_buffered(
            Socket(..socket, fragment: Some(Fragment(opcode, combined))),
            budget,
          )
      }
    }
  }
}

fn complete_message(
  socket: Socket,
  opcode: frame.Opcode,
  payload: BitArray,
) -> Result(#(Socket, Event), Error) {
  // Both initial and continuation fragments have been charged before this point, including an unfragmented message's first and only frame.
  case opcode {
    frame.Text ->
      bit_array.to_string(payload)
      |> result.map(fn(message) { #(socket, TextMessage(message)) })
      |> result.replace_error(InvalidUtf8)
    frame.Binary -> Ok(#(socket, BinaryMessage(payload)))
    _ -> Error(ProtocolViolation)
  }
}

fn handle_close(
  socket: Socket,
  payload: BitArray,
) -> Result(#(Socket, Event), Error) {
  use #(status, reason) <- result.try(parse_close_payload(payload))
  let received = Socket(..socket, close_received: True)
  use closed <- result.try(case socket.close_sent {
    True -> Ok(received)
    False -> close(received, status, reason)
  })
  use _ <- result.try(finish_transport(closed.transport))
  Ok(#(discard_closed_input(closed), CloseReceived(status, reason)))
}

fn finish_transport(transport: Transport) -> Result(Nil, Error) {
  case transport {
    ClientTransport(stream) ->
      client.finish(stream) |> result.map_error(ClientFailure)
    ServerTransport(request) ->
      server.finish_response(request) |> result.map_error(ServerFailure)
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

fn send_frame(socket: Socket, outbound: frame.Frame) -> Result(Socket, Error) {
  let role = case socket.transport {
    ClientTransport(_) -> frame.Client
    ServerTransport(_) -> frame.Server
  }
  use encoded <- result.try(
    frame.encode(role, outbound) |> result.replace_error(FrameError),
  )
  case socket.transport {
    ClientTransport(stream) ->
      client.send_chunk(stream, encoded)
      |> result.map(fn(_) { socket })
      |> result.map_error(ClientFailure)
    ServerTransport(request) ->
      server.send_chunk(request, encoded)
      |> result.map(fn(_) { socket })
      |> result.map_error(ServerFailure)
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
