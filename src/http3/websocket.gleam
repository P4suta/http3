//// RFC 9220 WebSockets over HTTP/3 with bounded RFC 6455 framing.
////
//// Compression is intentionally not negotiated. Client frames are masked,
//// server frames are not, fragmented messages are reassembled within a
//// finite message limit, and transport reads retain at most the configured
//// finite buffer.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request.{type Request}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http3/client
import http3/internal/websocket_frame as frame
import http3/server

const default_message_bytes = 1_048_576

const frame_overhead_bytes = 14

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

@external(erlang, "http3_websocket_ffi", "client_key")
fn client_key() -> Result(String, Nil)

@external(erlang, "http3_websocket_ffi", "accept")
fn accept_value(key: String) -> Result(String, Nil)

/// Construct immediately usable finite WebSocket limits.
pub fn new() -> Configuration {
  Configuration(
    maximum_message_bytes: default_message_bytes,
    maximum_buffered_bytes: default_message_bytes + frame_overhead_bytes,
  )
}

/// Replace both finite limits atomically.
///
/// The frame buffer must accommodate the largest message plus its RFC 6455
/// header. Fragment reassembly is separately bounded by the message limit.
pub fn with_limits(
  _configuration: Configuration,
  maximum_message_bytes: Int,
  maximum_buffered_bytes: Int,
) -> Result(Configuration, ConfigurationError) {
  case
    maximum_message_bytes > 0,
    maximum_buffered_bytes >= maximum_message_bytes + frame_overhead_bytes
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
/// The generated `sec-websocket-accept` value cannot be replaced and
/// extensions cannot be negotiated through this API. Connection-specific
/// headers remain rejected by the HTTP/3 response validator.
pub fn accept_with_headers(
  configuration: Configuration,
  request: server.Request,
  response_headers: List(#(String, String)),
) -> Result(Socket, Error) {
  use <- bool.guard(
    when: has_header(response_headers, "sec-websocket-accept")
      || has_header(response_headers, "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  use key <- result.try(validate_server_handshake(request))
  use accepted <- result.try(
    accept_value(key) |> result.replace_error(InvalidKey),
  )
  use _ <- result.try(
    server.send_response(request, 200, [
      #("sec-websocket-accept", accepted),
      ..response_headers
    ])
    |> result.map_error(ServerFailure),
  )
  socket(ServerTransport(request), frame.Server, configuration)
}

/// Open and validate an RFC 9220 Extended CONNECT client handshake.
///
/// The request supplies the HTTPS origin, path, query, cookies,
/// authorization, and any requested subprotocol header. The generated nonce
/// and mandatory version headers replace caller-provided values.
pub fn connect(
  configuration: Configuration,
  connection: client.Connection,
  request: Request(Nil),
) -> Result(Socket, Error) {
  use key <- result.try(client_key() |> result.replace_error(InvalidKey))
  let outbound =
    request
    |> request.set_header("sec-websocket-version", "13")
    |> request.set_header("sec-websocket-key", key)
  use stream <- result.try(
    client.open_extended_connect(connection, outbound, "websocket")
    |> result.map_error(ClientFailure),
  )
  use headers <- result.try(await_client_handshake(stream))
  use expected <- result.try(
    accept_value(key) |> result.replace_error(InvalidKey),
  )
  use actual <- result.try(single_header(headers, "sec-websocket-accept"))
  use <- bool.guard(when: actual != expected, return: Error(AcceptMismatch))
  use <- bool.guard(
    when: has_header(headers, "sec-websocket-extensions"),
    return: Error(InvalidHandshake),
  )
  socket(ClientTransport(stream), frame.Client, configuration)
}

fn socket(
  transport: Transport,
  role: frame.Role,
  configuration: Configuration,
) -> Result(Socket, Error) {
  frame.decoder(
    role,
    configuration.maximum_message_bytes,
    configuration.maximum_buffered_bytes,
  )
  |> result.map(fn(decoder) {
    Socket(transport, configuration, decoder, None, False, False)
  })
  |> result.replace_error(FrameError)
}

fn validate_server_handshake(request: server.Request) -> Result(String, Error) {
  use <- bool.guard(
    when: server.method(request) != http.Connect
      || server.protocol(request) != Some("websocket")
      || server.scheme(request) != "https"
      || string.is_empty(server.authority(request)),
    return: Error(InvalidHandshake),
  )
  use version <- result.try(
    single_header(server.headers(request), "sec-websocket-version")
    |> result.replace_error(UnsupportedVersion),
  )
  use <- bool.guard(when: version != "13", return: Error(UnsupportedVersion))
  single_header(server.headers(request), "sec-websocket-key")
}

fn await_client_handshake(
  stream: client.Stream,
) -> Result(List(#(String, String)), Error) {
  case client.next_event(stream) {
    Ok(client.InformationalResponse(_, _)) -> await_client_handshake(stream)
    Ok(client.Response(200, headers)) -> Ok(headers)
    Ok(client.Response(status, _)) -> Error(UnexpectedStatus(status))
    Ok(client.Data(_)) | Ok(client.Trailers(_)) | Ok(client.End) ->
      Error(InvalidHandshake)
    Error(error) -> Error(ClientFailure(error))
  }
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

/// Send one Ping control frame. The payload may contain at most 125 bytes.
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
/// Omit the status only with an empty reason. A reason is UTF-8 by type and
/// may occupy at most 123 bytes after the two-byte status code.
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
      |> result.map(fn(_) { Socket(..socket, close_sent: True) })
      |> result.map_error(ClientFailure)
    ServerTransport(request) ->
      server.finish_response(request)
      |> result.map(fn(_) { Socket(..socket, close_sent: True) })
      |> result.map_error(ServerFailure)
  }
}

/// Pull the next complete message or control frame.
///
/// Ping is answered with Pong before the event is returned. A received Close
/// is echoed once when necessary and then makes subsequent reads return
/// `AlreadyClosed`.
pub fn receive(socket: Socket) -> Result(#(Socket, Event), Error) {
  use <- bool.guard(when: socket.close_received, return: Error(AlreadyClosed))
  receive_buffered(socket)
}

fn receive_buffered(socket: Socket) -> Result(#(Socket, Event), Error) {
  case frame.next(socket.decoder) {
    Error(_) -> Error(FrameError)
    Ok(frame.NeedMore(_)) -> read_transport(socket)
    Ok(frame.Ready(decoder, incoming)) ->
      handle_frame(Socket(..socket, decoder: decoder), incoming)
  }
}

fn read_transport(socket: Socket) -> Result(#(Socket, Event), Error) {
  case next_transport_event(socket.transport) {
    Ok(bytes) -> {
      use decoder <- result.try(
        frame.push(socket.decoder, bytes)
        |> result.replace_error(FrameError),
      )
      receive_buffered(Socket(..socket, decoder: decoder))
    }
    Error(error) -> Error(error)
  }
}

fn next_transport_event(transport: Transport) -> Result(BitArray, Error) {
  case transport {
    ServerTransport(request) ->
      case server.next_event(request) {
        Ok(server.Data(bytes)) -> Ok(bytes)
        Ok(server.Trailers(_)) | Ok(server.End) -> Error(ProtocolViolation)
        Error(error) -> Error(ServerFailure(error))
      }
    ClientTransport(stream) ->
      case client.next_event(stream) {
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
    frame.Continuation -> continue_fragment(socket, fin, payload)
    frame.Text | frame.Binary -> start_message(socket, fin, opcode, payload)
  }
}

fn start_message(
  socket: Socket,
  fin: Bool,
  opcode: frame.Opcode,
  payload: BitArray,
) -> Result(#(Socket, Event), Error) {
  use <- bool.guard(
    when: socket.fragment != None,
    return: Error(ProtocolViolation),
  )
  case fin {
    True -> complete_message(socket, opcode, payload)
    False ->
      receive_buffered(
        Socket(..socket, fragment: Some(Fragment(opcode, payload))),
      )
  }
}

fn continue_fragment(
  socket: Socket,
  fin: Bool,
  payload: BitArray,
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
  use <- bool.guard(
    when: bit_array.byte_size(payload)
      > socket.configuration.maximum_message_bytes,
    return: Error(MessageTooLarge(socket.configuration.maximum_message_bytes)),
  )
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
  Ok(#(closed, CloseReceived(status, reason)))
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
