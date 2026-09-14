//// One bounded HTTP/2 client exchange over verified TLS and active-once I/O.

import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/body
import http/error
import http/internal/http1
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/message
import http/internal/http2/origin
import http/internal/http2/response_reader
import http/internal/http2/settings
import http/internal/http2/wire
import http/internal/transport

const h2_alpn = <<"h2":utf8>>

const http1_alpn = <<"http/1.1":utf8>>

const maximum_informational_responses = 8

/// Finite policy for one negotiated HTTP/2 exchange.
pub opaque type Config {
  Config(
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    tls_timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    total_timeout_milliseconds: Int,
    maximum_body_bytes: Int,
    maximum_stream_buffer_bytes: Int,
    ca_certificates: List(BitArray),
    proxy_host: Option(String),
    proxy_port: Int,
    proxy_authorization: Option(String),
    origin: String,
    reuse_connections: Bool,
    checkout: fn(String) ->
      Result(Option(#(transport.Socket, wire.State, fn() -> Nil)), error.Error),
    checkin: fn(String, transport.Socket, wire.State, fn() -> Nil) -> Bool,
    attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
    cancelled: fn() -> Bool,
    http1_fallback: Option(
      fn(transport.Socket, Request(body.Body), fn() -> Nil, Int) ->
        Result(Response(body.Body), error.Error),
    ),
    cleanup: fn() -> Nil,
  )
}

/// ALPN result. HTTP/1.1 is reported before any application bytes are sent.
pub type Outcome {
  Http2Response(Response(body.Body))
  Http1Response(Response(body.Body))
  Http1Required
}

type Prepared {
  Prepared(
    outgoing: Request(body.Body),
    declared_length: Option(Int),
    host: String,
    port: Int,
    origin: String,
  )
}

type DeadlineTimeout {
  DeadlineTimeout(milliseconds: Int, expiry: error.TimeoutPhase)
}

type OperationDeadlines {
  OperationDeadlines(total: Int, operation: Int)
}

type ConnectionGuard

@external(erlang, "http_client_ffi", "new_connection_guard")
fn new_connection_guard() -> ConnectionGuard

@external(erlang, "http_client_ffi", "mark_connection_released")
fn mark_connection_released(guard: ConnectionGuard) -> Bool

@external(erlang, "http_client_ffi", "claim_connection_close")
fn claim_connection_close(guard: ConnectionGuard) -> Bool

type UploadProgress {
  UploadComplete(wire.State, response_reader.State)
  EarlyResponse(Response(body.Body))
}

type ResponseBodyState {
  ResponseBodyState(
    socket: transport.Socket,
    wire: wire.State,
    reader: response_reader.State,
    stream_id: Int,
    pending: List(response_reader.Chunk),
    completion: Option(body.Headers),
    config: Config,
    deadlines: OperationDeadlines,
    connection_guard: ConnectionGuard,
  )
}

/// Product defaults for finite one-shot HTTP/2 work.
pub fn defaults() -> Config {
  Config(
    dns_timeout_milliseconds: 5000,
    connect_timeout_milliseconds: 10_000,
    tls_timeout_milliseconds: 10_000,
    operation_timeout_milliseconds: 30_000,
    idle_timeout_milliseconds: 30_000,
    total_timeout_milliseconds: 30_000,
    maximum_body_bytes: 67_108_864,
    maximum_stream_buffer_bytes: 262_144,
    ca_certificates: [],
    proxy_host: None,
    proxy_port: 0,
    proxy_authorization: None,
    origin: "",
    reuse_connections: False,
    checkout: fn(_) { Ok(None) },
    checkin: fn(_, _, _, _) { False },
    attach: fn(_, _) { Ok(fn() { Nil }) },
    cancelled: fn() { False },
    http1_fallback: None,
    cleanup: fn() { Nil },
  )
}

/// Replace the OS trust store with an explicit finite DER CA set.
pub fn with_ca_certificates(
  config: Config,
  ca_certificates: List(BitArray),
) -> Config {
  Config(..config, ca_certificates:)
}

/// Establish verified HTTPS through one explicit HTTP CONNECT proxy.
pub fn with_proxy(
  config: Config,
  host: String,
  port: Int,
  authorization: Option(String),
) -> Config {
  Config(
    ..config,
    proxy_host: Some(host),
    proxy_port: port,
    proxy_authorization: authorization,
  )
}

/// Replace every phase deadline after checking that waits remain finite.
pub fn with_timeouts(
  config: Config,
  dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds: Int,
  tls_timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
) -> Result(Config, error.Error) {
  use <- require(
    valid_timeout(dns_timeout_milliseconds)
      && valid_timeout(connect_timeout_milliseconds)
      && valid_timeout(tls_timeout_milliseconds)
      && valid_timeout(operation_timeout_milliseconds)
      && valid_timeout(idle_timeout_milliseconds)
      && valid_timeout(total_timeout_milliseconds),
    security_policy_error(),
  )
  Ok(
    Config(
      ..config,
      dns_timeout_milliseconds:,
      connect_timeout_milliseconds:,
      tls_timeout_milliseconds:,
      operation_timeout_milliseconds:,
      idle_timeout_milliseconds:,
      total_timeout_milliseconds:,
    ),
  )
}

/// Bound retained request/response bytes and each active-once read.
pub fn with_body_limits(
  config: Config,
  maximum_body_bytes: Int,
  maximum_stream_buffer_bytes: Int,
) -> Result(Config, error.Error) {
  use <- require(
    maximum_body_bytes > 0 && maximum_stream_buffer_bytes > 0,
    security_policy_error(),
  )
  Ok(Config(..config, maximum_body_bytes:, maximum_stream_buffer_bytes:))
}

/// Attach connection admission, ownership, and cancellation hooks.
pub fn with_lifecycle(
  config: Config,
  attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
  cancelled: fn() -> Bool,
) -> Config {
  Config(..config, attach:, cancelled:)
}

/// Reuse completed HTTP/2 sessions through the caller-owned finite pool.
pub fn with_pool(
  config: Config,
  checkout: fn(String) ->
    Result(Option(#(transport.Socket, wire.State, fn() -> Nil)), error.Error),
  checkin: fn(String, transport.Socket, wire.State, fn() -> Nil) -> Bool,
) -> Config {
  Config(..config, reuse_connections: True, checkout:, checkin:)
}

/// Disable connection reuse for one independently supervised attempt.
pub fn without_pool(config: Config) -> Config {
  Config(..config, reuse_connections: False)
}

/// Continue HTTP/1.1 on the same authenticated socket when ALPN selects it.
/// The callback receives ownership of both the socket and its cleanup hook.
pub fn with_http1_fallback(
  config: Config,
  fallback: fn(transport.Socket, Request(body.Body), fn() -> Nil, Int) ->
    Result(Response(body.Body), error.Error),
) -> Config {
  Config(..config, http1_fallback: Some(fallback))
}

/// Negotiate and perform one HTTPS request without retaining a connection.
pub fn run(
  outgoing: Request(body.Body),
  config: Config,
) -> Result(Outcome, error.Error) {
  let deadline =
    transport.monotonic_millisecond() + config.total_timeout_milliseconds
  use _ <- result.try(require_active(config))
  use prepared <- result.try(prepare(outgoing))
  let config = Config(..config, origin: prepared.origin)
  use pooled <- result.try(case config.reuse_connections {
    True -> config.checkout(prepared.origin)
    False -> Ok(None)
  })
  case pooled {
    Some(#(socket, state, cleanup)) ->
      run_reused(socket, state, prepared, Config(..config, cleanup:), deadline)
    None -> connect(prepared, config, deadline)
  }
}

fn connect(
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  use dns_timeout <- result.try(timeout_for(
    deadline,
    config.dns_timeout_milliseconds,
    error.DnsLookup,
  ))
  use connect_timeout <- result.try(timeout_for(
    deadline,
    config.connect_timeout_milliseconds,
    error.Connect,
  ))
  use total_timeout <- result.try(remaining_total_timeout(deadline))
  let #(connect_host, connect_port) = case config.proxy_host {
    Some(host) -> #(host, config.proxy_port)
    None -> #(prepared.host, prepared.port)
  }
  use socket <- result.try(
    transport.connect_with_deadlines(
      connect_host,
      connect_port,
      dns_timeout.milliseconds,
      connect_timeout.milliseconds,
      total_timeout,
      smallest(
        config.operation_timeout_milliseconds,
        connect_timeout.milliseconds,
      ),
    )
    |> result.map_error(map_connect_error(
      _,
      dns_timeout.expiry,
      connect_timeout.expiry,
    )),
  )
  case config.attach(prepared.origin, socket) {
    Error(failure) -> close_with(socket, prefer_cancelled(config, failure))
    Ok(cleanup) -> {
      let config = Config(..config, cleanup: cleanup)
      case establish_proxy_tunnel(socket, prepared, config, deadline) {
        Error(failure) -> close_with_config(socket, config, failure)
        Ok(socket) -> negotiate(socket, prepared, config, deadline)
      }
    }
  }
}

fn establish_proxy_tunnel(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(transport.Socket, error.Error) {
  case config.proxy_host {
    None -> Ok(socket)
    Some(_) -> {
      use _ <- result.try(require_active(config))
      use _ <- result.try(timeout_for(
        deadline,
        config.operation_timeout_milliseconds,
        error.Operation,
      ))
      use _ <- result.try(
        transport.send(socket, proxy_connect_head(prepared, config))
        |> result.map_error(fn(failure) {
          prefer_cancelled(config, map_operation_error(failure))
        }),
      )
      use parser <- result.try(
        http1.response_parser(proxy_head_limits(), <<"CONNECT":utf8>>)
        |> result.map_error(fn(_) { proxy_protocol_error() }),
      )
      receive_proxy_response(socket, parser, <<>>, 0, config, deadline)
    }
  }
}

fn receive_proxy_response(
  socket: transport.Socket,
  parser: http1.ResponseParser,
  input: BitArray,
  informational_count: Int,
  config: Config,
  deadline: Int,
) -> Result(transport.Socket, error.Error) {
  use _ <- result.try(require_active(config))
  case http1.feed_response(parser, input) {
    Error(_) -> Error(proxy_protocol_error())
    Ok(http1.ResponseNeedMore(parser)) -> {
      use timeout <- result.try(timeout_for(
        deadline,
        config.idle_timeout_milliseconds,
        error.Idle,
      ))
      case
        transport.read(
          socket,
          config.maximum_stream_buffer_bytes,
          timeout.milliseconds,
        )
      {
        Error(failure) ->
          Error(prefer_cancelled(
            config,
            map_read_error(failure, timeout.expiry),
          ))
        Ok(transport.ReadEnd(_)) -> Error(proxy_protocol_error())
        Ok(transport.ReadData(bytes, socket)) ->
          receive_proxy_response(
            socket,
            parser,
            bytes,
            informational_count,
            config,
            deadline,
          )
      }
    }
    Ok(http1.ResponseReady(head, remaining)) ->
      case head.status >= 100 && head.status < 200 && head.status != 101 {
        True -> {
          use <- require(
            informational_count < maximum_informational_responses,
            proxy_protocol_error(),
          )
          use parser <- result.try(
            http1.response_parser(proxy_head_limits(), <<"CONNECT":utf8>>)
            |> result.map_error(fn(_) { proxy_protocol_error() }),
          )
          receive_proxy_response(
            socket,
            parser,
            remaining,
            informational_count + 1,
            config,
            deadline,
          )
        }
        False -> {
          use <- require(
            head.status >= 200
              && head.status < 300
              && head.framing == http1.Tunnel,
            proxy_policy_error(),
          )
          use <- require(remaining == <<>>, proxy_protocol_error())
          Ok(socket)
        }
      }
  }
}

fn proxy_connect_head(prepared: Prepared, config: Config) -> BitArray {
  let authority = connect_authority(prepared.host, prepared.port)
  let authorization = case config.proxy_authorization {
    None -> ""
    Some(value) -> "Proxy-Authorization: " <> value <> "\r\n"
  }
  bit_array.from_string(
    "CONNECT "
    <> authority
    <> " HTTP/1.1\r\nHost: "
    <> authority
    <> "\r\n"
    <> authorization
    <> "\r\n",
  )
}

fn connect_authority(host: String, port: Int) -> String {
  let host = case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }
  host <> ":" <> int.to_string(port)
}

fn proxy_head_limits() -> http1.Limits {
  http1.Limits(
    maximum_head_bytes: 16_384,
    maximum_header_count: 32,
    maximum_line_bytes: 12_288,
  )
}

fn run_reused(
  socket: transport.Socket,
  state: wire.State,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  case run_h2_reused(socket, state, prepared, config, deadline) {
    Ok(outcome) -> Ok(outcome)
    Error(failure) -> close_with_config(socket, config, failure)
  }
}

fn prepare(outgoing: Request(body.Body)) -> Result(Prepared, error.Error) {
  use <- require(outgoing.scheme == gleam_http.Https, security_policy_error())
  use port <- result.try(request_port(outgoing.port))
  use declared_length <- result.try(
    message.request_content_length(outgoing)
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  use _ <- result.try(require_known_matching_length(
    declared_length,
    body.known_length(outgoing.body),
  ))
  Ok(Prepared(
    outgoing:,
    declared_length:,
    host: outgoing.host,
    port:,
    origin: origin.connection_key(host: outgoing.host, port: port),
  ))
}

fn require_known_matching_length(
  declared: Option(Int),
  known: Option(Int),
) -> Result(Nil, error.Error) {
  case declared, known {
    Some(expected), Some(received) if expected != received ->
      Error(error.new(error.Body(error.LengthMismatch(expected, received))))
    _, _ -> Ok(Nil)
  }
}

fn require_matching_length(
  declared: Option(Int),
  received: Int,
) -> Result(Nil, error.Error) {
  case declared {
    Some(expected) if expected != received ->
      Error(error.new(error.Body(error.LengthMismatch(expected, received))))
    _ -> Ok(Nil)
  }
}

fn negotiate(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  case
    timeout_for(deadline, config.tls_timeout_milliseconds, error.TlsHandshake)
  {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(timeout) ->
      case
        transport.upgrade_client_tls(
          socket,
          prepared.host,
          config.ca_certificates,
          [h2_alpn, http1_alpn],
          timeout.milliseconds,
        )
      {
        Error(failure) ->
          close_with_config(
            socket,
            config,
            map_tls_error(failure, timeout.expiry),
          )
        Ok(transport.TlsReady(socket, selected, _)) -> {
          config.cleanup()
          case config.attach(config.origin, socket) {
            Error(failure) ->
              close_with(socket, prefer_cancelled(config, failure))
            Ok(cleanup) ->
              run_negotiated(
                socket,
                selected,
                prepared,
                Config(..config, cleanup: cleanup),
                deadline,
              )
          }
        }
      }
  }
}

fn run_negotiated(
  socket: transport.Socket,
  selected: BitArray,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  case selected {
    <<"h2":utf8>> ->
      case run_h2(socket, prepared, config, deadline) {
        Ok(outcome) -> Ok(outcome)
        Error(failure) -> close_with_config(socket, config, failure)
      }
    <<"http/1.1":utf8>> ->
      run_http1_fallback(socket, prepared, config, deadline)
    _ -> close_with_config(socket, config, error.new(error.Tls))
  }
}

fn run_http1_fallback(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  case config.http1_fallback {
    None -> {
      discard_connection(socket, config)
      Ok(Http1Required)
    }
    Some(fallback) ->
      fallback(socket, prepared.outgoing, config.cleanup, deadline)
      |> result.map(Http1Response)
  }
}

fn run_h2(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  use collected <- result.try(collect_outgoing_body(prepared, config))
  let #(body_bytes, trailers) = collected
  let deadlines =
    OperationDeadlines(
      total: deadline,
      operation: transport.monotonic_millisecond()
        + config.operation_timeout_milliseconds,
    )
  use state <- result.try(
    wire.new(connection.Client, connection_limits(), wire_limits(config))
    |> result.map_error(map_wire_error),
  )
  use started <- result.try(
    wire.initial_bytes(state, local_settings())
    |> result.map_error(map_wire_error),
  )
  let wire.Started(state, initial) = started
  use _ <- result.try(send_bytes(socket, initial, deadlines))
  run_h2_stream(
    socket,
    state,
    prepared,
    body_bytes,
    trailers,
    config,
    deadlines,
  )
}

fn run_h2_reused(
  socket: transport.Socket,
  state: wire.State,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  use collected <- result.try(collect_outgoing_body(prepared, config))
  let #(body_bytes, trailers) = collected
  let deadlines =
    OperationDeadlines(
      total: deadline,
      operation: transport.monotonic_millisecond()
        + config.operation_timeout_milliseconds,
    )
  run_h2_stream(
    socket,
    state,
    prepared,
    body_bytes,
    trailers,
    config,
    deadlines,
  )
}

fn collect_outgoing_body(
  prepared: Prepared,
  config: Config,
) -> Result(#(BitArray, body.Headers), error.Error) {
  use collected <- result.try(body.read_all(
    prepared.outgoing.body,
    config.maximum_body_bytes,
  ))
  let #(body_bytes, trailers) = collected
  use _ <- result.try(require_matching_length(
    prepared.declared_length,
    bit_array.byte_size(body_bytes),
  ))
  use _ <- result.try(
    message.trailer_headers(trailers)
    |> result.map_error(fn(_) { protocol_error() }),
  )
  Ok(#(body_bytes, trailers))
}

fn run_h2_stream(
  socket: transport.Socket,
  state: wire.State,
  prepared: Prepared,
  body_bytes: BitArray,
  trailers: body.Headers,
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(Outcome, error.Error) {
  use written <- result.try(
    wire.send_request_headers(
      state,
      prepared.outgoing,
      end_stream: bit_array.byte_size(body_bytes) == 0
        && list.is_empty(trailers),
    )
    |> result.map_error(map_wire_error),
  )
  let wire.HeadersWritten(state, stream_id, headers) = written
  use _ <- result.try(send_frames(socket, headers, deadlines))
  use response_state <- result.try(
    response_reader.new(
      stream_id: stream_id,
      maximum_body_bytes: config.maximum_body_bytes,
      maximum_informational: maximum_informational_responses,
    )
    |> result.map_error(map_response_reader_error),
  )
  use upload <- result.try(send_request_body(
    socket,
    state,
    response_state,
    stream_id,
    body_bytes,
    config,
    deadlines,
    end_stream: list.is_empty(trailers),
  ))
  use upload <- result.try(send_request_trailers(
    socket,
    upload,
    stream_id,
    trailers,
    deadlines,
  ))
  case upload {
    EarlyResponse(incoming) -> Ok(Http2Response(incoming))
    UploadComplete(state, response_state) ->
      receive_response_headers(
        socket,
        state,
        response_state,
        stream_id,
        config,
        deadlines,
      )
      |> result.map(Http2Response)
  }
}

fn send_request_body(
  socket: transport.Socket,
  state: wire.State,
  response_state: response_reader.State,
  stream_id: Int,
  bytes: BitArray,
  config: Config,
  deadlines: OperationDeadlines,
  end_stream end_stream: Bool,
) -> Result(UploadProgress, error.Error) {
  case bit_array.byte_size(bytes) {
    0 -> Ok(UploadComplete(state, response_state))
    _ -> {
      use progress <- result.try(
        wire.send_data(
          state,
          stream_id: stream_id,
          bytes: bytes,
          end_stream: end_stream,
        )
        |> result.map_error(map_wire_error),
      )
      case progress {
        wire.DataBlocked(state) ->
          await_upload_progress(
            socket,
            state,
            response_state,
            stream_id,
            bytes,
            end_stream,
            config,
            deadlines,
          )
        wire.DataWritten(state, frames, remaining, end_stream_sent) -> {
          use _ <- result.try(send_frames(socket, frames, deadlines))
          case bit_array.byte_size(remaining), end_stream_sent == end_stream {
            0, True -> Ok(UploadComplete(state, response_state))
            _, _ ->
              await_upload_progress(
                socket,
                state,
                response_state,
                stream_id,
                remaining,
                end_stream,
                config,
                deadlines,
              )
          }
        }
      }
    }
  }
}

fn await_upload_progress(
  socket: transport.Socket,
  state: wire.State,
  response_state: response_reader.State,
  stream_id: Int,
  remaining: BitArray,
  end_stream: Bool,
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(UploadProgress, error.Error) {
  use _ <- result.try(require_active(config))
  use timeout <- result.try(operation_timeout(
    deadlines,
    config.idle_timeout_milliseconds,
  ))
  case
    transport.read(
      socket,
      config.maximum_stream_buffer_bytes,
      timeout.milliseconds,
    )
  {
    Error(failure) -> Error(map_read_error(failure, timeout.expiry))
    Ok(transport.ReadEnd(_)) -> Error(protocol_error())
    Ok(transport.ReadData(bytes, socket)) -> {
      use fed <- result.try(
        wire.feed(state, bytes)
        |> result.map_error(map_wire_error),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(map_wire_error),
      )
      use _ <- result.try(send_frames(socket, automatic, deadlines))
      use progress <- result.try(
        response_reader.accept(response_state, actions)
        |> result.map_error(map_response_reader_error),
      )
      let response_reader.Progress(response_state, head, chunks, completion) =
        progress
      case head {
        Some(head) -> {
          use incoming <- result.try(streaming_response(
            socket,
            state,
            response_state,
            stream_id,
            head,
            chunks,
            completion,
            config,
            deadlines,
          ))
          Ok(EarlyResponse(incoming))
        }
        None ->
          send_request_body(
            socket,
            state,
            response_state,
            stream_id,
            remaining,
            config,
            deadlines,
            end_stream: end_stream,
          )
      }
    }
  }
}

fn send_request_trailers(
  socket: transport.Socket,
  upload: UploadProgress,
  stream_id: Int,
  trailers: body.Headers,
  deadlines: OperationDeadlines,
) -> Result(UploadProgress, error.Error) {
  case upload, trailers {
    EarlyResponse(_), _ | UploadComplete(_, _), [] -> Ok(upload)
    UploadComplete(state, response_state), trailers -> {
      use written <- result.try(
        wire.send_trailers(state, stream_id, trailers)
        |> result.map_error(map_wire_error),
      )
      let wire.HeadersWritten(state, _, frames) = written
      use _ <- result.try(send_frames(socket, frames, deadlines))
      Ok(UploadComplete(state, response_state))
    }
  }
}

fn receive_response_headers(
  socket: transport.Socket,
  state: wire.State,
  response_state: response_reader.State,
  stream_id: Int,
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(Response(body.Body), error.Error) {
  use _ <- result.try(require_active(config))
  use timeout <- result.try(operation_timeout(
    deadlines,
    config.idle_timeout_milliseconds,
  ))
  case
    transport.read(
      socket,
      config.maximum_stream_buffer_bytes,
      timeout.milliseconds,
    )
  {
    Error(failure) -> Error(map_read_error(failure, timeout.expiry))
    Ok(transport.ReadEnd(_)) -> Error(protocol_error())
    Ok(transport.ReadData(bytes, socket)) -> {
      use fed <- result.try(
        wire.feed(state, bytes)
        |> result.map_error(map_wire_error),
      )
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(map_wire_error),
      )
      use _ <- result.try(send_frames(socket, automatic, deadlines))
      use progress <- result.try(
        response_reader.accept(response_state, actions)
        |> result.map_error(map_response_reader_error),
      )
      let response_reader.Progress(response_state, head, chunks, completion) =
        progress
      case head {
        None ->
          receive_response_headers(
            socket,
            state,
            response_state,
            stream_id,
            config,
            deadlines,
          )
        Some(head) ->
          streaming_response(
            socket,
            state,
            response_state,
            stream_id,
            head,
            chunks,
            completion,
            config,
            deadlines,
          )
      }
    }
  }
}

fn streaming_response(
  socket: transport.Socket,
  wire_state: wire.State,
  reader: response_reader.State,
  stream_id: Int,
  head: response_reader.Head,
  pending: List(response_reader.Chunk),
  completion: Option(body.Headers),
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(Response(body.Body), error.Error) {
  let response_reader.Head(incoming, content_length) = head
  // RFC 8336 removes a 421 response's request origin from this connection's
  // Origin Set. The pool is intentionally keyed to one authenticated origin,
  // so evicting the whole idle connection is the conservative equivalent and
  // cannot accidentally retain other authority learned from peer input.
  let config = case incoming.status == 421 {
    True -> Config(..config, reuse_connections: False)
    False -> config
  }
  let connection_guard = new_connection_guard()
  case pending, completion {
    [], Some(trailers) -> {
      finish_connection(socket, wire_state, config, connection_guard)
      Ok(
        Response(
          ..incoming,
          body: body.from_bytes_with_trailers(<<>>, trailers),
        ),
      )
    }
    _, _ -> {
      let state =
        ResponseBodyState(
          socket:,
          wire: wire_state,
          reader:,
          stream_id:,
          pending:,
          completion:,
          config:,
          deadlines:,
          connection_guard:,
        )
      use incoming_body <- result.try(
        body.from_pull(response_body_source(state), content_length, None, fn() {
          discard_response_connection(socket, config, connection_guard)
        }),
      )
      Ok(Response(..incoming, body: incoming_body))
    }
  }
}

fn response_body_source(state: ResponseBodyState) -> body.Pull {
  body.pull(fn(maximum_bytes) { pull_response_body(state, maximum_bytes) })
}

fn pull_response_body(
  state: ResponseBodyState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case require_active(state.config) {
    Error(failure) -> response_body_failure(state, failure)
    Ok(_) ->
      case ensure_operation_deadline(state.deadlines) {
        Error(failure) -> response_body_failure(state, failure)
        Ok(_) -> pull_ready_response_body(state, maximum_bytes)
      }
  }
}

fn pull_ready_response_body(
  state: ResponseBodyState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case state.pending, state.completion {
    [], Some(trailers) -> {
      finish_connection(
        state.socket,
        state.wire,
        state.config,
        state.connection_guard,
      )
      Ok(body.PullEnd(trailers))
    }
    [], None -> read_response_body(state, maximum_bytes)
    [chunk, ..rest], _ -> emit_response_chunk(state, chunk, rest, maximum_bytes)
  }
}

fn emit_response_chunk(
  state: ResponseBodyState,
  chunk: response_reader.Chunk,
  rest: List(response_reader.Chunk),
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  use read <- result.try(
    response_reader.read_chunk(chunk, maximum_bytes)
    |> result.map_error(map_response_reader_error)
    |> close_response_body_on_error(state),
  )
  let response_reader.ChunkPart(bytes, remaining, released_credit) = read
  use state <- result.try(release_response_credit(state, released_credit))
  let pending = case remaining {
    Some(remaining) -> [remaining, ..rest]
    None -> rest
  }
  let following = ResponseBodyState(..state, pending:)
  case bit_array.byte_size(bytes) {
    0 -> pull_ready_response_body(following, maximum_bytes)
    _ -> Ok(body.PullData(bytes, response_body_source(following)))
  }
}

fn read_response_body(
  state: ResponseBodyState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  use timeout <- result.try(
    operation_timeout(state.deadlines, state.config.idle_timeout_milliseconds)
    |> close_response_body_on_error(state),
  )
  case
    transport.read(
      state.socket,
      state.config.maximum_stream_buffer_bytes,
      timeout.milliseconds,
    )
  {
    Error(failure) ->
      response_body_failure(state, map_read_error(failure, timeout.expiry))
    Ok(transport.ReadEnd(_)) -> response_body_failure(state, protocol_error())
    Ok(transport.ReadData(bytes, socket)) -> {
      let state = ResponseBodyState(..state, socket:)
      use fed <- result.try(
        wire.feed(state.wire, bytes)
        |> result.map_error(map_wire_error)
        |> close_response_body_on_error(state),
      )
      let wire.Fed(wire_state, actions) = fed
      let state = ResponseBodyState(..state, wire: wire_state)
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384)
        |> result.map_error(map_wire_error)
        |> close_response_body_on_error(state),
      )
      use _ <- result.try(
        send_frames(socket, automatic, state.deadlines)
        |> close_response_body_on_error(state),
      )
      use progress <- result.try(
        response_reader.accept(state.reader, actions)
        |> result.map_error(map_response_reader_error)
        |> close_response_body_on_error(state),
      )
      let response_reader.Progress(reader, head, pending, completion) = progress
      case head {
        Some(_) -> response_body_failure(state, protocol_error())
        None ->
          pull_ready_response_body(
            ResponseBodyState(..state, reader:, pending:, completion:),
            maximum_bytes,
          )
      }
    }
  }
}

fn release_response_credit(
  state: ResponseBodyState,
  controlled: Int,
) -> Result(ResponseBodyState, error.Error) {
  case controlled <= 0 {
    True -> Ok(state)
    False -> {
      use released <- result.try(
        wire.release_receive_credit(
          state.wire,
          stream_id: state.stream_id,
          octets: controlled,
        )
        |> result.map_error(map_wire_error)
        |> close_response_body_on_error(state),
      )
      let wire.ReceiveCreditReleased(wire_state, frames) = released
      use _ <- result.try(
        send_frames(state.socket, frames, state.deadlines)
        |> close_response_body_on_error(state),
      )
      Ok(ResponseBodyState(..state, wire: wire_state))
    }
  }
}

fn close_response_body_on_error(
  outcome: Result(value, error.Error),
  state: ResponseBodyState,
) -> Result(value, error.Error) {
  case outcome {
    Ok(value) -> Ok(value)
    Error(failure) -> response_body_failure(state, failure)
  }
}

fn response_body_failure(
  state: ResponseBodyState,
  failure: error.Error,
) -> Result(value, error.Error) {
  discard_response_connection(
    state.socket,
    state.config,
    state.connection_guard,
  )
  Error(prefer_cancelled(state.config, failure))
}

fn send_frames(
  socket: transport.Socket,
  frames: List(BitArray),
  deadlines: OperationDeadlines,
) -> Result(Nil, error.Error) {
  case frames {
    [] -> Ok(Nil)
    [bytes, ..rest] -> {
      use _ <- result.try(send_bytes(socket, bytes, deadlines))
      send_frames(socket, rest, deadlines)
    }
  }
}

fn send_bytes(
  socket: transport.Socket,
  bytes: BitArray,
  deadlines: OperationDeadlines,
) -> Result(Nil, error.Error) {
  use _ <- result.try(ensure_operation_deadline(deadlines))
  transport.send(socket, bytes)
  |> result.map_error(map_operation_error)
}

fn connection_limits() -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 1024,
    maximum_active_streams: 100,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 65_536,
      maximum_header_list_bytes: 65_536,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: 100,
    ),
  )
}

fn wire_limits(config: Config) -> wire.Limits {
  wire.Limits(
    maximum_frame_bytes: 16_384,
    maximum_feed_bytes: config.maximum_stream_buffer_bytes,
    maximum_frames_per_feed: 1024,
  )
}

fn local_settings() -> List(settings.Setting) {
  [
    settings.EnablePush(False),
    settings.MaxConcurrentStreams(100),
    settings.MaxHeaderListSize(65_536),
  ]
}

fn request_port(configured: Option(Int)) -> Result(Int, error.Error) {
  case configured {
    Some(port) if port > 0 && port <= 65_535 -> Ok(port)
    Some(_) -> Error(security_policy_error())
    None -> Ok(443)
  }
}

fn timeout_for(
  deadline: Int,
  maximum: Int,
  phase: error.TimeoutPhase,
) -> Result(DeadlineTimeout, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining <= 0 {
    True -> Error(error.new(error.Timeout(error.Total)))
    False ->
      case remaining < maximum {
        True -> Ok(DeadlineTimeout(remaining, error.Total))
        False -> Ok(DeadlineTimeout(maximum, phase))
      }
  }
}

fn operation_timeout(
  deadlines: OperationDeadlines,
  idle_maximum: Int,
) -> Result(DeadlineTimeout, error.Error) {
  let OperationDeadlines(total, operation) = deadlines
  let now = transport.monotonic_millisecond()
  let total_remaining = total - now
  let operation_remaining = operation - now
  case total_remaining <= 0, operation_remaining <= 0 {
    True, _ -> Error(error.new(error.Timeout(error.Total)))
    False, True -> Error(error.new(error.Timeout(error.Operation)))
    False, False ->
      case
        total_remaining <= operation_remaining
        && total_remaining <= idle_maximum,
        operation_remaining <= idle_maximum
      {
        True, _ -> Ok(DeadlineTimeout(total_remaining, error.Total))
        False, True -> Ok(DeadlineTimeout(operation_remaining, error.Operation))
        False, False -> Ok(DeadlineTimeout(idle_maximum, error.Idle))
      }
  }
}

fn ensure_operation_deadline(
  deadlines: OperationDeadlines,
) -> Result(Nil, error.Error) {
  let OperationDeadlines(total, operation) = deadlines
  let now = transport.monotonic_millisecond()
  case total - now > 0, operation - now > 0 {
    False, _ -> Error(error.new(error.Timeout(error.Total)))
    True, False -> Error(error.new(error.Timeout(error.Operation)))
    True, True -> Ok(Nil)
  }
}

fn remaining_total_timeout(deadline: Int) -> Result(Int, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining > 0 {
    True -> Ok(remaining)
    False -> Error(error.new(error.Timeout(error.Total)))
  }
}

fn map_connect_error(
  failure: transport.Error,
  dns_timeout: error.TimeoutPhase,
  connect_timeout: error.TimeoutPhase,
) -> error.Error {
  case failure {
    transport.DnsTimeout -> error.new(error.Timeout(dns_timeout))
    transport.TotalTimeout -> error.new(error.Timeout(error.Total))
    transport.Timeout -> error.new(error.Timeout(connect_timeout))
    transport.DnsFailure -> error.new(error.Dns)
    transport.InvalidInput -> security_policy_error()
    _ -> error.new(error.ConnectFailed)
  }
}

fn map_tls_error(
  failure: transport.Error,
  timeout: error.TimeoutPhase,
) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(timeout))
    transport.InvalidInput -> security_policy_error()
    _ -> error.new(error.Tls)
  }
}

fn map_read_error(
  failure: transport.Error,
  timeout: error.TimeoutPhase,
) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(timeout))
    _ -> protocol_error()
  }
}

fn map_operation_error(failure: transport.Error) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(error.Operation))
    _ -> protocol_error()
  }
}

fn map_wire_error(failure: wire.Error) -> error.Error {
  case failure {
    wire.InvalidLimits -> security_policy_error()
    wire.ChunkTooLarge(_) | wire.TooManyFrames(_) ->
      error.new(error.Resource(error.Memory))
    _ -> protocol_error()
  }
}

fn map_response_reader_error(failure: response_reader.Error) -> error.Error {
  case failure {
    response_reader.InvalidLimits | response_reader.InvalidReadLimit ->
      security_policy_error()
    response_reader.BodyTooLarge(maximum) ->
      error.new(error.Body(error.TooLarge(maximum)))
    _ -> protocol_error()
  }
}

fn close_with_config(
  socket: transport.Socket,
  config: Config,
  failure: error.Error,
) -> Result(value, error.Error) {
  discard_connection(socket, config)
  Error(prefer_cancelled(config, failure))
}

fn discard_connection(socket: transport.Socket, config: Config) -> Nil {
  let _close_result = transport.close(socket)
  config.cleanup()
}

fn finish_connection(
  socket: transport.Socket,
  state: wire.State,
  config: Config,
  guard: ConnectionGuard,
) -> Nil {
  case mark_connection_released(guard) {
    False -> Nil
    True ->
      case
        config.reuse_connections
        && !connection.draining(wire.connection_state(state))
      {
        True ->
          case config.checkin(config.origin, socket, state, config.cleanup) {
            True -> Nil
            False -> config.cleanup()
          }
        False -> {
          let _close_result = transport.close(socket)
          config.cleanup()
        }
      }
  }
}

fn discard_response_connection(
  socket: transport.Socket,
  config: Config,
  guard: ConnectionGuard,
) -> Nil {
  case claim_connection_close(guard) {
    False -> Nil
    True -> discard_connection(socket, config)
  }
}

fn close_with(
  socket: transport.Socket,
  failure: error.Error,
) -> Result(value, error.Error) {
  let _close_result = transport.close(socket)
  Error(failure)
}

fn require_active(config: Config) -> Result(Nil, error.Error) {
  case config.cancelled() {
    True -> Error(error.new(error.Cancelled))
    False -> Ok(Nil)
  }
}

fn prefer_cancelled(config: Config, failure: error.Error) -> error.Error {
  case config.cancelled() {
    True -> error.new(error.Cancelled)
    False -> failure
  }
}

fn valid_timeout(timeout_milliseconds: Int) -> Bool {
  timeout_milliseconds > 0 && timeout_milliseconds <= 2_147_483_647
}

fn security_policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http2))
}

fn proxy_protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http1))
}

fn proxy_policy_error() -> error.Error {
  error.new(error.Policy(error.ProxyPolicy))
}

fn require(
  condition: Bool,
  failure: error,
  continue: fn() -> Result(value, error),
) -> Result(value, error) {
  case condition {
    True -> continue()
    False -> Error(failure)
  }
}

fn smallest(left: Int, right: Int) -> Int {
  case left <= right {
    True -> left
    False -> right
  }
}
