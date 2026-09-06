//// One bounded HTTP/1.1 client exchange over the active-once transport.

import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/body
import http/error
import http/internal/http1
import http/internal/http1/body as http1_body
import http/internal/http1/encode
import http/internal/transport

const http1_alpn = <<"http/1.1":utf8>>

const maximum_informational_responses = 8

/// Finite policy for one HTTP/1.1 exchange.
pub opaque type Config {
  Config(
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    tls_timeout_milliseconds: Int,
    operation_timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    total_timeout_milliseconds: Int,
    maximum_head_bytes: Int,
    maximum_header_count: Int,
    maximum_line_bytes: Int,
    maximum_body_bytes: Int,
    maximum_stream_buffer_bytes: Int,
    maximum_trailer_bytes: Int,
    maximum_trailer_count: Int,
    ca_certificates: List(BitArray),
    proxy_host: Option(String),
    proxy_port: Int,
    proxy_authorization: Option(String),
    reuse_connections: Bool,
    checkout: fn(String) -> Result(Option(transport.Socket), error.Error),
    checkin: fn(String, transport.Socket) -> Bool,
    pool_key: String,
    connection_reusable: Bool,
    connection_guard: Option(ConnectionGuard),
    attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
    cancelled: fn() -> Bool,
    cleanup: fn() -> Nil,
  )
}

type Prepared {
  Prepared(
    method: BitArray,
    head: BitArray,
    body: body.Body,
    framing: http1.Framing,
    scheme: gleam_http.Scheme,
    host: String,
    port: Int,
    connect_host: String,
    connect_port: Int,
    pool_key: String,
    reusable: Bool,
    expect_continue: Bool,
  )
}

/// A successfully established HTTP/1.1 CONNECT or Upgrade stream. This type
/// is consumed only by the public client's opaque tunnel wrapper.
pub type TunnelReady {
  TunnelReady(
    status: Int,
    headers: List(#(String, String)),
    socket: transport.Socket,
    buffered: BitArray,
    cleanup: fn() -> Nil,
  )
}

type ConnectionGuard

type TunnelIntent {
  ConnectTunnel
  UpgradeTunnel
}

type DeadlineTimeout {
  DeadlineTimeout(milliseconds: Int, expiry: error.TimeoutPhase)
}

@external(erlang, "http_client_ffi", "new_connection_guard")
fn new_connection_guard() -> ConnectionGuard

@external(erlang, "http_client_ffi", "mark_connection_released")
fn mark_connection_released(guard: ConnectionGuard) -> Bool

@external(erlang, "http_client_ffi", "claim_connection_close")
fn claim_connection_close(guard: ConnectionGuard) -> Bool

type StreamState {
  Reading(
    socket: transport.Socket,
    decoder: http1_body.Decoder,
    input: BitArray,
    deadline: Int,
    config: Config,
  )
  Pending(bytes: BitArray, following: StreamState)
  Finished(trailers: body.Headers, deadline: Int, config: Config)
}

/// Product defaults shared by one-shot exchanges and the reusable client.
pub fn defaults() -> Config {
  Config(
    dns_timeout_milliseconds: 5000,
    connect_timeout_milliseconds: 10_000,
    tls_timeout_milliseconds: 10_000,
    operation_timeout_milliseconds: 30_000,
    idle_timeout_milliseconds: 30_000,
    total_timeout_milliseconds: 30_000,
    maximum_head_bytes: 65_536,
    maximum_header_count: 100,
    maximum_line_bytes: 8192,
    maximum_body_bytes: 67_108_864,
    maximum_stream_buffer_bytes: 262_144,
    maximum_trailer_bytes: 65_536,
    maximum_trailer_count: 100,
    ca_certificates: [],
    proxy_host: None,
    proxy_port: 0,
    proxy_authorization: None,
    reuse_connections: False,
    checkout: fn(_) { Ok(None) },
    checkin: fn(_, _) { False },
    pool_key: "",
    connection_reusable: False,
    connection_guard: None,
    attach: fn(_, _) { Ok(fn() { Nil }) },
    cancelled: fn() { False },
    cleanup: fn() { Nil },
  )
}

/// Replace the DNS phase deadline independently of TCP connection setup.
pub fn with_dns_timeout(
  config: Config,
  dns_timeout_milliseconds: Int,
) -> Result(Config, error.Error) {
  use <- require(
    valid_timeout(dns_timeout_milliseconds),
    security_policy_error(),
  )
  Ok(Config(..config, dns_timeout_milliseconds:))
}

/// Replace all exchange deadlines after validating that every wait is finite.
pub fn with_timeouts(
  config: Config,
  connect_timeout_milliseconds: Int,
  tls_timeout_milliseconds: Int,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  total_timeout_milliseconds: Int,
) -> Result(Config, error.Error) {
  use <- require(
    valid_timeout(connect_timeout_milliseconds)
      && valid_timeout(tls_timeout_milliseconds)
      && valid_timeout(operation_timeout_milliseconds)
      && valid_timeout(idle_timeout_milliseconds)
      && valid_timeout(total_timeout_milliseconds),
    security_policy_error(),
  )
  Ok(
    Config(
      ..config,
      connect_timeout_milliseconds:,
      tls_timeout_milliseconds:,
      operation_timeout_milliseconds:,
      idle_timeout_milliseconds:,
      total_timeout_milliseconds:,
    ),
  )
}

/// Replace the OS trust store with an explicit finite DER CA set. Certificate
/// decoding and chain validation remain inside the TLS boundary.
pub fn with_ca_certificates(
  config: Config,
  ca_certificates: List(BitArray),
) -> Config {
  Config(..config, ca_certificates:)
}

/// Route cleartext requests through one validated forward proxy.
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

/// Remove proxy routing after an authenticated CONNECT tunnel is established.
pub fn without_proxy(config: Config) -> Config {
  Config(..config, proxy_host: None, proxy_port: 0, proxy_authorization: None)
}

/// Bound total decoded bytes for one response body.
pub fn with_maximum_body_bytes(
  config: Config,
  maximum_body_bytes: Int,
) -> Result(Config, error.Error) {
  with_body_limits(
    config,
    maximum_body_bytes,
    config.maximum_stream_buffer_bytes,
  )
}

/// Bound decoded body bytes and every active-once stream read.
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

/// Attach connection ownership and cancellation hooks supplied by the
/// reusable client. The one-shot default remains self-contained.
pub fn with_lifecycle(
  config: Config,
  attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
  cancelled: fn() -> Bool,
) -> Config {
  Config(..config, attach:, cancelled:)
}

/// Enable bounded connection reuse through callbacks owned by one Client.
pub fn with_pool(
  config: Config,
  checkout: fn(String) -> Result(Option(transport.Socket), error.Error),
  checkin: fn(String, transport.Socket) -> Bool,
) -> Config {
  Config(..config, reuse_connections: True, checkout:, checkin:)
}

/// Disable connection reuse for one independently supervised attempt.
pub fn without_pool(config: Config) -> Config {
  Config(..config, reuse_connections: False)
}

/// Perform one request without retaining a pool or any global state.
///
/// A successful response body owns the connection until it completes or is
/// cancelled. Every failure after connection establishment closes the stream.
pub fn run(
  request: Request(body.Body),
  config: Config,
) -> Result(Response(body.Body), error.Error) {
  let deadline =
    transport.monotonic_millisecond() + config.total_timeout_milliseconds
  use _ <- result.try(require_active(config))
  use prepared <- result.try(prepare(request, config))
  let config =
    Config(
      ..config,
      pool_key: prepared.pool_key,
      connection_reusable: prepared.reusable,
    )
  use reused <- result.try(checkout_connection(prepared, config))
  case reused {
    Some(socket) -> run_reused_or_reconnect(socket, prepared, config, deadline)
    None -> connect(prepared, config, deadline)
  }
}

/// Establish one CONNECT or Upgrade stream without sending application bytes
/// before the successful 2xx or 101 response.
pub fn run_tunnel(
  request: Request(body.Body),
  config: Config,
) -> Result(TunnelReady, error.Error) {
  let deadline =
    transport.monotonic_millisecond() + config.total_timeout_milliseconds
  use _ <- result.try(require_active(config))
  use <- require(
    body.known_length(request.body) == Some(0),
    security_policy_error(),
  )
  use intent <- result.try(tunnel_intent(request))
  let tunnel_config = Config(..config, reuse_connections: True)
  use prepared <- result.try(prepare(request, tunnel_config))
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
  use socket <- result.try(
    transport.connect_with_deadlines(
      prepared.connect_host,
      prepared.connect_port,
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
  case run_connected_tunnel(socket, prepared, intent, config, deadline) {
    Ok(ready) -> Ok(ready)
    Error(failure) -> close_with(socket, failure)
  }
}

/// Continue an HTTPS exchange on an already authenticated HTTP/1.1 socket.
///
/// The supplied cleanup owns the existing lifecycle registration. Every
/// failure before response-body ownership is established closes the socket.
pub fn run_presecured(
  request: Request(body.Body),
  socket: transport.Socket,
  cleanup: fn() -> Nil,
  config: Config,
  total_deadline_millisecond: Int,
) -> Result(Response(body.Body), error.Error) {
  let registered = Config(..config, cleanup:)
  case require_active(registered) {
    Error(failure) -> close_with_config(socket, registered, failure)
    Ok(_) ->
      case prepare(request, registered) {
        Error(failure) -> close_with_config(socket, registered, failure)
        Ok(prepared) ->
          case
            prepared.scheme == gleam_http.Https
            && total_deadline_millisecond > transport.monotonic_millisecond()
          {
            False ->
              close_with_config(socket, registered, security_policy_error())
            True -> {
              let registered =
                Config(
                  ..registered,
                  pool_key: prepared.pool_key,
                  connection_reusable: prepared.reusable,
                )
              run_registered(
                socket,
                prepared,
                registered,
                total_deadline_millisecond,
              )
            }
          }
      }
  }
}

fn connect(
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
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
  use socket <- result.try(
    transport.connect_with_deadlines(
      prepared.connect_host,
      prepared.connect_port,
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
  case run_connected(socket, prepared, config, deadline) {
    Ok(response) -> Ok(response)
    Error(failure) -> close_with(socket, failure)
  }
}

fn checkout_connection(
  prepared: Prepared,
  config: Config,
) -> Result(Option(transport.Socket), error.Error) {
  case prepared.reusable {
    True -> config.checkout(prepared.pool_key)
    False -> Ok(None)
  }
}

fn run_reused(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  use cleanup <- result.try(config.attach(config.pool_key, socket))
  let registered = Config(..config, cleanup:)
  run_registered(socket, prepared, registered, deadline)
}

fn run_reused_or_reconnect(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  case run_reused(socket, prepared, config, deadline) {
    Ok(incoming) -> Ok(incoming)
    Error(failure) ->
      case request_is_retryable(prepared) {
        False -> Error(failure)
        True ->
          case body.replay(prepared.body) {
            Error(_) -> Error(failure)
            Ok(replayed) ->
              connect(Prepared(..prepared, body: replayed), config, deadline)
          }
      }
  }
}

fn request_is_retryable(prepared: Prepared) -> Bool {
  body.is_replayable(prepared.body)
  && case prepared.method {
    <<"GET":utf8>>
    | <<"HEAD":utf8>>
    | <<"PUT":utf8>>
    | <<"DELETE":utf8>>
    | <<"OPTIONS":utf8>>
    | <<"TRACE":utf8>> -> True
    _ -> False
  }
}

fn run_connected(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  use cleanup <- result.try(config.attach(config.pool_key, socket))
  let registered = Config(..config, cleanup:)
  case
    secure_if_needed(
      socket,
      prepared.scheme,
      prepared.host,
      registered,
      deadline,
    )
  {
    Error(failure) -> close_with_config(socket, registered, failure)
    Ok(secured) ->
      case prepared.scheme {
        gleam_http.Http ->
          run_registered(secured, prepared, registered, deadline)
        gleam_http.Https -> {
          registered.cleanup()
          use cleanup <- result.try(config.attach(config.pool_key, secured))
          let registered = Config(..config, cleanup:)
          run_registered(secured, prepared, registered, deadline)
        }
      }
  }
}

fn run_connected_tunnel(
  socket: transport.Socket,
  prepared: Prepared,
  intent: TunnelIntent,
  config: Config,
  deadline: Int,
) -> Result(TunnelReady, error.Error) {
  use cleanup <- result.try(config.attach(prepared.pool_key, socket))
  let registered = Config(..config, cleanup:)
  case
    secure_if_needed(
      socket,
      prepared.scheme,
      prepared.host,
      registered,
      deadline,
    )
  {
    Error(failure) -> close_with_config(socket, registered, failure)
    Ok(secured) ->
      case prepared.scheme {
        gleam_http.Http ->
          run_secured_tunnel(secured, prepared, intent, registered, deadline)
        gleam_http.Https -> {
          registered.cleanup()
          use cleanup <- result.try(config.attach(prepared.pool_key, secured))
          run_secured_tunnel(
            secured,
            prepared,
            intent,
            Config(..config, cleanup:),
            deadline,
          )
        }
      }
  }
}

fn run_secured_tunnel(
  socket: transport.Socket,
  prepared: Prepared,
  intent: TunnelIntent,
  config: Config,
  deadline: Int,
) -> Result(TunnelReady, error.Error) {
  case send_bytes(socket, prepared.head, config, deadline) {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(Nil) ->
      case
        http1.response_parser(head_limits(config), prepared.method)
        |> result.map_error(fn(_) { protocol_error() })
      {
        Error(failure) -> close_with_config(socket, config, failure)
        Ok(parser) ->
          receive_tunnel_response(socket, parser, intent, config, deadline)
      }
  }
}

fn receive_tunnel_response(
  socket: transport.Socket,
  parser: http1.ResponseParser,
  intent: TunnelIntent,
  config: Config,
  deadline: Int,
) -> Result(TunnelReady, error.Error) {
  case receive_final_head(socket, parser, <<>>, 0, config, deadline) {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(#(head, remaining, socket)) ->
      case valid_tunnel_response(intent, head) {
        False -> close_with_config(socket, config, protocol_error())
        True -> finish_tunnel_response(socket, head, remaining, config)
      }
  }
}

fn finish_tunnel_response(
  socket: transport.Socket,
  head: http1.ResponseHead,
  remaining: BitArray,
  config: Config,
) -> Result(TunnelReady, error.Error) {
  case response_headers(head.headers) {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(headers) ->
      Ok(TunnelReady(
        status: head.status,
        headers:,
        socket:,
        buffered: remaining,
        cleanup: config.cleanup,
      ))
  }
}

fn valid_tunnel_response(
  intent: TunnelIntent,
  head: http1.ResponseHead,
) -> Bool {
  case intent {
    ConnectTunnel ->
      head.status >= 200 && head.status < 300 && head.framing == http1.Tunnel
    UpgradeTunnel -> head.status == 101 && head.framing == http1.Tunnel
  }
}

fn run_registered(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  case run_secured(socket, prepared, config, deadline) {
    Ok(response) -> Ok(response)
    Error(failure) -> close_with_config(socket, config, failure)
  }
}

fn run_secured(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  use _ <- result.try(send_bytes(socket, prepared.head, config, deadline))
  use parser <- result.try(
    http1.response_parser(head_limits(config), prepared.method)
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use #(head, remaining, socket) <- result.try(case prepared.expect_continue {
    False -> {
      use _ <- result.try(send_request_body(socket, prepared, config, deadline))
      receive_final_head(socket, parser, <<>>, 0, config, deadline)
    }
    True ->
      receive_expectation_response(
        socket,
        parser,
        <<>>,
        0,
        prepared,
        config,
        deadline,
      )
  })
  response_from_head(socket, head, remaining, config, deadline)
}

fn prepare(
  request: Request(body.Body),
  config: Config,
) -> Result(Prepared, error.Error) {
  use port <- result.try(request_port(request.scheme, request.port))
  let method =
    request.method |> gleam_http.method_to_string |> bit_array.from_string
  use target <- result.try(proxy_request_target(
    config,
    request.scheme,
    request.host,
    port,
    request.method,
    request.path,
    request.query,
  ))
  use expect_continue <- result.try(expect_continue(request.headers))
  let expected_host = authority(request.host, port, request.scheme)
  let headers = proxy_headers(request.headers, config)
  use headers <- result.try(prepare_headers(
    headers,
    expected_host,
    config.reuse_connections,
  ))
  let framing = case body.known_length(request.body) {
    Some(0) -> http1.NoBody
    Some(length) -> http1.ContentLength(length)
    None -> http1.Chunked
  }
  use head <- result.try(
    encode.request(method, target, headers, framing, head_limits(config))
    |> result.map_error(fn(_) { security_policy_error() }),
  )
  let #(connect_host, connect_port) = case config.proxy_host {
    Some(proxy_host) -> #(proxy_host, config.proxy_port)
    None -> #(request.host, port)
  }
  Ok(Prepared(
    method:,
    head:,
    body: request.body,
    framing:,
    scheme: request.scheme,
    host: request.host,
    port:,
    connect_host:,
    connect_port:,
    pool_key: connection_key(request.scheme, request.host, port),
    reusable: config.reuse_connections
      && !header_contains_token(request.headers, "connection", "close"),
    expect_continue:,
  ))
}

fn prepare_headers(
  headers: List(#(String, String)),
  expected_host: String,
  reuse_connections: Bool,
) -> Result(List(http1.Header), error.Error) {
  use <- require(count_header(headers, "host", 0) <= 1, security_policy_error())
  use <- require(host_matches(headers, expected_host), security_policy_error())
  let headers = case count_header(headers, "host", 0) {
    0 -> list.append(headers, [#("Host", expected_host)])
    _ -> headers
  }
  let headers = case count_header(headers, "connection", 0), reuse_connections {
    0, False -> list.append(headers, [#("Connection", "close")])
    _, _ -> headers
  }
  Ok(
    list.map(headers, fn(header) {
      http1.Header(
        header.0 |> bit_array.from_string,
        header.1 |> bit_array.from_string,
      )
    }),
  )
}

fn connection_key(
  scheme: gleam_http.Scheme,
  host: String,
  port: Int,
) -> String {
  let scheme = case scheme {
    gleam_http.Http -> "http"
    gleam_http.Https -> "https"
  }
  scheme <> "://" <> string.lowercase(host) <> ":" <> int.to_string(port)
}

fn count_header(
  headers: List(#(String, String)),
  expected: String,
  count: Int,
) -> Int {
  case headers {
    [] -> count
    [#(name, _), ..rest] -> {
      let next = case string.lowercase(name) == expected {
        True -> count + 1
        False -> count
      }
      count_header(rest, expected, next)
    }
  }
}

fn expect_continue(
  headers: List(#(String, String)),
) -> Result(Bool, error.Error) {
  expect_continue_loop(headers, False)
}

fn expect_continue_loop(
  headers: List(#(String, String)),
  found: Bool,
) -> Result(Bool, error.Error) {
  case headers {
    [] -> Ok(found)
    [#(name, value), ..rest] ->
      case string.lowercase(name) == "expect" {
        False -> expect_continue_loop(rest, found)
        True ->
          case
            !found
            && { value |> string.trim |> string.lowercase } == "100-continue"
          {
            True -> expect_continue_loop(rest, True)
            False -> Error(security_policy_error())
          }
      }
  }
}

fn tunnel_intent(
  request: Request(body.Body),
) -> Result(TunnelIntent, error.Error) {
  case request.method {
    gleam_http.Connect -> Ok(ConnectTunnel)
    _ ->
      case
        header_contains_token(request.headers, "connection", "upgrade")
        && has_nonempty_header(request.headers, "upgrade")
      {
        True -> Ok(UpgradeTunnel)
        False -> Error(security_policy_error())
      }
  }
}

fn has_nonempty_header(
  headers: List(#(String, String)),
  expected_name: String,
) -> Bool {
  case headers {
    [] -> False
    [#(name, value), ..rest] ->
      case string.lowercase(name) == expected_name {
        True -> value |> string.trim != ""
        False -> has_nonempty_header(rest, expected_name)
      }
  }
}

fn header_contains_token(
  headers: List(#(String, String)),
  expected_name: String,
  expected_token: String,
) -> Bool {
  case headers {
    [] -> False
    [#(name, value), ..rest] ->
      case string.lowercase(name) == expected_name {
        True ->
          value
          |> string.split(",")
          |> list.any(fn(token) {
            token |> string.trim |> string.lowercase == expected_token
          })
        False -> header_contains_token(rest, expected_name, expected_token)
      }
  }
}

fn host_matches(headers: List(#(String, String)), expected: String) -> Bool {
  case headers {
    [] -> True
    [#(name, value), ..rest] ->
      case string.lowercase(name) {
        "host" -> string.lowercase(value) == string.lowercase(expected)
        _ -> host_matches(rest, expected)
      }
  }
}

fn request_port(
  scheme: gleam_http.Scheme,
  configured: Option(Int),
) -> Result(Int, error.Error) {
  case configured, scheme {
    Some(port), _ if port > 0 && port <= 65_535 -> Ok(port)
    Some(_), _ -> Error(security_policy_error())
    None, gleam_http.Http -> Ok(80)
    None, gleam_http.Https -> Ok(443)
  }
}

fn proxy_headers(
  headers: List(#(String, String)),
  config: Config,
) -> List(#(String, String)) {
  let headers = remove_header(headers, "proxy-authorization", [])
  case config.proxy_host, config.proxy_authorization {
    Some(_), Some(value) ->
      list.append(headers, [#("Proxy-Authorization", value)])
    _, _ -> headers
  }
}

fn remove_header(
  headers: List(#(String, String)),
  expected: String,
  reversed: List(#(String, String)),
) -> List(#(String, String)) {
  case headers {
    [] -> list.reverse(reversed)
    [#(name, value), ..rest] ->
      case string.lowercase(name) == expected {
        True -> remove_header(rest, expected, reversed)
        False -> remove_header(rest, expected, [#(name, value), ..reversed])
      }
  }
}

fn proxy_request_target(
  config: Config,
  scheme: gleam_http.Scheme,
  host: String,
  port: Int,
  method: gleam_http.Method,
  path: String,
  query: Option(String),
) -> Result(BitArray, error.Error) {
  use target <- result.try(request_target(method, path, query))
  case config.proxy_host, scheme, method {
    Some(_), gleam_http.Http, gleam_http.Connect -> Ok(target)
    Some(_), gleam_http.Http, _ -> {
      use target <- result.try(
        bit_array.to_string(target)
        |> result.replace_error(security_policy_error()),
      )
      Ok(bit_array.from_string(
        "http://" <> authority(host, port, scheme) <> target,
      ))
    }
    _, _, _ -> Ok(target)
  }
}

fn request_target(
  method: gleam_http.Method,
  path: String,
  query: Option(String),
) -> Result(BitArray, error.Error) {
  let path = case path {
    "" -> "/"
    path -> path
  }
  let valid_path = case method {
    gleam_http.Connect ->
      path != ""
      && !string.contains(path, " ")
      && !string.contains(path, "?")
      && !string.contains(path, "#")
    _ ->
      { string.starts_with(path, "/") || path == "*" }
      && !string.contains(path, "?")
      && !string.contains(path, "#")
  }
  use <- require(valid_path, security_policy_error())
  use <- require(
    method != gleam_http.Connect || query == None,
    security_policy_error(),
  )
  let target = case query {
    None -> path
    Some(query) -> path <> "?" <> query
  }
  use <- require(!string.contains(target, "#"), security_policy_error())
  Ok(bit_array.from_string(target))
}

fn authority(host: String, port: Int, scheme: gleam_http.Scheme) -> String {
  let host = case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }
  case scheme, port {
    gleam_http.Http, 80 | gleam_http.Https, 443 -> host
    _, port -> host <> ":" <> int.to_string(port)
  }
}

fn secure_if_needed(
  socket: transport.Socket,
  scheme: gleam_http.Scheme,
  host: String,
  config: Config,
  deadline: Int,
) -> Result(transport.Socket, error.Error) {
  use _ <- result.try(require_active(config))
  case scheme {
    gleam_http.Http -> Ok(socket)
    gleam_http.Https -> {
      use timeout <- result.try(timeout_for(
        deadline,
        config.tls_timeout_milliseconds,
        error.TlsHandshake,
      ))
      use ready <- result.try(
        transport.upgrade_client_tls(
          socket,
          host,
          config.ca_certificates,
          [http1_alpn],
          timeout.milliseconds,
        )
        |> result.map_error(map_tls_error(_, timeout.expiry)),
      )
      let transport.TlsReady(socket, selected, _) = ready
      case selected == <<>> || selected == http1_alpn {
        True -> Ok(socket)
        False -> Error(error.new(error.Protocol(error.Http1)))
      }
    }
  }
}

fn send_request_body(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Nil, error.Error) {
  case prepared.framing {
    http1.NoBody | http1.ContentLength(_) ->
      send_fixed_body(socket, prepared.body, config, deadline)
    http1.Chunked -> send_chunked_body(socket, prepared.body, config, deadline)
    http1.CloseDelimited | http1.Tunnel -> Error(protocol_error())
  }
}

fn receive_expectation_response(
  socket: transport.Socket,
  parser: http1.ResponseParser,
  input: BitArray,
  informational_count: Int,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(#(http1.ResponseHead, BitArray, transport.Socket), error.Error) {
  use _ <- result.try(require_active(config))
  case http1.feed_response(parser, input) {
    Error(_) -> Error(protocol_error())
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
        Ok(transport.ReadEnd(_)) -> Error(protocol_error())
        Ok(transport.ReadData(bytes, socket)) ->
          receive_expectation_response(
            socket,
            parser,
            bytes,
            informational_count,
            prepared,
            config,
            deadline,
          )
      }
    }
    Ok(http1.ResponseReady(head, remaining)) ->
      case head.status {
        100 -> {
          use <- require(
            informational_count < maximum_informational_responses,
            protocol_error(),
          )
          use _ <- result.try(send_request_body(
            socket,
            prepared,
            config,
            deadline,
          ))
          use parser <- result.try(
            http1.response_parser(head_limits(config), prepared.method)
            |> result.map_error(fn(_) { protocol_error() }),
          )
          receive_final_head(
            socket,
            parser,
            remaining,
            informational_count + 1,
            config,
            deadline,
          )
        }
        status if status > 100 && status < 200 && status != 101 -> {
          use <- require(
            informational_count < maximum_informational_responses,
            protocol_error(),
          )
          use parser <- result.try(
            http1.response_parser(head_limits(config), prepared.method)
            |> result.map_error(fn(_) { protocol_error() }),
          )
          receive_expectation_response(
            socket,
            parser,
            remaining,
            informational_count + 1,
            prepared,
            config,
            deadline,
          )
        }
        _ -> Ok(#(head, remaining, socket))
      }
  }
}

fn send_fixed_body(
  socket: transport.Socket,
  outgoing: body.Body,
  config: Config,
  deadline: Int,
) -> Result(Nil, error.Error) {
  use _ <- result.try(require_active(config))
  use _ <- result.try(ensure_deadline(deadline))
  case body.read(outgoing, config.maximum_stream_buffer_bytes) {
    Error(failure) -> Error(failure)
    Ok(body.Done(_)) -> Ok(Nil)
    Ok(body.Data(bytes, next)) -> {
      use _ <- result.try(send_bytes(socket, bytes, config, deadline))
      send_fixed_body(socket, next, config, deadline)
    }
  }
}

fn send_chunked_body(
  socket: transport.Socket,
  outgoing: body.Body,
  config: Config,
  deadline: Int,
) -> Result(Nil, error.Error) {
  use _ <- result.try(require_active(config))
  use _ <- result.try(ensure_deadline(deadline))
  case body.read(outgoing, config.maximum_stream_buffer_bytes) {
    Error(failure) -> Error(failure)
    Ok(body.Data(bytes, next)) -> {
      use encoded <- result.try(
        encode.chunk(bytes) |> result.map_error(fn(_) { protocol_error() }),
      )
      use _ <- result.try(send_bytes(socket, encoded, config, deadline))
      send_chunked_body(socket, next, config, deadline)
    }
    Ok(body.Done(completed)) -> {
      let trailers = body.trailers(completed) |> option_headers
      let trailers =
        list.map(trailers, fn(header) {
          http1.Header(
            header.0 |> bit_array.from_string,
            header.1 |> bit_array.from_string,
          )
        })
      use final <- result.try(
        encode.final_chunk(trailers, head_limits(config))
        |> result.map_error(fn(_) { protocol_error() }),
      )
      send_bytes(socket, final, config, deadline)
    }
  }
}

fn send_bytes(
  socket: transport.Socket,
  bytes: BitArray,
  config: Config,
  deadline: Int,
) -> Result(Nil, error.Error) {
  use _ <- result.try(require_active(config))
  use timeout <- result.try(timeout_for(
    deadline,
    config.operation_timeout_milliseconds,
    error.Operation,
  ))
  case transport.send(socket, bytes) {
    Ok(value) -> Ok(value)
    Error(failure) ->
      Error(prefer_cancelled(
        config,
        map_operation_error(failure, timeout.expiry),
      ))
  }
}

fn receive_final_head(
  socket: transport.Socket,
  parser: http1.ResponseParser,
  input: BitArray,
  informational_count: Int,
  config: Config,
  deadline: Int,
) -> Result(#(http1.ResponseHead, BitArray, transport.Socket), error.Error) {
  use _ <- result.try(require_active(config))
  case http1.feed_response(parser, input) {
    Error(_) -> Error(protocol_error())
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
        Ok(transport.ReadEnd(_)) -> Error(protocol_error())
        Ok(transport.ReadData(bytes, socket)) ->
          receive_final_head(
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
        False -> Ok(#(head, remaining, socket))
        True -> {
          use <- require(
            informational_count < maximum_informational_responses,
            protocol_error(),
          )
          use parser <- result.try(
            http1.response_parser(head_limits(config), response_method(parser))
            |> result.map_error(fn(_) { protocol_error() }),
          )
          receive_final_head(
            socket,
            parser,
            remaining,
            informational_count + 1,
            config,
            deadline,
          )
        }
      }
  }
}

fn response_method(parser: http1.ResponseParser) -> BitArray {
  http1.response_request_method(parser)
}

fn response_from_head(
  socket: transport.Socket,
  head: http1.ResponseHead,
  remaining: BitArray,
  config: Config,
  deadline: Int,
) -> Result(Response(body.Body), error.Error) {
  use headers <- result.try(response_headers(head.headers))
  case head.framing {
    http1.Tunnel -> Error(protocol_error())
    http1.NoBody | http1.ContentLength(0) -> {
      use <- require(bit_array.byte_size(remaining) == 0, protocol_error())
      let config = response_connection(config, head.framing, headers)
      finish_connection(socket, config)
      Ok(gleam_http_response(head.status, headers, body.empty()))
    }
    framing -> {
      use decoder <- result.try(
        http1_body.decoder(framing, body_limits(config))
        |> result.map_error(map_body_decoder_error),
      )
      let known_length = case framing {
        http1.ContentLength(length) -> Some(length)
        _ -> None
      }
      let config = response_connection(config, framing, headers)
      let source =
        stream_source(Reading(socket, decoder, remaining, deadline, config))
      use incoming <- result.try(
        body.from_pull(source, known_length, None, fn() {
          discard_connection(socket, config)
        }),
      )
      Ok(gleam_http_response(head.status, headers, incoming))
    }
  }
}

fn response_connection(
  config: Config,
  framing: http1.Framing,
  headers: List(#(String, String)),
) -> Config {
  let reusable =
    config.connection_reusable
    && response_framing_is_reusable(framing)
    && !header_contains_token(headers, "connection", "close")
  Config(
    ..config,
    connection_reusable: reusable,
    connection_guard: Some(new_connection_guard()),
  )
}

fn response_framing_is_reusable(framing: http1.Framing) -> Bool {
  case framing {
    http1.NoBody | http1.ContentLength(_) | http1.Chunked -> True
    http1.CloseDelimited | http1.Tunnel -> False
  }
}

fn gleam_http_response(
  status: Int,
  headers: List(#(String, String)),
  incoming: body.Body,
) -> Response(body.Body) {
  gleam_http_response_ffi(status, headers, incoming)
}

fn gleam_http_response_ffi(
  status: Int,
  headers: List(#(String, String)),
  incoming: body.Body,
) -> Response(body.Body) {
  // Keeping construction in one helper makes the standard response boundary
  // explicit without introducing a product-specific response type.
  response.Response(status:, headers:, body: incoming)
}

fn response_headers(
  headers: List(http1.Header),
) -> Result(List(#(String, String)), error.Error) {
  list.try_map(headers, fn(header) {
    use name <- result.try(
      bit_array.to_string(header.name)
      |> result.map_error(fn(_) { protocol_error() }),
    )
    use value <- result.try(
      bit_array.to_string(header.value)
      |> result.map_error(fn(_) { protocol_error() }),
    )
    Ok(#(string.lowercase(name), value))
  })
}

fn stream_source(state: StreamState) -> body.Pull {
  body.pull(fn(maximum_bytes) { pull_stream(state, maximum_bytes) })
}

fn pull_stream(
  state: StreamState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case state {
    Finished(trailers, _, _) -> Ok(body.PullEnd(trailers))
    _ -> pull_active_stream(state, maximum_bytes)
  }
}

fn pull_active_stream(
  state: StreamState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case state_cancelled(state) {
    True -> close_state(state, error.new(error.Cancelled))
    False ->
      case state_deadline(state) {
        Error(failure) -> close_state(state, failure)
        Ok(_) ->
          case state {
            Finished(_, _, _) -> Error(protocol_error())
            Pending(bytes, following) -> emit(bytes, following, maximum_bytes)
            Reading(socket, decoder, input, deadline, config) ->
              case bit_array.byte_size(input) {
                size if size > 0 ->
                  decode_body(
                    socket,
                    decoder,
                    input,
                    deadline,
                    config,
                    maximum_bytes,
                  )
                _ -> read_body(socket, decoder, deadline, config, maximum_bytes)
              }
          }
      }
  }
}

fn read_body(
  socket: transport.Socket,
  decoder: http1_body.Decoder,
  deadline: Int,
  config: Config,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  use timeout <- result.try(timeout_for(
    deadline,
    config.idle_timeout_milliseconds,
    error.Idle,
  ))
  let read_size = smallest(maximum_bytes, config.maximum_stream_buffer_bytes)
  case transport.read(socket, read_size, timeout.milliseconds) {
    Error(failure) ->
      close_with_config(
        socket,
        config,
        prefer_cancelled(config, map_read_error(failure, timeout.expiry)),
      )
    Ok(transport.ReadData(bytes, socket)) ->
      decode_body(socket, decoder, bytes, deadline, config, maximum_bytes)
    Ok(transport.ReadEnd(socket)) ->
      case http1_body.finish(decoder) {
        Error(failure) ->
          close_with_config(socket, config, map_body_decoder_error(failure))
        Ok(outcome) ->
          decoder_outcome(socket, outcome, deadline, config, maximum_bytes)
      }
  }
}

fn decode_body(
  socket: transport.Socket,
  decoder: http1_body.Decoder,
  bytes: BitArray,
  deadline: Int,
  config: Config,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case http1_body.feed(decoder, bytes) {
    Error(failure) ->
      close_with_config(socket, config, map_body_decoder_error(failure))
    Ok(outcome) ->
      decoder_outcome(socket, outcome, deadline, config, maximum_bytes)
  }
}

fn decoder_outcome(
  socket: transport.Socket,
  outcome: http1_body.Outcome,
  deadline: Int,
  config: Config,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case outcome {
    http1_body.BodyNeedMore(decoder) ->
      pull_stream(
        Reading(socket, decoder, <<>>, deadline, config),
        maximum_bytes,
      )
    http1_body.BodyData(bytes, decoder) ->
      emit(
        bytes,
        Reading(socket, decoder, <<>>, deadline, config),
        maximum_bytes,
      )
    http1_body.BodyComplete(bytes, trailers, remaining) ->
      case bit_array.byte_size(remaining) == 0, response_headers(trailers) {
        False, _ -> close_with_config(socket, config, protocol_error())
        _, Error(failure) -> close_with_config(socket, config, failure)
        True, Ok(trailers) -> {
          finish_connection(socket, config)
          emit(bytes, Finished(trailers, deadline, config), maximum_bytes)
        }
      }
  }
}

fn emit(
  bytes: BitArray,
  following: StreamState,
  maximum_bytes: Int,
) -> Result(body.PullEvent, error.Error) {
  case bit_array.byte_size(bytes) {
    0 -> pull_stream(following, maximum_bytes)
    size if size <= maximum_bytes ->
      Ok(body.PullData(bytes, stream_source(following)))
    _ -> {
      use #(chunk, remaining) <- result.try(
        take_bytes(bytes, maximum_bytes)
        |> result.map_error(fn(_) { protocol_error() }),
      )
      Ok(body.PullData(chunk, stream_source(Pending(remaining, following))))
    }
  }
}

fn state_deadline(state: StreamState) -> Result(Nil, error.Error) {
  case state {
    Reading(_, _, _, deadline, _) -> ensure_deadline(deadline)
    Pending(_, following) -> state_deadline(following)
    Finished(_, deadline, _) -> ensure_deadline(deadline)
  }
}

fn state_cancelled(state: StreamState) -> Bool {
  case state {
    Reading(_, _, _, _, config) -> config.cancelled()
    Pending(_, following) -> state_cancelled(following)
    Finished(_, _, config) -> config.cancelled()
  }
}

fn close_state(
  state: StreamState,
  failure: error.Error,
) -> Result(value, error.Error) {
  case state {
    Reading(socket, _, _, _, config) ->
      close_with_config(socket, config, failure)
    Pending(_, following) -> close_state(following, failure)
    Finished(_, _, config) -> {
      config.cleanup()
      Error(failure)
    }
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

fn ensure_deadline(deadline: Int) -> Result(Nil, error.Error) {
  case deadline - transport.monotonic_millisecond() > 0 {
    True -> Ok(Nil)
    False -> Error(error.new(error.Timeout(error.Total)))
  }
}

fn remaining_total_timeout(deadline: Int) -> Result(Int, error.Error) {
  let remaining = deadline - transport.monotonic_millisecond()
  case remaining > 0 {
    True -> Ok(remaining)
    False -> Error(error.new(error.Timeout(error.Total)))
  }
}

fn valid_timeout(timeout_milliseconds: Int) -> Bool {
  timeout_milliseconds > 0 && timeout_milliseconds <= 2_147_483_647
}

fn head_limits(config: Config) -> http1.Limits {
  http1.Limits(
    maximum_head_bytes: config.maximum_head_bytes,
    maximum_header_count: config.maximum_header_count,
    maximum_line_bytes: config.maximum_line_bytes,
  )
}

fn body_limits(config: Config) -> http1_body.Limits {
  http1_body.Limits(
    maximum_body_bytes: config.maximum_body_bytes,
    maximum_buffered_bytes: config.maximum_stream_buffer_bytes,
    maximum_trailer_bytes: config.maximum_trailer_bytes,
    maximum_trailer_count: config.maximum_trailer_count,
    maximum_line_bytes: config.maximum_line_bytes,
  )
}

fn option_headers(value: Option(body.Headers)) -> body.Headers {
  case value {
    Some(headers) -> headers
    None -> []
  }
}

fn take_bytes(
  bytes: BitArray,
  count: Int,
) -> Result(#(BitArray, BitArray), Nil) {
  use chunk <- result.try(bit_array.slice(bytes, at: 0, take: count))
  use remaining <- result.try(bit_array.slice(
    bytes,
    at: count,
    take: bit_array.byte_size(bytes) - count,
  ))
  Ok(#(chunk, remaining))
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

fn map_operation_error(
  failure: transport.Error,
  timeout: error.TimeoutPhase,
) -> error.Error {
  case failure {
    transport.Timeout -> error.new(error.Timeout(timeout))
    _ -> protocol_error()
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

fn map_body_decoder_error(failure: http1_body.Error) -> error.Error {
  case failure {
    http1_body.BodyTooLarge(maximum) ->
      error.new(error.Body(error.TooLarge(maximum)))
    http1_body.BufferLimitExceeded(_) | http1_body.TrailerTooLarge(_) ->
      error.new(error.Resource(error.BufferedBody))
    http1_body.InvalidLimit -> security_policy_error()
    _ -> protocol_error()
  }
}

fn security_policy_error() -> error.Error {
  error.new(error.Policy(error.SecurityPolicy))
}

fn protocol_error() -> error.Error {
  error.new(error.Protocol(error.Http1))
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

fn close_with_config(
  socket: transport.Socket,
  config: Config,
  failure: error.Error,
) -> Result(value, error.Error) {
  discard_connection(socket, config)
  Error(prefer_cancelled(config, failure))
}

fn finish_connection(socket: transport.Socket, config: Config) -> Nil {
  case config.connection_reusable, config.connection_guard {
    True, Some(guard) ->
      case mark_connection_released(guard) {
        False -> Nil
        True ->
          case config.checkin(config.pool_key, socket) {
            True -> Nil
            False -> config.cleanup()
          }
      }
    _, _ -> discard_connection(socket, config)
  }
}

fn discard_connection(socket: transport.Socket, config: Config) -> Nil {
  let should_close = case config.connection_guard {
    None -> True
    Some(guard) -> claim_connection_close(guard)
  }
  case should_close {
    False -> Nil
    True -> {
      let _close_result = transport.close(socket)
      config.cleanup()
    }
  }
}

fn close_with(
  socket: transport.Socket,
  failure: error.Error,
) -> Result(value, error.Error) {
  let _close_result = transport.close(socket)
  Error(failure)
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
