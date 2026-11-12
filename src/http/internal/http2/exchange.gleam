//// One bounded HTTP/2 client exchange over verified TLS and active-once I/O.

import gleam/bit_array
import gleam/erlang/process.{type Pid}
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/client_trace
import http/internal/http1
import http/internal/http2/connection
import http/internal/http2/header_codec
import http/internal/http2/message
import http/internal/http2/origin
import http/internal/http2/response_reader
import http/internal/http2/settings
import http/internal/http2/wire
import http/internal/tcp_reservation
import http/internal/transport
import http/internal/upload
import http/resource

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
    checkout_http1: fn(String) -> Result(Option(transport.Socket), error.Error),
    attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
    adopt: fn(transport.Socket, Pid) -> Result(Nil, error.Error),
    cancelled: fn() -> Bool,
    http1_fallback: Option(
      fn(transport.Socket, Request(body.Body), fn() -> Nil, Int) ->
        Result(Response(body.Body), error.Error),
    ),
    cleanup: fn() -> Nil,
    reserve: fn(String) -> Result(tcp_reservation.Reservation, error.Error),
    replace: fn(transport.Socket, transport.Socket) -> Result(Nil, error.Error),
    trace: Option(client_trace.Trace),
    connect_trace: Option(client_trace.Trace),
    connect_observation: Option(#(transport.Diagnostics, ConnectionGuard)),
    shared_resources: Option(resource.Controller),
    lifecycle_owner: Option(Pid),
    source_worker: Option(upload.Upload),
    connection_guard: Option(ConnectionGuard),
    selected_protocol: Option(context.Protocol),
    exchange_started: Bool,
    request_phase_started: Option(ConnectionGuard),
    request_phase_finished: Option(ConnectionGuard),
    response_phase_started: Option(ConnectionGuard),
    response_phase_finished: Option(ConnectionGuard),
    release_phase_started: Option(ConnectionGuard),
    release_phase_finished: Option(ConnectionGuard),
  )
}

/// ALPN result.
/// HTTP/1.1 is reported before any application bytes are sent.
pub type Outcome {
  Http2Response(Response(body.Body))
  Http1Response(Response(body.Body))
  Http1Required
}

/// A verified connection paused before any application request bytes.
/// This internal value can be transferred to the winner of a connection race.
pub opaque type Ready {
  Ready(
    socket: transport.Socket,
    selected: BitArray,
    reused: Option(wire.State),
    prepared: Prepared,
    config: Config,
    deadline: Int,
    once: ConnectionGuard,
  )
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

type FrameWriteFailure {
  FrameDeadline(error.Error)
  FrameTransport(transport.Error)
}

type ConnectionGuard

@external(erlang, "http_client_ffi", "new_connection_guard")
fn new_connection_guard() -> ConnectionGuard

@external(erlang, "http_client_ffi", "mark_connection_released")
fn mark_connection_released(guard: ConnectionGuard) -> Bool

@external(erlang, "http_client_ffi", "claim_connection_close")
fn claim_connection_close(guard: ConnectionGuard) -> Bool

type UploadProgress {
  UploadComplete(Sending)
  EarlyResponse(Response(body.Body))
}

type Sending {
  Sending(
    socket: transport.Socket,
    state: wire.State,
    reader: response_reader.State,
    stream_id: Int,
    received: Int,
    declared_length: Option(Int),
    config: Config,
    deadlines: OperationDeadlines,
  )
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
    checkout_http1: fn(_) { Ok(None) },
    attach: fn(_, _) { Ok(fn() { Nil }) },
    adopt: fn(socket, owner) {
      transport.transfer_owner(socket, owner)
      |> result.map_error(map_operation_error)
    },
    cancelled: fn() { False },
    http1_fallback: None,
    cleanup: fn() { Nil },
    reserve: fn(_) { Ok(tcp_reservation.unmanaged()) },
    replace: fn(_, _) { Ok(Nil) },
    trace: None,
    connect_trace: None,
    connect_observation: None,
    shared_resources: None,
    lifecycle_owner: None,
    source_worker: None,
    connection_guard: None,
    selected_protocol: None,
    exchange_started: False,
    request_phase_started: None,
    request_phase_finished: None,
    response_phase_started: None,
    response_phase_finished: None,
    release_phase_started: None,
    release_phase_finished: None,
  )
}

/// Attach the bounded diagnostic correlation for this request attempt.
pub fn with_trace(config: Config, trace: Option(client_trace.Trace)) -> Config {
  Config(..config, trace:)
}

/// Observe connection candidates independently from the selected exchange.
pub fn with_connect_trace(
  config: Config,
  trace: Option(client_trace.Trace),
) -> Config {
  Config(..config, connect_trace: trace)
}

/// Give only the selected TCP contender authority over attempt completion.
pub fn with_ready_trace(
  ready: Ready,
  trace: Option(client_trace.Trace),
) -> Ready {
  Ready(..ready, config: with_trace(ready.config, trace))
}

/// Share request-worker admission and the reusable client's lifetime.
pub fn with_supervision(
  config config: Config,
  resources resources: resource.Controller,
  lifecycle_owner lifecycle_owner: Pid,
) -> Config {
  Config(
    ..config,
    shared_resources: Some(resources),
    lifecycle_owner: Some(lifecycle_owner),
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

/// Acquire the shared connection budget before DNS/dial and atomically replace its transport during TLS upgrade without releasing the grant.
pub fn with_admission(
  config: Config,
  reserve: fn(String) -> Result(tcp_reservation.Reservation, error.Error),
  replace: fn(transport.Socket, transport.Socket) -> Result(Nil, error.Error),
) -> Config {
  Config(..config, reserve:, replace:)
}

/// Attach connection admission, ownership, and cancellation hooks.
pub fn with_lifecycle(
  config: Config,
  attach: fn(String, transport.Socket) -> Result(fn() -> Nil, error.Error),
  cancelled: fn() -> Bool,
) -> Config {
  Config(..config, attach:, cancelled:)
}

/// Transfer a prepared transport and commit its lifecycle ownership together.
/// This hook is internal to the reusable client and exposes no runtime handle.
@internal
pub fn with_owner_adoption(
  config: Config,
  adopt: fn(transport.Socket, Pid) -> Result(Nil, error.Error),
) -> Config {
  Config(..config, adopt:)
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

/// Continue HTTP/1.1 on the same authenticated socket when ALPN selects it.
/// The callback receives ownership of both the socket and its cleanup hook.
pub fn with_http1_fallback(
  config: Config,
  fallback: fn(transport.Socket, Request(body.Body), fn() -> Nil, Int) ->
    Result(Response(body.Body), error.Error),
) -> Config {
  Config(..config, http1_fallback: Some(fallback))
}

/// Include previously authenticated HTTP/1.1 sessions when preparing a TCP contender.
/// Checkout transfers ownership without consuming the request body.
pub fn with_http1_pool(
  config: Config,
  checkout: fn(String) -> Result(Option(transport.Socket), error.Error),
) -> Config {
  Config(..config, checkout_http1: checkout)
}

/// Negotiate and perform one HTTPS request without retaining a connection.
pub fn run(
  outgoing: Request(body.Body),
  config: Config,
) -> Result(Outcome, error.Error) {
  use ready <- result.try(prepare_connection(outgoing, config))
  run_ready(ready)
}

/// Resolve, connect, and authenticate without invoking the outgoing Body.
pub fn prepare_connection(
  outgoing: Request(body.Body),
  config: Config,
) -> Result(Ready, error.Error) {
  let deadline =
    transport.monotonic_millisecond() + config.total_timeout_milliseconds
  prepare_connection_before(outgoing, config, deadline)
}

/// Prepare against an existing absolute deadline owned by a protocol race.
/// No candidate may create a fresh total-time budget while another candidate or its cleanup is consuming the original exchange budget.
@internal
pub fn prepare_connection_before(
  outgoing: Request(body.Body),
  config: Config,
  deadline: Int,
) -> Result(Ready, error.Error) {
  use _ <- result.try(remaining_total_timeout(deadline))
  use _ <- result.try(require_active(config))
  use prepared <- result.try(prepare(outgoing))
  let config = Config(..config, origin: prepared.origin)
  use pooled <- result.try(case config.reuse_connections {
    True -> config.checkout(prepared.origin)
    False -> Ok(None)
  })
  case pooled {
    Some(#(socket, state, cleanup)) ->
      case config.attach(prepared.origin, socket) {
        Error(failure) ->
          close_with_config(socket, Config(..config, cleanup:), failure)
        Ok(cleanup) ->
          Ok(Ready(
            socket,
            h2_alpn,
            Some(state),
            prepared,
            Config(..config, cleanup:),
            deadline,
            new_connection_guard(),
          ))
      }
    None -> prepare_http1_or_connect(prepared, config, deadline)
  }
}

fn prepare_http1_or_connect(
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Ready, error.Error) {
  use pooled <- result.try(
    case config.reuse_connections, config.http1_fallback {
      True, Some(_) -> config.checkout_http1(prepared.origin)
      _, _ -> Ok(None)
    },
  )
  case pooled {
    None -> connect(prepared, config, deadline)
    Some(socket) ->
      case config.attach(prepared.origin, socket) {
        Error(failure) -> close_with_config(socket, config, failure)
        Ok(cleanup) ->
          Ok(Ready(
            socket,
            http1_alpn,
            None,
            prepared,
            Config(..config, cleanup:),
            deadline,
            new_connection_guard(),
          ))
      }
  }
}

/// Transfer a prepared socket before its connection contender exits.
pub fn transfer_ready(ready: Ready, owner: Pid) -> Result(Ready, error.Error) {
  case ready.config.adopt(ready.socket, owner) {
    Ok(Nil) -> Ok(ready)
    Error(failure) -> Error(failure)
  }
}

/// Replace a contender's temporary ownership guard after selecting it.
pub fn with_ready_cleanup(ready: Ready, cleanup: fn() -> Nil) -> Ready {
  Ready(..ready, config: Config(..ready.config, cleanup:))
}

/// Commit the selected connection to exactly one application exchange.
pub fn run_ready(ready: Ready) -> Result(Outcome, error.Error) {
  use <- require(
    mark_connection_released(ready.once),
    error.new(error.Cancelled),
  )
  let ready =
    Ready(
      ..ready,
      config: Config(
        ..ready.config,
        connection_guard: Some(new_connection_guard()),
        request_phase_started: Some(new_connection_guard()),
        request_phase_finished: Some(new_connection_guard()),
        response_phase_started: Some(new_connection_guard()),
        response_phase_finished: Some(new_connection_guard()),
        release_phase_started: Some(new_connection_guard()),
        release_phase_finished: Some(new_connection_guard()),
      ),
    )
  let active = {
    use _ <- result.try(require_active(ready.config))
    remaining_total_timeout(ready.deadline)
  }
  use _ <- result.try(case active {
    Ok(_) -> Ok(Nil)
    Error(failure) -> close_with_config(ready.socket, ready.config, failure)
  })
  case ready.reused {
    Some(state) ->
      run_reused(
        ready.socket,
        state,
        ready.prepared,
        ready.config,
        ready.deadline,
      )
    None ->
      run_negotiated(
        ready.socket,
        ready.selected,
        ready.prepared,
        ready.config,
        ready.deadline,
      )
  }
}

/// Release an unselected connection without consuming the request Body.
pub fn discard_ready(ready: Ready) -> Nil {
  case mark_connection_released(ready.once) {
    True -> discard_connection(ready.socket, ready.config)
    False -> Nil
  }
}

fn connect(
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Ready, error.Error) {
  let config = observe_connection(config)
  use #(socket, cancel) <- result.try(
    tcp_reservation.connect(config.reserve, prepared.origin, fn() {
      dial(prepared, config, deadline)
    })
    |> result.map_error(fn(failure) {
      publish_connection(config)
      failure
    }),
  )
  let config = Config(..config, cleanup: cancel)
  case config.attach(prepared.origin, socket) {
    Error(failure) ->
      close_with_config(socket, config, prefer_cancelled(config, failure))
    Ok(cleanup) -> {
      let config = Config(..config, cleanup: cleanup)
      case establish_proxy_tunnel(socket, prepared, config, deadline) {
        Error(failure) -> close_with_config(socket, config, failure)
        Ok(socket) -> negotiate(socket, prepared, config, deadline)
      }
    }
  }
}

fn dial(
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(transport.Socket, error.Error) {
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
  case config.connect_observation {
    None ->
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
    Some(#(diagnostics, _)) ->
      transport.connect_with_diagnostics(
        connect_host,
        connect_port,
        dns_timeout.milliseconds,
        connect_timeout.milliseconds,
        total_timeout,
        smallest(
          config.operation_timeout_milliseconds,
          connect_timeout.milliseconds,
        ),
        diagnostics,
      )
  }
  |> result.map_error(map_connect_error(
    _,
    dns_timeout.expiry,
    connect_timeout.expiry,
  ))
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
  let config = Config(..config, selected_protocol: Some(context.Http2))
  client_trace.protocol_selected(config.trace, context.Http2)
  run_h2_reused(socket, state, prepared, config, deadline)
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
) -> Result(Ready, error.Error) {
  let outcome = negotiate_transport(socket, prepared, config, deadline)
  publish_connection(config)
  outcome
}

fn negotiate_transport(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Ready, error.Error) {
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
        Ok(transport.TlsReady(secured, selected, _)) -> {
          use _ <- result.try(case config.replace(socket, secured) {
            Ok(Nil) -> Ok(Nil)
            Error(failure) -> close_with_config(secured, config, failure)
          })
          let socket = secured
          config.cleanup()
          case config.attach(config.origin, socket) {
            Error(failure) ->
              close_with(socket, prefer_cancelled(config, failure))
            Ok(cleanup) -> {
              let config = Config(..config, cleanup:)
              case selected == h2_alpn || selected == http1_alpn {
                False -> close_with_config(socket, config, error.new(error.Tls))
                True ->
                  Ok(Ready(
                    socket,
                    selected,
                    None,
                    prepared,
                    config,
                    deadline,
                    new_connection_guard(),
                  ))
              }
            }
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
    <<"h2":utf8>> -> {
      let config = Config(..config, selected_protocol: Some(context.Http2))
      client_trace.protocol_selected(config.trace, context.Http2)
      run_h2(socket, prepared, config, deadline)
    }
    <<"http/1.1":utf8>> -> {
      let config = Config(..config, selected_protocol: Some(context.Http1))
      client_trace.protocol_selected(config.trace, context.Http1)
      run_http1_fallback(socket, prepared, config, deadline)
    }
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
  case
    wire.new(connection.Client, connection_limits(), wire_limits(config))
    |> result.map_error(map_wire_error)
  {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(state) ->
      case
        wire.initial_bytes(state, local_settings())
        |> result.map_error(map_wire_error)
      {
        Error(failure) -> close_with_config(socket, config, failure)
        Ok(wire.Started(state, initial)) ->
          run_supervised(socket, state, initial, prepared, config, deadline)
      }
  }
}

fn run_h2_reused(
  socket: transport.Socket,
  state: wire.State,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  run_supervised(socket, state, <<>>, prepared, config, deadline)
}

fn run_supervised(
  socket: transport.Socket,
  state: wire.State,
  initial: BitArray,
  prepared: Prepared,
  config: Config,
  deadline: Int,
) -> Result(Outcome, error.Error) {
  let deadlines =
    OperationDeadlines(
      total: deadline,
      operation: transport.monotonic_millisecond()
        + config.operation_timeout_milliseconds,
    )
  case start_source(socket, prepared, config, deadlines) {
    Error(failure) -> close_with_config(socket, config, failure)
    Ok(active) -> {
      begin_exchange_phases(active, context.Http2)
      let outcome = {
        use _ <- result.try(send_bytes(socket, initial, deadlines))
        run_h2_stream(socket, state, prepared, active, deadlines)
      }
      case outcome {
        Ok(incoming) -> Ok(incoming)
        Error(failure) -> close_with_config(socket, active, failure)
      }
    }
  }
}

fn start_source(
  socket: transport.Socket,
  prepared: Prepared,
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(Config, error.Error) {
  use timeout <- result.try(operation_timeout(
    deadlines,
    config.operation_timeout_milliseconds,
  ))
  client_trace.phase_started(config.trace, diagnostics.ResourceAdmission)
  let active = Config(..config, exchange_started: True)
  let started =
    upload.start(
      source: prepared.outgoing.body,
      maximum_chunk: config.maximum_stream_buffer_bytes,
      deadline: transport.monotonic_millisecond() + timeout.milliseconds,
      expiry: timeout.expiry,
      total_deadline: deadlines.total,
      resources: config.shared_resources,
      lifecycle_owner: config.lifecycle_owner,
      abandon: fn(failure) {
        begin_exchange_phases(active, context.Http2)
        finish_exchange_phases(active, context.Http2, Error(failure))
        begin_release_phase(active)
        client_trace.finished(active.trace, Some(context.Http2), Error(failure))
        case claim_close(active) {
          True -> {
            let _closed = transport.close(socket)
            active.cleanup()
          }
          False -> Nil
        }
      },
      released: fn(outcome) {
        finish_release_phase(active, outcome)
        client_trace.released(active.trace, Some(context.Http2), outcome)
      },
    )
  client_trace.phase_finished(
    config.trace,
    diagnostics.ResourceAdmission,
    result.map(started, fn(_) { Nil }),
  )
  case started {
    Ok(worker) -> Ok(Config(..active, source_worker: Some(worker)))
    Error(failure) -> {
      body.cancel(prepared.outgoing.body)
      Error(failure)
    }
  }
}

fn run_h2_stream(
  socket: transport.Socket,
  state: wire.State,
  prepared: Prepared,
  config: Config,
  deadlines: OperationDeadlines,
) -> Result(Outcome, error.Error) {
  // The source is non-replayable and potentially blocked.
  // Commit only headers here; FIN and trailers follow the source's actual terminal event.
  use written <- result.try(
    wire.send_request_headers(state, prepared.outgoing, end_stream: False)
    |> result.map_error(map_wire_error),
  )
  let wire.HeadersWritten(state, stream_id, headers) = written
  use _ <- result.try(send_frames(socket, headers, deadlines))
  use reader <- result.try(
    response_reader.new(
      stream_id: stream_id,
      maximum_body_bytes: config.maximum_body_bytes,
      maximum_informational: maximum_informational_responses,
    )
    |> result.map_error(map_response_reader_error),
  )
  next_source_chunk(Sending(
    socket:,
    state:,
    reader:,
    stream_id:,
    received: 0,
    declared_length: prepared.declared_length,
    config:,
    deadlines:,
  ))
  |> result.map(Http2Response)
}

fn next_source_chunk(
  sending: Sending,
) -> Result(Response(body.Body), error.Error) {
  use _ <- result.try(require_active(sending.config))
  case sending.config.source_worker {
    None -> Error(error.new(error.Service))
    Some(worker) -> {
      upload.request_next(worker)
      await_source_chunk(sending, worker)
    }
  }
}

fn await_source_chunk(
  sending: Sending,
  worker: upload.Upload,
) -> Result(Response(body.Body), error.Error) {
  use timeout <- result.try(operation_timeout(
    sending.deadlines,
    sending.config.idle_timeout_milliseconds,
  ))
  case
    transport.read_or_message(
      sending.socket,
      sending.config.maximum_stream_buffer_bytes,
      timeout.milliseconds,
      upload.events(worker),
    )
  {
    Error(failure) ->
      Error(prefer_cancelled(
        sending.config,
        map_read_error(failure, timeout.expiry),
      ))
    Ok(transport.ReadSocket(transport.ReadEnd(_))) -> Error(protocol_error())
    Ok(transport.ReadSocket(transport.ReadData(bytes, socket))) -> {
      use progress <- result.try(accept_upload_input(
        Sending(..sending, socket:),
        bytes,
      ))
      case progress {
        EarlyResponse(incoming) -> Ok(incoming)
        UploadComplete(sending) -> await_source_chunk(sending, worker)
      }
    }
    Ok(transport.ReadMessage(event, socket)) ->
      accept_source_chunk(Sending(..sending, socket:), event)
  }
}

fn accept_source_chunk(
  sending: Sending,
  event: upload.Event,
) -> Result(Response(body.Body), error.Error) {
  case event {
    upload.Failed(failure) -> Error(failure)
    upload.SourceDisposed -> Error(error.new(error.Service))
    upload.Chunk(bytes) -> {
      let received = sending.received + bit_array.byte_size(bytes)
      use <- require(
        received <= sending.config.maximum_body_bytes,
        error.new(error.Body(error.TooLarge(sending.config.maximum_body_bytes))),
      )
      use <- require(
        case sending.declared_length {
          Some(length) -> received <= length
          None -> True
        },
        protocol_error(),
      )
      use progress <- result.try(send_request_chunk(
        Sending(..sending, received:),
        bytes,
        False,
      ))
      case progress {
        EarlyResponse(incoming) -> Ok(incoming)
        UploadComplete(sending) -> next_source_chunk(sending)
      }
    }
    upload.End(trailers) -> finish_upload(sending, trailers)
  }
}

fn finish_upload(
  sending: Sending,
  trailers: body.Headers,
) -> Result(Response(body.Body), error.Error) {
  use _ <- result.try(require_matching_length(
    sending.declared_length,
    sending.received,
  ))
  use _ <- result.try(
    message.trailer_headers(trailers)
    |> result.map_error(fn(_) { protocol_error() }),
  )
  use progress <- result.try(case trailers {
    [] -> send_request_chunk(sending, <<>>, True)
    _ -> {
      use written <- result.try(
        wire.send_trailers(sending.state, sending.stream_id, trailers)
        |> result.map_error(map_wire_error),
      )
      let wire.HeadersWritten(state, _, frames) = written
      use _ <- result.try(send_frames(sending.socket, frames, sending.deadlines))
      Ok(UploadComplete(Sending(..sending, state:)))
    }
  })
  case progress {
    EarlyResponse(incoming) -> Ok(incoming)
    UploadComplete(sending) -> {
      use _ <- result.try(finish_source(sending.config, Ok(Nil)))
      receive_response_headers(
        sending.socket,
        sending.state,
        sending.reader,
        sending.stream_id,
        sending.config,
        sending.deadlines,
      )
    }
  }
}

fn send_request_chunk(
  sending: Sending,
  bytes: BitArray,
  end_stream: Bool,
) -> Result(UploadProgress, error.Error) {
  use _ <- result.try(require_active(sending.config))
  use progress <- result.try(
    wire.send_data(
      sending.state,
      stream_id: sending.stream_id,
      bytes:,
      end_stream:,
    )
    |> result.map_error(map_wire_error),
  )
  case progress {
    wire.DataBlocked(state) ->
      await_upload_credit(Sending(..sending, state:), bytes, end_stream)
    wire.DataWritten(state, frames, remaining, end_stream_sent) -> {
      use _ <- result.try(send_frames(sending.socket, frames, sending.deadlines))
      let sending = Sending(..sending, state:)
      case
        bit_array.byte_size(remaining) == 0 && end_stream_sent == end_stream
      {
        True -> Ok(UploadComplete(sending))
        False -> await_upload_credit(sending, remaining, end_stream)
      }
    }
  }
}

fn await_upload_credit(
  sending: Sending,
  remaining: BitArray,
  end_stream: Bool,
) -> Result(UploadProgress, error.Error) {
  use _ <- result.try(require_active(sending.config))
  use timeout <- result.try(operation_timeout(
    sending.deadlines,
    sending.config.idle_timeout_milliseconds,
  ))
  case
    transport.read(
      sending.socket,
      sending.config.maximum_stream_buffer_bytes,
      timeout.milliseconds,
    )
  {
    Error(failure) ->
      Error(prefer_cancelled(
        sending.config,
        map_read_error(failure, timeout.expiry),
      ))
    Ok(transport.ReadEnd(_)) -> Error(protocol_error())
    Ok(transport.ReadData(bytes, socket)) -> {
      use progress <- result.try(accept_upload_input(
        Sending(..sending, socket:),
        bytes,
      ))
      case progress {
        EarlyResponse(incoming) -> Ok(EarlyResponse(incoming))
        UploadComplete(sending) ->
          send_request_chunk(sending, remaining, end_stream)
      }
    }
  }
}

fn accept_upload_input(
  sending: Sending,
  bytes: BitArray,
) -> Result(UploadProgress, error.Error) {
  use fed <- result.try(
    wire.feed(sending.state, bytes)
    |> result.map_error(map_wire_error),
  )
  let wire.Fed(state, actions) = fed
  use automatic <- result.try(
    wire.automatic_writes(actions, 16_384)
    |> result.map_error(map_wire_error),
  )
  use _ <- result.try(send_frames(sending.socket, automatic, sending.deadlines))
  use progress <- result.try(
    response_reader.accept(sending.reader, actions)
    |> result.map_error(map_response_reader_error),
  )
  let response_reader.Progress(reader, head, chunks, completion) = progress
  case head {
    None -> Ok(UploadComplete(Sending(..sending, state:, reader:)))
    Some(head) -> {
      // A final response can arrive before source EOF.
      // Join its reader before disposing it, and never return this unfinished request to the pool.
      use _ <- result.try(finish_source(
        sending.config,
        Error(error.new(error.Cancelled)),
      ))
      streaming_response(
        sending.socket,
        state,
        reader,
        sending.stream_id,
        head,
        chunks,
        completion,
        Config(..sending.config, reuse_connections: False),
        sending.deadlines,
      )
      |> result.map(EarlyResponse)
    }
  }
}

fn finish_source(
  config: Config,
  outcome: Result(Nil, error.Error),
) -> Result(Nil, error.Error) {
  let finished = case config.source_worker {
    None -> Ok(Nil)
    Some(worker) -> upload.finish_source(upload: worker, outcome:)
  }
  let phase_outcome = case finished {
    Error(failure) -> Error(failure)
    Ok(Nil) -> outcome
  }
  finish_request_phase(config, context.Http2, phase_outcome)
  finished
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
  client_trace.headers(config.trace, context.Http2, incoming.status)
  // RFC 8336 removes a 421 response's request origin from this connection's Origin Set.
  // The pool is intentionally keyed to one authenticated origin,
  // so evicting the whole idle connection is the conservative equivalent and cannot accidentally retain other authority learned from peer input.
  let config = case incoming.status == 421 {
    True -> Config(..config, reuse_connections: False)
    False -> config
  }
  let connection_guard = case config.connection_guard {
    Some(guard) -> guard
    None -> new_connection_guard()
  }
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
      case
        write_frames(state.socket, frames, state.deadlines),
        state.completion
      {
        Ok(Nil), _ -> Ok(ResponseBodyState(..state, wire: wire_state))
        Error(FrameTransport(transport.Closed)), Some(_) -> {
          use _ <- result.try(
            require_active(state.config) |> close_response_body_on_error(state),
          )
          let config = Config(..state.config, reuse_connections: False)
          finish_connection(
            state.socket,
            wire_state,
            config,
            state.connection_guard,
          )
          Ok(ResponseBodyState(..state, wire: wire_state, config:))
        }
        Error(failure), _ ->
          response_body_failure(state, map_frame_write_failure(failure))
      }
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
  let failure = prefer_cancelled(state.config, failure)
  finish_exchange_phases(state.config, context.Http2, Error(failure))
  client_trace.finished(state.config.trace, Some(context.Http2), Error(failure))
  discard_response_connection(
    state.socket,
    state.config,
    state.connection_guard,
  )
  Error(failure)
}

fn send_frames(
  socket: transport.Socket,
  frames: List(BitArray),
  deadlines: OperationDeadlines,
) -> Result(Nil, error.Error) {
  write_frames(socket, frames, deadlines)
  |> result.map_error(map_frame_write_failure)
}

fn write_frames(
  socket: transport.Socket,
  frames: List(BitArray),
  deadlines: OperationDeadlines,
) -> Result(Nil, FrameWriteFailure) {
  case frames {
    [] -> Ok(Nil)
    [bytes, ..rest] -> {
      use _ <- result.try(
        ensure_operation_deadline(deadlines) |> result.map_error(FrameDeadline),
      )
      use _ <- result.try(
        transport.send(socket, bytes) |> result.map_error(FrameTransport),
      )
      write_frames(socket, rest, deadlines)
    }
  }
}

fn map_frame_write_failure(failure: FrameWriteFailure) -> error.Error {
  case failure {
    FrameDeadline(failure) -> failure
    FrameTransport(failure) -> map_operation_error(failure)
  }
}

fn send_bytes(
  socket: transport.Socket,
  bytes: BitArray,
  deadlines: OperationDeadlines,
) -> Result(Nil, error.Error) {
  send_frames(socket, [bytes], deadlines)
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
  let failure = prefer_cancelled(config, failure)
  finish_exchange_phases(config, context.Http2, Error(failure))
  case config.source_worker {
    None -> Nil
    Some(worker) -> upload.fail_source(upload: worker, failure:)
  }
  publish_connection(config)
  client_trace.finished(config.trace, config.selected_protocol, Error(failure))
  discard_connection(socket, config)
  Error(failure)
}

fn discard_connection(socket: transport.Socket, config: Config) -> Nil {
  case claim_close(config) {
    True -> close_owned_connection(socket, config)
    False ->
      case config.source_worker {
        None -> Nil
        Some(_) -> release_source(config, Ok(Nil))
      }
  }
}

fn claim_close(config: Config) -> Bool {
  case config.connection_guard {
    None -> True
    Some(guard) -> claim_connection_close(guard)
  }
}

fn close_owned_connection(socket: transport.Socket, config: Config) -> Nil {
  let close_result =
    transport.close(socket) |> result.map_error(map_operation_error)
  config.cleanup()
  release_source(config, close_result)
}

fn release_source(config: Config, outcome: Result(Nil, error.Error)) -> Nil {
  begin_release_phase(config)
  case config.source_worker {
    None -> {
      finish_release_phase(config, outcome)
      client_trace.released(config.trace, config.selected_protocol, outcome)
    }
    Some(worker) -> {
      // The reaper owns the lease and publishes release after actual DOWN,
      // including when this caller's bounded acknowledgement wait expires.
      let _awaited = upload.release(upload: worker, outcome:)
      Nil
    }
  }
}

fn finish_connection(
  socket: transport.Socket,
  state: wire.State,
  config: Config,
  guard: ConnectionGuard,
) -> Nil {
  finish_exchange_phases(config, context.Http2, Ok(Nil))
  client_trace.finished(config.trace, Some(context.Http2), Ok(Nil))
  case mark_connection_released(guard) {
    False -> Nil
    True ->
      case
        config.reuse_connections
        && !connection.draining(wire.connection_state(state))
      {
        True ->
          case config.checkin(config.origin, socket, state, config.cleanup) {
            True -> release_source(config, Ok(Nil))
            False -> {
              config.cleanup()
              release_source(config, Ok(Nil))
            }
          }
        False -> close_owned_connection(socket, config)
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
    True -> {
      let failure = error.new(error.Cancelled)
      finish_exchange_phases(config, context.Http2, Error(failure))
      client_trace.finished(config.trace, Some(context.Http2), Error(failure))
      close_owned_connection(socket, config)
    }
  }
}

fn begin_exchange_phases(config: Config, protocol: context.Protocol) -> Nil {
  case config.exchange_started {
    False -> Nil
    True -> {
      begin_phase_once(
        config.trace,
        config.request_phase_started,
        diagnostics.RequestTransmission(protocol),
      )
      begin_phase_once(
        config.trace,
        config.response_phase_started,
        diagnostics.ResponseReception(protocol),
      )
    }
  }
}

fn finish_exchange_phases(
  config: Config,
  protocol: context.Protocol,
  outcome: Result(Nil, error.Error),
) -> Nil {
  case config.exchange_started {
    False -> Nil
    True -> {
      finish_request_phase(config, protocol, outcome)
      finish_phase_once(
        config.trace,
        config.response_phase_finished,
        diagnostics.ResponseReception(protocol),
        outcome,
      )
    }
  }
}

fn finish_request_phase(
  config: Config,
  protocol: context.Protocol,
  outcome: Result(Nil, error.Error),
) -> Nil {
  finish_phase_once(
    config.trace,
    config.request_phase_finished,
    diagnostics.RequestTransmission(protocol),
    outcome,
  )
}

fn begin_release_phase(config: Config) -> Nil {
  begin_phase_once(
    config.trace,
    config.release_phase_started,
    diagnostics.ResourceRelease,
  )
}

fn finish_release_phase(
  config: Config,
  outcome: Result(Nil, error.Error),
) -> Nil {
  finish_phase_once(
    config.trace,
    config.release_phase_finished,
    diagnostics.ResourceRelease,
    outcome,
  )
}

fn begin_phase_once(
  trace: Option(client_trace.Trace),
  guard: Option(ConnectionGuard),
  phase: diagnostics.ClientPhase,
) -> Nil {
  case guard {
    None -> Nil
    Some(guard) ->
      case mark_connection_released(guard) {
        True -> client_trace.phase_started(trace, phase)
        False -> Nil
      }
  }
}

fn finish_phase_once(
  trace: Option(client_trace.Trace),
  guard: Option(ConnectionGuard),
  phase: diagnostics.ClientPhase,
  outcome: Result(Nil, error.Error),
) -> Nil {
  case guard {
    None -> Nil
    Some(guard) ->
      case mark_connection_released(guard) {
        True -> client_trace.phase_finished(trace, phase, outcome)
        False -> Nil
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

fn require_active(config: Config) -> Result(Nil, error.Error) {
  case config.cancelled() {
    True -> Error(error.new(error.Cancelled))
    False -> Ok(Nil)
  }
}

fn prefer_cancelled(config: Config, failure: error.Error) -> error.Error {
  case config.cancelled() {
    True -> error.new(error.Cancelled)
    False ->
      case config.source_worker {
        None -> failure
        Some(worker) ->
          case upload.failure(worker) {
            None -> failure
            Some(observed) -> observed
          }
      }
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

fn observe_connection(config: Config) -> Config {
  case config.connect_trace {
    None -> config
    Some(_) ->
      Config(
        ..config,
        connect_observation: Some(#(
          transport.diagnostics_new(),
          new_connection_guard(),
        )),
      )
  }
}

fn publish_connection(config: Config) -> Nil {
  case config.connect_observation {
    None -> Nil
    Some(#(diagnostics, once)) ->
      case mark_connection_released(once) {
        False -> Nil
        True ->
          client_trace.tcp_snapshot(
            config.connect_trace,
            transport.diagnostics_snapshot(diagnostics),
          )
      }
  }
}
