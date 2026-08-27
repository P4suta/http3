//// Typed normalization around the repository-owned HTTP/3 server.

import gleam/bool
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic
import http3/config
import http3/failure as runtime_failure
import http3/internal/native/server as native_server

pub type ListenerHandle =
  native_server.Listener

pub type RequestHandle =
  native_server.Request

pub type PushHandle =
  native_server.Push

pub type ReplayGuard =
  native_server.ReplayGuard

pub opaque type OperationalKey {
  OperationalKey(native: native_server.OperationalKey)
}

pub opaque type KeyRing {
  KeyRing(native: native_server.KeyRing)
}

pub opaque type OperationalKeys {
  OperationalKeys(
    ticket: KeyRing,
    address_token: KeyRing,
    stateless_reset: KeyRing,
  )
}

pub type RawError =
  #(Int, Int, String)

pub type Incoming =
  #(
    RequestHandle,
    String,
    String,
    Option(String),
    String,
    String,
    List(#(String, String)),
  )

pub type RawEvent =
  #(Int, List(#(String, String)), BitArray)

pub type Failure {
  RuntimeFailure(runtime_failure.Failure)
  RequestBodyTooLarge(Int)
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentAccept
  ConcurrentDrain
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  PushCancelled
  InvalidContentLength
}

pub fn valid_certificate(certificate: BitArray) -> Bool {
  native_server.is_valid_certificate(certificate)
}

pub fn valid_private_key(private_key: BitArray) -> Bool {
  native_server.is_valid_private_key(private_key)
}

pub fn valid_server_name(server_name: String) -> Bool {
  native_server.is_valid_server_name(server_name)
}

pub fn operational_key(bytes: BitArray) -> Result(OperationalKey, Nil) {
  native_server.operational_key(bytes)
  |> result.map(OperationalKey)
  |> result.replace_error(Nil)
}

pub fn key_ring(key: OperationalKey) -> KeyRing {
  KeyRing(native_server.key_ring(key.native))
}

pub fn rotate_key_ring(
  ring ring: KeyRing,
  key key: OperationalKey,
) -> Result(KeyRing, Nil) {
  native_server.rotate_key_ring(ring.native, key.native)
  |> result.map(KeyRing)
  |> result.replace_error(Nil)
}

pub fn operational_keys(
  ticket ticket: KeyRing,
  address_token address_token: KeyRing,
  stateless_reset stateless_reset: KeyRing,
) -> Result(OperationalKeys, Nil) {
  use <- bool.guard(
    when: !native_server.operational_key_rings_are_distinct(
      ticket.native,
      address_token.native,
      stateless_reset.native,
    ),
    return: Error(Nil),
  )
  Ok(OperationalKeys(ticket, address_token, stateless_reset))
}

pub fn replay_guard(
  timeout_milliseconds: Int,
  check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(ReplayGuard, Nil) {
  native_server.replay_guard(timeout_milliseconds, check)
  |> result.replace_error(Nil)
}

pub fn start(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  alternative_certificates alternative_certificates: List(
    #(String, BitArray, BitArray),
  ),
  port port: Int,
  bind_address bind_address: Option(BitArray),
  timeout_milliseconds timeout_milliseconds: Int,
  drain_timeout_milliseconds drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds idle_timeout_milliseconds: Int,
  request_body_limit request_body_limit: Int,
  response_body_limit response_body_limit: Int,
  stream_buffer_limit stream_buffer_limit: Int,
  connection_limit connection_limit: Int,
  handshake_limit handshake_limit: Int,
  queue_limit queue_limit: Int,
  telemetry_limit telemetry_limit: Int,
  bidirectional_stream_limit bidirectional_stream_limit: Int,
  unidirectional_stream_limit unidirectional_stream_limit: Int,
  frame_limit frame_limit: Int,
  datagram_limit datagram_limit: Int,
  qpack_table_limit qpack_table_limit: Int,
  qpack_blocked_stream_limit qpack_blocked_stream_limit: Int,
  accept_waiter_limit accept_waiter_limit: Int,
  http_datagrams http_datagrams: Bool,
  keepalive_milliseconds keepalive_milliseconds: Int,
  address_family address_family: config.AddressFamily,
  qlog_directory qlog_directory: String,
  allow_zero_rtt allow_zero_rtt: Bool,
  replay_guard replay_guard: Option(ReplayGuard),
  operational_keys operational_keys: Option(OperationalKeys),
) -> Result(ListenerHandle, Failure) {
  use configuration <- result.try(
    native_server.new(certificate, private_key)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(configure_certificates(
    configuration,
    alternative_certificates,
  ))
  use configuration <- result.try(
    native_server.with_port(configuration, port)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(case bind_address {
    None -> Ok(configuration)
    Some(address) ->
      native_server.with_bind_address(configuration, address)
      |> result.map_error(map_configuration_error)
  })
  use configuration <- result.try(
    native_server.with_timeout(configuration, timeout_milliseconds)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_drain_timeout(configuration, drain_timeout_milliseconds)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_idle_timeout(configuration, idle_timeout_milliseconds)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_request_body_limit(configuration, request_body_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_response_body_limit(configuration, response_body_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_stream_buffer_limit(configuration, stream_buffer_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_connection_limit(configuration, connection_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_handshake_limit(configuration, handshake_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_queue_limit(configuration, queue_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_telemetry_limit(configuration, telemetry_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_bidirectional_stream_limit(
      configuration,
      bidirectional_stream_limit,
    )
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_unidirectional_stream_limit(
      configuration,
      unidirectional_stream_limit,
    )
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_frame_limit(configuration, frame_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_datagram_limit(configuration, datagram_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_qpack_table_limit(configuration, qpack_table_limit)
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_qpack_blocked_stream_limit(
      configuration,
      qpack_blocked_stream_limit,
    )
    |> result.map_error(map_configuration_error),
  )
  use configuration <- result.try(
    native_server.with_accept_waiter_limit(configuration, accept_waiter_limit)
    |> result.map_error(map_configuration_error),
  )
  let configuration = case http_datagrams {
    True -> native_server.with_http_datagrams(configuration)
    False -> configuration
  }
  use configuration <- result.try(case keepalive_milliseconds {
    0 -> Ok(configuration)
    interval ->
      native_server.with_keepalive(configuration, interval)
      |> result.map_error(map_configuration_error)
  })
  let configuration =
    native_server.with_address_family(configuration, case address_family {
      config.Ipv4 -> gleam_quic.Ipv4
      config.Ipv6 -> gleam_quic.Ipv6
      config.DualStack -> gleam_quic.DualStack
    })
  let configuration = case qlog_directory {
    "" -> Ok(configuration)
    _ -> native_server.with_qlog(configuration, qlog_directory)
  }
  use configuration <- result.try(
    configuration |> result.map_error(map_configuration_error),
  )
  let configuration = case replay_guard, allow_zero_rtt {
    Some(guard), _ -> native_server.with_external_zero_rtt(configuration, guard)
    None, True -> native_server.with_single_node_zero_rtt(configuration)
    None, False -> configuration
  }
  use configuration <- result.try(configure_operational_keys(
    configuration,
    operational_keys,
  ))
  native_server.start(configuration) |> result.map_error(map_native_error)
}

/// Replace the complete prevalidated certificate set for new handshakes.
pub fn reload_certificates(
  listener listener: ListenerHandle,
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  alternative_certificates alternative_certificates: List(
    #(String, BitArray, BitArray),
  ),
) -> Result(Nil, Failure) {
  use replacement <- result.try(
    native_server.new(certificate, private_key)
    |> result.map_error(map_configuration_error),
  )
  use replacement <- result.try(configure_certificates(
    replacement,
    alternative_certificates,
  ))
  native_server.reload_certificates(listener, replacement)
  |> result.map_error(map_native_error)
}

/// Atomically replace current/previous server operational keys.
pub fn reload_operational_keys(
  listener listener: ListenerHandle,
  keys keys: OperationalKeys,
) -> Result(Nil, Failure) {
  let OperationalKeys(ticket, address_token, stateless_reset) = keys
  native_server.reload_operational_key_rings(
    listener,
    ticket.native,
    address_token.native,
    stateless_reset.native,
  )
  |> result.map_error(map_native_error)
}

fn configure_operational_keys(
  server: native_server.Server,
  keys: Option(OperationalKeys),
) -> Result(native_server.Server, Failure) {
  case keys {
    None -> Ok(server)
    Some(OperationalKeys(ticket, address_token, stateless_reset)) ->
      native_server.with_operational_key_rings(
        server,
        ticket.native,
        address_token.native,
        stateless_reset.native,
      )
      |> result.map_error(map_configuration_error)
  }
}

fn map_configuration_error(
  _error: native_server.ConfigurationError,
) -> Failure {
  RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
}

fn configure_certificates(
  server: native_server.Server,
  certificates: List(#(String, BitArray, BitArray)),
) -> Result(native_server.Server, Failure) {
  case certificates {
    [] -> Ok(server)
    [#(server_name, certificate, private_key), ..rest] -> {
      use server <- result.try(
        native_server.with_certificate(
          server,
          server_name,
          certificate,
          private_key,
        )
        |> result.map_error(map_configuration_error),
      )
      configure_certificates(server, rest)
    }
  }
}

pub fn port(listener: ListenerHandle) -> Result(Int, Failure) {
  native_server.port(listener) |> result.map_error(map_native_error)
}

pub fn accept(listener: ListenerHandle) -> Result(Incoming, Failure) {
  case native_server.accept(listener) {
    Ok(native_server.Incoming(
      request,
      method,
      path,
      protocol,
      scheme,
      authority,
      headers,
    )) -> Ok(#(request, method, path, protocol, scheme, authority, headers))
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn peer_endpoint(
  request: RequestHandle,
) -> Result(#(BitArray, Int), Failure) {
  native_server.peer_endpoint(request) |> result.map_error(map_native_error)
}

pub fn next_event(request: RequestHandle) -> Result(RawEvent, Failure) {
  case native_server.next_event(request) {
    Ok(native_server.Data(bytes)) -> Ok(#(1, [], bytes))
    Ok(native_server.Trailers(headers)) -> Ok(#(2, headers, <<>>))
    Ok(native_server.End) -> Ok(#(3, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn respond(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Nil, Failure) {
  native_server.respond(request, status, headers, body)
  |> result.map_error(map_native_error)
}

pub fn send_response(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  declared_content_length declared_content_length: Int,
) -> Result(Nil, Failure) {
  let declared = case declared_content_length {
    -1 -> None
    value -> Some(value)
  }
  native_server.send_response(request, status, headers, declared)
  |> result.map_error(map_native_error)
}

pub fn send_informational(
  request request: RequestHandle,
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(Nil, Failure) {
  native_server.send_informational(request, status, headers)
  |> result.map_error(map_native_error)
}

pub fn send_chunk(
  request request: RequestHandle,
  chunk chunk: BitArray,
) -> Result(Nil, Failure) {
  native_server.send_chunk(request, chunk) |> result.map_error(map_native_error)
}

pub fn finish_response(request: RequestHandle) -> Result(Nil, Failure) {
  native_server.finish_response(request) |> result.map_error(map_native_error)
}

pub fn send_trailers(
  request request: RequestHandle,
  headers headers: List(#(String, String)),
) -> Result(Nil, Failure) {
  native_server.send_trailers(request, headers)
  |> result.map_error(map_native_error)
}

pub fn promise_push(
  request request: RequestHandle,
  path path: String,
  headers headers: List(#(String, String)),
) -> Result(PushHandle, Failure) {
  native_server.promise_push(request, path, headers)
  |> result.map_error(map_native_error)
}

pub fn send_push_response(
  push push: PushHandle,
  status status: Int,
  headers headers: List(#(String, String)),
  declared_content_length declared_content_length: Int,
) -> Result(Nil, Failure) {
  let declared = case declared_content_length {
    -1 -> None
    value -> Some(value)
  }
  native_server.send_push_response(push, status, headers, declared)
  |> result.map_error(map_native_error)
}

pub fn send_push_chunk(
  push push: PushHandle,
  chunk chunk: BitArray,
) -> Result(Nil, Failure) {
  native_server.send_push_chunk(push, chunk)
  |> result.map_error(map_native_error)
}

pub fn finish_push(push: PushHandle) -> Result(Nil, Failure) {
  native_server.finish_push(push) |> result.map_error(map_native_error)
}

pub fn send_push_trailers(
  push push: PushHandle,
  headers headers: List(#(String, String)),
) -> Result(Nil, Failure) {
  native_server.send_push_trailers(push, headers)
  |> result.map_error(map_native_error)
}

pub fn stop(listener: ListenerHandle) -> Result(Int, Failure) {
  case native_server.stop(listener) {
    Ok(native_server.Stopped) -> Ok(1)
    Ok(native_server.AlreadyStopped) -> Ok(2)
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn graceful_stop(listener: ListenerHandle) -> Result(Int, Failure) {
  case native_server.graceful_stop(listener) {
    Ok(native_server.Drained) -> Ok(1)
    Ok(native_server.Forced) -> Ok(2)
    Ok(native_server.AlreadyDrained) -> Ok(3)
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn normalize_error(error: RawError) -> Failure {
  case error {
    #(1, _, _) ->
      RuntimeFailure(runtime_failure.Socket(runtime_failure.BindSocket))
    #(2, _, _) ->
      RuntimeFailure(runtime_failure.Timeout(runtime_failure.Operation))
    #(3, _, _) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Local, None))
    #(4, _, _) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, None))
    #(5, code, _) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, Some(code)))
    #(6, code, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Peer, Some(code)))
    #(7, limit, _) -> RequestBodyTooLarge(limit)
    #(8, limit, _) -> ResponseBodyTooLarge(limit)
    #(9, limit, _) -> ConsumerTooSlow(limit)
    #(10, _, _) -> ConcurrentAccept
    #(11, _, _) -> ConcurrentReceive
    #(12, _, _) -> ResponseAlreadyStarted
    #(13, _, _) -> ResponseNotStarted
    #(14, _, _) -> ResponseAlreadyFinished
    #(15, _, _) -> InvalidContentLength
    #(_, _, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}

fn map_native_error(error: native_server.Error) -> Failure {
  case error {
    native_server.StartFailed ->
      RuntimeFailure(runtime_failure.Socket(runtime_failure.BindSocket))
    native_server.Timeout ->
      RuntimeFailure(runtime_failure.Timeout(runtime_failure.Operation))
    native_server.ListenerClosed ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Local, None))
    native_server.ConnectionClosed ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, None))
    native_server.StreamReset(code) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, Some(code)))
    native_server.Failure(failure) -> RuntimeFailure(failure)
    native_server.RequestBodyTooLarge(limit) -> RequestBodyTooLarge(limit)
    native_server.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
    native_server.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    native_server.ConcurrentAccept -> ConcurrentAccept
    native_server.ConcurrentDrain -> ConcurrentDrain
    native_server.ConcurrentReceive -> ConcurrentReceive
    native_server.ResponseAlreadyStarted -> ResponseAlreadyStarted
    native_server.ResponseNotStarted -> ResponseNotStarted
    native_server.ResponseAlreadyFinished -> ResponseAlreadyFinished
    native_server.PushCancelled -> PushCancelled
    native_server.InvalidContentLength -> InvalidContentLength
    native_server.DatagramTooLarge(maximum) ->
      RuntimeFailure(runtime_failure.Limit(runtime_failure.Datagram, maximum))
    native_server.DatagramBufferExceeded(maximum) ->
      RuntimeFailure(runtime_failure.Limit(runtime_failure.Buffer, maximum))
    native_server.ConcurrentDatagramReceive ->
      RuntimeFailure(runtime_failure.Overload(runtime_failure.AcceptWaiters))
    native_server.CongestionLimited ->
      RuntimeFailure(runtime_failure.Overload(runtime_failure.Queue))
    native_server.InvalidInput
    | native_server.InvalidHeaderEncoding
    | native_server.DatagramsNotNegotiated
    | native_server.DatagramNotAssociated
    | native_server.StreamFinished ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
  }
}
