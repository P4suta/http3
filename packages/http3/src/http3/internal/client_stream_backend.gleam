//// Typed boundary around the repository-owned reusable HTTP/3 client.

import gleam/option.{type Option, None, Some}
import gleam/result
import http3/address
import http3/config
import http3/failure as runtime_failure
import http3/internal/client_backend
import http3/internal/client_request.{
  type PreparedStreamingRequest, PreparedStreamingRequest,
}
import http3/internal/native/client as native_client
import http3/internal/qlog_admission
import quic_core
import quic_core/diagnostics

/// Opaque native connection identity.
pub type ConnectionHandle =
  native_client.Connection

/// Opaque native request-stream identity.
pub type StreamHandle =
  native_client.Stream

/// Opaque native server-push identity.
pub type PushHandle =
  native_client.Push

/// Opaque backend-owned TLS resumption material.
pub type ResumptionTicketHandle =
  native_client.ResumptionTicket

/// Primitive event data consumed by the stable parent-package adapter.
pub type RawEvent =
  #(Int, Int, List(#(String, String)), BitArray)

/// Establish one reusable, securely verified HTTP/3 connection.
pub fn connect(
  host host: String,
  port port: Int,
  connect_address connect_address: Option(address.Address),
  connect_port connect_port: Int,
  ca_certificates ca_certificates: List(BitArray),
  address_family address_family: config.AddressFamily,
  dns_timeout_milliseconds dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds connect_timeout_milliseconds: Int,
  handshake_timeout_milliseconds handshake_timeout_milliseconds: Int,
  timeout_milliseconds timeout_milliseconds: Int,
  operation_timeout_milliseconds operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds idle_timeout_milliseconds: Int,
  drain_timeout_milliseconds drain_timeout_milliseconds: Int,
  stream_buffer_limit stream_buffer_limit: Int,
  endpoint_memory_limit endpoint_memory_limit: Int,
  queue_limit queue_limit: Int,
  telemetry_limit telemetry_limit: Int,
  bidirectional_stream_limit bidirectional_stream_limit: Int,
  unidirectional_stream_limit unidirectional_stream_limit: Int,
  frame_limit frame_limit: Int,
  datagram_limit datagram_limit: Int,
  qpack_table_limit qpack_table_limit: Int,
  qpack_blocked_stream_limit qpack_blocked_stream_limit: Int,
  http_datagrams http_datagrams: Bool,
  maximum_pushes maximum_pushes: Int,
  keepalive_milliseconds keepalive_milliseconds: Int,
  quic_v2 quic_v2: Bool,
  qlog_directory qlog_directory: String,
  resumption_tickets resumption_tickets: List(ResumptionTicketHandle),
  connect_trace connect_trace: Option(diagnostics.ConnectTrace),
  qlog_reservation qlog_reservation: Option(qlog_admission.Reservation),
) -> Result(ConnectionHandle, client_backend.Failure) {
  case resumption_tickets {
    [_, _, ..] ->
      Error(
        client_backend.RuntimeFailure(runtime_failure.Limit(
          runtime_failure.Queue,
          1,
        )),
      )
    _ -> {
      use configured <- result.try(
        native_client.new(host, port) |> map_configuration_result,
      )
      let configured =
        native_client.with_qlog_reservation(configured, qlog_reservation)
      let configured = case connect_trace {
        None -> configured
        Some(trace) -> native_client.with_connect_trace(configured, trace)
      }
      use configured <- result.try(
        native_client.with_connect_port(configured, connect_port)
        |> map_configuration_result,
      )
      let configured = case connect_address {
        None -> configured
        Some(address) ->
          native_client.with_connect_address(
            configured,
            address.to_bytes(address),
          )
      }
      let configured =
        native_client.with_quic_version(configured, case quic_v2 {
          False -> native_client.QuicV1
          True -> native_client.QuicV2
        })
      let configured =
        native_client.with_address_family(configured, case address_family {
          config.Ipv4 -> quic_core.Ipv4
          config.Ipv6 -> quic_core.Ipv6
          config.DualStack -> quic_core.DualStack
        })
      use configured <- result.try(
        native_client.with_dns_timeout(configured, dns_timeout_milliseconds)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_connect_timeout(
          configured,
          connect_timeout_milliseconds,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_handshake_timeout(
          configured,
          handshake_timeout_milliseconds,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_timeout(configured, timeout_milliseconds)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_operation_timeout(
          configured,
          operation_timeout_milliseconds,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_idle_timeout(configured, idle_timeout_milliseconds)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_drain_timeout(configured, drain_timeout_milliseconds)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_stream_buffer_limit(configured, stream_buffer_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_endpoint_memory_limit(
          configured,
          endpoint_memory_limit,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_queue_limit(configured, queue_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_telemetry_limit(configured, telemetry_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_bidirectional_stream_limit(
          configured,
          bidirectional_stream_limit,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_unidirectional_stream_limit(
          configured,
          unidirectional_stream_limit,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_frame_limit(configured, frame_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_datagram_limit(configured, datagram_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_qpack_table_limit(configured, qpack_table_limit)
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_qpack_blocked_stream_limit(
          configured,
          qpack_blocked_stream_limit,
        )
        |> map_configuration_result,
      )
      use configured <- result.try(
        native_client.with_push_limit(configured, maximum_pushes)
        |> map_configuration_result,
      )
      use configured <- result.try(case keepalive_milliseconds {
        0 -> Ok(configured)
        interval ->
          native_client.with_keepalive(configured, interval)
          |> map_configuration_result
      })
      use configured <- result.try(configure_trust(configured, ca_certificates))
      let configured = case http_datagrams {
        True -> native_client.with_http_datagrams(configured)
        False -> configured
      }
      let configured = case qlog_directory {
        "" -> Ok(configured)
        _ -> native_client.with_qlog(configured, qlog_directory)
      }
      use configured <- result.try(configured |> map_configuration_result)
      let configured = case resumption_tickets {
        [ticket] -> native_client.with_resumption_ticket(configured, ticket)
        [] -> configured
        _ -> configured
      }
      native_client.connect(configured) |> map_native_result
    }
  }
}

/// Pull the next validated server push promise.
pub fn next_push(
  connection: ConnectionHandle,
) -> Result(
  #(PushHandle, String, String, List(#(String, String))),
  client_backend.Failure,
) {
  native_client.next_push(connection)
  |> result.map(fn(push) {
    #(
      push,
      native_client.push_method(push),
      native_client.push_path(push),
      native_client.push_headers(push),
    )
  })
  |> map_native_result
}

/// Test-only payload-free snapshot of retained stream and connection state.
@internal
pub fn resource_state_stats(
  connection: ConnectionHandle,
) -> Result(
  #(Int, Int, Int, Int, Int, Int, Int, Int, Int),
  client_backend.Failure,
) {
  native_client.resource_state_stats(connection) |> map_native_result
}

/// Return whether this connection can still accept a future request stream.
pub fn connection_reusable(
  connection: ConnectionHandle,
) -> Result(Bool, client_backend.Failure) {
  native_client.connection_reusable(connection) |> map_native_result
}

/// Open a request stream without ending its request body.
pub fn open_stream(
  connection connection: ConnectionHandle,
  request request: PreparedStreamingRequest,
) -> Result(StreamHandle, client_backend.Failure) {
  let PreparedStreamingRequest(host, port, headers, _) = request
  native_client.open_stream(connection, host, port, headers)
  |> map_native_result
}

/// Send one request-body chunk with synchronous flow-control feedback.
pub fn send_chunk(
  stream stream: StreamHandle,
  chunk chunk: BitArray,
) -> Result(Nil, client_backend.Failure) {
  native_client.send_chunk(stream, chunk) |> map_native_result
}

/// Send pre-encoded Capsule Protocol bytes through the guarded native path.
pub fn send_capsule(
  stream stream: StreamHandle,
  bytes bytes: BitArray,
) -> Result(Nil, client_backend.Failure) {
  native_client.send_capsule(stream, bytes) |> map_native_result
}

/// Send request trailers and the terminal FIN.
pub fn send_trailers(
  stream stream: StreamHandle,
  headers headers: List(#(String, String)),
) -> Result(Nil, client_backend.Failure) {
  native_client.send_trailers(stream, headers) |> map_native_result
}

/// End a request body.
pub fn finish(stream: StreamHandle) -> Result(Nil, client_backend.Failure) {
  native_client.finish(stream) |> map_native_result
}

/// Wait for transport acknowledgement of the request FIN.
@internal
pub fn await_request_completion(
  stream: StreamHandle,
) -> Result(Nil, client_backend.Failure) {
  native_client.await_request_completion(stream) |> map_native_result
}

/// Queue one bounded payload-free application diagnostic when qlog is on.
@internal
pub fn record_application_error(
  stream stream: StreamHandle,
  code code: Int,
) -> Nil {
  native_client.record_application_error(stream, code)
}

/// Configured per-operation duration; this does not start a read.
@internal
pub fn operation_timeout_milliseconds(stream: StreamHandle) -> Int {
  native_client.operation_timeout_milliseconds(stream)
}

/// Pull the next response event.
pub fn next_event(
  stream: StreamHandle,
) -> Result(RawEvent, client_backend.Failure) {
  map_next_event(native_client.next_event(stream))
}

/// Pull using one absolute monotonic deadline across multiple events.
@internal
pub fn next_event_until(
  stream stream: StreamHandle,
  deadline_milliseconds deadline: Int,
) -> Result(RawEvent, client_backend.Failure) {
  map_next_event(native_client.next_event_until(stream, deadline))
}

fn map_next_event(
  outcome: Result(native_client.ResponseEvent, native_client.Error),
) -> Result(RawEvent, client_backend.Failure) {
  case outcome {
    Ok(native_client.InformationalResponse(status, headers)) ->
      Ok(#(1, status, headers, <<>>))
    Ok(native_client.ResponseHeaders(status, headers)) ->
      Ok(#(2, status, headers, <<>>))
    Ok(native_client.Data(bytes)) -> Ok(#(3, 0, [], bytes))
    Ok(native_client.Trailers(headers)) -> Ok(#(4, 0, headers, <<>>))
    Ok(native_client.End) -> Ok(#(5, 0, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

/// Pull the next response event for one server push.
pub fn next_push_event(
  push: PushHandle,
) -> Result(RawEvent, client_backend.Failure) {
  case native_client.next_push_event(push) {
    Ok(native_client.InformationalResponse(status, headers)) ->
      Ok(#(1, status, headers, <<>>))
    Ok(native_client.ResponseHeaders(status, headers)) ->
      Ok(#(2, status, headers, <<>>))
    Ok(native_client.Data(bytes)) -> Ok(#(3, 0, [], bytes))
    Ok(native_client.Trailers(headers)) -> Ok(#(4, 0, headers, <<>>))
    Ok(native_client.End) -> Ok(#(5, 0, [], <<>>))
    Error(error) -> Error(map_native_error(error))
  }
}

/// Cancel a request stream and return a primitive idempotence status.
pub fn cancel(stream: StreamHandle) -> Result(Int, client_backend.Failure) {
  case native_client.cancel(stream) {
    Ok(native_client.Cancelled) -> Ok(1)
    Ok(native_client.AlreadyCancelled) -> Ok(2)
    Ok(native_client.AlreadyCompleted) -> Ok(3)
    Error(error) -> Error(map_native_error(error))
  }
}

/// Cancel a server push and return a primitive idempotence status.
pub fn cancel_push(push: PushHandle) -> Result(Int, client_backend.Failure) {
  case native_client.cancel_push(push) {
    Ok(native_client.Cancelled) -> Ok(1)
    Ok(native_client.AlreadyCancelled) -> Ok(2)
    Ok(native_client.AlreadyCompleted) -> Ok(3)
    Error(error) -> Error(map_native_error(error))
  }
}

/// Close a connection and return a primitive idempotence status.
pub fn close(
  connection: ConnectionHandle,
) -> Result(Int, client_backend.Failure) {
  case native_client.close(connection) {
    Ok(native_client.Closed) -> Ok(1)
    Ok(native_client.AlreadyClosed) -> Ok(2)
    Error(error) -> Error(map_native_error(error))
  }
}

pub fn close_within(
  connection connection: ConnectionHandle,
  within_milliseconds within_milliseconds: Int,
) -> Result(Int, client_backend.Failure) {
  case native_client.close_within(connection, within_milliseconds) {
    Ok(native_client.Closed) -> Ok(1)
    Ok(native_client.AlreadyClosed) -> Ok(2)
    Error(error) -> Error(map_native_error(error))
  }
}

fn configure_trust(
  client: native_client.Client,
  certificates: List(BitArray),
) -> Result(native_client.Client, client_backend.Failure) {
  case certificates {
    [] -> Ok(client)
    _ ->
      native_client.with_ca_certificates(client, certificates)
      |> map_configuration_result
  }
}

// nolint: error_context_lost -- the public layer validates this configuration first.
fn map_configuration_result(
  outcome: Result(value, native_client.ConfigurationError),
) -> Result(value, client_backend.Failure) {
  result.map_error(outcome, fn(_error) {
    client_backend.RuntimeFailure(runtime_failure.Http3(
      runtime_failure.Local,
      None,
    ))
  })
}

fn map_native_result(
  outcome: Result(value, native_client.Error),
) -> Result(value, client_backend.Failure) {
  result.map_error(outcome, map_native_error)
}

fn map_native_error(error: native_client.Error) -> client_backend.Failure {
  case error {
    native_client.InvalidRequest ->
      client_backend.RuntimeFailure(runtime_failure.Http3(
        runtime_failure.Local,
        None,
      ))
    native_client.ResolutionFailed ->
      client_backend.RuntimeFailure(runtime_failure.Resolution)
    native_client.TrustStoreFailed ->
      client_backend.RuntimeFailure(runtime_failure.Tls(runtime_failure.Local))
    native_client.ConnectFailed ->
      client_backend.RuntimeFailure(runtime_failure.Socket(
        runtime_failure.ConnectSocket,
      ))
    native_client.HandshakeFailed ->
      client_backend.RuntimeFailure(runtime_failure.Tls(runtime_failure.Peer))
    native_client.Failure(failure) -> client_backend.RuntimeFailure(failure)
    native_client.TimedOut(phase) ->
      client_backend.RuntimeFailure(
        runtime_failure.Timeout(timeout_phase(phase)),
      )
    native_client.ConnectionClosed ->
      client_backend.RuntimeFailure(runtime_failure.Closed(
        runtime_failure.Peer,
        None,
      ))
    native_client.StreamReset(code) ->
      client_backend.RuntimeFailure(runtime_failure.Closed(
        runtime_failure.Peer,
        Some(code),
      ))
    native_client.ProtocolError ->
      client_backend.RuntimeFailure(runtime_failure.Http3(
        runtime_failure.Peer,
        Some(0x101),
      ))
    native_client.InvalidHeaderEncoding ->
      client_backend.RuntimeFailure(runtime_failure.Http3(
        runtime_failure.Peer,
        Some(0x109),
      ))
    native_client.InvalidContentLength -> client_backend.InvalidContentLength
    native_client.ResponseBodyTooLarge(_) -> client_backend.ResponseBodyTooLarge
    native_client.ConsumerTooSlow(limit) ->
      client_backend.ConsumerTooSlow(limit)
    native_client.OperationQueueFull(_) ->
      client_backend.RuntimeFailure(runtime_failure.Overload(
        runtime_failure.Queue,
      ))
    native_client.ConcurrentReceive -> client_backend.ConcurrentReceive
    native_client.RequestAlreadyFinished ->
      client_backend.RequestAlreadyFinished
    native_client.StreamFinished -> client_backend.StreamFinished
    native_client.StreamCancelled -> client_backend.StreamCancelled
    native_client.ConnectionDraining -> client_backend.ConnectionDraining
    native_client.RequestRejected -> client_backend.RequestRejected
    native_client.OriginMismatch -> client_backend.OriginMismatch
    native_client.UnsafeEarlyDataMethod(method) ->
      client_backend.UnsafeEarlyDataMethod(method)
    native_client.ResumptionOriginMismatch ->
      client_backend.ResumptionOriginMismatch
    native_client.CapsuleProtocolUnavailable ->
      client_backend.CapsuleProtocolUnavailable
    native_client.DatagramsNotNegotiated ->
      client_backend.RuntimeFailure(runtime_failure.Http3(
        runtime_failure.Local,
        None,
      ))
    native_client.DatagramNotAssociated ->
      client_backend.RuntimeFailure(runtime_failure.Http3(
        runtime_failure.Local,
        None,
      ))
    native_client.DatagramTooLarge(maximum) ->
      client_backend.RuntimeFailure(runtime_failure.Limit(
        runtime_failure.Datagram,
        maximum,
      ))
    native_client.DatagramBufferExceeded(maximum) ->
      client_backend.RuntimeFailure(runtime_failure.Limit(
        runtime_failure.Buffer,
        maximum,
      ))
    native_client.ConcurrentDatagramReceive ->
      client_backend.RuntimeFailure(runtime_failure.Overload(
        runtime_failure.AcceptWaiters,
      ))
    native_client.MigrationUnavailable ->
      client_backend.RuntimeFailure(runtime_failure.Quic(
        runtime_failure.Local,
        None,
      ))
    native_client.CongestionLimited ->
      client_backend.RuntimeFailure(runtime_failure.Overload(
        runtime_failure.Queue,
      ))
    native_client.UnsupportedCongestionControl ->
      client_backend.RuntimeFailure(runtime_failure.Quic(
        runtime_failure.Local,
        None,
      ))
    native_client.TicketUnavailable ->
      client_backend.RuntimeFailure(runtime_failure.Timeout(
        runtime_failure.Operation,
      ))
    native_client.QlogUnavailable ->
      client_backend.RuntimeFailure(runtime_failure.Socket(
        runtime_failure.WriteFile,
      ))
    native_client.InvalidStoredTicket ->
      client_backend.RuntimeFailure(runtime_failure.Tls(runtime_failure.Local))
    native_client.VersionNegotiationFailed ->
      client_backend.RuntimeFailure(runtime_failure.Quic(
        runtime_failure.Peer,
        None,
      ))
  }
}

fn timeout_phase(
  phase: native_client.TimeoutPhase,
) -> runtime_failure.TimeoutPhase {
  case phase {
    native_client.Dns -> runtime_failure.Dns
    native_client.Connect -> runtime_failure.Connect
    native_client.Handshake -> runtime_failure.Handshake
    native_client.Operation -> runtime_failure.Operation
    native_client.Total -> runtime_failure.Total
  }
}
