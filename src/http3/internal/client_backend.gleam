//// Typed normalization around the Erlang HTTP/3 client FFI.

import gleam/option.{None, Some}
import gleam/result
import gleam_quic
import http3/config
import http3/failure as runtime_failure
import http3/internal/client_request.{type PreparedRequest, PreparedRequest}
import http3/internal/native/client as native_client

/// A response returned by the backend boundary.
pub type Response =
  #(Int, List(#(String, String)), BitArray)

/// Primitive error data returned by the Erlang FFI.
pub type RawError =
  #(Int, Int, String)

/// A backend-independent client failure.
pub type Failure {
  RuntimeFailure(runtime_failure.Failure)
  ResponseBodyTooLarge
  ConsumerTooSlow(Int)
  ConcurrentReceive
  RequestAlreadyFinished
  StreamFinished
  StreamCancelled
  ConnectionDraining
  RequestRejected
  OriginMismatch
  UnsafeEarlyDataMethod(String)
  ResumptionOriginMismatch
  InvalidContentLength
}

/// Return whether bytes decode as one DER X.509 certificate.
pub fn is_valid_ca_certificate(certificate: BitArray) -> Bool {
  native_client.is_valid_ca_certificate(certificate)
}

/// Execute one prepared request through the backend adapter.
pub fn send(
  request request: PreparedRequest,
  ca_certificates ca_certificates: List(BitArray),
  address_family address_family: config.AddressFamily,
  dns_timeout_milliseconds dns_timeout_milliseconds: Int,
  connect_timeout_milliseconds connect_timeout_milliseconds: Int,
  handshake_timeout_milliseconds handshake_timeout_milliseconds: Int,
  timeout_milliseconds timeout_milliseconds: Int,
  operation_timeout_milliseconds operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds idle_timeout_milliseconds: Int,
  response_body_limit response_body_limit: Int,
  quic_v2 quic_v2: Bool,
  keepalive_milliseconds keepalive_milliseconds: Int,
) -> Result(Response, Failure) {
  let PreparedRequest(host, port, headers, body) = request
  use client <- result.try(
    native_client.new(host, port)
    |> result.map_error(from_native_configuration_error),
  )
  let client =
    native_client.with_quic_version(client, case quic_v2 {
      False -> native_client.QuicV1
      True -> native_client.QuicV2
    })
  let client =
    native_client.with_address_family(
      client,
      native_address_family(address_family),
    )
  use client <- result.try(
    native_client.with_dns_timeout(client, dns_timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_connect_timeout(client, connect_timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_handshake_timeout(client, handshake_timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_timeout(client, timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_operation_timeout(client, operation_timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_idle_timeout(client, idle_timeout_milliseconds)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(
    native_client.with_response_body_limit(client, response_body_limit)
    |> result.map_error(from_native_configuration_error),
  )
  use client <- result.try(case keepalive_milliseconds {
    0 -> Ok(client)
    interval ->
      native_client.with_keepalive(client, interval)
      |> result.map_error(from_native_configuration_error)
  })
  use client <- result.try(case ca_certificates {
    [] -> Ok(client)
    certificates ->
      native_client.with_ca_certificates(client, certificates)
      |> result.map_error(from_native_configuration_error)
  })
  case native_client.send(client, headers, body) {
    Ok(native_client.Response(status, headers, body)) ->
      Ok(#(status, headers, body))
    Error(error) -> Error(from_native_error(error))
  }
}

fn native_address_family(
  address_family: config.AddressFamily,
) -> gleam_quic.AddressFamily {
  case address_family {
    config.Ipv4 -> gleam_quic.Ipv4
    config.Ipv6 -> gleam_quic.Ipv6
    config.DualStack -> gleam_quic.DualStack
  }
}

fn from_native_configuration_error(
  _error: native_client.ConfigurationError,
) -> Failure {
  RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
}

fn from_native_error(error: native_client.Error) -> Failure {
  case error {
    native_client.InvalidRequest ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
    native_client.ResolutionFailed -> RuntimeFailure(runtime_failure.Resolution)
    native_client.TrustStoreFailed ->
      RuntimeFailure(runtime_failure.Tls(runtime_failure.Local))
    native_client.ConnectFailed ->
      RuntimeFailure(runtime_failure.Socket(runtime_failure.ConnectSocket))
    native_client.HandshakeFailed ->
      RuntimeFailure(runtime_failure.Tls(runtime_failure.Peer))
    native_client.Failure(failure) -> RuntimeFailure(failure)
    native_client.TimedOut(phase) ->
      RuntimeFailure(runtime_failure.Timeout(timeout_phase(phase)))
    native_client.ConnectionClosed ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, None))
    native_client.StreamReset(code) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, Some(code)))
    native_client.ProtocolError ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Peer, Some(0x0102)))
    native_client.InvalidHeaderEncoding ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Peer, Some(0x0102)))
    native_client.InvalidContentLength -> InvalidContentLength
    native_client.ResponseBodyTooLarge(_) -> ResponseBodyTooLarge
    native_client.ConsumerTooSlow(limit) -> ConsumerTooSlow(limit)
    native_client.OperationQueueFull(_) ->
      RuntimeFailure(runtime_failure.Overload(runtime_failure.Queue))
    native_client.ConcurrentReceive -> ConcurrentReceive
    native_client.RequestAlreadyFinished -> RequestAlreadyFinished
    native_client.StreamFinished -> StreamFinished
    native_client.StreamCancelled -> StreamCancelled
    native_client.ConnectionDraining -> ConnectionDraining
    native_client.RequestRejected -> RequestRejected
    native_client.OriginMismatch -> OriginMismatch
    native_client.UnsafeEarlyDataMethod(method) -> UnsafeEarlyDataMethod(method)
    native_client.ResumptionOriginMismatch -> ResumptionOriginMismatch
    native_client.DatagramsNotNegotiated
    | native_client.DatagramNotAssociated
    | native_client.DatagramTooLarge(_)
    | native_client.DatagramBufferExceeded(_)
    | native_client.ConcurrentDatagramReceive
    | native_client.MigrationUnavailable
    | native_client.CongestionLimited
    | native_client.UnsupportedCongestionControl
    | native_client.TicketUnavailable
    | native_client.QlogUnavailable ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
    native_client.InvalidStoredTicket ->
      RuntimeFailure(runtime_failure.Tls(runtime_failure.Local))
    native_client.VersionNegotiationFailed ->
      RuntimeFailure(runtime_failure.Quic(runtime_failure.Peer, None))
  }
}

/// Convert primitive FFI error data into an internal typed failure.
pub fn normalize_error(error: RawError) -> Failure {
  case error {
    #(1, _, _) ->
      RuntimeFailure(runtime_failure.Socket(runtime_failure.ConnectSocket))
    #(2, _, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
    #(3, _, _) -> RuntimeFailure(runtime_failure.Timeout(runtime_failure.Total))
    #(4, _, _) -> ResponseBodyTooLarge
    #(5, _, _) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, None))
    #(6, code, _) ->
      RuntimeFailure(runtime_failure.Closed(runtime_failure.Peer, Some(code)))
    #(7, code, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Peer, Some(code)))
    #(14, _, _) -> InvalidContentLength
    #(15, limit, _) -> ConsumerTooSlow(limit)
    #(16, _, _) -> ConcurrentReceive
    #(17, _, _) -> RequestAlreadyFinished
    #(18, _, _) -> StreamFinished
    #(19, _, _) -> StreamCancelled
    #(20, _, _) -> OriginMismatch
    #(21, _, method) -> UnsafeEarlyDataMethod(method)
    #(22, _, _) -> ResumptionOriginMismatch
    #(23, _, _) -> ConnectionDraining
    #(24, _, _) -> RequestRejected
    #(_, _, _) ->
      RuntimeFailure(runtime_failure.Http3(runtime_failure.Local, None))
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
