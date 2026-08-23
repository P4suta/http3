//// Bounded HTTP/3 client powered by the repository-owned QUIC stack.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam_quic/internal/http3/bounded_client
import gleam_quic/internal/tls/authentication

const default_timeout_milliseconds = 30_000

const maximum_timeout_milliseconds = 3_600_000

const default_response_body_limit = 8_388_608

type Trust {
  SystemTrust
  ExplicitTrust(List(BitArray))
}

/// Secure bounded-client configuration.
pub opaque type Client {
  Client(
    hostname: String,
    port: Int,
    timeout_milliseconds: Int,
    response_body_limit: Int,
    trust: Trust,
  )
}

/// Invalid client policy or endpoint input.
pub type ConfigurationError {
  InvalidHost
  InvalidPort(Int)
  InvalidTimeout
  InvalidResponseBodyLimit
  InvalidCaCertificate
}

/// A complete response retained within the configured body bound.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// Native name resolution, TLS, QUIC, HTTP/3, or resource failure.
pub type Error {
  InvalidRequest
  ResolutionFailed
  TrustStoreFailed
  ConnectFailed
  HandshakeFailed
  TransportError(String)
  Http3Error(String)
  Timeout
  ConnectionClosed
  StreamReset(Int)
  ProtocolError
  InvalidHeaderEncoding
  ResponseBodyTooLarge(Int)
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Configure one secure origin. Certificate and hostname checks are mandatory.
pub fn new(
  hostname hostname: String,
  port port: Int,
) -> Result(Client, ConfigurationError) {
  case hostname, port {
    "", _ -> Error(InvalidHost)
    _, value if value <= 0 || value > 65_535 -> Error(InvalidPort(value))
    _, _ ->
      Ok(Client(
        hostname,
        port,
        default_timeout_milliseconds,
        default_response_body_limit,
        SystemTrust,
      ))
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set one total connect/request deadline from one millisecond to one hour.
pub fn with_timeout(
  client client: Client,
  milliseconds milliseconds: Int,
) -> Result(Client, ConfigurationError) {
  case milliseconds > 0 && milliseconds <= maximum_timeout_milliseconds {
    True -> Ok(Client(..client, timeout_milliseconds: milliseconds))
    False -> Error(InvalidTimeout)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Set the maximum buffered response body in bytes.
pub fn with_response_body_limit(
  client client: Client,
  bytes bytes: Int,
) -> Result(Client, ConfigurationError) {
  case bytes > 0 {
    True -> Ok(Client(..client, response_body_limit: bytes))
    False -> Error(InvalidResponseBodyLimit)
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Replace system roots with a non-empty explicit DER trust set.
pub fn with_ca_certificates(
  client client: Client,
  certificates certificates: List(BitArray),
) -> Result(Client, ConfigurationError) {
  case certificates, valid_certificate_alignment(certificates) {
    [], _ -> Error(InvalidCaCertificate)
    _, False -> Error(InvalidCaCertificate)
    _, True ->
      case authentication.trust_store_from_der(certificates) {
        Ok(_) -> Ok(Client(..client, trust: ExplicitTrust(certificates)))
        Error(_) -> Error(InvalidCaCertificate)
      }
  }
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Return whether bytes are one valid DER X.509 trust anchor.
pub fn is_valid_ca_certificate(certificate: BitArray) -> Bool {
  authentication.trust_store_from_der([certificate]) |> result.is_ok
}

// nolint: unused_exports -- consumed by the parent http3 package.
/// Execute one bounded request and close its connection before returning.
pub fn send(
  client client: Client,
  headers headers: List(#(String, String)),
  body body: BitArray,
) -> Result(Response, Error) {
  use trust_store <- result.try(load_trust(client.trust))
  let config =
    bounded_client.Config(
      hostname: client.hostname,
      port: client.port,
      timeout_milliseconds: client.timeout_milliseconds,
      maximum_response_body_bytes: client.response_body_limit,
      trust_store: trust_store,
    )
  case bounded_client.send(config, headers, body) {
    Ok(bounded_client.Response(status, headers, body)) ->
      Ok(Response(status, headers, body))
    Error(error) -> Error(map_error(error))
  }
}

fn load_trust(trust: Trust) -> Result(authentication.TrustStore, Error) {
  let loaded = case trust {
    SystemTrust -> authentication.system_trust_store()
    ExplicitTrust(certificates) ->
      authentication.trust_store_from_der(certificates)
  }
  loaded |> result.replace_error(TrustStoreFailed)
}

fn valid_certificate_alignment(certificates: List(BitArray)) -> Bool {
  list.all(certificates, fn(certificate) {
    bit_array.byte_size(certificate) > 0
    && bit_array.bit_size(certificate) % 8 == 0
  })
}

fn map_error(error: bounded_client.Error) -> Error {
  case error {
    bounded_client.InvalidInput -> InvalidRequest
    bounded_client.ResolutionFailed -> ResolutionFailed
    bounded_client.SocketUnavailable -> ConnectFailed
    bounded_client.Timeout -> Timeout
    bounded_client.TlsHandshakeFailed -> HandshakeFailed
    bounded_client.QuicTransportFailed(operation, error) ->
      TransportError(operation <> ": " <> driver_error_name(error))
    bounded_client.Http3ProtocolFailed -> Http3Error("invalid response state")
    bounded_client.Http3OperationFailed(operation, error) ->
      Http3Error(operation <> ": " <> session_error_name(error))
    bounded_client.PeerClosed -> ConnectionClosed
    bounded_client.StreamReset(code) -> StreamReset(code)
    bounded_client.InvalidHeaderEncoding -> InvalidHeaderEncoding
    bounded_client.ResponseBodyTooLarge(limit) -> ResponseBodyTooLarge(limit)
  }
}

fn driver_error_name(error: bounded_client.DriverError) -> String {
  bounded_client.driver_error_name(error)
}

fn session_error_name(error: bounded_client.SessionError) -> String {
  bounded_client.session_error_name(error)
}
