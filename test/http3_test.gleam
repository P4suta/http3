import gleeunit
import http3
import http3/client
import http3/server
import http3_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn quic_backend_is_available_test() -> Nil {
  assert http3.is_supported()
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_positive_timeout_test() -> Nil {
  assert client.with_timeout(client.new(), 0) == Error(client.InvalidTimeout)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_excessive_timeout_test() -> Nil {
  assert client.with_timeout(client.new(), 3_600_001)
    == Error(client.InvalidTimeout)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_positive_response_body_limit_test() -> Nil {
  assert client.with_response_body_limit(client.new(), 0)
    == Error(client.InvalidResponseBodyLimit)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_positive_request_body_limit_test() -> Nil {
  assert client.with_request_body_limit(client.new(), 0)
    == Error(client.InvalidRequestBodyLimit)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_empty_ca_certificate_test() -> Nil {
  assert client.with_ca_certificate(client.new(), <<>>)
    == Error(client.InvalidCaCertificate)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_malformed_ca_certificate_test() -> Nil {
  assert client.with_ca_certificate(client.new(), <<0, 1, 2>>)
    == Error(client.InvalidCaCertificate)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_rejects_non_positive_stream_buffer_limit_test() -> Nil {
  assert client.with_stream_buffer_limit(client.new(), 0)
    == Error(client.InvalidStreamBufferLimit)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_rejects_invalid_port_test() -> Nil {
  let #(certificate, private_key, _) = http3_test_support.server_credentials()
  let configuration = server.new(certificate, private_key)
  // nolint: assert_ok_pattern -- valid fixtures are part of the test setup.
  let assert Ok(configuration) = configuration
  assert server.with_port(configuration, -1) == Error(server.InvalidPort(-1))
}
