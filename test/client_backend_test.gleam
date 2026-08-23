import http3/internal/client_backend

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn backend_timeout_is_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(3, 0, "request timeout"))
    == client_backend.Timeout
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn backend_body_limit_is_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(4, 0, "response body too large"))
    == client_backend.ResponseBodyTooLarge
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn backend_stream_reset_is_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(6, 268, "stream reset"))
    == client_backend.StreamReset(268)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn backend_protocol_error_is_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(7, 257, "protocol failure"))
    == client_backend.ProtocolError(257, "protocol failure")
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unknown_backend_error_is_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(99, 0, "unknown"))
    == client_backend.BackendFailure("unknown")
}
