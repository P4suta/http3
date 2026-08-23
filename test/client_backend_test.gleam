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
pub fn backend_streaming_failures_are_normalized_test() -> Nil {
  assert client_backend.normalize_error(#(14, 0, "invalid content length"))
    == client_backend.InvalidContentLength
  assert client_backend.normalize_error(#(15, 128, "consumer too slow"))
    == client_backend.ConsumerTooSlow(128)
  assert client_backend.normalize_error(#(16, 0, "concurrent receive"))
    == client_backend.ConcurrentReceive
  assert client_backend.normalize_error(#(17, 0, "request finished"))
    == client_backend.RequestAlreadyFinished
  assert client_backend.normalize_error(#(18, 0, "stream finished"))
    == client_backend.StreamFinished
  assert client_backend.normalize_error(#(19, 0, "stream cancelled"))
    == client_backend.StreamCancelled
  assert client_backend.normalize_error(#(20, 0, "origin mismatch"))
    == client_backend.OriginMismatch
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
