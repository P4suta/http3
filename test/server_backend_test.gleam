import http3/internal/server_backend

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_backend_failures_are_normalized_test() -> Nil {
  assert server_backend.normalize_error(#(2, 0, "timeout"))
    == server_backend.Timeout
  assert server_backend.normalize_error(#(7, 32, "request limit"))
    == server_backend.RequestBodyTooLarge(32)
  assert server_backend.normalize_error(#(8, 64, "response limit"))
    == server_backend.ResponseBodyTooLarge(64)
  assert server_backend.normalize_error(#(9, 16, "consumer slow"))
    == server_backend.ConsumerTooSlow(16)
  assert server_backend.normalize_error(#(10, 0, "concurrent accept"))
    == server_backend.ConcurrentAccept
  assert server_backend.normalize_error(#(11, 0, "concurrent receive"))
    == server_backend.ConcurrentReceive
  assert server_backend.normalize_error(#(5, 270, "stream reset"))
    == server_backend.StreamReset(270)
  assert server_backend.normalize_error(#(15, 0, "content-length mismatch"))
    == server_backend.InvalidContentLength
}
