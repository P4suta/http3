import http3/internal/server_response

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_response_rejects_informational_final_status_test() -> Nil {
  assert server_response.prepare_streaming(103, [])
    == Error(server_response.InvalidStatus(103))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_response_rejects_forbidden_header_test() -> Nil {
  assert server_response.prepare_streaming(200, [#("connection", "close")])
    == Error(server_response.InvalidHeader("connection"))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounded_server_response_checks_content_length_test() -> Nil {
  assert server_response.prepare_bounded(200, [#("content-length", "2")], 1)
    == Error(server_response.InvalidContentLength)
}
