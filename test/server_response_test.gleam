import http3/internal/server_response

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_response_rejects_informational_final_status_test() -> Nil {
  assert server_response.prepare_streaming(103, [])
    == Error(server_response.InvalidStatus(103))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_response_prepares_informational_headers_test() -> Nil {
  assert server_response.prepare_informational(103, [#("link", "</style.css>")])
    == Ok([#("link", "</style.css>")])
  assert server_response.prepare_informational(101, [])
    == Error(server_response.InvalidStatus(101))
  assert server_response.prepare_informational(200, [])
    == Error(server_response.InvalidStatus(200))
  assert server_response.prepare_informational(103, [
      #("content-length", "0"),
    ])
    == Error(server_response.InvalidContentLength)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_response_prepares_strict_trailers_test() -> Nil {
  assert server_response.prepare_trailers([#("digest", "sha-256=:abc=:")])
    == Ok([#("digest", "sha-256=:abc=:")])
  assert server_response.prepare_trailers([#("content-length", "0")])
    == Error(server_response.InvalidHeader("content-length"))
  assert server_response.prepare_trailers([#(":status", "200")])
    == Error(server_response.InvalidHeader(":status"))
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
