import gleam/http
import gleam/http/request
import gleam/option.{Some}
import http3/internal/client_request

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_request_preserves_declared_content_length_test() -> Nil {
  let request =
    request.new()
    |> request.set_host("example.com")
    |> request.set_path("/upload")
    |> request.set_method(http.Post)
    |> request.set_header("content-length", "42")
    |> request.set_body(Nil)

  // nolint: assert_ok_pattern -- normalized fields are the test assertion.
  let assert Ok(client_request.PreparedStreamingRequest(
    "example.com",
    443,
    headers,
    Some(42),
  )) = client_request.prepare_streaming(request)
  assert headers
    == [
      #(":method", "POST"),
      #(":scheme", "https"),
      #(":path", "/upload"),
      #(":authority", "example.com"),
      #("content-length", "42"),
    ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn streaming_request_rejects_negative_content_length_test() -> Nil {
  let request =
    request.new()
    |> request.set_host("example.com")
    |> request.set_header("content-length", "-1")
    |> request.set_body(Nil)

  assert client_request.prepare_streaming(request)
    == Error(client_request.InvalidContentLength)
}
