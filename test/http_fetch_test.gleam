import gleam/http as gleam_http
import gleam/http/request
import gleam/option.{None, Some}
import gleeunit
import http
import http/error

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn one_shot_fetch_rejects_plaintext_before_connecting_test() -> Nil {
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(1),
      path: "/fetch",
      query: None,
    )

  let assert Error(failure) = http.fetch(outgoing)
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
  Nil
}
