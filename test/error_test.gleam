import gleam/string
import gleeunit
import http/error

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn exposes_stable_error_kind_without_private_detail_test() -> Nil {
  let failure = error.new(error.Timeout(error.Operation))

  assert error.kind(failure) == error.Timeout(error.Operation)
  assert error.message(failure) == "HTTP operation timed out"
  assert !string.contains(error.message(failure), "secret.example")
}

pub fn body_limit_error_is_typed_and_redacted_test() -> Nil {
  let failure = error.new(error.Body(error.TooLarge(1024)))

  assert error.kind(failure) == error.Body(error.TooLarge(1024))
  assert error.message(failure) == "HTTP body exceeds its configured limit"
}
