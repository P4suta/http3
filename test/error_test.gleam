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

pub fn peer_rejection_retry_evidence_keeps_the_public_error_stable_test() -> Nil {
  let rejected = error.peer_rejected_before_processing(error.Http3)

  assert error.kind(rejected) == error.Protocol(error.Http3)
  assert error.message(rejected) == "HTTP/3 protocol failure"
  assert error.retry_evidence(rejected) == error.PeerGuaranteedUnprocessed
  assert error.retry_evidence(error.new(error.Protocol(error.Http3)))
    == error.NoRetryEvidence
}
