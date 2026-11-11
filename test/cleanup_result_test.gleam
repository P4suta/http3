import gleam/option.{None, Some}
import http/error
import http/internal/cleanup_result

pub fn cleanup_result_waits_for_completion_and_preserves_the_first_failure_test() -> Nil {
  let completion = cleanup_result.new()
  let failure = error.new(error.Timeout(error.Operation))
  assert cleanup_result.outcome(completion) == None
  cleanup_result.complete(completion, Error(failure))
  cleanup_result.complete(completion, Ok(Nil))
  assert cleanup_result.outcome(completion) == Some(Error(failure))
}

pub fn completed_cleanup_cannot_be_replaced_by_a_late_failure_test() -> Nil {
  let completion = cleanup_result.new()
  cleanup_result.complete(completion, Ok(Nil))
  cleanup_result.complete(completion, Error(error.new(error.Service)))
  assert cleanup_result.outcome(completion) == Some(Ok(Nil))
}
