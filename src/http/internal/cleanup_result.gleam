//// One shared, actor-free cleanup outcome with a closed scalar encoding.

import gleam/option.{type Option}
import gleam/result
import http/error

pub type Completion

@external(erlang, "http_body_ffi", "new_cleanup_result")
pub fn new() -> Completion

@external(erlang, "http_body_ffi", "complete_cleanup_result")
fn write(completion: Completion, outcome: Result(Nil, Int)) -> Nil

@external(erlang, "http_body_ffi", "read_cleanup_result")
fn read(completion: Completion) -> Option(Result(Nil, Int))

pub fn complete(
  completion completion: Completion,
  outcome outcome: Result(Nil, error.Error),
) -> Nil {
  write(completion, result.map_error(outcome, encode_failure))
}

pub fn outcome(completion: Completion) -> Option(Result(Nil, error.Error)) {
  read(completion)
  |> option.map(fn(outcome) { result.map_error(outcome, decode_failure) })
}

fn encode_failure(failure: error.Error) -> Int {
  case error.kind(failure) {
    error.Timeout(_) -> 2
    error.Cancelled -> 3
    _ -> 1
  }
}

fn decode_failure(code: Int) -> error.Error {
  case code {
    2 -> error.new(error.Timeout(error.Operation))
    3 -> error.new(error.Cancelled)
    _ -> error.new(error.Service)
  }
}
