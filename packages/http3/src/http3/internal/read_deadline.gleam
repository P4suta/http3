//// Pure operation-budget calculation shared by the HTTP/3 event readers.

import gleam/bool
import gleam/int

/// Return the effective absolute deadline and its remaining duration from one clock sample.
/// A caller cannot extend the configured operation limit.
pub fn plan(
  now now: Int,
  deadline deadline: Int,
  operation operation: Int,
) -> Result(#(Int, Int), Nil) {
  use <- bool.guard(when: operation <= 0 || deadline <= now, return: Error(Nil))
  let remaining = int.min(deadline - now, operation)
  Ok(#(now + remaining, remaining))
}
