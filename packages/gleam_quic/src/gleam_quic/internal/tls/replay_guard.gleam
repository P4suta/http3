//// Finite execution boundary for a caller-managed 0-RTT replay guard.
////
//// The callback performs an atomic test-and-record in shared storage. It runs
//// in a disposable process so a crash, error, or timeout can only reject
//// early data; TLS resumption can continue safely at 1-RTT.

import gleam/erlang/process
import gleam_quic/internal/process_label

const maximum_timeout_milliseconds = 10_000

/// A bounded external atomic test-and-record operation.
pub opaque type Guard {
  Guard(
    timeout_milliseconds: Int,
    check: fn(BitArray, Int) -> Result(Bool, Nil),
  )
}

/// Invalid external guard policy.
pub type Error {
  InvalidTimeout
}

type GuardMessage {
  GuardResult(Result(Bool, Nil))
  GuardExited
}

/// Validate a finite external replay-guard deadline.
pub fn new(
  timeout_milliseconds timeout_milliseconds: Int,
  check check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(Guard, Error) {
  case
    timeout_milliseconds > 0
    && timeout_milliseconds <= maximum_timeout_milliseconds
  {
    True -> Ok(Guard(timeout_milliseconds, check))
    False -> Error(InvalidTimeout)
  }
}

/// Return `True` only when the external operation completes and accepts.
///
/// `Error`, callback process exit, and deadline expiry all fail closed. A
/// zero validity interval is never submitted to caller storage.
pub fn permits(
  guard guard: Guard,
  fingerprint fingerprint: BitArray,
  valid_for_milliseconds valid_for_milliseconds: Int,
) -> Bool {
  case valid_for_milliseconds > 0 {
    False -> False
    True -> {
      let reply = process.new_subject()
      let worker =
        process.spawn_unlinked(fn() {
          process_label.set(process_label.ReplayGuard)
          process.send(reply, guard.check(fingerprint, valid_for_milliseconds))
        })
      let monitor = process.monitor(worker)
      let selector =
        process.new_selector()
        |> process.select_map(reply, GuardResult)
        |> process.select_specific_monitor(monitor, fn(_) { GuardExited })
      case process.selector_receive(selector, guard.timeout_milliseconds) {
        Ok(GuardResult(outcome)) -> {
          process.demonitor_process(monitor)
          outcome == Ok(True)
        }
        Ok(GuardExited) -> {
          process.demonitor_process(monitor)
          False
        }
        Error(Nil) -> {
          process.kill(worker)
          await_exit(selector)
          // A result can race the timeout by one scheduler turn. Once DOWN
          // has arrived the worker cannot send again, so this zero-time drain
          // guarantees no unique reply remains in the TLS actor's mailbox.
          let _late_result = process.receive(reply, 0)
          False
        }
      }
    }
  }
}

fn await_exit(selector: process.Selector(GuardMessage)) -> Nil {
  case process.selector_receive_forever(selector) {
    GuardExited -> Nil
    GuardResult(_) -> await_exit(selector)
  }
}
