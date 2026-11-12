//// Internal scalar publication into a caller-owned bounded connect trace.

import gleam/list
import gleam/option.{type Option, None, Some}
import quic_core/diagnostics
import quic_core/internal/runtime/happy_eyeballs as schedule

/// Fixed internal DNS evidence; no names, addresses or backend errors.
pub type ResolutionObservation {
  ResolutionObservation(
    sequence: Int,
    attempt: Int,
    family: schedule.Family,
    outcome: schedule.ResolutionOutcome,
    milliseconds: Int,
  )
}

pub type ResolutionSnapshot {
  ResolutionSnapshot(
    consistent: Bool,
    dropped: Int,
    events: List(ResolutionObservation),
  )
}

@external(erlang, "quic_core_connect_trace_ffi", "record_resolution")
fn publish_resolution(
  trace: diagnostics.ConnectTrace,
  attempt: Int,
  family: Int,
  outcome: Int,
) -> Nil

@external(erlang, "quic_core_connect_trace_ffi", "resolution_snapshot")
fn raw_resolution_snapshot(
  trace: diagnostics.ConnectTrace,
) -> #(Bool, Int, List(#(Int, Int, Int, Int, Int)))

/// Record a callback result or a joined lifecycle cancellation, without values.
pub fn resolution(
  context: Option(Context),
  family: schedule.Family,
  outcome: schedule.ResolutionOutcome,
) -> Nil {
  case context {
    None -> Nil
    Some(Context(trace, attempt, _)) ->
      publish_resolution(
        trace,
        attempt,
        case family {
          schedule.Ipv4 -> 4
          schedule.Ipv6 -> 6
        },
        case outcome {
          schedule.ResolutionStarted -> 1
          schedule.ResolutionUsable -> 2
          schedule.ResolutionEmpty -> 3
          schedule.ResolutionRejected -> 4
          schedule.ResolutionExpired -> 5
          schedule.ResolutionCancelled -> 6
          schedule.ResolutionWorkerExited -> 7
          schedule.ResolutionStartFailed -> 8
        },
      )
  }
}

/// Read bounded family evidence attached to an opaque public trace handle.
pub fn resolution_snapshot(
  trace: diagnostics.ConnectTrace,
) -> ResolutionSnapshot {
  let #(consistent, dropped, rows) = raw_resolution_snapshot(trace)
  ResolutionSnapshot(
    consistent,
    dropped,
    list.map(rows, fn(row) {
      let #(sequence, attempt, family, outcome, milliseconds) = row
      ResolutionObservation(
        sequence,
        attempt,
        case family {
          4 -> schedule.Ipv4
          _ -> schedule.Ipv6
        },
        case outcome {
          1 -> schedule.ResolutionStarted
          2 -> schedule.ResolutionUsable
          3 -> schedule.ResolutionEmpty
          4 -> schedule.ResolutionRejected
          5 -> schedule.ResolutionExpired
          6 -> schedule.ResolutionCancelled
          7 -> schedule.ResolutionWorkerExited
          _ -> schedule.ResolutionStartFailed
        },
        milliseconds,
      )
    }),
  )
}

pub opaque type Context {
  Context(trace: diagnostics.ConnectTrace, attempt: Int, candidate: Int)
}

@external(erlang, "quic_core_connect_trace_ffi", "begin_attempt")
fn begin_attempt(trace: diagnostics.ConnectTrace) -> Int

@external(erlang, "quic_core_connect_trace_ffi", "record")
fn publish(
  trace: diagnostics.ConnectTrace,
  attempt: Int,
  candidate: Int,
  phase: Int,
  outcome: Int,
) -> Nil

pub fn begin(trace: Option(diagnostics.ConnectTrace)) -> Option(Context) {
  case trace {
    None -> None
    Some(trace) -> Some(Context(trace, begin_attempt(trace), 0))
  }
}

pub fn candidate(context: Option(Context), index: Int) -> Option(Context) {
  case context {
    None -> None
    Some(context) -> Some(Context(..context, candidate: index))
  }
}

pub fn record(context: Option(Context), phase: Int, outcome: Int) -> Nil {
  case context {
    None -> Nil
    Some(Context(trace, attempt, candidate)) ->
      publish(trace, attempt, candidate, phase, outcome)
  }
}

/// A failed establishment must not leave its pre-dial resolution phase open.
pub fn fail_resolution_if_pending(context: Option(Context)) -> Nil {
  case context {
    None -> Nil
    Some(Context(trace, attempt, _)) -> {
      let completed =
        diagnostics.connect_snapshot(trace).events
        |> list.any(fn(event) {
          event.attempt == attempt
          && event.candidate == 0
          && event.phase == diagnostics.NameResolution
          && event.outcome != diagnostics.Started
        })
      case completed {
        True -> Nil
        False -> record(context, 1, 3)
      }
    }
  }
}

/// Complete only observed, unfinished phases after cancelling their writer.
pub fn abandon(context: Option(Context)) -> Nil {
  case context {
    None -> Nil
    Some(Context(trace, attempt, candidate)) -> {
      let events = diagnostics.connect_snapshot(trace).events
      events
      |> list.filter(fn(event) {
        event.attempt == attempt
        && { candidate == 0 || event.candidate == candidate }
        && event.outcome == diagnostics.Started
      })
      |> list.each(fn(started) {
        let finished =
          list.any(events, fn(event) {
            event.attempt == attempt
            && event.candidate == started.candidate
            && event.phase == started.phase
            && event.outcome != diagnostics.Started
          })
        case !finished {
          True ->
            publish(
              trace,
              attempt,
              started.candidate,
              phase_code(started.phase),
              4,
            )
          False -> Nil
        }
      })
    }
  }
}

fn phase_code(phase: diagnostics.ConnectPhase) -> Int {
  case phase {
    diagnostics.NameResolution -> 1
    diagnostics.UdpOpen -> 2
    diagnostics.TlsHandshake -> 3
    diagnostics.OwnershipPublication -> 4
  }
}
