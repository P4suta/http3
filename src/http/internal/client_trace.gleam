//// Correlation and once-only publication for bounded client diagnostics.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http/context
import http/diagnostics
import http/error
import http/internal/transport
import http3/client as h3_client

type Once

type AttemptState

@external(erlang, "http_body_ffi", "new_cancel_handle")
fn once() -> Once

@external(erlang, "http_body_ffi", "mark_cancelled")
fn claim(once: Once) -> Bool

@external(erlang, "http_server_ffi", "client_trace_new_state")
fn new_attempt_state() -> AttemptState

@external(erlang, "http_server_ffi", "client_trace_phase_transition")
fn phase_transition(state: AttemptState, phase: Int, transition: Int) -> Bool

@external(erlang, "http_server_ffi", "client_trace_phase_transition_if_missing")
fn phase_transition_if_missing(
  state: AttemptState,
  phase: Int,
  transition: Int,
) -> Bool

@external(erlang, "http_server_ffi", "client_trace_record_headers")
fn record_headers(state: AttemptState) -> Bool

@external(erlang, "http_server_ffi", "client_trace_publish_headers")
fn publish_headers(state: AttemptState) -> Nil

@external(erlang, "http_server_ffi", "client_trace_record_read")
fn record_read(state: AttemptState) -> Bool

@external(erlang, "http_server_ffi", "client_trace_publish_read")
fn publish_read(state: AttemptState) -> Nil

@external(erlang, "http_server_ffi", "client_trace_record_finished")
fn record_finished(state: AttemptState, succeeded: Bool) -> Bool

@external(erlang, "http_server_ffi", "client_trace_record_finished_if_missing")
fn record_finished_if_missing(state: AttemptState, succeeded: Bool) -> Bool

@external(erlang, "http_server_ffi", "client_trace_publish_finished")
fn publish_finished(state: AttemptState) -> Nil

@external(erlang, "http_server_ffi", "client_trace_record_release")
fn record_release(state: AttemptState, protocol: Int, outcome: Int) -> Bool

@external(erlang, "http_server_ffi", "client_trace_record_release_if_missing")
fn record_release_if_missing(
  state: AttemptState,
  protocol: Int,
  outcome: Int,
) -> Bool

@external(erlang, "http_server_ffi", "client_trace_take_release")
fn take_release(state: AttemptState) -> #(Bool, Int, Int)

@external(erlang, "http_server_ffi", "client_trace_publish_release")
fn publish_release(state: AttemptState) -> Nil

@external(erlang, "http_server_ffi", "client_trace_request_success")
fn request_success(state: AttemptState) -> Nil

@external(erlang, "http_server_ffi", "client_trace_success_ready")
fn success_ready(state: AttemptState) -> Bool

@external(erlang, "http_server_ffi", "client_trace_snapshot")
fn raw_transition_snapshot(state: AttemptState) -> #(Int, Int, Int, Int)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn now() -> Int

/// One logical request; an attempt copy shares only its logical completion.
pub opaque type Trace {
  Trace(
    reporter: diagnostics.Reporter,
    request_id: diagnostics.RequestId,
    started: Int,
    attempt: Int,
    state: AttemptState,
    protocol_selection: Once,
    cancellation: Once,
    exchange_finished: Once,
  )
}

/// Saturating observations of rejected attempt transitions.
pub type TransitionSnapshot {
  TransitionSnapshot(duplicates: Int, out_of_order: Int, late: Int)
}

/// Disabled diagnostics allocate neither identifiers nor delivery workers.
pub fn start(reporter: Option(diagnostics.Reporter)) -> Option(Trace) {
  case reporter {
    None -> None
    Some(reporter) -> {
      let trace =
        Some(Trace(
          reporter:,
          request_id: diagnostics.request_id(),
          started: now(),
          attempt: 0,
          state: new_attempt_state(),
          protocol_selection: once(),
          cancellation: once(),
          exchange_finished: once(),
        ))
      emit(trace, diagnostics.ExchangeStarted)
      trace
    }
  }
}

/// A retry or redirect keeps the request ID and receives new terminal claims.
pub fn attempt(trace: Option(Trace)) -> Option(Trace) {
  case trace {
    None -> None
    Some(trace) -> {
      let trace =
        Trace(
          ..trace,
          attempt: diagnostics.request_id() |> diagnostics.request_id_value,
          state: new_attempt_state(),
          protocol_selection: once(),
          cancellation: once(),
        )
      emit(Some(trace), diagnostics.AttemptStarted(trace.attempt))
      Some(trace)
    }
  }
}

/// Publish the application protocol only after its connection has won selection and before any request bytes are consumed.
/// TLS connections have completed authentication before this point.
pub fn protocol_selected(
  trace trace: Option(Trace),
  protocol protocol: context.Protocol,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) ->
      case claim(active.protocol_selection) {
        False -> Nil
        True -> {
          let phase = diagnostics.ProtocolSelection(protocol)
          phase_started(trace: trace, phase: phase)
          phase_finished(trace: trace, phase: phase, outcome: Ok(Nil))
        }
      }
  }
}

/// Publish one phase transition with the original logical correlation.
pub fn phase_started(
  trace trace: Option(Trace),
  phase phase: diagnostics.ClientPhase,
) -> Nil {
  case trace {
    None -> Nil
    Some(trace) ->
      case phase_transition(trace.state, phase_code(phase), 1) {
        True ->
          emit(Some(trace), diagnostics.PhaseStarted(trace.attempt, phase))
        False -> Nil
      }
  }
}

/// Publish one completed phase with a redacted typed result.
pub fn phase_finished(
  trace trace: Option(Trace),
  phase phase: diagnostics.ClientPhase,
  outcome outcome: Result(Nil, error.Error),
) -> Nil {
  case trace {
    None -> Nil
    Some(trace) ->
      case phase_transition(trace.state, phase_code(phase), 2) {
        True ->
          emit(
            Some(trace),
            diagnostics.PhaseFinished(trace.attempt, phase, outcome),
          )
        False -> Nil
      }
  }
}

/// Preserve original native times and candidates, including partial snapshots.
pub fn http3_snapshot(
  trace trace: Option(Trace),
  snapshot snapshot: h3_client.ConnectSnapshot,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) -> {
      list.each(snapshot.events, fn(event) {
        let phase = case event.phase {
          h3_client.NameResolution ->
            diagnostics.NameResolution(diagnostics.Quic)
          h3_client.UdpOpen -> diagnostics.ConnectionAttempt(diagnostics.Quic)
          h3_client.TlsHandshake -> diagnostics.TlsHandshake(diagnostics.Quic)
          h3_client.OwnershipPublication ->
            diagnostics.ConnectionOwnership(diagnostics.Quic)
        }
        let progress = case event.outcome {
          h3_client.Started -> diagnostics.ConnectStarted
          h3_client.Succeeded -> diagnostics.ConnectSucceeded
          h3_client.Failed -> diagnostics.ConnectFailed
          h3_client.Abandoned -> diagnostics.ConnectAbandoned
          h3_client.Skipped -> diagnostics.ConnectSkipped
        }
        emit(
          trace,
          diagnostics.ConnectObserved(
            active.attempt,
            diagnostics.Quic,
            event.sequence,
            event.attempt,
            event.candidate,
            phase,
            progress,
            event.elapsed_milliseconds,
          ),
        )
      })
      emit(
        trace,
        diagnostics.ConnectTraceFinished(
          active.attempt,
          diagnostics.Quic,
          snapshot.consistent,
          snapshot.dropped,
        ),
      )
    }
  }
}

/// Copy one completed TCP/TLS snapshot without endpoints or backend failures.
pub fn tcp_snapshot(
  trace trace: Option(Trace),
  snapshot snapshot: transport.DiagnosticSnapshot,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) -> {
      list.index_fold(snapshot.events, Nil, fn(_, event, sequence) {
        tcp_event(trace: active, event: event, sequence: sequence + 1)
      })
      emit(
        trace,
        diagnostics.ConnectTraceFinished(
          active.attempt,
          diagnostics.Tcp,
          snapshot.consistent,
          snapshot.dropped_events,
        ),
      )
    }
  }
}

fn tcp_event(
  trace trace: Trace,
  event event: transport.DiagnosticEvent,
  sequence sequence: Int,
) -> Nil {
  let phase = case event.step {
    transport.DnsStarted | transport.DnsCompleted ->
      Some(diagnostics.NameResolution(diagnostics.Tcp))
    transport.DialStarted | transport.DialCompleted ->
      Some(diagnostics.ConnectionAttempt(diagnostics.Tcp))
    transport.ClientTlsStarted | transport.ClientTlsCompleted ->
      Some(diagnostics.TlsHandshake(diagnostics.Tcp))
    transport.OwnershipStarted | transport.ConnectionCompleted ->
      Some(diagnostics.ConnectionOwnership(diagnostics.Tcp))
    _ -> None
  }
  case phase {
    None -> Nil
    Some(phase) -> {
      let progress = case event.outcome {
        transport.Pending -> diagnostics.ConnectStarted
        transport.Successful -> diagnostics.ConnectSucceeded
        transport.Failed(_) -> diagnostics.ConnectFailed
        transport.Abandoned -> diagnostics.ConnectAbandoned
      }
      emit(
        Some(trace),
        diagnostics.ConnectObserved(
          trace.attempt,
          diagnostics.Tcp,
          sequence,
          1,
          event.attempt,
          phase,
          progress,
          event.elapsed_milliseconds,
        ),
      )
    }
  }
}

/// Record final response headers exactly once, before terminal wire cleanup.
pub fn headers(
  trace trace: Option(Trace),
  protocol protocol: context.Protocol,
  status status: Int,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) ->
      case record_headers(active.state) {
        False -> Nil
        True -> {
          let admitted =
            publish_stage(
              active,
              diagnostics.ResponseHeaders(active.attempt, protocol, status),
            )
          case admitted {
            True -> publish_headers(active.state)
            False -> Nil
          }
          maybe_publish_success(active)
        }
      }
  }
}

/// Consumer EOF is independent of protocol transfer and resource completion.
pub fn read_finished(
  trace trace: Option(Trace),
  protocol protocol: context.Protocol,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) ->
      case record_read(active.state) {
        False -> Nil
        True -> {
          let admitted =
            publish_stage(
              active,
              diagnostics.ResponseReadFinished(active.attempt, protocol),
            )
          case admitted {
            True -> publish_read(active.state)
            False -> Nil
          }
          maybe_publish_success(active)
        }
      }
  }
}

/// Record the actual protocol result once for this attempt.
pub fn finished(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  outcome outcome: Result(Nil, error.Error),
) -> Nil {
  let _recorded = finish_with(trace, protocol, outcome, record_finished)
  Nil
}

/// Supply an outer-dispatch failure only when no lower adapter recorded one.
/// An existing typed protocol terminal remains authoritative and is not counted as a duplicate transition.
@internal
pub fn finished_if_missing(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  outcome outcome: Result(Nil, error.Error),
) -> Nil {
  let _recorded =
    finish_with(trace, protocol, outcome, record_finished_if_missing)
  Nil
}

/// Claim and publish an outer-dispatch terminal only when no protocol adapter established one.
/// `True` identifies a request body that is still owned by the unified boundary and must be disposed there.
@internal
pub fn claim_finished_if_missing(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  outcome outcome: Result(Nil, error.Error),
) -> Bool {
  finish_with(trace, protocol, outcome, record_finished_if_missing)
}

fn finish_with(
  trace: Option(Trace),
  protocol: Option(context.Protocol),
  outcome: Result(Nil, error.Error),
  record: fn(AttemptState, Bool) -> Bool,
) -> Bool {
  case trace {
    None -> True
    Some(active) -> {
      record_cancellation(active, outcome)
      use <- bool.guard(
        when: !record(active.state, result.is_ok(outcome)),
        return: False,
      )
      let admitted =
        publish_stage(
          active,
          diagnostics.AttemptFinished(active.attempt, protocol, outcome),
        )
      case admitted {
        True -> publish_finished(active.state)
        False -> Nil
      }
      publish_pending_release(active)
      maybe_publish_success(active)
      True
    }
  }
}

fn record_cancellation(
  active: Trace,
  outcome: Result(Nil, error.Error),
) -> Nil {
  case outcome {
    Error(failure) ->
      case error.kind(failure) {
        error.Cancelled ->
          case claim(active.cancellation) {
            False -> Nil
            True -> {
              phase_started(
                trace: Some(active),
                phase: diagnostics.Cancellation,
              )
              phase_finished(
                trace: Some(active),
                phase: diagnostics.Cancellation,
                outcome: Error(failure),
              )
            }
          }
        _ -> Nil
      }
    _ -> Nil
  }
}

fn phase_code(phase: diagnostics.ClientPhase) -> Int {
  case phase {
    diagnostics.NameResolution(diagnostics.Tcp) -> 1
    diagnostics.NameResolution(diagnostics.Quic) -> 2
    diagnostics.ConnectionAttempt(diagnostics.Tcp) -> 3
    diagnostics.ConnectionAttempt(diagnostics.Quic) -> 4
    diagnostics.TlsHandshake(diagnostics.Tcp) -> 5
    diagnostics.TlsHandshake(diagnostics.Quic) -> 6
    diagnostics.ConnectionOwnership(diagnostics.Tcp) -> 7
    diagnostics.ConnectionOwnership(diagnostics.Quic) -> 8
    diagnostics.ProtocolSelection(context.Http1) -> 9
    diagnostics.ProtocolSelection(context.Http2) -> 10
    diagnostics.ProtocolSelection(context.Http3) -> 11
    diagnostics.RequestTransmission(context.Http1) -> 12
    diagnostics.RequestTransmission(context.Http2) -> 13
    diagnostics.RequestTransmission(context.Http3) -> 14
    diagnostics.ResponseReception(context.Http1) -> 15
    diagnostics.ResponseReception(context.Http2) -> 16
    diagnostics.ResponseReception(context.Http3) -> 17
    diagnostics.ResourceAdmission -> 18
    diagnostics.Cancellation -> 19
    diagnostics.ResourceRelease -> 20
  }
}

/// Record actual resource cleanup once; a body EOF cannot imply this event.
pub fn released(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  cleanup cleanup: Result(Nil, error.Error),
) -> Nil {
  release_with(trace, protocol, cleanup, record_release)
}

/// Supply cleanup for a request that failed before protocol ownership.
/// An adapter's already-recorded release remains authoritative and is not counted as a duplicate transition.
@internal
pub fn released_if_missing(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  cleanup cleanup: Result(Nil, error.Error),
) -> Nil {
  release_with(trace, protocol, cleanup, record_release_if_missing)
}

/// Complete a fallback release after its protocol coordinator has exited.
/// Already-recorded cleanup and phase transitions remain authoritative.
@internal
pub fn cleanup_failed_if_missing(
  trace trace: Option(Trace),
  protocol protocol: Option(context.Protocol),
  failure failure: error.Error,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) -> {
      let recorded =
        record_release_if_missing(
          active.state,
          protocol_code(protocol),
          outcome_code(Error(failure)),
        )
      case recorded {
        False -> Nil
        True -> record_cleanup_failure_phases(active, failure)
      }
      publish_pending_release(active)
      maybe_publish_success(active)
    }
  }
}

fn record_cleanup_failure_phases(active: Trace, failure: error.Error) -> Nil {
  let phase = diagnostics.ResourceRelease
  case phase_transition_if_missing(active.state, phase_code(phase), 1) {
    True -> emit(Some(active), diagnostics.PhaseStarted(active.attempt, phase))
    False -> Nil
  }
  case phase_transition_if_missing(active.state, phase_code(phase), 2) {
    True ->
      emit(
        Some(active),
        diagnostics.PhaseFinished(active.attempt, phase, Error(failure)),
      )
    False -> Nil
  }
}

fn release_with(
  trace: Option(Trace),
  protocol: Option(context.Protocol),
  cleanup: Result(Nil, error.Error),
  record: fn(AttemptState, Int, Int) -> Bool,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) -> {
      let _recorded =
        record(active.state, protocol_code(protocol), outcome_code(cleanup))
      publish_pending_release(active)
      maybe_publish_success(active)
    }
  }
}

/// Record the logical result only for its final body, never an intermediate retry.
pub fn exchange_finished(
  trace trace: Option(Trace),
  outcome outcome: Result(Nil, error.Error),
) -> Nil {
  case trace, outcome {
    None, _ -> Nil
    Some(_), Error(failure) ->
      emit_once(
        trace: trace,
        token: fn(current) { current.exchange_finished },
        stage: fn(_) { diagnostics.ExchangeFinished(Error(failure)) },
      )
    Some(active), Ok(Nil) -> {
      request_success(active.state)
      maybe_publish_success(active)
    }
  }
}

fn publish_pending_release(active: Trace) -> Nil {
  let #(ready, protocol, outcome) = take_release(active.state)
  use <- bool.guard(when: !ready, return: Nil)
  let admitted =
    publish_stage(
      active,
      diagnostics.AttemptReleased(
        active.attempt,
        protocol_from_code(protocol),
        outcome_from_code(outcome),
      ),
    )
  use <- bool.guard(when: !admitted, return: Nil)
  publish_release(active.state)
  case outcome_from_code(outcome) {
    Ok(Nil) -> Nil
    Error(failure) ->
      exchange_finished(trace: Some(active), outcome: Error(failure))
  }
}

fn maybe_publish_success(active: Trace) -> Nil {
  use <- bool.guard(
    when: !{ success_ready(active.state) && claim(active.exchange_finished) },
    return: Nil,
  )
  let _admitted = publish_stage(active, diagnostics.ExchangeFinished(Ok(Nil)))
  Nil
}

/// Inspect only bounded transition anomaly counts, never retained payloads.
@internal
pub fn transition_snapshot(trace: Option(Trace)) -> TransitionSnapshot {
  case trace {
    None -> TransitionSnapshot(0, 0, 0)
    Some(active) -> {
      let #(_, duplicates, out_of_order, late) =
        raw_transition_snapshot(active.state)
      TransitionSnapshot(duplicates:, out_of_order:, late:)
    }
  }
}

fn protocol_code(protocol: Option(context.Protocol)) -> Int {
  case protocol {
    None -> 0
    Some(context.Http1) -> 1
    Some(context.Http2) -> 2
    Some(context.Http3) -> 3
  }
}

fn protocol_from_code(code: Int) -> Option(context.Protocol) {
  case code {
    1 -> Some(context.Http1)
    2 -> Some(context.Http2)
    3 -> Some(context.Http3)
    _ -> None
  }
}

fn outcome_code(outcome: Result(Nil, error.Error)) -> Int {
  case outcome {
    Ok(Nil) -> 1
    Error(failure) -> failure_code(error.kind(failure))
  }
}

fn failure_code(kind: error.ErrorKind) -> Int {
  case kind {
    error.Dns -> 2
    error.ConnectFailed -> 3
    error.Tls -> 4
    error.Timeout(error.DnsLookup) -> 5
    error.Timeout(error.Connect) -> 6
    error.Timeout(error.TlsHandshake) -> 7
    error.Timeout(error.Operation) -> 8
    error.Timeout(error.Idle) -> 9
    error.Timeout(error.Total) -> 10
    error.Protocol(error.Http1) -> 11
    error.Protocol(error.Http2) -> 12
    error.Protocol(error.Http3) -> 13
    error.Protocol(error.Quic) -> 14
    error.Policy(error.RedirectPolicy) -> 15
    error.Policy(error.RetryPolicy) -> 16
    error.Policy(error.SecurityPolicy) -> 17
    error.Policy(error.ProxyPolicy) -> 18
    error.Policy(error.CachePolicy) -> 19
    error.Body(error.InvalidLimit) -> 20
    error.Body(error.ReadFailed) -> 21
    error.Body(error.TooLarge(_)) -> 22
    error.Body(error.InvalidChunk) -> 23
    error.Body(error.LengthMismatch(_, _)) -> 24
    error.Body(error.NotReplayable) -> 25
    error.Resource(error.Connections) -> 26
    error.Resource(error.Streams) -> 27
    error.Resource(error.RequestWorkers) -> 28
    error.Resource(error.Memory) -> 29
    error.Resource(error.Queue) -> 30
    error.Resource(error.BufferedBody) -> 31
    error.Resource(error.FileHandles) -> 32
    error.Cancelled -> 33
    error.Service -> 34
  }
}

/// Round-trip the payload-free deferred-release classification codec.
/// Value-bearing body counts are canonicalised to zero.
@internal
pub fn release_classification_round_trip(
  kind: error.ErrorKind,
) -> error.ErrorKind {
  case outcome_from_code(failure_code(kind)) {
    Ok(Nil) -> error.Service
    Error(failure) -> error.kind(failure)
  }
}

fn outcome_from_code(code: Int) -> Result(Nil, error.Error) {
  case code {
    1 -> Ok(Nil)
    2 -> Error(error.new(error.Dns))
    3 -> Error(error.new(error.ConnectFailed))
    4 -> Error(error.new(error.Tls))
    5 -> Error(error.new(error.Timeout(error.DnsLookup)))
    6 -> Error(error.new(error.Timeout(error.Connect)))
    7 -> Error(error.new(error.Timeout(error.TlsHandshake)))
    8 -> Error(error.new(error.Timeout(error.Operation)))
    9 -> Error(error.new(error.Timeout(error.Idle)))
    10 -> Error(error.new(error.Timeout(error.Total)))
    11 -> Error(error.new(error.Protocol(error.Http1)))
    12 -> Error(error.new(error.Protocol(error.Http2)))
    13 -> Error(error.new(error.Protocol(error.Http3)))
    14 -> Error(error.new(error.Protocol(error.Quic)))
    15 -> Error(error.new(error.Policy(error.RedirectPolicy)))
    16 -> Error(error.new(error.Policy(error.RetryPolicy)))
    17 -> Error(error.new(error.Policy(error.SecurityPolicy)))
    18 -> Error(error.new(error.Policy(error.ProxyPolicy)))
    19 -> Error(error.new(error.Policy(error.CachePolicy)))
    20 -> Error(error.new(error.Body(error.InvalidLimit)))
    21 -> Error(error.new(error.Body(error.ReadFailed)))
    // Counts are configuration or peer influenced, so a deferred release preserves the public constructor while canonicalising values to zero.
    22 -> Error(error.new(error.Body(error.TooLarge(0))))
    23 -> Error(error.new(error.Body(error.InvalidChunk)))
    24 -> Error(error.new(error.Body(error.LengthMismatch(0, 0))))
    25 -> Error(error.new(error.Body(error.NotReplayable)))
    26 -> Error(error.new(error.Resource(error.Connections)))
    27 -> Error(error.new(error.Resource(error.Streams)))
    28 -> Error(error.new(error.Resource(error.RequestWorkers)))
    29 -> Error(error.new(error.Resource(error.Memory)))
    30 -> Error(error.new(error.Resource(error.Queue)))
    31 -> Error(error.new(error.Resource(error.BufferedBody)))
    32 -> Error(error.new(error.Resource(error.FileHandles)))
    33 -> Error(error.new(error.Cancelled))
    _ -> Error(error.new(error.Service))
  }
}

fn emit_once(
  trace trace: Option(Trace),
  token token: fn(Trace) -> Once,
  stage stage: fn(Trace) -> diagnostics.ClientStage,
) -> Nil {
  case trace {
    None -> Nil
    Some(active) ->
      case claim(token(active)) {
        True -> emit(trace, stage(active))
        False -> Nil
      }
  }
}

fn emit(trace: Option(Trace), stage: diagnostics.ClientStage) -> Nil {
  case trace {
    None -> Nil
    Some(trace) -> {
      let _admitted = publish_stage(trace, stage)
      Nil
    }
  }
}

fn publish_stage(trace: Trace, stage: diagnostics.ClientStage) -> Bool {
  diagnostics.emit(
    trace.reporter,
    diagnostics.ClientObserved(
      trace.request_id,
      elapsed_milliseconds(started: trace.started, observed: now()),
      stage,
    ),
  )
}

/// Project an injected monotonic clock sample into a safe elapsed scalar.
@internal
pub fn elapsed_milliseconds(
  started started: Int,
  observed observed: Int,
) -> Int {
  int.max(0, observed - started)
}
