//// Bounded, payload-free application diagnostics.

import gleam/erlang/process.{type Monitor, type Pid}
import gleam/option.{type Option}
import http/context
import http/error
import http/internal/diagnostic_delivery
import http/internal/process_role

const maximum_limit = 2_147_483_647

const shutdown_margin_milliseconds = 100

type Credit

/// A payload-free identifier shared by every event for one request attempt.
/// Every request reaching the common server boundary receives an identifier before resource admission.
/// Refused and pre-admission-cancelled attempts can therefore correlate their start, terminal decision, and source release without exposing request or endpoint data.
///
/// Values are monotonic within the BEAM instance.
/// They contain no endpoint,
/// path, header, body, certificate, process identifier, or backend term.
pub opaque type RequestId {
  RequestId(value: Int)
}

/// Candidate transport without an endpoint, hostname, or connection handle.
pub type ClientTransport {
  Tcp
  Quic
}

/// Common client phases.
/// Protocol and transport labels contain no peer data.
pub type ClientPhase {
  NameResolution(transport: ClientTransport)
  ConnectionAttempt(transport: ClientTransport)
  TlsHandshake(transport: ClientTransport)
  ConnectionOwnership(transport: ClientTransport)
  ProtocolSelection(protocol: context.Protocol)
  RequestTransmission(protocol: context.Protocol)
  ResponseReception(protocol: context.Protocol)
  ResourceAdmission
  Cancellation
  ResourceRelease
}

/// Native connect progress; failure records carry no native exception values.
pub type ClientConnectProgress {
  ConnectStarted
  ConnectSucceeded
  ConnectFailed
  ConnectAbandoned
  ConnectSkipped
}

/// One observation within a logical client exchange.
/// Attempt identifiers are positive opaque numbers, not endpoints or retry counts.
/// Redirects and retries keep the same request identifier and receive distinct attempts.
///
/// Connect observations retain their native trace's elapsed time and sequence;
/// they are sampled after connection selection and can contain unfinished phases from losing candidates.
/// `ConnectTraceFinished` reports that sample's consistency and dropped records, without inventing completion events.
///
/// Attempt completion describes wire framing.
/// Release follows worker exit,
/// source disposal and connection cleanup or pool publication.
/// Consumer EOF is separate.
/// A successful logical exchange is admitted only after response headers, successful wire completion, consumer EOF, and release have each been admitted in causal order.
/// A terminal body failure can therefore never be replaced by success derived from headers or EOF alone.
pub type ClientStage {
  ExchangeStarted
  AttemptStarted(attempt: Int)
  ConnectObserved(
    attempt: Int,
    transport: ClientTransport,
    sequence: Int,
    native_attempt: Int,
    candidate: Int,
    phase: ClientPhase,
    progress: ClientConnectProgress,
    elapsed_milliseconds: Int,
  )
  ConnectTraceFinished(
    attempt: Int,
    transport: ClientTransport,
    consistent: Bool,
    dropped: Int,
  )
  PhaseStarted(attempt: Int, phase: ClientPhase)
  PhaseFinished(
    attempt: Int,
    phase: ClientPhase,
    outcome: Result(Nil, error.Error),
  )
  ResponseHeaders(attempt: Int, protocol: context.Protocol, status: Int)
  ResponseReadFinished(attempt: Int, protocol: context.Protocol)
  AttemptFinished(
    attempt: Int,
    protocol: Option(context.Protocol),
    outcome: Result(Nil, error.Error),
  )
  AttemptReleased(
    attempt: Int,
    protocol: Option(context.Protocol),
    cleanup: Result(Nil, error.Error),
  )
  ExchangeFinished(outcome: Result(Nil, error.Error))
}

/// Redacted client, server, and request observations.
///
/// Events intentionally contain no host, path, query, headers, body bytes,
/// certificate bytes, backend terms, or handler exception reason.
/// `RequestStarted` means that the common server boundary accepted the typed request attempt; it precedes resource admission and handler creation.
/// `RequestRefused` is the terminal resource decision for an unadmitted attempt.
/// The server offers one terminal decision and one `RequestReleased` for every started attempt, including when no worker was created.
/// A bounded reporter may still reject an event when its configured capacity is full.
pub type Event {
  ClientObserved(
    request_id: RequestId,
    elapsed_milliseconds: Int,
    stage: ClientStage,
  )
  RequestStarted(request_id: RequestId, protocol: context.Protocol)
  HandlerFinished(
    request_id: RequestId,
    protocol: context.Protocol,
    status: Int,
    elapsed_milliseconds: Int,
  )
  ResponseBodyReadFinished(
    request_id: RequestId,
    protocol: context.Protocol,
    elapsed_milliseconds: Int,
  )
  RequestFinished(
    request_id: RequestId,
    protocol: context.Protocol,
    status: Int,
    elapsed_milliseconds: Int,
  )
  RequestFailed(
    request_id: RequestId,
    protocol: context.Protocol,
    failure: error.Error,
    elapsed_milliseconds: Int,
  )
  RequestRefused(
    request_id: RequestId,
    protocol: context.Protocol,
    resource: error.ResourceKind,
  )
  RequestReleased(
    request_id: RequestId,
    protocol: context.Protocol,
    cleanup: Result(Nil, error.Error),
    elapsed_milliseconds: Int,
  )
  ServerDraining
  HandlerReloaded
  ServerStopped
}

/// One admitted diagnostic event and its reporter-local causal sequence.
///
/// Sink callbacks may finish out of order.
/// Sorting by `sequence` reconstructs the order in which `emit` admitted records without serialising application callbacks.
pub type Observation {
  Observation(sequence: Int, monotonic_milliseconds: Int, event: Event)
}

/// A diagnostic callback.
/// Its return value carries no application payload.
pub type Sink =
  fn(Observation) -> Result(Nil, Nil)

/// One bounded diagnostic bridge.
pub opaque type Reporter {
  Reporter(credit: Credit, sink_timeout_milliseconds: Int, sink: Sink)
}

/// Current diagnostic delivery counters.
/// `in_flight` includes a killed sink whose termination could not yet be confirmed; that finite quarantine keeps `stop` fail-closed without admitting replacement callbacks.
pub type Snapshot {
  Snapshot(in_flight: Int, delivered: Int, dropped: Int, sink_failures: Int)
}

@external(erlang, "http_server_ffi", "new_diagnostic_credit")
fn new_credit(maximum: Int) -> Result(Credit, Nil)

@external(erlang, "http_server_ffi", "diagnostic_reserve")
fn reserve(credit: Credit) -> Int

@external(erlang, "http_server_ffi", "new_diagnostic_request_id")
fn unique_request_id() -> Int

@external(erlang, "http_server_ffi", "diagnostic_complete")
fn complete(credit: Credit, delivered: Bool) -> Nil

@external(erlang, "http_server_ffi", "diagnostic_abandon")
fn abandon(credit: Credit) -> Nil

@external(erlang, "http_server_ffi", "diagnostic_snapshot")
fn raw_snapshot(credit: Credit) -> #(Int, Int, Int, Int)

@external(erlang, "http_server_ffi", "diagnostic_close")
fn close_credit(credit: Credit) -> Nil

@external(erlang, "http_server_ffi", "run_guarded")
fn run_guarded(run: fn() -> value) -> Result(value, Nil)

@external(erlang, "http_server_ffi", "spawn_monitor")
fn spawn_monitor(run: fn() -> Nil) -> #(Pid, Monitor)

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

/// Construct a finite non-blocking diagnostic bridge.
pub fn start(
  maximum_in_flight maximum_in_flight: Int,
  sink_timeout_milliseconds sink_timeout_milliseconds: Int,
  sink sink: Sink,
) -> Result(Reporter, error.Error) {
  case
    maximum_in_flight > 0
    && maximum_in_flight <= maximum_limit
    && sink_timeout_milliseconds > 0
    && sink_timeout_milliseconds <= maximum_limit
  {
    True ->
      case new_credit(maximum_in_flight) {
        Ok(credit) -> Ok(Reporter(credit:, sink_timeout_milliseconds:, sink:))
        Error(Nil) -> Error(error.new(error.Resource(error.Memory)))
      }
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Allocate a redacted identifier for one request attempt.
///
/// Servers allocate this before resource admission so refusals, cancellation,
/// and admitted requests use the same correlation contract.
pub fn request_id() -> RequestId {
  RequestId(unique_request_id())
}

/// Return the positive numeric form used by structured log exporters.
pub fn request_id_value(request_id: RequestId) -> Int {
  request_id.value
}

/// Offer one event without waiting for the application sink.
///
/// `False` means the finite bridge was full, had already stopped, exhausted its unique sequence space, or could not start its owned guardian.
/// The event is counted as dropped in every case.
pub fn emit(reporter: Reporter, event: Event) -> Bool {
  case reserve(reporter.credit) {
    0 -> False
    sequence -> {
      let record =
        Observation(
          sequence:,
          monotonic_milliseconds: monotonic_millisecond(),
          event:,
        )
      case run_guarded(fn() { start_delivery(reporter, record) }) {
        Ok(_) -> True
        Error(Nil) -> {
          abandon(reporter.credit)
          False
        }
      }
    }
  }
}

fn start_delivery(reporter: Reporter, record: Observation) -> Pid {
  process.spawn_unlinked(fn() {
    process_role.set(process_role.DiagnosticGuardian)
    supervise_delivery(reporter, record)
  })
}

/// Inspect bounded delivery counters.
pub fn snapshot(reporter: Reporter) -> Snapshot {
  let #(in_flight, delivered, dropped, sink_failures) =
    raw_snapshot(reporter.credit)
  Snapshot(in_flight:, delivered:, dropped:, sink_failures:)
}

/// Refuse new events and wait a finite interval for admitted sinks.
/// A sink whose termination is still unconfirmed returns a typed operation timeout;
/// its slot remains quarantined if the final bounded observation also expires.
pub fn stop(reporter: Reporter) -> Result(Nil, error.Error) {
  close_credit(reporter.credit)
  await_empty(
    reporter,
    monotonic_millisecond()
      + reporter.sink_timeout_milliseconds
      + shutdown_margin_milliseconds,
  )
}

fn supervise_delivery(reporter: Reporter, record: Observation) -> Nil {
  let completed = process.new_subject()
  let started =
    run_guarded(fn() {
      spawn_monitor(fn() {
        process_role.set(process_role.DiagnosticSink)
        process.send(completed, run_guarded(fn() { reporter.sink(record) }))
      })
    })
  case started {
    Error(Nil) -> abandon(reporter.credit)
    Ok(#(sink_pid, sink_monitor)) -> {
      let delivered =
        diagnostic_delivery.await(
          sink_pid,
          sink_monitor,
          completed,
          reporter.sink_timeout_milliseconds,
        )
      finish_delivery(reporter, sink_pid, delivered)
    }
  }
}

fn finish_delivery(
  reporter: Reporter,
  sink_pid: Pid,
  delivered: diagnostic_delivery.Outcome,
) -> Nil {
  case delivered {
    diagnostic_delivery.Delivered -> complete(reporter.credit, True)
    diagnostic_delivery.Failed -> complete(reporter.credit, False)
    diagnostic_delivery.Unconfirmed -> {
      // One final bounded observation may return the credit.
      // Otherwise it stays quarantined and every `stop` remains fail-closed.
      case
        diagnostic_delivery.reap(
          sink: sink_pid,
          milliseconds: shutdown_margin_milliseconds,
        )
      {
        True -> complete(reporter.credit, False)
        False -> Nil
      }
    }
  }
}

fn await_empty(
  reporter: Reporter,
  deadline_milliseconds: Int,
) -> Result(Nil, error.Error) {
  case snapshot(reporter).in_flight, monotonic_millisecond() {
    0, _ -> Ok(Nil)
    _, now if now >= deadline_milliseconds ->
      Error(error.new(error.Timeout(error.Operation)))
    _, _ -> {
      process.sleep(1)
      await_empty(reporter, deadline_milliseconds)
    }
  }
}
