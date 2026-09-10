//// Bounded, payload-free application diagnostics.

import gleam/erlang/process.{type Monitor, type Pid}
import http/context
import http/error

const maximum_limit = 2_147_483_647

const shutdown_margin_milliseconds = 100

type Credit

/// A payload-free identifier shared by every event for one admitted request.
///
/// Values are monotonic within the BEAM instance. They contain no endpoint,
/// path, header, body, certificate, process identifier, or backend term.
pub opaque type RequestId {
  RequestId(value: Int)
}

/// Redacted server lifecycle and request observations.
///
/// Events intentionally contain no host, path, query, headers, body bytes,
/// certificate bytes, backend terms, or handler exception reason.
pub type Event {
  RequestStarted(request_id: RequestId, protocol: context.Protocol)
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
  RequestRefused(resource: error.ResourceKind)
  ServerDraining
  HandlerReloaded
  ServerStopped
}

/// One admitted diagnostic event and its reporter-local causal sequence.
///
/// Sink callbacks may finish out of order. Sorting by `sequence` reconstructs
/// the order in which `emit` admitted records without serialising application
/// callbacks.
pub type Observation {
  Observation(sequence: Int, event: Event)
}

/// A diagnostic callback. Its return value carries no application payload.
pub type Sink =
  fn(Observation) -> Result(Nil, Nil)

/// One bounded diagnostic bridge.
pub opaque type Reporter {
  Reporter(credit: Credit, sink_timeout_milliseconds: Int, sink: Sink)
}

/// Current diagnostic delivery counters.
pub type Snapshot {
  Snapshot(in_flight: Int, delivered: Int, dropped: Int, sink_failures: Int)
}

type Delivery {
  SinkResult(Result(Result(Nil, Nil), Nil))
  SinkDown
}

@external(erlang, "http_server_ffi", "new_diagnostic_credit")
fn new_credit(maximum: Int) -> Credit

@external(erlang, "http_server_ffi", "diagnostic_reserve")
fn reserve(credit: Credit) -> Int

@external(erlang, "http_server_ffi", "new_diagnostic_request_id")
fn unique_request_id() -> Int

@external(erlang, "http_server_ffi", "diagnostic_complete")
fn complete(credit: Credit, delivered: Bool) -> Nil

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
      Ok(Reporter(
        credit: new_credit(maximum_in_flight),
        sink_timeout_milliseconds:,
        sink:,
      ))
    False -> Error(error.new(error.Policy(error.SecurityPolicy)))
  }
}

/// Allocate a redacted identifier for one admitted request trace.
pub fn request_id() -> RequestId {
  RequestId(unique_request_id())
}

/// Return the positive numeric form used by structured log exporters.
pub fn request_id_value(request_id: RequestId) -> Int {
  request_id.value
}

/// Offer one event without waiting for the application sink.
///
/// `False` means the finite bridge was full or had already stopped. The event
/// is counted as dropped in either case.
pub fn emit(reporter: Reporter, event: Event) -> Bool {
  case reserve(reporter.credit) {
    0 -> False
    sequence -> {
      let _supervisor =
        process.spawn_unlinked(fn() {
          supervise_delivery(reporter, Observation(sequence:, event:))
        })
      True
    }
  }
}

/// Inspect bounded delivery counters.
pub fn snapshot(reporter: Reporter) -> Snapshot {
  let #(in_flight, delivered, dropped, sink_failures) =
    raw_snapshot(reporter.credit)
  Snapshot(in_flight:, delivered:, dropped:, sink_failures:)
}

/// Refuse new events and wait a finite interval for admitted sinks.
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
  let #(sink_pid, sink_monitor) =
    spawn_monitor(fn() {
      process.send(completed, run_guarded(fn() { reporter.sink(record) }))
    })
  let selector =
    process.new_selector()
    |> process.select_map(completed, SinkResult)
    |> process.select_specific_monitor(sink_monitor, fn(_) { SinkDown })
  let outcome =
    process.selector_receive(
      selector,
      within: reporter.sink_timeout_milliseconds,
    )
  let delivered = case outcome {
    Ok(SinkResult(Ok(Ok(Nil)))) -> True
    Ok(SinkResult(_)) -> False
    Ok(SinkDown) -> False
    Error(Nil) -> {
      process.kill(sink_pid)
      False
    }
  }
  process.demonitor_process(sink_monitor)
  complete(reporter.credit, delivered)
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
