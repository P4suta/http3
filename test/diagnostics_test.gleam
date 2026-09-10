import gleam/bool
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleeunit
import http/body
import http/context
import http/diagnostics
import http/error
import http/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn diagnostic_events_are_typed_and_contain_no_request_payload_test() -> Nil {
  let delivered = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 2,
      sink_timeout_milliseconds: 100,
      sink: fn(event) {
        process.send(delivered, event)
        Ok(Nil)
      },
    )
  let request_id = diagnostics.request_id()
  let event =
    diagnostics.RequestFailed(
      request_id,
      context.Http3,
      error.new(error.Protocol(error.Http3)),
      elapsed_milliseconds: 7,
    )

  assert diagnostics.emit(reporter, event)
  assert process.receive(delivered, within: 1000)
    == Ok(diagnostics.Observation(sequence: 1, event:))
  assert diagnostics.request_id_value(request_id) > 0
  assert await_delivered(reporter, 1, 100)
  assert diagnostics.snapshot(reporter)
    == diagnostics.Snapshot(
      in_flight: 0,
      delivered: 1,
      dropped: 0,
      sink_failures: 0,
    )
  assert diagnostics.stop(reporter) == Ok(Nil)
  assert !diagnostics.emit(reporter, diagnostics.ServerStopped)
  assert diagnostics.snapshot(reporter).dropped == 1
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn diagnostic_sink_timeout_and_overload_are_bounded_test() -> Nil {
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 1,
      sink_timeout_milliseconds: 10,
      sink: fn(_) {
        process.sleep(1000)
        Ok(Nil)
      },
    )

  assert diagnostics.emit(reporter, diagnostics.ServerDraining)
  assert !diagnostics.emit(reporter, diagnostics.HandlerReloaded)
  assert await_failures(reporter, 1, 200)
  let snapshot = diagnostics.snapshot(reporter)
  assert snapshot.in_flight == 0
  assert snapshot.delivered == 0
  assert snapshot.dropped == 1
  assert snapshot.sink_failures == 1
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn diagnostic_sink_panic_is_isolated_and_redacted_test() -> Nil {
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 1,
      sink_timeout_milliseconds: 100,
      sink: fn(_) { panic as "diagnostic-secret" },
    )

  assert diagnostics.emit(reporter, diagnostics.ServerStopped)
  assert await_failures(reporter, 1, 200)
  assert diagnostics.snapshot(reporter).sink_failures == 1
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn causal_sequence_survives_out_of_order_sink_completion_test() -> Nil {
  let entered = process.new_subject()
  let delivered = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 2,
      sink_timeout_milliseconds: 1000,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestStarted(_, _) -> {
            let release = process.new_subject()
            process.send(entered, release)
            let _released = process.receive(release, within: 1000)
            Nil
          }
          _ -> Nil
        }
        process.send(delivered, record)
        Ok(Nil)
      },
    )
  let request_id = diagnostics.request_id()
  let started = diagnostics.RequestStarted(request_id, context.Http2)
  let failed =
    diagnostics.RequestFailed(
      request_id,
      context.Http2,
      error.new(error.Cancelled),
      elapsed_milliseconds: 3,
    )

  assert diagnostics.emit(reporter, started)
  let assert Ok(release) = process.receive(entered, within: 1000)
  assert diagnostics.emit(reporter, failed)
  assert process.receive(delivered, within: 1000)
    == Ok(diagnostics.Observation(sequence: 2, event: failed))
  process.send(release, Nil)
  assert process.receive(delivered, within: 1000)
    == Ok(diagnostics.Observation(sequence: 1, event: started))
  assert await_delivered(reporter, 2, 100)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn server_cancellation_trace_has_one_correlated_start_and_failure_test() -> Nil {
  let delivered = process.new_subject()
  let started = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 4,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        process.send(delivered, record)
        Ok(Nil)
      },
    )
  let configuration = server.with_diagnostics(server.defaults(), reporter)
  let assert Ok(running) =
    server.start(configuration, fn(_, _) {
      process.send(started, Nil)
      process.sleep(1000)
      Ok(response.new(204) |> response.set_body(body.empty()))
    })
  let metadata = test_context()
  let task =
    http_test_support.start_task(fn() {
      server.handle(
        running,
        request.new()
          |> request.set_path("/cancel")
          |> request.set_body(body.empty()),
        metadata,
      )
    })
  assert process.receive(started, within: 1000) == Ok(Nil)

  context.cancel(metadata)

  let assert Error(failure) = http_test_support.await_task(task)
  assert error.kind(failure) == error.Cancelled
  let assert Ok(first) = process.receive(delivered, within: 1000)
  let assert Ok(second) = process.receive(delivered, within: 1000)
  assert_cancel_trace(first, second)
  assert server.stop(running) == Ok(Nil)
  assert await_delivered(reporter, 3, 100)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn diagnostic_sequence_is_unique_under_250_concurrent_emitters_test() -> Nil {
  let delivered = process.new_subject()
  let accepted = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 250,
      sink_timeout_milliseconds: 1000,
      sink: fn(observation) {
        process.send(delivered, observation)
        Ok(Nil)
      },
    )

  spawn_diagnostic_emitters(reporter, accepted, 250)
  assert receive_acceptances(accepted, 250)
  let sequences = receive_unique_sequences(delivered, 250, [])
  assert list.length(sequences) == 250
  assert await_delivered(reporter, 250, 1000)
  assert diagnostics.snapshot(reporter).dropped == 0
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn concurrent_emit_and_stop_is_linearized_500_times_test() -> Nil {
  repeat_emit_stop_race(500)
}

pub fn stop_waits_for_an_admitted_sink_then_refuses_later_events_test() -> Nil {
  let entered = process.new_subject()
  let stopped = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 1,
      sink_timeout_milliseconds: 1000,
      sink: fn(_) {
        let release = process.new_subject()
        process.send(entered, release)
        let _released = process.receive(release, within: 1000)
        Ok(Nil)
      },
    )
  assert diagnostics.emit(reporter, diagnostics.ServerDraining)
  let assert Ok(release) = process.receive(entered, within: 1000)
  let _stopper =
    process.spawn_unlinked(fn() {
      process.send(stopped, diagnostics.stop(reporter))
    })

  assert process.receive(stopped, within: 20) == Error(Nil)
  assert !diagnostics.emit(reporter, diagnostics.HandlerReloaded)
  process.send(release, Nil)
  assert process.receive(stopped, within: 1000) == Ok(Ok(Nil))
  assert diagnostics.snapshot(reporter)
    == diagnostics.Snapshot(
      in_flight: 0,
      delivered: 1,
      dropped: 1,
      sink_failures: 0,
    )
  assert !diagnostics.emit(reporter, diagnostics.ServerStopped)
}

fn await_delivered(
  reporter: diagnostics.Reporter,
  expected: Int,
  remaining: Int,
) -> Bool {
  case diagnostics.snapshot(reporter).delivered >= expected, remaining <= 0 {
    True, _ -> True
    False, True -> False
    False, False -> {
      process.sleep(2)
      await_delivered(reporter, expected, remaining - 2)
    }
  }
}

fn await_failures(
  reporter: diagnostics.Reporter,
  expected: Int,
  remaining: Int,
) -> Bool {
  case
    diagnostics.snapshot(reporter).sink_failures >= expected,
    remaining <= 0
  {
    True, _ -> True
    False, True -> False
    False, False -> {
      process.sleep(2)
      await_failures(reporter, expected, remaining - 2)
    }
  }
}

fn assert_cancel_trace(
  first: diagnostics.Observation,
  second: diagnostics.Observation,
) -> Nil {
  let #(started, failed) = case first.sequence < second.sequence {
    True -> #(first, second)
    False -> #(second, first)
  }
  let assert diagnostics.Observation(
    sequence: started_sequence,
    event: diagnostics.RequestStarted(started_id, context.Http3),
  ) = started
  let assert diagnostics.Observation(
    sequence: failed_sequence,
    event: diagnostics.RequestFailed(
      failed_id,
      context.Http3,
      failure,
      elapsed_milliseconds,
    ),
  ) = failed
  assert started_sequence < failed_sequence
  assert started_id == failed_id
  assert diagnostics.request_id_value(started_id) > 0
  assert error.kind(failure) == error.Cancelled
  assert elapsed_milliseconds >= 0
}

fn test_context() -> context.Context {
  let assert Ok(value) =
    context.new(
      context.Http3,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 443),
      within_milliseconds: 5000,
      tls_identity: context.TlsIdentity("localhost", None),
      early_data: context.EarlyDataDisabled,
    )
  value
}

fn spawn_diagnostic_emitters(
  reporter: diagnostics.Reporter,
  accepted: process.Subject(Bool),
  remaining: Int,
) -> Nil {
  use <- bool.guard(when: remaining <= 0, return: Nil)
  let _emitter =
    process.spawn_unlinked(fn() {
      process.send(
        accepted,
        diagnostics.emit(reporter, diagnostics.ServerDraining),
      )
    })
  spawn_diagnostic_emitters(reporter, accepted, remaining - 1)
}

fn receive_acceptances(
  accepted: process.Subject(Bool),
  remaining: Int,
) -> Bool {
  use <- bool.guard(when: remaining <= 0, return: True)
  case process.receive(accepted, within: 1000) {
    Ok(True) -> receive_acceptances(accepted, remaining - 1)
    Ok(False) | Error(Nil) -> False
  }
}

fn receive_unique_sequences(
  delivered: process.Subject(diagnostics.Observation),
  remaining: Int,
  sequences: List(Int),
) -> List(Int) {
  use <- bool.guard(when: remaining <= 0, return: sequences)
  let assert Ok(diagnostics.Observation(sequence, diagnostics.ServerDraining)) =
    process.receive(delivered, within: 1000)
  assert sequence > 0
  assert sequence <= 250
  assert !list.contains(sequences, sequence)
  receive_unique_sequences(delivered, remaining - 1, [sequence, ..sequences])
}

fn repeat_emit_stop_race(remaining: Int) -> Nil {
  use <- bool.guard(when: remaining <= 0, return: Nil)
  let delivered = process.new_subject()
  let accepted = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 1,
      sink_timeout_milliseconds: 100,
      sink: fn(_) {
        process.send(delivered, Nil)
        Ok(Nil)
      },
    )
  let _emitter =
    process.spawn_unlinked(fn() {
      process.send(
        accepted,
        diagnostics.emit(reporter, diagnostics.ServerDraining),
      )
    })

  assert diagnostics.stop(reporter) == Ok(Nil)
  let delivered_when_stop_returned = process.receive(delivered, within: 0)
  let assert Ok(was_accepted) = process.receive(accepted, within: 1000)
  let snapshot = diagnostics.snapshot(reporter)
  case was_accepted {
    True -> {
      assert delivered_when_stop_returned == Ok(Nil)
      assert snapshot.delivered == 1
      assert snapshot.dropped == 0
    }
    False -> {
      assert delivered_when_stop_returned == Error(Nil)
      assert snapshot.delivered == 0
      assert snapshot.dropped == 1
    }
  }
  assert snapshot.in_flight == 0
  assert !diagnostics.emit(reporter, diagnostics.ServerStopped)
  assert diagnostics.snapshot(reporter).dropped == snapshot.dropped + 1
  assert diagnostics.stop(reporter) == Ok(Nil)
  repeat_emit_stop_race(remaining - 1)
}
