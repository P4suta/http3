import gleam/bool
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleam/result
import gleeunit
import http/body
import http/context
import http/diagnostics
import http/error
import http/resource
import http/server
import http_test_support

@external(erlang, "http_server_ffi", "monotonic_millisecond")
fn monotonic_milliseconds() -> Int

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn resource_refusal_has_a_unique_request_id_and_protocol_test() -> Nil {
  let started = process.new_subject()
  let refused = process.new_subject()
  let released = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 8,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestStarted(request_id, protocol) ->
            process.send(started, #(request_id, protocol, record.sequence))
          diagnostics.RequestRefused(request_id, protocol, resource) ->
            process.send(refused, #(
              request_id,
              protocol,
              resource,
              record.sequence,
            ))
          diagnostics.RequestReleased(request_id, protocol, cleanup, _) ->
            process.send(released, #(
              request_id,
              protocol,
              result.map_error(cleanup, error.kind),
              record.sequence,
            ))
          _ -> Nil
        }
        Ok(Nil)
      },
    )
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let assert Ok(config) =
    server.with_resource_limits(
      server.with_diagnostics(server.defaults(), reporter),
      limits,
      worker_memory_bytes: 64,
    )
  let assert Ok(running) =
    server.start(config, fn(_, _) {
      Ok(response.new(200) |> response.set_body(body.from_text("held")))
    })

  let assert Ok(first) =
    server.handle(
      running,
      request.new() |> request.set_body(body.empty()),
      test_context(),
    )
  let assert Ok(#(started_id, context.Http3, first_started_sequence)) =
    process.receive(started, within: 1000)
  let assert Error(failure) =
    server.handle(
      running,
      request.new() |> request.set_body(body.empty()),
      test_context(),
    )
  assert error.kind(failure) == error.Resource(error.RequestWorkers)
  let assert Ok(#(refused_started_id, context.Http3, refused_started_sequence)) =
    process.receive(started, within: 1000)
  let assert Ok(#(
    refused_id,
    context.Http3,
    error.RequestWorkers,
    refused_sequence,
  )) = process.receive(refused, within: 1000)
  let assert Ok(#(released_id, context.Http3, Ok(Nil), released_sequence)) =
    process.receive(released, within: 1000)

  assert diagnostics.request_id_value(refused_id) > 0
  assert refused_id != started_id
  assert refused_started_id == refused_id && refused_id == released_id
  assert first_started_sequence < refused_started_sequence
  assert refused_started_sequence < refused_sequence
  assert refused_sequence < released_sequence
  assert process.receive(started, within: 0) == Error(Nil)
  body.cancel(first.body)
  assert server.stop(running) == Ok(Nil)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn handler_return_does_not_report_a_successful_exchange_test() -> Nil {
  let delivered = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 8,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        process.send(delivered, record.event)
        Ok(Nil)
      },
    )
  let assert Ok(running) =
    server.start(server.with_diagnostics(server.defaults(), reporter), fn(_, _) {
      let assert Ok(outgoing) =
        body.from_pull(
          body.pull(fn(_) { Error(error.new(error.Body(error.ReadFailed))) }),
          None,
          None,
          fn() { Nil },
        )
      Ok(response.new(200) |> response.set_body(outgoing))
    })
  let result =
    server.handle(
      running,
      request.new() |> request.set_body(body.empty()),
      test_context(),
    )
  let assert Ok(outgoing) = result
  let assert Ok(first) = process.receive(delivered, within: 1000)
  let assert Ok(second) = process.receive(delivered, within: 1000)
  let claimed_success = fn(event) {
    case event {
      diagnostics.RequestFinished(..) -> True
      _ -> False
    }
  }
  assert !claimed_success(first)
  assert !claimed_success(second)
  let failed_read = case body.read(outgoing.body, 16) {
    Error(failure) -> error.kind(failure) == error.Body(error.ReadFailed)
    Ok(_) -> False
  }
  assert failed_read
  let assert Ok(diagnostics.RequestFailed(_, _, failure, _)) =
    process.receive(delivered, within: 1000)
  assert error.kind(failure) == error.Body(error.ReadFailed)
  body.cancel(outgoing.body)
  assert server.stop(running) == Ok(Nil)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn eof_and_final_write_failure_are_distinct_once_across_cursors_test() -> Nil {
  let source_done = process.new_subject()
  let terminal = process.new_subject()
  let original =
    body.from_text("one chunk")
    |> body.observe_transfer(
      fn() { process.send(source_done, Nil) },
      fn(outcome) { process.send(terminal, outcome) },
    )
  let assert Ok(body.Data(_, next)) = body.read(original, 32)
  let assert Ok(body.Done(completed)) = body.read(next, 32)
  let assert Ok(body.Done(_)) = body.read(completed, 32)
  assert process.receive(source_done, within: 1000) == Ok(Nil)
  assert process.receive(source_done, within: 0) == Error(Nil)
  assert process.receive(terminal, within: 0) == Error(Nil)
  let failure = error.new(error.ConnectFailed)
  body.transfer_finished(original, Error(failure))
  body.transfer_finished(completed, Ok(Nil))
  body.cancel(next)
  assert process.receive(terminal, within: 1000) == Ok(Error(failure))
  assert process.receive(terminal, within: 0) == Error(Nil)
}

pub fn suppressed_body_disposal_preserves_successful_final_write_test() -> Nil {
  let terminal = process.new_subject()
  let outgoing =
    body.from_text("suppressed")
    |> body.observe_transfer(fn() { Nil }, fn(outcome) {
      process.send(terminal, outcome)
    })
  body.transfer_finished(outgoing, Ok(Nil))
  body.cancel(outgoing)
  assert process.receive(terminal, within: 1000) == Ok(Ok(Nil))
  assert process.receive(terminal, within: 0) == Error(Nil)
}

pub fn invalid_read_limit_does_not_terminate_a_usable_body_test() -> Nil {
  let terminal = process.new_subject()
  let outgoing =
    body.from_text("bounded")
    |> body.observe_transfer(fn() { Nil }, fn(outcome) {
      process.send(terminal, result.map_error(outcome, error.kind))
    })
  let invalid = body.read(outgoing, 0) |> result.map_error(error.kind)
  let rejected = case invalid {
    Error(failure) -> failure == error.Body(error.InvalidLimit)
    Ok(_) -> False
  }
  let ended_early = process.receive(terminal, within: 0)
  let consumed = body.read_all(outgoing, 32) |> result.map(fn(_) { Nil })
  body.transfer_finished(outgoing, Ok(Nil))
  body.cancel(outgoing)
  assert rejected
  assert consumed == Ok(Nil)
  assert ended_early == Error(Nil)
  assert process.receive(terminal, within: 1000) == Ok(Ok(Nil))
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
  assert_observation(process.receive(delivered, within: 1000), 1, event)
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

pub fn one_panicking_sink_cannot_suppress_a_following_delivery_test() -> Nil {
  let delivered = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 2,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        case record.event {
          diagnostics.ServerDraining -> panic as "private-sink-reason"
          diagnostics.HandlerReloaded -> {
            process.send(delivered, record.sequence)
            Ok(Nil)
          }
          _ -> Ok(Nil)
        }
      },
    )
  assert diagnostics.emit(reporter, diagnostics.ServerDraining)
  assert diagnostics.emit(reporter, diagnostics.HandlerReloaded)
  let assert Ok(sequence) = process.receive(delivered, within: 1000)
  assert sequence == 2
  assert await_failures(reporter, 1, 200)
  assert await_delivered(reporter, 1, 200)
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
  assert_observation(process.receive(delivered, within: 1000), 2, failed)
  process.send(release, Nil)
  assert_observation(process.receive(delivered, within: 1000), 1, started)
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
    ..,
  ) = started
  let assert diagnostics.Observation(
    sequence: failed_sequence,
    event: diagnostics.RequestFailed(
      failed_id,
      context.Http3,
      failure,
      elapsed_milliseconds,
    ),
    ..,
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
  let assert Ok(diagnostics.Observation(
    sequence:,
    event: diagnostics.ServerDraining,
    ..,
  )) = process.receive(delivered, within: 1000)
  assert sequence > 0
  assert sequence <= 250
  assert !list.contains(sequences, sequence)
  receive_unique_sequences(delivered, remaining - 1, [sequence, ..sequences])
}

fn assert_observation(
  received: Result(diagnostics.Observation, Nil),
  sequence: Int,
  event: diagnostics.Event,
) -> Nil {
  let assert Ok(observed) = received
  assert observed.sequence == sequence
  assert observed.event == event
  assert observed.monotonic_milliseconds <= monotonic_milliseconds()
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
