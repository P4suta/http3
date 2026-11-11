import gleam/erlang/process
import gleam/http/request
import gleam/http/response
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

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn final_transfer_disposes_the_source_without_explicit_cancellation_test() -> Nil {
  let disposed = process.new_subject()
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      let assert Ok(outgoing) =
        body.from_pull(
          body.pull(fn(_) { Ok(body.PullEnd([])) }),
          None,
          None,
          fn() { process.send(disposed, Nil) },
        )
      Ok(response.new(200) |> response.set_body(outgoing))
    })
  let assert Ok(outgoing) = server.handle(running, incoming(), metadata())
  body.transfer_finished(outgoing.body, Ok(Nil))
  let released_before_stop = process.receive(disposed, within: 1000) == Ok(Nil)
  let stopped = server.stop(running)
  body.cancel(outgoing.body)
  assert stopped == Ok(Nil)
  assert released_before_stop
  assert process.receive(disposed, within: 0) == Error(Nil)
}

pub fn final_transfer_returns_the_only_worker_slot_before_next_dispatch_test() -> Nil {
  let released = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 16,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestReleased(_, _, outcome, _) ->
            process.send(released, result.map_error(outcome, error.kind))
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
      Ok(response.new(200) |> response.set_body(body.from_text("bounded")))
    })
  let assert Ok(first) = server.handle(running, incoming(), metadata())
  body.transfer_finished(first.body, Ok(Nil))
  let first_released = process.receive(released, within: 1000)
  let second = server.handle(running, incoming(), metadata())
  let admitted = result.is_ok(second)
  let _disposed =
    result.map(second, fn(outgoing) { body.cancel(outgoing.body) })
  body.cancel(first.body)
  let stopped = server.stop(running)
  let reporter_stopped = diagnostics.stop(reporter)
  assert stopped == Ok(Nil)
  assert reporter_stopped == Ok(Nil)
  assert first_released == Ok(Ok(Nil))
  assert admitted
}

pub fn an_unreleased_response_keeps_its_admission_reservation_test() -> Nil {
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let assert Ok(config) =
    server.with_resource_limits(
      server.defaults(),
      limits,
      worker_memory_bytes: 64,
    )
  let assert Ok(running) =
    server.start(config, fn(_, _) {
      Ok(response.new(200) |> response.set_body(body.from_text("bounded")))
    })
  let first = server.handle(running, incoming(), metadata())
  let second = server.handle(running, incoming(), metadata())
  let held = case second {
    Error(failure) ->
      error.kind(failure) == error.Resource(error.RequestWorkers)
    Ok(outgoing) -> {
      body.cancel(outgoing.body)
      False
    }
  }
  let disposed =
    first
    |> result.map(fn(outgoing) { body.cancel(outgoing.body) })
    |> result.map_error(error.kind)
  let stopped = server.stop(running)
  assert disposed == Ok(Nil)
  assert stopped == Ok(Nil)
  assert held
}

pub fn stop_disposes_a_body_after_the_handler_has_returned_test() -> Nil {
  let cancelled = process.new_subject()
  let assert Ok(outgoing) =
    body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
      process.send(cancelled, Nil)
    })
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      Ok(response.new(200) |> response.set_body(outgoing))
    })
  let received = server.handle(running, incoming(), metadata())
  let stopped = server.stop(running)
  let released = process.receive(cancelled, within: 1000) == Ok(Nil)
  body.cancel(outgoing)
  assert result.is_ok(received)
  assert stopped == Ok(Nil)
  assert released
}

pub fn successful_transfer_and_failed_cleanup_have_distinct_results_test() -> Nil {
  let finished = process.new_subject()
  let released = process.new_subject()
  let failed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 16,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestFinished(id, _, _, _) ->
            process.send(finished, #(
              diagnostics.request_id_value(id),
              record.sequence,
            ))
          diagnostics.RequestReleased(id, _, outcome, _) ->
            process.send(released, #(
              diagnostics.request_id_value(id),
              record.sequence,
              result.map_error(outcome, error.kind),
            ))
          diagnostics.RequestFailed(..) -> process.send(failed, Nil)
          _ -> Nil
        }
        Ok(Nil)
      },
    )
  let assert Ok(running) =
    server.start(server.with_diagnostics(server.defaults(), reporter), fn(_, _) {
      let assert Ok(outgoing) =
        body.from_pull(
          body.pull(fn(_) { Ok(body.PullEnd([])) }),
          None,
          None,
          fn() { http_test_support.exit_now() },
        )
      Ok(response.new(200) |> response.set_body(outgoing))
    })
  let assert Ok(outgoing) = server.handle(running, incoming(), metadata())
  body.transfer_finished(outgoing.body, Ok(Nil))
  body.cancel(outgoing.body)
  let terminal = process.receive(finished, within: 1000)
  let cleanup = process.receive(released, within: 1000)
  let stopped = server.stop(running)
  assert diagnostics.stop(reporter) == Ok(Nil)
  assert stopped == Ok(Nil)
  let assert Ok(#(finished_id, finished_sequence)) = terminal
  let assert Ok(#(released_id, released_sequence, outcome)) = cleanup
  assert finished_id == released_id
  assert finished_sequence < released_sequence
  assert outcome == Error(error.Service)
  assert process.receive(failed, within: 0) == Error(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
}

fn incoming() -> request.Request(body.Body) {
  request.new() |> request.set_body(body.empty())
}

pub fn server_owner_exit_disposes_an_inflight_response_test() -> Nil {
  let ready = process.new_subject()
  let cancelled = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      let assert Ok(running) =
        server.start(server.defaults(), fn(_, _) {
          let assert Ok(outgoing) =
            body.from_pull(
              body.pull(fn(_) { Ok(body.PullEnd([])) }),
              None,
              None,
              fn() { process.send(cancelled, Nil) },
            )
          Ok(response.new(200) |> response.set_body(outgoing))
        })
      process.send(ready, running)
      let hold = process.new_subject()
      process.receive_forever(hold)
    })
  let assert Ok(running) = process.receive(ready, within: 1000)
  let received = server.handle(running, incoming(), metadata())
  process.kill(owner)
  let disposed = process.receive(cancelled, within: 1000) == Ok(Nil)
  let stopped = server.stop(running)
  assert result.is_ok(received)
  assert stopped == Ok(Nil)
  assert disposed
}

fn metadata() -> context.Context {
  let assert Ok(value) =
    context.new(
      context.Http1,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 8080),
      within_milliseconds: 5000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  value
}
