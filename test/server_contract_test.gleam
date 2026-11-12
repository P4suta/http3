import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/option.{None}
import gleeunit
import gleeunit/should
import http/body
import http/context
import http/error
import http/internal/transport
import http/resource
import http/server
import http_test_support

type Once

@external(erlang, "http_server_contract_test_ffi", "new_once")
fn new_once() -> Once

@external(erlang, "http_server_contract_test_ffi", "claim_once")
fn claim_once(once: Once) -> Bool

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn startup_primitive_failure_stops_allocated_controller_test() -> Nil {
  let observed = process.new_subject()
  let config =
    server.defaults()
    |> server.with_startup_failure_probe(fn(controller) {
      process.send(observed, controller)
      http_test_support.exit_now()
    })
  let assert Error(failure) =
    server.start(config, fn(_, _) { Ok(test_response(204, body.empty())) })
  assert error.kind(failure) == error.Resource(error.Memory)

  let assert Ok(controller) = process.receive(observed, within: 1000)
  let assert Error(stopped) = resource.acquire(controller, memory_bytes: 1)
  assert error.kind(stopped) == error.Service
  assert resource.snapshot(controller).active_workers == 0
  assert resource.snapshot(controller).memory_bytes == 0
}

pub fn worker_spawn_failure_releases_admission_and_request_body_test() -> Nil {
  let fail_next_spawn = new_once()
  let request_cancelled = process.new_subject()
  let config =
    server.defaults()
    |> server.with_worker_spawn_failure_probe(fn() {
      case claim_once(fail_next_spawn) {
        True -> http_test_support.exit_now()
        False -> Nil
      }
    })
  let assert Ok(running) =
    server.start(config, fn(_, _) { Ok(test_response(204, body.empty())) })
  let assert Ok(failing_body) =
    body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
      process.send(request_cancelled, Nil)
    })

  let assert Error(failure) =
    server.handle(
      running,
      test_request("/spawn-failure", failing_body),
      test_context(),
    )
  assert error.kind(failure) == error.Resource(error.RequestWorkers)
  assert process.receive(request_cancelled, within: 1000) == Ok(Nil)

  let assert Ok(recovered) =
    server.handle(
      running,
      test_request("/after-spawn-failure", body.empty()),
      test_context(),
    )
  assert recovered.status == 204
  body.cancel(recovered.body)
  assert server.stop(running) == Ok(Nil)
}

pub fn handler_panic_and_exit_are_isolated_and_redacted_test() -> Nil {
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      panic as "handler-private-secret"
    })

  let assert Error(panic_failure) =
    server.handle(running, test_request("/panic", body.empty()), test_context())
  assert error.kind(panic_failure) == error.Service
  assert error.message(panic_failure) == "HTTP service failed"

  assert server.reload_handler(running, fn(_, _) {
      http_test_support.exit_now()
      Ok(test_response(200, body.empty()))
    })
    == Ok(Nil)
  let assert Error(exit_failure) =
    server.handle(running, test_request("/exit", body.empty()), test_context())
  assert error.kind(exit_failure) == error.Service

  assert server.reload_handler(running, fn(_, _) {
      Ok(test_response(204, body.empty()))
    })
    == Ok(Nil)
  let assert Ok(completed) =
    server.handle(running, test_request("/ok", body.empty()), test_context())
  assert completed.status == 204
  assert server.stop(running) == Ok(Nil)
  assert server.stop(running) == Ok(Nil)
}

pub fn streaming_request_and_response_remain_pull_backpressured_test() -> Nil {
  let request_pulled = process.new_subject()
  let response_pulled = process.new_subject()
  let request_source =
    body.pull(fn(_) {
      process.send(request_pulled, Nil)
      Ok(body.PullEnd([]))
    })
  let response_source =
    body.pull(fn(_) {
      process.send(response_pulled, Nil)
      Ok(body.PullData(<<"ok":utf8>>, body.pull(fn(_) { Ok(body.PullEnd([])) })))
    })
  let assert Ok(request_body) =
    body.from_pull(request_source, None, None, fn() { Nil })
  let assert Ok(response_body) =
    body.from_pull(response_source, None, None, fn() { Nil })
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      Ok(test_response(200, response_body))
    })

  let assert Ok(completed) =
    server.handle(
      running,
      test_request("/stream", request_body),
      test_context(),
    )
  assert process.receive(request_pulled, within: 0) == Error(Nil)
  assert process.receive(response_pulled, within: 0) == Error(Nil)
  let assert Ok(body.Data(<<"ok":utf8>>, _)) = body.read(completed.body, 2)
  assert process.receive(response_pulled, within: 0) == Ok(Nil)
  assert server.stop(running) == Ok(Nil)
}

pub fn successful_handler_leaves_request_body_cleanup_to_the_adapter_test() -> Nil {
  let cancelled = process.new_subject()
  let source = body.pull(fn(_) { Ok(body.PullEnd([])) })
  let assert Ok(request_body) =
    body.from_pull(source, None, None, fn() { process.send(cancelled, Nil) })
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      Ok(test_response(204, body.empty()))
    })
  let metadata = test_context()

  let assert Ok(response) =
    server.handle(running, test_request("/complete", request_body), metadata)
  assert response.status == 204
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert context.cancellation_snapshot(metadata)
    == context.CancellationSnapshot(
      cancelled: False,
      broker_stopped: False,
      active_subscriptions: 1,
      notifications: 0,
      explicit_unsubscriptions: 1,
      abandoned_subscriptions: 0,
    )
  body.cancel(response.body)
  assert await_cancellation_broker(metadata, 1000)
    == context.CancellationSnapshot(
      cancelled: False,
      broker_stopped: True,
      active_subscriptions: 0,
      notifications: 0,
      explicit_unsubscriptions: 2,
      abandoned_subscriptions: 0,
    )
  assert server.stop(running) == Ok(Nil)
}

pub fn cancellation_stops_the_worker_and_cancels_the_request_body_test() -> Nil {
  let started = process.new_subject()
  let cancelled = process.new_subject()
  let blocked_handler = process.new_subject()
  let source = body.pull(fn(_) { Ok(body.PullEnd([])) })
  let assert Ok(request_body) =
    body.from_pull(source, None, None, fn() { process.send(cancelled, Nil) })
  let metadata = test_context()
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      process.send(started, Nil)
      // Cancellation must stop a handler that is waiting on application work;
      // a finite never-released latch models that state without a timing race.
      let assert Ok(Nil) = process.receive(blocked_handler, within: 5000)
      Ok(test_response(200, body.empty()))
    })
  let task =
    http_test_support.start_task(fn() {
      server.handle(running, test_request("/cancel", request_body), metadata)
    })
  assert process.receive(started, within: 1000) == Ok(Nil)

  context.cancel(metadata)

  let assert Error(failure) = http_test_support.await_task(task)
  assert error.kind(failure) == error.Cancelled
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  let cancellation = await_cancellation_broker(metadata, 100)
  assert cancellation.cancelled
  assert cancellation.broker_stopped
  assert cancellation.active_subscriptions == 0
  assert cancellation.notifications == 2
  assert server.stop(running) == Ok(Nil)
}

pub fn reload_is_atomic_and_drain_rejects_new_work_then_waits_test() -> Nil {
  let started = process.new_subject()
  let assert Ok(limits) =
    resource.limits(maximum_workers: 4, memory_bytes: 65_536)
  let assert Ok(configuration) =
    server.with_resource_limits(
      server.defaults(),
      limits,
      worker_memory_bytes: 4096,
    )
  let assert Ok(configuration) = server.with_drain_timeout(configuration, 1000)
  let assert Ok(running) =
    server.start(configuration, fn(_, _) {
      let release_old_handler = process.new_subject()
      process.send(started, release_old_handler)
      // A bounded latch holds the accepted request until the drain transition and refusal have both been observed.
      // This avoids inferring actor state from elapsed wall time.
      let assert Ok(Nil) = process.receive(release_old_handler, within: 5000)
      Ok(test_response(201, body.empty()))
    })
  let first =
    http_test_support.start_task(fn() {
      server.handle(running, test_request("/old", body.empty()), test_context())
    })
  let release_old_handler =
    process.receive(started, within: 1000) |> should.be_ok

  assert server.reload_handler(running, fn(_, _) {
      Ok(test_response(202, body.empty()))
    })
    == Ok(Nil)
  let assert Ok(after_reload) =
    server.handle(running, test_request("/new", body.empty()), test_context())
  assert after_reload.status == 202
  body.cancel(after_reload.body)

  let draining = http_test_support.start_task(fn() { server.drain(running) })
  let state_deadline = transport.monotonic_millisecond() + 2000
  assert await_server_state(
      running: running,
      expected: server.Draining,
      deadline_milliseconds: state_deadline,
    )
    == server.Draining
  let assert Error(refused) =
    server.handle(
      running,
      test_request("/refused", body.empty()),
      test_context(),
    )
  assert error.kind(refused) == error.Service

  process.send(release_old_handler, Nil)
  let assert Ok(before_reload) = http_test_support.await_task(first)
  assert before_reload.status == 201
  body.cancel(before_reload.body)
  assert http_test_support.await_task(draining) == Ok(Nil)
  assert server.state(running) == server.Draining
  assert server.stop(running) == Ok(Nil)
  assert server.state(running) == server.Stopped
}

fn await_server_state(
  running running: server.Server,
  expected expected: server.State,
  deadline_milliseconds deadline_milliseconds: Int,
) -> server.State {
  let observed = server.state(running)
  case observed == expected {
    True -> observed
    False -> {
      assert transport.monotonic_millisecond() < deadline_milliseconds
      await_server_state(
        running: running,
        expected: expected,
        deadline_milliseconds: deadline_milliseconds,
      )
    }
  }
}

fn test_request(
  path: String,
  contents: body.Body,
) -> request.Request(body.Body) {
  request.new()
  |> request.set_path(path)
  |> request.set_body(contents)
}

fn test_response(
  status: Int,
  contents: body.Body,
) -> response.Response(body.Body) {
  response.new(status) |> response.set_body(contents)
}

fn test_context() -> context.Context {
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

fn await_cancellation_broker(
  metadata: context.Context,
  remaining_milliseconds: Int,
) -> context.CancellationSnapshot {
  let snapshot = context.cancellation_snapshot(metadata)
  case snapshot.broker_stopped || remaining_milliseconds <= 0 {
    True -> snapshot
    False -> {
      process.sleep(1)
      await_cancellation_broker(metadata, remaining_milliseconds - 1)
    }
  }
}
