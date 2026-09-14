import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/option.{None}
import gleeunit
import http/body
import http/context
import http/error
import http/resource
import http/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
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
  assert await_cancellation_broker(metadata, 100)
    == context.CancellationSnapshot(
      cancelled: False,
      broker_stopped: True,
      active_subscriptions: 0,
      notifications: 0,
      explicit_unsubscriptions: 1,
      abandoned_subscriptions: 0,
    )
  assert server.stop(running) == Ok(Nil)
}

pub fn cancellation_stops_the_worker_and_cancels_the_request_body_test() -> Nil {
  let started = process.new_subject()
  let cancelled = process.new_subject()
  let source = body.pull(fn(_) { Ok(body.PullEnd([])) })
  let assert Ok(request_body) =
    body.from_pull(source, None, None, fn() { process.send(cancelled, Nil) })
  let metadata = test_context()
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      process.send(started, Nil)
      process.sleep(1000)
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
  assert cancellation.notifications == 1
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
      process.send(started, Nil)
      process.sleep(100)
      Ok(test_response(201, body.empty()))
    })
  let first =
    http_test_support.start_task(fn() {
      server.handle(running, test_request("/old", body.empty()), test_context())
    })
  assert process.receive(started, within: 1000) == Ok(Nil)

  assert server.reload_handler(running, fn(_, _) {
      Ok(test_response(202, body.empty()))
    })
    == Ok(Nil)
  let assert Ok(after_reload) =
    server.handle(running, test_request("/new", body.empty()), test_context())
  assert after_reload.status == 202

  let draining = http_test_support.start_task(fn() { server.drain(running) })
  process.sleep(10)
  let assert Error(refused) =
    server.handle(
      running,
      test_request("/refused", body.empty()),
      test_context(),
    )
  assert error.kind(refused) == error.Service

  let assert Ok(before_reload) = http_test_support.await_task(first)
  assert before_reload.status == 201
  assert http_test_support.await_task(draining) == Ok(Nil)
  assert server.state(running) == server.Draining
  assert server.stop(running) == Ok(Nil)
  assert server.state(running) == server.Stopped
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
