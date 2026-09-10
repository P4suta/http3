import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleeunit
import http/body
import http/context
import http/middleware

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn middleware_runs_in_declared_order_around_the_handler_test() -> Nil {
  let trace = process.new_subject()
  let outer = fn(outgoing, metadata, next) {
    process.send(trace, "outer-before")
    let outcome = middleware.next(next, outgoing, metadata)
    process.send(trace, "outer-after")
    outcome
  }
  let inner = fn(outgoing, metadata, next) {
    process.send(trace, "inner-before")
    let outcome = middleware.next(next, outgoing, metadata)
    process.send(trace, "inner-after")
    outcome
  }
  let handler = fn(_, _) {
    process.send(trace, "handler")
    Ok(response.new(204) |> response.set_body(body.empty()))
  }

  let assert Ok(completed) =
    middleware.run([outer, inner], handler, test_request(), test_context())

  assert completed.status == 204
  assert process.receive(trace, within: 0) == Ok("outer-before")
  assert process.receive(trace, within: 0) == Ok("inner-before")
  assert process.receive(trace, within: 0) == Ok("handler")
  assert process.receive(trace, within: 0) == Ok("inner-after")
  assert process.receive(trace, within: 0) == Ok("outer-after")
}

pub fn middleware_can_short_circuit_without_calling_inner_layers_test() -> Nil {
  let called = process.new_subject()
  let short_circuit = fn(_, _, _) {
    Ok(response.new(403) |> response.set_body(body.empty()))
  }
  let unreachable = fn(outgoing, metadata, next) {
    process.send(called, Nil)
    middleware.next(next, outgoing, metadata)
  }
  let handler = fn(_, _) {
    process.send(called, Nil)
    Ok(response.new(204) |> response.set_body(body.empty()))
  }

  let assert Ok(completed) =
    middleware.run(
      [short_circuit, unreachable],
      handler,
      test_request(),
      test_context(),
    )

  assert completed.status == 403
  assert process.receive(called, within: 0) == Error(Nil)
}

fn test_request() -> request.Request(body.Body) {
  request.new() |> request.set_body(body.empty())
}

fn test_context() -> context.Context {
  let assert Ok(value) =
    context.new(
      context.Http1,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 8080),
      within_milliseconds: 1000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  value
}
