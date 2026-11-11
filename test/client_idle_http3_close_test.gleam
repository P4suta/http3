import gleam/erlang/process
import gleam/http/request
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/client
import http/error
import http/internal/http3/client as http3_adapter
import http3/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

@external(erlang, "http_client_lifecycle_close_test", "confirmed_graceful_idle_resource_owner_join")
fn confirmed_graceful_idle_resource_owner_join() -> #(
  Result(Nil, Int),
  Bool,
  Bool,
  Result(Nil, Int),
)

@external(erlang, "http_client_lifecycle_close_test", "timed_out_graceful_idle_resource_owner_join")
fn timed_out_graceful_idle_resource_owner_join() -> #(
  Result(Nil, Int),
  Bool,
  Bool,
  Result(Nil, Int),
)

@external(erlang, "http_client_lifecycle_close_test", "confirmed_idle_resource_owner_join")
fn confirmed_idle_resource_owner_join() -> #(
  Result(Nil, Int),
  Bool,
  Result(Nil, Int),
)

@external(erlang, "http_client_lifecycle_close_test", "unconfirmed_idle_resource_owner_join")
fn unconfirmed_idle_resource_owner_join() -> #(
  Result(Nil, Int),
  Bool,
  Result(Nil, Int),
  Result(Nil, Int),
)

@external(erlang, "http_client_lifecycle_close_test", "concurrent_idle_resource_owner_join")
fn concurrent_idle_resource_owner_join() -> #(
  Result(Nil, Int),
  Result(Nil, Int),
  Bool,
  Result(Nil, Int),
)

pub fn lifecycle_close_joins_all_idle_resource_owners_before_success_test() -> Nil {
  assert confirmed_idle_resource_owner_join() == #(Ok(Nil), True, Ok(Nil))
}

pub fn lifecycle_close_requests_graceful_idle_http3_shutdown_before_success_test() -> Nil {
  assert confirmed_graceful_idle_resource_owner_join()
    == #(Ok(Nil), True, True, Ok(Nil))
}

pub fn lifecycle_close_quarantines_and_force_joins_a_stalled_http3_owner_test() -> Nil {
  assert timed_out_graceful_idle_resource_owner_join()
    == #(Error(1), True, True, Ok(Nil))
}

pub fn concurrent_close_callers_share_one_confirmed_owner_join_test() -> Nil {
  assert concurrent_idle_resource_owner_join()
    == #(Ok(Nil), Ok(Nil), True, Ok(Nil))
}

pub fn lifecycle_close_rejects_an_unconfirmed_idle_owner_join_test() -> Nil {
  assert unconfirmed_idle_resource_owner_join()
    == #(Error(1), True, Ok(Nil), Ok(Nil))
}

pub fn public_close_rejects_an_unconfirmed_idle_http3_owner_join_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let serving =
    http_test_support.start_task(fn() {
      let incoming = server.accept(listener) |> should.be_ok
      server.respond(incoming, 200, [], <<>>)
    })
  let configuration =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
    |> should.be_ok
  let running =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_lifecycle_close_join_confirmation(False)
    |> client.start
    |> should.be_ok
  let exchanged =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let body_completed =
    result.map(exchanged, fn(exchange) {
      body.read_all(client.response(exchange).body, 1) == Ok(#(<<>>, []))
    })
    |> result.unwrap(False)
  let serving_done = http_test_support.await_task(serving)
  let pooled = client.lifecycle_pool_counts(running) == #(1, 1)
  let first_close = client.close(running)
  let second_close = client.close(running)
  let third_close = client.close(running)
  let stopped = server.stop(listener)
  assert #(
      body_completed,
      serving_done,
      pooled,
      first_close,
      second_close,
      third_close,
      stopped,
    )
    == #(
      True,
      Ok(Nil),
      True,
      Error(error.new(error.Timeout(error.Operation))),
      Ok(Nil),
      Ok(Nil),
      Ok(server.Stopped),
    )
}

pub fn unconsumed_response_close_observation() -> #(
  Bool,
  client.ClosePhaseObservation,
  Bool,
  Bool,
) {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let serving =
    http_test_support.start_task(fn() {
      let incoming = server.accept(listener) |> should.be_ok
      server.send_response(incoming, 200, [])
    })
  let running =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.start
    |> should.be_ok
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let observation = client.close_observed(running)
  let stopped = server.stop(listener) == Ok(server.Stopped)
  let serving_done = http_test_support.await_task(serving) == Ok(Nil)
  #(result.is_ok(received), observation, stopped, serving_done)
}

pub fn public_close_reports_the_exact_unconsumed_response_release_phase_test() -> Nil {
  let #(received, observation, stopped, serving_done) =
    unconsumed_response_close_observation()
  let client.ClosePhaseObservation(
    active_workers_before,
    lifecycle_outcome,
    _,
    _,
    resource_outcome,
    _,
    active_workers_after_resource,
  ) = observation
  assert #(
      received,
      active_workers_before,
      lifecycle_outcome,
      resource_outcome,
      active_workers_after_resource,
      stopped,
      serving_done,
    )
    == #(True, 1, Ok(Nil), Ok(Nil), 0, True, True)
}

type TerminalDownOrder {
  WorkerFirst
  GuardianFirst
}

pub fn terminal_cancellation_survives_worker_first_shutdown_test() -> Nil {
  assert_terminal_classification(
    order: WorkerFirst,
    terminal_cancelled: True,
    expected: error.Cancelled,
  )
}

pub fn terminal_cancellation_survives_guardian_first_shutdown_test() -> Nil {
  assert_terminal_classification(
    order: GuardianFirst,
    terminal_cancelled: True,
    expected: error.Cancelled,
  )
}

pub fn missing_terminal_marker_keeps_worker_first_crash_as_service_test() -> Nil {
  assert_terminal_classification(
    order: WorkerFirst,
    terminal_cancelled: False,
    expected: error.Service,
  )
}

pub fn missing_terminal_marker_keeps_guardian_first_crash_as_service_test() -> Nil {
  assert_terminal_classification(
    order: GuardianFirst,
    terminal_cancelled: False,
    expected: error.Service,
  )
}

fn assert_terminal_classification(
  order order: TerminalDownOrder,
  terminal_cancelled terminal_cancelled: Bool,
  expected expected: error.ErrorKind,
) -> Nil {
  let worker =
    process.spawn_unlinked(fn() {
      let keep_worker = process.new_subject()
      process.receive_forever(keep_worker)
    })
  let guardian =
    process.spawn_unlinked(fn() {
      let keep_guardian = process.new_subject()
      process.receive_forever(keep_guardian)
    })
  let clock_requests = process.new_subject()
  let read_dispatched = process.new_subject()
  let cancel_dispatched = process.new_subject()
  let read_completed = process.new_subject()
  let reading =
    http_test_support.start_task(fn() {
      let outcome =
        http3_adapter.response_pull_once_with_cancelled_marker_probe(
          worker:,
          guardian:,
          deadline: 10_000,
          cleanup_budget_milliseconds: 100,
          terminal_cancelled:,
          clock: fn() {
            let reply = process.new_subject()
            process.send(clock_requests, reply)
            process.receive_forever(reply)
          },
          dispatch_read: fn(_, _) { process.send(read_dispatched, Nil) },
          dispatch_cancel: fn() {
            process.send(cancel_dispatched, Nil)
            process.kill(worker)
            process.kill(guardian)
          },
        )
      process.send(read_completed, outcome)
      outcome
    })
  let first_clock =
    process.receive(clock_requests, within: 1000) |> should.be_ok
  process.send(first_clock, 0)
  let Nil = process.receive(read_dispatched, within: 1000) |> should.be_ok
  let selector_clock =
    process.receive(clock_requests, within: 1000) |> should.be_ok
  case order {
    WorkerFirst -> process.kill(worker)
    GuardianFirst -> process.kill(guardian)
  }
  process.send(selector_clock, 0)
  let post_selection_clock =
    process.receive(clock_requests, within: 1000) |> should.be_ok
  process.send(post_selection_clock, 9999)
  let Nil = process.receive(cancel_dispatched, within: 1000) |> should.be_ok
  let _read_outcome =
    process.receive(read_completed, within: 1000) |> should.be_ok
  let outcome = http_test_support.await_task(reading)
  assert outcome == Error(error.new(expected))
  assert !process.is_alive(worker)
  assert !process.is_alive(guardian)
  assert process.receive(clock_requests, within: 0) == Error(Nil)
}
