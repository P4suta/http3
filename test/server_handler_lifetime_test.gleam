import gleam/bool
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/option.{None}
import gleam/result
import gleeunit
import http/body
import http/context
import http/error
import http/internal/http1/server as http1_server
import http/resource
import http/server

type Probe

@external(erlang, "http_handler_lifetime_test_ffi", "new_probe")
fn new_probe() -> Probe

@external(erlang, "http_handler_lifetime_test_ffi", "record_handler")
fn record_handler(probe: Probe) -> Nil

@external(erlang, "http_handler_lifetime_test_ffi", "record_cleanup")
fn record_cleanup(probe: Probe) -> Nil

@external(erlang, "http_handler_lifetime_test_ffi", "snapshot")
fn snapshot(probe: Probe, server: server.Server) -> #(Bool, Int, Int, Int)

@external(erlang, "http_handler_lifetime_test_ffi", "pause_worker")
fn pause_worker(probe: Probe, server: server.Server) -> process.Pid

@external(erlang, "http_handler_lifetime_test_ffi", "resume")
fn resume(pid: process.Pid) -> Nil

@external(erlang, "http_handler_lifetime_test_ffi", "executor")
fn executor(server: server.Server) -> process.Pid

@external(erlang, "http_handler_lifetime_test_ffi", "dispose")
fn dispose(probe: Probe) -> Nil

@external(erlang, "http_handler_lifetime_test_ffi", "join_reaper")
fn join_reaper(probe: Probe) -> Bool

@external(erlang, "http_handler_lifetime_test_ffi", "reaper_retains_until_down")
fn reaper_retains_until_down() -> #(Bool, Bool, Bool, Bool, Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "unadopted_reaper_does_not_release")
fn unadopted_reaper_does_not_release() -> #(Bool, Bool, Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "quarantined_reaper_does_not_release")
fn quarantined_reaper_does_not_release() -> #(Bool, Bool, Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "atomic_monitor_contracts")
fn atomic_monitor_contracts() -> #(#(Bool, Bool), Bool, #(Bool, Bool), Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_normal_contract")
fn http1_handler_normal_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_stop_contract")
fn http1_handler_stop_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_timeout_contract")
fn http1_handler_timeout_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_crash_contract")
fn http1_handler_crash_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_owner_down_contract")
fn http1_handler_owner_down_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_unconfirmed_cleanup_contract")
fn http1_handler_unconfirmed_cleanup_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_startup_deadline_contract")
fn http1_handler_startup_deadline_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_entry_deadline_contract")
fn http1_handler_entry_deadline_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_owner_startup_contract")
fn http1_handler_owner_startup_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_cleanup_deadline_contract")
fn http1_handler_cleanup_deadline_contract() -> List(Bool)

@external(erlang, "http_handler_lifetime_test_ffi", "http1_handler_quarantine_retry_deadline_contract")
fn http1_handler_quarantine_retry_deadline_contract() -> List(Bool)

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn monitor_and_link_exist_before_each_worker_starts_test() -> Nil {
  assert atomic_monitor_contracts()
    == #(#(True, True), True, #(True, True), True)
}

pub fn http1_handler_result_is_published_after_original_down_test() -> Nil {
  assert http1_handler_normal_contract()
    == [True, True, True, True, True, True, True]
}

pub fn http1_handler_stop_joins_and_discards_a_late_result_once_test() -> Nil {
  assert http1_handler_stop_contract()
    == [True, True, True, True, True, True, True]
}

pub fn http1_handler_uses_one_absolute_deadline_and_joins_test() -> Nil {
  assert http1_handler_timeout_contract()
    == [True, True, True, True, True, True]
}

pub fn http1_handler_crash_is_redacted_cancelled_and_joined_test() -> Nil {
  assert http1_handler_crash_contract() == [True, True, True, True, True]
}

pub fn http1_handler_owner_down_cancels_and_joins_test() -> Nil {
  assert http1_handler_owner_down_contract()
    == [True, True, True, True, True, True]
}

pub fn http1_handler_unconfirmed_cleanup_retains_one_reaper_test() -> Nil {
  assert http1_handler_unconfirmed_cleanup_contract()
    == [True, True, True, True, True, True, True, True]
}

pub fn http1_handler_startup_is_dominated_by_request_deadline_test() -> Nil {
  assert http1_handler_startup_deadline_contract()
    == [True, True, True, True, True, True]
}

pub fn http1_handler_entry_rechecks_deadline_before_user_code_test() -> Nil {
  assert http1_handler_entry_deadline_contract()
    == [True, True, True, True, True, True, True, True, True, True]
}

pub fn http1_handler_owner_death_during_startup_cancels_without_handler_test() -> Nil {
  assert http1_handler_owner_startup_contract()
    == [True, True, True, True, True, True, True]
}

pub fn http1_handler_cleanup_budget_is_not_reset_on_command_receipt_test() -> Nil {
  assert http1_handler_cleanup_deadline_contract()
    == [True, True, True, True, True, True, True]
}

pub fn http1_handler_quarantine_retry_deadline_ignores_mailbox_traffic_test() -> Nil {
  assert http1_handler_quarantine_retry_deadline_contract()
    == [True, True, True, True, True, True, True, True]
}

pub fn http1_handler_await_traffic_cannot_reset_absolute_deadline_test() -> Nil {
  let traffic = process.new_subject()
  let sender_ready = process.new_subject()
  let sender =
    process.spawn_unlinked(fn() {
      let start = process.new_subject()
      process.send(sender_ready, start)
      send_deadline_traffic(traffic: traffic, start: start, remaining: 64)
    })
  let assert Ok(start) = process.receive(sender_ready, within: 1000)
  let consumed =
    http1_server.handler_deadline_traffic_control(
      traffic,
      start,
      within_milliseconds: 150,
      relative_timeout_milliseconds: 100,
    )
  process.kill(sender)
  let sender_down = await_down(sender)
  assert consumed > 0
  assert consumed < 64
  assert sender_down
}

type Fixture {
  Fixture(
    probe: Probe,
    running: server.Server,
    caller: process.Pid,
    handler: process.Pid,
    cleaned: process.Subject(Nil),
    replied: process.Subject(Result(Nil, error.ErrorKind)),
    context: context.Context,
  )
}

pub fn executor_death_holds_the_grant_until_the_handler_is_down_test() -> Nil {
  let fixture = start_fixture(5000)
  let worker = pause_worker(fixture.probe, fixture.running)
  process.kill(executor(fixture.running))
  let reply = process.receive(fixture.replied, within: 1000)
  let held = snapshot(fixture.probe, fixture.running)
  resume(worker)
  let cleaned = process.receive(fixture.cleaned, within: 1000)
  let joined = await_down(fixture.handler)
  let guardian_joined = await_down(worker)
  let reaper_joined = join_reaper(fixture.probe)
  let released = snapshot(fixture.probe, fixture.running)
  dispose(fixture.probe)
  assert reply == Ok(Error(error.Service))
  assert held == #(True, 1, 0, 0)
  assert cleaned == Ok(Nil)
  assert joined
  assert guardian_joined
  assert reaper_joined
  assert released == #(False, 0, 1, 0)
}

pub fn guardian_publication_does_not_release_its_admission_grant_test() -> Nil {
  assert reaper_retains_until_down() == #(True, True, True, True, True)
}

pub fn abandoned_dispatch_keeps_its_cleanup_owner_test() -> Nil {
  assert unadopted_reaper_does_not_release() == #(True, True, True)
}

pub fn unconfirmed_handler_join_quarantines_its_admission_grant_test() -> Nil {
  assert quarantined_reaper_does_not_release() == #(True, True, True)
}

pub fn requester_death_stops_a_blocked_handler_and_releases_once_test() -> Nil {
  let fixture = start_fixture(5000)
  process.kill(fixture.caller)
  let joined = await_down(fixture.handler)
  let cleaned = process.receive(fixture.cleaned, within: 1000)
  let stopped = server.stop(fixture.running)
  let released = snapshot(fixture.probe, fixture.running)
  dispose(fixture.probe)
  assert joined
  assert cleaned == Ok(Nil)
  assert stopped == Ok(Nil)
  assert released == #(False, 0, 1, 0)
}

pub fn handler_deadline_does_not_depend_on_the_requester_running_test() -> Nil {
  let fixture = start_fixture(100)
  suspend(fixture.caller)
  let joined = await_down(fixture.handler)
  let cleaned = process.receive(fixture.cleaned, within: 1000)
  resume(fixture.caller)
  let reply = process.receive(fixture.replied, within: 1000)
  let stopped = server.stop(fixture.running)
  let released = snapshot(fixture.probe, fixture.running)
  dispose(fixture.probe)
  assert joined
  assert cleaned == Ok(Nil)
  assert reply == Ok(Error(error.Timeout(error.Operation)))
  assert stopped == Ok(Nil)
  assert released == #(False, 0, 1, 0)
}

pub fn cancellation_joins_the_handler_before_input_cleanup_test() -> Nil {
  let fixture = start_fixture(5000)
  context.cancel(fixture.context)
  let reply = process.receive(fixture.replied, within: 1000)
  let joined = await_down(fixture.handler)
  let stopped = server.stop(fixture.running)
  let released = snapshot(fixture.probe, fixture.running)
  dispose(fixture.probe)
  assert reply == Ok(Error(error.Cancelled))
  assert joined
  assert stopped == Ok(Nil)
  assert released == #(False, 0, 1, 0)
}

pub fn server_owner_death_joins_a_blocked_handler_test() -> Nil {
  let probe = new_probe()
  let ready = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      process.send(ready, start_fixture_with_probe(probe, 5000))
      let hold = process.new_subject()
      process.receive_forever(hold)
    })
  let assert Ok(fixture) = process.receive(ready, within: 1000)
  process.kill(owner)
  let joined = await_down(fixture.handler)
  let stopped = server.stop(fixture.running)
  let released = snapshot(probe, fixture.running)
  dispose(probe)
  assert joined
  assert stopped == Ok(Nil)
  assert released == #(False, 0, 1, 0)
}

@external(erlang, "http_handler_lifetime_test_ffi", "await_dispatch")
fn await_dispatch(server: server.Server) -> Bool

pub fn executor_death_before_dispatch_adoption_reclaims_the_grant_test() -> Nil {
  let probe = new_probe()
  let replied = process.new_subject()
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, _) {
      record_handler(probe)
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  suspend(executor(running))
  let assert Ok(incoming) =
    body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
      record_cleanup(probe)
    })
  let metadata = metadata()
  let _caller =
    process.spawn_unlinked(fn() {
      let outcome =
        server.handle(
          running,
          request.new() |> request.set_body(incoming),
          metadata,
        )
        |> result.map(fn(outgoing) { body.cancel(outgoing.body) })
        |> result.map_error(error.kind)
      process.send(replied, outcome)
    })
  let queued = await_dispatch(running)
  let held = snapshot(probe, running)
  process.kill(executor(running))
  let reply = process.receive(replied, within: 1000)
  let released = snapshot(probe, running)
  dispose(probe)
  assert queued
  assert held == #(False, 1, 0, 0)
  assert reply == Ok(Error(error.Service))
  assert released == #(False, 0, 1, 0)
}

@external(erlang, "http_handler_lifetime_test_ffi", "suspend")
fn suspend(pid: process.Pid) -> Nil

fn start_fixture(timeout: Int) -> Fixture {
  let probe = new_probe()
  start_fixture_with_probe(probe, timeout)
}

fn start_fixture_with_probe(probe: Probe, timeout: Int) -> Fixture {
  let started = process.new_subject()
  let cleaned = process.new_subject()
  let replied = process.new_subject()
  let assert Ok(limits) = resource.limits(1, 4096)
  let assert Ok(config) =
    server.with_resource_limits(server.defaults(), limits, 64)
  let assert Ok(config) = server.with_operation_timeout(config, timeout)
  let assert Ok(running) =
    server.start(config, fn(_, _) {
      record_handler(probe)
      process.send(started, process.self())
      let gate = process.new_subject()
      process.receive_forever(gate)
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  let assert Ok(incoming) =
    body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
      record_cleanup(probe)
      process.send(cleaned, Nil)
    })
  let metadata = metadata()
  let caller =
    process.spawn_unlinked(fn() {
      let outcome =
        server.handle(
          running,
          request.new() |> request.set_body(incoming),
          metadata,
        )
        |> result.map(fn(outgoing) { body.cancel(outgoing.body) })
        |> result.map_error(error.kind)
      process.send(replied, outcome)
    })
  let assert Ok(handler) = process.receive(started, within: 1000)
  Fixture(probe, running, caller, handler, cleaned, replied, metadata)
}

fn send_deadline_traffic(
  traffic traffic: process.Subject(process.Subject(Nil)),
  start start: process.Subject(Nil),
  remaining remaining: Int,
) -> Nil {
  case process.receive(start, within: 1000) {
    Error(Nil) -> Nil
    Ok(Nil) -> send_deadline_traffic_loop(traffic, remaining)
  }
}

fn send_deadline_traffic_loop(
  traffic: process.Subject(process.Subject(Nil)),
  remaining: Int,
) -> Nil {
  use <- bool.guard(when: remaining <= 0, return: Nil)
  let acknowledged = process.new_subject()
  process.send(traffic, acknowledged)
  case process.receive(acknowledged, within: 250) {
    Error(Nil) -> Nil
    Ok(Nil) -> {
      process.sleep(10)
      send_deadline_traffic_loop(traffic, remaining - 1)
    }
  }
}

fn metadata() -> context.Context {
  let assert Ok(metadata) =
    context.new(
      context.Http1,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 8080),
      within_milliseconds: 5000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  metadata
}

fn await_down(pid: process.Pid) -> Bool {
  let monitor = process.monitor(pid)
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
  let joined = process.selector_receive(selector, within: 1000) == Ok(Nil)
  process.demonitor_process(monitor)
  joined
}
