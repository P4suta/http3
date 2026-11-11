import gleam/erlang/process
import gleam/http/request
import gleam/option.{Some}
import gleam/result
import gleeunit
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/client_trace
import http/internal/http3/client as adapter
import http/internal/transport
import http/resource
import http3/client as native
import http3/server
import http_test_support

const observation_milliseconds = 3000

type AckFixture {
  AckFixture(exit_guardian: process.Subject(Nil))
}

type CallbackFixture {
  CallbackFixture(
    continue: process.Subject(Nil),
    callback: process.Pid,
    linked: List(process.Pid),
  )
}

@external(erlang, "http_client_resource_test", "linked_processes")
fn linked_processes() -> List(process.Pid)

pub fn main() -> Nil {
  gleeunit.main()
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn response_cancel_waits_for_release_publication_and_resource_reclaim_test() -> Nil {
  let assert Ok(reporter) = diagnostics.start(1, 100, fn(_) { Ok(Nil) })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.protocol_selected(trace, context.Http3)
  let assert Ok(Nil) = diagnostics.stop(reporter)
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_config) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_config)
  let assert Ok(port) = server.port(listener)
  let peer_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      let sent = server.send_response(incoming, 204, [])
      let peer_release = process.new_subject()
      process.send(peer_waiting, peer_release)
      let _released = process.receive(peer_release, within: 5000)
      sent
    })

  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let release_started = process.new_subject()
  let admission_release_started = process.new_subject()
  let assert Ok(native_config) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: observation_milliseconds,
      idle_milliseconds: observation_milliseconds,
    )
  let configuration =
    configuration
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_request_lease_release_probe(fn() {
      let continue = process.new_subject()
      process.send(admission_release_started, continue)
      let _continued = process.receive(continue, within: 5000)
      Nil
    })
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(incoming) =
    adapter.exchange_observed(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + observation_milliseconds,
      fn() {
        let continue = process.new_subject()
        process.send(release_started, continue)
        let _continued = process.receive(continue, within: 5000)
        Nil
      },
      trace,
    )

  let cancel_finished = process.new_subject()
  let cancelling =
    http_test_support.start_task(fn() {
      let outcome = body.cancel_within(incoming.body, observation_milliseconds)
      process.send(cancel_finished, outcome)
      outcome
    })
  let assert Ok(release_gate) =
    process.receive(release_started, within: observation_milliseconds)
  let premature = process.receive(cancel_finished, within: 0)
  let held = resource.snapshot(resources)
  process.send(release_gate, Nil)
  let assert Ok(admission_release_gate) =
    process.receive(admission_release_started, within: observation_milliseconds)
  let premature_terminal = process.receive(cancel_finished, within: 0)
  let held_before_global_release = resource.snapshot(resources)
  let admission_before_release = resource.acquire(resources, memory_bytes: 4096)
  result.map(admission_before_release, fn(lease) { resource.release(lease) })
  |> result.unwrap(Nil)
  process.send(admission_release_gate, Nil)
  let cancellation =
    process.receive(cancel_finished, within: observation_milliseconds + 1000)
  let cancellation_task = http_test_support.await_task(cancelling)
  let admission_after_ack = resource.acquire(resources, memory_bytes: 4096)
  result.map(admission_after_ack, fn(lease) { resource.release(lease) })
  |> result.unwrap(Nil)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )
  body.cancel(incoming.body)
  let duplicate_release = process.receive(release_started, within: 0)

  adapter.close(connection)
  resource.stop(resources)
  let assert Ok(peer_release) =
    process.receive(peer_waiting, within: observation_milliseconds)
  process.send(peer_release, Nil)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)

  assert premature == Error(Nil)
  assert held.active_workers == 1
  assert held.memory_bytes == 4096
  assert premature_terminal == Error(Nil)
  assert held_before_global_release.active_workers == 1
  assert held_before_global_release.memory_bytes == 4096
  assert result.is_error(admission_before_release)
  assert cancellation == Ok(Ok(Nil))
  assert cancellation_task == Ok(Nil)
  assert result.is_ok(admission_after_ack)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert duplicate_release == Error(Nil)
  assert serving_done == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn peer_reset_releases_once_and_leaves_no_request_resource_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_config) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_config)
  let assert Ok(port) = server.port(listener)
  let peer_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      let response = server.send_response(incoming, 200, [])
      let reset = process.new_subject()
      process.send(peer_waiting, reset)
      let _reset = process.receive(reset, within: observation_milliseconds)
      #(response, server.cancel(incoming))
    })

  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let released = process.new_subject()
  let assert Ok(native_config) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: observation_milliseconds,
      idle_milliseconds: observation_milliseconds,
    )
  let configuration =
    adapter.with_supervision(configuration, resources, process.self())
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(incoming) =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + observation_milliseconds,
      fn() { process.send(released, Nil) },
    )
  let assert Ok(reset) =
    process.receive(peer_waiting, within: observation_milliseconds)
  let reading =
    http_test_support.start_task(fn() { body.read(incoming.body, 1) })
  process.send(reset, Nil)
  let read = http_test_support.await_task(reading)
  let release = process.receive(released, within: observation_milliseconds)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )

  adapter.close(connection)
  resource.stop(resources)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)
  let assert Error(read_failure) = read
  assert error.kind(read_failure) == error.Cancelled
  assert release == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert serving_done == #(Ok(Nil), Ok(server.Cancelled))
  assert stopped == Ok(server.Stopped)
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn release_callback_exception_fails_ack_and_eventually_recovers_admission_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_config) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_config)
  let assert Ok(port) = server.port(listener)
  let peer_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      let response = server.send_response(incoming, 204, [])
      let peer_release = process.new_subject()
      process.send(peer_waiting, peer_release)
      let _released =
        process.receive(peer_release, within: observation_milliseconds)
      response
    })

  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let callback_started = process.new_subject()
  let assert Ok(native_config) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: observation_milliseconds,
      idle_milliseconds: observation_milliseconds,
    )
  let configuration =
    adapter.with_supervision(configuration, resources, process.self())
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(incoming) =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + observation_milliseconds,
      fn() {
        let continue = process.new_subject()
        process.send(
          callback_started,
          CallbackFixture(continue, process.self(), linked_processes()),
        )
        let _continued =
          process.receive(continue, within: observation_milliseconds)
        http_test_support.exit_now()
      },
    )

  let cancel_finished = process.new_subject()
  let cancelling =
    http_test_support.start_task(fn() {
      let outcome = body.cancel_within(incoming.body, observation_milliseconds)
      process.send(cancel_finished, outcome)
      outcome
    })
  let assert Ok(CallbackFixture(continue, callback, [reaper])) =
    process.receive(callback_started, within: observation_milliseconds)
  let callback_monitor = process.monitor(callback)
  let reaper_monitor = process.monitor(reaper)
  assert process.receive(cancel_finished, within: 0) == Error(Nil)
  process.send(continue, Nil)
  let cancellation =
    process.receive(cancel_finished, within: observation_milliseconds)
  let cancellation_task = http_test_support.await_task(cancelling)
  let callback_reaped = join(callback_monitor)
  let reaper_reaped = join(reaper_monitor)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 8000,
    )
  body.cancel(incoming.body)
  let duplicate_callback = process.receive(callback_started, within: 0)

  adapter.close(connection)
  resource.stop(resources)
  let assert Ok(peer_release) =
    process.receive(peer_waiting, within: observation_milliseconds)
  process.send(peer_release, Nil)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)

  assert cancellation == Ok(Error(error.new(error.Service)))
  assert cancellation_task == Error(error.new(error.Service))
  assert callback_reaped
  assert reaper_reaped
  assert !process.is_alive(callback)
  assert !process.is_alive(reaper)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert duplicate_callback == Error(Nil)
  assert serving_done == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn stalled_source_cleanup_times_out_and_eventually_recovers_admission_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_config) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_config)
  let assert Ok(port) = server.port(listener)
  let peer_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      let response = server.send_response(incoming, 204, [])
      let peer_release = process.new_subject()
      process.send(peer_waiting, peer_release)
      let _released =
        process.receive(peer_release, within: observation_milliseconds)
      response
    })

  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let cleanup_started = process.new_subject()
  let released = process.new_subject()
  let assert Ok(native_config) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: observation_milliseconds,
      idle_milliseconds: observation_milliseconds,
    )
  let configuration =
    configuration
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_source_cleanup_probe(fn(_, _) {
      process.send(
        cleanup_started,
        CallbackFixture(
          process.new_subject(),
          process.self(),
          linked_processes(),
        ),
      )
      let never = process.new_subject()
      let _never = process.receive(never, within: 10_000)
      Ok(Nil)
    })
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(incoming) =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + observation_milliseconds,
      fn() { process.send(released, Nil) },
    )

  let cancel_finished = process.new_subject()
  let cancelling =
    http_test_support.start_task(fn() {
      let outcome = body.cancel_within(incoming.body, observation_milliseconds)
      process.send(cancel_finished, outcome)
      outcome
    })
  let assert Ok(CallbackFixture(_, callback, [reaper])) =
    process.receive(cleanup_started, within: observation_milliseconds)
  let callback_monitor = process.monitor(callback)
  let reaper_monitor = process.monitor(reaper)
  assert process.receive(cancel_finished, within: 0) == Error(Nil)
  let cancellation_task = http_test_support.await_task(cancelling)
  let cancellation = process.receive(cancel_finished, within: 0)
  let callback_reaped = join(callback_monitor)
  let reaper_reaped = join(reaper_monitor)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 8000,
    )

  adapter.close(connection)
  resource.stop(resources)
  let assert Ok(peer_release) =
    process.receive(peer_waiting, within: observation_milliseconds)
  process.send(peer_release, Nil)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)

  assert cancellation == Ok(Error(error.new(error.Timeout(error.Operation))))
  assert cancellation_task == Error(error.new(error.Timeout(error.Operation)))
  assert callback_reaped
  assert reaper_reaped
  assert !process.is_alive(callback)
  assert !process.is_alive(reaper)
  assert process.receive(released, within: 0) == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert serving_done == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn release_ack_requires_typed_success_and_actual_reaper_exit_test() -> Nil {
  let fixture_ready = process.new_subject()
  let ack_sent = process.new_subject()
  let completed = process.new_subject()
  let waiting =
    http_test_support.start_task(fn() {
      let acknowledgement = process.new_subject()
      let guardian_ready = process.new_subject()
      let guardian =
        process.spawn_unlinked(fn() {
          let exit_guardian = process.new_subject()
          process.send(guardian_ready, exit_guardian)
          process.send(acknowledgement, Ok(Nil))
          process.send(ack_sent, Nil)
          let _exit =
            process.receive(exit_guardian, within: observation_milliseconds)
          Nil
        })
      let assert Ok(exit_guardian) =
        process.receive(guardian_ready, within: observation_milliseconds)
      process.send(fixture_ready, AckFixture(exit_guardian))
      let outcome =
        adapter.await_response_release_ack(
          guardian: guardian,
          acknowledgement: acknowledgement,
          deadline: transport.monotonic_millisecond() + observation_milliseconds,
        )
      process.send(completed, outcome)
      outcome
    })
  let assert Ok(AckFixture(exit_guardian)) =
    process.receive(fixture_ready, within: observation_milliseconds)
  assert process.receive(ack_sent, within: observation_milliseconds) == Ok(Nil)
  assert process.receive(completed, within: 0) == Error(Nil)
  process.send(exit_guardian, Nil)
  assert process.receive(completed, within: observation_milliseconds)
    == Ok(Ok(Nil))
  assert http_test_support.await_task(waiting) == Ok(Nil)
}

pub fn release_ack_rejects_failure_and_reaper_exit_without_ack_test() -> Nil {
  let failure_ack = process.new_subject()
  let failure_guardian =
    process.spawn_unlinked(fn() {
      process.send(failure_ack, Error(error.new(error.Service)))
    })
  assert adapter.await_response_release_ack(
      guardian: failure_guardian,
      acknowledgement: failure_ack,
      deadline: transport.monotonic_millisecond() + observation_milliseconds,
    )
    == Error(error.new(error.Service))

  let missing_ack = process.new_subject()
  let missing_guardian = process.spawn_unlinked(fn() { Nil })
  assert adapter.await_response_release_ack(
      guardian: missing_guardian,
      acknowledgement: missing_ack,
      deadline: transport.monotonic_millisecond() + observation_milliseconds,
    )
    == Error(error.new(error.Service))
}

// nolint: assert_ok_pattern -- Fixture setup failures must fail this lifecycle test.
pub fn release_ack_timeout_uses_one_absolute_deadline_and_reaps_fixture_test() -> Nil {
  let ready = process.new_subject()
  let guardian =
    process.spawn_unlinked(fn() {
      let exit_guardian = process.new_subject()
      process.send(ready, exit_guardian)
      let _exit =
        process.receive(exit_guardian, within: observation_milliseconds)
      Nil
    })
  let monitor = process.monitor(guardian)
  let assert Ok(exit_guardian) =
    process.receive(ready, within: observation_milliseconds)
  let acknowledgement = process.new_subject()
  let timeout =
    adapter.await_response_release_ack(
      guardian: guardian,
      acknowledgement: acknowledgement,
      deadline: transport.monotonic_millisecond(),
    )
  process.send(exit_guardian, Nil)
  let reaped =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: observation_milliseconds)
  process.demonitor_process(monitor)
  assert timeout == Error(error.new(error.Timeout(error.Operation)))
  assert reaped == Ok(Nil)
  assert !process.is_alive(guardian)
}

fn join(monitor: process.Monitor) -> Bool {
  let reaped =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: observation_milliseconds)
  process.demonitor_process(monitor)
  reaped == Ok(Nil)
}

fn await_resource_usage(
  resources resources: resource.Controller,
  workers workers: Int,
  memory memory: Int,
  remaining_milliseconds remaining_milliseconds: Int,
) -> resource.Snapshot {
  let snapshot = resource.snapshot(resources)
  case
    snapshot.active_workers == workers && snapshot.memory_bytes == memory,
    remaining_milliseconds > 0
  {
    True, _ -> snapshot
    False, True -> {
      process.sleep(10)
      await_resource_usage(
        resources: resources,
        workers: workers,
        memory: memory,
        remaining_milliseconds: remaining_milliseconds - 10,
      )
    }
    False, False -> snapshot
  }
}
