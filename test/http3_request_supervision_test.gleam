import gleam/bit_array
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/client as unified_client
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

pub fn main() -> Nil {
  gleeunit.main()
}

type LeaseStartEvent {
  LeaseAdoptedBeforeStart(holder_is_reaper: Bool)
  LeaseStreamAccepted
}

@external(erlang, "http3_multiplexing_probe_ffi", "is_request_reaper")
fn is_http3_request_reaper(pid: process.Pid) -> Bool

pub fn short_connection_budget_does_not_shrink_reused_stream_deadline_test() -> Nil {
  let config =
    adapter.configure(
      native: native.new(),
      pull_bytes: 1024,
      maximum_body_bytes: 4096,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let config = adapter.with_connection_budget(config, 25) |> should.be_ok
  assert adapter.timeout_budgets(config) == #(25, 3000)
  assert adapter.request_operation_deadline(
      config: config,
      total_deadline: 5000,
      current: 0,
    )
    == 3000
  assert adapter.request_operation_deadline(
      config: config,
      total_deadline: 1000,
      current: 0,
    )
    == 1000
}

pub fn aggregate_request_budget_outlives_one_physical_ledger_test() -> Nil {
  let limits =
    unified_client.PoolLimits(
      maximum_connections: 2,
      maximum_connections_per_origin: 2,
      idle_milliseconds: 3000,
    )
  assert unified_client.http3_request_worker_limit(limits) == 200
}

pub fn lease_reaper_startup_uses_one_absolute_cleanup_allowance_test() -> Nil {
  assert adapter.lease_reaper_start_wait(request_deadline: 1000, current: 900)
    == 1100
  assert adapter.lease_reaper_start_wait(request_deadline: 1000, current: 1100)
    == 900
  assert adapter.lease_reaper_start_wait(request_deadline: 1000, current: 2000)
    == 0
}

pub fn request_worker_cleanup_never_rebases_after_a_stall_test() -> Nil {
  assert adapter.request_worker_join_wait(request_deadline: 1000, current: 900)
    == 3100
  assert adapter.request_worker_join_wait(request_deadline: 1000, current: 3500)
    == 500
  assert adapter.request_worker_join_wait(request_deadline: 1000, current: 4000)
    == 0
  assert adapter.request_worker_termination_wait(
      request_deadline: 1000,
      current: 4500,
    )
    == 500
  assert adapter.request_worker_termination_wait(
      request_deadline: 1000,
      current: 5000,
    )
    == 0
  assert adapter.local_process_registration_wait(deadline: 1000, current: 900)
    == 100
  assert adapter.local_process_registration_wait(deadline: 1000, current: 1100)
    == 0
}

pub fn detached_request_lease_requires_every_ownership_proof_test() -> Nil {
  assert adapter.request_lease_recovery_ready(True, True, True)
  assert !adapter.request_lease_recovery_ready(False, True, True)
  assert !adapter.request_lease_recovery_ready(True, False, True)
  assert !adapter.request_lease_recovery_ready(True, True, False)
  assert adapter.request_lease_publication_ready(True, True)
  assert !adapter.request_lease_publication_ready(False, True)
  // Accepting the recovery plan is only an ownership handoff.
  // This mutation guard forbids treating it as proof that resource.release has completed.
  assert !adapter.request_lease_publication_ready(True, False)
  assert adapter.request_recovery_requires_drain(False, True, True)
  assert adapter.request_recovery_requires_drain(True, False, True)
  assert adapter.request_recovery_requires_drain(True, True, False)
  assert !adapter.request_recovery_requires_drain(True, True, True)
}

pub fn unconfirmed_native_cancel_closes_owner_before_admission_release_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let serving =
    http_test_support.start_task(fn() {
      let incoming = server.accept(listener) |> should.be_ok
      server.respond(incoming, 200, [], <<>>)
    })
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_native_cleanup_probe(fn() { Error(Nil) })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let released = process.new_subject()
  let incoming =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
    |> should.be_ok
  let response = body.read_all(incoming.body, 1)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 6000,
    )
  let owner_alive = adapter.connection_owner_is_alive(connection)
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert response == Ok(#(<<>>, []))
  assert process.receive(released, within: 0) == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert !owner_alive
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

pub fn shared_lease_is_adopted_by_the_reaper_before_stream_open_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let starts = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      case server.accept(listener) {
        Error(_) -> Error(Nil)
        Ok(incoming) -> {
          process.send(starts, LeaseStreamAccepted)
          server.respond(incoming, 200, [], <<"leased":utf8>>)
          |> result.replace_error(Nil)
        }
      }
    })
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter.with_supervision(adapter_config, resources, process.self())
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let released = process.new_subject()
  let received =
    adapter.exchange_observed_with_lease_adoption(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + 3000,
      fn() {
        process.send(released, Nil)
        Ok(Nil)
      },
      fn(holder) {
        process.send(
          starts,
          LeaseAdoptedBeforeStart(is_http3_request_reaper(holder)),
        )
        Ok(Nil)
      },
      None,
    )
  let safe_response =
    received
    |> result.try(fn(incoming) {
      use contents <- result.try(body.read_all(incoming.body, 6))
      Ok(#(incoming.status, contents))
    })
  let first_start = process.receive(starts, within: 1000)
  let second_start = process.receive(starts, within: 1000)
  let release = process.receive(released, within: 1000)
  let serving_done = http_test_support.await_task(serving)
  let snapshot =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  assert safe_response == Ok(#(200, #(<<"leased":utf8>>, [])))
  assert first_start == Ok(LeaseAdoptedBeforeStart(True))
  assert second_start == Ok(LeaseStreamAccepted)
  assert release == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert serving_done == Ok(Nil)
  assert snapshot.active_workers == 0
  assert snapshot.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
}

pub fn unstarted_source_return_follows_global_admission_release_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let opened = process.new_subject()
  let retired = process.new_subject()
  let released = process.new_subject()
  let pulls = process.new_subject()
  let source =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulls, Nil)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { Nil },
    )
    |> should.be_ok
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_stream_open_refusal_probe(fn() {
      process.send(opened, Nil)
      Ok(True)
    })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let routed =
    adapter.exchange_observed_routable(
      connection,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
      fn() {
        process.send(retired, Nil)
        Ok(Nil)
      },
      None,
    )
  let observation = case routed {
    Ok(adapter.RequestUnstarted(failure, returned_source)) -> {
      let next_admission = resource.acquire(resources, memory_bytes: 4096)
      let admitted =
        result.map(next_admission, fn(lease) {
          {
            resource.release(lease)
            True
          }
        })
        |> result.unwrap(False)
      #(Some(error.kind(failure)), admitted, body.read_all(returned_source, 1))
    }
    Ok(adapter.ResponseStarted(incoming)) -> {
      body.cancel(incoming.body)
      #(None, False, Error(error.new(error.Service)))
    }
    Error(failure) -> #(Some(error.kind(failure)), False, Error(failure))
  }
  let final_usage =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 1000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  assert process.receive(opened, within: 0) == Ok(Nil)
  assert process.receive(retired, within: 0) == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert process.receive(pulls, within: 0) == Ok(Nil)
  assert process.receive(pulls, within: 0) == Error(Nil)
  assert observation
    == #(Some(error.Protocol(error.Http3)), True, Ok(#(<<>>, [])))
  assert final_usage.active_workers == 0
  assert final_usage.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
}

pub fn early_response_cancels_live_upload_before_response_and_release_terminals_test() -> Nil {
  let observed = process.new_subject()
  let reporter =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
    |> should.be_ok
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.protocol_selected(trace, context.Http3)
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let server_ready = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let upload_started = process.new_subject()
      process.send(server_ready, upload_started)
      let incoming = server.accept(listener) |> should.be_ok
      let started = process.receive(upload_started, within: 3000)
      let response_started = server.send_response(incoming, 413, [])
      let response_chunk = server.send_chunk(incoming, <<0, 1, 2>>)
      let response_finished =
        server.send_trailers(incoming, [#("x-result", "early")])
      #(started, response_started, response_chunk, response_finished)
    })
  let upload_started =
    process.receive(server_ready, within: 1000) |> should.be_ok
  let source_cancelled = process.new_subject()
  let source =
    body.from_pull(
      body.pull(fn(_) {
        process.send(upload_started, Nil)
        let never = process.new_subject()
        process.receive_forever(never)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { process.send(source_cancelled, Nil) },
    )
    |> should.be_ok
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 5000,
      idle_milliseconds: 5000,
    )
    |> should.be_ok
  let adapter_config =
    adapter.with_supervision(adapter_config, resources, process.self())
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let released = process.new_subject()
  let received =
    adapter.exchange_observed(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() + 5000,
      fn() { process.send(released, Nil) },
      trace,
    )
  let safe_response =
    received
    |> result.try(fn(incoming) {
      use contents <- result.try(body.read_all(incoming.body, 8))
      Ok(#(
        incoming.status,
        bit_array.byte_size(contents.0),
        list.length(contents.1),
      ))
    })
    |> result.map_error(error.kind)
  let cancellation = process.receive(source_cancelled, within: 2000)
  let publication = process.receive(released, within: 2000)
  let serving_done = http_test_support.await_task(serving)
  let snapshot =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let diagnostics_stopped = diagnostics.stop(reporter)
  let stages = request_stages(collect_observations(observed, []))
  let transmission_starts =
    list.filter(stages, fn(entry) {
      case entry.1 {
        diagnostics.PhaseStarted(
          _,
          diagnostics.RequestTransmission(context.Http3),
        ) -> True
        _ -> False
      }
    })
  let transmission_finishes =
    list.filter(stages, fn(entry) {
      case entry.1 {
        diagnostics.PhaseFinished(
          _,
          diagnostics.RequestTransmission(context.Http3),
          _,
        ) -> True
        _ -> False
      }
    })
  let response_finishes =
    list.filter(stages, fn(entry) {
      case entry.1 {
        diagnostics.PhaseFinished(
          _,
          diagnostics.ResponseReception(context.Http3),
          _,
        ) -> True
        _ -> False
      }
    })
  let releases =
    list.filter(stages, fn(entry) {
      case entry.1 {
        diagnostics.AttemptReleased(_, Some(context.Http3), _) -> True
        _ -> False
      }
    })
  let #(transmission_started, attempt) =
    case transmission_starts {
      [#(transmission_started, diagnostics.PhaseStarted(attempt, _))] ->
        Ok(#(transmission_started, attempt))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let #(transmission_finished, finished_attempt, transmission_failure) =
    case transmission_finishes {
      [
        #(
          transmission_finished,
          diagnostics.PhaseFinished(
            finished_attempt,
            _,
            Error(transmission_failure),
          ),
        ),
      ] -> Ok(#(transmission_finished, finished_attempt, transmission_failure))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let #(response_finished, response_attempt) =
    case response_finishes {
      [
        #(
          response_finished,
          diagnostics.PhaseFinished(response_attempt, _, Ok(Nil)),
        ),
      ] -> Ok(#(response_finished, response_attempt))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  let #(released_sequence, release_attempt) =
    case releases {
      [#(released_sequence, diagnostics.AttemptReleased(release_attempt, _, _))] ->
        Ok(#(released_sequence, release_attempt))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert safe_response == Ok(#(413, 3, 1))
  assert cancellation == Ok(Nil)
  assert publication == Ok(Nil)
  assert serving_done == #(Ok(Nil), Ok(Nil), Ok(Nil), Ok(Nil))
  assert snapshot.active_workers == 0
  assert snapshot.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
  assert diagnostics_stopped == Ok(Nil)
  assert attempt == finished_attempt
  assert attempt == response_attempt
  assert attempt == release_attempt
  assert error.kind(transmission_failure) == error.Cancelled
  assert transmission_started < transmission_finished
  assert transmission_finished < response_finished
  assert response_finished < released_sequence
}

pub fn request_supervisor_start_failure_releases_every_unstarted_owner_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let cancelled = process.new_subject()
  let released = process.new_subject()
  let source =
    body.from_pull(
      body.pull(fn(_) { Error(error.new(error.Service)) }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
    |> should.be_ok
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_request_supervisor_start_probe(fn() {
      Error(error.new(error.Service))
    })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let failure =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
  let snapshot =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let failure =
    case failure {
      Error(failure) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Service
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert process.receive(released, within: 1000) == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert snapshot.active_workers == 0
  assert snapshot.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
}

pub fn request_supervisor_start_cleanup_failure_recovers_lease_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let cleanup_attempted = process.new_subject()
  let released = process.new_subject()
  let source =
    body.from_pull(
      body.pull(fn(_) { Error(error.new(error.Service)) }),
      None,
      None,
      fn() { Nil },
    )
    |> should.be_ok
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_source_cleanup_probe(fn(_, _) {
      process.send(cleanup_attempted, Nil)
      Error(error.new(error.Timeout(error.Operation)))
    })
    |> adapter.with_request_supervisor_start_probe(fn() {
      Error(error.new(error.Service))
    })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let outcome =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 5000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let failure =
    case outcome {
      Error(failure) -> Ok(failure)
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert error.kind(failure) == error.Service
  assert process.receive(cleanup_attempted, within: 1000) == Ok(Nil)
  assert process.receive(cleanup_attempted, within: 0) == Error(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
}

pub fn preheader_deadline_waits_for_cleanup_proof_before_release_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let server_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      result.map(server.accept(listener), fn(incoming) {
        {
          let gate = process.new_subject()
          process.send(server_waiting, gate)
          let _continued = process.receive(gate, within: 5000)
          let _responded = server.respond(incoming, 200, [], <<>>)
          Nil
        }
      })
      |> result.unwrap(Nil)
    })
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let cleanup_started = process.new_subject()
  let released = process.new_subject()
  let completed = process.new_subject()
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_source_cleanup_probe(fn(_, _) {
      let gate = process.new_subject()
      process.send(cleanup_started, gate)
      case process.receive(gate, within: 10_000) {
        Ok(Nil) -> Ok(Nil)
        Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
      }
    })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let exchange_task =
    http_test_support.start_task(fn() {
      let classification = case
        adapter.exchange(
          connection,
          request.new()
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_body(body.empty()),
          transport.monotonic_millisecond() + 500,
          fn() { process.send(released, Nil) },
        )
      {
        Error(failure) -> error.kind(failure)
        Ok(incoming) -> {
          body.cancel(incoming.body)
          error.Service
        }
      }
      process.send(completed, classification)
    })
  let server_gate =
    process.receive(server_waiting, within: 3000) |> should.be_ok
  let cleanup_gate =
    process.receive(cleanup_started, within: 5000) |> should.be_ok
  let premature = process.receive(completed, within: 100)
  let held = resource.snapshot(resources)
  let early_publication = process.receive(released, within: 0)
  // Existing admissions remain releasable after stop.
  // Holding this proof gate makes that ordering deterministic rather than scheduler dependent.
  resource.stop(resources)
  process.send(cleanup_gate, Nil)
  let outcome = process.receive(completed, within: 4000)
  let publication = process.receive(released, within: 1000)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 5000,
    )
  process.send(server_gate, Nil)
  let exchange_done = http_test_support.await_task(exchange_task)
  adapter.close(connection)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert premature == Error(Nil)
  assert held.active_workers == 1
  assert held.memory_bytes == 4096
  assert early_publication == Error(Nil)
  assert outcome == Ok(error.Timeout(error.Total))
  assert publication == Ok(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert exchange_done == Nil
  assert stopped == Ok(server.Stopped)
  assert serving_done == Nil
}

pub fn preheader_cleanup_down_order_is_typed_and_recovers_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let server_config = server.new(certificate, private_key) |> should.be_ok
  let listener = server.start(server_config) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let server_waiting = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      result.map(server.accept(listener), fn(incoming) {
        {
          let gate = process.new_subject()
          process.send(server_waiting, gate)
          let _continued = process.receive(gate, within: 5000)
          let _responded = server.respond(incoming, 200, [], <<>>)
          Nil
        }
      })
      |> result.unwrap(Nil)
    })
  let terminal_protocols = process.new_subject()
  let release_results = process.new_subject()
  let reporter =
    diagnostics.start(32, 1000, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptFinished(_, protocol, _),
        ) -> process.send(terminal_protocols, protocol)
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptReleased(_, protocol, cleanup),
        ) ->
          process.send(release_results, #(
            protocol,
            result.map_error(cleanup, error.kind),
          ))
        _ -> Nil
      }
      Ok(Nil)
    })
    |> should.be_ok
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.protocol_selected(trace, context.Http3)
  let limits =
    resource.limits(maximum_workers: 1, memory_bytes: 4096) |> should.be_ok
  let resources = resource.start(limits)
  let upload_started = process.new_subject()
  let child_cleanup_started = process.new_subject()
  let source_cancelled = process.new_subject()
  let released = process.new_subject()
  let completed = process.new_subject()
  let source =
    body.from_pull(
      body.pull(fn(_) {
        process.send(upload_started, Nil)
        let never = process.new_subject()
        process.receive_forever(never)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { process.send(source_cancelled, Nil) },
    )
    |> should.be_ok
  let native_config =
    native.with_ca_certificate(native.new(), ca_certificate) |> should.be_ok
  let adapter_config =
    adapter.configure(
      native: native_config,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 500,
      idle_milliseconds: 3000,
    )
    |> should.be_ok
  let adapter_config =
    adapter_config
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_child_cleanup_probe(fn() {
      let gate = process.new_subject()
      process.send(child_cleanup_started, gate)
      let _continued = process.receive(gate, within: 10_000)
      Error(error.new(error.Timeout(error.Operation)))
    })
  let connection =
    adapter.connect(adapter_config, "localhost", port, fn(_) {
      Ok(fn() { Nil })
    })
    |> should.be_ok
  let exchange_task =
    http_test_support.start_task(fn() {
      let classification = case
        adapter.exchange_observed(
          connection,
          request.new()
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_body(source),
          transport.monotonic_millisecond() + 500,
          fn() { process.send(released, Nil) },
          trace,
        )
      {
        Error(failure) -> {
          client_trace.finished_if_missing(trace, None, Error(failure))
          error.kind(failure)
        }
        Ok(incoming) -> {
          body.cancel(incoming.body)
          error.Service
        }
      }
      process.send(completed, classification)
    })
  let server_gate =
    process.receive(server_waiting, within: 3000) |> should.be_ok
  assert process.receive(upload_started, within: 3000) == Ok(Nil)
  let first_cleanup_gate =
    process.receive(child_cleanup_started, within: 5000) |> should.be_ok
  let premature = process.receive(completed, within: 100)
  let held = resource.snapshot(resources)
  process.send(first_cleanup_gate, Nil)
  let second_cleanup_gate =
    process.receive(child_cleanup_started, within: 3000) |> should.be_ok
  let between_child_downs = resource.snapshot(resources)
  process.send(second_cleanup_gate, Nil)
  let outcome = process.receive(completed, within: 4000)
  let publication = process.receive(released, within: 0)
  let converged =
    await_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 6000,
    )
  let source_cleanup = process.receive(source_cancelled, within: 1000)
  process.send(server_gate, Nil)
  let exchange_done = http_test_support.await_task(exchange_task)
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  let transitions = client_trace.transition_snapshot(trace)
  let diagnostics_stopped = diagnostics.stop(reporter)
  let terminal = process.receive(terminal_protocols, within: 0)
  let diagnostic_release = process.receive(release_results, within: 0)
  assert premature == Error(Nil)
  assert held.active_workers == 1
  assert held.memory_bytes == 4096
  assert between_child_downs.active_workers == 1
  assert between_child_downs.memory_bytes == 4096
  assert outcome == Ok(error.Timeout(error.Total))
  assert publication == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert source_cleanup == Ok(Nil)
  assert exchange_done == Nil
  assert stopped == Ok(server.Stopped)
  assert serving_done == Nil
  assert transitions == client_trace.TransitionSnapshot(0, 0, 0)
  assert diagnostics_stopped == Ok(Nil)
  assert terminal == Ok(Some(context.Http3))
  assert process.receive(terminal_protocols, within: 0) == Error(Nil)
  assert diagnostic_release
    == Ok(#(Some(context.Http3), Error(error.Timeout(error.Operation))))
  assert process.receive(release_results, within: 0) == Error(Nil)
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

fn collect_observations(
  observed: process.Subject(diagnostics.Observation),
  reversed: List(diagnostics.Observation),
) -> List(diagnostics.Observation) {
  case process.receive(observed, within: 0) {
    Ok(record) -> collect_observations(observed, [record, ..reversed])
    Error(Nil) -> list.reverse(reversed)
  }
}

fn request_stages(
  records: List(diagnostics.Observation),
) -> List(#(Int, diagnostics.ClientStage)) {
  records
  |> list.filter_map(fn(record) {
    case record.event {
      diagnostics.ClientObserved(_, _, stage) -> Ok(#(record.sequence, stage))
      _ -> Error(Nil)
    }
  })
  |> list.sort(fn(first, second) { int.compare(first.0, second.0) })
}
