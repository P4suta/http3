import gleam/bool
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/client
import http/context
import http/error
import http/internal/http3/client as adapter
import http/internal/transport
import http/resource
import http/server as http_server
import http3/address
import http3/client as native
import http3/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn request_rejected_preserves_peer_unprocessed_evidence_test() -> Nil {
  let rejected = adapter.map_error(native.RequestRejected)
  let draining = adapter.map_error(native.ConnectionDraining)

  assert error.kind(rejected) == error.Protocol(error.Http3)
  assert error.retry_evidence(rejected) == error.PeerGuaranteedUnprocessed
  assert error.kind(draining) == error.Protocol(error.Http3)
  assert error.retry_evidence(draining) == error.NoRetryEvidence
}

@external(erlang, "http_client_resource_test", "reservation_precedes_connection_actor_test")
pub fn http3_connection_reserves_capacity_before_spawning_test() -> Nil

@external(erlang, "http_client_resource_test", "resource_and_tcp_share_the_connection_budget_test")
pub fn http3_and_tcp_share_connection_capacity_test() -> Nil

@external(erlang, "http_client_resource_test", "deadline_aware_resource_cancel_never_uses_the_global_owner_wait_test")
pub fn tcp_race_resource_cancel_uses_its_cleanup_deadline_test() -> Nil

@external(erlang, "http_client_resource_test", "deadline_aware_resource_checkout_preserves_a_late_pool_entry_test")
pub fn http3_resource_checkout_preserves_the_pool_after_its_deadline_test() -> Nil

@external(erlang, "http_client_resource_test", "offered_resource_checkout_abandon_restores_pool_test")
pub fn http3_resource_checkout_abandon_restores_the_offered_pool_entry_test() -> Nil

@external(erlang, "http_client_resource_test", "offered_resource_checkout_expiry_restores_pool_and_rejects_waiter_test")
pub fn http3_resource_checkout_expiry_restores_pool_and_rejects_waiter_test() -> Nil

@external(erlang, "http_client_resource_test", "confirmed_resource_checkout_is_rejected_when_caller_resumes_late_test")
pub fn http3_resource_checkout_rejects_confirmation_observed_after_deadline_test() -> Nil

@external(erlang, "http_client_resource_test", "late_resource_checkout_confirm_is_rejected_test")
pub fn http3_resource_checkout_rejects_a_late_confirmation_test() -> Nil

@external(erlang, "http_client_resource_test", "pending_resource_checkout_returns_to_pool_when_caller_dies_test")
pub fn http3_resource_checkout_restores_pending_entry_on_caller_exit_test() -> Nil

@external(erlang, "http_client_resource_test", "pending_resource_checkout_is_reclaimed_by_drain_and_close_test")
pub fn http3_pending_resource_checkout_is_reclaimed_by_drain_and_close_test() -> Nil

@external(erlang, "http_client_resource_test", "pending_resource_checkout_never_exceeds_connection_limit_test")
pub fn http3_pending_resource_checkout_obeys_the_connection_limit_test() -> Nil

pub fn http3_resource_failure_tcp_fallback_respects_total_deadline_test() -> Nil {
  let starts = process.new_subject()
  let start = fn(remaining) {
    process.send(starts, remaining)
    Ok(Nil)
  }
  let at_deadline =
    client.run_tcp_fallback_before_total_deadline(100, 100, start)
  let after_deadline =
    client.run_tcp_fallback_before_total_deadline(100, 101, start)
  assert at_deadline == Error(error.new(error.Timeout(error.Total)))
  assert after_deadline == Error(error.new(error.Timeout(error.Total)))
  assert process.receive(starts, within: 0) == Error(Nil)

  let before_deadline =
    client.run_tcp_fallback_before_total_deadline(100, 99, start)
  assert before_deadline == Ok(Nil)
  assert process.receive(starts, within: 0) == Ok(1)
  assert process.receive(starts, within: 0) == Error(Nil)
}

@external(erlang, "http_client_resource_test", "close_terminates_an_adopted_resource_owner_test")
pub fn http3_adopted_owner_closes_with_client_lifecycle_test() -> Nil

@external(erlang, "http_client_resource_test", "late_adoption_after_close_reclaims_the_resource_owner_test")
pub fn http3_late_adoption_closes_the_candidate_test() -> Nil

@external(erlang, "http_client_resource_test", "idle_resource_pool_preserves_value_and_closes_on_drain_test")
pub fn http3_idle_pool_is_owned_and_drainable_test() -> Nil

@external(erlang, "http_client_resource_test", "abandoned_reservation_releases_capacity_test")
pub fn http3_abandoned_connection_reservation_releases_capacity_test() -> Nil

@external(erlang, "http_client_resource_test", "socket_owner_handoff_releases_capacity_on_new_owner_down_test")
pub fn tcp_race_winner_owner_down_closes_socket_and_releases_capacity_test() -> Nil

@external(erlang, "http_client_resource_test", "reserved_socket_adoption_installs_owner_monitor_test")
pub fn reserved_tcp_socket_adoption_installs_an_owner_monitor_test() -> Nil

@external(erlang, "http_client_resource_test", "tls_replacement_refreshes_the_owned_socket_monitor_test")
pub fn tls_replacement_refreshes_the_lifecycle_owner_monitor_test() -> Nil

@external(erlang, "http_client_resource_test", "http1_pool_updates_owner_on_checkin_and_checkout_test")
pub fn http1_pool_checkin_and_checkout_update_lifecycle_owner_test() -> Nil

@external(erlang, "http_client_resource_test", "http2_pool_updates_lifecycle_owner_on_checkin_and_checkout_test")
pub fn http2_pool_checkin_and_checkout_update_lifecycle_owner_test() -> Nil

@external(erlang, "http_client_resource_test", "race_guard_processes")
fn race_guard_processes() -> List(process.Pid)

@external(erlang, "http_client_resource_test", "race_attempt_processes")
fn race_attempt_processes() -> List(process.Pid)

@external(erlang, "http_client_resource_test", "linked_processes")
fn linked_processes() -> List(process.Pid)

pub fn http3_final_headers_and_response_body_arrive_while_upload_is_stalled_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      assert server.send_response(incoming, 413, [
          #("content-type", "text/plain"),
        ])
        == Ok(Nil)
      assert server.send_chunk(incoming, <<"rejected":utf8>>) == Ok(Nil)
      assert server.send_trailers(incoming, [#("x-result", "early")]) == Ok(Nil)
    })
  let pulling = process.new_subject()
  let cancelled = process.new_subject()
  let released = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        let gate = process.new_subject()
        process.send(pulling, process.self())
        let _released = process.receive(gate, within: 10_000)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) = native.with_timeout(configuration, 3000)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let outgoing =
    request.new()
    |> request.set_method(http.Put)
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(source)
  let incoming =
    adapter.exchange(
      connection,
      outgoing,
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
  let started = process.receive(pulling, within: 1000)
  let read = case incoming {
    Ok(incoming) -> body.read_all(incoming.body, 8)
    Error(failure) -> Error(failure)
  }
  let disposed = process.receive(cancelled, within: 2000)
  let release = process.receive(released, within: 1000)
  adapter.close(connection)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)
  let assert Ok(incoming) = incoming
  assert incoming.status == 413
  let assert Ok(_pulling_pid) = started
  assert read == Ok(#(<<"rejected":utf8>>, [#("x-result", "early")]))
  assert disposed == Ok(Nil)
  assert release == Ok(Nil)
  assert serving_done == Nil
  assert stopped == Ok(server.Stopped)
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

pub fn http3_request_and_response_trailers_survive_streaming_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      assert server.next_event(incoming) == Ok(server.Data(<<"upload":utf8>>))
      assert server.next_event(incoming)
        == Ok(server.Trailers([#("x-upload", "finished")]))
      assert server.next_event(incoming) == Ok(server.End)
      assert server.send_response(incoming, 200, []) == Ok(Nil)
      assert server.send_chunk(incoming, <<"download":utf8>>) == Ok(Nil)
      assert server.send_trailers(incoming, [#("x-download", "finished")])
        == Ok(Nil)
    })
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let outgoing =
    request.new()
    |> request.set_method(http.Post)
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(
      body.from_bytes_with_trailers(<<"upload":utf8>>, [
        #("x-upload", "finished"),
      ]),
    )
  let received =
    adapter.exchange(
      connection,
      outgoing,
      transport.monotonic_millisecond() + 3000,
      fn() { Nil },
    )
  let completed = case received {
    Error(failure) -> Error(failure)
    Ok(incoming) -> body.read_all(incoming.body, 8)
  }
  adapter.close(connection)
  let serving_done = http_test_support.await_task(serving)
  let stopped = server.stop(listener)
  assert completed == Ok(#(<<"download":utf8>>, [#("x-download", "finished")]))
  assert serving_done == Nil
  assert stopped == Ok(server.Stopped)
}

pub fn unified_http3_accepts_a_nonreplayable_upload_and_returns_early_headers_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      case server.accept(listener) {
        Ok(incoming) -> server.respond(incoming, 413, [], <<"early":utf8>>)
        Error(failure) -> Error(failure)
      }
    })
  let cancelled = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.sleep(10_000)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
    )
  let completed = case received {
    Error(failure) -> Error(failure)
    Ok(exchange) -> body.read_all(client.response(exchange).body, 5)
  }
  let closed = client.close(running)
  let stopped = server.stop(listener)
  let _serving_done = http_test_support.await_task(serving)
  let assert Ok(exchange) = received
  assert client.selected_protocol(exchange) == client.Http3
  assert client.response(exchange).status == 413
  assert completed == Ok(#(<<"early":utf8>>, []))
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  assert closed == Ok(Nil)
  assert stopped == Ok(server.Stopped)
}

pub fn deferred_http3_failure_keeps_a_shared_supervisor_admission_slot_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(first) = server.accept(listener)
      assert server.send_response(first, 200, []) == Ok(Nil)
      case server.accept(listener) {
        Ok(second) -> server.respond(second, 200, [], <<>>)
        Error(failure) -> Error(failure)
      }
    })
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 8192)
  let resources = resource.start(limits)
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let configuration =
    adapter.with_supervision(configuration, resources, process.self())
  let assert Ok(first_connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(second_connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let pulling = process.new_subject()
  let failed = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        let gate = process.new_subject()
        process.send(pulling, gate)
        let _released = process.receive(gate, within: 3000)
        process.send(failed, Nil)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { Nil },
    )
  let outgoing =
    request.new()
    |> request.set_method(http.Put)
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(source)
  let assert Ok(first) =
    adapter.exchange(
      first_connection,
      outgoing,
      transport.monotonic_millisecond() + 3000,
      fn() { Nil },
    )
  let assert Ok(gate) = process.receive(pulling, within: 1000)
  process.send(gate, Nil)
  let failure_retained = process.receive(failed, within: 1000)
  let retained = resource.snapshot(resources)
  let second =
    adapter.exchange(
      second_connection,
      request.set_body(outgoing, body.empty()),
      transport.monotonic_millisecond() + 1000,
      fn() { Nil },
    )
  let second_kind = case second {
    Ok(response) -> {
      body.cancel(response.body)
      None
    }
    Error(failure) -> Some(error.kind(failure))
  }
  let observed = body.read(first.body, 1)
  adapter.close(first_connection)
  adapter.close(second_connection)
  let stopped = server.stop(listener)
  let _serving_done = http_test_support.await_task(serving)
  let converged =
    await_adapter_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 3000,
    )
  assert failure_retained == Ok(Nil)
  assert retained.active_workers == 1
  assert second_kind == Some(error.Resource(error.RequestWorkers))
  assert observed == Error(error.new(error.Service))
  assert converged.active_workers == 0
  assert stopped == Ok(server.Stopped)
}

pub fn http3_preflight_resource_refusal_releases_the_checked_out_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let assert Ok(blocker) = resource.acquire(resources, memory_bytes: 4096)
  let cancelled = process.new_subject()
  let released = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) { Error(error.new(error.Service)) }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let configuration =
    adapter.with_supervision(configuration, resources, process.self())
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
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
  let release = process.receive(released, within: 1000)
  let cancellation = process.receive(cancelled, within: 1000)
  resource.release(blocker)
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  assert outcome == Error(error.new(error.Resource(error.RequestWorkers)))
  assert cancellation == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert release == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert resource.snapshot(resources).active_workers == 0
  assert stopped == Ok(server.Stopped)
}

pub fn http3_expired_preflight_deadline_releases_the_checked_out_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let cancelled = process.new_subject()
  let released = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) { Error(error.new(error.Service)) }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let outcome =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() - 1,
      fn() { process.send(released, Nil) },
    )
  let release = process.receive(released, within: 1000)
  let cancellation = process.receive(cancelled, within: 1000)
  adapter.close(connection)
  let stopped = server.stop(listener)
  assert outcome == Error(error.new(error.Timeout(error.Total)))
  assert cancellation == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert release == Ok(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  assert stopped == Ok(server.Stopped)
}

pub fn connection_race_guard_exits_when_its_requester_dies_test() -> Nil {
  let existing = race_guard_processes()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_connect_gate(fn() {
      let blocked = process.new_subject()
      process.receive(blocked, within: 30_000)
      |> result.replace_error(error.new(error.ConnectFailed))
    })
    |> client.start
  let requester =
    process.spawn_unlinked(fn() {
      let _result =
        client.exchange(
          running,
          request.new()
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_body(body.empty()),
        )
      Nil
    })
  let accepted = transport.accept(listener, 1000)
  let guard = await_new_race_guard(existing, 100)
  let attempts = race_attempt_processes()
  let attempt_monitors = list.map(attempts, process.monitor)
  process.kill(requester)
  let joined = case guard {
    None -> False
    Some(pid) -> {
      let monitor = process.monitor(pid)
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.demonitor_process(monitor)
      process.kill(pid)
      joined == Ok(Nil)
    }
  }
  let closed = client.close(running)
  let attempts_joined =
    list.map(attempt_monitors, fn(monitor) {
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 0)
      process.demonitor_process(monitor)
      joined == Ok(Nil)
    })
  let accepted_closed = case accepted {
    Ok(socket) -> transport.close(socket)
    Error(failure) -> Error(failure)
  }
  let _stopped = transport.stop(listener)
  assert joined
  assert closed == Ok(Nil)
  assert accepted_closed == Ok(Nil)
  assert attempts != []
  assert list.all(attempts_joined, fn(joined) { joined })
}

pub fn unconfirmed_connection_race_join_is_typed_and_quarantined_test() -> Nil {
  let existing = race_guard_processes()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_configuration)
  let assert Ok(port) = server.port(listener)
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
  let assert Ok(configuration) =
    client.with_timeouts(
      configuration,
      client.Timeouts(1000, 2000, 2000, 3000, 3000, 5000),
    )
  let assert Ok(running) =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_race_join_confirmation(False)
    |> client.start
  let outcome =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let classification = case outcome {
    Error(failure) -> Some(error.kind(failure))
    Ok(exchange) -> {
      body.cancel(client.response(exchange).body)
      None
    }
  }
  let close_started = transport.monotonic_millisecond()
  let closed = client.close(running)
  let close_elapsed = transport.monotonic_millisecond() - close_started
  let stopped = server.stop(listener)
  let no_new_guards =
    list.all(race_guard_processes(), fn(pid) { list.contains(existing, pid) })
  assert classification == Some(error.Timeout(error.Operation))
  assert closed == Error(error.new(error.Timeout(error.Operation)))
  assert close_elapsed >= 2500
  assert close_elapsed <= 6000
  assert stopped == Ok(server.Stopped)
  assert no_new_guards
}

pub fn late_tcp_claim_offer_releases_before_the_next_race_test() -> Nil {
  run_tcp_handoff_confirmation_failure(False, True)
}

pub fn unconfirmed_tcp_claim_commit_releases_before_the_next_race_test() -> Nil {
  run_tcp_handoff_confirmation_failure(True, False)
}

fn run_tcp_handoff_confirmation_failure(
  offer_confirmed: Bool,
  commit_confirmed: Bool,
) -> Nil {
  let existing = race_guard_processes()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(_: request.Request(body.Body), _) {
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_text("tcp-winner"),
    ))
  }
  let assert Ok(executor) = http_server.start(http_server.defaults(), handler)
  let assert Ok(tcp_listener) =
    http_server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      http_server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = http_server.listener_endpoint(tcp_listener)
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(2, 2, 3000))
  let assert Ok(configuration) =
    client.with_timeouts(
      configuration,
      client.Timeouts(1000, 2000, 2000, 3000, 3000, 5000),
    )
  let assert Ok(running) =
    configuration
    |> client.without_pooling
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_connect_gate(fn() {
      Error(error.new(error.ConnectFailed))
    })
    |> client.with_race_handoff_confirmation(offer_confirmed, commit_confirmed)
    |> client.start
  let first = client.exchange(running, tcp_race_request(port, "/first"))
  let second = client.exchange(running, tcp_race_request(port, "/second"))
  let first_kind = exchange_failure_kind(first)
  let second_kind = exchange_failure_kind(second)
  let no_new_guards =
    list.all(race_guard_processes(), fn(pid) { list.contains(existing, pid) })
  let closed = client.close(running)
  let drained = http_server.drain_listener(tcp_listener)
  let stopped = http_server.stop_listener(tcp_listener)
  let executor_stopped = http_server.stop(executor)
  assert first_kind == Some(error.Timeout(error.Operation))
  assert second_kind == Some(error.Timeout(error.Operation))
  assert no_new_guards
  assert closed == Ok(Nil)
  assert drained == Ok(Nil)
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}

pub fn tcp_claim_commit_keeps_the_socket_after_contender_exit_test() -> Nil {
  let existing = race_guard_processes()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(_: request.Request(body.Body), _) {
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_text("adopted"),
    ))
  }
  let assert Ok(executor) = http_server.start(http_server.defaults(), handler)
  let assert Ok(tcp_listener) =
    http_server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      http_server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = http_server.listener_endpoint(tcp_listener)
  let assert Ok(running) =
    client.defaults()
    |> client.without_pooling
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_connect_gate(fn() {
      Error(error.new(error.ConnectFailed))
    })
    |> client.start
  let assert Ok(exchange) =
    client.exchange(running, tcp_race_request(port, "/adopted"))
  let protocol = client.selected_protocol(exchange)
  let read = body.read_all(client.response(exchange).body, 7)
  let no_new_guards =
    list.all(race_guard_processes(), fn(pid) { list.contains(existing, pid) })
  let closed = client.close(running)
  let drained = http_server.drain_listener(tcp_listener)
  let stopped = http_server.stop_listener(tcp_listener)
  let executor_stopped = http_server.stop(executor)
  assert protocol == client.Http2
  assert read == Ok(#(<<"adopted":utf8>>, []))
  assert no_new_guards
  assert closed == Ok(Nil)
  assert drained == Ok(Nil)
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}

pub fn authenticated_tcp_candidate_requester_death_releases_guard_and_capacity_test() -> Nil {
  let existing = race_guard_processes()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(_: request.Request(body.Body), _) {
    Ok(response.Response(status: 200, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = http_server.start(http_server.defaults(), handler)
  let assert Ok(tcp_listener) =
    http_server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      http_server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = http_server.listener_endpoint(tcp_listener)
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(2, 2, 3000))
  let candidate_waiting = process.new_subject()
  let assert Ok(running) =
    configuration
    |> client.without_pooling
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_connect_gate(fn() {
      Error(error.new(error.ConnectFailed))
    })
    |> client.with_https_race_candidate_gate(fn(candidate, deadline) {
      case candidate {
        client.Http3AuthenticatedCandidate -> Ok(Nil)
        client.TcpAuthenticatedCandidate -> {
          let release = process.new_subject()
          process.send(candidate_waiting, release)
          process.receive(
            release,
            within: int.max(0, deadline - transport.monotonic_millisecond()),
          )
          |> result.replace_error(error.new(error.Timeout(error.Total)))
        }
      }
    })
    |> client.with_race_handoff_confirmation(True, False)
    |> client.start
  let requester =
    process.spawn_unlinked(fn() {
      let _outcome =
        client.exchange(running, tcp_race_request(port, "/owner-dies"))
      Nil
    })
  let requester_monitor = process.monitor(requester)
  let _first_candidate =
    process.receive(candidate_waiting, within: 2500) |> should.be_ok
  let guard_monitor = case await_new_race_guard(existing, 100) {
    None -> None
    Some(pid) -> Some(process.monitor(pid))
  }
  process.kill(requester)
  let requester_joined =
    process.new_selector()
    |> process.select_specific_monitor(requester_monitor, fn(_) { Nil })
    |> process.selector_receive(within: 1000)
  process.demonitor_process(requester_monitor)
  let guard_joined = case guard_monitor {
    None -> False
    Some(monitor) -> {
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.demonitor_process(monitor)
      joined == Ok(Nil)
    }
  }
  let probe =
    http_test_support.start_task(fn() {
      client.exchange(running, tcp_race_request(port, "/probe"))
      |> exchange_failure_kind
    })
  let probe_release =
    process.receive(candidate_waiting, within: 2500) |> should.be_ok
  process.send(probe_release, Nil)
  let probe_kind = http_test_support.await_task(probe)
  let no_new_guards =
    list.all(race_guard_processes(), fn(pid) { list.contains(existing, pid) })
  let closed = client.close(running)
  let drained = http_server.drain_listener(tcp_listener)
  let stopped = http_server.stop_listener(tcp_listener)
  let executor_stopped = http_server.stop(executor)
  assert requester_joined == Ok(Nil)
  assert guard_joined
  assert probe_kind == Some(error.Timeout(error.Operation))
  assert no_new_guards
  assert closed == Ok(Nil)
  assert drained == Ok(Nil)
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}

fn tcp_race_request(port: Int, path: String) -> request.Request(body.Body) {
  request.Request(
    method: http.Get,
    headers: [],
    body: body.empty(),
    scheme: http.Https,
    host: "localhost",
    port: Some(port),
    path: path,
    query: None,
  )
}

fn exchange_failure_kind(
  outcome: Result(client.Exchange, error.Error),
) -> option.Option(error.ErrorKind) {
  case outcome {
    Error(failure) -> Some(error.kind(failure))
    Ok(exchange) -> {
      body.cancel(client.response(exchange).body)
      None
    }
  }
}

fn await_new_race_guard(
  previous: List(process.Pid),
  remaining: Int,
) -> option.Option(process.Pid) {
  case
    list.find(race_guard_processes(), fn(pid) { !list.contains(previous, pid) })
  {
    Ok(pid) -> Some(pid)
    Error(Nil) if remaining > 0 -> {
      process.sleep(1)
      await_new_race_guard(previous, remaining - 1)
    }
    Error(Nil) -> None
  }
}

pub fn unified_http3_reuses_one_connection_and_streams_past_the_fetch_limit_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let peers = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(first) = server.accept(listener)
      let first_peer = server.peer_endpoint(first)
      let first_authority = server.authority(first)
      assert server.respond(first, 200, [], <<"streamed":utf8>>) == Ok(Nil)
      let assert Ok(second) = server.accept(listener)
      process.send(peers, #(
        first_peer,
        server.peer_endpoint(second),
        first_authority,
        server.authority(second),
      ))
      server.respond(second, 200, [], <<"reused":utf8>>)
    })
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
  let assert Ok(configuration) =
    client.with_body_limits(
      configuration,
      client.BodyLimits(4, 4096, 1_048_576),
    )
  let assert Ok(running) =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.start
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(body.empty())
  let assert Ok(first) = client.exchange(running, outgoing)
  let first_body = body.read_all(client.response(first).body, 8)
  let assert Ok(replayed) = body.replay(outgoing.body)
  let second = client.exchange(running, request.set_body(outgoing, replayed))
  let second_body = case second {
    Ok(exchange) -> body.read_all(client.response(exchange).body, 6)
    Error(failure) -> Error(failure)
  }
  let observed = process.receive(peers, within: 1000)
  let closed = client.close(running)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert first_body == Ok(#(<<"streamed":utf8>>, []))
  assert second_body == Ok(#(<<"reused":utf8>>, []))
  let assert Ok(#(first_peer, second_peer, first_authority, second_authority)) =
    observed
  assert first_peer == second_peer
  assert first_authority == second_authority
  assert closed == Ok(Nil)
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

/// Two first-use exchanges for the same authenticated origin must join one in-flight connection generation.
/// The explicit connect gate holds the sole leader before QUIC establishment while the second caller becomes a broker waiter; no elapsed-time ordering is used to decide when the gate opens.
pub fn concurrent_first_use_exchanges_share_one_authenticated_http3_dial_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)

  let same_connection = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      use first <- result.try(server.accept(listener))
      use _ <- result.try(server.respond(first, 204, [], <<>>))
      use second <- result.try(server.accept(listener))
      process.send(same_connection, multiplexing_same_connection(first, second))
      server.respond(second, 204, [], <<>>)
    })

  let gate_entered = process.new_subject()
  let connect_gate = fn() {
    let release_gate = process.new_subject()
    process.send(gate_entered, release_gate)
    case process.receive(release_gate, within: 5000) {
      Ok(Nil) -> Ok(Nil)
      Error(Nil) -> Error(error.new(error.ConnectFailed))
    }
  }
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
  let assert Ok(configuration) =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_connect_gate(connect_gate)
    |> client.with_timeouts(client.Timeouts(1000, 2000, 2000, 3000, 3000, 8000))
  let assert Ok(running) = client.start(configuration)
  let request_for = fn(path) {
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path(path)
    |> request.set_body(body.empty())
  }
  let exchange_and_release = fn(path) {
    use exchange <- result.try(client.exchange(running, request_for(path)))
    use body_result <- result.try(body.read_all(
      client.response(exchange).body,
      0,
    ))
    Ok(#(
      client.selected_protocol(exchange),
      client.response(exchange).status,
      body_result,
    ))
  }

  let first =
    http_test_support.start_task(fn() { exchange_and_release("/first-use-a") })
  let gate_observation = process.receive(gate_entered, within: 2000)
  let second =
    http_test_support.start_task(fn() { exchange_and_release("/first-use-b") })
  let joined_generation =
    await_http3_dial_census(
      running: running,
      inflight: 1,
      waiters: 1,
      remaining_milliseconds: 2000,
    )

  release_connect_gate(gate_observation)
  let duplicate_gate = process.receive(gate_entered, within: 0)
  release_connect_gate(duplicate_gate)
  let first_result = http_test_support.await_task(first)
  let second_result = http_test_support.await_task(second)
  let connection_observation = process.receive(same_connection, within: 1000)
  let extra_gate_entry = process.receive(gate_entered, within: 0)
  let broker_converged =
    client.http3_dial_census(running) == client.Http3DialCensus(0, 0)
  let pool_converged = client.lifecycle_pool_counts(running) == #(1, 1)
  let closed = client.close(running)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)

  assert result.is_ok(gate_observation)
  assert duplicate_gate == Error(Nil)
  assert joined_generation
  assert first_result == Ok(#(client.Http3, 204, #(<<>>, [])))
  assert second_result == Ok(#(client.Http3, 204, #(<<>>, [])))
  assert connection_observation == Ok(True)
  assert extra_gate_entry == Error(Nil)
  assert broker_converged
  assert pool_converged
  assert closed == Ok(Nil)
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

fn release_connect_gate(observed: Result(process.Subject(Nil), Nil)) -> Nil {
  case observed {
    Ok(release) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
}

fn await_http3_dial_census(
  running running: client.Client,
  inflight inflight: Int,
  waiters waiters: Int,
  remaining_milliseconds remaining_milliseconds: Int,
) -> Bool {
  case client.http3_dial_census(running), remaining_milliseconds > 0 {
    client.Http3DialCensus(observed_inflight, observed_waiters), _
      if observed_inflight == inflight && observed_waiters == waiters
    -> True
    _, True -> {
      process.sleep(1)
      await_http3_dial_census(
        running: running,
        inflight: inflight,
        waiters: waiters,
        remaining_milliseconds: remaining_milliseconds - 1,
      )
    }
    _, False -> False
  }
}

pub fn unified_http3_reuses_authenticated_origin_after_alt_svc_route_change_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(primary_configuration) = server.new(certificate, private_key)
  let assert Ok(alternate_configuration) = server.new(certificate, private_key)
  let assert Ok(primary) = server.start(primary_configuration)
  let assert Ok(alternate) = server.start(alternate_configuration)
  let assert Ok(primary_port) = server.port(primary)
  let assert Ok(alternate_port) = server.port(alternate)
  let observed_route = process.new_subject()
  let primary_task =
    http_test_support.start_task(fn() {
      let assert Ok(first) = server.accept(primary)
      assert server.respond(
          first,
          200,
          [
            #(
              "alt-svc",
              "h3=\":" <> int.to_string(alternate_port) <> "\"; ma=60",
            ),
          ],
          <<"first":utf8>>,
        )
        == Ok(Nil)
      case server.accept(primary) {
        Error(failure) -> Error(failure)
        Ok(second) -> {
          process.send(observed_route, "primary")
          server.respond(second, 200, [], <<"reused":utf8>>)
        }
      }
    })
  let alternate_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(alternate), fn(incoming) {
        {
          process.send(observed_route, "alternate")
          server.respond(incoming, 200, [], <<"rerouted":utf8>>)
        }
      })
      |> result.unwrap(Ok(Nil))
    })
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, _, _) {
      Ok([client.HttpsRecord(["h3"], primary_port, True, 60_000)])
    })
    |> client.start
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(primary_port)
    |> request.set_body(body.empty())
  let assert Ok(first) = client.exchange(running, outgoing)
  let first_body = body.read_all(client.response(first).body, 5)
  let assert Ok(replayed) = body.replay(outgoing.body)
  let assert Ok(second) =
    client.exchange(running, request.set_body(outgoing, replayed))
  let second_body = body.read_all(client.response(second).body, 6)
  let route = process.receive(observed_route, within: 1000)
  let closed = client.close(running)
  let primary_stopped = server.stop(primary)
  let alternate_stopped = server.stop(alternate)
  let primary_done = http_test_support.await_task(primary_task)
  let alternate_done = http_test_support.await_task(alternate_task)
  let first_body_matches = first_body == Ok(#(<<"first":utf8>>, []))
  let second_body_matches = second_body == Ok(#(<<"reused":utf8>>, []))
  assert first_body_matches
  assert second_body_matches
  assert route == Ok("primary")
  assert closed == Ok(Nil)
  assert primary_stopped == Ok(server.Stopped)
  assert alternate_stopped == Ok(server.Stopped)
  assert primary_done == Ok(Nil)
  assert alternate_done == Ok(Nil)
}

pub fn unified_http3_retires_a_drained_pooled_connection_before_nonreplayable_alt_svc_request_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(primary_configuration) = server.new(certificate, private_key)
  let assert Ok(alternate_configuration) = server.new(certificate, private_key)
  let assert Ok(primary) = server.start(primary_configuration)
  let assert Ok(alternate) = server.start(alternate_configuration)
  let assert Ok(primary_port) = server.port(primary)
  let assert Ok(alternate_port) = server.port(alternate)
  let accepted = process.new_subject()
  let pulls = process.new_subject()
  let primary_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(primary), fn(incoming) {
        {
          process.send(accepted, "primary")
          server.respond(
            incoming,
            200,
            [
              #(
                "alt-svc",
                "h3=\":" <> int.to_string(alternate_port) <> "\"; ma=60",
              ),
            ],
            <<"first":utf8>>,
          )
          == Ok(Nil)
        }
      })
      |> result.unwrap(False)
    })
  let alternate_task =
    http_test_support.start_task(fn() {
      result.map(server.accept(alternate), fn(incoming) {
        {
          let ended = server.next_event(incoming) == Ok(server.End)
          process.send(accepted, "alternate")
          ended
          && server.respond(incoming, 200, [], <<"rerouted":utf8>>) == Ok(Nil)
        }
      })
      |> result.unwrap(False)
    })
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
  let assert Ok(configuration) =
    client.with_timeouts(
      configuration,
      client.Timeouts(1000, 2000, 2000, 3000, 3000, 5000),
    )
  let assert Ok(running) =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, _, _) {
      Ok([client.HttpsRecord(["h3"], primary_port, True, 60_000)])
    })
    |> client.start
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(primary_port)
    |> request.set_body(body.empty())
  let first = client.exchange(running, outgoing)
  let first_body_matches =
    result.map(first, fn(exchange) {
      body.read_all(client.response(exchange).body, 5)
      == Ok(#(<<"first":utf8>>, []))
    })
    |> result.unwrap(False)
  let first_route = process.receive(accepted, within: 1000)
  let drain_task =
    http_test_support.start_task(fn() { server.graceful_stop(primary) })
  let drained = http_test_support.await_task(drain_task)
  let assert Ok(nonreplayable) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulls, Nil)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { Nil },
    )
  let second_outgoing =
    request.new()
    |> request.set_method(http.Put)
    |> request.set_host("localhost")
    |> request.set_port(primary_port)
    |> request.set_body(nonreplayable)
  let second = client.exchange(running, second_outgoing)
  let second_body_matches =
    result.map(second, fn(exchange) {
      body.read_all(client.response(exchange).body, 8)
      == Ok(#(<<"rerouted":utf8>>, []))
    })
    |> result.unwrap(False)
  let second_route = process.receive(accepted, within: 1000)
  let pulled_once = process.receive(pulls, within: 0) == Ok(Nil)
  let no_second_pull = process.receive(pulls, within: 0) == Error(Nil)
  let closed = client.close(running)
  let primary_stopped = server.stop(primary)
  let alternate_stopped = server.stop(alternate)
  let primary_done = http_test_support.await_task(primary_task)
  let alternate_done = http_test_support.await_task(alternate_task)
  let primary_stopped_cleanly = result.is_ok(primary_stopped)
  let alternate_stopped_cleanly = result.is_ok(alternate_stopped)
  assert #(
      first_body_matches,
      first_route == Ok("primary"),
      drained == Ok(server.Drained),
      second_body_matches,
      second_route == Ok("alternate"),
      pulled_once,
      no_second_pull,
      closed == Ok(Nil),
      primary_stopped_cleanly,
      alternate_stopped_cleanly,
      primary_done,
      alternate_done,
    )
    == #(True, True, True, True, True, True, True, True, True, True, True, True)
}

pub fn unified_http3_release_gate_never_publishes_a_nonreusable_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(server_configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      result.map(server.accept(listener), fn(incoming) {
        server.respond(incoming, 200, [], <<>>) == Ok(Nil)
      })
      |> result.unwrap(False)
    })
  let reuse_probed = process.new_subject()
  let assert Ok(configuration) =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
  let assert Ok(running) =
    configuration
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_http3_release_reuse_probe(fn() {
      process.send(reuse_probed, False)
      Ok(False)
    })
    |> client.start
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
  let probe_observed = process.receive(reuse_probed, within: 0) == Ok(False)
  let #(_, idle_connections) = client.lifecycle_pool_counts(running)
  let pool_empty = idle_connections == 0
  let closed = client.close(running)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert #(
      body_completed,
      probe_observed,
      pool_empty,
      closed == Ok(Nil),
      stopped == Ok(server.Stopped),
      serving_done,
    )
    == #(True, True, True, True, True, True)
}

pub fn unified_http3_close_joins_a_stalled_upload_callback_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      server.send_response(incoming, 200, [])
    })
  let pulling = process.new_subject()
  let cancelled = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulling, process.self())
        process.sleep(10_000)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.start
  let incoming =
    client.exchange(
      running,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
    )
  let assert Ok(callback) = process.receive(pulling, within: 1000)
  let monitor = process.monitor(callback)
  let closed = client.close(running)
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: 0)
  process.demonitor_process(monitor)
  let cancellation = process.receive(cancelled, within: 0)
  let remaining = case incoming {
    Ok(exchange) -> body.read(client.response(exchange).body, 1)
    Error(failure) -> Error(failure)
  }
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert closed == Ok(Nil)
  assert joined == Ok(Nil)
  assert cancellation == Ok(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert remaining == Error(error.new(error.Cancelled))
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

pub fn http3_release_callback_observes_stream_supervisor_termination_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      server.respond(incoming, 200, [], <<>>)
    })
  let supervisor_seen = process.new_subject()
  let release_query = process.new_subject()
  let release_observed = process.new_subject()
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(supervisor_seen, linked_processes())
        process.sleep(10_000)
        Error(error.new(error.Service))
      }),
      None,
      None,
      fn() { Nil },
    )
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let assert Ok(incoming) =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_method(http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
      transport.monotonic_millisecond() + 3000,
      fn() {
        let query = process.new_subject()
        process.send(release_query, query)
        let assert Ok(supervisor) = process.receive(query, within: 1000)
        process.send(release_observed, process.is_alive(supervisor))
      },
    )
  let assert Ok([supervisor]) = process.receive(supervisor_seen, within: 1000)
  let reading =
    http_test_support.start_task(fn() { body.read_all(incoming.body, 1) })
  let assert Ok(query) = process.receive(release_query, within: 1000)
  process.send(query, supervisor)
  let alive_at_release = process.receive(release_observed, within: 1000)
  let completed = http_test_support.await_task(reading)
  adapter.close(connection)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert alive_at_release == Ok(False)
  assert completed == Ok(#(<<>>, []))
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

pub fn failed_http3_source_cleanup_recovers_admission_after_proof_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = server.accept(listener)
      server.respond(incoming, 200, [], <<>>)
    })
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let cleanup_attempted = process.new_subject()
  let released = process.new_subject()
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let configuration =
    configuration
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_source_cleanup_probe(fn(_, _) {
      process.send(cleanup_attempted, Nil)
      Error(error.new(error.Timeout(error.Operation)))
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
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
  let completed = body.read_all(incoming.body, 1)
  let cleanup = process.receive(cleanup_attempted, within: 1000)
  let publication = process.receive(released, within: 0)
  let converged =
    await_adapter_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 6000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert completed == Ok(#(<<>>, []))
  assert cleanup == Ok(Nil)
  assert publication == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

pub fn failed_http3_child_cleanup_returns_typed_failure_and_recovers_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let response_finished = process.new_subject()
  let probe_ready = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let probe_requests = process.new_subject()
      process.send(probe_ready, probe_requests)
      let assert Ok(incoming) = server.accept(listener)
      let assert Ok(accepted) = process.receive(probe_requests, within: 3000)
      process.send(accepted, Nil)
      let _peer_outcome = server.respond(incoming, 200, [], <<>>)
      process.send(response_finished, Nil)
    })
  let assert Ok(probe_requests) = process.receive(probe_ready, within: 3000)
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let cleanup_attempted = process.new_subject()
  let released = process.new_subject()
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
    )
  let configuration =
    configuration
    |> adapter.with_supervision(resources, process.self())
    |> adapter.with_child_cleanup_probe(fn() {
      let accepted = process.new_subject()
      process.send(probe_requests, accepted)
      let assert Ok(Nil) = process.receive(accepted, within: 3000)
      process.send(cleanup_attempted, Nil)
      Error(error.new(error.Timeout(error.Operation)))
    })
  let assert Ok(connection) =
    adapter.connect(configuration, "localhost", port, fn(_) { Ok(fn() { Nil }) })
  let exchange =
    adapter.exchange(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
      transport.monotonic_millisecond() + 3000,
      fn() { process.send(released, Nil) },
    )
  let classification = case exchange {
    Error(failure) -> Some(error.kind(failure))
    Ok(incoming) ->
      case body.read(incoming.body, 1) {
        Error(failure) -> Some(error.kind(failure))
        Ok(_) -> None
      }
  }
  let cleanup = process.receive(cleanup_attempted, within: 1000)
  let publication = process.receive(released, within: 0)
  let converged =
    await_adapter_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 6000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  let peer_finished = process.receive(response_finished, within: 0)
  assert classification == Some(error.Timeout(error.Operation))
  assert cleanup == Ok(Nil)
  assert publication == Error(Nil)
  assert converged.active_workers == 0
  assert converged.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
  assert serving_done == Nil
  assert peer_finished == Ok(Nil)
}

pub fn stalled_http3_pool_publication_reports_failure_and_releases_admission_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(first) = server.accept(listener)
      server.respond(first, 200, [], <<>>)
    })
  let assert Ok(limits) =
    resource.limits(maximum_workers: 1, memory_bytes: 4096)
  let resources = resource.start(limits)
  let publication_started = process.new_subject()
  let assert Ok(configuration) =
    native.with_ca_certificate(native.new(), ca_certificate)
  let assert Ok(configuration) =
    adapter.configure(
      native: configuration,
      pull_bytes: 4096,
      maximum_body_bytes: 1_048_576,
      operation_milliseconds: 3000,
      idle_milliseconds: 3000,
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
      transport.monotonic_millisecond() + 3000,
      fn() {
        process.send(publication_started, process.self())
        process.sleep(10_000)
      },
    )
  let completed = body.read_all(incoming.body, 1)
  let callback_joined = case process.receive(publication_started, within: 0) {
    Ok(callback) -> !process.is_alive(callback)
    Error(Nil) -> False
  }
  let after_failed_publication =
    await_adapter_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 6000,
    )
  let assert Ok(next_admission) =
    resource.acquire(resources, memory_bytes: 4096)
  let during_next_admission = resource.snapshot(resources)
  resource.release(next_admission)
  let after_next_admission =
    await_adapter_resource_usage(
      resources: resources,
      workers: 0,
      memory: 0,
      remaining_milliseconds: 1000,
    )
  adapter.close(connection)
  resource.stop(resources)
  let stopped = server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  assert completed == Ok(#(<<>>, []))
  assert callback_joined
  assert after_failed_publication.active_workers == 0
  assert after_failed_publication.memory_bytes == 0
  assert during_next_admission.active_workers == 1
  assert during_next_admission.memory_bytes == 4096
  assert after_next_admission.active_workers == 0
  assert after_next_admission.memory_bytes == 0
  assert stopped == Ok(server.Stopped)
  assert serving_done == Ok(Nil)
}

fn await_adapter_resource_usage(
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
      await_adapter_resource_usage(
        resources: resources,
        workers: workers,
        memory: memory,
        remaining_milliseconds: remaining_milliseconds - 10,
      )
    }
    False, False -> snapshot
  }
}

/// Finite, payload-free classification for the physical-connection multiplexing fixture.
pub type MultiplexingObservation {
  Multiplexed
  SecondStreamUnavailableWhileFirstBodyOpen
  UnexpectedFinitePhase(MultiplexingPhase)
}

/// The first unexpected phase observed after all owned fixture resources have been driven to a bounded terminal state.
pub type MultiplexingPhase {
  ServerConfigurationPhase
  ServerDeadlineConfigurationPhase
  ListenerStartPhase
  ListenerPortPhase
  ClientPoolConfigurationPhase
  ClientTimeoutConfigurationPhase
  ClientStartPhase
  FirstAcceptPhase
  FirstResponseHeadersPhase
  FirstExchangePhase
  FirstHeadersSignalPhase
  FirstResponseBodyPhase
  LifecycleStatePhase
  SecondAcceptedSignalPhase
  SecondResourceRejectionPhase
  SecondResponseExchangePhase
  SecondResponseBodyPhase
  SecondOwnerJoinPhase
  VerificationExchangePhase
  VerificationResponseBodyPhase
  PeerObservationPhase
  PeerMismatchPhase
  ConnectionIdentityPhase
  ServerJoinPhase
  ClientClosePhase
  ResourceReleasePhase
  ListenerStopPhase
  ResidualRolePhase
  CensusBaselinePhase
}

/// Stable, payload-free code used only to classify a failed fixture phase.
@internal
pub fn multiplexing_phase_code(phase: MultiplexingPhase) -> Int {
  case phase {
    ServerConfigurationPhase -> 1
    ServerDeadlineConfigurationPhase -> 2
    ListenerStartPhase -> 3
    ListenerPortPhase -> 4
    ClientPoolConfigurationPhase -> 5
    ClientTimeoutConfigurationPhase -> 6
    ClientStartPhase -> 7
    FirstAcceptPhase -> 8
    FirstResponseHeadersPhase -> 9
    FirstExchangePhase -> 10
    FirstHeadersSignalPhase -> 11
    FirstResponseBodyPhase -> 12
    LifecycleStatePhase -> 13
    SecondAcceptedSignalPhase -> 14
    SecondResourceRejectionPhase -> 15
    SecondResponseExchangePhase -> 16
    SecondResponseBodyPhase -> 17
    SecondOwnerJoinPhase -> 18
    VerificationExchangePhase -> 19
    VerificationResponseBodyPhase -> 20
    PeerObservationPhase -> 21
    PeerMismatchPhase -> 22
    ConnectionIdentityPhase -> 23
    ServerJoinPhase -> 24
    ClientClosePhase -> 25
    ResourceReleasePhase -> 26
    ListenerStopPhase -> 27
    ResidualRolePhase -> 28
    CensusBaselinePhase -> 29
  }
}

type MultiplexingServerOutcome {
  MultiplexingServerCompleted
  MultiplexingSecondRequestNotAccepted
  MultiplexingServerFailed(MultiplexingPhase)
}

type MultiplexingRaceEvent {
  MultiplexingSecondAccepted
  MultiplexingSecondFinished(
    Result(client.Exchange, error.Error),
    process.Subject(Nil),
  )
}

type MultiplexingClassification {
  ExpectedMultiplexed
  ExpectedUnavailable
  MultiplexingFailedAt(MultiplexingPhase)
}

@external(erlang, "http3_multiplexing_probe_ffi", "fixture_roles_clear")
fn multiplexing_fixture_roles_clear() -> Bool

@external(erlang, "http3_multiplexing_probe_ffi", "registry_census_controls")
fn registry_census_controls() -> Bool

@external(erlang, "http3_multiplexing_probe_ffi", "with_unrelated_fixture")
fn with_unrelated_multiplexing_fixture(contract: fn() -> Bool) -> Bool

@external(erlang, "http3_multiplexing_probe_ffi", "isolated_fixture_contract")
fn isolated_multiplexing_contract() -> Bool

pub fn multiplexing_census_rejects_active_registry_controllers_test() -> Nil {
  assert registry_census_controls()
}

@external(erlang, "http3_multiplexing_probe_ffi", "fixture_role_count")
fn raw_multiplexing_fixture_role_count() -> Int

/// Count only fixture-owned labelled roles without exposing their identities.
@internal
pub fn multiplexing_fixture_role_count() -> Int {
  raw_multiplexing_fixture_role_count()
}

@external(erlang, "http3_multiplexing_probe_ffi", "same_connection")
fn multiplexing_same_connection(
  first: server.Request,
  second: server.Request,
) -> Bool

pub fn unified_http3_multiplexes_while_an_earlier_response_body_is_open_test() -> Nil {
  assert with_unrelated_multiplexing_fixture(isolated_multiplexing_contract)
}

/// Observe one complete two-stream scenario.
/// A missed second-response deadline still releases the first response, waits for the late second exchange to converge, disposes both bodies, joins both fixture tasks, and closes the client and listener before returning its closed classification.
pub fn observe_http3_multiplexing() -> MultiplexingObservation {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  case start_multiplexing_listener(certificate, private_key) {
    Error(phase) -> UnexpectedFinitePhase(phase)
    Ok(#(listener, port)) ->
      observe_http3_multiplexing_on(
        listener: listener,
        port: port,
        ca_certificate: ca_certificate,
      )
  }
}

fn start_multiplexing_listener(
  certificate: BitArray,
  private_key: BitArray,
) -> Result(#(server.Listener, Int), MultiplexingPhase) {
  use configuration <- result.try(
    server.new(certificate, private_key)
    |> result.replace_error(ServerConfigurationPhase),
  )
  use configuration <- result.try(
    server.with_timeout(configuration, 5000)
    |> result.replace_error(ServerDeadlineConfigurationPhase),
  )
  use listener <- result.try(
    server.start(configuration)
    |> result.replace_error(ListenerStartPhase),
  )
  case server.port(listener) {
    Ok(port) -> Ok(#(listener, port))
    Error(_) -> {
      let _stopped = server.stop(listener)
      Error(ListenerPortPhase)
    }
  }
}

fn observe_http3_multiplexing_on(
  listener listener: server.Listener,
  port port: Int,
  ca_certificate ca_certificate: BitArray,
) -> MultiplexingObservation {
  let configured =
    client.with_pool_limits(client.defaults(), client.PoolLimits(1, 1, 3000))
    |> result.replace_error(ClientPoolConfigurationPhase)
    |> result.try(fn(configuration) {
      client.with_timeouts(
        configuration,
        client.Timeouts(1000, 2000, 2000, 3000, 3000, 5000),
      )
      |> result.replace_error(ClientTimeoutConfigurationPhase)
    })
  case configured {
    Error(phase) -> {
      let stopped = server.stop(listener)
      result.map(stopped, fn(_) { UnexpectedFinitePhase(phase) })
      |> result.unwrap(UnexpectedFinitePhase(ListenerStopPhase))
    }
    Ok(configuration) -> {
      let configured =
        configuration
        |> client.with_http3_resource_limit_terminal_probe(fn() { True })
        |> client.with_ca_certificates([ca_certificate])
        |> client.with_https_record_resolver(fn(_, origin_port, _) {
          Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
        })
      case client.start(configured) |> result.replace_error(Nil) {
        Error(Nil) -> {
          let stopped = server.stop(listener)
          use <- bool.guard(
            when: result.is_error(stopped),
            return: UnexpectedFinitePhase(ListenerStopPhase),
          )
          UnexpectedFinitePhase(ClientStartPhase)
        }
        Ok(running) ->
          observe_started_http3_multiplexing(
            running: running,
            listener: listener,
            port: port,
          )
      }
    }
  }
}

fn observe_started_http3_multiplexing(
  running running: client.Client,
  listener listener: server.Listener,
  port port: Int,
) -> MultiplexingObservation {
  case client.lifecycle_census(running) {
    client.LifecycleCensus(0, 0, 0, 0, 0, 0, 0) ->
      observe_started_http3_multiplexing_at_baseline(
        running: running,
        listener: listener,
        port: port,
      )
    _ -> finish_unserved_multiplexing_failure(running, listener)
  }
}

fn observe_started_http3_multiplexing_at_baseline(
  running running: client.Client,
  listener listener: server.Listener,
  port port: Int,
) -> MultiplexingObservation {
  let first_headers = process.new_subject()
  let first_release_ready = process.new_subject()
  let second_accepted = process.new_subject()
  let same_peer = process.new_subject()
  let same_connection = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      serve_http3_multiplexing(
        listener: listener,
        first_headers: first_headers,
        first_release_ready: first_release_ready,
        second_accepted: second_accepted,
        same_peer: same_peer,
        same_connection: same_connection,
      )
    })
  let request_for = fn(path) {
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path(path)
    |> request.set_body(body.empty())
  }
  case
    client.exchange(running, request_for("/first")) |> result.replace_error(Nil)
  {
    Error(Nil) ->
      finish_failed_first_exchange(
        running: running,
        listener: listener,
        serving: serving,
        first_release_ready: first_release_ready,
      )
    Ok(first) ->
      case process.receive(first_headers, within: 1000) {
        Error(Nil) ->
          finish_open_first_exchange(
            running: running,
            listener: listener,
            serving: serving,
            first_release_ready: first_release_ready,
            first: first,
            phase: FirstHeadersSignalPhase,
          )
        Ok(Nil) ->
          case process.receive(first_release_ready, within: 1000) {
            Error(Nil) ->
              finish_open_first_exchange(
                running: running,
                listener: listener,
                serving: serving,
                first_release_ready: first_release_ready,
                first: first,
                phase: FirstResponseBodyPhase,
              )
            Ok(release_first) ->
              observe_second_http3_exchange(
                running,
                listener,
                serving,
                release_first,
                second_accepted,
                same_peer,
                same_connection,
                first,
                request_for,
              )
          }
      }
  }
}

fn serve_http3_multiplexing(
  listener listener: server.Listener,
  first_headers first_headers: process.Subject(Nil),
  first_release_ready first_release_ready: process.Subject(process.Subject(Nil)),
  second_accepted second_accepted: process.Subject(Nil),
  same_peer same_peer: process.Subject(Bool),
  same_connection same_connection: process.Subject(Bool),
) -> MultiplexingServerOutcome {
  let served = {
    use first <- result.try(
      server.accept(listener) |> result.replace_error(FirstAcceptPhase),
    )
    let first_peer = server.peer_endpoint(first)
    use _ <- result.try(
      server.send_response(first, 200, [])
      |> result.replace_error(FirstResponseHeadersPhase),
    )
    process.send(first_headers, Nil)
    let first_sender =
      http_test_support.start_task(fn() {
        send_first_multiplexed_response(first, first_release_ready)
      })
    let second_outcome = case
      server.accept(listener) |> result.replace_error(Nil)
    {
      Error(Nil) -> MultiplexingSecondRequestNotAccepted
      Ok(second) -> {
        process.send(second_accepted, Nil)
        process.send(
          same_connection,
          multiplexing_same_connection(first, second),
        )
        respond_to_second_multiplexed_request(
          second: second,
          first_peer: first_peer,
          same_peer: same_peer,
        )
      }
    }
    use _ <- result.try(http_test_support.await_task(first_sender))
    Ok(second_outcome)
  }
  case served {
    Ok(outcome) -> outcome
    Error(phase) -> MultiplexingServerFailed(phase)
  }
}

fn respond_to_second_multiplexed_request(
  second second: server.Request,
  first_peer first_peer: Result(address.Endpoint, server.Error),
  same_peer same_peer: process.Subject(Bool),
) -> MultiplexingServerOutcome {
  case first_peer, server.peer_endpoint(second) {
    Ok(first_peer), Ok(second_peer) -> {
      process.send(same_peer, first_peer == second_peer)
      server.respond(second, 200, [], <<"second":utf8>>)
      |> result.replace(MultiplexingServerCompleted)
      |> result.unwrap(MultiplexingServerFailed(SecondResponseBodyPhase))
    }
    _, _ -> MultiplexingServerFailed(PeerObservationPhase)
  }
}

fn send_first_multiplexed_response(
  first: server.Request,
  first_release_ready: process.Subject(process.Subject(Nil)),
) -> Result(Nil, MultiplexingPhase) {
  let release_first = process.new_subject()
  process.send(first_release_ready, release_first)
  use _ <- result.try(
    process.receive(release_first, within: 6000)
    |> result.replace_error(FirstResponseBodyPhase),
  )
  use _ <- result.try(
    server.send_chunk(first, <<"first":utf8>>)
    |> result.replace_error(FirstResponseBodyPhase),
  )
  server.finish_response(first)
  |> result.replace_error(FirstResponseBodyPhase)
}

fn finish_failed_first_exchange(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  first_release_ready first_release_ready: process.Subject(process.Subject(Nil)),
) -> MultiplexingObservation {
  case process.receive(first_release_ready, within: 1000) {
    Ok(release_first) -> process.send(release_first, Nil)
    Error(Nil) -> Nil
  }
  finish_multiplexing_failure(
    running: running,
    listener: listener,
    serving: serving,
    phase: FirstExchangePhase,
  )
}

fn finish_open_first_exchange(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  first_release_ready first_release_ready: process.Subject(process.Subject(Nil)),
  first first: client.Exchange,
  phase phase: MultiplexingPhase,
) -> MultiplexingObservation {
  case process.receive(first_release_ready, within: 1000) {
    Ok(release_first) -> process.send(release_first, Nil)
    Error(Nil) -> Nil
  }
  let first_body = body.read_all(client.response(first).body, 5)
  let observed_phase =
    result.map(first_body, fn(_) { phase })
    |> result.unwrap(FirstResponseBodyPhase)
  finish_multiplexing_failure(
    running: running,
    listener: listener,
    serving: serving,
    phase: observed_phase,
  )
}

fn finish_unserved_multiplexing_failure(
  running: client.Client,
  listener: server.Listener,
) -> MultiplexingObservation {
  let client.ClosePhaseObservation(
    _,
    lifecycle_outcome,
    _,
    _,
    resource_outcome,
    _,
    active_after_resource,
  ) = client.close_observed(running)
  let #(resource_workers, resource_memory) =
    client.http3_resource_usage(running)
  let stopped = server.stop(listener)
  let roles_clear = multiplexing_fixture_roles_clear()
  case
    result.is_error(lifecycle_outcome),
    result.is_error(resource_outcome),
    active_after_resource,
    resource_workers,
    resource_memory,
    result.is_error(stopped),
    roles_clear
  {
    True, _, _, _, _, _, _ -> UnexpectedFinitePhase(ClientClosePhase)
    _, True, _, _, _, _, _ -> UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, active, _, _, _, _ if active != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, workers, _, _, _ if workers != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, _, memory, _, _ if memory != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, _, _, True, _ -> UnexpectedFinitePhase(ListenerStopPhase)
    _, _, _, _, _, _, False -> UnexpectedFinitePhase(ResidualRolePhase)
    _, _, _, _, _, _, True -> UnexpectedFinitePhase(CensusBaselinePhase)
  }
}

fn finish_multiplexing_failure(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  phase phase: MultiplexingPhase,
) -> MultiplexingObservation {
  let client.ClosePhaseObservation(
    _,
    lifecycle_outcome,
    _,
    _,
    resource_outcome,
    _,
    active_after_resource,
  ) = client.close_observed(running)
  let #(resource_workers, resource_memory) =
    client.http3_resource_usage(running)
  let stopped = server.stop(listener)
  let _server_outcome = http_test_support.await_task(serving)
  let roles_clear = multiplexing_fixture_roles_clear()
  case
    result.is_error(lifecycle_outcome),
    result.is_error(resource_outcome),
    active_after_resource,
    resource_workers,
    resource_memory,
    result.is_error(stopped),
    roles_clear
  {
    True, _, _, _, _, _, _ -> UnexpectedFinitePhase(ClientClosePhase)
    _, True, _, _, _, _, _ -> UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, active, _, _, _, _ if active != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, workers, _, _, _ if workers != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, _, memory, _, _ if memory != 0 ->
      UnexpectedFinitePhase(ResourceReleasePhase)
    _, _, _, _, _, True, _ -> UnexpectedFinitePhase(ListenerStopPhase)
    _, _, _, _, _, _, False -> UnexpectedFinitePhase(ResidualRolePhase)
    _, _, _, _, _, _, True -> UnexpectedFinitePhase(phase)
  }
}

fn observe_second_http3_exchange(
  running: client.Client,
  listener: server.Listener,
  serving: http_test_support.Task(MultiplexingServerOutcome),
  release_first: process.Subject(Nil),
  second_accepted: process.Subject(Nil),
  same_peer: process.Subject(Bool),
  same_connection: process.Subject(Bool),
  first: client.Exchange,
  request_for: fn(String) -> request.Request(body.Body),
) -> MultiplexingObservation {
  let lifecycle_held = client.lifecycle_pool_counts(running) == #(1, 0)
  let second_result = process.new_subject()
  let second_task =
    http_test_support.start_task(fn() {
      let retain_second_owner = process.new_subject()
      process.send(second_result, #(
        client.exchange(running, request_for("/second")),
        retain_second_owner,
      ))
      process.receive(retain_second_owner, within: 7000)
    })
  let race =
    process.new_selector()
    |> process.select_map(second_accepted, fn(_) { MultiplexingSecondAccepted })
    |> process.select_map(second_result, fn(result) {
      MultiplexingSecondFinished(result.0, result.1)
    })
    |> process.selector_receive(within: 1500)
  case race {
    Ok(MultiplexingSecondAccepted) ->
      case process.receive(second_result, within: 1500) {
        Ok(#(Ok(second), retain_second_owner)) ->
          finish_multiplexed_second_exchange(
            running: running,
            listener: listener,
            serving: serving,
            release_first: release_first,
            same_peer: same_peer,
            same_connection: same_connection,
            first: first,
            second: second,
            retain_second_owner: retain_second_owner,
            second_task: second_task,
            lifecycle_held: lifecycle_held,
          )
        Ok(#(Error(_), retain_second_owner)) ->
          finish_unexpected_second_rejection(
            running: running,
            listener: listener,
            serving: serving,
            release_first: release_first,
            first: first,
            retain_second_owner: retain_second_owner,
            second_task: second_task,
            phase: SecondResponseExchangePhase,
          )
        Error(Nil) ->
          finish_second_exchange_timeout(
            running: running,
            listener: listener,
            serving: serving,
            release_first: release_first,
            first: first,
            second_result: second_result,
            second_task: second_task,
          )
      }
    Ok(MultiplexingSecondFinished(Ok(second), retain_second_owner)) ->
      case process.receive(second_accepted, within: 1500) {
        Ok(Nil) ->
          finish_multiplexed_second_exchange(
            running: running,
            listener: listener,
            serving: serving,
            release_first: release_first,
            same_peer: same_peer,
            same_connection: same_connection,
            first: first,
            second: second,
            retain_second_owner: retain_second_owner,
            second_task: second_task,
            lifecycle_held: lifecycle_held,
          )
        Error(Nil) -> {
          body.cancel(client.response(second).body)
          finish_unexpected_second_rejection(
            running: running,
            listener: listener,
            serving: serving,
            release_first: release_first,
            first: first,
            retain_second_owner: retain_second_owner,
            second_task: second_task,
            phase: SecondAcceptedSignalPhase,
          )
        }
      }
    Ok(MultiplexingSecondFinished(Error(failure), retain_second_owner)) ->
      finish_rejected_second_exchange(
        running,
        listener,
        serving,
        release_first,
        second_accepted,
        same_peer,
        same_connection,
        first,
        request_for,
        failure,
        retain_second_owner,
        second_task,
        lifecycle_held,
      )
    Error(Nil) ->
      finish_second_exchange_timeout(
        running: running,
        listener: listener,
        serving: serving,
        release_first: release_first,
        first: first,
        second_result: second_result,
        second_task: second_task,
      )
  }
}

fn finish_multiplexed_second_exchange(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  release_first release_first: process.Subject(Nil),
  same_peer same_peer: process.Subject(Bool),
  same_connection same_connection: process.Subject(Bool),
  first first: client.Exchange,
  second second: client.Exchange,
  retain_second_owner retain_second_owner: process.Subject(Nil),
  second_task second_task: http_test_support.Task(Result(Nil, Nil)),
  lifecycle_held lifecycle_held: Bool,
) -> MultiplexingObservation {
  let second_body =
    client.response(second).status == 200
    && body.read_all(client.response(second).body, 6)
    == Ok(#(<<"second":utf8>>, []))
  process.send(retain_second_owner, Nil)
  let second_owner_done = http_test_support.await_task(second_task)
  process.send(release_first, Nil)
  let first_body =
    body.read_all(client.response(first).body, 5) == Ok(#(<<"first":utf8>>, []))
  let lifecycle_converged =
    lifecycle_held && client.lifecycle_pool_counts(running) == #(1, 1)
  finish_multiplexing_observation(
    classification: ExpectedMultiplexed,
    first_body_ok: first_body,
    second_body_ok: second_body,
    lifecycle_converged:,
    peer_observation: process.receive(same_peer, within: 1000),
    connection_observation: process.receive(same_connection, within: 1000),
    second_owner_done:,
    running:,
    listener:,
    serving:,
  )
}

fn finish_rejected_second_exchange(
  running: client.Client,
  listener: server.Listener,
  serving: http_test_support.Task(MultiplexingServerOutcome),
  release_first: process.Subject(Nil),
  second_accepted: process.Subject(Nil),
  same_peer: process.Subject(Bool),
  same_connection: process.Subject(Bool),
  first: client.Exchange,
  request_for: fn(String) -> request.Request(body.Body),
  failure: error.Error,
  retain_second_owner: process.Subject(Nil),
  second_task: http_test_support.Task(Result(Nil, Nil)),
  lifecycle_held: Bool,
) -> MultiplexingObservation {
  let exact_rejection = error.kind(failure) == error.Resource(error.Connections)
  let accepted_absent =
    process.receive(second_accepted, within: 0) == Error(Nil)
  let lifecycle_still_held = client.lifecycle_pool_counts(running) == #(1, 0)
  process.send(retain_second_owner, Nil)
  let second_owner_done = http_test_support.await_task(second_task)
  process.send(release_first, Nil)
  let first_body =
    body.read_all(client.response(first).body, 5) == Ok(#(<<"first":utf8>>, []))
  let first_released = client.lifecycle_pool_counts(running) == #(1, 1)
  case
    exact_rejection
    && accepted_absent
    && lifecycle_held
    && lifecycle_still_held
    && first_released
  {
    False ->
      finish_multiplexing_observation(
        classification: MultiplexingFailedAt(SecondResourceRejectionPhase),
        first_body_ok: first_body,
        second_body_ok: False,
        lifecycle_converged: first_released,
        peer_observation: Error(Nil),
        connection_observation: Error(Nil),
        second_owner_done:,
        running:,
        listener:,
        serving:,
      )
    True ->
      verify_http3_after_rejection(
        running,
        listener,
        serving,
        second_accepted,
        same_peer,
        same_connection,
        request_for,
        first_body,
        second_owner_done,
      )
  }
}

fn verify_http3_after_rejection(
  running: client.Client,
  listener: server.Listener,
  serving: http_test_support.Task(MultiplexingServerOutcome),
  second_accepted: process.Subject(Nil),
  same_peer: process.Subject(Bool),
  same_connection: process.Subject(Bool),
  request_for: fn(String) -> request.Request(body.Body),
  first_body_ok: Bool,
  second_owner_done: Result(Nil, Nil),
) -> MultiplexingObservation {
  case
    client.exchange(running, request_for("/verification"))
    |> result.replace_error(Nil)
  {
    Error(Nil) ->
      finish_multiplexing_observation(
        classification: MultiplexingFailedAt(VerificationExchangePhase),
        first_body_ok:,
        second_body_ok: False,
        lifecycle_converged: False,
        peer_observation: Error(Nil),
        connection_observation: Error(Nil),
        second_owner_done:,
        running:,
        listener:,
        serving:,
      )
    Ok(verification) -> {
      let accepted = process.receive(second_accepted, within: 1500)
      let verification_body =
        client.response(verification).status == 200
        && body.read_all(client.response(verification).body, 6)
        == Ok(#(<<"second":utf8>>, []))
      let lifecycle_converged = client.lifecycle_pool_counts(running) == #(1, 1)
      let classification = case accepted {
        Ok(Nil) -> ExpectedUnavailable
        Error(Nil) -> MultiplexingFailedAt(SecondAcceptedSignalPhase)
      }
      finish_multiplexing_observation(
        classification:,
        first_body_ok:,
        second_body_ok: verification_body,
        lifecycle_converged:,
        peer_observation: process.receive(same_peer, within: 1000),
        connection_observation: process.receive(same_connection, within: 1000),
        second_owner_done:,
        running:,
        listener:,
        serving:,
      )
    }
  }
}

fn finish_unexpected_second_rejection(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  release_first release_first: process.Subject(Nil),
  first first: client.Exchange,
  retain_second_owner retain_second_owner: process.Subject(Nil),
  second_task second_task: http_test_support.Task(Result(Nil, Nil)),
  phase phase: MultiplexingPhase,
) -> MultiplexingObservation {
  process.send(retain_second_owner, Nil)
  let second_owner_done = http_test_support.await_task(second_task)
  process.send(release_first, Nil)
  let first_body =
    body.read_all(client.response(first).body, 5) == Ok(#(<<"first":utf8>>, []))
  finish_multiplexing_observation(
    classification: MultiplexingFailedAt(phase),
    first_body_ok: first_body,
    second_body_ok: False,
    lifecycle_converged: False,
    peer_observation: Error(Nil),
    connection_observation: Error(Nil),
    second_owner_done:,
    running:,
    listener:,
    serving:,
  )
}

fn finish_second_exchange_timeout(
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
  release_first release_first: process.Subject(Nil),
  first first: client.Exchange,
  second_result second_result: process.Subject(
    #(Result(client.Exchange, error.Error), process.Subject(Nil)),
  ),
  second_task second_task: http_test_support.Task(Result(Nil, Nil)),
) -> MultiplexingObservation {
  process.send(release_first, Nil)
  let first_body =
    body.read_all(client.response(first).body, 5) == Ok(#(<<"first":utf8>>, []))
  case process.receive(second_result, within: 6000) {
    Ok(#(Ok(second), retain_second_owner)) -> {
      body.cancel(client.response(second).body)
      process.send(retain_second_owner, Nil)
      let second_owner_done = http_test_support.await_task(second_task)
      finish_multiplexing_observation(
        classification: MultiplexingFailedAt(SecondResponseExchangePhase),
        first_body_ok: first_body,
        second_body_ok: False,
        lifecycle_converged: False,
        peer_observation: Error(Nil),
        connection_observation: Error(Nil),
        second_owner_done:,
        running:,
        listener:,
        serving:,
      )
    }
    Ok(#(Error(_), retain_second_owner)) -> {
      process.send(retain_second_owner, Nil)
      let second_owner_done = http_test_support.await_task(second_task)
      finish_multiplexing_observation(
        classification: MultiplexingFailedAt(SecondResponseExchangePhase),
        first_body_ok: first_body,
        second_body_ok: False,
        lifecycle_converged: False,
        peer_observation: Error(Nil),
        connection_observation: Error(Nil),
        second_owner_done:,
        running:,
        listener:,
        serving:,
      )
    }
    Error(Nil) -> {
      let _closed = client.close(running)
      let _stopped = server.stop(listener)
      let _second_owner_done = http_test_support.await_task(second_task)
      let _server_outcome = http_test_support.await_task(serving)
      case multiplexing_fixture_roles_clear() {
        True -> UnexpectedFinitePhase(SecondResponseExchangePhase)
        False -> UnexpectedFinitePhase(ResidualRolePhase)
      }
    }
  }
}

fn finish_multiplexing_observation(
  classification classification: MultiplexingClassification,
  first_body_ok first_body_ok: Bool,
  second_body_ok second_body_ok: Bool,
  lifecycle_converged lifecycle_converged: Bool,
  peer_observation peer_observation: Result(Bool, Nil),
  connection_observation connection_observation: Result(Bool, Nil),
  second_owner_done second_owner_done: Result(Nil, Nil),
  running running: client.Client,
  listener listener: server.Listener,
  serving serving: http_test_support.Task(MultiplexingServerOutcome),
) -> MultiplexingObservation {
  let client.ClosePhaseObservation(
    _,
    lifecycle_outcome,
    _,
    _,
    resource_outcome,
    _,
    active_after_resource,
  ) = client.close_observed(running)
  let #(resource_workers, resource_memory) =
    client.http3_resource_usage(running)
  let stopped = server.stop(listener)
  let server_outcome = http_test_support.await_task(serving)
  let roles_clear = multiplexing_fixture_roles_clear()
  use <- bool.guard(
    when: result.is_error(lifecycle_outcome),
    return: UnexpectedFinitePhase(ClientClosePhase),
  )
  use <- bool.guard(
    when: result.is_error(resource_outcome)
      || active_after_resource != 0
      || resource_workers != 0
      || resource_memory != 0,
    return: UnexpectedFinitePhase(ResourceReleasePhase),
  )
  use <- bool.guard(
    when: result.is_error(stopped),
    return: UnexpectedFinitePhase(ListenerStopPhase),
  )
  use <- bool.guard(
    when: !roles_clear,
    return: UnexpectedFinitePhase(ResidualRolePhase),
  )
  finish_clean_multiplexing_observation(
    classification: classification,
    first_body_ok: first_body_ok,
    second_body_ok: second_body_ok,
    lifecycle_converged: lifecycle_converged,
    peer_observation: peer_observation,
    connection_observation: connection_observation,
    second_owner_done: second_owner_done,
    server_outcome: server_outcome,
  )
}

fn finish_clean_multiplexing_observation(
  classification classification: MultiplexingClassification,
  first_body_ok first_body_ok: Bool,
  second_body_ok second_body_ok: Bool,
  lifecycle_converged lifecycle_converged: Bool,
  peer_observation peer_observation: Result(Bool, Nil),
  connection_observation connection_observation: Result(Bool, Nil),
  second_owner_done second_owner_done: Result(Nil, Nil),
  server_outcome server_outcome: MultiplexingServerOutcome,
) -> MultiplexingObservation {
  case classification {
    MultiplexingFailedAt(phase) -> UnexpectedFinitePhase(phase)
    ExpectedMultiplexed ->
      validate_expected_multiplexing(
        observation: Multiplexed,
        first_body_ok: first_body_ok,
        second_body_ok: second_body_ok,
        lifecycle_converged: lifecycle_converged,
        peer_observation: peer_observation,
        connection_observation: connection_observation,
        second_owner_done: second_owner_done,
        server_outcome: server_outcome,
      )
    ExpectedUnavailable ->
      validate_expected_multiplexing(
        observation: SecondStreamUnavailableWhileFirstBodyOpen,
        first_body_ok: first_body_ok,
        second_body_ok: second_body_ok,
        lifecycle_converged: lifecycle_converged,
        peer_observation: peer_observation,
        connection_observation: connection_observation,
        second_owner_done: second_owner_done,
        server_outcome: server_outcome,
      )
  }
}

fn validate_expected_multiplexing(
  observation observation: MultiplexingObservation,
  first_body_ok first_body_ok: Bool,
  second_body_ok second_body_ok: Bool,
  lifecycle_converged lifecycle_converged: Bool,
  peer_observation peer_observation: Result(Bool, Nil),
  connection_observation connection_observation: Result(Bool, Nil),
  second_owner_done second_owner_done: Result(Nil, Nil),
  server_outcome server_outcome: MultiplexingServerOutcome,
) -> MultiplexingObservation {
  use <- bool.guard(
    when: !first_body_ok,
    return: UnexpectedFinitePhase(FirstResponseBodyPhase),
  )
  use <- bool.guard(
    when: !second_body_ok,
    return: UnexpectedFinitePhase(SecondResponseBodyPhase),
  )
  use <- bool.guard(
    when: second_owner_done == Error(Nil),
    return: UnexpectedFinitePhase(SecondOwnerJoinPhase),
  )
  use <- bool.guard(
    when: !lifecycle_converged,
    return: UnexpectedFinitePhase(LifecycleStatePhase),
  )
  use <- bool.guard(
    when: peer_observation == Error(Nil),
    return: UnexpectedFinitePhase(PeerObservationPhase),
  )
  use <- bool.guard(
    when: peer_observation == Ok(False),
    return: UnexpectedFinitePhase(PeerMismatchPhase),
  )
  use <- bool.guard(
    when: connection_observation != Ok(True),
    return: UnexpectedFinitePhase(ConnectionIdentityPhase),
  )
  case server_outcome {
    MultiplexingServerCompleted -> observation
    MultiplexingSecondRequestNotAccepted ->
      UnexpectedFinitePhase(SecondAcceptedSignalPhase)
    MultiplexingServerFailed(phase) -> UnexpectedFinitePhase(phase)
  }
}
