import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/context
import http/error
import http/internal/http3/server as adapter
import http/internal/transport
import http3/client as http3_client
import http3/failure as http3_failure
import http3/server as http3_server
import http3_server_test_support as server_test_support
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn http3_shutdown_latch_preserves_every_finite_error_classification_test() -> Nil {
  let classifications = [
    error.Dns,
    error.ConnectFailed,
    error.Tls,
    error.Timeout(error.DnsLookup),
    error.Timeout(error.Connect),
    error.Timeout(error.TlsHandshake),
    error.Timeout(error.Operation),
    error.Timeout(error.Idle),
    error.Timeout(error.Total),
    error.Protocol(error.Http1),
    error.Protocol(error.Http2),
    error.Protocol(error.Http3),
    error.Protocol(error.Quic),
    error.Policy(error.RedirectPolicy),
    error.Policy(error.RetryPolicy),
    error.Policy(error.SecurityPolicy),
    error.Policy(error.ProxyPolicy),
    error.Policy(error.CachePolicy),
    error.Body(error.InvalidLimit),
    error.Body(error.ReadFailed),
    error.Body(error.TooLarge(0)),
    error.Body(error.InvalidChunk),
    error.Body(error.LengthMismatch(0, 0)),
    error.Body(error.NotReplayable),
    error.Resource(error.Connections),
    error.Resource(error.Streams),
    error.Resource(error.RequestWorkers),
    error.Resource(error.Memory),
    error.Resource(error.Queue),
    error.Resource(error.BufferedBody),
    error.Resource(error.FileHandles),
    error.Cancelled,
    error.Service,
  ]
  let round_tripped =
    list.map(classifications, adapter.shutdown_classification_round_trip)
  let value_bearing_failures_are_redacted =
    adapter.shutdown_classification_round_trip(error.Body(error.TooLarge(8192)))
    == error.Body(error.TooLarge(0))
    && adapter.shutdown_classification_round_trip(
      error.Body(error.LengthMismatch(12, 7)),
    )
    == error.Body(error.LengthMismatch(0, 0))
  assert #(
      list.length(classifications) == 33,
      round_tripped == classifications,
      value_bearing_failures_are_redacted,
    )
    == #(True, True, True)
}

pub fn http3_shutdown_latch_preserves_the_first_terminal_outcome_test() -> Nil {
  let dns_failure = Error(error.new(error.Dns))
  let service_failure = Error(error.new(error.Service))
  let failure_then_success =
    adapter.shutdown_latch_sequence(dns_failure, Ok(Nil))
  let success_then_failure =
    adapter.shutdown_latch_sequence(Ok(Nil), service_failure)
  let failure_then_other_failure =
    adapter.shutdown_latch_sequence(dns_failure, service_failure)
  assert #(
      failure_then_success == #(dns_failure, dns_failure),
      success_then_failure == #(Ok(Nil), Ok(Nil)),
      failure_then_other_failure == #(dns_failure, dns_failure),
    )
    == #(True, True, True)
}

pub fn http3_shutdown_uses_one_absolute_cleanup_deadline_for_128_workers_test() -> Nil {
  let shared_deadline = 91_337
  let plan = adapter.shutdown_join_plan(128, shared_deadline)
  let all_workers_share_deadline =
    list.length(plan) == 128
    && list.all(plan, fn(deadline) { deadline == shared_deadline })
  let unconfirmed =
    adapter.shutdown_join_probe(
      list.repeat(Nil, 128),
      shared_deadline,
      fn(_, observed_deadline) { observed_deadline != shared_deadline },
    )
  let every_fixed_failure_was_retained = unconfirmed == list.repeat(Nil, 128)
  let empty_plans_are_finite =
    adapter.shutdown_join_plan(0, shared_deadline) == []
    && adapter.shutdown_join_plan(-1, shared_deadline) == []
  assert #(
      all_workers_share_deadline,
      every_fixed_failure_was_retained,
      empty_plans_are_finite,
    )
    == #(True, True, True)
}

pub fn http3_accept_continues_after_two_observed_operation_timeouts_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let attempts = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_accept_probe(configuration, fn(listener) {
      // The accept probe runs in the acceptor child.
      // Create the decision subject here, then publish only its send capability to the test owner.
      let decision = process.new_subject()
      process.send(attempts, decision)
      case process.receive(decision, within: 1000) {
        Ok(False) ->
          Error(
            http3_server.Failure(http3_failure.Timeout(http3_failure.Operation)),
          )
        Ok(True) -> http3_server.accept(listener)
        Error(Nil) ->
          Error(
            http3_server.Failure(http3_failure.Timeout(http3_failure.Operation)),
          )
      }
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let first = process.receive(attempts, within: 1000) |> should.be_ok
  process.send(first, False)
  let second = process.receive(attempts, within: 1000) |> should.be_ok
  process.send(second, False)
  let third = process.receive(attempts, within: 1000) |> should.be_ok
  process.send(third, True)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let received =
    http3_client.send(
      client,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(<<>>),
    )
  let stopped = adapter.stop(listener)
  assert #(response_status_is(received, 204), stopped == Ok(Nil))
    == #(True, True)
}

pub fn fatal_http3_accept_failure_is_preserved_across_repeated_stop_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let attempted = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_accept_probe(configuration, fn(_) {
      process.send(attempted, Nil)
      Error(http3_server.Failure(http3_failure.Resolution))
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let accept_failed = process.receive(attempted, within: 1000)
  let first = adapter.stop(listener)
  let second = adapter.stop(listener)
  let expected = Error(error.new(error.Dns))
  assert #(
      accept_failed == Ok(Nil),
      first == expected,
      second == expected,
      first == second,
    )
    == #(True, True, True, True)
}

pub fn abnormal_http3_acceptor_exit_is_preserved_across_repeated_stop_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let attempted = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_accept_probe(configuration, fn(_) {
      process.send(attempted, Nil)
      http_test_support.exit_now()
      Error(
        http3_server.Failure(http3_failure.Timeout(http3_failure.Operation)),
      )
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let acceptor_exited = process.receive(attempted, within: 1000)
  let first = adapter.stop(listener)
  let second = adapter.stop(listener)
  let expected = Error(error.new(error.Service))
  assert #(
      acceptor_exited == Ok(Nil),
      first == expected,
      second == expected,
      first == second,
    )
    == #(True, True, True, True)
}

pub fn failed_http3_listener_startup_joins_and_rejects_unconfirmed_cleanup_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let startup_entered = process.new_subject()
  let accepting = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_accept_probe(fn(_) {
      let release = process.new_subject()
      process.send(accepting, #(release, process.self()))
      let _released = process.receive(release, within: 10_000)
      Error(
        http3_server.Failure(http3_failure.Timeout(http3_failure.Operation)),
      )
    })
    |> adapter.with_coordinator_startup_probe(fn() {
      let release = process.new_subject()
      process.send(startup_entered, Nil)
      let _released = process.receive(release, within: 10_000)
      Nil
    })
    |> adapter.with_startup_join_probe(fn() { False })
  let startup_started = transport.monotonic_millisecond()
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
  let startup_elapsed = transport.monotonic_millisecond() - startup_started
  let startup_seen = process.receive(startup_entered, within: 0)
  let accept_running = process.receive(accepting, within: 1000)
  let acceptor_joined = case accept_running {
    Ok(#(_, pid)) -> monitor_pid_joined(pid, 1000)
    Error(Nil) -> False
  }
  case accept_running {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  assert #(
      listener_failed_with(listener, error.Timeout(error.Operation)),
      startup_seen == Ok(Nil),
      received_sync_point(accept_running),
      acceptor_joined,
      startup_elapsed >= 0 && startup_elapsed <= 3000,
    )
    == #(True, True, True, True, True)
}

pub fn failed_http3_port_discovery_closes_the_owned_native_listener_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let observed_port = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let faulty =
    adapter.with_listener_port_probe(configuration, fn(native_listener) {
      result.map(http3_server.port(native_listener), fn(port) {
        process.send(observed_port, port)
      })
      |> result.unwrap(Nil)
      Error(http3_server.Failure(http3_failure.Resolution))
    })
  let first =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      faulty,
    )
  let port = process.receive(observed_port, within: 1000)
  let rebound = case port {
    Ok(port) ->
      adapter.listen(
        fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
        <<127, 0, 0, 1>>,
        port,
        configuration,
      )
    Error(Nil) -> Error(error.new(error.Service))
  }
  let rebound_stopped = case rebound {
    Ok(listener) -> adapter.stop(listener)
    Error(failure) -> Error(failure)
  }
  assert #(
      listener_failed_with(first, error.Dns),
      received_port(port),
      listener_started(rebound),
      rebound_stopped == Ok(Nil),
    )
    == #(True, True, True, True)
}

pub fn http3_startup_rollback_preserves_join_and_lower_stop_failures_test() -> Nil {
  let unconfirmed = adapter.startup_rollback_error(False, Ok(Nil)) |> error.kind
  let lower_failure =
    adapter.startup_rollback_error(
      True,
      Error(error.new(error.Protocol(error.Quic))),
    )
    |> error.kind
  let startup_failure =
    adapter.startup_rollback_error(True, Ok(Nil)) |> error.kind
  assert #(
      unconfirmed == error.Timeout(error.Operation),
      lower_failure == error.Protocol(error.Quic),
      startup_failure == error.Service,
    )
    == #(True, True, True)
}

pub fn joined_http3_response_startup_timeout_cancels_stream_and_accepts_next_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let startups = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_response_startup_probe(configuration, fn() {
      let release = process.new_subject()
      process.send(startups, #(release, process.self()))
      let _released = process.receive(release, within: 10_000)
      Nil
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let first_stream =
    http3_client.open_stream(connection, outgoing) |> should.be_ok
  let first_finished = http3_client.finish(first_stream)
  let first_startup = process.receive(startups, within: 3000)
  let first_joined = case first_startup {
    Ok(#(_, pid)) -> monitor_pid_joined(pid, 2500)
    Error(Nil) -> False
  }
  let first_terminal = http3_client.next_event(first_stream)
  case first_startup {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let second_stream =
    http3_client.open_stream(connection, outgoing) |> should.be_ok
  let second_finished = http3_client.finish(second_stream)
  let second_startup = process.receive(startups, within: 3000)
  case second_startup {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let second_head = http3_client.next_event(second_stream)
  let second_end = http3_client.next_event(second_stream)
  let _closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert #(
      first_finished == Ok(Nil),
      received_sync_point(first_startup),
      first_joined,
      response_event_failed(first_terminal),
      second_finished == Ok(Nil),
      received_sync_point(second_startup),
      server_test_support.default_response_head(
        outcome: second_head,
        status: 204,
      ),
      second_end == Ok(http3_client.End),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True, True, True)
}

pub fn unconfirmed_http3_response_startup_timeout_fails_listener_closed_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let startups = process.new_subject()
  let phases = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_response_startup_probe(fn() {
      let release = process.new_subject()
      process.send(startups, #(release, process.self()))
      let _released = process.receive(release, within: 10_000)
      Nil
    })
    |> adapter.with_response_start_join_probe(fn(phase, _) {
      process.send(phases, phase)
      False
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let startup = process.receive(startups, within: 3000)
  let monitor = case startup {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let stop_started = transport.monotonic_millisecond()
  let first = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let second = adapter.stop(listener)
  let worker_joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case startup {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let normal_phase = process.receive(phases, within: 0)
  let forced_phase = process.receive(phases, within: 0)
  let no_second_accept = process.receive(startups, within: 0)
  let _closed = http3_client.close(connection)
  let expected = Error(error.new(error.Timeout(error.Operation)))
  assert #(
      finished == Ok(Nil),
      received_sync_point(startup),
      worker_joined,
      first == expected,
      second == expected,
      first == second,
      coordinator_join_phase_is(normal_phase, 1),
      coordinator_join_phase_is(forced_phase, 2),
      no_second_accept == Error(Nil),
      stop_elapsed >= 0 && stop_elapsed <= 3500,
    )
    == #(True, True, True, True, True, True, True, True, True, True)
}

pub fn missing_http3_shutdown_record_can_never_report_success_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let #(listener, _) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: fn(_, _) {
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
    )
  let interrupted = adapter.interrupt_coordinator_before_shutdown(listener)
  let first = adapter.stop(listener)
  let second = adapter.stop(listener)
  let expected = Error(error.new(error.Service))
  assert #(interrupted, first == expected, second == expected, first == second)
    == #(True, True, True, True)
}

pub fn stopped_http3_listener_joins_a_stalled_accept_operation_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let accepting = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_accept_probe(configuration, fn(_) {
      let release = process.new_subject()
      process.send(accepting, #(release, process.self()))
      let _released = process.receive(release, within: 10_000)
      Error(
        http3_server.Failure(http3_failure.Timeout(http3_failure.Operation)),
      )
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let running = process.receive(accepting, within: 1000)
  let monitor = case running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let stop_started = transport.monotonic_millisecond()
  let stopped = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let stop_was_bounded = stop_elapsed >= 0 && stop_elapsed <= 2500
  let joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case running {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let stopped_again = adapter.stop(listener)
  assert #(
      received_sync_point(running),
      stopped == Ok(Nil),
      stopped_again == Ok(Nil),
      joined,
      stop_was_bounded,
    )
    == #(True, True, True, True, True)
}

pub fn unconfirmed_http3_coordinator_exit_cannot_latch_success_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let phases = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_coordinator_join_probe(configuration, fn(phase, _) {
      process.send(phases, phase)
      False
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let stop_started = transport.monotonic_millisecond()
  let first = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let second = adapter.stop(listener)
  let normal_phase = process.receive(phases, within: 0)
  let forced_phase = process.receive(phases, within: 0)
  let expected = Error(error.new(error.Timeout(error.Operation)))
  assert #(
      first == expected,
      second == expected,
      first == second,
      coordinator_join_phase_is(normal_phase, 1),
      coordinator_join_phase_is(forced_phase, 2),
      stop_elapsed >= 0 && stop_elapsed <= 2500,
    )
    == #(True, True, True, True, True, True)
}

pub fn successful_http3_response_disposes_its_source_exactly_once_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let disposed = process.new_subject()
  let handler = fn(_, _) {
    let source =
      body.from_pull(
        body.pull(fn(_) {
          Ok(body.PullData(
            <<"ok":utf8>>,
            body.pull(fn(_) { Ok(body.PullEnd([])) }),
          ))
        }),
        Some(2),
        None,
        fn() { process.send(disposed, Nil) },
      )
      |> should.be_ok
    Ok(response.new(200) |> response.set_body(source))
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let received = send_empty(client: client, port: port, path: "/success")
  let first_disposal = process.receive(disposed, within: 1500)
  let duplicate_disposal = process.receive(disposed, within: 0)
  let stopped = adapter.stop(listener)
  assert #(
      response_is(incoming: received, expected_status: 200, expected_body: <<
        "ok":utf8,
      >>),
      first_disposal == Ok(Nil),
      duplicate_disposal == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True)
}

pub fn exiting_http3_source_cleanup_is_typed_and_does_not_rewrite_delivery_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let transferred = process.new_subject()
  let released = process.new_subject()
  let handler = fn(_, _) {
    let source =
      body.from_pull(
        body.pull(fn(_) { Ok(body.PullEnd([])) }),
        Some(0),
        None,
        fn() {
          http_test_support.exit_now()
          Nil
        },
      )
      |> should.be_ok
    let source =
      source
      |> body.observe_transfer(fn() { Nil }, fn(outcome) {
        process.send(transferred, outcome)
      })
      |> body.observe_release(fn(outcome) { process.send(released, outcome) })
    Ok(response.new(200) |> response.set_body(source))
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  // Keep the transport alive until the response terminal observer publishes the FIN acknowledgement.
  // The buffered one-shot helper closes immediately after reading End, which races the peer close against that wire evidence and cannot prove whether transfer or close won.
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/cleanup-exit")
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let response_head = http3_client.next_event(stream)
  let response_end = http3_client.next_event(stream)
  let transfer_outcome = process.receive(transferred, within: 1500)
  let release_outcome = process.receive(released, within: 1500)
  let _closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert #(
      finished == Ok(Nil),
      server_test_support.default_response_head(
        outcome: response_head,
        status: 200,
      ),
      response_end == Ok(http3_client.End),
      transfer_outcome == Ok(Ok(Nil)),
      release_outcome == Ok(Error(error.new(error.Service))),
      process.receive(transferred, within: 0) == Error(Nil),
      process.receive(released, within: 0) == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True, True)
}

pub fn stalled_http3_source_cleanup_is_stopped_and_reported_once_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let cleaning = process.new_subject()
  let released = process.new_subject()
  let handler = fn(_, _) {
    let source =
      body.from_pull(
        body.pull(fn(_) { Ok(body.PullEnd([])) }),
        Some(0),
        None,
        fn() {
          let unblock = process.new_subject()
          process.send(cleaning, #(unblock, process.self()))
          let _unblocked = process.receive(unblock, within: 10_000)
          Nil
        },
      )
      |> should.be_ok
    let source =
      body.observe_release(source, fn(outcome) {
        process.send(released, outcome)
      })
    Ok(response.new(200) |> response.set_body(source))
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let received = send_empty(client: client, port: port, path: "/cleanup-stall")
  let cleanup_running = process.receive(cleaning, within: 1500)
  let monitor = case cleanup_running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let release_outcome = process.receive(released, within: 2500)
  let cleanup_joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case cleanup_running {
    Ok(#(unblock, _)) -> process.send(unblock, Nil)
    Error(Nil) -> Nil
  }
  let stopped = adapter.stop(listener)
  assert #(
      response_is(incoming: received, expected_status: 200, expected_body: <<>>),
      received_sync_point(cleanup_running),
      release_outcome == Ok(Error(error.new(error.Cancelled))),
      cleanup_joined,
      process.receive(cleaning, within: 0) == Error(Nil),
      process.receive(released, within: 0) == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True)
}

pub fn early_http3_response_disposes_unfinished_request_once_and_reuses_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let request_disposed = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_request_disposed_probe(configuration, fn() {
      process.send(request_disposed, Nil)
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let early = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let early_head = http3_client.next_event(early)
  let early_end = http3_client.next_event(early)
  let first_disposal = process.receive(request_disposed, within: 2000)
  let no_duplicate_first = process.receive(request_disposed, within: 0)
  let upload_stopped =
    await_upload_stop(early, transport.monotonic_millisecond() + 1000)
  let late_upload_was_stopped =
    upload_stopped
    && case http3_client.send_chunk(early, <<"late":utf8>>) {
      Error(failure) -> upload_terminal_failure(failure)
      Ok(Nil) -> False
    }
  let next = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let next_finished = http3_client.finish(next)
  let next_head = http3_client.next_event(next)
  let next_end = http3_client.next_event(next)
  let second_disposal = process.receive(request_disposed, within: 2000)
  let no_duplicate_second = process.receive(request_disposed, within: 0)
  let _closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert #(
      server_test_support.default_response_head(
        outcome: early_head,
        status: 204,
      ),
      early_end == Ok(http3_client.End),
      first_disposal == Ok(Nil),
      no_duplicate_first == Error(Nil),
      late_upload_was_stopped,
      next_finished == Ok(Nil),
      server_test_support.default_response_head(outcome: next_head, status: 204),
      next_end == Ok(http3_client.End),
      second_disposal == Ok(Nil),
      no_duplicate_second == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True, True, True, True, True)
}

// A response can arrive before the peer's asynchronous STOP_SENDING signal.
fn await_upload_stop(stream: http3_client.Stream, deadline: Int) -> Bool {
  case http3_client.send_chunk(stream, <<>>) {
    Error(failure) -> upload_terminal_failure(failure)
    Ok(Nil) ->
      case transport.monotonic_millisecond() >= deadline {
        True -> False
        False -> {
          process.sleep(1)
          await_upload_stop(stream, deadline)
        }
      }
  }
}

fn upload_terminal_failure(failure: http3_client.Error) -> Bool {
  case failure {
    http3_client.RequestAlreadyFinished | http3_client.StreamFinished -> True
    http3_client.Failure(http3_failure.Cancelled)
    | http3_client.Failure(http3_failure.Http3(http3_failure.Local, None)) ->
      True
    _ -> False
  }
}

pub fn rejected_http3_request_setup_disposes_its_stream_body_exactly_once_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let request_disposed = process.new_subject()
  let handler_called = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_request_disposed_probe(fn() {
      process.send(request_disposed, Nil)
    })
    |> adapter.with_request_setup_probe(fn(_, _) {
      Error(error.new(error.Protocol(error.Http3)))
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        process.send(handler_called, Nil)
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let rejected = send_empty(client: client, port: port, path: "/rejected-setup")
  let first_disposal = process.receive(request_disposed, within: 1500)
  let handler_was_skipped = process.receive(handler_called, within: 0)
  let duplicate_disposal = process.receive(request_disposed, within: 0)
  let stopped = adapter.stop(listener)
  assert #(
      buffered_response_failed_safely(rejected),
      first_disposal == Ok(Nil),
      handler_was_skipped == Error(Nil),
      duplicate_disposal == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True)
}

pub fn stopped_http3_request_setup_is_joined_before_body_disposal_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let setting_up = process.new_subject()
  let request_disposed = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_request_disposed_probe(fn() {
      process.send(request_disposed, Nil)
    })
    |> adapter.with_request_setup_probe(fn(_, _) {
      let unblock = process.new_subject()
      process.send(setting_up, #(unblock, process.self()))
      let _unblocked = process.receive(unblock, within: 10_000)
      Error(error.new(error.Protocol(error.Http3)))
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let setup_running = process.receive(setting_up, within: 3000)
  let setup_monitor = case setup_running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let stop_started = transport.monotonic_millisecond()
  let stopped = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let setup_joined = case setup_monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  let first_disposal = process.receive(request_disposed, within: 1000)
  case setup_running {
    Ok(#(unblock, _)) -> process.send(unblock, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  assert #(
      finished == Ok(Nil),
      received_sync_point(setup_running),
      stopped == Ok(Nil),
      stop_elapsed >= 0 && stop_elapsed <= 2500,
      setup_joined,
      first_disposal == Ok(Nil),
      process.receive(request_disposed, within: 0) == Error(Nil),
    )
    == #(True, True, True, True, True, True, True)
}

pub fn stalled_http3_transfer_observer_cannot_block_source_disposal_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let observing = process.new_subject()
  let disposed = process.new_subject()
  let handler = fn(_, _) {
    let source =
      body.from_pull(
        body.pull(fn(_) { Ok(body.PullEnd([])) }),
        Some(0),
        None,
        fn() { process.send(disposed, Nil) },
      )
      |> should.be_ok
    let source =
      body.observe_transfer(source, fn() { Nil }, fn(_) {
        let release = process.new_subject()
        process.send(observing, #(release, process.self()))
        let _released = process.receive(release, within: 10_000)
        Nil
      })
    Ok(response.new(200) |> response.set_body(source))
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let received = send_empty(client: client, port: port, path: "/observer")
  let observer_running = process.receive(observing, within: 1000)
  let observer_monitor = case observer_running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let observer_joined = case observer_monitor {
    Some(monitor) -> monitor_joined(monitor, 1500)
    None -> False
  }
  let source_disposed = process.receive(disposed, within: 1000)
  case observer_running {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let stopped = adapter.stop(listener)
  assert #(
      response_is(incoming: received, expected_status: 200, expected_body: <<>>),
      received_sync_point(observer_running),
      observer_joined,
      source_disposed == Ok(Nil),
      process.receive(observing, within: 0) == Error(Nil),
      process.receive(disposed, within: 0) == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True)
}

pub fn stopped_http3_listener_joins_a_blocked_handler_worker_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let handler = fn(_, _) {
    let blocked = process.new_subject()
    process.send(started, #(blocked, process.self()))
    let _released = process.receive(blocked, within: 10_000)
    Ok(response.new(200) |> response.set_body(body.empty()))
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let running = process.receive(started, within: 3000)
  let monitor = case running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let stop_started = transport.monotonic_millisecond()
  let stopped = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let stop_was_bounded = stop_elapsed >= 0 && stop_elapsed <= 2500
  let joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case running {
    Ok(#(blocked, _)) -> process.send(blocked, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  assert #(
      finished == Ok(Nil),
      received_sync_point(running),
      stopped == Ok(Nil),
      joined,
      stop_was_bounded,
    )
    == #(True, True, True, True, True)
}

pub fn unconfirmed_http3_worker_cleanup_cannot_report_stop_success_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_shutdown_join_probe(configuration, fn(worker_count, _) {
      list.repeat(False, worker_count)
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        let blocked = process.new_subject()
        process.send(started, #(blocked, process.self()))
        let _released = process.receive(blocked, within: 10_000)
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let running = process.receive(started, within: 3000)
  let monitor = case running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let stop_started = transport.monotonic_millisecond()
  let stopped = adapter.stop(listener)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  let stopped_again = adapter.stop(listener)
  case running {
    Ok(#(blocked, _)) -> process.send(blocked, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  assert #(
      finished == Ok(Nil),
      received_sync_point(running),
      stopped == Error(error.new(error.Timeout(error.Operation))),
      stopped_again == Error(error.new(error.Timeout(error.Operation))),
      stop_elapsed >= 0 && stop_elapsed <= 2500,
      joined,
    )
    == #(True, True, True, True, True, True)
}

pub fn concurrent_http3_stops_observe_the_same_terminal_failure_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler_started = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_shutdown_join_probe(configuration, fn(worker_count, _) {
      list.repeat(False, worker_count)
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        let blocked = process.new_subject()
        process.send(handler_started, #(blocked, process.self()))
        let _released = process.receive(blocked, within: 10_000)
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let stream =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  let finished = http3_client.finish(stream)
  let running = process.receive(handler_started, within: 3000)
  let monitor = case running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let ready = process.new_subject()
  let first =
    http_test_support.start_task(fn() {
      let begin_stop = process.new_subject()
      process.send(ready, begin_stop)
      let _started = process.receive(begin_stop, within: 1000)
      adapter.stop(listener)
    })
  let second =
    http_test_support.start_task(fn() {
      let begin_stop = process.new_subject()
      process.send(ready, begin_stop)
      let _started = process.receive(begin_stop, within: 1000)
      adapter.stop(listener)
    })
  let first_ready = process.receive(ready, within: 1000)
  let second_ready = process.receive(ready, within: 1000)
  let stop_started = transport.monotonic_millisecond()
  case first_ready {
    Ok(begin_stop) -> process.send(begin_stop, Nil)
    Error(Nil) -> Nil
  }
  case second_ready {
    Ok(begin_stop) -> process.send(begin_stop, Nil)
    Error(Nil) -> Nil
  }
  let first_outcome = http_test_support.await_task(first)
  let second_outcome = http_test_support.await_task(second)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  let joined = case monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case running {
    Ok(#(blocked, _)) -> process.send(blocked, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  let terminal_failure = Error(error.new(error.Timeout(error.Operation)))
  assert #(
      finished == Ok(Nil),
      received_sync_point(running),
      received_stop_gate(first_ready),
      received_stop_gate(second_ready),
      first_outcome == terminal_failure,
      second_outcome == terminal_failure,
      first_outcome == second_outcome,
      stop_elapsed >= 0 && stop_elapsed <= 2500,
      joined,
    )
    == #(True, True, True, True, True, True, True, True, True)
}

pub fn concurrent_http3_stops_observe_the_same_terminal_success_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let #(listener, _) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: fn(_, _) {
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
    )
  let ready = process.new_subject()
  let first =
    http_test_support.start_task(fn() {
      let begin_stop = process.new_subject()
      process.send(ready, begin_stop)
      let _started = process.receive(begin_stop, within: 1000)
      adapter.stop(listener)
    })
  let second =
    http_test_support.start_task(fn() {
      let begin_stop = process.new_subject()
      process.send(ready, begin_stop)
      let _started = process.receive(begin_stop, within: 1000)
      adapter.stop(listener)
    })
  let first_ready = process.receive(ready, within: 1000)
  let second_ready = process.receive(ready, within: 1000)
  let stop_started = transport.monotonic_millisecond()
  case first_ready {
    Ok(begin_stop) -> process.send(begin_stop, Nil)
    Error(Nil) -> Nil
  }
  case second_ready {
    Ok(begin_stop) -> process.send(begin_stop, Nil)
    Error(Nil) -> Nil
  }
  let first_outcome = http_test_support.await_task(first)
  let second_outcome = http_test_support.await_task(second)
  let stop_elapsed = transport.monotonic_millisecond() - stop_started
  assert #(
      received_stop_gate(first_ready),
      received_stop_gate(second_ready),
      first_outcome == Ok(Nil),
      second_outcome == Ok(Nil),
      first_outcome == second_outcome,
      stop_elapsed >= 0 && stop_elapsed <= 2500,
    )
    == #(True, True, True, True, True, True)
}

pub fn exiting_http3_handler_is_isolated_from_the_next_request_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/exiting" -> {
        http_test_support.exit_now()
        Ok(response.new(200) |> response.set_body(body.empty()))
      }
      _ -> Ok(response.new(204) |> response.set_body(body.empty()))
    }
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let failed =
    stream_exchange_is(
      connection,
      request.set_path(outgoing, "/exiting"),
      response_failed_safely,
    )
  let healthy =
    stream_exchange_is(
      connection,
      request.set_path(outgoing, "/healthy"),
      fn(head, ended) {
        server_test_support.default_response_head(outcome: head, status: 204)
        && ended == Ok(http3_client.End)
      },
    )
  let _closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert #(failed, healthy, stopped == Ok(Nil)) == #(True, True, True)
}

pub fn blocked_http3_response_source_does_not_block_another_stream_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let pulling = process.new_subject()
  let disposed = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/blocked" -> {
        let source =
          body.from_pull(
            body.pull(fn(_) {
              let release = process.new_subject()
              process.send(pulling, #(release, process.self()))
              let _released = process.receive(release, within: 10_000)
              Error(error.new(error.Service))
            }),
            None,
            None,
            fn() { process.send(disposed, Nil) },
          )
          |> should.be_ok
        Ok(response.new(200) |> response.set_body(source))
      }
      _ -> Ok(response.new(204) |> response.set_body(body.empty()))
    }
  }
  let #(listener, port) =
    start_listener(
      certificate: certificate,
      private_key: private_key,
      handler: handler,
    )
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let blocked =
    http3_client.open_stream(connection, request.set_path(outgoing, "/blocked"))
    |> should.be_ok
  let blocked_finished = http3_client.finish(blocked)
  let blocked_head = http3_client.next_event(blocked)
  let source_running = process.receive(pulling, within: 3000)
  let source_monitor = case source_running {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let fast =
    http3_client.open_stream(connection, request.set_path(outgoing, "/fast"))
    |> should.be_ok
  let fast_finished = http3_client.finish(fast)
  let fast_head = http3_client.next_event(fast)
  let fast_end = http3_client.next_event(fast)
  let _cancelled = http3_client.cancel(blocked)
  let source_disposed = process.receive(disposed, within: 1000)
  let source_joined = case source_monitor {
    Some(monitor) -> monitor_joined(monitor, 1000)
    None -> False
  }
  case source_running {
    Ok(#(release, _)) -> process.send(release, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert #(
      blocked_finished == Ok(Nil),
      server_test_support.default_response_head(
        outcome: blocked_head,
        status: 200,
      ),
      received_sync_point(source_running),
      fast_finished == Ok(Nil),
      server_test_support.default_response_head(outcome: fast_head, status: 204),
      fast_end == Ok(http3_client.End),
      source_disposed == Ok(Nil),
      source_joined,
      process.receive(disposed, within: 0) == Error(Nil),
      stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True, True, True, True)
}

fn start_listener(
  certificate certificate: BitArray,
  private_key private_key: BitArray,
  handler handler: adapter.Handler,
) -> #(adapter.Listener, Int) {
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let listener =
    adapter.listen(handler, <<127, 0, 0, 1>>, 0, configuration) |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  #(listener, port)
}

fn send_empty(
  client client: http3_client.Client,
  port port: Int,
  path path: String,
) -> Result(response.Response(BitArray), http3_client.Error) {
  http3_client.send(
    client,
    request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path(path)
      |> request.set_body(<<>>),
  )
}

fn response_status_is(
  incoming: Result(response.Response(BitArray), http3_client.Error),
  expected: Int,
) -> Bool {
  result.map(incoming, fn(incoming) { incoming.status == expected })
  |> result.unwrap(False)
}

fn response_is(
  incoming incoming: Result(response.Response(BitArray), http3_client.Error),
  expected_status expected_status: Int,
  expected_body expected_body: BitArray,
) -> Bool {
  result.map(incoming, fn(incoming) {
    incoming.status == expected_status && incoming.body == expected_body
  })
  |> result.unwrap(False)
}

fn buffered_response_failed_safely(
  incoming: Result(response.Response(BitArray), http3_client.Error),
) -> Bool {
  case incoming {
    Ok(incoming) -> incoming.status == 500 && incoming.body == <<>>
    Error(http3_client.Failure(http3_failure.Closed(
      http3_failure.Peer,
      Some(0x10c),
    ))) -> True
    _ -> False
  }
}

fn response_event_failed(
  event: Result(http3_client.ResponseEvent, http3_client.Error),
) -> Bool {
  result.is_error(event)
}

fn stream_exchange_is(
  connection: http3_client.Connection,
  outgoing: request.Request(Nil),
  matches: fn(
    Result(http3_client.ResponseEvent, http3_client.Error),
    Result(http3_client.ResponseEvent, http3_client.Error),
  ) -> Bool,
) -> Bool {
  result.map(http3_client.open_stream(connection, outgoing), fn(stream) {
    {
      let finished = http3_client.finish(stream)
      let head = http3_client.next_event(stream)
      let ended = case head {
        Error(failure) -> Error(failure)
        Ok(_) -> http3_client.next_event(stream)
      }
      finished == Ok(Nil) && matches(head, ended)
    }
  })
  |> result.unwrap(False)
}

fn response_failed_safely(
  head: Result(http3_client.ResponseEvent, http3_client.Error),
  ended: Result(http3_client.ResponseEvent, http3_client.Error),
) -> Bool {
  case head {
    Ok(http3_client.Response(500, _)) -> ended == Ok(http3_client.End)
    Error(http3_client.Failure(http3_failure.Closed(
      http3_failure.Peer,
      Some(0x10c),
    ))) -> True
    _ -> False
  }
}

fn received_sync_point(
  received: Result(#(process.Subject(Nil), process.Pid), Nil),
) -> Bool {
  case received {
    Ok(_) -> True
    Error(Nil) -> False
  }
}

fn received_stop_gate(received: Result(process.Subject(Nil), Nil)) -> Bool {
  case received {
    Ok(_) -> True
    Error(Nil) -> False
  }
}

fn listener_failed_with(
  received: Result(adapter.Listener, error.Error),
  expected: error.ErrorKind,
) -> Bool {
  case received {
    Error(failure) -> error.kind(failure) == expected
    Ok(_) -> False
  }
}

fn listener_started(received: Result(adapter.Listener, error.Error)) -> Bool {
  result.is_ok(received)
}

fn received_port(received: Result(Int, Nil)) -> Bool {
  case received {
    Ok(port) -> port > 0 && port <= 65_535
    Error(Nil) -> False
  }
}

fn monitor_pid_joined(pid: process.Pid, milliseconds: Int) -> Bool {
  monitor_joined(process.monitor(pid), milliseconds)
}

fn coordinator_join_phase_is(
  received: Result(Int, Nil),
  expected: Int,
) -> Bool {
  case received {
    Ok(phase) -> phase == expected
    Error(Nil) -> False
  }
}

fn monitor_joined(monitor: process.Monitor, milliseconds: Int) -> Bool {
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: milliseconds)
  process.demonitor_process(monitor)
  joined == Ok(Nil)
}
