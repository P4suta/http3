import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
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
import http/diagnostics
import http/error
import http/internal/client_trace
import http/internal/transport
import http/server
import http3/client as h3_client
import http3/server as h3_server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn logical_success_waits_for_headers_wire_eof_and_release_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(16, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt

  // Request success before any terminal transition.
  // The trace must retain only the bounded intent until every required event has been admitted.
  client_trace.exchange_finished(trace, Ok(Nil))
  client_trace.headers(trace, context.Http2, 200)
  client_trace.finished(trace, Some(context.Http2), Ok(Nil))
  client_trace.read_finished(trace, context.Http2)
  client_trace.released(trace, Some(context.Http2), Ok(Nil))

  assert diagnostics.stop(reporter) == Ok(Nil)
  let stages = sequenced_client_stages(collect(observed, []))
  let assert [#(header_sequence, diagnostics.ResponseHeaders(..))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.ResponseHeaders(..) -> True
        _ -> False
      }
    })
  let assert [#(finished_sequence, diagnostics.AttemptFinished(..))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptFinished(..) -> True
        _ -> False
      }
    })
  let assert [#(read_sequence, diagnostics.ResponseReadFinished(..))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.ResponseReadFinished(..) -> True
        _ -> False
      }
    })
  let assert [#(release_sequence, diagnostics.AttemptReleased(..))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptReleased(..) -> True
        _ -> False
      }
    })
  let assert [#(success_sequence, diagnostics.ExchangeFinished(Ok(Nil)))] =
    matching_stages(stages, fn(stage) {
      stage == diagnostics.ExchangeFinished(Ok(Nil))
    })
  assert header_sequence < finished_sequence
  assert finished_sequence < read_sequence
  assert finished_sequence < release_sequence
  assert success_sequence > read_sequence
  assert success_sequence > release_sequence
}

pub fn failed_body_cannot_be_reclassified_by_a_late_success_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(16, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  let failure = error.new(error.Body(error.ReadFailed))
  client_trace.headers(trace, context.Http3, 200)
  client_trace.finished(trace, Some(context.Http3), Error(failure))
  client_trace.released(trace, Some(context.Http3), Ok(Nil))

  // This is the retained headers/EOF mutation.
  // It must remain pending because the attempt has a failed wire terminal, then the actual failure wins.
  client_trace.read_finished(trace, context.Http3)
  client_trace.exchange_finished(trace, Ok(Nil))
  client_trace.exchange_finished(trace, Error(failure))

  assert diagnostics.stop(reporter) == Ok(Nil)
  let final =
    sequenced_client_stages(collect(observed, []))
    |> matching_stages(fn(stage) {
      case stage {
        diagnostics.ExchangeFinished(..) -> True
        _ -> False
      }
    })
  let assert [#(_, diagnostics.ExchangeFinished(Error(observed_failure)))] =
    final
  assert error.kind(observed_failure) == error.Body(error.ReadFailed)
}

pub fn release_racing_ahead_is_published_after_attempt_completion_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(16, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.headers(trace, context.Http1, 204)
  client_trace.released(
    trace,
    Some(context.Http1),
    Error(error.new(error.Timeout(error.Operation))),
  )
  client_trace.finished(trace, Some(context.Http1), Ok(Nil))
  client_trace.read_finished(trace, context.Http1)
  client_trace.exchange_finished(trace, Ok(Nil))

  assert diagnostics.stop(reporter) == Ok(Nil)
  let stages = sequenced_client_stages(collect(observed, []))
  let assert [#(finished_sequence, diagnostics.AttemptFinished(..))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptFinished(..) -> True
        _ -> False
      }
    })
  let assert [
    #(
      release_sequence,
      diagnostics.AttemptReleased(_, Some(context.Http1), Error(cleanup)),
    ),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptReleased(..) -> True
        _ -> False
      }
    })
  assert error.kind(cleanup) == error.Timeout(error.Operation)
  assert release_sequence > finished_sequence
  let assert [#(failure_sequence, diagnostics.ExchangeFinished(Error(failure)))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.ExchangeFinished(Error(_)) -> True
        _ -> False
      }
    })
  assert error.kind(failure) == error.Timeout(error.Operation)
  assert failure_sequence > release_sequence
  let assert client_trace.TransitionSnapshot(
    duplicates: 0,
    out_of_order: 1,
    late: 0,
  ) = client_trace.transition_snapshot(trace)
  Nil
}

pub fn duplicate_out_of_order_and_late_transitions_are_finite_and_typed_test() -> Nil {
  let assert Ok(reporter) = diagnostics.start(8, 100, fn(_) { Ok(Nil) })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.headers(trace, context.Http1, 200)
  client_trace.headers(trace, context.Http1, 201)
  client_trace.finished(
    trace,
    Some(context.Http1),
    Error(error.new(error.Protocol(error.Http1))),
  )
  // The unified dispatcher may observe the same lower-adapter failure.
  // Its protocol-free fallback must preserve the typed terminal without turning an expected ownership handoff into a duplicate anomaly.
  client_trace.finished_if_missing(
    trace,
    None,
    Error(error.new(error.Protocol(error.Http1))),
  )
  client_trace.read_finished(trace, context.Http1)
  client_trace.released(trace, Some(context.Http1), Ok(Nil))
  client_trace.released(trace, Some(context.Http1), Ok(Nil))
  let assert client_trace.TransitionSnapshot(
    duplicates: 2,
    out_of_order: 0,
    late: 1,
  ) = client_trace.transition_snapshot(trace)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn outer_dispatch_supplies_only_a_missing_terminal_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(8, 100, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  let failure = error.new(error.ConnectFailed)
  client_trace.finished_if_missing(trace, None, Error(failure))
  client_trace.finished_if_missing(trace, None, Error(failure))
  client_trace.released_if_missing(trace, None, Ok(Nil))
  client_trace.released_if_missing(trace, None, Ok(Nil))
  let assert client_trace.TransitionSnapshot(0, 0, 0) =
    client_trace.transition_snapshot(trace)
  assert diagnostics.stop(reporter) == Ok(Nil)
  let stages = sequenced_client_stages(collect(observed, []))
  let terminals =
    stages
    |> matching_stages(fn(stage) {
      case stage {
        diagnostics.AttemptFinished(..) -> True
        _ -> False
      }
    })
  let assert [
    #(_, diagnostics.AttemptFinished(_, None, Error(observed_failure))),
  ] = terminals
  assert error.kind(observed_failure) == error.ConnectFailed
  let releases =
    stages
    |> matching_stages(fn(stage) {
      case stage {
        diagnostics.AttemptReleased(..) -> True
        _ -> False
      }
    })
  let assert [#(_, diagnostics.AttemptReleased(_, None, Ok(Nil)))] = releases
  Nil
}

pub fn rejected_exchange_disposes_request_body_before_logical_failure_test() -> Nil {
  let observed = process.new_subject()
  let cancelled = process.new_subject()
  let pulled = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(32, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulled, Nil)
        Ok(body.PullEnd([]))
      }),
      Some(0),
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(running) =
    client.defaults()
    |> client.with_diagnostics(reporter)
    |> client.start
  let outcome =
    client.exchange(
      running,
      request.new()
        |> request.set_scheme(gleam_http.Http)
        |> request.set_host("localhost")
        |> request.set_body(source),
    )
  let cancellation = process.receive(cancelled, within: 1000)
  let duplicate_cancellation = process.receive(cancelled, within: 0)
  let unexpected_pull = process.receive(pulled, within: 0)
  let closed = client.close(running)
  let stopped = diagnostics.stop(reporter)
  let stages = sequenced_client_stages(collect(observed, []))

  let assert Error(failure) = outcome
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
  assert cancellation == Ok(Nil)
  assert duplicate_cancellation == Error(Nil)
  assert unexpected_pull == Error(Nil)
  assert closed == Ok(Nil)
  assert stopped == Ok(Nil)
  let assert [#(started_at, diagnostics.AttemptStarted(attempt))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptStarted(_) -> True
        _ -> False
      }
    })
  let assert [
    #(
      finished_at,
      diagnostics.AttemptFinished(
        finished_attempt,
        None,
        Error(attempt_failure),
      ),
    ),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptFinished(..) -> True
        _ -> False
      }
    })
  let assert [
    #(released_at, diagnostics.AttemptReleased(released_attempt, None, Ok(Nil))),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptReleased(..) -> True
        _ -> False
      }
    })
  let assert [
    #(
      release_started_at,
      diagnostics.PhaseStarted(
        release_phase_attempt,
        diagnostics.ResourceRelease,
      ),
    ),
    #(
      release_finished_at,
      diagnostics.PhaseFinished(
        finished_release_phase_attempt,
        diagnostics.ResourceRelease,
        Ok(Nil),
      ),
    ),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(_, diagnostics.ResourceRelease)
        | diagnostics.PhaseFinished(_, diagnostics.ResourceRelease, _) -> True
        _ -> False
      }
    })
  let assert [
    #(logical_failure_at, diagnostics.ExchangeFinished(Error(logical_failure))),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.ExchangeFinished(Error(_)) -> True
        _ -> False
      }
    })
  assert attempt == finished_attempt
  assert attempt == released_attempt
  assert attempt == release_phase_attempt
  assert attempt == finished_release_phase_attempt
  assert error.kind(attempt_failure) == error.Policy(error.SecurityPolicy)
  assert error.kind(logical_failure) == error.Policy(error.SecurityPolicy)
  assert started_at < finished_at
  assert finished_at < release_started_at
  assert release_started_at < release_finished_at
  assert release_finished_at < released_at
  assert released_at < logical_failure_at
}

pub fn closed_exchange_disposes_request_body_and_reports_cancellation_test() -> Nil {
  let observed = process.new_subject()
  let cancelled = process.new_subject()
  let pulled = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(32, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(pulled, Nil)
        Ok(body.PullEnd([]))
      }),
      Some(0),
      None,
      fn() { process.send(cancelled, Nil) },
    )
  let assert Ok(running) =
    client.defaults()
    |> client.with_diagnostics(reporter)
    |> client.start
  assert client.close(running) == Ok(Nil)
  let outcome =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_body(source),
    )
  let cancellation = process.receive(cancelled, within: 1000)
  let duplicate_cancellation = process.receive(cancelled, within: 0)
  let unexpected_pull = process.receive(pulled, within: 0)
  let stopped = diagnostics.stop(reporter)
  let stages = sequenced_client_stages(collect(observed, []))

  let assert Error(failure) = outcome
  assert error.kind(failure) == error.Cancelled
  assert cancellation == Ok(Nil)
  assert duplicate_cancellation == Error(Nil)
  assert unexpected_pull == Error(Nil)
  assert stopped == Ok(Nil)
  let cancellations =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(_, diagnostics.Cancellation)
        | diagnostics.PhaseFinished(_, diagnostics.Cancellation, Error(_)) ->
          True
        _ -> False
      }
    })
  let assert [#(cancel_started, _), #(cancel_finished, _)] = cancellations
  let assert [#(attempt_finished, diagnostics.AttemptFinished(_, None, _))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptFinished(..) -> True
        _ -> False
      }
    })
  let assert [#(released, diagnostics.AttemptReleased(_, None, Ok(Nil)))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptReleased(..) -> True
        _ -> False
      }
    })
  let assert [
    #(
      release_started,
      diagnostics.PhaseStarted(release_attempt, diagnostics.ResourceRelease),
    ),
    #(
      release_finished,
      diagnostics.PhaseFinished(
        finished_release_attempt,
        diagnostics.ResourceRelease,
        Ok(Nil),
      ),
    ),
  ] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(_, diagnostics.ResourceRelease)
        | diagnostics.PhaseFinished(_, diagnostics.ResourceRelease, _) -> True
        _ -> False
      }
    })
  let assert [#(logical_failure, diagnostics.ExchangeFinished(Error(_)))] =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.ExchangeFinished(Error(_)) -> True
        _ -> False
      }
    })
  assert cancel_started < cancel_finished
  assert cancel_finished < attempt_finished
  assert release_attempt == finished_release_attempt
  assert attempt_finished < release_started
  assert release_started < release_finished
  assert release_finished < released
  assert released < logical_failure
}

pub fn deferred_release_codec_preserves_every_safe_error_constructor_test() -> Nil {
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
  assert list.map(
      classifications,
      client_trace.release_classification_round_trip,
    )
    == classifications
  assert client_trace.release_classification_round_trip(
      error.Body(error.TooLarge(123_456)),
    )
    == error.Body(error.TooLarge(0))
  assert client_trace.release_classification_round_trip(
      error.Body(error.LengthMismatch(123, 456)),
    )
    == error.Body(error.LengthMismatch(0, 0))
}

pub fn client_elapsed_projection_is_monotonic_and_non_negative_test() -> Nil {
  assert client_trace.elapsed_milliseconds(started: 10, observed: 15) == 5
  assert client_trace.elapsed_milliseconds(started: 15, observed: 15) == 0
  assert client_trace.elapsed_milliseconds(started: 15, observed: 10) == 0
}

pub fn protocol_selection_and_cancellation_are_once_only_per_attempt_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(16, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.protocol_selected(trace, context.Http2)
  client_trace.protocol_selected(trace, context.Http2)
  let cancelled = error.new(error.Cancelled)
  client_trace.finished(trace, Some(context.Http2), Error(cancelled))
  client_trace.finished(trace, Some(context.Http2), Error(cancelled))

  assert diagnostics.stop(reporter) == Ok(Nil)
  let stages = sequenced_client_stages(collect(observed, []))
  let selections =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(
          _,
          diagnostics.ProtocolSelection(context.Http2),
        )
        | diagnostics.PhaseFinished(
            _,
            diagnostics.ProtocolSelection(context.Http2),
            Ok(Nil),
          ) -> True
        _ -> False
      }
    })
  let cancellations =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(_, diagnostics.Cancellation)
        | diagnostics.PhaseFinished(_, diagnostics.Cancellation, Error(_)) ->
          True
        _ -> False
      }
    })
  let assert [#(selection_started, _), #(selection_finished, _)] = selections
  let assert [#(cancellation_started, _), #(cancellation_finished, _)] =
    cancellations
  assert selection_started < selection_finished
  assert cancellation_started < cancellation_finished
}

pub fn phase_state_machine_rejects_duplicate_and_out_of_order_events_test() -> Nil {
  let assert Ok(reporter) = diagnostics.start(8, 100, fn(_) { Ok(Nil) })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.phase_finished(trace, diagnostics.ResourceAdmission, Ok(Nil))
  client_trace.phase_started(trace, diagnostics.ResourceAdmission)
  client_trace.phase_started(trace, diagnostics.ResourceAdmission)
  client_trace.phase_finished(trace, diagnostics.ResourceAdmission, Ok(Nil))
  client_trace.phase_finished(trace, diagnostics.ResourceAdmission, Ok(Nil))
  let assert client_trace.TransitionSnapshot(
    duplicates: 2,
    out_of_order: 1,
    late: 0,
  ) = client_trace.transition_snapshot(trace)
  assert diagnostics.stop(reporter) == Ok(Nil)
}

pub fn successful_client_trace_correlates_headers_eof_and_release_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 64,
      sink_timeout_milliseconds: 1000,
      sink: fn(record) {
        process.send(observed, record)
        Ok(Nil)
      },
    )
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let serving =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(socket, 4096, 1000))
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
        >>),
      )
      transport.close(socket)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_diagnostics(reporter)
    |> client.start
  let incoming =
    client.exchange(
      running,
      request.new()
        |> request.set_scheme(gleam_http.Http)
        |> request.set_host("127.0.0.1")
        |> request.set_port(port)
        |> request.set_path("/private-path-never-export")
        |> request.set_header("authorization", "secret-token")
        |> request.set_body(body.empty()),
    )
  let completed = case incoming {
    Ok(exchange) -> body.read_all(client.response(exchange).body, 2)
    Error(failure) -> Error(failure)
  }
  let closed = client.close(running)
  let stopped = diagnostics.stop(reporter)
  let _listener_stopped = transport.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  let records = collect(observed, [])
  assert completed == Ok(#(<<"ok":utf8>>, []))
  assert closed == Ok(Nil)
  assert stopped == Ok(Nil)
  assert serving_done == Ok(Nil)
  assert_tcp_connect_trace(
    records: records,
    phase: diagnostics.ConnectionAttempt(diagnostics.Tcp),
    progress: diagnostics.ConnectSucceeded,
  )
  assert_successful_phase(records, diagnostics.ProtocolSelection(context.Http1))
  assert_successful_phase(records, diagnostics.ResourceAdmission)
  assert_successful_phase(
    records,
    diagnostics.RequestTransmission(context.Http1),
  )
  assert_successful_phase(records, diagnostics.ResponseReception(context.Http1))
  assert_successful_phase(records, diagnostics.ResourceRelease)
  let stages =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(id, _, stage) -> Ok(#(id, stage))
        _ -> Error(Nil)
      }
    })
  let assert [#(request_id, _), ..] = stages
  assert list.all(stages, fn(pair) { pair.0 == request_id })
  assert list.any(stages, fn(pair) { pair.1 == diagnostics.ExchangeStarted })
  assert list.any(stages, fn(pair) {
    case pair.1 {
      diagnostics.ResponseHeaders(_, context.Http1, 200) -> True
      _ -> False
    }
  })
  assert list.any(stages, fn(pair) {
    case pair.1 {
      diagnostics.ResponseReadFinished(_, context.Http1) -> True
      _ -> False
    }
  })
  assert list.any(stages, fn(pair) {
    case pair.1 {
      diagnostics.AttemptReleased(_, _, Ok(Nil)) -> True
      _ -> False
    }
  })
  assert list.any(stages, fn(pair) {
    pair.1 == diagnostics.ExchangeFinished(Ok(Nil))
  })
}

pub fn status_retry_releases_old_attempt_before_new_attempt_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 128,
      sink_timeout_milliseconds: 1000,
      sink: fn(record) {
        process.send(observed, record)
        Ok(Nil)
      },
    )
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 3000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let serving =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 3000))
      use _ <- result.try(transport.read(first, 4096, 3000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 503 Service Unavailable\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))
      use second <- result.try(transport.accept(listener, 3000))
      use _ <- result.try(transport.read(second, 4096, 3000))
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
        >>),
      )
      transport.close(second)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_diagnostics(reporter)
    |> client.with_retry_policy(
      client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [503]),
    )
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.new()
    |> request.set_scheme(gleam_http.Http)
    |> request.set_host("127.0.0.1")
    |> request.set_port(port)
    |> request.set_path("/retry-after-release")
    |> request.set_body(body.empty())
  let assert Ok(completed) = client.exchange(running, outgoing)
  let incoming = client.response(completed)
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(incoming.body, 2)
  let assert Ok(Nil) = http_test_support.await_task(serving)
  assert client.close(running) == Ok(Nil)
  assert transport.stop(listener) == Ok(Nil)
  assert diagnostics.stop(reporter) == Ok(Nil)
  let stages = sequenced_client_stages(collect(observed, []))
  let starts =
    list.filter_map(stages, fn(entry) {
      case entry.1 {
        diagnostics.AttemptStarted(attempt) -> Ok(#(entry.0, attempt))
        _ -> Error(Nil)
      }
    })
  let assert [
    #(first_started, first_attempt),
    #(second_started, second_attempt),
  ] = starts
  assert first_attempt != second_attempt
  let finished =
    list.filter_map(stages, fn(entry) {
      case entry.1 {
        diagnostics.AttemptFinished(attempt, Some(context.Http1), outcome) ->
          Ok(#(entry.0, attempt, outcome))
        _ -> Error(Nil)
      }
    })
  let assert [
    #(first_finished, first_finished_attempt, Ok(Nil)),
    #(second_finished, second_finished_attempt, Ok(Nil)),
  ] = finished
  assert first_finished_attempt == first_attempt
  assert second_finished_attempt == second_attempt
  let releases =
    list.filter_map(stages, fn(entry) {
      case entry.1 {
        diagnostics.AttemptReleased(attempt, Some(context.Http1), cleanup) ->
          Ok(#(entry.0, attempt, cleanup))
        _ -> Error(Nil)
      }
    })
  let assert [
    #(first_released, first_released_attempt, Ok(Nil)),
    #(second_released, second_released_attempt, Ok(Nil)),
  ] = releases
  assert first_released_attempt == first_attempt
  assert second_released_attempt == second_attempt
  assert first_started < first_finished
  assert first_finished < first_released
  assert first_released < second_started
  assert second_started < second_finished
  assert second_finished < second_released
  let assert [#(logical_success, diagnostics.ExchangeFinished(Ok(Nil)))] =
    matching_stages(stages, fn(stage) {
      stage == diagnostics.ExchangeFinished(Ok(Nil))
    })
  assert logical_success > second_released
}

pub fn partial_response_failure_is_terminal_and_never_retried_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 30_000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use first_read <- result.try(transport.read(first, 4096, 1000))
      let assert transport.ReadData(_, first) = first_read
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 4\r\nConnection: close\r\n\r\nab":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))
      result.map(transport.accept(listener, 30_000), fn(second) {
        {
          let _closed = transport.close(second)
          Ok(True)
        }
      })
      |> result.unwrap(Ok(False))
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_diagnostics(reporter)
    |> client.start
  let outgoing =
    request.new()
    |> request.set_scheme(gleam_http.Http)
    |> request.set_host("127.0.0.1")
    |> request.set_port(port)
    |> request.set_path("/partial")
    |> request.set_body(body.empty())

  let assert Ok(exchange) = client.exchange(running, outgoing)
  let assert Error(failure) = body.read_all(client.response(exchange).body, 4)
  assert error.kind(failure) == error.Protocol(error.Http1)
  let assert Ok(Nil) = transport.stop(listener)
  let assert Ok(False) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = diagnostics.stop(reporter)

  let stages =
    collect(observed, [])
    |> list.filter_map(fn(record) {
      case record.event {
        diagnostics.ClientObserved(_, _, stage) -> Ok(stage)
        _ -> Error(Nil)
      }
    })
  assert list.count(stages, fn(stage) {
      case stage {
        diagnostics.AttemptStarted(_) -> True
        _ -> False
      }
    })
    == 1
  let logical_outcomes =
    list.filter_map(stages, fn(stage) {
      case stage {
        diagnostics.ExchangeFinished(outcome) -> Ok(outcome)
        _ -> Error(Nil)
      }
    })
  let assert [Error(logical_failure)] = logical_outcomes
  assert error.kind(logical_failure) == error.Protocol(error.Http1)
}

pub fn retry_policy_does_not_replay_a_possibly_processed_pooled_request_test() -> Nil {
  assert stale_http1_pool_reconnect_fixture(True) == Ok(Nil)
}

pub fn disabling_retries_prevents_hidden_http1_pool_reconnect_test() -> Nil {
  assert stale_http1_pool_reconnect_fixture(False) == Ok(Nil)
}

fn stale_http1_pool_reconnect_fixture(retry_enabled: Bool) -> Result(Nil, Nil) {
  let observed = process.new_subject()
  let pooled_request_gate = process.new_subject()
  use reporter <- result.try(
    diagnostics.start(
      maximum_in_flight: 128,
      sink_timeout_milliseconds: 1000,
      sink: fn(record) {
        process.send(observed, record)
        Ok(Nil)
      },
    )
    |> result.replace_error(Nil),
  )
  use listener <- result.try(
    transport.listen(<<127, 0, 0, 1>>, 0, 8, 3000)
    |> result.replace_error(Nil),
  )
  use endpoint <- result.try(
    transport.local_endpoint(listener) |> result.replace_error(Nil),
  )
  let #(_, port) = endpoint
  let first_serving =
    http_test_support.start_task(fn() {
      // Subjects are bound to their creator's mailbox.
      // Publish this worker-owned gate to the parent, which only sends the release.
      let permit_pooled_request = process.new_subject()
      process.send(pooled_request_gate, permit_pooled_request)
      use first <- result.try(
        transport.accept(listener, 3000) |> result.replace_error(Nil),
      )
      use first_read <- result.try(
        transport.read(first, 4096, 3000) |> result.replace_error(Nil),
      )
      use first <- result.try(case first_read {
        transport.ReadData(_, first) -> Ok(first)
        _ -> Error(Nil)
      })
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n":utf8,
        >>)
        |> result.replace_error(Nil),
      )
      // The client signals only after the zero-length response has returned this socket to its pool.
      // Reading the next request proves that checkout,
      // ownership transfer, and wire transmission happened before peer close.
      use _ <- result.try(process.receive(permit_pooled_request, within: 3000))
      use pooled_read <- result.try(
        transport.read(first, 4096, 3000) |> result.replace_error(Nil),
      )
      use first <- result.try(case pooled_read {
        transport.ReadData(_, first) -> Ok(first)
        _ -> Error(Nil)
      })
      use _ <- result.try(transport.close(first) |> result.replace_error(Nil))
      Ok(Nil)
    })
  let defaults =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_diagnostics(reporter)
  use config <- result.try(
    client.with_timeouts(
      defaults,
      client.Timeouts(
        dns_milliseconds: 1000,
        connect_milliseconds: 1000,
        tls_milliseconds: 1000,
        operation_milliseconds: 3000,
        idle_milliseconds: 3000,
        total_milliseconds: 5000,
      ),
    )
    |> result.replace_error(Nil),
  )
  let config = case retry_enabled {
    True -> config
    False -> client.without_retries(config)
  }
  use running <- result.try(
    client.start(config)
    |> result.replace_error(Nil),
  )
  let first_request =
    request.new()
    |> request.set_scheme(gleam_http.Http)
    |> request.set_host("127.0.0.1")
    |> request.set_port(port)
    |> request.set_path("/first")
    |> request.set_body(<<>>)
  let second_request =
    request.new()
    |> request.set_scheme(gleam_http.Http)
    |> request.set_host("127.0.0.1")
    |> request.set_port(port)
    |> request.set_path("/second")
    |> request.set_body(<<>>)

  use first <- result.try(
    client.fetch(running, first_request) |> result.replace_error(Nil),
  )
  use first_body <- result.try(
    body.read_all(first.body, 0) |> result.replace_error(Nil),
  )
  assert first_body == #(<<>>, [])
  let second_serving =
    http_test_support.start_task(fn() {
      result.map(transport.accept(listener, 3000), fn(second) {
        {
          use second_read <- result.try(
            transport.read(second, 4096, 3000)
            |> result.replace_error(Nil),
          )
          use second <- result.try(case second_read {
            transport.ReadData(_, second) -> Ok(second)
            _ -> Error(Nil)
          })
          use _ <- result.try(
            transport.send(second, <<
              "HTTP/1.1 200 OK\r\n":utf8,
              "Content-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
            >>)
            |> result.replace_error(Nil),
          )
          use _ <- result.try(
            transport.close(second) |> result.replace_error(Nil),
          )
          Ok(True)
        }
      })
      |> result.unwrap(Ok(False))
    })
  use permit_pooled_request <- result.try(process.receive(
    pooled_request_gate,
    within: 3000,
  ))
  process.send(permit_pooled_request, Nil)
  let #(second_succeeded, second_body_matches) = case
    client.fetch(running, second_request) |> result.replace_error(Nil)
  {
    Error(Nil) -> #(False, False)
    Ok(second) ->
      result.map(body.read_all(second.body, 2), fn(successful_value) {
        let #(bytes, trailers) = successful_value
        #(True, bytes == <<"ok":utf8>> && trailers == [])
      })
      |> result.unwrap(#(True, False))
  }
  use _ <- result.try(http_test_support.await_task(first_serving))
  // Closing the listener wakes the pending accept immediately, so proving the absence of a reconnect needs no sleep or relative scheduling assumption.
  use _ <- result.try(transport.stop(listener) |> result.replace_error(Nil))
  use second_connection <- result.try(http_test_support.await_task(
    second_serving,
  ))
  assert !second_succeeded
  assert !second_body_matches
  assert !second_connection
  use _ <- result.try(client.close(running) |> result.replace_error(Nil))
  use _ <- result.try(diagnostics.stop(reporter) |> result.replace_error(Nil))
  let stages =
    collect(observed, [])
    |> list.filter_map(fn(record) {
      case record.event {
        diagnostics.ClientObserved(request_id, _, stage) ->
          Ok(#(request_id, record.sequence, stage))
        _ -> Error(Nil)
      }
    })
  let exchange_starts =
    stages
    |> list.filter_map(fn(entry) {
      case entry.2 {
        diagnostics.ExchangeStarted -> Ok(#(entry.1, entry.0))
        _ -> Error(Nil)
      }
    })
    |> list.sort(fn(first, second) { int.compare(first.0, second.0) })
  let assert [#(_, _), #(_, second_request_id)] = exchange_starts
  let second_request_stages =
    stages
    |> list.filter(fn(entry) { entry.0 == second_request_id })
    |> list.sort(fn(first, second) { int.compare(first.1, second.1) })
  case retry_enabled {
    True -> assert_enabled_stale_pool_retry(second_request_stages)
    False -> assert_disabled_stale_pool_retry(second_request_stages)
  }
  Ok(Nil)
}

fn assert_enabled_stale_pool_retry(
  stages: List(#(diagnostics.RequestId, Int, diagnostics.ClientStage)),
) -> Nil {
  // Enabling retries does not weaken the request-processing safety proof.
  // The original failed attempt remains the sole diagnostic outcome.
  assert_disabled_stale_pool_retry(stages)
}

fn assert_disabled_stale_pool_retry(
  stages: List(#(diagnostics.RequestId, Int, diagnostics.ClientStage)),
) -> Nil {
  let starts =
    list.filter_map(stages, fn(entry) {
      case entry.2 {
        diagnostics.AttemptStarted(attempt) -> Ok(#(entry.1, attempt))
        _ -> Error(Nil)
      }
    })
  let assert [#(started, attempt)] = starts
  let finished =
    list.filter_map(stages, fn(entry) {
      case entry.2 {
        diagnostics.AttemptFinished(
          finished_attempt,
          Some(context.Http1),
          outcome,
        ) -> Ok(#(entry.1, finished_attempt, outcome))
        _ -> Error(Nil)
      }
    })
  let assert [#(finished_at, finished_attempt, attempt_outcome)] = finished
  assert finished_attempt == attempt
  assert result.is_error(attempt_outcome)
  let releases =
    list.filter_map(stages, fn(entry) {
      case entry.2 {
        diagnostics.AttemptReleased(
          released_attempt,
          Some(context.Http1),
          cleanup,
        ) -> Ok(#(entry.1, released_attempt, cleanup))
        _ -> Error(Nil)
      }
    })
  let assert [#(released_at, released_attempt, cleanup)] = releases
  assert released_attempt == attempt
  assert cleanup == Ok(Nil)
  assert started < finished_at
  assert finished_at < released_at
  assert list.count(stages, fn(entry) {
      case entry.2 {
        diagnostics.PhaseStarted(
          selected_attempt,
          diagnostics.ProtocolSelection(context.Http1),
        ) -> selected_attempt == attempt
        _ -> False
      }
    })
    == 1
  assert !list.any(stages, fn(entry) {
    case entry.2 {
      diagnostics.ConnectTraceFinished(_, diagnostics.Tcp, _, _) -> True
      _ -> False
    }
  })
  let exchange_failures =
    list.filter_map(stages, fn(entry) {
      case entry.2 {
        diagnostics.ExchangeFinished(Error(failure)) ->
          Ok(#(entry.1, error.kind(failure)))
        _ -> Error(Nil)
      }
    })
  let assert [#(failed_at, error.Protocol(error.Http1))] = exchange_failures
  assert failed_at > released_at
  assert !list.any(stages, fn(entry) {
    entry.2 == diagnostics.ExchangeFinished(Ok(Nil))
  })
}

fn collect(
  observed: process.Subject(diagnostics.Observation),
  reversed: List(diagnostics.Observation),
) -> List(diagnostics.Observation) {
  case process.receive(observed, within: 0) {
    Ok(record) -> collect(observed, [record, ..reversed])
    Error(Nil) -> list.reverse(reversed)
  }
}

fn sequenced_client_stages(
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

fn matching_stages(
  stages: List(#(Int, diagnostics.ClientStage)),
  matches: fn(diagnostics.ClientStage) -> Bool,
) -> List(#(Int, diagnostics.ClientStage)) {
  list.filter(stages, fn(entry) { matches(entry.1) })
}

pub fn http2_client_trace_records_wire_completion_before_release_test() -> Nil {
  http2_transfer(False)
}

pub fn http2_failed_trailers_never_publish_successful_attempt_test() -> Nil {
  http2_transfer(True)
}

pub fn completed_http3_upload_disposes_source_before_attempt_release_test() -> Nil {
  http3_transfer(False)
}

pub fn http3_cleanup_timeout_remains_separate_from_successful_wire_result_test() -> Nil {
  http3_transfer(True)
}

pub fn http3_close_without_response_consumption_reports_cancellation_and_release_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = h3_server.new(certificate, private_key)
  let assert Ok(listener) = h3_server.start(configuration)
  let assert Ok(port) = h3_server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = h3_server.accept(listener)
      h3_server.send_response(incoming, 200, [])
    })
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_diagnostics(reporter)
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let closed = client.close(running)
  let _stopped = h3_server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  let stopped = diagnostics.stop(reporter)
  let records = collect(observed, [])
  assert result.is_ok(received)
  assert closed == Ok(Nil)
  assert serving_done == Ok(Nil)
  assert stopped == Ok(Nil)
  let outcomes =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptFinished(_, Some(context.Http3), outcome),
        ) -> Ok(result.map_error(outcome, error.kind))
        _ -> Error(Nil)
      }
    })
  assert outcomes == [Error(error.Cancelled)]
  assert list.count(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptReleased(_, Some(context.Http3), _),
        ) -> True
        _ -> False
      }
    })
    == 1
  assert !list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(_, _, diagnostics.ResponseReadFinished(..))
      | diagnostics.ClientObserved(_, _, diagnostics.ExchangeFinished(Ok(Nil))) ->
        True
      _ -> False
    }
  })
}

pub fn early_http3_response_records_one_cancelled_upload_terminal_before_release_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(128, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = h3_server.new(certificate, private_key)
  let assert Ok(listener) = h3_server.start(configuration)
  let assert Ok(port) = h3_server.port(listener)
  let server_ready = process.new_subject()
  let serving =
    http_test_support.start_task(fn() {
      let upload_started = process.new_subject()
      process.send(server_ready, upload_started)
      let assert Ok(incoming) = h3_server.accept(listener)
      let upload_observation = process.receive(upload_started, within: 5000)
      #(
        upload_observation,
        h3_server.send_response(incoming, 413, []),
        h3_server.send_chunk(incoming, <<0, 1, 2>>),
        h3_server.send_trailers(incoming, [#("x-result", "early")]),
      )
    })
  let assert Ok(upload_started) = process.receive(server_ready, within: 1000)
  let source_cancelled = process.new_subject()
  let assert Ok(source) =
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
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_diagnostics(reporter)
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_method(gleam_http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
    )
  let outcome =
    received
    |> result.try(fn(exchange) {
      let incoming = client.response(exchange)
      use contents <- result.try(body.read_all(incoming.body, 8))
      Ok(#(
        incoming.status,
        bit_array.byte_size(contents.0),
        list.length(contents.1),
      ))
    })
    |> result.map_error(error.kind)
  let cancellation = process.receive(source_cancelled, within: 2000)
  let duplicate_cancellation = process.receive(source_cancelled, within: 0)
  let closed = client.close(running)
  let serving_done = http_test_support.await_task(serving)
  let _listener_stopped = h3_server.stop(listener)
  let stopped = diagnostics.stop(reporter)
  let stages = sequenced_client_stages(collect(observed, []))
  let transmission_starts =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(
          _,
          diagnostics.RequestTransmission(context.Http3),
        ) -> True
        _ -> False
      }
    })
  let transmission_finishes =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseFinished(
          _,
          diagnostics.RequestTransmission(context.Http3),
          _,
        ) -> True
        _ -> False
      }
    })
  let response_finishes =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseFinished(
          _,
          diagnostics.ResponseReception(context.Http3),
          _,
        ) -> True
        _ -> False
      }
    })
  let releases =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.AttemptReleased(_, Some(context.Http3), _) -> True
        _ -> False
      }
    })
  let assert [#(transmission_started, diagnostics.PhaseStarted(attempt, _))] =
    transmission_starts
  let assert [
    #(
      transmission_finished,
      diagnostics.PhaseFinished(
        finished_attempt,
        _,
        Error(transmission_failure),
      ),
    ),
  ] = transmission_finishes
  let assert [
    #(
      response_finished,
      diagnostics.PhaseFinished(response_attempt, _, Ok(Nil)),
    ),
  ] = response_finishes
  let assert [#(released, diagnostics.AttemptReleased(release_attempt, _, _))] =
    releases
  assert outcome == Ok(#(413, 3, 1))
  assert cancellation == Ok(Nil)
  assert duplicate_cancellation == Error(Nil)
  assert closed == Ok(Nil)
  assert serving_done == #(Ok(Nil), Ok(Nil), Ok(Nil), Ok(Nil))
  assert stopped == Ok(Nil)
  assert attempt == finished_attempt
  assert attempt == response_attempt
  assert attempt == release_attempt
  assert error.kind(transmission_failure) == error.Cancelled
  assert transmission_started < transmission_finished
  assert transmission_finished < response_finished
  assert response_finished < released
}

fn http3_transfer(stalled_cleanup: Bool) -> Nil {
  let observed = process.new_subject()
  let cleaned = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = h3_server.new(certificate, private_key)
  let assert Ok(listener) = h3_server.start(configuration)
  let assert Ok(port) = h3_server.port(listener)
  let serving =
    http_test_support.start_task(fn() {
      let assert Ok(incoming) = h3_server.accept(listener)
      assert h3_server.read_body(incoming) == Ok(<<>>)
      h3_server.respond(incoming, 200, [], <<"ok":utf8>>)
    })
  let assert Ok(source) =
    body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
      process.send(cleaned, Nil)
      case stalled_cleanup {
        True -> process.sleep(10_000)
        False -> Nil
      }
    })
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_record_resolver(fn(_, origin_port, _) {
      Ok([client.HttpsRecord(["h3"], origin_port, True, 60_000)])
    })
    |> client.with_diagnostics(reporter)
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_method(gleam_http.Put)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
    )
  let outcome =
    received
    |> result.try(fn(exchange) {
      body.read_all(client.response(exchange).body, 2)
    })
  let cleanup = process.receive(cleaned, within: 100)
  let closed = client.close(running)
  let _stopped = h3_server.stop(listener)
  let serving_done = http_test_support.await_task(serving)
  let stopped = diagnostics.stop(reporter)
  let records = collect(observed, [])
  assert outcome == Ok(#(<<"ok":utf8>>, []))
  assert closed == Ok(Nil)
  assert serving_done == Ok(Nil)
  assert stopped == Ok(Nil)
  assert cleanup == Ok(Nil)
  assert process.receive(cleaned, within: 0) == Error(Nil)
  let finished =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptFinished(_, Some(context.Http3), outcome),
        ) -> Ok(#(record.sequence, outcome))
        _ -> Error(Nil)
      }
    })
  let released =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.AttemptReleased(_, Some(context.Http3), outcome),
        ) -> Ok(#(record.sequence, outcome))
        _ -> Error(Nil)
      }
    })
  let logical =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(_, _, diagnostics.ExchangeFinished(outcome)) ->
          Ok(result.map_error(outcome, error.kind))
        _ -> Error(Nil)
      }
    })
  let assert [#(finished_sequence, Ok(Nil))] = finished
  let assert [#(released_sequence, cleanup_outcome)] = released
  let expected_cleanup = case stalled_cleanup {
    True -> Error(error.Timeout(error.Operation))
    False -> Ok(Nil)
  }
  assert result.map_error(cleanup_outcome, error.kind) == expected_cleanup
  assert logical == [expected_cleanup]
  assert released_sequence > finished_sequence
  assert_successful_phase(records, diagnostics.ProtocolSelection(context.Http3))
  assert_successful_phase(records, diagnostics.ResourceAdmission)
  assert_successful_phase(
    records,
    diagnostics.RequestTransmission(context.Http3),
  )
  assert_successful_phase(records, diagnostics.ResponseReception(context.Http3))
  assert_phase_outcome(
    records: records,
    expected: diagnostics.ResourceRelease,
    failed: stalled_cleanup,
  )
  assert list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(
        _,
        _,
        diagnostics.ConnectObserved(
          _,
          diagnostics.Quic,
          _,
          _,
          _,
          diagnostics.TlsHandshake(diagnostics.Quic),
          diagnostics.ConnectSucceeded,
          _,
        ),
      ) -> True
      _ -> False
    }
  })
}

pub fn native_phase_snapshots_preserve_original_time_and_partial_publication_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(32, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let trace = client_trace.start(Some(reporter)) |> client_trace.attempt
  client_trace.http3_snapshot(
    trace,
    h3_client.ConnectSnapshot(False, 7, [
      h3_client.ConnectEvent(
        2,
        3,
        0,
        h3_client.NameResolution,
        h3_client.Skipped,
        1234,
      ),
      h3_client.ConnectEvent(
        3,
        3,
        9,
        h3_client.TlsHandshake,
        h3_client.Started,
        1235,
      ),
    ]),
  )
  client_trace.tcp_snapshot(
    trace,
    transport.DiagnosticSnapshot(True, 0, [
      transport.DiagnosticEvent(
        transport.DialStarted,
        transport.Ipv6,
        4,
        51,
        transport.Pending,
      ),
      transport.DiagnosticEvent(
        transport.DialCompleted,
        transport.Ipv6,
        4,
        99,
        transport.Failed(transport.ConnectFailure),
      ),
    ]),
  )
  assert diagnostics.stop(reporter) == Ok(Nil)
  let records = collect(observed, [])
  let native_records =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.ConnectObserved(
            _,
            transport,
            sequence,
            attempt,
            candidate,
            phase,
            progress,
            elapsed,
          ),
        ) ->
          Ok(#(
            transport,
            sequence,
            attempt,
            candidate,
            phase,
            progress,
            elapsed,
          ))
        _ -> Error(Nil)
      }
    })
  assert list.sort(native_records, fn(a, b) { int.compare(a.6, b.6) })
    == [
      #(
        diagnostics.Tcp,
        1,
        1,
        4,
        diagnostics.ConnectionAttempt(diagnostics.Tcp),
        diagnostics.ConnectStarted,
        51,
      ),
      #(
        diagnostics.Tcp,
        2,
        1,
        4,
        diagnostics.ConnectionAttempt(diagnostics.Tcp),
        diagnostics.ConnectFailed,
        99,
      ),
      #(
        diagnostics.Quic,
        2,
        3,
        0,
        diagnostics.NameResolution(diagnostics.Quic),
        diagnostics.ConnectSkipped,
        1234,
      ),
      #(
        diagnostics.Quic,
        3,
        3,
        9,
        diagnostics.TlsHandshake(diagnostics.Quic),
        diagnostics.ConnectStarted,
        1235,
      ),
    ]
  assert list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(
        _,
        _,
        diagnostics.ConnectTraceFinished(_, diagnostics.Quic, False, 7),
      ) -> True
      _ -> False
    }
  })
}

fn http2_transfer(invalid_trailers: Bool) -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let assert Ok(executor) =
    server.start(server.defaults(), fn(_, _) {
      let trailers = case invalid_trailers {
        True -> [#("bad\nname", "rejected")]
        False -> [#("x-finished", "yes")]
      }
      let assert Ok(source) =
        body.from_pull(
          body.pull(fn(_) {
            Ok(body.PullData(
              <<"ok":utf8>>,
              body.pull(fn(_) { Ok(body.PullEnd(trailers)) }),
            ))
          }),
          None,
          None,
          fn() { Nil },
        )
      Ok(response.new(200) |> response.set_body(source))
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    // This fixture explicitly isolates one attempt.
    // A reset coalesced with final headers is possibly processed and remains terminal under the ordinary retry policy as well.
    |> client.without_retries
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_diagnostics(reporter)
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let outcome =
    received
    |> result.try(fn(exchange) {
      body.read_all(client.response(exchange).body, 16)
    })
  let closed = client.close(running)
  let _listener_stopped = server.stop_listener(listener)
  let _executor_stopped = server.stop(executor)
  let stopped = diagnostics.stop(reporter)
  let records = collect(observed, [])
  assert_tcp_connect_trace(
    records: records,
    phase: diagnostics.TlsHandshake(diagnostics.Tcp),
    progress: diagnostics.ConnectSucceeded,
  )
  assert_successful_phase(records, diagnostics.ProtocolSelection(context.Http2))
  assert_successful_phase(records, diagnostics.ResourceAdmission)
  assert_successful_phase(
    records,
    diagnostics.RequestTransmission(context.Http2),
  )
  assert_phase_outcome(
    records: records,
    expected: diagnostics.ResponseReception(context.Http2),
    failed: invalid_trailers,
  )
  assert_successful_phase(records, diagnostics.ResourceRelease)
  assert closed == Ok(Nil)
  assert stopped == Ok(Nil)
  case invalid_trailers {
    True -> {
      assert result.is_error(outcome)
    }
    False -> {
      assert outcome == Ok(#(<<"ok":utf8>>, [#("x-finished", "yes")]))
    }
  }
  let completions =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          id,
          _,
          diagnostics.AttemptFinished(attempt, Some(context.Http2), result),
        ) -> Ok(#(id, attempt, record.sequence, result))
        _ -> Error(Nil)
      }
    })
  let assert [#(id, attempt, finished_sequence, completed)] = completions
  assert result.is_error(completed) == invalid_trailers
  let releases =
    list.filter_map(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          release_id,
          _,
          diagnostics.AttemptReleased(
            release_attempt,
            Some(context.Http2),
            cleanup,
          ),
        ) -> Ok(#(release_id, release_attempt, record.sequence, cleanup))
        _ -> Error(Nil)
      }
    })
  let assert [#(release_id, release_attempt, released_sequence, _)] = releases
  assert release_id == id
  assert release_attempt == attempt
  assert released_sequence > finished_sequence
  assert !list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(_, _, diagnostics.ExchangeFinished(Ok(Nil))) ->
        invalid_trailers
      _ -> False
    }
  })
}

fn assert_successful_phase(
  records: List(diagnostics.Observation),
  expected: diagnostics.ClientPhase,
) -> Nil {
  assert_phase_outcome(records: records, expected: expected, failed: False)
}

fn assert_phase_outcome(
  records records: List(diagnostics.Observation),
  expected expected: diagnostics.ClientPhase,
  failed failed: Bool,
) -> Nil {
  let stages = sequenced_client_stages(records)
  let starts =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseStarted(_, phase) -> phase == expected
        _ -> False
      }
    })
  let finishes =
    matching_stages(stages, fn(stage) {
      case stage {
        diagnostics.PhaseFinished(_, phase, _) -> phase == expected
        _ -> False
      }
    })
  let assert [#(started, diagnostics.PhaseStarted(attempt, _))] = starts
  let assert [
    #(finished, diagnostics.PhaseFinished(finished_attempt, _, outcome)),
  ] = finishes
  assert attempt == finished_attempt
  assert started < finished
  case result.is_error(outcome) == failed {
    True -> Nil
    False -> should.be_ok(Error(phase_outcome_mismatch(expected, failed)))
  }
}

fn phase_outcome_mismatch(
  phase: diagnostics.ClientPhase,
  expected_failure: Bool,
) -> String {
  let expectation = case expected_failure {
    True -> "failure"
    False -> "success"
  }
  let name = case phase {
    diagnostics.NameResolution(diagnostics.Tcp) -> "tcp_name_resolution"
    diagnostics.NameResolution(diagnostics.Quic) -> "quic_name_resolution"
    diagnostics.ConnectionAttempt(diagnostics.Tcp) -> "tcp_connection_attempt"
    diagnostics.ConnectionAttempt(diagnostics.Quic) -> "quic_connection_attempt"
    diagnostics.TlsHandshake(diagnostics.Tcp) -> "tcp_tls_handshake"
    diagnostics.TlsHandshake(diagnostics.Quic) -> "quic_tls_handshake"
    diagnostics.ConnectionOwnership(diagnostics.Tcp) ->
      "tcp_connection_ownership"
    diagnostics.ConnectionOwnership(diagnostics.Quic) ->
      "quic_connection_ownership"
    diagnostics.ProtocolSelection(context.Http1) -> "http1_protocol_selection"
    diagnostics.ProtocolSelection(context.Http2) -> "http2_protocol_selection"
    diagnostics.ProtocolSelection(context.Http3) -> "http3_protocol_selection"
    diagnostics.RequestTransmission(context.Http1) ->
      "http1_request_transmission"
    diagnostics.RequestTransmission(context.Http2) ->
      "http2_request_transmission"
    diagnostics.RequestTransmission(context.Http3) ->
      "http3_request_transmission"
    diagnostics.ResponseReception(context.Http1) -> "http1_response_reception"
    diagnostics.ResponseReception(context.Http2) -> "http2_response_reception"
    diagnostics.ResponseReception(context.Http3) -> "http3_response_reception"
    diagnostics.ResourceAdmission -> "resource_admission"
    diagnostics.Cancellation -> "cancellation"
    diagnostics.ResourceRelease -> "resource_release"
  }
  "expected " <> expectation <> " outcome for " <> name
}

fn assert_tcp_connect_trace(
  records records: List(diagnostics.Observation),
  phase phase: diagnostics.ClientPhase,
  progress progress: diagnostics.ClientConnectProgress,
) -> Nil {
  assert list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(
        _,
        _,
        diagnostics.ConnectObserved(
          _,
          diagnostics.Tcp,
          _,
          _,
          _,
          observed_phase,
          observed_progress,
          elapsed,
        ),
      ) ->
        observed_phase == phase && observed_progress == progress && elapsed >= 0
      _ -> False
    }
  })
  assert list.count(records, fn(record) {
      case record.event {
        diagnostics.ClientObserved(
          _,
          _,
          diagnostics.ConnectTraceFinished(_, diagnostics.Tcp, True, 0),
        ) -> True
        _ -> False
      }
    })
    == 1
}

pub fn rejected_tls_certificate_has_a_native_failed_handshake_trace_test() -> Nil {
  let observed = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(64, 1000, fn(record) {
      process.send(observed, record)
      Ok(Nil)
    })
  let assert Ok(executor) =
    server.start(server.defaults(), fn(_, _) {
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.without_retries
    |> client.with_diagnostics(reporter)
    |> client.start
  let received =
    client.exchange(
      running,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(body.empty()),
    )
  let closed = client.close(running)
  let _listener_stopped = server.stop_listener(listener)
  let _executor_stopped = server.stop(executor)
  let stopped = diagnostics.stop(reporter)
  let records = collect(observed, [])
  assert result.map_error(received, error.kind) == Error(error.Tls)
  assert closed == Ok(Nil)
  assert stopped == Ok(Nil)
  assert_tcp_connect_trace(
    records: records,
    phase: diagnostics.TlsHandshake(diagnostics.Tcp),
    progress: diagnostics.ConnectFailed,
  )
  assert !list.any(records, fn(record) {
    case record.event {
      diagnostics.ClientObserved(_, _, diagnostics.ResponseHeaders(..)) -> True
      _ -> False
    }
  })
}
