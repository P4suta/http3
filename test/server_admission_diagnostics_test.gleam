import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None}
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/context
import http/diagnostics
import http/error
import http/resource
import http/server
import http_test_support

@external(erlang, "http_server_admission_test_ffi", "suspend_executor")
fn suspend_executor(server: server.Server) -> Nil

@external(erlang, "http_server_admission_test_ffi", "resume_executor")
fn resume_executor(server: server.Server) -> Nil

@external(erlang, "http_server_admission_test_ffi", "await_dispatch")
fn await_dispatch(server: server.Server) -> Bool

@external(erlang, "http_server_admission_test_ffi", "begin_drain")
fn begin_drain(server: server.Server) -> Nil

@external(erlang, "http_server_admission_test_ffi", "resource_usage")
fn resource_usage(server: server.Server) -> #(Int, Int)

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn pre_cancelled_requests_have_one_common_trace_on_every_protocol_test() -> Nil {
  assert_pre_cancelled([context.Http1, context.Http2, context.Http3])
}

pub fn worker_and_memory_refusal_have_one_common_trace_on_every_protocol_test() -> Nil {
  assert_resource_refusal(
    protocols: [context.Http1, context.Http2, context.Http3],
    maximum_workers: 1,
    memory_bytes: 4096,
    expected: error.RequestWorkers,
  )
  assert_resource_refusal(
    protocols: [context.Http1, context.Http2, context.Http3],
    maximum_workers: 2,
    memory_bytes: 64,
    expected: error.Memory,
  )
}

pub fn acquire_then_cancel_has_one_common_trace_on_every_protocol_test() -> Nil {
  assert_acquire_race(
    [context.Http1, context.Http2, context.Http3],
    CancelBeforeAdoption,
  )
}

pub fn acquire_then_drain_fails_and_releases_once_before_handler_admission_test() -> Nil {
  assert_acquire_race([context.Http2], DrainBeforeAdoption)
}

pub fn caller_timeout_wins_delayed_adoption_without_duplicate_release_test() -> Nil {
  let events = process.new_subject()
  let cleaned = process.new_subject()
  let handler_calls = process.new_subject()
  let adoption_entered = process.new_subject()
  let reporter = request_reporter(events) |> should.be_ok
  let configuration =
    server.with_diagnostics(server.defaults(), reporter)
    |> server.with_worker_adoption_probe(fn() {
      let release = process.new_subject()
      process.send(adoption_entered, release)
      let _released = process.receive(release, within: 5000)
      Nil
    })
  let running =
    server.start(configuration, fn(_, _) {
      process.send(handler_calls, Nil)
      Ok(response.new(204) |> response.set_body(body.empty()))
    })
    |> should.be_ok
  let metadata = request_context(context.Http3)
  let call =
    http_test_support.start_task(fn() {
      server.handle(
        running,
        request.new() |> request.set_body(tracked_body(cleaned)),
        metadata,
      )
      |> result.map_error(error.kind)
    })
  let release_adoption =
    process.receive(adoption_entered, within: 1000) |> should.be_ok
  context.cancel(metadata)
  let outcome = http_test_support.await_task(call)
  let trace =
    receive_events(delivered: events, remaining: 3, reversed: []) |> ordered()
  let cleanup = process.receive(cleaned, within: 1000)
  let released_before_adoption = resource_usage(running)
  process.send(release_adoption, Nil)
  let stopped = server.stop(running)
  let released_after_adoption = resource_usage(running)
  let reporter_stopped = diagnostics.stop(reporter)

  assert outcome == Error(error.Cancelled)
  assert_failed_trace(
    trace: trace,
    protocol: context.Http3,
    expected: error.Cancelled,
  )
  assert cleanup == Ok(Nil)
  assert released_before_adoption == #(0, 0)
  assert released_after_adoption == #(0, 0)
  assert process.receive(cleaned, within: 0) == Error(Nil)
  assert process.receive(handler_calls, within: 0) == Error(Nil)
  assert process.receive(events, within: 0) == Error(Nil)
  assert stopped == Ok(Nil)
  assert reporter_stopped == Ok(Nil)
}

type AcquireRace {
  CancelBeforeAdoption
  DrainBeforeAdoption
}

fn assert_resource_refusal(
  protocols protocols: List(context.Protocol),
  maximum_workers maximum_workers: Int,
  memory_bytes memory_bytes: Int,
  expected expected: error.ResourceKind,
) -> Nil {
  case protocols {
    [] -> Nil
    [protocol, ..rest] -> {
      let events = process.new_subject()
      let cleaned = process.new_subject()
      let handler_calls = process.new_subject()
      let reporter = request_reporter(events) |> should.be_ok
      let limits =
        resource.limits(maximum_workers, memory_bytes) |> should.be_ok
      let configuration =
        server.with_resource_limits(
          server.with_diagnostics(server.defaults(), reporter),
          limits,
          worker_memory_bytes: 64,
        )
        |> should.be_ok
      let running =
        server.start(configuration, fn(_, _) {
          process.send(handler_calls, Nil)
          Ok(response.new(200) |> response.set_body(body.from_text("held")))
        })
        |> should.be_ok
      let first =
        server.handle(
          running,
          request.new() |> request.set_body(body.empty()),
          request_context(protocol),
        )
        |> should.be_ok
      let first_trace =
        receive_events(delivered: events, remaining: 1, reversed: [])
      let first_handler = process.receive(handler_calls, within: 1000)
      let refused =
        server.handle(
          running,
          request.new() |> request.set_body(tracked_body(cleaned)),
          request_context(protocol),
        )
        |> result.map_error(error.kind)
      let refused_trace =
        receive_events(delivered: events, remaining: 3, reversed: [])
        |> ordered()
      let cleanup = process.receive(cleaned, within: 1000)
      let held = resource_usage(running)
      body.cancel(first.body)
      let stopped = server.stop(running)
      let released = resource_usage(running)
      let reporter_stopped = diagnostics.stop(reporter)

      assert refused == Error(error.Resource(expected))
      assert_started_trace(first_trace, protocol)
      assert_refused_trace(
        trace: refused_trace,
        protocol: protocol,
        expected: expected,
      )
      assert first_handler == Ok(Nil)
      assert process.receive(handler_calls, within: 0) == Error(Nil)
      assert cleanup == Ok(Nil)
      assert process.receive(cleaned, within: 0) == Error(Nil)
      assert held == #(1, 64)
      assert stopped == Ok(Nil)
      assert released == #(0, 0)
      assert reporter_stopped == Ok(Nil)
      assert_resource_refusal(
        protocols: rest,
        maximum_workers:,
        memory_bytes:,
        expected:,
      )
    }
  }
}

fn assert_pre_cancelled(protocols: List(context.Protocol)) -> Nil {
  case protocols {
    [] -> Nil
    [protocol, ..rest] -> {
      let events = process.new_subject()
      let cleaned = process.new_subject()
      let handler_calls = process.new_subject()
      let reporter = request_reporter(events) |> should.be_ok
      let running =
        server.start(
          server.with_diagnostics(server.defaults(), reporter),
          fn(_, _) {
            process.send(handler_calls, Nil)
            Ok(response.new(204) |> response.set_body(body.empty()))
          },
        )
        |> should.be_ok
      let metadata = request_context(protocol)
      context.cancel(metadata)
      let outcome =
        server.handle(
          running,
          request.new() |> request.set_body(tracked_body(cleaned)),
          metadata,
        )
        |> result.map_error(error.kind)
      let trace =
        receive_events(delivered: events, remaining: 3, reversed: [])
        |> ordered()
      let cleanup = process.receive(cleaned, within: 1000)
      let usage = resource_usage(running)
      let stopped = server.stop(running)
      let reporter_stopped = diagnostics.stop(reporter)

      assert outcome == Error(error.Cancelled)
      assert_failed_trace(
        trace: trace,
        protocol: protocol,
        expected: error.Cancelled,
      )
      assert cleanup == Ok(Nil)
      assert process.receive(cleaned, within: 0) == Error(Nil)
      assert process.receive(handler_calls, within: 0) == Error(Nil)
      assert usage == #(0, 0)
      assert stopped == Ok(Nil)
      assert reporter_stopped == Ok(Nil)
      assert_pre_cancelled(rest)
    }
  }
}

fn assert_acquire_race(
  protocols: List(context.Protocol),
  race: AcquireRace,
) -> Nil {
  case protocols {
    [] -> Nil
    [protocol, ..rest] -> {
      let events = process.new_subject()
      let cleaned = process.new_subject()
      let handler_calls = process.new_subject()
      let reporter = request_reporter(events) |> should.be_ok
      let limits = resource.limits(1, 4096) |> should.be_ok
      let configuration =
        server.with_resource_limits(
          server.with_diagnostics(server.defaults(), reporter),
          limits,
          worker_memory_bytes: 64,
        )
        |> should.be_ok
      let running =
        server.start(configuration, fn(_, _) {
          process.send(handler_calls, Nil)
          Ok(response.new(204) |> response.set_body(body.empty()))
        })
        |> should.be_ok
      suspend_executor(running)
      let metadata = request_context(protocol)
      let call =
        http_test_support.start_task(fn() {
          server.handle(
            running,
            request.new() |> request.set_body(tracked_body(cleaned)),
            metadata,
          )
          |> result.map_error(error.kind)
        })
      let queued = await_dispatch(running)
      let held = resource_usage(running)
      let expected = case race {
        CancelBeforeAdoption -> {
          context.cancel(metadata)
          error.Cancelled
        }
        DrainBeforeAdoption -> {
          begin_drain(running)
          error.Service
        }
      }
      resume_executor(running)
      let outcome = http_test_support.await_task(call)
      let trace =
        receive_events(delivered: events, remaining: 3, reversed: [])
        |> ordered()
      let cleanup = process.receive(cleaned, within: 1000)
      let released = resource_usage(running)
      let stopped = server.stop(running)
      let reporter_stopped = diagnostics.stop(reporter)

      assert queued
      assert held == #(1, 64)
      assert outcome == Error(expected)
      assert_failed_trace(trace: trace, protocol: protocol, expected: expected)
      assert cleanup == Ok(Nil)
      assert process.receive(cleaned, within: 0) == Error(Nil)
      assert process.receive(handler_calls, within: 0) == Error(Nil)
      assert released == #(0, 0)
      assert stopped == Ok(Nil)
      assert reporter_stopped == Ok(Nil)
      assert_acquire_race(rest, race)
    }
  }
}

fn request_reporter(
  delivered: process.Subject(diagnostics.Observation),
) -> Result(diagnostics.Reporter, error.Error) {
  diagnostics.start(
    maximum_in_flight: 16,
    sink_timeout_milliseconds: 1000,
    sink: fn(observation) {
      case observation.event {
        diagnostics.RequestStarted(..)
        | diagnostics.RequestFailed(..)
        | diagnostics.RequestRefused(..)
        | diagnostics.RequestReleased(..) ->
          process.send(delivered, observation)
        _ -> Nil
      }
      Ok(Nil)
    },
  )
}

fn tracked_body(cleaned: process.Subject(Nil)) -> body.Body {
  body.from_pull(body.pull(fn(_) { Ok(body.PullEnd([])) }), None, None, fn() {
    process.send(cleaned, Nil)
  })
  |> should.be_ok
}

fn request_context(protocol: context.Protocol) -> context.Context {
  let identity = case protocol {
    context.Http1 -> context.CleartextIdentity
    context.Http2 | context.Http3 -> context.TlsIdentity("localhost", None)
  }
  context.new(
    protocol,
    context.Endpoint("127.0.0.1", 50_000),
    context.Endpoint("127.0.0.1", 443),
    within_milliseconds: 5000,
    tls_identity: identity,
    early_data: context.EarlyDataDisabled,
  )
  |> should.be_ok
}

fn receive_events(
  delivered delivered: process.Subject(diagnostics.Observation),
  remaining remaining: Int,
  reversed reversed: List(diagnostics.Observation),
) -> List(diagnostics.Observation) {
  case remaining {
    0 -> list.reverse(reversed)
    _ -> {
      let observation = process.receive(delivered, within: 1000) |> should.be_ok
      receive_events(delivered: delivered, remaining: remaining - 1, reversed: [
        observation,
        ..reversed
      ])
    }
  }
}

fn ordered(
  observations: List(diagnostics.Observation),
) -> List(diagnostics.Observation) {
  list.sort(observations, fn(first, second) {
    int.compare(first.sequence, second.sequence)
  })
}

fn assert_failed_trace(
  trace trace: List(diagnostics.Observation),
  protocol protocol: context.Protocol,
  expected expected: error.ErrorKind,
) -> Nil {
  let #(
    started_sequence,
    started_id,
    started_protocol,
    failed_sequence,
    failed_id,
    failed_protocol,
    failure,
    released_sequence,
    released_id,
    released_protocol,
    cleanup,
  ) =
    case trace {
      [
        diagnostics.Observation(
          sequence: started_sequence,
          event: diagnostics.RequestStarted(started_id, started_protocol),
          ..,
        ),
        diagnostics.Observation(
          sequence: failed_sequence,
          event: diagnostics.RequestFailed(
            failed_id,
            failed_protocol,
            failure,
            _,
          ),
          ..,
        ),
        diagnostics.Observation(
          sequence: released_sequence,
          event: diagnostics.RequestReleased(
            released_id,
            released_protocol,
            cleanup,
            _,
          ),
          ..,
        ),
      ] ->
        Ok(#(
          started_sequence,
          started_id,
          started_protocol,
          failed_sequence,
          failed_id,
          failed_protocol,
          failure,
          released_sequence,
          released_id,
          released_protocol,
          cleanup,
        ))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert started_sequence < failed_sequence
  assert failed_sequence < released_sequence
  assert started_id == failed_id && failed_id == released_id
  assert started_protocol == protocol
  assert failed_protocol == protocol
  assert released_protocol == protocol
  assert error.kind(failure) == expected
  assert cleanup == Ok(Nil)
}

fn assert_started_trace(
  trace: List(diagnostics.Observation),
  protocol: context.Protocol,
) -> Nil {
  let #(id, observed_protocol) =
    case trace {
      [
        diagnostics.Observation(
          event: diagnostics.RequestStarted(id, observed_protocol),
          ..,
        ),
      ] -> Ok(#(id, observed_protocol))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert diagnostics.request_id_value(id) > 0
  assert observed_protocol == protocol
}

fn assert_refused_trace(
  trace trace: List(diagnostics.Observation),
  protocol protocol: context.Protocol,
  expected expected: error.ResourceKind,
) -> Nil {
  let #(
    started_sequence,
    started_id,
    started_protocol,
    refused_sequence,
    refused_id,
    refused_protocol,
    resource,
    released_sequence,
    released_id,
    released_protocol,
    cleanup,
  ) =
    case trace {
      [
        diagnostics.Observation(
          sequence: started_sequence,
          event: diagnostics.RequestStarted(started_id, started_protocol),
          ..,
        ),
        diagnostics.Observation(
          sequence: refused_sequence,
          event: diagnostics.RequestRefused(
            refused_id,
            refused_protocol,
            resource,
          ),
          ..,
        ),
        diagnostics.Observation(
          sequence: released_sequence,
          event: diagnostics.RequestReleased(
            released_id,
            released_protocol,
            cleanup,
            _,
          ),
          ..,
        ),
      ] ->
        Ok(#(
          started_sequence,
          started_id,
          started_protocol,
          refused_sequence,
          refused_id,
          refused_protocol,
          resource,
          released_sequence,
          released_id,
          released_protocol,
          cleanup,
        ))
      unexpected -> Error(unexpected)
    }
    |> should.be_ok
  assert started_sequence < refused_sequence
  assert refused_sequence < released_sequence
  assert started_id == refused_id && refused_id == released_id
  assert started_protocol == protocol
  assert refused_protocol == protocol
  assert released_protocol == protocol
  assert resource == expected
  assert cleanup == Ok(Nil)
}
