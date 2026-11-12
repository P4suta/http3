import gleam/bool
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/body
import http/client
import http/context
import http/error
import http/internal/http1/exchange as http1_exchange
import http/internal/transport
import http/internal/upload
import http/resource
import http/server
import http_test_support

type Probe

type Termination {
  OperationDeadline
  CloseClient
  KillCaller
  SuspendCaller
}

@external(erlang, "http_upload_test_ffi", "new_probe")
fn new_probe() -> Probe

@external(erlang, "http_upload_test_ffi", "started")
fn record_started(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "cleanup")
fn record_cleanup(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "snapshot")
fn snapshot(probe: Probe) -> #(Bool, Int, Int)

@external(erlang, "http_upload_test_ffi", "stop_pull")
fn stop_pull(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "dispose")
fn dispose(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "await_cleanup")
fn await_cleanup(probe: Probe, timeout: Int) -> Bool

@external(erlang, "http_upload_test_ffi", "suspend")
fn suspend(pid: process.Pid) -> Nil

@external(erlang, "http_upload_test_ffi", "resume")
fn resume(pid: process.Pid) -> Nil

@external(erlang, "http_upload_test_ffi", "pause_upload")
fn pause_upload(probe: Probe, worker: upload.Upload) -> Bool

@external(erlang, "http_upload_test_ffi", "resume_upload")
fn resume_upload(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "released")
fn record_release(probe: Probe) -> Nil

@external(erlang, "http_upload_test_ffi", "release_snapshot")
fn release_snapshot(probe: Probe) -> #(Int, Bool)

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn http1_stalled_upload_obeys_the_operation_deadline_test() -> Nil {
  stalled_upload(
    http2: False,
    early_response: False,
    termination: OperationDeadline,
  )
}

pub fn http2_stalled_upload_obeys_the_operation_deadline_test() -> Nil {
  stalled_upload(
    http2: True,
    early_response: False,
    termination: OperationDeadline,
  )
}

pub fn http1_early_final_response_interrupts_a_stalled_upload_test() -> Nil {
  stalled_upload(
    http2: False,
    early_response: True,
    termination: OperationDeadline,
  )
}

pub fn http2_sends_headers_before_pulling_the_entire_upload_test() -> Nil {
  stalled_upload(
    http2: True,
    early_response: True,
    termination: OperationDeadline,
  )
}

pub fn http1_close_joins_a_stalled_upload_callback_test() -> Nil {
  stalled_upload(http2: False, early_response: False, termination: CloseClient)
}

pub fn http2_close_joins_a_stalled_upload_callback_test() -> Nil {
  stalled_upload(http2: True, early_response: False, termination: CloseClient)
}

pub fn http1_requester_death_disposes_its_upload_test() -> Nil {
  stalled_upload(http2: False, early_response: False, termination: KillCaller)
}

pub fn http2_requester_death_disposes_its_upload_test() -> Nil {
  stalled_upload(http2: True, early_response: False, termination: KillCaller)
}

pub fn http1_upload_deadline_runs_while_requester_is_suspended_test() -> Nil {
  stalled_upload(
    http2: False,
    early_response: False,
    termination: SuspendCaller,
  )
}

pub fn http2_upload_deadline_runs_while_requester_is_suspended_test() -> Nil {
  stalled_upload(http2: True, early_response: False, termination: SuspendCaller)
}

pub fn http1_source_owner_death_cannot_close_an_already_pooled_connection_test() -> Nil {
  let owner = process.self()
  let checked_in = process.new_subject()
  let assert Ok(limits) = resource.limits(1, 65_536)
  let resources = resource.start(limits)
  let assert Ok(executor) =
    server.start(server.defaults(), fn(_, _) {
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  let assert Ok(listener) =
    server.listen_http1(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults() |> server.allow_http1_cleartext,
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(config) =
    http1_exchange.with_body_limits(http1_exchange.defaults(), 65_536, 65_536)
  let config =
    config
    |> http1_exchange.with_supervision(resources:, lifecycle_owner: owner)
    |> http1_exchange.with_pool(fn(_) { Ok(None) }, fn(_, socket) {
      let transferred = transport.transfer_owner(socket, owner)
      process.send(checked_in, case transferred {
        Ok(Nil) -> Ok(socket)
        Error(_) -> Error(Nil)
      })
      let never = process.new_subject()
      process.receive_forever(never)
      True
    })
  let caller =
    process.spawn_unlinked(fn() {
      let _outcome =
        http1_exchange.run(
          request.new()
            |> request.set_scheme(gleam_http.Http)
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_body(body.empty()),
          config,
        )
      Nil
    })
  let handed_off = process.receive(checked_in, within: 1000)
  process.kill(caller)
  let joined = await_worker_release(resources, 500)
  let remained_usable = case handed_off {
    Ok(Ok(socket)) -> {
      let sent =
        transport.send(socket, <<
          "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n":utf8,
        >>)
        == Ok(Nil)
      let _closed = transport.close(socket)
      sent
    }
    _ -> False
  }
  let stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  assert joined
  assert remained_usable
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}

pub fn upload_eof_and_release_timeout_keep_the_grant_until_guardian_down_test() -> Nil {
  let probe = new_probe()
  let assert Ok(limits) = resource.limits(1, 4)
  let resources = resource.start(limits)
  let assert Ok(worker) =
    upload.start(
      source: body.empty(),
      maximum_chunk: 4,
      deadline: transport.monotonic_millisecond() + 5000,
      expiry: error.Operation,
      total_deadline: transport.monotonic_millisecond() + 5000,
      resources: Some(resources),
      lifecycle_owner: None,
      abandon: fn(_) { Nil },
      released: fn(_) { record_release(probe) },
    )
  upload.request_next(worker)
  let reached_eof =
    process.receive(upload.events(worker), within: 1000) == Ok(upload.End([]))
  let source_disposed = upload.finish_source(upload: worker, outcome: Ok(Nil))
  let retained = resource.snapshot(resources)
  let paused = pause_upload(probe, worker)
  let waited = upload.release(upload: worker, outcome: Ok(Nil))
  let held = resource.snapshot(resources)
  let premature = release_snapshot(probe)
  let refused =
    resource.acquire(resources, 1)
    |> result.map(fn(lease) {
      resource.release(lease)
      Nil
    })
  resume_upload(probe)
  let joined = upload.release(upload: worker, outcome: Ok(Nil))
  let released = release_snapshot(probe)
  let converged = resource.snapshot(resources)
  dispose(probe)
  assert reached_eof
  assert source_disposed == Ok(Nil)
  assert #(retained.active_workers, retained.memory_bytes) == #(1, 4)
  assert paused
  assert waited == Error(error.new(error.Timeout(error.Operation)))
  assert #(held.active_workers, held.memory_bytes) == #(1, 4)
  assert premature == #(0, False)
  assert refused == Error(error.new(error.Resource(error.RequestWorkers)))
  assert joined == Ok(Nil)
  assert released == #(1, False)
  assert #(converged.active_workers, converged.memory_bytes) == #(0, 0)
}

pub fn upload_deadline_closes_the_transport_before_waiting_for_source_cleanup_test() -> Nil {
  let started = process.new_subject()
  let cleaning = process.new_subject()
  let closed = process.new_subject()
  let assert Ok(limits) = resource.limits(1, 4)
  let resources = resource.start(limits)
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(started, Nil)
        let never = process.new_subject()
        process.receive_forever(never)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() {
        let gate = process.new_subject()
        process.send(cleaning, gate)
        let _released = process.receive(gate, within: 2000)
        Nil
      },
    )
  let assert Ok(worker) =
    upload.start(
      source:,
      maximum_chunk: 4,
      deadline: transport.monotonic_millisecond() + 100,
      expiry: error.Operation,
      total_deadline: transport.monotonic_millisecond() + 2000,
      resources: Some(resources),
      lifecycle_owner: None,
      abandon: fn(failure) { process.send(closed, error.kind(failure)) },
      released: fn(_) { Nil },
    )
  upload.request_next(worker)
  let entered = process.receive(started, within: 500) == Ok(Nil)
  let cleanup_started = process.receive(cleaning, within: 500)
  let closure = process.receive(closed, within: 50)
  let retained = resource.snapshot(resources)
  case cleanup_started {
    Ok(gate) -> process.send(gate, Nil)
    Error(Nil) -> Nil
  }
  let joined = upload.release(upload: worker, outcome: Ok(Nil))
  let converged = resource.snapshot(resources)
  assert entered
  assert closure == Ok(error.Timeout(error.Operation))
  assert retained.active_workers == 1
  assert joined == Ok(Nil)
  assert converged.active_workers == 0
}

pub fn http1_rejected_request_trailers_preserve_the_actual_transfer_error_test() -> Nil {
  rejected_request_trailers(False)
}

pub fn http2_rejected_request_trailers_preserve_the_actual_transfer_error_test() -> Nil {
  rejected_request_trailers(True)
}

fn rejected_request_trailers(http2: Bool) -> Nil {
  let read_complete = process.new_subject()
  let transfer_complete = process.new_subject()
  let assert Ok(executor) =
    server.start(server.defaults(), fn(incoming, _) {
      use _ <- result.try(body.read_all(incoming.body, 4))
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = case http2 {
    True ->
      server.listen_http2_tls(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http2_defaults(),
        certificate,
        private_key,
        "localhost",
      )
    False ->
      server.listen_http1(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http1_defaults() |> server.allow_http1_cleartext,
      )
  }
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_ca_certificates([ca_certificate])
    |> client.without_protocol_discovery
    |> client.start
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) { Ok(body.PullEnd([#("content-length", "0")])) }),
      None,
      None,
      fn() { Nil },
    )
  let source =
    body.observe_transfer(
      source,
      fn() { process.send(read_complete, Nil) },
      fn(outcome) {
        process.send(transfer_complete, result.map_error(outcome, error.kind))
      },
    )
  let outcome =
    client.exchange(
      running,
      request.new()
        |> request.set_method(gleam_http.Post)
        |> request.set_scheme(case http2 {
          True -> gleam_http.Https
          False -> gleam_http.Http
        })
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(source),
    )
    |> result.map(fn(_) { Nil })
    |> result.map_error(error.kind)
  let read = process.receive(read_complete, within: 500)
  let transferred = process.receive(transfer_complete, within: 500)
  let closed = client.close(running)
  let listener_stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  let expected =
    error.Protocol(case http2 {
      True -> error.Http2
      False -> error.Http1
    })
  assert outcome == Error(expected)
  assert read == Ok(Nil)
  assert transferred == Ok(Error(expected))
  assert closed == Ok(Nil)
  assert listener_stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}

fn await_worker_release(
  resources: resource.Controller,
  remaining: Int,
) -> Bool {
  use <- bool.guard(resource.snapshot(resources).active_workers == 0, True)
  use <- bool.guard(remaining <= 0, False)
  process.sleep(1)
  await_worker_release(resources, remaining - 1)
}

fn stalled_upload(
  http2 http2: Bool,
  early_response early_response: Bool,
  termination termination: Termination,
) -> Nil {
  let probe = new_probe()
  let started = process.new_subject()
  let head_seen = process.new_subject()
  let completed = process.new_subject()
  let assert Ok(executor) =
    server.start(server.defaults(), fn(incoming, _) {
      let release = process.new_subject()
      process.send(head_seen, release)
      case early_response {
        True -> {
          let _released = process.receive(release, within: 2000)
          Ok(response.new(413) |> response.set_body(body.empty()))
        }
        False -> {
          use _ <- result.try(body.read_all(incoming.body, 16))
          Ok(response.new(200) |> response.set_body(body.empty()))
        }
      }
    })
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = case http2 {
    True ->
      server.listen_http2_tls(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http2_defaults(),
        certificate,
        private_key,
        "localhost",
      )
    False ->
      server.listen_http1(
        executor,
        <<127, 0, 0, 1>>,
        0,
        server.http1_defaults() |> server.allow_http1_cleartext,
      )
  }
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let defaults =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_ca_certificates([ca_certificate])
    |> client.without_protocol_discovery
  let configured_timeouts = client.timeouts(defaults)
  let assert Ok(config) =
    client.with_timeouts(
      defaults,
      client.Timeouts(
        ..configured_timeouts,
        operation_milliseconds: case
          early_response
          || termination == CloseClient
          || termination == KillCaller
        {
          True -> 1500
          False -> 100
        },
        total_milliseconds: 2500,
      ),
    )
  let assert Ok(running) = client.start(config)
  let assert Ok(source) =
    body.from_pull(
      body.pull(fn(_) {
        record_started(probe)
        process.send(started, Nil)
        let never = process.new_subject()
        process.receive_forever(never)
        Ok(body.PullEnd([]))
      }),
      None,
      None,
      fn() { record_cleanup(probe) },
    )
  let caller =
    process.spawn_unlinked(fn() {
      let outcome =
        client.exchange(
          running,
          request.new()
            |> request.set_method(gleam_http.Post)
            |> request.set_scheme(case http2 {
              True -> gleam_http.Https
              False -> gleam_http.Http
            })
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_body(source),
        )
        |> result.map(fn(exchange) {
          let incoming = client.response(exchange)
          body.cancel(incoming.body)
          incoming.status
        })
        |> result.map_error(error.kind)
      process.send(completed, outcome)
    })
  let entered = process.receive(started, within: 1000) == Ok(Nil)
  let interrupted = case termination {
    OperationDeadline -> True
    CloseClient -> client.close(running) == Ok(Nil)
    KillCaller -> {
      process.kill(caller)
      await_cleanup(probe, 700)
    }
    SuspendCaller -> {
      suspend(caller)
      let disposed = await_cleanup(probe, 700)
      resume(caller)
      disposed
    }
  }
  let headers_arrived = case early_response {
    False -> True
    True ->
      case process.receive(head_seen, within: 500) {
        Ok(release) -> {
          process.send(release, Nil)
          True
        }
        Error(Nil) -> False
      }
  }
  let outcome = case termination {
    KillCaller -> Ok(Error(error.Cancelled))
    _ -> process.receive(completed, within: 700)
  }
  let observed = snapshot(probe)
  // A failed old implementation must still leave the fixture fully disposed.
  process.kill(caller)
  stop_pull(probe)
  body.cancel(source)
  let closed = client.close(running)
  let listener_stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  dispose(probe)
  assert entered
  assert interrupted
  assert headers_arrived
  assert outcome
    == Ok(case early_response, termination {
      True, _ -> Ok(413)
      False, CloseClient | False, KillCaller -> Error(error.Cancelled)
      False, _ -> Error(error.Timeout(error.Operation))
    })
  assert observed == #(False, 1, 0)
  assert closed == Ok(Nil)
  assert listener_stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
}
