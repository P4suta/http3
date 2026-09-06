//// Live, payload-free idle-wakeup qualification for the complete HTTP/3
//// actor stack. The fixture uses only public client/server/transport APIs;
//// the Erlang seam observes fixed process labels and BEAM receive outcomes.

import gleam/http
import gleam/http/request
import gleam/result
import http3/client
import http3/config
import http3/failure
import http3/server
import http3/transport
import http3_test_support

const operation_timeout_milliseconds = 1000

const idle_timeout_milliseconds = 10_000

const quiescence_poll_milliseconds = 100

const quiescence_stable_samples = 5

const quiescence_maximum_attempts = 80

const observation_milliseconds = 2500

type IdleTrace

type IdleEvidence

type QuiescenceSnapshot {
  QuiescenceSnapshot(
    client_counters: transport.ConnectionStats,
    server_counters: transport.ConnectionStats,
    client_bytes_in_flight: Int,
    server_bytes_in_flight: Int,
    client_in_recovery: Bool,
    server_in_recovery: Bool,
  )
}

@external(erlang, "http3_idle_wakeup_ffi", "start")
fn start_trace(
  quiescence_milliseconds: Int,
  stable_samples: Int,
  poll_milliseconds: Int,
  maximum_attempts: Int,
) -> Result(IdleTrace, Int)

@external(erlang, "http3_idle_wakeup_ffi", "monotonic_millisecond")
fn monotonic_millisecond() -> Int

/// Terminate the qualification command with structured failure evidence.
@external(erlang, "http3_idle_wakeup_ffi", "fail")
fn fail(reason: reason) -> value

@external(erlang, "http3_idle_wakeup_ffi", "begin_observation")
fn begin_observation(trace: IdleTrace) -> Result(Nil, Int)

@external(erlang, "http3_idle_wakeup_ffi", "finish")
fn finish_trace(
  trace: IdleTrace,
  minimum_milliseconds: Int,
) -> Result(IdleEvidence, Int)

@external(erlang, "http3_idle_wakeup_ffi", "passed")
fn evidence_passed(evidence: IdleEvidence) -> Bool

@external(erlang, "http3_idle_wakeup_ffi", "write")
fn write_evidence(evidence: IdleEvidence) -> Nil

pub fn main() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let deadlines =
    config.default_deadlines()
    |> set_deadline(
      phase: failure.Operation,
      milliseconds: operation_timeout_milliseconds,
    )
    |> set_deadline(
      phase: failure.Idle,
      milliseconds: idle_timeout_milliseconds,
    )
  let listener =
    server.new(certificate, private_key)
    |> must
    |> server.with_address_family(config.Ipv4)
    |> server.with_deadlines(deadlines)
    |> server.start
    |> must
  let port = server.port(listener) |> must
  let server_task = http3_test_support.start_task(fn() { serve_once(listener) })
  let client_configuration =
    client.new()
    |> client.with_address_family(config.Ipv4)
    |> client.with_ca_certificate(ca_certificate)
    |> must
  let connection =
    client.connect(client_configuration, "localhost", port) |> must
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/idle-wakeup")
    |> request.set_method(http.Get)
    |> request.set_body(Nil)
  let stream = client.open_stream(connection, outbound) |> must
  client.finish(stream) |> must
  receive_empty_response(stream)
  let server_request = http3_test_support.await_task(server_task) |> must

  // DPLPMTUD, delayed acknowledgements, and recovery are finite setup work.
  // Do not guess their duration: require every public traffic counter to stay
  // unchanged, with no bytes in flight and neither path in recovery, across a
  // bounded sequence of samples. Only then measure periodic idle wakeups.
  let quiescence_started = monotonic_millisecond()
  await_quiescence(connection, server_request)
  let quiescence_milliseconds = monotonic_millisecond() - quiescence_started
  let trace =
    start_trace(
      quiescence_milliseconds,
      quiescence_stable_samples,
      quiescence_poll_milliseconds,
      quiescence_maximum_attempts,
    )
    |> must_trace
  capture_liveness(connection, server_request)
  begin_observation(trace) |> must_trace
  http3_test_support.pause_milliseconds(observation_milliseconds)
  capture_liveness(connection, server_request)
  let evidence = finish_trace(trace, observation_milliseconds) |> must_trace

  let client_stop = client.close(connection)
  let server_stop = server.stop(listener)
  write_evidence(evidence)
  case client_stop, server_stop, evidence_passed(evidence) {
    Ok(client.Closed), Ok(server.Stopped), True -> Nil
    Ok(client.AlreadyClosed), _, _ -> fail("idle client closed early")
    _, Ok(server.AlreadyStopped), _ -> fail("idle server stopped early")
    Error(error), _, _ -> fail(#("idle client cleanup failed", error))
    _, Error(error), _ -> fail(#("idle server cleanup failed", error))
    _, _, False -> fail("idle periodic wakeup qualification failed")
  }
}

fn serve_once(
  listener: server.Listener,
) -> Result(server.Request, server.Error) {
  use request <- result.try(server.accept(listener))
  use _body <- result.try(server.read_body(request))
  use Nil <- result.try(server.respond(request, 204, [], <<>>))
  Ok(request)
}

fn receive_empty_response(stream: client.Stream) -> Nil {
  case client.next_event(stream) |> must {
    client.InformationalResponse(_, _) | client.Response(_, _) ->
      receive_empty_response(stream)
    client.Data(_) -> fail("idle response emitted a body event")
    client.Trailers(_) -> receive_empty_response(stream)
    client.End -> Nil
  }
}

fn capture_liveness(
  connection: client.Connection,
  request: server.Request,
) -> Nil {
  transport.connection_stats(client.connection_transport(connection)) |> must
  transport.stream_connection_stats(server.request_transport(request)) |> must
  Nil
}

fn await_quiescence(
  connection: client.Connection,
  request: server.Request,
) -> Nil {
  await_quiescence_loop(
    connection: connection,
    request: request,
    previous: quiescence_snapshot(connection, request),
    stable_samples: 0,
    attempts: quiescence_maximum_attempts,
  )
}

fn await_quiescence_loop(
  connection connection: client.Connection,
  request request: server.Request,
  previous previous: QuiescenceSnapshot,
  stable_samples stable_samples: Int,
  attempts attempts: Int,
) -> Nil {
  case attempts <= 0 {
    True -> fail("transport did not reach bounded quiescence")
    False -> {
      http3_test_support.pause_milliseconds(quiescence_poll_milliseconds)
      let current = quiescence_snapshot(connection, request)
      let next_stable = case current == previous, quiescent(current) {
        True, True -> stable_samples + 1
        _, _ -> 0
      }
      case next_stable >= quiescence_stable_samples {
        True -> Nil
        False ->
          await_quiescence_loop(
            connection: connection,
            request: request,
            previous: current,
            stable_samples: next_stable,
            attempts: attempts - 1,
          )
      }
    }
  }
}

fn quiescence_snapshot(
  connection: client.Connection,
  request: server.Request,
) -> QuiescenceSnapshot {
  let client_transport = client.connection_transport(connection)
  let server_transport = server.request_transport(request)
  let client_counters = transport.connection_stats(client_transport) |> must
  let server_counters =
    transport.stream_connection_stats(server_transport) |> must
  let transport.PathStats(_, _, _, _, _, client_flight, client_recovery, _) =
    transport.path_stats(client_transport) |> must
  let transport.PathStats(_, _, _, _, _, server_flight, server_recovery, _) =
    transport.stream_path_stats(server_transport) |> must
  QuiescenceSnapshot(
    client_counters,
    server_counters,
    client_flight,
    server_flight,
    client_recovery,
    server_recovery,
  )
}

fn quiescent(snapshot: QuiescenceSnapshot) -> Bool {
  let QuiescenceSnapshot(
    client_bytes_in_flight: client_flight,
    server_bytes_in_flight: server_flight,
    client_in_recovery: client_recovery,
    server_in_recovery: server_recovery,
    ..,
  ) = snapshot
  client_flight == 0
  && server_flight == 0
  && !client_recovery
  && !server_recovery
}

fn set_deadline(
  deadlines deadlines: config.Deadlines,
  phase phase: failure.TimeoutPhase,
  milliseconds milliseconds: Int,
) -> config.Deadlines {
  config.with_deadline(deadlines, phase, milliseconds) |> must
}

fn must(value: Result(value, error)) -> value {
  case value {
    Ok(value) -> value
    Error(error) -> fail(#("idle fixture operation failed", error))
  }
}

fn must_trace(value: Result(value, Int)) -> value {
  case value {
    Ok(value) -> value
    Error(error) -> fail(#("idle trace operation failed", error))
  }
}
