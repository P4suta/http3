//// Optional, test-only BeamTrace diagnostic workloads.
////
//// Every protocol operation goes through the public HTTP/3 API. The small
//// diagnostic FFI below is used only for arguments, output, finite task
//// ownership, and aggregate process/mailbox convergence checks.

import gleam/bit_array
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/option.{type Option, None, Some}
import http3/client
import http3/server
import http3/transport
import http3_test_support

const operation_timeout_milliseconds = 5000

const cleanup_timeout_milliseconds = 5000

const cleanup_process_allowance = 8

const cleanup_mailbox_allowance = 128

/// Run one warm-up workload followed by the single traced root.
pub fn main() -> Nil {
  let scenario = case arguments() {
    [scenario] ->
      case is_supported_scenario(scenario) {
        True -> scenario
        False ->
          fail(
            "usage: http3_diagnostic <round-trip|connection-isolation|slow-consumer|cleanup>",
          )
      }
    _ ->
      fail(
        "usage: http3_diagnostic <round-trip|connection-isolation|slow-consumer|cleanup>",
      )
  }

  run_and_check_cleanup(scenario, None)
  trace_root(scenario)
  write_line("http3 diagnostic scenario completed: " <> scenario)
}

/// The one and only BeamTrace root, entered after code and crypto warm-up.
pub fn trace_root(scenario: String) -> Nil {
  let qlog = case qlog_directory() {
    "" -> None
    directory -> Some(directory)
  }
  run_and_check_cleanup(scenario, qlog)
}

/// Fixed scenario allowlist used by the runner and direct unit test.
pub fn supported_scenarios() -> List(String) {
  ["round-trip", "connection-isolation", "slow-consumer", "cleanup"]
}

/// Return whether a scenario is safe and finitely bounded.
pub fn is_supported_scenario(scenario: String) -> Bool {
  scenario == "round-trip"
  || scenario == "connection-isolation"
  || scenario == "slow-consumer"
  || scenario == "cleanup"
}

fn run_and_check_cleanup(scenario: String, qlog: Option(String)) -> Nil {
  let #(processes_before, messages_before) = runtime_metrics()
  run_scenario(scenario, qlog)
  assert await_cleanup(
    processes_before + cleanup_process_allowance,
    messages_before + cleanup_mailbox_allowance,
    cleanup_timeout_milliseconds,
  )
}

fn run_scenario(scenario: String, qlog: Option(String)) -> Nil {
  case scenario {
    "round-trip" -> round_trip(qlog)
    "connection-isolation" -> connection_isolation(qlog)
    "slow-consumer" -> slow_consumer(qlog)
    "cleanup" -> owner_cleanup(qlog)
    _ -> fail(#("unsupported diagnostic scenario", scenario))
  }
}

fn round_trip(qlog: Option(String)) -> Nil {
  with_server(qlog, fn(port, ca_certificate) {
    let configuration = client_configuration(ca_certificate, qlog, 1024)
    run_stream_echo(configuration, port, <<"diagnostic-round-trip":utf8>>)
  })
}

fn connection_isolation(qlog: Option(String)) -> Nil {
  with_server(qlog, fn(port, ca_certificate) {
    let configuration = client_configuration(ca_certificate, qlog, 1024)
    let assert Ok(first) = client.connect(configuration, "localhost", port)
    let assert Ok(blocked) =
      streaming_request(port, "/timeout")
      |> client.open_stream(first, _)
    let assert Ok(Nil) = client.finish(blocked)
    let assert Ok(client.Closed) = client.close(first)

    // A separately owned connection must remain usable after the first one
    // closes with an unanswered request.
    run_stream_echo(configuration, port, <<"isolated-connection":utf8>>)
  })
}

fn slow_consumer(qlog: Option(String)) -> Nil {
  with_server(qlog, fn(port, ca_certificate) {
    let configuration = client_configuration(ca_certificate, qlog, 8)
    let assert Ok(connection) = client.connect(configuration, "localhost", port)
    let assert Ok(stream) =
      streaming_request(port, "/large")
      |> client.open_stream(connection, _)
    let assert Ok(Nil) = client.finish(stream)
    let assert Ok(client.Response(200, _)) = client.next_event(stream)
    assert client.next_event(stream) == Error(client.ConsumerTooSlow(8))
    let assert Ok(client.AlreadyCancelled) = client.cancel(stream)
    let assert Ok(client.Closed) = client.close(connection)
    Nil
  })
}

fn owner_cleanup(qlog: Option(String)) -> Nil {
  with_server(qlog, fn(port, ca_certificate) {
    let configuration = client_configuration(ca_certificate, qlog, 1024)
    let #(processes_before, messages_before) = runtime_metrics()
    let connected = process.new_subject()
    let _owner =
      process.spawn_unlinked(fn() {
        let assert Ok(_connection) =
          client.connect(configuration, "localhost", port)
        process.send(connected, Nil)
        // Deliberately crash without close to exercise owner-monitor cleanup.
        fail("intentional diagnostic connection-owner crash")
      })
    let assert Ok(Nil) =
      process.receive(connected, within: operation_timeout_milliseconds)
    assert await_cleanup(
      processes_before + cleanup_process_allowance,
      messages_before + cleanup_mailbox_allowance,
      cleanup_timeout_milliseconds,
    )

    // The listener and a new isolated connection remain healthy afterwards.
    run_stream_echo(configuration, port, <<"after-owner-exit":utf8>>)
  })
}

fn with_server(qlog: Option(String), run: fn(Int, BitArray) -> Nil) -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(configuration) =
    server.with_timeout(configuration, operation_timeout_milliseconds)
  let assert Ok(configuration) =
    server.with_stream_buffer_limit(configuration, 65_536)
  let configuration = case qlog {
    None -> configuration
    Some(directory) -> {
      let assert Ok(writer) = transport.qlog(directory)
      server.with_qlog(configuration, writer)
    }
  }
  let assert Ok(listener) = server.start(configuration)
  let assert Ok(port) = server.port(listener)
  let server_task = http3_test_support.start_task(fn() { serve(listener) })

  run(port, ca_certificate)

  case server.stop(listener) {
    Ok(server.Stopped) | Ok(server.AlreadyStopped) -> Nil
    outcome -> fail(#("diagnostic listener cleanup", outcome))
  }
  let Nil = http3_test_support.await_task(server_task)
}

fn serve(listener: server.Listener) -> Nil {
  case server.accept(listener) {
    Error(_) -> Nil
    Ok(incoming) -> {
      let _handler =
        http3_test_support.start_task(fn() { handle_request(incoming) })
      serve(listener)
    }
  }
}

fn handle_request(incoming: server.Request) -> Nil {
  case server.path(incoming) {
    "/timeout" -> Nil
    "/large" -> {
      let assert Ok(Nil) =
        server.respond(
          incoming,
          200,
          [#("content-type", "application/octet-stream")],
          http3_test_support.repeated_bytes(64),
        )
      Nil
    }
    _ -> {
      let assert Ok(body) = server.read_body(incoming)
      let assert Ok(Nil) =
        server.respond(
          incoming,
          200,
          [#("content-type", "application/octet-stream")],
          body,
        )
      Nil
    }
  }
}

fn client_configuration(
  ca_certificate: BitArray,
  qlog: Option(String),
  stream_buffer_limit: Int,
) -> client.Client {
  let assert Ok(configuration) =
    client.with_timeout(client.new(), operation_timeout_milliseconds)
  let assert Ok(configuration) =
    client.with_stream_buffer_limit(configuration, stream_buffer_limit)
  let assert Ok(configuration) =
    client.with_ca_certificate(configuration, ca_certificate)
  case qlog {
    None -> configuration
    Some(directory) -> {
      let assert Ok(writer) = transport.qlog(directory)
      client.with_qlog(configuration, writer)
    }
  }
}

fn run_stream_echo(
  configuration: client.Client,
  port: Int,
  payload: BitArray,
) -> Nil {
  let assert Ok(connection) = client.connect(configuration, "localhost", port)
  let request =
    streaming_request(port, "/echo")
    |> request.set_method(http.Post)
  let assert Ok(stream) = client.open_stream(connection, request)
  let assert Ok(Nil) = client.send_chunk(stream, payload)
  let assert Ok(Nil) = client.finish(stream)
  assert receive_response(stream, <<>>, False) == payload
  let assert Ok(client.Closed) = client.close(connection)
  Nil
}

fn streaming_request(port: Int, path: String) -> request.Request(Nil) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(Nil)
}

fn receive_response(
  stream: client.Stream,
  body: BitArray,
  response_seen: Bool,
) -> BitArray {
  case client.next_event(stream) {
    Ok(client.InformationalResponse(_, _)) ->
      receive_response(stream, body, response_seen)
    Ok(client.Response(200, _)) -> receive_response(stream, body, True)
    Ok(client.Response(status, _)) -> fail(#("unexpected status", status))
    Ok(client.Data(chunk)) ->
      receive_response(stream, bit_array.append(body, chunk), response_seen)
    Ok(client.Trailers(_)) -> receive_response(stream, body, response_seen)
    Ok(client.End) -> {
      assert response_seen
      body
    }
    Error(error) -> fail(#("response receive failed", error))
  }
}

@external(erlang, "http3_diagnostic_ffi", "arguments")
fn arguments() -> List(String)

@external(erlang, "http3_diagnostic_ffi", "qlog_directory")
fn qlog_directory() -> String

@external(erlang, "http3_diagnostic_ffi", "runtime_metrics")
fn runtime_metrics() -> #(Int, Int)

@external(erlang, "http3_diagnostic_ffi", "await_cleanup")
fn await_cleanup(
  maximum_processes: Int,
  maximum_mailbox_messages: Int,
  timeout_milliseconds: Int,
) -> Bool

@external(erlang, "http3_diagnostic_ffi", "write_line")
fn write_line(line: String) -> Nil

@external(erlang, "http3_diagnostic_ffi", "fail")
fn fail(reason: reason) -> value
