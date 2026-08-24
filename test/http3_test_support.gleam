//// Test-only HTTP/3 loopback fixtures.

import gleam/http
import gleam/list
import gleam/result
import gleam/string
import http3/client
import http3/server
import http3/transport

/// A monitored test-only asynchronous operation.
pub type Task(value)

/// Run a test operation in a monitored process.
@external(erlang, "http3_test_ffi", "start_task")
pub fn start_task(run: fn() -> value) -> Task(value)

/// Wait a fixed time for a monitored test operation.
@external(erlang, "http3_test_ffi", "await_task")
pub fn await_task(task: Task(value)) -> value

/// Read the local PEM server certificate, key, and DER CA certificate.
@external(erlang, "http3_test_ffi", "server_credentials")
pub fn server_credentials() -> #(BitArray, BitArray, BitArray)

/// Read fallback and localhost credentials for the SNI selection test.
@external(erlang, "http3_test_ffi", "server_certificate_selection_credentials")
pub fn server_certificate_selection_credentials() -> #(
  BitArray,
  BitArray,
  BitArray,
  BitArray,
  BitArray,
)

/// A test-only one-shot process checkpoint.
pub type Signal

/// Construct a process checkpoint owned by the caller.
@external(erlang, "http3_test_ffi", "new_signal")
pub fn new_signal() -> Signal

/// Notify the signal owner and wait for release with a fixed timeout.
@external(erlang, "http3_test_ffi", "checkpoint")
pub fn checkpoint(signal: Signal) -> Nil

/// Wait for a checkpoint and release it.
@external(erlang, "http3_test_ffi", "release_signal")
pub fn release_signal(signal: Signal) -> Nil

/// Race two listener accepts and stop the listener to release the blocked one.
@external(erlang, "http3_test_ffi", "concurrent_accepts")
pub fn concurrent_accepts(
  listener: server.Listener,
) -> List(Result(server.Request, server.Error))

/// Verify a listener worker exits when its creating process exits.
@external(erlang, "http3_test_ffi", "server_owner_cleanup")
pub fn server_owner_cleanup(configuration: server.Configuration) -> Bool

/// Run a callback against the repository-owned server over real UDP.
pub fn with_server(run: fn(Int, BitArray) -> result) -> result {
  let #(certificate, private_key, ca_certificate) = server_credentials()
  let assert Ok(configuration) = server.new(certificate, private_key)
  let assert Ok(configuration) = server.with_timeout(configuration, 10_000)
  let assert Ok(configuration) =
    server.with_request_body_limit(configuration, 1_048_576)
  let assert Ok(listener) = server.start(configuration)
  let accept_task = start_task(fn() { serve(listener) })
  let assert Ok(port) = server.port(listener)
  let outcome = run(port, ca_certificate)
  let _stop = server.stop(listener)
  let _served = await_task(accept_task)
  outcome
}

/// Run a test through a proxy that drops the first client datagram.
pub fn with_lossy_server(run: fn(Int, BitArray) -> result) -> result {
  with_server(fn(port, ca_certificate) {
    with_lossy_proxy(port, ca_certificate, run)
  })
}

/// Run a test through a proxy that reverses the first two client datagrams.
pub fn with_reordering_proxy(run: fn(Int, BitArray) -> result) -> result {
  with_server(fn(port, ca_certificate) {
    with_reordering_proxy_ffi(port, ca_certificate, run)
  })
}

@external(erlang, "http3_test_ffi", "with_lossy_proxy")
fn with_lossy_proxy(
  server_port: Int,
  ca_certificate: BitArray,
  run: fn(Int, BitArray) -> result,
) -> result

@external(erlang, "http3_test_ffi", "with_reordering_proxy")
fn with_reordering_proxy_ffi(
  server_port: Int,
  ca_certificate: BitArray,
  run: fn(Int, BitArray) -> result,
) -> result

/// Run a fixture with a unique qlog directory and clean it afterwards.
@external(erlang, "http3_test_ffi", "with_qlog_directory")
pub fn with_qlog_directory(run: fn(String) -> result) -> #(result, Int)

/// Count exact qlog event names across all trace files in a fixture directory.
@external(erlang, "http3_test_ffi", "qlog_event_count")
pub fn qlog_event_count(directory: String, event_name: String) -> Int

/// Race two receivers, cancel the blocked one, and return both outcomes.
@external(erlang, "http3_test_ffi", "concurrent_next_events")
pub fn concurrent_next_events(
  stream: client.Stream,
) -> List(Result(client.ResponseEvent, client.Error))

/// Race two idempotent cancellation calls.
@external(erlang, "http3_test_ffi", "concurrent_cancellations")
pub fn concurrent_cancellations(
  stream: client.Stream,
) -> List(Result(client.Cancellation, client.Error))

/// Race two Datagram receivers, then invoke a peer-side release operation.
@external(erlang, "http3_test_ffi", "concurrent_next_datagrams")
pub fn concurrent_next_datagrams(
  stream: transport.Stream,
  release: fn() -> Nil,
) -> List(Result(BitArray, transport.Error))

/// Construct a byte-aligned test payload of the requested size.
@external(erlang, "http3_test_ffi", "repeated_bytes")
pub fn repeated_bytes(size: Int) -> BitArray

/// Verify that a connection worker exits when its creating process exits.
@external(erlang, "http3_test_ffi", "connection_owner_cleanup")
pub fn connection_owner_cleanup(
  configuration: client.Client,
  host: String,
  port: Int,
) -> Bool

fn serve(listener: server.Listener) -> Nil {
  case server.accept(listener) {
    Ok(request) -> {
      let _request_task = start_task(fn() { handle_request(listener, request) })
      serve(listener)
    }
    Error(_) -> Nil
  }
}

fn handle_request(listener: server.Listener, request: server.Request) -> Nil {
  let path = server.path(request)
  case path {
    "/timeout" -> Nil
    "/close" -> {
      let _stopped = server.stop(listener)
      Nil
    }
    "/stream-close" -> {
      let _body = server.read_body(request)
      let _stopped = server.stop(listener)
      Nil
    }
    "/empty" -> {
      let _response = server.respond(request, 204, [], <<>>)
      Nil
    }
    "/chunks" -> {
      let _head =
        server.send_response(request, 200, [#("content-type", "text/plain")])
      let _first = server.send_chunk(request, <<"one-":utf8>>)
      let _second = server.send_chunk(request, <<"two":utf8>>)
      let _finished = server.finish_response(request)
      Nil
    }
    _ -> handle_routed_request(path, request)
  }
}

fn handle_routed_request(path: String, request: server.Request) -> Nil {
  case string.starts_with(path, "/echo"), string.starts_with(path, "/large") {
    True, _ -> respond_echo(request)
    _, True -> {
      let _response =
        server.respond(
          request,
          200,
          [#("content-type", "text/plain")],
          repeated_bytes(64),
        )
      Nil
    }
    False, False -> {
      let _response =
        server.respond(request, 404, [#("content-type", "text/plain")], <<
          "not found":utf8,
        >>)
      Nil
    }
  }
}

fn respond_echo(request: server.Request) -> Nil {
  case server.read_body(request) {
    Error(_) -> Nil
    Ok(body) -> {
      let test_header =
        list.key_find(server.headers(request), "x-test")
        |> result.unwrap("missing")
      let headers = [
        #("content-type", "application/octet-stream"),
        #("x-request-method", http.method_to_string(server.method(request))),
        #("x-request-path", server.path(request)),
        #("x-received-test", test_header),
      ]
      let _response = server.respond(request, 200, headers, body)
      Nil
    }
  }
}
