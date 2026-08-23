//// Test-only HTTP/3 loopback fixtures.

import http3/client
import http3/server

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

@external(erlang, "http3_test_ffi", "with_server")
pub fn with_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that drops the first client datagram.
@external(erlang, "http3_test_ffi", "with_lossy_server")
pub fn with_lossy_server(run: fn(Int, BitArray) -> result) -> result

/// Run a test through a proxy that reverses the first two client datagrams.
@external(erlang, "http3_test_ffi", "with_reordering_proxy")
pub fn with_reordering_proxy(run: fn(Int, BitArray) -> result) -> result

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

/// Verify that a connection worker exits when its creating process exits.
@external(erlang, "http3_test_ffi", "connection_owner_cleanup")
pub fn connection_owner_cleanup(
  configuration: client.Client,
  host: String,
  port: Int,
) -> Bool
