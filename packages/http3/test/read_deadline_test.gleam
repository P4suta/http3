import gleam/erlang/process
import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/result
import http3/client
import http3/config
import http3/failure
import http3/internal/read_deadline
import http3/server
import http3_test_support
import quic_core/diagnostics

@external(erlang, "http3_read_deadline_test_ffi", "late_delivery")
fn late_delivery(kind: Int, handle: handle, send: fn() -> Bool) -> #(Int, Bool)

@external(erlang, "http3_read_deadline_test_ffi", "late_observation")
fn late_observation(
  kind: Int,
  handle: handle,
  send: fn() -> Bool,
) -> #(Int, Bool)

pub fn client_rejects_a_reply_observed_after_the_deadline_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let #(phase, timed_out) =
    late_observation(1, outgoing, fn() {
      server.send_response(incoming, 200, []) == Ok(Nil)
    })
  let closed = cleanup(listener:, connection:)
  assert phase == 6
  assert timed_out
  assert closed
}

pub fn server_rejects_a_reply_observed_after_the_deadline_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let #(phase, timed_out) =
    late_observation(2, incoming, fn() {
      client.send_chunk(outgoing, <<"body">>) == Ok(Nil)
    })
  let closed = cleanup(listener:, connection:)
  assert phase == 6
  assert timed_out
  assert closed
}

pub fn queued_client_network_event_survives_waiter_expiry_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let #(phase, retained) =
    late_delivery(1, outgoing, fn() {
      server.send_response(incoming, 200, []) == Ok(Nil)
    })
  let closed = cleanup(listener:, connection:)
  assert phase == 6
  assert retained
  assert closed
}

pub fn queued_server_network_event_survives_waiter_expiry_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let #(phase, retained) =
    late_delivery(2, incoming, fn() {
      client.send_chunk(outgoing, <<"body">>) == Ok(Nil)
    })
  let closed = cleanup(listener:, connection:)
  assert phase == 6
  assert retained
  assert closed
}

pub fn injected_clock_rejects_past_and_exact_deadlines_test() -> Nil {
  assert read_deadline.plan(now: 100, deadline: 99, operation: 500)
    == Error(Nil)
  assert read_deadline.plan(now: 100, deadline: 100, operation: 500)
    == Error(Nil)
}

pub fn injected_clock_preserves_short_remaining_time_test() -> Nil {
  assert read_deadline.plan(now: 100, deadline: 107, operation: 500)
    == Ok(#(107, 7))
  assert read_deadline.plan(now: -100, deadline: -93, operation: 500)
    == Ok(#(-93, 7))
}

pub fn injected_clock_clamps_to_the_original_operation_test() -> Nil {
  assert read_deadline.plan(now: 100, deadline: 100_000, operation: 500)
    == Ok(#(600, 500))
  assert read_deadline.plan(now: 100, deadline: 600, operation: 500)
    == Ok(#(600, 500))
  assert read_deadline.plan(now: 100, deadline: 600, operation: 0) == Error(Nil)
  assert read_deadline.plan(now: 100, deadline: 600, operation: -1)
    == Error(Nil)
}

pub fn injected_clock_never_renews_a_shared_deadline_test() -> Nil {
  let assert Ok(#(deadline, _)) =
    read_deadline.plan(now: 100, deadline: 600, operation: 500)
  assert read_deadline.plan(now: 595, deadline:, operation: 500)
    == Ok(#(600, 5))
  assert read_deadline.plan(now: 600, deadline:, operation: 500) == Error(Nil)
}

pub fn expired_client_read_preserves_the_queued_response_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let sent = server.send_response(incoming, 200, [])
  let expired =
    client.next_event_until(outgoing, diagnostics.monotonic_milliseconds() - 1)
  let head = client.next_event(outgoing)
  let closed = cleanup(listener:, connection:)
  assert sent == Ok(Nil)
  assert expired == client_timeout()
  assert head == Ok(client.Response(200, []))
  assert closed
}

pub fn expired_server_read_preserves_the_queued_body_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let sent = client.send_chunk(outgoing, <<"body">>)
  let expired =
    server.next_event_until(incoming, diagnostics.monotonic_milliseconds() - 1)
  let body = server.next_event(incoming)
  let closed = cleanup(listener:, connection:)
  assert sent == Ok(Nil)
  assert expired == server_timeout()
  assert body == Ok(server.Data(<<"body">>))
  assert closed
}

pub fn short_client_read_releases_its_waiter_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let started = diagnostics.monotonic_milliseconds()
  let expired = client.next_event_until(outgoing, started + 100)
  let elapsed = diagnostics.monotonic_milliseconds() - started
  let sent = server.send_response(incoming, 200, [])
  let head =
    client.next_event_until(
      outgoing,
      diagnostics.monotonic_milliseconds() + 2000,
    )
  let closed = cleanup(listener:, connection:)
  assert expired == client_timeout()
  assert elapsed < 1000
  assert sent == Ok(Nil) && head == Ok(client.Response(200, []))
  assert closed
}

pub fn short_server_read_releases_its_waiter_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture(operation: 2000)
  let started = diagnostics.monotonic_milliseconds()
  let expired = server.next_event_until(incoming, started + 100)
  let elapsed = diagnostics.monotonic_milliseconds() - started
  let sent = client.send_chunk(outgoing, <<"body">>)
  let body =
    server.next_event_until(
      incoming,
      diagnostics.monotonic_milliseconds() + 2000,
    )
  let closed = cleanup(listener:, connection:)
  assert expired == server_timeout()
  assert elapsed < 1000
  assert sent == Ok(Nil) && body == Ok(server.Data(<<"body">>))
  assert closed
}

pub fn long_client_deadline_still_obeys_configured_operation_test() -> Nil {
  let #(listener, connection, outgoing, _) = fixture(operation: 250)
  let configured = client.operation_timeout_milliseconds(outgoing)
  let started = diagnostics.monotonic_milliseconds()
  let expired = client.next_event_until(outgoing, started + 10_000)
  let elapsed = diagnostics.monotonic_milliseconds() - started
  let closed = cleanup(listener:, connection:)
  assert configured == 250
  assert expired == client_timeout() && elapsed < 1500
  assert closed
}

pub fn long_server_deadline_still_obeys_configured_operation_test() -> Nil {
  let #(listener, connection, _, incoming) = fixture(operation: 250)
  let configured = server.operation_timeout_milliseconds(incoming)
  let started = diagnostics.monotonic_milliseconds()
  let expired = server.next_event_until(incoming, started + 10_000)
  let elapsed = diagnostics.monotonic_milliseconds() - started
  let closed = cleanup(listener:, connection:)
  assert configured == 250
  assert expired == server_timeout() && elapsed < 1500
  assert closed
}

pub fn cancel_releases_the_admitted_client_deadline_waiter_test() -> Nil {
  let #(listener, connection, outgoing, _) = fixture(operation: 2000)
  let replies = process.new_subject()
  let wait = fn() {
    let outcome =
      client.next_event_until(
        outgoing,
        diagnostics.monotonic_milliseconds() + 2000,
      )
    process.send(replies, outcome)
    outcome
  }
  let first = http3_test_support.start_task(wait)
  let second = http3_test_support.start_task(wait)
  // ConcurrentReceive proves the other reader has actually occupied the slot.
  let rejected = process.receive(replies, within: 1000)
  let cancelled = client.cancel(outgoing)
  let outcomes = [
    http3_test_support.await_task(first),
    http3_test_support.await_task(second),
  ]
  let repeated =
    client.next_event_until(
      outgoing,
      diagnostics.monotonic_milliseconds() + 2000,
    )
  let closed = cleanup(listener:, connection:)
  assert rejected == Ok(Error(client.ConcurrentReceive))
  assert cancelled == Ok(client.Cancelled)
  assert list.contains(outcomes, Error(client.ConcurrentReceive))
  assert list.contains(outcomes, Error(client.Failure(failure.Cancelled)))
  assert repeated == Error(client.Failure(failure.Cancelled))
  assert closed
}

pub fn cancel_releases_the_admitted_server_deadline_waiter_test() -> Nil {
  let #(listener, connection, _, incoming) = fixture(operation: 2000)
  let replies = process.new_subject()
  let wait = fn() {
    let outcome =
      server.next_event_until(
        incoming,
        diagnostics.monotonic_milliseconds() + 2000,
      )
    process.send(replies, outcome)
    outcome
  }
  let first = http3_test_support.start_task(wait)
  let second = http3_test_support.start_task(wait)
  let rejected = process.receive(replies, within: 1000)
  let cancelled = server.cancel(incoming)
  let outcomes = [
    http3_test_support.await_task(first),
    http3_test_support.await_task(second),
  ]
  let repeated =
    server.next_event_until(
      incoming,
      diagnostics.monotonic_milliseconds() + 2000,
    )
  let closed = cleanup(listener:, connection:)
  let stopped =
    Error(server.Failure(failure.Closed(failure.Local, Some(0x10c))))
  assert rejected == Ok(Error(server.ConcurrentReceive))
  assert cancelled == Ok(server.Cancelled)
  assert list.contains(outcomes, Error(server.ConcurrentReceive))
  assert list.contains(outcomes, stopped)
  assert repeated == stopped
  assert closed
}

fn client_timeout() -> Result(client.ResponseEvent, client.Error) {
  Error(client.Failure(failure.Timeout(failure.Operation)))
}

fn server_timeout() -> Result(server.RequestEvent, server.Error) {
  Error(server.Failure(failure.Timeout(failure.Operation)))
}

fn fixture(
  operation operation: Int,
) -> #(server.Listener, client.Connection, client.Stream, server.Request) {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let assert Ok(deadlines) =
    config.with_deadline(
      config.default_deadlines(),
      failure.Operation,
      operation,
    )
  let assert Ok(server_config) = server.new(certificate, key)
  let listener = server.start(server.with_deadlines(server_config, deadlines))
  let assert Ok(listener) = listener
  let assert Ok(port) = server.port(listener)
  let assert Ok(client_config) = client.with_ca_certificate(client.new(), ca)
  let assert Ok(connection) =
    client.connect(
      client.with_deadlines(client_config, deadlines),
      "localhost",
      port,
    )
  let assert Ok(outgoing) =
    client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
  let assert Ok(incoming) = server.accept(listener)
  #(listener, connection, outgoing, incoming)
}

fn cleanup(
  listener listener: server.Listener,
  connection connection: client.Connection,
) -> Bool {
  let closed =
    client.close_within(connection: connection, within_milliseconds: 5000)
  let stopped = server.stop(listener)
  result.is_ok(closed) && result.is_ok(stopped)
}
