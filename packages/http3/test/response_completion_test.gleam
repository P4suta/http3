import gleam/erlang/process
import gleam/http/request
import gleam/option.{Some}
import gleam/result
import gleeunit/should
import http3/client
import http3/failure
import http3/server
import http3_test_support

// nolint: unused_exports -- EUnit discovers the exported test suffix.
pub fn response_completion_does_not_consume_request_end_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture()
  let waiter =
    http3_test_support.start_task(fn() {
      server.await_response_completion(incoming)
    })
  let sent = server.respond(incoming, 201, [], <<"complete">>)
  let response = receive_response(stream: outgoing, received: False)
  let completed = http3_test_support.await_task(waiter)
  let repeated = server.await_response_completion(incoming)
  let request_end = server.next_event(incoming)
  let closed = client.close(connection)
  let stopped = server.stop(listener)
  assert sent == Ok(Nil)
  assert response
  assert completed == Ok(Nil)
  assert repeated == Ok(Nil)
  assert request_end == Ok(server.End)
  assert result.is_ok(closed) && result.is_ok(stopped)
}

// nolint: unused_exports -- EUnit discovers the exported test suffix.
pub fn peer_stop_after_request_fin_releases_response_completion_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture()
  // Consume the request FIN before cancellation: no request reader remains to discover the later stop of the independent response direction.
  let request_end = server.next_event(incoming)
  let sent = server.send_response(incoming, 200, [])
  let head = client.next_event(outgoing)
  let ready = process.new_subject()
  let waiter =
    http3_test_support.start_task(fn() {
      let completion = server.await_response_completion(incoming)
      process.send(ready, completion)
      completion
    })
  let cancelled = client.cancel(outgoing)
  let timely = process.receive(ready, within: 1000)
  let closed = client.close(connection)
  let completed = http3_test_support.await_task(waiter)
  let stopped = server.stop(listener)
  assert request_end == Ok(server.End)
  assert sent == Ok(Nil)
  assert head == Ok(client.Response(200, []))
  assert result.is_ok(cancelled)
  assert timely
    == Ok(Error(server.Failure(failure.Closed(failure.Peer, Some(0x10c)))))
  assert completed
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x10c))))
  assert result.is_ok(closed) && result.is_ok(stopped)
}

// nolint: unused_exports -- EUnit discovers the exported test suffix.
pub fn peer_close_releases_response_completion_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture()
  let sent = server.send_response(incoming, 200, [])
  let head = client.next_event(outgoing)
  let waiter =
    http3_test_support.start_task(fn() {
      server.await_response_completion(incoming)
    })
  let closed = client.close(connection)
  let completed = http3_test_support.await_task(waiter)
  let stopped = server.stop(listener)
  assert sent == Ok(Nil)
  assert head == Ok(client.Response(200, []))
  assert completed
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x10c))))
  assert result.is_ok(closed) && result.is_ok(stopped)
}

// nolint: unused_exports -- EUnit discovers the exported test suffix.
pub fn completion_timeout_releases_its_waiter_without_cancelling_response_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture_with_timeout(500)
  let expired = server.await_response_completion(incoming)
  let sent = server.respond(incoming, 201, [], <<"complete">>)
  let response = receive_response(stream: outgoing, received: False)
  let completed = server.await_response_completion(incoming)
  let closed = client.close(connection)
  let stopped = server.stop(listener)
  assert expired == Error(server.Failure(failure.Timeout(failure.Operation)))
  assert sent == Ok(Nil) && response
  assert completed == Ok(Nil)
  assert result.is_ok(closed) && result.is_ok(stopped)
}

// nolint: unused_exports -- EUnit discovers the exported test suffix.
pub fn concurrent_completion_waiters_have_one_finite_slot_test() -> Nil {
  let #(listener, connection, outgoing, incoming) = fixture()
  let outcomes = process.new_subject()
  let wait = fn() {
    let outcome = server.await_response_completion(incoming)
    process.send(outcomes, outcome)
    outcome
  }
  let first = http3_test_support.start_task(wait)
  let second = http3_test_support.start_task(wait)
  // The rejected operation itself is the synchronization barrier: an independent accepted waiter must still be alive until response completion.
  let rejected = process.receive(outcomes, within: 1000)
  let sent = server.respond(incoming, 201, [], <<"complete">>)
  let response = receive_response(stream: outgoing, received: False)
  let first = http3_test_support.await_task(first)
  let second = http3_test_support.await_task(second)
  let closed = client.close(connection)
  let stopped = server.stop(listener)
  assert rejected == Ok(Error(server.ConcurrentReceive))
  assert #(first, second) == #(Ok(Nil), Error(server.ConcurrentReceive))
    || #(second, first) == #(Ok(Nil), Error(server.ConcurrentReceive))
  assert sent == Ok(Nil) && response
  assert result.is_ok(closed) && result.is_ok(stopped)
}

fn fixture() -> #(
  server.Listener,
  client.Connection,
  client.Stream,
  server.Request,
) {
  fixture_with_timeout(3000)
}

fn fixture_with_timeout(
  timeout: Int,
) -> #(server.Listener, client.Connection, client.Stream, server.Request) {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let configuration = server.new(certificate, key) |> should.be_ok
  let configuration =
    server.with_timeout(configuration, timeout) |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let configuration =
    client.with_ca_certificate(client.new(), ca) |> should.be_ok
  let configuration = client.with_timeout(configuration, 3000) |> should.be_ok
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let outgoing =
    client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
    |> should.be_ok
  client.finish(outgoing) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  #(listener, connection, outgoing, incoming)
}

fn receive_response(
  stream stream: client.Stream,
  received received: Bool,
) -> Bool {
  case client.next_event(stream) {
    Ok(client.Response(201, _)) -> receive_response(stream:, received:)
    Ok(client.Data(<<"complete">>)) -> receive_response(stream:, received: True)
    Ok(client.End) -> received
    _ -> False
  }
}
