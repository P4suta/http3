import gleam/erlang/process.{type Pid}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import quic_core
import quic_core/client
import quic_core/config
import quic_core/failure
import quic_core/internal/runtime/connection_worker
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

@external(erlang, "quic_send_completion_test_ffi", "registered_waiter")
fn registered_waiter(
  connection: server.Connection,
  await: fn() -> Result(server.SendCompletion, server.Error),
  action: fn() -> value,
  counts: fn() -> Int,
) -> #(Bool, value, Bool)

@external(erlang, "quic_core_test_ffi", "connection_handle")
fn connection_handle(
  connection: server.Connection,
) -> Result(connection_worker.Connection, Nil)

@external(erlang, "quic_core_test_ffi", "labelled_pid")
fn labelled_pid(
  connection: server.Connection,
  label: BitArray,
) -> Result(Pid, Nil)

@external(erlang, "quic_send_completion_test_ffi", "saturate_waiters")
fn saturate_waiters(
  callbacks: List(fn() -> Bool),
  counts: fn() -> #(Int, Int, Int),
  limit: Int,
) -> #(Int, Int, Bool, Bool)

@external(erlang, "quic_send_completion_test_ffi", "concurrent_observers")
fn concurrent_observers(
  actor: Pid,
  feed: fn() -> Result(server.SendCompletionBatch, server.Error),
  await: fn() -> Result(server.SendCompletion, server.Error),
  action: fn() -> action,
  counts: fn() -> #(Int, Int, Int),
) -> #(
  Bool,
  action,
  Result(server.SendCompletionBatch, server.Error),
  Result(server.SendCompletion, server.Error),
  Bool,
  Bool,
)

@external(erlang, "quic_send_completion_test_ffi", "owner_exit_releases_waiter")
fn owner_exit_releases_waiter(
  capture_owner: fn() -> server.CompletionFeedOwner,
  await: fn(server.CompletionFeedOwner) ->
    Result(server.SendCompletionBatch, server.Error),
  counts: fn() -> #(Int, Int, Int),
) -> #(Bool, Result(server.SendCompletionBatch, server.Error), Bool, Bool, Bool)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unfunded_waiters_are_rejected_before_monitors_and_all_admitted_reservations_return_test() -> Nil {
  let #(listener, connection, peer, _, incoming) = pair_with_memory(65_536)
  let streams =
    int.range(1, 16, [incoming], fn(streams, _) {
      let assert Ok(outgoing) = client.open_bidirectional(connection)
      assert client.send_and_finish(outgoing, <<"request">>) == Ok(Nil)
      let assert Ok(server.IncomingStream(incoming, server.Bidirectional)) =
        server.accept_stream(peer)
      [incoming, ..streams]
    })
  let callbacks =
    list.map(streams, fn(stream) {
      fn() {
        server.await_send_completion(stream, 2000)
        == Error(server.Failure(failure.Overload(failure.EndpointMemory)))
      }
    })
  let #(admitted, refused, bounded, joined) =
    saturate_waiters(
      callbacks,
      fn() { completion_counts(peer) |> result.unwrap(#(-1, -1, -1)) },
      65_536,
    )
  assert admitted > 0
  assert refused > 0
  assert admitted + refused == 16
  assert bounded
  assert joined
  assert completion_counts(peer) == Ok(#(0, 0, 4096))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn public_client_preserves_the_configured_memory_limit_and_accepts_exact_admission_test() -> Nil {
  let assert Ok(ca) = fixture("ca.pem")
  let assert Ok(configured) =
    client.new_with_ca_certificates("localhost", 1, "send-completion", ca)
  let assert Ok(limits) =
    config.with_limit(config.default_limits(), failure.EndpointMemory, 65_535)
  assert configured
    |> client.with_limits(limits)
    |> client.connect
    |> result.replace(Nil)
    == Error(client.Failure(failure.Limit(failure.EndpointMemory, 65_535)))
  let #(listener, connection, peer, outgoing, incoming) =
    pair_with_limits(65_536, 65_536)
  assert server.send_and_finish(incoming, <<"response">>) == Ok(Nil)
  assert client.receive(outgoing, 32) == Ok(client.Data(<<"response">>, True))
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendAcknowledged)
  cleanup(listener, connection, peer)
}

fn waiter_count(connection: server.Connection) -> Int {
  let assert Ok(handle) = connection_handle(connection)
  connection_worker.send_completion_counts(handle)
  |> result.map(fn(counts) { counts.0 })
  |> result.unwrap(-1)
}

fn completion_counts(
  connection: server.Connection,
) -> Result(#(Int, Int, Int), connection_worker.Error) {
  let assert Ok(handle) = connection_handle(connection)
  connection_worker.send_completion_counts(handle)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn duplicate_wait_is_rejected_and_caller_death_removes_its_monitor_test() -> Nil {
  let #(listener, connection, peer, _, incoming) = pair()
  let observed =
    registered_waiter(
      peer,
      fn() { server.await_send_completion(incoming, 2000) },
      fn() {
        assert completion_counts(peer) == Ok(#(1, 0, 12_288))
        server.await_send_completion(incoming, 1000)
      },
      fn() { waiter_count(peer) },
    )
  assert observed == #(True, Error(server.ConcurrentOperation), True)
  assert completion_counts(peer) == Ok(#(0, 0, 4096))
  assert server.reset(incoming, 0x102) == Ok(Nil)
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendReset(0x102))
  assert completion_counts(peer) == Ok(#(0, 1, 4096))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn acknowledged_send_does_not_consume_request_receive_direction_test() -> Nil {
  let #(listener, connection, peer, outgoing, incoming) = pair()
  assert server.send_and_finish(incoming, <<"response">>) == Ok(Nil)
  assert client.receive(outgoing, 32) == Ok(client.Data(<<"response">>, True))
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendAcknowledged)
  assert server.receive(incoming, 32) == Ok(server.Data(<<"request">>, True))
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendAcknowledged)
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_stop_after_request_fin_preserves_its_application_code_test() -> Nil {
  let #(listener, connection, peer, outgoing, incoming) = pair()
  assert server.receive(incoming, 32) == Ok(server.Data(<<"request">>, True))
  assert server.send(incoming, <<"prefix">>) == Ok(Nil)
  assert client.receive(outgoing, 32) == Ok(client.Data(<<"prefix">>, False))
  assert client.stop_sending(outgoing, 0x10c) == Ok(Nil)
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendStopped(0x10c))
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendStopped(0x10c))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_reset_is_distinct_from_peer_stop_and_acknowledgement_test() -> Nil {
  let #(listener, connection, peer, _, incoming) = pair()
  assert server.reset(incoming, 0x101) == Ok(Nil)
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendReset(0x101))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_timeout_does_not_poison_a_later_wait_test() -> Nil {
  let #(listener, connection, peer, outgoing, incoming) = pair()
  assert server.await_send_completion(incoming, 0)
    == Error(server.InvalidOperation)
  assert server.await_send_completion(incoming, 20)
    == Error(server.Failure(failure.Timeout(failure.Operation)))
  assert server.send_and_finish(incoming, <<"response">>) == Ok(Nil)
  assert client.receive(outgoing, 32) == Ok(client.Data(<<"response">>, True))
  assert server.await_send_completion(incoming, 1000)
    == Ok(server.SendAcknowledged)
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_close_preserves_its_kind_and_code_for_completion_waiters_test() -> Nil {
  let #(listener, connection, peer, _, incoming) = pair()
  let assert Ok(code) = quic_core.application_error_code(0x106)
  assert client.close_with_code(connection, code) |> result.is_ok
  assert server.await_send_completion(incoming, 1000)
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x106))))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_feed_and_stream_waiter_observe_the_same_completion_test() -> Nil {
  let #(listener, connection, peer, outgoing, incoming) = pair()
  let assert Ok(handle) = connection_handle(peer)
  let assert Ok(actor) = labelled_pid(peer, <<"quic_core.connection">>)
  assert server.send_and_finish(incoming, <<"response">>) == Ok(Nil)
  let stream_id = server.stream_id(incoming) |> quic_core.stream_id_value
  let #(registered, received, feed, completion, joined, released) =
    concurrent_observers(
      actor,
      fn() { server.next_send_completions(peer, 0, 2000) },
      fn() { server.await_send_completion(incoming, 2000) },
      fn() { client.receive(outgoing, 32) },
      fn() {
        connection_worker.send_completion_counts(handle)
        |> result.unwrap(#(-1, -1, -1))
      },
    )
  assert registered
  assert received == Ok(client.Data(<<"response">>, True))
  assert feed
    == Ok(
      server.SendCompletionBatch(1, [
        server.SendCompletionEvent(1, stream_id, server.SendAcknowledged),
      ]),
    )
  assert completion == Ok(server.SendAcknowledged)
  assert joined
  assert released
  // Both observers consumed independent notifications; terminal history stays available to a late subscriber and the per-stream query alike.
  assert server.next_send_completions(peer, 0, 1000) == feed
  assert server.await_send_completion(incoming, 1000) == completion
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completion_feed_timeout_releases_waiter_monitor_and_grant_test() -> Nil {
  let #(listener, connection, peer, _, _) = pair()
  assert server.next_send_completions(peer, 0, 20)
    == Error(server.Failure(failure.Timeout(failure.Operation)))
  assert completion_counts(peer) == Ok(#(0, 0, 4096))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enclosing_owner_exit_promptly_joins_feed_and_releases_reservation_test() -> Nil {
  let #(listener, connection, peer, _, _) = pair()
  let assert Ok(handle) = connection_handle(peer)
  let #(registered, outcome, joined, removed, prompt) =
    owner_exit_releases_waiter(
      fn() { server.completion_feed_owner() },
      fn(owner) {
        server.next_send_completions_until_owner_exits(peer, 0, 60_000, owner)
      },
      fn() {
        connection_worker.send_completion_counts(handle)
        |> result.unwrap(#(-1, -1, -1))
      },
    )
  assert registered
  assert outcome == Error(server.Failure(failure.Closed(failure.Peer, None)))
  assert joined
  assert removed
  assert prompt
  assert completion_counts(peer) == Ok(#(0, 0, 4096))
  cleanup(listener, connection, peer)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_close_wakes_all_completion_observers_and_releases_them_test() -> Nil {
  let #(listener, connection, peer, _, incoming) = pair()
  let assert Ok(handle) = connection_handle(peer)
  let assert Ok(actor) = labelled_pid(peer, <<"quic_core.connection">>)
  let assert Ok(code) = quic_core.application_error_code(0x106)
  let #(registered, closed, feed, completion, joined, released) =
    concurrent_observers(
      actor,
      fn() { server.next_send_completions(peer, 0, 2000) },
      fn() { server.await_send_completion(incoming, 2000) },
      fn() { client.close_with_code(connection, code) },
      fn() {
        connection_worker.send_completion_counts(handle)
        |> result.unwrap(#(-1, -1, -1))
      },
    )
  assert registered
  assert closed |> result.is_ok
  assert feed
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x106))))
  assert completion
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x106))))
  assert joined
  assert released
  cleanup(listener, connection, peer)
}

fn pair() -> #(
  server.Listener,
  client.Connection,
  server.Connection,
  client.Stream,
  server.Stream,
) {
  pair_with_memory(0)
}

fn pair_with_memory(
  memory: Int,
) -> #(
  server.Listener,
  client.Connection,
  server.Connection,
  client.Stream,
  server.Stream,
) {
  pair_with_limits(memory, 0)
}

fn pair_with_limits(
  memory: Int,
  client_memory: Int,
) -> #(
  server.Listener,
  client.Connection,
  server.Connection,
  client.Stream,
  server.Stream,
) {
  let assert Ok(certificate) = fixture("server.pem")
  let assert Ok(key) = fixture("server-key.pem")
  let assert Ok(ca) = fixture("ca.pem")
  let assert Ok(deadlines) =
    config.default_deadlines()
    |> config.with_deadline(failure.Operation, 2000)
  let assert Ok(configured) = server.new(certificate, key, "send-completion")
  let configured = case memory > 0 {
    False -> configured
    True -> {
      let assert Ok(limits) =
        config.with_limit(
          config.default_limits(),
          failure.EndpointMemory,
          memory,
        )
      server.with_limits(configured, limits)
    }
  }
  let assert Ok(listener) =
    configured
    |> server.with_address_family(quic_core.Ipv4)
    |> server.with_deadlines(deadlines)
    |> server.start
  let assert Ok(port) = server.port(listener)
  let assert Ok(configured) =
    client.new_with_ca_certificates("localhost", port, "send-completion", ca)
  let configured = case client_memory > 0 {
    False -> configured
    True -> {
      let assert Ok(limits) =
        config.with_limit(
          config.default_limits(),
          failure.EndpointMemory,
          client_memory,
        )
      client.with_limits(configured, limits)
    }
  }
  let assert Ok(connection) =
    configured
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_deadlines(deadlines)
    |> client.connect
  let assert Ok(peer) = server.accept(listener)
  let assert Ok(outgoing) = client.open_bidirectional(connection)
  assert client.send_and_finish(outgoing, <<"request">>) == Ok(Nil)
  let assert Ok(server.IncomingStream(incoming, server.Bidirectional)) =
    server.accept_stream(peer)
  #(listener, connection, peer, outgoing, incoming)
}

fn cleanup(
  listener: server.Listener,
  connection: client.Connection,
  peer: server.Connection,
) -> Nil {
  let _client_closed = client.close(connection)
  let _server_closed = server.close(peer)
  assert server.stop(listener) |> result.is_ok
}
