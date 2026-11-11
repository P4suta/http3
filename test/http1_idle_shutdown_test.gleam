import gleam/erlang/process
import gleam/http/response
import gleam/result
import http/body
import http/error
import http/internal/transport
import http/server
import http_test_support

@external(erlang, "http1_idle_stop_test_ffi", "await_head_read")
fn await_head_read(listener: server.Listener, milliseconds: Int) -> Bool

pub fn stop_joins_an_idle_tcp_connection_without_a_failure_test() -> Nil {
  idle_shutdown(False, ListenerStop)
}

pub fn stop_joins_an_idle_tls_connection_without_a_failure_test() -> Nil {
  idle_shutdown(True, ListenerStop)
}

pub fn empty_peer_tcp_close_is_a_normal_connection_end_test() -> Nil {
  idle_shutdown(False, PeerClose)
}

pub fn empty_peer_tls_close_is_a_normal_connection_end_test() -> Nil {
  idle_shutdown(True, PeerClose)
}

pub fn partial_tcp_head_close_still_records_a_protocol_failure_test() -> Nil {
  idle_shutdown(False, TruncatedHead)
}

pub fn partial_tls_head_close_still_records_a_protocol_failure_test() -> Nil {
  idle_shutdown(True, TruncatedHead)
}

type Ending {
  ListenerStop
  PeerClose
  TruncatedHead
}

fn idle_shutdown(tls: Bool, ending: Ending) -> Nil {
  let executor =
    server.start(server.defaults(), fn(_, _) {
      Ok(response.new(204) |> response.set_body(body.empty()))
    })
    |> require_ok
  let config =
    server.http1_defaults()
    |> server.allow_http1_cleartext
    |> server.with_http1_timeouts(
      idle_milliseconds: 5000,
      operation_milliseconds: 5000,
      tls_milliseconds: 1000,
      drain_milliseconds: 1000,
      send_milliseconds: 1000,
    )
    |> require_ok
  let #(certificate, key, ca) = http_test_support.server_credentials()
  let listener =
    case tls {
      False -> server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
      True ->
        server.listen_http1_tls(
          executor,
          <<127, 0, 0, 1>>,
          0,
          config,
          certificate,
          key,
          "localhost",
        )
    }
    |> require_ok
  let socket =
    transport.connect(
      "127.0.0.1",
      server.listener_endpoint(listener).port,
      1000,
      1000,
    )
    |> require_ok
  let socket = case tls {
    False -> socket
    True -> {
      let transport.TlsReady(socket, _, _) =
        transport.upgrade_client_tls(
          socket,
          "localhost",
          [ca],
          [<<"http/1.1">>],
          1000,
        )
        |> require_ok
      socket
    }
  }
  // The listener's exact child must be blocked in the real head receive;
  // a published startup counter alone cannot prove the read has begun.
  let receiving = await_head_read(listener, 1000)
  let before = server.http1_listener_snapshot(listener) |> require_ok
  let ended = case ending {
    ListenerStop -> server.stop_listener(listener) |> result.is_ok
    PeerClose -> transport.close(socket) |> result.is_ok
    TruncatedHead -> {
      let sent = transport.send(socket, <<"GET /unfinished HTTP/1.1\r\nHost:">>)
      let closed = transport.close(socket)
      result.is_ok(sent) && result.is_ok(closed)
    }
  }
  let after =
    await_exit(listener, transport.monotonic_millisecond() + 1000)
    |> require_ok
  let listener_stopped = server.stop_listener(listener) |> result.is_ok
  let socket_closed = transport.close(socket) |> result.is_ok
  let executor_stopped = server.stop(executor) |> result.is_ok
  assert receiving
  assert before.started_connections == 1 && before.active_connections == 1
  assert before.parsed_request_heads == 0 && before.connection_failures == 0
  assert ended && listener_stopped && socket_closed && executor_stopped
  assert after.consistent && after.active_connections == 0
  assert after.exited_connections == 1
  assert after.parsed_request_heads == 0 && after.handler_dispatches == 0
  assert after.connection_failures
    == case ending {
      TruncatedHead -> 1
      _ -> 0
    }
}

fn await_exit(
  listener: server.Listener,
  deadline: Int,
) -> Result(server.Http1ListenerSnapshot, error.Error) {
  use snapshot <- result.try(server.http1_listener_snapshot(listener))
  case
    snapshot.active_connections == 0
    || transport.monotonic_millisecond() >= deadline
  {
    True -> Ok(snapshot)
    False -> {
      process.sleep(1)
      await_exit(listener, deadline)
    }
  }
}

// nolint: avoid_panic, thrown_away_error -- Fixed setup message excludes all sockets, certificates, and process values.
fn require_ok(value: Result(value, failure)) -> value {
  case value {
    Ok(value) -> value
    Error(_) -> panic as "idle shutdown fixture setup failed"
  }
}
