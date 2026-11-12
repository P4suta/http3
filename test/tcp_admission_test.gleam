import gleam/http/request
import gleam/int
import gleam/result
import http/body
import http/client
import http/error
import http/internal/transport
import http_test_support

@external(erlang, "http_tcp_admission_test_ffi", "dial_failure_cancels_reservation")
pub fn failed_dns_or_dial_releases_its_reservation_test() -> Nil

@external(erlang, "http_tcp_admission_test_ffi", "refusal_never_calls_dial")
pub fn refused_reservation_never_invokes_the_dial_callback_test() -> Nil

@external(erlang, "http_tcp_admission_test_ffi", "adoption_preserves_capacity")
pub fn raw_socket_adoption_preserves_reserved_capacity_test() -> Nil

@external(erlang, "http_tcp_admission_test_ffi", "replacement_is_atomic")
pub fn tls_replacement_preserves_capacity_despite_stale_cleanup_test() -> Nil

@external(erlang, "http_tcp_admission_test_ffi", "cancelled_adoption_closes_socket")
pub fn cancelled_reservation_closes_late_socket_test() -> Nil

@external(erlang, "http_tcp_admission_test_ffi", "lifecycle_close_closes_adopted_socket")
pub fn closing_lifecycle_closes_reserved_socket_test() -> Nil

pub fn exhausted_connection_budget_rejects_before_tcp_accept_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n":utf8,
        >>),
      )
      let accepted = case transport.accept(listener, 150) {
        Ok(second) -> {
          let _closed = transport.close(second)
          True
        }
        Error(transport.Timeout) -> False
        Error(failure) -> failure != transport.Timeout
      }
      let _closed = transport.close(first)
      Ok(accepted)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_pool_limits(client.PoolLimits(1, 1, 30_000))
  let assert Ok(running) = client.start(config)
  let assert Ok(outgoing) =
    request.to("http://127.0.0.1:" <> int.to_string(port) <> "/")
  let outgoing = request.set_body(outgoing, body.empty())
  let assert Ok(active) = client.exchange(running, outgoing)
  let rejected = case client.exchange(running, outgoing) {
    Error(failure) -> error.kind(failure) == error.Resource(error.Connections)
    Ok(unexpected) -> {
      body.cancel(client.response(unexpected).body)
      False
    }
  }
  let observed = http_test_support.await_task(server_task)
  body.cancel(client.response(active).body)
  let _closed = client.close(running)
  let _stopped = transport.stop(listener)
  assert rejected
  assert observed == Ok(False)
}

pub fn failed_tls_handshake_releases_the_connection_reservation_test() -> Nil {
  let assert Ok(rejecting) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, rejecting_port)) = transport.local_endpoint(rejecting)
  let reject_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(rejecting, 1000))
      transport.close(socket)
    })
  let assert Ok(serving) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, serving_port)) = transport.local_endpoint(serving)
  let serve_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(serving, 1000))
      use _ <- result.try(transport.read(socket, 4096, 1000))
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      transport.close(socket)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.without_retries
    |> client.with_pool_limits(client.PoolLimits(1, 1, 30_000))
  let assert Ok(running) = client.start(config)
  let assert Ok(rejected_request) =
    request.to("https://localhost:" <> int.to_string(rejecting_port) <> "/")
  let rejected =
    client.exchange(running, request.set_body(rejected_request, body.empty()))
    |> result.is_error
  let assert Ok(accepted_request) =
    request.to("http://127.0.0.1:" <> int.to_string(serving_port) <> "/")
  let accepted = case
    client.exchange(running, request.set_body(accepted_request, body.empty()))
  {
    Ok(completed) -> {
      body.cancel(client.response(completed).body)
      True
    }
    Error(failure) -> {
      assert error.kind(failure) != error.Resource(error.Connections)
      False
    }
  }
  let rejected_peer = http_test_support.await_task(reject_task)
  let accepted_peer = http_test_support.await_task(serve_task)
  let _closed = client.close(running)
  let _stopped = transport.stop(rejecting)
  let _stopped = transport.stop(serving)
  assert rejected
  assert accepted
  assert rejected_peer == Ok(Nil)
  assert accepted_peer == Ok(Nil)
}
