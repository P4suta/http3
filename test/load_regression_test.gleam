import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/result
import gleeunit/should
import http3/client
import http3/server
import http3_test_support

const concurrent_connections = 32

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn drains_bursty_concurrent_handshakes_over_real_udp_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let server_configuration =
    server.new(certificate, private_key) |> should.be_ok
  let server_configuration =
    server.with_timeout(server_configuration, 5000) |> should.be_ok
  let listener = server.start(server_configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let client_configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
    |> client.with_timeout(5000)
    |> should.be_ok
  let tasks =
    int.range(from: 0, to: concurrent_connections, with: [], run: fn(tasks, _) {
      let task =
        http3_test_support.start_task(fn() {
          let outbound =
            request.new()
            |> request.set_host("localhost")
            |> request.set_port(port)
            |> request.set_path("/burst")
            |> request.set_body(<<>>)
          client.send(client_configuration, outbound)
        })
      [task, ..tasks]
    })
  let server_result = serve_requests(listener, concurrent_connections)
  let stop_result = server.stop(listener)
  let client_results = list.map(tasks, http3_test_support.await_task)
  assert server_result == Ok(Nil)
  assert stop_result == Ok(server.Stopped)
  assert_client_results(client_results)
}

fn assert_client_results(
  results: List(Result(response.Response(BitArray), client.Error)),
) -> Nil {
  case results {
    [] -> Nil
    [result, ..rest] -> {
      let response = result |> should.be_ok
      assert response.status == 204
      assert response.body == <<>>
      assert_client_results(rest)
    }
  }
}

fn serve_requests(
  listener: server.Listener,
  remaining: Int,
) -> Result(Nil, server.Error) {
  case remaining {
    0 -> Ok(Nil)
    _ -> {
      use incoming <- result.try(server.accept(listener))
      use _ <- result.try(server.read_body(incoming))
      use _ <- result.try(server.respond(incoming, 204, [], <<>>))
      serve_requests(listener, remaining - 1)
    }
  }
}
