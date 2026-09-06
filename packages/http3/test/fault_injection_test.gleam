import gleam/bit_array
import gleam/http/request
import gleeunit/should
import http3/client
import http3/server
import http3/transport
import http3_test_support

pub fn fault_injection_duplicate_packet_is_idempotent_test() -> Nil {
  assert_round_trip(http3_test_support.with_duplicating_proxy)
}

pub fn fault_injection_corrupt_packet_is_discarded_and_retransmitted_test() -> Nil {
  assert_round_trip(http3_test_support.with_corrupting_proxy)
}

pub fn fault_injection_delayed_packet_is_recovered_test() -> Nil {
  assert_round_trip(http3_test_support.with_delaying_proxy)
}

pub fn fault_injection_packet_loss_is_recovered_test() -> Nil {
  assert_round_trip(http3_test_support.with_lossy_server)
}

// The proxy starts its two-datagram loss window only after forwarding the
// first server packet following `arm`. This pins the full shutdown path which
// a bursty coverage run exposed: response delivery succeeds, its delayed ACK
// and the client's first CONNECTION_CLOSE can both disappear, and a server
// retransmission still elicits a retained close before either finite deadline.
pub fn graceful_drain_survives_post_response_ack_and_close_loss_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let configuration =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_timeout(6000)
    |> should.be_ok
  let listener = server.start(configuration) |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  http3_test_support.with_armed_client_loss_proxy(
    port,
    ca_certificate,
    fn(proxy_port, ca_certificate, arm) {
      let client_task =
        http3_test_support.start_task(fn() {
          run_close_loss_client(proxy_port, ca_certificate)
        })
      let incoming = server.accept(listener) |> should.be_ok
      let _body = server.read_body(incoming) |> should.be_ok
      arm()
      server.respond(incoming, 204, [], <<>>) |> should.be_ok

      let drain = server.graceful_stop(listener)
      let #(valid_response, close) = http3_test_support.await_task(client_task)

      assert valid_response == True
      assert close == Ok(client.Closed)
      assert drain == Ok(server.Drained)
    },
  )
  assert server.stop(listener) == Ok(server.AlreadyStopped)
}

pub fn fault_injection_reordered_packets_are_recovered_test() -> Nil {
  assert_round_trip(http3_test_support.with_reordering_proxy)
}

pub fn fault_injection_path_mtu_limit_keeps_requests_live_test() -> Nil {
  http3_test_support.with_mtu_limited_proxy(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 6000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let connection =
      client.connect(configuration, "localhost", port) |> should.be_ok

    // PMTU probing starts after the connection has been idle for its fixed
    // probe interval. Do not make this assertion depend on request latency.
    http3_test_support.pause_milliseconds(75)
    run_requests(connection: connection, port: port, remaining: 8)

    let connection_transport = client.connection_transport(connection)
    assert transport.maximum_transmission_unit(connection_transport) == Ok(1200)
    assert client.close(connection) == Ok(client.Closed)
  })
}

fn assert_round_trip(with_proxy: fn(fn(Int, BitArray) -> Nil) -> Nil) -> Nil {
  with_proxy(fn(port, ca_certificate) {
    let configuration = client.with_timeout(client.new(), 6000) |> should.be_ok
    let configuration =
      client.with_ca_certificate(configuration, ca_certificate) |> should.be_ok
    let request =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/large")
      |> request.set_body(<<>>)

    let reply = client.send(configuration, request) |> should.be_ok
    assert reply.status == 200
    assert bit_array.byte_size(reply.body) == 64
  })
}

fn run_close_loss_client(
  port: Int,
  ca_certificate: BitArray,
) -> #(Bool, Result(client.CloseResult, client.Error)) {
  let configuration =
    client.new()
    |> client.with_ca_certificate(ca_certificate)
    |> should.be_ok
    |> client.with_timeout(6000)
    |> should.be_ok
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/closing-loss")
    |> request.set_body(Nil)
  let stream = client.open_stream(connection, outbound) |> should.be_ok
  client.finish(stream) |> should.be_ok
  let valid_response = case client.next_event(stream) |> should.be_ok {
    client.Response(204, _) -> True
    _ -> False
  }
  receive_response(stream)
  #(valid_response, client.close(connection))
}

fn run_requests(
  connection connection: client.Connection,
  port port: Int,
  remaining remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      let request =
        request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_path("/large")
        |> request.set_body(Nil)
      let stream = client.open_stream(connection, request) |> should.be_ok
      client.finish(stream) |> should.be_ok
      // nolint: assert_ok_pattern -- the response head is the fixture invariant.
      let assert client.Response(200, _) =
        client.next_event(stream) |> should.be_ok
      receive_response(stream)
      run_requests(connection: connection, port: port, remaining: remaining - 1)
    }
  }
}

fn receive_response(stream: client.Stream) -> Nil {
  case client.next_event(stream) |> should.be_ok {
    client.End -> Nil
    client.Data(_) | client.Trailers(_) | client.InformationalResponse(_, _) ->
      receive_response(stream)
    client.Response(_, _) -> receive_response(stream)
  }
}
