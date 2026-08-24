import gleam/bit_array
import gleam/http/request
import gleeunit/should
import http3/client
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
