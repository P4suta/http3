import gleam/bit_array
import gleam/list
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/udp

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_ipv4_and_ipv6_endpoints_test() -> Nil {
  let assert Ok(ipv4) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ipv4_endpoint) = udp.endpoint(ipv4, 443)
  assert udp.endpoint_parts(ipv4_endpoint) == #(<<127, 0, 0, 1>>, 443)
  assert udp.ipv4(256, 0, 0, 1) == Error(udp.InvalidInput)
  assert udp.endpoint(ipv4, 65_536) == Error(udp.InvalidInput)

  let assert Ok(ipv6) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(ipv6_endpoint) = udp.endpoint(ipv6, 8443)
  let #(ipv6_bytes, ipv6_port) = udp.endpoint_parts(ipv6_endpoint)
  assert bit_array.byte_size(ipv6_bytes) == 16
  assert ipv6_port == 8443
  assert udp.ipv6(65_536, 0, 0, 0, 0, 0, 0, 1) == Error(udp.InvalidInput)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resolves_literal_addresses_without_runtime_terms_test() -> Nil {
  let assert Ok(addresses) = udp.resolve("127.0.0.1", udp.Ipv4)
  assert list.any(addresses, fn(address) {
    udp.address_bytes(address) == <<127, 0, 0, 1>>
  })
  assert udp.resolve("", udp.Any) == Error(udp.InvalidInput)
  assert udp.resolve("bad\u{0000}name", udp.Any) == Error(udp.InvalidInput)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exchanges_real_ipv4_udp_datagrams_and_cleans_up_test() -> Nil {
  let started = udp.monotonic_millisecond()
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(left_socket) = udp.open(ephemeral)
  let assert Ok(right_socket) = udp.open(ephemeral)
  let assert Ok(left) = udp.local_endpoint(left_socket)
  let assert Ok(right) = udp.local_endpoint(right_socket)
  let #(_, left_port) = udp.endpoint_parts(left)
  let #(_, right_port) = udp.endpoint_parts(right)
  assert left_port > 0
  assert right_port > 0
  assert left_port != right_port

  let marking = case
    udp.supports_ecn(left_socket) && udp.supports_ecn(right_socket)
  {
    True -> ecn.Ect0
    False -> ecn.NotEct
  }
  let assert Ok(Nil) = udp.send(left_socket, right, <<"native-quic">>, marking)
  let assert Ok(udp.Datagram(peer, payload, received_marking)) =
    udp.receive(right_socket, 1000)
  assert udp.endpoint_parts(peer) == udp.endpoint_parts(left)
  assert payload == <<"native-quic">>
  case marking {
    ecn.Ect0 -> {
      assert received_marking == packet_space.Ect0
    }
    ecn.NotEct -> {
      assert received_marking == packet_space.NotEct
    }
    ecn.Ect1 -> {
      assert received_marking == packet_space.Ect1
    }
  }

  let assert Ok(Nil) = udp.send(right_socket, left, <<"response">>, ecn.NotEct)
  let assert Ok(udp.Datagram(_, <<"response">>, _)) =
    udp.receive(left_socket, 1000)
  assert udp.receive(right_socket, 1) == Error(udp.Timeout)
  let assert Ok(Nil) = udp.close(left_socket)
  let assert Ok(Nil) = udp.close(left_socket)
  let assert Ok(Nil) = udp.close(right_socket)
  assert udp.receive(left_socket, 1) == Error(udp.Closed)
  assert udp.monotonic_millisecond() >= started
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exchanges_real_ipv6_udp_datagrams_test() -> Nil {
  let assert Ok(loopback) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(left_socket) = udp.open(ephemeral)
  let assert Ok(right_socket) = udp.open(ephemeral)
  let assert Ok(left) = udp.local_endpoint(left_socket)
  let assert Ok(right) = udp.local_endpoint(right_socket)
  let #(left_address, left_port) = udp.endpoint_parts(left)
  let #(right_address, right_port) = udp.endpoint_parts(right)
  assert bit_array.byte_size(left_address) == 16
  assert bit_array.byte_size(right_address) == 16
  assert left_port > 0
  assert right_port > 0

  let assert Ok(Nil) = udp.send(left_socket, right, <<"ipv6-quic">>, ecn.NotEct)
  let assert Ok(udp.Datagram(peer, <<"ipv6-quic">>, _)) =
    udp.receive(right_socket, 1000)
  assert udp.endpoint_parts(peer) == udp.endpoint_parts(left)
  let assert Ok(Nil) = udp.close(left_socket)
  let assert Ok(Nil) = udp.close(right_socket)
  Nil
}
