import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/udp

@external(erlang, "gleam_quic_test_ffi", "inject_relay_connection_reset")
fn inject_relay_connection_reset(relay: udp.Relay) -> Nil

@external(erlang, "gleam_quic_test_ffi", "socket_buffer_bytes")
fn socket_buffer_bytes(socket: udp.Socket) -> List(Int)

/// The inet user-level receive buffer sizes the binary allocated for every
/// received datagram, so it only has to cover the largest UDP payload.
const expected_socket_buffer_bytes = 65_536

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn bounds_socket_receive_buffer_to_one_datagram_test() -> Nil {
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(socket) = udp.open(ephemeral)
  let buffers = socket_buffer_bytes(socket)
  let assert Ok(Nil) = udp.close(socket)
  assert buffers == [expected_socket_buffer_bytes]

  case udp.open_dual_stack(0) {
    Error(_) -> Nil
    Ok(dual) -> {
      let dual_buffers = socket_buffer_bytes(dual)
      let assert Ok(Nil) = udp.close(dual)
      assert dual_buffers
        == [expected_socket_buffer_bytes, expected_socket_buffer_bytes]
      Nil
    }
  }
}

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
  let assert Ok(localhost) = udp.resolve("localhost", udp.Ipv4)
  let localhost_bytes = list.map(localhost, udp.address_bytes)
  assert list.unique(localhost_bytes) == localhost_bytes
  assert udp.resolve("", udp.Any) == Error(udp.InvalidInput)
  assert udp.resolve("bad\u{0000}name", udp.Any) == Error(udp.InvalidInput)
  let assert Ok(timed) = udp.resolve_with_timeout("127.0.0.1", udp.Any, 1000)
  assert list.any(timed, fn(address) {
    udp.address_bytes(address) == <<127, 0, 0, 1>>
  })
  assert udp.resolve_with_timeout("localhost", udp.Any, 0)
    == Error(udp.InvalidInput)
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
pub fn active_once_delivers_exactly_one_bounded_mailbox_datagram_test() -> Nil {
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(sender) = udp.open(ephemeral)
  let assert Ok(receiver) = udp.open(ephemeral)
  let assert Ok(receiver_endpoint) = udp.local_endpoint(receiver)
  let selector =
    process.new_selector()
    |> process.select_other(fn(value) { value })

  let assert Ok(Nil) = udp.activate_once(receiver)
  let assert Ok(Nil) =
    udp.send(sender, receiver_endpoint, <<"first">>, ecn.NotEct)
  let assert Ok(Nil) =
    udp.send(sender, receiver_endpoint, <<"second">>, ecn.NotEct)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok(udp.Datagram(_, <<"first">>, _)) =
    udp.receive_active(receiver, message)
  assert process.selector_receive(selector, within: 10) == Error(Nil)

  let assert Ok(Nil) = udp.activate_once(receiver)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok(udp.Datagram(_, <<"second">>, _)) =
    udp.receive_active(receiver, message)
  let assert Ok(Nil) = udp.close(sender)
  let assert Ok(Nil) = udp.close(receiver)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn relay_waits_for_credit_before_forwarding_another_batch_test() -> Nil {
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(sender) = udp.open(ephemeral)
  let assert Ok(receiver) = udp.open(ephemeral)
  let assert Ok(receiver_endpoint) = udp.local_endpoint(receiver)
  let selector =
    process.new_selector()
    |> process.select_other(fn(value) { value })
  let assert Ok(relay) = udp.start_relay(receiver)

  let assert Ok(Nil) =
    udp.send(sender, receiver_endpoint, <<"first">>, ecn.NotEct)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok([udp.Datagram(_, <<"first">>, _)]) =
    udp.receive_relay_batch(relay, message)

  let assert Ok(Nil) =
    udp.send(sender, receiver_endpoint, <<"second">>, ecn.NotEct)
  assert process.selector_receive(selector, within: 10) == Error(Nil)

  let assert Ok(Nil) = udp.continue_relay(relay)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok([udp.Datagram(_, <<"second">>, _)]) =
    udp.receive_relay_batch(relay, message)

  let assert Ok(Nil) = udp.stop_relay(relay)
  let assert Ok(Nil) = udp.close(sender)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn relay_ignores_connection_local_icmp_reset_test() -> Nil {
  let assert Ok(loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(loopback, 0)
  let assert Ok(sender) = udp.open(ephemeral)
  let assert Ok(receiver) = udp.open(ephemeral)
  let assert Ok(receiver_endpoint) = udp.local_endpoint(receiver)
  let selector =
    process.new_selector()
    |> process.select_other(fn(value) { value })
  let assert Ok(relay) = udp.start_relay(receiver)

  inject_relay_connection_reset(relay)
  let assert Ok(Nil) =
    udp.send(sender, receiver_endpoint, <<"still-listening">>, ecn.NotEct)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok([udp.Datagram(_, <<"still-listening">>, _)]) =
    udp.receive_relay_batch(relay, message)

  let assert Ok(Nil) = udp.stop_relay(relay)
  let assert Ok(Nil) = udp.close(sender)
  Nil
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
  let assert Ok(Nil) =
    udp.send(left_socket, right, <<"ipv6-second">>, ecn.NotEct)
  let assert Ok(udp.Datagram(peer, <<"ipv6-quic">>, _)) =
    udp.receive(right_socket, 1000)
  assert udp.endpoint_parts(peer) == udp.endpoint_parts(left)
  let assert Ok(udp.Datagram(second_peer, <<"ipv6-second">>, _)) =
    udp.receive(right_socket, 1000)
  assert udp.endpoint_parts(second_peer) == udp.endpoint_parts(left)
  let assert Ok(Nil) = udp.close(left_socket)
  let assert Ok(Nil) = udp.close(right_socket)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exchanges_consecutive_ipv6_datagrams_from_wildcard_sockets_test() -> Nil {
  let assert Ok(wildcard) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0)
  let assert Ok(loopback) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(ephemeral) = udp.endpoint(wildcard, 0)
  let assert Ok(left_socket) = udp.open(ephemeral)
  let assert Ok(right_socket) = udp.open(ephemeral)
  let assert Ok(left_local) = udp.local_endpoint(left_socket)
  let assert Ok(right_local) = udp.local_endpoint(right_socket)
  let #(_, left_port) = udp.endpoint_parts(left_local)
  let #(_, right_port) = udp.endpoint_parts(right_local)
  let assert Ok(left) = udp.endpoint(loopback, left_port)
  let assert Ok(right) = udp.endpoint(loopback, right_port)

  let assert Ok(Nil) = udp.send(left_socket, right, <<0:9600>>, ecn.NotEct)
  let assert Ok(Nil) = udp.send(left_socket, right, <<1:5384>>, ecn.NotEct)
  let assert Ok(udp.Datagram(_, first, _)) = udp.receive(right_socket, 1000)
  let assert Ok(udp.Datagram(_, second, _)) = udp.receive(right_socket, 1000)
  assert bit_array.byte_size(first) == 1200
  assert bit_array.byte_size(second) == 673
  let assert Ok(Nil) = udp.send(right_socket, left, <<2:9600>>, ecn.NotEct)
  let assert Ok(udp.Datagram(_, reply, _)) = udp.receive(left_socket, 1000)
  assert bit_array.byte_size(reply) == 1200
  let assert Ok(Nil) = udp.close(left_socket)
  let assert Ok(Nil) = udp.close(right_socket)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dual_stack_socket_accepts_ipv4_and_ipv6_datagrams_test() -> Nil {
  let assert Ok(ipv4_loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ipv6_loopback) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(ipv4_ephemeral) = udp.endpoint(ipv4_loopback, 0)
  let assert Ok(ipv6_ephemeral) = udp.endpoint(ipv6_loopback, 0)
  let assert Ok(ipv4_sender) = udp.open(ipv4_ephemeral)
  let assert Ok(ipv6_sender) = udp.open(ipv6_ephemeral)
  let assert Ok(ipv4_sender_endpoint) = udp.local_endpoint(ipv4_sender)
  let assert Ok(ipv6_sender_endpoint) = udp.local_endpoint(ipv6_sender)
  let assert Ok(receiver) = udp.open_dual_stack(0)
  let assert Ok(local) = udp.local_endpoint(receiver)
  let #(_, port) = udp.endpoint_parts(local)
  let assert Ok(ipv4_receiver) = udp.endpoint(ipv4_loopback, port)
  let assert Ok(ipv6_receiver) = udp.endpoint(ipv6_loopback, port)

  let assert Ok(Nil) =
    udp.send(ipv4_sender, ipv4_receiver, <<"ipv4">>, ecn.NotEct)
  let assert Ok(Nil) =
    udp.send(ipv6_sender, ipv6_receiver, <<"ipv6">>, ecn.NotEct)
  let assert Ok(udp.Datagram(_, first, _)) = udp.receive(receiver, 1000)
  let assert Ok(udp.Datagram(_, second, _)) = udp.receive(receiver, 1000)
  assert {
    first == <<"ipv4">>
    && second == <<"ipv6">>
    || first == <<"ipv6">>
    && second == <<"ipv4">>
  }
  let assert Ok(Nil) =
    udp.send(receiver, ipv4_sender_endpoint, <<"to-ipv4">>, ecn.NotEct)
  let assert Ok(Nil) =
    udp.send(receiver, ipv6_sender_endpoint, <<"to-ipv6">>, ecn.NotEct)
  let assert Ok(udp.Datagram(_, <<"to-ipv4">>, _)) =
    udp.receive(ipv4_sender, 1000)
  let assert Ok(udp.Datagram(_, <<"to-ipv6">>, _)) =
    udp.receive(ipv6_sender, 1000)

  let assert Ok(Nil) = udp.close(ipv4_sender)
  let assert Ok(Nil) = udp.close(ipv6_sender)
  let assert Ok(Nil) = udp.close(receiver)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn dual_stack_relay_batches_ipv4_and_ipv6_datagrams_test() -> Nil {
  let assert Ok(ipv4_loopback) = udp.ipv4(127, 0, 0, 1)
  let assert Ok(ipv6_loopback) = udp.ipv6(0, 0, 0, 0, 0, 0, 0, 1)
  let assert Ok(ipv4_ephemeral) = udp.endpoint(ipv4_loopback, 0)
  let assert Ok(ipv6_ephemeral) = udp.endpoint(ipv6_loopback, 0)
  let assert Ok(ipv4_sender) = udp.open(ipv4_ephemeral)
  let assert Ok(ipv6_sender) = udp.open(ipv6_ephemeral)
  let assert Ok(receiver) = udp.open_dual_stack(0)
  let assert Ok(local) = udp.local_endpoint(receiver)
  let #(_, port) = udp.endpoint_parts(local)
  let assert Ok(ipv4_receiver) = udp.endpoint(ipv4_loopback, port)
  let assert Ok(ipv6_receiver) = udp.endpoint(ipv6_loopback, port)
  let selector =
    process.new_selector()
    |> process.select_other(fn(value) { value })

  let assert Ok(Nil) =
    udp.send(ipv4_sender, ipv4_receiver, <<"ipv4-relay">>, ecn.NotEct)
  let assert Ok(Nil) =
    udp.send(ipv6_sender, ipv6_receiver, <<"ipv6-relay">>, ecn.NotEct)
  let assert Ok(relay) = udp.start_relay(receiver)
  let assert Ok(message) = process.selector_receive(selector, within: 1000)
  let assert Ok(batch) = udp.receive_relay_batch(relay, message)
  let payloads =
    list.map(batch, fn(datagram) {
      let udp.Datagram(_, payload, _) = datagram
      payload
    })
  assert list.contains(payloads, <<"ipv4-relay">>)
  assert list.contains(payloads, <<"ipv6-relay">>)

  let assert Ok(Nil) = udp.stop_relay(relay)
  let assert Ok(Nil) = udp.close(ipv4_sender)
  let assert Ok(Nil) = udp.close(ipv6_sender)
  Nil
}
