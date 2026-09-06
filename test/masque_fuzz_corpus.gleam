//// Deterministic retained and generated inputs for the public MASQUE UDP
//// receive boundary. In addition to parser totality, every input proves that
//// exactly one finite, payload-redacted diagnostic counter advances.

import gleam/bit_array
import gleam/list
import gleam/option.{Some}
import gleam/result
import http/masque
import http/status
import http3/capsule as http3_capsule

const generator_modulus = 2_147_483_647

/// Exercise retained regressions and a reproducible generated corpus.
pub fn exercise(generated_cases: Int) -> Int {
  exercise_from(1_597_463_007, generated_cases)
}

/// Exercise the retained corpus and a deterministic generated shard.
pub fn exercise_from(seed: Int, generated_cases: Int) -> Int {
  let retained = retained_inputs()
  list.each(retained, exercise_one)
  exercise_generated(seed, generated_cases)
  list.length(retained) + generated_cases
}

fn exercise_generated(seed: Int, remaining: Int) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let seed = next_seed(seed)
      let length = seed % 257
      let #(seed, bytes) = generate_bytes(seed, length, <<>>)
      exercise_one(bytes)
      exercise_generated(seed, remaining - 1)
    }
  }
}

fn exercise_one(bytes: BitArray) -> Nil {
  let configured_limits = limits()
  assert observe_result(masque.decode_udp_datagram(bytes, configured_limits))
  assert observe_result(masque.decode_capsule(
    http3_capsule.Datagram(bytes),
    configured_limits,
  ))

  let assert Ok(receiver) = masque.udp_receiver(configured_limits)
  let assert masque.DropDatagram(receiver, masque.RequestNotReady) =
    masque.receive_proxy_datagram(receiver, bytes)
  assert masque.udp_receiver_snapshot(receiver)
    == masque.UdpReceiverSnapshot(False, 0, 1, 0, 0, 0)

  let receiver = masque.activate_udp_receiver(receiver)
  let outcome = masque.receive_proxy_datagram(receiver, bytes)
  let receiver = outcome_receiver(outcome)
  let snapshot = masque.udp_receiver_snapshot(receiver)
  assert snapshot.active
  assert snapshot.dropped_before_request == 1
  assert snapshot.accepted
    + snapshot.dropped_unknown_context
    + snapshot.aborts_required
    == 1

  case outcome {
    masque.ForwardPayload(_, payload) -> {
      assert masque.decode_udp_datagram(bytes, configured_limits) == Ok(payload)
    }
    masque.DropDatagram(_, reason) -> {
      assert reason != masque.RequestNotReady
    }
    masque.AbortRequestStream(_, _) -> {
      assert result.is_error(masque.decode_udp_datagram(
        bytes,
        configured_limits,
      ))
    }
  }
  assert_proxy_setup_answer_validation(bytes)
}

fn assert_proxy_setup_answer_validation(bytes: BitArray) -> Nil {
  let target = masque.UdpTarget("fuzz-target.example", 443)
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<0, 0, 0, 0>>), 0),
    )
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv6(<<0:size(128)>>), 0),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let socket_setup_timeout = 100 + bit_array.byte_size(bytes) % 50
  let socket_operation_timeout = 50 + bit_array.byte_size(bytes) % 50
  let assert Ok(config) =
    masque.proxy_setup_config_with_socket_timeouts(
      status.TokenIdentifier("fuzz.proxy"),
      dns_timeout_milliseconds: 100,
      socket_setup_timeout_milliseconds: socket_setup_timeout,
      socket_operation_timeout_milliseconds: socket_operation_timeout,
      maximum_adapter_heap_words: 16_384,
    )
  let answer = case bit_array.bit_size(bytes) == 128 {
    True -> masque.Ipv6(bytes)
    False -> masque.Ipv4(bytes)
  }
  let outcome =
    masque.establish_udp_proxy(
      authorized,
      config,
      resolver: fn(_, _) { Ok([answer]) },
      open_socket: fn(_, timeout_milliseconds) {
        assert timeout_milliseconds == socket_setup_timeout
        Ok(
          masque.udp_socket_resource(Nil, fn(timeout_milliseconds) {
            assert timeout_milliseconds == socket_operation_timeout
            Ok(Nil)
          }),
        )
      },
    )
  case bit_array.bit_size(bytes), outcome {
    32, masque.UdpProxyReady(tunnel: tunnel, ..)
    | 128, masque.UdpProxyReady(tunnel: tunnel, ..)
    -> {
      let peer = masque.udp_proxy_peer(tunnel)
      let spoofed = masque.UdpEndpoint(masque.Ipv4(<<203, 0, 113, 9>>), 9)
      let assert masque.DiscardUdpPacket(
        tunnel: tunnel,
        reason: masque.SocketSourceMismatch,
      ) = masque.receive_udp_socket_packet(tunnel, spoofed, bytes)
      let assert masque.ForwardHttpDatagram(
        tunnel: tunnel,
        datagram: <<0, bytes:bits>>,
      ) = masque.receive_udp_socket_packet(tunnel, peer, bytes)
      let session =
        masque.bind_udp_proxy_stream(
          tunnel,
          masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
        )
      let #(termination, closed) = case termination_selector(bytes) {
        0 -> #(
          masque.SocketUnusable,
          masque.notify_udp_socket_unusable(session),
        )
        1 -> #(
          masque.RequestStreamEnded,
          masque.notify_udp_request_stream_ended(session),
        )
        _ -> #(
          masque.ApplicationClosed,
          masque.close_udp_proxy_session(session),
        )
      }
      assert closed == Ok(Nil)
      let assert masque.DiscardSessionUdpPacket(
        session: session,
        reason: masque.SocketTunnelInactive,
      ) = masque.receive_udp_proxy_session_packet(session, peer, bytes)
      assert masque.close_udp_proxy_session(session) == Ok(Nil)
      assert masque.udp_proxy_session_receiver_snapshot(session)
        == masque.UdpSocketReceiverSnapshot(
          forwarded_packets: 1,
          forwarded_bytes: bit_array.byte_size(bytes),
          dropped_source_mismatch: 1,
          dropped_oversized: 0,
          dropped_malformed: 0,
          dropped_inactive: 1,
        )
      let lifetime = masque.udp_proxy_session_snapshot(session)
      assert lifetime.state == masque.UdpProxyClosed
      assert lifetime.termination == Some(termination)
      assert lifetime.termination_notifications == 2
      assert lifetime.cleanup_attempts == 1
      assert lifetime.socket.state == masque.UdpProxyClosed
      assert lifetime.request_stream.state == masque.UdpProxyClosed
    }
    _,
      masque.UdpProxyRejected(
        response_status: 502,
        response_headers: [#("proxy-status", "fuzz.proxy;error=dns_error")],
        failure: masque.ProxyDnsAnswerInvalid,
        snapshot: snapshot,
      )
    -> {
      assert snapshot.socket_attempted == False
    }
    _, _ -> {
      assert bit_array.bit_size(bytes) < 0
    }
  }
}

fn termination_selector(bytes: BitArray) -> Int {
  case bytes {
    <<first, _rest:bits>> -> first % 3
    _ -> 0
  }
}

fn outcome_receiver(outcome: masque.DatagramReceive) -> masque.UdpReceiver {
  case outcome {
    masque.ForwardPayload(receiver, _) -> receiver
    masque.DropDatagram(receiver, _) -> receiver
    masque.AbortRequestStream(receiver, _) -> receiver
  }
}

fn retained_inputs() -> List(BitArray) {
  [
    <<>>,
    <<0>>,
    <<1>>,
    <<0x3f>>,
    <<0x40>>,
    <<0x7f>>,
    <<0x80>>,
    <<0xc0>>,
    <<0xff>>,
    <<0x40, 0>>,
    <<0x80, 0, 0, 0>>,
    <<0xc0, 0, 0, 0, 0, 0, 0, 0>>,
    <<0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>,
    <<0:size(1)>>,
    <<1:size(7)>>,
    <<0, "payload":utf8>>,
    <<1, "unknown":utf8>>,
    <<0, 0:size(1024)>>,
  ]
}

fn generate_bytes(
  seed: Int,
  remaining: Int,
  accumulator: BitArray,
) -> #(Int, BitArray) {
  case remaining {
    0 -> #(seed, accumulator)
    _ -> {
      let seed = next_seed(seed)
      let byte = seed % 256
      generate_bytes(seed, remaining - 1, <<accumulator:bits, byte>>)
    }
  }
}

fn limits() -> masque.Limits {
  masque.Limits(
    maximum_datagram_bytes: 128,
    maximum_capsule_bytes: 256,
    maximum_address_entries: 8,
    maximum_route_entries: 8,
    maximum_policy_rules: 8,
  )
}

fn next_seed(seed: Int) -> Int {
  { seed * 48_271 + 1 } % generator_modulus
}

fn observe_result(outcome: Result(value, error)) -> Bool {
  result.is_ok(outcome) || result.is_error(outcome)
}
