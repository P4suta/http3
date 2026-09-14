//// Reproducible state-model properties for the public MASQUE UDP receiver.
////
//// Every transition compares the implementation's payload-free diagnostic
//// snapshot with an independent reference model. The campaign driver records
//// the starting seed and source digest so any failure is exactly replayable.

import gleam/http
import gleam/http/request
import gleam/int
import gleam/option.{None, Some}
import http/masque
import http/status

const generator_modulus = 2_147_483_647

type Model {
  Model(
    active: Bool,
    accepted: Int,
    dropped_before_request: Int,
    dropped_unknown_context: Int,
    discarded_capsules: Int,
    aborts_required: Int,
  )
}

/// Exercise a deterministic receiver model from the default campaign seed.
pub fn exercise(cases: Int) -> Int {
  exercise_from(982_451_653, cases)
}

/// Exercise a deterministic shard beginning from an explicitly retained seed.
pub fn exercise_from(seed: Int, cases: Int) -> Int {
  let assert Ok(receiver) = masque.udp_receiver(limits())
  exercise_cases(seed, cases, receiver, Model(False, 0, 0, 0, 0, 0))
  cases
}

fn exercise_cases(
  seed: Int,
  remaining: Int,
  receiver: masque.UdpReceiver,
  model: Model,
) -> Nil {
  case remaining <= 0 {
    True -> Nil
    False -> {
      let seed = next_seed(seed)
      let byte = seed % 256
      let payload = <<byte>>
      let assert Ok(encoded) = masque.encode_udp_datagram(payload, limits())
      assert masque.decode_udp_datagram(encoded, limits()) == Ok(payload)
      assert_http1_request_validation(seed)

      let #(receiver, model) = transition(seed % 8, byte, receiver, model)
      assert masque.udp_receiver_snapshot(receiver) == model_snapshot(model)
      exercise_cases(seed, remaining - 1, receiver, model)
    }
  }
}

fn assert_http1_request_validation(seed: Int) -> Nil {
  let target =
    masque.UdpTarget(
      "node-" <> int.to_string(seed % 100_000) <> ".example",
      1 + seed % 65_535,
    )
  let masque.UdpTarget(host, port) = target
  let path =
    "/.well-known/masque/udp/" <> host <> "/" <> int.to_string(port) <> "/"
  let base =
    request.Request(
      method: http.Get,
      headers: [
        #("host", "proxy.example"),
        #("connection", "Upgrade"),
        #("upgrade", "connect-udp"),
        #("capsule-protocol", "?1"),
      ],
      body: Nil,
      scheme: http.Https,
      host: "proxy.example",
      port: None,
      path: path,
      query: None,
    )
  let assert masque.AcceptProxyRequest(prepared) =
    masque.validate_http1_udp_proxy_request(base, limits())
  assert masque.request_udp_target(prepared) == Some(target)
  assert_supervised_proxy_setup(seed, prepared, target)

  let #(malformed, violation) = case seed % 4 {
    0 -> #(request.Request(..base, method: http.Post), masque.MethodMustBeGet)
    1 -> #(
      request.Request(..base, path: "/.well-known/masque/udp/example.com/0/"),
      masque.DefaultUdpTargetInvalid,
    )
    2 -> #(
      request.Request(..base, headers: [
        #("host", "duplicate.example"),
        ..base.headers
      ]),
      masque.SingleHostRequired,
    )
    _ -> #(
      request.Request(..base, headers: [
        #("content-length", "0"),
        ..base.headers
      ]),
      masque.MessageContentForbidden,
    )
  }
  assert masque.validate_http1_udp_proxy_request(malformed, limits())
    == masque.RejectProxyRequest(400, violation)
}

fn assert_supervised_proxy_setup(
  seed: Int,
  request: masque.PreparedRequest,
  target: masque.UdpTarget,
) -> Nil {
  let masque.UdpTarget(expected_host, expected_port) = target
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<198, 51, 100, 0>>), 24),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let socket_setup_timeout = 100 + seed % 50
  let socket_operation_timeout = 50 + seed % 50
  let assert Ok(config) =
    masque.proxy_setup_config_with_socket_timeouts(
      status.TokenIdentifier("campaign.proxy"),
      dns_timeout_milliseconds: 100,
      socket_setup_timeout_milliseconds: socket_setup_timeout,
      socket_operation_timeout_milliseconds: socket_operation_timeout,
      maximum_adapter_heap_words: 16_384,
    )
  let octet = 1 + seed % 254
  let address = masque.Ipv4(<<198, 51, 100, octet>>)
  let resolver = fn(host, timeout_milliseconds) {
    assert host == expected_host
    assert timeout_milliseconds == 100
    case seed % 5 {
      0 -> Error(masque.DnsLookupFailed)
      _ -> Ok([address])
    }
  }
  let outcome =
    masque.establish_udp_proxy(
      authorized,
      config,
      resolver: resolver,
      open_socket: fn(endpoint, timeout_milliseconds) {
        assert endpoint == masque.UdpEndpoint(address, expected_port)
        assert timeout_milliseconds == socket_setup_timeout
        Ok(
          masque.udp_socket_resource(seed, fn(timeout_milliseconds) {
            assert timeout_milliseconds == socket_operation_timeout
            Ok(Nil)
          }),
        )
      },
    )
  case seed % 5, outcome {
    0,
      masque.UdpProxyRejected(
        response_status: 502,
        response_headers: [#("proxy-status", "campaign.proxy;error=dns_error")],
        failure: masque.ProxyDnsError,
        snapshot: snapshot,
      )
    -> {
      assert snapshot.events
        == [
          masque.ProxyTargetAuthorized,
          masque.ProxyDnsStarted,
          masque.ProxySetupFailed(masque.ProxyDnsError),
        ]
    }
    _,
      masque.UdpProxyReady(
        tunnel: tunnel,
        response_status: 101,
        response_headers: [
          #("connection", "Upgrade"),
          #("upgrade", "connect-udp"),
          #("capsule-protocol", "?1"),
        ],
        snapshot: snapshot,
      )
    -> {
      assert masque.udp_proxy_socket(tunnel) == seed
      assert masque.udp_proxy_peer(tunnel)
        == masque.UdpEndpoint(address, expected_port)
      assert snapshot.resolved_addresses == 1
      assert snapshot.authorized_addresses == 1
      let payload_byte = seed % 256
      let payload = <<payload_byte>>
      let spoofed =
        masque.UdpEndpoint(masque.Ipv4(<<203, 0, 113, 1>>), expected_port)
      let assert masque.DiscardUdpPacket(
        tunnel: tunnel,
        reason: masque.SocketSourceMismatch,
      ) = masque.receive_udp_socket_packet(tunnel, spoofed, payload)
      let assert masque.ForwardHttpDatagram(
        tunnel: tunnel,
        datagram: <<0, payload:bits>>,
      ) =
        masque.receive_udp_socket_packet(
          tunnel,
          masque.UdpEndpoint(address, expected_port),
          payload,
        )
      let session =
        masque.bind_udp_proxy_stream(
          tunnel,
          masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
        )
      let #(termination, closed) = case seed % 3 {
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
      ) =
        masque.receive_udp_proxy_session_packet(
          session,
          masque.UdpEndpoint(address, expected_port),
          payload,
        )
      assert masque.close_udp_proxy_session(session) == Ok(Nil)
      assert masque.udp_proxy_session_receiver_snapshot(session)
        == masque.UdpSocketReceiverSnapshot(
          forwarded_packets: 1,
          forwarded_bytes: 1,
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
      assert lifetime.socket.cleanup_attempts == 1
      assert lifetime.request_stream.state == masque.UdpProxyClosed
      assert lifetime.request_stream.cleanup_attempts == 1
    }
    _, _ -> {
      assert seed < 0
    }
  }
}

fn transition(
  operation: Int,
  byte: Int,
  receiver: masque.UdpReceiver,
  model: Model,
) -> #(masque.UdpReceiver, Model) {
  case operation {
    0 -> #(masque.activate_udp_receiver(receiver), Model(..model, active: True))
    _ if !model.active -> {
      let assert masque.DropDatagram(receiver, masque.RequestNotReady) =
        masque.receive_proxy_datagram(
          receiver,
          operation_datagram(operation, byte),
        )
      #(
        receiver,
        Model(..model, dropped_before_request: model.dropped_before_request + 1),
      )
    }
    1 | 7 -> {
      let payload = <<byte>>
      let assert masque.ForwardPayload(receiver, forwarded) =
        masque.receive_proxy_datagram(receiver, <<0, payload:bits>>)
      assert forwarded == payload
      #(receiver, Model(..model, accepted: model.accepted + 1))
    }
    2 -> {
      let context = 1 + byte % 63
      let assert masque.DropDatagram(
        receiver,
        masque.ContextNotRegistered(observed_context),
      ) = masque.receive_proxy_datagram(receiver, <<context, byte>>)
      assert observed_context == context
      #(
        receiver,
        Model(
          ..model,
          dropped_unknown_context: model.dropped_unknown_context + 1,
        ),
      )
    }
    3 -> {
      let assert masque.AbortRequestStream(receiver, masque.NonByteAligned) =
        masque.receive_proxy_datagram(receiver, <<0:size(1)>>)
      #(receiver, Model(..model, aborts_required: model.aborts_required + 1))
    }
    4 -> {
      let assert masque.AbortRequestStream(receiver, masque.InvalidCapsule) =
        masque.receive_proxy_datagram(receiver, <<0b01:2, 0:6>>)
      #(receiver, Model(..model, aborts_required: model.aborts_required + 1))
    }
    5 -> {
      let assert masque.AbortRequestStream(
        receiver,
        masque.DatagramLimitExceeded(127),
      ) = masque.receive_proxy_datagram(receiver, <<0, 0:size(1024)>>)
      #(receiver, Model(..model, aborts_required: model.aborts_required + 1))
    }
    _ -> {
      let assert masque.ForwardPayload(receiver, <<>>) =
        masque.receive_proxy_datagram(receiver, <<0>>)
      #(receiver, Model(..model, accepted: model.accepted + 1))
    }
  }
}

fn operation_datagram(operation: Int, byte: Int) -> BitArray {
  case operation {
    2 -> {
      let context = 1 + byte % 63
      <<context, byte>>
    }
    3 -> <<0:size(1)>>
    4 -> <<0b01:2, 0:6>>
    5 -> <<0, 0:size(1024)>>
    6 -> <<0>>
    _ -> <<0, byte>>
  }
}

fn model_snapshot(model: Model) -> masque.UdpReceiverSnapshot {
  masque.UdpReceiverSnapshot(
    active: model.active,
    accepted: model.accepted,
    dropped_before_request: model.dropped_before_request,
    dropped_unknown_context: model.dropped_unknown_context,
    discarded_capsules: model.discarded_capsules,
    aborts_required: model.aborts_required,
  )
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
