import gleam/bool
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleeunit
import http/context
import http/masque
import http/status
import http3/address as http3_address
import http3/capsule as http3_capsule
import http3/client as http3_client
import http3/failure as http3_failure
import http3/server as http3_server
import http3/transport as http3_transport
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

type EventWaitTerminal {
  EventWaitObserved(masque.SystemUdpFailure)
  EventWaitTimedOut
  EventWaitBusy
  EventWaitStopped
  EventWaitFailed(masque.SystemUdpFailure)
}

type DuplicateEventWaiterTrace {
  DuplicateEventWaiterTrace(
    registration_seen: Bool,
    registration_queued_commands: Int,
    registration_timeouts: Int,
    registration_rejections: Int,
    duplicate: EventWaitTerminal,
    after_duplicate_waiting: Bool,
    after_duplicate_queued_commands: Int,
    after_duplicate_timeouts: Int,
    after_duplicate_rejections: Int,
    close_succeeded: Bool,
    first: EventWaitTerminal,
    final_state: masque.SystemUdpSocketState,
    final_waiting: Bool,
    final_queued_commands: Int,
    final_timeouts: Int,
    final_rejections: Int,
    final_socket_failures: Int,
  )
}

type ConcurrentTerminalTrace {
  ConcurrentTerminalTrace(
    callback_started: Bool,
    competing_notification: Result(Nil, masque.UdpProxySessionFailure),
    in_progress_state: masque.UdpProxyResourceState,
    in_progress_reason: Option(masque.UdpProxyTerminationReason),
    in_progress_notifications: Int,
    terminating_notification: Result(Nil, masque.UdpProxySessionFailure),
    request_stream_close_observed: Bool,
    socket_close_observed: Bool,
    extra_cleanup_event: Bool,
    final_state: masque.UdpProxyResourceState,
    final_reason: Option(masque.UdpProxyTerminationReason),
    final_cleanup_attempts: Int,
    final_request_stream_attempts: Int,
    final_socket_attempts: Int,
  )
}

type ConcurrentSocketCloseTrace {
  ConcurrentSocketCloseTrace(
    callback_started: Bool,
    competing_close: Result(Nil, masque.ProxySetupFailure),
    in_progress: masque.UdpProxyResourceSnapshot,
    owner_close: Result(Nil, masque.ProxySetupFailure),
    final: masque.UdpProxyResourceSnapshot,
  )
}

type IdleActivityTrace {
  IdleActivityTrace(
    initial_state: masque.UdpProxyIdleState,
    timeout_milliseconds: Option(Int),
    activity_state: masque.UdpProxyIdleState,
    activity_events: Int,
    outbound_events: Int,
    inbound_events: Int,
    accounting_consistent: Bool,
    wake_credit_bounded: Bool,
    close: Result(Nil, masque.UdpProxySessionFailure),
    close_reason: Result(masque.UdpProxyTerminationReason, Nil),
    final_idle_state: masque.UdpProxyIdleState,
    expirations: Int,
    stop_signals: Int,
    final_lifetime_state: masque.UdpProxyResourceState,
    final_reason: Option(masque.UdpProxyTerminationReason),
  )
}

type IdleExpiryTrace {
  IdleExpiryTrace(
    initial_state: masque.UdpProxyIdleState,
    timeout_milliseconds: Option(Int),
    close_reason: Result(masque.UdpProxyTerminationReason, Nil),
    final_idle_state: masque.UdpProxyIdleState,
    pending_command: Bool,
    deadline_observed: Bool,
    expirations: Int,
    stop_signals: Int,
    lifetime_state: masque.UdpProxyResourceState,
    lifetime_reason: Option(masque.UdpProxyTerminationReason),
    termination_notifications: Int,
    socket_close_calls: Int,
    request_stream_close_calls: Int,
    socket_state: masque.SystemUdpSocketState,
    socket_failures: Int,
  )
}

type IdleActivitySendFailureTrace {
  IdleActivitySendFailureTrace(
    kind: SystemUdpIoOutcomeKind,
    idle_state: masque.UdpProxyIdleState,
    activity_events: Int,
    lifetime_state: masque.UdpProxyResourceState,
    lifetime_reason: Option(masque.UdpProxyTerminationReason),
    socket_state: masque.SystemUdpSocketState,
  )
}

type SystemUdpIoOutcomeKind {
  SystemUdpIoInactive
  SystemUdpIoSent
  SystemUdpIoDiscarded
  SystemUdpIoAbort
  SystemUdpIoForward
  SystemUdpIoTooLarge
  SystemUdpIoSocketDiscarded
  SystemUdpIoReceiveTimeout
  SystemUdpIoReceiveBusy
  SystemUdpIoReceiveFailure
  SystemUdpIoSendBusy
  SystemUdpIoSendFailure
  SystemUdpIoTerminated
}

fn limits() -> masque.Limits {
  masque.Limits(
    maximum_datagram_bytes: 65_528,
    maximum_capsule_bytes: 4096,
    maximum_address_entries: 8,
    maximum_route_entries: 8,
    maximum_policy_rules: 8,
  )
}

pub fn rfc9298_udp_idle_policy_never_configures_below_two_minutes_test() -> Nil {
  let disabled = masque.udp_proxy_idle_timeout_disabled()
  assert masque.udp_proxy_idle_timeout_milliseconds(disabled) == None

  assert masque.udp_proxy_idle_timeout(119_999)
    == Error(masque.InvalidIdleTimeout)
  let assert Ok(minimum) = masque.udp_proxy_idle_timeout(120_000)
  assert masque.udp_proxy_idle_timeout_milliseconds(minimum) == Some(120_000)

  let assert Ok(maximum) = masque.udp_proxy_idle_timeout(2_147_483_647)
  assert masque.udp_proxy_idle_timeout_milliseconds(maximum)
    == Some(2_147_483_647)
  assert masque.udp_proxy_idle_timeout(2_147_483_648)
    == Error(masque.InvalidIdleTimeout)
}

fn udp_target() -> masque.UdpTarget {
  masque.UdpTarget("192.0.2.6", 443)
}

pub fn connect_udp_request_mapping_and_confirm_before_payload_test() -> Nil {
  let assert Ok(h1) =
    masque.connect_udp(masque.Http1, "proxy.example", udp_target(), limits())
  assert masque.request_method(h1) == http.Get
  assert masque.request_path(h1) == "/.well-known/masque/udp/192.0.2.6/443/"
  assert masque.request_protocol(h1) == None
  assert masque.request_headers(h1)
    == [
      #("host", "proxy.example"),
      #("connection", "Upgrade"),
      #("upgrade", "connect-udp"),
      #("capsule-protocol", "?1"),
    ]

  let assert Ok(h3) =
    masque.connect_udp(masque.Http3, "proxy.example", udp_target(), limits())
  assert masque.request_method(h3) == http.Connect
  assert masque.request_protocol(h3) == Some("connect-udp")
  assert masque.request_headers(h3) == [#("capsule-protocol", "?1")]

  // RFC 9931 forbids optimistic CONNECT-UDP payload on HTTP/1.x. Keep this
  // assertion protocol-specific so a future shared tunnel refactor cannot
  // accidentally permit the HTTP/1 Upgrade request to carry datagrams.
  let pending_h1 = masque.client_tunnel(h1)
  assert masque.send_datagram(pending_h1, <<"too-early":utf8>>)
    == Error(masque.NotEstablished)
  let assert Ok(active_h1) =
    masque.confirm(pending_h1, 101, [
      #("connection", "Upgrade"),
      #("upgrade", "connect-udp"),
      #("capsule-protocol", "?1"),
    ])
  assert masque.send_datagram(active_h1, <<"dns":utf8>>)
    == Ok(<<0, "dns":utf8>>)

  let pending = masque.client_tunnel(h3)
  assert masque.send_datagram(pending, <<"too-early":utf8>>)
    == Error(masque.NotEstablished)
  let assert Ok(active) =
    masque.confirm(pending, 200, [#("capsule-protocol", "?1")])
  assert masque.send_datagram(active, <<"dns":utf8>>) == Ok(<<0, "dns":utf8>>)
  assert masque.confirm(pending, 302, [#("capsule-protocol", "?1")])
    == Error(masque.UnexpectedStatus(302))
  let assert Ok(_) = masque.confirm(pending, 204, [#("capsule-protocol", "?1")])
  assert masque.confirm(pending, 200, [
      #("capsule-protocol", "?1"),
      #("content-length", "0"),
    ])
    == Error(masque.InvalidResponse)
  let assert Ok(_) =
    masque.confirm(pending, 200, [
      #("capsule-protocol", "?1;future=?1"),
    ])
  let assert Ok(_) =
    masque.confirm(pending, 200, [
      #("capsule-protocol", "?1; future=?1"),
    ])
  assert masque.confirm(pending, 200, [
      #("capsule-protocol", "?1;\tfuture=?1"),
    ])
    == Error(masque.InvalidResponse)
  assert masque.confirm(pending, 200, [#("capsule-protocol", "?0")])
    == Error(masque.InvalidResponse)
  assert masque.confirm(pending, 200, [#("capsule-protocol", "token")])
    == Error(masque.InvalidResponse)
  assert masque.confirm(pending, 200, [
      #("capsule-protocol", "?1"),
      #("capsule-protocol", "?1"),
    ])
    == Error(masque.InvalidResponse)
  Nil
}

pub fn rfc9298_target_authority_and_ipv6_expansion_are_strict_test() -> Nil {
  let invalid_targets = [
    masque.UdpTarget("", 443),
    masque.UdpTarget("example.com", 0),
    masque.UdpTarget("example.com", 65_536),
    masque.UdpTarget("bad^host", 443),
    masque.UdpTarget("bad[host", 443),
    masque.UdpTarget("2001:db8", 443),
    masque.UdpTarget("2001:::42", 443),
    masque.UdpTarget("2001:db8::1::42", 443),
    masque.UdpTarget("tést.example", 443),
  ]
  invalid_targets
  |> list.each(fn(target) {
    assert masque.connect_udp(masque.Http3, "proxy.example", target, limits())
      == Error(masque.InvalidTarget)
  })

  assert masque.connect_udp(
      masque.Http3,
      "proxy.example/path",
      udp_target(),
      limits(),
    )
    == Error(masque.InvalidAuthority)

  let assert Ok(ipv6) =
    masque.connect_udp(
      masque.Http3,
      "proxy.example",
      masque.UdpTarget("2001:db8::42", 443),
      limits(),
    )
  assert masque.request_path(ipv6)
    == "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"
}

pub fn rfc9298_http1_proxy_request_validator_accepts_default_route_test() -> Nil {
  let incoming = inbound_http1_udp_request()
  let assert masque.AcceptProxyRequest(prepared) =
    masque.validate_http1_udp_proxy_request(incoming, limits())
  assert masque.request_method(prepared) == http.Get
  assert masque.request_authority(prepared) == "proxy.example"
  assert masque.request_path(prepared)
    == "/.well-known/masque/udp/192.0.2.6/443/"
  assert masque.request_udp_target(prepared) == Some(udp_target())
}

pub fn rfc9298_http1_proxy_request_validator_has_redacted_400_matrix_test() -> Nil {
  let base = inbound_http1_udp_request()
  let malformed = [
    #(request.Request(..base, method: http.Post), masque.MethodMustBeGet),
    #(
      request.Request(..base, headers: list.drop(base.headers, 1)),
      masque.SingleHostRequired,
    ),
    #(
      request.Request(..base, headers: [
        #("host", "duplicate.example"),
        ..base.headers
      ]),
      masque.SingleHostRequired,
    ),
    #(
      request.Request(..base, headers: [
        #("host", "other.example"),
        ..list.drop(base.headers, 1)
      ]),
      masque.ProxyAuthorityMismatch,
    ),
    #(
      request.Request(..base, headers: [
        #("host", "proxy.example"),
        #("upgrade", "connect-udp"),
        #("capsule-protocol", "?1"),
      ]),
      masque.ConnectionUpgradeRequired,
    ),
    #(
      request.Request(..base, headers: [
        #("host", "proxy.example"),
        #("connection", "Upgrade"),
        #("upgrade", "connect-udp"),
        #("upgrade", "connect-udp"),
        #("capsule-protocol", "?1"),
      ]),
      masque.SingleConnectUdpUpgradeRequired,
    ),
    #(
      request.Request(..base, headers: [
        #("host", "proxy.example"),
        #("connection", "Upgrade"),
        #("upgrade", "connect-udp"),
        #("capsule-protocol", "?0"),
      ]),
      masque.CapsuleProtocolRequired,
    ),
    #(
      request.Request(..base, headers: [
        #("content-length", "0"),
        ..base.headers
      ]),
      masque.MessageContentForbidden,
    ),
    #(
      request.Request(..base, path: "/not-masque"),
      masque.DefaultUdpTargetInvalid,
    ),
    #(
      request.Request(..base, query: Some("unexpected=1")),
      masque.DefaultUdpTargetInvalid,
    ),
    #(
      request.Request(
        ..base,
        headers: list.append(
          base.headers,
          list.repeat(#("x-padding", "1"), times: 125),
        ),
      ),
      masque.RequestMetadataLimitExceeded(128),
    ),
  ]

  malformed
  |> list.each(fn(example) {
    let #(incoming, violation) = example
    assert masque.validate_http1_udp_proxy_request(incoming, limits())
      == masque.RejectProxyRequest(status: 400, violation: violation)
  })
}

pub fn rfc9298_http1_proxy_request_target_boundaries_are_strict_test() -> Nil {
  let base = inbound_http1_udp_request()
  let accepted_paths = [
    #(
      "/.well-known/masque/udp/example.com/1/",
      masque.UdpTarget("example.com", 1),
    ),
    #(
      "/.well-known/masque/udp/2001%3adb8%3a%3a42/65535/",
      masque.UdpTarget("2001:db8::42", 65_535),
    ),
  ]
  accepted_paths
  |> list.each(fn(example) {
    let #(path, target) = example
    let incoming = request.Request(..base, path:)
    let assert masque.AcceptProxyRequest(prepared) =
      masque.validate_http1_udp_proxy_request(incoming, limits())
    assert masque.request_udp_target(prepared) == Some(target)
  })

  let oversized_path =
    "/.well-known/masque/udp/"
    <> { list.repeat("a", times: 2049) |> string.join(with: "") }
    <> "/443/"
  let invalid_paths = [
    "/.well-known/masque/udp/example.com/0/",
    "/.well-known/masque/udp/example.com/65536/",
    "/.well-known/masque/udp/example.com/+1/",
    "/.well-known/masque/udp/2001:db8::42/443/",
    "/.well-known/masque/udp/2001%3Gdb8/443/",
    "/.well-known/masque/udp/bad%2Fhost/443/",
    "/.well-known/masque/udp//443/",
    oversized_path,
  ]
  invalid_paths
  |> list.each(fn(path) {
    let incoming = request.Request(..base, path:)
    assert masque.validate_http1_udp_proxy_request(incoming, limits())
      == masque.RejectProxyRequest(400, masque.DefaultUdpTargetInvalid)
  })

  let invalid_limits = masque.Limits(..limits(), maximum_datagram_bytes: 0)
  assert masque.validate_http1_udp_proxy_request(base, invalid_limits)
    == masque.ProxyRequestConfigurationFailure(masque.InvalidLimits)
}

pub fn rfc9298_default_well_known_h3_proxy_listener_is_exact_and_observable_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = http3_server.new(certificate, private_key)
  let assert Ok(configuration) = http3_server.with_timeout(configuration, 3000)
  let invalid_limits = masque.Limits(..limits(), maximum_datagram_bytes: 0)
  assert masque.start_udp_proxy_listener(configuration, invalid_limits)
    == Error(masque.UdpProxyListenerInvalidLimits)

  let assert Ok(listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  assert masque.udp_proxy_listener_snapshot(listener)
    == masque.UdpProxyListenerSnapshot(
      consistent: True,
      state: masque.UdpProxyListening,
      accept_calls: 0,
      accepted_requests: 0,
      rejected_requests: 0,
      accept_failures: 0,
      rejection_response_failures: 0,
      setup_calls: 0,
      established_requests: 0,
      policy_rejections: 0,
      setup_rejections: 0,
      setup_response_failures: 0,
      duplicate_setup_attempts: 0,
      setup_response_cleanup_calls: 0,
      setup_response_cleanup_failures: 0,
      drain_calls: 0,
      stop_calls: 0,
      lifecycle_failures: 0,
    )
  let assert Ok(port) = masque.udp_proxy_listener_port(listener)
  let #(port_guard, occupied_port) =
    http_test_support.start_exclusive_udp_port_guard()
  let assert Ok(loopback) = http3_address.parse("127.0.0.1")
  let occupied_configuration =
    configuration |> http3_server.with_bind_address(loopback)
  let assert Ok(occupied_configuration) =
    http3_server.with_port(occupied_configuration, occupied_port)
  assert masque.start_udp_proxy_listener(occupied_configuration, limits())
    == Error(masque.UdpProxyListenerStartFailed)
  http_test_support.stop_exclusive_udp_port_guard(port_guard)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let client_configuration =
    client_configuration |> http3_client.with_http_datagrams
  let assert Ok(connection) =
    http3_client.connect(client_configuration, "localhost", port)

  let malformed =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/not-the-default-masque-route")
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)
  let assert Ok(malformed_stream) =
    http3_client.open_extended_connect(connection, malformed, "connect-udp")
  assert masque.accept_udp_proxy_request(listener)
    == Ok(masque.UdpProxyRequestRejected(masque.DefaultUdpTargetInvalid))
  let assert Ok(http3_client.Response(400, _)) =
    http3_client.next_event(malformed_stream)

  let valid =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/.well-known/masque/udp/192.0.2.6/443/")
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)
  let assert Ok(valid_stream) =
    http3_client.open_extended_connect(connection, valid, "connect-udp")
  let assert Ok(masque.UdpProxyRequestAccepted(accepted)) =
    masque.accept_udp_proxy_request(listener)
  let prepared = masque.udp_proxy_prepared_request(accepted)
  assert masque.request_method(prepared) == http.Connect
  assert masque.request_authority(prepared)
    == "localhost:" <> int.to_string(port)
  assert masque.request_path(prepared)
    == "/.well-known/masque/udp/192.0.2.6/443/"
  assert masque.request_udp_target(prepared) == Some(udp_target())
  let assert Ok(deny_policy) = masque.deny_all(limits())
  assert masque.establish_system_udp_proxy_request(
      accepted,
      deny_policy,
      proxy_setup_config(100, 100),
      masque.udp_proxy_idle_timeout_disabled(),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
    == Ok(masque.SystemUdpProxyPolicyRejected(502))
  let assert Ok(http3_client.Response(502, _)) =
    http3_client.next_event(valid_stream)

  let snapshot = masque.udp_proxy_listener_snapshot(listener)
  assert snapshot.state == masque.UdpProxyListening
  assert snapshot.accept_calls == 2
  assert snapshot.accepted_requests == 1
  assert snapshot.rejected_requests == 1
  assert snapshot.accept_failures == 0
  assert snapshot.rejection_response_failures == 0
  assert snapshot.setup_calls == 1
  assert snapshot.established_requests == 0
  assert snapshot.policy_rejections == 1
  assert snapshot.setup_rejections == 0
  assert snapshot.setup_response_failures == 0

  let _closed = http3_client.close(connection)
  assert masque.stop_udp_proxy_listener(listener)
    == Ok(masque.UdpProxyListenerStopped)
  assert masque.stop_udp_proxy_listener(listener)
    == Ok(masque.UdpProxyListenerAlreadyStopped)
  let stopped = masque.udp_proxy_listener_snapshot(listener)
  assert stopped.state == masque.UdpProxyStopped
  assert stopped.stop_calls == 2
  assert stopped.lifecycle_failures == 0

  assert masque.accept_udp_proxy_request(listener)
    == Error(masque.UdpProxyListenerAcceptFailed)
  let post_stop = masque.udp_proxy_listener_snapshot(listener)
  assert post_stop.accept_calls == 3
  assert post_stop.accept_failures == 1

  let assert Ok(drain_listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  assert masque.drain_udp_proxy_listener(drain_listener)
    == Ok(masque.UdpProxyListenerDrained)
  assert masque.drain_udp_proxy_listener(drain_listener)
    == Ok(masque.UdpProxyListenerAlreadyDrained)
  let drained = masque.udp_proxy_listener_snapshot(drain_listener)
  assert drained.state == masque.UdpProxyStopped
  assert drained.drain_calls == 2
  assert drained.lifecycle_failures == 0
}

pub fn rfc9298_default_listener_establishes_before_2xx_and_relays_live_udp_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let assert masque.UdpEndpoint(masque.Ipv4(_), target_port) = peer
  let target = masque.UdpTarget("127.0.0.1", target_port)
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = http3_server.new(certificate, private_key)
  let assert Ok(configuration) = http3_server.with_timeout(configuration, 3000)
  let assert Ok(listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  let assert Ok(port) = masque.udp_proxy_listener_port(listener)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let client_configuration =
    client_configuration |> http3_client.with_http_datagrams
  let assert Ok(connection) =
    http3_client.connect(client_configuration, "localhost", port)
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path(
      "/.well-known/masque/udp/127.0.0.1/" <> int.to_string(target_port) <> "/",
    )
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)
  let assert Ok(stream) =
    http3_client.open_extended_connect(connection, outgoing, "connect-udp")
  let assert Ok(masque.UdpProxyRequestAccepted(accepted)) =
    masque.accept_udp_proxy_request(listener)
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<127, 0, 0, 0>>), 8),
    )
  let assert Ok(masque.SystemUdpProxyEstablished(active, _)) =
    masque.establish_system_udp_proxy_request(
      accepted,
      policy,
      proxy_setup_config(1000, 1000),
      masque.udp_proxy_idle_timeout_disabled(),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
  assert http3_client.next_event(stream)
    == Ok(http3_client.Response(200, [#("capsule-protocol", "?1")]))

  assert masque.establish_system_udp_proxy_request(
      accepted,
      policy,
      proxy_setup_config(1000, 1000),
      masque.udp_proxy_idle_timeout_disabled(),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
    == Error(masque.UdpProxyListenerSetupAlreadyStarted)

  let client_transport = http3_client.stream_transport(stream)
  let server_transport = masque.system_udp_proxy_transport(active)
  let session = masque.system_udp_proxy_session(active)
  let assert Ok(live_http_datagram_bytes) =
    http3_transport.maximum_datagram_size(server_transport)
  let assert Ok(guaranteed_http_datagram_bytes) =
    http3_transport.guaranteed_datagram_size(server_transport)
  let packet_too_big = masque.system_udp_packet_too_big_snapshot(session)
  assert packet_too_big.target_payload_limit_bytes
    == int.min(65_527, guaranteed_http_datagram_bytes - 1)
  assert guaranteed_http_datagram_bytes <= live_http_datagram_bytes
  assert http3_transport.send_datagram(client_transport, <<
      0,
      "listener-relay":utf8,
    >>)
    == Ok(Nil)
  let assert Ok(to_target) = http3_transport.next_datagram(server_transport)
  let assert masque.SystemUdpSent(session) =
    masque.forward_system_udp_datagram(session, to_target)
  let assert masque.SystemUdpForward(session: session, datagram: to_client) =
    masque.receive_system_udp_datagram(session, 1000)
  assert http3_transport.send_datagram(server_transport, to_client) == Ok(Nil)
  assert http3_transport.next_datagram(client_transport)
    == Ok(<<0, "listener-relay":utf8>>)

  let listener_snapshot = masque.udp_proxy_listener_snapshot(listener)
  assert listener_snapshot.accepted_requests == 1
  assert listener_snapshot.setup_calls == 1
  assert listener_snapshot.established_requests == 1
  assert listener_snapshot.policy_rejections == 0
  assert listener_snapshot.setup_rejections == 0
  assert listener_snapshot.setup_response_failures == 0
  assert listener_snapshot.duplicate_setup_attempts == 1
  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  let _closed = http3_client.close(connection)
  let assert Ok(_) = masque.stop_udp_proxy_listener(listener)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_default_listener_sends_typed_dns_rejection_and_trace_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = http3_server.new(certificate, private_key)
  let assert Ok(configuration) = http3_server.with_timeout(configuration, 3000)
  let assert Ok(listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  let assert Ok(port) = masque.udp_proxy_listener_port(listener)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(
      http3_client.with_http_datagrams(client_configuration),
      "localhost",
      port,
    )
  let target = masque.UdpTarget("dns.example", 443)
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/.well-known/masque/udp/dns.example/443/")
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)
  let assert Ok(stream) =
    http3_client.open_extended_connect(connection, outgoing, "connect-udp")
  let assert Ok(masque.UdpProxyRequestAccepted(accepted)) =
    masque.accept_udp_proxy_request(listener)
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<203, 0, 113, 0>>), 24),
    )
  let assert Ok(masque.SystemUdpProxySetupRejected(
    response_status: 502,
    failure: masque.ProxyDnsError,
    snapshot: setup,
  )) =
    masque.establish_system_udp_proxy_request(
      accepted,
      policy,
      proxy_setup_config(100, 100),
      masque.udp_proxy_idle_timeout_disabled(),
      resolver: fn(host, timeout) {
        assert host == "dns.example"
        assert timeout == 100
        Error(masque.DnsLookupFailed)
      },
    )
  assert setup.events
    == [
      masque.ProxyTargetAuthorized,
      masque.ProxyDnsStarted,
      masque.ProxySetupFailed(masque.ProxyDnsError),
    ]
  assert http3_client.next_event(stream)
    == Ok(
      http3_client.Response(502, [
        #("proxy-status", "edge.example;error=dns_error"),
      ]),
    )
  let snapshot = masque.udp_proxy_listener_snapshot(listener)
  assert snapshot.setup_calls == 1
  assert snapshot.established_requests == 0
  assert snapshot.policy_rejections == 0
  assert snapshot.setup_rejections == 1
  assert snapshot.setup_response_failures == 0
  let _closed = http3_client.close(connection)
  let assert Ok(_) = masque.stop_udp_proxy_listener(listener)
  Nil
}

pub fn rfc9298_default_listener_reclaims_socket_when_2xx_cannot_be_sent_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let assert masque.UdpEndpoint(masque.Ipv4(_), target_port) = peer
  let target = masque.UdpTarget("127.0.0.1", target_port)
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = http3_server.new(certificate, private_key)
  let assert Ok(configuration) = http3_server.with_timeout(configuration, 3000)
  let assert Ok(listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  let assert Ok(port) = masque.udp_proxy_listener_port(listener)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(
      http3_client.with_http_datagrams(client_configuration),
      "localhost",
      port,
    )
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path(
      "/.well-known/masque/udp/127.0.0.1/" <> int.to_string(target_port) <> "/",
    )
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)
  let assert Ok(_stream) =
    http3_client.open_extended_connect(connection, outgoing, "connect-udp")
  let assert Ok(masque.UdpProxyRequestAccepted(accepted)) =
    masque.accept_udp_proxy_request(listener)
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<127, 0, 0, 0>>), 8),
    )

  assert masque.stop_udp_proxy_listener(listener)
    == Ok(masque.UdpProxyListenerStopped)
  assert masque.establish_system_udp_proxy_request(
      accepted,
      policy,
      proxy_setup_config(100, 100),
      masque.udp_proxy_idle_timeout_disabled(),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
    == Error(masque.UdpProxyListenerSetupResponseFailed)
  let snapshot = masque.udp_proxy_listener_snapshot(listener)
  assert snapshot.setup_calls == 1
  assert snapshot.setup_response_failures == 1
  assert snapshot.setup_response_cleanup_calls == 1
  assert snapshot.setup_response_cleanup_failures == 0
  let _closed = http3_client.close(connection)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_default_listener_live_rejection_matrix_is_exact_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(configuration) = http3_server.new(certificate, private_key)
  let assert Ok(configuration) = http3_server.with_timeout(configuration, 3000)
  let assert Ok(listener) =
    masque.start_udp_proxy_listener(configuration, limits())
  let assert Ok(port) = masque.udp_proxy_listener_port(listener)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(
      http3_client.with_http_datagrams(client_configuration),
      "localhost",
      port,
    )
  let base =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/.well-known/masque/udp/192.0.2.6/443/")
    |> request.set_header("capsule-protocol", "?1")
    |> request.set_body(Nil)

  let assert Ok(get_stream) = http3_client.open_stream(connection, base)
  assert_live_udp_proxy_rejection(
    listener: listener,
    stream: get_stream,
    violation: masque.MethodMustBeConnect,
  )
  let assert Ok(protocol_stream) =
    http3_client.open_extended_connect(connection, base, "websocket")
  assert_live_udp_proxy_rejection(
    listener: listener,
    stream: protocol_stream,
    violation: masque.ConnectUdpProtocolRequired,
  )
  let assert Ok(capsule_stream) =
    request.Request(..base, headers: [])
    |> http3_client.open_extended_connect(connection, _, "connect-udp")
  assert_live_udp_proxy_rejection(
    listener: listener,
    stream: capsule_stream,
    violation: masque.CapsuleProtocolRequired,
  )
  let assert Ok(query_stream) =
    base
    |> request.set_query([#("forbidden", "query")])
    |> http3_client.open_extended_connect(connection, _, "connect-udp")
  assert_live_udp_proxy_rejection(
    listener: listener,
    stream: query_stream,
    violation: masque.DefaultUdpTargetInvalid,
  )
  let assert Ok(content_stream) =
    base
    |> request.set_header("content-type", "application/octet-stream")
    |> http3_client.open_extended_connect(connection, _, "connect-udp")
  assert_live_udp_proxy_rejection(
    listener: listener,
    stream: content_stream,
    violation: masque.MessageContentForbidden,
  )

  let snapshot = masque.udp_proxy_listener_snapshot(listener)
  assert snapshot.accept_calls == 5
  assert snapshot.accepted_requests == 0
  assert snapshot.rejected_requests == 5
  assert snapshot.rejection_response_failures == 0
  let _closed = http3_client.close(connection)
  let assert Ok(_) = masque.stop_udp_proxy_listener(listener)
  Nil
}

fn assert_live_udp_proxy_rejection(
  listener listener: masque.UdpProxyListener,
  stream stream: http3_client.Stream,
  violation violation: masque.ProxyRequestViolation,
) -> Nil {
  assert masque.accept_udp_proxy_request(listener)
    == Ok(masque.UdpProxyRequestRejected(violation))
  let assert Ok(http3_client.Response(400, [])) =
    http3_client.next_event(stream)
  Nil
}

pub fn rfc9298_default_listener_diagnostic_snapshot_is_atomic_under_race_test() -> Nil {
  let #(violations, calls, accepted, rejected, failures, response_failures) =
    http_test_support.masque_listener_snapshot_race(20_000)
  assert violations == 0
  assert calls == 80_000
  assert accepted == 20_000
  assert rejected == 40_000
  assert failures == 20_000
  assert response_failures == 20_000
}

pub fn rfc9298_default_listener_orphaned_writer_is_finite_and_observable_test() -> Nil {
  assert http_test_support.masque_listener_orphaned_writer_trace()
    == #(True, True, True)
}

pub fn rfc9298_default_listener_setup_snapshot_is_atomic_under_race_test() -> Nil {
  let #(
    violations,
    calls,
    established,
    policy_rejections,
    setup_rejections,
    response_failures,
    duplicates,
  ) = http_test_support.masque_listener_setup_snapshot_race(20_000)
  assert violations == 0
  assert calls == 80_000
  assert established == 20_000
  assert policy_rejections == 20_000
  assert setup_rejections == 20_000
  assert response_failures == 20_000
  assert duplicates == 20_000
}

pub fn rfc9298_proxy_setup_resolves_and_opens_before_success_test() -> Nil {
  let target = masque.UdpTarget("dns.example", 443)
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<203, 0, 113, 0>>), 24),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let calls = process.new_subject()

  let resolver = fn(host, timeout_milliseconds) {
    assert host == "dns.example"
    assert timeout_milliseconds == 100
    process.send(calls, "dns")
    Ok([masque.Ipv4(<<203, 0, 113, 7>>)])
  }
  let opener = fn(endpoint, timeout_milliseconds) {
    assert timeout_milliseconds == 200
    let expected = masque.UdpEndpoint(masque.Ipv4(<<203, 0, 113, 7>>), 443)
    assert endpoint == expected
    process.send(calls, "socket")
    Ok(
      masque.udp_socket_resource("udp-socket", fn(timeout) {
        assert timeout == 200
        process.send(calls, "closed")
        Ok(Nil)
      }),
    )
  }

  let assert masque.UdpProxyReady(
    tunnel: tunnel,
    response_status: 200,
    response_headers: [#("capsule-protocol", "?1")],
    snapshot: snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 200),
      resolver: resolver,
      open_socket: opener,
    )
  assert process.receive(calls, within: 0) == Ok("dns")
  assert process.receive(calls, within: 0) == Ok("socket")
  assert masque.udp_proxy_socket(tunnel) == "udp-socket"
  assert masque.udp_proxy_peer(tunnel)
    == masque.UdpEndpoint(masque.Ipv4(<<203, 0, 113, 7>>), 443)
  assert masque.udp_receiver_snapshot(masque.udp_proxy_receiver(tunnel))
    == masque.UdpReceiverSnapshot(True, 0, 0, 0, 0, 0)
  assert masque.udp_proxy_resource_snapshot(tunnel)
    == masque.UdpProxyResourceSnapshot(
      state: masque.UdpProxyOpen,
      close_calls: 0,
      cleanup_attempts: 0,
      cleanup_failures: 0,
      cleanup_timeouts: 0,
    )
  assert snapshot
    == masque.ProxySetupSnapshot(
      events: [
        masque.ProxyTargetAuthorized,
        masque.ProxyDnsStarted,
        masque.ProxyDnsCompleted(1),
        masque.ProxyDestinationsAuthorized(1),
        masque.ProxySocketStarted,
        masque.ProxySocketOpened,
      ],
      dns_required: True,
      dns_completed: True,
      resolved_addresses: 1,
      authorized_addresses: 1,
      socket_attempted: True,
      adapter_failures: 0,
      adapter_timeouts: 0,
      timing: snapshot.timing,
    )
  assert snapshot.timing.dns_milliseconds >= 0
  assert snapshot.timing.socket_open_milliseconds >= 0
  assert snapshot.timing.dns_timed_out == False
  assert snapshot.timing.socket_open_timed_out == False
  assert snapshot.timing.dns_adapter.callback_started == True
  assert snapshot.timing.dns_adapter.supervisor_timed_out == False
  assert snapshot.timing.socket_open_adapter.callback_started == True
  assert snapshot.timing.socket_open_adapter.supervisor_timed_out == False
  assert snapshot.timing.dns_milliseconds
    >= snapshot.timing.dns_adapter.queue_milliseconds
    + snapshot.timing.dns_adapter.callback_milliseconds
  assert snapshot.timing.socket_open_milliseconds
    >= snapshot.timing.socket_open_adapter.queue_milliseconds
    + snapshot.timing.socket_open_adapter.callback_milliseconds
  assert masque.close_udp_proxy(tunnel) == Ok(Nil)
  assert process.receive(calls, within: 0) == Ok("closed")
  assert masque.close_udp_proxy(tunnel) == Ok(Nil)
  assert process.receive(calls, within: 0) == Error(Nil)
  assert masque.udp_proxy_resource_snapshot(tunnel)
    == masque.UdpProxyResourceSnapshot(
      state: masque.UdpProxyClosed,
      close_calls: 2,
      cleanup_attempts: 1,
      cleanup_failures: 0,
      cleanup_timeouts: 0,
    )
}

pub fn rfc9298_dns_error_and_timeout_reject_without_opening_socket_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let never_open = fn(_, _) { Error(masque.UdpDestinationUnavailable) }

  let assert masque.UdpProxyRejected(
    response_status: 502,
    response_headers: [#("proxy-status", "edge.example;error=dns_error")],
    failure: masque.ProxyDnsError,
    snapshot: dns_error_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
      open_socket: never_open,
    )
  assert dns_error_snapshot.events
    == [
      masque.ProxyTargetAuthorized,
      masque.ProxyDnsStarted,
      masque.ProxySetupFailed(masque.ProxyDnsError),
    ]

  let before = http_test_support.message_queue_length()
  let assert masque.UdpProxyRejected(
    response_status: 504,
    response_headers: [#("proxy-status", "edge.example;error=dns_timeout")],
    failure: masque.ProxyDnsTimeout,
    snapshot: dns_timeout_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(5, 100),
      resolver: fn(_, _) {
        process.sleep(1000)
        Ok([masque.Ipv4(<<203, 0, 113, 7>>)])
      },
      open_socket: never_open,
    )
  assert dns_timeout_snapshot.adapter_timeouts == 1
  assert dns_timeout_snapshot.timing.dns_adapter.supervisor_timed_out == True
  assert dns_timeout_snapshot.timing.dns_milliseconds
    >= dns_timeout_snapshot.timing.dns_adapter.queue_milliseconds
    + dns_timeout_snapshot.timing.dns_adapter.callback_milliseconds
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
}

pub fn rfc9298_setup_trace_attributes_each_finite_adapter_deadline_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let assert masque.UdpProxyRejected(
    response_status: 504,
    response_headers: [
      #("proxy-status", "edge.example;error=connection_timeout"),
    ],
    failure: masque.ProxySocketTimeout,
    snapshot: snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      // This test is about the socket-open deadline. Keep the preceding DNS
      // adapter's budget well outside fresh-VM code-load and scheduler jitter
      // so an overloaded qualification host cannot legitimately time out the
      // wrong phase before the assertion is reached.
      proxy_setup_config(2000, 5),
      resolver: fn(_, _) {
        process.sleep(2)
        Ok([masque.Ipv4(<<203, 0, 113, 7>>)])
      },
      open_socket: fn(_, _) {
        process.sleep(50)
        Error(masque.UdpSocketOpenTimedOut)
      },
    )

  // Durations and deadline attribution are deliberately payload- and
  // target-free. They make a fresh-BEAM scheduler delay distinguishable from
  // DNS, adoption, and cleanup failures without retaining adapter error text.
  assert snapshot.timing.dns_milliseconds >= 2
  assert snapshot.timing.socket_open_milliseconds >= 5
  assert snapshot.timing.socket_adoption_milliseconds == 0
  assert snapshot.timing.socket_cleanup_milliseconds == 0
  assert snapshot.timing.dns_timed_out == False
  assert snapshot.timing.socket_open_timed_out == True
  assert snapshot.timing.socket_adoption_timed_out == False
  assert snapshot.timing.socket_cleanup_timed_out == False
  assert snapshot.timing.dns_adapter.callback_started == True
  assert snapshot.timing.dns_adapter.queue_milliseconds >= 0
  assert snapshot.timing.dns_adapter.callback_milliseconds >= 2
  assert snapshot.timing.dns_adapter.supervisor_timed_out == False
  assert snapshot.timing.socket_open_adapter.callback_started == True
  assert snapshot.timing.socket_open_adapter.queue_milliseconds >= 0
  assert snapshot.timing.socket_open_adapter.callback_milliseconds >= 5
  assert snapshot.timing.socket_open_adapter.supervisor_timed_out == True
  assert snapshot.timing.dns_milliseconds
    >= snapshot.timing.dns_adapter.queue_milliseconds
    + snapshot.timing.dns_adapter.callback_milliseconds
  assert snapshot.timing.socket_open_milliseconds
    >= snapshot.timing.socket_open_adapter.queue_milliseconds
    + snapshot.timing.socket_open_adapter.callback_milliseconds
  assert snapshot.events
    == [
      masque.ProxyTargetAuthorized,
      masque.ProxyDnsStarted,
      masque.ProxyDnsCompleted(1),
      masque.ProxyDestinationsAuthorized(1),
      masque.ProxySocketStarted,
      masque.ProxySetupFailed(masque.ProxySocketTimeout),
    ]

  let assert masque.UdpProxyRejected(
    failure: masque.ProxySocketTimeout,
    snapshot: adapter_reported,
    ..,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Ok([masque.Ipv4(<<203, 0, 113, 7>>)]) },
      open_socket: fn(_, _) { Error(masque.UdpSocketOpenTimedOut) },
    )
  assert adapter_reported.timing.socket_open_timed_out == True
  assert adapter_reported.timing.socket_open_adapter.callback_started == True
  assert adapter_reported.timing.socket_open_adapter.supervisor_timed_out
    == False
  assert adapter_reported.adapter_timeouts == 1
}

pub fn rfc9298_literal_skips_dns_but_still_requires_socket_and_ip_policy_test() -> Nil {
  let target = udp_target()
  let assert Ok(request) =
    masque.connect_udp(masque.Http1, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<192, 0, 2, 6>>), 32),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let never_resolve = fn(_, _) { Error(masque.DnsLookupFailed) }
  let opener = fn(_, _) {
    Ok(masque.udp_socket_resource("literal-socket", fn(_) { Ok(Nil) }))
  }
  let assert masque.UdpProxyReady(
    tunnel: tunnel,
    response_status: 101,
    response_headers: [
      #("connection", "Upgrade"),
      #("upgrade", "connect-udp"),
      #("capsule-protocol", "?1"),
    ],
    snapshot: snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: never_resolve,
      open_socket: opener,
    )
  assert masque.udp_proxy_socket(tunnel) == "literal-socket"
  assert snapshot.events
    == [
      masque.ProxyTargetAuthorized,
      masque.ProxyDnsSkippedForLiteral,
      masque.ProxyDestinationsAuthorized(1),
      masque.ProxySocketStarted,
      masque.ProxySocketOpened,
    ]

  let assert Ok(unsafe_policy) = masque.deny_all(limits())
  let assert Ok(unsafe_policy) = masque.allow_udp(unsafe_policy, target)
  let assert Ok(unsafe_request) =
    masque.authorize_udp_proxy(unsafe_policy, request)
  let assert masque.UdpProxyRejected(
    response_status: 502,
    response_headers: [
      #("proxy-status", "edge.example;error=destination_ip_prohibited"),
    ],
    failure: masque.ProxyDestinationForbidden,
    snapshot: forbidden_snapshot,
  ) =
    masque.establish_udp_proxy(
      unsafe_request,
      proxy_setup_config(100, 100),
      resolver: never_resolve,
      open_socket: fn(_, _) { Error(masque.UdpDestinationUnavailable) },
    )
  assert forbidden_snapshot.socket_attempted == False
}

pub fn proxy_setup_invalid_answers_panics_and_socket_failures_are_redacted_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let never_open = fn(_, _) { Error(masque.UdpDestinationUnavailable) }
  let cases = [
    #(fn(_, _) { Ok([]) }, masque.ProxyDnsAnswerInvalid, 0),
    #(
      fn(_, _) { Ok([masque.Ipv4(<<203, 0, 113>>)]) },
      masque.ProxyDnsAnswerInvalid,
      0,
    ),
    #(
      fn(_, _) -> Result(List(masque.IpAddress), masque.DnsLookupFailure) {
        panic as "private resolver panic"
      },
      masque.ProxyDnsAdapterFailed,
      1,
    ),
  ]
  cases
  |> list.each(fn(example) {
    let #(resolver, expected_failure, adapter_failures) = example
    let assert masque.UdpProxyRejected(
      response_status: 502,
      response_headers: [#("proxy-status", "edge.example;error=dns_error")],
      failure: failure,
      snapshot: snapshot,
    ) =
      masque.establish_udp_proxy(
        authorized,
        proxy_setup_config(100, 100),
        resolver: resolver,
        open_socket: never_open,
      )
    assert failure == expected_failure
    assert snapshot.adapter_failures == adapter_failures
    assert snapshot.timing.dns_adapter.callback_started == True
    assert snapshot.timing.dns_adapter.supervisor_timed_out == False
  })

  let allowed = masque.Ipv4(<<203, 0, 113, 7>>)
  let assert masque.UdpProxyRejected(
    response_status: 502,
    response_headers: [
      #("proxy-status", "edge.example;error=destination_ip_unroutable"),
    ],
    failure: masque.ProxySocketUnroutable,
    snapshot: socket_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Ok([allowed]) },
      open_socket: fn(_, _) { Error(masque.UdpDestinationUnroutable) },
    )
  assert socket_snapshot.events
    |> list.contains(masque.ProxySetupFailed(masque.ProxySocketUnroutable))
  assert socket_snapshot.timing.socket_open_adapter.callback_started == True
  assert socket_snapshot.timing.socket_open_adapter.supervisor_timed_out
    == False
}

pub fn malformed_foreign_proxy_adapters_are_isolated_and_redacted_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let before = http_test_support.message_queue_length()
  let assert masque.UdpProxyRejected(
    response_status: 502,
    response_headers: [#("proxy-status", "edge.example;error=dns_error")],
    failure: masque.ProxyDnsAdapterFailed,
    snapshot: dns_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: http_test_support.malformed_dns_adapter,
      open_socket: fn(_, _) { Error(masque.UdpDestinationUnavailable) },
    )
  assert dns_snapshot.adapter_failures == 1
  assert dns_snapshot.timing.dns_adapter.callback_started == True
  assert dns_snapshot.timing.dns_adapter.supervisor_timed_out == False

  let assert masque.UdpProxyRejected(
    response_status: 500,
    response_headers: [
      #("proxy-status", "edge.example;error=proxy_internal_error"),
    ],
    failure: masque.ProxySocketAdapterFailed,
    snapshot: socket_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Ok([masque.Ipv4(<<203, 0, 113, 7>>)]) },
      open_socket: http_test_support.malformed_udp_socket_adapter,
    )
  assert socket_snapshot.adapter_failures == 1
  assert socket_snapshot.timing.socket_open_adapter.callback_started == True
  assert socket_snapshot.timing.socket_open_adapter.supervisor_timed_out
    == False
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
}

pub fn proxy_cleanup_timeout_retry_and_concurrent_close_are_observable_test() -> Nil {
  let before = http_test_support.message_queue_length()
  let timeout_tunnel =
    literal_proxy_tunnel(5, fn(_) {
      process.sleep(1000)
      Ok(Nil)
    })
  assert masque.close_udp_proxy(timeout_tunnel)
    == Error(masque.ProxySocketCleanupTimeout)
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
  assert masque.udp_proxy_resource_snapshot(timeout_tunnel)
    == masque.UdpProxyResourceSnapshot(
      state: masque.UdpProxyOpen,
      close_calls: 1,
      cleanup_attempts: 1,
      cleanup_failures: 1,
      cleanup_timeouts: 1,
    )
  assert masque.close_udp_proxy(timeout_tunnel)
    == Error(masque.ProxySocketCleanupTimeout)
  assert masque.udp_proxy_resource_snapshot(timeout_tunnel).cleanup_attempts
    == 2

  let started = process.new_subject()
  let concurrent_tunnel =
    literal_proxy_tunnel(5000, fn(_) {
      let release = process.new_subject()
      process.send(started, release)
      process.receive(release, within: 5000)
    })
  let closing =
    http_test_support.start_task(fn() {
      masque.close_udp_proxy(concurrent_tunnel)
    })
  let assert Ok(release) = process.receive(started, within: 5000)
  let competing_close = masque.close_udp_proxy(concurrent_tunnel)
  let in_progress = masque.udp_proxy_resource_snapshot(concurrent_tunnel)
  process.send(release, Nil)
  let owner_close = http_test_support.await_task(closing)
  let final = masque.udp_proxy_resource_snapshot(concurrent_tunnel)
  let trace =
    ConcurrentSocketCloseTrace(
      callback_started: True,
      competing_close:,
      in_progress:,
      owner_close:,
      final:,
    )
  assert trace
    == ConcurrentSocketCloseTrace(
      callback_started: True,
      competing_close: Error(masque.ProxySocketCleanupInProgress),
      in_progress: masque.UdpProxyResourceSnapshot(
        state: masque.UdpProxyClosing,
        close_calls: 2,
        cleanup_attempts: 1,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
      owner_close: Ok(Nil),
      final: masque.UdpProxyResourceSnapshot(
        state: masque.UdpProxyClosed,
        close_calls: 2,
        cleanup_attempts: 1,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
    )
}

pub fn rfc9298_unusable_socket_closes_bound_request_stream_once_test() -> Nil {
  let calls = process.new_subject()
  let tunnel =
    literal_proxy_tunnel(100, fn(timeout_milliseconds) {
      assert timeout_milliseconds == 100
      process.send(calls, "socket-closed")
      Ok(Nil)
    })
  let request_stream =
    masque.udp_request_stream_resource(fn(reason, timeout_milliseconds) {
      assert reason == masque.SocketUnusable
      assert timeout_milliseconds == 100
      process.send(calls, "request-stream-closed")
      Ok(Nil)
    })
  let session = masque.bind_udp_proxy_stream(tunnel, request_stream)

  // Binding owns the two resources without shortening either lifetime.
  assert masque.udp_proxy_session_snapshot(session)
    == masque.UdpProxySessionSnapshot(
      state: masque.UdpProxyOpen,
      termination: None,
      termination_notifications: 0,
      cleanup_attempts: 0,
      cleanup_failures: 0,
      cleanup_timeouts: 0,
      socket: masque.UdpProxyResourceSnapshot(
        state: masque.UdpProxyOpen,
        close_calls: 0,
        cleanup_attempts: 0,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
      request_stream: masque.UdpRequestStreamSnapshot(
        state: masque.UdpProxyOpen,
        close_calls: 0,
        cleanup_attempts: 0,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
    )
  assert process.receive(calls, within: 0) == Error(Nil)

  // An operating-system unusable notification makes the session inactive
  // before cleanup callbacks run, then closes both sides under the finite
  // socket deadline. A duplicate notification is observable but idempotent.
  assert masque.notify_udp_socket_unusable(session) == Ok(Nil)
  assert process.receive(calls, within: 0) == Ok("request-stream-closed")
  assert process.receive(calls, within: 0) == Ok("socket-closed")
  assert masque.notify_udp_socket_unusable(session) == Ok(Nil)
  assert process.receive(calls, within: 0) == Error(Nil)
  assert masque.udp_proxy_session_snapshot(session)
    == masque.UdpProxySessionSnapshot(
      state: masque.UdpProxyClosed,
      termination: Some(masque.SocketUnusable),
      termination_notifications: 2,
      cleanup_attempts: 1,
      cleanup_failures: 0,
      cleanup_timeouts: 0,
      socket: masque.UdpProxyResourceSnapshot(
        state: masque.UdpProxyClosed,
        close_calls: 1,
        cleanup_attempts: 1,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
      request_stream: masque.UdpRequestStreamSnapshot(
        state: masque.UdpProxyClosed,
        close_calls: 1,
        cleanup_attempts: 1,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
    )

  // Termination wins before source and payload inspection. Even a spoofed,
  // oversized packet can only increment the inactive counter afterwards.
  let spoofed = masque.UdpEndpoint(masque.Ipv4(<<203, 0, 113, 9>>), 9)
  let assert masque.DiscardSessionUdpPacket(
    session: session,
    reason: masque.SocketTunnelInactive,
  ) =
    masque.receive_udp_proxy_session_packet(session, spoofed, <<
      0:size(524_224),
    >>)
  assert masque.udp_proxy_session_receiver_snapshot(session)
    == masque.UdpSocketReceiverSnapshot(
      forwarded_packets: 0,
      forwarded_bytes: 0,
      dropped_source_mismatch: 0,
      dropped_oversized: 0,
      dropped_malformed: 0,
      dropped_inactive: 1,
    )
}

pub fn protocol_context_request_stream_resource_cancels_once_test() -> Nil {
  let assert Ok(request_context) =
    context.new(
      context.Http2,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 443),
      within_milliseconds: 1000,
      tls_identity: context.TlsIdentity("proxy.example", None),
      early_data: context.EarlyDataDisabled,
    )
  let tunnel = literal_proxy_tunnel(100, fn(_) { Ok(Nil) })
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.context_udp_request_stream_resource(request_context),
    )
  assert !context.is_cancelled(request_context)

  assert masque.notify_udp_socket_unusable(session) == Ok(Nil)
  assert context.is_cancelled(request_context)
  assert masque.notify_udp_socket_unusable(session) == Ok(Nil)
  let snapshot = masque.udp_proxy_session_snapshot(session)
  assert snapshot.state == masque.UdpProxyClosed
  assert snapshot.termination == Some(masque.SocketUnusable)
  assert snapshot.termination_notifications == 2
  assert snapshot.request_stream.close_calls == 1
  assert snapshot.request_stream.cleanup_attempts == 1
}

pub fn rfc9298_supervised_context_end_closes_udp_for_every_protocol_test() -> Nil {
  [context.Http1, context.Http2, context.Http3]
  |> list.each(assert_supervised_context_end_closes_udp)
}

fn assert_supervised_context_end_closes_udp(protocol: context.Protocol) -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let assert Ok(request_context) =
    context.new(
      protocol,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 443),
      within_milliseconds: 1000,
      tls_identity: context.TlsIdentity("proxy.example", None),
      early_data: context.EarlyDataDisabled,
    )
  let session =
    masque.bind_supervised_system_udp_proxy_context(
      system_udp_tunnel(peer, 25),
      request_context,
    )
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  context.cancel(request_context)
  wait_for_system_udp_session_state(
    session: session,
    expected: masque.UdpProxyClosed,
    attempts: 100,
  )

  let socket = masque.system_udp_socket_snapshot(session)
  assert socket.state == masque.SystemUdpClosed
  assert socket.event_waiting == False
  assert socket.event_timeouts == 0
  assert socket.socket_failures == 0
  let lifetime = masque.udp_proxy_session_snapshot(session)
  assert lifetime.termination == Some(masque.RequestStreamEnded)
  assert lifetime.termination_notifications == 1
  assert lifetime.socket.close_calls == 1
  assert lifetime.request_stream.close_calls == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_request_stream_end_closes_socket_at_same_transition_test() -> Nil {
  let calls = process.new_subject()
  let tunnel =
    literal_proxy_tunnel(100, fn(_) {
      process.send(calls, "socket-closed")
      Ok(Nil)
    })
  let request_stream =
    masque.udp_request_stream_resource(fn(_, _) {
      process.send(calls, "unexpected-request-stream-close")
      Ok(Nil)
    })
  let session = masque.bind_udp_proxy_stream(tunnel, request_stream)

  assert masque.notify_udp_request_stream_ended(session) == Ok(Nil)
  assert process.receive(calls, within: 0) == Ok("socket-closed")
  assert process.receive(calls, within: 0) == Error(Nil)

  // A later kernel notification cannot replace the causal first reason or
  // invoke either already-converged cleanup operation again.
  assert masque.notify_udp_socket_unusable(session) == Ok(Nil)
  assert process.receive(calls, within: 0) == Error(Nil)
  let snapshot = masque.udp_proxy_session_snapshot(session)
  assert snapshot.state == masque.UdpProxyClosed
  assert snapshot.termination == Some(masque.RequestStreamEnded)
  assert snapshot.termination_notifications == 2
  assert snapshot.cleanup_attempts == 1
  assert snapshot.socket.close_calls == 1
  assert snapshot.request_stream
    == masque.UdpRequestStreamSnapshot(
      state: masque.UdpProxyClosed,
      close_calls: 1,
      cleanup_attempts: 1,
      cleanup_failures: 0,
      cleanup_timeouts: 0,
    )
}

pub fn rfc9298_unusable_cleanup_timeout_is_bounded_and_payload_free_test() -> Nil {
  let before = http_test_support.message_queue_length()
  let calls = process.new_subject()
  let tunnel =
    literal_proxy_tunnel(5, fn(_) {
      process.send(calls, "socket-closed")
      Ok(Nil)
    })
  let request_stream =
    masque.udp_request_stream_resource(fn(_, _) {
      process.sleep(1000)
      Ok(Nil)
    })
  let session = masque.bind_udp_proxy_stream(tunnel, request_stream)

  assert masque.notify_udp_socket_unusable(session)
    == Error(masque.UdpProxyCleanupIncomplete(
      socket: None,
      request_stream: Some(masque.UdpRequestStreamCleanupTimeout),
    ))
  assert process.receive(calls, within: 0) == Ok("socket-closed")
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
  assert masque.udp_proxy_session_snapshot(session)
    == masque.UdpProxySessionSnapshot(
      state: masque.UdpProxyClosing,
      termination: Some(masque.SocketUnusable),
      termination_notifications: 1,
      cleanup_attempts: 1,
      cleanup_failures: 1,
      cleanup_timeouts: 1,
      socket: masque.UdpProxyResourceSnapshot(
        state: masque.UdpProxyClosed,
        close_calls: 1,
        cleanup_attempts: 1,
        cleanup_failures: 0,
        cleanup_timeouts: 0,
      ),
      request_stream: masque.UdpRequestStreamSnapshot(
        state: masque.UdpProxyOpen,
        close_calls: 1,
        cleanup_attempts: 1,
        cleanup_failures: 1,
        cleanup_timeouts: 1,
      ),
    )
}

pub fn udp_proxy_application_close_is_supervised_without_skipping_socket_test() -> Nil {
  let before = http_test_support.message_queue_length()
  let calls = process.new_subject()
  let tunnel =
    literal_proxy_tunnel(100, fn(_) {
      process.send(calls, "socket-closed")
      Ok(Nil)
    })
  let request_stream =
    masque.udp_request_stream_resource(fn(_, _) {
      http_test_support.exit_now()
      Ok(Nil)
    })
  let session = masque.bind_udp_proxy_stream(tunnel, request_stream)

  assert masque.close_udp_proxy_session(session)
    == Error(masque.UdpProxyCleanupIncomplete(
      socket: None,
      request_stream: Some(masque.UdpRequestStreamCleanupFailed),
    ))
  assert process.receive(calls, within: 0) == Ok("socket-closed")
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
  let snapshot = masque.udp_proxy_session_snapshot(session)
  assert snapshot.state == masque.UdpProxyClosing
  assert snapshot.termination == Some(masque.ApplicationClosed)
  assert snapshot.cleanup_attempts == 1
  assert snapshot.cleanup_failures == 1
  assert snapshot.request_stream.cleanup_failures == 1
  assert snapshot.socket.state == masque.UdpProxyClosed
}

pub fn rfc9298_concurrent_terminal_notifications_keep_first_reason_test() -> Nil {
  let started = process.new_subject()
  let calls = process.new_subject()
  let tunnel =
    literal_proxy_tunnel(5000, fn(_) {
      process.send(calls, "socket-closed")
      Ok(Nil)
    })
  let request_stream =
    masque.udp_request_stream_resource(fn(_, _) {
      // The worker creates the release subject because a Gleam Subject can be
      // received only by its owner. This two-sided barrier fixes the exact
      // overlap under test without racing a sleep against the cleanup lease.
      let release = process.new_subject()
      process.send(started, release)
      case process.receive(release, within: 5000) {
        Ok(Nil) -> {
          process.send(calls, "request-stream-closed")
          Ok(Nil)
        }
        Error(Nil) -> Error(Nil)
      }
    })
  let session = masque.bind_udp_proxy_stream(tunnel, request_stream)
  let terminating =
    http_test_support.start_task(fn() {
      masque.notify_udp_socket_unusable(session)
    })

  let assert Ok(release) = process.receive(started, within: 5000)
  let competing = masque.notify_udp_request_stream_ended(session)
  let in_progress = masque.udp_proxy_session_snapshot(session)
  process.send(release, Nil)
  let terminating = http_test_support.await_task(terminating)
  let request_stream_close_observed =
    process.receive(calls, within: 0) == Ok("request-stream-closed")
  let socket_close_observed =
    process.receive(calls, within: 0) == Ok("socket-closed")
  let extra_cleanup_event = process.receive(calls, within: 0) != Error(Nil)
  let closed = masque.udp_proxy_session_snapshot(session)
  let trace =
    ConcurrentTerminalTrace(
      callback_started: True,
      competing_notification: competing,
      in_progress_state: in_progress.state,
      in_progress_reason: in_progress.termination,
      in_progress_notifications: in_progress.termination_notifications,
      terminating_notification: terminating,
      request_stream_close_observed:,
      socket_close_observed:,
      extra_cleanup_event:,
      final_state: closed.state,
      final_reason: closed.termination,
      final_cleanup_attempts: closed.cleanup_attempts,
      final_request_stream_attempts: closed.request_stream.cleanup_attempts,
      final_socket_attempts: closed.socket.cleanup_attempts,
    )
  assert trace
    == ConcurrentTerminalTrace(
      callback_started: True,
      competing_notification: Error(masque.UdpProxyTerminationInProgress),
      in_progress_state: masque.UdpProxyClosing,
      in_progress_reason: Some(masque.SocketUnusable),
      in_progress_notifications: 2,
      terminating_notification: Ok(Nil),
      request_stream_close_observed: True,
      socket_close_observed: True,
      extra_cleanup_event: False,
      final_state: masque.UdpProxyClosed,
      final_reason: Some(masque.SocketUnusable),
      final_cleanup_attempts: 1,
      final_request_stream_attempts: 1,
      final_socket_attempts: 1,
    )
}

pub fn proxy_setup_configuration_answer_count_and_heap_are_bounded_test() -> Nil {
  assert masque.proxy_setup_config(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: 0,
      socket_timeout_milliseconds: 100,
      maximum_adapter_heap_words: 262_144,
    )
    == Error(masque.InvalidProxySetup)
  assert masque.proxy_setup_config_with_socket_timeouts(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: 100,
      socket_setup_timeout_milliseconds: 0,
      socket_operation_timeout_milliseconds: 100,
      maximum_adapter_heap_words: 262_144,
    )
    == Error(masque.InvalidProxySetup)
  assert masque.proxy_setup_config_with_socket_timeouts(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: 100,
      socket_setup_timeout_milliseconds: 100,
      socket_operation_timeout_milliseconds: 0,
      maximum_adapter_heap_words: 262_144,
    )
    == Error(masque.InvalidProxySetup)
  assert masque.proxy_setup_config(
      status.TokenIdentifier("bad token"),
      dns_timeout_milliseconds: 100,
      socket_timeout_milliseconds: 100,
      maximum_adapter_heap_words: 262_144,
    )
    == Error(masque.InvalidProxySetup)
  assert masque.proxy_setup_config(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: 100,
      socket_timeout_milliseconds: 100,
      maximum_adapter_heap_words: 1023,
    )
    == Error(masque.InvalidProxySetup)

  let assert Ok(authorized) = authorized_dns_request()
  let too_many_addresses = [
    masque.Ipv4(<<203, 0, 113, 1>>),
    masque.Ipv4(<<203, 0, 113, 2>>),
    masque.Ipv4(<<203, 0, 113, 3>>),
    masque.Ipv4(<<203, 0, 113, 4>>),
    masque.Ipv4(<<203, 0, 113, 5>>),
    masque.Ipv4(<<203, 0, 113, 6>>),
    masque.Ipv4(<<203, 0, 113, 7>>),
    masque.Ipv4(<<203, 0, 113, 8>>),
    masque.Ipv4(<<203, 0, 113, 9>>),
  ]
  let assert masque.UdpProxyRejected(
    failure: masque.ProxyDnsAnswerInvalid,
    snapshot: count_snapshot,
    ..,
  ) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Ok(too_many_addresses) },
      open_socket: fn(_, _) { Error(masque.UdpDestinationUnavailable) },
    )
  assert count_snapshot.dns_completed == True
  assert count_snapshot.resolved_addresses == 9
  assert count_snapshot.socket_attempted == False

  let assert Ok(tiny_heap) =
    masque.proxy_setup_config(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: 100,
      socket_timeout_milliseconds: 100,
      maximum_adapter_heap_words: 1024,
    )
  let before = http_test_support.message_queue_length()
  let assert masque.UdpProxyRejected(
    response_status: 502,
    response_headers: [#("proxy-status", "edge.example;error=dns_error")],
    failure: masque.ProxyDnsAdapterFailed,
    snapshot: heap_snapshot,
  ) =
    masque.establish_udp_proxy(
      authorized,
      tiny_heap,
      resolver: fn(_, _) {
        Ok(list.repeat(masque.Ipv4(<<203, 0, 113, 7>>), times: 100_000))
      },
      open_socket: fn(_, _) { Error(masque.UdpDestinationUnavailable) },
    )
  assert heap_snapshot.adapter_failures == 1
  assert heap_snapshot.timing.dns_adapter.callback_started == True
  assert heap_snapshot.timing.dns_adapter.supervisor_timed_out == False
  process.sleep(10)
  assert http_test_support.message_queue_length() == before
}

pub fn proxy_socket_setup_and_operation_deadlines_are_independent_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let calls = process.new_subject()
  let config =
    proxy_setup_config_with_socket_timeouts(
      dns_timeout_milliseconds: 100,
      socket_setup_timeout_milliseconds: 250,
      socket_operation_timeout_milliseconds: 25,
    )
  let assert masque.UdpProxyReady(tunnel: tunnel, ..) =
    masque.establish_udp_proxy(
      authorized,
      config,
      resolver: fn(_, _) { Ok([masque.Ipv4(<<203, 0, 113, 7>>)]) },
      open_socket: fn(_, timeout_milliseconds) {
        process.send(calls, #("setup", timeout_milliseconds))
        Ok(
          masque.udp_socket_resource("socket", fn(timeout_milliseconds) {
            process.send(calls, #("operation", timeout_milliseconds))
            Ok(Nil)
          }),
        )
      },
    )

  assert process.receive(calls, within: 0) == Ok(#("setup", 250))
  assert masque.close_udp_proxy(tunnel) == Ok(Nil)
  assert process.receive(calls, within: 0) == Ok(#("operation", 25))
  assert process.receive(calls, within: 0) == Error(Nil)
}

pub fn dns_dedup_rebinding_filter_and_ipv6_literal_are_observable_test() -> Nil {
  let assert Ok(authorized) = authorized_dns_request()
  let selected = process.new_subject()
  let allowed = masque.Ipv4(<<203, 0, 113, 7>>)
  let second_allowed = masque.Ipv4(<<203, 0, 113, 8>>)
  let forbidden = masque.Ipv4(<<192, 168, 1, 7>>)
  let assert masque.UdpProxyReady(tunnel: mixed_tunnel, snapshot: mixed, ..) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Ok([allowed, allowed, forbidden, second_allowed]) },
      open_socket: fn(endpoint, _) {
        process.send(selected, endpoint)
        Ok(masque.udp_socket_resource("mixed-socket", fn(_) { Ok(Nil) }))
      },
    )
  assert process.receive(selected, within: 0)
    == Ok(masque.UdpEndpoint(allowed, 443))
  assert mixed.resolved_addresses == 3
  assert mixed.authorized_addresses == 2
  assert mixed.events
    |> list.contains(masque.ProxyDestinationsAuthorized(2))
  assert masque.close_udp_proxy(mixed_tunnel) == Ok(Nil)

  let ipv6 =
    masque.Ipv6(<<
      0x20,
      0x01,
      0x0d,
      0xb8,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0x42,
    >>)
  let ipv6_target = masque.UdpTarget("2001:db8::42", 443)
  let assert Ok(ipv6_request) =
    masque.connect_udp(masque.Http3, "proxy.example", ipv6_target, limits())
  let assert Ok(ipv6_policy) = masque.deny_all(limits())
  let assert Ok(ipv6_policy) = masque.allow_udp(ipv6_policy, ipv6_target)
  let assert Ok(ipv6_policy) =
    masque.allow_udp_destination(ipv6_policy, masque.IpPrefix(ipv6, 128))
  let assert Ok(ipv6_request) =
    masque.authorize_udp_proxy(ipv6_policy, ipv6_request)
  let resolver_calls = process.new_subject()
  let assert masque.UdpProxyReady(tunnel: ipv6_tunnel, snapshot: ipv6_trace, ..) =
    masque.establish_udp_proxy(
      ipv6_request,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) {
        process.send(resolver_calls, Nil)
        Error(masque.DnsLookupFailed)
      },
      open_socket: fn(endpoint, _) {
        assert endpoint == masque.UdpEndpoint(ipv6, 443)
        Ok(masque.udp_socket_resource("ipv6-socket", fn(_) { Ok(Nil) }))
      },
    )
  assert process.receive(resolver_calls, within: 0) == Error(Nil)
  assert ipv6_trace.events
    == [
      masque.ProxyTargetAuthorized,
      masque.ProxyDnsSkippedForLiteral,
      masque.ProxyDestinationsAuthorized(1),
      masque.ProxySocketStarted,
      masque.ProxySocketOpened,
    ]
  assert masque.close_udp_proxy(ipv6_tunnel) == Ok(Nil)
}

fn authorized_dns_request() -> Result(masque.AuthorizedUdpRequest, masque.Error) {
  let target = masque.UdpTarget("dns.example", 443)
  use request <- result.try(masque.connect_udp(
    masque.Http3,
    "proxy.example",
    target,
    limits(),
  ))
  use policy <- result.try(masque.deny_all(limits()))
  use policy <- result.try(masque.allow_udp(policy, target))
  use policy <- result.try(masque.allow_udp_destination(
    policy,
    masque.IpPrefix(masque.Ipv4(<<203, 0, 113, 0>>), 24),
  ))
  masque.authorize_udp_proxy(policy, request)
}

fn proxy_setup_config(
  dns_timeout_milliseconds: Int,
  socket_timeout_milliseconds: Int,
) -> masque.ProxySetupConfig {
  let assert Ok(config) =
    masque.proxy_setup_config(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: dns_timeout_milliseconds,
      socket_timeout_milliseconds: socket_timeout_milliseconds,
      maximum_adapter_heap_words: 262_144,
    )
  config
}

fn proxy_setup_config_with_socket_timeouts(
  dns_timeout_milliseconds dns_timeout_milliseconds: Int,
  socket_setup_timeout_milliseconds socket_setup_timeout_milliseconds: Int,
  socket_operation_timeout_milliseconds socket_operation_timeout_milliseconds: Int,
) -> masque.ProxySetupConfig {
  let assert Ok(config) =
    masque.proxy_setup_config_with_socket_timeouts(
      status.TokenIdentifier("edge.example"),
      dns_timeout_milliseconds: dns_timeout_milliseconds,
      socket_setup_timeout_milliseconds: socket_setup_timeout_milliseconds,
      socket_operation_timeout_milliseconds: socket_operation_timeout_milliseconds,
      maximum_adapter_heap_words: 262_144,
    )
  config
}

fn literal_proxy_tunnel(
  socket_timeout_milliseconds: Int,
  close: fn(Int) -> Result(Nil, Nil),
) -> masque.UdpProxyTunnel(String) {
  let target = udp_target()
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<192, 0, 2, 6>>), 32),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let assert masque.UdpProxyReady(tunnel: tunnel, ..) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, socket_timeout_milliseconds),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
      open_socket: fn(_, _) { Ok(masque.udp_socket_resource("socket", close)) },
    )
  tunnel
}

fn system_udp_session(
  peer: masque.UdpEndpoint,
  socket_timeout_milliseconds: Int,
) -> masque.UdpProxySession(masque.SystemUdpSocket) {
  system_udp_session_with_limits(
    peer: peer,
    socket_timeout_milliseconds: socket_timeout_milliseconds,
    relay_limits: limits(),
  )
}

fn system_udp_session_with_limits(
  peer peer: masque.UdpEndpoint,
  socket_timeout_milliseconds socket_timeout_milliseconds: Int,
  relay_limits relay_limits: masque.Limits,
) -> masque.UdpProxySession(masque.SystemUdpSocket) {
  let tunnel =
    system_udp_tunnel_with_limits(
      peer: peer,
      socket_timeout_milliseconds: socket_timeout_milliseconds,
      relay_limits: relay_limits,
    )
  masque.bind_udp_proxy_stream(
    tunnel,
    masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
  )
}

fn system_udp_tunnel(
  peer: masque.UdpEndpoint,
  socket_timeout_milliseconds: Int,
) -> masque.UdpProxyTunnel(masque.SystemUdpSocket) {
  system_udp_tunnel_with_limits(
    peer: peer,
    socket_timeout_milliseconds: socket_timeout_milliseconds,
    relay_limits: limits(),
  )
}

fn system_udp_tunnel_with_limits(
  peer peer: masque.UdpEndpoint,
  socket_timeout_milliseconds socket_timeout_milliseconds: Int,
  relay_limits relay_limits: masque.Limits,
) -> masque.UdpProxyTunnel(masque.SystemUdpSocket) {
  let masque.UdpEndpoint(address, port) = peer
  let target = masque.UdpTarget("127.0.0.1", port)
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, relay_limits)
  let assert Ok(policy) = masque.deny_all(relay_limits)
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(policy, masque.IpPrefix(address, 32))
  let assert Ok(request) = masque.authorize_udp_proxy(policy, request)
  let assert masque.UdpProxyReady(tunnel: tunnel, ..) =
    masque.establish_system_udp_proxy(
      request,
      proxy_setup_config_with_socket_timeouts(
        dns_timeout_milliseconds: 100,
        socket_setup_timeout_milliseconds: 1000,
        socket_operation_timeout_milliseconds: socket_timeout_milliseconds,
      ),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
  tunnel
}

fn packet_too_big_delivery_is_terminal(
  delivery: masque.PacketTooBigDelivery,
) -> Bool {
  case delivery {
    masque.PacketTooBigDelivered
    | masque.PacketTooBigRateLimited
    | masque.PacketTooBigPermissionDenied
    | masque.PacketTooBigUnsupported
    | masque.PacketTooBigTimedOut
    | masque.PacketTooBigProhibited
    | masque.PacketTooBigDeliveryFailed -> True
  }
}

fn literal_system_udp_tunnel(
  socket: masque.SystemUdpSocket,
  socket_timeout_milliseconds: Int,
) -> masque.UdpProxyTunnel(masque.SystemUdpSocket) {
  let target = udp_target()
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(
      policy,
      masque.IpPrefix(masque.Ipv4(<<192, 0, 2, 6>>), 32),
    )
  let assert Ok(authorized) = masque.authorize_udp_proxy(policy, request)
  let assert masque.UdpProxyReady(tunnel: tunnel, ..) =
    masque.establish_udp_proxy(
      authorized,
      proxy_setup_config(100, socket_timeout_milliseconds),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
      open_socket: fn(_, _) {
        Ok(masque.udp_socket_resource(socket, fn(_) { Ok(Nil) }))
      },
    )
  tunnel
}

pub fn udp_proxy_is_exact_match_default_deny_and_finite_test() -> Nil {
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", udp_target(), limits())
  let assert Ok(policy) = masque.deny_all(limits())
  assert masque.authorize(policy, request) == Error(masque.DestinationForbidden)
  let assert Ok(policy) = masque.allow_udp(policy, udp_target())
  assert masque.authorize(policy, request) == Ok(Nil)

  let assert Ok(other) =
    masque.connect_udp(
      masque.Http3,
      "proxy.example",
      masque.UdpTarget("192.0.2.7", 443),
      limits(),
    )
  assert masque.authorize(policy, other) == Error(masque.DestinationForbidden)

  let tiny = masque.Limits(..limits(), maximum_policy_rules: 1)
  let assert Ok(policy) = masque.deny_all(tiny)
  let assert Ok(policy) = masque.allow_udp(policy, udp_target())
  assert masque.allow_udp(policy, masque.UdpTarget("198.51.100.1", 53))
    == Error(masque.PolicyLimitExceeded(1))
}

pub fn datagram_context_payload_and_udp_ceiling_are_strict_test() -> Nil {
  assert masque.encode_udp_datagram(<<"payload":utf8>>, limits())
    == Ok(<<0, "payload":utf8>>)
  assert masque.decode_udp_datagram(<<0, "payload":utf8>>, limits())
    == Ok(<<"payload":utf8>>)
  assert masque.decode_udp_datagram(<<1, "unknown":utf8>>, limits())
    == Error(masque.UnknownContext(1))

  let too_large = <<0:size(524_224)>>
  assert masque.encode_udp_datagram(too_large, limits())
    == Error(masque.DatagramLimitExceeded(65_527))
  assert masque.decode_udp_datagram(<<0:size(1)>>, limits())
    == Error(masque.NonByteAligned)
}

pub fn rfc9298_proxy_receiver_drops_without_buffering_and_requires_abort_test() -> Nil {
  let assert Ok(receiver) = masque.udp_receiver(limits())
  let assert masque.DropDatagram(receiver, masque.RequestNotReady) =
    masque.receive_proxy_datagram(receiver, <<0, "early":utf8>>)
  assert masque.udp_receiver_snapshot(receiver)
    == masque.UdpReceiverSnapshot(
      active: False,
      accepted: 0,
      dropped_before_request: 1,
      dropped_unknown_context: 0,
      discarded_capsules: 0,
      aborts_required: 0,
    )

  let receiver = masque.activate_udp_receiver(receiver)
  let assert masque.DropDatagram(receiver, masque.ContextNotRegistered(1)) =
    masque.receive_proxy_datagram(receiver, <<1, "unknown":utf8>>)
  let assert masque.ForwardPayload(receiver, <<"payload":utf8>>) =
    masque.receive_proxy_datagram(receiver, <<0, "payload":utf8>>)

  let too_large = <<0, 0:size(524_224)>>
  let assert masque.AbortRequestStream(
    receiver,
    masque.DatagramLimitExceeded(65_527),
  ) = masque.receive_proxy_datagram(receiver, too_large)
  let assert masque.AbortRequestStream(receiver, masque.NonByteAligned) =
    masque.receive_proxy_datagram(receiver, <<0:size(1)>>)
  assert masque.udp_receiver_snapshot(receiver)
    == masque.UdpReceiverSnapshot(
      active: True,
      accepted: 1,
      dropped_before_request: 1,
      dropped_unknown_context: 1,
      discarded_capsules: 0,
      aborts_required: 2,
    )
}

pub fn rfc9298_udp_socket_source_is_checked_before_payload_and_counted_test() -> Nil {
  let tunnel = literal_proxy_tunnel(100, fn(_) { Ok(Nil) })
  let peer = masque.udp_proxy_peer(tunnel)
  let oversized = <<0:size(524_224)>>

  let wrong_address = masque.UdpEndpoint(masque.Ipv4(<<192, 0, 2, 7>>), 443)
  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketSourceMismatch,
  ) = masque.receive_udp_socket_packet(tunnel, wrong_address, oversized)
  assert masque.udp_socket_receiver_snapshot(tunnel)
    == masque.UdpSocketReceiverSnapshot(
      forwarded_packets: 0,
      forwarded_bytes: 0,
      dropped_source_mismatch: 1,
      dropped_oversized: 0,
      dropped_malformed: 0,
      dropped_inactive: 0,
    )

  let masque.UdpEndpoint(address, port) = peer
  let wrong_port = masque.UdpEndpoint(address, port + 1)
  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketSourceMismatch,
  ) = masque.receive_udp_socket_packet(tunnel, wrong_port, <<"ignored":utf8>>)

  let malformed_source = masque.UdpEndpoint(masque.Ipv4(<<192, 0, 2>>), port)
  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketSourceMismatch,
  ) =
    masque.receive_udp_socket_packet(tunnel, malformed_source, <<
      "ignored":utf8,
    >>)

  let assert masque.ForwardHttpDatagram(
    tunnel: tunnel,
    datagram: <<0, "reply":utf8>>,
  ) = masque.receive_udp_socket_packet(tunnel, peer, <<"reply":utf8>>)

  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketPayloadTooLarge(65_527),
  ) = masque.receive_udp_socket_packet(tunnel, peer, oversized)
  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketPayloadMalformed(masque.NonByteAligned),
  ) = masque.receive_udp_socket_packet(tunnel, peer, <<0:size(1)>>)

  assert masque.close_udp_proxy(tunnel) == Ok(Nil)
  let assert masque.DiscardUdpPacket(
    tunnel: tunnel,
    reason: masque.SocketTunnelInactive,
  ) = masque.receive_udp_socket_packet(tunnel, peer, <<"late":utf8>>)
  assert masque.udp_socket_receiver_snapshot(tunnel)
    == masque.UdpSocketReceiverSnapshot(
      forwarded_packets: 1,
      forwarded_bytes: 5,
      dropped_source_mismatch: 3,
      dropped_oversized: 1,
      dropped_malformed: 1,
      dropped_inactive: 1,
    )
}

pub fn rfc9298_live_unconnected_udp_source_tuple_is_enforced_test() -> Nil {
  let #(expected_source, observed_source, payload) =
    http_test_support.udp_loopback_packet(<<"live-source":utf8>>)
  assert observed_source == expected_source
  let masque.UdpEndpoint(address, port) = expected_source
  let target = masque.UdpTarget("127.0.0.1", port)
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(policy, masque.IpPrefix(address, 32))
  let assert Ok(request) = masque.authorize_udp_proxy(policy, request)
  let assert masque.UdpProxyReady(tunnel: tunnel, ..) =
    masque.establish_udp_proxy(
      request,
      proxy_setup_config(100, 100),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
      open_socket: fn(endpoint, _) {
        assert endpoint == expected_source
        Ok(masque.udp_socket_resource("live-socket", fn(_) { Ok(Nil) }))
      },
    )
  let assert masque.ForwardHttpDatagram(
    tunnel: tunnel,
    datagram: <<0, "live-source":utf8>>,
  ) = masque.receive_udp_socket_packet(tunnel, observed_source, payload)
  assert masque.udp_socket_receiver_snapshot(tunnel).forwarded_packets == 1
  assert masque.close_udp_proxy(tunnel) == Ok(Nil)
}

pub fn rfc9298_system_udp_owner_relays_loopback_with_bounded_trace_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let masque.UdpEndpoint(address, port) = peer
  let target = masque.UdpTarget("127.0.0.1", port)
  let assert Ok(request) =
    masque.connect_udp(masque.Http3, "proxy.example", target, limits())
  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_udp(policy, target)
  let assert Ok(policy) =
    masque.allow_udp_destination(policy, masque.IpPrefix(address, 32))
  let assert Ok(request) = masque.authorize_udp_proxy(policy, request)
  let assert masque.UdpProxyReady(tunnel: tunnel, snapshot: setup_trace, ..) =
    masque.establish_system_udp_proxy(
      request,
      proxy_setup_config(1000, 1000),
      resolver: fn(_, _) { Error(masque.DnsLookupFailed) },
    )
  assert list.drop(setup_trace.events, 5)
    == [masque.ProxySocketAdoptionStarted, masque.ProxySocketAdopted]
  assert setup_trace.timing.socket_open_milliseconds >= 0
  assert setup_trace.timing.socket_adoption_milliseconds >= 0
  assert setup_trace.timing.socket_open_timed_out == False
  assert setup_trace.timing.socket_adoption_timed_out == False
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
    )

  let assert masque.SystemUdpSent(session) =
    masque.forward_system_udp_datagram(session, <<0, "echo":utf8>>)
  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "echo":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)

  let snapshot = masque.system_udp_socket_snapshot(session)
  assert snapshot.state == masque.SystemUdpOpen
  assert snapshot.maximum_queued_commands == 8
  assert snapshot.requested_socket_buffer_bytes == 262_144
  assert snapshot.receive_socket_buffer_bytes > 0
  assert snapshot.receive_socket_buffer_bytes <= 16_777_216
  assert snapshot.send_socket_buffer_bytes > 0
  assert snapshot.send_socket_buffer_bytes <= 16_777_216
  assert snapshot.maximum_payload_bytes == 65_527
  assert snapshot.queued_commands == 0
  assert snapshot.buffered_packets == 0
  assert snapshot.receive_waiting == False
  assert snapshot.rejected_commands == 0
  assert snapshot.sent_packets == 1
  assert snapshot.sent_bytes == 4
  assert snapshot.received_packets == 1
  assert snapshot.received_bytes == 4
  assert snapshot.receive_timeouts == 0
  assert snapshot.socket_failures == 0
  assert snapshot.not_ect == True

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  assert masque.system_udp_socket_snapshot(session).state
    == masque.SystemUdpClosed
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_relay_has_one_to_one_bounded_timing_trace_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  let session =
    int.range(from: 0, to: 8, with: session, run: fn(session, _) {
      process.sleep(2)
      let assert masque.SystemUdpSent(session: next) =
        masque.forward_system_udp_datagram(session, <<0, "paced":utf8>>)
      next
    })

  let trace = masque.system_udp_socket_snapshot(session)
  assert trace.sent_packets == 8
  assert trace.relay_timing_samples == 8
  assert trace.maximum_send_batch_packets == 1
  assert trace.maximum_relay_delay_microseconds >= 0
  assert trace.maximum_relay_delay_microseconds < 100_000
  assert trace.maximum_send_service_microseconds >= 0
  assert trace.maximum_send_service_microseconds < 100_000
  assert trace.material_burst_compressions == 0
  assert trace.maximum_burst_compression_microseconds <= 1000
  assert trace.queued_commands == 0

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_live_wire_ignores_target_ecn_and_sends_not_ect_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_ecn_echo_server()
  let session = system_udp_session(peer, 1000)

  let assert masque.SystemUdpSent(session: session) =
    masque.forward_system_udp_datagram(session, <<0, "ecn-wire":utf8>>)
  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "ecn-wire":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)

  let #(received_packets, proxy_to_target_tos, target_to_proxy_tos) =
    http_test_support.udp_ecn_echo_snapshot(echo_server)
  assert received_packets == 1
  assert proxy_to_target_tos == 0
  assert target_to_proxy_tos == 3
  let socket = masque.system_udp_socket_snapshot(session)
  assert socket.not_ect == True
  assert socket.sent_packets == 1
  assert socket.received_packets == 1

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_ipv4_df_rejects_without_fragmentation_retry_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)

  let assert masque.SystemUdpSendFailed(
    session: session,
    failure: masque.SystemUdpMessageTooLarge,
  ) = masque.forward_system_udp_datagram(session, <<0, 0:size(524_216)>>)
  let rejected = masque.system_udp_socket_snapshot(session)
  assert rejected.state == masque.SystemUdpOpen
  assert rejected.dont_fragment == True
  assert rejected.message_too_large_sends == 1
  assert rejected.fragmentation_retries == 0
  assert rejected.sent_packets == 0
  assert rejected.relay_timing_samples == 0

  let assert masque.SystemUdpSent(session: session) =
    masque.forward_system_udp_datagram(session, <<0, "after-emsgsize":utf8>>)
  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "after-emsgsize":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)
  let recovered = masque.system_udp_socket_snapshot(session)
  assert recovered.message_too_large_sends == 1
  assert recovered.fragmentation_retries == 0
  assert recovered.sent_packets == 1

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_target_oversize_is_dropped_before_mailbox_and_reports_ptb_test() -> Nil {
  let response = <<0:size(512)>>
  let #(server, peer) =
    http_test_support.start_udp_fixed_response_server(response)
  let constrained = masque.Limits(..limits(), maximum_datagram_bytes: 33)
  let session =
    system_udp_session_with_limits(
      peer: peer,
      socket_timeout_milliseconds: 1000,
      relay_limits: constrained,
    )

  let assert masque.SystemUdpSent(session: session) =
    masque.forward_system_udp_datagram(session, <<0, "trigger":utf8>>)
  wait_for_system_udp_buffered_packets(
    session: session,
    expected: 1,
    attempts: 100,
  )

  let held = masque.system_udp_socket_snapshot(session)
  let held_ptb = masque.system_udp_packet_too_big_snapshot(session)
  assert held.buffered_packets == 1
  assert held.buffered_payload_bytes == 0
  assert held_ptb.consistent == True
  assert held_ptb.buffered_events == 1
  assert held_ptb.retained_payload_bytes == 0
  assert held_ptb.oversized_target_packets == 1
  assert held_ptb.oversized_target_bytes == 64

  let assert masque.SystemUdpTargetPayloadTooLarge(
    session: session,
    report: masque.PacketTooBigReport(
      family: masque.PacketTooBigIpv4,
      maximum_udp_payload_bytes: 32,
      advertised_mtu_bytes: 60,
      quoted_packet_bytes: 92,
      delivery: delivery,
    ),
  ) = masque.receive_system_udp_datagram(session, 1000)
  assert packet_too_big_delivery_is_terminal(delivery)

  let drained = masque.system_udp_socket_snapshot(session)
  let ptb = masque.system_udp_packet_too_big_snapshot(session)
  assert drained.buffered_packets == 0
  assert drained.buffered_payload_bytes == 0
  assert drained.received_packets == 1
  assert drained.received_bytes == 64
  assert ptb.consistent == True
  assert ptb.target_payload_limit_bytes == 32
  assert ptb.maximum_response_burst == 10
  assert ptb.response_refill_per_second == 10
  assert ptb.maximum_send_deadline_milliseconds == 100
  assert ptb.buffered_events == 0
  assert ptb.retained_payload_bytes == 0
  assert ptb.oversized_target_packets == 1
  assert ptb.oversized_target_bytes == 64
  assert ptb.delivered_messages
    + ptb.rate_limited
    + ptb.permission_denied
    + ptb.unsupported
    + ptb.timed_out
    + ptb.prohibited
    + ptb.failures
    == ptb.oversized_target_packets
  assert ptb.maximum_quote_bytes == 92
  assert ptb.advertised_mtu_bytes == 60

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(server)
}

pub fn rfc9298_packet_too_big_wire_and_rate_limit_vectors_test() -> Nil {
  let #(ipv4, ipv6) = http_test_support.packet_too_big_wire_vectors()
  assert ipv4
    == <<
      0x03,
      0x04,
      0xe9,
      0x35,
      0x00,
      0x00,
      0x00,
      0x20,
      0x45,
      0x00,
      0x00,
      0x25,
      0x00,
      0x00,
      0x00,
      0x00,
      0x40,
      0x11,
      0x8e,
      0x91,
      0xc6,
      0x33,
      0x64,
      0x02,
      0xc0,
      0x00,
      0x02,
      0x01,
      0x01,
      0xbb,
      0x15,
      0xb3,
      0x00,
      0x11,
      0xd5,
      0x6e,
      0x6f,
      0x76,
      0x65,
      0x72,
      0x73,
      0x69,
      0x7a,
      0x65,
      0x64,
    >>
  assert ipv6
    == <<
      0x02,
      0x00,
      0x30,
      0xac,
      0x00,
      0x00,
      0x00,
      0x34,
      0x60,
      0x00,
      0x00,
      0x00,
      0x00,
      0x11,
      0x11,
      0x40,
      0x20,
      0x01,
      0x0d,
      0xb8,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x02,
      0x20,
      0x01,
      0x0d,
      0xb8,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
      0x01,
      0xbb,
      0x15,
      0xb3,
      0x00,
      0x11,
      0x66,
      0x31,
      0x6f,
      0x76,
      0x65,
      0x72,
      0x73,
      0x69,
      0x7a,
      0x65,
      0x64,
    >>

  let #(allowed, limited, refilled) =
    http_test_support.packet_too_big_limiter_trace()
  assert #(allowed, limited, refilled) == #(10, 1, 1)
}

pub fn rfc9298_packet_too_big_builder_bounds_and_prohibitions_test() -> Nil {
  assert http_test_support.packet_too_big_builder_boundary_trace()
    == #(556, 548, 65_535, 1240, 1232, 65_575, 5, 5, 6, 6)
}

pub fn rfc9298_packet_too_big_refills_from_negative_monotonic_epoch_test() -> Nil {
  let trace = http_test_support.packet_too_big_negative_epoch_refill_trace()
  assert trace == #(5, 1, 0, 1)
}

pub fn rfc9298_packet_too_big_orphaned_seqlock_is_finite_test() -> Nil {
  assert http_test_support.packet_too_big_orphaned_seqlock_trace()
    == #(True, False)
}

pub fn rfc9298_packet_too_big_snapshot_is_atomic_under_race_test() -> Nil {
  let #(violations, oversized, outcomes, attempts, cached) =
    http_test_support.packet_too_big_snapshot_race(20_000)
  assert violations == 0
  assert oversized == 20_000
  assert outcomes == 20_000
  assert attempts == 10_000
  assert cached == 10_000
}

/// Wait for a payload-free condition instead of guessing a sleep.
///
/// A fixed sleep is a guess about scheduling: too short and the assertion after
/// it races, too long and every run pays for it. This polls until the condition
/// holds or a finite deadline passes, and reports which happened.
fn await_condition(
  within deadline_milliseconds: Int,
  until check: fn() -> Bool,
) -> Bool {
  use <- bool.guard(when: check(), return: True)
  use <- bool.guard(when: deadline_milliseconds <= 0, return: False)
  process.sleep(1)
  await_condition(within: deadline_milliseconds - 1, until: check)
}

pub fn rfc9298_system_udp_receive_credit_timeout_and_mailbox_converge_test() -> Nil {
  let before = http_test_support.message_queue_length()
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  // The second pull is only refused while the first is still waiting, so the
  // first deadline has to outlast the scheduling delay between them rather
  // than merely exceed a sleep. A tenth of a second did not: under load the
  // first pull expired before the second was issued and the refusal became a
  // timeout.
  let waiting =
    http_test_support.start_task(fn() {
      masque.receive_system_udp_datagram(session, 1000)
    })
  assert await_condition(within: 1000, until: fn() {
    masque.system_udp_socket_snapshot(session).receive_waiting
  })

  let waiting_snapshot = masque.system_udp_socket_snapshot(session)
  assert waiting_snapshot.queued_commands == 0
  assert waiting_snapshot.buffered_packets == 0
  assert waiting_snapshot.receive_waiting == True

  let assert masque.SystemUdpReceiveBusy(session: busy_session) =
    masque.receive_system_udp_datagram(session, 10)
  let assert masque.SystemUdpReceiveTimedOut(session: timed_out_session) =
    http_test_support.await_task(waiting)
  assert masque.system_udp_socket_snapshot(busy_session).rejected_commands == 1
  assert masque.system_udp_socket_snapshot(timed_out_session).receive_timeouts
    == 1
  assert masque.system_udp_socket_snapshot(timed_out_session).receive_waiting
    == False
  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
  assert await_condition(within: 1000, until: fn() {
    http_test_support.message_queue_length() == before
  })
}

pub fn rfc9298_system_udp_fatal_event_closes_request_stream_once_test() -> Nil {
  let closed = http_test_support.closed_system_udp_socket()
  let tunnel = literal_system_udp_tunnel(closed, 100)
  let closed_stream = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(closed_stream, reason)
        Ok(Nil)
      }),
    )

  let assert masque.SystemUdpSocketTerminated(
    session: session,
    failure: masque.SystemUdpSocketClosed,
    cleanup: Ok(Nil),
  ) = masque.receive_system_udp_datagram(session, 10)
  assert process.receive(closed_stream, within: 0) == Ok(masque.SocketUnusable)
  assert masque.udp_proxy_session_snapshot(session).termination
    == Some(masque.SocketUnusable)

  let assert masque.SystemUdpSessionInactive(session: session) =
    masque.receive_system_udp_datagram(session, 10)
  assert process.receive(closed_stream, within: 0) == Error(Nil)
  assert masque.udp_proxy_session_snapshot(session).termination_notifications
    == 1
}

pub fn rfc9298_system_udp_active_once_holds_one_packet_until_credit_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  let assert masque.SystemUdpSent(session) =
    masque.forward_system_udp_datagram(session, <<0, "first":utf8>>)
  let assert masque.SystemUdpSent(session) =
    masque.forward_system_udp_datagram(session, <<0, "second":utf8>>)
  process.sleep(20)

  let held = masque.system_udp_socket_snapshot(session)
  assert held.sent_packets == 2
  assert held.buffered_packets == 1
  assert held.received_packets == 0
  assert held.queued_commands == 0

  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "first":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)
  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "second":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)
  let drained = masque.system_udp_socket_snapshot(session)
  assert drained.buffered_packets == 0
  assert drained.received_packets == 2
  assert drained.received_bytes == 11

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_rejects_before_os_send_and_aborts_stream_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  let assert masque.SystemUdpDatagramDiscarded(
    session: session,
    reason: masque.ContextNotRegistered(1),
  ) = masque.forward_system_udp_datagram(session, <<1, "unknown":utf8>>)
  assert masque.system_udp_socket_snapshot(session).sent_packets == 0

  let oversized = <<0:size(524_232)>>
  let assert masque.SystemUdpRequestStreamAbort(
    session: session,
    error: masque.DatagramLimitExceeded(65_527),
    cleanup: Ok(Nil),
  ) = masque.forward_system_udp_datagram(session, oversized)
  assert masque.system_udp_socket_snapshot(session).sent_packets == 0
  assert masque.system_udp_socket_snapshot(session).state
    == masque.SystemUdpClosed
  assert masque.udp_proxy_session_snapshot(session).termination
    == Some(masque.ApplicationClosed)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_owner_exit_closes_orphan_before_next_call_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let handed_off = process.new_subject()
  let owner =
    http_test_support.start_task(fn() {
      process.send(handed_off, system_udp_session(peer, 100))
      Nil
    })
  let assert Ok(session) = process.receive(handed_off, within: 1000)
  assert http_test_support.await_task(owner) == Nil
  process.sleep(20)
  assert masque.system_udp_socket_snapshot(session).state
    == masque.SystemUdpClosed

  let assert masque.SystemUdpSocketTerminated(
    session: session,
    failure: masque.SystemUdpSocketClosed,
    cleanup: Ok(Nil),
  ) = masque.receive_system_udp_datagram(session, 10)
  assert masque.udp_proxy_session_snapshot(session).termination
    == Some(masque.SocketUnusable)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_actor_crash_converges_credit_and_both_resources_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 100)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  http_test_support.kill_system_udp_owner(socket)

  let assert masque.SystemUdpSocketTerminated(
    session: session,
    failure: masque.SystemUdpSocketClosed,
    cleanup: Ok(Nil),
  ) = masque.receive_system_udp_datagram(session, 10)
  assert process.receive(stream_closed, within: 0) == Ok(masque.SocketUnusable)
  let socket_snapshot = masque.system_udp_socket_snapshot(session)
  assert socket_snapshot.state == masque.SystemUdpClosed
  assert socket_snapshot.queued_commands == 0
  assert socket_snapshot.buffered_packets == 0
  assert socket_snapshot.receive_waiting == False
  assert socket_snapshot.socket_failures == 1
  assert masque.udp_proxy_session_snapshot(session).state
    == masque.UdpProxyClosed
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_event_wait_is_finite_and_payload_free_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)

  let assert masque.SystemUdpEventTimedOut(session: timed_out) =
    masque.wait_system_udp_event(session, 10)
  let snapshot = masque.system_udp_socket_snapshot(timed_out)
  assert snapshot.event_waiting == False
  assert snapshot.event_timeouts == 1
  assert snapshot.socket_failures == 0

  assert masque.close_udp_proxy_session(timed_out) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_event_wait_observes_actor_crash_and_cleans_once_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 100)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  let waiting =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  http_test_support.kill_system_udp_owner(socket)

  let assert masque.SystemUdpEventObserved(
    session: observed,
    failure: masque.SystemUdpSocketClosed,
    cleanup: Ok(Nil),
  ) = http_test_support.await_task(waiting)
  assert process.receive(stream_closed, within: 0) == Ok(masque.SocketUnusable)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  let snapshot = masque.system_udp_socket_snapshot(observed)
  assert snapshot.state == masque.SystemUdpClosed
  assert snapshot.event_waiting == False
  assert snapshot.socket_failures == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_normal_close_wakes_event_waiter_without_reclassification_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 100)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  let waiting =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  let assert masque.SystemUdpEventStopped(session: stopped) =
    http_test_support.await_task(waiting)
  assert process.receive(stream_closed, within: 0)
    == Ok(masque.ApplicationClosed)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  let snapshot = masque.system_udp_socket_snapshot(stopped)
  assert snapshot.state == masque.SystemUdpClosed
  assert snapshot.event_waiting == False
  assert snapshot.socket_failures == 0
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_production_shaped_close_event_cleans_without_next_io_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 100)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  let waiting =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  http_test_support.close_system_udp_port_and_notify_owner(socket)

  let assert masque.SystemUdpEventObserved(
    session: observed,
    failure: masque.SystemUdpSocketClosed,
    cleanup: Ok(Nil),
  ) = http_test_support.await_task(waiting)
  assert process.receive(stream_closed, within: 0) == Ok(masque.SocketUnusable)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  let snapshot = masque.system_udp_socket_snapshot(observed)
  assert snapshot.state == masque.SystemUdpClosed
  assert snapshot.event_waiting == False
  assert snapshot.socket_failures == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_supervised_system_udp_session_holds_terminal_waiter_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 25)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_supervised_system_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  // The terminal watcher is not a short poll based on the socket-operation
  // deadline. With no traffic it remains installed and records no timeout.
  process.sleep(50)
  let idle = masque.system_udp_socket_snapshot(session)
  assert idle.state == masque.SystemUdpOpen
  assert idle.event_waiting == True
  assert idle.event_timeouts == 0

  // No send, receive, or explicit wait follows this production-shaped event.
  // The permanent watcher alone must close the request stream and UDP owner.
  http_test_support.close_system_udp_port_and_notify_owner(socket)
  assert process.receive(stream_closed, within: 1000)
    == Ok(masque.SocketUnusable)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  wait_for_system_udp_session_state(
    session: session,
    expected: masque.UdpProxyClosed,
    attempts: 100,
  )
  let closed_socket = masque.system_udp_socket_snapshot(session)
  assert closed_socket.state == masque.SystemUdpClosed
  assert closed_socket.event_waiting == False
  assert closed_socket.event_timeouts == 0
  assert closed_socket.socket_failures == 1
  let closed_session = masque.udp_proxy_session_snapshot(session)
  assert closed_session.termination == Some(masque.SocketUnusable)
  assert closed_session.termination_notifications == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_supervised_system_udp_normal_close_preserves_reason_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 25)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_supervised_system_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  assert process.receive(stream_closed, within: 1000)
    == Ok(masque.ApplicationClosed)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  wait_for_system_udp_event_waiter(
    session: session,
    expected: False,
    attempts: 100,
  )
  let socket = masque.system_udp_socket_snapshot(session)
  assert socket.state == masque.SystemUdpClosed
  assert socket.event_timeouts == 0
  assert socket.socket_failures == 0
  let lifetime = masque.udp_proxy_session_snapshot(session)
  assert lifetime.state == masque.UdpProxyClosed
  assert lifetime.termination == Some(masque.ApplicationClosed)
  assert lifetime.termination_notifications == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_idle_activity_is_event_driven_bounded_and_atomic_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let stream_closed = process.new_subject()
  let session =
    masque.bind_supervised_system_udp_proxy_stream_with_idle(
      system_udp_tunnel(peer, 1000),
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
      masque.udp_proxy_idle_timeout_for_testing(5000),
    )
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  let initial = masque.udp_proxy_idle_snapshot(session)

  let active =
    int.range(from: 0, to: 64, with: session, run: fn(session, _) {
      require_idle_activity_send(
        masque.forward_system_udp_datagram(session, <<0, "activity":utf8>>),
      )
    })
  let activity = masque.udp_proxy_idle_snapshot(active)
  let close = masque.close_udp_proxy_session(active)
  let close_reason = process.receive(stream_closed, within: 5000)
  wait_for_udp_idle_state(
    session: active,
    expected: masque.UdpIdleStopped,
    attempts: 100,
  )
  wait_for_system_udp_session_state(
    session: active,
    expected: masque.UdpProxyClosed,
    attempts: 100,
  )
  let stopped = masque.udp_proxy_idle_snapshot(active)
  let lifetime = masque.udp_proxy_session_snapshot(active)
  let trace =
    IdleActivityTrace(
      initial_state: initial.state,
      timeout_milliseconds: initial.timeout_milliseconds,
      activity_state: activity.state,
      activity_events: activity.activity_events,
      outbound_events: activity.outbound_activity_events,
      inbound_events: activity.inbound_activity_events,
      accounting_consistent: activity.activity_events
        == activity.outbound_activity_events + activity.inbound_activity_events,
      wake_credit_bounded: activity.maximum_pending_commands == 1
        && activity.wake_signals <= activity.activity_events
        && activity.owner_wakeups <= activity.wake_signals,
      close:,
      close_reason:,
      final_idle_state: stopped.state,
      expirations: stopped.expirations,
      stop_signals: stopped.stop_signals,
      final_lifetime_state: lifetime.state,
      final_reason: lifetime.termination,
    )
  assert trace
    == IdleActivityTrace(
      initial_state: masque.UdpIdleWatching,
      timeout_milliseconds: Some(5000),
      activity_state: masque.UdpIdleWatching,
      activity_events: 64,
      outbound_events: 64,
      inbound_events: 0,
      accounting_consistent: True,
      wake_credit_bounded: True,
      close: Ok(Nil),
      close_reason: Ok(masque.ApplicationClosed),
      final_idle_state: masque.UdpIdleStopped,
      expirations: 0,
      stop_signals: 1,
      final_lifetime_state: masque.UdpProxyClosed,
      final_reason: Some(masque.ApplicationClosed),
    )
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_idle_owner_expires_without_activity_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let stream_closed = process.new_subject()
  let session =
    masque.bind_supervised_system_udp_proxy_stream_with_idle(
      system_udp_tunnel(peer, 1000),
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
      masque.udp_proxy_idle_timeout_for_testing(1000),
    )
  let initial = masque.udp_proxy_idle_snapshot(session)
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  // With no activity, the short package-internal policy exercises the same
  // owner deadline and first-reason transition as the public two-minute floor.
  let close_reason = process.receive(stream_closed, within: 5000)
  wait_for_udp_idle_state(
    session: session,
    expected: masque.UdpIdleExpired,
    attempts: 100,
  )
  wait_for_system_udp_session_state(
    session: session,
    expected: masque.UdpProxyClosed,
    attempts: 100,
  )
  let expired = masque.udp_proxy_idle_snapshot(session)
  let lifetime = masque.udp_proxy_session_snapshot(session)
  let socket = masque.system_udp_socket_snapshot(session)
  let trace =
    IdleExpiryTrace(
      initial_state: initial.state,
      timeout_milliseconds: initial.timeout_milliseconds,
      close_reason:,
      final_idle_state: expired.state,
      pending_command: expired.pending_command,
      deadline_observed: expired.deadline_checks > 0,
      expirations: expired.expirations,
      stop_signals: expired.stop_signals,
      lifetime_state: lifetime.state,
      lifetime_reason: lifetime.termination,
      termination_notifications: lifetime.termination_notifications,
      socket_close_calls: lifetime.socket.close_calls,
      request_stream_close_calls: lifetime.request_stream.close_calls,
      socket_state: socket.state,
      socket_failures: socket.socket_failures,
    )
  assert trace
    == IdleExpiryTrace(
      initial_state: masque.UdpIdleWatching,
      timeout_milliseconds: Some(1000),
      close_reason: Ok(masque.IdleTimeout),
      final_idle_state: masque.UdpIdleExpired,
      pending_command: False,
      deadline_observed: True,
      expirations: 1,
      stop_signals: 0,
      lifetime_state: masque.UdpProxyClosed,
      lifetime_reason: Some(masque.IdleTimeout),
      termination_notifications: 1,
      socket_close_calls: 1,
      request_stream_close_calls: 1,
      socket_state: masque.SystemUdpClosed,
      socket_failures: 0,
    )
  http_test_support.stop_udp_echo_server(echo_server)
}

fn require_idle_activity_send(
  outcome: masque.SystemUdpIo,
) -> masque.UdpProxySession(masque.SystemUdpSocket) {
  case outcome {
    masque.SystemUdpSent(session) -> session
    other -> {
      let #(kind, session) = redacted_system_udp_io(other)
      let idle = masque.udp_proxy_idle_snapshot(session)
      let lifetime = masque.udp_proxy_session_snapshot(session)
      let socket = masque.system_udp_socket_snapshot(session)
      panic as format_idle_activity_send_failure(IdleActivitySendFailureTrace(
          kind:,
          idle_state: idle.state,
          activity_events: idle.activity_events,
          lifetime_state: lifetime.state,
          lifetime_reason: lifetime.termination,
          socket_state: socket.state,
        ))
    }
  }
}

fn redacted_system_udp_io(
  outcome: masque.SystemUdpIo,
) -> #(SystemUdpIoOutcomeKind, masque.UdpProxySession(masque.SystemUdpSocket)) {
  case outcome {
    masque.SystemUdpSessionInactive(session) -> #(SystemUdpIoInactive, session)
    masque.SystemUdpSent(session) -> #(SystemUdpIoSent, session)
    masque.SystemUdpDatagramDiscarded(session:, ..) -> #(
      SystemUdpIoDiscarded,
      session,
    )
    masque.SystemUdpRequestStreamAbort(session:, ..) -> #(
      SystemUdpIoAbort,
      session,
    )
    masque.SystemUdpForward(session:, ..) -> #(SystemUdpIoForward, session)
    masque.SystemUdpTargetPayloadTooLarge(session:, ..) -> #(
      SystemUdpIoTooLarge,
      session,
    )
    masque.SystemUdpSocketPacketDiscarded(session:, ..) -> #(
      SystemUdpIoSocketDiscarded,
      session,
    )
    masque.SystemUdpReceiveTimedOut(session) -> #(
      SystemUdpIoReceiveTimeout,
      session,
    )
    masque.SystemUdpReceiveBusy(session) -> #(SystemUdpIoReceiveBusy, session)
    masque.SystemUdpReceiveFailed(session:, ..) -> #(
      SystemUdpIoReceiveFailure,
      session,
    )
    masque.SystemUdpSendBusy(session) -> #(SystemUdpIoSendBusy, session)
    masque.SystemUdpSendFailed(session:, ..) -> #(
      SystemUdpIoSendFailure,
      session,
    )
    masque.SystemUdpSocketTerminated(session:, ..) -> #(
      SystemUdpIoTerminated,
      session,
    )
  }
}

fn format_idle_activity_send_failure(
  trace: IdleActivitySendFailureTrace,
) -> String {
  let IdleActivitySendFailureTrace(
    kind:,
    idle_state:,
    activity_events:,
    lifetime_state:,
    lifetime_reason:,
    socket_state:,
  ) = trace
  "idle_activity_send_failure{kind="
  <> system_udp_io_outcome_kind_name(kind)
  <> ",idle_state="
  <> udp_proxy_idle_state_name(idle_state)
  <> ",activity_events="
  <> int.to_string(activity_events)
  <> ",lifetime_state="
  <> udp_proxy_resource_state_name(lifetime_state)
  <> ",lifetime_reason="
  <> optional_udp_proxy_termination_reason_name(lifetime_reason)
  <> ",socket_state="
  <> system_udp_socket_state_name(socket_state)
  <> "}"
}

fn system_udp_io_outcome_kind_name(kind: SystemUdpIoOutcomeKind) -> String {
  case kind {
    SystemUdpIoInactive -> "inactive"
    SystemUdpIoSent -> "sent"
    SystemUdpIoDiscarded -> "discarded"
    SystemUdpIoAbort -> "abort"
    SystemUdpIoForward -> "forward"
    SystemUdpIoTooLarge -> "too-large"
    SystemUdpIoSocketDiscarded -> "socket-discarded"
    SystemUdpIoReceiveTimeout -> "receive-timeout"
    SystemUdpIoReceiveBusy -> "receive-busy"
    SystemUdpIoReceiveFailure -> "receive-failed"
    SystemUdpIoSendBusy -> "send-busy"
    SystemUdpIoSendFailure -> "send-failed"
    SystemUdpIoTerminated -> "terminated"
  }
}

fn udp_proxy_idle_state_name(state: masque.UdpProxyIdleState) -> String {
  case state {
    masque.UdpIdleDisabled -> "disabled"
    masque.UdpIdleWatching -> "watching"
    masque.UdpIdleStopped -> "stopped"
    masque.UdpIdleExpired -> "expired"
  }
}

fn udp_proxy_resource_state_name(
  state: masque.UdpProxyResourceState,
) -> String {
  case state {
    masque.UdpProxyOpen -> "open"
    masque.UdpProxyClosing -> "closing"
    masque.UdpProxyClosed -> "closed"
  }
}

fn optional_udp_proxy_termination_reason_name(
  reason: Option(masque.UdpProxyTerminationReason),
) -> String {
  case reason {
    None -> "none"
    Some(masque.RequestStreamEnded) -> "request-stream-ended"
    Some(masque.SocketUnusable) -> "socket-unusable"
    Some(masque.ApplicationClosed) -> "application-closed"
    Some(masque.IdleTimeout) -> "idle-timeout"
  }
}

fn system_udp_socket_state_name(state: masque.SystemUdpSocketState) -> String {
  case state {
    masque.SystemUdpSetup -> "setup"
    masque.SystemUdpOpen -> "open"
    masque.SystemUdpUnusable -> "unusable"
    masque.SystemUdpClosed -> "closed"
  }
}

pub fn idle_activity_send_failure_trace_is_stable_and_bounded_test() -> Nil {
  let trace =
    IdleActivitySendFailureTrace(
      kind: SystemUdpIoSendFailure,
      idle_state: masque.UdpIdleWatching,
      activity_events: 7,
      lifetime_state: masque.UdpProxyClosing,
      lifetime_reason: Some(masque.SocketUnusable),
      socket_state: masque.SystemUdpUnusable,
    )
  assert format_idle_activity_send_failure(trace)
    == "idle_activity_send_failure{kind=send-failed,idle_state=watching,activity_events=7,lifetime_state=closing,lifetime_reason=socket-unusable,socket_state=unusable}"
}

pub fn rfc9298_system_udp_idle_owner_stops_without_reclassification_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session =
    masque.bind_supervised_system_udp_proxy_stream_with_idle(
      system_udp_tunnel(peer, 25),
      masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
      masque.udp_proxy_idle_timeout_for_testing(100),
    )
  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  wait_for_udp_idle_state(
    session: session,
    expected: masque.UdpIdleStopped,
    attempts: 100,
  )
  process.sleep(125)
  let idle = masque.udp_proxy_idle_snapshot(session)
  assert idle.state == masque.UdpIdleStopped
  assert idle.expirations == 0
  assert idle.stop_signals == 1
  let lifetime = masque.udp_proxy_session_snapshot(session)
  assert lifetime.termination == Some(masque.ApplicationClosed)
  assert lifetime.termination_notifications == 1
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_udp_idle_trace_distinguishes_bidirectional_activity_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session =
    masque.bind_supervised_system_udp_proxy_stream_with_idle(
      system_udp_tunnel(peer, 1000),
      masque.udp_request_stream_resource(fn(_, _) { Ok(Nil) }),
      masque.udp_proxy_idle_timeout_for_testing(1000),
    )

  let initial = masque.udp_proxy_idle_snapshot(session)
  assert initial.activity_events == 0
  assert initial.outbound_activity_events == 0
  assert initial.inbound_activity_events == 0

  // A rejected HTTP Datagram cannot keep a target socket alive.
  let assert masque.SystemUdpDatagramDiscarded(
    session: session,
    reason: masque.ContextNotRegistered(1),
  ) = masque.forward_system_udp_datagram(session, <<1, "ignored":utf8>>)
  let rejected = masque.udp_proxy_idle_snapshot(session)
  assert rejected.activity_events == 0
  assert rejected.outbound_activity_events == 0
  assert rejected.inbound_activity_events == 0

  let assert masque.SystemUdpSent(session: session) =
    masque.forward_system_udp_datagram(session, <<0, "direction":utf8>>)
  let outbound = masque.udp_proxy_idle_snapshot(session)
  assert outbound.activity_events == 1
  assert outbound.outbound_activity_events == 1
  assert outbound.inbound_activity_events == 0

  let assert masque.SystemUdpForward(
    session: session,
    datagram: <<0, "direction":utf8>>,
  ) = masque.receive_system_udp_datagram(session, 1000)
  let round_trip = masque.udp_proxy_idle_snapshot(session)
  assert round_trip.activity_events == 2
  assert round_trip.outbound_activity_events == 1
  assert round_trip.inbound_activity_events == 1

  assert masque.close_udp_proxy_session(session) == Ok(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_udp_idle_direction_snapshot_is_atomic_under_race_test() -> Nil {
  let #(violations, total, outbound, inbound) =
    http_test_support.idle_direction_snapshot_race(20_000)
  assert violations == 0
  assert total == 40_000
  assert outbound == 20_000
  assert inbound == 20_000
}

pub fn rfc9298_terminal_system_udp_session_rejects_before_parse_or_io_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  assert masque.close_udp_proxy_session(session) == Ok(Nil)

  let lifetime_before = masque.udp_proxy_session_snapshot(session)
  let receiver_before = masque.udp_proxy_session_receiver_snapshot(session)
  let socket_before = masque.system_udp_socket_snapshot(session)

  // This bit array is deliberately malformed. A terminal session must reject
  // it before Context ID/alignment parsing or an owner command is attempted.
  let assert masque.SystemUdpSessionInactive(session: session) =
    masque.forward_system_udp_datagram(session, <<0:size(1)>>)
  let assert masque.SystemUdpSessionInactive(session: session) =
    masque.receive_system_udp_datagram(session, 10)

  assert masque.udp_proxy_session_snapshot(session) == lifetime_before
  assert masque.udp_proxy_session_receiver_snapshot(session) == receiver_before
  assert masque.system_udp_socket_snapshot(session) == socket_before
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_event_and_datagram_waiters_have_independent_credit_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  let event_wait =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  let assert masque.SystemUdpSent(session: sent) =
    masque.forward_system_udp_datagram(session, <<0, "independent":utf8>>)
  let assert masque.SystemUdpForward(
    session: received,
    datagram: <<0, "independent":utf8>>,
  ) = masque.receive_system_udp_datagram(sent, 1000)
  assert masque.system_udp_socket_snapshot(received).event_waiting == True

  assert masque.close_udp_proxy_session(received) == Ok(Nil)
  let assert masque.SystemUdpEventStopped(..) =
    http_test_support.await_task(event_wait)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_duplicate_event_waiter_is_busy_then_converges_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let session = system_udp_session(peer, 1000)
  // Timeout delivery itself has a dedicated test. Keep this waiter alive long
  // enough to make duplicate admission, rather than a scheduler race with its
  // expiry, the only transition under test here.
  let first =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 5000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )

  let registered = masque.system_udp_socket_snapshot(session)
  let duplicate = masque.wait_system_udp_event(session, 1000)
  let after_duplicate = masque.system_udp_socket_snapshot(session)
  let close_succeeded = masque.close_udp_proxy_session(session) == Ok(Nil)
  let first = http_test_support.await_task(first)
  let final = masque.system_udp_socket_snapshot(session)
  let trace =
    DuplicateEventWaiterTrace(
      registration_seen: registered.event_waiting,
      registration_queued_commands: registered.queued_commands,
      registration_timeouts: registered.event_timeouts,
      registration_rejections: registered.rejected_commands,
      duplicate: event_wait_terminal(duplicate),
      after_duplicate_waiting: after_duplicate.event_waiting,
      after_duplicate_queued_commands: after_duplicate.queued_commands,
      after_duplicate_timeouts: after_duplicate.event_timeouts,
      after_duplicate_rejections: after_duplicate.rejected_commands,
      close_succeeded:,
      first: event_wait_terminal(first),
      final_state: final.state,
      final_waiting: final.event_waiting,
      final_queued_commands: final.queued_commands,
      final_timeouts: final.event_timeouts,
      final_rejections: final.rejected_commands,
      final_socket_failures: final.socket_failures,
    )
  assert trace
    == DuplicateEventWaiterTrace(
      registration_seen: True,
      registration_queued_commands: 0,
      registration_timeouts: 0,
      registration_rejections: 0,
      duplicate: EventWaitBusy,
      after_duplicate_waiting: True,
      after_duplicate_queued_commands: 0,
      after_duplicate_timeouts: 0,
      after_duplicate_rejections: 1,
      close_succeeded: True,
      first: EventWaitStopped,
      final_state: masque.SystemUdpClosed,
      final_waiting: False,
      final_queued_commands: 0,
      final_timeouts: 0,
      final_rejections: 1,
      final_socket_failures: 0,
    )
  http_test_support.stop_udp_echo_server(echo_server)
}

fn event_wait_terminal(wait: masque.SystemUdpEventWait) -> EventWaitTerminal {
  case wait {
    masque.SystemUdpEventObserved(failure:, ..) -> EventWaitObserved(failure)
    masque.SystemUdpEventTimedOut(..) -> EventWaitTimedOut
    masque.SystemUdpEventBusy(..) -> EventWaitBusy
    masque.SystemUdpEventStopped(..) -> EventWaitStopped
    masque.SystemUdpEventFailed(failure:, ..) -> EventWaitFailed(failure)
  }
}

pub fn rfc9298_system_udp_error_releases_both_waiters_and_cleans_once_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let tunnel = system_udp_tunnel(peer, 100)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  let datagram_wait =
    http_test_support.start_task(fn() {
      masque.receive_system_udp_datagram(session, 1000)
    })
  let event_wait =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_receive_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  http_test_support.notify_system_udp_error(socket)

  let assert masque.SystemUdpSocketTerminated(
    session: datagram_session,
    failure: masque.SystemUdpSocketFailure,
    ..,
  ) = http_test_support.await_task(datagram_wait)
  let assert masque.SystemUdpEventObserved(
    session: event_session,
    failure: masque.SystemUdpSocketFailure,
    ..,
  ) = http_test_support.await_task(event_wait)
  assert process.receive(stream_closed, within: 0) == Ok(masque.SocketUnusable)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  let socket_snapshot = masque.system_udp_socket_snapshot(event_session)
  assert socket_snapshot.state == masque.SystemUdpClosed
  assert socket_snapshot.receive_waiting == False
  assert socket_snapshot.event_waiting == False
  assert socket_snapshot.socket_failures == 1
  assert masque.udp_proxy_session_snapshot(datagram_session).termination
    == Some(masque.SocketUnusable)
  assert masque.udp_proxy_session_snapshot(event_session).termination_notifications
    == 2
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_error_cancels_live_http3_request_stream_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(server_configuration) =
    http3_server.new(certificate, private_key)
  let assert Ok(server_configuration) =
    http3_server.with_timeout(server_configuration, 3000)
  let assert Ok(listener) =
    server_configuration
    |> http3_server.with_http_datagrams
    |> http3_server.start
  let assert Ok(port) = http3_server.port(listener)
  let assert Ok(client_configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let client_configuration =
    client_configuration |> http3_client.with_http_datagrams
  let assert Ok(connection) =
    http3_client.connect(client_configuration, "localhost", port)
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/.well-known/masque/udp/127.0.0.1/9/")
    |> request.set_body(Nil)
  let assert Ok(stream) =
    http3_client.open_extended_connect(connection, outgoing, "connect-udp")
  let assert Ok(incoming) = http3_server.accept(listener)
  assert http3_server.protocol(incoming) == Some("connect-udp")
  assert http3_server.send_response(incoming, 200, [#("capsule-protocol", "?1")])
    == Ok(Nil)
  assert http3_client.next_event(stream)
    == Ok(http3_client.Response(200, [#("capsule-protocol", "?1")]))

  let tunnel = system_udp_tunnel(peer, 1000)
  let socket = masque.udp_proxy_socket(tunnel)
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.http3_udp_request_stream_resource(incoming),
    )
  let event_wait =
    http_test_support.start_task(fn() {
      masque.wait_system_udp_event(session, 1000)
    })
  wait_for_system_udp_event_waiter(
    session: session,
    expected: True,
    attempts: 100,
  )
  http_test_support.notify_system_udp_error(socket)

  let assert masque.SystemUdpEventObserved(
    session: observed,
    failure: masque.SystemUdpSocketFailure,
    cleanup: Ok(Nil),
  ) = http_test_support.await_task(event_wait)
  assert http3_client.next_event(stream)
    == Error(
      http3_client.Failure(http3_failure.Closed(http3_failure.Peer, Some(0x10c))),
    )
  assert http3_server.cancel(incoming) == Ok(http3_server.AlreadyCancelled)
  assert masque.notify_udp_socket_unusable(observed) == Ok(Nil)
  let snapshot = masque.udp_proxy_session_snapshot(observed)
  assert snapshot.state == masque.UdpProxyClosed
  assert snapshot.termination == Some(masque.SocketUnusable)
  assert snapshot.termination_notifications == 2
  assert snapshot.cleanup_attempts == 1
  assert snapshot.request_stream.close_calls == 1
  assert snapshot.request_stream.cleanup_attempts == 1
  assert snapshot.socket.close_calls == 1
  assert snapshot.socket.cleanup_attempts == 1

  let _closed = http3_client.close(connection)
  assert http3_server.stop(listener) == Ok(http3_server.Stopped)
  http_test_support.stop_udp_echo_server(echo_server)
}

pub fn rfc9298_system_udp_command_flood_is_grant_before_growth_test() -> Nil {
  let #(echo_server, peer) = http_test_support.start_udp_echo_server()
  // This test drives each receive with its own 1 ms deadline below. Give the
  // unrelated fresh-BEAM socket-owner startup a production-shaped budget so
  // scheduler cold-start latency cannot masquerade as a command-credit bug.
  let tunnel = system_udp_tunnel(peer, 1000)
  let socket = masque.udp_proxy_socket(tunnel)
  let stream_closed = process.new_subject()
  let session =
    masque.bind_udp_proxy_stream(
      tunnel,
      masque.udp_request_stream_resource(fn(reason, _) {
        process.send(stream_closed, reason)
        Ok(Nil)
      }),
    )
  http_test_support.suspend_system_udp_owner(socket)
  let admitted =
    list.repeat(Nil, times: 8)
    |> list.map(fn(_) {
      http_test_support.start_task(fn() {
        masque.receive_system_udp_datagram(session, 1)
      })
    })
  wait_for_system_udp_queue(session: session, expected: 8, attempts: 100)
  let queued = masque.system_udp_socket_snapshot(session)
  assert queued.queued_commands == 8
  assert queued.maximum_queued_commands == 8

  let assert masque.SystemUdpReceiveBusy(session: busy_session) =
    masque.receive_system_udp_datagram(session, 1)
  assert masque.system_udp_socket_snapshot(busy_session).rejected_commands == 1
  list.each(admitted, fn(task) {
    let assert masque.SystemUdpSocketTerminated(..) =
      http_test_support.await_task(task)
  })

  let converged = masque.system_udp_socket_snapshot(session)
  assert converged.state == masque.SystemUdpClosed
  assert converged.queued_commands == 0
  assert converged.buffered_packets == 0
  assert converged.receive_waiting == False
  assert converged.rejected_commands == 1
  assert converged.socket_failures == 1
  assert process.receive(stream_closed, within: 0) == Ok(masque.SocketUnusable)
  assert process.receive(stream_closed, within: 0) == Error(Nil)
  http_test_support.stop_udp_echo_server(echo_server)
}

fn wait_for_system_udp_queue(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: Int,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.system_udp_socket_snapshot(session).queued_commands
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_system_udp_queue(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

fn wait_for_system_udp_buffered_packets(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: Int,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.system_udp_socket_snapshot(session).buffered_packets
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_system_udp_buffered_packets(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

fn wait_for_system_udp_event_waiter(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: Bool,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.system_udp_socket_snapshot(session).event_waiting
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_system_udp_event_waiter(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

fn wait_for_system_udp_session_state(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: masque.UdpProxyResourceState,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.udp_proxy_session_snapshot(session).state
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_system_udp_session_state(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

fn wait_for_udp_idle_state(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: masque.UdpProxyIdleState,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.udp_proxy_idle_snapshot(session).state
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_udp_idle_state(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

fn wait_for_system_udp_receive_waiter(
  session session: masque.UdpProxySession(masque.SystemUdpSocket),
  expected expected: Bool,
  attempts attempts: Int,
) -> Nil {
  let observed = masque.system_udp_socket_snapshot(session).receive_waiting
  case observed == expected, attempts {
    True, _ -> Nil
    False, remaining if remaining > 0 -> {
      process.sleep(1)
      wait_for_system_udp_receive_waiter(
        session: session,
        expected: expected,
        attempts: remaining - 1,
      )
    }
    False, _ -> {
      assert observed == expected
      Nil
    }
  }
}

pub fn rfc9298_datagram_capsule_admission_discards_before_payload_test() -> Nil {
  let capsule_limits = masque.Limits(..limits(), maximum_capsule_bytes: 4)
  let assert Ok(receiver) = masque.udp_receiver(capsule_limits)

  let assert Ok(masque.DiscardDatagramCapsule(receiver, masque.RequestNotReady)) =
    masque.admit_proxy_datagram_capsule(receiver, 4)
  assert masque.udp_receiver_snapshot(receiver)
    == masque.UdpReceiverSnapshot(False, 0, 1, 0, 0, 0)

  let receiver = masque.activate_udp_receiver(receiver)
  assert masque.admit_proxy_datagram_capsule(receiver, -1)
    == Error(masque.InvalidCapsule)
  let assert Ok(masque.InspectDatagramCapsuleContext(receiver, 65_536)) =
    masque.admit_proxy_datagram_capsule(receiver, 65_536)
  let assert Ok(masque.DiscardDatagramCapsule(
    receiver,
    masque.ContextNotRegistered(1),
  )) =
    masque.classify_proxy_datagram_capsule_context(
      receiver,
      declared_value_bytes: 65_536,
      context: 1,
      encoded_context_bytes: 1,
    )

  let assert Ok(masque.AbortDatagramCapsuleStream(
    receiver,
    masque.DatagramLimitExceeded(65_527),
  )) =
    masque.classify_proxy_datagram_capsule_context(
      receiver,
      declared_value_bytes: 65_529,
      context: 0,
      encoded_context_bytes: 1,
    )

  let assert Ok(masque.InspectDatagramCapsuleContext(receiver, 5)) =
    masque.admit_proxy_datagram_capsule(receiver, 5)
  let assert Ok(masque.DiscardDatagramCapsule(
    receiver,
    masque.CapsuleValueTooLarge(4),
  )) =
    masque.classify_proxy_datagram_capsule_context(
      receiver,
      declared_value_bytes: 5,
      context: 0,
      encoded_context_bytes: 1,
    )

  let assert Ok(masque.InspectDatagramCapsuleContext(receiver, 4)) =
    masque.admit_proxy_datagram_capsule(receiver, 4)
  let assert Ok(masque.ReadDatagramCapsulePayload(receiver, 3)) =
    masque.classify_proxy_datagram_capsule_context(
      receiver,
      declared_value_bytes: 4,
      context: 0,
      encoded_context_bytes: 1,
    )
  let assert masque.ForwardPayload(receiver, <<1, 2, 3>>) =
    masque.receive_proxy_datagram(receiver, <<0, 1, 2, 3>>)
  assert masque.udp_receiver_snapshot(receiver)
    == masque.UdpReceiverSnapshot(True, 1, 1, 1, 1, 1)
}

pub fn connect_ip_packet_forwarding_enforces_scope_route_and_ttl_test() -> Nil {
  let scope = masque.IpScope(Some("198.51.100.0/24"), Some(17))
  let assert Ok(request) =
    masque.connect_ip(masque.Http2, "proxy.example", scope, limits())
  assert masque.request_path(request)
    == "/.well-known/masque/ip/198.51.100.0%2F24/17/"
  assert masque.request_protocol(request) == Some("connect-ip")

  let assert Ok(policy) = masque.deny_all(limits())
  let assert Ok(policy) = masque.allow_ip_scope(policy, scope)
  let route = masque.IpPrefix(masque.Ipv4(<<198, 51, 100, 0>>), 24)
  let assert Ok(policy) = masque.allow_ip_destination(policy, route, Some(17))
  assert masque.authorize(policy, request) == Ok(Nil)

  let packet = <<
    0x45,
    0,
    28:size(16),
    1:size(16),
    0:size(16),
    64,
    17,
    0x8e99:size(16),
    192,
    0,
    2,
    1,
    198,
    51,
    100,
    2,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
  >>
  let assert Ok(forwarded) = masque.forward_ip_packet(policy, packet, limits())
  let assert <<
    0x45,
    0,
    28:size(16),
    1:size(16),
    0:size(16),
    63,
    17,
    0x8f99:size(16),
    _rest:bits,
  >> = forwarded
  assert masque.encode_ip_datagram(forwarded, limits())
    == Ok(<<0, forwarded:bits>>)

  let denied = <<
    0x45,
    0,
    20:size(16),
    0:size(16),
    0:size(16),
    64,
    17,
    0x7cd6:size(16),
    192,
    0,
    2,
    1,
    203,
    0,
    113,
    1,
  >>
  assert masque.forward_ip_packet(policy, denied, limits())
    == Error(masque.DestinationForbidden)
}

pub fn permanent_ip_capsules_have_exact_wire_vectors_test() -> Nil {
  let assigned =
    masque.AssignedAddress(
      request_id: 0,
      prefix: masque.IpPrefix(masque.Ipv4(<<192, 0, 2, 1>>), 32),
    )
  let assert Ok(encoded) =
    masque.encode_capsule(masque.AddressAssign([assigned]), limits())
  assert http3_capsule.encode(encoded) == Ok(<<1, 7, 0, 4, 192, 0, 2, 1, 32>>)
  assert masque.decode_capsule(encoded, limits())
    == Ok(Some(masque.AddressAssign([assigned])))

  let requested =
    masque.RequestedAddress(
      request_id: 1,
      prefix: masque.IpPrefix(masque.Ipv4(<<0, 0, 0, 0>>), 24),
    )
  let assert Ok(encoded) =
    masque.encode_capsule(masque.AddressRequest([requested]), limits())
  assert http3_capsule.encode(encoded) == Ok(<<2, 7, 1, 4, 0, 0, 0, 0, 24>>)

  let route =
    masque.IpRoute(
      start: masque.Ipv4(<<192, 0, 2, 0>>),
      end: masque.Ipv4(<<192, 0, 2, 255>>),
      ip_protocol: 17,
    )
  let assert Ok(encoded) =
    masque.encode_capsule(masque.RouteAdvertisement([route]), limits())
  assert http3_capsule.encode(encoded)
    == Ok(<<3, 10, 4, 192, 0, 2, 0, 192, 0, 2, 255, 17>>)
  assert masque.decode_capsule(encoded, limits())
    == Ok(Some(masque.RouteAdvertisement([route])))
}

// A route advertisement is peer input. Every bound the validator checks is
// checked here, because the ordering and overlap scans read these ranges as
// plain integers and cannot re-decide a malformed one.
pub fn route_advertisement_rejects_malformed_and_unordered_ranges_test() -> Nil {
  let reversed =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 255>>),
      masque.Ipv4(<<192, 0, 2, 0>>),
      17,
    )
  assert masque.encode_capsule(masque.RouteAdvertisement([reversed]), limits())
    == Error(masque.InvalidRoute)

  // A range whose bounds are in different address spaces has no decoding at
  // all, so it is refused before any numeric comparison is reached.
  let mixed_family =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv6(<<255, 0:size(120)>>),
      17,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([mixed_family]),
      limits(),
    )
    == Error(masque.InvalidRoute)

  let unknown_protocol =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv4(<<192, 0, 2, 255>>),
      256,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([unknown_protocol]),
      limits(),
    )
    == Error(masque.InvalidRoute)

  let earlier =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv4(<<192, 0, 2, 255>>),
      17,
    )
  let later =
    masque.IpRoute(
      masque.Ipv4(<<198, 51, 100, 0>>),
      masque.Ipv4(<<198, 51, 100, 255>>),
      17,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([later, earlier]),
      limits(),
    )
    == Error(masque.InvalidRoute)
  let assert Ok(_) =
    masque.encode_capsule(masque.RouteAdvertisement([earlier, later]), limits())

  // Ordering across address families is decided before either range is read,
  // so it needs a pair which the same-family comparison cannot also reject.
  let ipv6 =
    masque.IpRoute(
      masque.Ipv6(<<0x20, 0x01, 0x0d, 0xb8, 0:size(96)>>),
      masque.Ipv6(<<0x20, 0x01, 0x0d, 0xb8, 0xff, 0:size(88)>>),
      17,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([ipv6, earlier]),
      limits(),
    )
    == Error(masque.InvalidRoute)
  let assert Ok(_) =
    masque.encode_capsule(masque.RouteAdvertisement([earlier, ipv6]), limits())

  // A wildcard protocol sorts ahead of a numbered one, so this pair is
  // correctly ordered and only the overlap scan can reject it. Without a case
  // like this the ordering check answers for the overlap check as well.
  let any_protocol =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv4(<<192, 0, 2, 255>>),
      0,
    )
  let inside =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 64>>),
      masque.Ipv4(<<192, 0, 2, 128>>),
      17,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([any_protocol, inside]),
      limits(),
    )
    == Error(masque.InvalidRoute)

  let below =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv4(<<192, 0, 2, 63>>),
      0,
    )
  let assert Ok(_) =
    masque.encode_capsule(masque.RouteAdvertisement([below, inside]), limits())

  // Two address families share no address space even when their ranges read as
  // overlapping integers. `::` to `::ffff:ffff` covers exactly the numbers an
  // IPv4 range can hold, so an overlap scan which forgot the family would
  // refuse this pair.
  let low_ipv6 =
    masque.IpRoute(
      masque.Ipv6(<<0:size(128)>>),
      masque.Ipv6(<<0:size(96), 255, 255, 255, 255>>),
      17,
    )
  let assert Ok(_) =
    masque.encode_capsule(
      masque.RouteAdvertisement([earlier, low_ipv6]),
      limits(),
    )

  Nil
}

pub fn capsule_state_rejects_reuse_overlap_bombs_and_provisional_types_test() -> Nil {
  let request =
    masque.RequestedAddress(
      request_id: 7,
      prefix: masque.IpPrefix(masque.Ipv4(<<0, 0, 0, 0>>), 32),
    )
  let state = masque.ip_state(limits())
  let assert Ok(#(state, _)) = masque.request_addresses(state, [request])
  assert masque.request_addresses(state, [request])
    == Error(masque.RequestIdReused(7))
  assert masque.encode_capsule(masque.AddressRequest([]), limits())
    == Error(masque.InvalidCapsule)

  let first =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 0>>),
      masque.Ipv4(<<192, 0, 2, 127>>),
      17,
    )
  let overlap =
    masque.IpRoute(
      masque.Ipv4(<<192, 0, 2, 64>>),
      masque.Ipv4(<<192, 0, 2, 255>>),
      17,
    )
  assert masque.encode_capsule(
      masque.RouteAdvertisement([first, overlap]),
      limits(),
    )
    == Error(masque.InvalidRoute)

  assert masque.decode_capsule(
      http3_capsule.Extension(8, <<"provisional":utf8>>),
      limits(),
    )
    == Ok(None)
  assert masque.decode_capsule(
      http3_capsule.Extension(0x243f, <<1, 2>>),
      limits(),
    )
    == Ok(Some(masque.PermanentExtension(0x243f, <<1, 2>>)))
  let tiny = masque.Limits(..limits(), maximum_capsule_bytes: 1)
  assert masque.decode_capsule(http3_capsule.Extension(0x243f, <<1, 2>>), tiny)
    == Error(masque.CapsuleLimitExceeded(1))
}

fn inbound_http1_udp_request() -> request.Request(Nil) {
  request.Request(
    method: http.Get,
    headers: [
      #("host", "proxy.example"),
      #("connection", "keep-alive, Upgrade"),
      #("upgrade", "connect-udp"),
      #("capsule-protocol", "?1"),
    ],
    body: Nil,
    scheme: http.Https,
    host: "proxy.example",
    port: None,
    path: "/.well-known/masque/udp/192.0.2.6/443/",
    query: None,
  )
}
