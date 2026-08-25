import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/list
import gleam/option.{None, Some}
import gleeunit/should
import http3/capsule
import http3/client
import http3/config
import http3/failure as runtime_failure
import http3/internal/transport_backend
import http3/server
import http3/transport
import http3_test_support

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn priority_is_typed_and_bounded_test() -> Nil {
  assert transport.priority(-1, False) == Error(transport.InvalidUrgency(-1))
  assert transport.priority(8, False) == Error(transport.InvalidUrgency(8))

  let priority = transport.priority(1, True) |> should.be_ok
  assert transport.urgency(priority) == 1
  assert transport.is_incremental(priority)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn qlog_directory_is_explicit_and_validated_test() -> Nil {
  assert transport.qlog("") == Error(transport.InvalidQlogDirectory)

  let qlog = transport.qlog("/tmp/http3-qlog") |> should.be_ok
  assert transport.qlog_directory(qlog) == "/tmp/http3-qlog"
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_keepalive_sends_ping_over_real_udp_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let configuration =
    client_configuration(ca_certificate)
    |> client.with_keepalive(1000)
    |> should.be_ok
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let controls = client.connection_transport(connection)
  let sent = settle_sent_packets(controls, -1, 0, 100)
  assert await_sent_packets(controls, sent, 150) > sent
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_keepalive_sends_ping_over_real_udp_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_keepalive(1000)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let controls = client.connection_transport(connection)
  let received = settle_received_packets(controls, -1, 0, 100)
  assert await_received_packets(controls, received, 150) > received
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn transport_backend_errors_are_normalized_test() -> Nil {
  assert transport_backend.normalize_error(#(1, 0, "ignored"))
    == transport_backend.ConnectionClosed
  assert transport_backend.normalize_error(#(2, 0, "ignored"))
    == transport_backend.Timeout
  assert transport_backend.normalize_error(#(3, 0, "ignored"))
    == transport_backend.DatagramsNotNegotiated
  assert transport_backend.normalize_error(#(4, 1200, "ignored"))
    == transport_backend.DatagramTooLarge(1200)
  assert transport_backend.normalize_error(#(7, 4096, "ignored"))
    == transport_backend.DatagramBufferExceeded(4096)
  assert transport_backend.normalize_error(#(99, 0, "backend"))
    == transport_backend.RuntimeFailure(runtime_failure.Http3(
      runtime_failure.Local,
      None,
    ))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn http_datagrams_require_explicit_negotiation_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let stream =
    client.open_extended_connect(
      connection,
      streaming_request(port, "/no-datagrams"),
      "test-datagram",
    )
    |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.protocol(incoming) == Some("test-datagram")
  server.send_response(incoming, 200, []) |> should.be_ok
  assert client.next_event(stream) == Ok(client.Response(200, []))
  let client_transport = client.stream_transport(stream)
  let server_transport = server.request_transport(incoming)

  assert transport.stream_capabilities(client_transport)
    == Ok(transport.Capabilities(False, True, False, False))
  assert transport.maximum_datagram_size(client_transport)
    == Error(transport.DatagramsNotNegotiated)
  assert transport.send_datagram(client_transport, <<1:size(1)>>)
    == Error(transport.InvalidDatagram)
  assert transport.send_datagram(server_transport, <<"disabled":utf8>>)
    == Error(transport.DatagramsNotNegotiated)

  client.finish(stream) |> should.be_ok
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.finish_response(incoming) |> should.be_ok
  assert receive_response(stream) == <<>>

  let ordinary =
    client.open_stream(connection, streaming_request(port, "/ordinary"))
    |> should.be_ok
  client.finish(ordinary) |> should.be_ok
  let ordinary_request = server.accept(listener) |> should.be_ok
  assert server.protocol(ordinary_request) == None
  assert transport.maximum_datagram_size(client.stream_transport(ordinary))
    == Error(transport.DatagramNotAssociated)
  assert transport.send_datagram(server.request_transport(ordinary_request), <<
      "forbidden":utf8,
    >>)
    == Error(transport.DatagramNotAssociated)
  assert server.read_body(ordinary_request) |> should.be_ok == <<>>
  server.respond(ordinary_request, 200, [], <<>>) |> should.be_ok
  assert receive_response(ordinary) == <<>>
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn http_datagram_limits_and_concurrent_receive_are_typed_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let datagram_limits =
    config.default_limits()
    |> config.with_limit(runtime_failure.Datagram, 32)
    |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_limits(datagram_limits)
    |> server.with_http_datagrams
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let configuration =
    client_configuration(ca_certificate)
    |> client.with_limits(datagram_limits)
    |> client.with_http_datagrams
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let stream =
    client.open_extended_connect(
      connection,
      streaming_request(port, "/datagram-race"),
      "test-datagram",
    )
    |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.protocol(incoming) == Some("test-datagram")
  server.send_response(incoming, 200, []) |> should.be_ok
  assert client.next_event(stream) == Ok(client.Response(200, []))
  let client_transport = client.stream_transport(stream)
  let server_transport = server.request_transport(incoming)
  let maximum =
    transport.maximum_datagram_size(client_transport) |> should.be_ok
  assert maximum > 0
  assert maximum <= 32

  client.send_capsule(stream, capsule.Datagram(<<"reliable-request":utf8>>))
  |> should.be_ok
  // nolint: assert_ok_pattern -- capsule DATA is the integration assertion.
  let assert Ok(server.Data(request_capsule)) = server.next_event(incoming)
  assert decode_capsule(request_capsule)
    == capsule.Datagram(<<"reliable-request":utf8>>)
  server.send_capsule(incoming, capsule.Datagram(<<"reliable-response":utf8>>))
  |> should.be_ok
  // nolint: assert_ok_pattern -- capsule DATA is the integration assertion.
  let assert Ok(client.Data(response_capsule)) = client.next_event(stream)
  assert decode_capsule(response_capsule)
    == capsule.Datagram(<<"reliable-response":utf8>>)

  // nolint: assert_ok_pattern -- typed oversize error is the integration assertion.
  let assert Error(transport.DatagramTooLarge(reported_maximum)) =
    transport.send_datagram(
      client_transport,
      http3_test_support.repeated_bytes(65_536),
    )
  assert reported_maximum >= maximum
  let results =
    http3_test_support.concurrent_next_datagrams(client_transport, fn() {
      transport.send_datagram(server_transport, <<"released":utf8>>)
      |> should.be_ok
    })
  assert list.contains(results, Error(transport.ConcurrentDatagramReceive))
  assert list.contains(results, Ok(<<"released":utf8>>))

  client.finish(stream) |> should.be_ok
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.finish_response(incoming) |> should.be_ok
  assert receive_response(stream) == <<>>
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn advanced_transport_controls_round_trip_test() -> Nil {
  let #(_, qlog_files) =
    http3_test_support.with_qlog_directory(fn(qlog_directory) {
      let #(certificate, private_key, ca_certificate) =
        http3_test_support.server_credentials()
      let qlog = transport.qlog(qlog_directory) |> should.be_ok
      let server_configuration =
        server.new(certificate, private_key)
        |> should.be_ok
        |> server.with_http_datagrams
        |> server.with_qlog(qlog)
      let listener = server.start(server_configuration) |> should.be_ok
      let port = server.port(listener) |> should.be_ok
      let client_task =
        http3_test_support.start_task(fn() {
          advanced_client(
            port: port,
            ca_certificate: ca_certificate,
            qlog_directory: qlog_directory,
          )
        })

      let incoming = server.accept(listener) |> should.be_ok
      assert server.protocol(incoming) == Some("test-datagram")
      server.send_response(incoming, 200, []) |> should.be_ok
      let stream_transport = server.request_transport(incoming)
      assert transport.stream_capabilities(stream_transport)
        == Ok(transport.Capabilities(True, True, False, True))
      assert transport.maximum_datagram_size(stream_transport) |> should.be_ok
        > 0
      assert await_stream_mtu(stream_transport, 100) > 1200
      let transport.PathStats(_, _, _, _, window, in_flight, _, _) =
        transport.stream_path_stats(stream_transport) |> should.be_ok
      assert window > 0
      assert in_flight >= 0
      let transport.ConnectionStats(
        packets_received,
        packets_sent,
        _,
        _,
        acknowledgements,
        _,
        _,
        _,
      ) = transport.stream_connection_stats(stream_transport) |> should.be_ok
      assert packets_received > 0
      assert packets_sent > 0
      assert acknowledgements > 0
      let transport.TelemetryStats(_, qlog_errors, queued_events) =
        transport.stream_telemetry_stats(stream_transport) |> should.be_ok
      assert qlog_errors == 0
      assert queued_events <= 1025

      let client_priority =
        await_stream_priority(stream_transport, 1, True, 100)
      assert transport.urgency(client_priority) == 1
      assert transport.is_incremental(client_priority)

      let server_priority = transport.priority(2, True) |> should.be_ok
      transport.set_priority(stream_transport, server_priority) |> should.be_ok
      let observed_priority =
        transport.get_priority(stream_transport) |> should.be_ok
      assert transport.urgency(observed_priority) == 2
      assert transport.is_incremental(observed_priority)

      assert transport.next_datagram(stream_transport) |> should.be_ok
        == <<"ping":utf8>>
      transport.send_datagram(stream_transport, <<"pong":utf8>>)
      |> should.be_ok
      assert server.read_body(incoming) |> should.be_ok == <<>>
      server.send_chunk(incoming, <<"first":utf8>>) |> should.be_ok
      server.finish_response(incoming) |> should.be_ok

      let migrated = server.accept(listener) |> should.be_ok
      assert server.path(migrated) == "/after-migration"
      assert server.read_body(migrated) |> should.be_ok == <<>>
      server.respond(migrated, 200, [], <<"second":utf8>>) |> should.be_ok

      http3_test_support.await_task(client_task)
      assert server.stop(listener) == Ok(server.Stopped)
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:connection_started",
        )
        == 2
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:udp_datagrams_sent",
        )
        > 0
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:udp_datagrams_received",
        )
        > 0
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:connection_closed",
        )
        == 2
    })

  assert qlog_files > 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_qlog_uses_one_trace_per_connection_test() -> Nil {
  let #(_, qlog_files) =
    http3_test_support.with_qlog_directory(fn(qlog_directory) {
      let #(certificate, private_key, ca_certificate) =
        http3_test_support.server_credentials()
      let qlog = transport.qlog(qlog_directory) |> should.be_ok
      let listener =
        server.new(certificate, private_key)
        |> should.be_ok
        |> server.with_qlog(qlog)
        |> server.start
        |> should.be_ok
      let port = server.port(listener) |> should.be_ok

      exercise_qlog_connection(
        listener: listener,
        port: port,
        ca_certificate: ca_certificate,
        path: "/qlog-one",
      )
      exercise_qlog_connection(
        listener: listener,
        port: port,
        ca_certificate: ca_certificate,
        path: "/qlog-two",
      )

      assert server.stop(listener) == Ok(server.Stopped)
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:connection_started",
        )
        == 2
      assert http3_test_support.qlog_event_count(
          qlog_directory,
          "quic:connection_closed",
        )
        == 2
    })

  assert qlog_files == 2
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_push_round_trips_with_bounded_pull_api_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let configuration =
    client_configuration(ca_certificate)
    |> client.with_push_limit(2)
    |> should.be_ok
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/document"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok

  let incoming = server.accept(listener) |> should.be_ok
  assert server.read_body(incoming) |> should.be_ok == <<>>
  let push =
    server.promise_push(incoming, "/style.css?version=1", [
      #("accept", "text/css"),
    ])
    |> should.be_ok
  server.send_push_response(push, 200, [#("content-type", "text/css")])
  |> should.be_ok
  server.send_push_chunk(push, <<"body{}":utf8>>) |> should.be_ok
  server.send_push_trailers(push, [#("x-push-complete", "yes")])
  |> should.be_ok
  server.respond(incoming, 200, [], <<"document":utf8>>) |> should.be_ok

  let promised = client.next_push(connection) |> should.be_ok
  assert client.push_method(promised) == "GET"
  assert client.push_path(promised) == "/style.css?version=1"
  assert client.push_headers(promised) == [#("accept", "text/css")]
  assert client.next_push_event(promised)
    == Ok(client.Response(200, [#("content-type", "text/css")]))
  assert client.next_push_event(promised) == Ok(client.Data(<<"body{}":utf8>>))
  assert client.next_push_event(promised)
    == Ok(client.Trailers([#("x-push-complete", "yes")]))
  assert client.next_push_event(promised) == Ok(client.End)
  assert client.cancel_push(promised) == Ok(client.AlreadyCompleted)
  assert receive_response(stream) == <<"document":utf8>>
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn zero_rtt_resumption_is_typed_and_replay_safe_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_single_node_zero_rtt
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok

  let safe_ticket =
    acquire_ticket(
      listener: listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/ticket-safe",
    )
  let unsafe_ticket =
    acquire_ticket(
      listener: listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/ticket-unsafe",
    )

  let resumed_configuration =
    client_configuration(ca_certificate)
    |> client.with_resumption_ticket(safe_ticket)
  let wrong_port = case port == 65_535 {
    True -> port - 1
    False -> port + 1
  }
  assert client.connect(resumed_configuration, "localhost", wrong_port)
    == Error(client.ResumptionOriginMismatch)

  let unsafe_configuration =
    client_configuration(ca_certificate)
    |> client.with_resumption_ticket(unsafe_ticket)
  let unsafe_connection =
    client.connect(unsafe_configuration, "localhost", port) |> should.be_ok
  let unsafe_request =
    streaming_request(port, "/unsafe")
    |> request.set_method(http.Post)
  assert client.open_stream(unsafe_connection, unsafe_request)
    == Error(client.UnsafeEarlyDataMethod("POST"))

  // Complete one safe stream before close so both sides leave the resumed
  // handshake through an observable state rather than racing teardown.
  let safe_after_rejection =
    client.open_stream(
      unsafe_connection,
      streaming_request(port, "/safe-after-rejection"),
    )
    |> should.be_ok
  client.finish(safe_after_rejection) |> should.be_ok
  let safe_after_rejection_request = server.accept(listener) |> should.be_ok
  assert server.path(safe_after_rejection_request) == "/safe-after-rejection"
  assert transport.stream_early_data_status(server.request_transport(
      safe_after_rejection_request,
    ))
    == Ok(transport.Accepted)
  assert server.read_body(safe_after_rejection_request) |> should.be_ok == <<>>
  server.respond(safe_after_rejection_request, 200, [], <<"safe":utf8>>)
  |> should.be_ok
  assert receive_response(safe_after_rejection) == <<"safe":utf8>>
  assert client.close(unsafe_connection) == Ok(client.Closed)

  let resumed_connection =
    client.connect(resumed_configuration, "localhost", port) |> should.be_ok
  let resumed_transport = client.connection_transport(resumed_connection)
  assert transport.early_data_status(resumed_transport)
    != Ok(transport.NotAttempted)
  let resumed_stream =
    client.open_stream(resumed_connection, streaming_request(port, "/early"))
    |> should.be_ok
  client.finish(resumed_stream) |> should.be_ok
  let early_request = server.accept(listener) |> should.be_ok
  assert server.path(early_request) == "/early"
  assert transport.stream_early_data_status(server.request_transport(
      early_request,
    ))
    == Ok(transport.Accepted)
  assert server.read_body(early_request) |> should.be_ok == <<>>
  server.respond(early_request, 200, [], <<"accepted":utf8>>)
  |> should.be_ok
  assert receive_response(resumed_stream) == <<"accepted":utf8>>
  assert transport.early_data_status(resumed_transport)
    == Ok(transport.Accepted)
  assert transport.stream_early_data_status(client.stream_transport(
      resumed_stream,
    ))
    == Ok(transport.Accepted)
  assert client.close(resumed_connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn external_replay_guard_accepts_real_zero_rtt_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  assert server.replay_guard(0, fn(_) { Ok(server.AcceptEarlyData) })
    == Error(server.InvalidReplayGuardTimeout)
  assert server.replay_guard(10_001, fn(_) { Ok(server.AcceptEarlyData) })
    == Error(server.InvalidReplayGuardTimeout)
  let guard =
    server.replay_guard(100, fn(attempt) {
      assert bit_array.byte_size(server.replay_fingerprint(attempt)) == 32
      assert server.replay_valid_for_milliseconds(attempt) > 0
      Ok(server.AcceptEarlyData)
    })
    |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_external_zero_rtt(guard)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let ticket =
    acquire_ticket(
      listener: listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/external-ticket",
    )
  let connection =
    client_configuration(ca_certificate)
    |> client.with_address_family(config.Ipv4)
    |> client.with_resumption_ticket(ticket)
    |> client.connect("localhost", port)
    |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/external-early"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == "/external-early"
  assert transport.stream_early_data_status(server.request_transport(incoming))
    == Ok(transport.Accepted)
  server.respond(incoming, 200, [], <<"accepted":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"accepted":utf8>>
  assert transport.early_data_status(client.connection_transport(connection))
    == Ok(transport.Accepted)

  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn external_replay_guard_failure_falls_back_to_one_rtt_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let guard = server.replay_guard(100, fn(_) { Error(Nil) }) |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_external_zero_rtt(guard)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let ticket =
    acquire_ticket(
      listener: listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/fallback-ticket",
    )
  let connection =
    client_configuration(ca_certificate)
    |> client.with_address_family(config.Ipv4)
    |> client.with_resumption_ticket(ticket)
    |> client.connect("localhost", port)
    |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/fallback-1rtt"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == "/fallback-1rtt"
  assert transport.stream_early_data_status(server.request_transport(incoming))
    == Ok(transport.Rejected)
  server.respond(incoming, 200, [], <<"fallback":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"fallback":utf8>>
  let controls = client.connection_transport(connection)
  assert transport.early_data_status(controls) == Ok(transport.Rejected)
  assert transport.resumption_status(controls) == Ok(transport.Resumed)
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn stale_address_token_falls_back_to_authenticated_retry_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let first_listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let port = server.port(first_listener) |> should.be_ok
  let ticket =
    acquire_ticket(
      listener: first_listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/stale-token-ticket",
    )
  assert server.stop(first_listener) == Ok(server.Stopped)

  let replacement_listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_port(port)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let resumed_configuration =
    client_configuration(ca_certificate)
    |> client.with_resumption_ticket(ticket)
  let connection =
    client.connect(resumed_configuration, "localhost", port) |> should.be_ok
  let stream =
    client.open_stream(
      connection,
      streaming_request(port, "/after-stale-token"),
    )
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(replacement_listener) |> should.be_ok
  assert server.path(incoming) == "/after-stale-token"
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"retried":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"retried":utf8>>
  assert transport.early_data_status(client.connection_transport(connection))
    == Ok(transport.NotAttempted)
  assert transport.resumption_status(client.connection_transport(connection))
    == Ok(transport.FullHandshake)
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(replacement_listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn operational_keys_survive_listener_restart_without_enabling_zero_rtt_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let ticket_key = server.operational_key(<<0x11:256>>) |> should.be_ok
  let token_key = server.operational_key(<<0x22:256>>) |> should.be_ok
  let reset_key = server.operational_key(<<0x33:256>>) |> should.be_ok
  let keys =
    server.operational_keys(
      server.key_ring(ticket_key),
      server.key_ring(token_key),
      server.key_ring(reset_key),
    )
    |> should.be_ok
  let first_listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_operational_keys(keys)
    |> server.start
    |> should.be_ok
  let port = server.port(first_listener) |> should.be_ok
  let ticket =
    acquire_ticket(
      listener: first_listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/restart-ticket",
    )
  assert transport.ticket_storage_key(<<1>>)
    == Error(transport.InvalidTicketStorageKey)
  let storage_key = transport.ticket_storage_key(<<0x55:256>>) |> should.be_ok
  let wrong_storage_key =
    transport.ticket_storage_key(<<0x56:256>>) |> should.be_ok
  let exported =
    transport.export_resumption_ticket(ticket, storage_key) |> should.be_ok
  assert transport.import_resumption_ticket(exported, wrong_storage_key)
    == Error(transport.InvalidResumptionTicket)
  assert transport.import_resumption_ticket(
      flip_last_byte(exported),
      storage_key,
    )
    == Error(transport.InvalidResumptionTicket)
  assert server.stop(first_listener) == Ok(server.Stopped)

  let replacement_listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_operational_keys(keys)
    |> server.with_port(port)
    |> should.be_ok
    |> server.start
    |> should.be_ok
  let restored_ticket =
    transport.import_resumption_ticket(exported, storage_key) |> should.be_ok
  let connection =
    client_configuration(ca_certificate)
    |> client.with_resumption_ticket(restored_ticket)
    |> client.connect("localhost", port)
    |> should.be_ok
  assert transport.early_data_status(client.connection_transport(connection))
    == Ok(transport.NotAttempted)
  assert transport.resumption_status(client.connection_transport(connection))
    == Ok(transport.Resumed)
  let post_request =
    streaming_request(port, "/after-restart")
    |> request.set_method(http.Post)
  let stream =
    client.open_stream(connection, post_request)
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(replacement_listener) |> should.be_ok
  assert server.method(incoming) == http.Post
  assert server.path(incoming) == "/after-restart"
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"resumed":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"resumed":utf8>>
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(replacement_listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn operational_keys_are_opaque_bounded_and_domain_separated_test() -> Nil {
  assert server.operational_key(<<1>>) == Error(server.InvalidOperationalKey)
  let first = server.operational_key(<<0x41:256>>) |> should.be_ok
  let second = server.operational_key(<<0x42:256>>) |> should.be_ok
  let third = server.operational_key(<<0x43:256>>) |> should.be_ok
  let fourth = server.operational_key(<<0x44:256>>) |> should.be_ok
  let ring = server.key_ring(first)
  assert server.rotate_key_ring(ring, first)
    == Error(server.DuplicateOperationalKey)
  let rotated = server.rotate_key_ring(ring, fourth) |> should.be_ok
  assert server.operational_keys(rotated, server.key_ring(second), ring)
    == Error(server.DuplicateOperationalKey)
  let _keys =
    server.operational_keys(
      rotated,
      server.key_ring(second),
      server.key_ring(third),
    )
    |> should.be_ok
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn live_operational_key_rotation_accepts_exactly_one_previous_generation_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let old_ticket = server.operational_key(<<0x10:256>>) |> should.be_ok
  let old_token = server.operational_key(<<0x20:256>>) |> should.be_ok
  let old_reset = server.operational_key(<<0x30:256>>) |> should.be_ok
  let old_keys =
    server.operational_keys(
      server.key_ring(old_ticket),
      server.key_ring(old_token),
      server.key_ring(old_reset),
    )
    |> should.be_ok
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_operational_keys(old_keys)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let issued_with_old =
    acquire_ticket(
      listener: listener,
      port: port,
      ca_certificate: ca_certificate,
      path: "/old-generation",
    )

  let new_ticket = server.operational_key(<<0x11:256>>) |> should.be_ok
  let new_token = server.operational_key(<<0x21:256>>) |> should.be_ok
  let new_reset = server.operational_key(<<0x31:256>>) |> should.be_ok
  let rotating_keys =
    server.operational_keys(
      server.rotate_key_ring(server.key_ring(old_ticket), new_ticket)
        |> should.be_ok,
      server.rotate_key_ring(server.key_ring(old_token), new_token)
        |> should.be_ok,
      server.rotate_key_ring(server.key_ring(old_reset), new_reset)
        |> should.be_ok,
    )
    |> should.be_ok
  server.reload_operational_keys(listener, rotating_keys) |> should.be_ok
  let issued_with_new =
    resume_and_acquire_ticket(
      listener,
      port,
      ca_certificate,
      issued_with_old,
      "/accepted-previous",
      transport.Resumed,
    )

  let current_only =
    server.operational_keys(
      server.key_ring(new_ticket),
      server.key_ring(new_token),
      server.key_ring(new_reset),
    )
    |> should.be_ok
  server.reload_operational_keys(listener, current_only) |> should.be_ok
  let _expired_ticket =
    resume_and_acquire_ticket(
      listener,
      port,
      ca_certificate,
      issued_with_old,
      "/expired-previous",
      transport.FullHandshake,
    )
  let _current_ticket =
    resume_and_acquire_ticket(
      listener,
      port,
      ca_certificate,
      issued_with_new,
      "/accepted-current",
      transport.Resumed,
    )
  assert server.stop(listener) == Ok(server.Stopped)
}

fn acquire_ticket(
  listener listener: server.Listener,
  port port: Int,
  ca_certificate ca_certificate: BitArray,
  path path: String,
) -> transport.ResumptionTicket {
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, path))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == path
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"ticket":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"ticket":utf8>>
  let ticket =
    client.connection_transport(connection)
    |> transport.resumption_ticket
    |> should.be_ok
  assert client.close(connection) == Ok(client.Closed)
  ticket
}

// nolint: label_possible -- positional arguments keep this private fixture compact.
fn resume_and_acquire_ticket(
  listener: server.Listener,
  port: Int,
  ca_certificate: BitArray,
  ticket: transport.ResumptionTicket,
  path: String,
  expected: transport.ResumptionStatus,
) -> transport.ResumptionTicket {
  let connection =
    client_configuration(ca_certificate)
    |> client.with_resumption_ticket(ticket)
    |> client.connect("localhost", port)
    |> should.be_ok
  let controls = client.connection_transport(connection)
  assert transport.resumption_status(controls) == Ok(expected)
  let stream =
    client.open_stream(connection, streaming_request(port, path))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == path
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"rotated":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"rotated":utf8>>
  let next = transport.resumption_ticket(controls) |> should.be_ok
  assert client.close(connection) == Ok(client.Closed)
  next
}

fn exercise_qlog_connection(
  listener listener: server.Listener,
  port port: Int,
  ca_certificate ca_certificate: BitArray,
  path path: String,
) -> Nil {
  let connection =
    client.connect(client_configuration(ca_certificate), "localhost", port)
    |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, path))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  assert server.path(incoming) == path
  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 204, [], <<>>) |> should.be_ok
  assert receive_response(stream) == <<>>
  assert client.close(connection) == Ok(client.Closed)
}

fn advanced_client(
  port port: Int,
  ca_certificate ca_certificate: BitArray,
  qlog_directory qlog_directory: String,
) -> Nil {
  let qlog = transport.qlog(qlog_directory) |> should.be_ok
  let configuration =
    client_configuration(ca_certificate)
    |> client.with_http_datagrams
    |> client.with_qlog(qlog)
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let connection_transport = client.connection_transport(connection)
  assert transport.capabilities(connection_transport)
    == Ok(transport.Capabilities(True, True, False, True))

  let stream =
    client.open_extended_connect(
      connection,
      streaming_request(port, "/advanced"),
      "test-datagram",
    )
    |> should.be_ok
  assert client.next_event(stream) == Ok(client.Response(200, []))
  let stream_transport = client.stream_transport(stream)
  let priority = transport.priority(1, True) |> should.be_ok
  transport.set_priority(stream_transport, priority) |> should.be_ok
  let observed_priority =
    transport.get_priority(stream_transport) |> should.be_ok
  assert transport.urgency(observed_priority) == 1
  assert transport.is_incremental(observed_priority)
  assert transport.maximum_datagram_size(stream_transport) |> should.be_ok > 0
  transport.send_datagram(stream_transport, <<"ping":utf8>>) |> should.be_ok
  assert transport.next_datagram(stream_transport) |> should.be_ok
    == <<"pong":utf8>>
  client.finish(stream) |> should.be_ok
  assert receive_response(stream) == <<"first":utf8>>

  transport.set_congestion_control(connection_transport, transport.Cubic)
  |> should.be_ok
  transport.ping(connection_transport) |> should.be_ok
  assert await_connection_mtu(connection_transport, 100) > 1200
  let transport.PathStats(_, _, _, _, window, in_flight, _, _) =
    transport.path_stats(connection_transport) |> should.be_ok
  assert window > 0
  assert in_flight >= 0

  transport.migrate(connection_transport) |> should.be_ok
  let migrated =
    client.open_stream(connection, streaming_request(port, "/after-migration"))
    |> should.be_ok
  client.finish(migrated) |> should.be_ok
  assert receive_response(migrated) == <<"second":utf8>>
  let transport.ConnectionStats(received, sent, _, _, acknowledgements, _, _, _) =
    transport.connection_stats(connection_transport) |> should.be_ok
  assert received > 0
  assert sent > 0
  assert acknowledgements > 0
  let transport.TelemetryStats(_, qlog_errors, queued_events) =
    transport.telemetry_stats(connection_transport) |> should.be_ok
  assert qlog_errors == 0
  assert queued_events <= 1025
  assert client.close(connection) == Ok(client.Closed)
}

// nolint: label_possible -- recursive polling arguments are conventional.
fn await_stream_priority(
  stream: transport.Stream,
  urgency: Int,
  incremental: Bool,
  attempts: Int,
) -> transport.Priority {
  let observed = transport.get_priority(stream) |> should.be_ok
  case
    transport.urgency(observed) == urgency
    && transport.is_incremental(observed) == incremental
  {
    True -> observed
    False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(1)
      await_stream_priority(stream, urgency, incremental, attempts - 1)
    }
  }
}

fn decode_capsule(bytes: BitArray) -> capsule.Capsule {
  let decoder = capsule.decoder(1024, 2048) |> should.be_ok
  let decoder = capsule.push(decoder, bytes) |> should.be_ok
  // nolint: assert_ok_pattern -- one complete encoded capsule is required.
  let assert Ok(capsule.Ready(decoder, decoded)) = capsule.next(decoder)
  assert capsule.finish(decoder) == Ok(Nil)
  decoded
}

// nolint: label_possible -- recursive polling arguments are conventional.
fn settle_sent_packets(
  connection: transport.Connection,
  previous: Int,
  stable: Int,
  attempts: Int,
) -> Int {
  let transport.ConnectionStats(_, current, _, _, _, _, _, _) =
    transport.connection_stats(connection) |> should.be_ok
  case current == previous, stable >= 5 {
    True, True -> current
    True, False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      settle_sent_packets(connection, current, stable + 1, attempts - 1)
    }
    False, _ -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      settle_sent_packets(connection, current, 0, attempts - 1)
    }
  }
}

// nolint: label_possible -- recursive polling arguments are conventional.
fn await_sent_packets(
  connection: transport.Connection,
  baseline: Int,
  attempts: Int,
) -> Int {
  let transport.ConnectionStats(_, current, _, _, _, _, _, _) =
    transport.connection_stats(connection) |> should.be_ok
  case current > baseline {
    True -> current
    False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      await_sent_packets(connection, baseline, attempts - 1)
    }
  }
}

// nolint: label_possible -- recursive polling arguments are conventional.
fn settle_received_packets(
  connection: transport.Connection,
  previous: Int,
  stable: Int,
  attempts: Int,
) -> Int {
  let transport.ConnectionStats(current, _, _, _, _, _, _, _) =
    transport.connection_stats(connection) |> should.be_ok
  case current == previous, stable >= 5 {
    True, True -> current
    True, False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      settle_received_packets(connection, current, stable + 1, attempts - 1)
    }
    False, _ -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      settle_received_packets(connection, current, 0, attempts - 1)
    }
  }
}

// nolint: label_possible -- recursive polling arguments are conventional.
fn await_received_packets(
  connection: transport.Connection,
  baseline: Int,
  attempts: Int,
) -> Int {
  let transport.ConnectionStats(current, _, _, _, _, _, _, _) =
    transport.connection_stats(connection) |> should.be_ok
  case current > baseline {
    True -> current
    False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      await_received_packets(connection, baseline, attempts - 1)
    }
  }
}

fn await_connection_mtu(
  connection: transport.Connection,
  attempts: Int,
) -> Int {
  let current = transport.maximum_transmission_unit(connection) |> should.be_ok
  case current > 1200 {
    True -> current
    False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      await_connection_mtu(connection, attempts - 1)
    }
  }
}

fn await_stream_mtu(stream: transport.Stream, attempts: Int) -> Int {
  let current =
    transport.stream_maximum_transmission_unit(stream) |> should.be_ok
  case current > 1200 {
    True -> current
    False -> {
      assert attempts > 0
      http3_test_support.pause_milliseconds(10)
      await_stream_mtu(stream, attempts - 1)
    }
  }
}

fn client_configuration(ca_certificate: BitArray) -> client.Client {
  client.with_ca_certificate(client.new(), ca_certificate) |> should.be_ok
}

fn streaming_request(port: Int, path: String) -> request.Request(Nil) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(Nil)
}

fn receive_response(stream: client.Stream) -> BitArray {
  receive_response_loop(stream, <<>>)
}

fn receive_response_loop(stream: client.Stream, body: BitArray) -> BitArray {
  case client.next_event(stream) |> should.be_ok {
    client.Data(chunk) ->
      receive_response_loop(stream, bit_array.append(body, chunk))
    client.End -> body
    _ -> receive_response_loop(stream, body)
  }
}

fn flip_last_byte(bytes: BitArray) -> BitArray {
  let prefix_size = { bit_array.byte_size(bytes) - 1 } * 8
  // nolint: assert_ok_pattern -- callers always provide non-empty ciphertext.
  let assert <<prefix:bits-size(prefix_size), last>> = bytes
  let changed = { last + 1 } % 256
  <<prefix:bits, changed>>
}
