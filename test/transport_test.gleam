import gleam/bit_array
import gleam/http
import gleam/http/request
import gleam/list
import gleeunit/should
import http3/client
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
    == transport_backend.BackendFailure("backend")
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
    client.open_stream(connection, streaming_request(port, "/no-datagrams"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
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

  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"done":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"done":utf8>>
  assert client.close(connection) == Ok(client.Closed)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn http_datagram_limits_and_concurrent_receive_are_typed_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
    |> server.with_http_datagrams
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let configuration =
    client_configuration(ca_certificate) |> client.with_http_datagrams
  let connection =
    client.connect(configuration, "localhost", port) |> should.be_ok
  let stream =
    client.open_stream(connection, streaming_request(port, "/datagram-race"))
    |> should.be_ok
  client.finish(stream) |> should.be_ok
  let incoming = server.accept(listener) |> should.be_ok
  let client_transport = client.stream_transport(stream)
  let server_transport = server.request_transport(incoming)
  let maximum =
    transport.maximum_datagram_size(client_transport) |> should.be_ok

  assert transport.send_datagram(
      client_transport,
      http3_test_support.repeated_bytes(maximum + 1),
    )
    == Error(transport.DatagramTooLarge(maximum))
  let results =
    http3_test_support.concurrent_next_datagrams(client_transport, fn() {
      transport.send_datagram(server_transport, <<"released":utf8>>)
      |> should.be_ok
    })
  assert list.contains(results, Error(transport.ConcurrentDatagramReceive))
  assert list.contains(results, Ok(<<"released":utf8>>))

  assert server.read_body(incoming) |> should.be_ok == <<>>
  server.respond(incoming, 200, [], <<"done":utf8>>) |> should.be_ok
  assert receive_response(stream) == <<"done":utf8>>
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
      let stream_transport = server.request_transport(incoming)
      assert transport.stream_capabilities(stream_transport)
        == Ok(transport.Capabilities(True, True, False, True))
      assert transport.maximum_datagram_size(stream_transport) |> should.be_ok
        > 0

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
      server.respond(incoming, 200, [], <<"first":utf8>>) |> should.be_ok

      let migrated = server.accept(listener) |> should.be_ok
      assert server.path(migrated) == "/after-migration"
      assert server.read_body(migrated) |> should.be_ok == <<>>
      server.respond(migrated, 200, [], <<"second":utf8>>) |> should.be_ok

      http3_test_support.await_task(client_task)
      assert server.stop(listener) == Ok(server.Stopped)
    })

  assert qlog_files > 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn zero_rtt_resumption_is_typed_and_replay_safe_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http3_test_support.server_credentials()
  let listener =
    server.new(certificate, private_key)
    |> should.be_ok
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
    client.open_stream(connection, streaming_request(port, "/advanced"))
    |> should.be_ok
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
  assert transport.maximum_transmission_unit(connection_transport)
    |> should.be_ok
    >= 1200
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
  let transport.ConnectionStats(received, sent, _, _, _, _, _, _) =
    transport.connection_stats(connection_transport) |> should.be_ok
  assert received > 0
  assert sent > 0
  assert client.close(connection) == Ok(client.Closed)
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
