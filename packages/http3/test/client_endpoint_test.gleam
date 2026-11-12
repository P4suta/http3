import gleam/http/request
import gleam/int
import gleam/list
import gleam/result
import gleeunit/should
import http3/address
import http3/client
import http3/config
import http3/failure
import http3/transport
import http3_test_support

@external(erlang, "http3_quic_core_test_ffi", "without_system_roots")
fn without_system_roots(run: fn() -> value) -> value

type RootlessFailure {
  Configuration(client.ConfigurationError)
  Runtime(client.Error)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn explicit_anchors_support_reusable_and_buffered_requests_without_os_roots_test() -> Nil {
  let observed =
    http3_test_support.with_ipv4_server_timeout(5000, fn(port, ca) {
      without_system_roots(fn() {
        let default_failed = case
          client.connect(client.new(), "localhost", port)
        {
          Error(failure) ->
            failure == client.Failure(failure.Tls(failure.Local))
          Ok(connection) -> {
            let _closed = client.close(connection)
            False
          }
        }
        use configured <- result.try(
          client.with_ca_certificate(client.new(), ca)
          |> result.map_error(Configuration),
        )
        use connection <- result.try(
          client.connect(configured, "localhost", port)
          |> result.map_error(Runtime),
        )
        let closed = client.close(connection)
        use response <- result.try(
          client.send(
            configured,
            request.new()
              |> request.set_host("localhost")
              |> request.set_port(port)
              |> request.set_path("/echo")
              |> request.set_body(<<>>),
          )
          |> result.map_error(Runtime),
        )
        Ok(#(default_failed, closed, response.status))
      })
    })
  assert observed == Ok(#(True, Ok(client.Closed), 200))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn explicit_rootless_anchors_still_verify_the_original_service_name_test() -> Nil {
  let observed =
    http3_test_support.with_ipv4_server_timeout(5000, fn(port, ca) {
      without_system_roots(fn() {
        use configured <- result.try(
          client.with_ca_certificate(client.new(), ca)
          |> result.map_error(Configuration),
        )
        let configured =
          client.with_connect_address(
            configured,
            address.parse("127.0.0.1") |> should.be_ok,
          )
        case client.connect_to(configured, "wrong-origin.invalid", 443, port) {
          Error(failure) -> Error(Runtime(failure))
          Ok(connection) -> {
            let _closed = client.close(connection)
            Ok(Nil)
          }
        }
      })
    })
  assert observed == Error(Runtime(client.Failure(failure.Tls(failure.Peer))))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn alternate_port_preserves_reusable_origin_authority_test() -> Nil {
  http3_test_support.with_ipv4_server_timeout(5000, fn(endpoint_port, ca) {
    let trace = client.new_connect_trace()
    let configured = configure(ca) |> client.with_connect_trace(trace:)
    verify_origin(configured, endpoint_port)
    assert_phase(
      trace:,
      phase: client.NameResolution,
      outcome: client.Succeeded,
    )
    assert_phase(trace:, phase: client.UdpOpen, outcome: client.Succeeded)
    assert_phase(trace:, phase: client.TlsHandshake, outcome: client.Succeeded)
    assert_phase(
      trace:,
      phase: client.OwnershipPublication,
      outcome: client.Succeeded,
    )
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn explicit_address_and_port_preserve_reusable_origin_test() -> Nil {
  http3_test_support.with_ipv4_server_timeout(5000, fn(endpoint_port, ca) {
    let trace = client.new_connect_trace()
    let configured =
      configure(ca)
      |> client.with_connect_trace(trace:)
      |> client.with_connect_address(address.parse("127.0.0.1") |> should.be_ok)
    verify_origin(configured, endpoint_port)
    assert_phase(trace:, phase: client.NameResolution, outcome: client.Skipped)
    assert_phase(trace:, phase: client.TlsHandshake, outcome: client.Succeeded)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn explicit_destination_keeps_certificate_identity_verification_test() -> Nil {
  http3_test_support.with_ipv4_server_timeout(5000, fn(endpoint_port, ca) {
    let trace = client.new_connect_trace()
    let configured =
      configure(ca)
      |> client.with_connect_trace(trace:)
      |> client.with_connect_address(address.parse("127.0.0.1") |> should.be_ok)
    // The local fixture certificate covers localhost, never this origin.
    let outcome =
      client.connect_to(configured, "wrong-origin.invalid", 443, endpoint_port)
    assert outcome == Error(client.Failure(failure.Tls(failure.Peer)))
    assert_phase(trace:, phase: client.NameResolution, outcome: client.Skipped)
    assert_phase(trace:, phase: client.TlsHandshake, outcome: client.Failed)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn trace_follows_both_plain_connect_and_buffered_send_test() -> Nil {
  http3_test_support.with_ipv4_server_timeout(5000, fn(port, ca) {
    let trace = client.new_connect_trace()
    let configured = configure(ca) |> client.with_connect_trace(trace:)
    let connection =
      client.connect(configured, "localhost", port) |> should.be_ok
    client.close(connection) |> should.be_ok
    assert_phase(trace:, phase: client.TlsHandshake, outcome: client.Succeeded)
    let outgoing =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(port)
      |> request.set_path("/echo")
      |> request.set_body(<<>>)
    let response = client.send(configured, outgoing) |> should.be_ok
    assert response.status == 200
    let attempts =
      client.connect_snapshot(trace).events
      |> list.filter(fn(event) {
        event.phase == client.TlsHandshake && event.outcome == client.Succeeded
      })
      |> list.map(fn(event) { event.attempt })
    assert attempts == [1, 2]
  })
}

fn assert_phase(
  trace trace: client.ConnectTrace,
  phase phase: client.ConnectPhase,
  outcome outcome: client.ConnectOutcome,
) -> Nil {
  let snapshot = client.connect_snapshot(trace)
  assert snapshot.consistent
  assert snapshot.dropped == 0
  let observed =
    list.any(snapshot.events, fn(event) {
      event.phase == phase
      && event.outcome == outcome
      && event.elapsed_milliseconds >= 0
    })
  assert observed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn alternate_port_is_validated_before_connecting_test() -> Nil {
  assert client.connect_to(client.new(), "localhost", 443, 0)
    == Error(client.InvalidPort(0))
  assert client.connect_to(client.new(), "localhost", 443, 65_536)
    == Error(client.InvalidPort(65_536))
  assert client.connect_to(client.new(), "localhost", 0, 443)
    == Error(client.InvalidPort(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn alternate_destination_keeps_resumption_bound_to_origin_test() -> Nil {
  http3_test_support.with_ipv4_server_timeout(5000, fn(endpoint_port, ca) {
    let origin_port = case endpoint_port == 443 {
      True -> 444
      False -> 443
    }
    let configured = configure(ca)
    let connection =
      client.connect_to(configured, "localhost", origin_port, endpoint_port)
      |> should.be_ok
    let outgoing =
      request.new()
      |> request.set_host("localhost")
      |> request.set_port(origin_port)
      |> request.set_path("/echo")
      |> request.set_body(Nil)
    let stream = client.open_stream(connection, outgoing) |> should.be_ok
    client.finish(stream) |> should.be_ok
    // nolint: assert_ok_pattern -- the exact response variant is the regression contract.
    let assert Ok(client.Response(200, _)) = client.next_event(stream)
    assert client.next_event(stream) == Ok(client.End)
    let ticket =
      client.connection_transport(connection)
      |> transport.resumption_ticket
      |> should.be_ok
    let closed = client.close(connection)
    let trace = client.new_connect_trace()
    let configured =
      client.with_resumption_ticket(configured, ticket)
      |> client.with_connect_trace(trace:)
    let wrong_origin =
      client.connect_to(configured, "localhost", endpoint_port, endpoint_port)
    let resumed =
      client.connect_to(configured, "localhost", origin_port, endpoint_port)
      |> should.be_ok
    let status =
      client.connection_transport(resumed) |> transport.resumption_status
    let resumed_closed = client.close(resumed)
    assert closed == Ok(client.Closed)
    assert wrong_origin == Error(client.ResumptionOriginMismatch)
    assert status == Ok(transport.Resumed)
    assert_phase(trace:, phase: client.TlsHandshake, outcome: client.Succeeded)
    assert resumed_closed == Ok(client.Closed)
  })
}

fn configure(ca: BitArray) -> client.Client {
  client.new()
  |> client.with_ca_certificate(ca)
  |> should.be_ok
  |> client.with_address_family(config.Ipv4)
}

fn verify_origin(configured: client.Client, endpoint_port: Int) -> Nil {
  // Select a distinct valid origin without requiring another listener.
  let origin_port = case endpoint_port == 443 {
    True -> 444
    False -> 443
  }
  let connection =
    client.connect_to(configured, "localhost", origin_port, endpoint_port)
    |> should.be_ok
  let original =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(origin_port)
    |> request.set_path("/echo")
    |> request.set_body(Nil)
  let wrong_origin =
    client.open_stream(connection, request.set_port(original, endpoint_port))
  let stream = client.open_stream(connection, original) |> should.be_ok
  let finished = client.finish(stream)
  let response = client.next_event(stream)
  let closed = client.close(connection)
  assert wrong_origin == Error(client.OriginMismatch)
  assert finished == Ok(Nil)
  // nolint: assert_ok_pattern -- the exact response variant is the regression contract.
  let assert Ok(client.Response(200, headers)) = response
  let authority = case origin_port {
    443 -> "localhost"
    _ -> "localhost:" <> int.to_string(origin_port)
  }
  assert list.key_find(headers, "x-request-authority") == Ok(authority)
  assert closed == Ok(client.Closed)
}
