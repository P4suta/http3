import gleam/erlang/process
import gleam/list
import gleam/result
import gleeunit
import http/internal/transport
import http_test_support

@external(erlang, "http_tls_log_test_ffi", "capture")
fn capture_native_tls_logs(run: fn() -> value) -> #(value, Int, Int, Bool)

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn authenticated_tls13_alpn_and_active_once_data_round_trip_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let owner = process.self()
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"h2":utf8>>, <<"http/1.1":utf8>>],
        1000,
      ))
      let transport.TlsReady(socket, _, _) = ready
      use _ <- result.try(transport.transfer_owner(socket, owner))
      Ok(ready)
    })

  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(client_ready) =
    transport.upgrade_client_tls(
      client,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>, <<"http/1.1":utf8>>],
      1000,
    )
  let assert Ok(server_ready) = http_test_support.await_task(server_task)
  let transport.TlsReady(client, client_alpn, client_version) = client_ready
  let transport.TlsReady(server, server_alpn, server_version) = server_ready

  assert client_alpn == <<"h2":utf8>>
  assert server_alpn == <<"h2":utf8>>
  assert client_version == transport.Tls13
  assert server_version == transport.Tls13
  let assert Ok(Nil) = transport.send(client, <<"encrypted":utf8>>)
  let assert Ok(transport.ReadData(<<"encr":utf8>>, server)) =
    transport.read(server, 4, 1000)
  let assert Ok(transport.ReadData(<<"ypte":utf8>>, server)) =
    transport.read(server, 4, 1000)
  let assert Ok(transport.ReadData(<<"d":utf8>>, server)) =
    transport.read(server, 4, 1000)

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(transport.ReadEnd(server)) = transport.read(server, 4, 1000)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn hostname_mismatch_fails_closed_with_a_typed_error_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let diagnostics = transport.diagnostics_new()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let listener = transport.with_listener_diagnostics(listener, diagnostics)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1":utf8>>],
        1000,
      )
      |> close_and_summarize_tls
    })

  let assert Ok(client) =
    transport.connect_with_diagnostics(
      "127.0.0.1",
      port,
      1000,
      1000,
      1500,
      1000,
      diagnostics,
    )
  let rejection =
    transport.upgrade_client_tls(
      client,
      "wrong.test",
      [ca_certificate],
      [<<"http/1.1":utf8>>],
      1000,
    )
    |> close_and_summarize_tls
  assert rejection == Error(transport.TlsAuthentication)
  let _server_result = http_test_support.await_task(server_task)

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.stop(listener)
  let snapshot = transport.diagnostics_snapshot(diagnostics)
  let typed_authentication_failure =
    list.any(snapshot.events, fn(event) {
      event.step == transport.ClientTlsCompleted
      && event.outcome == transport.Failed(transport.TlsAuthentication)
    })
  assert typed_authentication_failure
  Nil
}

pub fn rejected_tls_identity_never_logs_native_certificate_or_hostname_reports_test() -> Nil {
  let #(_, client_reports, server_reports, observer_verified) =
    capture_native_tls_logs(fn() {
      hostname_mismatch_fails_closed_with_a_typed_error_test()
    })
  assert observer_verified
  assert #(client_reports, server_reports) == #(0, 0)
}

pub fn malformed_tls_inputs_are_rejected_before_a_handshake_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(server) = transport.accept(listener, 1000)

  assert transport.upgrade_client_tls(
      client,
      "localhost",
      [<<1, 2, 3>>],
      [<<"http/1.1":utf8>>],
      1000,
    )
    == Error(transport.InvalidInput)
  assert transport.upgrade_client_tls(client, "localhost", [], [<<>>], 1000)
    == Error(transport.InvalidInput)
  assert transport.upgrade_server_tls(
      server,
      <<"not a certificate":utf8>>,
      <<"not a key":utf8>>,
      [<<"http/1.1":utf8>>],
      1000,
    )
    == Error(transport.InvalidInput)

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.close(server)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn tls_negotiation_is_limited_to_forward_secret_aead_suites_test() -> Nil {
  // RFC 9325 section 4.1: an implementation SHOULD NOT negotiate a cipher suite built on non-ephemeral Diffie-Hellman, finite-field or elliptic curve, and a TLS 1.2 implementation SHOULD NOT negotiate the ephemeral finite-field suites either; the same section requires forward secrecy to be supported and preferred.
  // The platform's default TLS 1.2 list carries static ECDH and TLS_DHE_* suites, so inheriting it offers exactly what those clauses exclude: the list has to be pinned on both sides.
  let #(client, server) = http_test_support.tls_option_cipher_profile()
  let #(client_count, client_exchanges, client_macs) = client
  let #(server_count, server_exchanges, server_macs) = server

  // A pinned list, not an absent one that would fall back to the default.
  assert client_count > 0
  assert server_count > 0

  // `any` is how TLS 1.3 spells its own key schedule, which is always ephemeral; every TLS 1.2 suite left is an ECDHE one.
  assert client_exchanges == ["any", "ecdhe_ecdsa", "ecdhe_rsa"]
  assert server_exchanges == ["any", "ecdhe_ecdsa", "ecdhe_rsa"]

  // Section 4.2: a CBC suite may be used only with encrypt_then_mac, which is simpler to satisfy by carrying no suite that needs it.
  assert client_macs == ["aead"]
  assert server_macs == ["aead"]
}

pub fn localhost_dial_pairs_accept_and_tls_observations_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let diagnostics = transport.diagnostics_new()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let listener = transport.with_listener_diagnostics(listener, diagnostics)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"h2":utf8>>],
        1000,
      )
      |> close_and_summarize_tls
    })
  let client_result = {
    use socket <- result.try(transport.connect_with_diagnostics(
      "localhost",
      port,
      1000,
      1000,
      1500,
      1000,
      diagnostics,
    ))
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      1000,
    )
    |> close_and_summarize_tls
  }
  let server_result = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  let snapshot = transport.diagnostics_snapshot(diagnostics)
  assert client_result == Ok(#(<<"h2":utf8>>, transport.Tls13))
  assert server_result == Ok(#(<<"h2":utf8>>, transport.Tls13))
  assert snapshot.consistent
  assert snapshot.dropped_events == 0
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.DialCompleted
    && event.family == transport.Ipv4
    && event.outcome == transport.Successful
  })
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.AcceptCompleted
    && event.outcome == transport.Successful
  })
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.ClientTlsCompleted
    && event.outcome == transport.Successful
  })
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.ServerTlsCompleted
    && event.outcome == transport.Successful
  })
}

pub fn expired_accept_is_distinct_from_the_later_tls_timeout_test() -> Nil {
  let #(_, _, ca_certificate) = http_test_support.server_credentials()
  let diagnostics = transport.diagnostics_new()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let listener = transport.with_listener_diagnostics(listener, diagnostics)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  assert transport.accept(listener, 5) == Error(transport.Timeout)
  let client_result = {
    use socket <- result.try(transport.connect_with_diagnostics(
      "127.0.0.1",
      port,
      1000,
      1000,
      1500,
      1000,
      diagnostics,
    ))
    transport.upgrade_client_tls(
      socket,
      "localhost",
      [ca_certificate],
      [<<"h2":utf8>>],
      30,
    )
    |> close_and_summarize_tls
  }
  let assert Ok(Nil) = transport.stop(listener)
  let snapshot = transport.diagnostics_snapshot(diagnostics)
  assert client_result == Error(transport.Timeout)
  assert snapshot.consistent
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.AcceptCompleted
    && event.outcome == transport.Failed(transport.Timeout)
  })
  assert list.any(snapshot.events, fn(event) {
    event.step == transport.ClientTlsCompleted
    && event.outcome == transport.Failed(transport.Timeout)
  })
}

fn close_and_summarize_tls(
  outcome: Result(transport.TlsReady, transport.Error),
) -> Result(#(BitArray, transport.TlsVersion), transport.Error) {
  use transport.TlsReady(socket, alpn, version) <- result.try(outcome)
  use _ <- result.try(transport.close(socket))
  Ok(#(alpn, version))
}
