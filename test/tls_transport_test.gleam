import gleam/erlang/process
import gleam/result
import gleeunit
import http/internal/transport
import http_test_support

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
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
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
    })

  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  assert transport.upgrade_client_tls(
      client,
      "wrong.test",
      [ca_certificate],
      [<<"http/1.1":utf8>>],
      1000,
    )
    == Error(transport.TlsAuthentication)
  let _server_result = http_test_support.await_task(server_task)

  let assert Ok(Nil) = transport.close(client)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
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
