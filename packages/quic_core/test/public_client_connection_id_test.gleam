import gleeunit/should
import quic_core
import quic_core/client
import quic_core/diagnostics
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_issues_bounded_identifiers_after_authenticated_handshake_test() -> Nil {
  let certificate = fixture("server.pem") |> should.be_ok
  let key = fixture("server-key.pem") |> should.be_ok
  let ca = fixture("ca.pem") |> should.be_ok
  let listener =
    server.new(certificate, key, "sample")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new("localhost", port, "sample")
    |> should.be_ok
    |> client.with_ca_certificates(ca)
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let snapshot = client.local_connection_id_stats(connection)
  let closed = client.close(connection)
  let peer_closed = server.close(peer)
  let stopped = server.stop(listener)
  assert snapshot == Ok(diagnostics.ConnectionIdStats(4, 4, 0, 4096))
  assert closed == Ok(client.Closed)
  assert peer_closed == Ok(server.AlreadyClosed)
    || peer_closed == Ok(server.Closed)
  assert stopped == Ok(server.Stopped)
}
