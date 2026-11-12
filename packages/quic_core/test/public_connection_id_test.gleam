import gleam/erlang/process.{type Pid}
import gleam/int
import quic_core
import quic_core/client
import quic_core/diagnostics
import quic_core/internal/udp
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

@external(erlang, "quic_core_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn real_migration_retires_and_replenishes_registered_server_routes_test() -> Nil {
  let #(listener, connection, peer) = peers()
  round_trip(connection, peer)
  let _ready = await_local(peer, 0, udp.monotonic_millisecond() + 2000)
  let initial = server.local_connection_id_stats(peer)
  assert initial == Ok(diagnostics.ConnectionIdStats(4, 4, 0, 4096))
  int.range(1, 5, Nil, fn(_, retired) {
    assert client.migrate(connection) == Ok(Nil)
    round_trip(connection, peer)
    let client_ids = client.local_connection_id_stats(connection)
    assert client_ids
      == Ok(diagnostics.ConnectionIdStats(4, 4 + retired, retired, 4096))
    let ready = await_local(peer, retired, udp.monotonic_millisecond() + 2000)
    assert ready
    assert server.local_connection_id_stats(peer)
      == Ok(diagnostics.ConnectionIdStats(4, 4 + retired, retired, 4096))
    assert server.connection_id_stats(listener)
      == Ok(diagnostics.ListenerConnectionIdStats(1, 4))
  })
  let assert Ok(actor) = labelled_pid(peer, "quic_core.connection")
  process.kill(actor)
  let released =
    await_routes(listener, 0, 0, udp.monotonic_millisecond() + 2000)
  assert released
  let _closed = client.close(connection)
  assert server.stop(listener) == Ok(server.Stopped)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn connection_actor_death_releases_all_aliases_and_preserves_other_routes_test() -> Nil {
  let #(listener, first, first_peer) = peers()
  let assert Ok(port) = server.port(listener)
  let second = connect(port)
  let assert Ok(second_peer) = server.accept(listener)
  round_trip(first, first_peer)
  round_trip(second, second_peer)
  let _ready = await_routes(listener, 2, 8, udp.monotonic_millisecond() + 2000)
  let routes = server.connection_id_stats(listener)
  assert routes == Ok(diagnostics.ListenerConnectionIdStats(2, 8))
  let assert Ok(actor) = labelled_pid(first_peer, "quic_core.connection")
  process.kill(actor)
  let released =
    await_routes(listener, 1, 4, udp.monotonic_millisecond() + 2000)
  assert released
  assert client.migrate(second) == Ok(Nil)
  round_trip(second, second_peer)
  let ready = await_local(second_peer, 1, udp.monotonic_millisecond() + 2000)
  assert ready
  let _first_closed = client.close(first)
  let _second_closed = client.close(second)
  let _peer_closed = server.close(second_peer)
  assert server.stop(listener) == Ok(server.Stopped)
}

fn peers() -> #(server.Listener, client.Connection, server.Connection) {
  let assert Ok(certificate) = fixture("server.pem")
  let assert Ok(key) = fixture("server-key.pem")
  let assert Ok(configured) = server.new(certificate, key, "sample")
  let assert Ok(listener) =
    configured
    |> server.with_address_family(quic_core.Ipv4)
    |> server.start
  let assert Ok(port) = server.port(listener)
  let connection = connect(port)
  let assert Ok(peer) = server.accept(listener)
  #(listener, connection, peer)
}

fn connect(port: Int) -> client.Connection {
  let assert Ok(ca) = fixture("ca.pem")
  let assert Ok(configured) = client.new("localhost", port, "sample")
  let assert Ok(configured) = client.with_ca_certificates(configured, ca)
  let assert Ok(connection) =
    configured
    |> client.with_address_family(quic_core.Ipv4)
    |> client.connect
  connection
}

fn round_trip(connection: client.Connection, peer: server.Connection) -> Nil {
  let assert Ok(stream) = client.open_bidirectional(connection)
  assert client.send_and_finish(stream, <<"route":utf8>>) == Ok(Nil)
  let assert Ok(server.IncomingStream(inbound, server.Bidirectional)) =
    server.accept_stream(peer)
  assert server.receive(inbound, 64) == Ok(server.Data(<<"route":utf8>>, True))
  assert server.send_and_finish(inbound, <<"ack":utf8>>) == Ok(Nil)
  assert client.receive(stream, 64) == Ok(client.Data(<<"ack":utf8>>, True))
}

fn await_local(peer: server.Connection, retired: Int, deadline: Int) -> Bool {
  case server.local_connection_id_stats(peer) {
    Ok(diagnostics.ConnectionIdStats(4, issued, count, _))
      if count == retired && issued == count + 4
    -> True
    _ ->
      case udp.monotonic_millisecond() < deadline {
        False -> False
        True -> {
          process.sleep(5)
          await_local(peer, retired, deadline)
        }
      }
  }
}

fn await_routes(
  listener: server.Listener,
  connections: Int,
  routes: Int,
  deadline: Int,
) -> Bool {
  case server.connection_id_stats(listener) {
    Ok(diagnostics.ListenerConnectionIdStats(
      current_connections,
      current_routes,
    ))
      if current_connections == connections && current_routes == routes
    -> True
    _ ->
      case udp.monotonic_millisecond() < deadline {
        False -> False
        True -> {
          process.sleep(5)
          await_routes(listener, connections, routes, deadline)
        }
      }
  }
}
