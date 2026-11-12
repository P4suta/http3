import gleam/erlang/process.{type Pid}
import gleam/option.{None, Some}
import gleam/result
import gleeunit/should
import quic_core
import quic_core/client
import quic_core/config
import quic_core/failure
import quic_core/server

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

@external(erlang, "quic_core_test_ffi", "labelled_pid")
fn labelled_pid(handle: handle, label: String) -> Result(Pid, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn default_peer_close_remains_uncoded_after_actor_release_test() -> Nil {
  assert observed_close(0)
    == #(Error(server.Failure(failure.Closed(failure.Peer, None))), True)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn application_peer_close_survives_actor_release_test() -> Nil {
  assert observed_close(0x106)
    == #(Error(server.Failure(failure.Closed(failure.Peer, Some(0x106)))), True)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn unknown_maximum_peer_close_code_is_preserved_without_reason_test() -> Nil {
  assert observed_close(4_611_686_018_427_387_903)
    == #(
      Error(
        server.Failure(failure.Closed(
          failure.Peer,
          Some(4_611_686_018_427_387_903),
        )),
      ),
      True,
    )
}

fn observed_close(code: Int) -> #(Result(Nil, server.Error), Bool) {
  let certificate = fixture("server.pem") |> should.be_ok
  let private_key = fixture("server-key.pem") |> should.be_ok
  let ca = fixture("ca.pem") |> should.be_ok
  let deadlines =
    config.default_deadlines()
    |> config.with_deadline(failure.Operation, 2000)
    |> should.be_ok
  let listener =
    server.new(certificate, private_key, "close-cause")
    |> should.be_ok
    |> server.with_address_family(quic_core.Ipv4)
    |> server.with_deadlines(deadlines)
    |> server.start
    |> should.be_ok
  let port = server.port(listener) |> should.be_ok
  let connection =
    client.new_with_ca_certificates("localhost", port, "close-cause", ca)
    |> should.be_ok
    |> client.with_address_family(quic_core.Ipv4)
    |> client.with_deadlines(deadlines)
    |> client.connect
    |> should.be_ok
  let peer = server.accept(listener) |> should.be_ok
  let actor = labelled_pid(peer, "quic_core.connection") |> should.be_ok
  let monitor = process.monitor(actor)
  let exited =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
  let code = quic_core.application_error_code(code) |> should.be_ok
  client.close_with_code(connection, code) |> should.be_ok
  // Waiting for real DOWN proves that no actor retention or caller scheduling accident is responsible for preserving the bounded terminal cause.
  let released = process.selector_receive(exited, within: 2000) == Ok(Nil)
  process.demonitor_process(monitor)
  let observed = server.accept_stream_next(peer) |> result.replace(Nil)
  let _closed = server.close(peer)
  server.stop(listener) |> should.be_ok
  #(observed, released)
}
