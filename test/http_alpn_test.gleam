import gleam/erlang/process
import gleam/http/response
import gleam/list
import gleam/option.{None}
import http/body
import http/context
import http/server

@external(erlang, "http_alpn_test_ffi", "credentials")
fn credentials(version: Int) -> #(BitArray, BitArray, BitArray)

@external(erlang, "http_alpn_test_ffi", "probe")
fn probe(
  port: Int,
  ca: BitArray,
  protocols: List(BitArray),
  version: Int,
) -> Int

pub fn http1_tls_accepts_peers_without_an_alpn_extension_test() -> Nil {
  list.each([12, 13], fn(version) {
    run_peer(protocols: [], version:, accepted: True)
  })
}

pub fn http1_tls_accepts_an_explicit_http1_protocol_test() -> Nil {
  list.each([12, 13], fn(version) {
    run_peer(protocols: [<<"http/1.1">>], version:, accepted: True)
  })
}

pub fn http1_tls_rejects_an_incompatible_nonempty_protocol_test() -> Nil {
  list.each([12, 13], fn(version) {
    run_peer(protocols: [<<"h2">>], version:, accepted: False)
  })
}

fn run_peer(
  protocols protocols: List(BitArray),
  version version: Int,
  accepted accepted: Bool,
) -> Nil {
  let #(certificate, key, ca) = credentials(version)
  let invoked = process.new_subject()
  let assert Ok(running) =
    server.start(server.defaults(), fn(_, metadata) {
      let authenticated =
        context.protocol(metadata) == context.Http1
        && context.tls_identity(metadata)
        == context.TlsIdentity("localhost", None)
      process.send(invoked, authenticated)
      Ok(response.Response(status: 204, headers: [], body: body.empty()))
    })
  let assert Ok(listener) =
    server.listen_http1_tls(
      running,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults(),
      certificate,
      key,
      "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let outcome = probe(port, ca, protocols, version)
  let stopped = server.stop_listener(listener)
  let closed = server.stop(running)
  assert stopped == Ok(Nil)
  assert closed == Ok(Nil)
  case accepted {
    True -> {
      assert outcome == 0
      assert process.receive(invoked, within: 0) == Ok(True)
    }
    False -> {
      assert outcome == 8
      assert process.receive(invoked, within: 0) == Error(Nil)
    }
  }
}
