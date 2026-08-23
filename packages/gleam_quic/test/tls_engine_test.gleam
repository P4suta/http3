import gleam/bit_array
import gleam/list
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/transport_parameter
import gleam_quic/version

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_authenticated_client_server_handshake_test() -> Nil {
  let #(client_config, server_config) = configs([<<"h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client(client_config)
  let client_hello = sent_at(client_actions, engine.Initial)

  let assert Ok(engine.Step(server, server_actions)) =
    engine.handle_server(server, engine.Initial, client_hello)
  let server_hello = sent_at(server_actions, engine.Initial)
  let server_flight = sent_at(server_actions, engine.Handshake)

  let assert Ok(engine.Step(client, hello_actions)) =
    engine.handle_client(client, engine.Initial, server_hello)
  assert has_write_keys(hello_actions, engine.Handshake)
  assert has_read_keys(hello_actions, engine.Handshake)

  let assert Ok(engine.Step(client, finish_actions)) =
    engine.handle_client(client, engine.Handshake, server_flight)
  assert engine.client_phase(client) == engine.Connected
  assert has_write_keys(finish_actions, engine.OneRtt)
  assert has_read_keys(finish_actions, engine.OneRtt)
  assert has_complete(finish_actions)
  let client_finished = sent_at(finish_actions, engine.Handshake)

  let assert Ok(engine.Step(server, complete_actions)) =
    engine.handle_server(server, engine.Handshake, client_finished)
  assert engine.server_phase(server) == engine.Connected
  assert has_complete(complete_actions)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_alpn_mismatch_and_tampered_finished_test() -> Nil {
  let #(mismatch_client_config, server_config) = configs([<<"not-h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(_client, client_actions)) =
    engine.start_client(mismatch_client_config)
  assert engine.handle_server(
      server,
      engine.Initial,
      sent_at(client_actions, engine.Initial),
    )
    == Error(engine.NoApplicationProtocol)

  let #(client_config, server_config) = configs([<<"h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client(client_config)
  let assert Ok(engine.Step(_server, server_actions)) =
    engine.handle_server(
      server,
      engine.Initial,
      sent_at(client_actions, engine.Initial),
    )
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client,
      engine.Initial,
      sent_at(server_actions, engine.Initial),
    )
  let tampered = flip_last(sent_at(server_actions, engine.Handshake))
  assert engine.handle_client(client, engine.Handshake, tampered)
    == Error(engine.FinishedMismatch)
}

fn configs(
  client_alpn: List(BitArray),
) -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  let client =
    engine.ClientConfig(
      version: version.Version1,
      hostname: "localhost",
      application_protocols: client_alpn,
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(<<1>>),
        transport_parameter.MaxUdpPayloadSize(1200),
      ],
      trust_store: trust_store,
      retried: False,
    )
  let server =
    engine.ServerConfig(
      version: version.Version1,
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.OriginalDestinationConnectionId(<<9>>),
        transport_parameter.InitialSourceConnectionId(<<2>>),
        transport_parameter.MaxUdpPayloadSize(1200),
        transport_parameter.MaxDatagramFrameSize(1200),
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
    )
  #(client, server)
}

fn sent_at(
  actions: List(engine.Action),
  level: engine.EncryptionLevel,
) -> BitArray {
  let assert [engine.Send(_, bytes)] =
    list.filter(actions, fn(action) {
      case action {
        engine.Send(action_level, _) -> action_level == level
        _ -> False
      }
    })
  bytes
}

fn has_write_keys(
  actions: List(engine.Action),
  level: engine.EncryptionLevel,
) -> Bool {
  list.any(actions, fn(action) {
    case action {
      engine.InstallWriteKeys(action_level, _) -> action_level == level
      _ -> False
    }
  })
}

fn has_read_keys(
  actions: List(engine.Action),
  level: engine.EncryptionLevel,
) -> Bool {
  list.any(actions, fn(action) {
    case action {
      engine.InstallReadKeys(action_level, _) -> action_level == level
      _ -> False
    }
  })
}

fn has_complete(actions: List(engine.Action)) -> Bool {
  list.contains(actions, engine.HandshakeComplete)
}

fn flip_last(bytes: BitArray) -> BitArray {
  let prefix_size = { bit_array.byte_size(bytes) - 1 } * 8
  let assert <<prefix:bits-size(prefix_size), last>> = bytes
  let changed = case last {
    0 -> 1
    _ -> last - 1
  }
  <<prefix:bits, changed>>
}
