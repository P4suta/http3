import gleam/bit_array
import gleam/list
import gleam/option.{Some}
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/tls/session_ticket
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
  let assert Ok(engine.Step(client, confirmation_actions)) =
    engine.confirm_client_handshake(client)
  assert has_discard(confirmation_actions, engine.Handshake)
  let assert Ok(engine.Step(_, [])) = engine.confirm_client_handshake(client)
  Nil
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

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn accepts_arbitrarily_fragmented_crypto_bytes_test() -> Nil {
  let #(client_config, server_config) = configs([<<"h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client(client_config)
  let #(client_hello_prefix, client_hello_suffix) =
    split_at(sent_at(client_actions, engine.Initial), 7)

  let assert Ok(engine.Step(server, [])) =
    engine.handle_server(server, engine.Initial, client_hello_prefix)
  let assert Ok(engine.Step(server, server_actions)) =
    engine.handle_server(server, engine.Initial, client_hello_suffix)

  let #(server_hello_prefix, server_hello_suffix) =
    split_at(sent_at(server_actions, engine.Initial), 11)
  let assert Ok(engine.Step(client, [])) =
    engine.handle_client(client, engine.Initial, server_hello_prefix)
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(client, engine.Initial, server_hello_suffix)

  let server_flight = sent_at(server_actions, engine.Handshake)
  let #(flight_prefix, flight_rest) = split_at(server_flight, 5)
  let #(flight_middle, flight_suffix) = split_at(flight_rest, 37)
  let assert Ok(engine.Step(client, [])) =
    engine.handle_client(client, engine.Handshake, flight_prefix)
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(client, engine.Handshake, flight_middle)
  let assert Ok(engine.Step(_client, finish_actions)) =
    engine.handle_client(client, engine.Handshake, flight_suffix)

  let #(finished_prefix, finished_suffix) =
    split_at(sent_at(finish_actions, engine.Handshake), 3)
  let assert Ok(engine.Step(server, [])) =
    engine.handle_server(server, engine.Handshake, finished_prefix)
  let assert Ok(engine.Step(server, complete_actions)) =
    engine.handle_server(server, engine.Handshake, finished_suffix)
  assert engine.server_phase(server) == engine.Connected
  assert has_complete(complete_actions)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_one_hello_retry_request_and_discards_initial_keys_test() -> Nil {
  let #(client_config, server_config) = configs([<<"h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client_with_strategy(client_config, engine.DeferredKeyShare)

  let assert Ok(engine.Step(server, retry_actions)) =
    engine.handle_server(
      server,
      engine.Initial,
      sent_at(client_actions, engine.Initial),
    )
  assert engine.server_phase(server) == engine.AwaitingPeerHello

  let assert Ok(engine.Step(client, second_hello_actions)) =
    engine.handle_client(
      client,
      engine.Initial,
      sent_at(retry_actions, engine.Initial),
    )
  let assert Ok(engine.Step(server, server_actions)) =
    engine.handle_server(
      server,
      engine.Initial,
      sent_at(second_hello_actions, engine.Initial),
    )
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client,
      engine.Initial,
      sent_at(server_actions, engine.Initial),
    )
  let assert Ok(engine.Step(_client, finish_actions)) =
    engine.handle_client(
      client,
      engine.Handshake,
      sent_at(server_actions, engine.Handshake),
    )
  assert has_discard(finish_actions, engine.Initial)

  let assert Ok(engine.Step(server, complete_actions)) =
    engine.handle_server(
      server,
      engine.Handshake,
      sent_at(finish_actions, engine.Handshake),
    )
  assert has_discard(complete_actions, engine.Initial)
  assert has_discard(complete_actions, engine.Handshake)
  assert engine.server_phase(server) == engine.Connected
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn completes_psk_resumption_and_accepts_replay_checked_early_data_test() -> Nil {
  let #(client_config, server_config) = configs([<<"h3">>])
  let ticket_key = <<0x61:256>>
  let resumption_master_secret = <<0x72:256>>
  let issued_at = 10_000_000
  let assert Ok(remembered_parameters) =
    transport_parameter.encode_all(
      server_config.transport_parameters,
      transport_parameter.Server,
    )
  let assert Ok(new_ticket) =
    session_ticket.issue(
      ticket_key:,
      issued_at_milliseconds: issued_at,
      lifetime_seconds: 3600,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "localhost",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: remembered_parameters,
      permit_early_data: True,
    )
  let assert Ok(ticket) =
    session_ticket.store(
      new_ticket:,
      received_at_milliseconds: issued_at,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "localhost",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: remembered_parameters,
    )
  let assert Ok(replay_cache) = anti_replay.new(60_000, 128)
  let assert Ok(policy) =
    resumption.server_policy(
      ticket_key:,
      now_milliseconds: issued_at + 50,
      ticket_age_tolerance_milliseconds: 100,
      replay_cache:,
    )
  let assert Ok(server) =
    engine.start_server_with_resumption(server_config, policy)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client_resuming(client_config, ticket, issued_at + 50, True)
  assert has_write_keys(client_actions, engine.ZeroRtt)
  assert has_peer_parameters(client_actions)

  let assert Ok(engine.Step(server, server_actions)) =
    engine.handle_server(
      server,
      engine.Initial,
      sent_at(client_actions, engine.Initial),
    )
  assert has_read_keys(server_actions, engine.ZeroRtt)
  assert list.contains(server_actions, engine.EarlyDataAccepted)

  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client,
      engine.Initial,
      sent_at(server_actions, engine.Initial),
    )
  let assert Ok(engine.Step(client, finish_actions)) =
    engine.handle_client(
      client,
      engine.Handshake,
      sent_at(server_actions, engine.Handshake),
    )
  assert engine.client_phase(client) == engine.Connected
  assert list.contains(finish_actions, engine.EarlyDataAccepted)
  assert has_discard(finish_actions, engine.ZeroRtt)

  let assert Ok(engine.Step(server, complete_actions)) =
    engine.handle_server(
      server,
      engine.Handshake,
      sent_at(finish_actions, engine.Handshake),
    )
  assert engine.server_phase(server) == engine.Connected
  assert has_discard(complete_actions, engine.ZeroRtt)
  let assert Some(_) = engine.server_replay_cache(server)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn issues_fragments_stores_and_reuses_post_handshake_ticket_test() -> Nil {
  let #(client_config, server_config) = configs([<<"h3">>])
  let assert Ok(server) = engine.start_server(server_config)
  let assert Ok(engine.Step(client, client_actions)) =
    engine.start_client(client_config)
  let assert Ok(engine.Step(server, server_actions)) =
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
  let assert Ok(engine.Step(client, finish_actions)) =
    engine.handle_client(
      client,
      engine.Handshake,
      sent_at(server_actions, engine.Handshake),
    )
  let assert Ok(engine.Step(server, _)) =
    engine.handle_server(
      server,
      engine.Handshake,
      sent_at(finish_actions, engine.Handshake),
    )

  let ticket_key = <<0x83:256>>
  let ticket_time = 20_000_000
  let assert Ok(engine.Step(_server, ticket_actions)) =
    engine.issue_new_session_ticket(server, ticket_key, ticket_time, 3600, True)
  let #(ticket_prefix, ticket_suffix) =
    split_at(sent_at(ticket_actions, engine.OneRtt), 9)
  let assert Ok(engine.Step(client, [])) =
    engine.handle_client_at(client, engine.OneRtt, ticket_prefix, ticket_time)
  let assert Ok(engine.Step(_client, stored_actions)) =
    engine.handle_client_at(client, engine.OneRtt, ticket_suffix, ticket_time)
  let ticket = stored_ticket(stored_actions)
  assert session_ticket.early_data_allowed(ticket)

  let assert Ok(cache) = anti_replay.new(60_000, 128)
  let assert Ok(policy) =
    resumption.server_policy(ticket_key, ticket_time + 10, 100, cache)
  let assert Ok(resumed_server) =
    engine.start_server_with_resumption(server_config, policy)
  let assert Ok(engine.Step(_resumed_client, resumed_actions)) =
    engine.start_client_resuming(client_config, ticket, ticket_time + 10, True)
  let assert Ok(engine.Step(_, accepted_actions)) =
    engine.handle_server(
      resumed_server,
      engine.Initial,
      sent_at(resumed_actions, engine.Initial),
    )
  assert list.contains(accepted_actions, engine.EarlyDataAccepted)
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

fn has_peer_parameters(actions: List(engine.Action)) -> Bool {
  list.any(actions, fn(action) {
    case action {
      engine.PeerTransportParameters(_) -> True
      _ -> False
    }
  })
}

fn stored_ticket(actions: List(engine.Action)) -> session_ticket.ClientTicket {
  let assert [engine.StoreSessionTicket(ticket)] =
    list.filter(actions, fn(action) {
      case action {
        engine.StoreSessionTicket(_) -> True
        _ -> False
      }
    })
  ticket
}

fn has_discard(
  actions: List(engine.Action),
  level: engine.EncryptionLevel,
) -> Bool {
  list.any(actions, fn(action) {
    case action {
      engine.DiscardKeys(action_level) -> action_level == level
      _ -> False
    }
  })
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

fn split_at(bytes: BitArray, byte_count: Int) -> #(BitArray, BitArray) {
  let prefix_size = byte_count * 8
  let assert <<prefix:bits-size(prefix_size), suffix:bits>> = bytes
  #(prefix, suffix)
}
