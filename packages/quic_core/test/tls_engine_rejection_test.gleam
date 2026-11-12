import gleam/bit_array
import gleam/list
import gleam/option.{None}
import gleam/result
import quic_core/internal/crypto
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/extension
import quic_core/internal/tls/extension_value
import quic_core/internal/tls/handshake
import quic_core/internal/tls/hello
import quic_core/internal/tls/key_exchange
import quic_core/internal/tls/message_body
import quic_core/internal/tls/pre_shared_key
import quic_core/internal/tls/resumption
import quic_core/internal/tls/session_ticket
import quic_core/transport_parameter
import quic_core/version

@external(erlang, "quic_core_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// RFC 8446 sections 4.1.2 and 4.2.2 permit a cookie without a new key_share.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn cookie_only_retry_preserves_the_original_key_share_test() -> Nil {
  list.each(
    [engine.EagerKeyShare, engine.EagerP256KeyShare, engine.DeferredKeyShare],
    fn(strategy) {
      assert cookie_retry_summary(strategy) == Ok(#(True, True, True))
    },
  )
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_refreshes_ticket_age_from_the_complete_receive_time_test() -> Nil {
  assert retry_age_summary(retry(group: extension_value.Secp256r1), False)
    == Ok(#(True, True, True))
  assert retry_age_summary(retry(group: extension_value.Secp256r1), True)
    == Ok(#(True, True, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn resumed_cookie_only_retry_refreshes_age_and_reseals_binder_test() -> Nil {
  assert retry_age_summary(cookie_retry(), False) == Ok(#(True, True, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_rejects_expired_tickets_and_backwards_receive_time_test() -> Nil {
  let #(config, _) = configs()
  let assert Ok(engine.Step(client, _)) =
    engine.start_client_resuming(config, ticket(), 1001, True)
  list.each([1000, 2001], fn(now) {
    assert engine.handle_client_at(
        client,
        engine.Initial,
        retry(group: extension_value.Secp256r1),
        now,
      )
      |> outcome
      == Error(engine.ResumptionFailure(resumption.InvalidClientTicket))
  })
}

// A second ClientHello must change in response to a cookie or a new group.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_without_cookie_or_selected_group_is_rejected_test() -> Nil {
  let #(config, _) = configs()
  let assert Ok(engine.Step(client, _)) = engine.start_client(config)
  let assert Ok(body) =
    hello.encode_server(
      hello.HelloRetryRequest(<<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.SupportedVersions, <<3, 4>>),
      ]),
      hello.default_limits(),
    )
  assert engine.handle_client(
      client,
      engine.Initial,
      message(kind: handshake.ServerHello, body: body),
    )
    |> outcome
    == Error(engine.InvalidHelloRetryRequest)
}

fn cookie_retry() -> BitArray {
  let assert Ok(cookie) = extension_value.encode_cookie(<<1, 2, 3>>)
  let assert Ok(body) =
    hello.encode_server(
      hello.HelloRetryRequest(<<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.SupportedVersions, <<3, 4>>),
        extension.Extension(extension.Cookie, cookie),
      ]),
      hello.default_limits(),
    )
  message(kind: handshake.ServerHello, body: body)
}

fn cookie_retry_summary(
  strategy: engine.KeyShareStrategy,
) -> Result(#(Bool, Bool, Bool), engine.Error) {
  let #(config, _) = configs()
  use engine.Step(client, first_actions) <- result.try(
    engine.start_client_with_strategy(config, strategy),
  )
  let assert Ok(first_bytes) =
    sent(actions: first_actions, level: engine.Initial)
  let assert Ok(first) = client_hello(bytes: first_bytes)
  use engine.Step(client, actions) <- result.try(engine.handle_client(
    client,
    engine.Initial,
    cookie_retry(),
  ))
  let assert Ok(second_bytes) = sent(actions: actions, level: engine.Initial)
  let assert Ok(second) = client_hello(bytes: second_bytes)
  let assert Ok(expected_cookie) = extension_value.encode_cookie(<<1, 2, 3>>)
  let copied_cookie =
    extension_bytes(extensions: second.extensions, kind: extension.Cookie)
    == Ok(expected_cookie)
  Ok(#(
    list.filter(second.extensions, fn(value) { value.kind != extension.Cookie })
      == first.extensions,
    copied_cookie && second.random == first.random,
    engine.client_phase(client) == engine.AwaitingPeerHello
      && list.length(actions) == 1,
  ))
}

fn retry_age_summary(
  encoded_retry: BitArray,
  fragmented: Bool,
) -> Result(#(Bool, Bool, Bool), engine.Error) {
  let #(config, _) = configs()
  let ticket = ticket()
  use engine.Step(client, first_actions) <- result.try(
    engine.start_client_resuming(config, ticket, 1001, True),
  )
  let assert Ok(first) = sent(actions: first_actions, level: engine.Initial)
  use engine.Step(_, actions) <- result.try(case fragmented {
    False ->
      engine.handle_client_at(client, engine.Initial, encoded_retry, 1501)
    True -> {
      let assert <<prefix:size(3)-bytes, rest:bytes>> = encoded_retry
      use engine.Step(client, pending_actions) <- result.try(
        engine.handle_client_at(client, engine.Initial, prefix, 1201),
      )
      assert list.is_empty(pending_actions)
      engine.handle_client_at(client, engine.Initial, rest, 1501)
    }
  })
  let assert Ok(second) = sent(actions: actions, level: engine.Initial)
  let assert Ok(decoded) = client_hello(bytes: second)
  let assert Ok(psk_bytes) =
    extension_bytes(
      extensions: decoded.extensions,
      kind: extension.PreSharedKey,
    )
  let assert Ok(offered) = pre_shared_key.decode_offered(psk_bytes)
  let assert [pre_shared_key.Identity(_, age)] = offered.identities
  let assert Ok(expected_age) =
    session_ticket.obfuscated_ticket_age(ticket, 1501)
  let assert Ok(truncated) = pre_shared_key.binder_transcript(second, offered)
  let assert Ok(first_hash) = crypto.hash(crypto.Sha256, first)
  let assert [binder] = offered.binders
  let binder_valid =
    pre_shared_key.verify_binder(
      crypto.Sha256,
      ticket.pre_shared_key,
      <<254, 32:size(24), first_hash:bits, encoded_retry:bits, truncated:bits>>,
      binder,
      False,
    )
    == Ok(True)
  let assert Ok(last) = list.last(decoded.extensions)
  Ok(#(
    age == expected_age,
    binder_valid && last.kind == extension.PreSharedKey,
    !list.any(decoded.extensions, fn(value) {
      value.kind == extension.EarlyData
    })
      && list.count(actions, fn(action) {
      action == engine.DiscardKeys(engine.ZeroRtt)
    })
      == 1,
  ))
}

// RFC 8446 section 4.2.8 permits a mutually supported group absent from the first key_share.
// The existence of another share must not reject that HRR.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn eager_x25519_accepts_retry_for_advertised_p256_test() -> Nil {
  assert retry_summary(engine.EagerKeyShare, extension_value.Secp256r1)
    == Ok(#(engine.AwaitingPeerHello, [extension_value.Secp256r1], True, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn eager_p256_accepts_retry_for_advertised_x25519_test() -> Nil {
  assert retry_summary(engine.EagerP256KeyShare, extension_value.X25519)
    == Ok(#(engine.AwaitingPeerHello, [extension_value.X25519], True, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_reseals_psk_with_the_full_retry_transcript_and_discards_early_keys_test() -> Nil {
  assert resumed_retry_summary() == Ok(#(True, True, True, True))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ticket_expiry_and_clock_rollback_are_rejected_before_client_keys_test() -> Nil {
  let #(config, _) = configs()
  let ticket = ticket()
  list.each([999, 2001], fn(now) {
    assert engine.start_client_resuming(
        config: config,
        ticket: ticket,
        now_milliseconds: now,
        request_early_data: True,
      )
      |> outcome
      == Error(engine.ResumptionFailure(resumption.InvalidClientTicket))
  })
  assert engine.start_client_resuming(
      config: config,
      ticket: ticket,
      now_milliseconds: 1999,
      request_early_data: True,
    )
    |> outcome
    == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_server_cannot_reaccept_early_data_after_hello_retry_request_test() -> Nil {
  let #(config, server) = configs()
  let assert Ok(engine.Step(client, _)) =
    engine.start_client_resuming(
      config: config,
      ticket: ticket(),
      now_milliseconds: 1001,
      request_early_data: True,
    )
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: retry(group: extension_value.Secp256r1),
    )
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: selected_psk_server_hello(),
    )
  let assert Ok(alpn) = extension_value.encode_alpn([<<"h3">>])
  let assert Ok(parameters) =
    transport_parameter.encode_all(
      parameters: server.transport_parameters,
      sent_by: transport_parameter.Server,
    )
  let extensions = [
    extension.Extension(extension.ApplicationLayerProtocolNegotiation, alpn),
    extension.Extension(extension.QuicTransportParameters, parameters),
  ]
  let assert Ok(forbidden) =
    message_body.encode_encrypted_extensions(
      extensions: [extension.Extension(extension.EarlyData, <<>>), ..extensions],
      limits: message_body.default_limits(),
    )
  assert engine.handle_client(
      client: client,
      level: engine.Handshake,
      bytes: message(kind: handshake.EncryptedExtensions, body: forbidden),
    )
    |> outcome
    == Error(engine.InvalidConfiguration)
  let assert Ok(accepted) =
    message_body.encode_encrypted_extensions(
      extensions: extensions,
      limits: message_body.default_limits(),
    )
  let assert Ok(engine.Step(client, actions)) =
    engine.handle_client(
      client: client,
      level: engine.Handshake,
      bytes: message(kind: handshake.EncryptedExtensions, body: accepted),
    )
  assert engine.client_phase(client) == engine.AwaitingPeerFlight
  assert !engine.client_resumed(client)
  assert !list.any(actions, fn(action) {
    action == engine.EarlyDataAccepted
    || action == engine.EarlyDataRejected
    || action == engine.DiscardKeys(engine.ZeroRtt)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn crypto_size_limits_reject_before_progress_in_both_initial_directions_test() -> Nil {
  let #(config, server_config) = configs()
  let assert Ok(engine.Step(client, _)) = engine.start_client(config: config)
  let assert Ok(server) = engine.start_server(config: server_config)
  let buffer_size = handshake.default_limits().maximum_buffered_length + 1
  let oversized = <<0:size(buffer_size * 8)>>
  let expected =
    Error(engine.HandshakeFailure(handshake.BufferTooLarge(buffer_size)))
  assert engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: oversized,
    )
    |> outcome
    == expected
  assert engine.handle_server(
      server: server,
      level: engine.Initial,
      bytes: oversized,
    )
    |> outcome
    == expected
  let assert Ok(engine.Step(client, client_actions)) =
    engine.handle_client(client: client, level: engine.Initial, bytes: <<2>>)
  let assert Ok(engine.Step(server, server_actions)) =
    engine.handle_server(server: server, level: engine.Initial, bytes: <<1>>)
  assert list.is_empty(client_actions) && list.is_empty(server_actions)
  let oversized_length = <<1_048_577:size(24)>>
  let expected =
    Error(engine.HandshakeFailure(handshake.MessageTooLarge(1_048_577)))
  assert engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: oversized_length,
    )
    |> outcome
    == expected
  assert engine.handle_server(
      server: server,
      level: engine.Initial,
      bytes: oversized_length,
    )
    |> outcome
    == expected
  assert engine.client_phase(client) == engine.AwaitingPeerHello
  assert engine.server_phase(server) == engine.AwaitingPeerHello
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_rejects_unsolicited_extensions_and_nonempty_session_echo_test() -> Nil {
  let #(config, _) = configs()
  let assert Ok(engine.Step(client, _)) =
    engine.start_client_with_strategy(
      config: config,
      strategy: engine.DeferredKeyShare,
    )
  let assert Ok(selected) =
    extension_value.encode_selected_group(group: extension_value.X25519)
  let extensions = [
    extension.Extension(extension.SupportedVersions, <<3, 4>>),
    extension.Extension(extension.KeyShare, selected),
  ]
  list.each(
    [
      hello.HelloRetryRequest(<<1>>, hello.Aes128GcmSha256, extensions),
      hello.HelloRetryRequest(<<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.Unknown(0x1234), <<>>),
        ..extensions
      ]),
    ],
    fn(retry) {
      let assert Ok(body) =
        hello.encode_server(hello: retry, limits: hello.default_limits())
      assert engine.handle_client(
          client: client,
          level: engine.Initial,
          bytes: message(kind: handshake.ServerHello, body: body),
        )
        |> outcome
        == Error(engine.InvalidHelloRetryRequest)
    },
  )
}

fn selected_psk_server_hello() -> BitArray {
  let assert Ok(pair) = key_exchange.generate_p256()
  let assert Ok(share) =
    extension_value.encode_server_key_share(extension_value.KeyShare(
      extension_value.Secp256r1,
      key_exchange.public_key(pair),
    ))
  let assert Ok(body) =
    hello.encode_server(
      hello: hello.ServerHello(<<0x41:256>>, <<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.SupportedVersions, <<3, 4>>),
        extension.Extension(extension.KeyShare, share),
        extension.Extension(extension.PreSharedKey, <<0:16>>),
      ]),
      limits: hello.default_limits(),
    )
  message(kind: handshake.ServerHello, body: body)
}

fn message(kind kind: handshake.MessageType, body body: BitArray) -> BitArray {
  let assert Ok(bytes) =
    handshake.encode(
      message: handshake.Message(kind, body),
      maximum_message_length: handshake.default_limits().maximum_message_length,
    )
  bytes
}

fn resumed_retry_summary() -> Result(#(Bool, Bool, Bool, Bool), engine.Error) {
  let #(config, _) = configs()
  let ticket = ticket()
  use engine.Step(client, initial) <- result.try(engine.start_client_resuming(
    config: config,
    ticket: ticket,
    now_milliseconds: 1001,
    request_early_data: True,
  ))
  let assert Ok(first) = sent(actions: initial, level: engine.Initial)
  let encoded_retry = retry(group: extension_value.Secp256r1)
  use engine.Step(_, actions) <- result.try(engine.handle_client(
    client: client,
    level: engine.Initial,
    bytes: encoded_retry,
  ))
  let assert Ok(second) = sent(actions: actions, level: engine.Initial)
  let assert Ok(decoded) = client_hello(bytes: second)
  let assert Ok(psk_bytes) =
    extension_bytes(
      extensions: decoded.extensions,
      kind: extension.PreSharedKey,
    )
  let assert Ok(offered) = pre_shared_key.decode_offered(bytes: psk_bytes)
  let assert Ok(truncated) =
    pre_shared_key.binder_transcript(
      encoded_client_hello: second,
      offered: offered,
    )
  let assert Ok(first_hash) = crypto.hash(crypto.Sha256, first)
  let binder_input = <<
    254, 32:size(24), first_hash:bits, encoded_retry:bits, truncated:bits,
  >>
  let binders_valid = case offered.binders {
    [binder] ->
      pre_shared_key.verify_binder(
        algorithm: crypto.Sha256,
        pre_shared_key: ticket.pre_shared_key,
        client_hello_truncated: binder_input,
        received: binder,
        external: False,
      )
      == Ok(True)
    _ -> False
  }
  Ok(#(
    binders_valid,
    !list.any(decoded.extensions, fn(value) {
      value.kind == extension.EarlyData
    }),
    list.count(actions, fn(action) {
      action == engine.DiscardKeys(engine.ZeroRtt)
    })
      == 1,
    list.count(actions, fn(action) { action == engine.EarlyDataRejected }) == 1,
  ))
}

fn ticket() -> session_ticket.ClientTicket {
  let #(_, server) = configs()
  let assert Ok(parameters) =
    transport_parameter.encode_all(
      parameters: server.transport_parameters,
      sent_by: transport_parameter.Server,
    )
  let secret = <<0x72:256>>
  let assert Ok(ticket) =
    session_ticket.issue(
      ticket_key: <<0x61:256>>,
      issued_at_milliseconds: 1000,
      lifetime_seconds: 1,
      resumption_master_secret: secret,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "localhost",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: parameters,
      permit_early_data: True,
    )
  let assert Ok(stored) =
    session_ticket.store(
      new_ticket: ticket,
      received_at_milliseconds: 1000,
      resumption_master_secret: secret,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "localhost",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: parameters,
    )
  stored
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retry_rejects_already_shared_and_unadvertised_groups_test() -> Nil {
  let #(config, _) = configs()
  let assert Ok(engine.Step(client, _)) = engine.start_client(config: config)
  list.each([extension_value.X25519, extension_value.Secp384r1], fn(group) {
    assert engine.handle_client(
        client: client,
        level: engine.Initial,
        bytes: retry(group: group),
      )
      |> outcome
      == Error(engine.InvalidHelloRetryRequest)
  })
  assert engine.client_phase(client) == engine.AwaitingPeerHello
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_second_retry_is_rejected_without_replacing_pending_client_state_test() -> Nil {
  let #(config, _) = configs()
  let assert Ok(engine.Step(client, _)) =
    engine.start_client_with_strategy(
      config: config,
      strategy: engine.DeferredKeyShare,
    )
  let encoded = retry(group: extension_value.X25519)
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(client: client, level: engine.Initial, bytes: encoded)
  assert engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: encoded,
    )
    |> outcome
    == Error(engine.InvalidHelloRetryRequest)
  assert engine.client_phase(client) == engine.AwaitingPeerHello
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn initial_rejections_preserve_a_valid_subsequent_handshake_test() -> Nil {
  let #(client_config, server_config) = configs()
  let assert Ok(server) = engine.start_server(config: server_config)
  let assert Ok(engine.Step(client, actions)) =
    engine.start_client(config: client_config)
  let assert Ok(client_hello) = sent(actions: actions, level: engine.Initial)
  list.each([engine.Handshake, engine.ZeroRtt, engine.OneRtt], fn(level) {
    assert engine.handle_server(
        server: server,
        level: level,
        bytes: client_hello,
      )
      |> outcome
      == Error(engine.UnexpectedEncryptionLevel)
    assert engine.handle_client(client: client, level: level, bytes: <<>>)
      |> outcome
      == Error(engine.UnexpectedEncryptionLevel)
  })
  let malformed = [
    #(<<1:size(1)>>, engine.HandshakeFailure(handshake.NonByteAligned)),
    #(
      <<1, 1_048_577:size(24)>>,
      engine.HandshakeFailure(handshake.MessageTooLarge(1_048_577)),
    ),
    #(<<24, 0:size(24)>>, engine.UnexpectedMessage),
    #(<<client_hello:bits, 0>>, engine.UnexpectedMessage),
  ]
  list.each(malformed, fn(entry) {
    let #(bytes, expected) = entry
    assert engine.handle_server(
        server: server,
        level: engine.Initial,
        bytes: bytes,
      )
      |> outcome
      == Error(expected)
  })
  let assert Ok(engine.Step(server, actions)) =
    engine.handle_server(
      server: server,
      level: engine.Initial,
      bytes: client_hello,
    )
  let assert Ok(server_hello) = sent(actions: actions, level: engine.Initial)
  let assert Ok(server_flight) = sent(actions: actions, level: engine.Handshake)
  let assert Ok(engine.Step(client, _)) =
    engine.handle_client(
      client: client,
      level: engine.Initial,
      bytes: server_hello,
    )
  let assert Ok(engine.Step(client, actions)) =
    engine.handle_client(
      client: client,
      level: engine.Handshake,
      bytes: server_flight,
    )
  let assert Ok(finished) = sent(actions: actions, level: engine.Handshake)
  let assert Ok(engine.Step(server, _)) =
    engine.handle_server(
      server: server,
      level: engine.Handshake,
      bytes: finished,
    )
  assert engine.client_phase(client) == engine.Connected
  assert engine.server_phase(server) == engine.Connected
}

fn retry_summary(
  strategy: engine.KeyShareStrategy,
  group: extension_value.NamedGroup,
) -> Result(
  #(engine.Phase, List(extension_value.NamedGroup), Bool, Bool),
  engine.Error,
) {
  let #(config, _) = configs()
  use engine.Step(client, first_actions) <- result.try(
    engine.start_client_with_strategy(config: config, strategy: strategy),
  )
  let assert Ok(first_bytes) =
    sent(actions: first_actions, level: engine.Initial)
  let assert Ok(first) = client_hello(bytes: first_bytes)
  use engine.Step(client, actions) <- result.try(engine.handle_client(
    client: client,
    level: engine.Initial,
    bytes: retry(group: group),
  ))
  let assert Ok(second_bytes) = sent(actions: actions, level: engine.Initial)
  let assert Ok(second) = client_hello(bytes: second_bytes)
  let assert Ok(share_bytes) =
    extension_bytes(extensions: second.extensions, kind: extension.KeyShare)
  let assert Ok(shares) =
    extension_value.decode_client_key_shares(bytes: share_bytes)
  let sizes_valid =
    list.all(shares, fn(share) {
      case share.group {
        extension_value.X25519 -> bit_array.byte_size(share.key_exchange) == 32
        extension_value.Secp256r1 ->
          bit_array.byte_size(share.key_exchange) == 65
        _ -> False
      }
    })
  Ok(#(
    engine.client_phase(client),
    list.map(shares, fn(share) { share.group }),
    sizes_valid && list.length(actions) == 1,
    first.random == second.random
      && first.legacy_session_id == second.legacy_session_id
      && first.cipher_suites == second.cipher_suites,
  ))
}

fn outcome(value: Result(a, engine.Error)) -> Result(Nil, engine.Error) {
  result.map(value, fn(_) { Nil })
}

fn sent(
  actions actions: List(engine.Action),
  level level: engine.EncryptionLevel,
) -> Result(BitArray, Nil) {
  case
    list.filter_map(actions, fn(action) {
      case action {
        engine.Send(found, bytes) if found == level -> Ok(bytes)
        _ -> Error(Nil)
      }
    })
  {
    [bytes] -> Ok(bytes)
    _ -> Error(Nil)
  }
}

fn extension_bytes(
  extensions extensions: List(extension.Extension),
  kind kind: extension.Kind,
) -> Result(BitArray, Nil) {
  case
    list.filter_map(extensions, fn(value) {
      case value.kind == kind {
        True -> Ok(value.data)
        False -> Error(Nil)
      }
    })
  {
    [bytes] -> Ok(bytes)
    _ -> Error(Nil)
  }
}

// nolint: error_context_lost -- Test setup projects codec errors to a fixed value before any assertion can include handshake data.
fn client_hello(bytes bytes: BitArray) -> Result(hello.ClientHello, Nil) {
  case handshake.decode_next(bytes: bytes, limits: handshake.default_limits()) {
    Ok(handshake.Complete(handshake.Message(handshake.ClientHello, body), <<>>)) ->
      hello.decode_client(body: body, limits: hello.default_limits())
      |> result.map_error(fn(_) { Nil })
    _ -> Error(Nil)
  }
}

fn retry(group group: extension_value.NamedGroup) -> BitArray {
  let assert Ok(selected) = extension_value.encode_selected_group(group: group)
  let assert Ok(version) =
    extension_value.encode_server_supported_version(
      protocol_version: extension_value.Tls13,
    )
  let assert Ok(body) =
    hello.encode_server(
      hello: hello.HelloRetryRequest(<<>>, hello.Aes128GcmSha256, [
        extension.Extension(extension.SupportedVersions, version),
        extension.Extension(extension.KeyShare, selected),
      ]),
      limits: hello.default_limits(),
    )
  let assert Ok(bytes) =
    handshake.encode(
      message: handshake.Message(handshake.ServerHello, body),
      maximum_message_length: handshake.default_limits().maximum_message_length,
    )
  bytes
}

fn configs() -> #(engine.ClientConfig, engine.ServerConfig) {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  #(
    engine.ClientConfig(
      version: version.Version1,
      hostname: "localhost",
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.InitialSourceConnectionId(<<1>>),
        transport_parameter.MaxUdpPayloadSize(1200),
      ],
      trust_store: trust_store,
      client_credential: None,
      retried: False,
      version_negotiated: False,
    ),
    engine.ServerConfig(
      version: version.Version1,
      application_protocols: [<<"h3">>],
      transport_parameters: [
        transport_parameter.OriginalDestinationConnectionId(<<9>>),
        transport_parameter.InitialSourceConnectionId(<<2>>),
        transport_parameter.MaxUdpPayloadSize(1200),
      ],
      certificate_chain: chain,
      signing_key: signing_key,
      signature_scheme: extension_value.Ed25519,
      alternative_credentials: [],
      client_authentication: engine.ClientAuthenticationDisabled,
    ),
  )
}
