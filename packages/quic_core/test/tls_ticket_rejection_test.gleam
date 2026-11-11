import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import quic_core/internal/crypto
import quic_core/internal/tls/extension
import quic_core/internal/tls/hello
import quic_core/internal/tls/message_body
import quic_core/internal/tls/session_ticket

const key = <<0x71:256>>

const now = 1_000_000

const maximum_timestamp = 0x7fff_ffff_ffff_ffff

// These fixtures seal independently encoded claims with a synthetic test key.
// A valid authentication tag alone must never bypass structural validation.
// The fixed nonce is used only with this public, test-only key.
fn seal(plaintext: BitArray, context: BitArray) -> BitArray {
  let nonce = <<0x53:96>>
  let assert Ok(protected) =
    crypto.aes_256_gcm_encrypt(key, nonce, context, plaintext)
  <<2, nonce:bits, protected:bits>>
}

fn seal_ticket(plaintext: BitArray) -> BitArray {
  seal(plaintext, <<"quic_core tls ticket", 2>>)
}

fn seal_export(plaintext: BitArray) -> BitArray {
  seal(plaintext, <<"quic_core client ticket export", 2>>)
}

fn claims_header(
  timestamp: Int,
  lifetime: Int,
  suite: Int,
  flags: Int,
  psk: BitArray,
) -> BitArray {
  <<
    timestamp:size(64),
    lifetime:size(32),
    0xffff_fff0:size(32),
    suite:size(16),
    1:size(32),
    flags,
    { bit_array.byte_size(psk) },
    psk:bits,
  >>
}

fn claims_with_origin(name: BitArray, alpn: BitArray) -> BitArray {
  let header = claims_header(now, 60, 0x1301, 0, <<0x31:256>>)
  <<
    header:bits,
    { bit_array.byte_size(name) }:size(16),
    name:bits,
    { bit_array.byte_size(alpn) },
    alpn:bits,
    0:size(16),
    0:size(16),
  >>
}

fn valid_claims() -> BitArray {
  claims_with_origin(<<"example.test">>, <<"h3">>)
}

fn open_at(ticket: BitArray, time: Int) -> Result(Nil, session_ticket.Error) {
  session_ticket.open(
    ticket_key: key,
    opaque_ticket: ticket,
    now_milliseconds: time,
    expected_server_name: "example.test",
    expected_alpn: <<"h3">>,
    expected_quic_version: 1,
  )
  |> result.map(fn(_) { Nil })
}

fn import_at(
  stored: BitArray,
  monotonic: Int,
  unix: Int,
) -> Result(Nil, session_ticket.Error) {
  session_ticket.import_client(stored, key, monotonic, unix)
  |> result.map(fn(_) { Nil })
}

fn export_plaintext(claims: BitArray) -> BitArray {
  <<
    now:size(64),
    0:size(64),
    1:size(16),
    7,
    { bit_array.byte_size(claims) }:size(32),
    claims:bits,
  >>
}

fn stored_ticket() -> session_ticket.ClientTicket {
  let assert Ok(ticket) =
    session_ticket.store(
      new_ticket: message_body.NewSessionTicket(60, 0, <<1>>, <<7>>, []),
      received_at_milliseconds: now,
      resumption_master_secret: <<0x31:256>>,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.test",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<>>,
    )
  ticket
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_ticket_rejects_every_truncated_claim_prefix_test() -> Nil {
  let plaintext = valid_claims()
  assert open_at(seal_ticket(plaintext), now) == Ok(Nil)
  int.range(0, bit_array.byte_size(plaintext), with: Nil, run: fn(_, length) {
    let assert Ok(prefix) = bit_array.slice(plaintext, 0, length)
    assert open_at(seal_ticket(prefix), now)
      == Error(session_ticket.InvalidTicket)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_ticket_rejects_unknown_flags_suite_and_psk_size_test() -> Nil {
  [
    #(0x1301, 2, <<0x31:256>>),
    #(0x1301, 255, <<0x31:256>>),
    #(0x1300, 0, <<0x31:256>>),
    #(0x1301, 0, <<>>),
    #(0x1302, 0, <<0x31:256>>),
  ]
  |> list.each(fn(fields) {
    let #(suite, flags, psk) = fields
    let header = claims_header(now, 60, suite, flags, psk)
    let plaintext = <<
      header:bits,
      12:size(16),
      "example.test",
      2,
      "h3",
      0:size(16),
      0:size(16),
    >>
    assert open_at(seal_ticket(plaintext), now)
      == Error(session_ticket.InvalidTicket)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_ticket_rejects_invalid_origin_and_trailing_claims_test() -> Nil {
  [
    claims_with_origin(<<>>, <<"h3">>),
    claims_with_origin(<<255>>, <<"h3">>),
    claims_with_origin(<<"example.test">>, <<>>),
    <<{ valid_claims() }:bits, 0>>,
  ]
  |> list.each(fn(plaintext) {
    assert open_at(seal_ticket(plaintext), now)
      == Error(session_ticket.InvalidTicket)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ticket_envelope_rejects_unknown_version_truncation_and_wrong_key_test() -> Nil {
  let valid = seal_ticket(valid_claims())
  let assert <<_, tail:bits>> = valid
  [<<>>, <<2>>, <<2, 0:96>>, <<3, tail:bits>>, <<1:size(1)>>]
  |> list.each(fn(ticket) {
    assert result.is_error(open_at(ticket, now))
  })
  assert session_ticket.open(
      <<0x72:256>>,
      valid,
      now,
      "example.test",
      <<"h3">>,
      1,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidTicket)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn authenticated_ticket_distinguishes_future_expired_and_wrong_alpn_test() -> Nil {
  let ticket = seal_ticket(valid_claims())
  assert open_at(ticket, now - 1) == Error(session_ticket.InvalidTimestamp)
  assert open_at(ticket, now + 60_001) == Error(session_ticket.Expired)
  assert session_ticket.open(key, ticket, now, "example.test", <<"other">>, 1)
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.OriginMismatch)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_export_rejects_every_authenticated_truncated_prefix_test() -> Nil {
  let plaintext = export_plaintext(valid_claims())
  assert import_at(seal_export(plaintext), now, now) == Ok(Nil)
  int.range(0, bit_array.byte_size(plaintext), with: Nil, run: fn(_, length) {
    let assert Ok(prefix) = bit_array.slice(plaintext, 0, length)
    assert import_at(seal_export(prefix), now, now)
      == Error(session_ticket.InvalidTicket)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_export_rejects_empty_identity_and_trailing_authenticated_bytes_test() -> Nil {
  let claims = valid_claims()
  [
    <<
      now:size(64),
      0:size(64),
      0:size(16),
      { bit_array.byte_size(claims) }:size(32),
      claims:bits,
    >>,
    <<{ export_plaintext(claims) }:bits, 0>>,
  ]
  |> list.each(fn(plaintext) {
    assert import_at(seal_export(plaintext), now, now)
      == Error(session_ticket.InvalidTicket)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_export_authentication_is_bound_to_its_distinct_context_test() -> Nil {
  assert import_at(seal_ticket(export_plaintext(valid_claims())), now, now)
    == Error(session_ticket.InvalidTicket)
  assert open_at(seal_export(valid_claims()), now)
    == Error(session_ticket.InvalidTicket)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn restored_ticket_rejects_wall_clock_rollback_and_expiry_test() -> Nil {
  let stored = seal_export(export_plaintext(valid_claims()))
  assert import_at(stored, now, now - 1)
    == Error(session_ticket.InvalidTimestamp)
  assert import_at(stored, -1, now) == Error(session_ticket.InvalidTimestamp)
  assert import_at(stored, now, now + 60_001) == Error(session_ticket.Expired)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ticket_age_wrap_is_validated_with_finite_clock_tolerance_test() -> Nil {
  let assert Ok(claims) =
    session_ticket.open(
      key,
      seal_ticket(valid_claims()),
      now,
      "example.test",
      <<"h3">>,
      1,
    )
  assert session_ticket.ticket_age_is_valid(claims, 16, now + 32, 0)
  assert session_ticket.ticket_age_is_valid(claims, 17, now + 32, 1)
  assert !session_ticket.ticket_age_is_valid(claims, 18, now + 32, 1)
  [#(-1, now, 0), #(0x1_0000_0000, now, 0), #(0, now - 1, 0), #(0, now, -1)]
  |> list.each(fn(values) {
    let #(age, timestamp, tolerance) = values
    assert !session_ticket.ticket_age_is_valid(
      claims,
      age,
      timestamp,
      tolerance,
    )
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn duplicate_or_malformed_early_data_never_enables_resumption_test() -> Nil {
  let valid = extension.Extension(extension.EarlyData, <<0xffff_ffff:size(32)>>)
  [
    [valid, valid],
    [extension.Extension(extension.EarlyData, <<>>)],
    [extension.Extension(extension.EarlyData, <<1:size(1)>>)],
  ]
  |> list.each(fn(extensions) {
    assert session_ticket.store(
        message_body.NewSessionTicket(60, 0, <<1>>, <<7>>, extensions),
        now,
        <<0x31:256>>,
        crypto.Sha256,
        hello.Aes128GcmSha256,
        "example.test",
        <<"h3">>,
        1,
        <<>>,
      )
      |> result.map(fn(_) { Nil })
      == Error(session_ticket.InvalidEarlyData)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_export_rejects_unrepresentable_timestamps_before_encryption_test() -> Nil {
  let ticket = stored_ticket()
  assert session_ticket.export_client(ticket, key, now, maximum_timestamp + 1)
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidTimestamp)
  assert session_ticket.export_client(ticket, key, maximum_timestamp + 1, now)
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidTimestamp)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_export_accepts_the_last_representable_timestamp_test() -> Nil {
  let assert Ok(stored) =
    session_ticket.export_client(stored_ticket(), key, now, maximum_timestamp)
  assert import_at(stored, now, maximum_timestamp) == Ok(Nil)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_import_rejects_unrepresentable_timestamps_test() -> Nil {
  let stored = seal_export(export_plaintext(valid_claims()))
  assert import_at(stored, maximum_timestamp + 1, now)
    == Error(session_ticket.InvalidTimestamp)
  assert import_at(stored, now, maximum_timestamp + 1)
    == Error(session_ticket.InvalidTimestamp)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn every_ticket_cipher_preserves_its_hash_and_origin_binding_test() -> Nil {
  [
    #(hello.Aes128GcmSha256, crypto.Sha256),
    #(hello.Aes256GcmSha384, crypto.Sha384),
    #(hello.Chacha20Poly1305Sha256, crypto.Sha256),
    #(hello.Aes128CcmSha256, crypto.Sha256),
    #(hello.Aes128Ccm8Sha256, crypto.Sha256),
  ]
  |> list.each(fn(algorithms) {
    let #(suite, hash) = algorithms
    let secret = <<0:size(crypto.hash_length(hash))-unit(8)>>
    let assert Ok(new_ticket) =
      session_ticket.issue(
        key,
        now,
        60,
        secret,
        hash,
        suite,
        "example.test",
        <<"h3">>,
        1,
        <<1, 2>>,
        True,
      )
    let message_body.NewSessionTicket(_, _, _, identity, _) = new_ticket
    let assert Ok(claims) =
      session_ticket.open(key, identity, now, "example.test", <<"h3">>, 1)
    assert claims.algorithm == hash
    assert claims.cipher_suite == suite
    assert claims.permit_early_data
    let assert Ok(ticket) =
      session_ticket.store(
        new_ticket,
        now,
        secret,
        hash,
        suite,
        "example.test",
        <<"h3">>,
        1,
        <<1, 2>>,
      )
    let assert Ok(stored) = session_ticket.export_client(ticket, key, now, now)
    let assert Ok(restored) =
      session_ticket.import_client(stored, key, now, now)
    assert restored.algorithm == hash
    assert restored.cipher_suite == suite
    assert session_ticket.early_data_allowed(restored)
    assert session_ticket.is_usable(restored, now, "example.test", <<"h3">>, 1)
  })
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ticket_policy_rejects_invalid_key_timestamp_cipher_and_transport_parameters_test() -> Nil {
  assert session_ticket.issue(
      <<1:size(1)>>,
      now,
      60,
      <<0x31:256>>,
      crypto.Sha256,
      hello.Aes128GcmSha256,
      "example.test",
      <<"h3">>,
      1,
      <<>>,
      False,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.NonByteAligned)
  assert session_ticket.issue(
      <<1>>,
      now,
      60,
      <<0x31:256>>,
      crypto.Sha256,
      hello.Aes128GcmSha256,
      "example.test",
      <<"h3">>,
      1,
      <<>>,
      False,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidKey)
  assert session_ticket.issue(
      key,
      -1,
      60,
      <<0x31:256>>,
      crypto.Sha256,
      hello.Aes128GcmSha256,
      "example.test",
      <<"h3">>,
      1,
      <<>>,
      False,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidTimestamp)
  assert session_ticket.issue(
      key,
      now,
      60,
      <<0x31:256>>,
      crypto.Sha384,
      hello.Aes128GcmSha256,
      "example.test",
      <<"h3">>,
      1,
      <<>>,
      False,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidCipherSuite)
  assert session_ticket.issue(
      key,
      now,
      60,
      <<0x31:256>>,
      crypto.Sha256,
      hello.Aes128GcmSha256,
      "example.test",
      <<"h3">>,
      1,
      <<1:size(1)>>,
      False,
    )
    |> result.map(fn(_) { Nil })
    == Error(session_ticket.InvalidTransportParameters)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ticket_store_rejects_invalid_age_nonce_and_identity_test() -> Nil {
  [
    #(
      message_body.NewSessionTicket(60, -1, <<1>>, <<7>>, []),
      session_ticket.InvalidTicketAge,
    ),
    #(
      message_body.NewSessionTicket(60, 0, <<1:size(1)>>, <<7>>, []),
      session_ticket.NonByteAligned,
    ),
    #(
      message_body.NewSessionTicket(60, 0, <<1>>, <<>>, []),
      session_ticket.InvalidTicket,
    ),
  ]
  |> list.each(fn(rejection) {
    let #(new_ticket, expected) = rejection
    assert session_ticket.store(
        new_ticket,
        now,
        <<0x31:256>>,
        crypto.Sha256,
        hello.Aes128GcmSha256,
        "example.test",
        <<"h3">>,
        1,
        <<>>,
      )
      |> result.map(fn(_) { Nil })
      == Error(expected)
  })
}
