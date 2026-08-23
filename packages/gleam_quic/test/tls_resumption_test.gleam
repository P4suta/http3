import gleam/bit_array
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/tls/session_ticket

const ticket_key = <<0x31:256>>

const resumption_master_secret = <<0x42:256>>

const issued_at = 5_000_000

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn selects_authenticated_psk_and_accepts_first_early_use_test() -> Nil {
  let #(offer, encoded, decoded) = client_hello(True)
  let assert Ok(cache) = anti_replay.new(10_000, 16)
  let assert Ok(policy) =
    resumption.server_policy(
      ticket_key:,
      now_milliseconds: issued_at + 100,
      ticket_age_tolerance_milliseconds: 100,
      replay_cache: cache,
    )
  let assert Ok(resumption.Resumed(selection)) =
    resumption.select(
      policy:,
      encoded_client_hello: encoded,
      transcript_prefix: <<>>,
      client_hello: decoded,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<1, 2>>,
    )
  let resumption.Selected(
    identity_index,
    _,
    early_data_offered,
    early_data_accepted,
    replay_cache,
  ) = selection
  assert identity_index == 0
  assert early_data_offered
  assert early_data_accepted
  assert anti_replay.size(replay_cache) == 1
  assert resumption.client_early_data_requested(offer)
  assert resumption.client_cipher_suite(offer) == hello.Aes128GcmSha256
  assert bit_array.byte_size(resumption.client_pre_shared_key(offer)) == 32

  let assert Ok(replay_policy) =
    resumption.server_policy(
      ticket_key:,
      now_milliseconds: issued_at + 101,
      ticket_age_tolerance_milliseconds: 100,
      replay_cache:,
    )
  let assert Ok(resumption.Resumed(replayed)) =
    resumption.select(
      policy: replay_policy,
      encoded_client_hello: encoded,
      transcript_prefix: <<>>,
      client_hello: decoded,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<1, 2>>,
    )
  assert replayed.early_data_offered
  assert !replayed.early_data_accepted

  let assert Ok(fresh_cache) = anti_replay.new(10_000, 16)
  let assert Ok(changed_policy) =
    resumption.server_policy(ticket_key, issued_at + 101, 100, fresh_cache)
  let assert Ok(resumption.Resumed(changed_parameters)) =
    resumption.select(
      policy: changed_policy,
      encoded_client_hello: encoded,
      transcript_prefix: <<>>,
      client_hello: decoded,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<9>>,
    )
  assert changed_parameters.early_data_offered
  assert !changed_parameters.early_data_accepted
  assert anti_replay.size(changed_parameters.replay_cache) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_recognized_ticket_with_invalid_binder_test() -> Nil {
  let #(_, encoded, decoded) = client_hello(True)
  let assert Ok(cache) = anti_replay.new(10_000, 16)
  let assert Ok(policy) =
    resumption.server_policy(ticket_key, issued_at + 100, 100, cache)
  assert resumption.select(
      policy:,
      encoded_client_hello: flip_last(encoded),
      transcript_prefix: <<>>,
      client_hello: decoded,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<1, 2>>,
    )
    == Error(resumption.InvalidBinder)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn ignores_unusable_ticket_and_supports_hrr_transcript_prefix_test() -> Nil {
  let retry_prefix = <<254, 0, 0, 32, 0:256, 2, 0, 0, 0>>
  let #(_, encoded, decoded) = client_hello_with_prefix(False, retry_prefix)
  let assert Ok(cache) = anti_replay.new(10_000, 16)
  let assert Ok(policy) =
    resumption.server_policy(ticket_key, issued_at + 100, 100, cache)
  let assert Ok(resumption.Resumed(selection)) =
    resumption.select(
      policy:,
      encoded_client_hello: encoded,
      transcript_prefix: retry_prefix,
      client_hello: decoded,
      expected_server_name: "example.com",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<1, 2>>,
    )
  assert !selection.early_data_offered
  assert !selection.early_data_accepted

  let assert Ok(resumption.FullHandshake(_)) =
    resumption.select(
      policy:,
      encoded_client_hello: encoded,
      transcript_prefix: retry_prefix,
      client_hello: decoded,
      expected_server_name: "other.example",
      expected_alpn: <<"h3">>,
      expected_quic_version: 1,
      expected_transport_parameters: <<1, 2>>,
    )
  Nil
}

fn client_hello(
  request_early_data: Bool,
) -> #(resumption.ClientOffer, BitArray, hello.ClientHello) {
  client_hello_with_prefix(request_early_data, <<>>)
}

fn client_hello_with_prefix(
  request_early_data: Bool,
  transcript_prefix: BitArray,
) -> #(resumption.ClientOffer, BitArray, hello.ClientHello) {
  let assert Ok(new_ticket) =
    session_ticket.issue(
      ticket_key:,
      issued_at_milliseconds: issued_at,
      lifetime_seconds: 3600,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2>>,
      permit_early_data: True,
    )
  let assert Ok(ticket) =
    session_ticket.store(
      new_ticket:,
      received_at_milliseconds: issued_at,
      resumption_master_secret:,
      algorithm: crypto.Sha256,
      cipher_suite: hello.Aes128GcmSha256,
      server_name: "example.com",
      alpn: <<"h3">>,
      quic_version: 1,
      remembered_transport_parameters: <<1, 2>>,
    )
  let assert Ok(offer) =
    resumption.client_offer(
      ticket:,
      now_milliseconds: issued_at + 100,
      request_early_data:,
    )
  let extensions = [
    extension.Extension(extension.SupportedVersions, <<2, 3, 4>>),
    ..resumption.client_extensions(offer)
  ]
  let placeholder =
    hello.ClientHello(
      random: <<0x77:256>>,
      legacy_session_id: <<>>,
      cipher_suites: [hello.Aes128GcmSha256],
      extensions:,
    )
  let assert Ok(body) = hello.encode_client(placeholder, hello.default_limits())
  let assert Ok(encoded_placeholder) =
    handshake.encode(handshake.Message(handshake.ClientHello, body), 65_535)
  let assert Ok(encoded) =
    resumption.seal_client_hello(
      offer:,
      encoded_placeholder_client_hello: encoded_placeholder,
      transcript_prefix:,
    )
  let assert Ok(decoded) = decode_client_hello(encoded)
  #(offer, encoded, decoded)
}

fn decode_client_hello(encoded: BitArray) -> Result(hello.ClientHello, Nil) {
  case handshake.decode_next(encoded, handshake.default_limits()) {
    Ok(handshake.Complete(handshake.Message(handshake.ClientHello, body), <<>>)) ->
      case hello.decode_client(body, hello.default_limits()) {
        Ok(value) -> Ok(value)
        Error(_) -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

fn flip_last(bytes: BitArray) -> BitArray {
  let prefix_size = { bit_array.byte_size(bytes) - 1 } * 8
  let assert <<prefix:bits-size(prefix_size), last>> = bytes
  let changed = { last + 1 } % 256
  <<prefix:bits, changed>>
}
