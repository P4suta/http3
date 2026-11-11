import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/result
import gleeunit
import http/bhttp
import http/ohttp

@external(erlang, "http_ohttp_guard_tests", "fixture_request")
fn fixture_request(plaintext: BitArray) -> #(BitArray, ohttp.ClientContext)

pub fn main() -> Nil {
  gleeunit.main()
}

fn hex(value: String) -> BitArray {
  let assert Ok(value) = bit_array.base16_decode(value)
  value
}

fn configuration_wire() -> BitArray {
  hex(
    "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003",
  )
}

fn private_key() -> BitArray {
  hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")
}

fn request_plaintext() -> BitArray {
  hex("00034745540568747470730b6578616d706c652e636f6d012f")
}

fn encapsulated_request() -> BitArray {
  hex(
    "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525",
  )
}

fn expect_encapsulated_request() -> BitArray {
  // A committed test fixture produced from the RFC vector key material before the deterministic production entry points were removed.
  // It contains only a synthetic example.com request and no credential or runtime identifier.
  hex(
    "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726373f36314086b852e166bbdfacfb80074418cc70dac248bbe8dc512b8521fafb5a4f84e0cc74a6f0df5be0c0dc3efb39f41c9fe1a499d237f8897a8368bbf615f07966e371146e8c063139118471f63e03f6c4956",
  )
}

fn response_plaintext() -> BitArray {
  hex("0140c8")
}

fn encapsulated_response() -> BitArray {
  hex("c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd")
}

fn config() -> ohttp.KeyConfiguration {
  let assert Ok(value) = ohttp.decode_key_configuration(configuration_wire())
  value
}

fn key() -> ohttp.GatewayKey {
  let assert Ok(value) =
    ohttp.gateway_key(key_id: 1, private_key: private_key(), algorithms: [
      ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 1),
      ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 3),
    ])
  value
}

fn error_code(error: ohttp.Error) -> Int {
  case error {
    ohttp.InvalidConfiguration -> 101
    ohttp.InvalidMessage -> 102
    ohttp.InvalidMediaType -> 103
    ohttp.InvalidRelay -> 104
    ohttp.InvalidKey -> 105
    ohttp.UnsupportedAlgorithm -> 106
    ohttp.NonByteAligned -> 107
    ohttp.LimitExceeded -> 108
    ohttp.ReplayDetected -> 109
    ohttp.ReplayCapacityExceeded -> 110
    ohttp.ReplayStoreUnavailable -> 111
    ohttp.ContextReuseDetected -> 112
    ohttp.ContinueExpectationForbidden -> 113
    ohttp.TargetNotAllowed -> 114
    ohttp.DecryptionFailed -> 115
    ohttp.CryptoFailure -> 116
  }
}

fn outcome_code(outcome: Result(value, ohttp.Error)) -> Int {
  case outcome {
    Ok(_) -> 1
    Error(error) -> error_code(error)
  }
}

fn bytes_result_matches(
  outcome: Result(BitArray, ohttp.Error),
  expected: BitArray,
) -> Bool {
  result.map(outcome, fn(actual) { actual == expected }) |> result.unwrap(False)
}

fn opened_bytes_match(
  outcome: Result(
    #(BitArray, ohttp.GatewayContext, ohttp.ReplayStore),
    ohttp.Error,
  ),
  expected: BitArray,
) -> Bool {
  result.map(outcome, fn(successful_value) {
    let #(actual, _, _) = successful_value
    actual == expected
  })
  |> result.unwrap(False)
}

fn response_status(outcome: Result(bhttp.Message, ohttp.Error)) -> Int {
  case outcome {
    Ok(bhttp.Response([], status, [], [], [], 0)) -> status
    Ok(bhttp.Response(..)) -> 2
    Ok(bhttp.Request(..)) -> 1
    Error(error) -> error_code(error)
  }
}

fn rejection_code(failure: ohttp.ProtectedRequestFailure) -> Int {
  case failure {
    ohttp.MalformedRequest -> 400
    ohttp.ContinueExpectationRejected -> 417
    ohttp.TargetRejected -> 403
  }
}

fn rejected_request(
  outcome: Result(#(ohttp.GatewayOpen(value), ohttp.ReplayStore), ohttp.Error),
) -> Result(
  #(ohttp.ProtectedRequestFailure, ohttp.GatewayContext, ohttp.ReplayStore),
  Nil,
) {
  case outcome {
    Ok(#(ohttp.GatewayRejected(failure, context), replays)) ->
      Ok(#(failure, context, replays))
    Ok(#(ohttp.GatewayOpened(_, _), _)) | Error(_) -> Error(Nil)
  }
}

fn protected_admission(
  outcome: Result(#(ohttp.GatewayAdmission, ohttp.ReplayStore), ohttp.Error),
) -> Result(#(BitArray, ohttp.ReplayStore), Nil) {
  case outcome {
    Ok(#(ohttp.ProtectedResponse(response), replays)) ->
      Ok(#(response, replays))
    Ok(#(ohttp.ForwardRequest(_, _), _)) | Error(_) -> Error(Nil)
  }
}

fn flip_last_byte(bytes: BitArray) -> Result(BitArray, Nil) {
  let size = bit_array.byte_size(bytes)
  case size > 0 {
    False -> Error(Nil)
    True -> {
      let prefix_size = size - 1
      case bytes {
        <<prefix:bytes-size(prefix_size), byte>> ->
          Ok(<<prefix:bits, int.bitwise_exclusive_or(byte, 1)>>)
        _ -> Error(Nil)
      }
    }
  }
}

pub fn rfc9458_key_configuration_vector_and_strict_collection_test() -> Nil {
  let expected =
    ohttp.KeyConfiguration(
      key_id: 1,
      kem_id: 0x0020,
      public_key: hex(
        "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155",
      ),
      algorithms: [
        ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 1),
        ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 3),
      ],
    )
  let decoded_matches =
    result.map(ohttp.decode_key_configuration(configuration_wire()), fn(actual) {
      actual == expected
    })
    |> result.unwrap(False)
  let encoded_matches =
    bytes_result_matches(
      ohttp.encode_key_configuration(expected),
      configuration_wire(),
    )
  assert decoded_matches
  assert encoded_matches

  let collection = <<0, 45, configuration_wire():bits>>
  let collection_decodes =
    result.map(
      ohttp.decode_key_configurations(collection, maximum_configurations: 4),
      fn(actual) { actual == [expected] },
    )
    |> result.unwrap(False)
  let collection_encodes =
    bytes_result_matches(
      ohttp.encode_key_configurations([expected]),
      collection,
    )
  assert collection_decodes
  assert collection_encodes
  assert outcome_code(ohttp.decode_key_configurations(
      <<collection:bits, 0>>,
      maximum_configurations: 4,
    ))
    == error_code(ohttp.InvalidConfiguration)
}

pub fn rfc9458_request_and_response_crypto_vectors_test() -> Nil {
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  assert opened_bytes_match(
    ohttp.open_request_bytes(gateway, replays, encapsulated_request()),
    request_plaintext(),
  )
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      replays,
      encapsulated_request(),
    ))
    == error_code(ohttp.ReplayDetected)

  // The deterministic sender is confined to the test tree.
  // Its context opens the RFC's fixed response, preventing matching response-KDF defects in the production sealer and opener from validating one another.
  let #(fixed_sealed, fixed_client_context) =
    fixture_request(request_plaintext())
  let fixed_request_matches = fixed_sealed == encapsulated_request()
  assert fixed_request_matches
  assert response_status(ohttp.open_response(
      fixed_client_context,
      encapsulated_response(),
    ))
    == 200

  // The production client has no deterministic key path.
  // Its fresh request context still completes a full request/response round trip against the same gateway key used by the fixed RFC request vector.
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(sealed, client_context)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let assert Ok(roundtrip_replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, gateway_context, _)) =
    ohttp.open_request_bytes(gateway, roundtrip_replays, sealed)
  assert outcome_code(ohttp.seal_response_bytes(
      gateway_context,
      request_plaintext(),
    ))
    == error_code(ohttp.InvalidMessage)
  let assert Ok(response) =
    ohttp.seal_response_bytes(gateway_context, response_plaintext())
  assert outcome_code(ohttp.open_response_bytes(client_context, <<>>))
    == error_code(ohttp.InvalidMessage)
  assert bytes_result_matches(
    ohttp.open_response_bytes(client_context, response),
    response_plaintext(),
  )
  assert outcome_code(ohttp.seal_response_bytes(
      gateway_context,
      response_plaintext(),
    ))
    == error_code(ohttp.ContextReuseDetected)
  assert outcome_code(ohttp.open_response_bytes(client_context, response))
    == error_code(ohttp.ContextReuseDetected)
}

pub fn rfc9458_gateway_response_context_is_claimed_once_across_callers_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, gateway_context, _)) =
    ohttp.open_request_bytes(gateway, replays, sealed)
  let outcomes = process.new_subject()
  spawn_response_sealers(
    outcomes: outcomes,
    context: gateway_context,
    remaining: 32,
  )
  let assert Ok(#(sealed_count, reused_count, other_count)) =
    receive_outcomes(
      outcomes: outcomes,
      remaining: 32,
      succeeded: 0,
      rejected: 0,
      other: 0,
    )
  assert sealed_count == 1
  assert reused_count == 31
  assert other_count == 0
}

pub fn rfc9458_client_response_context_is_claimed_once_across_callers_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(sealed, client_context)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, gateway_context, _)) =
    ohttp.open_request_bytes(gateway, replays, sealed)
  let assert Ok(response) =
    ohttp.seal_response_bytes(gateway_context, response_plaintext())
  let outcomes = process.new_subject()
  spawn_response_openers(
    outcomes: outcomes,
    context: client_context,
    response: response,
    remaining: 32,
  )
  let assert Ok(#(opened_count, reused_count, other_count)) =
    receive_outcomes(
      outcomes: outcomes,
      remaining: 32,
      succeeded: 0,
      rejected: 0,
      other: 0,
    )
  assert opened_count == 1
  assert reused_count == 31
  assert other_count == 0
}

pub fn rfc9458_production_client_uses_fresh_request_contexts_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(first, _)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let assert Ok(#(second, _)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let repeated = first == second
  assert repeated == False

  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, _, replays)) =
    ohttp.open_request_bytes(gateway, replays, first)
  let assert Ok(#(_, _, _)) = ohttp.open_request_bytes(gateway, replays, second)
  Nil
}

pub fn rfc9458_failed_response_authentication_consumes_context_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(sealed, client_context)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, gateway_context, _)) =
    ohttp.open_request_bytes(gateway, replays, sealed)
  let assert Ok(response) =
    ohttp.seal_response_bytes(gateway_context, response_plaintext())
  let assert Ok(tampered) = flip_last_byte(response)
  assert outcome_code(ohttp.open_response_bytes(client_context, tampered))
    == error_code(ohttp.DecryptionFailed)
  assert outcome_code(ohttp.open_response_bytes(client_context, response))
    == error_code(ohttp.ContextReuseDetected)
}

pub fn rfc9458_expect_100_continue_is_rejected_at_both_boundaries_test() -> Nil {
  let request =
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [bhttp.Field("expect", <<"extension, 100-Continue":utf8>>)],
      [<<1, 2, 3>>],
      [],
      0,
    )
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  assert outcome_code(ohttp.seal_request(client, request, bhttp.KnownLength))
    == error_code(ohttp.ContinueExpectationForbidden)

  let assert Ok(encoded) =
    bhttp.encode(request, bhttp.KnownLength, bhttp.defaults())
  assert outcome_code(ohttp.seal_request_bytes(client, encoded))
    == error_code(ohttp.ContinueExpectationForbidden)
}

pub fn rfc9110_expect_bare_obs_text_fails_closed_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  // Bare obs-text is not RFC 9110 expectation grammar and fails closed before request encryption.
  let obs_text_request =
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [
        bhttp.Field("expect", <<
          "extension,":utf8,
          255,
          ",\t100-ConTinue":utf8,
        >>),
      ],
      [<<1>>],
      [],
      0,
    )
  let assert Ok(obs_text_encoded) =
    bhttp.encode(obs_text_request, bhttp.KnownLength, bhttp.defaults())
  assert outcome_code(ohttp.seal_request(
      client,
      obs_text_request,
      bhttp.KnownLength,
    ))
    == error_code(ohttp.InvalidMessage)
  assert outcome_code(ohttp.seal_request_bytes(client, obs_text_encoded))
    == error_code(ohttp.InvalidMessage)
}

pub fn rfc9458_expect_rejection_keeps_client_reusable_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  // Policy rejection leaves the reusable production client healthy.
  let assert Ok(#(_, _)) = ohttp.seal_request_bytes(client, request_plaintext())
  Nil
}

pub fn rfc9458_gateway_expect_rejection_commits_replay_test() -> Nil {
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      replays,
      expect_encapsulated_request(),
    ))
    == error_code(ohttp.ContinueExpectationForbidden)
  assert outcome_code(ohttp.open_request(
      gateway,
      replays,
      expect_encapsulated_request(),
    ))
    == error_code(ohttp.ReplayDetected)
}

pub fn rfc9110_expect_extension_token_is_not_continue_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  // Substrings are extension tokens, not the reserved 100-continue member.
  let extension_request =
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [bhttp.Field("expect", <<"x100-continue":utf8>>)],
      [<<1>>],
      [],
      0,
    )
  let assert Ok(#(extension_sealed, _)) =
    ohttp.seal_request(client, extension_request, bhttp.KnownLength)
  let assert Ok(extension_replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(_, _, _)) =
    ohttp.open_request(gateway, extension_replays, extension_sealed)
  Nil
}

pub fn rfc9110_expect_grammar_handles_values_parameters_and_quoted_commas_test() -> Nil {
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let request = fn(value) {
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [bhttp.Field("expect", value)],
      [],
      [],
      0,
    )
  }

  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"100-continue=token":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.ContinueExpectationForbidden)
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"100-ConTinue=\"a,b\"; mode=fast":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.ContinueExpectationForbidden)
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"100-continue; malformed=parameter":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.ContinueExpectationForbidden)
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"extension=\"a,100-continue,b\"":utf8>>),
      bhttp.KnownLength,
    ))
    == 1
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"extension=token ; ; mode=\"a,b\", other":utf8>>),
      bhttp.KnownLength,
    ))
    == 1
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"extension; malformed":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.InvalidMessage)
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"extension =token":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.InvalidMessage)
  assert outcome_code(ohttp.seal_request(
      client,
      request(<<"extension=token; mode =fast":utf8>>),
      bhttp.KnownLength,
    ))
    == error_code(ohttp.InvalidMessage)
}

pub fn rfc9458_post_decryption_failures_keep_context_and_are_protected_test() -> Nil {
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )

  let #(malformed_wire, malformed_client_context) = fixture_request(<<255>>)
  let assert Ok(malformed_replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(malformed, malformed_context, malformed_replays)) =
    rejected_request(ohttp.open_request_detailed(
      gateway,
      malformed_replays,
      malformed_wire,
    ))
  assert rejection_code(malformed) == 400
  let assert Ok(protected_malformed) =
    ohttp.seal_protected_failure(malformed, malformed_context)
  assert response_status(ohttp.open_response(
      malformed_client_context,
      protected_malformed,
    ))
    == 400
  assert outcome_code(ohttp.open_request(
      gateway,
      malformed_replays,
      malformed_wire,
    ))
    == error_code(ohttp.ReplayDetected)
  let #(_, malformed_admission_context) = fixture_request(<<255>>)
  let assert Ok(malformed_admission_replays) =
    ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(malformed_response, _)) =
    protected_admission(ohttp.admit_request(
      gateway,
      malformed_admission_replays,
      malformed_wire,
    ))
  assert response_status(ohttp.open_response(
      malformed_admission_context,
      malformed_response,
    ))
    == 400

  let expect_request =
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [bhttp.Field("expect", <<"100-continue=ready":utf8>>)],
      [],
      [],
      0,
    )
  let assert Ok(expect_plaintext) =
    bhttp.encode(expect_request, bhttp.KnownLength, bhttp.defaults())
  let #(expect_wire, expect_client_context) = fixture_request(expect_plaintext)
  let assert Ok(expect_replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(expect_failure, expect_context, _)) =
    rejected_request(ohttp.open_request_bytes_detailed(
      gateway,
      expect_replays,
      expect_wire,
    ))
  assert rejection_code(expect_failure) == 417
  let assert Ok(protected_expect) =
    ohttp.seal_protected_failure(expect_failure, expect_context)
  assert response_status(ohttp.open_response(
      expect_client_context,
      protected_expect,
    ))
    == 417
  let #(_, expect_admission_context) = fixture_request(expect_plaintext)
  let assert Ok(expect_admission_replays) =
    ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(expect_response, _)) =
    protected_admission(ohttp.admit_request(
      gateway,
      expect_admission_replays,
      expect_wire,
    ))
  assert response_status(ohttp.open_response(
      expect_admission_context,
      expect_response,
    ))
    == 417

  let disallowed =
    bhttp.Request("GET", "https", "tracker.example", "/", [], [], [], 0)
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(disallowed_wire, disallowed_context)) =
    ohttp.seal_request(client, disallowed, bhttp.KnownLength)
  let assert Ok(disallowed_replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(protected_denial, _)) =
    protected_admission(ohttp.admit_request(
      gateway,
      disallowed_replays,
      disallowed_wire,
    ))
  assert response_status(ohttp.open_response(
      disallowed_context,
      protected_denial,
    ))
    == 403
}

pub fn replay_identity_is_enc_and_shared_store_serializes_32_callers_test() -> Nil {
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )

  let assert Ok(identity_replays) = ohttp.replay_store(maximum_entries: 8)
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      identity_replays,
      encapsulated_request(),
    ))
    == 1
  let assert Ok(same_enc_different_ciphertext) =
    flip_last_byte(encapsulated_request())
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      identity_replays,
      same_enc_different_ciphertext,
    ))
    == error_code(ohttp.ReplayDetected)

  let assert Ok(abort_replays) = ohttp.replay_store(maximum_entries: 1)
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      abort_replays,
      same_enc_different_ciphertext,
    ))
    == error_code(ohttp.DecryptionFailed)
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      abort_replays,
      encapsulated_request(),
    ))
    == 1

  let assert Ok(concurrent_replays) = ohttp.replay_store(maximum_entries: 8)
  let outcomes = process.new_subject()
  spawn_request_openers(
    outcomes: outcomes,
    gateway: gateway,
    replays: concurrent_replays,
    request: encapsulated_request(),
    remaining: 32,
  )
  let assert Ok(#(opened_count, replayed_count, other_count)) =
    receive_outcomes(
      outcomes: outcomes,
      remaining: 32,
      succeeded: 0,
      rejected: 0,
      other: 0,
    )
  assert opened_count == 1
  assert replayed_count == 31
  assert other_count == 0
}

pub fn rfc9180_low_order_x25519_inputs_abort_before_key_schedule_test() -> Nil {
  let zero = <<0:size(256)>>
  let nonzero_low_order = <<1, 0:size(248)>>
  let configuration =
    ohttp.KeyConfiguration(
      key_id: 1,
      kem_id: 0x0020,
      public_key: zero,
      algorithms: [ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 1)],
    )
  let assert Ok(client) = ohttp.client(configuration, bhttp.defaults(), 4096)
  assert outcome_code(ohttp.seal_request_bytes(client, request_plaintext()))
    == error_code(ohttp.CryptoFailure)

  let nonzero_configuration =
    ohttp.KeyConfiguration(
      key_id: 1,
      kem_id: 0x0020,
      public_key: nonzero_low_order,
      algorithms: [ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 1)],
    )
  let assert Ok(nonzero_client) =
    ohttp.client(nonzero_configuration, bhttp.defaults(), 4096)
  assert outcome_code(ohttp.seal_request_bytes(
      nonzero_client,
      request_plaintext(),
    ))
    == error_code(ohttp.CryptoFailure)

  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let zero_encapsulation = <<
    1,
    0x0020:size(16),
    1:size(16),
    1:size(16),
    zero:bits,
    0:size(128),
  >>
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      replays,
      zero_encapsulation,
    ))
    == error_code(ohttp.CryptoFailure)

  let nonzero_encapsulation = <<
    1,
    0x0020:size(16),
    1:size(16),
    1:size(16),
    nonzero_low_order:bits,
    0:size(128),
  >>
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      replays,
      nonzero_encapsulation,
    ))
    == error_code(ohttp.CryptoFailure)
  assert outcome_code(ohttp.open_request_bytes(
      gateway,
      replays,
      nonzero_encapsulation,
    ))
    == error_code(ohttp.CryptoFailure)
}

pub fn rfc9180_unsupported_kem_kdf_and_aead_are_rejected_independently_test() -> Nil {
  let ohttp.KeyConfiguration(key_id, _, public_key, _) = config()
  let unsupported_kem =
    ohttp.KeyConfiguration(key_id, 0x0021, public_key, [
      ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 1),
    ])
  let unsupported_kdf =
    ohttp.KeyConfiguration(key_id, 0x0020, public_key, [
      ohttp.SymmetricAlgorithm(kdf_id: 2, aead_id: 1),
    ])
  let unsupported_aead =
    ohttp.KeyConfiguration(key_id, 0x0020, public_key, [
      ohttp.SymmetricAlgorithm(kdf_id: 1, aead_id: 2),
    ])
  assert outcome_code(ohttp.client(unsupported_kem, bhttp.defaults(), 4096))
    == error_code(ohttp.InvalidConfiguration)
  assert outcome_code(ohttp.client(unsupported_kdf, bhttp.defaults(), 4096))
    == error_code(ohttp.UnsupportedAlgorithm)
  assert outcome_code(ohttp.client(unsupported_aead, bhttp.defaults(), 4096))
    == error_code(ohttp.UnsupportedAlgorithm)

  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(request_key_id, payload)) =
    split_request_header(encapsulated_request())
  let wrong_kem = <<
    request_key_id,
    0x0021:size(16),
    1:size(16),
    1:size(16),
    payload:bits,
  >>
  let wrong_kdf = <<
    request_key_id,
    0x0020:size(16),
    2:size(16),
    1:size(16),
    payload:bits,
  >>
  let wrong_aead = <<
    request_key_id,
    0x0020:size(16),
    1:size(16),
    2:size(16),
    payload:bits,
  >>
  assert outcome_code(ohttp.open_request_bytes(gateway, replays, wrong_kem))
    == error_code(ohttp.InvalidKey)
  assert outcome_code(ohttp.open_request_bytes(gateway, replays, wrong_kdf))
    == error_code(ohttp.InvalidKey)
  assert outcome_code(ohttp.open_request_bytes(gateway, replays, wrong_aead))
    == error_code(ohttp.InvalidKey)
}

fn response_seal_outcome(outcome: Result(BitArray, ohttp.Error)) -> Int {
  case result.is_ok(outcome), outcome == Error(ohttp.ContextReuseDetected) {
    True, _ -> 1
    False, True -> 2
    False, False -> 3
  }
}

fn response_open_outcome(outcome: Result(BitArray, ohttp.Error)) -> Int {
  case result.is_ok(outcome), outcome == Error(ohttp.ContextReuseDetected) {
    True, _ -> 1
    False, True -> 2
    False, False -> 3
  }
}

fn request_open_outcome(
  outcome: Result(
    #(BitArray, ohttp.GatewayContext, ohttp.ReplayStore),
    ohttp.Error,
  ),
) -> Int {
  case result.is_ok(outcome), outcome == Error(ohttp.ReplayDetected) {
    True, _ -> 1
    False, True -> 2
    False, False -> 3
  }
}

fn spawn_response_sealers(
  outcomes outcomes: process.Subject(Int),
  context context: ohttp.GatewayContext,
  remaining remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      process.spawn_unlinked(fn() {
        process.send(
          outcomes,
          response_seal_outcome(ohttp.seal_response_bytes(
            context,
            response_plaintext(),
          )),
        )
      })
      spawn_response_sealers(
        outcomes: outcomes,
        context: context,
        remaining: remaining - 1,
      )
    }
  }
}

fn spawn_response_openers(
  outcomes outcomes: process.Subject(Int),
  context context: ohttp.ClientContext,
  response response: BitArray,
  remaining remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      process.spawn_unlinked(fn() {
        process.send(
          outcomes,
          response_open_outcome(ohttp.open_response_bytes(context, response)),
        )
      })
      spawn_response_openers(
        outcomes: outcomes,
        context: context,
        response: response,
        remaining: remaining - 1,
      )
    }
  }
}

fn spawn_request_openers(
  outcomes outcomes: process.Subject(Int),
  gateway gateway: ohttp.Gateway,
  replays replays: ohttp.ReplayStore,
  request request: BitArray,
  remaining remaining: Int,
) -> Nil {
  case remaining {
    0 -> Nil
    _ -> {
      process.spawn_unlinked(fn() {
        process.send(
          outcomes,
          request_open_outcome(ohttp.open_request_bytes(
            gateway,
            replays,
            request,
          )),
        )
      })
      spawn_request_openers(
        outcomes: outcomes,
        gateway: gateway,
        replays: replays,
        request: request,
        remaining: remaining - 1,
      )
    }
  }
}

fn receive_outcomes(
  outcomes outcomes: process.Subject(Int),
  remaining remaining: Int,
  succeeded succeeded: Int,
  rejected rejected: Int,
  other other: Int,
) -> Result(#(Int, Int, Int), Nil) {
  case remaining {
    0 -> Ok(#(succeeded, rejected, other))
    _ ->
      case process.receive(outcomes, within: 5000) {
        Ok(1) ->
          receive_outcomes(
            outcomes: outcomes,
            remaining: remaining - 1,
            succeeded: succeeded + 1,
            rejected: rejected,
            other: other,
          )
        Ok(2) ->
          receive_outcomes(
            outcomes: outcomes,
            remaining: remaining - 1,
            succeeded: succeeded,
            rejected: rejected + 1,
            other: other,
          )
        Ok(_) ->
          receive_outcomes(
            outcomes: outcomes,
            remaining: remaining - 1,
            succeeded: succeeded,
            rejected: rejected,
            other: other + 1,
          )
        Error(_) -> Error(Nil)
      }
  }
}

fn split_request_header(bytes: BitArray) -> Result(#(Int, BitArray), Nil) {
  case bytes {
    <<key_id, _:size(16), _:size(16), _:size(16), payload:bits>> ->
      Ok(#(key_id, payload))
    _ -> Error(Nil)
  }
}

pub fn bhttp_padding_tamper_and_target_policy_fail_closed_test() -> Nil {
  let padded =
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [],
      [<<1, 2>>],
      [],
      64,
    )
  let assert Ok(client) = ohttp.client(config(), bhttp.defaults(), 4096)
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, padded, bhttp.KnownLength)
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(opened, _, _)) = ohttp.open_request(gateway, replays, sealed)
  let opened_matches = opened == padded
  assert opened_matches

  let assert Ok(tampered) = flip_last_byte(sealed)
  let assert Ok(fresh_replays) = ohttp.replay_store(maximum_entries: 8)
  assert outcome_code(ohttp.open_request(gateway, fresh_replays, tampered))
    == error_code(ohttp.DecryptionFailed)

  let disallowed =
    bhttp.Request("GET", "https", "tracker.example", "/", [], [], [], 0)
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, disallowed, bhttp.KnownLength)
  assert outcome_code(ohttp.open_request_bytes(gateway, fresh_replays, sealed))
    == error_code(ohttp.TargetNotAllowed)
  assert outcome_code(ohttp.open_request(gateway, fresh_replays, sealed))
    == error_code(ohttp.ReplayDetected)

  let insecure = bhttp.Request("GET", "http", "example.com", "/", [], [], [], 0)
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, insecure, bhttp.KnownLength)
  assert outcome_code(ohttp.open_request_bytes(gateway, fresh_replays, sealed))
    == error_code(ohttp.TargetNotAllowed)
}

pub fn relay_forwards_only_ohttp_content_and_fixed_gateway_identity_test() -> Nil {
  let assert Ok(relay) =
    ohttp.relay("https://gateway.example/ohttp", maximum_message_bytes: 4096)
  let forward_matches =
    result.map(
      ohttp.forward_request(
        relay,
        content_type: "message/ohttp-req",
        body: encapsulated_request(),
      ),
      fn(successful_value) {
        let ohttp.RelayForward(uri, content_type, body) = successful_value
        uri == "https://gateway.example/ohttp"
        && content_type == "message/ohttp-req"
        && body == encapsulated_request()
      },
    )
    |> result.unwrap(False)
  assert forward_matches
  assert outcome_code(ohttp.forward_request(
      relay,
      content_type: "application/octet-stream",
      body: encapsulated_request(),
    ))
    == error_code(ohttp.InvalidMediaType)
  assert bytes_result_matches(
    ohttp.forward_response(
      content_type: "message/ohttp-res",
      body: encapsulated_response(),
      maximum_message_bytes: 4096,
    ),
    encapsulated_response(),
  )
}

pub fn a_hundred_continue_expectation_is_refused_in_both_directions_test() -> Nil {
  // RFC 9458 section 5.1: an encapsulated exchange has no way to carry the interim response a 100-continue expectation asks for, so a client does not construct one and a gateway that is handed one answers with an error.
  let expecting = fn(value: String) {
    bhttp.Request(
      "POST",
      "https",
      "example.com",
      "/submit",
      [bhttp.Field("expect", bit_array.from_string(value))],
      [<<1, 2>>],
      [],
      0,
    )
  }
  let assert Ok(client) =
    ohttp.client(config(), bhttp.defaults(), maximum_message_bytes: 4096)
  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )

  // The client refuses to build one, whatever case or parameters it carries.
  assert ohttp.seal_request(
      client,
      expecting("100-continue"),
      bhttp.KnownLength,
    )
    == Error(ohttp.ContinueExpectationForbidden)
  assert ohttp.seal_request(
      client,
      expecting("100-CONTINUE"),
      bhttp.KnownLength,
    )
    == Error(ohttp.ContinueExpectationForbidden)
  assert ohttp.seal_request(
      client,
      expecting("other, 100-continue;q=1"),
      bhttp.KnownLength,
    )
    == Error(ohttp.ContinueExpectationForbidden)

  // An expectation that merely contains the token is a different expectation and is carried through, so the refusal is on the token and not the text.
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, expecting("not-100-continue"), bhttp.KnownLength)
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(opened, _, _)) = ohttp.open_request(gateway, replays, sealed)
  assert opened == expecting("not-100-continue")

  // A peer that ignores the rule still gets an error from the gateway rather than a forwarded request, so the refusal does not depend on the sender.
  let assert Ok(smuggled) =
    bhttp.encode(expecting("100-continue"), bhttp.KnownLength, bhttp.defaults())
  let #(sealed, _) = fixture_request(smuggled)
  let assert Ok(fresh) = ohttp.replay_store(maximum_entries: 8)
  assert ohttp.open_request(gateway, fresh, sealed)
    == Error(ohttp.ContinueExpectationForbidden)
}
