import gleam/bit_array
import gleam/int
import gleeunit
import http/bhttp
import http/ohttp

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

fn ephemeral_key() -> BitArray {
  hex("bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73")
}

fn request_plaintext() -> BitArray {
  hex("00034745540568747470730b6578616d706c652e636f6d012f")
}

fn encapsulated_request() -> BitArray {
  hex(
    "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525",
  )
}

fn response_nonce() -> BitArray {
  hex("c789e7151fcba46158ca84b04464910d")
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
  assert ohttp.decode_key_configuration(configuration_wire()) == Ok(expected)
  assert ohttp.encode_key_configuration(expected) == Ok(configuration_wire())

  let collection = <<0, 45, configuration_wire():bits>>
  assert ohttp.decode_key_configurations(collection, maximum_configurations: 4)
    == Ok([expected])
  assert ohttp.encode_key_configurations([expected]) == Ok(collection)
  assert ohttp.decode_key_configurations(
      <<collection:bits, 0>>,
      maximum_configurations: 4,
    )
    == Error(ohttp.InvalidConfiguration)
}

pub fn rfc9458_request_and_response_crypto_vectors_test() -> Nil {
  let assert Ok(client) =
    ohttp.deterministic_client(
      config(),
      ephemeral_key(),
      bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(#(sealed, client_context)) =
    ohttp.seal_request_bytes(client, request_plaintext())
  assert sealed == encapsulated_request()

  let assert Ok(gateway) =
    ohttp.gateway(
      key(),
      allowed_authorities: ["example.com"],
      bhttp_limits: bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(opened, gateway_context, replays)) =
    ohttp.open_request_bytes(gateway, replays, sealed)
  assert opened == request_plaintext()

  let assert Ok(response) =
    ohttp.seal_response_bytes_with_nonce(
      gateway_context,
      hex("0140c8"),
      response_nonce(),
    )
  assert response == encapsulated_response()
  assert ohttp.open_response_bytes(client_context, response)
    == Ok(hex("0140c8"))

  assert ohttp.open_request_bytes(gateway, replays, sealed)
    == Error(ohttp.ReplayDetected)
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
  let assert Ok(client) =
    ohttp.deterministic_client(
      config(),
      ephemeral_key(),
      bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
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
  assert opened == padded

  let assert <<prefix:bytes-size(20), byte, suffix:bits>> = sealed
  let tampered = <<prefix:bits, int.bitwise_exclusive_or(byte, 1), suffix:bits>>
  let assert Ok(fresh_replays) = ohttp.replay_store(maximum_entries: 8)
  assert ohttp.open_request(gateway, fresh_replays, tampered)
    == Error(ohttp.DecryptionFailed)

  let disallowed =
    bhttp.Request("GET", "https", "tracker.example", "/", [], [], [], 0)
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, disallowed, bhttp.KnownLength)
  assert ohttp.open_request(gateway, fresh_replays, sealed)
    == Error(ohttp.TargetNotAllowed)
}

pub fn relay_forwards_only_ohttp_content_and_fixed_gateway_identity_test() -> Nil {
  let assert Ok(relay) =
    ohttp.relay("https://gateway.example/ohttp", maximum_message_bytes: 4096)
  assert ohttp.forward_request(
      relay,
      content_type: "message/ohttp-req",
      body: encapsulated_request(),
    )
    == Ok(ohttp.RelayForward(
      gateway_uri: "https://gateway.example/ohttp",
      content_type: "message/ohttp-req",
      body: encapsulated_request(),
    ))
  assert ohttp.forward_request(
      relay,
      content_type: "application/octet-stream",
      body: encapsulated_request(),
    )
    == Error(ohttp.InvalidMediaType)
  assert ohttp.forward_response(
      content_type: "message/ohttp-res",
      body: encapsulated_response(),
      maximum_message_bytes: 4096,
    )
    == Ok(encapsulated_response())
}

pub fn a_hundred_continue_expectation_is_refused_in_both_directions_test() -> Nil {
  // RFC 9458 section 5.1: an encapsulated exchange has no way to carry the
  // interim response a 100-continue expectation asks for, so a client does not
  // construct one and a gateway that is handed one answers with an error.
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
    ohttp.deterministic_client(
      config(),
      ephemeral_key(),
      bhttp.defaults(),
      maximum_message_bytes: 4096,
    )
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
    == Error(ohttp.InvalidMessage)
  assert ohttp.seal_request(
      client,
      expecting("100-CONTINUE"),
      bhttp.KnownLength,
    )
    == Error(ohttp.InvalidMessage)
  assert ohttp.seal_request(
      client,
      expecting("other, 100-continue;q=1"),
      bhttp.KnownLength,
    )
    == Error(ohttp.InvalidMessage)

  // An expectation that merely contains the token is a different expectation
  // and is carried through, so the refusal is on the token and not the text.
  let assert Ok(#(sealed, _)) =
    ohttp.seal_request(client, expecting("not-100-continue"), bhttp.KnownLength)
  let assert Ok(replays) = ohttp.replay_store(maximum_entries: 8)
  let assert Ok(#(opened, _, _)) = ohttp.open_request(gateway, replays, sealed)
  assert opened == expecting("not-100-continue")

  // A peer that ignores the rule still gets an error from the gateway rather
  // than a forwarded request, so the refusal does not depend on the sender.
  let assert Ok(smuggled) =
    bhttp.encode(expecting("100-continue"), bhttp.KnownLength, bhttp.defaults())
  let assert Ok(#(sealed, _)) = ohttp.seal_request_bytes(client, smuggled)
  let assert Ok(fresh) = ohttp.replay_store(maximum_entries: 8)
  assert ohttp.open_request(gateway, fresh, sealed)
    == Error(ohttp.InvalidMessage)
}
