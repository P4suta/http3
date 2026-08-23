import gleam_quic/internal/tls/extension_value

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_sni_alpn_and_versions_test() -> Nil {
  let assert Ok(sni) = extension_value.encode_server_name("example.com")
  assert sni == <<0, 14, 0, 0, 11, "example.com">>
  assert extension_value.decode_server_name(sni) == Ok("example.com")

  let protocols = [<<"h3">>, <<"h3-29">>]
  let assert Ok(alpn) = extension_value.encode_alpn(protocols)
  assert extension_value.decode_alpn(alpn) == Ok(protocols)

  let versions = [
    extension_value.Tls13,
    extension_value.UnknownVersion(0x7a7a),
  ]
  let assert Ok(client_versions) =
    extension_value.encode_client_supported_versions(versions)
  assert extension_value.decode_client_supported_versions(client_versions)
    == Ok(versions)
  assert extension_value.encode_server_supported_version(extension_value.Tls13)
    == Ok(<<3, 4>>)
  assert extension_value.decode_server_supported_version(<<3, 4>>)
    == Ok(extension_value.Tls13)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_trips_groups_signatures_and_key_shares_test() -> Nil {
  let groups = [
    extension_value.X25519,
    extension_value.Secp256r1,
    extension_value.UnknownGroup(0xaaaa),
  ]
  let assert Ok(encoded_groups) =
    extension_value.encode_supported_groups(groups)
  assert extension_value.decode_supported_groups(encoded_groups) == Ok(groups)

  let signatures = [
    extension_value.Ed25519,
    extension_value.EcdsaSecp256r1Sha256,
    extension_value.RsaPssRsaeSha256,
  ]
  let assert Ok(encoded_signatures) =
    extension_value.encode_signature_schemes(signatures)
  assert extension_value.decode_signature_schemes(encoded_signatures)
    == Ok(signatures)
  assert extension_value.encode_signature_scheme(extension_value.Ed25519)
    == Ok(<<8, 7>>)
  assert extension_value.decode_signature_scheme(<<8, 7>>)
    == Ok(extension_value.Ed25519)

  let shares = [
    extension_value.KeyShare(extension_value.X25519, <<1:256>>),
    extension_value.KeyShare(extension_value.Secp256r1, <<4, 2:512>>),
  ]
  let assert Ok(encoded_shares) =
    extension_value.encode_client_key_shares(shares)
  assert extension_value.decode_client_key_shares(encoded_shares) == Ok(shares)
  let assert Ok(server_share) =
    extension_value.encode_server_key_share(
      extension_value.KeyShare(extension_value.X25519, <<1:256>>),
    )
  assert extension_value.decode_server_key_share(server_share)
    == Ok(extension_value.KeyShare(extension_value.X25519, <<1:256>>))
  assert extension_value.encode_selected_group(extension_value.X25519)
    == Ok(<<0, 29>>)
  assert extension_value.decode_selected_group(<<0, 29>>)
    == Ok(extension_value.X25519)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_malformed_or_duplicate_semantic_extensions_test() -> Nil {
  assert extension_value.decode_server_name(<<0, 1, 0>>)
    == Error(extension_value.Truncated)
  assert extension_value.encode_server_name("")
    == Error(extension_value.InvalidServerName)
  assert extension_value.decode_alpn(<<0, 1, 0>>)
    == Error(extension_value.EmptyProtocol)
  assert extension_value.decode_client_supported_versions(<<2, 3, 3>>)
    == Error(extension_value.Tls13Required)
  assert extension_value.decode_supported_groups(<<0, 4, 0, 29, 0, 29>>)
    == Error(extension_value.DuplicateIdentifier(29))
  let duplicate_share = <<0, 72, 0, 29, 0, 32, 0:256, 0, 29, 0, 32, 1:256>>
  assert extension_value.decode_client_key_shares(duplicate_share)
    == Error(extension_value.DuplicateIdentifier(29))
  assert extension_value.decode_server_key_share(<<0, 29, 0, 31, 0:248>>)
    == Error(extension_value.InvalidKeyExchange)
}
