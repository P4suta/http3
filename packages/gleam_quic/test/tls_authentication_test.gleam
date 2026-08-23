import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension_value

@external(erlang, "gleam_quic_test_ffi", "fixture")
fn fixture(name: String) -> Result(BitArray, Nil)

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_chain_identity_and_certificate_verify_test() -> Nil {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(key_pem) = fixture("server-key.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  let assert Ok(peer) =
    authentication.validate_server_certificate(chain, trust_store, "localhost")

  let content = <<"TLS CertificateVerify input">>
  let assert Ok(signing_key) = authentication.signing_key_from_pem(key_pem)
  let assert Ok(signature) =
    authentication.sign(signing_key, extension_value.Ed25519, content)
  assert authentication.verify(
      peer,
      extension_value.Ed25519,
      content,
      signature,
    )
    == Ok(Nil)
  assert authentication.verify(
      peer,
      extension_value.Ed25519,
      <<content:bits, 0>>,
      signature,
    )
    == Error(authentication.InvalidSignature)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_wrong_hostname_untrusted_chain_and_mismatched_scheme_test() -> Nil {
  let assert Ok(ca_pem) = fixture("ca.pem")
  let assert Ok(server_pem) = fixture("server.pem")
  let assert Ok(trust_store) = authentication.trust_store_from_pem(ca_pem)
  let assert Ok(chain) = authentication.certificate_chain_from_pem(server_pem)
  assert authentication.validate_server_certificate(
      chain,
      trust_store,
      "127.0.0.1",
    )
    == Error(authentication.IdentityMismatch)

  let assert Ok(wrong_store) = authentication.trust_store_from_pem(server_pem)
  let assert Ok(ca_chain) = authentication.certificate_chain_from_pem(ca_pem)
  assert authentication.validate_server_certificate(
      ca_chain,
      wrong_store,
      "localhost",
    )
    == Error(authentication.UntrustedCertificate)

  let assert Ok(peer) =
    authentication.validate_server_certificate(chain, trust_store, "localhost")
  assert authentication.verify(
      peer,
      extension_value.RsaPssRsaeSha256,
      <<"input">>,
      <<0:512>>,
    )
    == Error(authentication.IncompatibleSignatureScheme)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn compares_authenticators_in_constant_time_test() -> Nil {
  assert authentication.constant_time_equal(<<1, 2, 3>>, <<1, 2, 3>>)
    == Ok(True)
  assert authentication.constant_time_equal(<<1, 2, 3>>, <<1, 2, 4>>)
    == Ok(False)
  assert authentication.constant_time_equal(<<1, 2>>, <<1, 2, 0>>) == Ok(False)
  assert authentication.constant_time_equal(<<1:size(1)>>, <<1:size(1)>>)
    == Error(authentication.NonByteAligned)
}
