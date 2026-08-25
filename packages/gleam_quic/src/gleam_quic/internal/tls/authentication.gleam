//// TLS 1.3 certificate paths, service identity, signatures, and tag comparison.

import gleam/bit_array
import gleam/list
import gleam/result

@external(erlang, "gleam_quic_tls_ffi", "is_ip_address")
fn raw_is_ip_address(hostname: String) -> Bool

import gleam_quic/internal/tls/extension_value.{type SignatureScheme}

/// Runtime-owned trust anchors. The contained X.509 terms never cross this API.
pub type TrustStore

/// A path- and identity-validated leaf certificate with its public key.
pub type VerifiedPeer

/// A decoded runtime-owned private signing key.
pub type SigningKey

/// A certificate authentication or signature failure.
pub type Error {
  NonByteAligned
  InvalidInput
  InvalidPem
  EmptyCertificateChain
  UntrustedCertificate
  IdentityMismatch
  InvalidSignature
  IncompatibleSignatureScheme
  InvalidCertificatePurpose
  RuntimeUnavailable
}

@external(erlang, "gleam_quic_tls_ffi", "trust_store_from_pem")
fn raw_trust_store_from_pem(pem: BitArray) -> Result(TrustStore, Int)

@external(erlang, "gleam_quic_tls_ffi", "trust_store_from_der")
fn raw_trust_store_from_der(
  certificates: List(BitArray),
) -> Result(TrustStore, Int)

@external(erlang, "gleam_quic_tls_ffi", "system_trust_store")
fn raw_system_trust_store() -> Result(TrustStore, Int)

@external(erlang, "gleam_quic_tls_ffi", "certificate_chain_from_pem")
fn raw_certificate_chain_from_pem(pem: BitArray) -> Result(List(BitArray), Int)

@external(erlang, "gleam_quic_tls_ffi", "validate_server_certificate")
fn raw_validate_server_certificate(
  certificate_chain: List(BitArray),
  trust_store: TrustStore,
  hostname: String,
) -> Result(VerifiedPeer, Int)

@external(erlang, "gleam_quic_tls_ffi", "validate_client_certificate")
fn raw_validate_client_certificate(
  certificate_chain: List(BitArray),
  trust_store: TrustStore,
) -> Result(VerifiedPeer, Int)

@external(erlang, "gleam_quic_tls_ffi", "validate_client_certificate_purpose")
fn raw_validate_client_certificate_purpose(
  certificate_chain: List(BitArray),
) -> Result(Nil, Int)

@external(erlang, "gleam_quic_tls_ffi", "verified_peer_fingerprint")
fn raw_verified_peer_fingerprint(peer: VerifiedPeer) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_tls_ffi", "signing_key_from_pem")
fn raw_signing_key_from_pem(pem: BitArray) -> Result(SigningKey, Int)

@external(erlang, "gleam_quic_tls_ffi", "signing_key_scheme")
fn raw_signing_key_scheme(signing_key: SigningKey) -> Result(Int, Int)

@external(erlang, "gleam_quic_tls_ffi", "signing_key_matches_certificate")
fn raw_signing_key_matches_certificate(
  certificate_chain: List(BitArray),
  signing_key: SigningKey,
  signature_scheme: Int,
) -> Result(Bool, Int)

@external(erlang, "gleam_quic_tls_ffi", "sign")
fn raw_sign(
  signing_key: SigningKey,
  signature_scheme: Int,
  content: BitArray,
) -> Result(BitArray, Int)

@external(erlang, "gleam_quic_tls_ffi", "verify")
fn raw_verify(
  peer: VerifiedPeer,
  signature_scheme: Int,
  content: BitArray,
  signature: BitArray,
) -> Result(Nil, Int)

@external(erlang, "gleam_quic_tls_ffi", "constant_time_equal")
fn raw_constant_time_equal(left: BitArray, right: BitArray) -> Result(Bool, Int)

/// Decode one or more PEM trust-anchor certificates.
pub fn trust_store_from_pem(pem pem: BitArray) -> Result(TrustStore, Error) {
  use Nil <- result.try(require_byte_aligned(pem))
  raw_trust_store_from_pem(pem) |> map_result
}

/// Validate non-empty DER trust anchors and retain them in runtime-owned form.
pub fn trust_store_from_der(
  certificates certificates: List(BitArray),
) -> Result(TrustStore, Error) {
  case certificates, all_byte_aligned(certificates) {
    [], _ -> Error(EmptyCertificateChain)
    _, False -> Error(NonByteAligned)
    _, True -> raw_trust_store_from_der(certificates) |> map_result
  }
}

/// Load the operating system trust anchors through Erlang/OTP `public_key`.
pub fn system_trust_store() -> Result(TrustStore, Error) {
  raw_system_trust_store() |> map_result
}

/// Decode a leaf-first PEM certificate chain into DER messages.
pub fn certificate_chain_from_pem(
  pem pem: BitArray,
) -> Result(List(BitArray), Error) {
  use Nil <- result.try(require_byte_aligned(pem))
  case raw_certificate_chain_from_pem(pem) |> map_result {
    Ok([]) -> Error(EmptyCertificateChain)
    other -> other
  }
}

/// Validate an RFC 5280 path and RFC 9525 DNS/IP service identity.
pub fn validate_server_certificate(
  certificate_chain certificate_chain: List(BitArray),
  trust_store trust_store: TrustStore,
  hostname hostname: String,
) -> Result(VerifiedPeer, Error) {
  case certificate_chain, hostname {
    [], _ -> Error(EmptyCertificateChain)
    _, "" -> Error(InvalidInput)
    _, _ ->
      case all_byte_aligned(certificate_chain) {
        False -> Error(NonByteAligned)
        True ->
          raw_validate_server_certificate(
            certificate_chain,
            trust_store,
            hostname,
          )
          |> map_result
      }
  }
}

/// Validate a non-empty client certificate path for TLS client authentication.
pub fn validate_client_certificate(
  certificate_chain certificate_chain: List(BitArray),
  trust_store trust_store: TrustStore,
) -> Result(VerifiedPeer, Error) {
  case certificate_chain {
    [] -> Error(EmptyCertificateChain)
    _ ->
      case all_byte_aligned(certificate_chain) {
        False -> Error(NonByteAligned)
        True ->
          raw_validate_client_certificate(certificate_chain, trust_store)
          |> map_result
      }
  }
}

/// Validate clientAuth purpose and digital-signature usage without implying
/// that the certificate has been accepted by any remote trust store.
pub fn validate_client_certificate_purpose(
  certificate_chain certificate_chain: List(BitArray),
) -> Result(Nil, Error) {
  case certificate_chain {
    [] -> Error(EmptyCertificateChain)
    _ ->
      case all_byte_aligned(certificate_chain) {
        False -> Error(NonByteAligned)
        True ->
          raw_validate_client_certificate_purpose(certificate_chain)
          |> map_result
      }
  }
}

/// Return the SHA-256 fingerprint of a path-validated leaf certificate.
pub fn verified_peer_fingerprint(
  peer peer: VerifiedPeer,
) -> Result(BitArray, Error) {
  raw_verified_peer_fingerprint(peer) |> map_result
}

/// Return whether a service identity is an IPv4 or IPv6 address literal.
pub fn is_ip_address(hostname: String) -> Bool {
  raw_is_ip_address(hostname)
}

/// Decode one unencrypted PEM private key for CertificateVerify.
pub fn signing_key_from_pem(pem pem: BitArray) -> Result(SigningKey, Error) {
  use Nil <- result.try(require_byte_aligned(pem))
  raw_signing_key_from_pem(pem) |> map_result
}

/// Select the TLS 1.3 signature scheme implied by a decoded private key.
///
/// Server configuration uses this once at listener startup. The runtime key
/// term and its algorithm identifiers remain behind the FFI boundary.
pub fn signing_key_scheme(
  signing_key signing_key: SigningKey,
) -> Result(SignatureScheme, Error) {
  use identifier <- result.try(
    raw_signing_key_scheme(signing_key) |> map_result,
  )
  case identifier {
    0x0403 -> Ok(extension_value.EcdsaSecp256r1Sha256)
    0x0503 -> Ok(extension_value.EcdsaSecp384r1Sha384)
    0x0603 -> Ok(extension_value.EcdsaSecp521r1Sha512)
    0x0804 -> Ok(extension_value.RsaPssRsaeSha256)
    0x0809 -> Ok(extension_value.RsaPssPssSha256)
    0x0807 -> Ok(extension_value.Ed25519)
    0x0808 -> Ok(extension_value.Ed448)
    _ -> Error(IncompatibleSignatureScheme)
  }
}

/// Check that the leaf certificate contains the public key for this signer.
pub fn signing_key_matches_certificate(
  certificate_chain certificate_chain: List(BitArray),
  signing_key signing_key: SigningKey,
  signature_scheme signature_scheme: SignatureScheme,
) -> Result(Bool, Error) {
  case certificate_chain, all_byte_aligned(certificate_chain) {
    [], _ -> Error(EmptyCertificateChain)
    _, False -> Error(NonByteAligned)
    _, True -> {
      use identifier <- result.try(signature_scheme_identifier(signature_scheme))
      raw_signing_key_matches_certificate(
        certificate_chain,
        signing_key,
        identifier,
      )
      |> map_result
    }
  }
}

/// Sign exact CertificateVerify content with a negotiated TLS 1.3 scheme.
pub fn sign(
  signing_key signing_key: SigningKey,
  signature_scheme signature_scheme: SignatureScheme,
  content content: BitArray,
) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(content))
  use identifier <- result.try(signature_scheme_identifier(signature_scheme))
  raw_sign(signing_key, identifier, content) |> map_result
}

/// Verify exact CertificateVerify content against the validated leaf key.
pub fn verify(
  peer peer: VerifiedPeer,
  signature_scheme signature_scheme: SignatureScheme,
  content content: BitArray,
  signature signature: BitArray,
) -> Result(Nil, Error) {
  case byte_aligned(content) && byte_aligned(signature) {
    False -> Error(NonByteAligned)
    True -> {
      use identifier <- result.try(signature_scheme_identifier(signature_scheme))
      raw_verify(peer, identifier, content, signature) |> map_result
    }
  }
}

/// Compare two authenticators without data-dependent comparison timing.
pub fn constant_time_equal(
  left left: BitArray,
  right right: BitArray,
) -> Result(Bool, Error) {
  case byte_aligned(left) && byte_aligned(right) {
    False -> Error(NonByteAligned)
    True -> raw_constant_time_equal(left, right) |> map_result
  }
}

fn signature_scheme_identifier(scheme: SignatureScheme) -> Result(Int, Error) {
  case scheme {
    extension_value.EcdsaSecp256r1Sha256 -> Ok(0x0403)
    extension_value.EcdsaSecp384r1Sha384 -> Ok(0x0503)
    extension_value.EcdsaSecp521r1Sha512 -> Ok(0x0603)
    extension_value.RsaPssRsaeSha256 -> Ok(0x0804)
    extension_value.RsaPssRsaeSha384 -> Ok(0x0805)
    extension_value.RsaPssRsaeSha512 -> Ok(0x0806)
    extension_value.Ed25519 -> Ok(0x0807)
    extension_value.Ed448 -> Ok(0x0808)
    extension_value.RsaPssPssSha256 -> Ok(0x0809)
    extension_value.RsaPssPssSha384 -> Ok(0x080a)
    extension_value.RsaPssPssSha512 -> Ok(0x080b)
    extension_value.UnknownSignatureScheme(_) ->
      Error(IncompatibleSignatureScheme)
  }
}

fn map_result(value: Result(output, Int)) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(1) -> Error(InvalidInput)
    Error(2) -> Error(RuntimeUnavailable)
    Error(3) -> Error(InvalidPem)
    Error(5) -> Error(UntrustedCertificate)
    Error(6) -> Error(IdentityMismatch)
    Error(7) -> Error(InvalidSignature)
    Error(8) -> Error(IncompatibleSignatureScheme)
    Error(9) -> Error(InvalidCertificatePurpose)
    Error(_) -> Error(RuntimeUnavailable)
  }
}

fn require_byte_aligned(bytes: BitArray) -> Result(Nil, Error) {
  case byte_aligned(bytes) {
    True -> Ok(Nil)
    False -> Error(NonByteAligned)
  }
}

fn all_byte_aligned(values: List(BitArray)) -> Bool {
  list.all(values, byte_aligned)
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}
