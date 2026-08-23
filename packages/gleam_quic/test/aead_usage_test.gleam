import gleam_quic/internal/aead_usage
import gleam_quic/internal/tls/hello

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_rfc9001_aead_usage_limits_test() -> Nil {
  let assert Ok(fresh) = aead_usage.new(hello.Aes128GcmSha256)
  assert aead_usage.encrypted_packets(fresh) == 0
  assert aead_usage.limits(hello.Aes128GcmSha256)
    == Ok(aead_usage.Limits(8_388_608, 4_503_599_627_370_496))
  assert aead_usage.limits(hello.Aes256GcmSha384)
    == Ok(aead_usage.Limits(8_388_608, 4_503_599_627_370_496))
  assert aead_usage.limits(hello.Chacha20Poly1305Sha256)
    == Ok(aead_usage.Limits(4_611_686_018_427_387_904, 68_719_476_736))

  let assert Ok(usage) =
    aead_usage.restore(hello.Aes128GcmSha256, 8_388_607, 4_503_599_627_370_495)
  assert aead_usage.needs_key_update(usage)
  let assert Ok(usage) = aead_usage.record_encrypted(usage)
  assert aead_usage.record_encrypted(usage)
    == Error(aead_usage.ConfidentialityLimitReached)
  let assert Ok(usage) = aead_usage.record_authentication_failure(usage)
  assert aead_usage.record_authentication_failure(usage)
    == Error(aead_usage.IntegrityLimitReached)
  assert aead_usage.encrypted_packets(aead_usage.reset_encryption(usage)) == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_unsupported_or_invalid_usage_state_test() -> Nil {
  assert aead_usage.new(hello.Aes128Ccm8Sha256)
    == Error(aead_usage.UnsupportedCipherSuite(hello.Aes128Ccm8Sha256))
  assert aead_usage.restore(hello.Aes128Ccm8Sha256, 0, 0)
    == Error(aead_usage.UnsupportedCipherSuite(hello.Aes128Ccm8Sha256))
  assert aead_usage.restore(hello.Aes128GcmSha256, -1, 0)
    == Error(aead_usage.InvalidCount)
}
