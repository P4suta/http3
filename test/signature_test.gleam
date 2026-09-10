import gleam/bit_array
import gleam/option.{None, Some}
import gleeunit
import http/signature

pub fn main() -> Nil {
  gleeunit.main()
}

fn rfc_message() -> signature.Message {
  signature.RequestMessage(
    method: "POST",
    scheme: "https",
    authority: "example.com",
    path: "/foo",
    query: Some("?param=Value&Pet=dog"),
    headers: [
      signature.Header("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
      signature.Header("content-type", "application/json"),
    ],
  )
}

fn rfc_key() -> signature.HmacKey {
  let assert Ok(bytes) =
    bit_array.base64_decode(
      "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==",
    )
  let assert Ok(key) = signature.hmac_key(bytes)
  key
}

pub fn rfc9421_hmac_sha256_vector_test() -> Nil {
  let components = [
    signature.Field("date"),
    signature.Authority,
    signature.Field("content-type"),
  ]
  let input =
    signature.SignatureInput(
      label: "sig-b25",
      components: components,
      parameters: signature.Parameters(
        created: 1_618_884_473,
        expires: None,
        nonce: None,
        algorithm: None,
        key_id: "test-shared-secret",
        tag: None,
        extensions: [],
      ),
    )
  let assert Ok(profile) = signature.profile(components, 300)
  let assert Ok(base) = signature.signature_base(rfc_message(), input, profile)
  assert base
    == "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n\"content-type\": application/json\n\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\""

  let assert Ok(fields) =
    signature.sign(rfc_message(), input, rfc_key(), profile)
  assert fields.signature_input
    == "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\""
  assert fields.signature
    == "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"
}

pub fn verification_enforces_time_authority_nonce_and_replay_test() -> Nil {
  let components = [
    signature.Method,
    signature.Authority,
    signature.Path,
    signature.Field("content-digest"),
  ]
  let message =
    signature.RequestMessage(
      method: "POST",
      scheme: "https",
      authority: "api.example",
      path: "/items",
      query: None,
      headers: [signature.Header("content-digest", "sha-256=:AQI=:")],
    )
  let input =
    signature.SignatureInput(
      label: "application",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: Some(160),
        nonce: Some("unique-1"),
        algorithm: Some(signature.HmacSha256),
        key_id: "application-key",
        tag: Some("example-profile"),
        extensions: [],
      ),
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let profile =
    profile
    |> signature.with_clock_skew(5)
    |> signature.with_required_nonce(True)
    |> signature.for_authority("api.example")
    |> signature.for_tag("example-profile")
  let assert Ok(key) = signature.hmac_key(<<0:256>>)
  let assert Ok(fields) = signature.sign(message, input, key, profile)
  let assert Ok(store) = signature.replay_store(8)
  let assert Ok(updated) =
    signature.verify(message, fields, key, 150, profile, store)
  assert signature.verify(message, fields, key, 150, profile, updated)
    == Error(signature.ReplayDetected)
  assert signature.verify(message, fields, key, 166, profile, store)
    == Error(signature.Expired)

  let wrong_authority =
    signature.RequestMessage(..message, authority: "other.example")
  assert signature.verify(wrong_authority, fields, key, 150, profile, store)
    == Error(signature.AuthorityMismatch)
}

pub fn signature_profile_and_canonicalization_fail_closed_test() -> Nil {
  let components = [signature.Method, signature.Authority]
  let assert Ok(profile) = signature.profile(components, 60)
  let assert Ok(key) = signature.hmac_key(<<1:256>>)
  let missing =
    signature.SignatureInput(
      label: "sig",
      components: [signature.Method],
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: None,
        key_id: "key",
        tag: None,
        extensions: [],
      ),
    )
  assert signature.sign(rfc_message(), missing, key, profile)
    == Error(signature.PolicyViolation)

  let invalid_header =
    signature.RequestMessage(
      method: "POST",
      scheme: "https",
      authority: "example.com",
      path: "/foo",
      query: Some("?param=Value&Pet=dog"),
      headers: [signature.Header("x-test", "safe\r\ninjected: value")],
    )
  let invalid =
    signature.SignatureInput(..missing, components: [
      signature.Field("x-test"),
    ])
  let assert Ok(field_profile) =
    signature.profile([signature.Field("x-test")], 60)
  assert signature.sign(invalid_header, invalid, key, field_profile)
    == Error(signature.InvalidMessage)
  assert signature.profile([], 60) == Error(signature.InvalidProfile)
  assert signature.hmac_key(<<1, 2>>) == Error(signature.InvalidKey)
}
