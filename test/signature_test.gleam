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

pub fn rfc9421_component_values_are_printable_and_normalized_test() -> Nil {
  // RFC 9421 section 2: a component value carries no newline, and section 2.2:
  // a derived component value is limited to printable characters and spaces and neither starts nor ends with whitespace.
  // A value that breaks either rule puts a line of the signer's choosing into the signature base, where it is indistinguishable from a line a covered component produced.
  let components = [
    signature.Method,
    signature.Path,
    signature.Scheme,
    signature.Authority,
  ]
  let input =
    signature.SignatureInput(
      label: "sig",
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
  let request = fn(scheme, authority, path, query, headers) {
    signature.signature_base(
      signature.RequestMessage(
        method: "POST",
        scheme: scheme,
        authority: authority,
        path: path,
        query: query,
        headers: headers,
      ),
      input,
      profile,
    )
  }
  let plain = fn(path) { request("https", "example.com", path, None, []) }

  let assert Ok(normalized) = plain("/foo")
  // A newline in the path writes a second line into the base.
  assert plain("/a\nb") == Error(signature.InvalidMessage)
  // So does a carriage return, and so does any other control character.
  assert plain("/a\rb") == Error(signature.InvalidMessage)
  assert plain("/a\u{0001}b") == Error(signature.InvalidMessage)
  // A trailing space is whitespace at the end of a derived value.
  assert plain("/foo ") == Error(signature.InvalidMessage)

  // The same holds for every other derived value.
  assert request("https ", "example.com", "/foo", None, [])
    == Error(signature.InvalidMessage)
  assert request("https", "example.com", "/foo", Some("?a=\nb"), [])
    == Error(signature.InvalidMessage)

  // RFC 9421 sections 2.2.3 and 2.2.4 normalize covered authority and scheme values.
  assert request("https", "Example.com", "/foo", None, []) == Ok(normalized)
  assert request("HTTPS", "example.com:443", "/foo", None, []) == Ok(normalized)
  let assert Ok(plain_http) = request("http", "example.com", "/foo", None, [])
  assert request("http", "example.com:80", "/foo", None, []) == Ok(plain_http)
  let assert Ok(_) = request("https", "example.com:8443", "/foo", None, [])
  let assert Ok(_) = request("http", "example.com:443", "/foo", None, [])

  // RFC 9421 section 2.1: a field value that is not ASCII is encoded to ASCII before it reaches the signature base, so one that has not been is refused rather than signed in whatever encoding it arrived in.
  let with_field = fn(value) {
    signature.signature_base(
      signature.RequestMessage(
        method: "POST",
        scheme: "https",
        authority: "example.com",
        path: "/foo",
        query: None,
        headers: [signature.Header("x-note", value)],
      ),
      input,
      profile,
    )
  }
  let assert Ok(_) = with_field("plain")
  assert with_field("caf\u{00e9}") == Error(signature.InvalidMessage)
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
    |> signature.for_key_id("application-key")
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

pub fn rfc9421_normalizes_scheme_authority_and_repeated_fields_test() -> Nil {
  let components = [
    signature.Scheme,
    signature.Authority,
    signature.Field("x-list"),
  ]
  let message =
    signature.RequestMessage(
      method: "GET",
      scheme: "HTTPS",
      authority: "EXAMPLE.COM:0443",
      path: "/items",
      query: None,
      headers: [
        signature.Header("X-List", "  first\t"),
        signature.Header("x-list", "\tsecond  "),
      ],
    )
  let input =
    signature.SignatureInput(
      label: "canonical",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: Some(signature.HmacSha256),
        key_id: "canonical-key",
        tag: None,
        extensions: [],
      ),
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let profile = signature.for_authority(profile, "EXAMPLE.COM:443")
  let assert Ok(base) = signature.signature_base(message, input, profile)
  assert base
    == "\"@scheme\": https\n\"@authority\": example.com\n\"x-list\": first, second\n\"@signature-params\": (\"@scheme\" \"@authority\" \"x-list\");created=100;alg=\"hmac-sha256\";keyid=\"canonical-key\""
}

pub fn rfc9421_component_values_are_ascii_and_line_safe_test() -> Nil {
  let components = [signature.Scheme]
  let input =
    signature.SignatureInput(
      label: "safe",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: None,
        key_id: "safe-key",
        tag: None,
        extensions: [],
      ),
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let injected_scheme =
    signature.RequestMessage(
      method: "GET",
      scheme: "https\nspoof",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [],
    )
  assert signature.signature_base(injected_scheme, input, profile)
    == Error(signature.InvalidMessage)

  let path_components = [signature.Path]
  let path_input =
    signature.SignatureInput(..input, components: path_components)
  let assert Ok(path_profile) = signature.profile(path_components, 60)
  let invalid_path =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/safe\tunsafe",
      query: None,
      headers: [],
    )
  assert signature.signature_base(invalid_path, path_input, path_profile)
    == Error(signature.InvalidMessage)

  let query_components = [signature.Query]
  let query_input =
    signature.SignatureInput(..input, components: query_components)
  let assert Ok(query_profile) = signature.profile(query_components, 60)
  let boundary_whitespace_query =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: Some("?name=value "),
      headers: [],
    )
  assert signature.signature_base(
      boundary_whitespace_query,
      query_input,
      query_profile,
    )
    == Error(signature.InvalidMessage)

  let field_components = [signature.Field("x-name")]
  let field_input =
    signature.SignatureInput(..input, components: field_components)
  let assert Ok(field_profile) = signature.profile(field_components, 60)
  let non_ascii_field =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [signature.Header("x-name", "caf\u{00e9}")],
    )
  assert signature.signature_base(non_ascii_field, field_input, field_profile)
    == Error(signature.InvalidMessage)
}

pub fn rfc9421_duplicate_signature_labels_fail_closed_test() -> Nil {
  let duplicate_inputs =
    "sig=(\"@method\");created=100;keyid=\"first\", sig=(\"@method\");created=100;keyid=\"second\""
  assert signature.parse_inputs(duplicate_inputs) == Error(signature.Invalid)
  let assert Ok([quoted_comma]) =
    signature.parse_inputs(
      "sig=(\"@method\");created=100;keyid=\"key\";extension=\"comma, fake=label\"",
    )
  assert quoted_comma.label == "sig"

  let components = [signature.Method]
  let input =
    signature.SignatureInput(
      label: "sig",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: Some(signature.HmacSha256),
        key_id: "duplicate-key",
        tag: None,
        extensions: [],
      ),
    )
  let message =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [],
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let assert Ok(key) = signature.hmac_key(<<2:256>>)
  let assert Ok(fields) = signature.sign(message, input, key, profile)
  let duplicate_fields =
    signature.SignedFields(
      signature_input: fields.signature_input,
      signature: fields.signature <> ", " <> fields.signature,
    )
  let assert Ok(store) = signature.replay_store(4)
  assert signature.verify(message, duplicate_fields, key, 100, profile, store)
    == Error(signature.Invalid)
}

pub fn rfc9421_verification_preserves_signature_parameter_order_test() -> Nil {
  let components = [signature.Method]
  let input =
    signature.SignatureInput(
      label: "sig",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: Some(signature.HmacSha256),
        key_id: "order-key",
        tag: None,
        extensions: [],
      ),
    )
  let message =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [],
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let profile = signature.for_key_id(profile, "order-key")
  let assert Ok(key) = signature.hmac_key(<<3:256>>)
  let assert Ok(fields) = signature.sign(message, input, key, profile)
  let reordered =
    signature.SignedFields(
      ..fields,
      signature_input: "sig=(\"@method\");keyid=\"order-key\";alg=\"hmac-sha256\";created=100",
    )
  let assert Ok(store) = signature.replay_store(4)
  assert signature.verify(message, reordered, key, 100, profile, store)
    == Error(signature.SignatureMismatch)
}

pub fn rfc9421_component_target_and_algorithm_fail_closed_test() -> Nil {
  assert signature.profile([signature.Method, signature.Method], 60)
    == Error(signature.InvalidProfile)
  assert signature.parse_inputs(
      "sig=(\"@method\";sf);created=100;keyid=\"parameterized\"",
    )
    == Error(signature.Invalid)
  assert signature.parse_inputs(
      "sig=(\"content-type\";tr);created=100;keyid=\"trailer\"",
    )
    == Error(signature.Invalid)
  assert signature.parse_inputs(
      "sig=(\"content-type\";req);created=100;keyid=\"request\"",
    )
    == Error(signature.Invalid)
  assert signature.parse_inputs(
      "sig=(\"@query-param\";name=\"id\");created=100;keyid=\"query\"",
    )
    == Error(signature.Invalid)
  assert signature.parse_inputs(
      "sig=(\"@request-target\");created=100;keyid=\"target\"",
    )
    == Error(signature.Invalid)
  assert signature.parse_inputs(
      "sig=(\"@signature-params\");created=100;keyid=\"reserved\"",
    )
    == Error(signature.Invalid)

  let input =
    signature.SignatureInput(
      label: "sig",
      components: [signature.Status],
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: Some(signature.HmacSha256),
        key_id: "target-key",
        tag: None,
        extensions: [],
      ),
    )
  let request =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [],
    )
  let assert Ok(status_profile) = signature.profile([signature.Status], 60)
  let assert Ok(key) = signature.hmac_key(<<4:256>>)
  assert signature.sign(request, input, key, status_profile)
    == Error(signature.MissingComponent)

  let method_input =
    signature.SignatureInput(
      ..input,
      components: [signature.Method],
      parameters: signature.Parameters(
        ..input.parameters,
        algorithm: Some(signature.Ed25519),
      ),
    )
  let assert Ok(method_profile) = signature.profile([signature.Method], 60)
  assert signature.sign(request, method_input, key, method_profile)
    == Error(signature.UnsupportedAlgorithm)
  let prohibited_input =
    signature.SignatureInput(
      ..method_input,
      parameters: signature.Parameters(
        ..method_input.parameters,
        algorithm: Some(signature.Extension("none")),
      ),
    )
  assert signature.sign(request, prohibited_input, key, method_profile)
    == Error(signature.UnsupportedAlgorithm)
}

pub fn rfc9421_verification_requires_trusted_key_id_binding_test() -> Nil {
  let components = [signature.Method]
  let input =
    signature.SignatureInput(
      label: "sig",
      components: components,
      parameters: signature.Parameters(
        created: 100,
        expires: None,
        nonce: None,
        algorithm: Some(signature.HmacSha256),
        key_id: "trusted-key",
        tag: None,
        extensions: [],
      ),
    )
  let message =
    signature.RequestMessage(
      method: "GET",
      scheme: "https",
      authority: "example.com",
      path: "/",
      query: None,
      headers: [],
    )
  let assert Ok(profile) = signature.profile(components, 60)
  let assert Ok(key) = signature.hmac_key(<<5:256>>)
  let assert Ok(fields) = signature.sign(message, input, key, profile)
  let assert Ok(store) = signature.replay_store(4)
  assert signature.verify(message, fields, key, 100, profile, store)
    == Error(signature.PolicyViolation)
  let wrong_profile = signature.for_key_id(profile, "other-key")
  assert signature.verify(message, fields, key, 100, wrong_profile, store)
    == Error(signature.PolicyViolation)
  let trusted_profile = signature.for_key_id(profile, "trusted-key")
  let assert Ok(wrong_key) = signature.hmac_key(<<6:256>>)
  assert signature.verify(
      message,
      fields,
      wrong_key,
      100,
      trusted_profile,
      store,
    )
    == Error(signature.SignatureMismatch)
  assert signature.verify(message, fields, key, 100, trusted_profile, store)
    == Ok(store)
}
