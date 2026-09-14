import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/internal/http2/origin

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn origin_entries_round_trip_and_invalid_serializations_are_ignored_test() -> Nil {
  let payload = <<
    19:size(16),
    "https://example.com":utf8,
    10:size(16),
    "not-origin":utf8,
    24:size(16),
    "https://example.org:8443":utf8,
  >>

  let expected = [
    origin.Origin("https", "example.com", None),
    origin.Origin("https", "example.org", Some(8443)),
  ]
  assert origin.decode(payload, maximum_entries: 3) == Ok(expected)
  assert origin.encode(expected, maximum_entries: 3)
    |> result.try(fn(encoded) { origin.decode(encoded, maximum_entries: 3) })
    == Ok(expected)
}

pub fn origin_payload_is_structurally_bounded_test() -> Nil {
  assert origin.decode(<<1:size(1)>>, maximum_entries: 1)
    == Error(origin.NonByteAligned)
  assert origin.decode(<<3:size(16), "ab":utf8>>, maximum_entries: 1)
    == Error(origin.Truncated)
  assert origin.decode(<<0:size(16), 0:size(16)>>, maximum_entries: 1)
    == Error(origin.TooManyOrigins(maximum: 1))
  assert origin.decode(<<>>, maximum_entries: 0) == Error(origin.InvalidLimit)
}

pub fn invalid_entries_still_consume_the_finite_entry_budget_test() -> Nil {
  let payload = <<
    10:size(16),
    "not-origin":utf8,
    19:size(16),
    "https://example.com":utf8,
  >>
  assert origin.decode(payload, maximum_entries: 1)
    == Error(origin.TooManyOrigins(maximum: 1))
}

pub fn origin_encoder_rejects_non_ascii_or_non_origin_values_test() -> Nil {
  assert origin.encode(
      [origin.Origin("https", "*.example.com", None)],
      maximum_entries: 1,
    )
    == Error(origin.InvalidOrigin)
  assert origin.encode(
      [origin.Origin("https", "日本.example", None)],
      maximum_entries: 1,
    )
    == Error(origin.NonAscii)
}

pub fn pool_authority_keys_are_canonical_and_default_deny_test() -> Nil {
  let primary = origin.connection_key(host: "EXAMPLE.com", port: 443)
  assert primary == "https://example.com:443"
  assert origin.same_connection_authority(
    current: primary,
    requested: origin.connection_key(host: "example.com", port: 443),
  )
  assert !origin.same_connection_authority(
    current: primary,
    requested: origin.connection_key(host: "example.org", port: 443),
  )
  assert !origin.same_connection_authority(
    current: primary,
    requested: origin.connection_key(host: "example.com", port: 8443),
  )
}
