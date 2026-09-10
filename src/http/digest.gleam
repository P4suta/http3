//// RFC 9530 Digest Fields with finite, algorithm-agile verification.

import gleam/bit_array
import gleam/list
import gleam/result
import http/structured_fields

const default_maximum_input_bytes = 16_777_216

const default_maximum_digests = 16

/// Active algorithms implemented through OTP, or an unimplemented registry
/// extension retained for forwarding and algorithm agility.
pub type Algorithm {
  Sha256
  Sha512
  Extension(key: String)
}

/// One Content-Digest or Repr-Digest dictionary member.
pub type Digest {
  Digest(
    algorithm: Algorithm,
    value: BitArray,
    parameters: List(structured_fields.Parameter),
  )
}

/// One Want-Content-Digest or Want-Repr-Digest preference.
pub type Preference {
  Preference(algorithm: Algorithm, weight: Int)
}

/// Finite verification policy. Every conveyed, accepted, implemented digest
/// is checked; at least one such digest is required.
pub type VerificationPolicy {
  VerificationPolicy(
    maximum_input_bytes: Int,
    maximum_digests: Int,
    accepted_algorithms: List(Algorithm),
  )
}

/// Digest syntax, policy, integrity, or cryptographic failure.
pub type Error {
  Invalid
  LimitExceeded
  NonByteAligned
  UnsupportedAlgorithm
  NoAcceptableDigest
  Mismatch
  CryptoFailure
}

/// A finite policy accepting only the active SHA-512 and SHA-256 algorithms.
pub fn defaults() -> VerificationPolicy {
  VerificationPolicy(
    maximum_input_bytes: default_maximum_input_bytes,
    maximum_digests: default_maximum_digests,
    accepted_algorithms: [Sha512, Sha256],
  )
}

/// Parse a complete Content-Digest or Repr-Digest dictionary.
pub fn parse(input: String) -> Result(List(Digest), Error) {
  use members <- result.try(
    structured_fields.parse_dictionary(input)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, parse_digest_member)
}

/// Serialize a Content-Digest or Repr-Digest dictionary canonically.
pub fn serialize(values: List(Digest)) -> Result(String, Error) {
  use members <- result.try(list.try_map(values, digest_member))
  structured_fields.serialize_dictionary(members)
  |> result.map_error(from_structured_error)
}

/// Parse a Want-Content-Digest or Want-Repr-Digest dictionary.
pub fn parse_preferences(input: String) -> Result(List(Preference), Error) {
  use members <- result.try(
    structured_fields.parse_dictionary(input)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, parse_preference_member)
}

/// Serialize integrity preferences. Weights must be from 0 through 10.
pub fn serialize_preferences(
  values: List(Preference),
) -> Result(String, Error) {
  use members <- result.try(list.try_map(values, preference_member))
  structured_fields.serialize_dictionary(members)
  |> result.map_error(from_structured_error)
}

/// Compute one active digest after checking byte alignment and input size.
pub fn compute(
  input input: BitArray,
  algorithm algorithm: Algorithm,
  maximum_input_bytes maximum_input_bytes: Int,
) -> Result(Digest, Error) {
  use _ <- result.try(validate_input(input, maximum_input_bytes))
  use value <- result.try(hash(input, algorithm))
  Ok(Digest(algorithm: algorithm, value: value, parameters: []))
}

/// Compute a finite ordered set of active digests over the same input.
pub fn compute_many(
  input input: BitArray,
  algorithms algorithms: List(Algorithm),
  maximum_input_bytes maximum_input_bytes: Int,
) -> Result(List(Digest), Error) {
  use _ <- result.try(validate_input(input, maximum_input_bytes))
  use _ <- result.try(case list.length(algorithms) <= default_maximum_digests {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  })
  list.try_map(algorithms, fn(algorithm) {
    use value <- result.try(hash(input, algorithm))
    Ok(Digest(algorithm: algorithm, value: value, parameters: []))
  })
}

/// Verify every conveyed digest selected by the policy. Unknown and
/// unaccepted algorithms are ignored, but can never make verification pass.
pub fn verify(
  input input: BitArray,
  values values: List(Digest),
  policy policy: VerificationPolicy,
) -> Result(Nil, Error) {
  use _ <- result.try(validate_policy(policy))
  use _ <- result.try(validate_input(input, policy.maximum_input_bytes))
  use _ <- result.try(case list.length(values) <= policy.maximum_digests {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  })
  use #(matched, all_equal) <- result.try(verify_values(
    input,
    values,
    policy.accepted_algorithms,
    0,
    True,
  ))
  case matched, all_equal {
    0, _ -> Error(NoAcceptableDigest)
    _, False -> Error(Mismatch)
    _, True -> Ok(Nil)
  }
}

fn parse_digest_member(
  member: structured_fields.DictionaryMember,
) -> Result(Digest, Error) {
  let structured_fields.DictionaryMember(key, value) = member
  case value {
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.ByteSequence(value),
      parameters,
    )) ->
      Ok(Digest(algorithm: algorithm(key), value: value, parameters: parameters))
    _ -> Error(Invalid)
  }
}

fn digest_member(
  value: Digest,
) -> Result(structured_fields.DictionaryMember, Error) {
  Ok(structured_fields.DictionaryMember(
    algorithm_key(value.algorithm),
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.ByteSequence(value.value),
      value.parameters,
    )),
  ))
}

fn parse_preference_member(
  member: structured_fields.DictionaryMember,
) -> Result(Preference, Error) {
  let structured_fields.DictionaryMember(key, value) = member
  case value {
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.Integer(weight),
      _,
    )) ->
      case valid_weight(weight) {
        True -> Ok(Preference(algorithm(key), weight))
        False -> Error(Invalid)
      }
    _ -> Error(Invalid)
  }
}

fn preference_member(
  value: Preference,
) -> Result(structured_fields.DictionaryMember, Error) {
  use _ <- result.try(case valid_weight(value.weight) {
    True -> Ok(Nil)
    False -> Error(Invalid)
  })
  Ok(structured_fields.DictionaryMember(
    algorithm_key(value.algorithm),
    structured_fields.ListItem(
      structured_fields.Item(structured_fields.Integer(value.weight), []),
    ),
  ))
}

// nolint: label_possible -- recursive verification state advances positionally.
fn verify_values(
  input: BitArray,
  values: List(Digest),
  accepted: List(Algorithm),
  matched: Int,
  all_equal: Bool,
) -> Result(#(Int, Bool), Error) {
  case values {
    [] -> Ok(#(matched, all_equal))
    [value, ..rest] ->
      case
        implemented(value.algorithm) && list.contains(accepted, value.algorithm)
      {
        False -> verify_values(input, rest, accepted, matched, all_equal)
        True -> {
          use calculated <- result.try(hash(input, value.algorithm))
          let equal = secure_equal(calculated, value.value)
          verify_values(input, rest, accepted, matched + 1, all_equal && equal)
        }
      }
  }
}

fn validate_policy(policy: VerificationPolicy) -> Result(Nil, Error) {
  case
    policy.maximum_input_bytes > 0,
    policy.maximum_digests > 0,
    list.length(policy.accepted_algorithms) <= default_maximum_digests
  {
    True, True, True -> Ok(Nil)
    _, _, _ -> Error(LimitExceeded)
  }
}

fn validate_input(
  input: BitArray,
  maximum_input_bytes: Int,
) -> Result(Nil, Error) {
  case maximum_input_bytes > 0, bit_array.bit_size(input) % 8 {
    False, _ -> Error(LimitExceeded)
    _, remainder if remainder != 0 -> Error(NonByteAligned)
    True, _ ->
      case bit_array.byte_size(input) <= maximum_input_bytes {
        True -> Ok(Nil)
        False -> Error(LimitExceeded)
      }
  }
}

fn hash(input: BitArray, algorithm: Algorithm) -> Result(BitArray, Error) {
  case algorithm {
    Extension(_) -> Error(UnsupportedAlgorithm)
    _ ->
      hash_ffi(input, algorithm_key(algorithm))
      |> result.replace_error(CryptoFailure)
  }
}

fn implemented(algorithm: Algorithm) -> Bool {
  case algorithm {
    Sha256 | Sha512 -> True
    Extension(_) -> False
  }
}

fn algorithm(key: String) -> Algorithm {
  case key {
    "sha-256" -> Sha256
    "sha-512" -> Sha512
    key -> Extension(key)
  }
}

fn algorithm_key(algorithm: Algorithm) -> String {
  case algorithm {
    Sha256 -> "sha-256"
    Sha512 -> "sha-512"
    Extension(key) -> key
  }
}

fn valid_weight(weight: Int) -> Bool {
  weight >= 0 && weight <= 10
}

fn from_structured_error(error: structured_fields.Error) -> Error {
  case error {
    structured_fields.Invalid -> Invalid
    structured_fields.LimitExceeded -> LimitExceeded
  }
}

@external(erlang, "http_digest_ffi", "hash")
fn hash_ffi(input: BitArray, algorithm: String) -> Result(BitArray, Nil)

@external(erlang, "http_digest_ffi", "secure_equal")
fn secure_equal(first: BitArray, second: BitArray) -> Bool
