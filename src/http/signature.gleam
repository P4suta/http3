//// Profile-driven RFC 9421 HTTP Message Signatures.
////
//// This module implements strict message canonicalization, Signature-Input
//// and Signature wire fields, HMAC-SHA256 signing, bounded verification, and
//// a finite immutable nonce replay store. Applications must select a profile
//// explicitly; signing is never enabled by a default client policy.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/structured_fields

const maximum_components = 32

const maximum_field_bytes = 1_048_576

const minimum_hmac_key_bytes = 32

const maximum_hmac_key_bytes = 4096

/// One normalized HTTP field line. Repeated names remain separate and are
/// combined in their original order during signature-base construction.
pub type Header {
  Header(name: String, value: String)
}

/// The message metadata available to the signer and verifier.
pub type Message {
  RequestMessage(
    method: String,
    scheme: String,
    authority: String,
    path: String,
    query: Option(String),
    headers: List(Header),
  )
  ResponseMessage(status: Int, headers: List(Header))
}

/// Supported unparameterized HTTP message components.
///
/// RFC component parameters (`sf`, `key`, `bs`, `req`, and `tr`) are rejected
/// rather than partially canonicalized by this profile implementation.
pub type Component {
  Field(name: String)
  Method
  Scheme
  Authority
  Path
  Query
  Status
}

/// Registered signature algorithms. Only HMAC-SHA256 key material is accepted
/// by this module's current signer; all names can be parsed without confusion.
pub type Algorithm {
  HmacSha256
  RsaPssSha512
  RsaV15Sha256
  EcdsaP256Sha256
  EcdsaP384Sha384
  Ed25519
  Extension(name: String)
}

/// Ordered RFC 9421 signature metadata.
pub type Parameters {
  Parameters(
    created: Int,
    expires: Option(Int),
    nonce: Option(String),
    algorithm: Option(Algorithm),
    key_id: String,
    tag: Option(String),
    extensions: List(structured_fields.Parameter),
  )
}

/// One labelled Signature-Input member.
pub type SignatureInput {
  SignatureInput(
    label: String,
    components: List(Component),
    parameters: Parameters,
  )
}

/// The two complete HTTP field values emitted by a signer.
pub type SignedFields {
  SignedFields(signature_input: String, signature: String)
}

/// An application-selected verification profile.
pub opaque type Profile {
  Profile(
    required_components: List(Component),
    maximum_age_seconds: Int,
    clock_skew_seconds: Int,
    require_nonce: Bool,
    authority: Option(String),
    tag: Option(String),
  )
}

/// Validated symmetric key material.
pub opaque type HmacKey {
  HmacKey(value: BitArray)
}

type ReplayEntry {
  ReplayEntry(key_id: String, nonce: String, expires: Int)
}

/// Finite immutable nonce state. Callers must retain the store returned by a
/// successful verification before admitting the authenticated operation.
pub opaque type ReplayStore {
  ReplayStore(maximum_entries: Int, entries: List(ReplayEntry))
}

type ParameterParts {
  ParameterParts(
    created: Option(Int),
    expires: Option(Int),
    nonce: Option(String),
    algorithm: Option(Algorithm),
    key_id: Option(String),
    tag: Option(String),
    extensions: List(structured_fields.Parameter),
  )
}

/// Syntax, canonicalization, policy, time, replay, or crypto failure.
pub type Error {
  Invalid
  InvalidMessage
  InvalidProfile
  InvalidKey
  LimitExceeded
  MissingComponent
  PolicyViolation
  AuthorityMismatch
  NotYetValid
  Expired
  ReplayDetected
  ReplayStoreFull
  UnsupportedAlgorithm
  SignatureMismatch
  CryptoFailure
}

/// Construct an explicit finite application profile.
pub fn profile(
  required_components required_components: List(Component),
  maximum_age_seconds maximum_age_seconds: Int,
) -> Result(Profile, Error) {
  case
    required_components != [],
    list.length(required_components) <= maximum_components,
    maximum_age_seconds > 0,
    components_unique(required_components),
    list.all(required_components, valid_component)
  {
    True, True, True, True, True ->
      Ok(Profile(
        required_components: required_components,
        maximum_age_seconds: maximum_age_seconds,
        clock_skew_seconds: 0,
        require_nonce: False,
        authority: None,
        tag: None,
      ))
    _, _, _, _, _ -> Error(InvalidProfile)
  }
}

/// Allow a finite amount of clock skew in both timestamp directions.
pub fn with_clock_skew(profile: Profile, seconds: Int) -> Profile {
  Profile(..profile, clock_skew_seconds: seconds)
}

/// Require every accepted signature to carry a non-empty nonce.
pub fn with_required_nonce(profile: Profile, required: Bool) -> Profile {
  Profile(..profile, require_nonce: required)
}

/// Bind a request profile to one exact lowercase service authority.
pub fn for_authority(profile: Profile, authority: String) -> Profile {
  Profile(..profile, authority: Some(authority))
}

/// Bind a profile to an exact application-specific tag.
pub fn for_tag(profile: Profile, tag: String) -> Profile {
  Profile(..profile, tag: Some(tag))
}

/// Validate HMAC key bytes. Short keys are rejected before crypto is invoked.
pub fn hmac_key(value: BitArray) -> Result(HmacKey, Error) {
  case
    bit_array.bit_size(value) % 8,
    bit_array.byte_size(value) >= minimum_hmac_key_bytes,
    bit_array.byte_size(value) <= maximum_hmac_key_bytes
  {
    0, True, True -> Ok(HmacKey(value))
    _, _, _ -> Error(InvalidKey)
  }
}

/// Allocate an empty finite replay store.
pub fn replay_store(maximum_entries: Int) -> Result(ReplayStore, Error) {
  case maximum_entries > 0 {
    True -> Ok(ReplayStore(maximum_entries: maximum_entries, entries: []))
    False -> Error(InvalidProfile)
  }
}

/// Construct the exact RFC 9421 signature base under an explicit profile.
pub fn signature_base(
  message message: Message,
  input input: SignatureInput,
  profile profile: Profile,
) -> Result(String, Error) {
  use _ <- result.try(validate_profile(profile))
  use _ <- result.try(validate_message(message))
  use _ <- result.try(validate_input(message, input, profile))
  use component_lines <- result.try(
    list.try_map(input.components, fn(component) {
      use identifier <- result.try(component_identifier(component))
      use value <- result.try(component_value(message, component))
      Ok(identifier <> ": " <> value)
    }),
  )
  use parameters <- result.try(serialize_parameters_value(input))
  let parameter_line = "\"@signature-params\": " <> parameters
  Ok(string.join(list.append(component_lines, [parameter_line]), with: "\n"))
}

/// Sign one labelled input with RFC 9421 HMAC-SHA256.
pub fn sign(
  message message: Message,
  input input: SignatureInput,
  key key: HmacKey,
  profile profile: Profile,
) -> Result(SignedFields, Error) {
  use base <- result.try(signature_base(
    message: message,
    input: input,
    profile: profile,
  ))
  use _ <- result.try(require_hmac(input.parameters.algorithm))
  use input_field <- result.try(serialize_input(input))
  use signature <- result.try(
    hmac_sha256(bit_array.from_string(base), key.value)
    |> result.replace_error(CryptoFailure),
  )
  use signature_field <- result.try(serialize_signature(input.label, signature))
  Ok(SignedFields(signature_input: input_field, signature: signature_field))
}

/// Parse, policy-check, and authenticate one labelled signature, returning the
/// replay store update that must be retained atomically with admission.
pub fn verify(
  message message: Message,
  fields fields: SignedFields,
  key key: HmacKey,
  now now: Int,
  profile profile: Profile,
  replay replay: ReplayStore,
) -> Result(ReplayStore, Error) {
  use _ <- result.try(validate_profile(profile))
  use inputs <- result.try(parse_inputs(fields.signature_input))
  use signatures <- result.try(parse_signatures(fields.signature))
  use #(input, signature) <- result.try(single_matching_signature(
    inputs,
    signatures,
  ))
  use _ <- result.try(validate_time(input.parameters, now, profile))
  use base <- result.try(signature_base(
    message: message,
    input: input,
    profile: profile,
  ))
  use _ <- result.try(require_hmac(input.parameters.algorithm))
  use expected <- result.try(
    hmac_sha256(bit_array.from_string(base), key.value)
    |> result.replace_error(CryptoFailure),
  )
  use _ <- result.try(case secure_equal(expected, signature) {
    True -> Ok(Nil)
    False -> Error(SignatureMismatch)
  })
  consume_nonce(replay, input.parameters, now, profile)
}

/// Parse all labelled Signature-Input members with strict supported component
/// semantics. Component parameters are rejected.
pub fn parse_inputs(value: String) -> Result(List(SignatureInput), Error) {
  use _ <- result.try(limit_field(value))
  use members <- result.try(
    structured_fields.parse_dictionary(value)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, parse_input_member)
}

/// Serialize a single labelled Signature-Input dictionary member.
pub fn serialize_input(input: SignatureInput) -> Result(String, Error) {
  use member <- result.try(input_member(input))
  structured_fields.serialize_dictionary([member])
  |> result.map_error(from_structured_error)
}

fn parse_input_member(
  member: structured_fields.DictionaryMember,
) -> Result(SignatureInput, Error) {
  let structured_fields.DictionaryMember(label, value) = member
  case value {
    structured_fields.InnerList(items, parameters) -> {
      use components <- result.try(list.try_map(items, parse_component_item))
      use parameters <- result.try(parse_parameters(parameters))
      let input = SignatureInput(label, components, parameters)
      use _ <- result.try(
        case
          components != [],
          list.length(components) <= maximum_components,
          components_unique(components)
        {
          True, True, True -> Ok(Nil)
          _, _, _ -> Error(Invalid)
        },
      )
      Ok(input)
    }
    _ -> Error(Invalid)
  }
}

fn input_member(
  input: SignatureInput,
) -> Result(structured_fields.DictionaryMember, Error) {
  use _ <- result.try(
    case
      input.components != [],
      list.length(input.components) <= maximum_components,
      components_unique(input.components)
    {
      True, True, True -> Ok(Nil)
      _, _, _ -> Error(Invalid)
    },
  )
  use items <- result.try(list.try_map(input.components, component_item))
  use parameters <- result.try(parameters_list(input.parameters))
  Ok(structured_fields.DictionaryMember(
    input.label,
    structured_fields.InnerList(items, parameters),
  ))
}

fn parse_signatures(value: String) -> Result(List(#(String, BitArray)), Error) {
  use _ <- result.try(limit_field(value))
  use members <- result.try(
    structured_fields.parse_dictionary(value)
    |> result.map_error(from_structured_error),
  )
  list.try_map(members, fn(member) {
    let structured_fields.DictionaryMember(label, value) = member
    case value {
      structured_fields.ListItem(structured_fields.Item(
        structured_fields.ByteSequence(signature),
        [],
      )) -> Ok(#(label, signature))
      _ -> Error(Invalid)
    }
  })
}

fn serialize_signature(
  label: String,
  signature: BitArray,
) -> Result(String, Error) {
  structured_fields.serialize_dictionary([
    structured_fields.DictionaryMember(
      label,
      structured_fields.ListItem(
        structured_fields.Item(structured_fields.ByteSequence(signature), []),
      ),
    ),
  ])
  |> result.map_error(from_structured_error)
}

fn single_matching_signature(
  inputs: List(SignatureInput),
  signatures: List(#(String, BitArray)),
) -> Result(#(SignatureInput, BitArray), Error) {
  case inputs {
    [input] ->
      case signatures {
        [#(label, signature)] if label == input.label -> Ok(#(input, signature))
        _ -> Error(Invalid)
      }
    _ -> Error(Invalid)
  }
}

fn validate_profile(profile: Profile) -> Result(Nil, Error) {
  case
    profile.required_components != [],
    list.length(profile.required_components) <= maximum_components,
    profile.maximum_age_seconds > 0,
    profile.clock_skew_seconds >= 0,
    components_unique(profile.required_components),
    list.all(profile.required_components, valid_component),
    valid_optional_text(profile.authority),
    valid_optional_text(profile.tag)
  {
    True, True, True, True, True, True, True, True -> Ok(Nil)
    _, _, _, _, _, _, _, _ -> Error(InvalidProfile)
  }
}

fn validate_input(
  message: Message,
  input: SignatureInput,
  profile: Profile,
) -> Result(Nil, Error) {
  use _ <- result.try(
    case
      input.components != [],
      list.length(input.components) <= maximum_components,
      components_unique(input.components),
      list.all(input.components, valid_component),
      list.all(profile.required_components, fn(component) {
        list.contains(input.components, component)
      })
    {
      True, True, True, True, True -> Ok(Nil)
      True, True, True, True, False -> Error(PolicyViolation)
      _, _, _, _, _ -> Error(Invalid)
    },
  )
  use _ <- result.try(validate_parameters(input.parameters))
  use _ <- result.try(validate_authority(message, input.components, profile))
  validate_tag(input.parameters.tag, profile.tag)
}

fn validate_parameters(parameters: Parameters) -> Result(Nil, Error) {
  case
    parameters.created >= 0,
    parameters.key_id != "",
    valid_optional_text(parameters.nonce),
    valid_optional_text(parameters.tag),
    optional_expiry_valid(parameters.expires, parameters.created)
  {
    True, True, True, True, True -> Ok(Nil)
    _, _, _, _, _ -> Error(Invalid)
  }
}

fn validate_authority(
  message: Message,
  components: List(Component),
  profile: Profile,
) -> Result(Nil, Error) {
  case profile.authority {
    None -> Ok(Nil)
    Some(expected) ->
      case message, list.contains(components, Authority) {
        RequestMessage(authority: actual, ..), True
          if actual == expected && expected != ""
        -> Ok(Nil)
        _, _ -> Error(AuthorityMismatch)
      }
  }
}

fn validate_tag(
  actual: Option(String),
  expected: Option(String),
) -> Result(Nil, Error) {
  case expected {
    None -> Ok(Nil)
    Some(expected) ->
      case actual {
        Some(actual) if actual == expected -> Ok(Nil)
        _ -> Error(PolicyViolation)
      }
  }
}

fn validate_time(
  parameters: Parameters,
  now: Int,
  profile: Profile,
) -> Result(Nil, Error) {
  use _ <- result.try(
    case parameters.created <= now + profile.clock_skew_seconds {
      True -> Ok(Nil)
      False -> Error(NotYetValid)
    },
  )
  use _ <- result.try(
    case
      now - parameters.created
      <= profile.maximum_age_seconds + profile.clock_skew_seconds
    {
      True -> Ok(Nil)
      False -> Error(Expired)
    },
  )
  use _ <- result.try(case parameters.expires {
    None -> Ok(Nil)
    Some(expires) ->
      case now <= expires + profile.clock_skew_seconds {
        True -> Ok(Nil)
        False -> Error(Expired)
      }
  })
  case profile.require_nonce, parameters.nonce {
    True, Some(nonce) if nonce != "" -> Ok(Nil)
    True, _ -> Error(PolicyViolation)
    False, _ -> Ok(Nil)
  }
}

fn consume_nonce(
  store: ReplayStore,
  parameters: Parameters,
  now: Int,
  profile: Profile,
) -> Result(ReplayStore, Error) {
  case parameters.nonce {
    None -> Ok(store)
    Some(nonce) -> {
      let entries =
        list.filter(store.entries, fn(entry) {
          entry.expires + profile.clock_skew_seconds >= now
        })
      case
        list.any(entries, fn(entry) {
          entry.key_id == parameters.key_id && entry.nonce == nonce
        })
      {
        True -> Error(ReplayDetected)
        False ->
          case list.length(entries) < store.maximum_entries {
            False -> Error(ReplayStoreFull)
            True -> {
              let expires = case parameters.expires {
                Some(expires) -> expires
                None -> parameters.created + profile.maximum_age_seconds
              }
              Ok(
                ReplayStore(..store, entries: [
                  ReplayEntry(parameters.key_id, nonce, expires),
                  ..entries
                ]),
              )
            }
          }
      }
    }
  }
}

fn validate_message(message: Message) -> Result(Nil, Error) {
  case message {
    RequestMessage(method, scheme, authority, path, query, headers) ->
      case
        valid_token(method),
        scheme != "" && string.lowercase(scheme) == scheme,
        valid_authority(authority),
        path == "*" || string.starts_with(path, "/"),
        valid_query(query),
        valid_headers(headers)
      {
        True, True, True, True, True, True -> Ok(Nil)
        _, _, _, _, _, _ -> Error(InvalidMessage)
      }
    ResponseMessage(status, headers) ->
      case status >= 100 && status <= 599, valid_headers(headers) {
        True, True -> Ok(Nil)
        _, _ -> Error(InvalidMessage)
      }
  }
}

fn component_value(
  message: Message,
  component: Component,
) -> Result(String, Error) {
  case component, message {
    Field(name), RequestMessage(headers: headers, ..) ->
      header_value(headers, name)
    Field(name), ResponseMessage(headers: headers, ..) ->
      header_value(headers, name)
    Method, RequestMessage(method: method, ..) -> Ok(method)
    Scheme, RequestMessage(scheme: scheme, ..) -> Ok(scheme)
    Authority, RequestMessage(authority: authority, ..) -> Ok(authority)
    Path, RequestMessage(path: "", ..) -> Ok("/")
    Path, RequestMessage(path: path, ..) -> Ok(path)
    Query, RequestMessage(query: None, ..) -> Ok("?")
    Query, RequestMessage(query: Some(query), ..) -> Ok(query)
    Status, ResponseMessage(status: status, ..) -> Ok(int.to_string(status))
    _, _ -> Error(MissingComponent)
  }
}

fn header_value(headers: List(Header), name: String) -> Result(String, Error) {
  let values = matching_header_values(headers, string.lowercase(name), [])
  case values {
    [] -> Error(MissingComponent)
    _ -> Ok(string.join(list.reverse(values), with: ", "))
  }
}

fn matching_header_values(
  headers: List(Header),
  name: String,
  reversed: List(String),
) -> List(String) {
  case headers {
    [] -> reversed
    [Header(header_name, value), ..rest] -> {
      let reversed = case string.lowercase(header_name) == name {
        True -> [trim_ows(value), ..reversed]
        False -> reversed
      }
      matching_header_values(rest, name, reversed)
    }
  }
}

fn component_identifier(component: Component) -> Result(String, Error) {
  structured_fields.serialize_item(
    structured_fields.Item(
      structured_fields.StringValue(component_name(component)),
      [],
    ),
  )
  |> result.map_error(from_structured_error)
}

fn component_item(
  component: Component,
) -> Result(structured_fields.Item, Error) {
  use _ <- result.try(case valid_component(component) {
    True -> Ok(Nil)
    False -> Error(Invalid)
  })
  Ok(
    structured_fields.Item(
      structured_fields.StringValue(component_name(component)),
      [],
    ),
  )
}

fn parse_component_item(
  item: structured_fields.Item,
) -> Result(Component, Error) {
  case item {
    structured_fields.Item(structured_fields.StringValue(name), []) ->
      component_from_name(name)
    _ -> Error(Invalid)
  }
}

fn component_name(component: Component) -> String {
  case component {
    Field(name) -> name
    Method -> "@method"
    Scheme -> "@scheme"
    Authority -> "@authority"
    Path -> "@path"
    Query -> "@query"
    Status -> "@status"
  }
}

fn component_from_name(name: String) -> Result(Component, Error) {
  case name {
    "@method" -> Ok(Method)
    "@scheme" -> Ok(Scheme)
    "@authority" -> Ok(Authority)
    "@path" -> Ok(Path)
    "@query" -> Ok(Query)
    "@status" -> Ok(Status)
    name ->
      case valid_field_name(name) && string.lowercase(name) == name {
        True -> Ok(Field(name))
        False -> Error(Invalid)
      }
  }
}

fn valid_component(component: Component) -> Bool {
  case component {
    Field(name) -> valid_field_name(name) && string.lowercase(name) == name
    _ -> True
  }
}

fn components_unique(components: List(Component)) -> Bool {
  components_unique_loop(components, [])
}

fn components_unique_loop(
  components: List(Component),
  seen: List(Component),
) -> Bool {
  case components {
    [] -> True
    [component, ..rest] ->
      case list.contains(seen, component) {
        True -> False
        False -> components_unique_loop(rest, [component, ..seen])
      }
  }
}

fn serialize_parameters_value(input: SignatureInput) -> Result(String, Error) {
  use items <- result.try(list.try_map(input.components, component_item))
  use parameters <- result.try(parameters_list(input.parameters))
  structured_fields.serialize_list([
    structured_fields.InnerList(items, parameters),
  ])
  |> result.map_error(from_structured_error)
}

fn parameters_list(
  parameters: Parameters,
) -> Result(List(structured_fields.Parameter), Error) {
  use _ <- result.try(validate_parameters(parameters))
  let values = [
    structured_fields.Parameter(
      "created",
      structured_fields.Integer(parameters.created),
    ),
  ]
  let values = add_optional_integer(values, "expires", parameters.expires)
  let values = add_optional_string(values, "nonce", parameters.nonce)
  let values = add_optional_algorithm(values, parameters.algorithm)
  let values =
    list.append(values, [
      structured_fields.Parameter(
        "keyid",
        structured_fields.StringValue(parameters.key_id),
      ),
    ])
  let values = add_optional_string(values, "tag", parameters.tag)
  Ok(list.append(values, parameters.extensions))
}

fn parse_parameters(
  values: List(structured_fields.Parameter),
) -> Result(Parameters, Error) {
  use parts <- result.try(parse_parameter_values(
    values,
    ParameterParts(None, None, None, None, None, None, []),
  ))
  case parts.created, parts.key_id {
    Some(created), Some(key_id) -> {
      let parameters =
        Parameters(
          created: created,
          expires: parts.expires,
          nonce: parts.nonce,
          algorithm: parts.algorithm,
          key_id: key_id,
          tag: parts.tag,
          extensions: list.reverse(parts.extensions),
        )
      use _ <- result.try(validate_parameters(parameters))
      Ok(parameters)
    }
    _, _ -> Error(Invalid)
  }
}

fn parse_parameter_values(
  values: List(structured_fields.Parameter),
  parts: ParameterParts,
) -> Result(ParameterParts, Error) {
  case values {
    [] -> Ok(parts)
    [parameter, ..rest] -> {
      let structured_fields.Parameter(name, value) = parameter
      use parts <- result.try(case name, value {
        "created", structured_fields.Integer(value) ->
          Ok(ParameterParts(..parts, created: Some(value)))
        "expires", structured_fields.Integer(value) ->
          Ok(ParameterParts(..parts, expires: Some(value)))
        "nonce", structured_fields.StringValue(value) ->
          Ok(ParameterParts(..parts, nonce: Some(value)))
        "alg", structured_fields.StringValue(value) ->
          Ok(ParameterParts(..parts, algorithm: Some(algorithm(value))))
        "keyid", structured_fields.StringValue(value) ->
          Ok(ParameterParts(..parts, key_id: Some(value)))
        "tag", structured_fields.StringValue(value) ->
          Ok(ParameterParts(..parts, tag: Some(value)))
        name, _ ->
          case registered_parameter(name) {
            True -> Error(Invalid)
            False ->
              Ok(
                ParameterParts(..parts, extensions: [
                  parameter,
                  ..parts.extensions
                ]),
              )
          }
      })
      parse_parameter_values(rest, parts)
    }
  }
}

fn add_optional_integer(
  values: List(structured_fields.Parameter),
  name: String,
  value: Option(Int),
) -> List(structured_fields.Parameter) {
  case value {
    None -> values
    Some(value) ->
      list.append(values, [
        structured_fields.Parameter(name, structured_fields.Integer(value)),
      ])
  }
}

fn add_optional_string(
  values: List(structured_fields.Parameter),
  name: String,
  value: Option(String),
) -> List(structured_fields.Parameter) {
  case value {
    None -> values
    Some(value) ->
      list.append(values, [
        structured_fields.Parameter(name, structured_fields.StringValue(value)),
      ])
  }
}

fn add_optional_algorithm(
  values: List(structured_fields.Parameter),
  value: Option(Algorithm),
) -> List(structured_fields.Parameter) {
  case value {
    None -> values
    Some(value) ->
      list.append(values, [
        structured_fields.Parameter(
          "alg",
          structured_fields.StringValue(algorithm_name(value)),
        ),
      ])
  }
}

fn algorithm(name: String) -> Algorithm {
  case name {
    "hmac-sha256" -> HmacSha256
    "rsa-pss-sha512" -> RsaPssSha512
    "rsa-v1_5-sha256" -> RsaV15Sha256
    "ecdsa-p256-sha256" -> EcdsaP256Sha256
    "ecdsa-p384-sha384" -> EcdsaP384Sha384
    "ed25519" -> Ed25519
    name -> Extension(name)
  }
}

fn algorithm_name(algorithm: Algorithm) -> String {
  case algorithm {
    HmacSha256 -> "hmac-sha256"
    RsaPssSha512 -> "rsa-pss-sha512"
    RsaV15Sha256 -> "rsa-v1_5-sha256"
    EcdsaP256Sha256 -> "ecdsa-p256-sha256"
    EcdsaP384Sha384 -> "ecdsa-p384-sha384"
    Ed25519 -> "ed25519"
    Extension(name) -> name
  }
}

fn require_hmac(algorithm: Option(Algorithm)) -> Result(Nil, Error) {
  case algorithm {
    None | Some(HmacSha256) -> Ok(Nil)
    _ -> Error(UnsupportedAlgorithm)
  }
}

fn registered_parameter(name: String) -> Bool {
  list.contains(["created", "expires", "nonce", "alg", "keyid", "tag"], name)
}

fn optional_expiry_valid(value: Option(Int), created: Int) -> Bool {
  case value {
    None -> True
    Some(expires) -> expires >= created
  }
}

fn valid_optional_text(value: Option(String)) -> Bool {
  case value {
    None -> True
    Some(value) ->
      value != ""
      && !string.contains(value, "\r")
      && !string.contains(value, "\n")
      && !string.contains(value, "\u{0000}")
  }
}

fn valid_query(query: Option(String)) -> Bool {
  case query {
    None -> True
    Some(query) ->
      string.starts_with(query, "?")
      && !string.contains(query, "\r")
      && !string.contains(query, "\n")
      && !string.contains(query, "\u{0000}")
  }
}

fn valid_authority(authority: String) -> Bool {
  authority != ""
  && !string.contains(authority, " ")
  && !string.contains(authority, "\t")
  && !string.contains(authority, "\r")
  && !string.contains(authority, "\n")
  && !string.contains(authority, "\u{0000}")
  && !string.contains(authority, "/")
}

fn valid_headers(headers: List(Header)) -> Bool {
  list.length(headers) <= 4096
  && list.all(headers, fn(header) {
    valid_field_name(header.name)
    && string.byte_size(header.value) <= maximum_field_bytes
    && !string.contains(header.value, "\r")
    && !string.contains(header.value, "\n")
    && !string.contains(header.value, "\u{0000}")
  })
}

fn valid_field_name(name: String) -> Bool {
  name != "" && valid_token(name)
}

fn valid_token(value: String) -> Bool {
  valid_token_bytes(bit_array.from_string(value))
}

fn valid_token_bytes(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True -> valid_token_bytes(rest)
        False -> False
      }
    _ -> False
  }
}

fn token_byte(byte: Int) -> Bool {
  byte >= 0x30
  && byte <= 0x39
  || byte >= 0x41
  && byte <= 0x5a
  || byte >= 0x61
  && byte <= 0x7a
  || list.contains(
    [
      0x21,
      0x23,
      0x24,
      0x25,
      0x26,
      0x27,
      0x2a,
      0x2b,
      0x2d,
      0x2e,
      0x5e,
      0x5f,
      0x60,
      0x7c,
      0x7e,
    ],
    byte,
  )
}

fn trim_ows(value: String) -> String {
  let bytes = value |> bit_array.from_string |> discard_leading_ows
  let reversed = reverse_bytes(bytes, []) |> discard_leading_byte_ows
  reversed
  |> list.reverse
  |> bit_array.concat
  |> bit_array.to_string
  |> result.unwrap(value)
}

fn discard_leading_ows(value: BitArray) -> BitArray {
  case value {
    <<byte, rest:bits>> if byte == 0x20 || byte == 0x09 ->
      discard_leading_ows(rest)
    _ -> value
  }
}

fn reverse_bytes(value: BitArray, reversed: List(BitArray)) -> List(BitArray) {
  case value {
    <<>> -> reversed
    <<byte, rest:bits>> -> reverse_bytes(rest, [<<byte>>, ..reversed])
    _ -> reversed
  }
}

fn discard_leading_byte_ows(value: List(BitArray)) -> List(BitArray) {
  case value {
    [<<byte>>, ..rest] if byte == 0x20 || byte == 0x09 ->
      discard_leading_byte_ows(rest)
    _ -> value
  }
}

fn limit_field(value: String) -> Result(Nil, Error) {
  case string.byte_size(value) <= maximum_field_bytes {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  }
}

fn from_structured_error(error: structured_fields.Error) -> Error {
  case error {
    structured_fields.Invalid -> Invalid
    structured_fields.LimitExceeded -> LimitExceeded
  }
}

@external(erlang, "http_signature_ffi", "hmac_sha256")
fn hmac_sha256(input: BitArray, key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "http_signature_ffi", "secure_equal")
fn secure_equal(first: BitArray, second: BitArray) -> Bool
