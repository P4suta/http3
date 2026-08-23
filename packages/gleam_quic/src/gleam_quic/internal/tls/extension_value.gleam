//// Typed, bounded codecs for TLS 1.3 extensions used by QUIC.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/result

const maximum_list_entries = 64

/// A TLS protocol version carried by supported_versions.
pub type ProtocolVersion {
  Tls13
  Tls12
  UnknownVersion(Int)
}

/// A TLS named group.
pub type NamedGroup {
  Secp256r1
  Secp384r1
  X25519
  X448
  UnknownGroup(Int)
}

/// A TLS 1.3 signature scheme relevant to certificate authentication.
pub type SignatureScheme {
  EcdsaSecp256r1Sha256
  EcdsaSecp384r1Sha384
  EcdsaSecp521r1Sha512
  RsaPssRsaeSha256
  RsaPssRsaeSha384
  RsaPssRsaeSha512
  Ed25519
  Ed448
  RsaPssPssSha256
  RsaPssPssSha384
  RsaPssPssSha512
  UnknownSignatureScheme(Int)
}

/// One key_share entry.
pub type KeyShare {
  KeyShare(group: NamedGroup, key_exchange: BitArray)
}

/// A semantic extension-value failure.
pub type Error {
  NonByteAligned
  Truncated
  TrailingData
  InvalidLength
  TooManyEntries
  InvalidIdentifier(Int)
  DuplicateIdentifier(Int)
  DuplicateProtocol
  InvalidServerName
  EmptyProtocol
  Tls13Required
  InvalidKeyExchange
}

/// Encode one strict ASCII DNS hostname for the server_name extension.
pub fn encode_server_name(
  hostname hostname: String,
) -> Result(BitArray, Error) {
  let name = <<hostname:utf8>>
  let name_length = bit_array.byte_size(name)
  case valid_dns_name(name) && name_length <= 253 {
    False -> Error(InvalidServerName)
    True -> {
      let entry_length = name_length + 3
      Ok(<<entry_length:size(16), 0, name_length:size(16), name:bits>>)
    }
  }
}

/// Decode a server_name list containing exactly one host_name entry.
pub fn decode_server_name(bytes bytes: BitArray) -> Result(String, Error) {
  use list <- result.try(exact_vector16(bytes))
  case list {
    <<0, name_length:size(16), name:bits>> ->
      decode_server_name_bytes(name, name_length)
    _ -> Error(Truncated)
  }
}

/// Encode an ALPN ProtocolNameList.
pub fn encode_alpn(
  protocols protocols: List(BitArray),
) -> Result(BitArray, Error) {
  case protocols == [] || list.length(protocols) > maximum_list_entries {
    True -> Error(InvalidLength)
    False -> {
      use encoded <- result.try(encode_protocols(protocols, dict.new(), <<>>))
      let length = bit_array.byte_size(encoded)
      case length > 65_535 {
        True -> Error(InvalidLength)
        False -> Ok(<<length:size(16), encoded:bits>>)
      }
    }
  }
}

/// Decode an ALPN ProtocolNameList while preserving client preference order.
pub fn decode_alpn(bytes bytes: BitArray) -> Result(List(BitArray), Error) {
  use payload <- result.try(exact_vector16(bytes))
  decode_protocols(payload, dict.new(), 0, [])
}

/// Encode the ClientHello form of supported_versions.
pub fn encode_client_supported_versions(
  versions versions: List(ProtocolVersion),
) -> Result(BitArray, Error) {
  case has_tls13(versions) {
    False -> Error(Tls13Required)
    True -> {
      use encoded <- result.try(
        encode_u16_items(versions, version_to_wire, dict.new(), <<>>),
      )
      let length = bit_array.byte_size(encoded)
      case length > 255 {
        True -> Error(InvalidLength)
        False -> Ok(<<length, encoded:bits>>)
      }
    }
  }
}

/// Decode and require TLS 1.3 in ClientHello supported_versions.
pub fn decode_client_supported_versions(
  bytes bytes: BitArray,
) -> Result(List(ProtocolVersion), Error) {
  use payload <- result.try(exact_vector8(bytes))
  case
    bit_array.byte_size(payload) >= 2 && bit_array.byte_size(payload) % 2 == 0
  {
    False -> Error(InvalidLength)
    True -> {
      use versions <- result.try(
        decode_u16_items(payload, version_from_wire, dict.new(), 0, []),
      )
      case has_tls13(versions) {
        True -> Ok(versions)
        False -> Error(Tls13Required)
      }
    }
  }
}

/// Encode the ServerHello selected supported_version.
pub fn encode_server_supported_version(
  protocol_version protocol_version: ProtocolVersion,
) -> Result(BitArray, Error) {
  use identifier <- result.try(version_to_wire(protocol_version))
  Ok(<<identifier:size(16)>>)
}

/// Decode the ServerHello selected supported_version.
pub fn decode_server_supported_version(
  bytes bytes: BitArray,
) -> Result(ProtocolVersion, Error) {
  case bytes {
    <<identifier:size(16)>> -> Ok(version_from_wire(identifier))
    _ -> Error(InvalidLength)
  }
}

/// Encode a supported_groups extension value.
pub fn encode_supported_groups(
  groups groups: List(NamedGroup),
) -> Result(BitArray, Error) {
  use encoded <- result.try(
    encode_u16_items(groups, group_to_wire, dict.new(), <<>>),
  )
  vector16(encoded)
}

/// Decode a supported_groups extension value.
pub fn decode_supported_groups(
  bytes bytes: BitArray,
) -> Result(List(NamedGroup), Error) {
  use payload <- result.try(exact_vector16(bytes))
  case
    bit_array.byte_size(payload) >= 2 && bit_array.byte_size(payload) % 2 == 0
  {
    False -> Error(InvalidLength)
    True -> decode_u16_items(payload, group_from_wire, dict.new(), 0, [])
  }
}

/// Encode a signature_algorithms extension value.
pub fn encode_signature_schemes(
  schemes schemes: List(SignatureScheme),
) -> Result(BitArray, Error) {
  use encoded <- result.try(
    encode_u16_items(schemes, signature_to_wire, dict.new(), <<>>),
  )
  vector16(encoded)
}

/// Decode a signature_algorithms extension value.
pub fn decode_signature_schemes(
  bytes bytes: BitArray,
) -> Result(List(SignatureScheme), Error) {
  use payload <- result.try(exact_vector16(bytes))
  case
    bit_array.byte_size(payload) >= 2 && bit_array.byte_size(payload) % 2 == 0
  {
    False -> Error(InvalidLength)
    True -> decode_u16_items(payload, signature_from_wire, dict.new(), 0, [])
  }
}

/// Encode one signature scheme identifier.
pub fn encode_signature_scheme(
  scheme scheme: SignatureScheme,
) -> Result(BitArray, Error) {
  use identifier <- result.try(signature_to_wire(scheme))
  Ok(<<identifier:size(16)>>)
}

/// Decode one signature scheme identifier.
pub fn decode_signature_scheme(
  bytes bytes: BitArray,
) -> Result(SignatureScheme, Error) {
  case bytes {
    <<identifier:size(16)>> -> Ok(signature_from_wire(identifier))
    _ -> Error(InvalidLength)
  }
}

/// Encode the ClientHello key_share vector.
pub fn encode_client_key_shares(
  shares shares: List(KeyShare),
) -> Result(BitArray, Error) {
  case shares == [] || list.length(shares) > maximum_list_entries {
    True -> Error(InvalidLength)
    False -> {
      use encoded <- result.try(encode_key_shares(shares, dict.new(), <<>>))
      vector16(encoded)
    }
  }
}

/// Decode the ClientHello key_share vector.
pub fn decode_client_key_shares(
  bytes bytes: BitArray,
) -> Result(List(KeyShare), Error) {
  use payload <- result.try(exact_vector16(bytes))
  decode_key_shares(payload, dict.new(), 0, [])
}

/// Encode the ServerHello key_share entry.
pub fn encode_server_key_share(
  share share: KeyShare,
) -> Result(BitArray, Error) {
  encode_key_share(share)
}

/// Decode the ServerHello key_share entry.
pub fn decode_server_key_share(
  bytes bytes: BitArray,
) -> Result(KeyShare, Error) {
  use #(share, rest, _) <- result.try(decode_one_key_share(bytes))
  case rest {
    <<>> -> Ok(share)
    _ -> Error(TrailingData)
  }
}

/// Encode the HelloRetryRequest selected_group form of key_share.
pub fn encode_selected_group(
  group group: NamedGroup,
) -> Result(BitArray, Error) {
  use identifier <- result.try(group_to_wire(group))
  Ok(<<identifier:size(16)>>)
}

/// Decode the HelloRetryRequest selected_group form of key_share.
pub fn decode_selected_group(
  bytes bytes: BitArray,
) -> Result(NamedGroup, Error) {
  case bytes {
    <<identifier:size(16)>> -> Ok(group_from_wire(identifier))
    _ -> Error(InvalidLength)
  }
}

fn encode_protocols(
  protocols: List(BitArray),
  seen: Dict(BitArray, Nil),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case protocols {
    [] -> Ok(accumulator)
    [protocol, ..rest] -> {
      use Nil <- result.try(require_byte_aligned(protocol))
      let length = bit_array.byte_size(protocol)
      case length {
        0 -> Error(EmptyProtocol)
        length if length > 255 -> Error(InvalidLength)
        _ ->
          case dict.has_key(seen, protocol) {
            True -> Error(DuplicateProtocol)
            False ->
              encode_protocols(rest, dict.insert(seen, protocol, Nil), <<
                accumulator:bits,
                length,
                protocol:bits,
              >>)
          }
      }
    }
  }
}

fn decode_protocols(
  bytes: BitArray,
  seen: Dict(BitArray, Nil),
  count: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case bytes {
    <<>> ->
      case reversed {
        [] -> Error(InvalidLength)
        _ -> Ok(list.reverse(reversed))
      }
    <<0, _:bits>> -> Error(EmptyProtocol)
    <<length, rest:bits>> -> {
      use #(protocol, remaining) <- result.try(take(rest, length))
      decode_new_protocol(protocol, remaining, seen, count, reversed)
    }
    _ -> Error(Truncated)
  }
}

fn encode_u16_items(
  values: List(value),
  to_wire: fn(value) -> Result(Int, Error),
  seen: Dict(Int, Nil),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case values {
    [] ->
      case bit_array.byte_size(accumulator) > 0 {
        True -> Ok(accumulator)
        False -> Error(InvalidLength)
      }
    [value, ..rest] -> {
      use identifier <- result.try(to_wire(value))
      case dict.has_key(seen, identifier) {
        True -> Error(DuplicateIdentifier(identifier))
        False ->
          encode_u16_items(rest, to_wire, dict.insert(seen, identifier, Nil), <<
            accumulator:bits,
            identifier:size(16),
          >>)
      }
    }
  }
}

fn decode_u16_items(
  bytes: BitArray,
  from_wire: fn(Int) -> value,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(value),
) -> Result(List(value), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<identifier:size(16), rest:bits>> ->
      case dict.has_key(seen, identifier) {
        True -> Error(DuplicateIdentifier(identifier))
        False -> {
          let next_count = count + 1
          case next_count > maximum_list_entries {
            True -> Error(TooManyEntries)
            False ->
              decode_u16_items(
                rest,
                from_wire,
                dict.insert(seen, identifier, Nil),
                next_count,
                [from_wire(identifier), ..reversed],
              )
          }
        }
      }
    _ -> Error(Truncated)
  }
}

fn encode_key_shares(
  shares: List(KeyShare),
  seen: Dict(Int, Nil),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case shares {
    [] -> Ok(accumulator)
    [share, ..rest] -> {
      let KeyShare(group, _) = share
      use identifier <- result.try(group_to_wire(group))
      case dict.has_key(seen, identifier) {
        True -> Error(DuplicateIdentifier(identifier))
        False -> {
          use encoded <- result.try(encode_key_share(share))
          encode_key_shares(rest, dict.insert(seen, identifier, Nil), <<
            accumulator:bits,
            encoded:bits,
          >>)
        }
      }
    }
  }
}

fn encode_key_share(share: KeyShare) -> Result(BitArray, Error) {
  let KeyShare(group, key_exchange) = share
  use Nil <- result.try(require_byte_aligned(key_exchange))
  use identifier <- result.try(group_to_wire(group))
  let length = bit_array.byte_size(key_exchange)
  case valid_key_exchange(group, key_exchange) && length <= 65_535 {
    True -> Ok(<<identifier:size(16), length:size(16), key_exchange:bits>>)
    False -> Error(InvalidKeyExchange)
  }
}

fn decode_key_shares(
  bytes: BitArray,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(KeyShare),
) -> Result(List(KeyShare), Error) {
  case bytes {
    <<>> ->
      case reversed {
        [] -> Error(InvalidLength)
        _ -> Ok(list.reverse(reversed))
      }
    _ -> {
      use #(share, rest, identifier) <- result.try(decode_one_key_share(bytes))
      decode_new_key_share(share, rest, identifier, seen, count, reversed)
    }
  }
}

fn decode_server_name_bytes(
  name: BitArray,
  declared_length: Int,
) -> Result(String, Error) {
  case bit_array.byte_size(name) == declared_length && valid_dns_name(name) {
    False -> Error(InvalidServerName)
    True ->
      case bit_array.to_string(name) {
        Ok(hostname) -> Ok(hostname)
        Error(_) -> Error(InvalidServerName)
      }
  }
}

fn decode_new_protocol(
  protocol: BitArray,
  remaining: BitArray,
  seen: Dict(BitArray, Nil),
  count: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case dict.has_key(seen, protocol) {
    True -> Error(DuplicateProtocol)
    False -> {
      let next_count = count + 1
      case next_count > maximum_list_entries {
        True -> Error(TooManyEntries)
        False ->
          decode_protocols(
            remaining,
            dict.insert(seen, protocol, Nil),
            next_count,
            [protocol, ..reversed],
          )
      }
    }
  }
}

fn decode_new_key_share(
  share: KeyShare,
  rest: BitArray,
  identifier: Int,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(KeyShare),
) -> Result(List(KeyShare), Error) {
  case dict.has_key(seen, identifier) {
    True -> Error(DuplicateIdentifier(identifier))
    False -> {
      let next_count = count + 1
      case next_count > maximum_list_entries {
        True -> Error(TooManyEntries)
        False ->
          decode_key_shares(
            rest,
            dict.insert(seen, identifier, Nil),
            next_count,
            [share, ..reversed],
          )
      }
    }
  }
}

fn decode_one_key_share(
  bytes: BitArray,
) -> Result(#(KeyShare, BitArray, Int), Error) {
  case bytes {
    <<identifier:size(16), length:size(16), rest:bits>> -> {
      use #(key_exchange, remaining) <- result.try(take(rest, length))
      let group = group_from_wire(identifier)
      case valid_key_exchange(group, key_exchange) {
        True -> Ok(#(KeyShare(group, key_exchange), remaining, identifier))
        False -> Error(InvalidKeyExchange)
      }
    }
    _ -> Error(Truncated)
  }
}

fn valid_key_exchange(group: NamedGroup, key_exchange: BitArray) -> Bool {
  let length = bit_array.byte_size(key_exchange)
  case group, key_exchange {
    X25519, _ -> length == 32
    X448, _ -> length == 56
    Secp256r1, <<4, _:bits>> -> length == 65
    Secp384r1, <<4, _:bits>> -> length == 97
    UnknownGroup(_), _ -> length > 0
    _, _ -> False
  }
}

fn version_to_wire(version: ProtocolVersion) -> Result(Int, Error) {
  case version {
    Tls13 -> Ok(0x0304)
    Tls12 -> Ok(0x0303)
    UnknownVersion(identifier) -> validate_unknown(identifier, [0x0303, 0x0304])
  }
}

fn version_from_wire(identifier: Int) -> ProtocolVersion {
  case identifier {
    0x0304 -> Tls13
    0x0303 -> Tls12
    _ -> UnknownVersion(identifier)
  }
}

fn group_to_wire(group: NamedGroup) -> Result(Int, Error) {
  case group {
    Secp256r1 -> Ok(23)
    Secp384r1 -> Ok(24)
    X25519 -> Ok(29)
    X448 -> Ok(30)
    UnknownGroup(identifier) -> validate_unknown(identifier, [23, 24, 29, 30])
  }
}

fn group_from_wire(identifier: Int) -> NamedGroup {
  case identifier {
    23 -> Secp256r1
    24 -> Secp384r1
    29 -> X25519
    30 -> X448
    _ -> UnknownGroup(identifier)
  }
}

fn signature_to_wire(scheme: SignatureScheme) -> Result(Int, Error) {
  case scheme {
    EcdsaSecp256r1Sha256 -> Ok(0x0403)
    EcdsaSecp384r1Sha384 -> Ok(0x0503)
    EcdsaSecp521r1Sha512 -> Ok(0x0603)
    RsaPssRsaeSha256 -> Ok(0x0804)
    RsaPssRsaeSha384 -> Ok(0x0805)
    RsaPssRsaeSha512 -> Ok(0x0806)
    Ed25519 -> Ok(0x0807)
    Ed448 -> Ok(0x0808)
    RsaPssPssSha256 -> Ok(0x0809)
    RsaPssPssSha384 -> Ok(0x080a)
    RsaPssPssSha512 -> Ok(0x080b)
    UnknownSignatureScheme(identifier) ->
      validate_unknown(identifier, [
        0x0403,
        0x0503,
        0x0603,
        0x0804,
        0x0805,
        0x0806,
        0x0807,
        0x0808,
        0x0809,
        0x080a,
        0x080b,
      ])
  }
}

fn signature_from_wire(identifier: Int) -> SignatureScheme {
  case identifier {
    0x0403 -> EcdsaSecp256r1Sha256
    0x0503 -> EcdsaSecp384r1Sha384
    0x0603 -> EcdsaSecp521r1Sha512
    0x0804 -> RsaPssRsaeSha256
    0x0805 -> RsaPssRsaeSha384
    0x0806 -> RsaPssRsaeSha512
    0x0807 -> Ed25519
    0x0808 -> Ed448
    0x0809 -> RsaPssPssSha256
    0x080a -> RsaPssPssSha384
    0x080b -> RsaPssPssSha512
    _ -> UnknownSignatureScheme(identifier)
  }
}

fn validate_unknown(identifier: Int, known: List(Int)) -> Result(Int, Error) {
  case
    identifier >= 0 && identifier <= 65_535 && !list.contains(known, identifier)
  {
    True -> Ok(identifier)
    False -> Error(InvalidIdentifier(identifier))
  }
}

fn has_tls13(versions: List(ProtocolVersion)) -> Bool {
  list.contains(versions, Tls13)
}

fn vector16(payload: BitArray) -> Result(BitArray, Error) {
  let length = bit_array.byte_size(payload)
  case length > 0 && length <= 65_535 {
    True -> Ok(<<length:size(16), payload:bits>>)
    False -> Error(InvalidLength)
  }
}

fn exact_vector16(bytes: BitArray) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(bytes))
  case bytes {
    <<length:size(16), payload:bits>> ->
      case bit_array.byte_size(payload) == length {
        True -> Ok(payload)
        False -> Error(Truncated)
      }
    _ -> Error(Truncated)
  }
}

fn exact_vector8(bytes: BitArray) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(bytes))
  case bytes {
    <<length, payload:bits>> ->
      case bit_array.byte_size(payload) == length {
        True -> Ok(payload)
        False -> Error(Truncated)
      }
    _ -> Error(Truncated)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(Truncated)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn require_byte_aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 == 0 {
    True -> Ok(Nil)
    False -> Error(NonByteAligned)
  }
}

fn valid_dns_name(bytes: BitArray) -> Bool {
  case bit_array.byte_size(bytes) > 0 && bit_array.byte_size(bytes) <= 253 {
    False -> False
    True -> valid_dns_bytes(bytes, 0, False)
  }
}

fn valid_dns_bytes(
  bytes: BitArray,
  label_length: Int,
  previous_hyphen: Bool,
) -> Bool {
  case bytes {
    <<>> -> label_length > 0 && !previous_hyphen
    <<46, rest:bits>> ->
      label_length > 0
      && label_length <= 63
      && !previous_hyphen
      && rest != <<>>
      && valid_dns_bytes(rest, 0, False)
    <<byte, rest:bits>> ->
      case dns_character(byte), label_length == 0 && byte == 45 {
        False, _ -> False
        _, True -> False
        True, False ->
          label_length < 63
          && valid_dns_bytes(rest, label_length + 1, byte == 45)
      }
    _ -> False
  }
}

fn dns_character(byte: Int) -> Bool {
  byte >= 65
  && byte <= 90
  || byte >= 97
  && byte <= 122
  || byte >= 48
  && byte <= 57
  || byte == 45
}
