//// Strict TLS 1.3 PSK extension codecs and transcript-bound binders.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/key_schedule

const maximum_identities = 16

const maximum_modes = 16

/// A TLS 1.3 PSK key-exchange mode.
pub type Mode {
  PskKe
  PskDheKe
}

/// One opaque ticket identity and its modulo-2^32 ticket age.
pub type Identity {
  Identity(identity: BitArray, obfuscated_ticket_age: Int)
}

/// The ClientHello pre_shared_key extension value.
pub type Offered {
  Offered(identities: List(Identity), binders: List(BitArray))
}

/// A malformed PSK extension or binder operation.
pub type Error {
  NonByteAligned
  Truncated
  TrailingData
  InvalidLength
  TooManyEntries
  InvalidMode(Int)
  DuplicateMode(Int)
  InvalidIdentity
  DuplicateIdentity
  InvalidTicketAge
  InvalidBinder
  MismatchedBinders
  BindersNotAtEnd
  CryptoFailure(crypto.Error)
  AuthenticationFailure(authentication.Error)
}

/// Encode the psk_key_exchange_modes vector.
pub fn encode_modes(modes modes: List(Mode)) -> Result(BitArray, Error) {
  case modes == [] || list.length(modes) > maximum_modes {
    True -> Error(InvalidLength)
    False -> {
      use encoded <- result.try(encode_mode_items(modes, [], <<>>))
      let length = bit_array.byte_size(encoded)
      Ok(<<length, encoded:bits>>)
    }
  }
}

/// Decode a strict psk_key_exchange_modes vector.
pub fn decode_modes(bytes bytes: BitArray) -> Result(List(Mode), Error) {
  use Nil <- result.try(require_byte_aligned(bytes))
  case bytes {
    <<length, payload:bits>> ->
      case
        length > 0
        && length <= maximum_modes
        && bit_array.byte_size(payload) == length
      {
        True -> decode_mode_items(payload, [], [])
        False -> Error(InvalidLength)
      }
    _ -> Error(Truncated)
  }
}

/// Encode a ClientHello pre_shared_key extension value.
pub fn encode_offered(offered offered: Offered) -> Result(BitArray, Error) {
  let Offered(identities, binders) = offered
  use Nil <- result.try(validate_counts(identities, binders))
  use encoded_identities <- result.try(
    encode_identities(identities, dict.new(), <<>>),
  )
  use encoded_binders <- result.try(encode_binder_items(binders, <<>>))
  let identities_length = bit_array.byte_size(encoded_identities)
  let binders_length = bit_array.byte_size(encoded_binders)
  case identities_length <= 65_535 && binders_length <= 65_535 {
    True ->
      Ok(<<
        identities_length:size(16),
        encoded_identities:bits,
        binders_length:size(16),
        encoded_binders:bits,
      >>)
    False -> Error(InvalidLength)
  }
}

// nolint: deep_nesting -- nested length-prefixed vectors are validated in order.
/// Decode a complete ClientHello pre_shared_key extension value.
pub fn decode_offered(bytes bytes: BitArray) -> Result(Offered, Error) {
  use Nil <- result.try(require_byte_aligned(bytes))
  case bytes {
    <<identities_length:size(16), rest:bits>> -> {
      use #(encoded_identities, after_identities) <- result.try(take(
        rest,
        identities_length,
      ))
      case after_identities {
        <<binders_length:size(16), binders_and_rest:bits>> -> {
          use #(encoded_binders, trailing) <- result.try(take(
            binders_and_rest,
            binders_length,
          ))
          case trailing {
            <<>> -> {
              use identities <- result.try(
                decode_identities(encoded_identities, dict.new(), 0, []),
              )
              use binders <- result.try(
                decode_binder_items(encoded_binders, 0, []),
              )
              use Nil <- result.try(validate_counts(identities, binders))
              Ok(Offered(identities:, binders:))
            }
            _ -> Error(TrailingData)
          }
        }
        _ -> Error(Truncated)
      }
    }
    _ -> Error(Truncated)
  }
}

/// Encode the ServerHello selected_identity value.
pub fn encode_selected_identity(index index: Int) -> Result(BitArray, Error) {
  case index >= 0 && index <= 65_535 {
    True -> Ok(<<index:size(16)>>)
    False -> Error(InvalidLength)
  }
}

/// Decode the ServerHello selected_identity value.
pub fn decode_selected_identity(bytes bytes: BitArray) -> Result(Int, Error) {
  case bytes {
    <<index:size(16)>> -> Ok(index)
    _ -> Error(InvalidLength)
  }
}

/// Return ClientHelloTruncated, retaining all enclosing length fields.
///
/// TLS requires pre_shared_key to be the final ClientHello extension, so the
/// encoded binders vector must be the exact suffix removed here.
pub fn binder_transcript(
  encoded_client_hello encoded_client_hello: BitArray,
  offered offered: Offered,
) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(encoded_client_hello))
  let Offered(_, binders) = offered
  use _ <- result.try(encode_offered(offered: offered))
  use encoded_binders <- result.try(encode_binders_vector(binders))
  let total_length = bit_array.byte_size(encoded_client_hello)
  let suffix_length = bit_array.byte_size(encoded_binders)
  case suffix_length <= total_length {
    False -> Error(BindersNotAtEnd)
    True -> {
      use #(prefix, suffix) <- result.try(take(
        encoded_client_hello,
        total_length - suffix_length,
      ))
      case suffix == encoded_binders {
        True -> Ok(prefix)
        False -> Error(BindersNotAtEnd)
      }
    }
  }
}

/// Compute a TLS 1.3 resumption or external-PSK binder.
pub fn compute_binder(
  algorithm algorithm: crypto.HashAlgorithm,
  pre_shared_key pre_shared_key: BitArray,
  client_hello_truncated client_hello_truncated: BitArray,
  external external: Bool,
) -> Result(BitArray, Error) {
  case
    bit_array.bit_size(pre_shared_key) % 8 == 0
    && bit_array.bit_size(client_hello_truncated) % 8 == 0
  {
    False -> Error(NonByteAligned)
    True -> {
      use early_secret <- result.try(
        key_schedule.derive_early_secret(algorithm, pre_shared_key)
        |> map_crypto_result,
      )
      use binder_key <- result.try(
        key_schedule.derive_binder_key(algorithm, early_secret, external)
        |> map_crypto_result,
      )
      use transcript_hash <- result.try(
        crypto.hash(algorithm, client_hello_truncated) |> map_crypto_result,
      )
      key_schedule.finished_verify_data_from_hash(
        algorithm,
        binder_key,
        transcript_hash,
      )
      |> map_crypto_result
    }
  }
}

/// Verify a binder without a data-dependent comparison.
pub fn verify_binder(
  algorithm algorithm: crypto.HashAlgorithm,
  pre_shared_key pre_shared_key: BitArray,
  client_hello_truncated client_hello_truncated: BitArray,
  received received: BitArray,
  external external: Bool,
) -> Result(Bool, Error) {
  case bit_array.byte_size(received) == crypto.hash_length(algorithm) {
    False -> Error(InvalidBinder)
    True -> {
      use expected <- result.try(compute_binder(
        algorithm: algorithm,
        pre_shared_key: pre_shared_key,
        client_hello_truncated: client_hello_truncated,
        external: external,
      ))
      authentication.constant_time_equal(received, expected)
      |> map_authentication_result
    }
  }
}

fn encode_mode_items(
  modes: List(Mode),
  seen: List(Int),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case modes {
    [] -> Ok(accumulator)
    [mode, ..rest] -> {
      let identifier = mode_to_wire(mode)
      case list.contains(seen, identifier) {
        True -> Error(DuplicateMode(identifier))
        False ->
          encode_mode_items(rest, [identifier, ..seen], <<
            accumulator:bits,
            identifier,
          >>)
      }
    }
  }
}

fn decode_mode_items(
  bytes: BitArray,
  seen: List(Int),
  reversed: List(Mode),
) -> Result(List(Mode), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<identifier, rest:bits>> ->
      case mode_from_wire(identifier), list.contains(seen, identifier) {
        Error(error), _ -> Error(error)
        _, True -> Error(DuplicateMode(identifier))
        Ok(mode), False ->
          decode_mode_items(rest, [identifier, ..seen], [mode, ..reversed])
      }
    _ -> Error(Truncated)
  }
}

fn encode_identities(
  identities: List(Identity),
  seen: Dict(BitArray, Nil),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case identities {
    [] -> Ok(accumulator)
    [Identity(identity, age), ..rest] -> {
      use Nil <- result.try(require_byte_aligned(identity))
      let length = bit_array.byte_size(identity)
      case length > 0 && length <= 65_535, valid_u32(age) {
        False, _ -> Error(InvalidIdentity)
        _, False -> Error(InvalidTicketAge)
        True, True ->
          case dict.has_key(seen, identity) {
            True -> Error(DuplicateIdentity)
            False ->
              encode_identities(rest, dict.insert(seen, identity, Nil), <<
                accumulator:bits,
                length:size(16),
                identity:bits,
                age:size(32),
              >>)
          }
      }
    }
  }
}

// nolint: deep_nesting -- one recursive branch validates each identity vector item.
fn decode_identities(
  bytes: BitArray,
  seen: Dict(BitArray, Nil),
  count: Int,
  reversed: List(Identity),
) -> Result(List(Identity), Error) {
  case bytes {
    <<>> ->
      case count > 0 {
        True -> Ok(list.reverse(reversed))
        False -> Error(InvalidLength)
      }
    <<length:size(16), rest:bits>> -> {
      use #(identity, age_and_rest) <- result.try(take(rest, length))
      case age_and_rest {
        <<age:size(32), remaining:bits>> ->
          case length > 0, dict.has_key(seen, identity) {
            False, _ -> Error(InvalidIdentity)
            _, True -> Error(DuplicateIdentity)
            True, False -> {
              let next_count = count + 1
              case next_count > maximum_identities {
                True -> Error(TooManyEntries)
                False ->
                  decode_identities(
                    remaining,
                    dict.insert(seen, identity, Nil),
                    next_count,
                    [Identity(identity, age), ..reversed],
                  )
              }
            }
          }
        _ -> Error(Truncated)
      }
    }
    _ -> Error(Truncated)
  }
}

fn encode_binders_vector(binders: List(BitArray)) -> Result(BitArray, Error) {
  use encoded <- result.try(encode_binder_items(binders, <<>>))
  let length = bit_array.byte_size(encoded)
  case length > 0 && length <= 65_535 {
    True -> Ok(<<length:size(16), encoded:bits>>)
    False -> Error(InvalidLength)
  }
}

fn encode_binder_items(
  binders: List(BitArray),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case binders {
    [] -> Ok(accumulator)
    [binder, ..rest] -> {
      use Nil <- result.try(require_byte_aligned(binder))
      let length = bit_array.byte_size(binder)
      case length >= 32 && length <= 255 {
        True ->
          encode_binder_items(rest, <<accumulator:bits, length, binder:bits>>)
        False -> Error(InvalidBinder)
      }
    }
  }
}

// nolint: deep_nesting -- one recursive branch validates each binder vector item.
fn decode_binder_items(
  bytes: BitArray,
  count: Int,
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case bytes {
    <<>> ->
      case count > 0 {
        True -> Ok(list.reverse(reversed))
        False -> Error(InvalidLength)
      }
    <<length, rest:bits>> -> {
      use #(binder, remaining) <- result.try(take(rest, length))
      case length >= 32 {
        False -> Error(InvalidBinder)
        True -> {
          let next_count = count + 1
          case next_count > maximum_identities {
            True -> Error(TooManyEntries)
            False ->
              decode_binder_items(remaining, next_count, [binder, ..reversed])
          }
        }
      }
    }
    _ -> Error(Truncated)
  }
}

fn validate_counts(
  identities: List(Identity),
  binders: List(BitArray),
) -> Result(Nil, Error) {
  let identity_count = list.length(identities)
  case
    identity_count > 0,
    identity_count <= maximum_identities,
    identity_count == list.length(binders)
  {
    False, _, _ -> Error(InvalidLength)
    _, False, _ -> Error(TooManyEntries)
    _, _, False -> Error(MismatchedBinders)
    True, True, True -> Ok(Nil)
  }
}

fn mode_to_wire(mode: Mode) -> Int {
  case mode {
    PskKe -> 0
    PskDheKe -> 1
  }
}

fn mode_from_wire(identifier: Int) -> Result(Mode, Error) {
  case identifier {
    0 -> Ok(PskKe)
    1 -> Ok(PskDheKe)
    _ -> Error(InvalidMode(identifier))
  }
}

fn valid_u32(value: Int) -> Bool {
  value >= 0 && value <= 0xffff_ffff
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

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(CryptoFailure(error))
  }
}

fn map_authentication_result(
  value: Result(output, authentication.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(AuthenticationFailure(error))
  }
}
