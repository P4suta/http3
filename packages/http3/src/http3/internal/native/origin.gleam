//// Bounded RFC 8336 ORIGIN payloads as carried by RFC 9412 HTTP/3 frames.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri

const maximum_entry_bytes = 0xffff

/// One parsed ASCII serialization of an HTTP origin.
pub type Origin {
  Origin(scheme: String, host: String, port: Option(Int))
}

/// Payload structure, resource, ASCII, or origin serialization failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  Truncated
  TooManyOrigins(maximum: Int)
  OriginTooLong(maximum: Int)
  NonAscii
  InvalidOrigin
}

/// Decode a finite ORIGIN payload. Syntactically invalid origin entries are
/// ignored individually, while malformed length framing is rejected.
pub fn decode(
  payload payload: BitArray,
  maximum_entries maximum_entries: Int,
) -> Result(List(Origin), Error) {
  case maximum_entries > 0, bit_array.bit_size(payload) % 8 {
    False, _ -> Error(InvalidLimit)
    _, remainder if remainder != 0 -> Error(NonByteAligned)
    True, _ -> decode_entries(payload, maximum_entries, 0, [])
  }
}

/// Encode normalized HTTP origins into one finite ORIGIN payload.
pub fn encode(
  origins origins: List(Origin),
  maximum_entries maximum_entries: Int,
) -> Result(BitArray, Error) {
  case maximum_entries > 0, list.length(origins) <= maximum_entries {
    False, _ -> Error(InvalidLimit)
    _, False -> Error(TooManyOrigins(maximum: maximum_entries))
    True, True -> {
      use entries <- result.try(list.try_map(origins, encode_entry))
      Ok(bit_array.concat(entries))
    }
  }
}

// Count every length-delimited entry before syntax validation. Otherwise an
// attacker could bypass the work bound with an unlimited series of invalid
// origins that RFC 8336 requires recipients to ignore.
fn decode_entries(
  payload: BitArray,
  maximum_entries: Int,
  count: Int,
  reversed: List(Origin),
) -> Result(List(Origin), Error) {
  case payload {
    <<>> -> Ok(list.reverse(reversed))
    <<length:size(16), rest:bytes>> ->
      case count >= maximum_entries, bit_array.byte_size(rest) < length {
        True, _ -> Error(TooManyOrigins(maximum: maximum_entries))
        _, True -> Error(Truncated)
        False, False -> {
          use encoded <- result.try(
            bit_array.slice(rest, at: 0, take: length)
            |> result.replace_error(Truncated),
          )
          use remaining <- result.try(
            bit_array.slice(
              rest,
              at: length,
              take: bit_array.byte_size(rest) - length,
            )
            |> result.replace_error(Truncated),
          )
          let reversed = case parse_origin(encoded) {
            Some(value) -> [value, ..reversed]
            None -> reversed
          }
          decode_entries(remaining, maximum_entries, count + 1, reversed)
        }
      }
    _ -> Error(Truncated)
  }
}

fn encode_entry(origin: Origin) -> Result(BitArray, Error) {
  let encoded = serialize(origin)
  use _ <- result.try(validate_ascii(encoded))
  use parsed <- result.try(case parse_origin(encoded) {
    Some(parsed) -> Ok(parsed)
    None -> Error(InvalidOrigin)
  })
  let encoded = serialize(parsed)
  let length = bit_array.byte_size(encoded)
  case length <= maximum_entry_bytes {
    True -> Ok(<<length:size(16), encoded:bits>>)
    False -> Error(OriginTooLong(maximum: maximum_entry_bytes))
  }
}

fn parse_origin(encoded: BitArray) -> Option(Origin) {
  case validate_ascii(encoded), bit_array.to_string(encoded) {
    Ok(Nil), Ok(text) ->
      case uri.parse(text) {
        Ok(uri.Uri(scheme, userinfo, host, port, path, query, fragment)) ->
          case scheme, userinfo, host, path, query, fragment {
            Some(scheme), None, Some(host), "", None, None ->
              case
                valid_scheme(scheme) && valid_host(host) && valid_port(port)
              {
                True -> Some(Origin(scheme, string.lowercase(host), port))
                False -> None
              }
            _, _, _, _, _, _ -> None
          }
        Error(Nil) -> None
      }
    _, _ -> None
  }
}

fn serialize(origin: Origin) -> BitArray {
  let Origin(scheme, host, port) = origin
  let authority = case port {
    None -> host
    Some(port) -> host <> ":" <> int.to_string(port)
  }
  <<scheme:utf8, "://":utf8, authority:utf8>>
}

fn validate_ascii(value: BitArray) -> Result(Nil, Error) {
  case value {
    <<>> -> Ok(Nil)
    <<byte, rest:bits>> if byte <= 0x7f -> validate_ascii(rest)
    _ -> Error(NonAscii)
  }
}

fn valid_scheme(scheme: String) -> Bool {
  scheme == "http" || scheme == "https"
}

fn valid_host(host: String) -> Bool {
  host != "" && !string.contains(host, "*")
}

fn valid_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(port) -> port > 0 && port <= 65_535
  }
}
