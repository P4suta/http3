//// Bounded special URL host parser; independent of hostname pattern pieces.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/host_idna as idna
import http/internal/url_pattern/host_ip as ip

/// Host parser from URL snapshot 8e14777cfa145b08a9fb735fe580ec0c366564c3.
/// The complete input and serialized result are each at most 2048 UTF-8 bytes.
/// Entirely ASCII domains use that snapshot's relaxed lowercase path.
/// A-label validation in non-ASCII domains still uses UTS46 with Unicode16 properties.
pub fn canonicalize(input: String) -> Result(String, Nil) {
  use <- bool.guard(input == "" || string.byte_size(input) > 2048, Error(Nil))
  use output <- result.try(case input {
    "[" <> inside ->
      case string.ends_with(inside, "]") {
        True -> ip.ipv6(string.drop_end(inside, 1))
        False -> Error(Nil)
      }
    _ -> domain(input)
  })
  case string.byte_size(output) > 2048 {
    True -> Error(Nil)
    False -> Ok(output)
  }
}

fn domain(input: String) -> Result(String, Nil) {
  use decoded <- result.try(
    percent_decode(bytes: bit_array.from_string(input), reversed: []),
  )
  let codes =
    decoded |> string.to_utf_codepoints |> list.map(string.utf_codepoint_to_int)
  use ascii <- result.try(case list.all(codes, fn(code) { code < 128 }) {
    True -> Ok(string.lowercase(decoded))
    False -> idna.to_ascii(codes)
  })
  case ascii == "" || forbidden(bit_array.from_string(ascii)) {
    True -> Error(Nil)
    False ->
      case ip.ends_in_number(ascii) {
        True -> ip.ipv4(ascii)
        False -> Ok(ascii)
      }
  }
}

fn forbidden(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> False
    <<byte, rest:bits>> ->
      case byte {
        code if code <= 32 || code == 127 -> True
        35 | 37 | 47 | 58 | 60 | 62 | 63 | 64 | 91 | 92 | 93 | 94 | 124 -> True
        _ -> forbidden(rest)
      }
    _ -> True
  }
}

fn percent_decode(
  bytes bytes: BitArray,
  reversed reversed: List(BitArray),
) -> Result(String, Nil) {
  case bytes {
    <<>> -> reversed |> list.reverse |> bit_array.concat |> bit_array.to_string
    <<37, a, b, rest:bits>> -> {
      let high = hex(a)
      let low = hex(b)
      case high >= 0 && low >= 0 {
        True -> {
          let byte = high * 16 + low
          percent_decode(bytes: rest, reversed: [<<byte>>, ..reversed])
        }
        False -> Error(Nil)
      }
    }
    <<byte, rest:bits>> ->
      percent_decode(bytes: rest, reversed: [<<byte>>, ..reversed])
    _ -> Error(Nil)
  }
}

fn hex(byte: Int) -> Int {
  case byte {
    code if code >= 48 && code <= 57 -> code - 48
    code if code >= 65 && code <= 70 -> code - 55
    code if code >= 97 && code <= 102 -> code - 87
    _ -> -1
  }
}
