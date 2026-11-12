//// WHATWG special-host IPv4/IPv6 parsing and canonical serialization.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string

pub fn ends_in_number(domain: String) -> Bool {
  case domain |> parts |> list.reverse {
    [last, ..] ->
      result.is_ok(number(last)) || digits(last) || hexadecimal(last)
    [] -> False
  }
}

// The ends-in-a-number step recognizes syntax before the IPv4 parser applies its value bound.
// An overflowing hexadecimal integer must still reach that later rejection, without constructing an arbitrarily large integer here.
fn hexadecimal(input: String) -> Bool {
  case input {
    "0x" <> rest | "0X" <> rest ->
      hexadecimal_bytes(bit_array.from_string(rest))
    _ -> False
  }
}

fn hexadecimal_bytes(input: BitArray) -> Bool {
  case input {
    <<>> -> True
    <<byte, rest:bits>>
      if { byte >= 48 && byte <= 57 }
      || { byte >= 65 && byte <= 70 }
      || { byte >= 97 && byte <= 102 }
    -> hexadecimal_bytes(rest)
    _ -> False
  }
}

pub fn ipv4(domain: String) -> Result(String, Nil) {
  let segments = parts(domain)
  let count = list.length(segments)
  use <- bool.guard(count < 1 || count > 4, Error(Nil))
  use numbers <- result.try(list.try_map(segments, number))
  let initial = list.take(numbers, count - 1)
  let last = list.last(numbers) |> result.unwrap(0)
  let width = power256(5 - count)
  use <- bool.guard(
    !list.all(initial, fn(n) { n <= 255 }) || last >= width,
    Error(Nil),
  )
  let prefix = list.fold(initial, 0, fn(n, piece) { n * 256 + piece })
  let address = prefix * width + last
  [
    address / 16_777_216,
    address / 65_536 % 256,
    address / 256 % 256,
    address % 256,
  ]
  |> list.map(int.to_string)
  |> string.join(".")
  |> Ok
}

fn parts(domain: String) -> List(String) {
  let segments = string.split(domain, ".")
  case list.reverse(segments) {
    ["", ..rest] -> list.reverse(rest)
    _ -> segments
  }
}

fn power256(count: Int) -> Int {
  case count {
    1 -> 256
    2 -> 65_536
    3 -> 16_777_216
    4 -> 4_294_967_296
    _ -> 1
  }
}

fn number(input: String) -> Result(Int, Nil) {
  case input {
    "" -> Error(Nil)
    "0x" <> rest | "0X" <> rest ->
      unsigned(
        input: bit_array.from_string(rest),
        base: 16,
        value: 0,
        maximum: 4_294_967_295,
      )
    "0" <> rest if rest != "" ->
      unsigned(
        input: bit_array.from_string(rest),
        base: 8,
        value: 0,
        maximum: 4_294_967_295,
      )
    _ ->
      unsigned(
        input: bit_array.from_string(input),
        base: 10,
        value: 0,
        maximum: 4_294_967_295,
      )
  }
}

fn digits(input: String) -> Bool {
  input != "" && decimal_bytes(bit_array.from_string(input))
}

fn decimal_bytes(input: BitArray) -> Bool {
  case input {
    <<>> -> True
    <<byte, rest:bits>> if byte >= 48 && byte <= 57 -> decimal_bytes(rest)
    _ -> False
  }
}

fn unsigned(
  input input: BitArray,
  base base: Int,
  value value: Int,
  maximum maximum: Int,
) -> Result(Int, Nil) {
  case input {
    <<>> -> Ok(value)
    <<byte, rest:bits>> -> {
      let digit = case byte {
        b if b >= 48 && b <= 57 -> b - 48
        b if b >= 65 && b <= 70 -> b - 55
        b if b >= 97 && b <= 102 -> b - 87
        _ -> 100
      }
      case digit < base && value <= { maximum - digit } / base {
        True ->
          unsigned(
            input: rest,
            base: base,
            value: value * base + digit,
            maximum: maximum,
          )
        False -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

pub fn ipv6(input: String) -> Result(String, Nil) {
  use pieces <- result.try(case string.split(input, "::") {
    [uncompressed] -> {
      use pieces <- result.try(pieces(input: uncompressed, allow_ipv4: True))
      case list.length(pieces) == 8 {
        True -> Ok(pieces)
        False -> Error(Nil)
      }
    }
    [left, right] -> {
      use prefix <- result.try(pieces(input: left, allow_ipv4: False))
      use suffix <- result.try(pieces(input: right, allow_ipv4: True))
      let missing = 8 - list.length(prefix) - list.length(suffix)
      case missing > 0 {
        True ->
          Ok(list.append(prefix, list.append(list.repeat(0, missing), suffix)))
        False -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  })
  Ok("[" <> serialize(pieces) <> "]")
}

fn pieces(
  input input: String,
  allow_ipv4 allow_ipv4: Bool,
) -> Result(List(Int), Nil) {
  case input {
    "" -> Ok([])
    _ ->
      parse_pieces(
        input: string.split(input, ":"),
        allow_ipv4: allow_ipv4,
        reversed: [],
      )
  }
}

fn parse_pieces(
  input input: List(String),
  allow_ipv4 allow_ipv4: Bool,
  reversed reversed: List(Int),
) -> Result(List(Int), Nil) {
  case input {
    [] -> Ok(list.reverse(reversed))
    [piece, ..rest] ->
      case string.contains(piece, ".") {
        True ->
          case allow_ipv4 && rest == [] {
            False -> Error(Nil)
            True -> append_ipv4(piece: piece, reversed: reversed)
          }
        False ->
          case string.byte_size(piece) >= 1 && string.byte_size(piece) <= 4 {
            False -> Error(Nil)
            True -> {
              use value <- result.try(unsigned(
                input: bit_array.from_string(piece),
                base: 16,
                value: 0,
                maximum: 65_535,
              ))
              parse_pieces(input: rest, allow_ipv4: allow_ipv4, reversed: [
                value,
                ..reversed
              ])
            }
          }
      }
  }
}

fn append_ipv4(
  piece piece: String,
  reversed reversed: List(Int),
) -> Result(List(Int), Nil) {
  use bytes <- result.try(list.try_map(string.split(piece, "."), ipv4_tail))
  case bytes {
    [a, b, c, d] -> Ok(list.reverse([c * 256 + d, a * 256 + b, ..reversed]))
    _ -> Error(Nil)
  }
}

fn ipv4_tail(input: String) -> Result(Int, Nil) {
  case input {
    "" -> Error(Nil)
    "0" <> rest if rest != "" -> Error(Nil)
    _ ->
      unsigned(
        input: bit_array.from_string(input),
        base: 10,
        value: 0,
        maximum: 255,
      )
  }
}

fn serialize(pieces: List(Int)) -> String {
  let #(start, count) =
    longest_zero(
      pieces: pieces,
      index: 0,
      start: 0,
      count: 0,
      best_start: 0,
      best_count: 0,
    )
  let text =
    list.map(pieces, fn(piece) { int.to_base16(piece) |> string.lowercase })
  case count >= 2 {
    False -> string.join(text, ":")
    True ->
      string.join(list.take(text, start), ":")
      <> "::"
      <> string.join(list.drop(text, start + count), ":")
  }
}

fn longest_zero(
  pieces pieces: List(Int),
  index index: Int,
  start start: Int,
  count count: Int,
  best_start best_start: Int,
  best_count best_count: Int,
) -> #(Int, Int) {
  let #(best_start, best_count) = case count > best_count {
    True -> #(start, count)
    False -> #(best_start, best_count)
  }
  case pieces {
    [] -> #(best_start, best_count)
    [0, ..rest] ->
      longest_zero(
        pieces: rest,
        index: index + 1,
        start: start,
        count: count + 1,
        best_start: best_start,
        best_count: best_count,
      )
    [_, ..rest] ->
      longest_zero(
        pieces: rest,
        index: index + 1,
        start: index + 1,
        count: 0,
        best_start: best_start,
        best_count: best_count,
      )
  }
}
