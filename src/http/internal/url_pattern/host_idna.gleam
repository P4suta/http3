//// UTS46 nontransitional ToASCII (CheckBidi/Joiners, relaxed URL DNS rules).
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bool
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/host_data as data
import http/internal/url_pattern/host_nfc as nfc
import http/internal/url_pattern/host_punycode as punycode

pub fn to_ascii(input: List(Int)) -> Result(String, Nil) {
  let mapped = input |> list.flat_map(map) |> nfc.normalize
  use labels <- result.try(
    mapped |> split(label: [], reversed: []) |> list.try_map(decode),
  )
  let bidi =
    list.any(labels, fn(label) {
      list.any(label, fn(code) {
        let kind = data.bidi(code)
        kind == 1 || kind == 2 || kind == 4
      })
    })
  case
    list.all(labels, fn(label) {
      valid(label) && { !bidi || valid_bidi(label) }
    })
  {
    False -> Error(Nil)
    True -> {
      use encoded <- result.try(list.try_map(labels, encode))
      Ok(string.join(encoded, "."))
    }
  }
}

fn map(code: Int) -> List(Int) {
  case data.mapping(code) {
    #(1, _) -> []
    #(2, codes) -> codes
    _ -> [code]
  }
}

fn split(
  codes codes: List(Int),
  label label: List(Int),
  reversed reversed: List(List(Int)),
) -> List(List(Int)) {
  case codes {
    [] -> list.reverse([list.reverse(label), ..reversed])
    [46, ..rest] ->
      split(codes: rest, label: [], reversed: [list.reverse(label), ..reversed])
    [code, ..rest] ->
      split(codes: rest, label: [code, ..label], reversed: reversed)
  }
}

fn decode(label: List(Int)) -> Result(List(Int), Nil) {
  case label {
    [120, 110, 45, 45, ..rest] -> decode_alabel(rest)
    _ -> Ok(label)
  }
}

fn decode_alabel(encoded: List(Int)) -> Result(List(Int), Nil) {
  use <- bool.guard(!list.all(encoded, fn(code) { code < 128 }), Error(Nil))
  use decoded <- result.try(punycode.decode(encoded))
  case list.any(decoded, fn(code) { code >= 128 }) {
    True -> Ok(decoded)
    False -> Error(Nil)
  }
}

fn valid(label: List(Int)) -> Bool {
  case label {
    [] -> True
    [120, 110, 45, 45, ..] -> False
    [first, ..] ->
      data.mark(first) == 0
      && nfc.normalize(label) == label
      && list.all(label, fn(code) { code != 46 && data.mapping(code).0 == 0 })
      && joiners(label: label, previous: -1, left: 0)
  }
}

fn joiners(
  label label: List(Int),
  previous previous: Int,
  left left: Int,
) -> Bool {
  case label {
    [] -> True
    [code, ..rest] -> {
      let valid =
        joiner_valid(code: code, previous: previous, left: left, rest: rest)
      let joining = data.joining(code)
      let left = case joining == 4 {
        True -> left
        False -> joining
      }
      valid && joiners(label: rest, previous: code, left: left)
    }
  }
}

fn joiner_valid(
  code code: Int,
  previous previous: Int,
  left left: Int,
  rest rest: List(Int),
) -> Bool {
  case code {
    8205 -> data.ccc(previous) == 9
    8204 ->
      data.ccc(previous) == 9
      || { { left == 2 || left == 3 } && right_joining(rest) }
    _ -> True
  }
}

fn right_joining(label: List(Int)) -> Bool {
  case label {
    [] -> False
    [code, ..rest] ->
      case data.joining(code) {
        4 -> right_joining(rest)
        1 | 3 -> True
        _ -> False
      }
  }
}

fn valid_bidi(label: List(Int)) -> Bool {
  let kinds = list.map(label, data.bidi)
  let last =
    kinds
    |> list.reverse
    |> list.drop_while(fn(kind) { kind == 10 })
    |> list.first
    |> result.unwrap(-1)
  case kinds {
    [] -> True
    [0, ..] ->
      list.all(kinds, fn(kind) {
        list.contains([0, 3, 5, 6, 7, 8, 9, 10], kind)
      })
      && { last == 0 || last == 3 }
    [1, ..] | [2, ..] ->
      list.all(kinds, fn(kind) { kind >= 1 && kind <= 10 })
      && { last >= 1 && last <= 4 }
      && !{ list.contains(kinds, 3) && list.contains(kinds, 4) }
    _ -> False
  }
}

fn encode(label: List(Int)) -> Result(String, Nil) {
  use <- bool.guard(!list.any(label, fn(code) { code >= 128 }), Ok(text(label)))
  punycode.encode(label) |> result.map(fn(codes) { "xn--" <> text(codes) })
}

fn text(codes: List(Int)) -> String {
  codes |> list.filter_map(string.utf_codepoint) |> string.from_utf_codepoints
}
