//// WHATWG URLPattern component canonicalization, with finite byte ceilings.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/component

pub type Kind {
  Protocol
  Userinfo
  Port
  Search
  Hash
  OpaquePath
  Ipv6Pattern
}

/// Port uses the corrected aeb2019 URLPattern callback: absent protocol means no implicit default port.
/// The caller separately normalizes a known scheme.
pub fn encode(
  kind kind: Kind,
  value value: String,
) -> Result(String, component.Error) {
  use _ <- result.try(case string.byte_size(value) <= 8192 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  case kind {
    Protocol -> protocol(value)
    Port -> port(strip_tabs(value))
    Ipv6Pattern -> ipv6_piece(value)
    Userinfo ->
      bytes(
        kind: kind,
        input: bit_array.from_string(value),
        reversed: [],
        remaining: 8192,
      )
    OpaquePath | Search | Hash ->
      bytes(
        kind: kind,
        input: bit_array.from_string(strip_tabs(value)),
        reversed: [],
        remaining: 8192,
      )
  }
}

fn strip_tabs(value: String) -> String {
  value
  |> string.replace("\t", "")
  |> string.replace("\n", "")
  |> string.replace("\r", "")
}

fn protocol(value: String) -> Result(String, component.Error) {
  let value = strip_tabs(value)
  let codes =
    value |> string.to_utf_codepoints |> list.map(string.utf_codepoint_to_int)
  case codes {
    [] -> Ok("")
    [first, ..rest] ->
      case
        alpha(first)
        && list.all(rest, fn(code) {
          alpha(code) || digit(code) || code == 43 || code == 45 || code == 46
        })
      {
        True -> Ok(string.lowercase(value))
        False -> Error(component.InvalidPattern)
      }
  }
}

fn port(value: String) -> Result(String, component.Error) {
  case value {
    "" -> Ok("")
    _ -> decimal(input: bit_array.from_string(value), value: 0, seen: False)
  }
}

fn decimal(
  input input: BitArray,
  value value: Int,
  seen seen: Bool,
) -> Result(String, component.Error) {
  case input {
    <<code, rest:bits>> if code >= 48 && code <= 57 -> {
      let next = value * 10 + code - 48
      case next <= 65_535 {
        True -> decimal(input: rest, value: next, seen: True)
        False -> Error(component.InvalidPattern)
      }
    }
    _ ->
      case seen {
        True -> Ok(int.to_string(value))
        False -> Error(component.InvalidPattern)
      }
  }
}

fn ipv6_piece(value: String) -> Result(String, component.Error) {
  let codes =
    value |> string.to_utf_codepoints |> list.map(string.utf_codepoint_to_int)
  case
    list.all(codes, fn(code) {
      digit(code)
      || { code >= 65 && code <= 70 }
      || { code >= 97 && code <= 102 }
      || code == 91
      || code == 93
      || code == 58
    })
  {
    True -> Ok(string.lowercase(value))
    False -> Error(component.InvalidPattern)
  }
}

fn alpha(code: Int) -> Bool {
  { code >= 65 && code <= 90 } || { code >= 97 && code <= 122 }
}

fn digit(code: Int) -> Bool {
  code >= 48 && code <= 57
}

fn bytes(
  kind kind: Kind,
  input input: BitArray,
  reversed reversed: List(String),
  remaining remaining: Int,
) -> Result(String, component.Error) {
  case input {
    <<>> -> Ok(reversed |> list.reverse |> string.concat)
    <<code, _:bits>> if kind == OpaquePath && { code == 63 || code == 35 } ->
      Ok(reversed |> list.reverse |> string.concat)
    <<code, rest:bits>> -> {
      let escaped =
        escape(kind, code)
        || { kind == OpaquePath && code == 32 && starts_delimiter(rest) }
      let cost = case escaped {
        True -> 3
        False -> 1
      }
      use <- bool.guard(remaining < cost, Error(component.WorkLimitExceeded))
      let value = case escaped {
        True -> "%" <> hex(code / 16) <> hex(code % 16)
        // The unescaped branch contains one ASCII byte only.
        False -> bit_array.to_string(<<code>>) |> result.unwrap("")
      }
      bytes(
        kind: kind,
        input: rest,
        reversed: [value, ..reversed],
        remaining: remaining - cost,
      )
    }
    _ -> Error(component.InvalidPattern)
  }
}

fn starts_delimiter(input: BitArray) -> Bool {
  case input {
    <<63, _:bits>> | <<35, _:bits>> -> True
    _ -> False
  }
}

fn escape(kind: Kind, code: Int) -> Bool {
  use <- bool.guard(code < 32 || code >= 127, True)
  case kind {
    OpaquePath -> False
    Hash -> code == 32 || code == 34 || code == 60 || code == 62 || code == 96
    Search ->
      code == 32
      || code == 34
      || code == 35
      || code == 39
      || code == 60
      || code == 62
    Userinfo ->
      code == 32
      || code == 34
      || code == 35
      || code == 47
      || code == 58
      || code == 59
      || code == 60
      || code == 61
      || code == 62
      || code == 63
      || code == 64
      || { code >= 91 && code <= 94 }
      || code == 96
      || code == 123
      || code == 124
      || code == 125
    Protocol | Port | Ipv6Pattern -> False
  }
}

fn hex(value: Int) -> String {
  string.slice("0123456789ABCDEF", at_index: value, length: 1)
}
