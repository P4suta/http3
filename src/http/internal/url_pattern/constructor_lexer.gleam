//// Lenient URLPattern tokens retain source code-point boundaries.
//// Only token kinds needed by the constructor state machine cross this seam.

import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/internal/url_pattern/component
import http/internal/url_pattern/unicode

pub type Kind {
  Character
  Name
  Regexp
  Open
  Close
  Asterisk
  Modifier
  End
}

pub type Token {
  Token(kind: Kind, position: Int, value: Int)
}

pub fn tokenize(
  input input: String,
  work work: Int,
) -> Result(#(Dict(Int, Token), Int), component.Error) {
  use _ <- result.try(case string.byte_size(input) <= 2048 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  let codes =
    string.to_utf_codepoints(input) |> list.map(string.utf_codepoint_to_int)
  let allowance = case work < 32_768 {
    True -> work
    False -> 32_768
  }
  use #(tokens, remaining) <- result.try(scan(
    input: codes,
    position: 0,
    reversed: [],
    work: allowance,
  ))
  Ok(#(
    tokens
      |> list.index_map(fn(token, index) { #(index, token) })
      |> dict.from_list,
    work - allowance + remaining,
  ))
}

fn scan(
  input input: List(Int),
  position position: Int,
  reversed reversed: List(Token),
  work work: Int,
) -> Result(#(List(Token), Int), component.Error) {
  case input {
    _ if work < 0 -> Error(component.WorkLimitExceeded)
    [] -> Ok(#(list.reverse([Token(End, position, -1), ..reversed]), work))
    _ if work <= 0 -> Error(component.WorkLimitExceeded)
    [92, code, ..rest] ->
      scan(
        input: rest,
        position: position + 2,
        reversed: [Token(Character, position, code), ..reversed],
        work: work - 2,
      )
    [58, code, ..rest] ->
      case name_start(code) {
        True -> {
          let #(count, tail) = name_end(rest, 2)
          scan(
            input: tail,
            position: position + count,
            reversed: [Token(Name, position, -1), ..reversed],
            work: work - count,
          )
        }
        False ->
          scan(
            input: [code, ..rest],
            position: position + 1,
            reversed: [Token(Character, position, 58), ..reversed],
            work: work - 1,
          )
      }
    [40, ..rest] -> {
      let #(length, remaining) =
        regexp_end(input: rest, count: 1, depth: 1, first: True, work: work - 1)
      case length {
        Some(count) ->
          scan(
            input: list.drop(input, count),
            position: position + count,
            reversed: [Token(Regexp, position, -1), ..reversed],
            work: remaining,
          )
        None ->
          scan(
            input: rest,
            position: position + 1,
            reversed: [Token(Character, position, 40), ..reversed],
            work: remaining,
          )
      }
    }
    [code, ..rest] -> {
      let kind = case code {
        123 -> Open
        125 -> Close
        42 -> Asterisk
        43 | 63 -> Modifier
        _ -> Character
      }
      scan(
        input: rest,
        position: position + 1,
        reversed: [Token(kind, position, code), ..reversed],
        work: work - 1,
      )
    }
  }
}

fn name_start(code: Int) -> Bool {
  code == 36 || code == 95 || unicode.id_start(code)
}

fn name_end(input: List(Int), count: Int) -> #(Int, List(Int)) {
  case input {
    [code, ..rest] ->
      case
        name_start(code)
        || unicode.id_continue(code)
        || code == 8204
        || code == 8205
      {
        True -> name_end(rest, count + 1)
        False -> #(count, input)
      }
    [] -> #(count, [])
  }
}

// A failed regexp token only consumes its opening character.
// All inspected characters still consume work, preventing repeated malformed suffix scans.
fn regexp_end(
  input input: List(Int),
  count count: Int,
  depth depth: Int,
  first first: Bool,
  work work: Int,
) -> #(Option(Int), Int) {
  case input {
    _ if work <= 0 -> #(None, -1)
    [] -> #(None, work)
    [code, ..] if code > 127 || { first && code == 63 } -> #(None, work - 1)
    [92, code, ..rest] if code <= 127 ->
      regexp_end(
        input: rest,
        count: count + 2,
        depth: depth,
        first: False,
        work: work - 2,
      )
    [92, ..] -> #(None, work - 1)
    [41, ..] if depth == 1 && count > 1 -> #(Some(count + 1), work - 1)
    [41, ..rest] if depth > 1 ->
      regexp_end(
        input: rest,
        count: count + 1,
        depth: depth - 1,
        first: False,
        work: work - 1,
      )
    [41, ..] -> #(None, work - 1)
    [40, 63, ..rest] ->
      regexp_end(
        input: [63, ..rest],
        count: count + 1,
        depth: depth + 1,
        first: False,
        work: work - 1,
      )
    [40, ..] -> #(None, work - 1)
    [_, ..rest] ->
      regexp_end(
        input: rest,
        count: count + 1,
        depth: depth,
        first: False,
        work: work - 1,
      )
  }
}
