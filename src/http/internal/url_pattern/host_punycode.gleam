//// RFC3492 Bootstring with fixed Unicode/Int32 and output work ceilings.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/bool
import gleam/int
import gleam/list
import gleam/result

const maximum = 2_147_483_647

pub fn encode(input: List(Int)) -> Result(List(Int), Nil) {
  let basic = list.filter(input, fn(code) { code < 128 })
  let count = list.length(basic)
  let output = case basic {
    [] -> []
    _ -> [45, ..list.reverse(basic)]
  }
  encode_next(
    input: input,
    n: 128,
    delta: 0,
    bias: 72,
    handled: count,
    basic: count,
    output: output,
    size: list.length(output),
  )
}

fn encode_next(
  input input: List(Int),
  n n: Int,
  delta delta: Int,
  bias bias: Int,
  handled handled: Int,
  basic basic: Int,
  output output: List(Int),
  size size: Int,
) -> Result(List(Int), Nil) {
  use <- bool.guard(handled == list.length(input), Ok(list.reverse(output)))
  let next =
    list.fold(input, 1_114_112, fn(smallest, code) {
      case code >= n && code < smallest {
        True -> code
        False -> smallest
      }
    })
  let addition = { next - n } * { handled + 1 }
  case next > 1_114_111 || addition > maximum - delta {
    True -> Error(Nil)
    False -> {
      use state <- result.try(encode_scan(
        input: input,
        n: next,
        delta: delta + addition,
        bias: bias,
        handled: handled,
        basic: basic,
        output: output,
        size: size,
      ))
      let #(delta, bias, handled, output, size) = state
      encode_next(
        input: input,
        n: next + 1,
        delta: delta + 1,
        bias: bias,
        handled: handled,
        basic: basic,
        output: output,
        size: size,
      )
    }
  }
}

fn encode_scan(
  input input: List(Int),
  n n: Int,
  delta delta: Int,
  bias bias: Int,
  handled handled: Int,
  basic basic: Int,
  output output: List(Int),
  size size: Int,
) -> Result(#(Int, Int, Int, List(Int), Int), Nil) {
  case input {
    [] -> Ok(#(delta, bias, handled, output, size))
    [code, ..rest] if code < n ->
      case delta == maximum {
        True -> Error(Nil)
        False ->
          encode_scan(
            input: rest,
            n: n,
            delta: delta + 1,
            bias: bias,
            handled: handled,
            basic: basic,
            output: output,
            size: size,
          )
      }
    [code, ..rest] if code == n -> {
      use encoded <- result.try(encode_integer(
        value: delta,
        bias: bias,
        k: 36,
        output: output,
        size: size,
      ))
      let #(output, size) = encoded
      encode_scan(
        input: rest,
        n: n,
        delta: 0,
        bias: adapt(delta: delta, points: handled + 1, first: handled == basic),
        handled: handled + 1,
        basic: basic,
        output: output,
        size: size,
      )
    }
    [_, ..rest] ->
      encode_scan(
        input: rest,
        n: n,
        delta: delta,
        bias: bias,
        handled: handled,
        basic: basic,
        output: output,
        size: size,
      )
  }
}

fn encode_integer(
  value value: Int,
  bias bias: Int,
  k k: Int,
  output output: List(Int),
  size size: Int,
) -> Result(#(List(Int), Int), Nil) {
  use <- bool.guard(size >= 2048, Error(Nil))
  let threshold_value = threshold(k: k, bias: bias)
  case value < threshold_value {
    True -> Ok(#([digit(value), ..output], size + 1))
    False ->
      encode_integer(
        value: { value - threshold_value } / { 36 - threshold_value },
        bias: bias,
        k: k + 36,
        output: [
          digit(
            threshold_value
            + { value - threshold_value }
            % { 36 - threshold_value },
          ),
          ..output
        ],
        size: size + 1,
      )
  }
}

pub fn decode(input: List(Int)) -> Result(List(Int), Nil) {
  let delimiter = last_delimiter(input: input, position: 0, last: -1)
  let #(basic, rest) = case delimiter >= 0 {
    True -> #(list.take(input, delimiter), list.drop(input, delimiter + 1))
    False -> #([], input)
  }
  case list.all(basic, fn(code) { code < 128 }) {
    False -> Error(Nil)
    True -> decode_next(input: rest, n: 128, i: 0, bias: 72, output: basic)
  }
}

fn last_delimiter(
  input input: List(Int),
  position position: Int,
  last last: Int,
) -> Int {
  case input {
    [] -> last
    [45, ..rest] ->
      last_delimiter(input: rest, position: position + 1, last: position)
    [_, ..rest] ->
      last_delimiter(input: rest, position: position + 1, last: last)
  }
}

fn decode_next(
  input input: List(Int),
  n n: Int,
  i i: Int,
  bias bias: Int,
  output output: List(Int),
) -> Result(List(Int), Nil) {
  case input {
    [] -> Ok(output)
    _ -> {
      use decoded <- result.try(decode_integer(
        input: input,
        value: i,
        weight: 1,
        k: 36,
        bias: bias,
      ))
      let #(value, rest) = decoded
      let size = list.length(output) + 1
      let next = n + value / size
      case
        size > 2048 || next > 1_114_111 || { next >= 55_296 && next <= 57_343 }
      {
        True -> Error(Nil)
        False -> {
          let index = value % size
          let output =
            list.append(list.take(output, index), [
              next,
              ..list.drop(output, index)
            ])
          decode_next(
            input: rest,
            n: next,
            i: index + 1,
            bias: adapt(delta: value - i, points: size, first: i == 0),
            output: output,
          )
        }
      }
    }
  }
}

fn decode_integer(
  input input: List(Int),
  value value: Int,
  weight weight: Int,
  k k: Int,
  bias bias: Int,
) -> Result(#(Int, List(Int)), Nil) {
  case input {
    [] -> Error(Nil)
    [code, ..rest] -> {
      let digit = case code {
        c if c >= 48 && c <= 57 -> c - 22
        c if c >= 65 && c <= 90 -> c - 65
        c if c >= 97 && c <= 122 -> c - 97
        _ -> 36
      }
      let threshold = threshold(k: k, bias: bias)
      use <- bool.guard(
        digit >= 36 || digit > { maximum - value } / weight,
        Error(Nil),
      )
      let value = value + digit * weight
      use <- bool.guard(digit < threshold, Ok(#(value, rest)))
      use <- bool.guard(weight > maximum / { 36 - threshold }, Error(Nil))
      decode_integer(
        input: rest,
        value: value,
        weight: weight * { 36 - threshold },
        k: k + 36,
        bias: bias,
      )
    }
  }
}

fn digit(value: Int) -> Int {
  case value < 26 {
    True -> value + 97
    False -> value + 22
  }
}

fn threshold(k k: Int, bias bias: Int) -> Int {
  int.clamp(k - bias, min: 1, max: 26)
}

fn adapt(delta delta: Int, points points: Int, first first: Bool) -> Int {
  let delta = case first {
    True -> delta / 700
    False -> delta / 2
  }
  adapt_loop(delta: delta + delta / points, k: 0)
}

fn adapt_loop(delta delta: Int, k k: Int) -> Int {
  case delta > 455 {
    True -> adapt_loop(delta: delta / 35, k: k + 36)
    False -> k + 36 * delta / { delta + 38 }
  }
}
