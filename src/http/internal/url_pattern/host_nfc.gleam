//// Pure Unicode16 canonical decomposition, ordering and composition.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: MIT OR Apache-2.0

import gleam/int
import gleam/list
import http/internal/url_pattern/host_data as data

pub fn normalize(input: List(Int)) -> List(Int) {
  input
  |> list.flat_map(decompose)
  |> order_segments(segment: [], reversed: [])
  |> compose(starter: -1, marks: [], previous: 0, reversed: [])
}

fn decompose(code: Int) -> List(Int) {
  case code >= 44_032 && code < 55_204 {
    False -> data.decomposition(code)
    True -> {
      let index = code - 44_032
      let leading = 4352 + index / 588
      let vowel = 4449 + index % 588 / 28
      case index % 28 {
        0 -> [leading, vowel]
        trailing -> [leading, vowel, 4519 + trailing]
      }
    }
  }
}

fn order_segments(
  input input: List(Int),
  segment segment: List(Int),
  reversed reversed: List(List(Int)),
) -> List(Int) {
  case input {
    [] -> list.reverse([order(segment), ..reversed]) |> list.flatten
    [code, ..rest] ->
      case data.ccc(code) == 0 {
        True ->
          order_segments(input: rest, segment: [code], reversed: [
            order(segment),
            ..reversed
          ])
        False ->
          order_segments(
            input: rest,
            segment: [code, ..segment],
            reversed: reversed,
          )
      }
  }
}

fn order(reversed: List(Int)) -> List(Int) {
  reversed
  |> list.reverse
  |> list.sort(fn(a, b) { int.compare(data.ccc(a), data.ccc(b)) })
}

fn compose(
  input input: List(Int),
  starter starter: Int,
  marks marks: List(Int),
  previous previous: Int,
  reversed reversed: List(Int),
) -> List(Int) {
  case input {
    [] ->
      flush(starter: starter, marks: marks, reversed: reversed) |> list.reverse
    [code, ..rest] -> {
      let class = data.ccc(code)
      let combined = combine(first: starter, second: code)
      case combined >= 0 && { previous == 0 || previous < class } {
        True ->
          compose(
            input: rest,
            starter: combined,
            marks: marks,
            previous: previous,
            reversed: reversed,
          )
        False ->
          case class == 0 {
            True ->
              compose(
                input: rest,
                starter: code,
                marks: [],
                previous: 0,
                reversed: flush(
                  starter: starter,
                  marks: marks,
                  reversed: reversed,
                ),
              )
            False ->
              compose(
                input: rest,
                starter: starter,
                marks: [code, ..marks],
                previous: class,
                reversed: reversed,
              )
          }
      }
    }
  }
}

fn flush(
  starter starter: Int,
  marks marks: List(Int),
  reversed reversed: List(Int),
) -> List(Int) {
  case starter < 0 {
    True -> list.append(marks, reversed)
    False -> list.append(marks, [starter, ..reversed])
  }
}

fn combine(first first: Int, second second: Int) -> Int {
  case first {
    leading
      if leading >= 4352 && leading < 4371 && second >= 4449 && second < 4470
    -> 44_032 + { leading - 4352 } * 588 + { second - 4449 } * 28
    syllable
      if syllable >= 44_032
      && syllable < 55_204
      && { syllable - 44_032 } % 28 == 0
      && second > 4519
      && second < 4547
    -> syllable + second - 4519
    value if value >= 0 -> data.composition(first: value, second: second)
    _ -> -1
  }
}
