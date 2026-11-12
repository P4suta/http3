//// Finite URLPattern component parser and Thompson automaton.
//// WHATWG 696b4029d52e5854044bac6b72cdb198cb962ed0, sections 2.1 and 2.2.
//// Regexp parts are rejected; canonical full/segment wildcards use primitives.

import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import http/internal/url_pattern/pathname
import http/internal/url_pattern/unicode

pub type Error {
  InvalidPattern
  WorkLimitExceeded
}

type Token {
  Char(Int)
  Escaped(Int)
  Name(String)
  Wildcard
  Full
  Segment
  Open
  Close
  Modifier(Int)
}

type Expression {
  Literal(Int)
  Any
  NonSeparator
  Sequence(List(Expression))
  Optional(Expression)
  Repeated(Expression, Bool)
}

type State {
  Character(Int, Int)
  Anything(Int)
  NotSeparator(Int, Int)
  Split(Int, Int)
  Accept
}

type Builder {
  Builder(next: Int, states: Dict(Int, State), separator: Int)
}

pub type Options {
  Options(
    separator: Int,
    prefix: Int,
    encode: fn(String) -> Result(String, Error),
  )
}

pub opaque type Compiled {
  Compiled(
    states: Dict(Int, State),
    start: Int,
    encode: fn(String) -> Result(String, Error),
  )
}

/// The fixed byte ceiling bounds tokens, AST nodes and automaton states.
pub fn compile_path(pattern: String) -> Result(Compiled, Error) {
  use _ <- result.try(case string.byte_size(pattern) <= 2048 {
    True -> Ok(Nil)
    False -> Error(WorkLimitExceeded)
  })
  compile_component(
    pattern: pattern,
    options: Options(47, 47, fn(input) { Ok(pathname.canonical_piece(input)) }),
  )
}

pub fn compile_component(
  pattern pattern: String,
  options options: Options,
) -> Result(Compiled, Error) {
  // Inherited, escaped base-URL pieces can exceed the authored pattern's 2048-byte ceiling.
  // The combined input and graph remain separately bounded.
  use _ <- result.try(case string.byte_size(pattern) <= 24_576 {
    True -> Ok(Nil)
    False -> Error(WorkLimitExceeded)
  })
  let codes =
    string.to_utf_codepoints(pattern) |> list.map(string.utf_codepoint_to_int)
  use tokens <- result.try(tokenize(
    input: codes,
    reversed: [],
    separator: options.separator,
  ))
  use expressions <- result.try(parse(tokens, dict.new(), [], options.prefix))
  use expressions <- result.try(normalize_sequence(
    expressions,
    [],
    [],
    options.encode,
  ))
  use _ <- result.try(reserve_sequence(expressions, 16_383))
  let #(start, builder) =
    compile_sequence(
      expressions,
      0,
      Builder(1, dict.from_list([#(0, Accept)]), options.separator),
    )
  case builder.next <= 16_384 {
    True -> Ok(Compiled(builder.states, start, options.encode))
    False -> Error(WorkLimitExceeded)
  }
}

fn reserve_sequence(
  expressions: List(Expression),
  remaining: Int,
) -> Result(Int, Error) {
  case expressions {
    _ if remaining < 0 -> Error(WorkLimitExceeded)
    [] -> Ok(remaining)
    [expression, ..rest] -> {
      use remaining <- result.try(case expression {
        Sequence(parts) -> reserve_sequence(parts, remaining)
        Optional(body) | Repeated(body, _) ->
          reserve_sequence([body], remaining - 1)
        Literal(_) | Any | NonSeparator -> Ok(remaining - 1)
      })
      reserve_sequence(rest, remaining)
    }
  }
}

/// Every visited edge/state consumes shared work credit, including epsilon closure.
/// An exhausted budget remains an error, never a negative match.
pub fn matches(
  compiled compiled: Compiled,
  input input: String,
  work work: Int,
) -> Result(#(Bool, Int), Error) {
  let remaining = work - string.byte_size(input) * 4
  use _ <- result.try(case string.byte_size(input) <= 8192 && remaining >= 0 {
    True -> Ok(Nil)
    False -> Error(WorkLimitExceeded)
  })
  use canonical <- result.try(compiled.encode(input))
  run_canonical(compiled: compiled, canonical: canonical, remaining: remaining)
}

/// Match a component of an already parsed URL.
/// Fixed-piece encoding callbacks belong to pattern construction and must not reinterpret complete hostnames or other canonical URL values during full URL matching.
pub fn matches_canonical(
  compiled compiled: Compiled,
  input input: String,
  work work: Int,
) -> Result(#(Bool, Int), Error) {
  let remaining = work - string.byte_size(input) * 4
  use _ <- result.try(case string.byte_size(input) <= 8192 && remaining >= 0 {
    True -> Ok(Nil)
    False -> Error(WorkLimitExceeded)
  })
  run_canonical(compiled: compiled, canonical: input, remaining: remaining)
}

fn run_canonical(
  compiled compiled: Compiled,
  canonical canonical: String,
  remaining remaining: Int,
) -> Result(#(Bool, Int), Error) {
  use _ <- result.try(case string.byte_size(canonical) <= 8192 {
    True -> Ok(Nil)
    False -> Error(WorkLimitExceeded)
  })
  let codes =
    canonical
    |> string.to_utf_codepoints
    |> list.map(string.utf_codepoint_to_int)
  run(compiled.states, codes, [compiled.start], remaining)
}

fn tokenize(
  input input: List(Int),
  reversed reversed: List(Token),
  separator separator: Int,
) -> Result(List(Token), Error) {
  case input {
    [] -> Ok(list.reverse(reversed))
    [92, code, ..rest] ->
      tokenize(
        input: rest,
        reversed: [Escaped(code), ..reversed],
        separator: separator,
      )
    [92] -> Error(InvalidPattern)
    [58, code, ..rest] -> {
      use _ <- result.try(case name_start(code) {
        True -> Ok(Nil)
        False -> Error(InvalidPattern)
      })
      let #(name, rest) = name_tail(rest, [code])
      tokenize(
        input: rest,
        reversed: [Name(name), ..reversed],
        separator: separator,
      )
    }
    [58] -> Error(InvalidPattern)
    [40, 46, 42, 41, ..rest] ->
      tokenize(input: rest, reversed: [Full, ..reversed], separator: separator)
    [40, 91, 94, 92, code, 93, 43, 63, 41, ..rest] if code == separator ->
      tokenize(
        input: rest,
        reversed: [Segment, ..reversed],
        separator: separator,
      )
    [40, 91, 94, 93, 43, 63, 41, ..rest] if separator == -1 ->
      tokenize(
        input: rest,
        reversed: [Segment, ..reversed],
        separator: separator,
      )
    [40, ..] | [41, ..] -> Error(InvalidPattern)
    [123, ..rest] ->
      tokenize(input: rest, reversed: [Open, ..reversed], separator: separator)
    [125, ..rest] ->
      tokenize(input: rest, reversed: [Close, ..reversed], separator: separator)
    [42, ..rest] ->
      tokenize(
        input: rest,
        reversed: [Wildcard, ..reversed],
        separator: separator,
      )
    [code, ..rest] if code == 43 || code == 63 ->
      tokenize(
        input: rest,
        reversed: [Modifier(code), ..reversed],
        separator: separator,
      )
    [code, ..rest] ->
      tokenize(
        input: rest,
        reversed: [Char(code), ..reversed],
        separator: separator,
      )
  }
}

fn name_start(code: Int) -> Bool {
  code == 95 || code == 36 || unicode.id_start(code)
}

fn name_tail(input: List(Int), reversed: List(Int)) -> #(String, List(Int)) {
  case input {
    [code, ..rest] ->
      case
        code == 36
        || code == 95
        || code == 8204
        || code == 8205
        || unicode.id_continue(code)
      {
        True -> name_tail(rest, [code, ..reversed])
        False -> #(codes_to_string(list.reverse(reversed)), input)
      }
    [] -> #(codes_to_string(list.reverse(reversed)), [])
  }
}

fn codes_to_string(codes: List(Int)) -> String {
  codes |> list.filter_map(string.utf_codepoint) |> string.from_utf_codepoints
}

// Canonicalization acts on each fixed piece.
// Normalizing the whole pattern first would incorrectly remove a variable before a following `/../` piece.
fn normalize_sequence(
  expressions: List(Expression),
  fixed: List(Int),
  reversed: List(Expression),
  encode: fn(String) -> Result(String, Error),
) -> Result(List(Expression), Error) {
  case expressions {
    // Unmodified braces have no matching effect.
    // The specification appends their fixed value to the same pending piece before canonicalization;
    // splitting here changes dot segments, IPv4 and Unicode composition.
    [Sequence(parts), ..rest] ->
      normalize_sequence(list.append(parts, rest), fixed, reversed, encode)
    [Literal(code), ..rest] ->
      normalize_sequence(rest, [code, ..fixed], reversed, encode)
    [expression, ..rest] -> {
      use reversed <- result.try(normalize_fixed(fixed, reversed, encode))
      use normalized <- result.try(normalize_expression(expression, encode))
      normalize_sequence(rest, [], [normalized, ..reversed], encode)
    }
    [] -> normalize_fixed(fixed, reversed, encode) |> result.map(list.reverse)
  }
}

fn normalize_fixed(
  fixed: List(Int),
  reversed: List(Expression),
  encode: fn(String) -> Result(String, Error),
) -> Result(List(Expression), Error) {
  case fixed {
    [] -> Ok(reversed)
    _ -> {
      use encoded <- result.try(
        fixed
        |> list.reverse
        |> codes_to_string
        |> encode,
      )
      let encoded =
        encoded
        |> string.to_utf_codepoints
        |> list.map(string.utf_codepoint_to_int)
      Ok(list.fold(encoded, reversed, fn(acc, code) { [Literal(code), ..acc] }))
    }
  }
}

fn normalize_expression(
  expression: Expression,
  encode: fn(String) -> Result(String, Error),
) -> Result(Expression, Error) {
  case expression {
    Sequence(expressions) ->
      normalize_sequence(expressions, [], [], encode) |> result.map(Sequence)
    Optional(body) -> normalize_expression(body, encode) |> result.map(Optional)
    Repeated(body, required) ->
      normalize_expression(body, encode)
      |> result.map(fn(value) { Repeated(value, required) })
    _ -> Ok(expression)
  }
}

// nolint: label_possible -- Token stream, unique names and reversed parts are threaded together.
fn parse(
  tokens: List(Token),
  names: Dict(String, Nil),
  reversed: List(Expression),
  prefix: Int,
) -> Result(List(Expression), Error) {
  case tokens {
    [] -> Ok(list.reverse(reversed))
    [Char(code), Name(_), ..]
      | [Char(code), Wildcard, ..]
      | [Char(code), Full, ..]
      | [Char(code), Segment, ..]
      if code == prefix
    -> {
      let rest = list.drop(tokens, 1)
      use #(body, rest, names) <- result.try(variable(rest, names))
      let #(expression, rest) = modified(Sequence([Literal(code), body]), rest)
      parse(rest, names, [expression, ..reversed], prefix)
    }
    [Name(_), ..] | [Wildcard, ..] | [Full, ..] | [Segment, ..] -> {
      use #(body, rest, names) <- result.try(variable(tokens, names))
      let #(expression, rest) = modified(body, rest)
      parse(rest, names, [expression, ..reversed], prefix)
    }
    [Char(code), ..rest] | [Escaped(code), ..rest] ->
      parse(rest, names, [Literal(code), ..reversed], prefix)
    [Open, ..rest] -> {
      use #(expression, rest, names) <- result.try(group(rest, names))
      parse(rest, names, [expression, ..reversed], prefix)
    }
    _ -> Error(InvalidPattern)
  }
}

fn group(
  tokens: List(Token),
  names: Dict(String, Nil),
) -> Result(#(Expression, List(Token), Dict(String, Nil)), Error) {
  let #(prefix, rest) = text(tokens, [])
  use #(body, rest, names) <- result.try(group_variable(rest, names))
  let #(suffix, rest) = text(rest, [])
  case rest {
    [Close, ..rest] -> {
      let middle = case body {
        Some(value) -> [value]
        None -> []
      }
      let expression =
        Sequence(list.append(prefix, list.append(middle, suffix)))
      let #(expression, rest) = modified(expression, rest)
      Ok(#(expression, rest, names))
    }
    _ -> Error(InvalidPattern)
  }
}

fn variable(
  tokens: List(Token),
  names: Dict(String, Nil),
) -> Result(#(Expression, List(Token), Dict(String, Nil)), Error) {
  case tokens {
    [Name(name), ..rest] ->
      case dict.has_key(names, name) {
        True -> Error(InvalidPattern)
        False -> {
          let #(body, rest) = case rest {
            [Full, ..tail] -> #(Repeated(Any, False), tail)
            [Segment, ..tail] -> #(Repeated(NonSeparator, True), tail)
            _ -> #(Repeated(NonSeparator, True), rest)
          }
          Ok(#(body, rest, dict.insert(names, name, Nil)))
        }
      }
    [Wildcard, ..rest] | [Full, ..rest] ->
      Ok(#(Repeated(Any, False), rest, names))
    [Segment, ..rest] -> Ok(#(Repeated(NonSeparator, True), rest, names))
    _ -> Error(InvalidPattern)
  }
}

fn group_variable(
  tokens: List(Token),
  names: Dict(String, Nil),
) -> Result(#(Option(Expression), List(Token), Dict(String, Nil)), Error) {
  case tokens {
    [Name(_), ..] | [Wildcard, ..] | [Full, ..] | [Segment, ..] -> {
      use #(body, rest, names) <- result.try(variable(tokens, names))
      Ok(#(Some(body), rest, names))
    }
    _ -> Ok(#(None, tokens, names))
  }
}

fn text(
  tokens: List(Token),
  reversed: List(Expression),
) -> #(List(Expression), List(Token)) {
  case tokens {
    [Char(code), ..rest] | [Escaped(code), ..rest] ->
      text(rest, [Literal(code), ..reversed])
    _ -> #(list.reverse(reversed), tokens)
  }
}

fn modified(
  body: Expression,
  tokens: List(Token),
) -> #(Expression, List(Token)) {
  case tokens {
    [Modifier(63), ..rest] -> #(Optional(body), rest)
    [Modifier(43), ..rest] -> #(Repeated(body, True), rest)
    [Wildcard, ..rest] -> #(Repeated(body, False), rest)
    _ -> #(body, tokens)
  }
}

fn add(state: State, builder: Builder) -> #(Int, Builder) {
  #(
    builder.next,
    Builder(
      ..builder,
      next: builder.next + 1,
      states: dict.insert(builder.states, builder.next, state),
    ),
  )
}

// nolint: label_possible -- Successor and graph builder follow the source expression.
fn compile_sequence(
  expressions: List(Expression),
  next: Int,
  builder: Builder,
) -> #(Int, Builder) {
  list.fold(list.reverse(expressions), #(next, builder), fn(acc, expression) {
    compile_expression(expression, acc.0, acc.1)
  })
}

// nolint: label_possible -- Successor and graph builder follow the source expression.
fn compile_expression(
  expression: Expression,
  next: Int,
  builder: Builder,
) -> #(Int, Builder) {
  case expression {
    Literal(code) -> add(Character(code, next), builder)
    Any -> add(Anything(next), builder)
    NonSeparator -> add(NotSeparator(builder.separator, next), builder)
    Sequence(expressions) -> compile_sequence(expressions, next, builder)
    Optional(body) -> {
      let #(start, builder) = compile_expression(body, next, builder)
      add(Split(start, next), builder)
    }
    Repeated(body, required) -> {
      let #(loop, builder) = add(Accept, builder)
      let #(start, builder) = compile_expression(body, loop, builder)
      let builder =
        Builder(
          ..builder,
          states: dict.insert(builder.states, loop, Split(start, next)),
        )
      #(
        case required {
          True -> start
          False -> loop
        },
        builder,
      )
    }
  }
}

// nolint: label_possible -- Every transition explicitly threads input, active states and work.
fn run(
  states: Dict(Int, State),
  input: List(Int),
  pending: List(Int),
  work: Int,
) -> Result(#(Bool, Int), Error) {
  use #(active, work) <- result.try(closure(
    states,
    pending,
    dict.new(),
    [],
    work,
  ))
  case input {
    [] -> Ok(#(list.contains(active, 0), work))
    [code, ..rest] -> {
      use #(next, work) <- result.try(advance(states, active, code, [], work))
      case next {
        [] -> Ok(#(False, work))
        _ -> run(states, rest, next, work)
      }
    }
  }
}

// nolint: label_possible -- Ordered graph/queue/visited/output/work accumulators expose convergence.
fn closure(
  states: Dict(Int, State),
  pending: List(Int),
  seen: Dict(Int, Nil),
  active: List(Int),
  work: Int,
) -> Result(#(List(Int), Int), Error) {
  case pending {
    [] -> Ok(#(active, work))
    _ if work <= 0 -> Error(WorkLimitExceeded)
    [id, ..rest] ->
      case dict.has_key(seen, id) {
        True -> closure(states, rest, seen, active, work - 1)
        False -> {
          let seen = dict.insert(seen, id, Nil)
          case dict.get(states, id) {
            Ok(Split(first, second)) ->
              closure(states, [first, second, ..rest], seen, active, work - 1)
            Ok(_) -> closure(states, rest, seen, [id, ..active], work - 1)
            Error(_) -> Error(InvalidPattern)
          }
        }
      }
  }
}

// nolint: label_possible -- Ordered graph/input/character/output/work accumulators expose consumption.
fn advance(
  states: Dict(Int, State),
  active: List(Int),
  code: Int,
  reversed: List(Int),
  work: Int,
) -> Result(#(List(Int), Int), Error) {
  case active {
    [] -> Ok(#(reversed, work))
    _ if work <= 0 -> Error(WorkLimitExceeded)
    [id, ..rest] -> {
      let next = case dict.get(states, id) {
        Ok(Character(expected, next)) if code == expected -> Some(next)
        Ok(Anything(next)) -> Some(next)
        Ok(NotSeparator(separator, next)) if code != separator -> Some(next)
        _ -> None
      }
      advance(
        states,
        rest,
        code,
        case next {
          Some(id) -> [id, ..reversed]
          None -> reversed
        },
        work - 1,
      )
    }
  }
}
