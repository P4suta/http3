//// Bounded WHATWG URLPattern constructor-string component boundaries.
//// Pinned algorithm: 696b4029d52e5854044bac6b72cdb198cb962ed0, section 1.6.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/component
import http/internal/url_pattern/constructor_lexer as lexer
import http/internal/url_pattern/encoding

pub type Part {
  Protocol
  Username
  Password
  Hostname
  Port
  Pathname
  Search
  Hash
}

type Stage {
  Init
  Authority
  Component(Part)
  Done
}

type Parser {
  Parser(
    input: List(UtfCodepoint),
    tokens: Dict(Int, lexer.Token),
    end: Int,
    index: Int,
    start: Int,
    stage: Stage,
    groups: Int,
    brackets: Int,
    special: Bool,
    parts: Dict(Part, String),
    work: Int,
  )
}

/// Returns raw component patterns, preserving absence separately from empty.
/// Component syntax and canonicalization are validated by the next layer.
pub fn parse(input: String) -> Result(Dict(Part, String), component.Error) {
  parse_with_work(input: input, work: 1_048_576)
  |> result.map(fn(parsed) { parsed.0 })
}

pub fn parse_with_work(
  input input: String,
  work work: Int,
) -> Result(#(Dict(Part, String), Int), component.Error) {
  use #(tokens, work) <- result.try(lexer.tokenize(input: input, work: work))
  let parser =
    Parser(
      string.to_utf_codepoints(input),
      tokens,
      string.to_utf_codepoints(input) |> list.length,
      0,
      0,
      Init,
      0,
      0,
      False,
      dict.new(),
      work,
    )
  use #(parts, remaining) <- result.try(walk(parser, 16_384))
  Ok(#(
    case dict.has_key(parts, Hostname) && !dict.has_key(parts, Port) {
      True -> dict.insert(parts, Port, "")
      False -> parts
    },
    remaining,
  ))
}

fn walk(
  parser: Parser,
  turns: Int,
) -> Result(#(Dict(Part, String), Int), component.Error) {
  case parser.stage {
    Done -> Ok(#(parser.parts, parser.work))
    _ if turns <= 0 || parser.work <= 0 -> Error(component.WorkLimitExceeded)
    _ -> {
      use next <- result.try(step(Parser(..parser, work: parser.work - 1)))
      walk(next, turns - 1)
    }
  }
}

fn step(parser: Parser) -> Result(Parser, component.Error) {
  let current = token(parser, parser.index)
  case current.kind {
    lexer.End -> Ok(at_end(parser))
    lexer.Open -> Ok(advance(Parser(..parser, groups: parser.groups + 1)))
    lexer.Close if parser.groups > 0 ->
      dispatch(Parser(..parser, groups: parser.groups - 1))
    _ if parser.groups > 0 -> Ok(advance(parser))
    _ -> dispatch(parser)
  }
}

fn at_end(parser: Parser) -> Parser {
  case parser.stage {
    Init -> {
      let parser = rewind(parser, Init)
      case char(parser, 35) {
        True -> change(parser: parser, stage: Component(Hash), skip: 1)
        False ->
          case search_prefix(parser) {
            True -> change(parser: parser, stage: Component(Search), skip: 1)
            False -> change(parser: parser, stage: Component(Pathname), skip: 0)
          }
      }
    }
    Authority -> rewind(parser, Component(Hostname))
    _ -> change(parser: parser, stage: Done, skip: 0)
  }
}

fn dispatch(parser: Parser) -> Result(Parser, component.Error) {
  case parser.stage {
    Init ->
      Ok(case char(parser, 58) {
        True -> rewind(parser, Component(Protocol))
        False -> advance(parser)
      })
    Component(Protocol) -> protocol_step(parser)
    Authority ->
      Ok(case char(parser, 64) {
        True -> rewind(parser, Component(Username))
        False ->
          case char(parser, 47) || search_prefix(parser) || char(parser, 35) {
            True -> rewind(parser, Component(Hostname))
            False -> advance(parser)
          }
      })
    Component(Username) ->
      Ok(case char(parser, 58) {
        True -> change(parser: parser, stage: Component(Password), skip: 1)
        False -> identity_end(parser)
      })
    Component(Password) -> Ok(identity_end(parser))
    Component(Hostname) -> Ok(hostname_step(parser))
    Component(Port) -> Ok(path_step(parser))
    Component(Pathname) -> Ok(query_step(parser))
    Component(Search) -> Ok(hash_step(parser))
    Component(Hash) | Done -> Ok(advance(parser))
  }
}

fn protocol_step(parser: Parser) -> Result(Parser, component.Error) {
  use <- bool.guard(!char(parser, 58), Ok(advance(parser)))
  let raw = piece(parser)
  let remaining = parser.work - string.byte_size(raw) * 8
  use _ <- result.try(case remaining >= 0 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  use compiled <- result.try(component.compile_component(
    pattern: raw,
    options: component.Options(-1, -1, fn(value) {
      encoding.encode(kind: encoding.Protocol, value: value)
    }),
  ))
  use #(special, remaining) <- result.try(special_scheme(
    compiled: compiled,
    schemes: ["ftp", "file", "http", "https", "ws", "wss"],
    work: remaining,
  ))
  let parser = Parser(..parser, special:, work: remaining)
  Ok(
    case
      non_special(token(parser, parser.index + 1), 47)
      && non_special(token(parser, parser.index + 2), 47)
    {
      True -> change(parser: parser, stage: Authority, skip: 3)
      False ->
        case special {
          True -> change(parser: parser, stage: Authority, skip: 1)
          False -> change(parser: parser, stage: Component(Pathname), skip: 1)
        }
    },
  )
}

fn identity_end(parser: Parser) -> Parser {
  case char(parser, 64) {
    True -> change(parser: parser, stage: Component(Hostname), skip: 1)
    False -> advance(parser)
  }
}

fn hostname_step(parser: Parser) -> Parser {
  case char(parser, 91), char(parser, 93), char(parser, 58) {
    True, _, _ -> advance(Parser(..parser, brackets: parser.brackets + 1))
    _, True, _ -> advance(Parser(..parser, brackets: parser.brackets - 1))
    _, _, True if parser.brackets == 0 ->
      change(parser: parser, stage: Component(Port), skip: 1)
    _, _, _ -> path_step(parser)
  }
}

fn path_step(parser: Parser) -> Parser {
  case char(parser, 47) {
    True -> change(parser: parser, stage: Component(Pathname), skip: 0)
    False -> query_step(parser)
  }
}

fn query_step(parser: Parser) -> Parser {
  case search_prefix(parser) {
    True -> change(parser: parser, stage: Component(Search), skip: 1)
    False -> hash_step(parser)
  }
}

fn hash_step(parser: Parser) -> Parser {
  case char(parser, 35) {
    True -> change(parser: parser, stage: Component(Hash), skip: 1)
    False -> advance(parser)
  }
}

fn change(parser parser: Parser, stage stage: Stage, skip skip: Int) -> Parser {
  let parts = case parser.stage {
    Component(part) -> dict.insert(parser.parts, part, piece(parser))
    _ -> parser.parts
  }
  let parts = fill_components(Parser(..parser, parts:), stage)
  Parser(
    ..parser,
    parts:,
    stage:,
    index: parser.index + skip,
    start: parser.index + skip,
  )
}

fn fill_components(parser: Parser, stage: Stage) -> Dict(Part, String) {
  let from = rank(parser.stage)
  let to = rank(stage)
  let parts = case
    from >= 0
    && from <= 3
    && to >= 5
    && to <= 8
    && !dict.has_key(parser.parts, Hostname)
  {
    True -> dict.insert(parser.parts, Hostname, "")
    False -> parser.parts
  }
  let parts = case
    from >= 0
    && from <= 5
    && to >= 7
    && to <= 8
    && !dict.has_key(parts, Pathname)
  {
    True ->
      dict.insert(parts, Pathname, case parser.special {
        True -> "/"
        False -> ""
      })
    False -> parts
  }
  case from >= 0 && from <= 6 && to == 8 && !dict.has_key(parts, Search) {
    True -> dict.insert(parts, Search, "")
    False -> parts
  }
}

fn rank(stage: Stage) -> Int {
  case stage {
    Init | Done -> -1
    Component(Protocol) -> 0
    Authority -> 1
    Component(Username) -> 2
    Component(Password) -> 3
    Component(Hostname) -> 4
    Component(Port) -> 5
    Component(Pathname) -> 6
    Component(Search) -> 7
    Component(Hash) -> 8
  }
}

fn rewind(parser: Parser, stage: Stage) -> Parser {
  Parser(..parser, stage:, index: parser.start)
}

fn advance(parser: Parser) -> Parser {
  Parser(..parser, index: parser.index + 1)
}

fn token(parser: Parser, index: Int) -> lexer.Token {
  dict.get(parser.tokens, index)
  |> result.unwrap(lexer.Token(lexer.End, parser.end, -1))
}

fn non_special(token: lexer.Token, code: Int) -> Bool {
  token.kind == lexer.Character && token.value == code
}

fn char(parser: Parser, code: Int) -> Bool {
  non_special(token(parser, parser.index), code)
}

fn search_prefix(parser: Parser) -> Bool {
  let current = token(parser, parser.index)
  case non_special(current, 63) {
    True -> True
    False ->
      case current.value == 63 {
        False -> False
        True ->
          case token(parser, parser.index - 1).kind {
            lexer.Name | lexer.Regexp | lexer.Close | lexer.Asterisk -> False
            _ -> True
          }
      }
  }
}

fn piece(parser: Parser) -> String {
  let first = token(parser, parser.start).position
  let last = token(parser, parser.index).position
  parser.input
  |> list.drop(first)
  |> list.take(last - first)
  |> string.from_utf_codepoints
}

fn special_scheme(
  compiled compiled: component.Compiled,
  schemes schemes: List(String),
  work work: Int,
) -> Result(#(Bool, Int), component.Error) {
  case schemes {
    [] -> Ok(#(False, work))
    [scheme, ..rest] -> {
      use #(matched, remaining) <- result.try(component.matches(
        compiled:,
        input: scheme,
        work:,
      ))
      case matched {
        True -> Ok(#(True, remaining))
        False ->
          special_scheme(compiled: compiled, schemes: rest, work: remaining)
      }
    }
  }
}
