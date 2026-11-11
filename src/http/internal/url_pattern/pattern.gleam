//// Complete bounded URLPattern construction over a parsed HTTP URL context.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/component
import http/internal/url_pattern/constructor
import http/internal/url_pattern/encoding
import http/internal/url_pattern/host
import http/internal/url_pattern/pathname
import http/internal/url_pattern/url

pub opaque type Compiled {
  Compiled(parts: List(#(constructor.Part, component.Compiled)))
}

pub fn compile(
  input input: String,
  base base: url.Url,
  work work: Int,
) -> Result(#(Compiled, Int), component.Error) {
  use #(parts, work) <- result.try(constructor.parse_with_work(
    input: input,
    work: work,
  ))
  let parts = apply_base(parts, base) |> remove_default_port
  let protocol_pattern = get(parts, constructor.Protocol)
  use #(protocol, work) <- result.try(compile_part(
    part: constructor.Protocol,
    raw: protocol_pattern,
    special: False,
    work: work,
  ))
  use #(special, work) <- result.try(special_scheme(
    compiled: protocol,
    schemes: ["ftp", "file", "http", "https", "ws", "wss"],
    work: work,
  ))
  compile_rest(
    remaining: [
      constructor.Username,
      constructor.Password,
      constructor.Hostname,
      constructor.Port,
      constructor.Pathname,
      constructor.Search,
      constructor.Hash,
    ],
    parts: parts,
    special: special,
    reversed: [#(constructor.Protocol, protocol)],
    work: work,
  )
}

pub fn matches(
  compiled compiled: Compiled,
  input input: url.Url,
  work work: Int,
) -> Result(#(Bool, Int), component.Error) {
  match_parts(parts: compiled.parts, input: input, work: work)
}

fn apply_base(
  parts: Dict(constructor.Part, String),
  base: url.Url,
) -> Dict(constructor.Part, String) {
  let inherited =
    inherit(
      remaining: [
        constructor.Protocol,
        constructor.Hostname,
        constructor.Port,
        constructor.Pathname,
        constructor.Search,
        constructor.Hash,
      ],
      original: parts,
      base: base,
      blocked: False,
      parts: parts,
    )
  let inherited = case dict.get(parts, constructor.Pathname) {
    Error(Nil) -> inherited
    Ok(path) ->
      case absolute_path(path) {
        True -> inherited
        False -> {
          let directory =
            base.pathname
            |> string.split(on: "/")
            |> list.reverse
            |> list.drop(1)
            |> list.reverse
            |> string.join("/")
          dict.insert(
            inherited,
            constructor.Pathname,
            escape(directory <> "/") <> path,
          )
        }
      }
  }
  inherited
  |> strip(constructor.Protocol, fn(value) {
    case string.ends_with(value, ":") {
      True -> string.drop_end(value, 1)
      False -> value
    }
  })
  |> strip(constructor.Search, fn(value) {
    case value {
      "?" <> rest -> rest
      _ -> value
    }
  })
  |> strip(constructor.Hash, fn(value) {
    case value {
      "#" <> rest -> rest
      _ -> value
    }
  })
}

fn strip(
  parts: Dict(constructor.Part, String),
  part: constructor.Part,
  transform: fn(String) -> String,
) -> Dict(constructor.Part, String) {
  case dict.get(parts, part) {
    Ok(value) -> dict.insert(parts, part, transform(value))
    Error(Nil) -> parts
  }
}

fn inherit(
  remaining remaining: List(constructor.Part),
  original original: Dict(constructor.Part, String),
  base base: url.Url,
  blocked blocked: Bool,
  parts parts: Dict(constructor.Part, String),
) -> Dict(constructor.Part, String) {
  case remaining {
    [] -> parts
    [part, ..rest] -> {
      let blocked = blocked || dict.has_key(original, part)
      let parts = case blocked {
        True -> parts
        False -> dict.insert(parts, part, escape(value(base, part)))
      }
      inherit(
        remaining: rest,
        original: original,
        base: base,
        blocked: blocked,
        parts: parts,
      )
    }
  }
}

fn absolute_path(path: String) -> Bool {
  string.starts_with(path, "/")
  || string.starts_with(path, "\\/")
  || string.starts_with(path, "{/")
}

fn escape(value: String) -> String {
  value
  |> string.to_utf_codepoints
  |> list.map(fn(code) {
    let text = string.from_utf_codepoints([code])
    case
      list.contains(
        [43, 42, 63, 58, 123, 125, 40, 41, 92],
        string.utf_codepoint_to_int(code),
      )
    {
      True -> "\\" <> text
      False -> text
    }
  })
  |> string.concat
}

fn get(
  parts: Dict(constructor.Part, String),
  part: constructor.Part,
) -> String {
  dict.get(parts, part) |> result.unwrap("*")
}

fn compile_rest(
  remaining remaining: List(constructor.Part),
  parts parts: Dict(constructor.Part, String),
  special special: Bool,
  reversed reversed: List(#(constructor.Part, component.Compiled)),
  work work: Int,
) -> Result(#(Compiled, Int), component.Error) {
  case remaining {
    [] -> Ok(#(Compiled(list.reverse(reversed)), work))
    [part, ..rest] -> {
      use #(compiled, work) <- result.try(compile_part(
        part: part,
        raw: get(parts, part),
        special: special,
        work: work,
      ))
      compile_rest(
        remaining: rest,
        parts: parts,
        special: special,
        reversed: [#(part, compiled), ..reversed],
        work: work,
      )
    }
  }
}

fn compile_part(
  part part: constructor.Part,
  raw raw: String,
  special special: Bool,
  work work: Int,
) -> Result(#(component.Compiled, Int), component.Error) {
  let remaining = work - string.byte_size(raw) * 8 - 1
  use _ <- result.try(case remaining >= 0 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  let options = options(part: part, raw: raw, special: special)
  use compiled <- result.try(component.compile_component(
    pattern: raw,
    options: options,
  ))
  Ok(#(compiled, remaining))
}

fn remove_default_port(
  parts: Dict(constructor.Part, String),
) -> Dict(constructor.Part, String) {
  // This high-level constructor step precedes component encoding.
  // Patterns that later normalize to a default port are not literal default ports.
  let default = case
    get(parts, constructor.Protocol),
    get(parts, constructor.Port)
  {
    "https", "443" | "wss", "443" | "http", "80" | "ws", "80" | "ftp", "21" ->
      True
    _, _ -> False
  }
  case default {
    True -> dict.insert(parts, constructor.Port, "")
    False -> parts
  }
}

fn options(
  part part: constructor.Part,
  raw raw: String,
  special special: Bool,
) -> component.Options {
  case part {
    constructor.Protocol -> generic(encoding.Protocol)
    constructor.Username | constructor.Password -> generic(encoding.Userinfo)
    constructor.Port -> generic(encoding.Port)
    constructor.Search -> generic(encoding.Search)
    constructor.Hash -> generic(encoding.Hash)
    constructor.Pathname ->
      case special {
        True ->
          component.Options(47, 47, fn(value) {
            Ok(pathname.canonical_piece(value))
          })
        False -> generic(encoding.OpaquePath)
      }
    constructor.Hostname ->
      case
        string.starts_with(raw, "[")
        || string.starts_with(raw, "{[")
        || string.starts_with(raw, "\\[")
      {
        True ->
          component.Options(46, -1, fn(value) {
            encoding.encode(kind: encoding.Ipv6Pattern, value: value)
          })
        False -> component.Options(46, -1, hostname_piece)
      }
  }
}

fn generic(kind: encoding.Kind) -> component.Options {
  component.Options(-1, -1, fn(value) {
    encoding.encode(kind: kind, value: value)
  })
}

fn hostname_piece(value: String) -> Result(String, component.Error) {
  case value {
    "" -> Ok("")
    _ -> {
      // URLPattern's callback uses the URL parser's hostname state.
      // Its preprocessing and delimiter handling differ from a complete host parse; the strict host parser remains shared with actual URL input.
      let bytes =
        value
        |> string.replace("\t", "")
        |> string.replace("\n", "")
        |> string.replace("\r", "")
        |> bit_array.from_string
      let length = hostname_length(bytes, 0)
      use prefix <- result.try(case bytes {
        <<prefix:bytes-size(length), _:bits>> ->
          bit_array.to_string(prefix)
          |> result.replace_error(component.InvalidPattern)
        _ -> Error(component.InvalidPattern)
      })
      host.canonicalize(prefix)
      |> result.replace_error(component.InvalidPattern)
    }
  }
}

fn hostname_length(input: BitArray, length: Int) -> Int {
  case input {
    <<code, _:bits>> if code == 47 || code == 92 || code == 63 || code == 35 ->
      length
    <<_, rest:bits>> -> hostname_length(rest, length + 1)
    _ -> length
  }
}

fn value(input: url.Url, part: constructor.Part) -> String {
  case part {
    constructor.Protocol -> input.protocol
    constructor.Username -> input.username
    constructor.Password -> input.password
    constructor.Hostname -> input.hostname
    constructor.Port -> input.port
    constructor.Pathname -> input.pathname
    constructor.Search -> input.search
    constructor.Hash -> input.hash
  }
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

fn match_parts(
  parts parts: List(#(constructor.Part, component.Compiled)),
  input input: url.Url,
  work work: Int,
) -> Result(#(Bool, Int), component.Error) {
  case parts {
    [] -> Ok(#(True, work))
    [#(part, compiled), ..rest] -> {
      use #(matched, remaining) <- result.try(component.matches_canonical(
        compiled:,
        input: value(input, part),
        work:,
      ))
      case matched {
        False -> Ok(#(False, remaining))
        True -> match_parts(parts: rest, input: input, work: remaining)
      }
    }
  }
}
