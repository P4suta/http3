//// Bounded special HTTP(S) URL context for dictionary URLPattern matching.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import http/internal/url_pattern/component
import http/internal/url_pattern/encoding
import http/internal/url_pattern/host
import http/internal/url_pattern/pathname

pub type Url {
  Url(
    protocol: String,
    username: String,
    password: String,
    hostname: String,
    port: String,
    pathname: String,
    search: String,
    hash: String,
    has_query: Bool,
    has_fragment: Bool,
    has_userinfo: Bool,
  )
}

/// Complete HTTP(S) URLs only.
/// Pattern constructors are parsed separately;
/// credentials and delimiters cannot be confused with hostname characters.
pub fn parse(input: String) -> Result(Url, component.Error) {
  use _ <- result.try(case string.byte_size(input) <= 10_240 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  let input = preprocess(input)
  use #(scheme, rest) <- result.try(
    string.split_once(input, ":")
    |> result.replace_error(component.InvalidPattern),
  )
  let protocol = string.lowercase(scheme)
  use _ <- result.try(case protocol == "https" || protocol == "http" {
    True -> Ok(Nil)
    False -> Error(component.InvalidPattern)
  })
  use #(authority, suffix) <- result.try(split_authority(
    bit_array.from_string(rest) |> skip_slashes,
  ))
  use #(username, password, address, has_userinfo) <- result.try(userinfo(
    authority,
  ))
  use #(hostname, port) <- result.try(host_port(address, protocol))
  let #(without_hash, fragment, has_fragment) = optional_split(suffix, "#")
  let #(path, query, has_query) = optional_split(without_hash, "?")
  let path = case path {
    "" -> "/"
    _ -> path
  }
  let pathname = pathname.canonical_piece(path)
  use _ <- result.try(case string.byte_size(pathname) <= 8192 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  use search <- result.try(encoding.encode(kind: encoding.Search, value: query))
  use hash <- result.try(encoding.encode(kind: encoding.Hash, value: fragment))
  let parsed =
    Url(
      protocol,
      username,
      password,
      hostname,
      port,
      pathname,
      search,
      hash,
      has_query,
      has_fragment,
      has_userinfo,
    )
  use _ <- result.try(case serialized_size(parsed) <= 10_240 {
    True -> Ok(Nil)
    False -> Error(component.WorkLimitExceeded)
  })
  Ok(parsed)
}

pub fn origin(value: Url) -> String {
  value.protocol
  <> "://"
  <> value.hostname
  <> case value.port {
    "" -> ""
    port -> ":" <> port
  }
}

fn preprocess(input: String) -> String {
  input
  |> string.to_utf_codepoints
  |> trim_controls
  |> list.reverse
  |> trim_controls
  |> list.reverse
  |> string.from_utf_codepoints
  |> string.replace("\t", "")
  |> string.replace("\n", "")
  |> string.replace("\r", "")
}

fn trim_controls(input: List(UtfCodepoint)) -> List(UtfCodepoint) {
  case input {
    [first, ..rest] ->
      case string.utf_codepoint_to_int(first) <= 32 {
        True -> trim_controls(rest)
        False -> input
      }
    [] -> []
  }
}

fn skip_slashes(input: BitArray) -> BitArray {
  case input {
    <<47, rest:bits>> | <<92, rest:bits>> -> skip_slashes(rest)
    _ -> input
  }
}

fn split_authority(
  input: BitArray,
) -> Result(#(String, String), component.Error) {
  let size = authority_size(input, 0)
  case input {
    <<head:bytes-size(size), tail:bits>> -> {
      use head <- result.try(
        bit_array.to_string(head)
        |> result.replace_error(component.InvalidPattern),
      )
      use tail <- result.try(
        bit_array.to_string(tail)
        |> result.replace_error(component.InvalidPattern),
      )
      Ok(#(head, tail))
    }
    _ -> Error(component.InvalidPattern)
  }
}

fn authority_size(input: BitArray, size: Int) -> Int {
  case input {
    <<code, _rest:bits>>
      if code == 47 || code == 92 || code == 63 || code == 35
    -> size
    <<_, rest:bits>> -> authority_size(rest, size + 1)
    _ -> size
  }
}

fn userinfo(
  authority: String,
) -> Result(#(String, String, String, Bool), component.Error) {
  case authority |> string.split(on: "@") |> list.reverse {
    [address] -> Ok(#("", "", address, False))
    [address, ..parts] -> {
      let credentials = parts |> list.reverse |> string.join("@")
      let #(user, password, _) = optional_split(credentials, ":")
      use user <- result.try(encoding.encode(
        kind: encoding.Userinfo,
        value: user,
      ))
      use password <- result.try(encoding.encode(
        kind: encoding.Userinfo,
        value: password,
      ))
      Ok(#(user, password, address, True))
    }
    [] -> Error(component.InvalidPattern)
  }
}

fn host_port(
  address: String,
  protocol: String,
) -> Result(#(String, String), component.Error) {
  use #(hostname, port) <- result.try(case string.starts_with(address, "[") {
    True -> bracketed_host(address)
    False -> {
      let #(hostname, port, _) = optional_split(address, ":")
      Ok(#(hostname, port))
    }
  })
  use hostname <- result.try(
    host.canonicalize(hostname)
    |> result.replace_error(component.InvalidPattern),
  )
  use _ <- result.try(case digits(bit_array.from_string(port)) {
    True -> Ok(Nil)
    False -> Error(component.InvalidPattern)
  })
  use port <- result.try(encoding.encode(kind: encoding.Port, value: port))
  Ok(
    #(hostname, case protocol, port {
      "https", "443" | "http", "80" -> ""
      _, _ -> port
    }),
  )
}

fn bracketed_host(
  address: String,
) -> Result(#(String, String), component.Error) {
  use #(prefix, rest) <- result.try(
    string.split_once(address, "]")
    |> result.replace_error(component.InvalidPattern),
  )
  case rest {
    "" -> Ok(#(prefix <> "]", ""))
    ":" <> port -> Ok(#(prefix <> "]", port))
    _ -> Error(component.InvalidPattern)
  }
}

fn digits(input: BitArray) -> Bool {
  case input {
    <<>> -> True
    <<code, rest:bits>> if code >= 48 && code <= 57 -> digits(rest)
    _ -> False
  }
}

fn optional_split(input: String, delimiter: String) -> #(String, String, Bool) {
  case string.split_once(input, delimiter) {
    Ok(#(first, rest)) -> #(first, rest, True)
    Error(Nil) -> #(input, "", False)
  }
}

fn serialized_size(value: Url) -> Int {
  [
    value.protocol,
    value.username,
    value.password,
    value.hostname,
    value.port,
    value.pathname,
    value.search,
    value.hash,
  ]
  |> list.map(string.byte_size)
  |> list.fold(16, fn(total, bytes) { total + bytes })
}
