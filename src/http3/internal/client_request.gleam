//// Pure normalization for bounded HTTP/3 client requests.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request.{type Request}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

/// A request ready for the backend adapter.
pub type PreparedRequest {
  PreparedRequest(
    host: String,
    port: Int,
    headers: List(#(String, String)),
    body: BitArray,
  )
}

/// A pure request-normalization failure.
pub type Error {
  InvalidScheme
  InvalidHost
  InvalidPort(Int)
  InvalidBody
  UnsupportedMethod(String)
  InvalidPath(String)
  InvalidHeader(String)
  InvalidContentLength
}

/// Validate and normalize a `gleam/http` request for HTTP/3.
pub fn prepare(request: Request(BitArray)) -> Result(PreparedRequest, Error) {
  case request.scheme {
    http.Https -> prepare_https_request(request)
    _ -> Error(InvalidScheme)
  }
}

fn prepare_https_request(
  request: Request(BitArray),
) -> Result(PreparedRequest, Error) {
  use _ <- result.try(validate_host(request.host))

  let port = case request.port {
    Some(port) -> port
    None -> 443
  }
  use _ <- result.try(validate_port(port))
  use _ <- result.try(validate_body(request.body))

  let method = http.method_to_string(request.method)
  use _ <- result.try(validate_method(method))
  use target <- result.try(request_target(request.path, request.query))
  use headers <- result.try(validate_headers(
    request.headers,
    bit_array.byte_size(request.body),
  ))

  let authority = authority(request.host, port)
  let headers = [
    #(":method", method),
    #(":scheme", "https"),
    #(":path", target),
    #(":authority", authority),
    ..headers
  ]

  Ok(PreparedRequest(request.host, port, headers, request.body))
}

fn validate_host(host: String) -> Result(Nil, Error) {
  use <- bool.guard(
    when: host == ""
      || string.trim(host) != host
      || !valid_visible_uri_text(host)
      || string.contains(host, "/")
      || string.contains(host, "?")
      || string.contains(host, "#")
      || string.contains(host, "@")
      || string.contains(host, "\\"),
    return: Error(InvalidHost),
  )
  Ok(Nil)
}

fn validate_port(port: Int) -> Result(Nil, Error) {
  use <- bool.guard(
    when: port <= 0 || port > 65_535,
    return: Error(InvalidPort(port)),
  )
  Ok(Nil)
}

fn validate_body(body: BitArray) -> Result(Nil, Error) {
  use <- bool.guard(
    when: bit_array.bit_size(body) % 8 != 0,
    return: Error(InvalidBody),
  )
  Ok(Nil)
}

fn validate_method(method: String) -> Result(Nil, Error) {
  case method {
    "CONNECT" -> Error(UnsupportedMethod(method))
    _ ->
      case http.parse_method(method) {
        Ok(_) -> Ok(Nil)
        Error(_) -> Error(UnsupportedMethod(method))
      }
  }
}

fn request_target(
  path: String,
  query: Option(String),
) -> Result(String, Error) {
  let path = case path {
    "" -> "/"
    path -> path
  }

  use <- bool.guard(
    when: !string.starts_with(path, "/")
      || !valid_visible_uri_text(path)
      || string.contains(path, "?")
      || string.contains(path, "#"),
    return: Error(InvalidPath(path)),
  )

  case query {
    Some(query) -> {
      let target = path <> "?" <> query
      use <- bool.guard(
        when: !valid_visible_uri_text(query) || string.contains(query, "#"),
        return: Error(InvalidPath(target)),
      )
      Ok(target)
    }
    None -> Ok(path)
  }
}

fn valid_visible_uri_text(value: String) -> Bool {
  list.all(string.to_utf_codepoints(value), fn(character) {
    let character = string.utf_codepoint_to_int(character)
    character > 32 && character != 127
  })
}

fn authority(host: String, port: Int) -> String {
  let host = case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }

  case port == 443 {
    True -> host
    False -> host <> ":" <> int.to_string(port)
  }
}

fn validate_headers(
  headers: List(#(String, String)),
  body_size: Int,
) -> Result(List(#(String, String)), Error) {
  validate_headers_loop(
    headers: headers,
    body_size: body_size,
    has_content_length: False,
    validated: [],
  )
}

fn validate_headers_loop(
  headers headers: List(#(String, String)),
  body_size body_size: Int,
  has_content_length has_content_length: Bool,
  validated validated: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  case headers {
    [] -> {
      let validated = list.reverse(validated)
      case body_size > 0 && !has_content_length {
        True -> Ok([#("content-length", int.to_string(body_size)), ..validated])
        False -> Ok(validated)
      }
    }
    [#(name, value), ..rest] -> {
      use _ <- result.try(validate_header(name, value))
      case name {
        "content-length" -> {
          use <- bool.guard(
            when: has_content_length,
            return: Error(InvalidContentLength),
          )
          use _ <- result.try(validate_content_length(value, body_size))
          validate_headers_loop(
            headers: rest,
            body_size: body_size,
            has_content_length: True,
            validated: [#(name, value), ..validated],
          )
        }
        _ ->
          validate_headers_loop(
            headers: rest,
            body_size: body_size,
            has_content_length: has_content_length,
            validated: [#(name, value), ..validated],
          )
      }
    }
  }
}

fn validate_content_length(
  value: String,
  body_size: Int,
) -> Result(Nil, Error) {
  case int.parse(string.trim(value)) {
    Ok(length) ->
      case length == body_size {
        True -> Ok(Nil)
        False -> Error(InvalidContentLength)
      }
    Error(_) -> Error(InvalidContentLength)
  }
}

fn validate_header(name: String, value: String) -> Result(Nil, Error) {
  use <- bool.guard(
    when: !valid_header_name(name)
      || string.starts_with(name, ":")
      || !valid_header_value(value)
      || forbidden_header(name, value),
    return: Error(InvalidHeader(name)),
  )
  Ok(Nil)
}

fn valid_header_name(name: String) -> Bool {
  name != ""
  && list.all(string.to_utf_codepoints(name), fn(character) {
    let character = string.utf_codepoint_to_int(character)
    character >= 48
    && character <= 57
    || character >= 97
    && character <= 122
    || list.contains(
      [33, 35, 36, 37, 38, 39, 42, 43, 45, 46, 94, 95, 96, 124, 126],
      character,
    )
  })
}

fn valid_header_value(value: String) -> Bool {
  list.all(string.to_utf_codepoints(value), fn(character) {
    let character = string.utf_codepoint_to_int(character)
    character == 9 || character >= 32 && character != 127
  })
}

fn forbidden_header(name: String, value: String) -> Bool {
  case name {
    "connection"
    | "host"
    | "keep-alive"
    | "proxy-connection"
    | "transfer-encoding"
    | "upgrade" -> True
    "te" -> string.lowercase(string.trim(value)) != "trailers"
    _ -> False
  }
}
