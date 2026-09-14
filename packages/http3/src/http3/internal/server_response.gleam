//// Pure validation for outbound HTTP/3 server response heads.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

/// A response validation failure.
pub type Error {
  InvalidStatus(Int)
  InvalidHeader(String)
  InvalidContentLength
}

/// Validate a bounded response and its declared content length.
pub fn prepare_bounded(
  status status: Int,
  headers headers: List(#(String, String)),
  body_size body_size: Int,
) -> Result(List(#(String, String)), Error) {
  use _ <- result.try(validate_status(status))
  validate_headers(headers, Some(body_size))
}

/// Validate a bounded HEAD response without equating its declared
/// representation length to the transmitted empty body.
pub fn prepare_bounded_head(
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  use _ <- result.try(validate_status(status))
  validate_headers(headers, None)
}

/// Validate a streaming response head.
pub fn prepare_streaming(
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(#(List(#(String, String)), Option(Int)), Error) {
  use _ <- result.try(validate_status(status))
  use headers <- result.try(validate_headers(headers, None))
  use declared_content_length <- result.try(find_content_length(headers))
  Ok(#(headers, declared_content_length))
}

/// Validate one informational response head. HTTP/3 forbids status 101 and
/// informational responses cannot carry a Content-Length field.
pub fn prepare_informational(
  status status: Int,
  headers headers: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  use _ <- result.try(validate_informational_status(status))
  use headers <- result.try(validate_headers(headers, None))
  use declared_content_length <- result.try(find_content_length(headers))
  case declared_content_length {
    Some(_) -> Error(InvalidContentLength)
    None -> Ok(headers)
  }
}

/// Validate a trailer field section without message-control fields.
pub fn prepare_trailers(
  headers: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  validate_trailers(headers, [])
}

/// Validate regular fields for a same-origin server push promise.
pub fn prepare_push_request(
  headers: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  use headers <- result.try(validate_headers(headers, None))
  use length <- result.try(find_content_length(headers))
  case length {
    Some(_) -> Error(InvalidContentLength)
    None -> Ok(headers)
  }
}

fn find_content_length(
  headers: List(#(String, String)),
) -> Result(Option(Int), Error) {
  case headers {
    [] -> Ok(None)
    [#("content-length", value), ..] ->
      parse_content_length(value) |> result.map(Some)
    [_, ..rest] -> find_content_length(rest)
  }
}

fn validate_status(status: Int) -> Result(Nil, Error) {
  use <- bool.guard(
    when: status < 200 || status > 599,
    return: Error(InvalidStatus(status)),
  )
  Ok(Nil)
}

fn validate_informational_status(status: Int) -> Result(Nil, Error) {
  use <- bool.guard(
    when: status < 100 || status >= 200 || status == 101,
    return: Error(InvalidStatus(status)),
  )
  Ok(Nil)
}

fn validate_trailers(
  headers: List(#(String, String)),
  validated: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  case headers {
    [] -> Ok(list.reverse(validated))
    [#(name, value) as field, ..rest] -> {
      use _ <- result.try(validate_header(name, value))
      use <- bool.guard(
        when: forbidden_trailer(name),
        return: Error(InvalidHeader(name)),
      )
      validate_trailers(rest, [field, ..validated])
    }
  }
}

fn validate_headers(
  headers: List(#(String, String)),
  body_size: Option(Int),
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
  body_size body_size: Option(Int),
  has_content_length has_content_length: Bool,
  validated validated: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  case headers {
    [] -> Ok(list.reverse(validated))
    [#(name, value), ..rest] -> {
      use _ <- result.try(validate_header(name, value))
      case name {
        "content-length" ->
          validate_content_length_header(
            rest: rest,
            name: name,
            value: value,
            body_size: body_size,
            has_content_length: has_content_length,
            validated: validated,
          )
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

fn validate_content_length_header(
  rest rest: List(#(String, String)),
  name name: String,
  value value: String,
  body_size body_size: Option(Int),
  has_content_length has_content_length: Bool,
  validated validated: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  use <- bool.guard(
    when: has_content_length,
    return: Error(InvalidContentLength),
  )
  use length <- result.try(parse_content_length(value))
  use <- bool.guard(
    when: case body_size {
      Some(size) -> length != size
      None -> False
    },
    return: Error(InvalidContentLength),
  )
  validate_headers_loop(
    headers: rest,
    body_size: body_size,
    has_content_length: True,
    validated: [#(name, value), ..validated],
  )
}

fn parse_content_length(value: String) -> Result(Int, Error) {
  case int.parse(string.trim(value)) {
    Ok(length) if length >= 0 -> Ok(length)
    _ -> Error(InvalidContentLength)
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

fn forbidden_trailer(name: String) -> Bool {
  list.contains(
    [
      "authorization",
      "content-encoding",
      "content-length",
      "content-range",
      "content-type",
      "host",
      "proxy-authenticate",
      "proxy-authorization",
      "te",
      "trailer",
      "www-authenticate",
    ],
    name,
  )
}
