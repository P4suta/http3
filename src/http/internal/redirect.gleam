//// Safe redirect target resolution and request regeneration.

import gleam/bool
import gleam/http.{type Method, type Scheme, Get, Head, Http, Https, Post}
import gleam/http/request.{type Request, Request}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import http/body
import http/error

type Destination {
  Destination(
    scheme: Scheme,
    host: String,
    port: Option(Int),
    path: String,
    query: Option(String),
  )
}

/// Resolve one redirect and construct a fresh safe request.
///
/// The caller remains responsible for enforcing the finite redirect count.
pub fn follow(
  outgoing outgoing: Request(body.Body),
  status status: Int,
  location location: String,
) -> Result(Request(body.Body), error.Error) {
  use destination <- result.try(resolve(outgoing, location))
  use #(method, redirected_body, remove_representation_headers) <- result.try(
    redirected_payload(outgoing, status),
  )
  let Destination(scheme, host, port, path, query) = destination
  let headers = case remove_representation_headers {
    True -> strip_representation_headers(outgoing.headers)
    False -> outgoing.headers
  }
  let headers = case same_origin(outgoing, destination) {
    True -> headers
    False -> strip_credentials(headers)
  }
  Ok(Request(
    method: method,
    headers: headers,
    body: redirected_body,
    scheme: scheme,
    host: host,
    port: port,
    path: path,
    query: query,
  ))
}

fn redirected_payload(
  outgoing: Request(body.Body),
  status: Int,
) -> Result(#(Method, body.Body, Bool), error.Error) {
  case status, outgoing.method {
    303, Head -> Ok(#(Head, body.empty(), True))
    303, _ -> Ok(#(Get, body.empty(), True))
    301, Post | 302, Post -> Ok(#(Get, body.empty(), True))
    301, _ | 302, _ | 307, _ | 308, _ ->
      body.replay(outgoing.body)
      |> result.map(fn(replayed) { #(outgoing.method, replayed, False) })
    _, _ -> Error(redirect_policy_error())
  }
}

fn resolve(
  outgoing: Request(body.Body),
  location: String,
) -> Result(Destination, error.Error) {
  use <- require(
    location != ""
    && !string.contains(location, "\r")
    && !string.contains(location, "\n")
    && !string.contains(location, "\u{0000}")
    && valid_uri_reference(location),
  )
  use reference <- result.try(
    uri.parse(location) |> result.replace_error(redirect_policy_error()),
  )
  use <- require(reference.userinfo == None)
  use <- require(valid_reference_authority(reference))
  use merged <- result.try(
    uri.merge(request.to_uri(outgoing), reference)
    |> result.replace_error(redirect_policy_error()),
  )
  destination(
    reference: reference,
    merged: merged,
    source_scheme: outgoing.scheme,
  )
}

fn valid_uri_reference(value: String) -> Bool {
  valid_uri_codepoints(string.to_utf_codepoints(value))
}

fn valid_uri_codepoints(codepoints: List(UtfCodepoint)) -> Bool {
  case codepoints {
    [] -> True
    [first, second, third, ..rest] ->
      case string.utf_codepoint_to_int(first) {
        37 ->
          is_hexadecimal(string.utf_codepoint_to_int(second))
          && is_hexadecimal(string.utf_codepoint_to_int(third))
          && valid_uri_codepoints(rest)
        value ->
          uri_character(value) && valid_uri_codepoints([second, third, ..rest])
      }
    [first, ..rest] -> {
      let value = string.utf_codepoint_to_int(first)
      value != 37 && uri_character(value) && valid_uri_codepoints(rest)
    }
  }
}

fn is_hexadecimal(value: Int) -> Bool {
  value >= 48
  && value <= 57
  || value >= 65
  && value <= 70
  || value >= 97
  && value <= 102
}

fn uri_character(value: Int) -> Bool {
  value >= 65
  && value <= 90
  || value >= 97
  && value <= 122
  || value >= 48
  && value <= 57
  || value == 45
  || value == 46
  || value == 95
  || value == 126
  || value == 58
  || value == 47
  || value == 63
  || value == 35
  || value == 91
  || value == 93
  || value == 64
  || value == 33
  || value == 36
  || value == 38
  || value == 39
  || value == 40
  || value == 41
  || value == 42
  || value == 43
  || value == 44
  || value == 59
  || value == 61
}

fn destination(
  reference reference: uri.Uri,
  merged merged: uri.Uri,
  source_scheme source_scheme: Scheme,
) -> Result(Destination, error.Error) {
  use scheme <- result.try(case merged.scheme {
    Some("http") -> Ok(Http)
    Some("https") -> Ok(Https)
    _ -> Error(redirect_policy_error())
  })
  use <- require(!{ source_scheme == Https && scheme == Http })
  use host <- result.try(case merged.host {
    Some(host) ->
      case host != "" && !string.contains(host, "\u{0000}") {
        True -> Ok(string.lowercase(host))
        False -> Error(redirect_policy_error())
      }
    _ -> Error(redirect_policy_error())
  })
  let port = case reference.host {
    Some(_) -> reference.port
    None -> merged.port
  }
  use <- require(valid_port(port))
  let path = case merged.path {
    "" -> "/"
    path -> path
  }
  use <- require(string.starts_with(path, "/"))
  Ok(Destination(scheme, host, port, path, merged.query))
}

fn valid_reference_authority(reference: uri.Uri) -> Bool {
  case reference.scheme, reference.host {
    Some("http"), Some(_) | Some("https"), Some(_) -> True
    Some(_), _ -> False
    None, _ -> True
  }
}

fn valid_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(port) -> port > 0 && port <= 65_535
  }
}

fn same_origin(source: Request(body.Body), destination: Destination) -> Bool {
  let Destination(scheme, host, port, _, _) = destination
  source.scheme == scheme
  && string.lowercase(source.host) == string.lowercase(host)
  && effective_port(source.scheme, source.port) == effective_port(scheme, port)
}

fn effective_port(scheme: Scheme, port: Option(Int)) -> Int {
  case port, scheme {
    Some(port), _ -> port
    None, Http -> 80
    None, Https -> 443
  }
}

fn strip_credentials(
  headers: List(#(String, String)),
) -> List(#(String, String)) {
  list.filter(headers, fn(header) {
    let #(name, _) = header
    case string.lowercase(name) {
      "authorization" | "proxy-authorization" | "cookie" -> False
      _ -> True
    }
  })
}

fn strip_representation_headers(
  headers: List(#(String, String)),
) -> List(#(String, String)) {
  list.filter(headers, fn(header) {
    let #(name, _) = header
    case string.lowercase(name) {
      "content-encoding"
      | "content-language"
      | "content-length"
      | "content-location"
      | "content-type"
      | "digest"
      | "repr-digest"
      | "transfer-encoding" -> False
      _ -> True
    }
  })
}

fn require(
  condition: Bool,
  continue: fn() -> Result(value, error.Error),
) -> Result(value, error.Error) {
  use <- bool.guard(when: !condition, return: Error(redirect_policy_error()))
  continue()
}

fn redirect_policy_error() -> error.Error {
  error.new(error.Policy(error.RedirectPolicy))
}
