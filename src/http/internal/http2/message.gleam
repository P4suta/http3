//// Standard gleam_http message conversion for HTTP/2 field sections.

import gleam/bit_array
import gleam/http as gleam_http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import http/internal/http2/header_semantics
import http/internal/http2/hpack/decoder.{type Header, Header}

/// Message conversion, URI policy, or field semantic failure.
pub type Error {
  InvalidPort
  InvalidTarget
  InvalidMethod
  InvalidScheme
  InvalidAuthority
  InvalidHeaderText
  UnexpectedControlData
  SemanticsFailure(header_semantics.Error)
}

/// Convert a standard request to an ordered HTTP/2 field section.
pub fn request_headers(outgoing: Request(body)) -> Result(List(Header), Error) {
  use port <- result.try(request_port(outgoing.scheme, outgoing.port))
  let method = gleam_http.method_to_string(outgoing.method)
  let authority =
    authority(
      outgoing.host,
      port,
      outgoing.scheme,
      outgoing.method == gleam_http.Connect,
    )
  use pseudo <- result.try(request_pseudo_headers(
    outgoing.method,
    method,
    outgoing.scheme,
    authority,
    outgoing.path,
    outgoing.query,
  ))
  let regular = convert_outgoing_headers(outgoing.headers, True, [])
  let fields = list_append(pseudo, regular)
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.RequestSection, False)
    |> result.map_error(SemanticsFailure),
  )
  Ok(fields)
}

/// Convert a typed Extended CONNECT request to its HTTP/2 field section.
///
/// The protocol pseudo-field is supplied separately so application headers
/// can never smuggle or duplicate it. Unlike classic CONNECT, the target URI
/// retains its scheme and path as required by RFC 8441.
pub fn extended_connect_headers(
  outgoing: Request(body),
  protocol: String,
) -> Result(List(Header), Error) {
  use _ <- result.try(case outgoing.method {
    gleam_http.Connect -> Ok(Nil)
    _ -> Error(InvalidMethod)
  })
  use port <- result.try(request_port(outgoing.scheme, outgoing.port))
  use target <- result.try(request_target(outgoing.path, outgoing.query))
  let authority = authority(outgoing.host, port, outgoing.scheme, False)
  let pseudo = [
    Header(<<":method">>, <<"CONNECT">>, False),
    Header(<<":protocol">>, bit_array.from_string(protocol), False),
    Header(
      <<":scheme">>,
      bit_array.from_string(gleam_http.scheme_to_string(outgoing.scheme)),
      False,
    ),
    Header(<<":authority">>, bit_array.from_string(authority), False),
    Header(<<":path">>, target, False),
  ]
  let regular = convert_outgoing_headers(outgoing.headers, True, [])
  let fields = list_append(pseudo, regular)
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.RequestSection, True)
    |> result.map_error(SemanticsFailure),
  )
  Ok(fields)
}

/// Return the normalized request content length after full field validation.
pub fn request_content_length(
  outgoing: Request(body),
) -> Result(Option(Int), Error) {
  use fields <- result.try(request_headers(outgoing))
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.RequestSection, False)
    |> result.map_error(SemanticsFailure),
  )
  let header_semantics.Validated(_, _, content_length) = validated
  Ok(content_length)
}

/// Convert a standard response to an ordered HTTP/2 field section.
pub fn response_headers(
  outgoing: Response(body),
) -> Result(List(Header), Error) {
  let fields = [
    Header(
      <<":status">>,
      bit_array.from_string(int.to_string(outgoing.status)),
      False,
    ),
    ..convert_outgoing_headers(outgoing.headers, False, [])
  ]
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
    |> result.map_error(SemanticsFailure),
  )
  Ok(fields)
}

/// Return the normalized response content length after full field validation.
pub fn response_content_length(
  outgoing: Response(body),
) -> Result(Option(Int), Error) {
  use fields <- result.try(response_headers(outgoing))
  use validated <- result.try(
    header_semantics.validate(fields, header_semantics.ResponseSection, False)
    |> result.map_error(SemanticsFailure),
  )
  let header_semantics.Validated(_, _, content_length) = validated
  Ok(content_length)
}

/// Convert standard name/value trailers after applying HTTP/2 restrictions.
pub fn trailer_headers(
  outgoing: List(#(String, String)),
) -> Result(List(Header), Error) {
  let fields = convert_outgoing_headers(outgoing, False, [])
  use _ <- result.try(
    header_semantics.validate(fields, header_semantics.TrailerSection, False)
    |> result.map_error(SemanticsFailure),
  )
  Ok(fields)
}

/// Build a standard response from a validated response field section.
pub fn response_from_validated(
  validated: header_semantics.Validated,
  body: body,
) -> Result(Response(body), Error) {
  case validated {
    header_semantics.Validated(
      header_semantics.ResponseControlData(status),
      fields,
      _,
    ) -> {
      use headers <- result.try(decode_headers(fields, []))
      Ok(gleam_http_response(status, headers, body))
    }
    _ -> Error(UnexpectedControlData)
  }
}

/// Convert a validated trailer field section to standard name/value pairs.
pub fn trailers_from_validated(
  validated: header_semantics.Validated,
) -> Result(List(#(String, String)), Error) {
  case validated {
    header_semantics.Validated(header_semantics.TrailerControlData, fields, _) ->
      decode_headers(fields, [])
    _ -> Error(UnexpectedControlData)
  }
}

/// Build a standard request from one validated request field section.
///
/// Classic CONNECT has no `:scheme`, so the listener's authenticated scheme
/// is supplied explicitly. Extended CONNECT retains its target components;
/// its `:protocol` remains available in the validated connection action.
pub fn request_from_validated(
  validated: header_semantics.Validated,
  body body: body,
  connection_scheme connection_scheme: gleam_http.Scheme,
) -> Result(Request(body), Error) {
  case validated {
    header_semantics.Validated(
      header_semantics.RequestControlData(header_semantics.RequestControl(
        encoded_method,
        encoded_scheme,
        encoded_authority,
        encoded_path,
        _,
      )),
      fields,
      _,
    ) -> {
      use method_text <- result.try(decode_text(encoded_method))
      use method <- result.try(
        gleam_http.parse_method(method_text)
        |> result.replace_error(InvalidMethod),
      )
      use scheme <- result.try(decode_scheme(encoded_scheme, connection_scheme))
      use authority <- result.try(require_authority(encoded_authority))
      use #(host, port) <- result.try(parse_authority(authority, scheme))
      use #(path, query) <- result.try(decode_target(encoded_path))
      use headers <- result.try(decode_headers(fields, []))
      Ok(request.Request(
        method: method,
        headers: headers,
        body: body,
        scheme: scheme,
        host: host,
        port: port,
        path: path,
        query: query,
      ))
    }
    _ -> Error(UnexpectedControlData)
  }
}

fn request_pseudo_headers(
  method: gleam_http.Method,
  encoded_method: String,
  scheme: gleam_http.Scheme,
  authority: String,
  path: String,
  query: Option(String),
) -> Result(List(Header), Error) {
  let method_header =
    Header(<<":method">>, bit_array.from_string(encoded_method), False)
  case method {
    gleam_http.Connect ->
      Ok([
        method_header,
        Header(<<":authority">>, bit_array.from_string(authority), False),
      ])
    _ -> {
      use target <- result.try(request_target(path, query))
      Ok([
        method_header,
        Header(
          <<":scheme">>,
          bit_array.from_string(gleam_http.scheme_to_string(scheme)),
          False,
        ),
        Header(<<":authority">>, bit_array.from_string(authority), False),
        Header(<<":path">>, target, False),
      ])
    }
  }
}

fn convert_outgoing_headers(
  headers: List(#(String, String)),
  omit_host: Bool,
  reversed: List(Header),
) -> List(Header) {
  case headers {
    [] -> list_reverse(reversed, [])
    [#(name, value), ..rest] ->
      case omit_host && name == "host" {
        True -> convert_outgoing_headers(rest, omit_host, reversed)
        False ->
          convert_outgoing_headers(rest, omit_host, [
            Header(
              bit_array.from_string(name),
              bit_array.from_string(value),
              sensitive(name),
            ),
            ..reversed
          ])
      }
  }
}

fn decode_headers(
  fields: List(Header),
  reversed: List(#(String, String)),
) -> Result(List(#(String, String)), Error) {
  case fields {
    [] -> Ok(list_reverse(reversed, []))
    [Header(name, value, _), ..rest] -> {
      use name <- result.try(
        bit_array.to_string(name)
        |> result.replace_error(InvalidHeaderText),
      )
      use value <- result.try(
        bit_array.to_string(value)
        |> result.replace_error(InvalidHeaderText),
      )
      decode_headers(rest, [#(name, value), ..reversed])
    }
  }
}

fn decode_text(value: BitArray) -> Result(String, Error) {
  bit_array.to_string(value)
  |> result.replace_error(InvalidHeaderText)
}

fn decode_scheme(
  encoded: Option(BitArray),
  fallback: gleam_http.Scheme,
) -> Result(gleam_http.Scheme, Error) {
  case encoded {
    None -> Ok(fallback)
    Some(encoded) -> {
      use value <- result.try(decode_text(encoded))
      gleam_http.scheme_from_string(value)
      |> result.replace_error(InvalidScheme)
    }
  }
}

fn require_authority(encoded: Option(BitArray)) -> Result(String, Error) {
  case encoded {
    None -> Error(InvalidAuthority)
    Some(encoded) -> {
      use value <- result.try(decode_text(encoded))
      case value == "" {
        True -> Error(InvalidAuthority)
        False -> Ok(value)
      }
    }
  }
}

fn parse_authority(
  authority: String,
  scheme: gleam_http.Scheme,
) -> Result(#(String, Option(Int)), Error) {
  let absolute = gleam_http.scheme_to_string(scheme) <> "://" <> authority
  use parsed <- result.try(
    uri.parse(absolute)
    |> result.replace_error(InvalidAuthority),
  )
  let uri.Uri(_, userinfo, host, port, path, query, fragment) = parsed
  case userinfo, host, path, query, fragment {
    None, Some(host), "", None, None ->
      case host != "" && valid_optional_port(port) {
        True -> Ok(#(host, port))
        False -> Error(InvalidAuthority)
      }
    _, _, _, _, _ -> Error(InvalidAuthority)
  }
}

fn valid_optional_port(port: Option(Int)) -> Bool {
  case port {
    None -> True
    Some(port) -> port > 0 && port <= 65_535
  }
}

fn decode_target(
  encoded: Option(BitArray),
) -> Result(#(String, Option(String)), Error) {
  case encoded {
    None -> Ok(#("", None))
    Some(encoded) -> {
      use target <- result.try(decode_text(encoded))
      case string.split_once(target, on: "?") {
        Ok(#(path, query)) -> Ok(#(path, Some(query)))
        Error(Nil) -> Ok(#(target, None))
      }
    }
  }
}

fn request_port(
  scheme: gleam_http.Scheme,
  configured: Option(Int),
) -> Result(Int, Error) {
  case configured, scheme {
    Some(port), _ if port > 0 && port <= 65_535 -> Ok(port)
    Some(_), _ -> Error(InvalidPort)
    None, gleam_http.Http -> Ok(80)
    None, gleam_http.Https -> Ok(443)
  }
}

fn request_target(
  path: String,
  query: Option(String),
) -> Result(BitArray, Error) {
  let path = case path {
    "" -> "/"
    path -> path
  }
  case
    { string.starts_with(path, "/") || path == "*" }
    && !string.contains(path, "?")
    && !string.contains(path, "#")
  {
    False -> Error(InvalidTarget)
    True -> {
      let target = case query {
        None -> path
        Some(query) -> path <> "?" <> query
      }
      case string.contains(target, "#") {
        True -> Error(InvalidTarget)
        False -> Ok(bit_array.from_string(target))
      }
    }
  }
}

fn authority(
  host: String,
  port: Int,
  scheme: gleam_http.Scheme,
  force_port: Bool,
) -> String {
  let host = case string.contains(host, ":") && !string.starts_with(host, "[") {
    True -> "[" <> host <> "]"
    False -> host
  }
  case force_port, scheme, port {
    False, gleam_http.Http, 80 | False, gleam_http.Https, 443 -> host
    _, _, port -> host <> ":" <> int.to_string(port)
  }
}

fn sensitive(name: String) -> Bool {
  case name {
    "authorization" | "proxy-authorization" | "cookie" | "set-cookie" -> True
    _ -> False
  }
}

fn list_append(first: List(value), second: List(value)) -> List(value) {
  case first {
    [] -> second
    [item, ..rest] -> [item, ..list_append(rest, second)]
  }
}

fn list_reverse(values: List(value), reversed: List(value)) -> List(value) {
  case values {
    [] -> reversed
    [value, ..rest] -> list_reverse(rest, [value, ..reversed])
  }
}

fn gleam_http_response(
  status: Int,
  headers: List(#(String, String)),
  body: body,
) -> Response(body) {
  response.Response(status: status, headers: headers, body: body)
}
