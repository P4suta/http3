//// Bounded RFC 6265-style cookie parsing and request matching.

import gleam/http.{type Scheme, Https}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

const session_lifetime_milliseconds = 86_400_000

const maximum_lifetime_milliseconds = 63_072_000_000

/// One validated cookie retained by the private finite policy store.
pub type Cookie {
  Cookie(
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: Bool,
    secure: Bool,
    expires_at: Int,
    retained_bytes: Int,
  )
}

type Attributes {
  Attributes(
    domain: Option(String),
    path: Option(String),
    secure: Bool,
    maximum_age_seconds: Option(Int),
  )
}

/// Parse one Set-Cookie field for a verified response origin.
///
/// Invalid, cross-domain, oversized, and control-bearing values are ignored.
pub fn parse(
  field_value: String,
  origin_scheme: Scheme,
  origin_host: String,
  request_path: String,
  now_milliseconds: Int,
) -> Option(Cookie) {
  case string.split(field_value, on: ";") {
    [] -> None
    [pair, ..raw_attributes] ->
      case string.split_once(string.trim(pair), on: "=") {
        Error(_) -> None
        Ok(#(name, value)) -> {
          let name = string.trim(name)
          let value = string.trim(value)
          let host = string.lowercase(origin_host)
          let attributes =
            parse_attributes(
              raw_attributes,
              Attributes(None, None, False, None),
            )
          let domain = case attributes.domain {
            Some(domain) -> domain
            None -> host
          }
          let path = case attributes.path {
            Some(path) -> path
            None -> default_path(request_path)
          }
          let expires_at = case attributes.maximum_age_seconds {
            Some(seconds) if seconds <= 0 -> now_milliseconds
            Some(seconds) ->
              now_milliseconds
              + int.min(seconds * 1000, maximum_lifetime_milliseconds)
            None -> now_milliseconds + session_lifetime_milliseconds
          }
          let retained_bytes =
            string.byte_size(name)
            + string.byte_size(value)
            + string.byte_size(domain)
            + string.byte_size(path)
            + 32
          case
            valid_name(name),
            valid_value(value),
            cookie_domain_allowed(host, domain, attributes.domain),
            valid_path(path),
            retained_bytes <= 4096,
            !attributes.secure || origin_scheme == Https
          {
            True, True, True, True, True, True ->
              Some(Cookie(
                name:,
                value:,
                domain:,
                path:,
                host_only: attributes.domain == None,
                secure: attributes.secure,
                expires_at:,
                retained_bytes:,
              ))
            _, _, _, _, _, _ -> None
          }
        }
      }
  }
}

/// Rebuild one persisted cookie only after applying the live parser's bounds.
pub fn from_persisted(
  name: String,
  value: String,
  domain: String,
  path: String,
  host_only: Bool,
  secure: Bool,
  expires_in_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Cookie) {
  let domain = string.lowercase(domain)
  let retained_bytes =
    string.byte_size(name)
    + string.byte_size(value)
    + string.byte_size(domain)
    + string.byte_size(path)
    + 32
  case
    valid_name(name),
    valid_value(value),
    valid_domain(domain),
    valid_path(path),
    retained_bytes <= 4096,
    expires_in_milliseconds > 0
    && expires_in_milliseconds <= maximum_lifetime_milliseconds
  {
    True, True, True, True, True, True ->
      Some(Cookie(
        name:,
        value:,
        domain:,
        path:,
        host_only:,
        secure:,
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes:,
      ))
    _, _, _, _, _, _ -> None
  }
}

fn cookie_domain_allowed(
  host: String,
  domain: String,
  configured: Option(String),
) -> Bool {
  case configured, ip_address(host) {
    Some(_), True -> host == domain
    _, _ -> domain_matches(host, domain)
  }
}

fn ip_address(host: String) -> Bool {
  string.contains(host, ":")
  || case string.split(host, on: ".") {
    [first, second, third, fourth] ->
      ipv4_octet(first)
      && ipv4_octet(second)
      && ipv4_octet(third)
      && ipv4_octet(fourth)
    _ -> False
  }
}

fn ipv4_octet(value: String) -> Bool {
  case int.parse(value) {
    Ok(octet) -> octet >= 0 && octet <= 255
    Error(_) -> False
  }
}

/// Stable replacement key for one name/domain/path tuple.
pub fn key(cookie: Cookie) -> String {
  cookie.domain <> "\u{0000}" <> cookie.path <> "\u{0000}" <> cookie.name
}

/// Build a Cookie request field from the matching, unexpired subset.
pub fn request_header(
  cookies: List(Cookie),
  scheme: Scheme,
  host: String,
  path: String,
  now_milliseconds: Int,
) -> Option(String) {
  let pairs =
    cookies
    |> list.filter(fn(cookie) {
      cookie.expires_at > now_milliseconds
      && case cookie.host_only {
        True -> string.lowercase(host) == cookie.domain
        False -> domain_matches(string.lowercase(host), cookie.domain)
      }
      && path_matches(path, cookie.path)
      && { !cookie.secure || scheme == Https }
    })
    |> list.map(fn(cookie) { cookie.name <> "=" <> cookie.value })
  case pairs {
    [] -> None
    _ -> Some(string.join(pairs, with: "; "))
  }
}

fn parse_attributes(raw: List(String), attributes: Attributes) -> Attributes {
  case raw {
    [] -> attributes
    [item, ..rest] -> {
      let item = string.trim(item)
      let next = case string.split_once(item, on: "=") {
        Error(_) ->
          case string.lowercase(item) {
            "secure" -> Attributes(..attributes, secure: True)
            _ -> attributes
          }
        Ok(#(name, value)) ->
          case string.lowercase(string.trim(name)) {
            "domain" -> {
              let domain =
                strip_leading_dot(string.lowercase(string.trim(value)))
              Attributes(..attributes, domain: Some(domain))
            }
            "path" -> Attributes(..attributes, path: Some(string.trim(value)))
            "max-age" ->
              case int.parse(string.trim(value)) {
                Ok(seconds) ->
                  Attributes(..attributes, maximum_age_seconds: Some(seconds))
                Error(_) -> attributes
              }
            _ -> attributes
          }
      }
      parse_attributes(rest, next)
    }
  }
}

fn strip_leading_dot(domain: String) -> String {
  case string.starts_with(domain, ".") {
    True -> string.slice(domain, at_index: 1, length: string.length(domain) - 1)
    False -> domain
  }
}

fn default_path(path: String) -> String {
  case string.starts_with(path, "/") {
    False -> "/"
    True -> default_path_segments(string.split(path, on: "/"), [])
  }
}

fn default_path_segments(
  segments: List(String),
  reversed: List(String),
) -> String {
  case segments {
    [] | [_] ->
      case list.reverse(reversed) {
        [] | [""] -> "/"
        kept -> string.join(kept, with: "/")
      }
    [segment, ..rest] -> default_path_segments(rest, [segment, ..reversed])
  }
}

fn domain_matches(host: String, domain: String) -> Bool {
  host == domain || { string.ends_with(host, "." <> domain) && domain != "" }
}

fn path_matches(request_path: String, cookie_path: String) -> Bool {
  case
    request_path == cookie_path,
    string.starts_with(request_path, cookie_path)
  {
    True, _ -> True
    False, False -> False
    False, True ->
      string.ends_with(cookie_path, "/")
      || string.slice(
        request_path,
        at_index: string.length(cookie_path),
        length: 1,
      )
      == "/"
  }
}

fn valid_name(name: String) -> Bool {
  name != ""
  && !string.contains(name, " ")
  && !string.contains(name, "\t")
  && !string.contains(name, "\r")
  && !string.contains(name, "\n")
  && !string.contains(name, ";")
  && !string.contains(name, ",")
  && !string.contains(name, "=")
}

fn valid_value(value: String) -> Bool {
  !string.contains(value, "\r")
  && !string.contains(value, "\n")
  && !string.contains(value, "\u{0000}")
  && !string.contains(value, ";")
}

fn valid_path(path: String) -> Bool {
  string.starts_with(path, "/")
  && !string.contains(path, "\r")
  && !string.contains(path, "\n")
  && !string.contains(path, "\u{0000}")
}

fn valid_domain(domain: String) -> Bool {
  domain != ""
  && string.byte_size(domain) <= 253
  && !string.starts_with(domain, ".")
  && !string.ends_with(domain, ".")
  && !string.contains(domain, " ")
  && !string.contains(domain, "\t")
  && !string.contains(domain, "\r")
  && !string.contains(domain, "\n")
  && !string.contains(domain, "\u{0000}")
  && !string.contains(domain, "/")
}
