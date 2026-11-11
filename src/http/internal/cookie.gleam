//// Bounded RFC 6265-style cookie parsing and request matching.

import gleam/http.{type Scheme, Https}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import http/internal/url_pattern/host as url_host
import http/internal/url_pattern/host_ip

const session_lifetime_milliseconds = 86_400_000

const maximum_lifetime_milliseconds = 63_072_000_000

const maximum_field_bytes = 8192

const maximum_attributes = 64

@external(erlang, "http_cookie_ffi", "parse_cookie_date")
fn parse_cookie_date(value: String) -> Result(Int, Nil)

@external(erlang, "http_cookie_ffi", "unix_seconds")
fn unix_seconds() -> Int

/// One validated cookie retained by the private finite policy store.
pub type Cookie {
  Cookie(
    name: String,
    value: String,
    domain: String,
    path: String,
    host_only: Bool,
    secure: Bool,
    http_only: Bool,
    persistent: Bool,
    creation_milliseconds: Int,
    expires_at: Int,
    retained_bytes: Int,
  )
}

type Attributes {
  Attributes(
    domain: Option(String),
    path: Option(String),
    secure: Bool,
    http_only: Bool,
    maximum_age_seconds: Option(Int),
    expires_unix_seconds: Option(Int),
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
  parse_with_unix_seconds(
    field_value,
    origin_scheme,
    origin_host,
    request_path,
    now_milliseconds,
    unix_seconds(),
  )
}

/// Parse using separate monotonic and wall clocks expressed in seconds.
pub fn parse_with_unix_seconds(
  field_value: String,
  origin_scheme: Scheme,
  origin_host: String,
  request_path: String,
  now_milliseconds: Int,
  now_unix_seconds: Int,
) -> Option(Cookie) {
  parse_with_unix_milliseconds(
    field_value,
    origin_scheme,
    origin_host,
    request_path,
    now_milliseconds,
    now_unix_seconds * 1000,
  )
}

/// Parse using the caller's separate monotonic and wall clocks.
pub fn parse_with_unix_milliseconds(
  field_value: String,
  origin_scheme: Scheme,
  origin_host: String,
  request_path: String,
  now_milliseconds: Int,
  now_unix_milliseconds: Int,
) -> Option(Cookie) {
  use <- option_guard(string.byte_size(field_value) <= maximum_field_bytes)
  use host <- option_try(canonical_host(origin_host))
  case string.split(field_value, on: ";") {
    [] -> None
    [pair, ..raw_attributes] -> {
      use <- option_guard(list.length(raw_attributes) <= maximum_attributes)
      case string.split_once(trim_wsp(pair), on: "=") {
        Error(_) -> None
        Ok(#(name, value)) -> {
          let name = trim_wsp(name)
          let value = trim_wsp(value)
          let request_default_path = default_path(request_path)
          let attributes =
            parse_attributes(
              raw_attributes,
              request_default_path,
              Attributes(None, None, False, False, None, None),
            )
          use domain <- option_try(case attributes.domain {
            Some(domain) -> canonical_host(domain)
            None -> Some(host)
          })
          let path = case attributes.path {
            Some(path) -> path
            None -> request_default_path
          }
          let #(expires_at, persistent) =
            expiry(attributes, now_milliseconds, now_unix_milliseconds)
          let retained_bytes =
            string.byte_size(name)
            + string.byte_size(value)
            + string.byte_size(domain)
            + string.byte_size(path)
            + 48
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
                http_only: attributes.http_only,
                persistent:,
                creation_milliseconds: now_milliseconds,
                expires_at:,
                retained_bytes:,
              ))
            _, _, _, _, _, _ -> None
          }
        }
      }
    }
  }
}

fn expiry(
  attributes: Attributes,
  now_milliseconds: Int,
  now_unix_milliseconds: Int,
) -> #(Int, Bool) {
  case attributes.maximum_age_seconds, attributes.expires_unix_seconds {
    Some(seconds), _ if seconds <= 0 -> #(now_milliseconds, True)
    Some(seconds), _ -> #(
      now_milliseconds + int.min(seconds * 1000, maximum_lifetime_milliseconds),
      True,
    )
    None, Some(expires_unix_seconds) -> {
      let remaining =
        int.max(0, expires_unix_seconds * 1000 - now_unix_milliseconds)
      #(
        now_milliseconds + int.min(remaining, maximum_lifetime_milliseconds),
        True,
      )
    }
    None, None -> #(now_milliseconds + session_lifetime_milliseconds, False)
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
  age_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Cookie) {
  use domain <- option_try(canonical_host(domain))
  let retained_bytes =
    string.byte_size(name)
    + string.byte_size(value)
    + string.byte_size(domain)
    + string.byte_size(path)
    + 48
  case
    valid_name(name),
    valid_value(value),
    valid_domain(domain),
    valid_path(path),
    retained_bytes <= 4096,
    expires_in_milliseconds > 0
    && expires_in_milliseconds <= maximum_lifetime_milliseconds
    && age_milliseconds >= 0
    && age_milliseconds <= maximum_lifetime_milliseconds
  {
    True, True, True, True, True, True ->
      Some(Cookie(
        name:,
        value:,
        domain:,
        path:,
        host_only:,
        secure:,
        http_only: False,
        persistent: True,
        creation_milliseconds: now_milliseconds - age_milliseconds,
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes:,
      ))
    _, _, _, _, _, _ -> None
  }
}

/// Preserve the original creation time when replacing the same cookie key.
pub fn with_creation(cookie: Cookie, creation_milliseconds: Int) -> Cookie {
  Cookie(..cookie, creation_milliseconds:)
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
  string.starts_with(host, "[")
  || host_ip.ends_in_number(host)
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

/// Return the exact cookie store keys accessed while generating one field.
pub fn request_selection(
  cookies: List(Cookie),
  scheme: Scheme,
  host: String,
  path: String,
  now_milliseconds: Int,
) -> #(Option(String), List(String)) {
  case canonical_host(host) {
    None -> #(None, [])
    Some(host) -> {
      let path = case string.starts_with(path, "/") {
        True -> path
        False -> "/"
      }
      let selected =
        cookies
        |> list.filter(fn(cookie) {
          cookie.expires_at > now_milliseconds
          && case cookie.host_only {
            True -> host == cookie.domain
            False -> domain_matches(host, cookie.domain)
          }
          && path_matches(path, cookie.path)
          && { !cookie.secure || scheme == Https }
        })
        |> sort_for_request
      case selected {
        [] -> #(None, [])
        _ -> #(
          selected
            |> list.map(fn(cookie) { cookie.name <> "=" <> cookie.value })
            |> string.join(with: "; ")
            |> Some,
          list.map(selected, key),
        )
      }
    }
  }
}

/// Build a Cookie request field from the matching, unexpired subset.
pub fn request_header(
  cookies: List(Cookie),
  scheme: Scheme,
  host: String,
  path: String,
  now_milliseconds: Int,
) -> Option(String) {
  let #(header, _) =
    request_selection(cookies, scheme, host, path, now_milliseconds)
  header
}

fn sort_for_request(cookies: List(Cookie)) -> List(Cookie) {
  list.fold(cookies, [], insert_for_request)
}

fn insert_for_request(sorted: List(Cookie), cookie: Cookie) -> List(Cookie) {
  case sorted {
    [] -> [cookie]
    [first, ..rest] ->
      case
        string.byte_size(cookie.path) > string.byte_size(first.path)
        || {
          string.byte_size(cookie.path) == string.byte_size(first.path)
          && cookie.creation_milliseconds < first.creation_milliseconds
        }
      {
        True -> [cookie, first, ..rest]
        False -> [first, ..insert_for_request(rest, cookie)]
      }
  }
}

fn parse_attributes(
  raw: List(String),
  request_default_path: String,
  attributes: Attributes,
) -> Attributes {
  case raw {
    [] -> attributes
    [item, ..rest] -> {
      let item = trim_wsp(item)
      let next = case string.split_once(item, on: "=") {
        Error(_) ->
          case string.lowercase(item) {
            "secure" -> Attributes(..attributes, secure: True)
            "httponly" -> Attributes(..attributes, http_only: True)
            _ -> attributes
          }
        Ok(#(name, value)) ->
          case string.lowercase(trim_wsp(name)) {
            "domain" -> {
              let domain = strip_leading_dot(string.lowercase(trim_wsp(value)))
              case domain {
                "" -> attributes
                _ -> Attributes(..attributes, domain: Some(domain))
              }
            }
            "path" -> {
              let path = trim_wsp(value)
              Attributes(
                ..attributes,
                path: Some(case string.starts_with(path, "/") {
                  True -> path
                  False -> request_default_path
                }),
              )
            }
            "max-age" ->
              case parse_maximum_age(trim_wsp(value)) {
                Some(seconds) ->
                  Attributes(..attributes, maximum_age_seconds: Some(seconds))
                None -> attributes
              }
            "expires" ->
              case parse_cookie_date(trim_wsp(value)) {
                Ok(seconds) ->
                  Attributes(..attributes, expires_unix_seconds: Some(seconds))
                Error(_) -> attributes
              }
            "secure" -> Attributes(..attributes, secure: True)
            "httponly" -> Attributes(..attributes, http_only: True)
            _ -> attributes
          }
      }
      parse_attributes(rest, request_default_path, next)
    }
  }
}

fn parse_maximum_age(value: String) -> Option(Int) {
  case string.to_utf_codepoints(value) {
    [] -> None
    [first, ..rest] -> {
      let first = string.utf_codepoint_to_int(first)
      case
        first == 45
        && rest != []
        && ascii_digits(rest)
        || { first >= 48 && first <= 57 && ascii_digits(rest) }
      {
        False -> None
        True ->
          case int.parse(value) {
            Ok(value) -> Some(value)
            Error(_) -> None
          }
      }
    }
  }
}

fn ascii_digits(characters: List(UtfCodepoint)) -> Bool {
  list.all(characters, fn(character) {
    let value = string.utf_codepoint_to_int(character)
    value >= 48 && value <= 57
  })
}

fn strip_leading_dot(domain: String) -> String {
  case string.starts_with(domain, ".") {
    True -> string.slice(domain, at_index: 1, length: string.length(domain) - 1)
    False -> domain
  }
}

fn canonical_host(host: String) -> Option(String) {
  case url_host.canonicalize(host) {
    Ok(host) ->
      case valid_domain(host) {
        True -> Some(host)
        False -> None
      }
    Error(_) -> None
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
  host == domain
  || {
    !ip_address(host) && string.ends_with(host, "." <> domain) && domain != ""
  }
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
  !has_ascii_control(value) && !string.contains(value, ";")
}

fn valid_path(path: String) -> Bool {
  string.starts_with(path, "/") && !has_ascii_control(path)
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

fn trim_wsp(value: String) -> String {
  value
  |> string.to_utf_codepoints
  |> list.drop_while(is_wsp)
  |> list.reverse
  |> list.drop_while(is_wsp)
  |> list.reverse
  |> string.from_utf_codepoints
}

fn is_wsp(character: UtfCodepoint) -> Bool {
  let value = string.utf_codepoint_to_int(character)
  value == 9 || value == 32
}

fn has_ascii_control(value: String) -> Bool {
  value
  |> string.to_utf_codepoints
  |> list.any(fn(character) {
    let value = string.utf_codepoint_to_int(character)
    value < 32 || value == 127
  })
}

fn option_try(value: Option(a), then: fn(a) -> Option(b)) -> Option(b) {
  case value {
    Some(value) -> then(value)
    None -> None
  }
}

fn option_guard(condition: Bool, then: fn() -> Option(a)) -> Option(a) {
  case condition {
    True -> then()
    False -> None
  }
}
