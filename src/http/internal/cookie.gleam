//// Bounded RFC 6265-style cookie parsing and request matching.

import gleam/http.{type Scheme, Https}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
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
    /// The monotonic instant this cookie was first stored, preserved when a
    /// later Set-Cookie replaces its value, so RFC 6265 section 5.4 can order
    /// equally specific cookies by age.
    created_at: Int,
    retained_bytes: Int,
  )
}

type Attributes {
  Attributes(
    domain: Option(String),
    path: Option(String),
    secure: Bool,
    maximum_age_seconds: Option(Int),
    expires_at_unix_milliseconds: Option(Int),
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
  now_unix_milliseconds: Int,
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
              Attributes(None, None, False, None, None),
            )
          let domain = case attributes.domain {
            Some(domain) -> domain
            None -> host
          }
          let path = case attributes.path {
            Some(path) -> path
            None -> default_path(request_path)
          }
          let expires_at =
            expiry_instant(attributes, now_milliseconds, now_unix_milliseconds)
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
                created_at: now_milliseconds,
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
  age_milliseconds: Int,
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
        expires_at: now_milliseconds + expires_in_milliseconds,
        created_at: now_milliseconds - age_milliseconds,
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

/// Return the unexpired cookies this request carries, in the order RFC 6265
/// section 5.4 asks for: longer paths before shorter ones, and among equally
/// long paths the cookie that was created first.
pub fn matching(
  cookies: List(Cookie),
  scheme: Scheme,
  host: String,
  path: String,
  now_milliseconds: Int,
) -> List(Cookie) {
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
  |> list.sort(by: fn(left, right) {
    case int.compare(string.byte_size(right.path), string.byte_size(left.path)) {
      order.Eq -> int.compare(left.created_at, right.created_at)
      ordering -> ordering
    }
  })
}

/// Serialize an already matched and ordered cookie list as a Cookie field.
pub fn field_value(cookies: List(Cookie)) -> Option(String) {
  let pairs = list.map(cookies, fn(cookie) { cookie.name <> "=" <> cookie.value })
  case pairs {
    [] -> None
    _ -> Some(string.join(pairs, with: "; "))
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
  field_value(matching(cookies, scheme, host, path, now_milliseconds))
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
            "expires" ->
              case cookie_date(value) {
                Some(instant) ->
                  Attributes(
                    ..attributes,
                    expires_at_unix_milliseconds: Some(instant),
                  )
                // Section 5.2.1 ignores an unparsable date rather than the
                // whole field, which leaves the cookie a session cookie.
                None -> attributes
              }
            _ -> attributes
          }
      }
      parse_attributes(rest, next)
    }
  }
}

/// Decide one cookie's expiry as a monotonic instant.
///
/// RFC 6265 section 5.3 gives Max-Age precedence over Expires, and treats a
/// non-positive Max-Age as already expired. Expires is a wall-clock date, so it
/// is read as the time remaining from the wall clock at this moment and that
/// remainder is added to the monotonic instant the store compares against; the
/// store therefore stays immune to a wall-clock jump after the fact.
fn expiry_instant(
  attributes: Attributes,
  now_milliseconds: Int,
  now_unix_milliseconds: Int,
) -> Int {
  case attributes.maximum_age_seconds, attributes.expires_at_unix_milliseconds {
    Some(seconds), _ if seconds <= 0 -> now_milliseconds
    Some(seconds), _ ->
      now_milliseconds + int.min(seconds * 1000, maximum_lifetime_milliseconds)
    None, Some(instant) ->
      case instant - now_unix_milliseconds {
        remaining if remaining <= 0 -> now_milliseconds
        remaining ->
          now_milliseconds + int.min(remaining, maximum_lifetime_milliseconds)
      }
    None, None -> now_milliseconds + session_lifetime_milliseconds
  }
}

/// Parse an `Expires` value with the RFC 6265 section 5.1.1 algorithm.
///
/// The algorithm is deliberately liberal: the value is cut into tokens on a
/// fixed delimiter set, and each token is offered to the time, day, month, and
/// year productions in that order until each has been found once. A two-digit
/// year is corrected the way the section states, and a date that fails any of
/// its bounds is refused rather than approximated.
fn cookie_date(value: String) -> Option(Int) {
  let fields =
    value
    |> string.to_graphemes
    |> split_date_tokens("", [])
    |> list.fold(DateFields(None, None, None, None), read_date_token)
  case fields.time, fields.day, fields.month, fields.year {
    Some(#(hour, minute, second)), Some(day), Some(month), Some(year) -> {
      let year = case year {
        value if value >= 70 && value <= 99 -> value + 1900
        value if value >= 0 && value <= 69 -> value + 2000
        value -> value
      }
      case
        day >= 1 && day <= 31,
        year >= 1601,
        hour <= 23 && minute <= 59 && second <= 59
      {
        True, True, True ->
          Some(
            {
              civil_days(year, month, day)
              * 86_400
              + hour
              * 3600
              + minute
              * 60
              + second
            }
            * 1000,
          )
        _, _, _ -> None
      }
    }
    _, _, _, _ -> None
  }
}

type DateFields {
  DateFields(
    time: Option(#(Int, Int, Int)),
    day: Option(Int),
    month: Option(Int),
    year: Option(Int),
  )
}

fn split_date_tokens(
  remaining: List(String),
  current: String,
  tokens: List(String),
) -> List(String) {
  case remaining {
    [] ->
      list.reverse(case current {
        "" -> tokens
        _ -> [current, ..tokens]
      })
    [grapheme, ..rest] ->
      case date_delimiter(grapheme) {
        False -> split_date_tokens(rest, current <> grapheme, tokens)
        True ->
          case current {
            "" -> split_date_tokens(rest, "", tokens)
            _ -> split_date_tokens(rest, "", [current, ..tokens])
          }
      }
  }
}

/// Section 5.1.1's delimiter set: HTAB, and the punctuation ranges either side
/// of the digits and letters. A colon is deliberately not one, which is what
/// keeps a time in a single token.
fn date_delimiter(grapheme: String) -> Bool {
  case string.to_utf_codepoints(grapheme) {
    [codepoint] ->
      case string.utf_codepoint_to_int(codepoint) {
        0x09 -> True
        byte if byte >= 0x20 && byte <= 0x2f -> True
        byte if byte >= 0x3b && byte <= 0x40 -> True
        byte if byte >= 0x5b && byte <= 0x60 -> True
        byte if byte >= 0x7b && byte <= 0x7e -> True
        _ -> False
      }
    _ -> False
  }
}

fn read_date_token(fields: DateFields, token: String) -> DateFields {
  case
    fields.time,
    fields.day,
    fields.month,
    fields.year,
    hms_time(token),
    leading_number(token),
    month_of(token)
  {
    None, _, _, _, Some(time), _, _ -> DateFields(..fields, time: Some(time))
    _, None, _, _, _, Some(#(day, digits)), _ if digits <= 2 ->
      DateFields(..fields, day: Some(day))
    _, _, None, _, _, _, Some(month) -> DateFields(..fields, month: Some(month))
    _, _, _, None, _, Some(#(year, digits)), _ if digits >= 2 && digits <= 4 ->
      DateFields(..fields, year: Some(year))
    _, _, _, _, _, _, _ -> fields
  }
}

/// The `hms-time` production: three colon-separated fields of one or two
/// digits each, with anything after them ignored.
fn hms_time(token: String) -> Option(#(Int, Int, Int)) {
  case string.split(token, on: ":") {
    [hour, minute, rest] ->
      case leading_number(hour), leading_number(minute), leading_number(rest) {
        Some(#(hour, first)),
          Some(#(minute, second_digits)),
          Some(#(second, third))
          if first <= 2 && second_digits <= 2 && third <= 2
        -> Some(#(hour, minute, second))
        _, _, _ -> None
      }
    _ -> None
  }
}

/// The leading run of digits in a token, with its length, or nothing when the
/// token does not start with one.
fn leading_number(token: String) -> Option(#(Int, Int)) {
  let digits = leading_digits(string.to_graphemes(token), "")
  case digits {
    "" -> None
    _ ->
      case int.parse(digits) {
        Ok(value) -> Some(#(value, string.length(digits)))
        Error(Nil) -> None
      }
  }
}

fn leading_digits(remaining: List(String), taken: String) -> String {
  case remaining {
    [grapheme, ..rest] ->
      case is_digit(grapheme) {
        True -> leading_digits(rest, taken <> grapheme)
        False -> taken
      }
    [] -> taken
  }
}

fn is_digit(grapheme: String) -> Bool {
  case grapheme {
    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" -> True
    _ -> False
  }
}

/// The `month` production: the first three characters of the token, matched
/// without regard to case, with anything after them ignored.
fn month_of(token: String) -> Option(Int) {
  case string.lowercase(string.slice(token, at_index: 0, length: 3)) {
    "jan" -> Some(1)
    "feb" -> Some(2)
    "mar" -> Some(3)
    "apr" -> Some(4)
    "may" -> Some(5)
    "jun" -> Some(6)
    "jul" -> Some(7)
    "aug" -> Some(8)
    "sep" -> Some(9)
    "oct" -> Some(10)
    "nov" -> Some(11)
    "dec" -> Some(12)
    _ -> None
  }
}

/// Days from the Unix epoch to one proleptic Gregorian date.
///
/// The year is already held at or above 1601 by the caller, so every
/// intermediate here is nonnegative and the truncating division Gleam performs
/// is the floor division this needs.
fn civil_days(year: Int, month: Int, day: Int) -> Int {
  let year = case month <= 2 {
    True -> year - 1
    False -> year
  }
  let era = year / 400
  let year_of_era = year - era * 400
  let shifted = case month > 2 {
    True -> month - 3
    False -> month + 9
  }
  let day_of_year = { 153 * shifted + 2 } / 5 + day - 1
  let day_of_era =
    year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year
  era * 146_097 + day_of_era - 719_468
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
