//// Finite Strict-Transport-Security parsing and host matching.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

const maximum_age_seconds = 63_072_000

/// One HSTS policy learned from a verified HTTPS response.
pub type Entry {
  Entry(
    host: String,
    include_subdomains: Bool,
    expires_at: Int,
    retained_bytes: Int,
  )
}

/// Parse one Strict-Transport-Security field with a bounded two-year lifetime.
pub fn parse(
  value: String,
  host: String,
  now_milliseconds: Int,
) -> Option(Entry) {
  let directives =
    value
    |> string.split(on: ";")
    |> list.map(string.trim)
  case parse_directives(directives, None, False, False) {
    Some(#(seconds, include_subdomains)) -> {
      let host = string.lowercase(host)
      let seconds = int.min(seconds, maximum_age_seconds)
      Some(Entry(
        host:,
        include_subdomains:,
        expires_at: now_milliseconds + seconds * 1000,
        retained_bytes: string.byte_size(host) + 24,
      ))
    }
    None -> None
  }
}

/// Return whether one unexpired exact or includeSubDomains policy applies.
pub fn applies(
  entries: List(Entry),
  host: String,
  now_milliseconds: Int,
) -> Bool {
  let host = string.lowercase(host)
  list.any(entries, fn(entry) {
    entry.expires_at > now_milliseconds
    && {
      entry.host == host
      || {
        entry.include_subdomains && string.ends_with(host, "." <> entry.host)
      }
    }
  })
}

/// Rebuild one persisted policy only after enforcing the live HSTS bounds.
pub fn from_persisted(
  host: String,
  include_subdomains: Bool,
  expires_in_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Entry) {
  let host = string.lowercase(host)
  case
    valid_host(host),
    expires_in_milliseconds > 0
    && expires_in_milliseconds <= maximum_age_seconds * 1000
  {
    True, True ->
      Some(Entry(
        host:,
        include_subdomains:,
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes: string.byte_size(host) + 24,
      ))
    _, _ -> None
  }
}

fn valid_host(host: String) -> Bool {
  host != ""
  && string.byte_size(host) <= 253
  && !string.starts_with(host, ".")
  && !string.ends_with(host, ".")
  && !string.contains(host, " ")
  && !string.contains(host, "\t")
  && !string.contains(host, "\r")
  && !string.contains(host, "\n")
  && !string.contains(host, "\u{0000}")
  && !string.contains(host, "/")
}

fn parse_directives(
  directives: List(String),
  age: Option(Int),
  include_subdomains: Bool,
  invalid: Bool,
) -> Option(#(Int, Bool)) {
  case directives, invalid {
    _, True -> None
    [], False ->
      case age {
        Some(seconds) -> Some(#(seconds, include_subdomains))
        None -> None
      }
    [directive, ..rest], False ->
      case string.split_once(directive, on: "=") {
        Ok(#(name, value)) ->
          case string.lowercase(string.trim(name)), age {
            "max-age", None ->
              case int.parse(string.trim(value)) {
                Ok(seconds) if seconds >= 0 ->
                  parse_directives(
                    rest,
                    Some(seconds),
                    include_subdomains,
                    False,
                  )
                _ -> None
              }
            "max-age", Some(_) -> None
            _, _ -> parse_directives(rest, age, include_subdomains, False)
          }
        Error(_) ->
          case string.lowercase(directive) {
            "includesubdomains" -> parse_directives(rest, age, True, False)
            _ -> parse_directives(rest, age, include_subdomains, False)
          }
      }
  }
}
