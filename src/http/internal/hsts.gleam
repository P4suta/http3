//// Finite Strict-Transport-Security parsing and host matching.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

const maximum_age_seconds = 63_072_000

/// RFC 6797 defines two directives and admits unrecognised ones. Sixteen names
/// is past anything a conforming host sends and keeps the seen-name list that
/// enforces the appear-once rule finite against a hostile field.
const maximum_directives = 16

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
  let host = string.lowercase(host)
  case named_host(host), parse_directives(directives, None, False, []) {
    False, _ -> None
    True, Some(#(seconds, include_subdomains)) -> {
      let seconds = int.min(seconds, maximum_age_seconds)
      Some(Entry(
        host:,
        include_subdomains:,
        expires_at: now_milliseconds + seconds * 1000,
        retained_bytes: string.byte_size(host) + 24,
      ))
    }
    True, None -> None
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

/// Whether a policy may be keyed on this host at all.
///
/// RFC 6797 section 8.1.1 refuses an IP literal: an address is not a name, so a
/// policy keyed on one would outlive whatever answers at that address. The
/// bracketed and bare IPv6 forms are both caught by the colon, and the dotted
/// form by four decimal labels. A label that merely looks numeric inside a
/// longer name is left alone.
fn named_host(host: String) -> Bool {
  !string.starts_with(host, "[")
  && !string.contains(host, ":")
  && !dotted_address(host)
}

fn dotted_address(host: String) -> Bool {
  case string.split(host, on: ".") {
    [first, second, third, fourth] ->
      list.all([first, second, third, fourth], decimal_octet)
    _ -> False
  }
}

fn decimal_octet(label: String) -> Bool {
  case string.length(label) <= 3, int.parse(label) {
    True, Ok(value) -> value >= 0 && value <= 255
    _, _ -> False
  }
}

fn valid_host(host: String) -> Bool {
  named_host(host)
  && host != ""
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
  seen: List(String),
) -> Option(#(Int, Bool)) {
  case directives {
    [] -> complete(age, include_subdomains)
    // The grammar makes the directive optional in every position, so an empty
    // span between two separators is well formed and carries no name that a
    // later one could repeat.
    ["", ..rest] -> parse_directives(rest, age, include_subdomains, seen)
    [directive, ..rest] ->
      case admissible_name(directive, seen) {
        None -> None
        Some(name) ->
          case apply_directive(directive, name, age, include_subdomains) {
            None -> None
            Some(#(age, include_subdomains)) ->
              parse_directives(rest, age, include_subdomains, [name, ..seen])
          }
      }
  }
}

/// A field carries a policy only once `max-age` has been read.
fn complete(
  age: Option(Int),
  include_subdomains: Bool,
) -> Option(#(Int, Bool)) {
  case age {
    Some(seconds) -> Some(#(seconds, include_subdomains))
    None -> None
  }
}

/// The directive's lowercase name, unless section 6.1's appear-once rule or the
/// finite ceiling on distinct names refuses the whole field.
fn admissible_name(directive: String, seen: List(String)) -> Option(String) {
  let name = string.lowercase(directive_name(directive))
  case list.contains(seen, name) || list.length(seen) >= maximum_directives {
    True -> None
    False -> Some(name)
  }
}

/// Fold one directive into the policy read so far, or refuse the whole field.
///
/// A recognised name carrying the wrong shape is left to the unrecognised arm:
/// section 6.1 asks for unrecognised directives to be ignored, and a bare
/// `max-age` or an `includeSubDomains` with a value conveys nothing either way.
fn apply_directive(
  directive: String,
  name: String,
  age: Option(Int),
  include_subdomains: Bool,
) -> Option(#(Option(Int), Bool)) {
  case name, string.split_once(directive, on: "=") {
    "max-age", Ok(#(_, value)) -> parse_age(value, include_subdomains)
    "includesubdomains", Error(Nil) -> Some(#(age, True))
    _, _ -> Some(#(age, include_subdomains))
  }
}

/// The `max-age` value is a nonnegative number of seconds and nothing else.
fn parse_age(
  value: String,
  include_subdomains: Bool,
) -> Option(#(Option(Int), Bool)) {
  case int.parse(string.trim(value)) {
    Ok(seconds) if seconds >= 0 -> Some(#(Some(seconds), include_subdomains))
    _ -> None
  }
}

/// The name half of a directive, which is the whole span when it carries no
/// value.
fn directive_name(directive: String) -> String {
  case string.split_once(directive, on: "=") {
    Ok(#(name, _)) -> string.trim(name)
    Error(_) -> directive
  }
}
