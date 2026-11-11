//// Finite Strict-Transport-Security parsing and host matching.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import http/internal/url_pattern/host as url_host
import http/internal/url_pattern/host_idna
import http/internal/url_pattern/host_ip

const maximum_field_bytes = 8192

const maximum_directives = 64

/// One HSTS policy learned from a verified HTTPS response.
pub type Entry {
  Entry(
    host: String,
    include_subdomains: Bool,
    expires_at: Int,
    retained_bytes: Int,
  )
}

/// Parse one Strict-Transport-Security field with bounded syntax work.
pub fn parse(
  value: String,
  host: String,
  now_milliseconds: Int,
) -> Option(Entry) {
  use host <- option_try(canonical_domain(host))
  case string.byte_size(value) <= maximum_field_bytes {
    False -> None
    True -> {
      use directives <- option_try(split_directives(value))
      use parsed <- option_try(parse_directives(directives, None, False, []))
      let #(seconds, include_subdomains) = parsed
      Some(Entry(
        host:,
        include_subdomains:,
        expires_at: now_milliseconds + seconds * 1000,
        retained_bytes: string.byte_size(host) + string.byte_size(value) + 24,
      ))
    }
  }
}

/// Return whether one unexpired exact or includeSubDomains policy applies.
pub fn applies(
  entries: List(Entry),
  host: String,
  now_milliseconds: Int,
) -> Bool {
  case canonical_domain(host) {
    None -> False
    Some(host) ->
      list.any(entries, fn(entry) {
        entry.expires_at > now_milliseconds
        && canonical_domain(entry.host) == Some(entry.host)
        && {
          entry.host == host
          || {
            entry.include_subdomains
            && string.ends_with(host, "." <> entry.host)
          }
        }
      })
  }
}

/// Apply RFC 6797's explicit-port mapping while preserving port absence.
pub fn upgrade_port(port: Option(Int)) -> Option(Int) {
  case port {
    Some(80) -> Some(443)
    configured -> configured
  }
}

fn option_try(value: Option(a), then: fn(a) -> Option(b)) -> Option(b) {
  case value {
    Some(value) -> then(value)
    None -> None
  }
}

fn canonical_domain(host: String) -> Option(String) {
  case url_host.canonicalize(host) {
    Error(_) -> None
    Ok(canonical) -> {
      let codes =
        canonical
        |> string.to_utf_codepoints
        |> list.map(string.utf_codepoint_to_int)
      case host_idna.to_ascii(codes) {
        Error(_) -> None
        Ok(validated) ->
          case
            validated == canonical
            && string.byte_size(canonical) <= 253
            && !string.starts_with(canonical, "[")
            && !host_ip.ends_in_number(canonical)
            && valid_domain_name(canonical)
          {
            True -> Some(canonical)
            False -> None
          }
      }
    }
  }
}

fn valid_domain_name(host: String) -> Bool {
  host != "" && list.all(string.split(host, "."), valid_domain_label)
}

fn valid_domain_label(label: String) -> Bool {
  let size = string.byte_size(label)
  size >= 1
  && size <= 63
  && !string.starts_with(label, "-")
  && !string.ends_with(label, "-")
  && list.all(string.to_utf_codepoints(label), fn(character) {
    let code = string.utf_codepoint_to_int(character)
    { code >= 97 && code <= 122 } || { code >= 48 && code <= 57 } || code == 45
  })
}

fn ascii_digits(value: String) -> Bool {
  case string.to_utf_codepoints(value) {
    [] -> False
    digits ->
      list.all(digits, fn(digit) {
        let digit = string.utf_codepoint_to_int(digit)
        digit >= 48 && digit <= 57
      })
  }
}

fn token(value: String) -> Bool {
  case string.to_utf_codepoints(value) {
    [] -> False
    characters ->
      list.all(characters, fn(character) {
        let character = string.utf_codepoint_to_int(character)
        character > 31
        && character < 127
        && !list.contains(
          [
            40, 41, 60, 62, 64, 44, 59, 58, 92, 34, 47, 91, 93, 63, 61, 123, 125,
            32, 9,
          ],
          character,
        )
      })
  }
}

fn unquote(value: String) -> Option(String) {
  case string.to_utf_codepoints(value) {
    [] -> None
    [first, ..rest] ->
      case string.utf_codepoint_to_int(first) == 34 {
        True -> unquote_characters(rest, False, [])
        False -> None
      }
  }
}

fn unquote_characters(
  characters: List(UtfCodepoint),
  escaped: Bool,
  reversed: List(UtfCodepoint),
) -> Option(String) {
  case characters, escaped {
    [], _ -> None
    [character], False ->
      case string.utf_codepoint_to_int(character) == 34 {
        True -> Some(string.from_utf_codepoints(list.reverse(reversed)))
        False -> None
      }
    [character, ..rest], True -> {
      let code = string.utf_codepoint_to_int(character)
      case code >= 0 && code <= 127 {
        True -> unquote_characters(rest, False, [character, ..reversed])
        False -> None
      }
    }
    [character, ..rest], False -> {
      let code = string.utf_codepoint_to_int(character)
      case code {
        34 -> None
        92 -> unquote_characters(rest, True, reversed)
        value if value == 9 || value >= 32 ->
          unquote_characters(rest, False, [character, ..reversed])
        _ -> None
      }
    }
  }
}

fn split_directives(value: String) -> Option(List(String)) {
  split_directive_characters(
    string.to_utf_codepoints(value),
    [],
    [],
    1,
    False,
    False,
  )
}

fn split_directive_characters(
  characters: List(UtfCodepoint),
  reversed_directive: List(UtfCodepoint),
  reversed_directives: List(String),
  count: Int,
  quoted: Bool,
  escaped: Bool,
) -> Option(List(String)) {
  case count <= maximum_directives, characters, quoted, escaped {
    False, _, _, _ -> None
    True, [], True, _ | True, [], _, True -> None
    True, [], False, False ->
      Some(
        list.reverse([directive_text(reversed_directive), ..reversed_directives]),
      )
    True, [character, ..rest], _, True ->
      split_directive_characters(
        rest,
        [character, ..reversed_directive],
        reversed_directives,
        count,
        quoted,
        False,
      )
    True, [character, ..rest], True, False ->
      case string.utf_codepoint_to_int(character) {
        34 ->
          split_directive_characters(
            rest,
            [character, ..reversed_directive],
            reversed_directives,
            count,
            False,
            False,
          )
        92 ->
          split_directive_characters(
            rest,
            [character, ..reversed_directive],
            reversed_directives,
            count,
            True,
            True,
          )
        _ ->
          split_directive_characters(
            rest,
            [character, ..reversed_directive],
            reversed_directives,
            count,
            True,
            False,
          )
      }
    True, [character, ..rest], False, False ->
      case string.utf_codepoint_to_int(character) {
        34 ->
          split_directive_characters(
            rest,
            [character, ..reversed_directive],
            reversed_directives,
            count,
            True,
            False,
          )
        59 ->
          split_directive_characters(
            rest,
            [],
            [directive_text(reversed_directive), ..reversed_directives],
            count + 1,
            False,
            False,
          )
        _ ->
          split_directive_characters(
            rest,
            [character, ..reversed_directive],
            reversed_directives,
            count,
            False,
            False,
          )
      }
  }
}

fn directive_text(reversed: List(UtfCodepoint)) -> String {
  reversed |> list.reverse |> string.from_utf_codepoints |> string.trim
}

/// Rebuild one persisted policy only after enforcing the live HSTS bounds.
pub fn from_persisted(
  host: String,
  include_subdomains: Bool,
  expires_in_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Entry) {
  let age_bytes = string.byte_size(int.to_string(expires_in_milliseconds))
  case
    canonical_domain(host),
    expires_in_milliseconds > 0 && age_bytes <= maximum_field_bytes
  {
    Some(host), True ->
      Some(Entry(
        host:,
        include_subdomains:,
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes: string.byte_size(host) + age_bytes + 24,
      ))
    _, _ -> None
  }
}

fn parse_directives(
  directives: List(String),
  age: Option(Int),
  include_subdomains: Bool,
  seen: List(String),
) -> Option(#(Int, Bool)) {
  case directives {
    [] ->
      case age {
        Some(seconds) -> Some(#(seconds, include_subdomains))
        None -> None
      }
    [directive, ..rest] ->
      case directive {
        "" -> parse_directives(rest, age, include_subdomains, seen)
        _ -> parse_directive(directive, rest, age, include_subdomains, seen)
      }
  }
}

fn parse_directive(
  directive: String,
  rest: List(String),
  age: Option(Int),
  include_subdomains: Bool,
  seen: List(String),
) -> Option(#(Int, Bool)) {
  let #(name, value) = case string.split_once(directive, on: "=") {
    Ok(#(name, value)) -> #(string.trim(name), Some(string.trim(value)))
    Error(_) -> #(string.trim(directive), None)
  }
  let lower_name = string.lowercase(name)
  use <- bool.guard(
    when: !token(name) || list.contains(seen, lower_name),
    return: None,
  )
  let seen = [lower_name, ..seen]
  case lower_name, value, age {
    "max-age", Some(value), None -> {
      use value <- option_try(directive_value(value))
      case ascii_digits(value), int.parse(value) {
        True, Ok(seconds) ->
          parse_directives(rest, Some(seconds), include_subdomains, seen)
        _, _ -> None
      }
    }
    "max-age", _, _ -> None
    "includesubdomains", None, _ -> parse_directives(rest, age, True, seen)
    "includesubdomains", Some(_), _ -> None
    _, None, _ -> parse_directives(rest, age, include_subdomains, seen)
    _, Some(value), _ -> {
      use _ <- option_try(directive_value(value))
      parse_directives(rest, age, include_subdomains, seen)
    }
  }
}

fn directive_value(value: String) -> Option(String) {
  use <- bool.guard(when: token(value), return: Some(value))
  unquote(value)
}
