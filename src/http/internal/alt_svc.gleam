//// Conservative Alt-Svc parsing for verified same-origin HTTP/3 discovery.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

const maximum_age_seconds = 604_800

/// One verified HTTP/3 alternative retained by the private finite store.
pub type Entry {
  Entry(
    origin_host: String,
    origin_port: Int,
    alternative_port: Int,
    expires_at: Int,
    retained_bytes: Int,
  )
}

/// Parse the first bounded same-host `h3` alternative with explicit max-age.
pub fn parse(
  value: String,
  origin_host: String,
  origin_port: Int,
  now_milliseconds: Int,
) -> Option(Entry) {
  let host = string.lowercase(origin_host)
  case string.lowercase(string.trim(value)) {
    "clear" if origin_port > 0 && origin_port <= 65_535 ->
      Some(Entry(
        origin_host: host,
        origin_port:,
        alternative_port: origin_port,
        expires_at: now_milliseconds,
        retained_bytes: string.byte_size(host) + 32,
      ))
    _ ->
      parse_alternatives(
        split_unquoted(value, ","),
        host,
        origin_port,
        now_milliseconds,
      )
  }
}

/// Stable exact-origin replacement key.
pub fn key(host: String, port: Int) -> String {
  string.lowercase(host) <> ":" <> int.to_string(port)
}

/// Construct a validated discovery entry from an authenticated HTTPS record.
pub fn from_https_record(
  origin_host: String,
  origin_port: Int,
  alternative_port: Int,
  expires_in_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Entry) {
  case
    origin_port > 0 && origin_port <= 65_535,
    alternative_port > 0 && alternative_port <= 65_535,
    expires_in_milliseconds > 0
    && expires_in_milliseconds <= maximum_age_seconds * 1000
  {
    True, True, True -> {
      let host = string.lowercase(origin_host)
      Some(Entry(
        origin_host: host,
        origin_port:,
        alternative_port:,
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes: string.byte_size(host) + 32,
      ))
    }
    _, _, _ -> None
  }
}

/// Return a usable same-port HTTP/3 alternative for this origin.
///
/// Alternate ports remain parsed and bounded but are not selected until the
/// transport adapter can preserve the original HTTP authority separately.
pub fn supports_same_port(
  entries: List(Entry),
  host: String,
  port: Int,
  now_milliseconds: Int,
) -> Bool {
  let host = string.lowercase(host)
  list.any(entries, fn(entry) {
    entry.origin_host == host
    && entry.origin_port == port
    && entry.alternative_port == port
    && entry.expires_at > now_milliseconds
  })
}

fn parse_alternatives(
  alternatives: List(String),
  host: String,
  origin_port: Int,
  now: Int,
) -> Option(Entry) {
  case alternatives {
    [] -> None
    [alternative, ..rest] ->
      case parse_alternative(string.trim(alternative), host, origin_port, now) {
        Some(entry) -> Some(entry)
        None -> parse_alternatives(rest, host, origin_port, now)
      }
  }
}

fn parse_alternative(
  alternative: String,
  host: String,
  origin_port: Int,
  now: Int,
) -> Option(Entry) {
  case split_unquoted(alternative, ";") {
    [] -> None
    [service, ..parameters] ->
      case string.split_once(string.trim(service), on: "=") {
        Ok(#(protocol, authority)) ->
          case
            string.lowercase(string.trim(protocol)),
            quoted_port(string.trim(authority)),
            maximum_age(parameters)
          {
            "h3", Some(port), Some(seconds)
              if port > 0 && port <= 65_535 && seconds >= 0
            -> {
              let seconds = int.min(seconds, maximum_age_seconds)
              Some(Entry(
                origin_host: host,
                origin_port:,
                alternative_port: port,
                expires_at: now + seconds * 1000,
                retained_bytes: string.byte_size(host) + 32,
              ))
            }
            _, _, _ -> None
          }
        Error(_) -> None
      }
  }
}

fn quoted_port(authority: String) -> Option(Int) {
  case unquote(authority) {
    None -> None
    Some(inner) ->
      case string.starts_with(inner, ":") {
        False -> None
        True ->
          inner
          |> string.drop_start(1)
          |> int.parse
          |> option_from_result
      }
  }
}

/// Split one field value on a delimiter, but only outside a quoted-string.
///
/// RFC 7838 section 3 makes a parameter value a token or a quoted-string, and
/// RFC 7230 admits both delimiters as `qdtext`, so splitting on every
/// occurrence ends an alt-value or a parameter in the middle of a value a
/// server is entitled to send. The walk is one pass and the caller has already
/// bounded the field.
fn split_unquoted(value: String, delimiter: String) -> List(String) {
  let #(parts, last, _, _) =
    value
    |> string.to_graphemes
    |> list.fold(#([], "", False, False), fn(state, grapheme) {
      let #(parts, current, quoted, escaped) = state
      case escaped, quoted, grapheme, grapheme == delimiter {
        // The character after a backslash is data, whatever it is.
        True, _, _, _ -> #(parts, current <> grapheme, quoted, False)
        False, True, "\\", _ -> #(parts, current <> grapheme, True, True)
        False, _, "\"", _ -> #(parts, current <> grapheme, !quoted, False)
        False, False, _, True -> #([current, ..parts], "", False, False)
        False, _, _, _ -> #(parts, current <> grapheme, quoted, False)
      }
    })
  list.reverse([last, ..parts])
}

/// Read a token or a quoted-string as the value it stands for.
///
/// A bare quote before the end, a backslash with nothing after it, and a value
/// that runs out before its closing quote are all refused; a token is returned
/// as it was written.
fn unquote(raw: String) -> Option(String) {
  case string.to_graphemes(raw) {
    ["\"", ..body] -> unquote_body(body, "")
    _ ->
      case string.contains(raw, "\"") {
        True -> None
        False -> Some(raw)
      }
  }
}

fn unquote_body(remaining: List(String), decoded: String) -> Option(String) {
  case remaining {
    ["\""] -> Some(decoded)
    ["\\", escaped, ..rest] -> unquote_body(rest, decoded <> escaped)
    ["\"", ..] -> None
    [grapheme, ..rest] -> unquote_body(rest, decoded <> grapheme)
    [] -> None
  }
}

fn maximum_age(parameters: List(String)) -> Option(Int) {
  case parameters {
    [] -> None
    [parameter, ..rest] ->
      case delta_seconds(parameter) {
        Some(seconds) -> Some(seconds)
        None -> maximum_age(rest)
      }
  }
}

/// The `ma` value, which the grammar admits as a token or a quoted-string.
fn delta_seconds(parameter: String) -> Option(Int) {
  case string.split_once(string.trim(parameter), on: "=") {
    Error(Nil) -> None
    Ok(#(name, value)) ->
      case string.lowercase(string.trim(name)) == "ma" {
        False -> None
        True ->
          case unquote(string.trim(value)) {
            None -> None
            Some(inner) -> option_from_result(int.parse(inner))
          }
      }
  }
}

fn option_from_result(result: Result(value, error)) -> Option(value) {
  case result {
    Ok(value) -> Some(value)
    Error(_) -> None
  }
}
