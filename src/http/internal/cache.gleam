//// Conservative bounded HTTP response-cache decisions.

import gleam/bit_array
import gleam/http.{type Scheme, Get, Head, Http, Https}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import http/body

const maximum_freshness_seconds = 86_400

const maximum_persisted_headers = 256

const maximum_persisted_key_bytes = 8192

/// One complete replayable response retained by the private finite store.
pub type Entry {
  Entry(
    key: String,
    status: Int,
    headers: List(#(String, String)),
    bytes: BitArray,
    trailers: body.Headers,
    stored_at: Int,
    arrival_age_seconds: Int,
    expires_at: Int,
    retained_bytes: Int,
  )
}

/// Return a cache key only for requests this non-revalidating cache can serve.
///
/// RFC 9111 section 5.2.1.5: a request carrying `no-store` means no part of it
/// or of any response to it is stored, in a private cache as much as a shared
/// one. Withholding the key is how that is enforced, because the key is what
/// every other path here needs.
pub fn key(outgoing: Request(body)) -> Option(String) {
  case
    outgoing.method == Get,
    has_header(outgoing.headers, "authorization"),
    has_header(outgoing.headers, "range"),
    request_forbids_storage(outgoing.headers)
  {
    True, False, False, False -> target_key(outgoing)
    _, _, _, _ -> None
  }
}

/// The store key for one request's target, independent of whether that request
/// may be served or stored.
fn target_key(outgoing: Request(body)) -> Option(String) {
  Some(
    scheme_text(outgoing.scheme)
    <> "://"
    <> string.lowercase(outgoing.host)
    <> ":"
    <> int.to_string(request_port(outgoing))
    <> outgoing.path
    <> case outgoing.query {
      Some(query) -> "?" <> query
      None -> ""
    },
  )
}

/// The key an unsafe request invalidates, if any.
///
/// RFC 9111 section 4.4: a non-error answer to an unsafe request invalidates
/// the target URI, so the next read does not serve what the write replaced. The
/// key is the exact scheme, host, port, and target, so one origin's write can
/// only reach its own entry.
pub fn invalidated_key(outgoing: Request(body), status: Int) -> Option(String) {
  case outgoing.method == Get || outgoing.method == Head, status < 400 {
    False, True -> target_key(outgoing)
    _, _ -> None
  }
}

/// An already-expired stand-in for one key.
///
/// Storing it removes whatever the key held, from the in-memory store and from
/// the persistence adapter alike, without first reading the entry back out to
/// rewrite it.
pub fn tombstone(key: String, now_milliseconds: Int) -> Entry {
  Entry(
    key:,
    status: 200,
    headers: [],
    bytes: <<>>,
    trailers: [],
    stored_at: now_milliseconds,
    arrival_age_seconds: 0,
    expires_at: now_milliseconds,
    retained_bytes: 1,
  )
}

/// Whether the request's own directives forbid storing anything about it.
fn request_forbids_storage(headers: List(#(String, String))) -> Bool {
  header_values(headers, "cache-control", [])
  |> list.flat_map(fn(value) { string.split(value, on: ",") })
  |> list.map(string.trim)
  |> directive_present("no-store")
}

/// Construct a cache entry only for an explicitly fresh, self-contained 200.
pub fn entry(
  outgoing: Request(body),
  incoming: Response(other_body),
  bytes: BitArray,
  trailers: body.Headers,
  now_milliseconds: Int,
) -> Option(Entry) {
  case
    key(outgoing),
    incoming.status == 200,
    has_header(incoming.headers, "vary"),
    has_header(incoming.headers, "set-cookie"),
    freshness_seconds(incoming.headers)
  {
    Some(key), True, False, False, Some(seconds) if seconds > 0 -> {
      let retained_bytes =
        bit_array.byte_size(bytes)
        + header_bytes(incoming.headers, 0)
        + header_bytes(trailers, 0)
        + string.byte_size(key)
        + 64
      Some(Entry(
        key:,
        status: incoming.status,
        headers: incoming.headers,
        bytes:,
        trailers:,
        stored_at: now_milliseconds,
        arrival_age_seconds: option.unwrap(response_age(incoming.headers), 0),
        expires_at: now_milliseconds + seconds * 1000,
        retained_bytes:,
      ))
    }
    _, _, _, _, _ -> None
  }
}

/// Recreate an independent standard response from one retained entry.
///
/// RFC 9111 section 4 requires a stored response served without validation to
/// carry an Age header field. It counts from the age the response already had
/// when it arrived, so a chain of caches accumulates rather than resets, and it
/// replaces whatever Age was stored rather than joining it as a second value.
pub fn response(entry: Entry, now_milliseconds: Int) -> Response(body.Body) {
  let held = int.max(0, now_milliseconds - entry.stored_at) / 1000
  let age = entry.arrival_age_seconds + held
  Response(
    status: entry.status,
    headers: [
      #("age", int.to_string(age)),
      ..list.filter(entry.headers, fn(field) {
        string.lowercase(field.0) != "age"
      })
    ],
    body: body.from_bytes_with_trailers(entry.bytes, entry.trailers),
  )
}

/// Rebuild a persisted response only after enforcing the live cache bounds.
pub fn from_persisted(
  key: String,
  status: Int,
  headers: List(#(String, String)),
  bytes: BitArray,
  trailers: body.Headers,
  expires_in_milliseconds: Int,
  now_milliseconds: Int,
) -> Option(Entry) {
  let retained_bytes =
    bit_array.byte_size(bytes)
    + header_bytes(headers, 0)
    + header_bytes(trailers, 0)
    + string.byte_size(key)
    + 64
  case
    status == 200,
    valid_persisted_key(key),
    bit_array.bit_size(bytes) % 8 == 0,
    list.length(headers) <= maximum_persisted_headers
    && list.length(trailers) <= maximum_persisted_headers,
    valid_headers(headers) && valid_headers(trailers),
    !has_header(headers, "vary") && !has_header(headers, "set-cookie"),
    expires_in_milliseconds > 0
    && expires_in_milliseconds <= maximum_freshness_seconds * 1000
  {
    True, True, True, True, True, True, True ->
      Some(Entry(
        key:,
        status:,
        headers:,
        bytes:,
        trailers:,
        stored_at: now_milliseconds,
        arrival_age_seconds: option.unwrap(response_age(headers), 0),
        expires_at: now_milliseconds + expires_in_milliseconds,
        retained_bytes:,
      ))
    _, _, _, _, _, _, _ -> None
  }
}

fn freshness_seconds(headers: List(#(String, String))) -> Option(Int) {
  case header_values(headers, "cache-control", []) {
    [] -> None
    values -> {
      let directives =
        values
        |> list.flat_map(fn(value) { string.split(value, on: ",") })
        |> list.map(string.trim)
      case
        directive_present(directives, "no-store")
        || directive_present(directives, "private")
        || directive_present(directives, "no-cache")
      {
        True -> None
        False -> remaining_freshness(directives, headers)
      }
    }
  }
}

fn remaining_freshness(
  directives: List(String),
  headers: List(#(String, String)),
) -> Option(Int) {
  case maximum_age(directives), response_age(headers) {
    Some(maximum), Some(age) if maximum > age ->
      Some(int.min(maximum - age, maximum_freshness_seconds))
    _, _ -> None
  }
}

fn response_age(headers: List(#(String, String))) -> Option(Int) {
  case header_values(headers, "age", []) {
    [] -> Some(0)
    [value] ->
      case int.parse(string.trim(value)) {
        Ok(seconds) if seconds >= 0 -> Some(seconds)
        _ -> None
      }
    _ -> None
  }
}

fn maximum_age(directives: List(String)) -> Option(Int) {
  case directives {
    [] -> None
    [directive, ..rest] ->
      case string.split_once(directive, on: "=") {
        Ok(#(name, value)) ->
          case
            string.lowercase(string.trim(name)),
            int.parse(string.trim(value))
          {
            "max-age", Ok(seconds) -> Some(seconds)
            _, _ -> maximum_age(rest)
          }
        Error(_) -> maximum_age(rest)
      }
  }
}

fn directive_present(directives: List(String), expected: String) -> Bool {
  case directives {
    [] -> False
    [directive, ..rest] ->
      string.lowercase(directive) == expected
      || directive_present(rest, expected)
  }
}

fn has_header(headers: List(#(String, String)), expected: String) -> Bool {
  case headers {
    [] -> False
    [#(name, _), ..rest] ->
      string.lowercase(name) == expected || has_header(rest, expected)
  }
}

fn header_values(
  headers: List(#(String, String)),
  expected: String,
  reversed: List(String),
) -> List(String) {
  case headers {
    [] -> list.reverse(reversed)
    [#(name, value), ..rest] ->
      case string.lowercase(name) == expected {
        True -> header_values(rest, expected, [value, ..reversed])
        False -> header_values(rest, expected, reversed)
      }
  }
}

fn header_bytes(headers: List(#(String, String)), total: Int) -> Int {
  case headers {
    [] -> total
    [#(name, value), ..rest] ->
      header_bytes(
        rest,
        total + string.byte_size(name) + string.byte_size(value) + 4,
      )
  }
}

fn valid_persisted_key(key: String) -> Bool {
  key != ""
  && string.byte_size(key) <= maximum_persisted_key_bytes
  && {
    string.starts_with(key, "http://") || string.starts_with(key, "https://")
  }
  && !string.contains(key, "\r")
  && !string.contains(key, "\n")
  && !string.contains(key, "\u{0000}")
}

fn valid_headers(headers: List(#(String, String))) -> Bool {
  list.all(headers, fn(header) {
    let #(name, value) = header
    name != ""
    && string.byte_size(name) <= 256
    && string.byte_size(value) <= 65_536
    && !string.contains(name, " ")
    && !string.contains(name, "\t")
    && !string.contains(name, ":")
    && !string.contains(name, "\r")
    && !string.contains(name, "\n")
    && !string.contains(name, "\u{0000}")
    && !string.contains(value, "\r")
    && !string.contains(value, "\n")
    && !string.contains(value, "\u{0000}")
  })
}

fn scheme_text(scheme: Scheme) -> String {
  case scheme {
    Http -> "http"
    Https -> "https"
  }
}

fn request_port(outgoing: Request(body)) -> Int {
  case outgoing.port, outgoing.scheme {
    Some(port), _ -> port
    None, Http -> 80
    None, Https -> 443
  }
}
