//// RFC 9204 Appendix A static field table.

import gleam/option.{type Option, None, Some}

/// One lower-case HTTP field name/value pair.
pub type Field {
  Field(name: String, value: String)
}

/// Look up a zero-based static table index.
pub fn get(index: Int) -> Option(Field) {
  get_at(entries(), index)
}

/// Find the lowest exact name/value index.
pub fn find(name: String, value: String) -> Option(Int) {
  find_exact(entries(), name, value, 0)
}

/// Find the lowest index carrying a name, regardless of value.
pub fn find_name(name: String) -> Option(Int) {
  find_named(entries(), name, 0)
}

/// Find an exact field supplied as wire bytes.
pub fn find_bytes(name: BitArray, value: BitArray) -> Option(Int) {
  find_exact_bytes(entries(), name, value, 0)
}

/// Find a field name supplied as wire bytes.
pub fn find_name_bytes(name: BitArray) -> Option(Int) {
  find_named_bytes(entries(), name, 0)
}

/// Number of entries frozen by RFC 9204.
pub fn size() -> Int {
  99
}

fn find_exact(
  fields: List(Field),
  name: String,
  value: String,
  index: Int,
) -> Option(Int) {
  case fields {
    [] -> None
    [Field(current_name, current_value), ..rest] ->
      case current_name == name && current_value == value {
        True -> Some(index)
        False -> find_exact(rest, name, value, index + 1)
      }
  }
}

fn get_at(fields: List(Field), index: Int) -> Option(Field) {
  case fields, index {
    _, value if value < 0 -> None
    [], _ -> None
    [field, ..], 0 -> Some(field)
    [_, ..rest], remaining -> get_at(rest, remaining - 1)
  }
}

fn find_named(fields: List(Field), name: String, index: Int) -> Option(Int) {
  case fields {
    [] -> None
    [Field(current_name, _), ..rest] ->
      case current_name == name {
        True -> Some(index)
        False -> find_named(rest, name, index + 1)
      }
  }
}

fn find_exact_bytes(
  fields: List(Field),
  name: BitArray,
  value: BitArray,
  index: Int,
) -> Option(Int) {
  case fields {
    [] -> None
    [Field(current_name, current_value), ..rest] ->
      case <<current_name:utf8>> == name && <<current_value:utf8>> == value {
        True -> Some(index)
        False -> find_exact_bytes(rest, name, value, index + 1)
      }
  }
}

fn find_named_bytes(
  fields: List(Field),
  name: BitArray,
  index: Int,
) -> Option(Int) {
  case fields {
    [] -> None
    [Field(current_name, _), ..rest] ->
      case <<current_name:utf8>> == name {
        True -> Some(index)
        False -> find_named_bytes(rest, name, index + 1)
      }
  }
}

fn entries() -> List(Field) {
  [
    Field(":authority", ""),
    Field(":path", "/"),
    Field("age", "0"),
    Field("content-disposition", ""),
    Field("content-length", "0"),
    Field("cookie", ""),
    Field("date", ""),
    Field("etag", ""),
    Field("if-modified-since", ""),
    Field("if-none-match", ""),
    Field("last-modified", ""),
    Field("link", ""),
    Field("location", ""),
    Field("referer", ""),
    Field("set-cookie", ""),
    Field(":method", "CONNECT"),
    Field(":method", "DELETE"),
    Field(":method", "GET"),
    Field(":method", "HEAD"),
    Field(":method", "OPTIONS"),
    Field(":method", "POST"),
    Field(":method", "PUT"),
    Field(":scheme", "http"),
    Field(":scheme", "https"),
    Field(":status", "103"),
    Field(":status", "200"),
    Field(":status", "304"),
    Field(":status", "404"),
    Field(":status", "503"),
    Field("accept", "*/*"),
    Field("accept", "application/dns-message"),
    Field("accept-encoding", "gzip, deflate, br"),
    Field("accept-ranges", "bytes"),
    Field("access-control-allow-headers", "cache-control"),
    Field("access-control-allow-headers", "content-type"),
    Field("access-control-allow-origin", "*"),
    Field("cache-control", "max-age=0"),
    Field("cache-control", "max-age=2592000"),
    Field("cache-control", "max-age=604800"),
    Field("cache-control", "no-cache"),
    Field("cache-control", "no-store"),
    Field("cache-control", "public, max-age=31536000"),
    Field("content-encoding", "br"),
    Field("content-encoding", "gzip"),
    Field("content-type", "application/dns-message"),
    Field("content-type", "application/javascript"),
    Field("content-type", "application/json"),
    Field("content-type", "application/x-www-form-urlencoded"),
    Field("content-type", "image/gif"),
    Field("content-type", "image/jpeg"),
    Field("content-type", "image/png"),
    Field("content-type", "text/css"),
    Field("content-type", "text/html; charset=utf-8"),
    Field("content-type", "text/plain"),
    Field("content-type", "text/plain;charset=utf-8"),
    Field("range", "bytes=0-"),
    Field("strict-transport-security", "max-age=31536000"),
    Field("strict-transport-security", "max-age=31536000; includesubdomains"),
    Field(
      "strict-transport-security",
      "max-age=31536000; includesubdomains; preload",
    ),
    Field("vary", "accept-encoding"),
    Field("vary", "origin"),
    Field("x-content-type-options", "nosniff"),
    Field("x-xss-protection", "1; mode=block"),
    Field(":status", "100"),
    Field(":status", "204"),
    Field(":status", "206"),
    Field(":status", "302"),
    Field(":status", "400"),
    Field(":status", "403"),
    Field(":status", "421"),
    Field(":status", "425"),
    Field(":status", "500"),
    Field("accept-language", ""),
    Field("access-control-allow-credentials", "FALSE"),
    Field("access-control-allow-credentials", "TRUE"),
    Field("access-control-allow-headers", "*"),
    Field("access-control-allow-methods", "get"),
    Field("access-control-allow-methods", "get, post, options"),
    Field("access-control-allow-methods", "options"),
    Field("access-control-expose-headers", "content-length"),
    Field("access-control-request-headers", "content-type"),
    Field("access-control-request-method", "get"),
    Field("access-control-request-method", "post"),
    Field("alt-svc", "clear"),
    Field("authorization", ""),
    Field(
      "content-security-policy",
      "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    Field("early-data", "1"),
    Field("expect-ct", ""),
    Field("forwarded", ""),
    Field("if-range", ""),
    Field("origin", ""),
    Field("purpose", "prefetch"),
    Field("server", ""),
    Field("timing-allow-origin", "*"),
    Field("upgrade-insecure-requests", "1"),
    Field("user-agent", ""),
    Field("x-forwarded-for", ""),
    Field("x-frame-options", "deny"),
    Field("x-frame-options", "sameorigin"),
  ]
}
