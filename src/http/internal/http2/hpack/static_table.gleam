//// RFC 7541 Appendix A static header table.

import gleam/option.{type Option, None, Some}

/// One immutable static-table field.
pub type Field {
  Field(name: BitArray, value: BitArray)
}

/// Look up a one-based HPACK static-table index.
pub fn get(index: Int) -> Option(Field) {
  get_at(entries(), index)
}

/// Find the lowest one-based exact name/value index.
pub fn find(field: Field) -> Option(Int) {
  find_exact(entries(), field, 1)
}

/// Find the lowest one-based index carrying `name`.
pub fn find_name(name: BitArray) -> Option(Int) {
  find_named(entries(), name, 1)
}

/// Number of entries frozen by RFC 7541.
pub fn size() -> Int {
  61
}

fn get_at(fields: List(Field), index: Int) -> Option(Field) {
  case fields, index {
    _, value if value < 1 -> None
    [], _ -> None
    [field, ..], 1 -> Some(field)
    [_, ..rest], remaining -> get_at(rest, remaining - 1)
  }
}

fn find_exact(fields: List(Field), wanted: Field, index: Int) -> Option(Int) {
  case fields {
    [] -> None
    [field, ..rest] ->
      case field == wanted {
        True -> Some(index)
        False -> find_exact(rest, wanted, index + 1)
      }
  }
}

fn find_named(
  fields: List(Field),
  wanted: BitArray,
  index: Int,
) -> Option(Int) {
  case fields {
    [] -> None
    [Field(name, _), ..rest] ->
      case name == wanted {
        True -> Some(index)
        False -> find_named(rest, wanted, index + 1)
      }
  }
}

fn entries() -> List(Field) {
  [
    field(":authority", ""),
    field(":method", "GET"),
    field(":method", "POST"),
    field(":path", "/"),
    field(":path", "/index.html"),
    field(":scheme", "http"),
    field(":scheme", "https"),
    field(":status", "200"),
    field(":status", "204"),
    field(":status", "206"),
    field(":status", "304"),
    field(":status", "400"),
    field(":status", "404"),
    field(":status", "500"),
    field("accept-charset", ""),
    field("accept-encoding", "gzip, deflate"),
    field("accept-language", ""),
    field("accept-ranges", ""),
    field("accept", ""),
    field("access-control-allow-origin", ""),
    field("age", ""),
    field("allow", ""),
    field("authorization", ""),
    field("cache-control", ""),
    field("content-disposition", ""),
    field("content-encoding", ""),
    field("content-language", ""),
    field("content-length", ""),
    field("content-location", ""),
    field("content-range", ""),
    field("content-type", ""),
    field("cookie", ""),
    field("date", ""),
    field("etag", ""),
    field("expect", ""),
    field("expires", ""),
    field("from", ""),
    field("host", ""),
    field("if-match", ""),
    field("if-modified-since", ""),
    field("if-none-match", ""),
    field("if-range", ""),
    field("if-unmodified-since", ""),
    field("last-modified", ""),
    field("link", ""),
    field("location", ""),
    field("max-forwards", ""),
    field("proxy-authenticate", ""),
    field("proxy-authorization", ""),
    field("range", ""),
    field("referer", ""),
    field("refresh", ""),
    field("retry-after", ""),
    field("server", ""),
    field("set-cookie", ""),
    field("strict-transport-security", ""),
    field("transfer-encoding", ""),
    field("user-agent", ""),
    field("vary", ""),
    field("via", ""),
    field("www-authenticate", ""),
  ]
}

fn field(name: String, value: String) -> Field {
  Field(<<name:utf8>>, <<value:utf8>>)
}
