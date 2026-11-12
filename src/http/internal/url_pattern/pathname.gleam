//// WHATWG URLPattern pathname encoding callback and URL path serialization.
//// Input/output byte ceilings are enforced by the calling component layer.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string

/// The `/-` sentinel preserves relative pieces, including a leading dot.
/// The same callback applies to a complete pathname received as URLPatternInit.
pub fn canonical_piece(value: String) -> String {
  case value {
    "" -> ""
    _ -> {
      let leading_slash = string.starts_with(value, "/")
      let modified = case leading_slash {
        True -> value
        False -> "/-" <> value
      }
      let normalized =
        modified
        |> string.replace("\t", "")
        |> string.replace("\n", "")
        |> string.replace("\r", "")
        |> string.replace("\\", "/")
      let segments = normalized |> string.split(on: "/") |> list.drop(1)
      let path = "/" <> string.join(remove_dots(segments, []), "/")
      let path = encode(bit_array.from_string(path), []) |> string.concat
      case leading_slash {
        True -> path
        False -> string.drop_start(path, 2)
      }
    }
  }
}

fn remove_dots(segments: List(String), reversed: List(String)) -> List(String) {
  case segments {
    [] -> list.reverse(reversed)
    [segment, ..rest] ->
      case string.lowercase(segment) {
        "." | "%2e" ->
          case rest {
            [] -> list.reverse(["", ..reversed])
            _ -> remove_dots(rest, reversed)
          }
        ".." | ".%2e" | "%2e." | "%2e%2e" -> {
          let shortened = list.drop(reversed, 1)
          case rest {
            [] -> list.reverse(["", ..shortened])
            _ -> remove_dots(rest, shortened)
          }
        }
        _ -> remove_dots(rest, [segment, ..reversed])
      }
  }
}

fn encode(bytes: BitArray, reversed: List(String)) -> List(String) {
  case bytes {
    <<>> -> list.reverse(reversed)
    <<byte, rest:bits>> -> {
      let value = case byte {
        code
          if code <= 32
          || code >= 127
          || code == 34
          || code == 35
          || code == 60
          || code == 62
          || code == 63
          || code == 96
          || code == 123
          || code == 125
        -> "%" <> hex_digit(code / 16) <> hex_digit(code % 16)
        // This branch contains only one ASCII byte, hence valid UTF-8.
        code -> bit_array.to_string(<<code>>) |> result.unwrap("")
      }
      encode(rest, [value, ..reversed])
    }
    _ -> []
  }
}

fn hex_digit(value: Int) -> String {
  string.slice("0123456789ABCDEF", at_index: value, length: 1)
}
