//// Header transformations applied exactly once at the generic HTTP boundary.

import gleam/list
import gleam/string

/// RFC 9114 permits QPACK to carry a Cookie field as multiple field lines.
/// Recombine exact lowercase `cookie` lines in their original order, placing the joined value at the first line's position.
/// `set-cookie` and every other field remain separate.
pub fn combine_cookie_fields(
  headers: List(#(String, String)),
) -> List(#(String, String)) {
  let values =
    headers
    |> list.filter_map(fn(field) {
      case field {
        #("cookie", value) -> Ok(value)
        _ -> Error(Nil)
      }
    })
  case values {
    [] -> headers
    _ ->
      replace_cookie_fields(
        headers: headers,
        combined: string.join(values, "; "),
        inserted: False,
      )
  }
}

fn replace_cookie_fields(
  headers headers: List(#(String, String)),
  combined combined: String,
  inserted inserted: Bool,
) -> List(#(String, String)) {
  case headers {
    [] -> []
    [#("cookie", _), ..rest] ->
      case inserted {
        True ->
          replace_cookie_fields(
            headers: rest,
            combined: combined,
            inserted: True,
          )
        False -> [
          #("cookie", combined),
          ..replace_cookie_fields(
            headers: rest,
            combined: combined,
            inserted: True,
          )
        ]
      }
    [field, ..rest] -> [
      field,
      ..replace_cookie_fields(
        headers: rest,
        combined: combined,
        inserted: inserted,
      )
    ]
  }
}
