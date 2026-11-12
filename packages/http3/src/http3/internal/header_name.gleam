//// Canonical outbound HTTP field-name handling.

import gleam/list
import gleam/string

/// Convert only ASCII A-Z to lowercase.
/// Non-ASCII codepoints are preserved so the subsequent HTTP token validator still rejects them rather than gaining meaning through Unicode case folding.
pub fn ascii_lowercase(value: String) -> String {
  value
  |> string.to_utf_codepoints
  |> list.map(fn(character) {
    let codepoint = string.utf_codepoint_to_int(character)
    case codepoint >= 65 && codepoint <= 90 {
      False -> character
      True ->
        case string.utf_codepoint(codepoint + 32) {
          Ok(lowercase) -> lowercase
          Error(Nil) -> character
        }
    }
  })
  |> string.from_utf_codepoints
}
