//// Shared decoded QPACK field representation.

import gleam/bit_array

/// One HTTP field. `never_index` preserves the QPACK N bit for intermediaries.
pub type Header {
  Header(name: BitArray, value: BitArray, never_index: Bool)
}

/// RFC field-section size contribution (name + value + 32 bytes).
pub fn size(header: Header) -> Int {
  let Header(name, value, _) = header
  bit_array.byte_size(name) + bit_array.byte_size(value) + 32
}
