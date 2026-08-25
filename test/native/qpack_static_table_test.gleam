import gleam/option.{None, Some}
import http3/internal/qpack/static_table

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn exposes_complete_static_table_and_searches_deterministically_test() -> Nil {
  assert static_table.size() == 99
  assert static_table.get(0) == Some(static_table.Field(":authority", ""))
  assert static_table.get(17) == Some(static_table.Field(":method", "GET"))
  assert static_table.get(98)
    == Some(static_table.Field("x-frame-options", "sameorigin"))
  assert static_table.get(99) == None
  assert static_table.find(":status", "200") == Some(25)
  assert static_table.find_name("content-type") == Some(44)
  assert static_table.find("missing", "") == None
}
