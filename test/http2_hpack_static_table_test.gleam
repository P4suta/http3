import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/hpack/static_table

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn rfc_static_indices_are_one_based_and_complete_test() -> Nil {
  assert static_table.size() == 61
  assert static_table.get(1)
    == Some(static_table.Field(<<":authority":utf8>>, <<>>))
  assert static_table.get(2)
    == Some(static_table.Field(<<":method":utf8>>, <<"GET":utf8>>))
  assert static_table.get(16)
    == Some(
      static_table.Field(<<"accept-encoding":utf8>>, <<"gzip, deflate":utf8>>),
    )
  assert static_table.get(61)
    == Some(static_table.Field(<<"www-authenticate":utf8>>, <<>>))
  assert static_table.get(0) == None
  assert static_table.get(62) == None
}

pub fn exact_and_name_lookup_use_the_lowest_static_index_test() -> Nil {
  assert static_table.find(
      static_table.Field(<<":method":utf8>>, <<"POST":utf8>>),
    )
    == Some(3)
  assert static_table.find_name(<<":method":utf8>>) == Some(2)
  assert static_table.find_name(<<":status":utf8>>) == Some(8)
  assert static_table.find_name(<<"missing":utf8>>) == None
}
