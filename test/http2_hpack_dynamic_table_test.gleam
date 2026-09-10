import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/hpack/dynamic_table

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn insertion_accounts_for_overhead_and_indexes_newest_first_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(128)
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("a", "1"))
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("b", "22"))

  assert dynamic_table.size(table) == 69
  assert dynamic_table.length(table) == 2
  assert dynamic_table.get_relative(table, 0) == Some(field("b", "22"))
  assert dynamic_table.get_relative(table, 1) == Some(field("a", "1"))
  assert dynamic_table.get_relative(table, 2) == None
}

pub fn insertion_and_capacity_reduction_evict_the_oldest_entries_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(70)
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("a", "1"))
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("b", "2"))
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("c", "3"))

  assert dynamic_table.length(table) == 2
  assert dynamic_table.get_relative(table, 0) == Some(field("c", "3"))
  assert dynamic_table.get_relative(table, 1) == Some(field("b", "2"))

  let assert Ok(table) = dynamic_table.set_capacity(table, 34)
  assert dynamic_table.capacity(table) == 34
  assert dynamic_table.get_relative(table, 0) == Some(field("c", "3"))
  assert dynamic_table.get_relative(table, 1) == None
}

pub fn oversized_entry_empties_the_table_without_being_inserted_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(40)
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("a", "1"))
  let assert Ok(#(table, False)) =
    dynamic_table.insert(table, field("too-long", "also-too-long"))

  assert dynamic_table.size(table) == 0
  assert dynamic_table.length(table) == 0
}

pub fn configured_maximum_and_field_shape_are_enforced_test() -> Nil {
  assert dynamic_table.new(-1) == Error(dynamic_table.InvalidCapacity)
  let assert Ok(table) = dynamic_table.new(64)
  assert dynamic_table.set_capacity(table, 65)
    == Error(dynamic_table.CapacityExceeded(maximum: 64))
  assert dynamic_table.insert(table, dynamic_table.Field(<<>>, <<>>))
    == Error(dynamic_table.InvalidField)
  assert dynamic_table.insert(
      table,
      dynamic_table.Field(<<"a":utf8>>, <<1:size(1)>>),
    )
    == Error(dynamic_table.InvalidField)
}

pub fn exact_and_name_lookup_prefer_the_newest_entry_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(256)
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("x", "old"))
  let assert Ok(#(table, True)) = dynamic_table.insert(table, field("x", "new"))

  assert dynamic_table.find(table, field("x", "new")) == Some(0)
  assert dynamic_table.find_name(table, <<"x":utf8>>) == Some(0)
}

fn field(name: String, value: String) -> dynamic_table.Field {
  dynamic_table.Field(<<name:utf8>>, <<value:utf8>>)
}
