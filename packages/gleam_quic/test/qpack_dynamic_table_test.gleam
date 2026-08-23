import gleam/option.{Some}
import gleam_quic/internal/qpack/dynamic_table

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn inserts_duplicates_evicts_and_resolves_indices_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(128)
  let assert Ok(table) = dynamic_table.set_capacity(table, 128)
  assert dynamic_table.capacity(table) == 128
  assert dynamic_table.maximum_allowed_capacity(table) == 128
  let assert Ok(#(table, 0)) =
    dynamic_table.insert(table, dynamic_table.Field(<<"a">>, <<"1">>))
  let assert Ok(#(table, 1)) =
    dynamic_table.insert(table, dynamic_table.Field(<<"b">>, <<"2">>))
  assert dynamic_table.get_relative(table, 0)
    == Ok(dynamic_table.Entry(1, dynamic_table.Field(<<"b">>, <<"2">>)))
  assert dynamic_table.find(table, dynamic_table.Field(<<"a">>, <<"1">>))
    == Some(dynamic_table.Entry(0, dynamic_table.Field(<<"a">>, <<"1">>)))
  assert dynamic_table.find_name(table, <<"b">>)
    == Some(dynamic_table.Entry(1, dynamic_table.Field(<<"b">>, <<"2">>)))
  let assert Ok(#(table, 2)) = dynamic_table.duplicate(table, 1)
  assert dynamic_table.get_absolute(table, 2)
    == Ok(dynamic_table.Entry(2, dynamic_table.Field(<<"a">>, <<"1">>)))
  assert dynamic_table.insert_count(table) == 3
  assert dynamic_table.size(table) == 102

  let assert Ok(table) = dynamic_table.set_capacity(table, 68)
  assert dynamic_table.get_absolute(table, 0)
    == Error(dynamic_table.MissingAbsoluteIndex(0))
  assert dynamic_table.size(table) == 68
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn prevents_referenced_eviction_until_release_test() -> Nil {
  let assert Ok(table) = dynamic_table.new(68)
  let assert Ok(table) = dynamic_table.set_capacity(table, 68)
  let assert Ok(#(table, 0)) =
    dynamic_table.insert(table, dynamic_table.Field(<<"a">>, <<"1">>))
  let assert Ok(table) = dynamic_table.acquire(table, [0])
  assert dynamic_table.insert(
      table,
      dynamic_table.Field(<<"long">>, <<"value">>),
    )
    == Error(dynamic_table.ReferencedEntryCannotBeEvicted(0))
  let assert Ok(table) = dynamic_table.release(table, [0])
  let assert Ok(#(_, 1)) =
    dynamic_table.insert(table, dynamic_table.Field(<<"long">>, <<"value">>))
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reconstructs_wrapped_required_insert_counts_test() -> Nil {
  assert dynamic_table.encode_required_insert_count(0, 128) == Ok(0)
  assert dynamic_table.encode_required_insert_count(5, 128) == Ok(6)
  assert dynamic_table.encode_required_insert_count(8, 128) == Ok(1)
  assert dynamic_table.decode_required_insert_count(1, 128, 8) == Ok(8)
  assert dynamic_table.decode_required_insert_count(6, 128, 8) == Ok(5)
  assert dynamic_table.decode_required_insert_count(9, 128, 8)
    == Error(dynamic_table.RequiredInsertCountFailure)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_impossible_wrapped_required_insert_counts_test() -> Nil {
  assert dynamic_table.decode_required_insert_count(5, 96, 0)
    == Error(dynamic_table.RequiredInsertCountFailure)
  assert dynamic_table.decode_required_insert_count(1, 96, 0)
    == Error(dynamic_table.RequiredInsertCountFailure)
}
