import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit
import http/structured_fields

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn dictionary_round_trips_all_rfc9651_bare_item_kinds_test() -> Nil {
  let input =
    "flag;level=2, values=(42 -1.25 \"text\" token :AQI=: ?0 @1700000000 %\"%c3%bcr\");x"
  let assert Ok(parsed) = structured_fields.parse_dictionary(input)
  let assert [
    structured_fields.DictionaryMember(
      "flag",
      structured_fields.ListItem(structured_fields.Item(
        structured_fields.Boolean(True),
        [structured_fields.Parameter("level", structured_fields.Integer(2))],
      )),
    ),
    structured_fields.DictionaryMember(
      "values",
      structured_fields.InnerList(
        [
          structured_fields.Item(structured_fields.Integer(42), []),
          structured_fields.Item(structured_fields.Decimal(-1250), []),
          structured_fields.Item(structured_fields.StringValue("text"), []),
          structured_fields.Item(structured_fields.Token("token"), []),
          structured_fields.Item(structured_fields.ByteSequence(<<1, 2>>), []),
          structured_fields.Item(structured_fields.Boolean(False), []),
          structured_fields.Item(structured_fields.Date(1_700_000_000), []),
          structured_fields.Item(structured_fields.DisplayString("ür"), []),
        ],
        [structured_fields.Parameter("x", structured_fields.Boolean(True))],
      ),
    ),
  ] = parsed
  let assert Ok(serialized) = structured_fields.serialize_dictionary(parsed)

  assert serialized == input
  assert structured_fields.parse_dictionary(serialized) == Ok(parsed)
}

pub fn duplicate_dictionary_and_parameter_keys_use_the_last_value_test() -> Nil {
  let assert Ok(parsed) =
    structured_fields.parse_dictionary("a=1;a=2, b, a=3;z=1;z=2")

  assert parsed
    == [
      structured_fields.DictionaryMember(
        "a",
        structured_fields.ListItem(
          structured_fields.Item(structured_fields.Integer(3), [
            structured_fields.Parameter("z", structured_fields.Integer(2)),
          ]),
        ),
      ),
      structured_fields.DictionaryMember(
        "b",
        structured_fields.ListItem(
          structured_fields.Item(structured_fields.Boolean(True), []),
        ),
      ),
    ]
}

pub fn structured_fields_are_strict_and_bounded_test() -> Nil {
  assert structured_fields.parse_dictionary("Upper=1")
    == Error(structured_fields.Invalid)
  assert structured_fields.parse_list(":not base64!:")
    == Error(structured_fields.Invalid)
  assert structured_fields.parse_item("\"bad\\q\"")
    == Error(structured_fields.Invalid)
  assert structured_fields.parse_item("token; x=1")
    == Ok(
      structured_fields.Item(structured_fields.Token("token"), [
        structured_fields.Parameter("x", structured_fields.Integer(1)),
      ]),
    )
  let limits =
    structured_fields.Limits(
      maximum_bytes: 8,
      maximum_members: 2,
      maximum_parameters: 2,
    )
  assert structured_fields.parse_list_with_limits("1, 2, 3", limits)
    == Error(structured_fields.LimitExceeded)
  assert structured_fields.parse_item_with_limits("\"123456789\"", limits)
    == Error(structured_fields.LimitExceeded)
}

pub fn rfc4648_base64_is_padded_unfolded_and_canonical_test() -> Nil {
  let one = structured_fields.Item(structured_fields.ByteSequence(<<255>>), [])
  let two =
    structured_fields.Item(structured_fields.ByteSequence(<<255, 255>>), [])
  assert structured_fields.serialize_item(one) == Ok(":/w==:")
  assert structured_fields.serialize_item(two) == Ok("://8=:")

  // These values have non-zero unused pad bits and would otherwise decode
  // to the same bytes as the canonical forms above.
  [":/x==:", ":/y==:", ":/z==:", "://9=:", "://+=:", ":///=:"]
  |> list.each(fn(value) {
    assert structured_fields.parse_item(value)
      == Error(structured_fields.Invalid)
  })
}

pub fn rfc4648_base64_rejects_missing_excess_embedded_and_folded_padding_test() -> Nil {
  [
    ":AQI:",
    ":AQI===:",
    ":A=QI:",
    ":AQ=I:",
    ":AQI=\r\n:",
    ":AQ I=:",
    ":AQI-_:",
  ]
  |> list.each(fn(value) {
    assert structured_fields.parse_item(value)
      == Error(structured_fields.Invalid)
  })
}

pub fn rfc9651_ordered_maps_are_accessible_by_index_and_key_test() -> Nil {
  let first = structured_fields.Parameter("first", structured_fields.Integer(1))
  let second =
    structured_fields.Parameter("second", structured_fields.StringValue("x"))
  let parameters = [first, second]
  assert structured_fields.parameter_at(parameters, 0) == Some(first)
  assert structured_fields.parameter_at(parameters, 1) == Some(second)
  assert structured_fields.parameter_at(parameters, -1) == None
  assert structured_fields.parameter_at(parameters, 2) == None
  assert structured_fields.parameter_by_key(parameters, "second")
    == Some(second)
  assert structured_fields.parameter_by_key(parameters, "missing") == None

  let first_member =
    structured_fields.DictionaryMember(
      "first",
      structured_fields.ListItem(
        structured_fields.Item(structured_fields.Boolean(True), []),
      ),
    )
  let second_member =
    structured_fields.DictionaryMember(
      "second",
      structured_fields.ListItem(
        structured_fields.Item(structured_fields.Integer(2), []),
      ),
    )
  let dictionary = [first_member, second_member]
  assert structured_fields.dictionary_member_at(dictionary, 0)
    == Some(first_member)
  assert structured_fields.dictionary_member_at(dictionary, 1)
    == Some(second_member)
  assert structured_fields.dictionary_member_at(dictionary, -1) == None
  assert structured_fields.dictionary_member_at(dictionary, 2) == None
  assert structured_fields.dictionary_member_by_key(dictionary, "first")
    == Some(first_member)
  assert structured_fields.dictionary_member_by_key(dictionary, "missing")
    == None
}

pub fn rfc9651_unknown_members_and_true_shorthand_are_safe_test() -> Nil {
  let assert Ok(dictionary) =
    structured_fields.parse_dictionary("known=1, future=2")
  let assert Some(structured_fields.DictionaryMember(
    "known",
    structured_fields.ListItem(structured_fields.Item(
      structured_fields.Integer(1),
      [],
    )),
  )) = structured_fields.dictionary_member_by_key(dictionary, "known")

  let item =
    structured_fields.Item(structured_fields.Integer(1), [
      structured_fields.Parameter("a", structured_fields.Boolean(True)),
      structured_fields.Parameter("b", structured_fields.Boolean(False)),
    ])
  assert structured_fields.serialize_item(item) == Ok("1;a;b=?0")

  let true_member =
    structured_fields.DictionaryMember(
      "enabled",
      structured_fields.ListItem(
        structured_fields.Item(structured_fields.Boolean(True), []),
      ),
    )
  assert structured_fields.serialize_dictionary([true_member]) == Ok("enabled")
}

pub fn rfc9651_field_lines_are_combined_once_under_finite_limits_test() -> Nil {
  assert structured_fields.parse_list_field_lines(["a, b", "c"])
    == structured_fields.parse_list("a, b, c")
  assert structured_fields.parse_dictionary_field_lines(["a=1", "b=2"])
    == structured_fields.parse_dictionary("a=1, b=2")
  assert structured_fields.parse_item_field_lines(["token"])
    == structured_fields.parse_item("token")
  assert structured_fields.parse_item_field_lines(["token", "second"])
    == Error(structured_fields.Invalid)

  let limits = structured_fields.Limits(8, 8, 8)
  assert structured_fields.parse_list_field_lines_with_limits(
      ["a", "bbbbbb"],
      limits,
    )
    == Error(structured_fields.LimitExceeded)
  assert structured_fields.parse_dictionary_field_lines_with_limits(
      ["a=1", "b=2"],
      limits,
    )
    == structured_fields.parse_dictionary("a=1, b=2")
  assert structured_fields.parse_dictionary_field_lines_with_limits(
      ["a=1", "bb=2"],
      limits,
    )
    == Error(structured_fields.LimitExceeded)
}

pub fn rfc9651_required_minimum_capacities_are_supported_test() -> Nil {
  let list_value = list.repeat("1", times: 1024) |> string.join(with: ", ")
  let assert Ok(list_members) = structured_fields.parse_list(list_value)
  assert list.length(list_members) == 1024

  let inner_value =
    "(" <> { list.repeat("1", times: 256) |> string.join(with: " ") } <> ")"
  let assert Ok([structured_fields.InnerList(inner_items, [])]) =
    structured_fields.parse_list(inner_value)
  assert list.length(inner_items) == 256

  let parameters = numbered_parameters(256, []) |> string.join(with: "")
  let assert Ok(structured_fields.Item(_, parsed_parameters)) =
    structured_fields.parse_item("1" <> parameters)
  assert list.length(parsed_parameters) == 256

  let long_key = string.repeat("k", times: 64)
  let assert Ok(structured_fields.Item(_, [structured_fields.Parameter(key, _)])) =
    structured_fields.parse_item("1;" <> long_key)
  assert key == long_key
  let assert Ok([structured_fields.DictionaryMember(key, _)]) =
    structured_fields.parse_dictionary(long_key <> "=1")
  assert key == long_key

  let dictionary_value =
    numbered_dictionary_members(1024, []) |> string.join(with: ", ")
  let assert Ok(dictionary) =
    structured_fields.parse_dictionary(dictionary_value)
  assert list.length(dictionary) == 1024

  let long_string = string.repeat("s", times: 1024)
  assert structured_fields.parse_item("\"" <> long_string <> "\"")
    == Ok(
      structured_fields.Item(structured_fields.StringValue(long_string), []),
    )
  let long_token = string.repeat("t", times: 512)
  assert structured_fields.parse_item(long_token)
    == Ok(structured_fields.Item(structured_fields.Token(long_token), []))

  let octets =
    string.repeat("x", times: 16_384)
    |> bit_array.from_string
  let item = structured_fields.Item(structured_fields.ByteSequence(octets), [])
  let assert Ok(encoded) = structured_fields.serialize_item(item)
  assert structured_fields.parse_item(encoded) == Ok(item)

  assert structured_fields.parse_item("@-62135596800")
    == Ok(structured_fields.Item(structured_fields.Date(-62_135_596_800), []))
  assert structured_fields.parse_item("@253402214400")
    == Ok(structured_fields.Item(structured_fields.Date(253_402_214_400), []))
}

fn numbered_parameters(remaining: Int, reversed: List(String)) -> List(String) {
  case remaining {
    0 -> list.reverse(reversed)
    _ ->
      numbered_parameters(remaining - 1, [
        ";p" <> int.to_string(remaining) <> "=1",
        ..reversed
      ])
  }
}

fn numbered_dictionary_members(
  remaining: Int,
  reversed: List(String),
) -> List(String) {
  case remaining {
    0 -> list.reverse(reversed)
    _ ->
      numbered_dictionary_members(remaining - 1, [
        "k" <> int.to_string(remaining) <> "=1",
        ..reversed
      ])
  }
}
