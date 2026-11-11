//// RFC 9842 fields use RFC 9651 Item/Inner List parameters and map semantics.
//// Assertions project dictionary, identifier, and hash values to fixed Booleans.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import http/compression
import http/structured_fields as sf

pub fn omitted_optional_members_have_the_registered_defaults_test() -> Nil {
  assert directive_is("match=\"/*\"", defaults())
}

pub fn known_members_keep_their_required_bare_item_types_test() -> Nil {
  assert all_directives_invalid([
    "match=token",
    "match=(\"/*\")",
    "match=\"/*\", id=token",
    "match=\"/*\", type=\"raw\"",
    "match=\"/*\", match-dest=\"script\"",
    "match=\"/*\", match-dest=(script)",
    "match=\"/*\", match-dest=(%\"script\")",
  ])
}

pub fn duplicate_members_use_the_last_parsed_value_test() -> Nil {
  assert directive_is(
    "match=\"/old\", id=\"old\", type=future, match-dest=(\"image\"), match=\"/*\", id=\"new\", type=raw, match-dest=(\"script\")",
    compression.UseAsDictionary(..defaults(), identifier: "new", destinations: [
      "script",
    ]),
  )
  assert directive_is("match=7, match=\"/*\"", defaults())
  assert all_directives_invalid(["match=\"/*\", match=7"])
}

pub fn an_invalid_earlier_duplicate_still_invalidates_the_whole_field_test() -> Nil {
  assert all_directives_invalid([
    "match=\"bad\\q\", match=\"/*\"",
    "match=\"/*\", future=:!:",
    "match=\"/*\", future=\"bad\\q\"",
    "match=\"/*\",",
  ])
}

pub fn unknown_members_preserve_their_values_parameters_and_order_test() -> Nil {
  let expected =
    compression.UseAsDictionary(..defaults(), extensions: [
      sf.DictionaryMember(
        "future",
        sf.ListItem(sf.Item(sf.Date(17), [sf.Parameter("p", sf.Boolean(True))])),
      ),
      sf.DictionaryMember(
        "another",
        sf.InnerList([sf.Item(sf.DisplayString("opaque"), [])], [
          sf.Parameter("q", sf.Integer(2)),
        ]),
      ),
    ])
  assert directive_is(
    "future=@17;p, match=\"/*\", another=(%\"opaque\");q=2",
    expected,
  )
  assert directive_round_trips(expected)
}

pub fn match_item_parameters_do_not_invalidate_the_directive_test() -> Nil {
  assert directive_is("match=\"/*\";future=7;future=8", defaults())
}

pub fn identifier_item_parameters_do_not_change_the_identifier_test() -> Nil {
  assert directive_is(
    "match=\"/*\", id=\"Opaque\";future=?1",
    compression.UseAsDictionary(..defaults(), identifier: "Opaque"),
  )
}

pub fn dictionary_type_parameters_do_not_change_the_raw_type_test() -> Nil {
  assert directive_is("match=\"/*\", type=raw;future=@17", defaults())
}

pub fn destination_inner_list_parameters_do_not_change_the_list_test() -> Nil {
  assert directive_is(
    "match=\"/*\", match-dest=(\"script\");future=%\"value\"",
    compression.UseAsDictionary(..defaults(), destinations: ["script"]),
  )
}

pub fn destination_item_parameters_do_not_change_the_destination_test() -> Nil {
  assert directive_is(
    "match=\"/*\", match-dest=(\"script\";future=:AQ==: \"image\";p)",
    compression.UseAsDictionary(..defaults(), destinations: ["script", "image"]),
  )
}

pub fn repeated_destinations_are_valid_inner_list_members_test() -> Nil {
  let expected =
    compression.UseAsDictionary(..defaults(), destinations: [
      "script", "script", "",
    ])
  assert directive_is(
    "match=\"/*\", match-dest=(\"script\" \"script\" \"\")",
    expected,
  )
  assert directive_round_trips(expected)
}

pub fn ignored_parameters_are_still_fully_parsed_test() -> Nil {
  assert all_directives_invalid([
    "match=\"/*\";p=\"bad\\q\"",
    "match=\"/*\", id=\"x\";p=:!:",
    "match=\"/*\", type=raw;p=",
    "match=\"/*\", match-dest=(\"script\";p=)",
    "match=\"/*\", match-dest=();p=\"bad\\q\"",
  ])
  assert result.is_error(compression.parse_dictionary_id("\"x\";p=:!:"))
  assert result.is_error(compression.parse_available_dictionary(
    hash_wire() <> ";p=",
  ))
}

pub fn supported_parameter_count_and_the_next_member_are_bounded_test() -> Nil {
  let parameters = parameter_names(256, []) |> string.concat
  assert directive_is("match=\"/*\"" <> parameters, defaults())
  assert all_directives_invalid(["match=\"/*\"" <> parameters <> ";extra"])
}

pub fn available_dictionary_parameters_do_not_change_the_hash_test() -> Nil {
  assert available_is(hash_wire() <> ";future=?0", hash())
}

pub fn available_dictionary_requires_exactly_32_aligned_bytes_test() -> Nil {
  assert available_is(hash_wire(), hash())
  assert all_available_invalid([":AQ==:", ":AQI=:", ":!:", "\"hash\"", "hash"])
  assert result.is_error(compression.serialize_available_dictionary(bytes(31)))
  assert result.is_ok(compression.serialize_available_dictionary(bytes(32)))
  assert result.is_error(compression.serialize_available_dictionary(bytes(33)))
  assert available_bytes_rejected(bytes(31))
  assert available_bytes_rejected(bytes(33))
  assert result.is_error(
    compression.serialize_available_dictionary(<<0:size(255)>>),
  )
  assert result.is_error(
    compression.serialize_available_dictionary(<<0:size(257)>>),
  )
  assert available_round_trips(hash())
}

pub fn multiple_available_dictionary_items_are_not_a_single_advertisement_test() -> Nil {
  assert all_available_invalid([
    hash_wire() <> ", " <> hash_wire(),
    "(" <> hash_wire() <> ")",
    hash_wire() <> ",",
  ])
}

pub fn dictionary_id_parameters_do_not_change_the_opaque_value_test() -> Nil {
  assert identifier_is("\"Opaque\";future=token;future=7", "Opaque")
}

pub fn opaque_identifier_escaping_and_empty_value_round_trip_test() -> Nil {
  assert identifier_round_trips(" Mixed \\\" value ")
  assert identifier_round_trips("")
  assert identifier_is("\"a\\\"b\\\\c\"", "a\"b\\c")
  assert directive_round_trips(
    compression.UseAsDictionary(..defaults(), identifier: " Mixed \\\" value "),
  )
}

pub fn identifier_limit_counts_decoded_ascii_not_wire_escapes_test() -> Nil {
  let identifier = string.repeat("\"\\", 512)
  assert string.byte_size(identifier) == 1024
  assert identifier_round_trips(identifier)
  assert directive_round_trips(
    compression.UseAsDictionary(..defaults(), identifier: identifier),
  )
  let too_long = identifier <> "x"
  assert result.is_error(compression.serialize_dictionary_id(too_long))
  assert result.is_error(compression.serialize_use_as_dictionary(
    compression.UseAsDictionary(..defaults(), identifier: too_long),
  ))
  assert identifier_wire_rejected(too_long)
  assert directive_identifier_wire_rejected(too_long)
}

pub fn identifier_is_a_single_ascii_string_item_test() -> Nil {
  assert all_identifiers_invalid([
    "token",
    "%\"display\"",
    "\"one\", \"two\"",
    "(\"one\")",
    "\"bad\\q\"",
    "\"non-ascii-\u{00e9}\"",
    "\"bad\nline\"",
  ])
  assert result.is_error(compression.serialize_dictionary_id("\u{00e9}"))
  assert result.is_error(compression.serialize_dictionary_id("bad\nline"))
}

pub fn serialization_cannot_override_known_members_through_extensions_test() -> Nil {
  let known =
    sf.DictionaryMember(
      "match",
      sf.ListItem(sf.Item(sf.StringValue("/other"), [])),
    )
  let unknown =
    sf.DictionaryMember("future", sf.ListItem(sf.Item(sf.Boolean(True), [])))
  assert result.is_error(compression.serialize_use_as_dictionary(
    compression.UseAsDictionary(..defaults(), extensions: [known]),
  ))
  assert result.is_error(compression.serialize_use_as_dictionary(
    compression.UseAsDictionary(..defaults(), extensions: [unknown, unknown]),
  ))
}

fn defaults() -> compression.UseAsDictionary {
  compression.UseAsDictionary("/*", [], "", compression.Raw, [])
}

fn parameter_names(remaining: Int, reversed: List(String)) -> List(String) {
  case remaining {
    0 -> reversed
    _ ->
      parameter_names(remaining - 1, [
        ";p" <> int.to_string(remaining),
        ..reversed
      ])
  }
}

fn directive_is(input: String, expected: compression.UseAsDictionary) -> Bool {
  compression.parse_use_as_dictionary(input) == Ok(expected)
}

fn directive_round_trips(value: compression.UseAsDictionary) -> Bool {
  let observed =
    compression.serialize_use_as_dictionary(value)
    |> result.map(fn(wire) { directive_is(wire, value) })
  observed == Ok(True)
}

fn all_directives_invalid(inputs: List(String)) -> Bool {
  list.all(inputs, fn(input) {
    compression.parse_use_as_dictionary(input)
    == Error(compression.InvalidDictionary)
  })
}

fn hash() -> BitArray {
  <<0:size(256)>>
}

fn hash_wire() -> String {
  ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:"
}

fn bytes(count: Int) -> BitArray {
  bit_array.from_string(string.repeat("x", count))
}

fn available_is(input: String, expected: BitArray) -> Bool {
  compression.parse_available_dictionary(input) == Ok(expected)
}

fn available_round_trips(value: BitArray) -> Bool {
  let observed =
    compression.serialize_available_dictionary(value)
    |> result.map(fn(wire) { available_is(wire, value) })
  observed == Ok(True)
}

fn available_bytes_rejected(value: BitArray) -> Bool {
  let observed =
    sf.serialize_item(sf.Item(sf.ByteSequence(value), []))
    |> result.map(fn(wire) {
      compression.parse_available_dictionary(wire)
      == Error(compression.InvalidDictionary)
    })
  observed == Ok(True)
}

fn all_available_invalid(inputs: List(String)) -> Bool {
  list.all(inputs, fn(input) {
    compression.parse_available_dictionary(input)
    == Error(compression.InvalidDictionary)
  })
}

fn identifier_is(input: String, expected: String) -> Bool {
  compression.parse_dictionary_id(input) == Ok(expected)
}

fn identifier_round_trips(value: String) -> Bool {
  let observed =
    compression.serialize_dictionary_id(value)
    |> result.map(fn(wire) { identifier_is(wire, value) })
  observed == Ok(True)
}

fn all_identifiers_invalid(inputs: List(String)) -> Bool {
  list.all(inputs, fn(input) {
    compression.parse_dictionary_id(input)
    == Error(compression.InvalidDictionary)
  })
}

fn identifier_wire_rejected(value: String) -> Bool {
  let observed =
    sf.serialize_item(sf.Item(sf.StringValue(value), []))
    |> result.map(fn(wire) {
      result.is_error(compression.parse_dictionary_id(wire))
    })
  observed == Ok(True)
}

fn directive_identifier_wire_rejected(value: String) -> Bool {
  let observed =
    sf.serialize_item(sf.Item(sf.StringValue(value), []))
    |> result.map(fn(wire) {
      result.is_error(compression.parse_use_as_dictionary(
        "match=\"/*\", id=" <> wire,
      ))
    })
  observed == Ok(True)
}
