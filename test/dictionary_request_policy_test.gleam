//// A new internal contract, not a claim that raw codec encode was defective.
//// Assertions expose only fixed classifications or Boolean equality.

import gleam/bit_array
import gleam/list
import gleam/option.{Some}
import gleam/result
import http/compression
import http/internal/dictionary_policy

pub fn both_dictionary_codings_round_trip_after_matching_advertisement_test() -> Nil {
  let selected = dictionary()
  assert list.all(
    [compression.DictionaryBrotli, compression.DictionaryZstandard],
    fn(coding) {
      apply(selected:, fields: fields(selected), now: 150, coding:)
      |> result.map(fn(encoded) {
        compression.decode(
          coding:,
          input: encoded,
          dictionary: Some(selected.content),
          limits: compression.defaults(),
        )
        == Ok(payload())
      })
      |> result.unwrap(False)
    },
  )
}

pub fn opaque_identifier_is_not_content_authority_test() -> Nil {
  let selected = dictionary()
  let renamed = compression.Dictionary(..selected, identifier: "unrelated-hint")
  assert result.is_ok(apply(
    selected: renamed,
    fields: fields(selected),
    now: 150,
    coding: compression.DictionaryBrotli,
  ))
}

pub fn wrong_advertised_hash_is_refused_before_encoding_test() -> Nil {
  let selected = dictionary()
  assert classify(apply(
      selected:,
      fields: fields(other()),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.DictionaryMismatch)
}

pub fn stale_identifier_lookup_cannot_substitute_different_content_test() -> Nil {
  let old = dictionary()
  let replacement = other()
  assert old.identifier == replacement.identifier
  assert classify(apply(
      selected: replacement,
      fields: fields(old),
      now: 150,
      coding: compression.DictionaryZstandard,
    ))
    == Error(compression.DictionaryMismatch)
}

pub fn cached_record_hash_is_recomputed_from_actual_bytes_test() -> Nil {
  let selected = dictionary()
  let forged = compression.Dictionary(..selected, content: other().content)
  assert classify(apply(
      selected: forged,
      fields: fields(selected),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.DictionaryMismatch)
  let forged = compression.Dictionary(..selected, hash: other().hash)
  assert classify(apply(
      selected: forged,
      fields: fields(selected),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.DictionaryMismatch)
}

pub fn missing_advertisement_is_typed_test() -> Nil {
  assert classify(apply(
      selected: dictionary(),
      fields: [],
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.DictionaryRequired)
}

pub fn multiple_field_lines_are_refused_even_when_identical_test() -> Nil {
  let selected = dictionary()
  let assert [value] = fields(selected)
  assert classify(apply(
      selected:,
      fields: [value, value],
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.InvalidDictionary)
}

pub fn a_single_line_cannot_advertise_a_list_of_hashes_test() -> Nil {
  let selected = dictionary()
  let assert [value] = fields(selected)
  assert classify(apply(
      selected:,
      fields: [value <> ", " <> value],
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.InvalidDictionary)
}

pub fn well_formed_unknown_item_parameters_are_ignored_test() -> Nil {
  let selected = dictionary()
  let assert [value] = fields(selected)
  assert result.is_ok(apply(
    selected:,
    fields: [value <> ";future=7"],
    now: 150,
    coding: compression.DictionaryBrotli,
  ))
}

pub fn malformed_and_wrong_sized_advertisements_are_refused_test() -> Nil {
  assert list.all([":AA==:", "token", ":!:", "", ":AA==:;bad="], fn(value) {
    classify(apply(
      selected: dictionary(),
      fields: [value],
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.InvalidDictionary)
  })
}

pub fn record_freshness_is_a_conservative_local_policy_test() -> Nil {
  let selected = dictionary()
  assert result.is_ok(apply(
    selected:,
    fields: fields(selected),
    now: 199,
    coding: compression.DictionaryBrotli,
  ))
  assert classify(apply(
      selected:,
      fields: fields(selected),
      now: 200,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.NoMatchingDictionary)
  assert classify(apply(
      selected:,
      fields: fields(selected),
      now: 201,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.NoMatchingDictionary)
}

pub fn malformed_or_unavailable_record_times_are_refused_test() -> Nil {
  let selected = dictionary()
  assert list.all(
    [-9_223_372_036_854_775_809, 9_223_372_036_854_775_808],
    fn(now) {
      classify(apply(
        selected:,
        fields: fields(selected),
        now:,
        coding: compression.DictionaryBrotli,
      ))
      == Error(compression.InvalidDictionary)
    },
  )
  assert classify(apply(
      selected:,
      fields: fields(selected),
      now: 99,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.NoMatchingDictionary)
  let invalid =
    compression.Dictionary(..selected, fetched_at: 200, fresh_until: 200)
  assert classify(apply(
      selected: invalid,
      fields: fields(selected),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.InvalidDictionary)
}

pub fn unsupported_record_type_is_never_used_test() -> Nil {
  let selected = dictionary()
  let invalid =
    compression.Dictionary(
      ..selected,
      dictionary_type: compression.ExtensionDictionaryType("future"),
    )
  assert classify(apply(
      selected: invalid,
      fields: fields(selected),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.UnsupportedAlgorithm)
}

pub fn non_dictionary_coding_is_outside_this_policy_test() -> Nil {
  let selected = dictionary()
  assert classify(apply(
      selected:,
      fields: fields(selected),
      now: 150,
      coding: compression.Identity,
    ))
    == Error(compression.UnsupportedAlgorithm)
}

pub fn validation_precedes_input_codec_processing_test() -> Nil {
  let selected = dictionary()
  let rejected =
    dictionary_policy.encode(
      coding: compression.DictionaryBrotli,
      input: <<1:size(1)>>,
      dictionary: selected,
      available_dictionary: fields(other()),
      now: 150,
      limits: compression.defaults(),
    )
  assert classify(rejected) == Error(compression.DictionaryMismatch)
}

pub fn existing_byte_alignment_and_size_guards_remain_test() -> Nil {
  let selected = dictionary()
  let limits =
    compression.Limits(..compression.defaults(), maximum_dictionary_bytes: 1)
  assert classify(dictionary_policy.encode(
      coding: compression.DictionaryBrotli,
      input: payload(),
      dictionary: selected,
      available_dictionary: fields(selected),
      now: 150,
      limits:,
    ))
    == Error(compression.InvalidDictionary)
  let invalid = compression.Dictionary(..selected, content: <<1:size(1)>>)
  assert classify(apply(
      selected: invalid,
      fields: fields(selected),
      now: 150,
      coding: compression.DictionaryBrotli,
    ))
    == Error(compression.NonByteAligned)
}

fn apply(
  selected selected: compression.Dictionary,
  fields fields: List(String),
  now now: Int,
  coding coding: compression.Coding,
) -> Result(BitArray, compression.Error) {
  dictionary_policy.encode(
    coding:,
    input: payload(),
    dictionary: selected,
    available_dictionary: fields,
    now:,
    limits: compression.defaults(),
  )
}

fn classify(
  value: Result(BitArray, compression.Error),
) -> Result(Nil, compression.Error) {
  result.map(value, fn(_) { Nil })
}

fn payload() -> BitArray {
  bit_array.from_string("dictionary policy representation")
}

fn dictionary() -> compression.Dictionary {
  record(bit_array.from_string("bounded original dictionary"))
}

fn other() -> compression.Dictionary {
  record(bit_array.from_string("bounded replacement dictionary"))
}

fn record(content: BitArray) -> compression.Dictionary {
  let assert Ok(hash) =
    compression.dictionary_hash(content, compression.defaults())
  compression.Dictionary(
    compression.IsolationKey("site", "profile"),
    "https://localhost",
    "/*",
    [],
    "same-opaque-id",
    compression.Raw,
    content,
    hash,
    200,
    100,
    2048,
  )
}

fn fields(selected: compression.Dictionary) -> List(String) {
  let assert Ok(value) =
    compression.serialize_available_dictionary(selected.hash)
  [value]
}
