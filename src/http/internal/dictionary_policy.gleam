//// Dictionary selection validation for an explicit server policy.
//// This module is not automatically invoked by the common server dispatcher.

import gleam/option.{Some}
import gleam/result
import http/compression

/// Validate the selected bytes before invoking a dictionary encoder.
/// `fields` contains every Available-Dictionary field line in wire order.
/// An opaque ID is only a lookup hint; neither it nor the record's cached hash proves content.
///
/// This record-based policy admits only Raw, fresh records with signed 64-bit times.
/// Fresh-only is a conservative local policy, not a claim that the RFC forbids a client from advertising a resource it may legitimately serve stale.
/// Origin, authenticated transport, coding negotiation, readability and cache policy remain the caller's responsibility.
/// No Body ownership is transferred.
pub fn encode(
  coding coding: compression.Coding,
  input input: BitArray,
  dictionary dictionary: compression.Dictionary,
  available_dictionary fields: List(String),
  now now: Int,
  limits limits: compression.Limits,
) -> Result(BitArray, compression.Error) {
  use advertised <- result.try(case fields {
    [] -> Error(compression.DictionaryRequired)
    [value] -> compression.parse_available_dictionary(value)
    _ -> Error(compression.InvalidDictionary)
  })
  use _ <- result.try(case coding, dictionary.dictionary_type {
    compression.DictionaryBrotli, compression.Raw
    | compression.DictionaryZstandard, compression.Raw
    -> Ok(Nil)
    _, _ -> Error(compression.UnsupportedAlgorithm)
  })
  use _ <- result.try(validate_time(dictionary:, now:))
  use actual <- result.try(compression.dictionary_hash(
    dictionary.content,
    limits,
  ))
  use _ <- result.try(case actual == advertised && actual == dictionary.hash {
    True -> Ok(Nil)
    False -> Error(compression.DictionaryMismatch)
  })
  compression.encode(
    coding:,
    input:,
    dictionary: Some(dictionary.content),
    limits:,
  )
}

fn validate_time(
  dictionary dictionary: compression.Dictionary,
  now now: Int,
) -> Result(Nil, compression.Error) {
  use _ <- result.try(
    case
      now >= -9_223_372_036_854_775_808
      && now <= 9_223_372_036_854_775_807
      && dictionary.fetched_at >= -9_223_372_036_854_775_808
      && dictionary.fresh_until <= 9_223_372_036_854_775_807
      && dictionary.fetched_at < dictionary.fresh_until
    {
      False -> Error(compression.InvalidDictionary)
      True -> Ok(Nil)
    },
  )
  case dictionary.fetched_at <= now && now < dictionary.fresh_until {
    True -> Ok(Nil)
    False -> Error(compression.NoMatchingDictionary)
  }
}
