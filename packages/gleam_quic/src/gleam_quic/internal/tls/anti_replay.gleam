//// Bounded, time-windowed replay detection for verified TLS 0-RTT binders.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/crypto

const maximum_window_milliseconds = 86_400_000

const maximum_capacity = 1_000_000

const fingerprint_domain = <<"gleam_quic 0rtt replay v1">>

/// A replay cache whose contents and retention are both explicitly bounded.
pub type Cache {
  Cache(
    window_milliseconds: Int,
    capacity: Int,
    entries: Dict(BitArray, Int),
    latest_timestamp: Option(Int),
  )
}

/// The result of recording a binder that has already passed authentication.
pub type Outcome {
  Accepted(Cache)
  Replayed(Cache)
  Saturated(Cache)
}

/// An invalid cache, clock, fingerprint, or fingerprint hash operation.
pub type Error {
  InvalidConfiguration
  InvalidTimestamp
  ClockMovedBackwards
  NonByteAligned
  InvalidIdentity
  InvalidClientRandom
  InvalidBinder
  InvalidFingerprint
  CryptoFailure(crypto.Error)
}

/// Construct an empty bounded replay cache.
pub fn new(
  window_milliseconds window_milliseconds: Int,
  capacity capacity: Int,
) -> Result(Cache, Error) {
  case
    window_milliseconds > 0
    && window_milliseconds <= maximum_window_milliseconds
    && capacity > 0
    && capacity <= maximum_capacity
  {
    True -> Ok(Cache(window_milliseconds, capacity, dict.new(), None))
    False -> Error(InvalidConfiguration)
  }
}

/// Hash all ClientHello replay coordinates with unambiguous lengths.
pub fn fingerprint(
  algorithm algorithm: crypto.HashAlgorithm,
  ticket_identity ticket_identity: BitArray,
  client_random client_random: BitArray,
  verified_binder verified_binder: BitArray,
) -> Result(BitArray, Error) {
  use #(identity_length, binder_length) <- result.try(
    validate_fingerprint_inputs(
      algorithm,
      ticket_identity,
      client_random,
      verified_binder,
    ),
  )
  let algorithm_identifier = case algorithm {
    crypto.Sha256 -> 1
    crypto.Sha384 -> 2
  }
  case
    crypto.hash(algorithm, <<
      fingerprint_domain:bits,
      algorithm_identifier,
      identity_length:size(16),
      ticket_identity:bits,
      client_random:bits,
      binder_length,
      verified_binder:bits,
    >>)
  {
    Ok(value) -> Ok(value)
    Error(error) -> Error(CryptoFailure(error))
  }
}

/// Record an authenticated fingerprint or reject replay/cache saturation.
///
/// Callers must invoke this only after the selected PSK binder and ticket age
/// have been authenticated. Rejected early data can still continue at 1-RTT.
pub fn record_verified(
  cache cache: Cache,
  fingerprint fingerprint: BitArray,
  now_milliseconds now_milliseconds: Int,
) -> Result(Outcome, Error) {
  use Nil <- result.try(validate_record_inputs(
    cache,
    fingerprint,
    now_milliseconds,
  ))
  let Cache(window, capacity, entries, _) = cache
  let oldest_retained = now_milliseconds - window
  let retained =
    dict.filter(entries, fn(_, recorded_at) { recorded_at >= oldest_retained })
  let current = Cache(window, capacity, retained, Some(now_milliseconds))
  record_in_retained(current, fingerprint, now_milliseconds)
}

/// Return the number of retained replay fingerprints.
pub fn size(cache cache: Cache) -> Int {
  dict.size(cache.entries)
}

/// Return whether a fingerprint is currently retained.
pub fn contains(cache cache: Cache, fingerprint fingerprint: BitArray) -> Bool {
  dict.has_key(cache.entries, fingerprint)
}

fn valid_fingerprint(fingerprint: BitArray) -> Bool {
  byte_aligned(fingerprint)
  && {
    let length = bit_array.byte_size(fingerprint)
    length == 32 || length == 48
  }
}

fn validate_fingerprint_inputs(
  algorithm: crypto.HashAlgorithm,
  ticket_identity: BitArray,
  client_random: BitArray,
  verified_binder: BitArray,
) -> Result(#(Int, Int), Error) {
  case
    byte_aligned(ticket_identity)
    && byte_aligned(client_random)
    && byte_aligned(verified_binder)
  {
    False -> Error(NonByteAligned)
    True -> {
      let identity_length = bit_array.byte_size(ticket_identity)
      let binder_length = bit_array.byte_size(verified_binder)
      case
        identity_length > 0 && identity_length <= 65_535,
        bit_array.byte_size(client_random) == 32,
        binder_length == crypto.hash_length(algorithm)
      {
        False, _, _ -> Error(InvalidIdentity)
        _, False, _ -> Error(InvalidClientRandom)
        _, _, False -> Error(InvalidBinder)
        True, True, True -> Ok(#(identity_length, binder_length))
      }
    }
  }
}

fn validate_record_inputs(
  cache: Cache,
  fingerprint: BitArray,
  now_milliseconds: Int,
) -> Result(Nil, Error) {
  case valid_fingerprint(fingerprint), now_milliseconds >= 0 {
    False, _ -> Error(InvalidFingerprint)
    _, False -> Error(InvalidTimestamp)
    True, True -> {
      let Cache(latest_timestamp: latest, ..) = cache
      case latest {
        Some(previous) if now_milliseconds < previous ->
          Error(ClockMovedBackwards)
        _ -> Ok(Nil)
      }
    }
  }
}

fn record_in_retained(
  cache: Cache,
  fingerprint: BitArray,
  now_milliseconds: Int,
) -> Result(Outcome, Error) {
  let Cache(window, capacity, entries, latest) = cache
  case dict.has_key(entries, fingerprint), dict.size(entries) >= capacity {
    True, _ -> Ok(Replayed(cache))
    False, True -> Ok(Saturated(cache))
    False, False ->
      Ok(
        Accepted(Cache(
          window,
          capacity,
          dict.insert(entries, fingerprint, now_milliseconds),
          latest,
        )),
      )
  }
}

fn byte_aligned(bytes: BitArray) -> Bool {
  bit_array.bit_size(bytes) % 8 == 0
}
