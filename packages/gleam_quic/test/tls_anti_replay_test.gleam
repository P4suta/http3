import gleam/bit_array
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/anti_replay

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_replay_bounds_memory_and_prunes_expired_entries_test() -> Nil {
  let assert Ok(cache) = anti_replay.new(window_milliseconds: 1000, capacity: 2)
  let first = <<1:256>>
  let second = <<2:256>>
  let third = <<3:256>>

  let assert Ok(anti_replay.Accepted(cache)) =
    anti_replay.record_verified(cache, first, 100)
  assert anti_replay.size(cache) == 1
  assert anti_replay.contains(cache, first)

  let assert Ok(anti_replay.Replayed(cache)) =
    anti_replay.record_verified(cache, first, 101)
  assert anti_replay.size(cache) == 1
  let assert Ok(anti_replay.Accepted(cache)) =
    anti_replay.record_verified(cache, second, 102)
  let assert Ok(anti_replay.Saturated(cache)) =
    anti_replay.record_verified(cache, third, 103)
  assert anti_replay.size(cache) == 2

  let assert Ok(anti_replay.Accepted(cache)) =
    anti_replay.record_verified(cache, third, 1201)
  assert anti_replay.size(cache) == 1
  assert !anti_replay.contains(cache, first)
  assert anti_replay.contains(cache, third)
  assert anti_replay.record_verified(cache, first, 1200)
    == Error(anti_replay.ClockMovedBackwards)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn derives_domain_separated_replay_fingerprint_test() -> Nil {
  let identity = <<"ticket">>
  let random = <<0xaa:256>>
  let binder = <<0xbb:256>>
  let assert Ok(first) =
    anti_replay.fingerprint(crypto.Sha256, identity, random, binder)
  let assert Ok(second) =
    anti_replay.fingerprint(crypto.Sha256, identity, random, binder)
  let assert Ok(changed) =
    anti_replay.fingerprint(crypto.Sha256, identity, <<0xab:256>>, binder)
  assert first == second
  assert first != changed
  assert bit_array.byte_size(first) == 32
  assert anti_replay.fingerprint(crypto.Sha256, identity, random, <<0xbb:248>>)
    == Error(anti_replay.InvalidBinder)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_invalid_cache_and_fingerprint_inputs_test() -> Nil {
  assert anti_replay.new(window_milliseconds: 0, capacity: 2)
    == Error(anti_replay.InvalidConfiguration)
  assert anti_replay.new(window_milliseconds: 1000, capacity: 0)
    == Error(anti_replay.InvalidConfiguration)
  let assert Ok(cache) = anti_replay.new(1000, 2)
  assert anti_replay.record_verified(cache, <<1:248>>, 0)
    == Error(anti_replay.InvalidFingerprint)
  assert anti_replay.record_verified(cache, <<1:256>>, -1)
    == Error(anti_replay.InvalidTimestamp)
}
