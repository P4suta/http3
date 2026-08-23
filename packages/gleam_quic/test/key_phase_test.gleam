import gleam/list
import gleam_quic/internal/key_phase
import gleam_quic/internal/tls/hello
import gleam_quic/internal/traffic_keys
import gleam_quic/version

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn enforces_confirm_ack_and_three_pto_update_spacing_test() -> Nil {
  let #(write_keys, read_keys) = keys()
  let assert Ok(state) = key_phase.new(write_keys, read_keys)
  assert key_phase.phase(state) == key_phase.PhaseZero
  assert key_phase.initiate(state, 10, 100, 20)
    == Error(key_phase.HandshakeNotConfirmed)

  let state = key_phase.confirm_handshake(state)
  let assert Ok(state) = key_phase.initiate(state, 10, 100, 20)
  assert key_phase.phase(state) == key_phase.PhaseOne
  assert key_phase.initiate(state, 11, 101, 20)
    == Error(key_phase.UpdateNotAcknowledged)

  let state = key_phase.acknowledge(state, 9)
  assert key_phase.initiate(state, 11, 160, 20)
    == Error(key_phase.UpdateNotAcknowledged)
  let state = key_phase.acknowledge(state, 10)
  assert key_phase.initiate(state, 11, 159, 20)
    == Error(key_phase.UpdateTooSoon(160))
  let assert Ok(state) = key_phase.initiate(state, 11, 160, 20)
  assert key_phase.phase(state) == key_phase.PhaseZero
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn distinguishes_reordered_old_packets_from_peer_updates_test() -> Nil {
  let #(write_keys, read_keys) = keys()
  let assert Ok(state) = key_phase.new(write_keys, read_keys)
  let state = key_phase.confirm_handshake(state)
  assert candidate_kinds(key_phase.read_candidates(
      state,
      key_phase.PhaseOne,
      100,
      100,
    ))
    == [key_phase.Next]

  let assert Ok(state) =
    key_phase.commit_peer_update(state, key_phase.PhaseOne, 100, 100, 20)
  let assert Ok(state) = key_phase.record_sent(state, 101)
  let assert Ok(state) = key_phase.record_received(state, 100)
  assert key_phase.phase(state) == key_phase.PhaseOne
  assert candidate_kinds(key_phase.read_candidates(
      state,
      key_phase.PhaseZero,
      99,
      159,
    ))
    == [key_phase.Previous]
  assert candidate_kinds(key_phase.read_candidates(
      state,
      key_phase.PhaseZero,
      101,
      159,
    ))
    == [key_phase.Next]
  assert candidate_kinds(key_phase.read_candidates(
      state,
      key_phase.PhaseZero,
      99,
      160,
    ))
    == []
  assert key_phase.commit_peer_update(state, key_phase.PhaseZero, 101, 159, 20)
    == Error(key_phase.UpdateTooSoon(160))
}

fn keys() -> #(traffic_keys.TrafficKeys, traffic_keys.TrafficKeys) {
  let assert Ok(write_keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<1:256>>)
  let assert Ok(read_keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<2:256>>)
  #(write_keys, read_keys)
}

fn candidate_kinds(
  candidates: List(key_phase.ReadCandidate),
) -> List(key_phase.CandidateKind) {
  list.map(candidates, key_phase.candidate_kind)
}
