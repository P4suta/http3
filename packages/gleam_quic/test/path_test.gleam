import gleam_quic/internal/amplification
import gleam_quic/internal/path_validation
import gleam_quic/internal/pmtu

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn limits_unvalidated_server_to_three_times_received_bytes_test() -> Nil {
  let assert Ok(server) = amplification.new(amplification.Server)
  assert !amplification.can_send(server, 1)
  let assert Ok(server) = amplification.record_received(server, 1200)
  assert amplification.can_send(server, 3600)
  let assert Ok(server) = amplification.record_sent(server, 3600)
  assert !amplification.can_send(server, 1)
  let server = amplification.validate(server)
  assert amplification.can_send(server, 65_527)

  let assert Ok(client) = amplification.new(amplification.Client)
  assert amplification.can_send(client, 65_527)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn validates_path_challenge_and_times_out_fixed_deadline_test() -> Nil {
  let validator = path_validation.new()
  let assert Ok(validator) =
    path_validation.start(validator, <<1, 2, 3, 4, 5, 6, 7, 8>>, 100, 50)
  assert path_validation.phase(validator) == path_validation.Validating
  assert path_validation.receive_response(validator, <<0:64>>, 120)
    == Error(path_validation.ChallengeMismatch)
  let assert Ok(validator) =
    path_validation.receive_response(validator, <<1, 2, 3, 4, 5, 6, 7, 8>>, 149)
  assert path_validation.phase(validator) == path_validation.Validated

  let assert Ok(validator) =
    path_validation.start(path_validation.new(), <<9:64>>, 0, 10)
  let validator = path_validation.on_timeout(validator, 10)
  assert path_validation.phase(validator) == path_validation.Failed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn raises_pmtu_on_ack_and_recovers_from_black_hole_test() -> Nil {
  let assert Ok(state) = pmtu.new(1500)
  assert pmtu.current(state) == 1200
  let assert Ok(#(state, 1350)) = pmtu.start_probe(state)
  let assert Ok(state) = pmtu.probe_acked(state, 1350)
  assert pmtu.current(state) == 1350
  let assert Ok(#(state, 1425)) = pmtu.start_probe(state)
  let assert Ok(state) = pmtu.probe_lost(state, 1425, True)
  let assert Ok(#(_state, next)) = pmtu.start_probe(state)
  assert next > 1350
  assert next < 1425
  assert pmtu.current(pmtu.black_hole_detected(state)) == 1200
}
