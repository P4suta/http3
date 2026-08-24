import gleam/option.{None, Some}
import gleam_quic/internal/connection_id

fn token(byte: Int) -> BitArray {
  <<
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
    byte,
  >>
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retires_prior_ids_and_selects_a_live_connection_id_test() -> Nil {
  let assert Ok(registry) = connection_id.new(3, <<0>>, token(0))
  let assert Ok(connection_id.Update(registry, [])) =
    connection_id.receive(registry, 1, 0, <<1>>, token(1))
  let assert Ok(connection_id.Update(registry, [])) =
    connection_id.receive(registry, 2, 0, <<2>>, token(2))
  assert connection_id.active_count(registry) == 3
  assert connection_id.receive(registry, 3, 0, <<3>>, token(3))
    == Error(connection_id.ActiveLimitExceeded(3))

  let assert Ok(connection_id.Update(registry, retired)) =
    connection_id.receive(registry, 3, 2, <<3>>, token(3))
  assert retired == [0, 1]
  assert connection_id.active_count(registry) == 2
  assert connection_id.current(registry)
    == Ok(connection_id.ConnectionId(2, <<2>>, Some(token(2))))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn rejects_connection_id_sequence_aliases_and_invalid_retirement_test() -> Nil {
  let assert Ok(registry) = connection_id.new(2, <<0>>, token(0))
  let assert Ok(connection_id.Update(registry, [])) =
    connection_id.receive(registry, 1, 0, <<1>>, token(1))
  assert connection_id.receive(registry, 1, 0, <<9>>, token(1))
    == Error(connection_id.SequenceConflict(1))
  assert connection_id.receive(registry, 2, 0, <<1>>, token(2))
    == Error(connection_id.ConnectionIdReused)
  assert connection_id.receive(registry, 2, 3, <<2>>, token(2))
    == Error(connection_id.InvalidRetirePriorTo)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn never_revives_ids_below_largest_retire_prior_to_test() -> Nil {
  let assert Ok(registry) = connection_id.new(3, <<0>>, token(0))
  let assert Ok(connection_id.Update(registry, retired)) =
    connection_id.receive(registry, 5, 5, <<5>>, token(5))
  assert retired == [0]

  // This valid but reordered frame was already covered by retire_prior_to=5.
  let assert Ok(connection_id.Update(registry, retired)) =
    connection_id.receive(registry, 3, 0, <<3>>, token(3))
  assert retired == [3]
  assert connection_id.active_count(registry) == 1
  assert connection_id.current(registry)
    == Ok(connection_id.ConnectionId(5, <<5>>, Some(token(5))))

  // Reusing a retired value or sequence remains a connection error.
  assert connection_id.receive(registry, 6, 0, <<3>>, token(6))
    == Error(connection_id.ConnectionIdReused)
  assert connection_id.receive(registry, 3, 0, <<9>>, token(3))
    == Error(connection_id.SequenceConflict(3))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn initial_connection_id_can_gain_an_authenticated_reset_token_test() -> Nil {
  let assert Ok(registry) = connection_id.new_without_reset_token(4, <<0>>)
  assert connection_id.current(registry)
    == Ok(connection_id.ConnectionId(0, <<0>>, None))

  let assert Ok(registry) =
    connection_id.set_initial_reset_token(registry, token(9))
  assert connection_id.current(registry)
    == Ok(connection_id.ConnectionId(0, <<0>>, Some(token(9))))
  assert connection_id.matches_stateless_reset(registry, <<
      1,
      2,
      3,
      4,
      5,
      token(9):bits,
    >>)
    == Ok(True)
}
