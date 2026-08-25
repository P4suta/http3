import gleam/erlang/process
import gleam_quic/internal/tls/replay_guard
import gleeunit/should

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn deadline_is_finite_test() -> Nil {
  let check = fn(_fingerprint, _valid_for) { Ok(True) }
  assert replay_guard.new(0, check) == Error(replay_guard.InvalidTimeout)
  assert replay_guard.new(10_001, check) == Error(replay_guard.InvalidTimeout)
  let _guard = replay_guard.new(1, check) |> should.be_ok
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn only_an_explicit_success_permits_early_data_test() -> Nil {
  let accepting =
    replay_guard.new(100, fn(fingerprint, valid_for) {
      assert fingerprint == <<0x42:256>>
      assert valid_for == 5000
      Ok(True)
    })
    |> should.be_ok
  let rejecting = replay_guard.new(100, fn(_, _) { Ok(False) }) |> should.be_ok
  let failing = replay_guard.new(100, fn(_, _) { Error(Nil) }) |> should.be_ok

  assert replay_guard.permits(accepting, <<0x42:256>>, 5000)
  assert !replay_guard.permits(rejecting, <<0x42:256>>, 5000)
  assert !replay_guard.permits(failing, <<0x42:256>>, 5000)
  assert !replay_guard.permits(accepting, <<0x42:256>>, 0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn callback_timeout_fails_closed_test() -> Nil {
  let guard =
    replay_guard.new(5, fn(_, _) {
      process.sleep(50)
      Ok(True)
    })
    |> should.be_ok
  assert !replay_guard.permits(guard, <<0x42:256>>, 5000)
}
