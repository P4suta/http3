import gleam/erlang/process
import gleeunit/should
import quic_core/internal/tls/replay_guard

@external(erlang, "quic_core_process_ffi", "spawn_monitor")
fn spawn_monitor(run: fn() -> Nil) -> #(process.Pid, process.Monitor)

@external(erlang, "quic_process_monitor_test_ffi", "atomic_monitor_contract")
fn atomic_monitor_contract() -> #(#(Bool, Bool), Bool)

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
pub fn replay_worker_is_monitored_before_it_starts_test() -> Nil {
  assert atomic_monitor_contract() == #(#(True, True), True)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn callback_timeout_fails_closed_test() -> Nil {
  let entered = process.new_subject()
  let finished = process.new_subject()
  let guard =
    replay_guard.new(100, fn(_, _) {
      process.send(entered, Nil)
      let hold = process.new_subject()
      process.receive_forever(hold)
      Ok(True)
    })
    |> should.be_ok
  let #(caller, monitor) =
    spawn_monitor(fn() {
      process.send(finished, replay_guard.permits(guard, <<0x42:256>>, 5000))
    })
  let started = process.receive(entered, within: 1000) == Ok(Nil)
  let rejected = process.receive(finished, within: 1000) == Ok(False)
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: 1000)
    == Ok(Nil)
  process.demonitor_process(monitor)
  process.kill(caller)
  assert #(started, rejected, joined) == #(True, True, True)
}
