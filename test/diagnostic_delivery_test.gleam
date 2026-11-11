import gleam/erlang/process
import gleeunit
import http/internal/diagnostic_delivery
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn published_sink_result_keeps_its_credit_until_the_sink_exits_test() -> Nil {
  let entered = process.new_subject()
  let publish = process.new_subject()
  let pending = process.new_subject()
  let observed = process.new_subject()
  let waiter =
    http_test_support.start_task(fn() {
      let completed = process.new_subject()
      let sink =
        process.spawn_unlinked(fn() {
          let release = process.new_subject()
          process.send(entered, release)
          process.send(completed, Ok(Ok(Nil)))
          process.send(publish, Nil)
          let _released = process.receive(release, within: 1000)
          Nil
        })
      process.send(pending, sink)
      let delivered =
        diagnostic_delivery.await(sink, process.monitor(sink), completed, 1000)
      process.send(observed, delivered)
      delivered
    })
  let assert Ok(release) = process.receive(entered, within: 1000)
  let assert Ok(sink) = process.receive(pending, within: 1000)
  let published = process.receive(publish, within: 1000)
  let premature = process.receive(observed, within: 20)
  process.send(release, Nil)
  let delivered = http_test_support.await_task(waiter)
  let joined = !process.is_alive(sink)
  process.kill(sink)
  assert published == Ok(Nil)
  assert premature == Error(Nil)
  assert delivered == diagnostic_delivery.Delivered
  assert joined
}

pub fn timed_out_sink_is_terminated_before_delivery_finishes_test() -> Nil {
  let entered = process.new_subject()
  let waiter =
    http_test_support.start_task(fn() {
      let completed = process.new_subject()
      let sink =
        process.spawn_unlinked(fn() {
          process.send(entered, process.self())
          process.sleep(10_000)
        })
      diagnostic_delivery.await(sink, process.monitor(sink), completed, 20)
    })
  let assert Ok(sink) = process.receive(entered, within: 1000)
  let delivered = http_test_support.await_task(waiter)
  let joined = !process.is_alive(sink)
  process.kill(sink)
  assert delivered == diagnostic_delivery.Failed
  assert joined
}

pub fn successful_result_from_a_sink_that_fails_to_exit_is_failed_test() -> Nil {
  let entered = process.new_subject()
  let waiter =
    http_test_support.start_task(fn() {
      let completed = process.new_subject()
      let sink =
        process.spawn_unlinked(fn() {
          process.send(entered, process.self())
          process.send(completed, Ok(Ok(Nil)))
          process.sleep(10_000)
        })
      diagnostic_delivery.await(sink, process.monitor(sink), completed, 20)
    })
  let assert Ok(sink) = process.receive(entered, within: 1000)
  let delivered = http_test_support.await_task(waiter)
  let joined = !process.is_alive(sink)
  process.kill(sink)
  assert delivered == diagnostic_delivery.Failed
  assert joined
}

pub fn unconfirmed_join_returns_a_typed_result_under_one_absolute_deadline_test() -> Nil {
  let entered = process.new_subject()
  let observed_deadline = process.new_subject()
  let waiter =
    http_test_support.start_task(fn() {
      let completed = process.new_subject()
      let sink =
        process.spawn_unlinked(fn() {
          process.send(entered, process.self())
          process.sleep(10_000)
        })
      let outcome =
        diagnostic_delivery.await_with_clock_and_termination(
          sink,
          process.monitor(sink),
          completed,
          20,
          fn() { 10 },
          fn(_, _, deadline) {
            process.send(observed_deadline, deadline)
            False
          },
        )
      #(sink, outcome)
    })
  let assert Ok(sink) = process.receive(entered, within: 1000)
  let #(returned_sink, outcome) = http_test_support.await_task(waiter)
  let assert Ok(deadline) = process.receive(observed_deadline, within: 1000)
  let still_alive = process.is_alive(sink)
  let returned_same_process = returned_sink == sink
  process.kill(sink)
  let cleanup_joined = diagnostic_delivery.reap(sink: sink, milliseconds: 100)
  assert returned_same_process
  assert outcome == diagnostic_delivery.Unconfirmed
  assert deadline == 130
  assert still_alive
  assert cleanup_joined
}

pub fn quarantine_reaper_uses_one_finite_observation_test() -> Nil {
  let entered = process.new_subject()
  let sink =
    process.spawn_unlinked(fn() {
      process.send(entered, Nil)
      process.sleep(10_000)
    })
  let started = process.receive(entered, within: 1000) == Ok(Nil)
  let premature = diagnostic_delivery.reap(sink: sink, milliseconds: 0)
  process.kill(sink)
  let joined = diagnostic_delivery.reap(sink: sink, milliseconds: 100)
  assert started
  assert !premature
  assert joined
}
