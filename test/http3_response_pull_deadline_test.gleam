import gleam/erlang/process
import gleam/option.{type Option, None, Some}
import gleeunit
import gleeunit/should
import http/body
import http/error
import http/internal/http3/client as adapter
import http_test_support

const deadline = 10_000

const cleanup_budget_milliseconds = 8000

const observation_milliseconds = 3000

const prompt_milliseconds = 500

type ReplyCase {
  DataReply
  EndReply
  ErrorReply
}

type ObservedRead {
  ObservedData(BitArray)
  ObservedEnd(body.Headers)
  ObservedFailure(error.ErrorKind)
}

type ReadRequest {
  ReadRequest(
    maximum: Int,
    reply: process.Subject(Result(body.PullEvent, error.Error)),
  )
}

type PullReady {
  PullReady(clock: process.Subject(process.Subject(Int)))
}

type PullObservation {
  PullObservation(read: ObservedRead, reply_mailbox_empty: Bool)
}

type GuardianFixture {
  GuardianFixture(
    guardian: process.Pid,
    worker: process.Pid,
    cancel_worker: process.Subject(Nil),
    release_guardian: process.Subject(Nil),
  )
}

type GuardianReady {
  GuardianReady(GuardianFixture)
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn response_selector_wait_excludes_the_cleanup_budget_test() -> Nil {
  assert adapter.response_pull_wait_milliseconds(deadline: deadline, current: 0)
    == deadline
  assert adapter.response_pull_wait_milliseconds(
      deadline: deadline,
      current: deadline,
    )
    == 0
  assert adapter.response_pull_wait_milliseconds(
      deadline: deadline,
      current: deadline + 1,
    )
    == 0
}

pub fn response_data_strictly_before_total_deadline_is_accepted_test() -> Nil {
  assert_within_deadline(DataReply, ObservedData(<<"within":utf8>>))
}

pub fn response_end_strictly_before_total_deadline_is_accepted_test() -> Nil {
  assert_within_deadline(EndReply, ObservedEnd([#("x-finished", "yes")]))
}

pub fn response_error_strictly_before_total_deadline_is_accepted_test() -> Nil {
  assert_within_deadline(ErrorReply, ObservedFailure(error.Service))
}

pub fn response_data_just_after_total_deadline_is_rejected_test() -> Nil {
  assert_after_deadline_is_total_timeout(DataReply)
}

pub fn response_end_just_after_total_deadline_is_rejected_test() -> Nil {
  assert_after_deadline_is_total_timeout(EndReply)
}

pub fn response_error_just_after_total_deadline_is_rejected_test() -> Nil {
  assert_after_deadline_is_total_timeout(ErrorReply)
}

pub fn total_timeout_cancels_reaps_and_drains_a_late_reply_test() -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  answer_clock(clock, deadline)
  let ReadRequest(maximum, reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  let cancellation = process.receive(cancelled, within: prompt_milliseconds)
  case cancellation {
    Ok(Nil) -> Nil
    Error(Nil) -> process.send(fixture.cancel_worker, Nil)
  }
  let child_cleanup =
    process.receive(child_reaped, within: observation_milliseconds)
  process.send(reply, reply_for(DataReply))
  let premature = process.receive(finished, within: 0)
  process.send(fixture.release_guardian, Nil)
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  let worker_joined = join(worker_monitor, observation_milliseconds)
  let guardian_joined = join(guardian_monitor, observation_milliseconds)
  assert maximum == 64
  assert cancellation == Ok(Nil)
  assert child_cleanup == Ok(True)
  assert premature == Error(Nil)
  assert observation == Ok(task_observation)
  assert task_observation.read == ObservedFailure(error.Timeout(error.Total))
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert worker_joined
  assert guardian_joined
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

pub fn guardian_stop_cancels_and_reaps_its_worker_test() -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  answer_clock(clock, 0)
  let ReadRequest(maximum, _reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  process.kill(fixture.guardian)
  answer_clock(clock, deadline - 1)
  let cancellation = process.receive(cancelled, within: prompt_milliseconds)
  case cancellation {
    Ok(Nil) -> Nil
    Error(Nil) -> process.send(fixture.cancel_worker, Nil)
  }
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  let worker_joined = join(worker_monitor, observation_milliseconds)
  let guardian_joined = join(guardian_monitor, observation_milliseconds)
  assert maximum == 64
  assert cancellation == Ok(Nil)
  assert observation == Ok(task_observation)
  assert task_observation.read == ObservedFailure(error.Cancelled)
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert worker_joined
  assert guardian_joined
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert process.receive(child_reaped, within: 0) == Error(Nil)
}

pub fn guardian_down_selected_before_a_terminal_reply_reconciles_the_reply_test() -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  answer_clock(clock, 0)
  let ReadRequest(maximum, reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  process.kill(fixture.guardian)
  let post_selection_clock =
    process.receive(clock, within: observation_milliseconds) |> should.be_ok
  process.send(reply, reply_for(EndReply))
  process.send(post_selection_clock, deadline - 1)
  let cancellation = process.receive(cancelled, within: prompt_milliseconds)
  case cancellation {
    Ok(Nil) -> Nil
    Error(Nil) -> process.send(fixture.cancel_worker, Nil)
  }
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  assert maximum == 64
  assert cancellation == Ok(Nil)
  assert observation == Ok(task_observation)
  assert task_observation.read == ObservedEnd([#("x-finished", "yes")])
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert join(worker_monitor, observation_milliseconds)
  assert join(guardian_monitor, observation_milliseconds)
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert process.receive(child_reaped, within: 0) == Error(Nil)
}

pub fn worker_down_selected_before_a_terminal_reply_reconciles_the_reply_test() -> Nil {
  assert_worker_down_result(
    reply_case: Some(EndReply),
    expected: ObservedEnd([#("x-finished", "yes")]),
    expect_cancel: False,
  )
}

pub fn worker_down_without_a_reply_fails_and_reaps_the_guardian_test() -> Nil {
  assert_worker_down_result(
    reply_case: None,
    expected: ObservedFailure(error.Service),
    expect_cancel: True,
  )
}

fn assert_worker_down_result(
  reply_case reply_case: Option(ReplyCase),
  expected expected: ObservedRead,
  expect_cancel expect_cancel: Bool,
) -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  let ReadRequest(maximum, reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  process.kill(fixture.worker)
  let child_cleanup =
    process.receive(child_reaped, within: observation_milliseconds)
  answer_clock(clock, deadline - 1000)
  let post_selection_clock =
    process.receive(clock, within: observation_milliseconds) |> should.be_ok
  case reply_case {
    Some(reply_case) -> process.send(reply, reply_for(reply_case))
    None -> Nil
  }
  process.send(post_selection_clock, deadline - 1)
  let cancellation = process.receive(cancelled, within: prompt_milliseconds)
  case expect_cancel, cancellation {
    True, Error(Nil) -> process.send(fixture.cancel_worker, Nil)
    _, _ -> Nil
  }
  let premature = process.receive(finished, within: 0)
  process.send(fixture.release_guardian, Nil)
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  assert maximum == 64
  assert child_cleanup == Ok(True)
  assert premature == Error(Nil)
  assert observation == Ok(task_observation)
  assert task_observation.read == expected
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert join(worker_monitor, observation_milliseconds)
  assert join(guardian_monitor, observation_milliseconds)
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
  case expect_cancel {
    True -> {
      assert cancellation == Ok(Nil)
    }
    False -> {
      assert cancellation == Error(Nil)
    }
  }
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

fn assert_within_deadline(
  reply_case: ReplyCase,
  expected: ObservedRead,
) -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  answer_clock(clock, 0)
  let ReadRequest(maximum, reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  process.send(reply, reply_for(reply_case))
  answer_clock(clock, deadline - 1)
  case reply_case {
    DataReply -> Nil
    EndReply | ErrorReply -> {
      process.send(fixture.cancel_worker, Nil)
      let _child_cleanup =
        process.receive(child_reaped, within: observation_milliseconds)
      process.send(fixture.release_guardian, Nil)
    }
  }
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  let cancellation = process.receive(cancelled, within: 0)
  case reply_case {
    DataReply ->
      stop_guardian(
        fixture: fixture,
        child_reaped: child_reaped,
        guardian_monitor: guardian_monitor,
      )
    EndReply | ErrorReply -> Nil
  }
  let worker_joined = join(worker_monitor, observation_milliseconds)
  let guardian_joined = case reply_case {
    DataReply -> !process.is_alive(fixture.guardian)
    EndReply | ErrorReply -> join(guardian_monitor, observation_milliseconds)
  }
  assert maximum == 64
  assert observation == Ok(task_observation)
  assert task_observation.read == expected
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert cancellation == Error(Nil)
  assert worker_joined
  assert guardian_joined
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
}

fn assert_after_deadline_is_total_timeout(reply_case: ReplyCase) -> Nil {
  let child_reaped = process.new_subject()
  let fixture = start_guardian(child_reaped)
  let guardian_monitor = process.monitor(fixture.guardian)
  let worker_monitor = process.monitor(fixture.worker)
  let ready = process.new_subject()
  let reads = process.new_subject()
  let cancelled = process.new_subject()
  let finished = process.new_subject()
  let pulling =
    start_pull(
      fixture: fixture,
      ready: ready,
      reads: reads,
      cancelled: cancelled,
      finished: finished,
    )
  let PullReady(clock) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  answer_clock(clock, 0)
  answer_clock(clock, 0)
  let ReadRequest(maximum, reply) =
    process.receive(reads, within: observation_milliseconds) |> should.be_ok
  process.send(reply, reply_for(reply_case))
  answer_clock(clock, deadline + 1)
  let cancellation = process.receive(cancelled, within: prompt_milliseconds)
  case cancellation {
    Ok(Nil) -> Nil
    Error(Nil) -> process.send(fixture.cancel_worker, Nil)
  }
  let child_cleanup =
    process.receive(child_reaped, within: observation_milliseconds)
  let premature = process.receive(finished, within: 0)
  process.send(fixture.release_guardian, Nil)
  let observation = process.receive(finished, within: observation_milliseconds)
  let task_observation = http_test_support.await_task(pulling)
  let worker_joined = join(worker_monitor, observation_milliseconds)
  let guardian_joined = join(guardian_monitor, observation_milliseconds)
  assert maximum == 64
  assert cancellation == Ok(Nil)
  assert child_cleanup == Ok(True)
  assert premature == Error(Nil)
  assert observation == Ok(task_observation)
  assert task_observation.read == ObservedFailure(error.Timeout(error.Total))
  assert task_observation.reply_mailbox_empty
  assert process.receive(clock, within: 0) == Error(Nil)
  assert worker_joined
  assert guardian_joined
  assert !process.is_alive(fixture.worker)
  assert !process.is_alive(fixture.guardian)
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

fn start_pull(
  fixture fixture: GuardianFixture,
  ready ready: process.Subject(PullReady),
  reads reads: process.Subject(ReadRequest),
  cancelled cancelled: process.Subject(Nil),
  finished finished: process.Subject(PullObservation),
) -> http_test_support.Task(PullObservation) {
  let clock = process.new_subject()
  http_test_support.start_task(fn() {
    let replies = process.new_subject()
    process.send(ready, PullReady(clock))
    let pull =
      adapter.response_pull_with_deadline_probe(
        worker: fixture.worker,
        guardian: fixture.guardian,
        deadline: deadline,
        cleanup_budget_milliseconds: cleanup_budget_milliseconds,
        clock: fn() {
          let reply = process.new_subject()
          process.send(clock, reply)
          process.receive_forever(reply)
        },
        dispatch_read: fn(maximum, reply) {
          process.send(replies, reply)
          process.send(reads, ReadRequest(maximum, reply))
        },
        dispatch_cancel: fn() {
          process.send(cancelled, Nil)
          process.send(fixture.cancel_worker, Nil)
        },
      )
    let source = body.from_pull(pull, None, None, fn() { Nil }) |> should.be_ok
    let read = observe_read(body.read(source, 64))
    let reply = process.receive_forever(replies)
    let observation =
      PullObservation(
        read: read,
        reply_mailbox_empty: process.receive(reply, within: 0) == Error(Nil),
      )
    process.send(finished, observation)
    observation
  })
}

fn answer_clock(
  clock: process.Subject(process.Subject(Int)),
  value: Int,
) -> Nil {
  let reply =
    process.receive(clock, within: observation_milliseconds) |> should.be_ok
  process.send(reply, value)
}

fn start_guardian(child_reaped: process.Subject(Bool)) -> GuardianFixture {
  let ready = process.new_subject()
  let _guardian =
    process.spawn_unlinked(fn() {
      process.trap_exits(True)
      let worker_ready = process.new_subject()
      let worker =
        process.spawn(fn() {
          // Match the production request worker: a guardian exit is observable but cannot substitute for the explicit Cancel/reap contract.
          process.trap_exits(True)
          let cancel = process.new_subject()
          process.send(worker_ready, cancel)
          let _cancelled = process.receive_forever(cancel)
          Nil
        })
      let cancel_worker = process.receive_forever(worker_ready)
      let release_guardian = process.new_subject()
      process.send(
        ready,
        GuardianReady(GuardianFixture(
          guardian: process.self(),
          worker: worker,
          cancel_worker: cancel_worker,
          release_guardian: release_guardian,
        )),
      )
      let worker_joined =
        join(process.monitor(worker), observation_milliseconds)
      process.send(child_reaped, worker_joined)
      let _released = process.receive_forever(release_guardian)
      Nil
    })
  let GuardianReady(fixture) =
    process.receive(ready, within: observation_milliseconds) |> should.be_ok
  fixture
}

fn stop_guardian(
  fixture fixture: GuardianFixture,
  child_reaped child_reaped: process.Subject(Bool),
  guardian_monitor guardian_monitor: process.Monitor,
) -> Nil {
  process.send(fixture.cancel_worker, Nil)
  case
    process.receive(child_reaped, within: observation_milliseconds)
    |> should.be_ok
  {
    True -> Ok(Nil)
    unexpected -> Error(unexpected)
  }
  |> should.be_ok
  process.send(fixture.release_guardian, Nil)
  assert join(guardian_monitor, observation_milliseconds)
}

fn observe_read(outcome: Result(body.Read, error.Error)) -> ObservedRead {
  case outcome {
    Ok(body.Data(bytes, _)) -> ObservedData(bytes)
    Ok(body.Done(completed)) ->
      case body.trailers(completed) {
        Some(trailers) -> ObservedEnd(trailers)
        None -> ObservedEnd([])
      }
    Error(failure) -> ObservedFailure(error.kind(failure))
  }
}

fn reply_for(reply_case: ReplyCase) -> Result(body.PullEvent, error.Error) {
  case reply_case {
    DataReply ->
      Ok(body.PullData(
        <<"within":utf8>>,
        body.pull(fn(_) { Ok(body.PullEnd([])) }),
      ))
    EndReply -> Ok(body.PullEnd([#("x-finished", "yes")]))
    ErrorReply -> Error(error.new(error.Service))
  }
}

fn join(monitor: process.Monitor, milliseconds: Int) -> Bool {
  let joined =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: milliseconds)
  process.demonitor_process(monitor)
  joined == Ok(Nil)
}
