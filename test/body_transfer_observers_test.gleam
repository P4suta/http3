import gleam/erlang/process.{type Subject}
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import http/body
import http/context
import http/diagnostics
import http/error
import http/server

type Event {
  ReadComplete(Int)
  TransferComplete(Int, Result(Nil, error.ErrorKind))
}

pub fn attaching_an_observer_preserves_prior_eof_notifications_test() -> Nil {
  let events = process.new_subject()
  let source =
    body.from_bytes(<<1, 2>>)
    |> observed(events:, index: 1)
    |> observed(events:, index: 2)
  assert consume(source) == Ok(Nil)
  assert process.receive(events, within: 0) == Ok(ReadComplete(1))
  assert process.receive(events, within: 0) == Ok(ReadComplete(2))
  // Reading EOF alone cannot report the result of a subsequent wire write.
  assert process.receive(events, within: 0) == Error(Nil)
  body.cancel(source)
}

pub fn failed_final_writes_reach_every_observer_once_test() -> Nil {
  let events = process.new_subject()
  let original = observed(source: body.from_text("fixture"), events:, index: 1)
  let source = observed(source: original, events:, index: 2)
  let failure = error.new(error.Protocol(error.Http2))
  body.transfer_finished(source, Error(failure))
  body.transfer_finished(original, Ok(Nil))
  body.transfer_finished(source, Ok(Nil))
  body.cancel(original)
  body.cancel(source)
  assert process.receive(events, within: 0)
    == Ok(TransferComplete(1, Error(error.Protocol(error.Http2))))
  assert process.receive(events, within: 0)
    == Ok(TransferComplete(2, Error(error.Protocol(error.Http2))))
  assert process.receive(events, within: 0) == Error(Nil)
}

pub fn attaching_after_eof_preserves_the_prior_read_claim_test() -> Nil {
  let events = process.new_subject()
  let original = observed(source: body.empty(), events:, index: 1)
  assert consume(original) == Ok(Nil)
  assert process.receive(events, within: 0) == Ok(ReadComplete(1))
  let source = observed(source: original, events:, index: 2)
  assert consume(source) == Ok(Nil)
  assert process.receive(events, within: 0) == Ok(ReadComplete(2))
  assert process.receive(events, within: 0) == Error(Nil)
  body.transfer_finished(source, Ok(Nil))
  assert process.receive(events, within: 0) == Ok(TransferComplete(1, Ok(Nil)))
  assert process.receive(events, within: 0) == Ok(TransferComplete(2, Ok(Nil)))
  body.cancel(source)
  assert process.receive(events, within: 0) == Error(Nil)
}

pub fn branched_cursors_share_the_prior_observers_claims_test() -> Nil {
  let events = process.new_subject()
  let original = observed(source: body.from_bytes(<<1>>), events:, index: 1)
  let first = observed(source: original, events:, index: 2)
  let second = observed(source: original, events:, index: 3)
  assert consume(first) == Ok(Nil)
  assert consume(second) == Ok(Nil)
  assert process.receive(events, within: 0) == Ok(ReadComplete(1))
  assert process.receive(events, within: 0) == Ok(ReadComplete(2))
  assert process.receive(events, within: 0) == Ok(ReadComplete(3))
  body.transfer_finished(first, Ok(Nil))
  body.transfer_finished(second, Ok(Nil))
  body.transfer_finished(original, Ok(Nil))
  assert process.receive(events, within: 0) == Ok(TransferComplete(1, Ok(Nil)))
  assert process.receive(events, within: 0) == Ok(TransferComplete(2, Ok(Nil)))
  assert process.receive(events, within: 0) == Ok(TransferComplete(3, Ok(Nil)))
  body.cancel(original)
  assert process.receive(events, within: 0) == Error(Nil)
}

pub fn cancellation_notifies_all_observers_without_claiming_eof_test() -> Nil {
  let events = process.new_subject()
  let original =
    observed(source: body.from_bytes(<<1, 2, 3>>), events:, index: 1)
  let source = observed(source: original, events:, index: 2)
  body.cancel(source)
  body.cancel(original)
  assert process.receive(events, within: 0)
    == Ok(TransferComplete(1, Error(error.Cancelled)))
  assert process.receive(events, within: 0)
    == Ok(TransferComplete(2, Error(error.Cancelled)))
  assert process.receive(events, within: 0) == Error(Nil)
}

pub fn stalled_prior_transfer_observer_cannot_suppress_later_observer_test() -> Nil {
  let stalled = process.new_subject()
  let completed = process.new_subject()
  let original =
    body.from_text("fixture")
    |> body.observe_transfer(fn() { Nil }, fn(_) {
      let release = process.new_subject()
      process.send(stalled, #(release, process.self()))
      let _released = process.receive(release, within: 10_000)
      Nil
    })
  let source =
    original
    |> body.observe_transfer(fn() { Nil }, fn(_) {
      process.send(completed, Nil)
    })

  body.transfer_finished(source, Ok(Nil))
  let stalled_worker = process.receive(stalled, within: 1000)
  let later_observer_ran = process.receive(completed, within: 1000)
  let stalled_worker_joined = case stalled_worker {
    Error(Nil) -> False
    Ok(#(release, pid)) -> {
      let monitor = process.monitor(pid)
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.demonitor_process(monitor)
      process.send(release, Nil)
      joined == Ok(Nil)
    }
  }
  body.cancel(source)

  assert #(later_observer_ran, stalled_worker_joined) == #(Ok(Nil), True)
}

pub fn stalled_prior_read_observer_cannot_suppress_later_observer_test() -> Nil {
  let stalled = process.new_subject()
  let completed = process.new_subject()
  let original =
    body.from_text("fixture")
    |> body.observe_transfer(
      fn() {
        let release = process.new_subject()
        process.send(stalled, #(release, process.self()))
        let _released = process.receive(release, within: 10_000)
        Nil
      },
      fn(_) { Nil },
    )
  let source =
    original
    |> body.observe_transfer(fn() { process.send(completed, Nil) }, fn(_) {
      Nil
    })

  let consumed = consume(source)
  let stalled_worker = process.receive(stalled, within: 1000)
  let later_observer_ran = process.receive(completed, within: 1000)
  let stalled_worker_joined = case stalled_worker {
    Error(Nil) -> False
    Ok(#(release, pid)) -> {
      let monitor = process.monitor(pid)
      let joined =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.demonitor_process(monitor)
      process.send(release, Nil)
      joined == Ok(Nil)
    }
  }
  body.cancel(source)

  assert #(consumed, later_observer_ran, stalled_worker_joined)
    == #(Ok(Nil), Ok(Nil), True)
}

pub fn a_preobserved_handler_source_survives_without_a_reporter_test() -> Nil {
  handler_source(False)
}

pub fn a_preobserved_handler_source_survives_with_a_reporter_test() -> Nil {
  handler_source(True)
}

fn handler_source(with_reporter: Bool) -> Nil {
  let events = process.new_subject()
  let diagnostics = process.new_subject()
  let reporter = case with_reporter {
    False -> None
    True -> {
      let assert Ok(reporter) =
        diagnostics.start(
          maximum_in_flight: 16,
          sink_timeout_milliseconds: 100,
          sink: fn(record) {
            case record.event {
              diagnostics.RequestFailed(_, _, failure, _) ->
                process.send(diagnostics, error.kind(failure))
              _ -> Nil
            }
            Ok(Nil)
          },
        )
      Some(reporter)
    }
  }
  let config = case reporter {
    None -> server.defaults()
    Some(reporter) -> server.with_diagnostics(server.defaults(), reporter)
  }
  let assert Ok(running) =
    server.start(config, fn(_, _) {
      Ok(
        response.new(200)
        |> response.set_body(observed(
          source: body.from_text("fixture"),
          events:,
          index: 1,
        )),
      )
    })
  let assert Ok(metadata) =
    context.new(
      context.Http1,
      context.Endpoint("127.0.0.1", 50_000),
      context.Endpoint("127.0.0.1", 8080),
      within_milliseconds: 5000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  let dispatched =
    server.handle(
      running,
      request.new() |> request.set_body(body.empty()),
      metadata,
    )
  let observed = case dispatched {
    Error(failure) -> Error(error.kind(failure))
    Ok(outgoing) -> {
      let consumed = consume(outgoing.body)
      let read = process.receive(events, within: 0)
      let premature = process.receive(events, within: 0)
      body.transfer_finished(outgoing.body, Error(error.new(error.Tls)))
      let transferred = process.receive(events, within: 0)
      body.cancel(outgoing.body)
      Ok(#(consumed, read, premature, transferred))
    }
  }
  let stopped = server.stop(running)
  let failure = case reporter {
    None -> Error(Nil)
    Some(reporter) -> {
      let received = process.receive(diagnostics, within: 1000)
      assert diagnostics.stop(reporter) == Ok(Nil)
      received
    }
  }
  assert stopped == Ok(Nil)
  assert observed
    == Ok(#(
      Ok(Nil),
      Ok(ReadComplete(1)),
      Error(Nil),
      Ok(TransferComplete(1, Error(error.Tls))),
    ))
  assert process.receive(events, within: 0) == Error(Nil)
  case with_reporter {
    True -> {
      assert failure == Ok(error.Tls)
    }
    False -> {
      assert failure == Error(Nil)
    }
  }
}

fn observed(
  source source: body.Body,
  events events: Subject(Event),
  index index: Int,
) -> body.Body {
  body.observe_transfer(
    source,
    fn() { process.send(events, ReadComplete(index)) },
    fn(outcome) {
      process.send(
        events,
        TransferComplete(index, result.map_error(outcome, error.kind)),
      )
    },
  )
}

fn consume(source: body.Body) -> Result(Nil, error.ErrorKind) {
  body.read_all(source, 1024)
  |> result.map(fn(_) { Nil })
  |> result.map_error(error.kind)
}
