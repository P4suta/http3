import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import gleeunit/should
import http/body
import http/context
import http/error
import http/internal/http3/server as adapter
import http3/client as http3_client
import http3_server_test_support as server_test_support
import http_test_support

type Once

@external(erlang, "http3_server_phase_join_test_ffi", "new_once")
fn new_once() -> Once

@external(erlang, "http3_server_phase_join_test_ffi", "claim_once")
fn claim_once(once: Once) -> Bool

@external(erlang, "http3_server_phase_join_test_ffi", "is_claimed")
fn is_claimed(once: Once) -> Bool

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn unconfirmed_setup_join_holds_body_and_accept_slot_until_down_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let armed = new_once()
  let quarantine_announced = new_once()
  let quarantine_released = new_once()
  let initial = process.new_subject()
  let quarantined = process.new_subject()
  let disposed = process.new_subject()
  let handled = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_response_worker_limit(configuration, 1) |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_request_disposed_probe(fn() { process.send(disposed, Nil) })
    |> adapter.with_response_phase_join_probe(fn(phase, stage, _) {
      case phase, stage {
        adapter.RequestSetup, adapter.InitialJoin ->
          case claim_once(armed) {
            True -> {
              process.send(initial, #(phase, stage))
              False
            }
            False -> True
          }
        adapter.RequestSetup, adapter.QuarantineJoin(attempt) -> {
          case claim_once(quarantine_announced) {
            True -> process.send(quarantined, #(phase, attempt))
            False -> Nil
          }
          is_claimed(quarantine_released)
        }
        _, _ -> True
      }
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        process.send(handled, Nil)
        Ok(response.new(204) |> response.set_body(body.empty()))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let first = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let first_finished = http3_client.finish(first)
  let initial_observation = process.receive(initial, within: 3000)
  let quarantine = process.receive(quarantined, within: 3000)
  let disposal_while_quarantined = process.receive(disposed, within: 0)
  let handler_while_quarantined = process.receive(handled, within: 0)
  let second = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let second_finished = http3_client.finish(second)
  let second_handler_while_quarantined = process.receive(handled, within: 100)
  case quarantine {
    Ok(_) -> {
      let _released = claim_once(quarantine_released)
      Nil
    }
    Error(Nil) -> Nil
  }
  let first_events = process.new_subject()
  let first_reader =
    http_test_support.start_task(fn() {
      process.send(first_events, http3_client.next_event(first))
    })
  let first_disposal = process.receive(disposed, within: 3000)
  let second_handler = process.receive(handled, within: 3000)
  let second_events = process.new_subject()
  let second_reader =
    http_test_support.start_task(fn() {
      let head = http3_client.next_event(second)
      let ended = case head {
        Ok(_) -> http3_client.next_event(second)
        Error(failure) -> Error(failure)
      }
      process.send(second_events, #(head, ended))
    })
  let first_terminal = process.receive(first_events, within: 3000)
  let second_response = process.receive(second_events, within: 3000)
  let second_disposal = process.receive(disposed, within: 3000)
  let no_duplicate_disposal = process.receive(disposed, within: 0)
  let _closed = http3_client.close(connection)
  let first_reader_done = http_test_support.await_task(first_reader)
  let second_reader_done = http_test_support.await_task(second_reader)
  let stopped = adapter.stop(listener)
  assert #(
      first_finished == Ok(Nil),
      setup_initial_observed(initial_observation),
      setup_quarantine_observed(quarantine),
      disposal_while_quarantined == Error(Nil),
      handler_while_quarantined == Error(Nil),
      second_finished == Ok(Nil),
      second_handler_while_quarantined == Error(Nil),
      response_observation_failed(first_terminal),
      first_disposal == Ok(Nil),
      second_handler == Ok(Nil),
      response_observation_is(second_response, 204),
      second_disposal == Ok(Nil),
      no_duplicate_disposal == Error(Nil),
      first_reader_done == Nil,
      second_reader_done == Nil,
      stopped == Ok(Nil),
    )
    == #(
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
    )
}

pub fn successful_request_observes_every_typed_phase_join_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let observed = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_response_phase_join_probe(configuration, fn(phase, stage, _) {
      process.send(observed, #(phase, stage))
      True
    })
  let listener =
    adapter.listen(
      fn(_, _) { Ok(response.new(204) |> response.set_body(body.empty())) },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let received =
    http3_client.send(
      client,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(<<>>),
    )
  let phases = [
    process.receive(observed, within: 1000),
    process.receive(observed, within: 1000),
    process.receive(observed, within: 1000),
    process.receive(observed, within: 1000),
  ]
  let stopped = adapter.stop(listener)
  assert phases
    == [
      Ok(#(adapter.RequestSetup, adapter.InitialJoin)),
      Ok(#(adapter.RequestHandler, adapter.InitialJoin)),
      Ok(#(adapter.ResponseSend, adapter.InitialJoin)),
      Ok(#(adapter.PeerTerminal, adapter.InitialJoin)),
    ]
  assert received
    |> response_status_is(204)
  assert process.receive(observed, within: 0) == Error(Nil)
  assert stopped == Ok(Nil)
}

pub fn unconfirmed_handler_join_holds_bodies_until_down_test() -> Nil {
  phase_quarantine_holds_bodies_until_down(adapter.RequestHandler)
}

pub fn unconfirmed_send_join_holds_bodies_until_down_test() -> Nil {
  phase_quarantine_holds_bodies_until_down(adapter.ResponseSend)
}

pub fn unconfirmed_peer_join_holds_bodies_until_down_test() -> Nil {
  phase_quarantine_holds_bodies_until_down(adapter.PeerTerminal)
}

pub fn stop_times_out_without_releasing_a_quarantined_phase_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let armed = new_once()
  let quarantine_announced = new_once()
  let quarantine_released = new_once()
  let quarantined = process.new_subject()
  let request_disposed = process.new_subject()
  let response_disposed = process.new_subject()
  let handled = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_response_worker_limit(configuration, 1) |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_request_disposed_probe(fn() {
      process.send(request_disposed, Nil)
    })
    |> adapter.with_response_phase_join_probe(fn(phase, stage, _) {
      case phase, stage {
        adapter.RequestHandler, adapter.InitialJoin ->
          case claim_once(armed) {
            True -> False
            False -> True
          }
        adapter.RequestHandler, adapter.QuarantineJoin(attempt) -> {
          case claim_once(quarantine_announced) {
            True -> process.send(quarantined, attempt)
            False -> Nil
          }
          is_claimed(quarantine_released)
        }
        _, _ -> True
      }
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        process.send(handled, Nil)
        let source =
          body.from_pull(
            body.pull(fn(_) { Ok(body.PullEnd([])) }),
            Some(0),
            None,
            fn() { process.send(response_disposed, Nil) },
          )
          |> should.be_ok
        Ok(response.new(200) |> response.set_body(source))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let stream = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let finished = http3_client.finish(stream)
  let events = process.new_subject()
  let reader =
    http_test_support.start_task(fn() {
      process.send(events, read_response_events(stream))
    })
  let first_handler = process.receive(handled, within: 3000)
  let quarantine = process.receive(quarantined, within: 3000)
  let stop_results = process.new_subject()
  let stopper =
    http_test_support.start_task(fn() {
      process.send(stop_results, adapter.stop(listener))
    })
  let stopped = process.receive(stop_results, within: 9000)
  let request_held = process.receive(request_disposed, within: 0)
  let response_held = process.receive(response_disposed, within: 0)
  let after_stop = http3_client.open_stream(connection, outgoing)
  result.map(after_stop, fn(unaccepted) {
    {
      let _finished = http3_client.finish(unaccepted)
      Nil
    }
  })
  |> result.unwrap(Nil)
  let no_accept_restart = process.receive(handled, within: 500)
  case quarantine {
    Ok(1) -> {
      let _released = claim_once(quarantine_released)
      Nil
    }
    _ -> Nil
  }
  let request_released = process.receive(request_disposed, within: 3000)
  let response_released = process.receive(response_disposed, within: 3000)
  let no_request_duplicate = process.receive(request_disposed, within: 0)
  let no_response_duplicate = process.receive(response_disposed, within: 0)
  let terminal = process.receive(events, within: 3000)
  let _closed = http3_client.close(connection)
  let reader_done = http_test_support.await_task(reader)
  let stopper_done = http_test_support.await_task(stopper)
  let repeated = adapter.stop(listener)
  let timeout = Error(error.new(error.Timeout(error.Operation)))
  assert #(
      finished == Ok(Nil),
      first_handler == Ok(Nil),
      stop_quarantine_observed(quarantine),
      stopped == Ok(timeout),
      request_held == Error(Nil),
      response_held == Error(Nil),
      no_accept_restart == Error(Nil),
      request_released == Ok(Nil),
      response_released == Ok(Nil),
      no_request_duplicate == Error(Nil),
      no_response_duplicate == Error(Nil),
      response_observation_is_terminal(terminal),
      reader_done == Nil,
      stopper_done == Nil,
      repeated == timeout,
    )
    == #(
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
    )
}

fn phase_quarantine_holds_bodies_until_down(
  target: adapter.ResponseWorkPhase,
) -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let armed = new_once()
  let quarantine_announced = new_once()
  let quarantine_released = new_once()
  let initial = process.new_subject()
  let quarantined = process.new_subject()
  let request_disposed = process.new_subject()
  let response_disposed = process.new_subject()
  let handled = process.new_subject()
  let configuration =
    adapter.defaults(certificate, private_key, "localhost") |> should.be_ok
  let configuration =
    adapter.with_response_worker_limit(configuration, 1) |> should.be_ok
  let configuration =
    configuration
    |> adapter.with_request_disposed_probe(fn() {
      process.send(request_disposed, Nil)
    })
    |> adapter.with_response_phase_join_probe(fn(phase, stage, _) {
      case phase == target, stage {
        True, adapter.InitialJoin ->
          case claim_once(armed) {
            True -> {
              process.send(initial, #(phase, stage))
              False
            }
            False -> True
          }
        True, adapter.QuarantineJoin(attempt) -> {
          case claim_once(quarantine_announced) {
            True -> process.send(quarantined, #(phase, attempt))
            False -> Nil
          }
          is_claimed(quarantine_released)
        }
        _, _ -> True
      }
    })
  let listener =
    adapter.listen(
      fn(_, _) {
        process.send(handled, Nil)
        let source =
          body.from_pull(
            body.pull(fn(_) { Ok(body.PullEnd([])) }),
            Some(0),
            None,
            fn() { process.send(response_disposed, Nil) },
          )
          |> should.be_ok
        Ok(response.new(200) |> response.set_body(source))
      },
      <<127, 0, 0, 1>>,
      0,
      configuration,
    )
    |> should.be_ok
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let client =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
    |> should.be_ok
  let connection =
    http3_client.connect(client, "localhost", port) |> should.be_ok
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let first = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let first_finished = http3_client.finish(first)
  let first_events = process.new_subject()
  let first_reader =
    http_test_support.start_task(fn() {
      process.send(first_events, read_response_events(first))
    })
  let initial_observation = process.receive(initial, within: 3000)
  let quarantine = process.receive(quarantined, within: 3000)
  let first_handler = process.receive(handled, within: 0)
  let request_held = process.receive(request_disposed, within: 0)
  let response_held = process.receive(response_disposed, within: 0)
  let second = http3_client.open_stream(connection, outgoing) |> should.be_ok
  let second_finished = http3_client.finish(second)
  let no_second_handler = process.receive(handled, within: 100)
  case quarantine {
    Ok(_) -> {
      let _released = claim_once(quarantine_released)
      Nil
    }
    Error(Nil) -> Nil
  }
  let first_request_disposal = process.receive(request_disposed, within: 3000)
  let first_response_disposal = process.receive(response_disposed, within: 3000)
  let second_handler = process.receive(handled, within: 3000)
  let second_events = process.new_subject()
  let second_reader =
    http_test_support.start_task(fn() {
      process.send(second_events, read_response_events(second))
    })
  let first_terminal = process.receive(first_events, within: 3000)
  let second_response = process.receive(second_events, within: 3000)
  let second_request_disposal = process.receive(request_disposed, within: 3000)
  let second_response_disposal =
    process.receive(response_disposed, within: 3000)
  let no_request_duplicate = process.receive(request_disposed, within: 0)
  let no_response_duplicate = process.receive(response_disposed, within: 0)
  let _closed = http3_client.close(connection)
  let first_reader_done = http_test_support.await_task(first_reader)
  let second_reader_done = http_test_support.await_task(second_reader)
  let stopped = adapter.stop(listener)
  assert #(
      first_finished == Ok(Nil),
      phase_initial_observed(initial_observation, target),
      phase_quarantine_observed(quarantine, target),
      first_handler == Ok(Nil),
      request_held == Error(Nil),
      response_held == Error(Nil),
      second_finished == Ok(Nil),
      no_second_handler == Error(Nil),
      first_request_disposal == Ok(Nil),
      first_response_disposal == Ok(Nil),
      response_observation_is_terminal(first_terminal),
      second_handler == Ok(Nil),
      response_observation_is(second_response, 200),
      second_request_disposal == Ok(Nil),
      second_response_disposal == Ok(Nil),
      no_request_duplicate == Error(Nil),
      no_response_duplicate == Error(Nil),
      first_reader_done == Nil,
      second_reader_done == Nil,
      stopped == Ok(Nil),
    )
    == #(
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
      True,
    )
}

fn setup_initial_observed(
  observation: Result(
    #(adapter.ResponseWorkPhase, adapter.ResponseJoinStage),
    Nil,
  ),
) -> Bool {
  observation == Ok(#(adapter.RequestSetup, adapter.InitialJoin))
}

fn setup_quarantine_observed(
  observation: Result(#(adapter.ResponseWorkPhase, Int), Nil),
) -> Bool {
  case observation {
    Ok(#(adapter.RequestSetup, 1)) -> True
    _ -> False
  }
}

fn phase_initial_observed(
  observation: Result(
    #(adapter.ResponseWorkPhase, adapter.ResponseJoinStage),
    Nil,
  ),
  expected: adapter.ResponseWorkPhase,
) -> Bool {
  observation == Ok(#(expected, adapter.InitialJoin))
}

fn phase_quarantine_observed(
  observation: Result(#(adapter.ResponseWorkPhase, Int), Nil),
  expected: adapter.ResponseWorkPhase,
) -> Bool {
  case observation {
    Ok(#(phase, 1)) -> phase == expected
    _ -> False
  }
}

fn stop_quarantine_observed(observation: Result(Int, Nil)) -> Bool {
  case observation {
    Ok(1) -> True
    _ -> False
  }
}

fn read_response_events(
  stream: http3_client.Stream,
) -> #(
  Result(http3_client.ResponseEvent, http3_client.Error),
  Result(http3_client.ResponseEvent, http3_client.Error),
) {
  let head = http3_client.next_event(stream)
  let terminal = case head {
    Ok(_) -> http3_client.next_event(stream)
    Error(failure) -> Error(failure)
  }
  #(head, terminal)
}

fn response_observation_is_terminal(
  event: Result(
    #(
      Result(http3_client.ResponseEvent, http3_client.Error),
      Result(http3_client.ResponseEvent, http3_client.Error),
    ),
    Nil,
  ),
) -> Bool {
  case event {
    Ok(#(Ok(http3_client.Response(_, _)), Ok(http3_client.End))) -> True
    Ok(#(Ok(http3_client.Response(_, _)), Error(_))) -> True
    Ok(#(Error(_), Error(_))) -> True
    _ -> False
  }
}

fn response_observation_failed(
  event: Result(Result(http3_client.ResponseEvent, http3_client.Error), Nil),
) -> Bool {
  case event {
    Ok(Error(_)) -> True
    _ -> False
  }
}

fn response_observation_is(
  event: Result(
    #(
      Result(http3_client.ResponseEvent, http3_client.Error),
      Result(http3_client.ResponseEvent, http3_client.Error),
    ),
    Nil,
  ),
  status: Int,
) -> Bool {
  case event {
    Ok(#(head, Ok(http3_client.End))) ->
      server_test_support.default_response_head(outcome: head, status: status)
    _ -> False
  }
}

fn response_status_is(
  received: Result(response.Response(BitArray), http3_client.Error),
  expected: Int,
) -> Bool {
  result.map(received, fn(incoming) { incoming.status == expected })
  |> result.unwrap(False)
}
