import http3/internal/native/orderly_close

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn server_goaway_application_flush_and_exact_close_are_causal_test() -> Nil {
  let assert Ok(state) = orderly_close.new(orderly_close.Server, 10, 90, 20)
  let initial = orderly_close.initial_goaway_identifier(orderly_close.Server)
  let assert Ok(#(state, orderly_close.InitialGoAway(initial_identifier))) =
    orderly_close.initial_queued(state, initial)
  assert initial_identifier == initial
  let assert Ok(#(state, orderly_close.FinalGoAway(8))) =
    orderly_close.final_queued(state, 8, 20)
  assert orderly_close.confirm_closed(state, orderly_close.h3_no_error)
    == Error(orderly_close.NotReadyToClose)

  let assert Ok(orderly_close.Continue(
    state,
    orderly_close.AwaitApplication(80),
  )) = orderly_close.observe(state, 20, False, False)
  let assert Ok(orderly_close.Continue(state, orderly_close.AwaitTransport(60))) =
    orderly_close.observe(state, 40, True, False)
  let assert Ok(orderly_close.Close(state, orderly_close.CloseWithNoError(code))) =
    orderly_close.observe(state, 99, True, True)
  assert code == 0x100
  let assert Ok(closed) = orderly_close.confirm_closed(state, code)
  assert orderly_close.confirm_closed(closed, code)
    == Error(orderly_close.AlreadyClosed)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn client_goaway_identifiers_are_role_correct_and_nonincreasing_test() -> Nil {
  let assert Ok(state) = orderly_close.new(orderly_close.Client, 0, 10, 1)
  let initial = orderly_close.initial_goaway_identifier(orderly_close.Client)
  let assert Ok(#(state, orderly_close.InitialGoAway(initial_identifier))) =
    orderly_close.initial_queued(state, initial)
  assert initial_identifier == initial
  let assert Ok(#(state, orderly_close.FinalGoAway(0))) =
    orderly_close.final_queued(state, 0, 1)
  let assert Ok(orderly_close.Close(_, orderly_close.CloseWithNoError(0x100))) =
    orderly_close.observe(state, 1, True, True)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn absolute_deadline_wins_at_edge_without_relative_extension_test() -> Nil {
  let assert Ok(state) = orderly_close.new(orderly_close.Server, 100, 50, 120)
  let initial = orderly_close.initial_goaway_identifier(orderly_close.Server)
  let assert Ok(#(state, _)) = orderly_close.initial_queued(state, initial)
  let assert Ok(#(state, _)) = orderly_close.final_queued(state, 4, 120)
  let assert Ok(orderly_close.Continue(state, orderly_close.AwaitTransport(1))) =
    orderly_close.observe(state, 149, True, False)
  let assert Ok(orderly_close.Abort(_, orderly_close.AbortAfterDeadline)) =
    orderly_close.observe(state, 150, True, True)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn wrong_order_clock_rollback_and_non_no_error_close_are_rejected_test() -> Nil {
  let assert Ok(server) = orderly_close.new(orderly_close.Server, 10, 50, 20)
  assert orderly_close.final_queued(server, 0, 20)
    == Error(orderly_close.InitialGoAwayMissing)
  assert orderly_close.initial_queued(server, 0)
    == Error(orderly_close.InvalidGoAwayIdentifier(0))

  let initial = orderly_close.initial_goaway_identifier(orderly_close.Server)
  let assert Ok(#(server, _)) = orderly_close.initial_queued(server, initial)
  let assert Ok(#(server, _)) = orderly_close.final_queued(server, 0, 20)
  let assert Ok(orderly_close.Continue(server, _)) =
    orderly_close.observe(server, 20, True, False)
  assert orderly_close.observe(server, 19, True, False)
    == Error(orderly_close.ClockMovedBackwards)
  let assert Ok(orderly_close.Close(server, _)) =
    orderly_close.observe(server, 21, True, True)
  assert orderly_close.confirm_closed(server, 0)
    == Error(orderly_close.InvalidCloseCode(0))
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn final_goaway_waits_for_injected_refinement_instant_test() -> Nil {
  let assert Ok(state) = orderly_close.new(orderly_close.Server, 100, 100, 125)
  let initial = orderly_close.initial_goaway_identifier(orderly_close.Server)
  let assert Ok(#(state, _)) = orderly_close.initial_queued(state, initial)

  assert orderly_close.final_queued(state, 4, 124)
    == Error(orderly_close.RefinementTooEarly(1))
  assert !orderly_close.final_goaway_queued(state)

  // A request arriving during the explicit interval advances the first stream the server will reject.
  // The final GOAWAY samples that later value.
  let next_request_stream_id_after_late_arrival = 12
  let assert Ok(#(state, orderly_close.FinalGoAway(12))) =
    orderly_close.final_queued(
      state,
      next_request_stream_id_after_late_arrival,
      125,
    )
  assert orderly_close.final_goaway_queued(state)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn refinement_schedule_is_capped_without_extending_terminal_deadline_test() -> Nil {
  assert orderly_close.refinement_not_before(100, 105, 100) == Ok(104)
  assert orderly_close.refinement_not_before(100, 101, 1)
    == Error(orderly_close.InvalidConfiguration)

  let assert Ok(state) = orderly_close.new(orderly_close.Client, 100, 5, 104)
  let initial = orderly_close.initial_goaway_identifier(orderly_close.Client)
  let assert Ok(#(state, _)) = orderly_close.initial_queued(state, initial)
  assert orderly_close.final_queued(state, 0, 105)
    == Error(orderly_close.RefinementDeadlineReached)
}
