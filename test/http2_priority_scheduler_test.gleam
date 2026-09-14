import gleam/option.{None, Some}
import gleeunit
import http/internal/http2/priority
import http/internal/http2/priority_scheduler

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn rfc9218_prefers_urgency_with_bounded_lower_priority_service_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(8, 2, 2)
  let assert Ok(state) =
    priority_scheduler.register(state, 1, priority.Priority(0, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 3, priority.Priority(3, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 5, priority.Priority(0, True))
  let assert Ok(state) = priority_scheduler.set_ready(state, 1, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 3, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 5, True)

  let assert Some(priority_scheduler.Selection(state, 1)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 1)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 3)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(_, 5)) =
    priority_scheduler.next(state)
  Nil
}

pub fn rfc9218_serializes_nonincremental_and_round_robins_incremental_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(4, 8, 2)
  let assert Ok(state) =
    priority_scheduler.register(state, 1, priority.Priority(2, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 3, priority.Priority(2, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 5, priority.Priority(2, True))
  let assert Ok(state) =
    priority_scheduler.register(state, 7, priority.Priority(2, True))
  let assert Ok(state) = priority_scheduler.set_ready(state, 1, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 3, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 5, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 7, True)

  // Non-incremental peers stay serialized in request order for two quanta.
  let assert Some(priority_scheduler.Selection(state, 1)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 1)) =
    priority_scheduler.next(state)
  // The finite burst admits incremental work, which then round-robins.
  let assert Some(priority_scheduler.Selection(state, 5)) =
    priority_scheduler.next(state)
  let assert Ok(state) = priority_scheduler.set_ready(state, 1, False)
  let assert Ok(state) = priority_scheduler.set_ready(state, 3, False)
  let assert Some(priority_scheduler.Selection(state, 7)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(_, 5)) =
    priority_scheduler.next(state)
  Nil
}

pub fn scheduler_registry_is_typed_finite_and_cleanup_observable_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(1, 8, 2)
  assert priority_scheduler.register(state, 2, priority.default())
    == Error(priority_scheduler.InvalidStreamId(2))
  let assert Ok(state) =
    priority_scheduler.register(state, 1, priority.default())
  assert priority_scheduler.tracked_count(state) == 1
  assert priority_scheduler.register(state, 3, priority.default())
    == Error(priority_scheduler.ItemLimitExceeded(1))
  assert priority_scheduler.update(state, 3, priority.default())
    == Error(priority_scheduler.MissingStream(3))
  let state = priority_scheduler.remove(state, 1)
  assert priority_scheduler.tracked_count(state) == 0
  assert priority_scheduler.set_ready(state, 1, True)
    == Error(priority_scheduler.MissingStream(1))
}

pub fn scheduler_snapshot_exposes_only_finite_control_state_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(2, 2, 2)
  let assert Ok(state) =
    priority_scheduler.register(state, 1, priority.Priority(3, True))
  let assert Ok(state) =
    priority_scheduler.register(state, 3, priority.Priority(5, False))
  let assert Ok(state) = priority_scheduler.set_ready(state, 1, True)
  let assert Some(priority_scheduler.Selection(state, 1)) =
    priority_scheduler.next(state)

  assert priority_scheduler.snapshot(state)
    == priority_scheduler.Snapshot(
      tracked: 2,
      ready: 1,
      last_urgency: Some(3),
      urgency_burst: 1,
      non_incremental_burst: 0,
      incremental_cursor_count: 1,
    )
}

pub fn scheduler_state_is_connection_local_test() -> Nil {
  let assert Ok(first_connection) = priority_scheduler.new(2, 2, 2)
  let assert Ok(second_connection) = priority_scheduler.new(2, 2, 2)
  let assert Ok(first_connection) =
    priority_scheduler.register(
      first_connection,
      1,
      priority.Priority(0, False),
    )
  let assert Ok(first_connection) =
    priority_scheduler.set_ready(first_connection, 1, True)

  assert priority_scheduler.snapshot(first_connection)
    == priority_scheduler.Snapshot(
      tracked: 1,
      ready: 1,
      last_urgency: None,
      urgency_burst: 0,
      non_incremental_burst: 0,
      incremental_cursor_count: 0,
    )
  assert priority_scheduler.snapshot(second_connection)
    == priority_scheduler.Snapshot(
      tracked: 0,
      ready: 0,
      last_urgency: None,
      urgency_burst: 0,
      non_incremental_burst: 0,
      incremental_cursor_count: 0,
    )
}
