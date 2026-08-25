import gleam/option.{Some}
import http3/internal/native/priority
import http3/internal/native/priority_scheduler

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn schedules_urgency_with_bounded_lower_priority_service_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(8, 2, 2)
  let assert Ok(state) =
    priority_scheduler.register(state, 0, priority.Priority(0, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 4, priority.Priority(3, False))
  let assert Ok(state) =
    priority_scheduler.register(state, 8, priority.Priority(0, True))
  let assert Ok(state) = priority_scheduler.set_ready(state, 0, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 4, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 8, True)

  let assert Some(priority_scheduler.Selection(state, 0)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 0)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 4)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(_, 8)) =
    priority_scheduler.next(state)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn round_robins_incremental_peers_and_validates_registry_test() -> Nil {
  let assert Ok(state) = priority_scheduler.new(2, 8, 1)
  let assert Ok(state) =
    priority_scheduler.register(state, 0, priority.Priority(2, True))
  let assert Ok(state) =
    priority_scheduler.register(state, 4, priority.Priority(2, True))
  assert priority_scheduler.register(state, 8, priority.Priority(2, True))
    == Error(priority_scheduler.ItemLimitExceeded(2))
  let assert Ok(state) = priority_scheduler.set_ready(state, 0, True)
  let assert Ok(state) = priority_scheduler.set_ready(state, 4, True)
  let assert Some(priority_scheduler.Selection(state, 0)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(state, 4)) =
    priority_scheduler.next(state)
  let assert Some(priority_scheduler.Selection(_, 0)) =
    priority_scheduler.next(state)

  assert priority_scheduler.register(state, 3, priority.default())
    == Error(priority_scheduler.InvalidStreamId(3))
  assert priority_scheduler.update(state, 8, priority.default())
    == Error(priority_scheduler.MissingStream(8))
  let state = priority_scheduler.remove(state, 4)
  assert priority_scheduler.set_ready(state, 4, True)
    == Error(priority_scheduler.MissingStream(4))
}
