//// Bounded, payload-free terminal evidence for one stream send direction.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}

pub type Outcome {
  Acknowledged
  Stopped(code: Int)
  Reset(code: Int)
}

/// One monotonically ordered, payload-free completion record.
pub type Event {
  Event(cursor: Int, identifier: Int, outcome: Outcome)
}

/// A consumer fell behind the finite ring or supplied a future cursor.
pub type ReadError {
  HistoryOverflow(oldest_available_cursor: Int)
  CursorAhead(latest_cursor: Int)
}

pub opaque type History {
  History(maximum: Int, latest_cursor: Int, entries: List(Event))
}

pub fn new(maximum: Int) -> History {
  History(int.clamp(maximum, 1, 32), 0, [])
}

/// Prepaid storage for 32 scalar entries, including a replacement list spine.
pub fn reserved_bytes() -> Int {
  4096
}

pub fn count(history: History) -> Int {
  list.length(history.entries)
}

/// Decide the absolute-deadline race immediately before publishing an event.
/// A completion observed at the deadline belongs to the timeout path.
pub fn publication_allowed(now: Int, deadline: Int) -> Bool {
  now < deadline
}

pub fn get(history: History, identifier: Int) -> Option(Outcome) {
  list.find_map(history.entries, fn(event) {
    case event.identifier == identifier {
      True -> Ok(event.outcome)
      False -> Error(Nil)
    }
  })
  |> option.from_result
}

pub fn record(history: History, identifier: Int, outcome: Outcome) -> History {
  case get(history, identifier) {
    Some(_) -> history
    None -> {
      let cursor = history.latest_cursor + 1
      History(
        ..history,
        latest_cursor: cursor,
        entries: list.take(
          [Event(cursor, identifier, outcome), ..history.entries],
          history.maximum,
        ),
      )
    }
  }
}

/// Return all retained events after `cursor` in causal order.
///
/// Cursor zero is the beginning of this connection.
/// Once the ring evicts an event, a slower observer receives a typed overflow instead of silently skipping terminal resource evidence.
pub fn after(history: History, cursor: Int) -> Result(List(Event), ReadError) {
  case cursor > history.latest_cursor, oldest_cursor(history.entries) {
    True, _ -> Error(CursorAhead(history.latest_cursor))
    False, Some(oldest) if cursor < oldest - 1 -> Error(HistoryOverflow(oldest))
    False, _ ->
      history.entries
      |> list.filter(fn(event) { event.cursor > cursor })
      |> list.reverse
      |> Ok
  }
}

fn oldest_cursor(entries: List(Event)) -> Option(Int) {
  case list.last(entries) {
    Ok(event) -> Some(event.cursor)
    Error(Nil) -> None
  }
}
