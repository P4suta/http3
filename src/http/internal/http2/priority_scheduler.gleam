//// Bounded starvation-resistant RFC 9218 HTTP/2 response scheduler.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result
import http/internal/http2/priority.{type Priority, Priority}

const maximum_stream_id = 0x7fff_ffff

type Item {
  Item(priority: Priority, ready: Bool)
}

/// Ready response selected for the next bounded DATA write quantum.
pub type Selection {
  Selection(state: State, stream_id: Int)
}

/// Payload-free bounded scheduler state for tests and live debugging.
pub type Snapshot {
  Snapshot(
    tracked: Int,
    ready: Int,
    last_urgency: Option(Int),
    urgency_burst: Int,
    non_incremental_burst: Int,
    incremental_cursor_count: Int,
  )
}

/// Finite response priorities and fairness cursors for one connection.
pub opaque type State {
  State(
    items: Dict(Int, Item),
    maximum_items: Int,
    maximum_urgency_burst: Int,
    maximum_non_incremental_burst: Int,
    last_urgency: Option(Int),
    urgency_burst: Int,
    non_incremental_burst: Int,
    incremental_cursors: Dict(Int, Int),
  )
}

/// Invalid policy, stream, priority, lifecycle operation, or capacity.
pub type Error {
  InvalidConfiguration
  InvalidStreamId(Int)
  InvalidPriority
  DuplicateStream(Int)
  MissingStream(Int)
  ItemLimitExceeded(Int)
}

/// Create a finite scheduler. Burst values count bounded DATA write quanta.
pub fn new(
  maximum_items maximum_items: Int,
  maximum_urgency_burst maximum_urgency_burst: Int,
  maximum_non_incremental_burst maximum_non_incremental_burst: Int,
) -> Result(State, Error) {
  let valid =
    maximum_items > 0
    && maximum_urgency_burst > 0
    && maximum_non_incremental_burst > 0
  use <- bool.guard(when: !valid, return: Error(InvalidConfiguration))
  Ok(State(
    dict.new(),
    maximum_items,
    maximum_urgency_burst,
    maximum_non_incremental_burst,
    None,
    0,
    0,
    dict.new(),
  ))
}

/// Register one client-initiated request stream before response scheduling.
pub fn register(
  state state: State,
  stream_id stream_id: Int,
  priority priority: Priority,
) -> Result(State, Error) {
  use _ <- result.try(validate_stream_id(stream_id))
  use _ <- result.try(validate_priority(priority))
  case dict.has_key(state.items, stream_id), dict.size(state.items) {
    True, _ -> Error(DuplicateStream(stream_id))
    False, count if count >= state.maximum_items ->
      Error(ItemLimitExceeded(state.maximum_items))
    False, _ ->
      Ok(
        State(
          ..state,
          items: dict.insert(state.items, stream_id, Item(priority, False)),
        ),
      )
  }
}

/// Replace the complete priority value for a registered stream.
pub fn update(
  state state: State,
  stream_id stream_id: Int,
  priority priority: Priority,
) -> Result(State, Error) {
  use _ <- result.try(validate_priority(priority))
  case dict.get(state.items, stream_id) {
    Error(_) -> Error(MissingStream(stream_id))
    Ok(Item(_, ready)) ->
      Ok(
        State(
          ..state,
          items: dict.insert(state.items, stream_id, Item(priority, ready)),
        ),
      )
  }
}

/// Mark whether a stream has one bounded response quantum available.
pub fn set_ready(
  state state: State,
  stream_id stream_id: Int,
  ready ready: Bool,
) -> Result(State, Error) {
  case dict.get(state.items, stream_id) {
    Error(_) -> Error(MissingStream(stream_id))
    Ok(Item(priority, _)) ->
      Ok(
        State(
          ..state,
          items: dict.insert(state.items, stream_id, Item(priority, ready)),
        ),
      )
  }
}

/// Remove a completed or reset stream and all scheduling state it owns.
pub fn remove(state state: State, stream_id stream_id: Int) -> State {
  State(..state, items: dict.delete(state.items, stream_id))
}

/// Number of request streams retaining scheduler state.
pub fn tracked_count(state: State) -> Int {
  dict.size(state.items)
}

/// Inspect finite control state without exposing response bytes or headers.
pub fn snapshot(state: State) -> Snapshot {
  Snapshot(
    tracked: dict.size(state.items),
    ready: count_ready(dict.to_list(state.items), 0),
    last_urgency: state.last_urgency,
    urgency_burst: state.urgency_burst,
    non_incremental_burst: state.non_incremental_burst,
    incremental_cursor_count: dict.size(state.incremental_cursors),
  )
}

/// Select the next ready stream and advance finite fairness cursors.
pub fn next(state: State) -> Option(Selection) {
  let ready = ready_items(dict.to_list(state.items), [])
  case ready {
    [] -> None
    _ -> {
      let highest = minimum_urgency(ready, 7)
      let selected_urgency =
        choose_urgency(state: state, ready: ready, highest: highest)
      let candidates =
        at_urgency(entries: ready, urgency: selected_urgency, reversed: [])
      let #(stream_id, incremental) = choose_candidate(state, candidates)
      let urgency_burst = case state.last_urgency == Some(selected_urgency) {
        True -> state.urgency_burst + 1
        False -> 1
      }
      let non_incremental_burst = case incremental {
        True -> 0
        False -> state.non_incremental_burst + 1
      }
      let cursors = case incremental {
        True ->
          dict.insert(state.incremental_cursors, selected_urgency, stream_id)
        False -> state.incremental_cursors
      }
      Some(Selection(
        State(
          ..state,
          last_urgency: Some(selected_urgency),
          urgency_burst: urgency_burst,
          non_incremental_burst: non_incremental_burst,
          incremental_cursors: cursors,
        ),
        stream_id,
      ))
    }
  }
}

fn choose_urgency(
  state state: State,
  ready ready: List(#(Int, Item)),
  highest highest: Int,
) -> Int {
  let burst_exhausted =
    state.last_urgency == Some(highest)
    && state.urgency_burst >= state.maximum_urgency_burst
  use <- bool.guard(when: !burst_exhausted, return: highest)
  next_lower_urgency(entries: ready, highest: highest, candidate: highest)
}

fn choose_candidate(
  state: State,
  candidates: List(#(Int, Item)),
) -> #(Int, Bool) {
  let non_incremental =
    filter_incremental(entries: candidates, wanted: False, reversed: [])
  let incremental =
    filter_incremental(entries: candidates, wanted: True, reversed: [])
  case
    non_incremental,
    incremental,
    state.non_incremental_burst >= state.maximum_non_incremental_burst
  {
    [], values, _ -> #(round_robin(state, values), True)
    values, [], _ -> #(minimum_stream(values), False)
    _, values, True -> #(round_robin(state, values), True)
    values, _, False -> #(minimum_stream(values), False)
  }
}

fn round_robin(state: State, values: List(#(Int, Item))) -> Int {
  let urgency = case values {
    [#(_, Item(Priority(value, _), _)), ..] -> value
    [] -> 0
  }
  case
    dict.get(state.incremental_cursors, urgency)
    |> result.map(Some)
    |> result.unwrap(None)
  {
    None -> minimum_stream(values)
    Some(cursor) ->
      case
        minimum_stream_after(entries: values, cursor: cursor, candidate: None)
      {
        Some(value) -> value
        None -> minimum_stream(values)
      }
  }
}

fn ready_items(
  entries: List(#(Int, Item)),
  reversed: List(#(Int, Item)),
) -> List(#(Int, Item)) {
  case entries {
    [] -> reversed
    [#(_, Item(_, False)), ..rest] -> ready_items(rest, reversed)
    [entry, ..rest] -> ready_items(rest, [entry, ..reversed])
  }
}

fn count_ready(entries: List(#(Int, Item)), count: Int) -> Int {
  case entries {
    [] -> count
    [#(_, Item(_, True)), ..rest] -> count_ready(rest, count + 1)
    [_, ..rest] -> count_ready(rest, count)
  }
}

fn at_urgency(
  entries entries: List(#(Int, Item)),
  urgency urgency: Int,
  reversed reversed: List(#(Int, Item)),
) -> List(#(Int, Item)) {
  case entries {
    [] -> reversed
    [#(_, Item(Priority(current, _), _)) as entry, ..rest] ->
      at_urgency(
        entries: rest,
        urgency: urgency,
        reversed: case current == urgency {
          True -> [entry, ..reversed]
          False -> reversed
        },
      )
  }
}

fn filter_incremental(
  entries entries: List(#(Int, Item)),
  wanted wanted: Bool,
  reversed reversed: List(#(Int, Item)),
) -> List(#(Int, Item)) {
  case entries {
    [] -> reversed
    [#(_, Item(Priority(_, incremental), _)) as entry, ..rest] ->
      filter_incremental(
        entries: rest,
        wanted: wanted,
        reversed: case incremental == wanted {
          True -> [entry, ..reversed]
          False -> reversed
        },
      )
  }
}

fn minimum_urgency(entries: List(#(Int, Item)), current: Int) -> Int {
  case entries {
    [] -> current
    [#(_, Item(Priority(urgency, _), _)), ..rest] ->
      minimum_urgency(rest, case urgency < current {
        True -> urgency
        False -> current
      })
  }
}

fn next_lower_urgency(
  entries entries: List(#(Int, Item)),
  highest highest: Int,
  candidate candidate: Int,
) -> Int {
  case entries {
    [] -> candidate
    [#(_, Item(Priority(urgency, _), _)), ..rest] -> {
      let candidate = case
        urgency > highest && { candidate == highest || urgency < candidate }
      {
        True -> urgency
        False -> candidate
      }
      next_lower_urgency(entries: rest, highest: highest, candidate: candidate)
    }
  }
}

fn minimum_stream(entries: List(#(Int, Item))) -> Int {
  case entries {
    [#(first, _), ..rest] -> minimum_stream_from(rest, first)
    [] -> 0
  }
}

fn minimum_stream_from(entries: List(#(Int, Item)), current: Int) -> Int {
  case entries {
    [] -> current
    [#(identifier, _), ..rest] ->
      minimum_stream_from(rest, case identifier < current {
        True -> identifier
        False -> current
      })
  }
}

fn minimum_stream_after(
  entries entries: List(#(Int, Item)),
  cursor cursor: Int,
  candidate candidate: Option(Int),
) -> Option(Int) {
  case entries {
    [] -> candidate
    [#(identifier, _), ..rest] -> {
      let candidate = case identifier > cursor, candidate {
        True, None -> Some(identifier)
        True, Some(current) if identifier < current -> Some(identifier)
        _, _ -> candidate
      }
      minimum_stream_after(entries: rest, cursor: cursor, candidate: candidate)
    }
  }
}

fn validate_stream_id(stream_id: Int) -> Result(Nil, Error) {
  let valid =
    stream_id > 0 && stream_id <= maximum_stream_id && stream_id % 2 == 1
  use <- bool.guard(when: !valid, return: Error(InvalidStreamId(stream_id)))
  Ok(Nil)
}

fn validate_priority(priority: Priority) -> Result(Nil, Error) {
  let valid = priority.urgency >= 0 && priority.urgency <= 7
  use <- bool.guard(when: !valid, return: Error(InvalidPriority))
  Ok(Nil)
}
