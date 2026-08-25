//// Bounded starvation-resistant RFC 9218 response scheduler.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/varint
import http3/internal/native/priority.{type Priority, Priority}

type Item {
  Item(priority: Priority, ready: Bool)
}

/// Ready response chosen for the next bounded output quantum.
pub type Selection {
  Selection(state: State, stream_id: Int)
}

/// Response priorities and fairness cursors.
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

/// Invalid configuration, identifier, priority, or resource exhaustion.
pub type Error {
  InvalidConfiguration
  InvalidStreamId(Int)
  InvalidPriority
  DuplicateStream(Int)
  MissingStream(Int)
  ItemLimitExceeded(Int)
}

/// Create a scheduler. Bursts are measured in caller-defined write quanta.
pub fn new(
  maximum_items: Int,
  maximum_urgency_burst: Int,
  maximum_non_incremental_burst: Int,
) -> Result(State, Error) {
  case
    maximum_items > 0
    && maximum_urgency_burst > 0
    && maximum_non_incremental_burst > 0
  {
    True ->
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
    False -> Error(InvalidConfiguration)
  }
}

/// Register one request stream before response scheduling begins.
pub fn register(
  state: State,
  stream_id: Int,
  priority: Priority,
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
  state: State,
  stream_id: Int,
  priority: Priority,
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

/// Mark whether a stream currently has a bounded output quantum available.
pub fn set_ready(
  state: State,
  stream_id: Int,
  ready: Bool,
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

/// Remove a completed or reset response stream.
pub fn remove(state: State, stream_id: Int) -> State {
  State(..state, items: dict.delete(state.items, stream_id))
}

/// Select the next ready stream. Higher urgency wins, with bounded service of
/// lower urgency and incremental peers to prevent indefinite starvation.
pub fn next(state: State) -> Option(Selection) {
  let ready = ready_items(dict.to_list(state.items), [])
  case ready {
    [] -> None
    _ -> {
      let highest = minimum_urgency(ready, 7)
      let selected_urgency = choose_urgency(state, ready, highest)
      let candidates = at_urgency(ready, selected_urgency, [])
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
  state: State,
  ready: List(#(Int, Item)),
  highest: Int,
) -> Int {
  case
    state.last_urgency == Some(highest)
    && state.urgency_burst >= state.maximum_urgency_burst
  {
    False -> highest
    True -> next_lower_urgency(ready, highest, highest)
  }
}

fn choose_candidate(
  state: State,
  candidates: List(#(Int, Item)),
) -> #(Int, Bool) {
  let non_incremental = filter_incremental(candidates, False, [])
  let incremental = filter_incremental(candidates, True, [])
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
    Some(cursor) -> {
      let after = minimum_stream_after(values, cursor, None)
      case after {
        Some(value) -> value
        None -> minimum_stream(values)
      }
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

fn at_urgency(
  entries: List(#(Int, Item)),
  urgency: Int,
  reversed: List(#(Int, Item)),
) -> List(#(Int, Item)) {
  case entries {
    [] -> reversed
    [#(_, Item(Priority(current, _), _)) as entry, ..rest] ->
      at_urgency(rest, urgency, case current == urgency {
        True -> [entry, ..reversed]
        False -> reversed
      })
  }
}

fn filter_incremental(
  entries: List(#(Int, Item)),
  wanted: Bool,
  reversed: List(#(Int, Item)),
) -> List(#(Int, Item)) {
  case entries {
    [] -> reversed
    [#(_, Item(Priority(_, incremental), _)) as entry, ..rest] ->
      filter_incremental(rest, wanted, case incremental == wanted {
        True -> [entry, ..reversed]
        False -> reversed
      })
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
  entries: List(#(Int, Item)),
  highest: Int,
  candidate: Int,
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
      next_lower_urgency(rest, highest, candidate)
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
  entries: List(#(Int, Item)),
  cursor: Int,
  candidate: Option(Int),
) -> Option(Int) {
  case entries {
    [] -> candidate
    [#(identifier, _), ..rest] -> {
      let candidate = case identifier > cursor, candidate {
        True, None -> Some(identifier)
        True, Some(current) if identifier < current -> Some(identifier)
        _, _ -> candidate
      }
      minimum_stream_after(rest, cursor, candidate)
    }
  }
}

fn validate_stream_id(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= varint.maximum && stream_id % 4 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidStreamId(stream_id))
  }
}

fn validate_priority(priority: Priority) -> Result(Nil, Error) {
  case priority.urgency >= 0 && priority.urgency <= 7 {
    True -> Ok(Nil)
    False -> Error(InvalidPriority)
  }
}
