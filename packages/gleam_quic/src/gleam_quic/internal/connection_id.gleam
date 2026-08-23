//// Active peer connection-ID registry and retire_prior_to processing.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam_quic/varint

const maximum_history_entries = 4096

/// One active peer-issued connection ID and stateless reset token.
pub type ConnectionId {
  ConnectionId(sequence: Int, value: BitArray, stateless_reset_token: BitArray)
}

/// Bounded active and retired peer-issued identifiers.
pub opaque type Registry {
  Registry(
    active_limit: Int,
    retire_prior_to: Int,
    active: List(ConnectionId),
    history: List(ConnectionId),
  )
}

/// Registry transition and sequences that need RETIRE_CONNECTION_ID frames.
pub type Update {
  Update(registry: Registry, retired_sequences: List(Int))
}

/// Invalid NEW_CONNECTION_ID state or identifier resource exhaustion.
pub type Error {
  InvalidConfiguration
  InvalidSequence
  InvalidRetirePriorTo
  InvalidConnectionId
  InvalidResetToken
  SequenceConflict(Int)
  ConnectionIdReused
  ResetTokenReused
  ActiveLimitExceeded(Int)
  HistoryLimitExceeded(Int)
  NoActiveConnectionId
}

/// Start with sequence zero and the peer's authenticated initial identifier.
pub fn new(
  active_limit: Int,
  initial_connection_id: BitArray,
  stateless_reset_token: BitArray,
) -> Result(Registry, Error) {
  case
    active_limit >= 2
    && active_limit <= varint.maximum
    && valid_initial_connection_id(initial_connection_id)
    && valid_reset_token(stateless_reset_token)
  {
    False -> Error(InvalidConfiguration)
    True -> {
      let initial =
        ConnectionId(0, initial_connection_id, stateless_reset_token)
      Ok(Registry(active_limit, 0, [initial], [initial]))
    }
  }
}

/// Process one authenticated NEW_CONNECTION_ID frame atomically.
pub fn receive(
  registry: Registry,
  sequence: Int,
  retire_prior_to: Int,
  connection_id: BitArray,
  stateless_reset_token: BitArray,
) -> Result(Update, Error) {
  use Nil <- result.try(validate_new_entry(
    sequence,
    retire_prior_to,
    connection_id,
    stateless_reset_token,
  ))
  receive_valid(
    registry,
    ConnectionId(sequence, connection_id, stateless_reset_token),
    retire_prior_to,
  )
}

/// Return the lowest-sequence active identifier.
pub fn current(registry: Registry) -> Result(ConnectionId, Error) {
  case registry.active {
    [connection_id, ..] -> Ok(connection_id)
    [] -> Error(NoActiveConnectionId)
  }
}

/// Return active identifier count for limit enforcement and diagnostics.
pub fn active_count(registry: Registry) -> Int {
  list.length(registry.active)
}

fn receive_valid(
  registry: Registry,
  incoming: ConnectionId,
  retire_prior_to: Int,
) -> Result(Update, Error) {
  case find_sequence(registry.history, incoming.sequence) {
    SomeConnectionId(existing) ->
      case existing == incoming {
        True -> apply_retirement(registry, incoming, retire_prior_to, False)
        False -> Error(SequenceConflict(incoming.sequence))
      }
    Missing -> insert_distinct(registry, incoming, retire_prior_to)
  }
}

fn insert_distinct(
  registry: Registry,
  incoming: ConnectionId,
  retire_prior_to: Int,
) -> Result(Update, Error) {
  let history_length = list.length(registry.history)
  case reused_value(registry.history, incoming) {
    ConnectionIdAlias -> Error(ConnectionIdReused)
    TokenAlias -> Error(ResetTokenReused)
    Distinct if history_length >= maximum_history_entries ->
      Error(HistoryLimitExceeded(maximum_history_entries))
    Distinct -> {
      let registry =
        Registry(
          ..registry,
          history: insert_sorted(registry.history, incoming, []),
        )
      apply_retirement(registry, incoming, retire_prior_to, True)
    }
  }
}

fn apply_retirement(
  registry: Registry,
  incoming: ConnectionId,
  frame_retire_prior_to: Int,
  is_new: Bool,
) -> Result(Update, Error) {
  let watermark = maximum(registry.retire_prior_to, frame_retire_prior_to)
  let active = case is_new && incoming.sequence >= watermark {
    True -> insert_sorted(registry.active, incoming, [])
    False -> registry.active
  }
  let #(remaining, retired) = retire_before(active, watermark, [], [])
  let retired = case incoming.sequence < watermark && is_new {
    True -> insert_int_sorted(retired, incoming.sequence, [])
    False -> retired
  }
  case list.length(remaining) > registry.active_limit {
    True -> Error(ActiveLimitExceeded(registry.active_limit))
    False ->
      Ok(Update(
        Registry(..registry, retire_prior_to: watermark, active: remaining),
        retired,
      ))
  }
}

type SequenceLookup {
  SomeConnectionId(ConnectionId)
  Missing
}

type Reuse {
  Distinct
  ConnectionIdAlias
  TokenAlias
}

fn find_sequence(entries: List(ConnectionId), sequence: Int) -> SequenceLookup {
  case entries {
    [] -> Missing
    [entry, ..rest] ->
      case entry.sequence == sequence {
        True -> SomeConnectionId(entry)
        False -> find_sequence(rest, sequence)
      }
  }
}

fn reused_value(entries: List(ConnectionId), incoming: ConnectionId) -> Reuse {
  case entries {
    [] -> Distinct
    [existing, ..rest] ->
      case
        existing.value == incoming.value,
        existing.stateless_reset_token == incoming.stateless_reset_token
      {
        True, _ -> ConnectionIdAlias
        _, True -> TokenAlias
        _, _ -> reused_value(rest, incoming)
      }
  }
}

fn retire_before(
  entries: List(ConnectionId),
  retire_prior_to: Int,
  remaining_reversed: List(ConnectionId),
  retired_reversed: List(Int),
) -> #(List(ConnectionId), List(Int)) {
  case entries {
    [] -> #(list.reverse(remaining_reversed), list.reverse(retired_reversed))
    [entry, ..rest] ->
      case entry.sequence < retire_prior_to {
        True ->
          retire_before(rest, retire_prior_to, remaining_reversed, [
            entry.sequence,
            ..retired_reversed
          ])
        False ->
          retire_before(
            rest,
            retire_prior_to,
            [entry, ..remaining_reversed],
            retired_reversed,
          )
      }
  }
}

fn insert_sorted(
  entries: List(ConnectionId),
  incoming: ConnectionId,
  reversed: List(ConnectionId),
) -> List(ConnectionId) {
  case entries {
    [] -> list.reverse([incoming, ..reversed])
    [entry, ..rest] ->
      case incoming.sequence < entry.sequence {
        True -> list.append(list.reverse(reversed), [incoming, entry, ..rest])
        False -> insert_sorted(rest, incoming, [entry, ..reversed])
      }
  }
}

fn insert_int_sorted(
  entries: List(Int),
  incoming: Int,
  reversed: List(Int),
) -> List(Int) {
  case entries {
    [] -> list.reverse([incoming, ..reversed])
    [entry, ..rest] ->
      case incoming < entry {
        True -> list.append(list.reverse(reversed), [incoming, entry, ..rest])
        False -> insert_int_sorted(rest, incoming, [entry, ..reversed])
      }
  }
}

fn validate_new_entry(
  sequence: Int,
  retire_prior_to: Int,
  connection_id: BitArray,
  stateless_reset_token: BitArray,
) -> Result(Nil, Error) {
  let connection_id_is_valid = valid_new_connection_id(connection_id)
  let reset_token_is_valid = valid_reset_token(stateless_reset_token)
  case sequence >= 0 && sequence <= varint.maximum {
    False -> Error(InvalidSequence)
    True if retire_prior_to < 0 || retire_prior_to > sequence ->
      Error(InvalidRetirePriorTo)
    True if !connection_id_is_valid -> Error(InvalidConnectionId)
    True if !reset_token_is_valid -> Error(InvalidResetToken)
    True -> Ok(Nil)
  }
}

fn valid_initial_connection_id(connection_id: BitArray) -> Bool {
  bit_array.bit_size(connection_id) % 8 == 0
  && bit_array.byte_size(connection_id) <= 20
}

fn valid_new_connection_id(connection_id: BitArray) -> Bool {
  valid_initial_connection_id(connection_id)
  && bit_array.byte_size(connection_id) > 0
}

fn valid_reset_token(token: BitArray) -> Bool {
  bit_array.bit_size(token) == 128
}

fn maximum(left: Int, right: Int) -> Int {
  case left > right {
    True -> left
    False -> right
  }
}
