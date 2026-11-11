//// Finite local connection-ID issuance and authenticated retirement.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core/internal/connection_id.{type ConnectionId, type Error}

const maximum_active = 4

const maximum_history = 4096

/// Issued values are retained so retirement never permits identifier reuse.
pub opaque type Issuer {
  Issuer(
    active: List(ConnectionId),
    history: List(ConnectionId),
    next_sequence: Int,
    highest_sent_sequence: Int,
    identifier_bytes: Int,
  )
}

/// Scalar local-issuer occupancy, independent of peer-controlled values.
pub type Snapshot {
  Snapshot(active: Int, issued: Int, retired: Int, history_limit: Int)
}

/// Sequence zero is the initial source connection ID.
pub fn new(initial: BitArray) -> Result(Issuer, Error) {
  let size = bit_array.byte_size(initial)
  case bit_array.bit_size(initial) % 8 == 0 && size >= 1 && size <= 20 {
    False -> Error(connection_id.InvalidConnectionId)
    True -> {
      let entry = connection_id.ConnectionId(0, initial, None)
      Ok(Issuer([entry], [entry], 1, 0, size))
    }
  }
}

/// Bound the advertised peer allowance by local active and history budgets.
pub fn available(issuer: Issuer, peer_limit: Int) -> Int {
  int.max(
    0,
    int.min(
      int.min(maximum_active, peer_limit) - list.length(issuer.active),
      maximum_history - issuer.next_sequence,
    ),
  )
}

/// Add exactly one already-routable identifier and return its wire record.
pub fn issue(
  issuer: Issuer,
  peer_limit: Int,
  identifier: BitArray,
  reset_token: BitArray,
) -> Result(#(Issuer, ConnectionId), Error) {
  use Nil <- result.try(
    case
      bit_array.bit_size(identifier) == issuer.identifier_bytes * 8,
      bit_array.bit_size(reset_token) == 128
    {
      False, _ -> Error(connection_id.InvalidConnectionId)
      _, False -> Error(connection_id.InvalidResetToken)
      True, True -> Ok(Nil)
    },
  )
  use Nil <- result.try(case issuer.next_sequence >= maximum_history {
    True -> Error(connection_id.HistoryLimitExceeded(maximum_history))
    False ->
      case available(issuer, peer_limit) == 0 {
        True ->
          Error(
            connection_id.ActiveLimitExceeded(int.min(
              maximum_active,
              peer_limit,
            )),
          )
        False -> Ok(Nil)
      }
  })
  use Nil <- result.try(distinct(issuer.history, identifier, reset_token))
  let entry =
    connection_id.ConnectionId(
      issuer.next_sequence,
      identifier,
      Some(reset_token),
    )
  Ok(#(
    Issuer(
      ..issuer,
      active: [entry, ..issuer.active],
      history: [entry, ..issuer.history],
      next_sequence: issuer.next_sequence + 1,
    ),
    entry,
  ))
}

/// Check every retirement before a packet can mutate protocol state.
pub fn validate_retirement(
  issuer: Issuer,
  sequence: Int,
  destination: Option(BitArray),
) -> Result(Nil, Error) {
  use Nil <- result.try(case sequence > issuer.highest_sent_sequence {
    True -> Error(connection_id.InvalidSequence)
    False -> Ok(Nil)
  })
  case list.find(issuer.history, fn(entry) { entry.sequence == sequence }) {
    Error(_) -> Error(connection_id.InvalidSequence)
    Ok(entry) ->
      case destination == Some(entry.value) {
        True -> Error(connection_id.InvalidConnectionId)
        False -> Ok(Nil)
      }
  }
}

/// Advance only after NEW_CONNECTION_ID was included in a successful UDP send.
pub fn record_sent(issuer: Issuer, sequence: Int) -> Issuer {
  case sequence >= 0 && sequence < issuer.next_sequence {
    True ->
      Issuer(
        ..issuer,
        highest_sent_sequence: int.max(issuer.highest_sent_sequence, sequence),
      )
    False -> issuer
  }
}

/// Charge variable local history to the endpoint's resident-memory grant.
pub fn retained_bytes(issuer: Issuer) -> Int {
  // The initial record belongs to the fixed admitted working set.
  // Additional entries cover ID/token bytes, tuple/list cells, and scalar metadata.
  { issuer.next_sequence - 1 } * { issuer.identifier_bytes + 16 + 96 }
}

/// Duplicate retirements are idempotent and never allocate replacements.
pub fn retire(
  issuer: Issuer,
  sequence: Int,
) -> Result(#(Issuer, Option(BitArray)), Error) {
  use Nil <- result.try(validate_retirement(issuer, sequence, None))
  case list.find(issuer.active, fn(entry) { entry.sequence == sequence }) {
    Error(Nil) -> Ok(#(issuer, None))
    Ok(entry) ->
      Ok(#(
        Issuer(
          ..issuer,
          active: list.filter(issuer.active, fn(value) {
            value.sequence != sequence
          }),
        ),
        Some(entry.value),
      ))
  }
}

/// Check active wire routes without exporting their contents to diagnostics.
pub fn accepts(issuer: Issuer, destination: BitArray) -> Bool {
  list.any(issuer.active, fn(entry) { entry.value == destination })
}

/// Return bounded scalar occupancy only.
pub fn snapshot(issuer: Issuer) -> Snapshot {
  let active = list.length(issuer.active)
  Snapshot(
    active,
    issuer.next_sequence,
    issuer.next_sequence - active,
    maximum_history,
  )
}

fn distinct(
  entries: List(ConnectionId),
  identifier: BitArray,
  token: BitArray,
) -> Result(Nil, Error) {
  case entries {
    [] -> Ok(Nil)
    [entry, ..] if entry.value == identifier ->
      Error(connection_id.ConnectionIdReused)
    [entry, ..rest] ->
      case entry.stateless_reset_token == Some(token) {
        True -> Error(connection_id.ResetTokenReused)
        False -> distinct(rest, identifier, token)
      }
  }
}
