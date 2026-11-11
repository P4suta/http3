//// Client configuration copies share diagnostic admission, without allocating an actor for unused configuration.
//// Unconfirmed openings remain charged;
//// absence of a returned writer is never treated as evidence of cleanup.

import gleam/option.{type Option, None, Some}
import quic_core/internal/qlog
import quic_core/internal/runtime/qlog_budget

pub type Identity

pub type Reservation

/// Payload-free counters for the finite late-cleanup registry.
pub type ReconciliationStats {
  ReconciliationStats(
    attempts: Int,
    admitted: Int,
    refused: Int,
    recovered: Int,
    expired: Int,
    retained: Int,
  )
}

@external(erlang, "quic_core_qlog_admission_ffi", "new")
pub fn new() -> Identity

@external(erlang, "quic_core_qlog_admission_ffi", "event_snapshot")
pub fn event_snapshot(identity: Identity) -> #(Int, Int, Int, Int, Int)

@external(erlang, "quic_core_qlog_admission_ffi", "snapshot")
pub fn allocation_snapshot(identity: Identity) -> #(Int, Int)

@external(erlang, "quic_core_qlog_admission_ffi", "reconciliation_snapshot")
fn raw_reconciliation_snapshot(
  identity: Identity,
) -> #(Int, Int, Int, Int, Int, Int)

/// Snapshot finite registry counters without a path, endpoint, payload,
/// process identity, socket or exception.
pub fn reconciliation_snapshot(identity: Identity) -> ReconciliationStats {
  let #(attempts, admitted, refused, recovered, expired, retained) =
    raw_reconciliation_snapshot(identity)
  ReconciliationStats(attempts, admitted, refused, recovered, expired, retained)
}

/// Reserve one core writer and bind at most one unopened, same-ledger scalar reservation to its confirmed settlement.
@external(erlang, "quic_core_qlog_admission_ffi", "reserve_linked")
pub fn reserve_linked(
  identity: Identity,
  charge: Int,
  maximum: Int,
  connections: Int,
  dependent: Option(Reservation),
) -> Result(Reservation, Int)

/// Charge diagnostic state owned by a higher protocol layer in the same ledger.
/// An already-full connection set is reported before byte pressure,
/// while the later core writer remains the only operation that claims a slot.
@external(erlang, "quic_core_qlog_admission_ffi", "reserve_auxiliary")
pub fn reserve_auxiliary(
  identity: Identity,
  charge: Int,
  maximum: Int,
  connections: Int,
) -> Result(Reservation, Int)

@external(erlang, "quic_core_qlog_admission_ffi", "begin_open")
pub fn begin_open(reservation: Reservation) -> Result(Nil, Nil)

/// Safe only once the bootstrap group is joined.
/// Begun I/O remains charged.
@external(erlang, "quic_core_qlog_admission_ffi", "release_unused")
pub fn release_unused(reservation: Reservation) -> Nil

@external(erlang, "quic_core_qlog_admission_ffi", "release_confirmed")
pub fn release_confirmed(reservation: Reservation) -> Nil

@external(erlang, "quic_core_qlog_admission_ffi", "reservation_snapshot")
fn reservation_snapshot(reservation: Reservation) -> #(Int, Int, Int, Int)

/// Confirm the affine reservation and every dynamic event charge returned.
/// This is a payload-free lifecycle observation used before close success.
pub fn reservation_returned(reservation: Reservation) -> Bool {
  let #(state, active, held_events, _) = reservation_snapshot(reservation)
  state == 4 && active == 0 && held_events == 0
}

/// A confirmed ticket returns its charge immediately.
/// A pending ticket is retained by one bounded reconciler which observes at most two native owners and returns the charge after their later confirmed join.
/// The identity holds at most 64 such tickets, and every observer stops after seven seconds.
@external(erlang, "quic_core_qlog_admission_ffi", "collect")
fn collect_native(
  reservation: Reservation,
  ticket: qlog.NativeCleanupTicket,
) -> Nil

pub fn collect(reservation: Reservation, ticket: qlog.CleanupTicket) -> Nil {
  case qlog.native_cleanup_ticket(ticket) {
    None -> release_confirmed(reservation)
    Some(ticket) -> collect_native(reservation, ticket)
  }
}

/// Bind a published writer to this begun reservation.
/// Each accepted event is then charged to the stable Client identity and each device completion returns its charge.
pub fn bind(writer: qlog.Writer, reservation: Reservation) -> Result(Nil, Nil) {
  case
    qlog.bind_admission(
      writer,
      reservation,
      qlog_budget.event_reservation_bytes(),
    )
  {
    Ok(Nil) -> Ok(Nil)
    Error(_) -> Error(Nil)
  }
}
