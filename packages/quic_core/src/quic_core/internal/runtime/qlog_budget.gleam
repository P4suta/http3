//// Qlog reservations are separate from transport grants.
//// Shrinking a stream buffer, releasing a connection, and receiving a duplicate DOWN therefore cannot return memory still held by its diagnostic actors or queued events.

import quic_core/internal/runtime/budget

/// Funds the temporary 65,536-word cleanup observer at 64-bit word size and conservative headroom for the four owners, their control messages, the bounded path, cleanup receipt, and transient fixed-schema serialization.
/// This leaves one complete 16 KiB quantum below the 1 MiB fixed charge for the prepaid terminal record described below.
/// This is charged once for each live trace.
/// Queued records are charged separately as they are accepted, so an idle trace does not reserve its entire configured queue in advance.
const runtime_working_bytes = 1_032_192

/// Each accepted event has a bounded encoded record, its binary reference,
/// queue links, and conservative collection/serialization headroom.
/// The one event being written is included in the configured event count.
const event_bytes = 1024

/// One reservation funds three library actors and one OTP file device.
/// During failed startup the cleanup observer replaces admission.
pub fn worker_slots() -> Int {
  4
}

fn rounded(bytes: Int) -> Int {
  let quantum = budget.quantum()
  { { bytes + quantum - 1 } / quantum } * quantum
}

/// Whole-quanta working-set charge before any qlog actor or filesystem request is created.
/// This remains held until every diagnostic owner and child joins.
pub fn connection_reservation_bytes() -> Int {
  let #(runtime, terminal) = connection_reservation_breakdown()
  rounded(runtime + terminal)
}

/// Exact fixed-charge components: runtime working set and one terminal record.
/// Both are whole ledger quanta.
/// Keeping this arithmetic executable prevents a future record-size change from silently consuming the terminal shutdown slot.
pub fn connection_reservation_breakdown() -> #(Int, Int) {
  #(rounded(runtime_working_bytes), rounded(event_bytes))
}

/// The transport-ledger charge for one accepted but unfinished qlog event.
/// One record is at most 512 encoded bytes, while this 16 KiB quantum also covers its queue cell, message envelope, binary references and allocator slack.
/// The deliberate over-count keeps admission on the safe side.
pub fn event_reservation_bytes() -> Int {
  rounded(event_bytes)
}

/// Conservative allowance for a writer and its admitted event queue.
pub fn reservation_bytes(maximum_events: Int) -> Int {
  connection_reservation_bytes() + rounded(maximum_events * event_bytes)
}

/// This key is longer than any valid QUIC connection ID, so no transport grant can name or shed a diagnostic reservation, even after future CID changes.
pub fn reservation_key(identifier: BitArray) -> BitArray {
  <<"qlog-memory-reservation":utf8, identifier:bits>>
}

/// Recover the bounded transport identifier from an internal reservation key.
/// This avoids a linear scan of all live traces for every qlog event.
pub fn reservation_identifier(key: BitArray) -> Result(BitArray, Nil) {
  case key {
    <<"qlog-memory-reservation":utf8, identifier:bits>> -> Ok(identifier)
    _ -> Error(Nil)
  }
}
