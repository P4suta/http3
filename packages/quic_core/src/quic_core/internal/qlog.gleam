//// Bounded streaming qlog output for native QUIC endpoints.

import gleam/bit_array
import gleam/erlang/process.{type Pid, type Subject}
import gleam/option.{type Option, None, Some}
import gleam/string
import quic_core/internal/runtime/qlog_close_deadline
import quic_core/internal/udp

/// One open JSON-SEQ qlog trace.
pub opaque type Writer {
  Writer(handle: Pid, epoch_milliseconds: Int)
}

/// The endpoint perspective recorded in the trace header.
pub type VantagePoint {
  Client
  Server
}

/// A filesystem or output-device failure.
pub type Error {
  InvalidDirectory
  InvalidLimit
  OpenFailed(Int)
  WriteFailed(Int)
}

/// Bounded asynchronous writer health without trace contents.
pub type Stats {
  Stats(dropped_events: Int, write_errors: Int, queued_events: Int)
}

@internal
pub type NativeCleanupTicket

/// Private ownership receipt.
/// A failed start can retain unconfirmed filesystem work, so the absence of a writer does not prove that its reservation is free.
pub opaque type CleanupTicket {
  NoCleanup
  NativeCleanup(NativeCleanupTicket)
}

/// Whether every known owner and child of this opening has actually exited.
/// Pending also covers an opening whose filesystem ownership is unconfirmed.
pub type CleanupState {
  Pending
  Released
}

/// Private requests from a qlog writer to the endpoint's existing memory ledger.
/// They contain only an opaque reservation key and finite counts.
/// No path, endpoint, payload, process identifier or exception crosses this boundary.
pub type BudgetRequest {
  ReserveEvent(reservation: BitArray, bytes: Int, reply: Subject(Bool))
  ReleaseEvents(reservation: BitArray, bytes: Int, events: Int)
}

@external(erlang, "quic_core_qlog_ffi", "open_accounted")
fn raw_open_accounted(
  directory: String,
  vantage_point: Int,
  maximum_queued_events: Int,
) -> #(Result(Pid, Int), NativeCleanupTicket)

@external(erlang, "quic_core_qlog_ffi", "cleanup_state")
fn raw_cleanup_state(ticket: NativeCleanupTicket) -> CleanupState

@external(erlang, "quic_core_qlog_ffi", "cleanup_owners")
fn raw_cleanup_owners(ticket: NativeCleanupTicket) -> List(Pid)

/// Observe completion without starting cleanup, waiting, or consuming messages.
pub fn cleanup_state(ticket: CleanupTicket) -> CleanupState {
  case ticket {
    NoCleanup -> Released
    NativeCleanup(ticket) -> raw_cleanup_state(ticket)
  }
}

/// At most two processes whose DOWN notices can make cleanup releasable.
/// Both must be dead even after the native child-join flag is confirmed.
pub fn cleanup_owners(ticket: CleanupTicket) -> List(Pid) {
  case ticket {
    NoCleanup -> []
    NativeCleanup(ticket) -> raw_cleanup_owners(ticket)
  }
}

/// Extract the native receipt for the bounded admission reconciler.
/// The handle remains opaque and never exposes its owners, path, device or cleanup flag.
@internal
pub fn native_cleanup_ticket(
  ticket: CleanupTicket,
) -> Option(NativeCleanupTicket) {
  case ticket {
    NoCleanup -> None
    NativeCleanup(ticket) -> Some(ticket)
  }
}

@external(erlang, "quic_core_qlog_ffi", "open")
fn raw_open(
  directory: String,
  vantage_point: Int,
  maximum_queued_events: Int,
) -> Result(Pid, Int)

@external(erlang, "quic_core_qlog_ffi", "event")
fn raw_event(
  handle: Pid,
  event: Int,
  relative_milliseconds: Int,
  value: Int,
  auxiliary: Int,
) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "frame_event")
fn raw_frame_event(
  handle: Pid,
  event: Int,
  relative_milliseconds: Int,
  stream_id: Int,
  frame_type: Int,
  payload_bytes: Int,
) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "close")
fn raw_close(handle: Pid) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "close_confirmed")
fn raw_close_confirmed(handle: Pid) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "close_confirmed_until")
fn raw_close_confirmed_until(
  handle: Pid,
  deadline_milliseconds: Int,
) -> Result(Nil, Int)

/// Additional caller wait required by the native confirmed-close operation.
///
/// The native implementation owns this scalar so its deadline and the public adapter allowance cannot drift apart.
@external(erlang, "quic_core_qlog_ffi", "close_completion_allowance_milliseconds")
pub fn close_completion_allowance_milliseconds() -> Int

/// Complete a writer taken exactly once from its endpoint owner.
/// A writer which died without acknowledging flush must not become success here.
pub fn close_confirmed(writer: Writer) -> Result(Nil, Error) {
  case raw_close_confirmed(writer.handle) {
    Ok(Nil) -> Ok(Nil)
    Error(code) -> Error(WriteFailed(code))
  }
}

/// Compatibility wrapper for code that only retains a remaining duration.
/// It establishes one absolute boundary at this function's entrance, and the native maximum still applies.
/// Lifecycle code should use `close_confirmed_until` so scheduling between phases cannot rebase time.
pub fn close_confirmed_within(
  writer: Writer,
  remaining_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    qlog_close_deadline.from_remaining(
      udp.monotonic_millisecond(),
      remaining_milliseconds,
      close_completion_allowance_milliseconds(),
    )
  {
    Ok(deadline_milliseconds) ->
      case raw_close_confirmed_until(writer.handle, deadline_milliseconds) {
        Ok(Nil) -> Ok(Nil)
        Error(code) -> Error(WriteFailed(code))
      }
    Error(qlog_close_deadline.DeadlineExpired) -> Error(WriteFailed(6))
    Error(_) -> Error(WriteFailed(1))
  }
}

/// Complete an affine writer within a caller-owned absolute deadline in the `quic_core/diagnostics.monotonic_milliseconds` clock domain.
///
/// The native qlog allowance may shorten this boundary.
/// No layer reconstructs it from a remaining duration, so a scheduler stall cannot extend shutdown.
pub fn close_confirmed_until(
  writer: Writer,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  case
    qlog_close_deadline.effective(
      udp.monotonic_millisecond(),
      deadline_milliseconds,
      close_completion_allowance_milliseconds(),
    )
  {
    Ok(effective_deadline) ->
      case raw_close_confirmed_until(writer.handle, effective_deadline) {
        Ok(Nil) -> Ok(Nil)
        Error(code) -> Error(WriteFailed(code))
      }
    Error(qlog_close_deadline.DeadlineExpired) -> Error(WriteFailed(6))
    Error(_) -> Error(WriteFailed(1))
  }
}

@external(erlang, "quic_core_qlog_ffi", "bind_owner")
fn raw_bind_owner(handle: Pid, owner: Pid) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "bind_budget")
fn raw_bind_budget(
  handle: Pid,
  requests: Subject(BudgetRequest),
  reservation: BitArray,
  event_bytes: Int,
) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "bind_admission")
fn raw_bind_admission(
  handle: Pid,
  reservation: reservation,
  event_bytes: Int,
) -> Result(Nil, Int)

@external(erlang, "quic_core_qlog_ffi", "stats")
fn raw_stats(handle: Pid) -> Result(#(Int, Int, Int), Int)

@external(erlang, "quic_core_qlog_ffi", "terminal_snapshot")
fn raw_terminal_snapshot(handle: Pid) -> Result(#(Int, Int), Int)

@external(erlang, "quic_core_qlog_ffi", "validate_directory")
fn raw_validate_directory(directory: String) -> Result(Nil, Int)

/// Validate endpoint configuration without opening files or spawning workers.
/// Writability is checked only after the connection reserves diagnostic work.
pub fn validate_path(directory: String) -> Result(Nil, Error) {
  case
    directory != ""
    && bit_array.byte_size(bit_array.from_string(directory)) <= 4096
    && !string.contains(directory, "\u{0}")
  {
    True -> Ok(Nil)
    False -> Error(InvalidDirectory)
  }
}

/// Verify that a qlog directory can be created and written without keeping a
/// trace file open.
pub fn validate_directory(directory: String) -> Result(Nil, Error) {
  case directory == "" {
    True -> Error(InvalidDirectory)
    False ->
      case raw_validate_directory(directory) {
        Ok(Nil) -> Ok(Nil)
        Error(1) -> Error(InvalidDirectory)
        Error(error) -> Error(OpenFailed(error))
      }
  }
}

/// Open a qlog JSON Text Sequence in an explicitly selected directory.
///
/// `maximum_queued_events` includes the one event currently being written to
/// the device. Admission therefore bounds all accepted but unfinished events,
/// independent of filesystem or scheduler progress. Admission also owns the
/// sole cross-producer timestamp watermark; it clamps an accepted observation
/// to the preceding accepted time without retaining timestamp history.
pub fn open(
  directory: String,
  vantage_point: VantagePoint,
  now_milliseconds: Int,
  maximum_queued_events: Int,
) -> Result(Writer, Error) {
  case directory == "" || now_milliseconds < 0 {
    True -> Error(InvalidDirectory)
    False
      if maximum_queued_events <= 0 || maximum_queued_events > 2_147_483_647
    -> Error(InvalidLimit)
    False ->
      case
        raw_open(
          directory,
          case vantage_point {
            Client -> 1
            Server -> 2
          },
          maximum_queued_events,
        )
      {
        Ok(handle) -> Ok(Writer(handle, now_milliseconds))
        Error(error) -> Error(OpenFailed(error))
      }
  }
}

/// Open against an already-funded endpoint reservation.
/// Every native result carries a cleanup receipt, including failure before writer publication.
pub fn open_accounted(
  directory: String,
  vantage_point: VantagePoint,
  now_milliseconds: Int,
  maximum_queued_events: Int,
) -> #(Result(Writer, Error), CleanupTicket) {
  case directory == "" || now_milliseconds < 0 {
    True -> #(Error(InvalidDirectory), NoCleanup)
    False
      if maximum_queued_events <= 0 || maximum_queued_events > 2_147_483_647
    -> #(Error(InvalidLimit), NoCleanup)
    False -> {
      let #(outcome, ticket) =
        raw_open_accounted(
          directory,
          case vantage_point {
            Client -> 1
            Server -> 2
          },
          maximum_queued_events,
        )
      let writer = case outcome {
        Ok(handle) -> Ok(Writer(handle, now_milliseconds))
        Error(error) -> Error(OpenFailed(error))
      }
      #(writer, NativeCleanup(ticket))
    }
  }
}

/// Record that a client attempted or a server accepted a connection.
pub fn connection_started(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 1, now_milliseconds, 0, 0)
}

/// Record one received UDP datagram without retaining payload data.
pub fn datagram_received(
  writer: Writer,
  now_milliseconds: Int,
  bytes: Int,
) -> Nil {
  write(writer, 2, now_milliseconds, 1, bytes)
}

/// Record one sent UDP datagram without retaining payload data.
pub fn datagram_sent(writer: Writer, now_milliseconds: Int, bytes: Int) -> Nil {
  write(writer, 3, now_milliseconds, 1, bytes)
}

/// Record a received UDP batch when only the datagram count is available.
pub fn datagrams_received(
  writer: Writer,
  now_milliseconds: Int,
  count: Int,
) -> Nil {
  case count > 0 {
    True -> write(writer, 2, now_milliseconds, count, 0)
    False -> Nil
  }
}

/// Record a sent UDP batch when only the datagram count is available.
pub fn datagrams_sent(
  writer: Writer,
  now_milliseconds: Int,
  count: Int,
) -> Nil {
  case count > 0 {
    True -> write(writer, 3, now_milliseconds, count, 0)
    False -> Nil
  }
}

/// Record one received QUIC packet without connection IDs, packet numbers,
/// frame contents, or any other correlatable wire value.
pub fn packet_received(
  writer: Writer,
  now_milliseconds: Int,
  packet_type: Int,
  bytes: Int,
) -> Nil {
  write(writer, 6, now_milliseconds, packet_type, bytes)
}

/// Record one sent QUIC packet under the same strict metadata profile.
pub fn packet_sent(
  writer: Writer,
  now_milliseconds: Int,
  packet_type: Int,
  bytes: Int,
) -> Nil {
  write(writer, 7, now_milliseconds, packet_type, bytes)
}

/// Record that a traffic-key class became usable, never the key itself.
pub fn key_updated(
  writer: Writer,
  now_milliseconds: Int,
  key_type: Int,
) -> Nil {
  write(writer, 8, now_milliseconds, key_type, 0)
}

/// Record that a traffic-key class was discarded, never the key itself.
pub fn key_discarded(
  writer: Writer,
  now_milliseconds: Int,
  key_type: Int,
) -> Nil {
  write(writer, 9, now_milliseconds, key_type, 0)
}

/// Record the two byte-valued recovery metrics most useful for pressure
/// diagnosis. RTT metrics remain available through the typed snapshot API.
pub fn recovery_metrics(
  writer: Writer,
  now_milliseconds: Int,
  congestion_window: Int,
  bytes_in_flight: Int,
) -> Nil {
  write(writer, 10, now_milliseconds, congestion_window, bytes_in_flight)
}

/// Record a semantic congestion-controller state without native internals.
pub fn congestion_state_updated(
  writer: Writer,
  now_milliseconds: Int,
  state: Int,
) -> Nil {
  write(writer, 11, now_milliseconds, state, 0)
}

/// Record a congestion state transition together with its non-secret cause.
pub fn congestion_state_updated_with_trigger(
  writer: Writer,
  now_milliseconds: Int,
  state: Int,
  trigger: Int,
) -> Nil {
  write(writer, 12, now_milliseconds, state, trigger)
}

/// Record local or remote HTTP/3 settings observation without field values.
pub fn http3_parameters_set(
  writer: Writer,
  now_milliseconds: Int,
  initiator: Int,
) -> Nil {
  write(writer, 14, now_milliseconds, initiator, 0)
}

/// Record a known HTTP/3 stream role without any stream contents.
pub fn http3_stream_type_set(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  stream_type: Int,
) -> Nil {
  write(writer, 15, now_milliseconds, stream_id, stream_type)
}

/// Record one locally created HTTP/3 frame with only its stream, kind, and
/// bounded payload length. Header fields and payload bytes are never retained.
pub fn http3_frame_created(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  frame_type: Int,
  payload_bytes: Int,
) -> Nil {
  write_frame(
    writer,
    12,
    now_milliseconds,
    stream_id,
    frame_type,
    payload_bytes,
  )
}

/// Record one parsed HTTP/3 frame under the same strict metadata profile.
pub fn http3_frame_parsed(
  writer: Writer,
  now_milliseconds: Int,
  stream_id: Int,
  frame_type: Int,
  payload_bytes: Int,
) -> Nil {
  write_frame(
    writer,
    13,
    now_milliseconds,
    stream_id,
    frame_type,
    payload_bytes,
  )
}

/// Record a bounded application diagnostic code without accepting a message,
/// payload, header, endpoint, or implementation term.
pub fn application_error(
  writer: Writer,
  now_milliseconds: Int,
  code: Int,
) -> Nil {
  write(writer, 18, now_milliseconds, code, 0)
}

/// Record that probing has advanced to an active migration attempt.
pub fn migration_started(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 16, now_milliseconds, 0, 0)
}

/// Record that a candidate path was abandoned without either endpoint tuple.
pub fn migration_abandoned(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 17, now_milliseconds, 0, 0)
}

/// Record an authenticated path migration or NAT rebinding.
pub fn path_updated(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 4, now_milliseconds, 0, 0)
}

/// Record local connection shutdown.
pub fn connection_closed(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 5, now_milliseconds, 0, 0)
}

/// Flush and close the trace idempotently.
/// A live writer confirms its admission,
/// guardian, device worker and file I/O process have exited before reporting success.
/// Shutdown has a four-second absolute flush deadline and a one-second child join allowance.
/// Expiry or a full set of 32 close waiters returns WriteFailed.
/// An independent guardian allows five seconds after owner exit for normal shutdown, then terminates an unresponsive admission process and joins its children within one second.
/// Filesystem setup before admission is synchronous.
pub fn close(writer: Writer) -> Result(Nil, Error) {
  case raw_close(writer.handle) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Bind one connection actor in addition to the endpoint that opened the trace.
/// Both the admission process and independent guardian confirm their monitors before success.
/// The original endpoint continues to supervise the writer.
pub fn bind_owner(writer: Writer, owner: Pid) -> Result(Nil, Error) {
  case raw_bind_owner(writer.handle, owner) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Bind an endpoint-owned trace to the same aggregate ledger as transport buffers.
/// Binding completes before the writer is published to a connection.
/// Every ordinary accepted record acquires one `event_bytes` charge and returns it only after device completion; cleanup releases any residue by reservation key.
/// One exactly-once `connection_closed` record uses the fixed writer working set and its own queue slot, so listener-led shutdown cannot form a budget callback cycle while the ordinary queue is full.
/// If an owner exits before it can make the synchronous terminal call, the writer consumes that same slot locally before closing.
pub fn bind_budget(
  writer: Writer,
  requests: Subject(BudgetRequest),
  reservation: BitArray,
  event_bytes: Int,
) -> Result(Nil, Error) {
  case raw_bind_budget(writer.handle, requests, reservation, event_bytes) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Bind a client trace to the stable admission token acquired before any connection or filesystem work.
/// The token type remains parametric here so qlog does not create an import cycle with its lifecycle owner.
pub fn bind_admission(
  writer: Writer,
  reservation: reservation,
  event_bytes: Int,
) -> Result(Nil, Error) {
  case raw_bind_admission(writer.handle, reservation, event_bytes) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Snapshot dropped events, filesystem write errors, and accepted events that
/// have not finished writing. An endpoint-bound writer can report one more
/// than the configured ordinary queue maximum while its prepaid terminal
/// `connection_closed` record is pending. Drop/error counters saturate at
/// 2_147_483_647 and contain no peer identifiers or protocol payloads.
pub fn stats(writer: Writer) -> Result(Stats, Error) {
  case raw_stats(writer.handle) {
    Ok(#(dropped, errors, queued)) -> Ok(Stats(dropped, errors, queued))
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Payload-free endpoint terminal state and duplicate-refusal count.
/// States are fixed: 0 has no prepaid slot, 1 is available, and 2 is accepted.
/// This internal seam exists for lifecycle and queue-admission verification.
pub fn terminal_snapshot(writer: Writer) -> Result(#(Int, Int), Error) {
  case raw_terminal_snapshot(writer.handle) {
    Ok(snapshot) -> Ok(snapshot)
    Error(error) -> Error(WriteFailed(error))
  }
}

fn write(
  writer: Writer,
  event: Int,
  now_milliseconds: Int,
  value: Int,
  auxiliary: Int,
) -> Nil {
  let relative = case now_milliseconds >= writer.epoch_milliseconds {
    True -> now_milliseconds - writer.epoch_milliseconds
    False -> 0
  }
  let _diagnostic_result =
    raw_event(writer.handle, event, relative, value, auxiliary)
  Nil
}

fn write_frame(
  writer: Writer,
  event: Int,
  now_milliseconds: Int,
  stream_id: Int,
  frame_type: Int,
  payload_bytes: Int,
) -> Nil {
  let relative = case now_milliseconds >= writer.epoch_milliseconds {
    True -> now_milliseconds - writer.epoch_milliseconds
    False -> 0
  }
  let _diagnostic_result =
    raw_frame_event(
      writer.handle,
      event,
      relative,
      stream_id,
      frame_type,
      payload_bytes,
    )
  Nil
}
