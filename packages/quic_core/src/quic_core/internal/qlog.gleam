//// Bounded streaming qlog output for native QUIC endpoints.

import gleam/erlang/process.{type Pid}

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

@external(erlang, "quic_core_qlog_ffi", "stats")
fn raw_stats(handle: Pid) -> Result(#(Int, Int, Int), Int)

@external(erlang, "quic_core_qlog_ffi", "validate_directory")
fn raw_validate_directory(directory: String) -> Result(Nil, Int)

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
pub fn close(writer: Writer) -> Result(Nil, Error) {
  case raw_close(writer.handle) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

/// Snapshot dropped events, filesystem write errors, and accepted events that
/// have not finished writing. The last value never exceeds the configured
/// maximum. Counters contain no peer identifiers or protocol payloads.
pub fn stats(writer: Writer) -> Result(Stats, Error) {
  case raw_stats(writer.handle) {
    Ok(#(dropped, errors, queued)) -> Ok(Stats(dropped, errors, queued))
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
