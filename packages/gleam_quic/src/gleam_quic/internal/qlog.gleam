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

@external(erlang, "gleam_quic_qlog_ffi", "open")
fn raw_open(
  directory: String,
  vantage_point: Int,
  maximum_queued_events: Int,
) -> Result(Pid, Int)

@external(erlang, "gleam_quic_qlog_ffi", "event")
fn raw_event(
  handle: Pid,
  event: Int,
  relative_milliseconds: Int,
  value: Int,
  auxiliary: Int,
) -> Result(Nil, Int)

@external(erlang, "gleam_quic_qlog_ffi", "close")
fn raw_close(handle: Pid) -> Result(Nil, Int)

@external(erlang, "gleam_quic_qlog_ffi", "stats")
fn raw_stats(handle: Pid) -> Result(#(Int, Int, Int), Int)

@external(erlang, "gleam_quic_qlog_ffi", "validate_directory")
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

/// Snapshot dropped events, filesystem write errors, and currently queued
/// events. Counters contain no peer identifiers or protocol payloads.
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
