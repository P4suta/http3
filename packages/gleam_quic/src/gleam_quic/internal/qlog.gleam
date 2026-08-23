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
  OpenFailed(Int)
  WriteFailed(Int)
}

@external(erlang, "gleam_quic_qlog_ffi", "open")
fn raw_open(directory: String, vantage_point: Int) -> Result(Pid, Int)

@external(erlang, "gleam_quic_qlog_ffi", "event")
fn raw_event(
  handle: Pid,
  event: Int,
  relative_milliseconds: Int,
  value: Int,
) -> Result(Nil, Int)

@external(erlang, "gleam_quic_qlog_ffi", "close")
fn raw_close(handle: Pid) -> Result(Nil, Int)

/// Open a qlog JSON Text Sequence in an explicitly selected directory.
pub fn open(
  directory: String,
  vantage_point: VantagePoint,
  now_milliseconds: Int,
) -> Result(Writer, Error) {
  case directory == "" || now_milliseconds < 0 {
    True -> Error(InvalidDirectory)
    False ->
      case
        raw_open(directory, case vantage_point {
          Client -> 1
          Server -> 2
        })
      {
        Ok(handle) -> Ok(Writer(handle, now_milliseconds))
        Error(error) -> Error(OpenFailed(error))
      }
  }
}

/// Record that a client attempted or a server accepted a connection.
pub fn connection_started(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 1, now_milliseconds, 0)
}

/// Record one received UDP datagram without retaining payload data.
pub fn datagram_received(
  writer: Writer,
  now_milliseconds: Int,
  bytes: Int,
) -> Nil {
  write(writer, 2, now_milliseconds, bytes)
}

/// Record one sent UDP datagram without retaining payload data.
pub fn datagram_sent(writer: Writer, now_milliseconds: Int, bytes: Int) -> Nil {
  write(writer, 3, now_milliseconds, bytes)
}

/// Record an authenticated path migration or NAT rebinding.
pub fn path_updated(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 4, now_milliseconds, 0)
}

/// Record local connection shutdown.
pub fn connection_closed(writer: Writer, now_milliseconds: Int) -> Nil {
  write(writer, 5, now_milliseconds, 0)
}

/// Record that a server UDP listener is ready.
pub fn server_listening(
  writer: Writer,
  now_milliseconds: Int,
  port: Int,
) -> Nil {
  write(writer, 6, now_milliseconds, port)
}

/// Flush and close the trace idempotently.
pub fn close(writer: Writer) -> Result(Nil, Error) {
  case raw_close(writer.handle) {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> Error(WriteFailed(error))
  }
}

fn write(writer: Writer, event: Int, now_milliseconds: Int, value: Int) -> Nil {
  let relative = case now_milliseconds >= writer.epoch_milliseconds {
    True -> now_milliseconds - writer.epoch_milliseconds
    False -> 0
  }
  let _diagnostic_result = raw_event(writer.handle, event, relative, value)
  Nil
}
