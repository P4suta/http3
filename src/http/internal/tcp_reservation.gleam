//// A connection grant acquired before DNS and socket creation.

import gleam/result
import http/error
import http/internal/transport

/// Ownership callbacks for one admitted TCP connection.
pub opaque type Reservation {
  Reservation(
    attach: fn(transport.Socket) -> Result(Nil, error.Error),
    cancel: fn() -> Nil,
  )
}

/// Construct a grant supplied by the reusable client's connection controller.
pub fn new(
  attach: fn(transport.Socket) -> Result(Nil, error.Error),
  cancel: fn() -> Nil,
) -> Reservation {
  Reservation(attach:, cancel:)
}

/// One-shot exchanges have no shared controller.
pub fn unmanaged() -> Reservation {
  new(fn(_) { Ok(Nil) }, fn() { Nil })
}

/// Failed resolution, connection, or adoption always releases the grant.
/// The returned cancellation remains available until lifecycle attachment.
pub fn connect(
  reserve: fn(String) -> Result(Reservation, error.Error),
  origin: String,
  dial: fn() -> Result(transport.Socket, error.Error),
) -> Result(#(transport.Socket, fn() -> Nil), error.Error) {
  use reservation <- result.try(reserve(origin))
  case dial() {
    Error(failure) -> {
      reservation.cancel()
      Error(failure)
    }
    Ok(socket) ->
      case reservation.attach(socket) {
        Ok(Nil) -> Ok(#(socket, reservation.cancel))
        Error(failure) -> {
          let _closed = transport.close(socket)
          reservation.cancel()
          Error(failure)
        }
      }
  }
}
