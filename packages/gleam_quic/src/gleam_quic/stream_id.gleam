//// QUIC stream identifier classes and endpoint permissions.

import gleam/int
import gleam_quic/varint

/// Endpoint that initiates a stream.
pub type Initiator {
  Client
  Server
}

/// Whether one or both endpoints may send stream data.
pub type Direction {
  Bidirectional
  Unidirectional
}

/// Decoded stream index and class.
pub type StreamId {
  StreamId(index: Int, initiator: Initiator, direction: Direction)
}

/// An identifier or stream-index range failure.
pub type Error {
  OutOfRange
}

/// Encode a stream index and its two low-bit class fields.
pub fn encode(
  index: Int,
  initiator: Initiator,
  direction: Direction,
) -> Result(Int, Error) {
  case index < 0 || index > varint.maximum / 4 {
    True -> Error(OutOfRange)
    False -> Ok(index * 4 + initiator_bit(initiator) + direction_bit(direction))
  }
}

/// Decode a QUIC stream identifier.
pub fn decode(identifier: Int) -> Result(StreamId, Error) {
  case valid(identifier) {
    False -> Error(OutOfRange)
    True ->
      Ok(StreamId(
        identifier / 4,
        initiator_from_bit(int.bitwise_and(identifier, 1)),
        direction_from_bit(int.bitwise_and(identifier, 2)),
      ))
  }
}

/// Return whether this endpoint is permitted to send STREAM data.
pub fn can_send(identifier: Int, endpoint: Initiator) -> Bool {
  case valid(identifier) {
    False -> False
    True -> {
      let initiator = initiator_from_bit(int.bitwise_and(identifier, 1))
      let direction = direction_from_bit(int.bitwise_and(identifier, 2))
      direction == Bidirectional || initiator == endpoint
    }
  }
}

/// Return whether this endpoint is permitted to receive STREAM data.
pub fn can_receive(identifier: Int, endpoint: Initiator) -> Bool {
  case valid(identifier) {
    False -> False
    True -> {
      let initiator = initiator_from_bit(int.bitwise_and(identifier, 1))
      let direction = direction_from_bit(int.bitwise_and(identifier, 2))
      direction == Bidirectional || initiator != endpoint
    }
  }
}

fn valid(identifier: Int) -> Bool {
  identifier >= 0 && identifier <= varint.maximum
}

fn initiator_bit(initiator: Initiator) -> Int {
  case initiator {
    Client -> 0
    Server -> 1
  }
}

fn direction_bit(direction: Direction) -> Int {
  case direction {
    Bidirectional -> 0
    Unidirectional -> 2
  }
}

fn initiator_from_bit(bit: Int) -> Initiator {
  case bit {
    0 -> Client
    _ -> Server
  }
}

fn direction_from_bit(bit: Int) -> Direction {
  case bit {
    0 -> Bidirectional
    _ -> Unidirectional
  }
}
