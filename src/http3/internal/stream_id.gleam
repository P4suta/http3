//// The HTTP/3-side copy of the QUIC stream identifier classes and endpoint
//// permissions defined by RFC 9000 section 2.1.
////
//// HTTP/3 classifies every stream it sees by initiator and direction before it
//// can route control, push, QPACK and request streams, so the root package
//// needs the helpers too. They are duplicated here rather than imported so
//// that root modules stop depending on `gleam_quic/stream_id`, which the core
//// package declares internal. One dependency remains: `native/session` still
//// imports the core module as `quic_stream_id`, because the core `Direction`
//// type is what `transport.open_stream` takes and the two types are distinct.
//// Removing that last import needs a transport-facing change and is not part
//// of this step.
////
//// Semantics are identical to the core module and must stay that way, so this
//// file mirrors it line for line: same declaration order, same signatures
//// without argument labels, and the same bodies. The core package turns the
//// `label_possible` and `prefer_guard_clause` glinter rules off for all of its
//// modules; the root package enables them, so the mirrored declarations carry
//// per-rule `nolint` annotations instead of being rewritten into a shape that
//// would no longer diff against the core file.
////
//// The two least significant bits of a stream identifier carry its class: bit
//// 0 names the initiator (0 client, 1 server) and bit 1 the direction (0
//// bidirectional, 1 unidirectional). The remaining bits hold the stream index,
//// and the identifier as a whole is a 62-bit variable-length integer.

import gleam/int
import http3/internal/varint

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

// nolint: label_possible -- mirrors the core module's signature exactly.
/// Encode a stream index and its two low-bit class fields.
pub fn encode(
  index: Int,
  initiator: Initiator,
  direction: Direction,
) -> Result(Int, Error) {
  // nolint: prefer_guard_clause -- mirrors the core module's body exactly.
  case index < 0 || index > varint.maximum / 4 {
    True -> Error(OutOfRange)
    False -> Ok(index * 4 + initiator_bit(initiator) + direction_bit(direction))
  }
}

/// Decode a QUIC stream identifier.
pub fn decode(identifier: Int) -> Result(StreamId, Error) {
  // nolint: prefer_guard_clause -- mirrors the core module's body exactly.
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

// nolint: label_possible -- mirrors the core module's signature exactly.
/// Return whether this endpoint is permitted to send STREAM data.
pub fn can_send(identifier: Int, endpoint: Initiator) -> Bool {
  // nolint: prefer_guard_clause -- mirrors the core module's body exactly.
  case valid(identifier) {
    False -> False
    True -> {
      let initiator = initiator_from_bit(int.bitwise_and(identifier, 1))
      let direction = direction_from_bit(int.bitwise_and(identifier, 2))
      direction == Bidirectional || initiator == endpoint
    }
  }
}

// nolint: label_possible -- mirrors the core module's signature exactly.
/// Return whether this endpoint is permitted to receive STREAM data.
pub fn can_receive(identifier: Int, endpoint: Initiator) -> Bool {
  // nolint: prefer_guard_clause -- mirrors the core module's body exactly.
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
