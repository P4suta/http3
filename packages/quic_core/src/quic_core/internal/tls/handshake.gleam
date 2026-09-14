//// Bounded incremental TLS 1.3 handshake-message envelopes for QUIC CRYPTO.

import gleam/bit_array

/// A TLS handshake message type.
pub type MessageType {
  ClientHello
  ServerHello
  NewSessionTicket
  EndOfEarlyData
  EncryptedExtensions
  Certificate
  CertificateRequest
  CertificateVerify
  Finished
  KeyUpdate
  MessageHash
  Unknown(Int)
}

/// One complete TLS handshake message without a record-layer wrapper.
pub type Message {
  Message(message_type: MessageType, body: BitArray)
}

/// The result of attempting to decode one message from ordered CRYPTO bytes.
pub type Decoded {
  NeedMore
  Complete(Message, BitArray)
}

/// Peer-controlled TLS handshake bounds.
pub type Limits {
  Limits(maximum_message_length: Int, maximum_buffered_length: Int)
}

/// A TLS handshake envelope failure.
pub type Error {
  NonByteAligned
  InvalidLimits
  InvalidMessageType(Int)
  MessageTooLarge(Int)
  BufferTooLarge(Int)
}

/// Conservative defaults for one TLS handshake flight.
pub fn default_limits() -> Limits {
  Limits(1_048_576, 4_194_304)
}

/// Decode one complete message or report that more ordered CRYPTO bytes are needed.
pub fn decode_next(
  bytes bytes: BitArray,
  limits limits: Limits,
) -> Result(Decoded, Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case valid_limits(limits) {
        False -> Error(InvalidLimits)
        True -> decode_aligned(bytes, limits)
      }
  }
}

/// Encode one TLS handshake message with a 24-bit body length.
pub fn encode(
  message message: Message,
  maximum_message_length maximum_message_length: Int,
) -> Result(BitArray, Error) {
  let Message(message_type, body) = message
  case bit_array.bit_size(body) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let body_length = bit_array.byte_size(body)
      case maximum_message_length < 0 || maximum_message_length > 0xff_ffff {
        True -> Error(InvalidLimits)
        False if body_length > maximum_message_length ->
          Error(MessageTooLarge(body_length))
        False if body_length > 0xff_ffff -> Error(MessageTooLarge(body_length))
        False ->
          case message_type_to_wire(message_type) {
            Error(error) -> Error(error)
            Ok(encoded_type) ->
              Ok(<<encoded_type, body_length:size(24), body:bits>>)
          }
      }
    }
  }
}

/// Return whether QUIC explicitly forbids this TLS handshake message.
pub fn forbidden_in_quic(message_type: MessageType) -> Bool {
  case message_type {
    EndOfEarlyData | KeyUpdate -> True
    _ -> False
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.maximum_message_length >= 0
  && limits.maximum_message_length <= 0xff_ffff
  && limits.maximum_buffered_length >= 4
}

fn decode_aligned(bytes: BitArray, limits: Limits) -> Result(Decoded, Error) {
  let buffered_length = bit_array.byte_size(bytes)
  case buffered_length > limits.maximum_buffered_length {
    True -> Error(BufferTooLarge(buffered_length))
    False ->
      case bytes {
        <<wire_type, body_length:size(24), body_and_rest:bits>> ->
          case body_length > limits.maximum_message_length {
            True -> Error(MessageTooLarge(body_length))
            False -> decode_body(wire_type, body_length, body_and_rest)
          }
        _ -> Ok(NeedMore)
      }
  }
}

fn decode_body(
  wire_type: Int,
  body_length: Int,
  bytes: BitArray,
) -> Result(Decoded, Error) {
  case body_length > bit_array.byte_size(bytes) {
    True -> Ok(NeedMore)
    False -> {
      let body_bits = body_length * 8
      case bytes {
        <<body:bits-size(body_bits), rest:bits>> ->
          Ok(Complete(Message(message_type_from_wire(wire_type), body), rest))
        _ -> Ok(NeedMore)
      }
    }
  }
}

fn message_type_from_wire(wire_type: Int) -> MessageType {
  case wire_type {
    1 -> ClientHello
    2 -> ServerHello
    4 -> NewSessionTicket
    5 -> EndOfEarlyData
    8 -> EncryptedExtensions
    11 -> Certificate
    13 -> CertificateRequest
    15 -> CertificateVerify
    20 -> Finished
    24 -> KeyUpdate
    254 -> MessageHash
    _ -> Unknown(wire_type)
  }
}

fn message_type_to_wire(message_type: MessageType) -> Result(Int, Error) {
  case message_type {
    ClientHello -> Ok(1)
    ServerHello -> Ok(2)
    NewSessionTicket -> Ok(4)
    EndOfEarlyData -> Ok(5)
    EncryptedExtensions -> Ok(8)
    Certificate -> Ok(11)
    CertificateRequest -> Ok(13)
    CertificateVerify -> Ok(15)
    Finished -> Ok(20)
    KeyUpdate -> Ok(24)
    MessageHash -> Ok(254)
    Unknown(identifier) ->
      case identifier >= 0 && identifier <= 255 && !known_type(identifier) {
        True -> Ok(identifier)
        False -> Error(InvalidMessageType(identifier))
      }
  }
}

fn known_type(identifier: Int) -> Bool {
  identifier == 1
  || identifier == 2
  || identifier == 4
  || identifier == 5
  || identifier == 8
  || identifier == 11
  || identifier == 13
  || identifier == 15
  || identifier == 20
  || identifier == 24
  || identifier == 254
}
