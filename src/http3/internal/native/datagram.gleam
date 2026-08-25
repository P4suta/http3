//// Semantics-bound RFC 9297 HTTP Datagram association and wire mapping.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/result
import gleam_quic/varint
import http3/internal/native/capsule

/// Validated negotiated HTTP extension protocol name.
pub opaque type Extension {
  Extension(BitArray)
}

/// Delivery mechanisms the owning HTTP extension negotiated.
pub type Delivery {
  Unreliable
  Capsules
  UnreliableAndCapsules
}

/// Decoded HTTP Datagram with its associated request and extension.
pub type Received {
  Received(stream_id: Int, extension: Extension, payload: BitArray)
}

/// Result of one capsule on an associated extension data stream.
pub type CapsuleOutcome {
  DatagramReceived(Received)
  ExtensionCapsule(
    stream_id: Int,
    extension: Extension,
    capsule_type: Int,
    value: BitArray,
  )
}

type Association {
  Association(extension: Extension, delivery: Delivery)
}

/// Connection negotiation and bounded request associations.
pub opaque type State {
  State(
    quic_datagram_negotiated: Bool,
    h3_datagram_enabled: Bool,
    maximum_associations: Int,
    maximum_payload_bytes: Int,
    associations: Dict(Int, Association),
  )
}

/// Missing negotiation, invalid association, size, or wire failure.
pub type Error {
  InvalidConfiguration
  InvalidExtension
  InvalidRequestStream(Int)
  DuplicateAssociation(Int)
  AssociationLimitExceeded(Int)
  UnknownAssociation(Int)
  UnreliableDatagramNotNegotiated
  CapsulesNotNegotiated
  PayloadLimitExceeded(Int)
  NonByteAligned
  InvalidQuarterStreamId(Int)
  Truncated
  IntegerFailure(varint.Error)
  CapsuleFailure(capsule.Error)
}

/// Create the connection-level HTTP Datagram registry.
pub fn new(
  quic_datagram_negotiated: Bool,
  h3_datagram_enabled: Bool,
  maximum_associations: Int,
  maximum_payload_bytes: Int,
) -> Result(State, Error) {
  case maximum_associations >= 0 && maximum_payload_bytes >= 0 {
    True ->
      Ok(State(
        quic_datagram_negotiated,
        h3_datagram_enabled,
        maximum_associations,
        maximum_payload_bytes,
        dict.new(),
      ))
    False -> Error(InvalidConfiguration)
  }
}

/// Validate a protocol token used by Extended CONNECT or another HTTP
/// extension that explicitly defines HTTP Datagram semantics.
pub fn extension(protocol: BitArray) -> Result(Extension, Error) {
  case bit_array.bit_size(protocol) % 8, protocol {
    remainder, _ if remainder != 0 -> Error(NonByteAligned)
    _, <<>> -> Error(InvalidExtension)
    _, _ ->
      case valid_token(protocol) {
        True -> Ok(Extension(protocol))
        False -> Error(InvalidExtension)
      }
  }
}

/// Associate delivery with a client-initiated bidirectional request stream.
/// No API accepts an ordinary method alone, preventing generic GET/POST use.
pub fn associate(
  state: State,
  stream_id: Int,
  extension: Extension,
  delivery: Delivery,
) -> Result(State, Error) {
  use _ <- result.try(validate_request_stream(stream_id))
  use _ <- result.try(validate_delivery(state, delivery))
  case
    dict.has_key(state.associations, stream_id),
    dict.size(state.associations)
  {
    True, _ -> Error(DuplicateAssociation(stream_id))
    False, count if count >= state.maximum_associations ->
      Error(AssociationLimitExceeded(state.maximum_associations))
    False, _ ->
      Ok(
        State(
          ..state,
          associations: dict.insert(
            state.associations,
            stream_id,
            Association(extension, delivery),
          ),
        ),
      )
  }
}

/// Remove all Datagram authority when the associated request ends.
pub fn remove(state: State, stream_id: Int) -> State {
  State(..state, associations: dict.delete(state.associations, stream_id))
}

/// Encode one HTTP/3 Datagram for a QUIC DATAGRAM frame payload.
pub fn encode_unreliable(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(BitArray, Error) {
  use Association(_, delivery) <- result.try(find_association(state, stream_id))
  use _ <- result.try(require_unreliable(delivery))
  use _ <- result.try(validate_payload(state, payload))
  use quarter_stream_id <- result.try(
    varint.encode(stream_id / 4) |> map_integer_result,
  )
  Ok(<<quarter_stream_id:bits, payload:bits>>)
}

/// Decode one QUIC DATAGRAM frame payload and require known extension
/// semantics for the associated request.
pub fn decode_unreliable(
  state: State,
  encoded: BitArray,
) -> Result(Received, Error) {
  use _ <- result.try(require_connection_datagrams(state))
  use #(quarter_stream_id, payload) <- result.try(decode_integer(encoded))
  case quarter_stream_id > varint.maximum / 4 {
    True -> Error(InvalidQuarterStreamId(quarter_stream_id))
    False -> {
      let stream_id = quarter_stream_id * 4
      use Association(extension, delivery) <- result.try(find_association(
        state,
        stream_id,
      ))
      use _ <- result.try(require_unreliable(delivery))
      use _ <- result.try(validate_payload(state, payload))
      Ok(Received(stream_id, extension, payload))
    }
  }
}

/// Encode a reliable DATAGRAM Capsule on its already-associated request data
/// stream. The stream ID is intentionally absent from Capsule payloads.
pub fn encode_capsule(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(BitArray, Error) {
  use Association(_, delivery) <- result.try(find_association(state, stream_id))
  use _ <- result.try(require_capsules(delivery))
  use _ <- result.try(validate_payload(state, payload))
  capsule.encode(capsule.Datagram(payload)) |> map_capsule_result
}

/// Validate a parsed DATAGRAM Capsule against its request association.
pub fn receive_capsule(
  state: State,
  stream_id: Int,
  incoming: capsule.Capsule,
) -> Result(CapsuleOutcome, Error) {
  use Association(extension, delivery) <- result.try(find_association(
    state,
    stream_id,
  ))
  use _ <- result.try(require_capsules(delivery))
  case incoming {
    capsule.Datagram(payload) -> {
      use _ <- result.try(validate_payload(state, payload))
      Ok(DatagramReceived(Received(stream_id, extension, payload)))
    }
    capsule.Unknown(capsule_type, value) ->
      Ok(ExtensionCapsule(stream_id, extension, capsule_type, value))
  }
}

fn find_association(
  state: State,
  stream_id: Int,
) -> Result(Association, Error) {
  case dict.get(state.associations, stream_id) {
    Ok(association) -> Ok(association)
    Error(_) -> Error(UnknownAssociation(stream_id))
  }
}

fn validate_delivery(state: State, delivery: Delivery) -> Result(Nil, Error) {
  case delivery {
    Unreliable -> require_connection_datagrams(state)
    Capsules -> Ok(Nil)
    UnreliableAndCapsules -> require_connection_datagrams(state)
  }
}

fn require_connection_datagrams(state: State) -> Result(Nil, Error) {
  case state.quic_datagram_negotiated && state.h3_datagram_enabled {
    True -> Ok(Nil)
    False -> Error(UnreliableDatagramNotNegotiated)
  }
}

fn require_unreliable(delivery: Delivery) -> Result(Nil, Error) {
  case delivery {
    Unreliable | UnreliableAndCapsules -> Ok(Nil)
    Capsules -> Error(UnreliableDatagramNotNegotiated)
  }
}

fn require_capsules(delivery: Delivery) -> Result(Nil, Error) {
  case delivery {
    Capsules | UnreliableAndCapsules -> Ok(Nil)
    Unreliable -> Error(CapsulesNotNegotiated)
  }
}

fn validate_payload(state: State, payload: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(payload) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case bit_array.byte_size(payload) > state.maximum_payload_bytes {
        True -> Error(PayloadLimitExceeded(state.maximum_payload_bytes))
        False -> Ok(Nil)
      }
  }
}

fn validate_request_stream(stream_id: Int) -> Result(Nil, Error) {
  case stream_id >= 0 && stream_id <= varint.maximum && stream_id % 4 == 0 {
    True -> Ok(Nil)
    False -> Error(InvalidRequestStream(stream_id))
  }
}

fn valid_token(value: BitArray) -> Bool {
  case value {
    <<>> -> True
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True -> valid_token(rest)
        False -> False
      }
    _ -> False
  }
}

fn token_byte(byte: Int) -> Bool {
  { byte >= 48 && byte <= 57 }
  || { byte >= 65 && byte <= 90 }
  || { byte >= 97 && byte <= 122 }
  || case byte {
    0x21
    | 0x23
    | 0x24
    | 0x25
    | 0x26
    | 0x27
    | 0x2a
    | 0x2b
    | 0x2d
    | 0x2e
    | 0x5e
    | 0x5f
    | 0x60
    | 0x7c
    | 0x7e -> True
    _ -> False
  }
}

fn decode_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(varint.Truncated) -> Error(Truncated)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_integer_result(
  value: Result(BitArray, varint.Error),
) -> Result(BitArray, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(IntegerFailure(error))
  }
}

fn map_capsule_result(
  value: Result(value, capsule.Error),
) -> Result(value, Error) {
  case value {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(CapsuleFailure(error))
  }
}
