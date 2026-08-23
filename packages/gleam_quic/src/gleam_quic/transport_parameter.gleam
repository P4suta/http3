//// Bounded QUIC transport parameter codec and semantic validation.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam_quic/varint
import gleam_quic/version.{type Version}

/// The endpoint that sent a transport parameter block.
pub type Role {
  Client
  Server
}

/// The RFC 9000 preferred_address transport parameter value.
pub type PreferredAddress {
  PreferredAddress(
    ipv4_address: BitArray,
    ipv4_port: Int,
    ipv6_address: BitArray,
    ipv6_port: Int,
    connection_id: BitArray,
    stateless_reset_token: BitArray,
  )
}

/// A known or preserved unknown QUIC transport parameter.
pub type Parameter {
  OriginalDestinationConnectionId(BitArray)
  MaxIdleTimeout(Int)
  StatelessResetToken(BitArray)
  MaxUdpPayloadSize(Int)
  InitialMaxData(Int)
  InitialMaxStreamDataBidiLocal(Int)
  InitialMaxStreamDataBidiRemote(Int)
  InitialMaxStreamDataUni(Int)
  InitialMaxStreamsBidi(Int)
  InitialMaxStreamsUni(Int)
  AckDelayExponent(Int)
  MaxAckDelay(Int)
  DisableActiveMigration
  PreferredAddressParameter(PreferredAddress)
  ActiveConnectionIdLimit(Int)
  InitialSourceConnectionId(BitArray)
  RetrySourceConnectionId(BitArray)
  VersionInformation(Version, List(Version))
  MaxDatagramFrameSize(Int)
  GreaseQuicBit
  Unknown(Int, BitArray)
}

/// Peer-controlled bounds for a TLS transport parameter block.
pub type Limits {
  Limits(max_parameters: Int, max_value_length: Int)
}

/// A transport parameter codec or semantic failure.
pub type Error {
  NonByteAligned
  Truncated
  InvalidLimits
  InvalidParameter(Int)
  DuplicateParameter(Int)
  ForbiddenForClient(Int)
  ParameterLimitExceeded(Int)
  ValueLimitExceeded(Int)
  MissingRequiredParameter(Int)
}

/// Conservative bounds for one authenticated TLS extension value.
pub fn default_limits() -> Limits {
  Limits(max_parameters: 128, max_value_length: 16_384)
}

/// Decode and validate a complete transport parameter block.
pub fn decode_all(
  bytes bytes: BitArray,
  sent_by sent_by: Role,
  limits limits: Limits,
) -> Result(List(Parameter), Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case limits.max_parameters > 0 && limits.max_value_length >= 0 {
        False -> Error(InvalidLimits)
        True -> decode_parameters(bytes, sent_by, limits, dict.new(), 0, [])
      }
  }
}

/// Encode and validate a complete transport parameter block.
pub fn encode_all(
  parameters parameters: List(Parameter),
  sent_by sent_by: Role,
) -> Result(BitArray, Error) {
  case parameters_are_byte_aligned(parameters) {
    False -> Error(NonByteAligned)
    True -> encode_parameters(parameters, sent_by, dict.new(), <<>>)
  }
}

fn parameters_are_byte_aligned(parameters: List(Parameter)) -> Bool {
  case parameters {
    [] -> True
    [parameter, ..rest] ->
      parameter_is_byte_aligned(parameter) && parameters_are_byte_aligned(rest)
  }
}

fn parameter_is_byte_aligned(parameter: Parameter) -> Bool {
  case parameter {
    OriginalDestinationConnectionId(value)
    | StatelessResetToken(value)
    | InitialSourceConnectionId(value)
    | RetrySourceConnectionId(value)
    | Unknown(_, value) -> bit_array.bit_size(value) % 8 == 0
    PreferredAddressParameter(PreferredAddress(
      ipv4,
      _,
      ipv6,
      _,
      connection_id,
      token,
    )) ->
      bit_array.bit_size(ipv4) % 8 == 0
      && bit_array.bit_size(ipv6) % 8 == 0
      && bit_array.bit_size(connection_id) % 8 == 0
      && bit_array.bit_size(token) % 8 == 0
    _ -> True
  }
}

/// Validate parameters that are mandatory in a completed QUIC handshake.
pub fn validate_handshake(
  parameters parameters: List(Parameter),
  sent_by sent_by: Role,
  retried retried: Bool,
) -> Result(Nil, Error) {
  case has_parameter(parameters, 0x0f) {
    False -> Error(MissingRequiredParameter(0x0f))
    True ->
      case sent_by {
        Client -> Ok(Nil)
        Server ->
          case has_parameter(parameters, 0x00), retried {
            False, _ -> Error(MissingRequiredParameter(0x00))
            True, True ->
              case has_parameter(parameters, 0x10) {
                True -> Ok(Nil)
                False -> Error(MissingRequiredParameter(0x10))
              }
            True, False -> Ok(Nil)
          }
      }
  }
}

fn decode_parameters(
  bytes: BitArray,
  sent_by: Role,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(Parameter),
) -> Result(List(Parameter), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    _ -> {
      use #(identifier, rest) <- result.try(read_integer(bytes))
      use #(length, rest) <- result.try(read_integer(rest))
      use #(value, rest) <- result.try(take_parameter_value(
        rest,
        length,
        limits,
      ))
      decode_parameter_entry(
        identifier,
        value,
        rest,
        sent_by,
        limits,
        seen,
        count,
        reversed,
      )
    }
  }
}

fn take_parameter_value(
  bytes: BitArray,
  length: Int,
  limits: Limits,
) -> Result(#(BitArray, BitArray), Error) {
  case length > limits.max_value_length {
    True -> Error(ValueLimitExceeded(limits.max_value_length))
    False -> take(bytes, length)
  }
}

fn decode_parameter_entry(
  identifier: Int,
  value: BitArray,
  rest: BitArray,
  sent_by: Role,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(Parameter),
) -> Result(List(Parameter), Error) {
  case dict.has_key(seen, identifier) {
    True -> Error(DuplicateParameter(identifier))
    False ->
      decode_new_parameter_entry(
        identifier,
        value,
        rest,
        sent_by,
        limits,
        seen,
        count,
        reversed,
      )
  }
}

fn decode_new_parameter_entry(
  identifier: Int,
  value: BitArray,
  rest: BitArray,
  sent_by: Role,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(Parameter),
) -> Result(List(Parameter), Error) {
  let next_count = count + 1
  case next_count > limits.max_parameters {
    True -> Error(ParameterLimitExceeded(limits.max_parameters))
    False -> {
      use parameter <- result.try(decode_parameter(identifier, value, sent_by))
      decode_parameters(
        rest,
        sent_by,
        limits,
        dict.insert(seen, identifier, Nil),
        next_count,
        [parameter, ..reversed],
      )
    }
  }
}

fn decode_parameter(
  identifier: Int,
  value: BitArray,
  sent_by: Role,
) -> Result(Parameter, Error) {
  case sent_by == Client && server_only(identifier) {
    True -> Error(ForbiddenForClient(identifier))
    False ->
      case identifier {
        0x00 ->
          decode_connection_id(
            identifier,
            value,
            OriginalDestinationConnectionId,
          )
        0x01 ->
          decode_integer_parameter(
            identifier,
            value,
            MaxIdleTimeout,
            any_integer,
          )
        0x02 ->
          case bit_array.byte_size(value) == 16 {
            True -> Ok(StatelessResetToken(value))
            False -> Error(InvalidParameter(identifier))
          }
        0x03 ->
          decode_integer_parameter(
            identifier,
            value,
            MaxUdpPayloadSize,
            valid_udp_payload_size,
          )
        0x04 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxData,
            any_integer,
          )
        0x05 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxStreamDataBidiLocal,
            any_integer,
          )
        0x06 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxStreamDataBidiRemote,
            any_integer,
          )
        0x07 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxStreamDataUni,
            any_integer,
          )
        0x08 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxStreamsBidi,
            valid_stream_count,
          )
        0x09 ->
          decode_integer_parameter(
            identifier,
            value,
            InitialMaxStreamsUni,
            valid_stream_count,
          )
        0x0a ->
          decode_integer_parameter(
            identifier,
            value,
            AckDelayExponent,
            fn(value) { value <= 20 },
          )
        0x0b ->
          decode_integer_parameter(identifier, value, MaxAckDelay, fn(value) {
            value < 16_384
          })
        0x0c ->
          case value {
            <<>> -> Ok(DisableActiveMigration)
            _ -> Error(InvalidParameter(identifier))
          }
        0x0d -> decode_preferred_address(value)
        0x0e ->
          decode_integer_parameter(
            identifier,
            value,
            ActiveConnectionIdLimit,
            fn(value) { value >= 2 },
          )
        0x0f ->
          decode_connection_id(identifier, value, InitialSourceConnectionId)
        0x10 -> decode_connection_id(identifier, value, RetrySourceConnectionId)
        0x11 -> decode_version_information(value, sent_by)
        0x20 ->
          decode_integer_parameter(
            identifier,
            value,
            MaxDatagramFrameSize,
            any_integer,
          )
        0x2ab2 ->
          case value {
            <<>> -> Ok(GreaseQuicBit)
            _ -> Error(InvalidParameter(identifier))
          }
        _ -> Ok(Unknown(identifier, value))
      }
  }
}

fn decode_integer_parameter(
  identifier: Int,
  value: BitArray,
  constructor: fn(Int) -> Parameter,
  valid: fn(Int) -> Bool,
) -> Result(Parameter, Error) {
  case read_integer(value) {
    Ok(#(decoded, <<>>)) ->
      case valid(decoded) {
        True -> Ok(constructor(decoded))
        False -> Error(InvalidParameter(identifier))
      }
    _ -> Error(InvalidParameter(identifier))
  }
}

fn decode_connection_id(
  identifier: Int,
  value: BitArray,
  constructor: fn(BitArray) -> Parameter,
) -> Result(Parameter, Error) {
  case bit_array.byte_size(value) <= 20 {
    True -> Ok(constructor(value))
    False -> Error(InvalidParameter(identifier))
  }
}

fn decode_preferred_address(value: BitArray) -> Result(Parameter, Error) {
  case value {
    <<
      ipv4_address:bits-size(32),
      ipv4_port:size(16),
      ipv6_address:bits-size(128),
      ipv6_port:size(16),
      connection_id_length,
      connection_id_and_token:bits,
    >> ->
      case connection_id_length < 1 || connection_id_length > 20 {
        True -> Error(InvalidParameter(0x0d))
        False -> {
          use #(connection_id, token) <- result.try(take(
            connection_id_and_token,
            connection_id_length,
          ))
          case token {
            <<stateless_reset_token:bits-size(128)>> ->
              Ok(
                PreferredAddressParameter(PreferredAddress(
                  ipv4_address,
                  ipv4_port,
                  ipv6_address,
                  ipv6_port,
                  connection_id,
                  stateless_reset_token,
                )),
              )
            _ -> Error(InvalidParameter(0x0d))
          }
        }
      }
    _ -> Error(InvalidParameter(0x0d))
  }
}

fn decode_version_information(
  value: BitArray,
  sent_by: Role,
) -> Result(Parameter, Error) {
  case value {
    <<chosen_wire:size(32), available_bytes:bits>> -> {
      use chosen <- result.try(decode_nonzero_version(chosen_wire))
      use available <- result.try(decode_versions(available_bytes, []))
      case sent_by == Client && !list.contains(available, chosen) {
        True -> Error(InvalidParameter(0x11))
        False -> Ok(VersionInformation(chosen, available))
      }
    }
    _ -> Error(InvalidParameter(0x11))
  }
}

fn decode_versions(
  bytes: BitArray,
  reversed: List(Version),
) -> Result(List(Version), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<wire:size(32), rest:bits>> -> {
      use decoded <- result.try(decode_nonzero_version(wire))
      decode_versions(rest, [decoded, ..reversed])
    }
    _ -> Error(InvalidParameter(0x11))
  }
}

fn decode_nonzero_version(wire: Int) -> Result(Version, Error) {
  case wire {
    0 -> Error(InvalidParameter(0x11))
    _ ->
      case version.from_wire(wire) {
        Ok(decoded) -> Ok(decoded)
        Error(_) -> Error(InvalidParameter(0x11))
      }
  }
}

fn encode_parameters(
  parameters: List(Parameter),
  sent_by: Role,
  seen: Dict(Int, Nil),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case parameters {
    [] -> Ok(accumulator)
    [parameter, ..rest] -> {
      use identifier <- result.try(parameter_id(parameter))
      case dict.has_key(seen, identifier) {
        True -> Error(DuplicateParameter(identifier))
        False -> {
          use value <- result.try(encode_value(parameter, sent_by))
          use encoded_identifier <- result.try(encode_integer(identifier))
          use encoded_length <- result.try(
            encode_integer(bit_array.byte_size(value)),
          )
          encode_parameters(rest, sent_by, dict.insert(seen, identifier, Nil), <<
            accumulator:bits,
            encoded_identifier:bits,
            encoded_length:bits,
            value:bits,
          >>)
        }
      }
    }
  }
}

fn parameter_id(parameter: Parameter) -> Result(Int, Error) {
  case parameter {
    OriginalDestinationConnectionId(_) -> Ok(0x00)
    MaxIdleTimeout(_) -> Ok(0x01)
    StatelessResetToken(_) -> Ok(0x02)
    MaxUdpPayloadSize(_) -> Ok(0x03)
    InitialMaxData(_) -> Ok(0x04)
    InitialMaxStreamDataBidiLocal(_) -> Ok(0x05)
    InitialMaxStreamDataBidiRemote(_) -> Ok(0x06)
    InitialMaxStreamDataUni(_) -> Ok(0x07)
    InitialMaxStreamsBidi(_) -> Ok(0x08)
    InitialMaxStreamsUni(_) -> Ok(0x09)
    AckDelayExponent(_) -> Ok(0x0a)
    MaxAckDelay(_) -> Ok(0x0b)
    DisableActiveMigration -> Ok(0x0c)
    PreferredAddressParameter(_) -> Ok(0x0d)
    ActiveConnectionIdLimit(_) -> Ok(0x0e)
    InitialSourceConnectionId(_) -> Ok(0x0f)
    RetrySourceConnectionId(_) -> Ok(0x10)
    VersionInformation(_, _) -> Ok(0x11)
    MaxDatagramFrameSize(_) -> Ok(0x20)
    GreaseQuicBit -> Ok(0x2ab2)
    Unknown(identifier, _) ->
      case
        identifier < 0
        || identifier > varint.maximum
        || known_parameter(identifier)
      {
        True -> Error(InvalidParameter(identifier))
        False -> Ok(identifier)
      }
  }
}

fn encode_value(
  parameter: Parameter,
  sent_by: Role,
) -> Result(BitArray, Error) {
  use identifier <- result.try(parameter_id(parameter))
  case sent_by == Client && server_only(identifier) {
    True -> Error(ForbiddenForClient(identifier))
    False ->
      case parameter {
        OriginalDestinationConnectionId(value)
        | InitialSourceConnectionId(value)
        | RetrySourceConnectionId(value) ->
          encode_connection_id(identifier, value)
        MaxIdleTimeout(value)
        | InitialMaxData(value)
        | InitialMaxStreamDataBidiLocal(value)
        | InitialMaxStreamDataBidiRemote(value)
        | InitialMaxStreamDataUni(value)
        | MaxDatagramFrameSize(value) ->
          encode_valid_integer(identifier, value, any_integer)
        StatelessResetToken(token) ->
          case bit_array.byte_size(token) == 16 {
            True -> Ok(token)
            False -> Error(InvalidParameter(identifier))
          }
        MaxUdpPayloadSize(value) ->
          encode_valid_integer(identifier, value, valid_udp_payload_size)
        InitialMaxStreamsBidi(value) | InitialMaxStreamsUni(value) ->
          encode_valid_integer(identifier, value, valid_stream_count)
        AckDelayExponent(value) ->
          encode_valid_integer(identifier, value, fn(value) { value <= 20 })
        MaxAckDelay(value) ->
          encode_valid_integer(identifier, value, fn(value) { value < 16_384 })
        DisableActiveMigration | GreaseQuicBit -> Ok(<<>>)
        PreferredAddressParameter(preferred) ->
          encode_preferred_address(preferred)
        ActiveConnectionIdLimit(value) ->
          encode_valid_integer(identifier, value, fn(value) { value >= 2 })
        VersionInformation(chosen, available) ->
          encode_version_information(chosen, available, sent_by)
        Unknown(_, value) ->
          case bit_array.bit_size(value) % 8 {
            0 -> Ok(value)
            _ -> Error(InvalidParameter(identifier))
          }
      }
  }
}

fn encode_connection_id(
  identifier: Int,
  value: BitArray,
) -> Result(BitArray, Error) {
  case bit_array.bit_size(value) % 8 == 0 && bit_array.byte_size(value) <= 20 {
    True -> Ok(value)
    False -> Error(InvalidParameter(identifier))
  }
}

fn encode_valid_integer(
  identifier: Int,
  value: Int,
  valid: fn(Int) -> Bool,
) -> Result(BitArray, Error) {
  case valid(value) {
    False -> Error(InvalidParameter(identifier))
    True ->
      case varint.encode(value) {
        Ok(encoded) -> Ok(encoded)
        Error(_) -> Error(InvalidParameter(identifier))
      }
  }
}

fn encode_preferred_address(
  preferred: PreferredAddress,
) -> Result(BitArray, Error) {
  let PreferredAddress(ipv4, ipv4_port, ipv6, ipv6_port, connection_id, token) =
    preferred
  let connection_id_length = bit_array.byte_size(connection_id)
  case
    bit_array.bit_size(ipv4) != 32
    || bit_array.bit_size(ipv6) != 128
    || ipv4_port < 0
    || ipv4_port > 65_535
    || ipv6_port < 0
    || ipv6_port > 65_535
    || connection_id_length < 1
    || connection_id_length > 20
    || bit_array.bit_size(connection_id) % 8 != 0
    || bit_array.bit_size(token) != 128
  {
    True -> Error(InvalidParameter(0x0d))
    False ->
      Ok(<<
        ipv4:bits,
        ipv4_port:size(16),
        ipv6:bits,
        ipv6_port:size(16),
        connection_id_length,
        connection_id:bits,
        token:bits,
      >>)
  }
}

fn encode_version_information(
  chosen: Version,
  available: List(Version),
  sent_by: Role,
) -> Result(BitArray, Error) {
  case sent_by == Client && !list.contains(available, chosen) {
    True -> Error(InvalidParameter(0x11))
    False -> {
      use chosen <- result.try(encode_nonzero_version(chosen))
      use available <- result.try(encode_versions(available, <<>>))
      Ok(<<chosen:32, available:bits>>)
    }
  }
}

fn encode_versions(
  versions: List(Version),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case versions {
    [] -> Ok(accumulator)
    [next, ..rest] -> {
      use encoded <- result.try(encode_nonzero_version(next))
      encode_versions(rest, <<accumulator:bits, encoded:32>>)
    }
  }
}

fn encode_nonzero_version(version_value: Version) -> Result(Int, Error) {
  case version.to_wire(version_value) {
    Ok(0) | Error(_) -> Error(InvalidParameter(0x11))
    Ok(encoded) -> Ok(encoded)
  }
}

fn encode_integer(value: Int) -> Result(BitArray, Error) {
  case varint.encode(value) {
    Ok(encoded) -> Ok(encoded)
    Error(_) -> Error(InvalidParameter(value))
  }
}

fn any_integer(value: Int) -> Bool {
  value >= 0 && value <= varint.maximum
}

fn valid_udp_payload_size(value: Int) -> Bool {
  value >= 1200 && value <= 65_527
}

fn valid_stream_count(value: Int) -> Bool {
  value >= 0 && value <= 1_152_921_504_606_846_975
}

fn server_only(identifier: Int) -> Bool {
  identifier == 0x00
  || identifier == 0x02
  || identifier == 0x0d
  || identifier == 0x10
}

fn known_parameter(identifier: Int) -> Bool {
  identifier >= 0x00
  && identifier <= 0x11
  || identifier == 0x20
  || identifier == 0x2ab2
}

fn has_parameter(parameters: List(Parameter), identifier: Int) -> Bool {
  case parameters {
    [] -> False
    [parameter, ..rest] ->
      case parameter_id(parameter) {
        Ok(found) if found == identifier -> True
        _ -> has_parameter(rest, identifier)
      }
  }
}

fn read_integer(bytes: BitArray) -> Result(#(Int, BitArray), Error) {
  case varint.decode(bytes) {
    Ok(decoded) -> Ok(decoded)
    Error(_) -> Error(Truncated)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length < 0 || length > bit_array.byte_size(bytes) {
    True -> Error(Truncated)
    False -> {
      let bit_length = length * 8
      case bytes {
        <<prefix:bits-size(bit_length), rest:bits>> -> Ok(#(prefix, rest))
        _ -> Error(Truncated)
      }
    }
  }
}
