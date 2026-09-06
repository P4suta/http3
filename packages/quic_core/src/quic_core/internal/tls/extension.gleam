//// Bounded TLS 1.3 extension-list codec.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/list
import gleam/result

/// A registered TLS extension used by TLS 1.3 or QUIC.
pub type Kind {
  ServerName
  StatusRequest
  SupportedGroups
  SignatureAlgorithms
  ApplicationLayerProtocolNegotiation
  SignedCertificateTimestamp
  Padding
  RecordSizeLimit
  PreSharedKey
  EarlyData
  SupportedVersions
  Cookie
  PskKeyExchangeModes
  CertificateAuthorities
  OidFilters
  PostHandshakeAuth
  SignatureAlgorithmsCertificate
  KeyShare
  QuicTransportParameters
  Unknown(Int)
}

/// One TLS extension and its bounded opaque value.
pub type Extension {
  Extension(kind: Kind, data: BitArray)
}

/// The containing handshake message affects extension ordering rules.
pub type Context {
  ClientHelloExtensions
  OtherExtensions
}

/// Peer-controlled extension-list limits.
pub type Limits {
  Limits(
    maximum_extensions: Int,
    maximum_data_length: Int,
    maximum_total_length: Int,
  )
}

/// A TLS extension-list failure.
pub type Error {
  NonByteAligned
  InvalidLimits
  Truncated
  InvalidKind(Int)
  DuplicateExtension(Int)
  PreSharedKeyNotLast
  ExtensionLimitExceeded(Int)
  DataTooLarge(Int)
  TotalTooLarge(Int)
}

/// Conservative defaults bounded by TLS's 16-bit extension vectors.
pub fn default_limits() -> Limits {
  Limits(128, 65_535, 65_535)
}

/// Decode all extensions from a complete extension vector value.
pub fn decode_all(
  bytes bytes: BitArray,
  context context: Context,
  limits limits: Limits,
) -> Result(List(Extension), Error) {
  case bit_array.bit_size(bytes) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case valid_limits(limits) {
        False -> Error(InvalidLimits)
        True -> {
          let total_length = bit_array.byte_size(bytes)
          case total_length > limits.maximum_total_length {
            True -> Error(TotalTooLarge(total_length))
            False ->
              decode_extensions(bytes, context, limits, dict.new(), 0, [])
          }
        }
      }
  }
}

/// Encode an extension vector value without its outer 16-bit length.
pub fn encode_all(
  extensions extensions: List(Extension),
  context context: Context,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  case valid_limits(limits) {
    False -> Error(InvalidLimits)
    True -> encode_extensions(extensions, context, limits, dict.new(), 0, <<>>)
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.maximum_extensions >= 0
  && limits.maximum_data_length >= 0
  && limits.maximum_data_length <= 65_535
  && limits.maximum_total_length >= 0
  && limits.maximum_total_length <= 65_535
}

fn decode_extensions(
  bytes: BitArray,
  context: Context,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(Extension),
) -> Result(List(Extension), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<identifier:size(16), data_length:size(16), data_and_rest:bits>> ->
      case data_length > limits.maximum_data_length {
        True -> Error(DataTooLarge(data_length))
        False -> {
          use #(data, rest) <- result.try(take(data_and_rest, data_length))
          decode_extension(
            identifier,
            data,
            rest,
            context,
            limits,
            seen,
            count,
            reversed,
          )
        }
      }
    _ -> Error(Truncated)
  }
}

fn decode_extension(
  identifier: Int,
  data: BitArray,
  rest: BitArray,
  context: Context,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  reversed: List(Extension),
) -> Result(List(Extension), Error) {
  case dict.has_key(seen, identifier) {
    True -> Error(DuplicateExtension(identifier))
    False -> {
      let next_count = count + 1
      case next_count > limits.maximum_extensions {
        True -> Error(ExtensionLimitExceeded(limits.maximum_extensions))
        False ->
          case
            context == ClientHelloExtensions && identifier == 41 && rest != <<>>
          {
            True -> Error(PreSharedKeyNotLast)
            False ->
              decode_extensions(
                rest,
                context,
                limits,
                dict.insert(seen, identifier, Nil),
                next_count,
                [Extension(kind_from_wire(identifier), data), ..reversed],
              )
          }
      }
    }
  }
}

fn encode_extensions(
  extensions: List(Extension),
  context: Context,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case extensions {
    [] -> Ok(accumulator)
    [Extension(kind, data), ..rest] ->
      case bit_array.bit_size(data) % 8 {
        remainder if remainder != 0 -> Error(NonByteAligned)
        _ -> {
          use identifier <- result.try(kind_to_wire(kind))
          case dict.has_key(seen, identifier) {
            True -> Error(DuplicateExtension(identifier))
            False ->
              encode_new_extension(
                identifier,
                data,
                rest,
                context,
                limits,
                seen,
                count,
                accumulator,
              )
          }
        }
      }
  }
}

fn encode_new_extension(
  identifier: Int,
  data: BitArray,
  rest: List(Extension),
  context: Context,
  limits: Limits,
  seen: Dict(Int, Nil),
  count: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  let next_count = count + 1
  let data_length = bit_array.byte_size(data)
  let next_total_length = bit_array.byte_size(accumulator) + 4 + data_length
  case
    next_count > limits.maximum_extensions,
    data_length > limits.maximum_data_length,
    next_total_length > limits.maximum_total_length,
    context == ClientHelloExtensions && identifier == 41 && rest != []
  {
    True, _, _, _ -> Error(ExtensionLimitExceeded(limits.maximum_extensions))
    _, True, _, _ -> Error(DataTooLarge(data_length))
    _, _, True, _ -> Error(TotalTooLarge(next_total_length))
    _, _, _, True -> Error(PreSharedKeyNotLast)
    _, _, _, _ ->
      encode_extensions(
        rest,
        context,
        limits,
        dict.insert(seen, identifier, Nil),
        next_count,
        <<
          accumulator:bits,
          identifier:size(16),
          data_length:size(16),
          data:bits,
        >>,
      )
  }
}

fn kind_from_wire(identifier: Int) -> Kind {
  case identifier {
    0 -> ServerName
    5 -> StatusRequest
    10 -> SupportedGroups
    13 -> SignatureAlgorithms
    16 -> ApplicationLayerProtocolNegotiation
    18 -> SignedCertificateTimestamp
    21 -> Padding
    28 -> RecordSizeLimit
    41 -> PreSharedKey
    42 -> EarlyData
    43 -> SupportedVersions
    44 -> Cookie
    45 -> PskKeyExchangeModes
    47 -> CertificateAuthorities
    48 -> OidFilters
    49 -> PostHandshakeAuth
    50 -> SignatureAlgorithmsCertificate
    51 -> KeyShare
    57 -> QuicTransportParameters
    _ -> Unknown(identifier)
  }
}

fn kind_to_wire(kind: Kind) -> Result(Int, Error) {
  case kind {
    ServerName -> Ok(0)
    StatusRequest -> Ok(5)
    SupportedGroups -> Ok(10)
    SignatureAlgorithms -> Ok(13)
    ApplicationLayerProtocolNegotiation -> Ok(16)
    SignedCertificateTimestamp -> Ok(18)
    Padding -> Ok(21)
    RecordSizeLimit -> Ok(28)
    PreSharedKey -> Ok(41)
    EarlyData -> Ok(42)
    SupportedVersions -> Ok(43)
    Cookie -> Ok(44)
    PskKeyExchangeModes -> Ok(45)
    CertificateAuthorities -> Ok(47)
    OidFilters -> Ok(48)
    PostHandshakeAuth -> Ok(49)
    SignatureAlgorithmsCertificate -> Ok(50)
    KeyShare -> Ok(51)
    QuicTransportParameters -> Ok(57)
    Unknown(identifier) ->
      case
        identifier >= 0
        && identifier <= 65_535
        && kind_from_wire(identifier) == Unknown(identifier)
      {
        True -> Ok(identifier)
        False -> Error(InvalidKind(identifier))
      }
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
