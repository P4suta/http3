//// Bounded TLS 1.3 ClientHello, ServerHello, and HelloRetryRequest bodies.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam_quic/internal/tls/extension

const legacy_version = 0x0303

const hello_retry_request_random = <<
  0xcf,
  0x21,
  0xad,
  0x74,
  0xe5,
  0x9a,
  0x61,
  0x11,
  0xbe,
  0x1d,
  0x8c,
  0x02,
  0x1e,
  0x65,
  0xb8,
  0x91,
  0xc2,
  0xa2,
  0x11,
  0x16,
  0x7a,
  0xbb,
  0x8c,
  0x5e,
  0x07,
  0x9e,
  0x09,
  0xe2,
  0xc8,
  0xa8,
  0x33,
  0x9c,
>>

/// A TLS cipher-suite identifier.
pub type CipherSuite {
  Aes128GcmSha256
  Aes256GcmSha384
  Chacha20Poly1305Sha256
  Aes128CcmSha256
  Aes128Ccm8Sha256
  UnknownCipherSuite(Int)
}

/// A decoded TLS 1.3 ClientHello body.
pub type ClientHello {
  ClientHello(
    random: BitArray,
    legacy_session_id: BitArray,
    cipher_suites: List(CipherSuite),
    extensions: List(extension.Extension),
  )
}

/// A decoded TLS 1.3 ServerHello or HelloRetryRequest body.
pub type ServerHello {
  ServerHello(
    random: BitArray,
    legacy_session_id_echo: BitArray,
    cipher_suite: CipherSuite,
    extensions: List(extension.Extension),
  )
  HelloRetryRequest(
    legacy_session_id_echo: BitArray,
    cipher_suite: CipherSuite,
    extensions: List(extension.Extension),
  )
}

/// Peer-controlled ClientHello and extension limits.
pub type Limits {
  Limits(maximum_cipher_suites: Int, extension_limits: extension.Limits)
}

/// A TLS hello body failure.
pub type Error {
  NonByteAligned
  InvalidLimits
  Truncated
  InvalidLegacyVersion(Int)
  InvalidRandom
  InvalidSessionId(Int)
  InvalidCipherSuites
  CipherSuiteLimitExceeded(Int)
  InvalidCompression
  InvalidExtensions
  ExtensionFailure(extension.Error)
}

/// Conservative defaults for public-Internet TLS ClientHello messages.
pub fn default_limits() -> Limits {
  Limits(64, extension.default_limits())
}

/// Decode one complete TLS ClientHello body.
pub fn decode_client(
  body body: BitArray,
  limits limits: Limits,
) -> Result(ClientHello, Error) {
  case bit_array.bit_size(body) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case valid_limits(limits) {
        False -> Error(InvalidLimits)
        True -> decode_client_aligned(body, limits)
      }
  }
}

/// Encode one canonical TLS 1.3 ClientHello body.
pub fn encode_client(
  hello hello: ClientHello,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  case valid_limits(limits) {
    False -> Error(InvalidLimits)
    True -> encode_client_with_limits(hello, limits)
  }
}

/// Decode one complete TLS ServerHello or HelloRetryRequest body.
pub fn decode_server(
  body body: BitArray,
  limits limits: Limits,
) -> Result(ServerHello, Error) {
  case bit_array.bit_size(body) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ ->
      case valid_limits(limits) {
        False -> Error(InvalidLimits)
        True -> decode_server_aligned(body, limits)
      }
  }
}

/// Encode one canonical TLS 1.3 ServerHello or HelloRetryRequest body.
pub fn encode_server(
  hello hello: ServerHello,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  case valid_limits(limits) {
    False -> Error(InvalidLimits)
    True ->
      case hello {
        ServerHello(random, session_id, cipher_suite, extensions) ->
          encode_server_fields(
            random,
            session_id,
            cipher_suite,
            extensions,
            limits,
          )
        HelloRetryRequest(session_id, cipher_suite, extensions) ->
          encode_server_fields(
            hello_retry_request_random,
            session_id,
            cipher_suite,
            extensions,
            limits,
          )
      }
  }
}

fn valid_limits(limits: Limits) -> Bool {
  limits.maximum_cipher_suites > 0
}

fn decode_client_aligned(
  body: BitArray,
  limits: Limits,
) -> Result(ClientHello, Error) {
  case body {
    <<
      wire_legacy_version:size(16),
      random:bits-size(256),
      session_length,
      rest:bits,
    >> ->
      case wire_legacy_version != legacy_version {
        True -> Error(InvalidLegacyVersion(wire_legacy_version))
        False ->
          case session_length > 32 {
            True -> Error(InvalidSessionId(session_length))
            False -> {
              use #(session_id, after_session) <- result.try(take(
                rest,
                session_length,
              ))
              decode_client_cipher_suites(
                random,
                session_id,
                after_session,
                limits,
              )
            }
          }
      }
    _ -> Error(Truncated)
  }
}

fn decode_client_cipher_suites(
  random: BitArray,
  session_id: BitArray,
  bytes: BitArray,
  limits: Limits,
) -> Result(ClientHello, Error) {
  case bytes {
    <<cipher_suites_length:size(16), suites_and_rest:bits>> ->
      case cipher_suites_length < 2 || cipher_suites_length % 2 != 0 {
        True -> Error(InvalidCipherSuites)
        False ->
          decode_client_suites_vector(
            random,
            session_id,
            cipher_suites_length,
            suites_and_rest,
            limits,
          )
      }
    _ -> Error(Truncated)
  }
}

fn decode_client_suites_vector(
  random: BitArray,
  session_id: BitArray,
  cipher_suites_length: Int,
  suites_and_rest: BitArray,
  limits: Limits,
) -> Result(ClientHello, Error) {
  let count = cipher_suites_length / 2
  case count > limits.maximum_cipher_suites {
    True -> Error(CipherSuiteLimitExceeded(limits.maximum_cipher_suites))
    False -> {
      use #(suite_bytes, after_suites) <- result.try(take(
        suites_and_rest,
        cipher_suites_length,
      ))
      let suites = decode_cipher_suites(suite_bytes, [])
      decode_client_compression(
        random,
        session_id,
        suites,
        after_suites,
        limits,
      )
    }
  }
}

fn decode_client_compression(
  random: BitArray,
  session_id: BitArray,
  cipher_suites: List(CipherSuite),
  bytes: BitArray,
  limits: Limits,
) -> Result(ClientHello, Error) {
  case bytes {
    <<compression_length, compression_and_extensions:bits>> -> {
      use #(compression, extension_bytes) <- result.try(take(
        compression_and_extensions,
        compression_length,
      ))
      case compression {
        <<0>> ->
          decode_client_extensions(
            random,
            session_id,
            cipher_suites,
            extension_bytes,
            limits,
          )
        _ -> Error(InvalidCompression)
      }
    }
    _ -> Error(Truncated)
  }
}

fn decode_client_extensions(
  random: BitArray,
  session_id: BitArray,
  cipher_suites: List(CipherSuite),
  bytes: BitArray,
  limits: Limits,
) -> Result(ClientHello, Error) {
  use extension_bytes <- result.try(take_exact_vector16(bytes))
  case
    extension.decode_all(
      extension_bytes,
      extension.ClientHelloExtensions,
      limits.extension_limits,
    )
  {
    Ok(extensions) ->
      Ok(ClientHello(random, session_id, cipher_suites, extensions))
    Error(error) -> Error(ExtensionFailure(error))
  }
}

fn decode_server_aligned(
  body: BitArray,
  limits: Limits,
) -> Result(ServerHello, Error) {
  case body {
    <<
      wire_legacy_version:size(16),
      random:bits-size(256),
      session_length,
      rest:bits,
    >> ->
      case wire_legacy_version != legacy_version {
        True -> Error(InvalidLegacyVersion(wire_legacy_version))
        False ->
          case session_length > 32 {
            True -> Error(InvalidSessionId(session_length))
            False -> {
              use #(session_id, after_session) <- result.try(take(
                rest,
                session_length,
              ))
              decode_server_fields(random, session_id, after_session, limits)
            }
          }
      }
    _ -> Error(Truncated)
  }
}

fn decode_server_fields(
  random: BitArray,
  session_id: BitArray,
  bytes: BitArray,
  limits: Limits,
) -> Result(ServerHello, Error) {
  case bytes {
    <<wire_cipher_suite:size(16), compression, extension_bytes:bits>> ->
      case compression {
        0 -> {
          use encoded_extensions <- result.try(take_exact_vector16(
            extension_bytes,
          ))
          use extensions <- result.try(
            case
              extension.decode_all(
                encoded_extensions,
                extension.OtherExtensions,
                limits.extension_limits,
              )
            {
              Ok(value) -> Ok(value)
              Error(error) -> Error(ExtensionFailure(error))
            },
          )
          let cipher_suite = cipher_suite_from_wire(wire_cipher_suite)
          case random == hello_retry_request_random {
            True -> Ok(HelloRetryRequest(session_id, cipher_suite, extensions))
            False ->
              Ok(ServerHello(random, session_id, cipher_suite, extensions))
          }
        }
        _ -> Error(InvalidCompression)
      }
    _ -> Error(Truncated)
  }
}

fn encode_client_with_limits(
  hello: ClientHello,
  limits: Limits,
) -> Result(BitArray, Error) {
  let ClientHello(random, session_id, cipher_suites, extensions) = hello
  use #(session_length, encoded_suites) <- result.try(validate_client_fields(
    random,
    session_id,
    cipher_suites,
    limits,
  ))
  use encoded_extensions <- result.try(encode_extensions(
    extensions,
    extension.ClientHelloExtensions,
    limits,
  ))
  let cipher_suites_length = bit_array.byte_size(encoded_suites)
  let extensions_length = bit_array.byte_size(encoded_extensions)
  Ok(<<
    legacy_version:size(16),
    random:bits,
    session_length,
    session_id:bits,
    cipher_suites_length:size(16),
    encoded_suites:bits,
    1,
    0,
    extensions_length:size(16),
    encoded_extensions:bits,
  >>)
}

fn validate_client_fields(
  random: BitArray,
  session_id: BitArray,
  cipher_suites: List(CipherSuite),
  limits: Limits,
) -> Result(#(Int, BitArray), Error) {
  case bit_array.bit_size(random) == 256 {
    False -> Error(InvalidRandom)
    True -> {
      use session_length <- result.try(validate_session_id(session_id))
      let cipher_suite_count = list.length(cipher_suites)
      case
        cipher_suite_count < 1,
        cipher_suite_count > limits.maximum_cipher_suites
      {
        True, _ -> Error(InvalidCipherSuites)
        _, True -> Error(CipherSuiteLimitExceeded(limits.maximum_cipher_suites))
        _, _ -> {
          use encoded <- result.try(encode_cipher_suites(cipher_suites, <<>>))
          Ok(#(session_length, encoded))
        }
      }
    }
  }
}

fn encode_server_fields(
  random: BitArray,
  session_id: BitArray,
  cipher_suite: CipherSuite,
  extensions: List(extension.Extension),
  limits: Limits,
) -> Result(BitArray, Error) {
  case bit_array.bit_size(random) == 256 {
    False -> Error(InvalidRandom)
    True -> {
      use session_length <- result.try(validate_session_id(session_id))
      use encoded_cipher <- result.try(cipher_suite_to_wire(cipher_suite))
      use encoded_extensions <- result.try(encode_extensions(
        extensions,
        extension.OtherExtensions,
        limits,
      ))
      let extensions_length = bit_array.byte_size(encoded_extensions)
      Ok(<<
        legacy_version:size(16),
        random:bits,
        session_length,
        session_id:bits,
        encoded_cipher:size(16),
        0,
        extensions_length:size(16),
        encoded_extensions:bits,
      >>)
    }
  }
}

fn validate_session_id(session_id: BitArray) -> Result(Int, Error) {
  case bit_array.bit_size(session_id) % 8 {
    remainder if remainder != 0 -> Error(NonByteAligned)
    _ -> {
      let session_length = bit_array.byte_size(session_id)
      case session_length > 32 {
        True -> Error(InvalidSessionId(session_length))
        False -> Ok(session_length)
      }
    }
  }
}

fn encode_extensions(
  extensions: List(extension.Extension),
  context: extension.Context,
  limits: Limits,
) -> Result(BitArray, Error) {
  case extension.encode_all(extensions, context, limits.extension_limits) {
    Ok(encoded) -> Ok(encoded)
    Error(error) -> Error(ExtensionFailure(error))
  }
}

fn decode_cipher_suites(
  bytes: BitArray,
  reversed: List(CipherSuite),
) -> List(CipherSuite) {
  case bytes {
    <<>> -> list.reverse(reversed)
    <<identifier:size(16), rest:bits>> ->
      decode_cipher_suites(rest, [
        cipher_suite_from_wire(identifier),
        ..reversed
      ])
    _ -> list.reverse(reversed)
  }
}

fn encode_cipher_suites(
  cipher_suites: List(CipherSuite),
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case cipher_suites {
    [] -> Ok(accumulator)
    [suite, ..rest] -> {
      use encoded <- result.try(cipher_suite_to_wire(suite))
      encode_cipher_suites(rest, <<accumulator:bits, encoded:size(16)>>)
    }
  }
}

fn cipher_suite_from_wire(identifier: Int) -> CipherSuite {
  case identifier {
    0x1301 -> Aes128GcmSha256
    0x1302 -> Aes256GcmSha384
    0x1303 -> Chacha20Poly1305Sha256
    0x1304 -> Aes128CcmSha256
    0x1305 -> Aes128Ccm8Sha256
    _ -> UnknownCipherSuite(identifier)
  }
}

fn cipher_suite_to_wire(cipher_suite: CipherSuite) -> Result(Int, Error) {
  case cipher_suite {
    Aes128GcmSha256 -> Ok(0x1301)
    Aes256GcmSha384 -> Ok(0x1302)
    Chacha20Poly1305Sha256 -> Ok(0x1303)
    Aes128CcmSha256 -> Ok(0x1304)
    Aes128Ccm8Sha256 -> Ok(0x1305)
    UnknownCipherSuite(identifier) ->
      case
        identifier >= 0
        && identifier <= 65_535
        && cipher_suite_from_wire(identifier) == UnknownCipherSuite(identifier)
      {
        True -> Ok(identifier)
        False -> Error(InvalidCipherSuites)
      }
  }
}

fn take_exact_vector16(bytes: BitArray) -> Result(BitArray, Error) {
  case bytes {
    <<length:size(16), value_and_rest:bits>> -> {
      use #(value, rest) <- result.try(take(value_and_rest, length))
      case rest {
        <<>> -> Ok(value)
        _ -> Error(InvalidExtensions)
      }
    }
    _ -> Error(Truncated)
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
