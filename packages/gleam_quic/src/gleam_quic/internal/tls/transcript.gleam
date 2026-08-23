//// Bounded TLS 1.3 transcript hashing with HelloRetryRequest rewriting.

import gleam/bit_array
import gleam/result
import gleam_quic/internal/crypto.{type HashAlgorithm}
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello

const maximum_configured_length = 16_777_216

/// A byte-exact TLS transcript. The constructor and stored bytes stay internal.
pub opaque type Transcript {
  Transcript(
    algorithm: HashAlgorithm,
    encoded_messages: BitArray,
    maximum_length: Int,
  )
}

/// A transcript validation or hashing failure.
pub type Error {
  InvalidLimit
  NonByteAligned
  Truncated
  MultipleMessages
  ForbiddenInQuic(handshake.MessageType)
  TranscriptTooLarge(Int)
  InvalidHelloRetryRequest
  HandshakeFailure(handshake.Error)
  HelloFailure(hello.Error)
  CryptoFailure(crypto.Error)
}

/// Create an empty bounded transcript.
pub fn new(
  algorithm algorithm: HashAlgorithm,
  maximum_length maximum_length: Int,
) -> Result(Transcript, Error) {
  case maximum_length > 0 && maximum_length <= maximum_configured_length {
    True -> Ok(Transcript(algorithm, <<>>, maximum_length))
    False -> Error(InvalidLimit)
  }
}

/// Append one complete, byte-exact TLS Handshake message.
pub fn append(
  transcript transcript: Transcript,
  encoded_message encoded_message: BitArray,
) -> Result(Transcript, Error) {
  let Transcript(algorithm, encoded_messages, maximum_length) = transcript
  use message <- result.try(decode_exact(encoded_message))
  let handshake.Message(message_type, _) = message
  case handshake.forbidden_in_quic(message_type) {
    True -> Error(ForbiddenInQuic(message_type))
    False -> {
      let next_length =
        bit_array.byte_size(encoded_messages)
        + bit_array.byte_size(encoded_message)
      case next_length > maximum_length {
        True -> Error(TranscriptTooLarge(next_length))
        False ->
          Ok(Transcript(
            algorithm,
            <<encoded_messages:bits, encoded_message:bits>>,
            maximum_length,
          ))
      }
    }
  }
}

/// Apply TLS 1.3's synthetic `message_hash` rewrite before a retry message.
pub fn replace_for_hello_retry_request(
  transcript transcript: Transcript,
  encoded_retry encoded_retry: BitArray,
) -> Result(Transcript, Error) {
  let Transcript(algorithm, encoded_messages, maximum_length) = transcript
  use Nil <- result.try(validate_first_client_hello(encoded_messages))
  use Nil <- result.try(validate_hello_retry_request(encoded_retry))
  use client_hello_hash <- result.try(
    crypto.hash(algorithm, encoded_messages) |> map_crypto_result,
  )
  let digest_length = crypto.hash_length(algorithm)
  let replacement = <<
    254,
    digest_length:size(24),
    client_hello_hash:bits,
    encoded_retry:bits,
  >>
  let replacement_length = bit_array.byte_size(replacement)
  case replacement_length > maximum_length {
    True -> Error(TranscriptTooLarge(replacement_length))
    False -> Ok(Transcript(algorithm, replacement, maximum_length))
  }
}

/// Hash all byte-exact Handshake messages currently in the transcript.
pub fn hash(transcript transcript: Transcript) -> Result(BitArray, Error) {
  let Transcript(algorithm, encoded_messages, _) = transcript
  crypto.hash(algorithm, encoded_messages) |> map_crypto_result
}

/// Return the encoded transcript for CRYPTO replay and deterministic tests.
pub fn bytes(transcript transcript: Transcript) -> BitArray {
  let Transcript(_, encoded_messages, _) = transcript
  encoded_messages
}

fn validate_first_client_hello(bytes: BitArray) -> Result(Nil, Error) {
  case decode_exact(bytes) {
    Ok(handshake.Message(handshake.ClientHello, _)) -> Ok(Nil)
    _ -> Error(InvalidHelloRetryRequest)
  }
}

fn validate_hello_retry_request(bytes: BitArray) -> Result(Nil, Error) {
  use message <- result.try(decode_exact(bytes))
  case message {
    handshake.Message(handshake.ServerHello, body) ->
      case hello.decode_server(body, hello.default_limits()) {
        Ok(hello.HelloRetryRequest(..)) -> Ok(Nil)
        Ok(_) -> Error(InvalidHelloRetryRequest)
        Error(error) -> Error(HelloFailure(error))
      }
    _ -> Error(InvalidHelloRetryRequest)
  }
}

fn decode_exact(bytes: BitArray) -> Result(handshake.Message, Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) -> Error(Truncated)
    Ok(handshake.Complete(message, <<>>)) -> Ok(message)
    Ok(handshake.Complete(_, _)) -> Error(MultipleMessages)
    Error(handshake.NonByteAligned) -> Error(NonByteAligned)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn map_crypto_result(
  value: Result(BitArray, crypto.Error),
) -> Result(BitArray, Error) {
  case value {
    Ok(bytes) -> Ok(bytes)
    Error(error) -> Error(CryptoFailure(error))
  }
}
