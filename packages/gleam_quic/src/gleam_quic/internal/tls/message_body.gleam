//// Bounded TLS 1.3 authentication, extension-flight, and ticket bodies.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam_quic/internal/crypto.{type HashAlgorithm}
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/extension_value

const maximum_ticket_lifetime = 604_800

const certificate_verify_padding = <<
  "                                                                ",
>>

/// One X.509 CertificateEntry and its per-certificate TLS extensions.
pub type CertificateEntry {
  CertificateEntry(
    certificate_der: BitArray,
    extensions: List(extension.Extension),
  )
}

/// A TLS 1.3 Certificate body.
pub type CertificateMessage {
  CertificateMessage(request_context: BitArray, entries: List(CertificateEntry))
}

/// A TLS 1.3 CertificateRequest body.
pub type CertificateRequest {
  CertificateRequest(
    request_context: BitArray,
    extensions: List(extension.Extension),
  )
}

/// A TLS 1.3 CertificateVerify body.
pub type CertificateVerify {
  CertificateVerify(
    signature_scheme: extension_value.SignatureScheme,
    signature: BitArray,
  )
}

/// A TLS 1.3 NewSessionTicket body.
pub type NewSessionTicket {
  NewSessionTicket(
    ticket_lifetime: Int,
    ticket_age_add: Int,
    ticket_nonce: BitArray,
    ticket: BitArray,
    extensions: List(extension.Extension),
  )
}

/// The signer determines the CertificateVerify context string.
pub type AuthenticationRole {
  Client
  Server
}

/// Peer-controlled bounds for certificate, signature, and ticket messages.
pub type Limits {
  Limits(
    maximum_certificates: Int,
    maximum_certificate_length: Int,
    maximum_chain_length: Int,
    maximum_signature_length: Int,
    maximum_ticket_length: Int,
    extension_limits: extension.Limits,
  )
}

/// A TLS message-body codec or semantic failure.
pub type Error {
  NonByteAligned
  InvalidLimits
  Truncated
  TrailingData
  InvalidLength
  EmptyCertificate
  EmptySignature
  TooManyCertificates
  CertificateTooLarge(Int)
  ChainTooLarge(Int)
  SignatureTooLarge(Int)
  TicketTooLarge(Int)
  InvalidTicketLifetime
  InvalidTicketAgeAdd
  InvalidFinishedLength(Int)
  ExtensionFailure(extension.Error)
  ExtensionValueFailure(extension_value.Error)
}

/// Conservative public-Internet message limits.
pub fn default_limits() -> Limits {
  Limits(
    maximum_certificates: 16,
    maximum_certificate_length: 1_048_576,
    maximum_chain_length: 4_194_304,
    maximum_signature_length: 16_384,
    maximum_ticket_length: 65_535,
    extension_limits: extension.default_limits(),
  )
}

/// Encode EncryptedExtensions with its outer 16-bit vector length.
pub fn encode_encrypted_extensions(
  extensions extensions: List(extension.Extension),
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_limits(limits))
  use encoded <- result.try(
    extension.encode_all(
      extensions,
      extension.OtherExtensions,
      limits.extension_limits,
    )
    |> map_extension_result,
  )
  vector16(encoded)
}

/// Decode EncryptedExtensions with its outer 16-bit vector length.
pub fn decode_encrypted_extensions(
  body body: BitArray,
  limits limits: Limits,
) -> Result(List(extension.Extension), Error) {
  use Nil <- result.try(validate_limits(limits))
  use encoded <- result.try(exact_vector16(body))
  extension.decode_all(
    encoded,
    extension.OtherExtensions,
    limits.extension_limits,
  )
  |> map_extension_result
}

/// Encode a TLS 1.3 Certificate body.
pub fn encode_certificate(
  certificate certificate: CertificateMessage,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_limits(limits))
  use Nil <- result.try(require_byte_aligned(certificate.request_context))
  let context_length = bit_array.byte_size(certificate.request_context)
  case context_length > 255 {
    True -> Error(InvalidLength)
    False -> {
      use encoded_entries <- result.try(
        encode_certificate_entries(certificate.entries, limits, 0, <<>>),
      )
      let chain_length = bit_array.byte_size(encoded_entries)
      case
        chain_length > limits.maximum_chain_length || chain_length > 0xff_ffff
      {
        True -> Error(ChainTooLarge(chain_length))
        False ->
          Ok(<<
            context_length,
            certificate.request_context:bits,
            chain_length:size(24),
            encoded_entries:bits,
          >>)
      }
    }
  }
}

/// Decode a TLS 1.3 Certificate body.
pub fn decode_certificate(
  body body: BitArray,
  limits limits: Limits,
) -> Result(CertificateMessage, Error) {
  use Nil <- result.try(validate_limits(limits))
  use Nil <- result.try(require_byte_aligned(body))
  case body {
    <<context_length, rest:bits>> -> {
      use #(request_context, after_context) <- result.try(take(
        rest,
        context_length,
      ))
      use certificate_list <- result.try(exact_vector24(after_context))
      let chain_length = bit_array.byte_size(certificate_list)
      case chain_length > limits.maximum_chain_length {
        True -> Error(ChainTooLarge(chain_length))
        False -> {
          use entries <- result.try(
            decode_certificate_entries(certificate_list, limits, 0, []),
          )
          Ok(CertificateMessage(request_context, entries))
        }
      }
    }
    _ -> Error(Truncated)
  }
}

/// Encode a TLS 1.3 CertificateRequest body.
pub fn encode_certificate_request(
  request request: CertificateRequest,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_limits(limits))
  let CertificateRequest(context, extensions) = request
  use Nil <- result.try(require_byte_aligned(context))
  let context_length = bit_array.byte_size(context)
  case context_length > 255 {
    True -> Error(InvalidLength)
    False -> {
      use encoded_extensions <- result.try(
        extension.encode_all(
          extensions,
          extension.OtherExtensions,
          limits.extension_limits,
        )
        |> map_extension_result,
      )
      use extension_vector <- result.try(vector16(encoded_extensions))
      Ok(<<context_length, context:bits, extension_vector:bits>>)
    }
  }
}

/// Decode a TLS 1.3 CertificateRequest body.
pub fn decode_certificate_request(
  body body: BitArray,
  limits limits: Limits,
) -> Result(CertificateRequest, Error) {
  use Nil <- result.try(validate_limits(limits))
  use Nil <- result.try(require_byte_aligned(body))
  case body {
    <<context_length, rest:bits>> -> {
      use #(context, encoded_extensions) <- result.try(take(
        rest,
        context_length,
      ))
      use extension_bytes <- result.try(exact_vector16(encoded_extensions))
      use extensions <- result.try(
        extension.decode_all(
          extension_bytes,
          extension.OtherExtensions,
          limits.extension_limits,
        )
        |> map_extension_result,
      )
      Ok(CertificateRequest(context, extensions))
    }
    _ -> Error(Truncated)
  }
}

/// Encode a TLS 1.3 CertificateVerify body.
pub fn encode_certificate_verify(
  verify verify: CertificateVerify,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_limits(limits))
  let CertificateVerify(scheme, signature) = verify
  use Nil <- result.try(require_byte_aligned(signature))
  let signature_length = bit_array.byte_size(signature)
  case signature_length {
    0 -> Error(EmptySignature)
    length if length > limits.maximum_signature_length ->
      Error(SignatureTooLarge(length))
    length if length > 65_535 -> Error(SignatureTooLarge(length))
    _ -> {
      use encoded_scheme <- result.try(
        extension_value.encode_signature_scheme(scheme)
        |> map_extension_value_result,
      )
      Ok(<<encoded_scheme:bits, signature_length:size(16), signature:bits>>)
    }
  }
}

/// Decode a TLS 1.3 CertificateVerify body.
pub fn decode_certificate_verify(
  body body: BitArray,
  limits limits: Limits,
) -> Result(CertificateVerify, Error) {
  use Nil <- result.try(validate_limits(limits))
  use Nil <- result.try(require_byte_aligned(body))
  case body {
    <<scheme:bits-size(16), signature_length:size(16), signature:bits>> ->
      case signature_length, bit_array.byte_size(signature) {
        0, _ -> Error(EmptySignature)
        declared, actual if declared != actual -> Error(Truncated)
        length, _ if length > limits.maximum_signature_length ->
          Error(SignatureTooLarge(length))
        _, _ -> {
          use decoded_scheme <- result.try(
            extension_value.decode_signature_scheme(scheme)
            |> map_extension_value_result,
          )
          Ok(CertificateVerify(decoded_scheme, signature))
        }
      }
    _ -> Error(Truncated)
  }
}

/// Validate and encode Finished.verify_data.
pub fn encode_finished(
  algorithm algorithm: HashAlgorithm,
  verify_data verify_data: BitArray,
) -> Result(BitArray, Error) {
  validate_finished(algorithm, verify_data)
}

/// Validate and decode Finished.verify_data.
pub fn decode_finished(
  algorithm algorithm: HashAlgorithm,
  body body: BitArray,
) -> Result(BitArray, Error) {
  validate_finished(algorithm, body)
}

/// Encode a TLS 1.3 NewSessionTicket body.
pub fn encode_new_session_ticket(
  ticket ticket: NewSessionTicket,
  limits limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(validate_limits(limits))
  let NewSessionTicket(lifetime, age_add, nonce, opaque_ticket, extensions) =
    ticket
  use Nil <- result.try(require_byte_aligned(nonce))
  use Nil <- result.try(require_byte_aligned(opaque_ticket))
  use Nil <- result.try(validate_ticket_fields(
    lifetime,
    age_add,
    nonce,
    opaque_ticket,
    limits,
  ))
  use encoded_extensions <- result.try(
    extension.encode_all(
      extensions,
      extension.OtherExtensions,
      limits.extension_limits,
    )
    |> map_extension_result,
  )
  let nonce_length = bit_array.byte_size(nonce)
  let ticket_length = bit_array.byte_size(opaque_ticket)
  let extension_length = bit_array.byte_size(encoded_extensions)
  Ok(<<
    lifetime:size(32),
    age_add:size(32),
    nonce_length,
    nonce:bits,
    ticket_length:size(16),
    opaque_ticket:bits,
    extension_length:size(16),
    encoded_extensions:bits,
  >>)
}

/// Decode a TLS 1.3 NewSessionTicket body.
pub fn decode_new_session_ticket(
  body body: BitArray,
  limits limits: Limits,
) -> Result(NewSessionTicket, Error) {
  use Nil <- result.try(validate_limits(limits))
  use Nil <- result.try(require_byte_aligned(body))
  case body {
    <<lifetime:size(32), age_add:size(32), nonce_length, rest:bits>> -> {
      use #(nonce, after_nonce) <- result.try(take(rest, nonce_length))
      use #(opaque_ticket, encoded_extensions) <- result.try(take_vector16(
        after_nonce,
      ))
      use extension_bytes <- result.try(exact_vector16(encoded_extensions))
      use Nil <- result.try(validate_ticket_fields(
        lifetime,
        age_add,
        nonce,
        opaque_ticket,
        limits,
      ))
      use extensions <- result.try(
        extension.decode_all(
          extension_bytes,
          extension.OtherExtensions,
          limits.extension_limits,
        )
        |> map_extension_result,
      )
      Ok(NewSessionTicket(lifetime, age_add, nonce, opaque_ticket, extensions))
    }
    _ -> Error(Truncated)
  }
}

/// Construct the exact context signed by CertificateVerify.
pub fn certificate_verify_content(
  role role: AuthenticationRole,
  transcript_hash transcript_hash: BitArray,
) -> BitArray {
  let context = case role {
    Client -> <<"TLS 1.3, client CertificateVerify">>
    Server -> <<"TLS 1.3, server CertificateVerify">>
  }
  <<certificate_verify_padding:bits, context:bits, 0, transcript_hash:bits>>
}

fn encode_certificate_entries(
  entries: List(CertificateEntry),
  limits: Limits,
  count: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  case entries {
    [] -> Ok(accumulator)
    [entry, ..rest] -> {
      let next_count = count + 1
      case next_count > limits.maximum_certificates {
        True -> Error(TooManyCertificates)
        False ->
          encode_next_certificate_entry(
            entry,
            rest,
            limits,
            next_count,
            accumulator,
          )
      }
    }
  }
}

fn encode_next_certificate_entry(
  entry: CertificateEntry,
  rest: List(CertificateEntry),
  limits: Limits,
  next_count: Int,
  accumulator: BitArray,
) -> Result(BitArray, Error) {
  use encoded <- result.try(encode_certificate_entry(entry, limits))
  let next_length =
    bit_array.byte_size(accumulator) + bit_array.byte_size(encoded)
  case next_length > limits.maximum_chain_length {
    True -> Error(ChainTooLarge(next_length))
    False ->
      encode_certificate_entries(rest, limits, next_count, <<
        accumulator:bits,
        encoded:bits,
      >>)
  }
}

fn encode_certificate_entry(
  entry: CertificateEntry,
  limits: Limits,
) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(entry.certificate_der))
  let certificate_length = bit_array.byte_size(entry.certificate_der)
  case certificate_length {
    0 -> Error(EmptyCertificate)
    length if length > limits.maximum_certificate_length ->
      Error(CertificateTooLarge(length))
    length if length > 0xff_ffff -> Error(CertificateTooLarge(length))
    _ -> {
      use encoded_extensions <- result.try(
        extension.encode_all(
          entry.extensions,
          extension.OtherExtensions,
          limits.extension_limits,
        )
        |> map_extension_result,
      )
      let extension_length = bit_array.byte_size(encoded_extensions)
      Ok(<<
        certificate_length:size(24),
        entry.certificate_der:bits,
        extension_length:size(16),
        encoded_extensions:bits,
      >>)
    }
  }
}

fn decode_certificate_entries(
  bytes: BitArray,
  limits: Limits,
  count: Int,
  reversed: List(CertificateEntry),
) -> Result(List(CertificateEntry), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<certificate_length:size(24), rest:bits>> -> {
      let next_count = count + 1
      case next_count > limits.maximum_certificates {
        True -> Error(TooManyCertificates)
        False -> {
          use #(certificate_der, after_certificate) <- result.try(take(
            rest,
            certificate_length,
          ))
          use #(extension_bytes, remaining) <- result.try(take_vector16(
            after_certificate,
          ))
          use entry <- result.try(decode_certificate_entry(
            certificate_der,
            extension_bytes,
            limits,
          ))
          decode_certificate_entries(remaining, limits, next_count, [
            entry,
            ..reversed
          ])
        }
      }
    }
    _ -> Error(Truncated)
  }
}

fn decode_certificate_entry(
  certificate_der: BitArray,
  extension_bytes: BitArray,
  limits: Limits,
) -> Result(CertificateEntry, Error) {
  let certificate_length = bit_array.byte_size(certificate_der)
  case certificate_length {
    0 -> Error(EmptyCertificate)
    length if length > limits.maximum_certificate_length ->
      Error(CertificateTooLarge(length))
    _ -> {
      use extensions <- result.try(
        extension.decode_all(
          extension_bytes,
          extension.OtherExtensions,
          limits.extension_limits,
        )
        |> map_extension_result,
      )
      Ok(CertificateEntry(certificate_der, extensions))
    }
  }
}

fn validate_finished(
  algorithm: HashAlgorithm,
  verify_data: BitArray,
) -> Result(BitArray, Error) {
  use Nil <- result.try(require_byte_aligned(verify_data))
  let length = bit_array.byte_size(verify_data)
  case length == crypto.hash_length(algorithm) {
    True -> Ok(verify_data)
    False -> Error(InvalidFinishedLength(length))
  }
}

fn validate_ticket_fields(
  lifetime: Int,
  age_add: Int,
  nonce: BitArray,
  opaque_ticket: BitArray,
  limits: Limits,
) -> Result(Nil, Error) {
  let ticket_length = bit_array.byte_size(opaque_ticket)
  case
    lifetime >= 0 && lifetime <= maximum_ticket_lifetime,
    age_add >= 0 && age_add <= 0xffff_ffff,
    bit_array.byte_size(nonce) <= 255,
    ticket_length > 0
    && ticket_length <= limits.maximum_ticket_length
    && ticket_length <= 65_535
  {
    False, _, _, _ -> Error(InvalidTicketLifetime)
    _, False, _, _ -> Error(InvalidTicketAgeAdd)
    _, _, False, _ -> Error(InvalidLength)
    _, _, _, False -> Error(TicketTooLarge(ticket_length))
    True, True, True, True -> Ok(Nil)
  }
}

fn validate_limits(limits: Limits) -> Result(Nil, Error) {
  case
    limits.maximum_certificates > 0
    && limits.maximum_certificate_length > 0
    && limits.maximum_certificate_length <= 0xff_ffff
    && limits.maximum_chain_length >= 0
    && limits.maximum_chain_length <= 0xff_ffff
    && limits.maximum_signature_length > 0
    && limits.maximum_signature_length <= 65_535
    && limits.maximum_ticket_length > 0
    && limits.maximum_ticket_length <= 65_535
  {
    True -> Ok(Nil)
    False -> Error(InvalidLimits)
  }
}

fn vector16(bytes: BitArray) -> Result(BitArray, Error) {
  let length = bit_array.byte_size(bytes)
  case length <= 65_535 {
    True -> Ok(<<length:size(16), bytes:bits>>)
    False -> Error(InvalidLength)
  }
}

fn exact_vector16(bytes: BitArray) -> Result(BitArray, Error) {
  use #(value, rest) <- result.try(take_vector16(bytes))
  case rest {
    <<>> -> Ok(value)
    _ -> Error(TrailingData)
  }
}

fn take_vector16(bytes: BitArray) -> Result(#(BitArray, BitArray), Error) {
  case bytes {
    <<length:size(16), rest:bits>> -> take(rest, length)
    _ -> Error(Truncated)
  }
}

fn exact_vector24(bytes: BitArray) -> Result(BitArray, Error) {
  case bytes {
    <<length:size(24), value:bits>> ->
      case bit_array.byte_size(value) == length {
        True -> Ok(value)
        False -> Error(Truncated)
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
        <<value:bits-size(bit_length), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Truncated)
      }
    }
  }
}

fn require_byte_aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 == 0 {
    True -> Ok(Nil)
    False -> Error(NonByteAligned)
  }
}

fn map_extension_result(
  value: Result(output, extension.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(ExtensionFailure(error))
  }
}

fn map_extension_value_result(
  value: Result(output, extension_value.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(ExtensionValueFailure(error))
  }
}
