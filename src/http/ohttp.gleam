//// RFC 9458 Oblivious HTTP client, relay, and gateway primitives.
////
//// Only RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256) is active.
//// The symmetric choices are HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305.
//// Unsupported registry identifiers fail closed and are never substituted.

import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import http/bhttp

const x25519_hkdf_sha256 = 0x0020

const hkdf_sha256 = 0x0001

const aes_128_gcm = 0x0001

const chacha20_poly1305 = 0x0003

const public_key_bytes = 32

const authentication_tag_bytes = 16

const request_header_bytes = 7

const replay_without_expiry = -1

type ContextClaim

type ReplayStoreHandle

type ReplayLease

/// One KDF and AEAD combination advertised for a gateway key.
pub type SymmetricAlgorithm {
  SymmetricAlgorithm(kdf_id: Int, aead_id: Int)
}

/// One authenticated OHTTP gateway key configuration.
pub type KeyConfiguration {
  KeyConfiguration(
    key_id: Int,
    kem_id: Int,
    public_key: BitArray,
    algorithms: List(SymmetricAlgorithm),
  )
}

/// A relay's deliberately metadata-free forwarding instruction.
pub type RelayForward {
  RelayForward(gateway_uri: String, content_type: String, body: BitArray)
}

/// Gateway private key material and its public configuration.
pub opaque type GatewayKey {
  GatewayKey(configuration: KeyConfiguration, private_key: BitArray)
}

/// Client configuration.
/// A fresh operating-system CSPRNG ephemeral key is generated for every request.
pub opaque type Client {
  Client(
    configuration: KeyConfiguration,
    algorithm: SymmetricAlgorithm,
    bhttp_limits: bhttp.Limits,
    maximum_message_bytes: Int,
  )
}

type CryptoContext {
  CryptoContext(
    exporter_secret: BitArray,
    encapsulated_key: BitArray,
    algorithm: SymmetricAlgorithm,
    bhttp_limits: bhttp.Limits,
    maximum_message_bytes: Int,
  )
}

/// Client-side response context bound to exactly one encapsulated request.
pub opaque type ClientContext {
  ClientContext(CryptoContext, ContextClaim)
}

/// Gateway-side response context bound to exactly one opened request.
pub opaque type GatewayContext {
  GatewayContext(CryptoContext, ContextClaim)
}

/// Gateway policy and private key.
/// The authority allowlist is exact and empty means deny all target requests.
pub opaque type Gateway {
  Gateway(
    key: GatewayKey,
    allowed_authorities: List(String),
    bhttp_limits: bhttp.Limits,
    maximum_message_bytes: Int,
  )
}

/// A shared, concurrent, finite replay set owned by its creating process.
///
/// Accepted request identities do not expire in the compatibility store.
/// Pending authentication work counts toward the same hard capacity, and is released on authentication failure, deadline, or caller termination.
pub opaque type ReplayStore {
  ReplayStore(handle: ReplayStoreHandle)
}

/// A policy failure found after an Encapsulated Request was authenticated.
///
/// These values contain no target, request bytes, credentials, or exception data and are safe to use for finite diagnostics.
pub type ProtectedRequestFailure {
  MalformedRequest
  ContinueExpectationRejected
  TargetRejected
}

/// The result of authenticating and applying gateway policy to one request.
///
/// Both variants retain the one-shot response context required by RFC 9458 section 5.2.
/// A rejected request therefore remains capable of producing an Encapsulated Response.
pub type GatewayOpen(payload) {
  GatewayOpened(payload: payload, response_context: GatewayContext)
  GatewayRejected(
    failure: ProtectedRequestFailure,
    response_context: GatewayContext,
  )
}

/// Integration-oriented gateway admission result.
pub type GatewayAdmission {
  ForwardRequest(request: bhttp.Message, response_context: GatewayContext)
  ProtectedResponse(body: BitArray)
}

/// A relay maps one public resource to one fixed HTTPS gateway.
pub opaque type Relay {
  Relay(gateway_uri: String, maximum_message_bytes: Int)
}

type HpkeContext {
  HpkeContext(key: BitArray, base_nonce: BitArray, exporter_secret: BitArray)
}

/// Configuration, policy, syntax, resource, replay, or cryptographic failure.
pub type Error {
  InvalidConfiguration
  InvalidMessage
  InvalidMediaType
  InvalidRelay
  InvalidKey
  UnsupportedAlgorithm
  NonByteAligned
  LimitExceeded
  ReplayDetected
  ReplayCapacityExceeded
  ReplayStoreUnavailable
  ContextReuseDetected
  ContinueExpectationForbidden
  TargetNotAllowed
  DecryptionFailed
  CryptoFailure
}

/// Decode exactly one RFC 9458 key configuration.
pub fn decode_key_configuration(
  bytes: BitArray,
) -> Result(KeyConfiguration, Error) {
  use _ <- result.try(aligned(bytes))
  case bytes {
    <<
      key_id,
      kem_id:size(16),
      public_key:bytes-size(public_key_bytes),
      algorithms_length:size(16),
      algorithms:bytes-size(algorithms_length),
    >> -> {
      use _ <- result.try(require(kem_id == x25519_hkdf_sha256))
      use _ <- result.try(require(
        algorithms_length >= 4 && algorithms_length % 4 == 0,
      ))
      use algorithms <- result.try(decode_algorithms(algorithms, []))
      let configuration =
        KeyConfiguration(key_id, kem_id, public_key, algorithms)
      use _ <- result.try(validate_configuration(configuration))
      Ok(configuration)
    }
    _ -> Error(InvalidConfiguration)
  }
}

/// Encode one key configuration without the collection length prefix.
pub fn encode_key_configuration(
  configuration: KeyConfiguration,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_configuration(configuration))
  use algorithms <- result.try(encode_algorithms(configuration.algorithms, []))
  let algorithms = bit_array.concat(algorithms)
  let length = bit_array.byte_size(algorithms)
  use _ <- result.try(require(length <= 65_532))
  Ok(<<
    configuration.key_id,
    configuration.kem_id:size(16),
    configuration.public_key:bits,
    length:size(16),
    algorithms:bits,
  >>)
}

/// Decode a strict `application/ohttp-keys` collection.
/// Any malformed member invalidates the complete collection to avoid client fingerprinting.
pub fn decode_key_configurations(
  bytes: BitArray,
  maximum_configurations maximum_configurations: Int,
) -> Result(List(KeyConfiguration), Error) {
  use _ <- result.try(aligned(bytes))
  use _ <- result.try(case maximum_configurations > 0 {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  })
  decode_configuration_collection(bytes, maximum_configurations, [])
}

/// Encode a non-empty strict `application/ohttp-keys` collection.
pub fn encode_key_configurations(
  configurations: List(KeyConfiguration),
) -> Result(BitArray, Error) {
  case configurations {
    [] -> Error(InvalidConfiguration)
    _ -> {
      use members <- result.try(
        encode_configuration_collection(configurations, []),
      )
      Ok(bit_array.concat(members))
    }
  }
}

/// Import an X25519 gateway private key and derive its public configuration.
pub fn gateway_key(
  key_id key_id: Int,
  private_key private_key: BitArray,
  algorithms algorithms: List(SymmetricAlgorithm),
) -> Result(GatewayKey, Error) {
  use _ <- result.try(aligned(private_key))
  use _ <- result.try(
    case
      key_id >= 0
      && key_id <= 255
      && bit_array.byte_size(private_key) == public_key_bytes
    {
      True -> Ok(Nil)
      False -> Error(InvalidKey)
    },
  )
  use public_key <- result.try(
    x25519_public(private_key) |> result.map_error(fn(_) { CryptoFailure }),
  )
  let configuration =
    KeyConfiguration(key_id, x25519_hkdf_sha256, public_key, algorithms)
  use _ <- result.try(validate_configuration(configuration))
  Ok(GatewayKey(configuration, private_key))
}

/// Return the public portion of a gateway key.
pub fn key_configuration(key: GatewayKey) -> KeyConfiguration {
  key.configuration
}

/// Create a client that generates a fresh ephemeral X25519 key for every seal.
pub fn client(
  configuration: KeyConfiguration,
  bhttp_limits: bhttp.Limits,
  maximum_message_bytes maximum_message_bytes: Int,
) -> Result(Client, Error) {
  new_client(configuration, bhttp_limits, maximum_message_bytes)
}

/// Encode and encapsulate a binary HTTP request.
pub fn seal_request(
  client client: Client,
  request request: bhttp.Message,
  mode mode: bhttp.Mode,
) -> Result(#(BitArray, ClientContext), Error) {
  use _ <- result.try(case request {
    bhttp.Request(..) -> Ok(Nil)
    bhttp.Response(..) -> Error(InvalidMessage)
  })
  use _ <- result.try(reject_continue_expectation(request))
  use encoded <- result.try(
    bhttp.encode(request, mode, client.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  seal_request_bytes_unchecked(client, encoded)
}

/// Validate and encapsulate already encoded `message/bhttp` request bytes.
///
/// Validation, including the OHTTP `Expect: 100-continue` prohibition, runs before a production HPKE key is derived.
pub fn seal_request_bytes(
  client client: Client,
  request request: BitArray,
) -> Result(#(BitArray, ClientContext), Error) {
  use _ <- result.try(validate_message_bytes(
    request,
    client.maximum_message_bytes
      - request_header_bytes
      - public_key_bytes
      - authentication_tag_bytes,
  ))
  use _ <- result.try(decode_target_request(request, client.bhttp_limits))
  seal_request_bytes_unchecked(client, request)
}

fn seal_request_bytes_unchecked(
  client: Client,
  request: BitArray,
) -> Result(#(BitArray, ClientContext), Error) {
  use _ <- result.try(validate_message_bytes(
    request,
    client.maximum_message_bytes
      - request_header_bytes
      - public_key_bytes
      - authentication_tag_bytes,
  ))
  use ephemeral_private <- result.try(
    random_bytes(public_key_bytes) |> crypto_result,
  )
  use encapsulated_key <- result.try(
    x25519_public(ephemeral_private) |> crypto_result,
  )
  use shared <- result.try(
    x25519_shared(ephemeral_private, client.configuration.public_key)
    |> crypto_result,
  )
  let header = configuration_header(client.configuration, client.algorithm)
  let info = <<"message/bhttp request":utf8, 0, header:bits>>
  use hpke <- result.try(setup_hpke(
    shared,
    <<
      encapsulated_key:bits,
      client.configuration.public_key:bits,
    >>,
    info,
    client.algorithm,
  ))
  use ciphertext <- result.try(
    aead_seal(client.algorithm.aead_id, hpke.key, hpke.base_nonce, request)
    |> crypto_result,
  )
  let sealed = <<header:bits, encapsulated_key:bits, ciphertext:bits>>
  use _ <- result.try(validate_message_bytes(
    sealed,
    client.maximum_message_bytes,
  ))
  let context =
    CryptoContext(
      hpke.exporter_secret,
      encapsulated_key,
      client.algorithm,
      client.bhttp_limits,
      client.maximum_message_bytes,
    )
  Ok(#(sealed, ClientContext(context, new_context_claim())))
}

/// Create a gateway with an exact HTTPS target-authority allowlist.
pub fn gateway(
  key: GatewayKey,
  allowed_authorities allowed_authorities: List(String),
  bhttp_limits bhttp_limits: bhttp.Limits,
  maximum_message_bytes maximum_message_bytes: Int,
) -> Result(Gateway, Error) {
  use _ <- result.try(validate_maximum(maximum_message_bytes))
  use _ <- result.try(validate_authorities(allowed_authorities))
  Ok(Gateway(key, allowed_authorities, bhttp_limits, maximum_message_bytes))
}

/// Create a shared finite replay set.
/// Capacity exhaustion fails closed.
///
/// The creating process owns the store.
/// Calls after that process or the store exits return `ReplayStoreUnavailable`; a dead store is never replaced with an empty one.
pub fn replay_store(
  maximum_entries maximum_entries: Int,
) -> Result(ReplayStore, Error) {
  case maximum_entries > 0 && maximum_entries <= 1_000_000 {
    True ->
      case new_replay_store(maximum_entries, replay_without_expiry) {
        Ok(handle) -> Ok(ReplayStore(handle))
        Error(_) -> Error(ReplayStoreUnavailable)
      }
    False -> Error(InvalidConfiguration)
  }
}

/// Create a shared replay set with an explicit accepted-identity retention window.
/// Applications must choose a window consistent with their request replay policy; expiry permits an old request to be admitted again.
pub fn replay_store_with_retention(
  maximum_entries maximum_entries: Int,
  retention_milliseconds retention_milliseconds: Int,
) -> Result(ReplayStore, Error) {
  case
    maximum_entries > 0
    && maximum_entries <= 1_000_000
    && retention_milliseconds > 0
  {
    True ->
      case new_replay_store(maximum_entries, retention_milliseconds) {
        Ok(handle) -> Ok(ReplayStore(handle))
        Error(_) -> Error(ReplayStoreUnavailable)
      }
    False -> Error(InvalidConfiguration)
  }
}

/// Close a replay store.
/// Closing an already closed or owner-terminated store is harmless.
pub fn close_replay_store(store: ReplayStore) -> Nil {
  let ReplayStore(handle) = store
  let _closed = close_replay_store_handle(handle)
  Nil
}

/// Authenticate, decode, and authorize one target request without losing the response context when policy validation fails after authenticated opening.
pub fn open_request_detailed(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
) -> Result(#(GatewayOpen(bhttp.Message), ReplayStore), Error) {
  use #(plaintext, context, replays) <- result.try(open_request_bytes_unchecked(
    gateway,
    replays,
    sealed,
  ))
  Ok(#(classify_opened_request(gateway, plaintext, context), replays))
}

/// Authenticate one encoded request and retain its response context for every failure discovered after authenticated opening.
pub fn open_request_bytes_detailed(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
) -> Result(#(GatewayOpen(BitArray), ReplayStore), Error) {
  use #(plaintext, context, replays) <- result.try(open_request_bytes_unchecked(
    gateway,
    replays,
    sealed,
  ))
  let opened = case classify_opened_request(gateway, plaintext, context) {
    GatewayOpened(_, context) -> GatewayOpened(plaintext, context)
    GatewayRejected(failure, context) -> GatewayRejected(failure, context)
  }
  Ok(#(opened, replays))
}

/// Produce a canonical, metadata-free Encapsulated Response for a failure discovered after authenticated opening.
pub fn seal_protected_failure(
  failure: ProtectedRequestFailure,
  context: GatewayContext,
) -> Result(BitArray, Error) {
  let status = case failure {
    MalformedRequest -> 400
    ContinueExpectationRejected -> 417
    TargetRejected -> 403
  }
  seal_response(
    context: context,
    response: bhttp.Response([], status, [], [], [], 0),
    mode: bhttp.KnownLength,
  )
}

/// Authenticate and admit an OHTTP request for an integrated gateway.
///
/// Pre-opening failures remain an outer HTTP error.
/// Every post-opening policy failure is converted immediately into a canonical Encapsulated Response.
pub fn admit_request(
  gateway: Gateway,
  replays: ReplayStore,
  sealed: BitArray,
) -> Result(#(GatewayAdmission, ReplayStore), Error) {
  use #(opened, replays) <- result.try(open_request_detailed(
    gateway: gateway,
    replays: replays,
    sealed: sealed,
  ))
  case opened {
    GatewayOpened(request, context) ->
      Ok(#(ForwardRequest(request, context), replays))
    GatewayRejected(failure, context) -> {
      use response <- result.try(seal_protected_failure(failure, context))
      Ok(#(ProtectedResponse(response), replays))
    }
  }
}

/// Decrypt, decode, and authorize one OHTTP target request.
pub fn open_request(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
) -> Result(#(bhttp.Message, GatewayContext, ReplayStore), Error) {
  case
    open_request_detailed(gateway: gateway, replays: replays, sealed: sealed)
  {
    Ok(#(GatewayOpened(request, context), replays)) ->
      Ok(#(request, context, replays))
    Ok(#(GatewayRejected(failure, _), _)) ->
      Error(protected_failure_error(failure))
    Error(error) -> Error(error)
  }
}

/// Decrypt, validate, and authorize one encoded request and return its context.
///
/// The byte-oriented API enforces the same target policy as `open_request`, so it cannot be used to bypass the gateway authority or Expect checks.
pub fn open_request_bytes(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
) -> Result(#(BitArray, GatewayContext, ReplayStore), Error) {
  case
    open_request_bytes_detailed(
      gateway: gateway,
      replays: replays,
      sealed: sealed,
    )
  {
    Ok(#(GatewayOpened(plaintext, context), replays)) ->
      Ok(#(plaintext, context, replays))
    Ok(#(GatewayRejected(failure, _), _)) ->
      Error(protected_failure_error(failure))
    Error(error) -> Error(error)
  }
}

fn open_request_bytes_unchecked(
  gateway: Gateway,
  replays: ReplayStore,
  sealed: BitArray,
) -> Result(#(BitArray, GatewayContext, ReplayStore), Error) {
  use _ <- result.try(validate_message_bytes(
    sealed,
    gateway.maximum_message_bytes,
  ))
  use #(key_id, kem_id, algorithm, encapsulated_key, ciphertext) <- result.try(
    parse_encapsulated_request(sealed),
  )
  use _ <- result.try(
    case
      key_id == gateway.key.configuration.key_id
      && kem_id == gateway.key.configuration.kem_id
      && list.contains(gateway.key.configuration.algorithms, algorithm)
    {
      True -> Ok(Nil)
      False -> Error(InvalidKey)
    },
  )
  let ReplayStore(handle) = replays
  use lease <- result.try(reserve_replay(handle, encapsulated_key))
  let opened =
    open_reserved_request(
      gateway,
      key_id,
      kem_id,
      encapsulated_key,
      ciphertext,
      algorithm,
    )
  case opened {
    Error(error) ->
      case replay_abort(handle, lease) {
        True -> Error(error)
        False -> Error(ReplayStoreUnavailable)
      }
    Ok(#(plaintext, context)) ->
      case replay_commit(handle, lease) {
        True -> Ok(#(plaintext, context, replays))
        False -> Error(ReplayStoreUnavailable)
      }
  }
}

fn open_reserved_request(
  gateway: Gateway,
  key_id: Int,
  kem_id: Int,
  encapsulated_key: BitArray,
  ciphertext: BitArray,
  algorithm: SymmetricAlgorithm,
) -> Result(#(BitArray, GatewayContext), Error) {
  use shared <- result.try(
    x25519_shared(gateway.key.private_key, encapsulated_key) |> crypto_result,
  )
  let header = <<
    key_id,
    kem_id:size(16),
    algorithm.kdf_id:size(16),
    algorithm.aead_id:size(16),
  >>
  let info = <<"message/bhttp request":utf8, 0, header:bits>>
  use hpke <- result.try(setup_hpke(
    shared,
    <<
      encapsulated_key:bits,
      gateway.key.configuration.public_key:bits,
    >>,
    info,
    algorithm,
  ))
  use plaintext <- result.try(
    case aead_open(algorithm.aead_id, hpke.key, hpke.base_nonce, ciphertext) {
      Ok(value) -> Ok(value)
      Error(_) -> Error(DecryptionFailed)
    },
  )
  let context =
    CryptoContext(
      hpke.exporter_secret,
      encapsulated_key,
      algorithm,
      gateway.bhttp_limits,
      gateway.maximum_message_bytes,
    )
  Ok(#(plaintext, GatewayContext(context, new_context_claim())))
}

/// Encode and encapsulate one binary HTTP response with fresh randomness.
pub fn seal_response(
  context context: GatewayContext,
  response response: bhttp.Message,
  mode mode: bhttp.Mode,
) -> Result(BitArray, Error) {
  use _ <- result.try(case response {
    bhttp.Response(..) -> Ok(Nil)
    bhttp.Request(..) -> Error(InvalidMessage)
  })
  let GatewayContext(crypto, _) = context
  use encoded <- result.try(
    bhttp.encode(response, mode, crypto.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  seal_response_bytes_validated(context, encoded)
}

/// Validate and encapsulate already encoded response bytes with fresh entropy.
///
/// A response context is claimed atomically across all copies.
/// Exactly one caller can derive response keying material; later calls fail closed.
pub fn seal_response_bytes(
  context context: GatewayContext,
  response response: BitArray,
) -> Result(BitArray, Error) {
  let GatewayContext(crypto, _) = context
  use _ <- result.try(validate_message_bytes(
    response,
    crypto.maximum_message_bytes,
  ))
  use _ <- result.try(decode_response_message(response, crypto.bhttp_limits))
  seal_response_bytes_validated(context, response)
}

fn seal_response_bytes_validated(
  context: GatewayContext,
  response: BitArray,
) -> Result(BitArray, Error) {
  let GatewayContext(crypto, claim) = context
  use #(_, nonce_bytes) <- result.try(aead_parameters(crypto.algorithm))
  let response_nonce_bytes =
    response_secret_length(crypto.algorithm, nonce_bytes)
  use _ <- result.try(validate_message_bytes(
    response,
    crypto.maximum_message_bytes
      - response_nonce_bytes
      - authentication_tag_bytes,
  ))
  use _ <- result.try(claim_context_once(claim))
  use response_nonce <- result.try(
    random_bytes(response_nonce_bytes) |> crypto_result,
  )
  use ciphertext <- result.try(protect_response(
    crypto,
    response,
    response_nonce,
    True,
  ))
  let sealed = <<response_nonce:bits, ciphertext:bits>>
  use _ <- result.try(validate_message_bytes(
    sealed,
    crypto.maximum_message_bytes,
  ))
  Ok(sealed)
}

/// Decode an encapsulated response into a binary HTTP response.
pub fn open_response(
  context context: ClientContext,
  sealed sealed: BitArray,
) -> Result(bhttp.Message, Error) {
  let ClientContext(crypto, _) = context
  use plaintext <- result.try(open_response_bytes_unchecked(context, sealed))
  decode_response_message(plaintext, crypto.bhttp_limits)
}

/// Open and validate already encoded `message/bhttp` response bytes.
///
/// A client response context is claimed atomically across all copies before authenticated decryption.
/// A second call fails closed.
pub fn open_response_bytes(
  context context: ClientContext,
  sealed sealed: BitArray,
) -> Result(BitArray, Error) {
  let ClientContext(crypto, _) = context
  use plaintext <- result.try(open_response_bytes_unchecked(context, sealed))
  use _ <- result.try(decode_response_message(plaintext, crypto.bhttp_limits))
  Ok(plaintext)
}

fn open_response_bytes_unchecked(
  context: ClientContext,
  sealed: BitArray,
) -> Result(BitArray, Error) {
  let ClientContext(crypto, claim) = context
  use _ <- result.try(validate_message_bytes(
    sealed,
    crypto.maximum_message_bytes,
  ))
  use #(_, nonce_bytes) <- result.try(aead_parameters(crypto.algorithm))
  let nonce_length = response_secret_length(crypto.algorithm, nonce_bytes)
  case bit_array.byte_size(sealed) >= nonce_length + authentication_tag_bytes {
    False -> Error(InvalidMessage)
    True ->
      case sealed {
        <<response_nonce:bytes-size(nonce_length), ciphertext:bits>> -> {
          use _ <- result.try(claim_context_once(claim))
          protect_response(crypto, ciphertext, response_nonce, False)
        }
        _ -> Error(InvalidMessage)
      }
  }
}

/// Create a metadata-minimizing relay bound to one HTTPS gateway resource.
pub fn relay(
  gateway_uri: String,
  maximum_message_bytes maximum_message_bytes: Int,
) -> Result(Relay, Error) {
  use _ <- result.try(validate_maximum(maximum_message_bytes))
  case
    string.starts_with(gateway_uri, "https://")
    && string.length(gateway_uri) > string.length("https://")
    && safe_text(gateway_uri)
  {
    True -> Ok(Relay(gateway_uri, maximum_message_bytes))
    False -> Error(InvalidRelay)
  }
}

/// Validate and construct the relay-to-gateway request.
/// No inbound client headers, address, connection identifier, or credentials enter this value.
pub fn forward_request(
  relay relay: Relay,
  content_type content_type: String,
  body body: BitArray,
) -> Result(RelayForward, Error) {
  use _ <- result.try(require_media_type(content_type, "message/ohttp-req"))
  use _ <- result.try(validate_message_bytes(body, relay.maximum_message_bytes))
  Ok(RelayForward(relay.gateway_uri, "message/ohttp-req", body))
}

/// Validate a gateway-to-client encapsulated response without exposing relay metadata to the OHTTP payload.
pub fn forward_response(
  content_type content_type: String,
  body body: BitArray,
  maximum_message_bytes maximum_message_bytes: Int,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_maximum(maximum_message_bytes))
  use _ <- result.try(require_media_type(content_type, "message/ohttp-res"))
  use _ <- result.try(validate_message_bytes(body, maximum_message_bytes))
  Ok(body)
}

fn new_client(
  configuration: KeyConfiguration,
  bhttp_limits: bhttp.Limits,
  maximum_message_bytes: Int,
) -> Result(Client, Error) {
  use _ <- result.try(validate_configuration(configuration))
  use _ <- result.try(validate_maximum(maximum_message_bytes))
  use algorithm <- result.try(select_algorithm(configuration.algorithms))
  Ok(Client(configuration, algorithm, bhttp_limits, maximum_message_bytes))
}

fn validate_configuration(
  configuration: KeyConfiguration,
) -> Result(Nil, Error) {
  use _ <- result.try(aligned(configuration.public_key))
  case
    configuration.key_id >= 0
    && configuration.key_id <= 255
    && configuration.kem_id == x25519_hkdf_sha256
    && bit_array.byte_size(configuration.public_key) == public_key_bytes
    && configuration.algorithms != []
    && list.length(configuration.algorithms) <= 16_383
    && valid_algorithms(configuration.algorithms)
  {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  }
}

fn valid_algorithms(algorithms: List(SymmetricAlgorithm)) -> Bool {
  case algorithms {
    [] -> True
    [algorithm, ..rest] ->
      case
        algorithm.kdf_id >= 0
        && algorithm.kdf_id <= 65_535
        && algorithm.aead_id >= 0
        && algorithm.aead_id <= 65_535
        && !list.contains(rest, algorithm)
      {
        True -> valid_algorithms(rest)
        False -> False
      }
  }
}

fn select_algorithm(
  algorithms: List(SymmetricAlgorithm),
) -> Result(SymmetricAlgorithm, Error) {
  case algorithms {
    [] -> Error(UnsupportedAlgorithm)
    [algorithm, ..rest] ->
      case supported(algorithm) {
        True -> Ok(algorithm)
        False -> select_algorithm(rest)
      }
  }
}

fn supported(algorithm: SymmetricAlgorithm) -> Bool {
  algorithm.kdf_id == hkdf_sha256
  && {
    algorithm.aead_id == aes_128_gcm || algorithm.aead_id == chacha20_poly1305
  }
}

fn decode_algorithms(
  bytes: BitArray,
  reversed: List(SymmetricAlgorithm),
) -> Result(List(SymmetricAlgorithm), Error) {
  case bytes {
    <<>> -> Ok(list.reverse(reversed))
    <<kdf_id:size(16), aead_id:size(16), rest:bits>> ->
      decode_algorithms(rest, [SymmetricAlgorithm(kdf_id, aead_id), ..reversed])
    _ -> Error(InvalidConfiguration)
  }
}

fn encode_algorithms(
  algorithms: List(SymmetricAlgorithm),
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case algorithms {
    [] -> Ok(list.reverse(reversed))
    [algorithm, ..rest] ->
      case
        algorithm.kdf_id >= 0
        && algorithm.kdf_id <= 65_535
        && algorithm.aead_id >= 0
        && algorithm.aead_id <= 65_535
      {
        False -> Error(InvalidConfiguration)
        True ->
          encode_algorithms(rest, [
            <<algorithm.kdf_id:size(16), algorithm.aead_id:size(16)>>,
            ..reversed
          ])
      }
  }
}

fn decode_configuration_collection(
  bytes: BitArray,
  remaining: Int,
  reversed: List(KeyConfiguration),
) -> Result(List(KeyConfiguration), Error) {
  case bytes, remaining {
    <<>>, _ ->
      case reversed {
        [] -> Error(InvalidConfiguration)
        _ -> Ok(list.reverse(reversed))
      }
    _, 0 -> Error(LimitExceeded)
    <<length:size(16), rest:bits>>, _ -> {
      use #(member, rest) <- result.try(take(rest, length))
      use configuration <- result.try(decode_key_configuration(member))
      decode_configuration_collection(rest, remaining - 1, [
        configuration,
        ..reversed
      ])
    }
    _, _ -> Error(InvalidConfiguration)
  }
}

fn encode_configuration_collection(
  configurations: List(KeyConfiguration),
  reversed: List(BitArray),
) -> Result(List(BitArray), Error) {
  case configurations {
    [] -> Ok(list.reverse(reversed))
    [configuration, ..rest] -> {
      use member <- result.try(encode_key_configuration(configuration))
      let length = bit_array.byte_size(member)
      use _ <- result.try(require(length <= 65_535))
      encode_configuration_collection(rest, [
        <<length:size(16), member:bits>>,
        ..reversed
      ])
    }
  }
}

fn configuration_header(
  configuration: KeyConfiguration,
  algorithm: SymmetricAlgorithm,
) -> BitArray {
  <<
    configuration.key_id,
    configuration.kem_id:size(16),
    algorithm.kdf_id:size(16),
    algorithm.aead_id:size(16),
  >>
}

fn parse_encapsulated_request(
  sealed: BitArray,
) -> Result(#(Int, Int, SymmetricAlgorithm, BitArray, BitArray), Error) {
  case sealed {
    <<
      key_id,
      kem_id:size(16),
      kdf_id:size(16),
      aead_id:size(16),
      encapsulated_key:bytes-size(public_key_bytes),
      ciphertext:bits,
    >> ->
      case bit_array.byte_size(ciphertext) >= authentication_tag_bytes {
        True ->
          Ok(#(
            key_id,
            kem_id,
            SymmetricAlgorithm(kdf_id, aead_id),
            encapsulated_key,
            ciphertext,
          ))
        False -> Error(InvalidMessage)
      }
    _ -> Error(InvalidMessage)
  }
}

fn setup_hpke(
  dh: BitArray,
  kem_context: BitArray,
  info: BitArray,
  algorithm: SymmetricAlgorithm,
) -> Result(HpkeContext, Error) {
  use _ <- result.try(case supported(algorithm) {
    True -> Ok(Nil)
    False -> Error(UnsupportedAlgorithm)
  })
  let kem_suite = <<"KEM":utf8, x25519_hkdf_sha256:size(16)>>
  use eae_prk <- result.try(labeled_extract(<<>>, kem_suite, "eae_prk", dh))
  use shared_secret <- result.try(labeled_expand(
    eae_prk,
    kem_suite,
    "shared_secret",
    kem_context,
    32,
  ))
  let suite = <<
    "HPKE":utf8,
    x25519_hkdf_sha256:size(16),
    algorithm.kdf_id:size(16),
    algorithm.aead_id:size(16),
  >>
  use psk_id_hash <- result.try(
    labeled_extract(<<>>, suite, "psk_id_hash", <<>>),
  )
  use info_hash <- result.try(labeled_extract(<<>>, suite, "info_hash", info))
  let key_schedule_context = <<0, psk_id_hash:bits, info_hash:bits>>
  use secret <- result.try(
    labeled_extract(shared_secret, suite, "secret", <<>>),
  )
  use #(key_bytes, nonce_bytes) <- result.try(aead_parameters(algorithm))
  use key <- result.try(labeled_expand(
    secret,
    suite,
    "key",
    key_schedule_context,
    key_bytes,
  ))
  use base_nonce <- result.try(labeled_expand(
    secret,
    suite,
    "base_nonce",
    key_schedule_context,
    nonce_bytes,
  ))
  use exporter_secret <- result.try(labeled_expand(
    secret,
    suite,
    "exp",
    key_schedule_context,
    32,
  ))
  Ok(HpkeContext(key, base_nonce, exporter_secret))
}

fn labeled_extract(
  salt: BitArray,
  suite: BitArray,
  label: String,
  input: BitArray,
) -> Result(BitArray, Error) {
  hkdf_extract(salt, <<"HPKE-v1":utf8, suite:bits, label:utf8, input:bits>>)
  |> crypto_result
}

fn labeled_expand(
  prk: BitArray,
  suite: BitArray,
  label: String,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Error) {
  case length >= 0 && length <= 65_535 {
    False -> Error(LimitExceeded)
    True ->
      hkdf_expand(
        prk,
        <<length:size(16), "HPKE-v1":utf8, suite:bits, label:utf8, info:bits>>,
        length,
      )
      |> crypto_result
  }
}

fn hpke_export(context: CryptoContext, length: Int) -> Result(BitArray, Error) {
  let suite = <<
    "HPKE":utf8,
    x25519_hkdf_sha256:size(16),
    context.algorithm.kdf_id:size(16),
    context.algorithm.aead_id:size(16),
  >>
  labeled_expand(
    context.exporter_secret,
    suite,
    "sec",
    <<"message/bhttp response":utf8>>,
    length,
  )
}

fn protect_response(
  context: CryptoContext,
  input: BitArray,
  response_nonce: BitArray,
  sealing: Bool,
) -> Result(BitArray, Error) {
  use _ <- result.try(validate_message_bytes(
    input,
    context.maximum_message_bytes,
  ))
  use #(key_bytes, nonce_bytes) <- result.try(aead_parameters(context.algorithm))
  let secret_length = response_secret_length(context.algorithm, nonce_bytes)
  use _ <- result.try(
    case
      bit_array.bit_size(response_nonce) % 8 == 0
      && bit_array.byte_size(response_nonce) == secret_length
    {
      True -> Ok(Nil)
      False -> Error(InvalidMessage)
    },
  )
  use secret <- result.try(hpke_export(context, secret_length))
  use prk <- result.try(
    hkdf_extract(<<context.encapsulated_key:bits, response_nonce:bits>>, secret)
    |> crypto_result,
  )
  use key <- result.try(
    hkdf_expand(prk, <<"key":utf8>>, key_bytes) |> crypto_result,
  )
  use nonce <- result.try(
    hkdf_expand(prk, <<"nonce":utf8>>, nonce_bytes) |> crypto_result,
  )
  case sealing {
    True ->
      aead_seal(context.algorithm.aead_id, key, nonce, input) |> crypto_result
    False ->
      case aead_open(context.algorithm.aead_id, key, nonce, input) {
        Ok(value) -> Ok(value)
        Error(_) -> Error(DecryptionFailed)
      }
  }
}

fn aead_parameters(
  algorithm: SymmetricAlgorithm,
) -> Result(#(Int, Int), Error) {
  case algorithm.kdf_id, algorithm.aead_id {
    1, 1 -> Ok(#(16, 12))
    1, 3 -> Ok(#(32, 12))
    _, _ -> Error(UnsupportedAlgorithm)
  }
}

fn response_secret_length(
  algorithm: SymmetricAlgorithm,
  nonce_bytes: Int,
) -> Int {
  case algorithm.aead_id {
    1 -> maximum(16, nonce_bytes)
    3 -> maximum(32, nonce_bytes)
    _ -> nonce_bytes
  }
}

fn maximum(first: Int, second: Int) -> Int {
  case first >= second {
    True -> first
    False -> second
  }
}

fn authorize_request(
  request: bhttp.Message,
  allowed_authorities: List(String),
) -> Result(Nil, Error) {
  case request {
    bhttp.Request(_, "https", authority, _, _, _, _, _) ->
      case list.contains(allowed_authorities, authority) {
        True -> Ok(Nil)
        False -> Error(TargetNotAllowed)
      }
    _ -> Error(TargetNotAllowed)
  }
}

fn classify_opened_request(
  gateway: Gateway,
  plaintext: BitArray,
  context: GatewayContext,
) -> GatewayOpen(bhttp.Message) {
  case decode_target_request(plaintext, gateway.bhttp_limits) {
    Ok(request) ->
      case
        result.is_ok(authorize_request(request, gateway.allowed_authorities))
      {
        True -> GatewayOpened(request, context)
        False -> GatewayRejected(TargetRejected, context)
      }
    Error(ContinueExpectationForbidden) ->
      GatewayRejected(ContinueExpectationRejected, context)
    Error(failure) -> GatewayRejected(classify_decode_failure(failure), context)
  }
}

fn classify_decode_failure(failure: Error) -> ProtectedRequestFailure {
  case failure {
    ContinueExpectationForbidden -> ContinueExpectationRejected
    InvalidConfiguration
    | InvalidMessage
    | InvalidMediaType
    | InvalidRelay
    | InvalidKey
    | UnsupportedAlgorithm
    | NonByteAligned
    | LimitExceeded
    | ReplayDetected
    | ReplayCapacityExceeded
    | ReplayStoreUnavailable
    | ContextReuseDetected
    | TargetNotAllowed
    | DecryptionFailed
    | CryptoFailure -> MalformedRequest
  }
}

fn protected_failure_error(failure: ProtectedRequestFailure) -> Error {
  case failure {
    MalformedRequest -> InvalidMessage
    ContinueExpectationRejected -> ContinueExpectationForbidden
    TargetRejected -> TargetNotAllowed
  }
}

fn reserve_replay(
  handle: ReplayStoreHandle,
  encapsulated_key: BitArray,
) -> Result(ReplayLease, Error) {
  case replay_reserve(handle, encapsulated_key) {
    Ok(lease) -> Ok(lease)
    Error(1) -> Error(ReplayDetected)
    Error(2) -> Error(ReplayCapacityExceeded)
    Error(_) -> Error(ReplayStoreUnavailable)
  }
}

fn reject_continue_expectation(request: bhttp.Message) -> Result(Nil, Error) {
  case request {
    bhttp.Request(_, _, _, _, headers, _, _, _) ->
      case has_continue_expectation(headers) {
        Ok(True) -> Error(ContinueExpectationForbidden)
        Ok(False) -> Ok(Nil)
        Error(_) -> Error(InvalidMessage)
      }
    bhttp.Response(..) -> Error(InvalidMessage)
  }
}

fn decode_target_request(
  encoded: BitArray,
  limits: bhttp.Limits,
) -> Result(bhttp.Message, Error) {
  use request <- result.try(
    bhttp.decode(encoded, limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  use _ <- result.try(case request {
    bhttp.Request(..) -> Ok(Nil)
    bhttp.Response(..) -> Error(InvalidMessage)
  })
  use _ <- result.try(reject_continue_expectation(request))
  Ok(request)
}

fn decode_response_message(
  encoded: BitArray,
  limits: bhttp.Limits,
) -> Result(bhttp.Message, Error) {
  use response <- result.try(
    bhttp.decode(encoded, limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  case response {
    bhttp.Response(..) -> Ok(response)
    bhttp.Request(..) -> Error(InvalidMessage)
  }
}

fn claim_context_once(claim: ContextClaim) -> Result(Nil, Error) {
  case claim_context(claim) {
    True -> Ok(Nil)
    False -> Error(ContextReuseDetected)
  }
}

fn has_continue_expectation(headers: List(bhttp.Field)) -> Result(Bool, Nil) {
  case headers {
    [] -> Ok(False)
    [bhttp.Field(name, value), ..rest] -> {
      case string.lowercase(name) {
        "expect" -> {
          use found <- result.try(parse_expectation_members(value))
          case found {
            True -> Ok(True)
            False -> has_continue_expectation(rest)
          }
        }
        _ -> has_continue_expectation(rest)
      }
    }
  }
}

fn parse_expectation_members(bytes: BitArray) -> Result(Bool, Nil) {
  let bytes = drop_expect_ows(bytes)
  case bytes {
    <<>> -> Ok(False)
    <<44, rest:bits>> -> parse_expectation_members(rest)
    _ -> {
      use #(rest, is_continue) <- result.try(parse_expectation_name(
        bytes,
        0,
        True,
      ))
      case is_continue {
        True -> Ok(True)
        False -> parse_expectation_suffix(rest)
      }
    }
  }
}

fn parse_expectation_name(
  bytes: BitArray,
  length: Int,
  matches_continue: Bool,
) -> Result(#(BitArray, Bool), Nil) {
  case bytes {
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True ->
          parse_expectation_name(
            rest,
            length + 1,
            matches_continue
              && ascii_lower_byte(byte) == continue_name_byte(length),
          )
        False -> finish_expectation_name(bytes, length, matches_continue)
      }
    <<>> -> finish_expectation_name(bytes, length, matches_continue)
    _ -> Error(Nil)
  }
}

fn finish_expectation_name(
  rest: BitArray,
  length: Int,
  matches_continue: Bool,
) -> Result(#(BitArray, Bool), Nil) {
  case length > 0 {
    True -> Ok(#(rest, matches_continue && length == 12))
    False -> Error(Nil)
  }
}

fn parse_expectation_suffix(bytes: BitArray) -> Result(Bool, Nil) {
  case bytes {
    <<>> -> Ok(False)
    <<44, rest:bits>> -> parse_expectation_members(rest)
    <<61, rest:bits>> -> {
      use rest <- result.try(parse_expectation_value(rest))
      parse_expectation_parameters(rest)
    }
    <<byte, _:bits>> if byte == 9 || byte == 32 -> {
      let rest = drop_expect_ows(bytes)
      case rest {
        <<>> -> Ok(False)
        <<44, tail:bits>> -> parse_expectation_members(tail)
        _ -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

fn parse_expectation_value(bytes: BitArray) -> Result(BitArray, Nil) {
  case bytes {
    <<34, rest:bits>> -> parse_expectation_quoted(rest)
    _ -> consume_expectation_token(bytes, 0)
  }
}

fn consume_expectation_token(
  bytes: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  case bytes {
    <<byte, rest:bits>> ->
      case token_byte(byte) {
        True -> consume_expectation_token(rest, length + 1)
        False -> finish_expectation_token(bytes, length)
      }
    <<>> -> finish_expectation_token(bytes, length)
    _ -> Error(Nil)
  }
}

fn finish_expectation_token(
  rest: BitArray,
  length: Int,
) -> Result(BitArray, Nil) {
  case length > 0 {
    True -> Ok(rest)
    False -> Error(Nil)
  }
}

fn parse_expectation_quoted(bytes: BitArray) -> Result(BitArray, Nil) {
  case bytes {
    <<34, rest:bits>> -> Ok(rest)
    <<92, byte, rest:bits>> ->
      case quoted_pair_byte(byte) {
        True -> parse_expectation_quoted(rest)
        False -> Error(Nil)
      }
    <<byte, rest:bits>> ->
      case quoted_text_byte(byte) {
        True -> parse_expectation_quoted(rest)
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

fn parse_expectation_parameters(bytes: BitArray) -> Result(Bool, Nil) {
  let bytes = drop_expect_ows(bytes)
  case bytes {
    <<>> -> Ok(False)
    <<44, rest:bits>> -> parse_expectation_members(rest)
    <<59, rest:bits>> -> {
      let rest = drop_expect_ows(rest)
      case rest {
        <<>> -> Ok(False)
        <<44, tail:bits>> -> parse_expectation_members(tail)
        <<59, _:bits>> -> parse_expectation_parameters(rest)
        _ -> {
          use rest <- result.try(consume_expectation_token(rest, 0))
          case rest {
            <<61, value:bits>> -> {
              use rest <- result.try(parse_expectation_value(value))
              parse_expectation_parameters(rest)
            }
            _ -> Error(Nil)
          }
        }
      }
    }
    _ -> Error(Nil)
  }
}

fn drop_expect_ows(bytes: BitArray) -> BitArray {
  case bytes {
    <<byte, rest:bits>> if byte == 9 || byte == 32 -> drop_expect_ows(rest)
    _ -> bytes
  }
}

fn token_byte(byte: Int) -> Bool {
  { byte >= 48 && byte <= 57 }
  || { byte >= 65 && byte <= 90 }
  || { byte >= 97 && byte <= 122 }
  || byte == 33
  || byte == 35
  || byte == 36
  || byte == 37
  || byte == 38
  || byte == 39
  || byte == 42
  || byte == 43
  || byte == 45
  || byte == 46
  || byte == 94
  || byte == 95
  || byte == 96
  || byte == 124
  || byte == 126
}

fn quoted_text_byte(byte: Int) -> Bool {
  byte == 9
  || byte == 32
  || byte == 33
  || { byte >= 35 && byte <= 91 }
  || { byte >= 93 && byte <= 126 }
  || byte >= 128
}

fn quoted_pair_byte(byte: Int) -> Bool {
  byte == 9 || byte == 32 || { byte >= 33 && byte <= 126 } || byte >= 128
}

fn continue_name_byte(index: Int) -> Int {
  case index {
    0 -> 49
    1 -> 48
    2 -> 48
    3 -> 45
    4 -> 99
    5 -> 111
    6 -> 110
    7 -> 116
    8 -> 105
    9 -> 110
    10 -> 117
    11 -> 101
    _ -> -1
  }
}

fn ascii_lower_byte(byte: Int) -> Int {
  case byte >= 65 && byte <= 90 {
    True -> byte + 32
    False -> byte
  }
}

fn validate_authorities(authorities: List(String)) -> Result(Nil, Error) {
  case authorities {
    [] -> Ok(Nil)
    [authority, ..rest] ->
      case
        authority != ""
        && string.byte_size(authority) <= 1024
        && safe_text(authority)
        && !list.contains(rest, authority)
      {
        True -> validate_authorities(rest)
        False -> Error(InvalidConfiguration)
      }
  }
}

fn safe_text(value: String) -> Bool {
  safe_bytes(bit_array.from_string(value))
}

fn safe_bytes(bytes: BitArray) -> Bool {
  case bytes {
    <<>> -> True
    <<byte, rest:bits>> if byte != 0 && byte != 10 && byte != 13 ->
      safe_bytes(rest)
    _ -> False
  }
}

fn require_media_type(actual: String, expected: String) -> Result(Nil, Error) {
  case string.lowercase(actual) == expected {
    True -> Ok(Nil)
    False -> Error(InvalidMediaType)
  }
}

fn validate_maximum(maximum_message_bytes: Int) -> Result(Nil, Error) {
  case
    maximum_message_bytes
    >= request_header_bytes + public_key_bytes + authentication_tag_bytes
    && maximum_message_bytes <= 1_073_741_824
  {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  }
}

fn validate_message_bytes(
  bytes: BitArray,
  maximum_message_bytes: Int,
) -> Result(Nil, Error) {
  use _ <- result.try(aligned(bytes))
  case bit_array.byte_size(bytes) <= maximum_message_bytes {
    True -> Ok(Nil)
    False -> Error(LimitExceeded)
  }
}

fn aligned(bytes: BitArray) -> Result(Nil, Error) {
  case bit_array.bit_size(bytes) % 8 {
    0 -> Ok(Nil)
    _ -> Error(NonByteAligned)
  }
}

fn require(condition: Bool) -> Result(Nil, Error) {
  case condition {
    True -> Ok(Nil)
    False -> Error(InvalidConfiguration)
  }
}

fn take(bytes: BitArray, length: Int) -> Result(#(BitArray, BitArray), Error) {
  case length >= 0 && length <= bit_array.byte_size(bytes) {
    False -> Error(InvalidConfiguration)
    True -> {
      let bits = length * 8
      case bytes {
        <<value:bits-size(bits), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(InvalidConfiguration)
      }
    }
  }
}

fn crypto_result(value: Result(value, Nil)) -> Result(value, Error) {
  result.map_error(value, fn(_) { CryptoFailure })
}

@external(erlang, "http_ohttp_ffi", "x25519_public")
fn x25519_public(private_key: BitArray) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "new_context_claim")
fn new_context_claim() -> ContextClaim

@external(erlang, "http_ohttp_ffi", "claim_context")
fn claim_context(claim: ContextClaim) -> Bool

@external(erlang, "http_ohttp_ffi", "x25519_shared")
fn x25519_shared(
  private_key: BitArray,
  peer_public_key: BitArray,
) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "random_bytes")
fn random_bytes(count: Int) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "hkdf_extract")
fn hkdf_extract(salt: BitArray, input: BitArray) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "hkdf_expand")
fn hkdf_expand(
  pseudorandom_key: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "aead_seal")
fn aead_seal(
  algorithm: Int,
  key: BitArray,
  nonce: BitArray,
  plaintext: BitArray,
) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "aead_open")
fn aead_open(
  algorithm: Int,
  key: BitArray,
  nonce: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, Nil)

@external(erlang, "http_ohttp_ffi", "new_replay_store")
fn new_replay_store(
  maximum_entries: Int,
  retention_milliseconds: Int,
) -> Result(ReplayStoreHandle, Nil)

@external(erlang, "http_ohttp_ffi", "replay_reserve")
fn replay_reserve(
  store: ReplayStoreHandle,
  encapsulated_key: BitArray,
) -> Result(ReplayLease, Int)

@external(erlang, "http_ohttp_ffi", "replay_commit")
fn replay_commit(store: ReplayStoreHandle, lease: ReplayLease) -> Bool

@external(erlang, "http_ohttp_ffi", "replay_abort")
fn replay_abort(store: ReplayStoreHandle, lease: ReplayLease) -> Bool

@external(erlang, "http_ohttp_ffi", "close_replay_store")
fn close_replay_store_handle(store: ReplayStoreHandle) -> Bool
