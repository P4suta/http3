//// RFC 9458 Oblivious HTTP client, relay, and gateway primitives.
////
//// Only RFC 9180 base mode with DHKEM(X25519, HKDF-SHA256) is active. The
//// symmetric choices are HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305.
//// Unsupported registry identifiers fail closed and are never substituted.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
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

/// Client configuration. Normal clients generate a fresh ephemeral key for
/// every request; deterministic clients exist solely for reproducible vectors.
pub opaque type Client {
  Client(
    configuration: KeyConfiguration,
    algorithm: SymmetricAlgorithm,
    deterministic_ephemeral: Option(BitArray),
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
  ClientContext(CryptoContext)
}

/// Gateway-side response context bound to exactly one opened request.
pub opaque type GatewayContext {
  GatewayContext(CryptoContext)
}

/// Gateway policy and private key. The authority allowlist is exact and empty
/// means deny all target requests.
pub opaque type Gateway {
  Gateway(
    key: GatewayKey,
    allowed_authorities: List(String),
    bhttp_limits: bhttp.Limits,
    maximum_message_bytes: Int,
  )
}

/// A finite fail-closed replay set. It never evicts live entries implicitly.
pub opaque type ReplayStore {
  ReplayStore(maximum_entries: Int, fingerprints: List(BitArray))
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

/// Decode a strict `application/ohttp-keys` collection. Any malformed member
/// invalidates the complete collection to avoid client fingerprinting.
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
  new_client(configuration, None, bhttp_limits, maximum_message_bytes)
}

/// Create a deterministic vector client. Reusing it repeats the HPKE
/// ephemeral key and is therefore not suitable for production traffic.
pub fn deterministic_client(
  configuration: KeyConfiguration,
  ephemeral_private_key: BitArray,
  bhttp_limits: bhttp.Limits,
  maximum_message_bytes maximum_message_bytes: Int,
) -> Result(Client, Error) {
  use _ <- result.try(aligned(ephemeral_private_key))
  use _ <- result.try(
    case bit_array.byte_size(ephemeral_private_key) == public_key_bytes {
      True -> Ok(Nil)
      False -> Error(InvalidKey)
    },
  )
  new_client(
    configuration,
    Some(ephemeral_private_key),
    bhttp_limits,
    maximum_message_bytes,
  )
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
  use encoded <- result.try(
    bhttp.encode(request, mode, client.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  seal_request_bytes(client: client, request: encoded)
}

/// Encapsulate already encoded `message/bhttp` request bytes.
pub fn seal_request_bytes(
  client client: Client,
  request request: BitArray,
) -> Result(#(BitArray, ClientContext), Error) {
  use _ <- result.try(validate_message_bytes(
    request,
    client.maximum_message_bytes,
  ))
  use ephemeral_private <- result.try(case client.deterministic_ephemeral {
    Some(value) -> Ok(value)
    None -> random_bytes(public_key_bytes) |> crypto_result
  })
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
  Ok(#(sealed, ClientContext(context)))
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

/// Create an empty finite replay set. Capacity exhaustion fails closed.
pub fn replay_store(
  maximum_entries maximum_entries: Int,
) -> Result(ReplayStore, Error) {
  case maximum_entries > 0 && maximum_entries <= 1_000_000 {
    True -> Ok(ReplayStore(maximum_entries, []))
    False -> Error(InvalidConfiguration)
  }
}

/// Decrypt, decode, and authorize one OHTTP target request.
pub fn open_request(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
) -> Result(#(bhttp.Message, GatewayContext, ReplayStore), Error) {
  use #(plaintext, context, replays) <- result.try(open_request_bytes(
    gateway: gateway,
    replays: replays,
    sealed: sealed,
  ))
  use request <- result.try(
    bhttp.decode(plaintext, gateway.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  use _ <- result.try(authorize_request(request, gateway.allowed_authorities))
  Ok(#(request, context, replays))
}

/// Decrypt one encapsulated request and return its response context.
pub fn open_request_bytes(
  gateway gateway: Gateway,
  replays replays: ReplayStore,
  sealed sealed: BitArray,
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
  use fingerprint <- result.try(sha256(sealed) |> crypto_result)
  use _ <- result.try(case list.contains(replays.fingerprints, fingerprint) {
    True -> Error(ReplayDetected)
    False -> Ok(Nil)
  })
  use _ <- result.try(
    case list.length(replays.fingerprints) < replays.maximum_entries {
      True -> Ok(Nil)
      False -> Error(ReplayCapacityExceeded)
    },
  )
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
  use _ <- result.try(validate_message_bytes(
    plaintext,
    gateway.maximum_message_bytes,
  ))
  let context =
    CryptoContext(
      hpke.exporter_secret,
      encapsulated_key,
      algorithm,
      gateway.bhttp_limits,
      gateway.maximum_message_bytes,
    )
  let replays =
    ReplayStore(..replays, fingerprints: [fingerprint, ..replays.fingerprints])
  Ok(#(plaintext, GatewayContext(context), replays))
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
  let GatewayContext(crypto) = context
  use encoded <- result.try(
    bhttp.encode(response, mode, crypto.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  seal_response_bytes(context: context, response: encoded)
}

/// Encapsulate already encoded response bytes with a fresh response nonce.
pub fn seal_response_bytes(
  context context: GatewayContext,
  response response: BitArray,
) -> Result(BitArray, Error) {
  let GatewayContext(crypto) = context
  use #(_, nonce_bytes) <- result.try(aead_parameters(crypto.algorithm))
  use response_nonce <- result.try(
    random_bytes(response_secret_length(crypto.algorithm, nonce_bytes))
    |> crypto_result,
  )
  seal_response_bytes_with_nonce(
    context: context,
    response: response,
    response_nonce: response_nonce,
  )
}

/// Deterministic response sealing for RFC vectors and controlled adapters.
/// Production callers should use `seal_response_bytes`.
pub fn seal_response_bytes_with_nonce(
  context context: GatewayContext,
  response response: BitArray,
  response_nonce response_nonce: BitArray,
) -> Result(BitArray, Error) {
  let GatewayContext(crypto) = context
  use ciphertext <- result.try(protect_response(
    crypto,
    response,
    response_nonce,
    True,
  ))
  Ok(<<response_nonce:bits, ciphertext:bits>>)
}

/// Decode an encapsulated response into a binary HTTP response.
pub fn open_response(
  context context: ClientContext,
  sealed sealed: BitArray,
) -> Result(bhttp.Message, Error) {
  let ClientContext(crypto) = context
  use plaintext <- result.try(open_response_bytes(
    context: context,
    sealed: sealed,
  ))
  use response <- result.try(
    bhttp.decode(plaintext, crypto.bhttp_limits)
    |> result.map_error(fn(_) { InvalidMessage }),
  )
  case response {
    bhttp.Response(..) -> Ok(response)
    bhttp.Request(..) -> Error(InvalidMessage)
  }
}

/// Open already encoded `message/bhttp` response bytes.
pub fn open_response_bytes(
  context context: ClientContext,
  sealed sealed: BitArray,
) -> Result(BitArray, Error) {
  let ClientContext(crypto) = context
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
        <<response_nonce:bytes-size(nonce_length), ciphertext:bits>> ->
          protect_response(crypto, ciphertext, response_nonce, False)
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

/// Validate and construct the relay-to-gateway request. No inbound client
/// headers, address, connection identifier, or credentials enter this value.
pub fn forward_request(
  relay relay: Relay,
  content_type content_type: String,
  body body: BitArray,
) -> Result(RelayForward, Error) {
  use _ <- result.try(require_media_type(content_type, "message/ohttp-req"))
  use _ <- result.try(validate_message_bytes(body, relay.maximum_message_bytes))
  Ok(RelayForward(relay.gateway_uri, "message/ohttp-req", body))
}

/// Validate a gateway-to-client encapsulated response without exposing relay
/// metadata to the OHTTP payload.
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
  deterministic_ephemeral: Option(BitArray),
  bhttp_limits: bhttp.Limits,
  maximum_message_bytes: Int,
) -> Result(Client, Error) {
  use _ <- result.try(validate_configuration(configuration))
  use _ <- result.try(validate_maximum(maximum_message_bytes))
  use algorithm <- result.try(select_algorithm(configuration.algorithms))
  Ok(Client(
    configuration,
    algorithm,
    deterministic_ephemeral,
    bhttp_limits,
    maximum_message_bytes,
  ))
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

@external(erlang, "http_ohttp_ffi", "sha256")
fn sha256(input: BitArray) -> Result(BitArray, Nil)
