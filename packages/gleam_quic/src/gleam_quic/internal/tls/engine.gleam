//// Authenticated TLS 1.3 handshake state machine for QUIC CRYPTO streams.

import gleam/list
import gleam/option.{None}
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/key_exchange
import gleam_quic/internal/tls/key_schedule
import gleam_quic/internal/tls/message_body
import gleam_quic/internal/tls/transcript
import gleam_quic/internal/traffic_keys
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}

const maximum_handshake_message_length = 1_048_576

const maximum_transcript_length = 4_194_304

/// QUIC packet-number space carrying a TLS handshake action.
pub type EncryptionLevel {
  Initial
  Handshake
  ZeroRtt
  OneRtt
}

/// Stable, role-independent handshake progress exposed to the transport core.
pub type Phase {
  AwaitingPeerHello
  AwaitingPeerFlight
  AwaitingPeerFinished
  Connected
}

/// Side effects which the QUIC transport applies outside this pure state model.
pub type Action {
  Send(EncryptionLevel, BitArray)
  InstallWriteKeys(EncryptionLevel, traffic_keys.TrafficKeys)
  InstallReadKeys(EncryptionLevel, traffic_keys.TrafficKeys)
  PeerTransportParameters(List(transport_parameter.Parameter))
  HandshakeComplete
}

/// One state transition and its ordered transport actions.
pub type Step(state) {
  Step(state, List(Action))
}

/// Inputs required for an authenticated client handshake.
pub type ClientConfig {
  ClientConfig(
    version: Version,
    hostname: String,
    application_protocols: List(BitArray),
    transport_parameters: List(transport_parameter.Parameter),
    trust_store: authentication.TrustStore,
    retried: Bool,
  )
}

/// Inputs required for a certificate-authenticated server handshake.
pub type ServerConfig {
  ServerConfig(
    version: Version,
    application_protocols: List(BitArray),
    transport_parameters: List(transport_parameter.Parameter),
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
  )
}

type ClientHandshakeContext {
  ClientHandshakeContext(
    config: ClientConfig,
    cipher_suite: hello.CipherSuite,
    hash_algorithm: crypto.HashAlgorithm,
    transcript: transcript.Transcript,
    secrets: key_schedule.HandshakeSecrets,
  )
}

/// Client TLS state. Private keys and traffic secrets have no accessors.
pub opaque type Client {
  ClientAwaitingServerHello(
    config: ClientConfig,
    key_pair: key_exchange.KeyPair,
    encoded_client_hello: BitArray,
  )
  ClientAwaitingEncryptedExtensions(ClientHandshakeContext)
  ClientAwaitingCertificate(ClientHandshakeContext)
  ClientAwaitingCertificateVerify(
    context: ClientHandshakeContext,
    peer: authentication.VerifiedPeer,
  )
  ClientAwaitingFinished(ClientHandshakeContext)
  ClientConnected(resumption_master_secret: BitArray)
}

type ServerHandshakeContext {
  ServerHandshakeContext(
    version: Version,
    hash_algorithm: crypto.HashAlgorithm,
    transcript: transcript.Transcript,
    secrets: key_schedule.HandshakeSecrets,
  )
}

/// Server TLS state. Private keys and traffic secrets have no accessors.
pub opaque type Server {
  ServerAwaitingClientHello(ServerConfig)
  ServerAwaitingClientFinished(ServerHandshakeContext)
  ServerConnected(resumption_master_secret: BitArray)
}

/// A fatal local configuration, TLS semantic, authentication, or state error.
pub type Error {
  InvalidConfiguration
  UnexpectedEncryptionLevel
  UnexpectedMessage
  TruncatedHandshake
  UnsupportedVersion(Version)
  UnsupportedCipherSuite(hello.CipherSuite)
  UnsupportedKeyShare
  MissingExtension(extension.Kind)
  NoApplicationProtocol
  FinishedMismatch
  HandshakeFailure(handshake.Error)
  HelloFailure(hello.Error)
  ExtensionValueFailure(extension_value.Error)
  TransportParameterFailure(transport_parameter.Error)
  CryptoFailure(crypto.Error)
  KeyExchangeFailure(key_exchange.Error)
  TranscriptFailure(transcript.Error)
  TrafficKeyFailure(traffic_keys.Error)
  MessageBodyFailure(message_body.Error)
  AuthenticationFailure(authentication.Error)
}

/// Generate an ephemeral ClientHello and enter the client Initial state.
pub fn start_client(
  config config: ClientConfig,
) -> Result(Step(Client), Error) {
  use Nil <- result.try(validate_client_config(config))
  use key_pair <- result.try(
    key_exchange.generate_x25519() |> map_key_exchange_result,
  )
  use random <- result.try(crypto.secure_random(32) |> map_crypto_result)
  use extensions <- result.try(client_extensions(config, key_pair))
  let client_hello =
    hello.ClientHello(
      random: random,
      legacy_session_id: <<>>,
      cipher_suites: supported_cipher_suites(),
      extensions: extensions,
    )
  use body <- result.try(
    hello.encode_client(client_hello, hello.default_limits())
    |> map_hello_result,
  )
  use encoded <- result.try(encode_message(handshake.ClientHello, body))
  Ok(
    Step(ClientAwaitingServerHello(config, key_pair, encoded), [
      Send(Initial, encoded),
    ]),
  )
}

/// Validate a server configuration without emitting network data.
pub fn start_server(config config: ServerConfig) -> Result(Server, Error) {
  use Nil <- result.try(validate_server_config(config))
  Ok(ServerAwaitingClientHello(config))
}

/// Feed ordered CRYPTO bytes to the client state machine.
pub fn handle_client(
  client client: Client,
  level level: EncryptionLevel,
  bytes bytes: BitArray,
) -> Result(Step(Client), Error) {
  case client, level {
    ClientAwaitingServerHello(..), Initial -> handle_server_hello(client, bytes)
    ClientAwaitingEncryptedExtensions(..), Handshake
    | ClientAwaitingCertificate(..), Handshake
    | ClientAwaitingCertificateVerify(..), Handshake
    | ClientAwaitingFinished(..), Handshake
    -> process_client_flight(client, bytes, [])
    ClientConnected(_), _ -> Error(UnexpectedMessage)
    _, _ -> Error(UnexpectedEncryptionLevel)
  }
}

/// Feed ordered CRYPTO bytes to the server state machine.
pub fn handle_server(
  server server: Server,
  level level: EncryptionLevel,
  bytes bytes: BitArray,
) -> Result(Step(Server), Error) {
  case server, level {
    ServerAwaitingClientHello(config), Initial ->
      handle_client_hello(config, bytes)
    ServerAwaitingClientFinished(context), Handshake ->
      handle_client_finished(context, bytes)
    ServerConnected(_), _ -> Error(UnexpectedMessage)
    _, _ -> Error(UnexpectedEncryptionLevel)
  }
}

/// Return client progress without exposing transcript or secret state.
pub fn client_phase(client: Client) -> Phase {
  case client {
    ClientAwaitingServerHello(..) -> AwaitingPeerHello
    ClientAwaitingEncryptedExtensions(..)
    | ClientAwaitingCertificate(..)
    | ClientAwaitingCertificateVerify(..)
    | ClientAwaitingFinished(..) -> AwaitingPeerFlight
    ClientConnected(_) -> Connected
  }
}

/// Return server progress without exposing transcript or secret state.
pub fn server_phase(server: Server) -> Phase {
  case server {
    ServerAwaitingClientHello(_) -> AwaitingPeerHello
    ServerAwaitingClientFinished(_) -> AwaitingPeerFinished
    ServerConnected(_) -> Connected
  }
}

fn validate_client_config(config: ClientConfig) -> Result(Nil, Error) {
  case supported_version(config.version), config.application_protocols {
    False, _ -> Error(UnsupportedVersion(config.version))
    _, [] -> Error(InvalidConfiguration)
    _, _ -> {
      use _ <- result.try(
        extension_value.encode_server_name(config.hostname)
        |> map_extension_value_result,
      )
      use _ <- result.try(
        extension_value.encode_alpn(config.application_protocols)
        |> map_extension_value_result,
      )
      use _ <- result.try(
        transport_parameter.encode_all(
          config.transport_parameters,
          transport_parameter.Client,
        )
        |> map_transport_parameter_result,
      )
      transport_parameter.validate_handshake(
        config.transport_parameters,
        transport_parameter.Client,
        False,
      )
      |> map_transport_parameter_result
    }
  }
}

fn validate_server_config(config: ServerConfig) -> Result(Nil, Error) {
  case
    supported_version(config.version),
    config.application_protocols,
    config.certificate_chain
  {
    False, _, _ -> Error(UnsupportedVersion(config.version))
    _, [], _ | _, _, [] -> Error(InvalidConfiguration)
    _, _, _ -> {
      use _ <- result.try(
        extension_value.encode_alpn(config.application_protocols)
        |> map_extension_value_result,
      )
      use _ <- result.try(
        extension_value.encode_signature_scheme(config.signature_scheme)
        |> map_extension_value_result,
      )
      use _ <- result.try(
        transport_parameter.encode_all(
          config.transport_parameters,
          transport_parameter.Server,
        )
        |> map_transport_parameter_result,
      )
      transport_parameter.validate_handshake(
        config.transport_parameters,
        transport_parameter.Server,
        has_retry_source_connection_id(config.transport_parameters),
      )
      |> map_transport_parameter_result
    }
  }
}

fn client_extensions(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
) -> Result(List(extension.Extension), Error) {
  use server_name <- result.try(
    extension_value.encode_server_name(config.hostname)
    |> map_extension_value_result,
  )
  use groups <- result.try(
    extension_value.encode_supported_groups([extension_value.X25519])
    |> map_extension_value_result,
  )
  use signatures <- result.try(
    extension_value.encode_signature_schemes(supported_signature_schemes())
    |> map_extension_value_result,
  )
  use alpn <- result.try(
    extension_value.encode_alpn(config.application_protocols)
    |> map_extension_value_result,
  )
  use versions <- result.try(
    extension_value.encode_client_supported_versions([
      extension_value.Tls13,
    ])
    |> map_extension_value_result,
  )
  let share =
    extension_value.KeyShare(
      extension_value.X25519,
      key_exchange.public_key(key_pair),
    )
  use key_share <- result.try(
    extension_value.encode_client_key_shares([share])
    |> map_extension_value_result,
  )
  use parameters <- result.try(
    transport_parameter.encode_all(
      config.transport_parameters,
      transport_parameter.Client,
    )
    |> map_transport_parameter_result,
  )
  Ok([
    extension.Extension(extension.ServerName, server_name),
    extension.Extension(extension.SupportedGroups, groups),
    extension.Extension(extension.SignatureAlgorithms, signatures),
    extension.Extension(extension.ApplicationLayerProtocolNegotiation, alpn),
    extension.Extension(extension.SupportedVersions, versions),
    extension.Extension(extension.KeyShare, key_share),
    extension.Extension(extension.QuicTransportParameters, parameters),
  ])
}

fn handle_client_hello(
  config: ServerConfig,
  bytes: BitArray,
) -> Result(Step(Server), Error) {
  use message <- result.try(decode_exact(bytes))
  let handshake.Message(message_type, body) = message
  case message_type {
    handshake.ClientHello -> {
      use client_hello <- result.try(
        hello.decode_client(body, hello.default_limits()) |> map_hello_result,
      )
      accept_client_hello(config, client_hello, bytes)
    }
    _ -> Error(UnexpectedMessage)
  }
}

fn accept_client_hello(
  config: ServerConfig,
  client_hello: hello.ClientHello,
  encoded_client_hello: BitArray,
) -> Result(Step(Server), Error) {
  let hello.ClientHello(_, session_id, cipher_suites, extensions) = client_hello
  case session_id {
    <<>> -> {
      use Nil <- result.try(require_client_tls13(extensions))
      use Nil <- result.try(require_client_server_name(extensions))
      use selected_alpn <- result.try(select_client_alpn(
        extensions,
        config.application_protocols,
      ))
      use Nil <- result.try(require_server_signature(
        extensions,
        config.signature_scheme,
      ))
      use client_public_key <- result.try(client_x25519_key(extensions))
      use peer_parameters <- result.try(client_transport_parameters(extensions))
      use cipher_suite <- result.try(select_cipher_suite(cipher_suites))
      build_server_flight(
        config,
        encoded_client_hello,
        cipher_suite,
        client_public_key,
        selected_alpn,
        peer_parameters,
      )
    }
    _ -> Error(InvalidConfiguration)
  }
}

fn build_server_flight(
  config: ServerConfig,
  encoded_client_hello: BitArray,
  cipher_suite: hello.CipherSuite,
  client_public_key: BitArray,
  selected_alpn: BitArray,
  peer_parameters: List(transport_parameter.Parameter),
) -> Result(Step(Server), Error) {
  use key_pair <- result.try(
    key_exchange.generate_x25519() |> map_key_exchange_result,
  )
  use random <- result.try(crypto.secure_random(32) |> map_crypto_result)
  use server_hello <- result.try(encode_server_hello(
    random,
    cipher_suite,
    key_exchange.public_key(key_pair),
  ))
  let algorithm = cipher_hash(cipher_suite)
  use hello_transcript <- result.try(new_hello_transcript(
    algorithm,
    encoded_client_hello,
    server_hello,
  ))
  use shared_secret <- result.try(
    key_exchange.shared_secret(key_pair, client_public_key)
    |> map_key_exchange_result,
  )
  use hello_hash <- result.try(
    transcript.hash(hello_transcript) |> map_transcript_result,
  )
  use secrets <- result.try(
    key_schedule.derive_handshake_secrets(
      algorithm,
      None,
      shared_secret,
      hello_hash,
    )
    |> map_crypto_result,
  )
  use #(flight, flight_transcript) <- result.try(server_handshake_messages(
    config,
    selected_alpn,
    algorithm,
    secrets,
    hello_transcript,
  ))
  use application_secrets <- result.try(derive_application_secrets(
    algorithm,
    secrets.master_secret,
    flight_transcript,
  ))
  use actions <- result.try(server_key_actions(
    config.version,
    cipher_suite,
    secrets,
    application_secrets,
    server_hello,
    flight,
    peer_parameters,
  ))
  let context =
    ServerHandshakeContext(
      version: config.version,
      hash_algorithm: algorithm,
      transcript: flight_transcript,
      secrets: secrets,
    )
  Ok(Step(ServerAwaitingClientFinished(context), actions))
}

fn encode_server_hello(
  random: BitArray,
  cipher_suite: hello.CipherSuite,
  public_key: BitArray,
) -> Result(BitArray, Error) {
  use supported_version <- result.try(
    extension_value.encode_server_supported_version(extension_value.Tls13)
    |> map_extension_value_result,
  )
  use key_share <- result.try(
    extension_value.encode_server_key_share(extension_value.KeyShare(
      extension_value.X25519,
      public_key,
    ))
    |> map_extension_value_result,
  )
  let body =
    hello.ServerHello(
      random: random,
      legacy_session_id_echo: <<>>,
      cipher_suite: cipher_suite,
      extensions: [
        extension.Extension(extension.SupportedVersions, supported_version),
        extension.Extension(extension.KeyShare, key_share),
      ],
    )
  use encoded_body <- result.try(
    hello.encode_server(body, hello.default_limits()) |> map_hello_result,
  )
  encode_message(handshake.ServerHello, encoded_body)
}

fn server_handshake_messages(
  config: ServerConfig,
  selected_alpn: BitArray,
  algorithm: crypto.HashAlgorithm,
  secrets: key_schedule.HandshakeSecrets,
  initial_transcript: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use #(encrypted_extensions, after_extensions) <- result.try(
    encode_server_encrypted_extensions(
      config,
      selected_alpn,
      initial_transcript,
    ),
  )
  use #(certificate, after_certificate) <- result.try(encode_server_certificate(
    config.certificate_chain,
    after_extensions,
  ))
  use #(certificate_verify, after_verify) <- result.try(
    encode_server_certificate_verify(config, after_certificate),
  )
  use #(finished, after_finished) <- result.try(encode_server_finished(
    algorithm,
    secrets.server_handshake_traffic_secret,
    after_verify,
  ))
  Ok(#(
    <<
      encrypted_extensions:bits,
      certificate:bits,
      certificate_verify:bits,
      finished:bits,
    >>,
    after_finished,
  ))
}

fn encode_server_encrypted_extensions(
  config: ServerConfig,
  selected_alpn: BitArray,
  current: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use alpn <- result.try(
    extension_value.encode_alpn([selected_alpn])
    |> map_extension_value_result,
  )
  use parameters <- result.try(
    transport_parameter.encode_all(
      config.transport_parameters,
      transport_parameter.Server,
    )
    |> map_transport_parameter_result,
  )
  use body <- result.try(
    message_body.encode_encrypted_extensions(
      [
        extension.Extension(extension.ApplicationLayerProtocolNegotiation, alpn),
        extension.Extension(extension.QuicTransportParameters, parameters),
      ],
      message_body.default_limits(),
    )
    |> map_message_body_result,
  )
  encode_and_append(handshake.EncryptedExtensions, body, current)
}

fn encode_server_certificate(
  chain: List(BitArray),
  current: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  let entries =
    list.map(chain, fn(certificate) {
      message_body.CertificateEntry(certificate, [])
    })
  use body <- result.try(
    message_body.encode_certificate(
      message_body.CertificateMessage(<<>>, entries),
      message_body.default_limits(),
    )
    |> map_message_body_result,
  )
  encode_and_append(handshake.Certificate, body, current)
}

fn encode_server_certificate_verify(
  config: ServerConfig,
  current: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use transcript_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  let content =
    message_body.certificate_verify_content(
      message_body.Server,
      transcript_hash,
    )
  use signature <- result.try(
    authentication.sign(config.signing_key, config.signature_scheme, content)
    |> map_authentication_result,
  )
  use body <- result.try(
    message_body.encode_certificate_verify(
      message_body.CertificateVerify(config.signature_scheme, signature),
      message_body.default_limits(),
    )
    |> map_message_body_result,
  )
  encode_and_append(handshake.CertificateVerify, body, current)
}

fn encode_server_finished(
  algorithm: crypto.HashAlgorithm,
  traffic_secret: BitArray,
  current: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use transcript_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  use verify_data <- result.try(
    key_schedule.finished_verify_data_from_hash(
      algorithm,
      traffic_secret,
      transcript_hash,
    )
    |> map_crypto_result,
  )
  use body <- result.try(
    message_body.encode_finished(algorithm, verify_data)
    |> map_message_body_result,
  )
  encode_and_append(handshake.Finished, body, current)
}

fn server_key_actions(
  version_value: Version,
  cipher_suite: hello.CipherSuite,
  secrets: key_schedule.HandshakeSecrets,
  application: key_schedule.ApplicationSecrets,
  server_hello: BitArray,
  flight: BitArray,
  peer_parameters: List(transport_parameter.Parameter),
) -> Result(List(Action), Error) {
  use handshake_write <- result.try(derive_traffic_keys(
    version_value,
    cipher_suite,
    secrets.server_handshake_traffic_secret,
  ))
  use handshake_read <- result.try(derive_traffic_keys(
    version_value,
    cipher_suite,
    secrets.client_handshake_traffic_secret,
  ))
  use application_write <- result.try(derive_traffic_keys(
    version_value,
    cipher_suite,
    application.server_application_traffic_secret,
  ))
  use application_read <- result.try(derive_traffic_keys(
    version_value,
    cipher_suite,
    application.client_application_traffic_secret,
  ))
  Ok([
    Send(Initial, server_hello),
    InstallWriteKeys(Handshake, handshake_write),
    InstallReadKeys(Handshake, handshake_read),
    Send(Handshake, flight),
    InstallWriteKeys(OneRtt, application_write),
    InstallReadKeys(OneRtt, application_read),
    PeerTransportParameters(peer_parameters),
  ])
}

fn handle_server_hello(
  client: Client,
  bytes: BitArray,
) -> Result(Step(Client), Error) {
  case client {
    ClientAwaitingServerHello(config, key_pair, client_hello) -> {
      use message <- result.try(decode_exact(bytes))
      let handshake.Message(message_type, body) = message
      case message_type {
        handshake.ServerHello -> {
          use server_hello <- result.try(
            hello.decode_server(body, hello.default_limits())
            |> map_hello_result,
          )
          accept_server_hello(
            config,
            key_pair,
            client_hello,
            bytes,
            server_hello,
          )
        }
        _ -> Error(UnexpectedMessage)
      }
    }
    _ -> Error(UnexpectedMessage)
  }
}

fn accept_server_hello(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
  client_hello: BitArray,
  encoded_server_hello: BitArray,
  server_hello: hello.ServerHello,
) -> Result(Step(Client), Error) {
  case server_hello {
    hello.HelloRetryRequest(..) -> Error(UnsupportedKeyShare)
    hello.ServerHello(_, session_id, cipher_suite, extensions) ->
      case session_id {
        <<>> ->
          establish_client_handshake(
            config,
            key_pair,
            client_hello,
            encoded_server_hello,
            cipher_suite,
            extensions,
          )
        _ -> Error(InvalidConfiguration)
      }
  }
}

fn establish_client_handshake(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
  client_hello: BitArray,
  server_hello: BitArray,
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
) -> Result(Step(Client), Error) {
  use Nil <- result.try(require_server_tls13(extensions))
  use public_key <- result.try(server_x25519_key(extensions))
  use algorithm <- result.try(require_supported_cipher(cipher_suite))
  use shared_secret <- result.try(
    key_exchange.shared_secret(key_pair, public_key) |> map_key_exchange_result,
  )
  use current <- result.try(new_hello_transcript(
    algorithm,
    client_hello,
    server_hello,
  ))
  use hello_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  use secrets <- result.try(
    key_schedule.derive_handshake_secrets(
      algorithm,
      None,
      shared_secret,
      hello_hash,
    )
    |> map_crypto_result,
  )
  use write_keys <- result.try(derive_traffic_keys(
    config.version,
    cipher_suite,
    secrets.client_handshake_traffic_secret,
  ))
  use read_keys <- result.try(derive_traffic_keys(
    config.version,
    cipher_suite,
    secrets.server_handshake_traffic_secret,
  ))
  let context =
    ClientHandshakeContext(
      config: config,
      cipher_suite: cipher_suite,
      hash_algorithm: algorithm,
      transcript: current,
      secrets: secrets,
    )
  Ok(
    Step(ClientAwaitingEncryptedExtensions(context), [
      InstallWriteKeys(Handshake, write_keys),
      InstallReadKeys(Handshake, read_keys),
    ]),
  )
}

fn process_client_flight(
  client: Client,
  bytes: BitArray,
  actions: List(Action),
) -> Result(Step(Client), Error) {
  case bytes {
    <<>> -> Ok(Step(client, actions))
    _ ->
      case handshake.decode_next(bytes, handshake.default_limits()) {
        Ok(handshake.NeedMore) -> Error(TruncatedHandshake)
        Ok(handshake.Complete(message, rest)) -> {
          use Step(next, new_actions) <- result.try(process_client_message(
            client,
            message,
          ))
          process_client_flight(next, rest, list.append(actions, new_actions))
        }
        Error(error) -> Error(HandshakeFailure(error))
      }
  }
}

fn process_client_message(
  client: Client,
  message: handshake.Message,
) -> Result(Step(Client), Error) {
  case client, message {
    ClientAwaitingEncryptedExtensions(context),
      handshake.Message(handshake.EncryptedExtensions, body)
    -> client_accept_encrypted_extensions(context, body)
    ClientAwaitingCertificate(context),
      handshake.Message(handshake.Certificate, body)
    -> client_accept_certificate(context, body)
    ClientAwaitingCertificateVerify(context, peer),
      handshake.Message(handshake.CertificateVerify, body)
    -> client_accept_certificate_verify(context, peer, body)
    ClientAwaitingFinished(context), handshake.Message(handshake.Finished, body)
    -> client_accept_finished(context, body)
    _, _ -> Error(UnexpectedMessage)
  }
}

fn client_accept_encrypted_extensions(
  context: ClientHandshakeContext,
  body: BitArray,
) -> Result(Step(Client), Error) {
  use extensions <- result.try(
    message_body.decode_encrypted_extensions(
      body,
      message_body.default_limits(),
    )
    |> map_message_body_result,
  )
  use _selected <- result.try(selected_server_alpn(
    extensions,
    context.config.application_protocols,
  ))
  use parameters <- result.try(server_transport_parameters(
    extensions,
    context.config.retried,
  ))
  use encoded <- result.try(encode_message(handshake.EncryptedExtensions, body))
  use next_transcript <- result.try(
    transcript.append(context.transcript, encoded) |> map_transcript_result,
  )
  let next_context =
    ClientHandshakeContext(..context, transcript: next_transcript)
  Ok(
    Step(ClientAwaitingCertificate(next_context), [
      PeerTransportParameters(parameters),
    ]),
  )
}

fn client_accept_certificate(
  context: ClientHandshakeContext,
  body: BitArray,
) -> Result(Step(Client), Error) {
  use certificate <- result.try(
    message_body.decode_certificate(body, message_body.default_limits())
    |> map_message_body_result,
  )
  let message_body.CertificateMessage(request_context, entries) = certificate
  case request_context, entries {
    <<>>, [_, ..] -> {
      let chain =
        list.map(entries, fn(entry) {
          let message_body.CertificateEntry(der, _) = entry
          der
        })
      use peer <- result.try(
        authentication.validate_server_certificate(
          chain,
          context.config.trust_store,
          context.config.hostname,
        )
        |> map_authentication_result,
      )
      use encoded <- result.try(encode_message(handshake.Certificate, body))
      use next_transcript <- result.try(
        transcript.append(context.transcript, encoded) |> map_transcript_result,
      )
      let next_context =
        ClientHandshakeContext(..context, transcript: next_transcript)
      Ok(Step(ClientAwaitingCertificateVerify(next_context, peer), []))
    }
    _, _ -> Error(InvalidConfiguration)
  }
}

fn client_accept_certificate_verify(
  context: ClientHandshakeContext,
  peer: authentication.VerifiedPeer,
  body: BitArray,
) -> Result(Step(Client), Error) {
  use verify <- result.try(
    message_body.decode_certificate_verify(body, message_body.default_limits())
    |> map_message_body_result,
  )
  let message_body.CertificateVerify(scheme, signature) = verify
  case list.contains(supported_signature_schemes(), scheme) {
    False ->
      Error(AuthenticationFailure(authentication.IncompatibleSignatureScheme))
    True -> {
      use transcript_hash <- result.try(
        transcript.hash(context.transcript) |> map_transcript_result,
      )
      let content =
        message_body.certificate_verify_content(
          message_body.Server,
          transcript_hash,
        )
      use Nil <- result.try(
        authentication.verify(peer, scheme, content, signature)
        |> map_authentication_result,
      )
      use encoded <- result.try(encode_message(
        handshake.CertificateVerify,
        body,
      ))
      use next_transcript <- result.try(
        transcript.append(context.transcript, encoded) |> map_transcript_result,
      )
      let next_context =
        ClientHandshakeContext(..context, transcript: next_transcript)
      Ok(Step(ClientAwaitingFinished(next_context), []))
    }
  }
}

fn client_accept_finished(
  context: ClientHandshakeContext,
  body: BitArray,
) -> Result(Step(Client), Error) {
  use actual <- result.try(
    message_body.decode_finished(context.hash_algorithm, body)
    |> map_message_body_result,
  )
  use before_finished_hash <- result.try(
    transcript.hash(context.transcript) |> map_transcript_result,
  )
  use expected <- result.try(
    key_schedule.finished_verify_data_from_hash(
      context.hash_algorithm,
      context.secrets.server_handshake_traffic_secret,
      before_finished_hash,
    )
    |> map_crypto_result,
  )
  use matches <- result.try(
    authentication.constant_time_equal(actual, expected)
    |> map_authentication_result,
  )
  case matches {
    False -> Error(FinishedMismatch)
    True -> finish_client_handshake(context, body)
  }
}

fn finish_client_handshake(
  context: ClientHandshakeContext,
  server_finished_body: BitArray,
) -> Result(Step(Client), Error) {
  use server_finished <- result.try(encode_message(
    handshake.Finished,
    server_finished_body,
  ))
  use after_server_finished <- result.try(
    transcript.append(context.transcript, server_finished)
    |> map_transcript_result,
  )
  use application <- result.try(derive_application_secrets(
    context.hash_algorithm,
    context.secrets.master_secret,
    after_server_finished,
  ))
  use client_finished_hash <- result.try(
    transcript.hash(after_server_finished) |> map_transcript_result,
  )
  use client_verify_data <- result.try(
    key_schedule.finished_verify_data_from_hash(
      context.hash_algorithm,
      context.secrets.client_handshake_traffic_secret,
      client_finished_hash,
    )
    |> map_crypto_result,
  )
  use client_finished_body <- result.try(
    message_body.encode_finished(context.hash_algorithm, client_verify_data)
    |> map_message_body_result,
  )
  use #(client_finished, completed_transcript) <- result.try(encode_and_append(
    handshake.Finished,
    client_finished_body,
    after_server_finished,
  ))
  use resumption_master_secret <- result.try(derive_resumption_master(
    context.hash_algorithm,
    context.secrets.master_secret,
    completed_transcript,
  ))
  use write_keys <- result.try(derive_traffic_keys(
    context.config.version,
    context.cipher_suite,
    application.client_application_traffic_secret,
  ))
  use read_keys <- result.try(derive_traffic_keys(
    context.config.version,
    context.cipher_suite,
    application.server_application_traffic_secret,
  ))
  Ok(
    Step(ClientConnected(resumption_master_secret), [
      InstallWriteKeys(OneRtt, write_keys),
      InstallReadKeys(OneRtt, read_keys),
      Send(Handshake, client_finished),
      HandshakeComplete,
    ]),
  )
}

fn handle_client_finished(
  context: ServerHandshakeContext,
  bytes: BitArray,
) -> Result(Step(Server), Error) {
  use message <- result.try(decode_exact(bytes))
  let handshake.Message(message_type, body) = message
  case message_type {
    handshake.Finished -> verify_client_finished(context, body)
    _ -> Error(UnexpectedMessage)
  }
}

fn verify_client_finished(
  context: ServerHandshakeContext,
  body: BitArray,
) -> Result(Step(Server), Error) {
  use actual <- result.try(
    message_body.decode_finished(context.hash_algorithm, body)
    |> map_message_body_result,
  )
  use current_hash <- result.try(
    transcript.hash(context.transcript) |> map_transcript_result,
  )
  use expected <- result.try(
    key_schedule.finished_verify_data_from_hash(
      context.hash_algorithm,
      context.secrets.client_handshake_traffic_secret,
      current_hash,
    )
    |> map_crypto_result,
  )
  use matches <- result.try(
    authentication.constant_time_equal(actual, expected)
    |> map_authentication_result,
  )
  case matches {
    False -> Error(FinishedMismatch)
    True -> complete_server_handshake(context, body)
  }
}

fn complete_server_handshake(
  context: ServerHandshakeContext,
  body: BitArray,
) -> Result(Step(Server), Error) {
  use encoded <- result.try(encode_message(handshake.Finished, body))
  use completed <- result.try(
    transcript.append(context.transcript, encoded) |> map_transcript_result,
  )
  use resumption_master_secret <- result.try(derive_resumption_master(
    context.hash_algorithm,
    context.secrets.master_secret,
    completed,
  ))
  Ok(Step(ServerConnected(resumption_master_secret), [HandshakeComplete]))
}

fn require_client_tls13(
  extensions: List(extension.Extension),
) -> Result(Nil, Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.SupportedVersions,
  ))
  use _ <- result.try(
    extension_value.decode_client_supported_versions(encoded)
    |> map_extension_value_result,
  )
  Ok(Nil)
}

fn require_server_tls13(
  extensions: List(extension.Extension),
) -> Result(Nil, Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.SupportedVersions,
  ))
  use selected <- result.try(
    extension_value.decode_server_supported_version(encoded)
    |> map_extension_value_result,
  )
  case selected {
    extension_value.Tls13 -> Ok(Nil)
    _ -> Error(InvalidConfiguration)
  }
}

fn require_client_server_name(
  extensions: List(extension.Extension),
) -> Result(Nil, Error) {
  use encoded <- result.try(require_extension(extensions, extension.ServerName))
  use _ <- result.try(
    extension_value.decode_server_name(encoded) |> map_extension_value_result,
  )
  Ok(Nil)
}

fn select_client_alpn(
  extensions: List(extension.Extension),
  supported: List(BitArray),
) -> Result(BitArray, Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.ApplicationLayerProtocolNegotiation,
  ))
  use offered <- result.try(
    extension_value.decode_alpn(encoded) |> map_extension_value_result,
  )
  find_first_shared(offered, supported)
}

fn selected_server_alpn(
  extensions: List(extension.Extension),
  offered: List(BitArray),
) -> Result(BitArray, Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.ApplicationLayerProtocolNegotiation,
  ))
  use selected <- result.try(
    extension_value.decode_alpn(encoded) |> map_extension_value_result,
  )
  case selected {
    [protocol] ->
      case list.contains(offered, protocol) {
        True -> Ok(protocol)
        False -> Error(NoApplicationProtocol)
      }
    _ -> Error(NoApplicationProtocol)
  }
}

fn require_server_signature(
  extensions: List(extension.Extension),
  signature_scheme: extension_value.SignatureScheme,
) -> Result(Nil, Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.SignatureAlgorithms,
  ))
  use signatures <- result.try(
    extension_value.decode_signature_schemes(encoded)
    |> map_extension_value_result,
  )
  case list.contains(signatures, signature_scheme) {
    True -> Ok(Nil)
    False ->
      Error(AuthenticationFailure(authentication.IncompatibleSignatureScheme))
  }
}

fn client_x25519_key(
  extensions: List(extension.Extension),
) -> Result(BitArray, Error) {
  use groups_data <- result.try(require_extension(
    extensions,
    extension.SupportedGroups,
  ))
  use groups <- result.try(
    extension_value.decode_supported_groups(groups_data)
    |> map_extension_value_result,
  )
  case list.contains(groups, extension_value.X25519) {
    False -> Error(UnsupportedKeyShare)
    True -> {
      use shares_data <- result.try(require_extension(
        extensions,
        extension.KeyShare,
      ))
      use shares <- result.try(
        extension_value.decode_client_key_shares(shares_data)
        |> map_extension_value_result,
      )
      find_x25519_share(shares)
    }
  }
}

fn server_x25519_key(
  extensions: List(extension.Extension),
) -> Result(BitArray, Error) {
  use encoded <- result.try(require_extension(extensions, extension.KeyShare))
  use share <- result.try(
    extension_value.decode_server_key_share(encoded)
    |> map_extension_value_result,
  )
  case share {
    extension_value.KeyShare(extension_value.X25519, public_key) ->
      Ok(public_key)
    _ -> Error(UnsupportedKeyShare)
  }
}

fn client_transport_parameters(
  extensions: List(extension.Extension),
) -> Result(List(transport_parameter.Parameter), Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.QuicTransportParameters,
  ))
  use parameters <- result.try(
    transport_parameter.decode_all(
      encoded,
      transport_parameter.Client,
      transport_parameter.default_limits(),
    )
    |> map_transport_parameter_result,
  )
  use Nil <- result.try(
    transport_parameter.validate_handshake(
      parameters,
      transport_parameter.Client,
      False,
    )
    |> map_transport_parameter_result,
  )
  Ok(parameters)
}

fn server_transport_parameters(
  extensions: List(extension.Extension),
  retried: Bool,
) -> Result(List(transport_parameter.Parameter), Error) {
  use encoded <- result.try(require_extension(
    extensions,
    extension.QuicTransportParameters,
  ))
  use parameters <- result.try(
    transport_parameter.decode_all(
      encoded,
      transport_parameter.Server,
      transport_parameter.default_limits(),
    )
    |> map_transport_parameter_result,
  )
  use Nil <- result.try(
    transport_parameter.validate_handshake(
      parameters,
      transport_parameter.Server,
      retried,
    )
    |> map_transport_parameter_result,
  )
  Ok(parameters)
}

fn require_extension(
  extensions: List(extension.Extension),
  expected: extension.Kind,
) -> Result(BitArray, Error) {
  case extensions {
    [] -> Error(MissingExtension(expected))
    [extension.Extension(kind, data), ..rest] ->
      case kind == expected {
        True -> Ok(data)
        False -> require_extension(rest, expected)
      }
  }
}

fn find_x25519_share(
  shares: List(extension_value.KeyShare),
) -> Result(BitArray, Error) {
  case shares {
    [] -> Error(UnsupportedKeyShare)
    [extension_value.KeyShare(extension_value.X25519, key), ..] -> Ok(key)
    [_, ..rest] -> find_x25519_share(rest)
  }
}

fn find_first_shared(
  preferred: List(BitArray),
  supported: List(BitArray),
) -> Result(BitArray, Error) {
  case preferred {
    [] -> Error(NoApplicationProtocol)
    [protocol, ..rest] ->
      case list.contains(supported, protocol) {
        True -> Ok(protocol)
        False -> find_first_shared(rest, supported)
      }
  }
}

fn select_cipher_suite(
  offered: List(hello.CipherSuite),
) -> Result(hello.CipherSuite, Error) {
  case offered {
    [] -> Error(UnsupportedCipherSuite(hello.UnknownCipherSuite(0)))
    [cipher_suite, ..rest] -> {
      case cipher_suite {
        hello.Aes128GcmSha256
        | hello.Aes256GcmSha384
        | hello.Chacha20Poly1305Sha256 -> Ok(cipher_suite)
        _ -> select_cipher_suite(rest)
      }
    }
  }
}

fn require_supported_cipher(
  cipher_suite: hello.CipherSuite,
) -> Result(crypto.HashAlgorithm, Error) {
  case cipher_suite {
    hello.Aes128GcmSha256 | hello.Chacha20Poly1305Sha256 -> Ok(crypto.Sha256)
    hello.Aes256GcmSha384 -> Ok(crypto.Sha384)
    _ -> Error(UnsupportedCipherSuite(cipher_suite))
  }
}

fn cipher_hash(cipher_suite: hello.CipherSuite) -> crypto.HashAlgorithm {
  case cipher_suite {
    hello.Aes256GcmSha384 -> crypto.Sha384
    _ -> crypto.Sha256
  }
}

fn supported_cipher_suites() -> List(hello.CipherSuite) {
  [
    hello.Aes128GcmSha256,
    hello.Aes256GcmSha384,
    hello.Chacha20Poly1305Sha256,
  ]
}

fn supported_signature_schemes() -> List(extension_value.SignatureScheme) {
  [
    extension_value.Ed25519,
    extension_value.EcdsaSecp256r1Sha256,
    extension_value.EcdsaSecp384r1Sha384,
    extension_value.RsaPssRsaeSha256,
    extension_value.RsaPssRsaeSha384,
    extension_value.RsaPssRsaeSha512,
    extension_value.RsaPssPssSha256,
    extension_value.RsaPssPssSha384,
    extension_value.RsaPssPssSha512,
  ]
}

fn supported_version(version_value: Version) -> Bool {
  case version_value {
    version.Version1 | version.Version2 -> True
    _ -> False
  }
}

fn has_retry_source_connection_id(
  parameters: List(transport_parameter.Parameter),
) -> Bool {
  list.any(parameters, fn(parameter) {
    case parameter {
      transport_parameter.RetrySourceConnectionId(_) -> True
      _ -> False
    }
  })
}

fn new_hello_transcript(
  algorithm: crypto.HashAlgorithm,
  client_hello: BitArray,
  server_hello: BitArray,
) -> Result(transcript.Transcript, Error) {
  use initial <- result.try(
    transcript.new(algorithm, maximum_transcript_length)
    |> map_transcript_result,
  )
  use after_client <- result.try(
    transcript.append(initial, client_hello) |> map_transcript_result,
  )
  transcript.append(after_client, server_hello) |> map_transcript_result
}

fn derive_application_secrets(
  algorithm: crypto.HashAlgorithm,
  master_secret: BitArray,
  current: transcript.Transcript,
) -> Result(key_schedule.ApplicationSecrets, Error) {
  use current_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  key_schedule.derive_application_secrets(
    algorithm,
    master_secret,
    current_hash,
  )
  |> map_crypto_result
}

fn derive_resumption_master(
  algorithm: crypto.HashAlgorithm,
  master_secret: BitArray,
  current: transcript.Transcript,
) -> Result(BitArray, Error) {
  use current_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  key_schedule.derive_resumption_master_secret(
    algorithm,
    master_secret,
    current_hash,
  )
  |> map_crypto_result
}

fn derive_traffic_keys(
  version_value: Version,
  cipher_suite: hello.CipherSuite,
  secret: BitArray,
) -> Result(traffic_keys.TrafficKeys, Error) {
  traffic_keys.from_secret(version_value, cipher_suite, secret)
  |> map_traffic_key_result
}

fn encode_and_append(
  message_type: handshake.MessageType,
  body: BitArray,
  current: transcript.Transcript,
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use encoded <- result.try(encode_message(message_type, body))
  use next <- result.try(
    transcript.append(current, encoded) |> map_transcript_result,
  )
  Ok(#(encoded, next))
}

fn encode_message(
  message_type: handshake.MessageType,
  body: BitArray,
) -> Result(BitArray, Error) {
  handshake.encode(
    handshake.Message(message_type, body),
    maximum_handshake_message_length,
  )
  |> map_handshake_result
}

fn decode_exact(bytes: BitArray) -> Result(handshake.Message, Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) -> Error(TruncatedHandshake)
    Ok(handshake.Complete(message, <<>>)) -> Ok(message)
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn map_handshake_result(
  value: Result(output, handshake.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn map_hello_result(
  value: Result(output, hello.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(HelloFailure(error))
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

fn map_transport_parameter_result(
  value: Result(output, transport_parameter.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TransportParameterFailure(error))
  }
}

fn map_crypto_result(
  value: Result(output, crypto.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(CryptoFailure(error))
  }
}

fn map_key_exchange_result(
  value: Result(output, key_exchange.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(KeyExchangeFailure(error))
  }
}

fn map_transcript_result(
  value: Result(output, transcript.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TranscriptFailure(error))
  }
}

fn map_traffic_key_result(
  value: Result(output, traffic_keys.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TrafficKeyFailure(error))
  }
}

fn map_message_body_result(
  value: Result(output, message_body.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(MessageBodyFailure(error))
  }
}

fn map_authentication_result(
  value: Result(output, authentication.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(AuthenticationFailure(error))
  }
}
