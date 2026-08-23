//// Authenticated TLS 1.3 handshake state machine for QUIC CRYPTO streams.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/handshake
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/key_exchange
import gleam_quic/internal/tls/key_schedule
import gleam_quic/internal/tls/message_body
import gleam_quic/internal/tls/pre_shared_key
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/tls/session_ticket
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

/// Whether the first ClientHello carries a key share or requests one via HRR.
pub type KeyShareStrategy {
  EagerKeyShare
  DeferredKeyShare
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
  DiscardKeys(EncryptionLevel)
  PeerTransportParameters(List(transport_parameter.Parameter))
  EarlyDataAccepted
  EarlyDataRejected
  StoreSessionTicket(session_ticket.ClientTicket)
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
    resumption_offer: Option(resumption.ClientOffer),
    resumed: Bool,
    early_data_accepted: Bool,
    selected_alpn: Option(BitArray),
    peer_transport_parameters: Option(List(transport_parameter.Parameter)),
    pending_crypto: BitArray,
  )
}

type ClientConnectedContext {
  ClientConnectedContext(
    config: ClientConfig,
    cipher_suite: hello.CipherSuite,
    hash_algorithm: crypto.HashAlgorithm,
    resumption_master_secret: BitArray,
    selected_alpn: BitArray,
    peer_transport_parameters: List(transport_parameter.Parameter),
    pending_crypto: BitArray,
    handshake_confirmed: Bool,
  )
}

/// Client TLS state. Private keys and traffic secrets have no accessors.
pub opaque type Client {
  ClientAwaitingServerHello(
    config: ClientConfig,
    key_pair: Option(key_exchange.KeyPair),
    encoded_client_hello: BitArray,
    resumption_offer: Option(resumption.ClientOffer),
    pending_crypto: BitArray,
  )
  ClientAwaitingServerHelloAfterRetry(
    config: ClientConfig,
    key_pair: key_exchange.KeyPair,
    selected_cipher_suite: hello.CipherSuite,
    retry_transcript: transcript.Transcript,
    encoded_client_hello: BitArray,
    resumption_offer: Option(resumption.ClientOffer),
    pending_crypto: BitArray,
  )
  ClientAwaitingEncryptedExtensions(ClientHandshakeContext)
  ClientAwaitingCertificate(ClientHandshakeContext)
  ClientAwaitingCertificateVerify(
    context: ClientHandshakeContext,
    peer: authentication.VerifiedPeer,
  )
  ClientAwaitingFinished(ClientHandshakeContext)
  ClientConnected(ClientConnectedContext)
}

type ServerHandshakeContext {
  ServerHandshakeContext(
    config: ServerConfig,
    server_name: String,
    selected_alpn: BitArray,
    version: Version,
    cipher_suite: hello.CipherSuite,
    hash_algorithm: crypto.HashAlgorithm,
    transcript: transcript.Transcript,
    secrets: key_schedule.HandshakeSecrets,
    resumption_selection: Option(resumption.Selected),
  )
}

type ServerConnectedContext {
  ServerConnectedContext(
    config: ServerConfig,
    server_name: String,
    selected_alpn: BitArray,
    hash_algorithm: crypto.HashAlgorithm,
    cipher_suite: hello.CipherSuite,
    resumption_master_secret: BitArray,
    replay_cache: Option(anti_replay.Cache),
  )
}

type ServerRetryContext {
  ServerRetryContext(
    config: ServerConfig,
    original_client_hello: hello.ClientHello,
    selected_cipher_suite: hello.CipherSuite,
    retry_transcript: transcript.Transcript,
    resumption_policy: Option(resumption.ServerPolicy),
  )
}

/// Server TLS state. Private keys and traffic secrets have no accessors.
pub opaque type Server {
  ServerAwaitingClientHello(
    config: ServerConfig,
    pending_crypto: BitArray,
    resumption_policy: Option(resumption.ServerPolicy),
  )
  ServerAwaitingSecondClientHello(
    context: ServerRetryContext,
    pending_crypto: BitArray,
  )
  ServerAwaitingClientFinished(
    context: ServerHandshakeContext,
    pending_crypto: BitArray,
  )
  ServerConnected(ServerConnectedContext)
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
  InvalidHelloRetryRequest
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
  ResumptionFailure(resumption.Error)
  SessionTicketFailure(session_ticket.Error)
}

/// Generate an ephemeral ClientHello and enter the client Initial state.
pub fn start_client(
  config config: ClientConfig,
) -> Result(Step(Client), Error) {
  start_client_with_strategy(config: config, strategy: EagerKeyShare)
}

/// Start a client with explicit key-share latency policy.
pub fn start_client_with_strategy(
  config config: ClientConfig,
  strategy strategy: KeyShareStrategy,
) -> Result(Step(Client), Error) {
  start_client_internal(config, strategy, None)
}

/// Start a PSK resumption attempt, optionally installing client 0-RTT keys.
pub fn start_client_resuming(
  config config: ClientConfig,
  ticket ticket: session_ticket.ClientTicket,
  now_milliseconds now_milliseconds: Int,
  request_early_data request_early_data: Bool,
) -> Result(Step(Client), Error) {
  use offer <- result.try(
    resumption.client_offer(ticket, now_milliseconds, request_early_data)
    |> map_resumption_result,
  )
  let version_identifier = version_identifier(config.version)
  case
    resumption.client_matches_origin(
      offer,
      config.hostname,
      config.application_protocols,
      version_identifier,
    )
  {
    False -> Error(InvalidConfiguration)
    True -> start_client_internal(config, EagerKeyShare, Some(offer))
  }
}

fn start_client_internal(
  config: ClientConfig,
  strategy: KeyShareStrategy,
  resumption_offer: Option(resumption.ClientOffer),
) -> Result(Step(Client), Error) {
  use Nil <- result.try(validate_client_config(config))
  use key_pair <- result.try(client_key_pair(strategy))
  use random <- result.try(crypto.secure_random(32) |> map_crypto_result)
  use extensions <- result.try(client_extensions(
    config,
    key_pair,
    resumption_offer,
  ))
  let client_hello =
    hello.ClientHello(
      random: random,
      legacy_session_id: <<>>,
      cipher_suites: client_cipher_suites(resumption_offer),
      extensions: extensions,
    )
  use body <- result.try(
    hello.encode_client(client_hello, hello.default_limits())
    |> map_hello_result,
  )
  use placeholder <- result.try(encode_message(handshake.ClientHello, body))
  use encoded <- result.try(seal_client_hello(resumption_offer, placeholder))
  use early_actions <- result.try(client_early_key_actions(
    config.version,
    resumption_offer,
    encoded,
  ))
  Ok(
    Step(
      ClientAwaitingServerHello(
        config,
        key_pair,
        encoded,
        resumption_offer,
        <<>>,
      ),
      [Send(Initial, encoded), ..early_actions],
    ),
  )
}

/// Validate a server configuration without emitting network data.
pub fn start_server(config config: ServerConfig) -> Result(Server, Error) {
  use Nil <- result.try(validate_server_config(config))
  Ok(ServerAwaitingClientHello(config, <<>>, None))
}

/// Start a server which can authenticate repository-owned resumption tickets.
pub fn start_server_with_resumption(
  config config: ServerConfig,
  policy policy: resumption.ServerPolicy,
) -> Result(Server, Error) {
  use Nil <- result.try(validate_server_config(config))
  Ok(ServerAwaitingClientHello(config, <<>>, Some(policy)))
}

/// Feed ordered CRYPTO bytes to the client state machine.
pub fn handle_client(
  client client: Client,
  level level: EncryptionLevel,
  bytes bytes: BitArray,
) -> Result(Step(Client), Error) {
  case client, level {
    ClientAwaitingServerHello(..), Initial
    | ClientAwaitingServerHelloAfterRetry(..), Initial
    -> handle_server_hello(client, bytes)
    ClientAwaitingEncryptedExtensions(..), Handshake
    | ClientAwaitingCertificate(..), Handshake
    | ClientAwaitingCertificateVerify(..), Handshake
    | ClientAwaitingFinished(..), Handshake
    -> prepare_client_flight(client, bytes)
    ClientConnected(_), _ -> Error(UnexpectedMessage)
    _, _ -> Error(UnexpectedEncryptionLevel)
  }
}

/// Feed CRYPTO bytes with the monotonic receive time required for tickets.
pub fn handle_client_at(
  client client: Client,
  level level: EncryptionLevel,
  bytes bytes: BitArray,
  now_milliseconds now_milliseconds: Int,
) -> Result(Step(Client), Error) {
  case client, level, now_milliseconds >= 0 {
    ClientConnected(context), OneRtt, True ->
      handle_client_post_handshake(context, bytes, now_milliseconds)
    ClientConnected(_), OneRtt, False -> Error(InvalidConfiguration)
    _, _, _ -> handle_client(client: client, level: level, bytes: bytes)
  }
}

/// Feed ordered CRYPTO bytes to the server state machine.
pub fn handle_server(
  server server: Server,
  level level: EncryptionLevel,
  bytes bytes: BitArray,
) -> Result(Step(Server), Error) {
  case server, level {
    ServerAwaitingClientHello(config, pending, policy), Initial ->
      handle_client_hello(config, policy, <<pending:bits, bytes:bits>>)
    ServerAwaitingSecondClientHello(context, pending), Initial ->
      handle_second_client_hello(context, <<pending:bits, bytes:bits>>)
    ServerAwaitingClientFinished(context, pending), Handshake ->
      handle_client_finished(context, <<pending:bits, bytes:bits>>)
    ServerConnected(_), _ -> Error(UnexpectedMessage)
    _, _ -> Error(UnexpectedEncryptionLevel)
  }
}

/// Return client progress without exposing transcript or secret state.
pub fn client_phase(client: Client) -> Phase {
  case client {
    ClientAwaitingServerHello(..) | ClientAwaitingServerHelloAfterRetry(..) ->
      AwaitingPeerHello
    ClientAwaitingEncryptedExtensions(..)
    | ClientAwaitingCertificate(..)
    | ClientAwaitingCertificateVerify(..)
    | ClientAwaitingFinished(..) -> AwaitingPeerFlight
    ClientConnected(_) -> Connected
  }
}

/// Retain the exact ClientHello after an authenticated QUIC Retry and mark
/// the eventual server transport parameters as belonging to a retried path.
pub fn accept_quic_retry(client: Client) -> Result(#(Client, BitArray), Error) {
  case client {
    ClientAwaitingServerHello(config, key_pair, encoded, offer, <<>>)
      if !config.retried
    -> {
      let config = ClientConfig(..config, retried: True)
      Ok(#(
        ClientAwaitingServerHello(config, key_pair, encoded, offer, <<>>),
        encoded,
      ))
    }
    _ -> Error(UnexpectedMessage)
  }
}

/// Return server progress without exposing transcript or secret state.
pub fn server_phase(server: Server) -> Phase {
  case server {
    ServerAwaitingClientHello(_, _, _)
    | ServerAwaitingSecondClientHello(_, _) -> AwaitingPeerHello
    ServerAwaitingClientFinished(_, _) -> AwaitingPeerFinished
    ServerConnected(_) -> Connected
  }
}

/// Issue one encrypted post-handshake ticket from a connected server.
pub fn issue_new_session_ticket(
  server server: Server,
  ticket_key ticket_key: BitArray,
  now_milliseconds now_milliseconds: Int,
  lifetime_seconds lifetime_seconds: Int,
  permit_early_data permit_early_data: Bool,
) -> Result(Step(Server), Error) {
  case server {
    ServerConnected(context) -> {
      use remembered_parameters <- result.try(
        transport_parameter.encode_all(
          context.config.transport_parameters,
          transport_parameter.Server,
        )
        |> map_transport_parameter_result,
      )
      use ticket <- result.try(
        session_ticket.issue(
          ticket_key:,
          issued_at_milliseconds: now_milliseconds,
          lifetime_seconds:,
          resumption_master_secret: context.resumption_master_secret,
          algorithm: context.hash_algorithm,
          cipher_suite: context.cipher_suite,
          server_name: context.server_name,
          alpn: context.selected_alpn,
          quic_version: version_identifier(context.config.version),
          remembered_transport_parameters: remembered_parameters,
          permit_early_data:,
        )
        |> map_session_ticket_result,
      )
      use body <- result.try(
        message_body.encode_new_session_ticket(
          ticket,
          message_body.default_limits(),
        )
        |> map_message_body_result,
      )
      use encoded <- result.try(encode_message(handshake.NewSessionTicket, body))
      Ok(Step(server, [Send(OneRtt, encoded)]))
    }
    _ -> Error(UnexpectedMessage)
  }
}

/// Return the updated early-data replay cache after a resumed handshake.
pub fn server_replay_cache(server server: Server) -> Option(anti_replay.Cache) {
  case server {
    ServerConnected(context) -> context.replay_cache
    _ -> None
  }
}

/// Confirm the client handshake after HANDSHAKE_DONE and discard its keys.
pub fn confirm_client_handshake(
  client client: Client,
) -> Result(Step(Client), Error) {
  case client {
    ClientConnected(context) ->
      case context.handshake_confirmed {
        True -> Ok(Step(client, []))
        False ->
          Ok(
            Step(
              ClientConnected(
                ClientConnectedContext(..context, handshake_confirmed: True),
              ),
              [DiscardKeys(Handshake)],
            ),
          )
      }
    _ -> Error(UnexpectedMessage)
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

fn client_key_pair(
  strategy: KeyShareStrategy,
) -> Result(Option(key_exchange.KeyPair), Error) {
  case strategy {
    DeferredKeyShare -> Ok(None)
    EagerKeyShare -> {
      use key_pair <- result.try(
        key_exchange.generate_x25519() |> map_key_exchange_result,
      )
      Ok(Some(key_pair))
    }
  }
}

fn client_extensions(
  config: ClientConfig,
  key_pair: Option(key_exchange.KeyPair),
  resumption_offer: Option(resumption.ClientOffer),
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
  use key_share <- result.try(encode_client_key_share(key_pair))
  use parameters <- result.try(
    transport_parameter.encode_all(
      config.transport_parameters,
      transport_parameter.Client,
    )
    |> map_transport_parameter_result,
  )
  let base = [
    extension.Extension(extension.ServerName, server_name),
    extension.Extension(extension.SupportedGroups, groups),
    extension.Extension(extension.SignatureAlgorithms, signatures),
    extension.Extension(extension.ApplicationLayerProtocolNegotiation, alpn),
    extension.Extension(extension.SupportedVersions, versions),
    extension.Extension(extension.KeyShare, key_share),
    extension.Extension(extension.QuicTransportParameters, parameters),
  ]
  case resumption_offer {
    None -> Ok(base)
    Some(offer) -> Ok(list.append(base, resumption.client_extensions(offer)))
  }
}

fn encode_client_key_share(
  key_pair: Option(key_exchange.KeyPair),
) -> Result(BitArray, Error) {
  let shares = case key_pair {
    None -> []
    Some(value) -> [
      extension_value.KeyShare(
        extension_value.X25519,
        key_exchange.public_key(value),
      ),
    ]
  }
  extension_value.encode_client_key_shares(shares)
  |> map_extension_value_result
}

fn seal_client_hello(
  offer: Option(resumption.ClientOffer),
  encoded_placeholder: BitArray,
) -> Result(BitArray, Error) {
  case offer {
    None -> Ok(encoded_placeholder)
    Some(value) ->
      resumption.seal_client_hello(value, encoded_placeholder, <<>>)
      |> map_resumption_result
  }
}

fn client_early_key_actions(
  version_value: Version,
  offer: Option(resumption.ClientOffer),
  encoded_client_hello: BitArray,
) -> Result(List(Action), Error) {
  case offer {
    None -> Ok([])
    Some(value) ->
      case resumption.client_early_data_requested(value) {
        False -> Ok([])
        True -> {
          let algorithm = resumption.client_hash_algorithm(value)
          use early_secret <- result.try(
            key_schedule.derive_early_secret(
              algorithm,
              resumption.client_pre_shared_key(value),
            )
            |> map_crypto_result,
          )
          use hello_hash <- result.try(
            crypto.hash(algorithm, encoded_client_hello) |> map_crypto_result,
          )
          use traffic_secret <- result.try(
            key_schedule.derive_client_early_traffic_secret(
              algorithm,
              early_secret,
              hello_hash,
            )
            |> map_crypto_result,
          )
          use keys <- result.try(derive_traffic_keys(
            version_value,
            resumption.client_cipher_suite(value),
            traffic_secret,
          ))
          use remembered_parameters <- result.try(
            transport_parameter.decode_all(
              resumption.client_remembered_transport_parameters(value),
              transport_parameter.Server,
              transport_parameter.default_limits(),
            )
            |> map_transport_parameter_result,
          )
          use Nil <- result.try(
            transport_parameter.validate_handshake(
              remembered_parameters,
              transport_parameter.Server,
              has_retry_source_connection_id(remembered_parameters),
            )
            |> map_transport_parameter_result,
          )
          Ok([
            PeerTransportParameters(remembered_parameters),
            InstallWriteKeys(ZeroRtt, keys),
          ])
        }
      }
  }
}

fn client_cipher_suites(
  offer: Option(resumption.ClientOffer),
) -> List(hello.CipherSuite) {
  case offer {
    None -> supported_cipher_suites()
    Some(value) -> {
      let selected = resumption.client_cipher_suite(value)
      [
        selected,
        ..list.filter(supported_cipher_suites(), fn(cipher_suite) {
          cipher_suite != selected
        })
      ]
    }
  }
}

fn version_identifier(version_value: Version) -> Int {
  case version_value {
    version.Version1 -> 1
    version.Version2 -> 0x6b33_43cf
    version.Negotiation -> 0
    version.Unknown(identifier) -> identifier
  }
}

fn handle_client_hello(
  config: ServerConfig,
  resumption_policy: Option(resumption.ServerPolicy),
  bytes: BitArray,
) -> Result(Step(Server), Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) ->
      Ok(Step(ServerAwaitingClientHello(config, bytes, resumption_policy), []))
    Ok(handshake.Complete(message, <<>>)) -> {
      let handshake.Message(message_type, body) = message
      case message_type {
        handshake.ClientHello -> {
          use client_hello <- result.try(
            hello.decode_client(body, hello.default_limits())
            |> map_hello_result,
          )
          accept_client_hello(config, resumption_policy, client_hello, bytes)
        }
        _ -> Error(UnexpectedMessage)
      }
    }
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn accept_client_hello(
  config: ServerConfig,
  resumption_policy: Option(resumption.ServerPolicy),
  client_hello: hello.ClientHello,
  encoded_client_hello: BitArray,
) -> Result(Step(Server), Error) {
  let hello.ClientHello(_, session_id, cipher_suites, extensions) = client_hello
  case session_id {
    <<>> -> {
      use Nil <- result.try(require_client_tls13(extensions))
      use server_name <- result.try(client_server_name(extensions))
      use selected_alpn <- result.try(select_client_alpn(
        extensions,
        config.application_protocols,
      ))
      use Nil <- result.try(require_server_signature(
        extensions,
        config.signature_scheme,
      ))
      use peer_parameters <- result.try(client_transport_parameters(extensions))
      use default_cipher_suite <- result.try(select_cipher_suite(cipher_suites))
      use selection <- result.try(select_server_resumption(
        resumption_policy,
        encoded_client_hello,
        <<>>,
        client_hello,
        server_name,
        selected_alpn,
        config,
      ))
      let cipher_suite =
        selected_resumption_cipher(selection, default_cipher_suite)
      use client_public_key <- result.try(offered_client_x25519_key(extensions))
      case client_public_key {
        Some(public_key) ->
          build_server_flight(
            config,
            server_name,
            encoded_client_hello,
            cipher_suite,
            public_key,
            selected_alpn,
            peer_parameters,
            None,
            selection,
          )
        None ->
          issue_hello_retry_request(
            config,
            client_hello,
            encoded_client_hello,
            cipher_suite,
            resumption_policy,
          )
      }
    }
    _ -> Error(InvalidConfiguration)
  }
}

fn issue_hello_retry_request(
  config: ServerConfig,
  client_hello: hello.ClientHello,
  encoded_client_hello: BitArray,
  cipher_suite: hello.CipherSuite,
  resumption_policy: Option(resumption.ServerPolicy),
) -> Result(Step(Server), Error) {
  use supported_version <- result.try(
    extension_value.encode_server_supported_version(extension_value.Tls13)
    |> map_extension_value_result,
  )
  use selected_group <- result.try(
    extension_value.encode_selected_group(extension_value.X25519)
    |> map_extension_value_result,
  )
  let retry =
    hello.HelloRetryRequest(<<>>, cipher_suite, [
      extension.Extension(extension.SupportedVersions, supported_version),
      extension.Extension(extension.KeyShare, selected_group),
    ])
  use body <- result.try(
    hello.encode_server(retry, hello.default_limits()) |> map_hello_result,
  )
  use encoded_retry <- result.try(encode_message(handshake.ServerHello, body))
  let algorithm = cipher_hash(cipher_suite)
  use initial <- result.try(
    transcript.new(algorithm, maximum_transcript_length)
    |> map_transcript_result,
  )
  use after_client <- result.try(
    transcript.append(initial, encoded_client_hello) |> map_transcript_result,
  )
  use retry_transcript <- result.try(
    transcript.replace_for_hello_retry_request(after_client, encoded_retry)
    |> map_transcript_result,
  )
  let context =
    ServerRetryContext(
      config,
      client_hello,
      cipher_suite,
      retry_transcript,
      resumption_policy,
    )
  Ok(
    Step(ServerAwaitingSecondClientHello(context, <<>>), [
      Send(Initial, encoded_retry),
    ]),
  )
}

fn handle_second_client_hello(
  context: ServerRetryContext,
  bytes: BitArray,
) -> Result(Step(Server), Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) ->
      Ok(Step(ServerAwaitingSecondClientHello(context, bytes), []))
    Ok(handshake.Complete(message, <<>>)) -> {
      let handshake.Message(message_type, body) = message
      case message_type {
        handshake.ClientHello -> {
          use client_hello <- result.try(
            hello.decode_client(body, hello.default_limits())
            |> map_hello_result,
          )
          accept_second_client_hello(context, client_hello, bytes)
        }
        _ -> Error(UnexpectedMessage)
      }
    }
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn accept_second_client_hello(
  context: ServerRetryContext,
  client_hello: hello.ClientHello,
  encoded_client_hello: BitArray,
) -> Result(Step(Server), Error) {
  use Nil <- result.try(validate_second_client_hello(
    context.original_client_hello,
    client_hello,
  ))
  let hello.ClientHello(_, session_id, cipher_suites, extensions) = client_hello
  case session_id {
    <<>> -> {
      use Nil <- result.try(require_client_tls13(extensions))
      use server_name <- result.try(client_server_name(extensions))
      use selected_alpn <- result.try(select_client_alpn(
        extensions,
        context.config.application_protocols,
      ))
      use Nil <- result.try(require_server_signature(
        extensions,
        context.config.signature_scheme,
      ))
      use peer_parameters <- result.try(client_transport_parameters(extensions))
      use client_public_key <- result.try(client_x25519_key(extensions))
      use selection <- result.try(select_server_resumption(
        context.resumption_policy,
        encoded_client_hello,
        transcript.bytes(context.retry_transcript),
        client_hello,
        server_name,
        selected_alpn,
        context.config,
      ))
      let selection_cipher =
        selected_resumption_cipher(selection, context.selected_cipher_suite)
      case
        list.contains(cipher_suites, context.selected_cipher_suite)
        && selection_cipher == context.selected_cipher_suite
      {
        False -> Error(InvalidHelloRetryRequest)
        True ->
          build_server_flight(
            context.config,
            server_name,
            encoded_client_hello,
            context.selected_cipher_suite,
            client_public_key,
            selected_alpn,
            peer_parameters,
            Some(context.retry_transcript),
            selection,
          )
      }
    }
    _ -> Error(InvalidHelloRetryRequest)
  }
}

fn validate_second_client_hello(
  original: hello.ClientHello,
  second: hello.ClientHello,
) -> Result(Nil, Error) {
  let hello.ClientHello(
    original_random,
    original_session,
    original_ciphers,
    original_extensions,
  ) = original
  let hello.ClientHello(
    second_random,
    second_session,
    second_ciphers,
    second_extensions,
  ) = second
  let has_forbidden_change =
    list.any(second_extensions, fn(value) {
      value.kind == extension.EarlyData || value.kind == extension.Cookie
    })
  use psk_identities_unchanged <- result.try(psk_identities_equal(
    original_extensions,
    second_extensions,
  ))
  case
    original_random == second_random
    && original_session == second_session
    && original_ciphers == second_ciphers
    && without_retry_mutable_extensions(original_extensions)
    == without_retry_mutable_extensions(second_extensions)
    && psk_identities_unchanged
    && !has_forbidden_change
  {
    True -> Ok(Nil)
    False -> Error(InvalidHelloRetryRequest)
  }
}

fn without_retry_mutable_extensions(
  extensions: List(extension.Extension),
) -> List(extension.Extension) {
  list.filter(extensions, fn(value) {
    case value.kind {
      extension.KeyShare
      | extension.Cookie
      | extension.EarlyData
      | extension.PreSharedKey -> False
      _ -> True
    }
  })
}

fn psk_identities_equal(
  original: List(extension.Extension),
  second: List(extension.Extension),
) -> Result(Bool, Error) {
  case
    optional_extension(original, extension.PreSharedKey),
    optional_extension(second, extension.PreSharedKey)
  {
    None, None -> Ok(True)
    Some(_), None | None, Some(_) -> Ok(False)
    Some(original_data), Some(second_data) -> {
      use original_offer <- result.try(
        pre_shared_key.decode_offered(original_data)
        |> map_pre_shared_key_result,
      )
      use second_offer <- result.try(
        pre_shared_key.decode_offered(second_data) |> map_pre_shared_key_result,
      )
      let pre_shared_key.Offered(original_identities, _) = original_offer
      let pre_shared_key.Offered(second_identities, _) = second_offer
      Ok(
        psk_identity_bytes(original_identities)
        == psk_identity_bytes(second_identities),
      )
    }
  }
}

fn psk_identity_bytes(
  identities: List(pre_shared_key.Identity),
) -> List(BitArray) {
  list.map(identities, fn(identity) {
    let pre_shared_key.Identity(bytes, _) = identity
    bytes
  })
}

fn select_server_resumption(
  policy: Option(resumption.ServerPolicy),
  encoded_client_hello: BitArray,
  transcript_prefix: BitArray,
  client_hello: hello.ClientHello,
  server_name: String,
  selected_alpn: BitArray,
  config: ServerConfig,
) -> Result(Option(resumption.Selected), Error) {
  case policy {
    None -> Ok(None)
    Some(value) -> {
      use encoded_parameters <- result.try(
        transport_parameter.encode_all(
          config.transport_parameters,
          transport_parameter.Server,
        )
        |> map_transport_parameter_result,
      )
      use decision <- result.try(
        resumption.select(
          policy: value,
          encoded_client_hello:,
          transcript_prefix:,
          client_hello:,
          expected_server_name: server_name,
          expected_alpn: selected_alpn,
          expected_quic_version: version_identifier(config.version),
          expected_transport_parameters: encoded_parameters,
        )
        |> map_resumption_result,
      )
      case decision {
        resumption.FullHandshake(_) -> Ok(None)
        resumption.Resumed(selection) -> Ok(Some(selection))
      }
    }
  }
}

fn selected_resumption_cipher(
  selection: Option(resumption.Selected),
  fallback: hello.CipherSuite,
) -> hello.CipherSuite {
  case selection {
    None -> fallback
    Some(selected) -> {
      let session_ticket.Claims(cipher_suite: cipher_suite, ..) =
        selected.claims
      cipher_suite
    }
  }
}

fn selected_pre_shared_key(
  selection: Option(resumption.Selected),
) -> Option(BitArray) {
  case selection {
    None -> None
    Some(selected) -> {
      let session_ticket.Claims(pre_shared_key: psk, ..) = selected.claims
      Some(psk)
    }
  }
}

fn selection_early_data_accepted(
  selection: Option(resumption.Selected),
) -> Bool {
  case selection {
    Some(selected) -> selected.early_data_accepted
    None -> False
  }
}

fn server_hello_psk_extension(
  selection: Option(resumption.Selected),
) -> Result(List(extension.Extension), Error) {
  case selection {
    None -> Ok([])
    Some(selected) -> {
      use encoded <- result.try(
        pre_shared_key.encode_selected_identity(selected.identity_index)
        |> map_pre_shared_key_result,
      )
      Ok([extension.Extension(extension.PreSharedKey, encoded)])
    }
  }
}

fn build_server_flight(
  config: ServerConfig,
  server_name: String,
  encoded_client_hello: BitArray,
  cipher_suite: hello.CipherSuite,
  client_public_key: BitArray,
  selected_alpn: BitArray,
  peer_parameters: List(transport_parameter.Parameter),
  retry_transcript: Option(transcript.Transcript),
  resumption_selection: Option(resumption.Selected),
) -> Result(Step(Server), Error) {
  use key_pair <- result.try(
    key_exchange.generate_x25519() |> map_key_exchange_result,
  )
  use random <- result.try(crypto.secure_random(32) |> map_crypto_result)
  use server_hello <- result.try(encode_server_hello(
    random,
    cipher_suite,
    key_exchange.public_key(key_pair),
    resumption_selection,
  ))
  let algorithm = cipher_hash(cipher_suite)
  use hello_transcript <- result.try(case retry_transcript {
    None -> new_hello_transcript(algorithm, encoded_client_hello, server_hello)
    Some(current) -> {
      use after_client <- result.try(
        transcript.append(current, encoded_client_hello)
        |> map_transcript_result,
      )
      transcript.append(after_client, server_hello) |> map_transcript_result
    }
  })
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
      selected_pre_shared_key(resumption_selection),
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
    resumption_selection,
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
    encoded_client_hello,
    resumption_selection,
  ))
  let context =
    ServerHandshakeContext(
      config:,
      server_name:,
      selected_alpn:,
      version: config.version,
      cipher_suite:,
      hash_algorithm: algorithm,
      transcript: flight_transcript,
      secrets: secrets,
      resumption_selection:,
    )
  Ok(Step(ServerAwaitingClientFinished(context, <<>>), actions))
}

fn encode_server_hello(
  random: BitArray,
  cipher_suite: hello.CipherSuite,
  public_key: BitArray,
  selection: Option(resumption.Selected),
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
  use psk_extensions <- result.try(server_hello_psk_extension(selection))
  let body =
    hello.ServerHello(
      random: random,
      legacy_session_id_echo: <<>>,
      cipher_suite: cipher_suite,
      extensions: list.append(
        [
          extension.Extension(extension.SupportedVersions, supported_version),
          extension.Extension(extension.KeyShare, key_share),
        ],
        psk_extensions,
      ),
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
  selection: Option(resumption.Selected),
) -> Result(#(BitArray, transcript.Transcript), Error) {
  use #(encrypted_extensions, after_extensions) <- result.try(
    encode_server_encrypted_extensions(
      config,
      selected_alpn,
      initial_transcript,
      selection_early_data_accepted(selection),
    ),
  )
  case selection {
    Some(_) -> {
      use #(finished, after_finished) <- result.try(encode_server_finished(
        algorithm,
        secrets.server_handshake_traffic_secret,
        after_extensions,
      ))
      Ok(#(<<encrypted_extensions:bits, finished:bits>>, after_finished))
    }
    None -> {
      use #(certificate, after_certificate) <- result.try(
        encode_server_certificate(config.certificate_chain, after_extensions),
      )
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
  }
}

fn encode_server_encrypted_extensions(
  config: ServerConfig,
  selected_alpn: BitArray,
  current: transcript.Transcript,
  accept_early_data: Bool,
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
  let early_data = case accept_early_data {
    True -> [extension.Extension(extension.EarlyData, <<>>)]
    False -> []
  }
  use body <- result.try(
    message_body.encode_encrypted_extensions(
      list.append(
        [
          extension.Extension(
            extension.ApplicationLayerProtocolNegotiation,
            alpn,
          ),
          extension.Extension(extension.QuicTransportParameters, parameters),
        ],
        early_data,
      ),
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
  encoded_client_hello: BitArray,
  selection: Option(resumption.Selected),
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
  use early_actions <- result.try(server_early_key_actions(
    version_value,
    encoded_client_hello,
    selection,
  ))
  Ok(list.append(
    [
      Send(Initial, server_hello),
      InstallWriteKeys(Handshake, handshake_write),
      InstallReadKeys(Handshake, handshake_read),
      Send(Handshake, flight),
      InstallWriteKeys(OneRtt, application_write),
      InstallReadKeys(OneRtt, application_read),
      PeerTransportParameters(peer_parameters),
    ],
    early_actions,
  ))
}

fn server_early_key_actions(
  version_value: Version,
  encoded_client_hello: BitArray,
  selection: Option(resumption.Selected),
) -> Result(List(Action), Error) {
  case selection {
    Some(selected) if selected.early_data_accepted -> {
      let session_ticket.Claims(
        pre_shared_key: psk,
        algorithm: algorithm,
        cipher_suite: cipher_suite,
        ..,
      ) = selected.claims
      use early_secret <- result.try(
        key_schedule.derive_early_secret(algorithm, psk) |> map_crypto_result,
      )
      use hello_hash <- result.try(
        crypto.hash(algorithm, encoded_client_hello) |> map_crypto_result,
      )
      use traffic_secret <- result.try(
        key_schedule.derive_client_early_traffic_secret(
          algorithm,
          early_secret,
          hello_hash,
        )
        |> map_crypto_result,
      )
      use keys <- result.try(derive_traffic_keys(
        version_value,
        cipher_suite,
        traffic_secret,
      ))
      Ok([InstallReadKeys(ZeroRtt, keys), EarlyDataAccepted])
    }
    Some(selected) if selected.early_data_offered -> Ok([EarlyDataRejected])
    _ -> Ok([])
  }
}

fn handle_server_hello(
  client: Client,
  bytes: BitArray,
) -> Result(Step(Client), Error) {
  case client {
    ClientAwaitingServerHello(config, key_pair, client_hello, offer, pending) ->
      decode_server_hello(config, key_pair, client_hello, offer, <<
        pending:bits,
        bytes:bits,
      >>)
    ClientAwaitingServerHelloAfterRetry(
      config,
      key_pair,
      selected_cipher_suite,
      retry_transcript,
      client_hello,
      offer,
      pending,
    ) ->
      decode_server_hello_after_retry(
        config,
        key_pair,
        selected_cipher_suite,
        retry_transcript,
        client_hello,
        offer,
        <<pending:bits, bytes:bits>>,
      )
    _ -> Error(UnexpectedMessage)
  }
}

fn decode_server_hello(
  config: ClientConfig,
  key_pair: Option(key_exchange.KeyPair),
  client_hello: BitArray,
  offer: Option(resumption.ClientOffer),
  bytes: BitArray,
) -> Result(Step(Client), Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) ->
      Ok(
        Step(
          ClientAwaitingServerHello(
            config,
            key_pair,
            client_hello,
            offer,
            bytes,
          ),
          [],
        ),
      )
    Ok(handshake.Complete(message, <<>>)) -> {
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
            offer,
            bytes,
            server_hello,
          )
        }
        _ -> Error(UnexpectedMessage)
      }
    }
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn accept_server_hello(
  config: ClientConfig,
  key_pair: Option(key_exchange.KeyPair),
  client_hello: BitArray,
  offer: Option(resumption.ClientOffer),
  encoded_server_hello: BitArray,
  server_hello: hello.ServerHello,
) -> Result(Step(Client), Error) {
  case server_hello {
    hello.HelloRetryRequest(session_id, cipher_suite, extensions) ->
      accept_hello_retry_request(
        config,
        key_pair,
        client_hello,
        encoded_server_hello,
        session_id,
        cipher_suite,
        extensions,
      )
    hello.ServerHello(_, session_id, cipher_suite, extensions) ->
      case session_id, key_pair {
        <<>>, Some(value) ->
          establish_client_handshake(
            config,
            value,
            client_hello,
            encoded_server_hello,
            cipher_suite,
            extensions,
            offer,
          )
        <<>>, None -> Error(UnsupportedKeyShare)
        _, _ -> Error(InvalidConfiguration)
      }
  }
}

fn accept_hello_retry_request(
  config: ClientConfig,
  key_pair: Option(key_exchange.KeyPair),
  encoded_client_hello: BitArray,
  encoded_retry: BitArray,
  session_id: BitArray,
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
) -> Result(Step(Client), Error) {
  case key_pair {
    Some(_) -> Error(InvalidHelloRetryRequest)
    None ->
      case session_id {
        <<>> ->
          build_second_client_hello(
            config,
            encoded_client_hello,
            encoded_retry,
            cipher_suite,
            extensions,
          )
        _ -> Error(InvalidHelloRetryRequest)
      }
  }
}

fn build_second_client_hello(
  config: ClientConfig,
  encoded_client_hello: BitArray,
  encoded_retry: BitArray,
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
) -> Result(Step(Client), Error) {
  use algorithm <- result.try(validate_hello_retry_request(
    encoded_client_hello,
    cipher_suite,
    extensions,
  ))
  use original <- result.try(decode_client_hello_message(encoded_client_hello))
  use retry_key_pair <- result.try(
    key_exchange.generate_x25519() |> map_key_exchange_result,
  )
  use share <- result.try(encode_client_key_share(Some(retry_key_pair)))
  use retry_extensions <- result.try(second_client_extensions(
    original.extensions,
    extensions,
    share,
  ))
  let second_hello = hello.ClientHello(..original, extensions: retry_extensions)
  use second_body <- result.try(
    hello.encode_client(second_hello, hello.default_limits())
    |> map_hello_result,
  )
  use encoded_second <- result.try(encode_message(
    handshake.ClientHello,
    second_body,
  ))
  use initial <- result.try(
    transcript.new(algorithm, maximum_transcript_length)
    |> map_transcript_result,
  )
  use after_first <- result.try(
    transcript.append(initial, encoded_client_hello) |> map_transcript_result,
  )
  use retry_transcript <- result.try(
    transcript.replace_for_hello_retry_request(after_first, encoded_retry)
    |> map_transcript_result,
  )
  Ok(
    Step(
      ClientAwaitingServerHelloAfterRetry(
        config,
        retry_key_pair,
        cipher_suite,
        retry_transcript,
        encoded_second,
        None,
        <<>>,
      ),
      [Send(Initial, encoded_second)],
    ),
  )
}

fn validate_hello_retry_request(
  encoded_client_hello: BitArray,
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
) -> Result(crypto.HashAlgorithm, Error) {
  use original <- result.try(decode_client_hello_message(encoded_client_hello))
  use algorithm <- result.try(require_supported_cipher(cipher_suite))
  use Nil <- result.try(require_server_tls13(extensions))
  use selected_data <- result.try(require_extension(
    extensions,
    extension.KeyShare,
  ))
  use selected_group <- result.try(
    extension_value.decode_selected_group(selected_data)
    |> map_extension_value_result,
  )
  use Nil <- result.try(validate_retry_extension_set(extensions))
  use _ <- result.try(retry_cookie(extensions))
  use offered_share_data <- result.try(require_extension(
    original.extensions,
    extension.KeyShare,
  ))
  use offered_shares <- result.try(
    extension_value.decode_client_key_shares(offered_share_data)
    |> map_extension_value_result,
  )
  case
    list.contains(original.cipher_suites, cipher_suite)
    && selected_group == extension_value.X25519
    && !has_x25519_share(offered_shares)
  {
    True -> Ok(algorithm)
    False -> Error(InvalidHelloRetryRequest)
  }
}

fn validate_retry_extension_set(
  extensions: List(extension.Extension),
) -> Result(Nil, Error) {
  let valid =
    list.all(extensions, fn(value) {
      case value.kind {
        extension.SupportedVersions | extension.KeyShare | extension.Cookie ->
          True
        _ -> False
      }
    })
  case valid {
    True -> Ok(Nil)
    False -> Error(InvalidHelloRetryRequest)
  }
}

fn retry_cookie(
  extensions: List(extension.Extension),
) -> Result(Option(BitArray), Error) {
  case extensions {
    [] -> Ok(None)
    [extension.Extension(extension.Cookie, data), ..] -> {
      use _ <- result.try(
        extension_value.decode_cookie(data) |> map_extension_value_result,
      )
      Ok(Some(data))
    }
    [_, ..rest] -> retry_cookie(rest)
  }
}

fn second_client_extensions(
  original: List(extension.Extension),
  retry_extensions: List(extension.Extension),
  key_share: BitArray,
) -> Result(List(extension.Extension), Error) {
  use cookie <- result.try(retry_cookie(retry_extensions))
  let unchanged =
    list.filter(original, fn(value) {
      case value.kind {
        extension.KeyShare | extension.Cookie | extension.EarlyData -> False
        _ -> True
      }
    })
  let additions = case cookie {
    None -> [extension.Extension(extension.KeyShare, key_share)]
    Some(data) -> [
      extension.Extension(extension.Cookie, data),
      extension.Extension(extension.KeyShare, key_share),
    ]
  }
  Ok(list.append(unchanged, additions))
}

fn decode_client_hello_message(
  encoded: BitArray,
) -> Result(hello.ClientHello, Error) {
  case handshake.decode_next(encoded, handshake.default_limits()) {
    Ok(handshake.Complete(handshake.Message(handshake.ClientHello, body), <<>>)) ->
      hello.decode_client(body, hello.default_limits()) |> map_hello_result
    Ok(_) -> Error(InvalidHelloRetryRequest)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn has_x25519_share(shares: List(extension_value.KeyShare)) -> Bool {
  list.any(shares, fn(share) {
    case share {
      extension_value.KeyShare(extension_value.X25519, _) -> True
      _ -> False
    }
  })
}

fn decode_server_hello_after_retry(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
  selected_cipher_suite: hello.CipherSuite,
  retry_transcript: transcript.Transcript,
  client_hello: BitArray,
  offer: Option(resumption.ClientOffer),
  bytes: BitArray,
) -> Result(Step(Client), Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) ->
      Ok(
        Step(
          ClientAwaitingServerHelloAfterRetry(
            config,
            key_pair,
            selected_cipher_suite,
            retry_transcript,
            client_hello,
            offer,
            bytes,
          ),
          [],
        ),
      )
    Ok(handshake.Complete(message, <<>>)) -> {
      let handshake.Message(message_type, body) = message
      case message_type {
        handshake.ServerHello -> {
          use server_hello <- result.try(
            hello.decode_server(body, hello.default_limits())
            |> map_hello_result,
          )
          accept_server_hello_after_retry(
            config,
            key_pair,
            selected_cipher_suite,
            retry_transcript,
            client_hello,
            offer,
            bytes,
            server_hello,
          )
        }
        _ -> Error(UnexpectedMessage)
      }
    }
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
  }
}

fn accept_server_hello_after_retry(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
  selected_cipher_suite: hello.CipherSuite,
  retry_transcript: transcript.Transcript,
  client_hello: BitArray,
  offer: Option(resumption.ClientOffer),
  encoded_server_hello: BitArray,
  server_hello: hello.ServerHello,
) -> Result(Step(Client), Error) {
  case server_hello {
    hello.HelloRetryRequest(..) -> Error(InvalidHelloRetryRequest)
    hello.ServerHello(_, session_id, cipher_suite, extensions) ->
      case session_id == <<>> && cipher_suite == selected_cipher_suite {
        False -> Error(InvalidHelloRetryRequest)
        True -> {
          use after_client <- result.try(
            transcript.append(retry_transcript, client_hello)
            |> map_transcript_result,
          )
          use current <- result.try(
            transcript.append(after_client, encoded_server_hello)
            |> map_transcript_result,
          )
          establish_client_handshake_with_transcript(
            config,
            key_pair,
            cipher_suite,
            extensions,
            current,
            offer,
          )
        }
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
  offer: Option(resumption.ClientOffer),
) -> Result(Step(Client), Error) {
  use algorithm <- result.try(require_supported_cipher(cipher_suite))
  use current <- result.try(new_hello_transcript(
    algorithm,
    client_hello,
    server_hello,
  ))
  establish_client_handshake_with_transcript(
    config,
    key_pair,
    cipher_suite,
    extensions,
    current,
    offer,
  )
}

fn establish_client_handshake_with_transcript(
  config: ClientConfig,
  key_pair: key_exchange.KeyPair,
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
  current: transcript.Transcript,
  offer: Option(resumption.ClientOffer),
) -> Result(Step(Client), Error) {
  use Nil <- result.try(require_server_tls13(extensions))
  use public_key <- result.try(server_x25519_key(extensions))
  use algorithm <- result.try(require_supported_cipher(cipher_suite))
  use selected_psk <- result.try(client_selected_pre_shared_key(
    offer,
    cipher_suite,
    extensions,
  ))
  use shared_secret <- result.try(
    key_exchange.shared_secret(key_pair, public_key) |> map_key_exchange_result,
  )
  use hello_hash <- result.try(
    transcript.hash(current) |> map_transcript_result,
  )
  use secrets <- result.try(
    key_schedule.derive_handshake_secrets(
      algorithm,
      selected_psk,
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
      resumption_offer: offer,
      resumed: selected_psk != None,
      early_data_accepted: False,
      selected_alpn: None,
      peer_transport_parameters: None,
      pending_crypto: <<>>,
    )
  Ok(
    Step(ClientAwaitingEncryptedExtensions(context), [
      InstallWriteKeys(Handshake, write_keys),
      InstallReadKeys(Handshake, read_keys),
    ]),
  )
}

fn prepare_client_flight(
  client: Client,
  bytes: BitArray,
) -> Result(Step(Client), Error) {
  let #(cleared, pending) = take_client_pending(client)
  process_client_flight(cleared, <<pending:bits, bytes:bits>>, [])
}

fn take_client_pending(client: Client) -> #(Client, BitArray) {
  case client {
    ClientAwaitingEncryptedExtensions(context) -> #(
      ClientAwaitingEncryptedExtensions(clear_pending(context)),
      context.pending_crypto,
    )
    ClientAwaitingCertificate(context) -> #(
      ClientAwaitingCertificate(clear_pending(context)),
      context.pending_crypto,
    )
    ClientAwaitingCertificateVerify(context, peer) -> #(
      ClientAwaitingCertificateVerify(clear_pending(context), peer),
      context.pending_crypto,
    )
    ClientAwaitingFinished(context) -> #(
      ClientAwaitingFinished(clear_pending(context)),
      context.pending_crypto,
    )
    _ -> #(client, <<>>)
  }
}

fn set_client_pending(client: Client, pending: BitArray) -> Client {
  case client {
    ClientAwaitingEncryptedExtensions(context) ->
      ClientAwaitingEncryptedExtensions(set_pending(context, pending))
    ClientAwaitingCertificate(context) ->
      ClientAwaitingCertificate(set_pending(context, pending))
    ClientAwaitingCertificateVerify(context, peer) ->
      ClientAwaitingCertificateVerify(set_pending(context, pending), peer)
    ClientAwaitingFinished(context) ->
      ClientAwaitingFinished(set_pending(context, pending))
    _ -> client
  }
}

fn clear_pending(context: ClientHandshakeContext) -> ClientHandshakeContext {
  ClientHandshakeContext(..context, pending_crypto: <<>>)
}

fn set_pending(
  context: ClientHandshakeContext,
  pending: BitArray,
) -> ClientHandshakeContext {
  ClientHandshakeContext(..context, pending_crypto: pending)
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
        Ok(handshake.NeedMore) ->
          Ok(Step(set_client_pending(client, bytes), actions))
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
  use selected <- result.try(selected_server_alpn(
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
  use #(early_data_accepted, early_actions) <- result.try(
    client_early_data_outcome(context, extensions),
  )
  let next_context =
    ClientHandshakeContext(
      ..context,
      transcript: next_transcript,
      early_data_accepted:,
      selected_alpn: Some(selected),
      peer_transport_parameters: Some(parameters),
    )
  let next = case context.resumed {
    True -> ClientAwaitingFinished(next_context)
    False -> ClientAwaitingCertificate(next_context)
  }
  Ok(Step(next, [PeerTransportParameters(parameters), ..early_actions]))
}

fn client_early_data_outcome(
  context: ClientHandshakeContext,
  extensions: List(extension.Extension),
) -> Result(#(Bool, List(Action)), Error) {
  use accepted <- result.try(server_accepted_early_data(extensions))
  case context.resumption_offer {
    None ->
      case accepted {
        True -> Error(InvalidConfiguration)
        False -> Ok(#(False, []))
      }
    Some(offer) -> {
      let requested = resumption.client_early_data_requested(offer)
      case requested, context.resumed, accepted {
        False, _, False -> Ok(#(False, []))
        False, _, True | True, False, True -> Error(InvalidConfiguration)
        True, True, True -> Ok(#(True, [EarlyDataAccepted]))
        True, _, False ->
          Ok(#(False, [DiscardKeys(ZeroRtt), EarlyDataRejected]))
      }
    }
  }
}

fn server_accepted_early_data(
  extensions: List(extension.Extension),
) -> Result(Bool, Error) {
  case optional_extension(extensions, extension.EarlyData) {
    None -> Ok(False)
    Some(<<>>) -> Ok(True)
    Some(_) -> Error(InvalidConfiguration)
  }
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
  use connected_context <- result.try(client_connected_context(
    context,
    resumption_master_secret,
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
  let early_discard = case context.early_data_accepted {
    True -> [DiscardKeys(ZeroRtt)]
    False -> []
  }
  Ok(Step(
    ClientConnected(connected_context),
    list.append(
      [
        InstallWriteKeys(OneRtt, write_keys),
        InstallReadKeys(OneRtt, read_keys),
        DiscardKeys(Initial),
        Send(Handshake, client_finished),
        HandshakeComplete,
      ],
      early_discard,
    ),
  ))
}

fn client_connected_context(
  context: ClientHandshakeContext,
  resumption_master_secret: BitArray,
) -> Result(ClientConnectedContext, Error) {
  case context.selected_alpn, context.peer_transport_parameters {
    Some(selected_alpn), Some(peer_transport_parameters) ->
      Ok(ClientConnectedContext(
        config: context.config,
        cipher_suite: context.cipher_suite,
        hash_algorithm: context.hash_algorithm,
        resumption_master_secret:,
        selected_alpn:,
        peer_transport_parameters:,
        pending_crypto: <<>>,
        handshake_confirmed: False,
      ))
    _, _ -> Error(InvalidConfiguration)
  }
}

fn handle_client_post_handshake(
  context: ClientConnectedContext,
  bytes: BitArray,
  now_milliseconds: Int,
) -> Result(Step(Client), Error) {
  process_client_post_handshake(
    ClientConnectedContext(..context, pending_crypto: <<>>),
    <<context.pending_crypto:bits, bytes:bits>>,
    [],
    now_milliseconds,
  )
}

fn process_client_post_handshake(
  context: ClientConnectedContext,
  bytes: BitArray,
  actions: List(Action),
  now_milliseconds: Int,
) -> Result(Step(Client), Error) {
  case bytes {
    <<>> -> Ok(Step(ClientConnected(context), actions))
    _ ->
      case handshake.decode_next(bytes, handshake.default_limits()) {
        Ok(handshake.NeedMore) ->
          Ok(Step(
            ClientConnected(
              ClientConnectedContext(..context, pending_crypto: bytes),
            ),
            actions,
          ))
        Ok(handshake.Complete(message, rest)) -> {
          use action <- result.try(client_post_handshake_message(
            context,
            message,
            now_milliseconds,
          ))
          process_client_post_handshake(
            context,
            rest,
            list.append(actions, [action]),
            now_milliseconds,
          )
        }
        Error(error) -> Error(HandshakeFailure(error))
      }
  }
}

fn client_post_handshake_message(
  context: ClientConnectedContext,
  message: handshake.Message,
  now_milliseconds: Int,
) -> Result(Action, Error) {
  case message {
    handshake.Message(handshake.NewSessionTicket, body) -> {
      use ticket <- result.try(
        message_body.decode_new_session_ticket(
          body,
          message_body.default_limits(),
        )
        |> map_message_body_result,
      )
      use remembered_parameters <- result.try(
        transport_parameter.encode_all(
          context.peer_transport_parameters,
          transport_parameter.Server,
        )
        |> map_transport_parameter_result,
      )
      use stored <- result.try(
        session_ticket.store(
          new_ticket: ticket,
          received_at_milliseconds: now_milliseconds,
          resumption_master_secret: context.resumption_master_secret,
          algorithm: context.hash_algorithm,
          cipher_suite: context.cipher_suite,
          server_name: context.config.hostname,
          alpn: context.selected_alpn,
          quic_version: version_identifier(context.config.version),
          remembered_transport_parameters: remembered_parameters,
        )
        |> map_session_ticket_result,
      )
      Ok(StoreSessionTicket(stored))
    }
    _ -> Error(UnexpectedMessage)
  }
}

fn handle_client_finished(
  context: ServerHandshakeContext,
  bytes: BitArray,
) -> Result(Step(Server), Error) {
  case handshake.decode_next(bytes, handshake.default_limits()) {
    Ok(handshake.NeedMore) ->
      Ok(Step(ServerAwaitingClientFinished(context, bytes), []))
    Ok(handshake.Complete(message, <<>>)) -> {
      let handshake.Message(message_type, body) = message
      case message_type {
        handshake.Finished -> verify_client_finished(context, body)
        _ -> Error(UnexpectedMessage)
      }
    }
    Ok(handshake.Complete(_, _)) -> Error(UnexpectedMessage)
    Error(error) -> Error(HandshakeFailure(error))
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
  let early_discard = case context.resumption_selection {
    Some(selected) if selected.early_data_accepted -> [DiscardKeys(ZeroRtt)]
    _ -> []
  }
  let replay_cache = case context.resumption_selection {
    Some(selected) -> Some(selected.replay_cache)
    None -> None
  }
  let connected_context =
    ServerConnectedContext(
      config: context.config,
      server_name: context.server_name,
      selected_alpn: context.selected_alpn,
      hash_algorithm: context.hash_algorithm,
      cipher_suite: context.cipher_suite,
      resumption_master_secret:,
      replay_cache:,
    )
  Ok(Step(
    ServerConnected(connected_context),
    list.append(
      [
        DiscardKeys(Initial),
        DiscardKeys(Handshake),
        HandshakeComplete,
      ],
      early_discard,
    ),
  ))
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

fn client_server_name(
  extensions: List(extension.Extension),
) -> Result(String, Error) {
  use encoded <- result.try(require_extension(extensions, extension.ServerName))
  extension_value.decode_server_name(encoded) |> map_extension_value_result
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
  use offered <- result.try(offered_client_x25519_key(extensions))
  case offered {
    Some(key) -> Ok(key)
    None -> Error(UnsupportedKeyShare)
  }
}

fn offered_client_x25519_key(
  extensions: List(extension.Extension),
) -> Result(Option(BitArray), Error) {
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
      Ok(find_x25519_share(shares))
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

fn optional_extension(
  extensions: List(extension.Extension),
  expected: extension.Kind,
) -> Option(BitArray) {
  case extensions {
    [] -> None
    [extension.Extension(kind, data), ..rest] ->
      case kind == expected {
        True -> Some(data)
        False -> optional_extension(rest, expected)
      }
  }
}

fn client_selected_pre_shared_key(
  offer: Option(resumption.ClientOffer),
  cipher_suite: hello.CipherSuite,
  extensions: List(extension.Extension),
) -> Result(Option(BitArray), Error) {
  case offer, optional_extension(extensions, extension.PreSharedKey) {
    None, None -> Ok(None)
    None, Some(_) -> Error(InvalidConfiguration)
    Some(_), None -> Ok(None)
    Some(value), Some(encoded_index) -> {
      use index <- result.try(
        pre_shared_key.decode_selected_identity(encoded_index)
        |> map_pre_shared_key_result,
      )
      case
        index == 0
        && cipher_suite == resumption.client_cipher_suite(value)
        && cipher_hash(cipher_suite) == resumption.client_hash_algorithm(value)
      {
        True -> Ok(Some(resumption.client_pre_shared_key(value)))
        False -> Error(InvalidConfiguration)
      }
    }
  }
}

fn find_x25519_share(
  shares: List(extension_value.KeyShare),
) -> Option(BitArray) {
  case shares {
    [] -> None
    [extension_value.KeyShare(extension_value.X25519, key), ..] -> Some(key)
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

fn map_pre_shared_key_result(
  value: Result(output, pre_shared_key.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(ResumptionFailure(resumption.PskFailure(error)))
  }
}

fn map_resumption_result(
  value: Result(output, resumption.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(ResumptionFailure(error))
  }
}

fn map_session_ticket_result(
  value: Result(output, session_ticket.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(SessionTicketFailure(error))
  }
}
