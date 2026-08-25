//// TLS 1.3 PSK offer, selection, binder, and QUIC early-data coordination.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/crypto
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/extension
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/pre_shared_key
import gleam_quic/internal/tls/replay_guard
import gleam_quic/internal/tls/session_ticket
import gleam_quic/transport_parameter

/// Prepared client state for one origin-bound resumption attempt.
pub opaque type ClientOffer {
  ClientOffer(
    ticket: session_ticket.ClientTicket,
    placeholder: pre_shared_key.Offered,
    encoded_extensions: List(extension.Extension),
    request_early_data: Bool,
  )
}

/// Server policy and replay state for one ClientHello evaluation.
pub opaque type ServerPolicy {
  ServerPolicy(
    ticket_keys: List(BitArray),
    now_milliseconds: Int,
    ticket_age_tolerance_milliseconds: Int,
    replay_cache: anti_replay.Cache,
    permit_early_data: Bool,
    external_replay_guard: Option(replay_guard.Guard),
  )
}

/// One authenticated PSK selection and its independent early-data outcome.
pub type Selected {
  Selected(
    identity_index: Int,
    claims: session_ticket.Claims,
    early_data_offered: Bool,
    early_data_accepted: Bool,
    replay_cache: anti_replay.Cache,
  )
}

/// Resumption falls back to a certificate handshake when no identity opens.
pub type Decision {
  FullHandshake(anti_replay.Cache)
  Resumed(Selected)
}

/// A malformed offer, recognized-ticket binder failure, or policy failure.
pub type Error {
  InvalidPolicy
  InvalidClientTicket
  EarlyDataNotPermitted
  MissingPskModes
  InvalidEarlyData
  InvalidBinder
  NonByteAligned
  PskFailure(pre_shared_key.Error)
  TicketFailure(session_ticket.Error)
  ReplayFailure(anti_replay.Error)
}

/// Prepare PSK extensions with a fixed-length binder placeholder.
pub fn client_offer(
  ticket ticket: session_ticket.ClientTicket,
  now_milliseconds now_milliseconds: Int,
  request_early_data request_early_data: Bool,
) -> Result(ClientOffer, Error) {
  let session_ticket.ClientTicket(
    identity: identity,
    server_name: server_name,
    alpn: alpn,
    quic_version: quic_version,
    algorithm: algorithm,
    permit_early_data: permit_early_data,
    ..,
  ) = ticket
  case
    session_ticket.is_usable(
      ticket,
      now_milliseconds,
      server_name,
      alpn,
      quic_version,
    ),
    request_early_data && !permit_early_data
  {
    False, _ -> Error(InvalidClientTicket)
    _, True -> Error(EarlyDataNotPermitted)
    True, False -> {
      use age <- result.try(
        session_ticket.obfuscated_ticket_age(ticket, now_milliseconds)
        |> map_ticket_result,
      )
      let placeholder =
        pre_shared_key.Offered(
          identities: [pre_shared_key.Identity(identity, age)],
          binders: [<<0:size(crypto.hash_length(algorithm) * 8)>>],
        )
      use encoded_offer <- result.try(
        pre_shared_key.encode_offered(placeholder) |> map_psk_result,
      )
      use modes <- result.try(
        pre_shared_key.encode_modes([pre_shared_key.PskDheKe])
        |> map_psk_result,
      )
      let early = case request_early_data {
        True -> [extension.Extension(extension.EarlyData, <<>>)]
        False -> []
      }
      let encoded_extensions =
        list.append(
          [extension.Extension(extension.PskKeyExchangeModes, modes)],
          list.append(early, [
            extension.Extension(extension.PreSharedKey, encoded_offer),
          ]),
        )
      Ok(ClientOffer(
        ticket:,
        placeholder:,
        encoded_extensions:,
        request_early_data:,
      ))
    }
  }
}

/// Return the prepared extensions; callers append them last in ClientHello.
pub fn client_extensions(
  offer offer: ClientOffer,
) -> List(extension.Extension) {
  offer.encoded_extensions
}

/// Replace the final placeholder binder using the exact retry-aware prefix.
pub fn seal_client_hello(
  offer offer: ClientOffer,
  encoded_placeholder_client_hello encoded_placeholder_client_hello: BitArray,
  transcript_prefix transcript_prefix: BitArray,
) -> Result(BitArray, Error) {
  case bit_array.bit_size(transcript_prefix) % 8 == 0 {
    False -> Error(NonByteAligned)
    True -> {
      use truncated <- result.try(
        pre_shared_key.binder_transcript(
          encoded_placeholder_client_hello,
          offer.placeholder,
        )
        |> map_psk_result,
      )
      let session_ticket.ClientTicket(
        pre_shared_key: psk,
        algorithm: algorithm,
        ..,
      ) = offer.ticket
      use binder <- result.try(
        pre_shared_key.compute_binder(
          algorithm: algorithm,
          pre_shared_key: psk,
          client_hello_truncated: <<transcript_prefix:bits, truncated:bits>>,
          external: False,
        )
        |> map_psk_result,
      )
      let binder_length = bit_array.byte_size(binder)
      let vector_length = binder_length + 1
      Ok(<<
        truncated:bits,
        vector_length:size(16),
        binder_length,
        binder:bits,
      >>)
    }
  }
}

/// Construct a bounded server policy for one handshake time snapshot.
pub fn server_policy(
  ticket_key ticket_key: BitArray,
  now_milliseconds now_milliseconds: Int,
  ticket_age_tolerance_milliseconds ticket_age_tolerance_milliseconds: Int,
  replay_cache replay_cache: anti_replay.Cache,
) -> Result(ServerPolicy, Error) {
  server_policy_with_keys(
    ticket_keys: [ticket_key],
    now_milliseconds: now_milliseconds,
    ticket_age_tolerance_milliseconds: ticket_age_tolerance_milliseconds,
    replay_cache: replay_cache,
  )
}

/// Construct a policy accepting the current and one previous ticket key.
pub fn server_policy_with_keys(
  ticket_keys ticket_keys: List(BitArray),
  now_milliseconds now_milliseconds: Int,
  ticket_age_tolerance_milliseconds ticket_age_tolerance_milliseconds: Int,
  replay_cache replay_cache: anti_replay.Cache,
) -> Result(ServerPolicy, Error) {
  case
    valid_ticket_keys(ticket_keys)
    && now_milliseconds >= 0
    && ticket_age_tolerance_milliseconds >= 0
    && ticket_age_tolerance_milliseconds <= 600_000
  {
    True ->
      Ok(ServerPolicy(
        ticket_keys:,
        now_milliseconds:,
        ticket_age_tolerance_milliseconds:,
        replay_cache:,
        permit_early_data: True,
        external_replay_guard: None,
      ))
    False -> Error(InvalidPolicy)
  }
}

/// Preserve authenticated PSK resumption while forcing 0-RTT rejection.
/// QUIC Retry uses this policy because receiving Retry invalidates early data.
pub fn reject_early_data(policy: ServerPolicy) -> ServerPolicy {
  ServerPolicy(..policy, permit_early_data: False)
}

/// Require a bounded caller-managed atomic test-and-record for early data.
///
/// Guard rejection, failure, or timeout rejects only 0-RTT. The authenticated
/// PSK can still resume the connection at 1-RTT.
pub fn with_external_replay_guard(
  policy policy: ServerPolicy,
  guard guard: replay_guard.Guard,
) -> ServerPolicy {
  ServerPolicy(..policy, external_replay_guard: Some(guard))
}

/// Select and authenticate a PSK, independently deciding early-data use.
pub fn select(
  policy policy: ServerPolicy,
  encoded_client_hello encoded_client_hello: BitArray,
  transcript_prefix transcript_prefix: BitArray,
  client_hello client_hello: hello.ClientHello,
  expected_server_name expected_server_name: String,
  expected_alpn expected_alpn: BitArray,
  expected_quic_version expected_quic_version: Int,
  expected_transport_parameters expected_transport_parameters: BitArray,
) -> Result(Decision, Error) {
  case bit_array.bit_size(transcript_prefix) % 8 == 0 {
    False -> Error(NonByteAligned)
    True -> {
      let hello.ClientHello(random, _, cipher_suites, extensions) = client_hello
      case find_extension(extensions, extension.PreSharedKey) {
        // nolint: thrown_away_error -- extension absence selects a full handshake.
        Error(_) -> Ok(FullHandshake(policy.replay_cache))
        Ok(encoded_offer) -> {
          use Nil <- result.try(require_psk_dhe_mode(extensions))
          use early_data_offered <- result.try(early_data_offered(extensions))
          use offered <- result.try(
            pre_shared_key.decode_offered(encoded_offer) |> map_psk_result,
          )
          use truncated <- result.try(
            pre_shared_key.binder_transcript(encoded_client_hello, offered)
            |> map_binder_transcript_result,
          )
          let pre_shared_key.Offered(identities, binders) = offered
          select_identity(
            policy,
            identities,
            binders,
            0,
            <<transcript_prefix:bits, truncated:bits>>,
            random,
            cipher_suites,
            early_data_offered,
            expected_server_name,
            expected_alpn,
            expected_quic_version,
            expected_transport_parameters,
          )
        }
      }
    }
  }
}

/// Return whether the client placed early_data in ClientHello.
pub fn client_early_data_requested(offer offer: ClientOffer) -> Bool {
  offer.request_early_data
}

/// Return the resumption cipher suite selected by the ticket.
pub fn client_cipher_suite(offer offer: ClientOffer) -> hello.CipherSuite {
  let session_ticket.ClientTicket(cipher_suite: cipher_suite, ..) = offer.ticket
  cipher_suite
}

/// Return the PSK only to the internal handshake key schedule.
pub fn client_pre_shared_key(offer offer: ClientOffer) -> BitArray {
  let session_ticket.ClientTicket(pre_shared_key: psk, ..) = offer.ticket
  psk
}

/// Return the authenticated peer transport parameters remembered for 0-RTT.
pub fn client_remembered_transport_parameters(
  offer offer: ClientOffer,
) -> BitArray {
  let session_ticket.ClientTicket(
    remembered_transport_parameters: parameters,
    ..,
  ) = offer.ticket
  parameters
}

/// Return the ticket hash algorithm to the internal key schedule.
pub fn client_hash_algorithm(offer offer: ClientOffer) -> crypto.HashAlgorithm {
  let session_ticket.ClientTicket(algorithm: algorithm, ..) = offer.ticket
  algorithm
}

/// Check that a prepared offer belongs to the requested connection origin.
pub fn client_matches_origin(
  offer offer: ClientOffer,
  server_name server_name: String,
  application_protocols application_protocols: List(BitArray),
  quic_version quic_version: Int,
) -> Bool {
  let session_ticket.ClientTicket(
    server_name: bound_name,
    alpn: bound_alpn,
    quic_version: bound_version,
    ..,
  ) = offer.ticket
  server_name == bound_name
  && list.contains(application_protocols, bound_alpn)
  && quic_version == bound_version
}

fn select_identity(
  policy: ServerPolicy,
  identities: List(pre_shared_key.Identity),
  binders: List(BitArray),
  index: Int,
  binder_transcript: BitArray,
  client_random: BitArray,
  cipher_suites: List(hello.CipherSuite),
  early_data_offered: Bool,
  expected_server_name: String,
  expected_alpn: BitArray,
  expected_quic_version: Int,
  expected_transport_parameters: BitArray,
) -> Result(Decision, Error) {
  case identities, binders {
    [], [] -> Ok(FullHandshake(policy.replay_cache))
    [pre_shared_key.Identity(identity, age), ..identity_rest],
      [binder, ..binder_rest]
    -> {
      let opened =
        open_ticket(
          policy.ticket_keys,
          identity,
          policy.now_milliseconds,
          expected_server_name,
          expected_alpn,
          expected_quic_version,
        )
      case opened {
        // nolint: thrown_away_error -- opaque identities can be from another key epoch.
        Error(_) ->
          select_identity(
            policy,
            identity_rest,
            binder_rest,
            index + 1,
            binder_transcript,
            client_random,
            cipher_suites,
            early_data_offered,
            expected_server_name,
            expected_alpn,
            expected_quic_version,
            expected_transport_parameters,
          )
        Ok(claims) ->
          authenticate_identity(
            policy,
            claims,
            identity,
            age,
            binder,
            index,
            binder_transcript,
            client_random,
            cipher_suites,
            early_data_offered,
            expected_transport_parameters,
          )
      }
    }
    _, _ -> Error(InvalidBinder)
  }
}

fn valid_ticket_keys(keys: List(BitArray)) -> Bool {
  case keys {
    [current] -> valid_ticket_key(current)
    [current, previous] ->
      current != previous
      && valid_ticket_key(current)
      && valid_ticket_key(previous)
    _ -> False
  }
}

fn valid_ticket_key(key: BitArray) -> Bool {
  bit_array.bit_size(key) % 8 == 0 && bit_array.byte_size(key) == 32
}

fn open_ticket(
  keys: List(BitArray),
  identity: BitArray,
  now_milliseconds: Int,
  server_name: String,
  alpn: BitArray,
  quic_version: Int,
) -> Result(session_ticket.Claims, session_ticket.Error) {
  case keys {
    [] -> Error(session_ticket.InvalidTicket)
    [key, ..rest] ->
      case
        session_ticket.open(
          key,
          identity,
          now_milliseconds,
          server_name,
          alpn,
          quic_version,
        )
      {
        Ok(claims) -> Ok(claims)
        Error(error) ->
          case rest {
            [] -> Error(error)
            _ ->
              open_ticket(
                rest,
                identity,
                now_milliseconds,
                server_name,
                alpn,
                quic_version,
              )
          }
      }
  }
}

fn authenticate_identity(
  policy: ServerPolicy,
  claims: session_ticket.Claims,
  identity: BitArray,
  obfuscated_age: Int,
  binder: BitArray,
  index: Int,
  binder_transcript: BitArray,
  client_random: BitArray,
  cipher_suites: List(hello.CipherSuite),
  early_data_offered: Bool,
  expected_transport_parameters: BitArray,
) -> Result(Decision, Error) {
  let session_ticket.Claims(
    pre_shared_key: psk,
    algorithm: algorithm,
    cipher_suite: cipher_suite,
    permit_early_data: permit_early_data,
    remembered_transport_parameters: remembered_transport_parameters,
    ..,
  ) = claims
  case list.contains(cipher_suites, cipher_suite) {
    False -> Ok(FullHandshake(policy.replay_cache))
    True -> {
      use verified <- result.try(
        pre_shared_key.verify_binder(
          algorithm: algorithm,
          pre_shared_key: psk,
          client_hello_truncated: binder_transcript,
          received: binder,
          external: False,
        )
        |> map_psk_result,
      )
      case verified {
        False -> Error(InvalidBinder)
        True -> {
          use #(accepted, replay_cache) <- result.try(decide_early_data(
            policy,
            claims,
            identity,
            obfuscated_age,
            binder,
            client_random,
            early_data_offered,
            permit_early_data,
            algorithm,
            remembered_transport_parameters_are_compatible(
              remembered_transport_parameters,
              expected_transport_parameters,
            ),
          ))
          Ok(
            Resumed(Selected(
              identity_index: index,
              claims:,
              early_data_offered:,
              early_data_accepted: accepted,
              replay_cache:,
            )),
          )
        }
      }
    }
  }
}

fn remembered_transport_parameters_are_compatible(
  remembered: BitArray,
  current: BitArray,
) -> Bool {
  case remembered == current {
    True -> True
    False ->
      case
        transport_parameter.decode_all(
          remembered,
          transport_parameter.Server,
          transport_parameter.default_limits(),
        ),
        transport_parameter.decode_all(
          current,
          transport_parameter.Server,
          transport_parameter.default_limits(),
        )
      {
        Ok(remembered), Ok(current) ->
          zero_rtt_transport_parameters(remembered)
          == zero_rtt_transport_parameters(current)
        _, _ -> False
      }
  }
}

/// Remove connection-instance parameters that RFC 9001 forbids carrying from
/// a previous connection into 0-RTT transport state.
pub fn zero_rtt_transport_parameters(
  parameters: List(transport_parameter.Parameter),
) -> List(transport_parameter.Parameter) {
  list.filter(parameters, remembered_for_zero_rtt)
}

fn remembered_for_zero_rtt(parameter: transport_parameter.Parameter) -> Bool {
  case parameter {
    transport_parameter.OriginalDestinationConnectionId(_)
    | transport_parameter.InitialSourceConnectionId(_)
    | transport_parameter.RetrySourceConnectionId(_)
    | transport_parameter.StatelessResetToken(_)
    | transport_parameter.PreferredAddressParameter(_) -> False
    _ -> True
  }
}

fn decide_early_data(
  policy: ServerPolicy,
  claims: session_ticket.Claims,
  identity: BitArray,
  obfuscated_age: Int,
  binder: BitArray,
  client_random: BitArray,
  offered: Bool,
  permitted: Bool,
  algorithm: crypto.HashAlgorithm,
  transport_parameters_match: Bool,
) -> Result(#(Bool, anti_replay.Cache), Error) {
  let age_is_valid =
    session_ticket.ticket_age_is_valid(
      claims,
      obfuscated_age,
      policy.now_milliseconds,
      policy.ticket_age_tolerance_milliseconds,
    )
  case
    offered
    && permitted
    && policy.permit_early_data
    && age_is_valid
    && transport_parameters_match
  {
    False -> Ok(#(False, policy.replay_cache))
    True -> {
      use replay_fingerprint <- result.try(
        anti_replay.fingerprint(algorithm, identity, client_random, binder)
        |> map_replay_result,
      )
      use outcome <- result.try(
        anti_replay.record_verified(
          policy.replay_cache,
          replay_fingerprint,
          policy.now_milliseconds,
        )
        |> map_replay_result,
      )
      case outcome {
        anti_replay.Accepted(cache) ->
          Ok(#(
            external_replay_permits(policy, claims, replay_fingerprint),
            cache,
          ))
        anti_replay.Replayed(cache) | anti_replay.Saturated(cache) ->
          Ok(#(False, cache))
      }
    }
  }
}

fn external_replay_permits(
  policy: ServerPolicy,
  claims: session_ticket.Claims,
  replay_fingerprint: BitArray,
) -> Bool {
  case policy.external_replay_guard {
    None -> True
    Some(guard) ->
      replay_guard.permits(
        guard,
        replay_fingerprint,
        ticket_valid_for_milliseconds(claims, policy.now_milliseconds),
      )
  }
}

fn ticket_valid_for_milliseconds(
  claims: session_ticket.Claims,
  now_milliseconds: Int,
) -> Int {
  let session_ticket.Claims(
    issued_at_milliseconds: issued_at,
    lifetime_seconds: lifetime,
    ..,
  ) = claims
  int.max(0, issued_at + lifetime * 1000 - now_milliseconds)
}

fn require_psk_dhe_mode(
  extensions: List(extension.Extension),
) -> Result(Nil, Error) {
  case find_extension(extensions, extension.PskKeyExchangeModes) {
    Error(_) -> Error(MissingPskModes)
    Ok(data) -> {
      use modes <- result.try(
        pre_shared_key.decode_modes(data) |> map_psk_result,
      )
      case list.contains(modes, pre_shared_key.PskDheKe) {
        True -> Ok(Nil)
        False -> Error(MissingPskModes)
      }
    }
  }
}

fn early_data_offered(
  extensions: List(extension.Extension),
) -> Result(Bool, Error) {
  case find_extension(extensions, extension.EarlyData) {
    // nolint: thrown_away_error -- early_data is an optional presence marker.
    Error(_) -> Ok(False)
    Ok(<<>>) -> Ok(True)
    Ok(_) -> Error(InvalidEarlyData)
  }
}

fn find_extension(
  extensions: List(extension.Extension),
  expected: extension.Kind,
) -> Result(BitArray, Nil) {
  case extensions {
    [] -> Error(Nil)
    [extension.Extension(kind, data), ..rest] ->
      case kind == expected {
        True -> Ok(data)
        False -> find_extension(rest, expected)
      }
  }
}

fn map_psk_result(
  value: Result(output, pre_shared_key.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(PskFailure(error))
  }
}

fn map_binder_transcript_result(
  value: Result(output, pre_shared_key.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(_) -> Error(InvalidBinder)
  }
}

fn map_ticket_result(
  value: Result(output, session_ticket.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(TicketFailure(error))
  }
}

fn map_replay_result(
  value: Result(output, anti_replay.Error),
) -> Result(output, Error) {
  case value {
    Ok(output) -> Ok(output)
    Error(error) -> Error(ReplayFailure(error))
  }
}
