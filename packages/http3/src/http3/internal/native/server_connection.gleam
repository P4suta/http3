//// One HTTP/3 server session over the public opaque `quic_core` API.
////
//// QUIC listener routing, UDP, TLS, Retry, tokens, recovery, migration, and
//// PMTU discovery stay inside `quic_core`. This adapter owns only public
//// connection/stream handles, a bounded stream registry, and role-neutral
//// HTTP/3 protocol state.

import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/native/connection_state as http3_state
import http3/internal/native/diagnostic_code
import http3/internal/native/drain
import http3/internal/native/grease
import http3/internal/native/header_semantics
import http3/internal/native/protocol
import http3/internal/qpack/header.{type Header}
import quic_core
import quic_core/diagnostics as qlog
import quic_core/failure as core_failure
import quic_core/server as core_server

const maximum_stream_read_bytes = 65_536

const request_rejected_code = 0x10b

/// A validated certificate/key pair retained only for public-core setup.
pub opaque type Credential {
  Credential(
    server_name: String,
    certificate_pem: BitArray,
    private_key_pem: BitArray,
  )
}

/// Stable credential-construction failures.
pub type CredentialError {
  InvalidCredentialCertificate
  InvalidCredentialPrivateKey
  IncompatibleCredentialPrivateKey
  InvalidCredentialServerName
}

/// A finite public-core replay check.
pub opaque type ReplayGuard {
  ReplayGuard(handle: core_server.ReplayGuard)
}

/// Parse the listener's fallback certificate and key.
pub fn default_credential(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Credential, CredentialError) {
  validate_credential(certificate_pem, private_key_pem)
  |> result.map(fn(_) { Credential("", certificate_pem, private_key_pem) })
}

/// Parse one SNI-selected certificate and key.
pub fn named_credential(
  server_name: String,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Credential, CredentialError) {
  use Nil <- result.try(case valid_server_name(server_name) {
    True -> Ok(Nil)
    False -> Error(InvalidCredentialServerName)
  })
  validate_credential(certificate_pem, private_key_pem)
  |> result.map(fn(_) {
    Credential(server_name, certificate_pem, private_key_pem)
  })
}

/// Return the normalized SNI pattern retained by one named credential.
pub fn credential_server_name(credential: Credential) -> String {
  credential.server_name
}

/// Return whether a name is an exact DNS name or one-label wildcard.
pub fn valid_server_name(server_name: String) -> Bool {
  core_server.valid_server_name(server_name)
}

/// Return whether bytes decode as a non-empty PEM certificate chain.
pub fn valid_certificate(certificate_pem: BitArray) -> Bool {
  core_server.valid_certificate(certificate_pem)
}

/// Return whether bytes decode as a supported compatible private key.
pub fn valid_private_key(private_key_pem: BitArray) -> Bool {
  core_server.valid_private_key(private_key_pem)
}

/// Validate and retain an external atomic test-and-record callback.
pub fn new_replay_guard(
  timeout_milliseconds: Int,
  check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(ReplayGuard, Nil) {
  core_server.replay_guard(timeout_milliseconds, check)
  |> result.map(ReplayGuard)
  |> result.replace_error(Nil)
}

/// Build the complete public-core credential set for a listener or reload.
pub fn server_configuration(
  default: Credential,
  alternatives: List(Credential),
) -> Result(core_server.Server, CredentialError) {
  use configured <- result.try(
    core_server.new(default.certificate_pem, default.private_key_pem, "h3")
    |> result.map_error(map_credential_configuration_error),
  )
  add_alternative_credentials(configured, alternatives)
}

/// Expose the validated replay capability only to the package-internal worker.
pub fn replay_guard_handle(guard: ReplayGuard) -> core_server.ReplayGuard {
  guard.handle
}

/// Per-connection HTTP/3 limits already validated by the public server API.
pub type Config {
  Config(
    http_datagrams: Bool,
    bidirectional_stream_limit: Int,
    frame_limit: Int,
    datagram_limit: Int,
    qpack_table_limit: Int,
    qpack_blocked_stream_limit: Int,
    authority_policies: header_semantics.AuthorityPolicies,
  )
}

/// State of the connection's explicit 0-RTT attempt.
pub type EarlyDataStatus {
  NotAttempted
  Pending
  Accepted
  Rejected
}

/// Runtime traffic counters owned by the public core connection actor.
pub type Stats {
  Stats(
    packets_received: Int,
    packets_sent: Int,
    data_received: Int,
    data_sent: Int,
    acknowledgements_sent: Int,
    retransmissions: Int,
    batch_flushes: Int,
    packets_coalesced: Int,
  )
}

/// Stable HTTP/3 and lifecycle events consumed by the connection actor.
pub type Event {
  Http3Event(http3_state.Event)
  StreamWasReset(stream_id: Int, application_error_code: Int)
  StreamSendCompleted(stream_id: Int, completion: core_server.SendCompletion)
  ConnectionTerminated
}

/// Typed public-core events. `connection_id` makes one shared subject safe for
/// every connection owned by a listener without exposing actor or socket terms.
pub type NetworkEvent {
  PeerStream(connection_id: Int, stream: core_server.Stream)
  StreamData(
    connection_id: Int,
    stream_id: Int,
    bytes: BitArray,
    finished: Bool,
  )
  StreamReset(connection_id: Int, stream_id: Int, application_error_code: Int)
  StreamCompletions(connection_id: Int, batch: core_server.SendCompletionBatch)
  CompletionFeedFailed(connection_id: Int, error: core_server.Error)
  DatagramReceived(connection_id: Int, bytes: BitArray)
  CoreConnectionClosed(connection_id: Int)
}

/// Application-visible operation classes retained by the HTTP/3 error map.
pub type OperationFailure {
  DatagramsNotNegotiated
  DatagramTooLarge(maximum: Int)
  CongestionLimited
}

/// Public-core, HTTP/3, or bounded resource failure.
pub type Error {
  InvalidInput
  OperationTimeout
  PeerClosed
  ProtocolFailure(protocol.Error)
  CoreFailure(core_server.Error)
}

type CoreResource {
  CoreResource(
    connection: core_server.Connection,
    streams: Dict(Int, core_server.Stream),
  )
}

/// One established public-core connection and its HTTP/3 state.
pub opaque type State {
  State(
    identifier: Int,
    session: protocol.State(CoreResource),
    network: Subject(NetworkEvent),
    events: List(Event),
    http_datagrams: Bool,
    application_diagnostics: Option(qlog.ApplicationSink),
  )
}

/// Bootstrap mandatory HTTP/3 streams and start typed public-core readers.
pub fn start(
  identifier: Int,
  connection: core_server.Connection,
  network: Subject(NetworkEvent),
  config: Config,
) -> Result(State, Error) {
  use application_diagnostics <- result.try(
    core_server.application_diagnostics(connection)
    |> result.map_error(CoreFailure),
  )
  let resource = CoreResource(connection, dict.new())
  use session <- result.try(
    protocol.start(
      core_resource(),
      resource,
      http3_config(config, identifier),
      config.http_datagrams,
    )
    |> result.map_error(ProtocolFailure),
  )
  let state =
    State(
      identifier,
      session,
      network,
      [],
      config.http_datagrams,
      application_diagnostics,
    )
  record_qlog_bootstrap(state, qlog.monotonic_milliseconds())
  let owner = process.self()
  let completion_feed_owner = core_server.completion_feed_owner()
  process.spawn_unlinked(fn() {
    accept_streams(identifier, connection, network)
  })
  process.spawn_unlinked(fn() {
    receive_send_completions(
      owner,
      completion_feed_owner,
      identifier,
      connection,
      network,
      0,
    )
  })
  case config.http_datagrams {
    True ->
      process.spawn_unlinked(fn() {
        receive_datagrams(identifier, connection, network)
      })
    False -> process.spawn_unlinked(fn() { Nil })
  }
  Ok(state)
}

/// Consume one typed event produced by public accept/read operations.
pub fn receive_active(
  state: State,
  event: NetworkEvent,
) -> Result(State, Error) {
  case event {
    PeerStream(identifier, stream) if identifier == state.identifier ->
      receive_peer_stream(state, stream)
    StreamData(identifier, stream_id, bytes, finished)
      if identifier == state.identifier
    -> {
      let outcome =
        protocol.receive_active_stream(
          state.session,
          stream_id,
          bytes,
          finished,
          qlog.monotonic_milliseconds(),
        )
      case outcome {
        Ok(protocol.StreamReceived(session)) -> map_session(Ok(session), state)
        Ok(protocol.MessageStreamAborted(session, _, code)) ->
          map_session(Ok(session), state)
          |> result.map(fn(state) {
            State(
              ..state,
              events: list.append(state.events, [
                StreamWasReset(stream_id, code),
              ]),
            )
          })
        Error(protocol.Http3Failure(http3_state.RequestRejected(rejected)))
          if rejected == stream_id
        ->
          protocol.abort_stream(state.session, stream_id, request_rejected_code)
          |> map_session(state)
        Error(error) -> Error(error) |> map_session(state)
      }
    }
    StreamReset(identifier, stream_id, code) if identifier == state.identifier -> {
      use state <- result.try(
        protocol.receive_reset(state.session, stream_id) |> map_session(state),
      )
      use state <- result.try(abort_reset_stream(state, stream_id, code))
      Ok(
        State(
          ..state,
          events: list.append(state.events, [StreamWasReset(stream_id, code)]),
        ),
      )
    }
    StreamCompletions(identifier, batch) if identifier == state.identifier -> {
      let core_server.SendCompletionBatch(_, events) = batch
      let completions =
        list.map(events, fn(event) {
          let core_server.SendCompletionEvent(_, stream_id, outcome) = event
          StreamSendCompleted(stream_id, outcome)
        })
      Ok(State(..state, events: list.append(state.events, completions)))
    }
    CompletionFeedFailed(identifier, error) if identifier == state.identifier ->
      Error(CoreFailure(error))
    DatagramReceived(identifier, bytes) if identifier == state.identifier ->
      protocol.receive_datagram(state.session, bytes) |> map_session(state)
    CoreConnectionClosed(identifier) if identifier == state.identifier ->
      Ok(
        State(
          ..state,
          events: list.append(state.events, [ConnectionTerminated]),
        ),
      )
    _ -> Ok(state)
  }
}

fn receive_send_completions(
  owner: Pid,
  completion_feed_owner: core_server.CompletionFeedOwner,
  identifier: Int,
  connection: core_server.Connection,
  network: Subject(NetworkEvent),
  cursor: Int,
) -> Nil {
  case process.is_alive(owner) {
    False -> Nil
    True ->
      case
        core_server.next_send_completions_until_owner_exits(
          connection,
          cursor,
          60_000,
          completion_feed_owner,
        )
      {
        Ok(core_server.SendCompletionBatch(next_cursor, _) as batch) -> {
          process.send(network, StreamCompletions(identifier, batch))
          receive_send_completions(
            owner,
            completion_feed_owner,
            identifier,
            connection,
            network,
            next_cursor,
          )
        }
        Error(core_server.Failure(core_failure.Timeout(core_failure.Operation))) ->
          receive_send_completions(
            owner,
            completion_feed_owner,
            identifier,
            connection,
            network,
            cursor,
          )
        Error(core_server.Failure(core_failure.Closed(_, _))) ->
          process.send(network, CoreConnectionClosed(identifier))
        Error(error) ->
          process.send(network, CompletionFeedFailed(identifier, error))
      }
  }
}

// A peer RESET finishes only receiving.
// The application reports a terminal request, so finish the still-open send direction before releasing its handle.
// A late reset may refer to a handle already retired after both directions ended.
fn abort_reset_stream(
  state: State,
  stream_id: Int,
  code: Int,
) -> Result(State, Error) {
  use <- bool.guard(
    when: !dict.has_key(protocol.connection(state.session).streams, stream_id),
    return: Ok(state),
  )
  use state <- result.try(abort_stream(state, stream_id, code))
  Ok(retire_stream(state, stream_id))
}

/// Pull and clear ordered HTTP/3 and lifecycle events.
pub fn take_events(state: State) -> #(State, List(Event)) {
  let #(session, events) = protocol.take_events(state.session)
  let events =
    list.filter_map(events, fn(event) {
      case event {
        protocol.Http3Event(event) -> {
          record_http3_event(state, event)
          Ok(Http3Event(event))
        }
        protocol.DataFrameParsed(identifier, bytes) -> {
          record_http3_frame_parsed(state, identifier, qlog.DataFrame, bytes)
          Error(Nil)
        }
        protocol.MessageStreamWasRejected(_, identifier, code) ->
          Ok(StreamWasReset(identifier, code))
      }
    })
  #(
    State(..state, session: session, events: []),
    list.append(state.events, events),
  )
}

pub fn send_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  protocol.send_response_headers(state.session, stream_id, fields, False)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(state, stream_id, qlog.HeadersFrame, 0)
    state
  })
}

pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  protocol.send_data(state.session, stream_id, bytes)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(
      state,
      stream_id,
      qlog.DataFrame,
      bit_array.byte_size(bytes),
    )
    state
  })
}

pub fn send_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  protocol.send_trailers(state.session, stream_id, fields, False)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(state, stream_id, qlog.HeadersFrame, 0)
    state
  })
}

pub fn finish_stream(state: State, stream_id: Int) -> Result(State, Error) {
  protocol.finish_stream(state.session, stream_id) |> map_session(state)
}

/// Return whether a response stream's FIN is acknowledged or its send
/// direction was reset, without exposing the underlying core stream.
pub fn stream_send_finished(
  state: State,
  stream_id: Int,
) -> Result(Bool, Error) {
  let resource = protocol.connection(state.session)
  use stream <- result.try(
    find_stream(resource, stream_id) |> result.replace_error(InvalidInput),
  )
  core_server.send_finished(stream) |> result.map_error(CoreFailure)
}

/// Share an admitted stream's opaque handle with its accepted request.
/// The handle retains no HTTP payload and lets a caller await the send direction without occupying the connection actor or consuming receive events.
pub fn response_stream(
  state: State,
  stream_id: Int,
) -> Result(core_server.Stream, Error) {
  find_stream(protocol.connection(state.session), stream_id)
  |> result.replace_error(InvalidInput)
}

/// Forget one fully settled public-core stream handle.
///
/// HTTP/3 state and the core connection have already observed both terminal
/// directions before this is called. Keeping the opaque handle beyond that
/// point would make memory grow with lifetime request count.
pub fn retire_stream(state: State, stream_id: Int) -> State {
  let resource = protocol.connection(state.session)
  let resource =
    CoreResource(..resource, streams: dict.delete(resource.streams, stream_id))
  State(..state, session: protocol.with_connection(state.session, resource))
}

/// Snapshot retained stream resources across the adapter, actor, transport,
/// parser, and HTTP/3 state machine without exposing identifiers or payloads.
pub fn resource_stats(
  state: State,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int), Error) {
  let resource = protocol.connection(state.session)
  use core_stats <- result.try(
    core_server.resource_stats(resource.connection)
    |> result.map_error(CoreFailure),
  )
  let qlog.ResourceStats(runtime_streams, transport_streams) = core_stats
  let #(inputs, transactions, push_transactions, blocked_streams) =
    protocol.resource_counts(state.session)
  Ok(#(
    dict.size(resource.streams),
    runtime_streams,
    transport_streams,
    inputs,
    transactions,
    push_transactions,
    blocked_streams,
  ))
}

/// Test-only payload-free send ownership evidence from the public core actor.
@internal
pub fn send_resource_stats(state: State) -> Result(#(Int, Int, Int), Error) {
  let resource = protocol.connection(state.session)
  core_server.send_resource_stats(resource.connection)
  |> result.map_error(CoreFailure)
}

/// Payload-free acknowledgement barrier for an orderly HTTP/3 close.
@internal
pub fn application_send_settled(state: State) -> Result(Bool, Error) {
  let resource = protocol.connection(state.session)
  core_server.application_send_settled(resource.connection)
  |> result.map_error(CoreFailure)
}

pub fn promise_push(
  state: State,
  request_stream_id: Int,
  fields: List(Header),
  now_milliseconds: Int,
) -> Result(#(State, Int, Int), Error) {
  protocol.promise_push(
    state.session,
    request_stream_id,
    fields,
    now_milliseconds,
  )
  |> result.map(fn(value) {
    let #(session, push_id, stream_id) = value
    let state = State(..state, session: session)
    record_http3_frame_created(
      state,
      request_stream_id,
      qlog.PushPromiseFrame,
      0,
    )
    record_http3_stream_type(state, stream_id, qlog.PushStream)
    #(state, push_id, stream_id)
  })
  |> result.map_error(ProtocolFailure)
}

pub fn send_push_response_headers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  protocol.send_push_response_headers(state.session, stream_id, fields)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(state, stream_id, qlog.HeadersFrame, 0)
    state
  })
}

pub fn send_push_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  protocol.send_push_data(state.session, stream_id, bytes)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(
      state,
      stream_id,
      qlog.DataFrame,
      bit_array.byte_size(bytes),
    )
    state
  })
}

pub fn send_push_trailers(
  state: State,
  stream_id: Int,
  fields: List(Header),
) -> Result(State, Error) {
  protocol.send_push_trailers(state.session, stream_id, fields)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(state, stream_id, qlog.HeadersFrame, 0)
    state
  })
}

pub fn finish_push(state: State, stream_id: Int) -> Result(State, Error) {
  protocol.finish_push(state.session, stream_id) |> map_session(state)
}

pub fn abort_stream(
  state: State,
  stream_id: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  protocol.abort_stream(state.session, stream_id, application_error_code)
  |> map_session(state)
}

/// Observe a core-confirmed response/send stop while preserving request input.
pub fn observe_send_stopped(
  state: State,
  stream_id: Int,
) -> Result(State, Error) {
  protocol.observe_send_stopped(state.session, stream_id)
  |> map_session(state)
}

pub fn datagrams_available(state: State) -> Bool {
  protocol.datagrams_available(state.session)
}

pub fn maximum_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  protocol.maximum_http_datagram_size(state.session, stream_id)
  |> result.map_error(ProtocolFailure)
}

pub fn guaranteed_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  protocol.guaranteed_http_datagram_size(state.session, stream_id)
  |> result.map_error(ProtocolFailure)
}

pub fn prospective_guaranteed_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  protocol.prospective_guaranteed_http_datagram_size(state.session, stream_id)
  |> result.map_error(ProtocolFailure)
}

pub fn send_http_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(State, Error) {
  protocol.send_http_datagram(state.session, stream_id, payload)
  |> map_session(state)
}

pub fn set_request_priority(
  state: State,
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(State, Error) {
  protocol.set_request_priority(state.session, stream_id, urgency, incremental)
  |> map_session(state)
}

/// Queue one public-core liveness PING.
pub fn ping(state: State) -> Result(State, Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.ping(connection)
  |> result.map(fn(_) { state })
  |> result.map_error(CoreFailure)
}

pub fn start_drain(state: State, now: Int) -> Result(State, Error) {
  protocol.start_drain(state.session, now)
  |> map_session(state)
  |> result.map(fn(state) {
    record_http3_frame_created(state, 3, qlog.GoAwayFrame, 0)
    state
  })
}

pub fn refine_drain(
  state: State,
  identifier: Int,
) -> Result(#(State, List(Int)), Error) {
  protocol.refine_drain(state.session, identifier)
  |> result.map(fn(value) {
    let #(session, rejected) = value
    let state = State(..state, session: session)
    record_http3_frame_created(state, 3, qlog.GoAwayFrame, 0)
    #(state, rejected)
  })
  |> result.map_error(ProtocolFailure)
}

pub fn close_drained(state: State) -> Result(State, Error) {
  protocol.close_drained(state.session) |> map_session(state)
}

pub fn drain_phase(state: State) -> drain.Phase {
  protocol.drain_phase(state.session)
}

pub fn peer_endpoint(state: State) -> Result(#(BitArray, Int), Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.peer_endpoint(connection)
  |> result.map(fn(value) {
    let #(address, port) = value
    #(quic_core.ip_address_bytes(address), port)
  })
  |> result.map_error(CoreFailure)
}

pub fn early_data_status(state: State) -> EarlyDataStatus {
  let CoreResource(connection, _) = protocol.connection(state.session)
  case core_server.connection_info(connection) {
    Ok(qlog.ConnectionInfo(_, _, _, _, qlog.Accepted, _)) -> Accepted
    Ok(qlog.ConnectionInfo(_, _, _, _, qlog.Pending, _)) -> Pending
    Ok(qlog.ConnectionInfo(_, _, _, _, qlog.Rejected, _)) -> Rejected
    _ -> NotAttempted
  }
}

pub fn path_stats(state: State) -> Result(qlog.PathStats, Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.path_stats(connection) |> result.map_error(CoreFailure)
}

pub fn path_mtu(state: State) -> Result(Int, Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.path_mtu(connection) |> result.map_error(CoreFailure)
}

pub fn stats(state: State) -> Result(Stats, Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.connection_stats(connection)
  |> result.map(fn(stats) {
    let qlog.ConnectionStats(a, b, c, d, e, f, g, h) = stats
    Stats(a, b, c, d, e, f, g, h)
  })
  |> result.map_error(CoreFailure)
}

pub fn telemetry_stats(state: State) -> Result(#(Int, Int, Int), Error) {
  let CoreResource(connection, _) = protocol.connection(state.session)
  core_server.telemetry_stats(connection)
  |> result.map(fn(stats) {
    let qlog.TelemetryStats(dropped, errors, queued) = stats
    #(dropped, errors, queued)
  })
  |> result.map_error(CoreFailure)
}

/// Close without placing an application reason payload in transport state.
pub fn close(state: State, application_error_code: Int) -> Nil {
  let CoreResource(connection, _) = protocol.connection(state.session)
  case quic_core.application_error_code(application_error_code) {
    Error(_) -> Nil
    Ok(code) -> {
      let _closed = core_server.close_with_code(connection, code)
      Nil
    }
  }
}

pub fn is_send_pressure(error: Error) -> Bool {
  case error {
    ProtocolFailure(protocol.ResourceFailure(protocol.ResourceSendLimited(_))) ->
      True
    _ -> False
  }
}

/// Return a registered application close code only for authenticated peer
/// protocol failures, never for local resource or public-core failures.
pub fn peer_application_error_code(error: Error) -> Option(Int) {
  case error {
    ProtocolFailure(protocol_error) ->
      protocol.peer_application_error_code(protocol_error)
    _ -> None
  }
}

/// Queue one validated payload-free application diagnostic when qlog is on.
///
/// The connection-owned writer is bounded and asynchronous.
/// A disabled,
/// stopped, saturated, or failed writer cannot delay the protocol operation which produced this observation.
pub fn record_application_error(state: State, value: Int) -> Nil {
  case state.application_diagnostics, qlog.application_code(value) {
    Some(sink), Ok(code) ->
      qlog.emit_application_error(sink, qlog.monotonic_milliseconds(), code)
    _, _ -> Nil
  }
}

pub fn operation_failure(error: Error) -> Option(OperationFailure) {
  case error {
    ProtocolFailure(protocol.ResourceFailure(
      protocol.ResourceDatagramsNotNegotiated,
    )) -> Some(DatagramsNotNegotiated)
    ProtocolFailure(protocol.ResourceFailure(protocol.ResourceDatagramTooLarge(
      maximum,
    ))) -> Some(DatagramTooLarge(maximum))
    _ -> None
  }
}

/// Reconstruct the application setup which completed synchronously while the
/// connection-owned core writer was already live. These fixed local stream IDs
/// are the first three server-initiated unidirectional streams opened by
/// `protocol.start`; no application stream can interleave with that bootstrap.
fn record_qlog_bootstrap(state: State, now_milliseconds: Int) -> Nil {
  case state.application_diagnostics {
    None -> Nil
    Some(sink) -> {
      qlog.emit_http3_parameters_set(
        sink,
        now_milliseconds,
        qlog.LocalInitiator,
      )
      qlog.emit_http3_stream_type_set(
        sink,
        now_milliseconds,
        quic_core.StreamId(3),
        qlog.ControlStream,
      )
      qlog.emit_http3_stream_type_set(
        sink,
        now_milliseconds,
        quic_core.StreamId(7),
        qlog.QpackEncoderStream,
      )
      qlog.emit_http3_stream_type_set(
        sink,
        now_milliseconds,
        quic_core.StreamId(11),
        qlog.QpackDecoderStream,
      )
      qlog.emit_http3_frame_created(
        sink,
        now_milliseconds,
        quic_core.StreamId(3),
        qlog.SettingsFrame,
        0,
      )
    }
  }
}

/// Translate only semantic, authenticated HTTP/3 observations into bounded
/// metadata. Fields, origins, priorities, capsule data, and payload bytes are
/// deliberately absent from this bridge.
fn record_http3_event(state: State, event: http3_state.Event) -> Nil {
  case event {
    http3_state.PeerSettings(_) ->
      record_http3_parameters_set(state, qlog.RemoteInitiator)
    http3_state.RequestHeaders(stream_id, _) -> {
      record_http3_stream_type(state, stream_id, qlog.RequestStream)
      record_http3_frame_parsed(state, stream_id, qlog.HeadersFrame, 0)
    }
    http3_state.InformationalResponse(stream_id, _)
    | http3_state.ResponseHeaders(stream_id, _)
    | http3_state.Trailers(stream_id, _) ->
      record_http3_frame_parsed(state, stream_id, qlog.HeadersFrame, 0)
    http3_state.PushInformationalResponse(_, stream_id, _)
    | http3_state.PushResponseHeaders(_, stream_id, _)
    | http3_state.PushTrailers(_, stream_id, _) ->
      record_http3_frame_parsed(state, stream_id, qlog.HeadersFrame, 0)
    http3_state.Data(_, _)
    | http3_state.PushData(_, _, _)
    | http3_state.HttpDatagram(_, _)
    | http3_state.StreamFinished(_)
    | http3_state.HeadersBlocked(_, _)
    | http3_state.PushPromised(_, _)
    | http3_state.PushPromiseRejected(_, _)
    | http3_state.PushAwaitingPromise(_, _)
    | http3_state.PushFinished(_, _)
    | http3_state.PushCancelled(_)
    | http3_state.PushStreamCancellationRequested(_, _)
    | http3_state.GoAwayReceived(_, _)
    | http3_state.OriginsReceived(_)
    | http3_state.PriorityChanged(_)
    | http3_state.ExtensionFrameIgnored(_)
    | http3_state.MessageStreamRejected(_, _, _) -> Nil
  }
}

fn record_http3_parameters_set(state: State, initiator: qlog.Initiator) -> Nil {
  case state.application_diagnostics {
    Some(sink) ->
      qlog.emit_http3_parameters_set(
        sink,
        qlog.monotonic_milliseconds(),
        initiator,
      )
    None -> Nil
  }
}

fn record_http3_stream_type(
  state: State,
  stream_id: Int,
  stream_type: qlog.Http3StreamType,
) -> Nil {
  case state.application_diagnostics {
    Some(sink) ->
      qlog.emit_http3_stream_type_set(
        sink,
        qlog.monotonic_milliseconds(),
        quic_core.StreamId(stream_id),
        stream_type,
      )
    None -> Nil
  }
}

fn record_http3_frame_created(
  state: State,
  stream_id: Int,
  frame_type: qlog.Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  case state.application_diagnostics {
    Some(sink) ->
      qlog.emit_http3_frame_created(
        sink,
        qlog.monotonic_milliseconds(),
        quic_core.StreamId(stream_id),
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
}

fn record_http3_frame_parsed(
  state: State,
  stream_id: Int,
  frame_type: qlog.Http3FrameType,
  payload_bytes: Int,
) -> Nil {
  case state.application_diagnostics {
    Some(sink) ->
      qlog.emit_http3_frame_parsed(
        sink,
        qlog.monotonic_milliseconds(),
        quic_core.StreamId(stream_id),
        frame_type,
        payload_bytes,
      )
    None -> Nil
  }
}

fn validate_credential(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Nil, CredentialError) {
  core_server.new(certificate_pem, private_key_pem, "h3")
  |> result.map(fn(_) { Nil })
  |> result.map_error(map_credential_configuration_error)
}

fn map_credential_configuration_error(
  error: core_server.ConfigurationError,
) -> CredentialError {
  case error {
    core_server.InvalidCertificate -> InvalidCredentialCertificate
    core_server.InvalidPrivateKey -> InvalidCredentialPrivateKey
    core_server.IncompatiblePrivateKey -> IncompatibleCredentialPrivateKey
    core_server.InvalidServerName | core_server.DuplicateServerName ->
      InvalidCredentialServerName
    _ -> InvalidCredentialCertificate
  }
}

fn add_alternative_credentials(
  configured: core_server.Server,
  credentials: List(Credential),
) -> Result(core_server.Server, CredentialError) {
  case credentials {
    [] -> Ok(configured)
    [credential, ..rest] -> {
      use configured <- result.try(
        core_server.with_certificate(
          configured,
          credential.server_name,
          credential.certificate_pem,
          credential.private_key_pem,
        )
        |> result.map_error(map_credential_configuration_error),
      )
      add_alternative_credentials(configured, rest)
    }
  }
}

fn http3_config(config: Config, grease_sample: Int) -> http3_state.Config {
  let base = http3_state.default_config(http3_state.Server)
  let settings =
    http3_state.Settings(
      ..base.settings,
      qpack_max_table_capacity: config.qpack_table_limit,
      qpack_blocked_streams: config.qpack_blocked_stream_limit,
      h3_datagram: config.http_datagrams,
      grease_sample: grease.runtime_sample(grease_sample),
    )
  http3_state.Config(
    ..base,
    settings: settings,
    preferred_qpack_table_capacity: config.qpack_table_limit,
    maximum_transactions: config.bidirectional_stream_limit,
    maximum_datagram_payload_bytes: config.datagram_limit,
    maximum_frame_payload_bytes: config.frame_limit,
    authority_policies: config.authority_policies,
  )
}

fn core_resource() -> protocol.Resource(CoreResource) {
  protocol.Resource(
    open_bidirectional: fn(resource: CoreResource) {
      use stream <- result.try(
        core_server.open_bidirectional(resource.connection)
        |> result.map_error(map_resource_error),
      )
      let identifier =
        core_server.stream_id(stream) |> quic_core.stream_id_value
      Ok(#(
        CoreResource(
          ..resource,
          streams: dict.insert(resource.streams, identifier, stream),
        ),
        identifier,
      ))
    },
    open_unidirectional: fn(resource: CoreResource) {
      use stream <- result.try(
        core_server.open_unidirectional(resource.connection)
        |> result.map_error(map_resource_error),
      )
      let identifier =
        core_server.stream_id(stream) |> quic_core.stream_id_value
      Ok(#(
        CoreResource(
          ..resource,
          streams: dict.insert(resource.streams, identifier, stream),
        ),
        identifier,
      ))
    },
    write: fn(
      resource: CoreResource,
      identifier: Int,
      bytes: BitArray,
      finished: Bool,
    ) {
      use stream <- result.try(
        find_stream(resource, identifier)
        |> result.replace_error(protocol.InvalidResourceOperation),
      )
      use Nil <- result.try(case bytes == <<>>, finished {
        True, False -> Ok(Nil)
        _, True ->
          core_server.send_and_finish(stream, bytes)
          |> result.map_error(map_resource_error)
        _, False ->
          core_server.send(stream, bytes)
          |> result.map_error(map_resource_error)
      })
      Ok(resource)
    },
    abort: fn(resource: CoreResource, identifier: Int, code: Int) {
      use stream <- result.try(
        find_stream(resource, identifier)
        |> result.replace_error(protocol.InvalidResourceOperation),
      )
      use Nil <- result.try(
        abort_stream_directions(
          identifier,
          fn() { core_server.reset(stream, code) },
          fn() { core_server.stop_sending(stream, code) },
        ),
      )
      Ok(resource)
    },
    send_datagram: fn(resource: CoreResource, bytes: BitArray) {
      core_server.send_datagram(resource.connection, bytes)
      |> result.map(fn(_) { resource })
      |> result.map_error(map_resource_error)
    },
    maximum_datagram_size: fn(resource: CoreResource) {
      core_server.maximum_datagram_size(resource.connection)
      |> result.map_error(map_resource_error)
    },
    guaranteed_datagram_size: fn(resource: CoreResource) {
      core_server.guaranteed_datagram_size(resource.connection)
      |> result.map_error(map_resource_error)
    },
  )
}

fn receive_peer_stream(
  state: State,
  stream: core_server.Stream,
) -> Result(State, Error) {
  let identifier = core_server.stream_id(stream) |> quic_core.stream_id_value
  let resource = protocol.connection(state.session)
  let resource =
    CoreResource(
      ..resource,
      streams: dict.insert(resource.streams, identifier, stream),
    )
  use session <- result.try(
    protocol.register_peer_stream(
      protocol.with_connection(state.session, resource),
      identifier,
    )
    |> result.map_error(ProtocolFailure),
  )
  process.spawn_unlinked(fn() {
    read_stream(state.identifier, stream, state.network)
  })
  Ok(State(..state, session: session))
}

fn accept_streams(
  identifier: Int,
  connection: core_server.Connection,
  network: Subject(NetworkEvent),
) -> Nil {
  case core_server.accept_stream_next(connection) {
    Ok(core_server.IncomingStream(stream, _)) -> {
      process.send(network, PeerStream(identifier, stream))
      accept_streams(identifier, connection, network)
    }
    Error(_) -> process.send(network, CoreConnectionClosed(identifier))
  }
}

fn read_stream(
  connection_id: Int,
  stream: core_server.Stream,
  network: Subject(NetworkEvent),
) -> Nil {
  let identifier = core_server.stream_id(stream) |> quic_core.stream_id_value
  case core_server.receive_next(stream, maximum_stream_read_bytes) {
    Ok(core_server.Data(bytes, finished)) -> {
      process.send(
        network,
        StreamData(connection_id, identifier, bytes, finished),
      )
      case finished {
        True -> Nil
        False -> read_stream(connection_id, stream, network)
      }
    }
    Ok(core_server.Finished) ->
      process.send(network, StreamData(connection_id, identifier, <<>>, True))
    Ok(core_server.Reset(code)) ->
      process.send(network, StreamReset(connection_id, identifier, code))
    Error(core_server.StreamFinished)
    | Error(core_server.InvalidDirection)
    | Error(core_server.InvalidOperation) -> Nil
    Error(_) -> process.send(network, CoreConnectionClosed(connection_id))
  }
}

fn receive_datagrams(
  identifier: Int,
  connection: core_server.Connection,
  network: Subject(NetworkEvent),
) -> Nil {
  case core_server.receive_datagram_next(connection) {
    Ok(bytes) -> {
      process.send(network, DatagramReceived(identifier, bytes))
      receive_datagrams(identifier, connection, network)
    }
    Error(_) -> Nil
  }
}

fn find_stream(
  resource: CoreResource,
  identifier: Int,
) -> Result(core_server.Stream, Nil) {
  dict.get(resource.streams, identifier)
}

fn map_session(
  value: Result(protocol.State(CoreResource), protocol.Error),
  state: State,
) -> Result(State, Error) {
  case value {
    Ok(session) -> Ok(State(..state, session: session))
    Error(error) -> {
      record_protocol_failure(state, error)
      Error(ProtocolFailure(error))
    }
  }
}

fn record_protocol_failure(state: State, error: protocol.Error) -> Nil {
  case state.application_diagnostics {
    None -> Nil
    Some(sink) ->
      list.each(diagnostic_code.protocol_errors(error), fn(value) {
        case qlog.application_code(value) {
          Ok(code) ->
            qlog.emit_application_error(
              sink,
              qlog.monotonic_milliseconds(),
              code,
            )
          Error(_) -> Nil
        }
      })
  }
}

/// Abort every direction that exists from the server's point of view.
@internal
pub fn abort_stream_directions(
  identifier: Int,
  reset: fn() -> Result(Nil, core_server.Error),
  stop: fn() -> Result(Nil, core_server.Error),
) -> Result(Nil, protocol.ResourceError) {
  let stream_id = quic_core.StreamId(identifier)
  case
    quic_core.stream_direction(stream_id),
    quic_core.stream_initiator(stream_id)
  {
    quic_core.UnidirectionalStream, quic_core.ServerInitiated ->
      abort_direction_outcome(reset())
    quic_core.UnidirectionalStream, quic_core.ClientInitiated ->
      abort_direction_outcome(stop())
    quic_core.BidirectionalStream, _ -> abort_directions(reset, stop)
  }
}

/// Abort the two bidirectional operations independently through public core.
/// A peer cancellation can finish sending before a local GOAWAY rejection reaches this callback.
/// That direction is already terminal; the receive direction must still be stopped, and unrelated requests remain usable.
pub fn abort_directions(
  reset: fn() -> Result(Nil, core_server.Error),
  stop: fn() -> Result(Nil, core_server.Error),
) -> Result(Nil, protocol.ResourceError) {
  let reset_outcome = abort_direction_outcome(reset())
  let stop_outcome = abort_direction_outcome(stop())
  case reset_outcome, stop_outcome {
    Error(error), _ -> Error(error)
    Ok(Nil), Error(error) -> Error(error)
    Ok(Nil), Ok(Nil) -> Ok(Nil)
  }
}

fn abort_direction_outcome(
  outcome: Result(Nil, core_server.Error),
) -> Result(Nil, protocol.ResourceError) {
  case outcome {
    Ok(Nil) | Error(core_server.StreamFinished) -> Ok(Nil)
    Error(error) -> Error(map_resource_error(error))
  }
}

fn map_resource_error(error: core_server.Error) -> protocol.ResourceError {
  case error {
    core_server.StreamFinished -> protocol.ResourceStreamFinished
    core_server.Failure(core_failure.Limit(core_failure.Buffer, maximum)) ->
      protocol.ResourceSendLimited(maximum)
    core_server.Failure(core_failure.Overload(_)) ->
      protocol.ResourceSendLimited(0)
    core_server.Failure(core_failure.Limit(core_failure.Datagram, maximum)) ->
      protocol.ResourceDatagramTooLarge(maximum)
    core_server.Failure(core_failure.Closed(_, _)) -> protocol.ResourceClosed
    core_server.InvalidDirection
    | core_server.InvalidOperation
    | core_server.ConcurrentOperation
    | core_server.CompletionHistoryExceeded(_)
    | core_server.Failure(_) -> protocol.InvalidResourceOperation
  }
}
