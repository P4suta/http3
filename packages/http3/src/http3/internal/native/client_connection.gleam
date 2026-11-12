//// One HTTP/3 client session over the public opaque `quic_core` API.
////
//// QUIC socket, TLS, Retry, token, recovery, and packet actors stay entirely inside `quic_core`.
//// This adapter owns only public connection/stream values,
//// a bounded stream registry, and role-neutral HTTP/3 protocol state.

import gleam/bool
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/native/connection_state as http3_state
import http3/internal/native/drain
import http3/internal/native/grease
import http3/internal/native/protocol
import http3/internal/native/settings_memory
import http3/internal/qlog_admission
import http3/internal/qpack/header.{type Header}
import quic_core.{type AddressFamily, type Version}
import quic_core/client as core_client
import quic_core/config as core_config
import quic_core/diagnostics as qlog
import quic_core/failure as core_failure

const maximum_stream_read_bytes = 65_536

/// Origin-bound TLS session resumption material owned by `quic_core`.
pub opaque type ResumptionTicket {
  ResumptionTicket(ticket: core_client.ResumptionTicket)
}

/// Stable ticket persistence failures retained by the HTTP/3 API.
pub type ResumptionTicketError {
  InvalidResumptionTicketKey
  InvalidResumptionTicket
  ExpiredResumptionTicket
  InvalidResumptionTicketTimestamp
  ResumptionTicketCryptoUnavailable
}

/// Stable connection events delivered to the owning HTTP/3 actor.
pub type Event {
  Http3Event(http3_state.Event)
  DataFrameParsed(stream_id: Int, payload_bytes: Int)
  StreamWasReset(stream_id: Int, application_error_code: Int)
  PushStreamWasReset(push_id: Int, stream_id: Int, application_error_code: Int)
  EarlyDataWasAccepted
  EarlyDataWasRejected
  NewTokenReceived(BitArray)
  SessionTicketStored(ResumptionTicket)
  PathValidated
  ConnectionTerminated
  IgnoredTransportEvent
}

/// Typed events produced only by public core accept/read operations.
pub type NetworkEvent {
  PeerStream(core_client.Stream)
  StreamData(stream_id: Int, bytes: BitArray, finished: Bool)
  StreamReset(stream_id: Int, application_error_code: Int)
  DatagramReceived(BitArray)
  TicketReceived(core_client.ResumptionTicket)
  ReaderFinished
  CoreConnectionClosed
}

/// Stable congestion algorithms accepted by the HTTP/3 actor boundary.
pub type CongestionAlgorithm {
  NewReno
  Cubic
}

/// Stable operation failures that need public HTTP/3 error mapping.
pub type OperationFailure {
  DatagramsNotNegotiated
  DatagramTooLarge(maximum: Int)
  CongestionLimited
}

/// Pure decision used by the bounded peer-SETTINGS wait loop.
@internal
pub type SettingsWaitDecision {
  SettingsReady
  WaitForSettings(remaining_milliseconds: Int)
  SettingsWaitExpired
}

/// Connection policy after public HTTP/3 input validation.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    address_family: AddressFamily,
    connect_address: Option(BitArray),
    dns_timeout_milliseconds: Int,
    connect_timeout_milliseconds: Int,
    handshake_timeout_milliseconds: Int,
    timeout_milliseconds: Int,
    idle_timeout_milliseconds: Int,
    ca_certificates: Option(List(BitArray)),
    http_datagrams: Bool,
    resumption_ticket: Option(ResumptionTicket),
    address_token: BitArray,
    maximum_pushes: Int,
    quic_version: Version,
    stream_buffer_limit: Int,
    endpoint_memory_limit: Int,
    bidirectional_stream_limit: Int,
    unidirectional_stream_limit: Int,
    frame_limit: Int,
    datagram_limit: Int,
    qpack_table_limit: Int,
    qpack_blocked_stream_limit: Int,
    telemetry_limit: Int,
    qlog_directory: String,
    connect_port: Int,
    connect_trace: Option(qlog.ConnectTrace),
    qlog_reservation: Option(qlog_admission.Reservation),
  )
}

type CoreResource {
  CoreResource(
    connection: core_client.Connection,
    streams: Dict(Int, core_client.Stream),
  )
}

/// An established public-core connection and HTTP/3 session.
pub opaque type State {
  State(
    session: protocol.State(CoreResource),
    network: Subject(NetworkEvent),
    events: List(Event),
    hostname: String,
    port: Int,
    early_data: qlog.EarlyDataStatus,
    resumption: qlog.ResumptionStatus,
    active_readers: Int,
    core_closed: Bool,
    pending_ticket: Option(core_client.ResumptionTicket),
    qlog_reservation: Option(qlog_admission.Reservation),
  )
}

/// Opaque capability for waiting on one core stream's local send direction without blocking the HTTP/3 connection actor.
pub opaque type SendCompletionHandle {
  SendCompletionHandle(stream: core_client.Stream)
}

/// Runtime traffic counters owned by the core connection actor.
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

/// Stable reusable-connection failures.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  DnsTimeout
  ConnectTimeout
  HandshakeTimeout
  OperationTimeout
  TotalTimeout
  TrustStoreFailed
  TlsHandshakeFailed
  QuicTransportFailed(operation: String)
  CoreFailure(core_failure.Failure)
  Http3OperationFailed(operation: String, error: protocol.Error)
  PeerClosed
  MigrationUnavailable
  VersionNegotiationReceived(List(Version))
  VersionNegotiationFailed
}

/// Return whether this ticket permits an explicit 0-RTT attempt.
pub fn resumption_ticket_allows_early_data(ticket: ResumptionTicket) -> Bool {
  core_client.resumption_ticket_allows_zero_rtt(ticket.ticket)
  && case remembered_peer_settings(ticket) {
    Ok(_) -> True
    Error(_) -> False
  }
}

/// Return the authenticated origin name retained in a ticket.
pub fn resumption_ticket_server_name(ticket: ResumptionTicket) -> String {
  let #(hostname, _) = core_client.resumption_ticket_origin(ticket.ticket)
  hostname
}

/// Return the authenticated origin port retained in a ticket.
pub fn resumption_ticket_port(ticket: ResumptionTicket) -> Int {
  let #(_, port) = core_client.resumption_ticket_origin(ticket.ticket)
  port
}

/// Return whether opaque resumption state is origin-bound.
///
/// The core authenticates expiry again when the ticket is attached.
/// This predicate intentionally exposes no TLS ticket fields.
pub fn resumption_ticket_is_usable(
  ticket: ResumptionTicket,
  _now_milliseconds: Int,
  server_name: String,
  _alpn: BitArray,
  _quic_version: Int,
) -> Bool {
  let #(hostname, port) = core_client.resumption_ticket_origin(ticket.ticket)
  hostname == server_name && port > 0
}

/// Export the complete core-owned ticket/token envelope at deterministic qualification clocks.
pub fn export_stored_resumption_ticket(
  ticket: ResumptionTicket,
  key: BitArray,
  monotonic_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(BitArray, ResumptionTicketError) {
  use storage_key <- result.try(
    core_client.ticket_storage_key(key)
    |> result.replace_error(InvalidResumptionTicketKey),
  )
  core_client.export_resumption_ticket_at(
    ticket.ticket,
    storage_key,
    monotonic_milliseconds,
    unix_milliseconds,
  )
  |> map_ticket_result
}

/// Authenticate and restore the complete core-owned ticket/token envelope.
pub fn import_stored_resumption_ticket(
  stored: BitArray,
  key: BitArray,
  monotonic_milliseconds: Int,
  unix_milliseconds: Int,
) -> Result(ResumptionTicket, ResumptionTicketError) {
  use storage_key <- result.try(
    core_client.ticket_storage_key(key)
    |> result.replace_error(InvalidResumptionTicketKey),
  )
  core_client.import_resumption_ticket_at(
    stored,
    storage_key,
    monotonic_milliseconds,
    unix_milliseconds,
  )
  |> map_ticket_result
  |> result.map(ResumptionTicket)
}

fn map_ticket_result(
  value: Result(value, core_client.Error),
) -> Result(value, ResumptionTicketError) {
  case value {
    Ok(value) -> Ok(value)
    Error(core_client.ExpiredStoredTicket) -> Error(ExpiredResumptionTicket)
    Error(core_client.StoredTicketClockRollback) ->
      Error(InvalidResumptionTicketTimestamp)
    Error(core_client.TicketCryptoUnavailable) ->
      Error(ResumptionTicketCryptoUnavailable)
    Error(_) -> Error(InvalidResumptionTicket)
  }
}

/// Resolve, authenticate, and establish one reusable public-core connection.
pub fn connect(config: Config) -> Result(State, Error) {
  connect_with_resource(config, core_resource())
}

/// Exercise the production startup/cleanup path with a deterministic failure while opening the third mandatory HTTP/3 critical stream.
/// This seam carries no endpoint data or mutable global state and is visible only to this package's lifecycle tests.
@internal
pub fn connect_with_third_critical_stream_failure(
  config: Config,
) -> Result(State, Error) {
  connect_with_resource(config, core_resource_with_third_critical_failure())
}

fn connect_with_resource(
  config: Config,
  resource_driver: protocol.Resource(CoreResource),
) -> Result(State, Error) {
  use Nil <- result.try(validate(config))
  use configured <- result.try(core_configuration(config))
  use connection <- result.try(
    core_client.connect(configured) |> result.map_error(map_core_error),
  )
  use Nil <- result.try(begin_adapter_diagnostics(
    connection,
    config.qlog_reservation,
  ))
  let outcome = start_http3_session(config, connection, resource_driver)
  case outcome {
    Ok(state) -> Ok(state)
    Error(error) -> {
      close_failed_start(connection)
      Error(error)
    }
  }
}

fn start_http3_session(
  config: Config,
  connection: core_client.Connection,
  resource_driver: protocol.Resource(CoreResource),
) -> Result(State, Error) {
  let network = process.new_subject()
  let resource = CoreResource(connection, dict.new())
  let #(early_data, resumption) = case
    core_client.handshake_attempt(connection)
  {
    Ok(qlog.HandshakeAttempt(_, _, _, early, resumed)) -> #(early, resumed)
    Error(_) -> #(qlog.NotAttempted, qlog.ResumptionNotAttempted)
  }
  use session <- result.try(
    protocol.start(
      resource_driver,
      resource,
      client_http3_config(config, early_data),
      config.http_datagrams,
    )
    |> result.map_error(fn(error) { Http3OperationFailed("start", error) }),
  )
  let state =
    State(
      session,
      network,
      [],
      config.hostname,
      config.port,
      early_data,
      resumption,
      0,
      False,
      None,
      config.qlog_reservation,
    )
  process.spawn_unlinked(fn() { accept_streams(connection, network) })
  process.spawn_unlinked(fn() { await_ticket(connection, network) })
  case config.http_datagrams {
    True ->
      process.spawn_unlinked(fn() { receive_datagrams(connection, network) })
    False -> process.spawn_unlinked(fn() { Nil })
  }
  use state <- result.try(case config.resumption_ticket {
    Some(ticket) ->
      case resumption_ticket_allows_early_data(ticket) {
        True -> Ok(state)
        False ->
          await_peer_settings(
            state,
            qlog.monotonic_milliseconds()
              + config.handshake_timeout_milliseconds,
          )
      }
    None ->
      await_peer_settings(
        state,
        qlog.monotonic_milliseconds() + config.handshake_timeout_milliseconds,
      )
  })
  case config.maximum_pushes {
    0 -> Ok(state)
    maximum ->
      protocol.permit_pushes(state.session, maximum - 1)
      |> result.map(fn(session) { State(..state, session: session) })
      |> result.map_error(fn(error) {
        Http3OperationFailed("permit_pushes", error)
      })
  }
}

fn begin_adapter_diagnostics(
  connection: core_client.Connection,
  reservation: Option(qlog_admission.Reservation),
) -> Result(Nil, Error) {
  case qlog_admission.begin_open(reservation) {
    Ok(Nil) -> Ok(Nil)
    Error(Nil) -> {
      let _ = core_client.close(connection)
      Error(CoreFailure(core_failure.Cancelled))
    }
  }
}

fn close_failed_start(connection: core_client.Connection) -> Nil {
  case core_client.close(connection) {
    Ok(core_client.Closed) | Ok(core_client.AlreadyClosed) | Error(_) -> Nil
  }
}

/// Subject selected by the owning HTTP/3 actor; it carries no raw mailbox payload and is never part of the package's public interface.
pub fn network_events(state: State) -> Subject(NetworkEvent) {
  state.network
}

/// Use the connection's funded trace without creating another writer.
pub fn application_diagnostics(
  state: State,
) -> Result(Option(qlog.ApplicationSink), Error) {
  core_client.application_diagnostics(core_connection(state))
  |> result.map_error(map_core_error)
}

/// Query the same core-owned queue used by transport and application events.
pub fn telemetry_stats(state: State) -> Result(#(Int, Int, Int), Error) {
  core_client.telemetry_stats(core_connection(state))
  |> result.map(fn(stats) {
    let qlog.TelemetryStats(dropped, errors, queued) = stats
    #(dropped, errors, queued)
  })
  |> result.map_error(map_core_error)
}

/// Open a request stream and queue its initial HEADERS frame.
pub fn open_request(
  state: State,
  headers: List(Header),
  allow_qpack_blocking: Bool,
  _timeout_milliseconds: Int,
) -> Result(#(State, Int), Error) {
  use #(session, identifier) <- result.try(
    protocol.open_request(state.session, headers, allow_qpack_blocking)
    |> map_protocol_result("open_request"),
  )
  use stream <- result.try(
    find_stream(protocol.connection(session), identifier)
    |> result.replace_error(QuicTransportFailed("open_request")),
  )
  process.spawn_unlinked(fn() { read_stream(stream, state.network) })
  Ok(#(
    State(..state, session: session, active_readers: state.active_readers + 1),
    identifier,
  ))
}

/// Public core connect returns only when application streams are usable.
pub fn request_streams_available(_state: State) -> Bool {
  True
}

/// Return whether actor-owned state can still accept a future request stream.
///
/// Stream credit is deliberately excluded: temporary flow-control pressure does not make an otherwise open connection stale.
pub fn connection_reusable(state: State) -> Bool {
  !state.core_closed && protocol.drain_phase(state.session) == drain.Open
}

/// Return only the scalar core terminal state for lifecycle coordination.
@internal
pub fn terminated(state: State) -> Bool {
  state.core_closed
}

/// Queue the client-role initial GOAWAY on the critical control stream.
pub fn start_drain(
  state: State,
  now_milliseconds: Int,
) -> Result(State, Error) {
  protocol.start_drain(state.session, now_milliseconds)
  |> map_session("start_drain", state)
}

/// Queue the final client GOAWAY Push ID cutoff.
pub fn refine_drain(
  state: State,
  push_id: Int,
) -> Result(#(State, List(Int)), Error) {
  protocol.refine_drain(state.session, push_id)
  |> result.map(fn(value) {
    let #(session, rejected) = value
    #(State(..state, session: session), rejected)
  })
  |> result.map_error(map_protocol_error("refine_drain"))
}

/// Mark the HTTP/3 drain closed immediately before exact H3_NO_ERROR close.
pub fn close_drained(state: State) -> Result(State, Error) {
  protocol.close_drained(state.session)
  |> map_session("close_drained", state)
}

/// Forget one application-terminal public-core stream handle.
///
/// The core connection actor and transport retain whatever acknowledgement or retransmission state is still required; this adapter no longer needs the opaque handle once its HTTP/3 stream has reached a terminal result.
pub fn retire_stream(state: State, stream_id: Int) -> State {
  let resource = protocol.connection(state.session)
  let resource =
    CoreResource(..resource, streams: dict.delete(resource.streams, stream_id))
  State(..state, session: protocol.with_connection(state.session, resource))
}

/// Capture one existing core stream before the HTTP/3 actor retires it.
pub fn send_completion_handle(
  state: State,
  stream_id: Int,
) -> Result(SendCompletionHandle, Error) {
  find_stream(protocol.connection(state.session), stream_id)
  |> result.map(SendCompletionHandle)
  |> result.replace_error(QuicTransportFailed("send_completion"))
}

/// Wait for the core transport to acknowledge the stream FIN.
///
/// STOP_SENDING and local reset are terminal but do not prove delivery, so they remain failures at this adapter boundary.
pub fn await_send_completion(
  handle: SendCompletionHandle,
  within_milliseconds: Int,
) -> Result(Nil, Error) {
  let SendCompletionHandle(stream) = handle
  case core_client.await_send_completion(stream, within_milliseconds) {
    Ok(core_client.SendAcknowledged) -> Ok(Nil)
    Ok(core_client.SendStopped(_)) | Ok(core_client.SendReset(_)) ->
      Error(QuicTransportFailed("send_completion"))
    Error(error) -> Error(map_core_error(error))
  }
}

/// Snapshot retained stream resources across the adapter, actor, transport,
/// parser, and HTTP/3 state machine without exposing identifiers or payloads.
pub fn resource_stats(
  state: State,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int), Error) {
  let resource = protocol.connection(state.session)
  use core_stats <- result.try(
    core_client.resource_stats(resource.connection)
    |> result.map_error(map_core_error),
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

/// Payload-free acknowledgement barrier for an orderly HTTP/3 close.
@internal
pub fn application_send_settled(state: State) -> Result(Bool, Error) {
  core_client.application_send_settled(core_connection(state))
  |> result.map_error(map_core_error)
}

/// Queue one bounded HTTP DATA frame.
pub fn send_data(
  state: State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(State, Error) {
  protocol.send_data(state.session, stream_id, bytes)
  |> map_session("send_data", state)
}

/// Queue request trailers without finishing.
pub fn send_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  protocol.send_trailers(state.session, stream_id, headers, False)
  |> map_session("send_trailers", state)
}

/// Queue request trailers and FIN atomically at the HTTP/3 layer.
pub fn finish_with_trailers(
  state: State,
  stream_id: Int,
  headers: List(Header),
) -> Result(State, Error) {
  use state <- result.try(send_trailers(state, stream_id, headers))
  finish_stream(state, stream_id)
}

/// Validate local request framing and queue FIN.
pub fn finish_stream(state: State, stream_id: Int) -> Result(State, Error) {
  protocol.finish_stream(state.session, stream_id)
  |> map_session("finish_stream", state)
}

/// Abort both stream directions with an HTTP/3 application code.
pub fn abort_stream(
  state: State,
  stream_id: Int,
  application_error_code: Int,
) -> Result(State, Error) {
  protocol.abort_stream(state.session, stream_id, application_error_code)
  |> map_session("abort_stream", state)
}

/// Retire an application cancellation after the core has already confirmed the transport direction terminal.
/// Preserve QPACK feedback write failures.
pub fn retire_aborted_stream(
  state: State,
  stream_id: Int,
) -> Result(State, Error) {
  protocol.retire_aborted_stream(state.session, stream_id)
  |> map_session("retire_aborted_stream", state)
}

/// Cancel one promised push.
pub fn cancel_push(state: State, push_id: Int) -> Result(State, Error) {
  protocol.cancel_push(state.session, push_id)
  |> map_session("cancel_push", state)
}

/// Return whether both QUIC and HTTP/3 Datagram settings were negotiated.
pub fn datagrams_available(state: State) -> Bool {
  protocol.datagrams_available(state.session)
}

/// Public core connections support authenticated active migration.
pub fn active_migration_available(state: State) -> Bool {
  core_client.phase(core_connection(state)) == Ok(qlog.Established)
}

/// Return the largest HTTP Datagram payload for one request stream.
pub fn maximum_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  protocol.maximum_http_datagram_size(state.session, stream_id)
  |> result.map_error(map_protocol_error("maximum_http_datagram_size"))
}

/// Return the request payload ceiling stable across ACK and path changes.
pub fn guaranteed_http_datagram_size(
  state: State,
  stream_id: Int,
) -> Result(Int, Error) {
  protocol.guaranteed_http_datagram_size(state.session, stream_id)
  |> result.map_error(map_protocol_error("guaranteed_http_datagram_size"))
}

/// Queue one HTTP Datagram through the public QUIC connection.
pub fn send_http_datagram(
  state: State,
  stream_id: Int,
  payload: BitArray,
) -> Result(State, Error) {
  protocol.send_http_datagram(state.session, stream_id, payload)
  |> map_session("send_http_datagram", state)
}

/// Queue a request PRIORITY_UPDATE.
pub fn set_request_priority(
  state: State,
  stream_id: Int,
  urgency: Int,
  incremental: Bool,
) -> Result(State, Error) {
  protocol.set_request_priority(state.session, stream_id, urgency, incremental)
  |> map_session("set_request_priority", state)
}

/// Queue one public-core PING.
pub fn ping(state: State) -> Result(State, Error) {
  core_client.ping(core_connection(state))
  |> result.map(fn(_) { state })
  |> result.map_error(map_core_error)
}

/// Change the live congestion controller.
pub fn set_congestion_algorithm(
  state: State,
  algorithm: CongestionAlgorithm,
) -> Result(State, Error) {
  core_client.set_congestion_control(core_connection(state), case algorithm {
    NewReno -> quic_core.NewReno
    Cubic -> quic_core.Cubic
  })
  |> result.map(fn(_) { state })
  |> result.map_error(map_core_error)
}

/// Return the full core-validated path MTU.
pub fn path_mtu(state: State) -> Int {
  core_client.path_mtu(core_connection(state)) |> result.unwrap(1200)
}

pub fn handshake_established(state: State) -> Bool {
  core_client.phase(core_connection(state)) == Ok(qlog.Established)
}

pub fn resumed(state: State) -> Bool {
  case core_client.handshake_attempt(core_connection(state)) {
    Ok(qlog.HandshakeAttempt(_, _, _, _, qlog.Resumed)) -> True
    _ -> False
  }
}

/// Snapshot the core actor's current 0-RTT outcome.
///
/// This direct query closes the race where the HTTP actor is idle while the independently owned QUIC actor completes its handshake.
pub fn early_data_status(state: State) -> qlog.EarlyDataStatus {
  case core_client.handshake_attempt(core_connection(state)) {
    Ok(qlog.HandshakeAttempt(_, _, _, status, _)) -> status
    Error(_) -> state.early_data
  }
}

/// Snapshot the core client's non-secret handshake intent and current result.
pub fn handshake_attempt(state: State) -> Result(qlog.HandshakeAttempt, Error) {
  core_client.handshake_attempt(core_connection(state))
  |> result.map_error(map_core_error)
}

/// Snapshot RTT and congestion state.
pub fn path_stats(state: State) -> qlog.PathStats {
  core_client.path_stats(core_connection(state))
  |> result.unwrap(qlog.PathStats(0, 0, 0, 0, 0, 0, False, False))
}

/// Snapshot public-core runtime traffic counters.
pub fn stats(state: State) -> Stats {
  case core_client.connection_stats(core_connection(state)) {
    Ok(qlog.ConnectionStats(a, b, c, d, e, f, g, h)) ->
      Stats(a, b, c, d, e, f, g, h)
    Error(_) -> Stats(0, 0, 0, 0, 0, 0, 0, 0)
  }
}

/// Validate a new local path and emit only the bounded semantic outcome.
pub fn migrate(state: State) -> Result(State, Error) {
  core_client.migrate(core_connection(state))
  |> result.map(fn(_) {
    State(..state, events: list.append(state.events, [PathValidated]))
  })
  |> result.map_error(map_core_error)
}

/// Pull and clear ordered HTTP/3 and core lifecycle events.
pub fn take_events(state: State) -> #(State, List(Event)) {
  let #(session, protocol_events) = protocol.take_events(state.session)
  let events =
    list.map(protocol_events, fn(event) {
      case event {
        protocol.Http3Event(event) -> Http3Event(event)
        protocol.DataFrameParsed(identifier, bytes) ->
          DataFrameParsed(identifier, bytes)
        protocol.MessageStreamWasRejected(
          protocol.RequestStream,
          identifier,
          code,
        ) -> StreamWasReset(identifier, code)
        protocol.MessageStreamWasRejected(
          protocol.PushStream(push_id),
          identifier,
          code,
        ) -> PushStreamWasReset(push_id, identifier, code)
      }
    })
  let state = refresh_status(State(..state, session: session))
  #(State(..state, events: []), list.append(state.events, events))
}

/// Wait for and process one bounded typed core event.
pub fn pump(state: State, timeout_milliseconds: Int) -> Result(State, Error) {
  case
    process.receive(state.network, within: int.max(0, timeout_milliseconds))
  {
    Ok(event) -> receive_active(state, event)
    Error(_) -> Ok(state)
  }
}

/// Core actors drive their own timers and output.
pub fn drive(state: State) -> Result(State, Error) {
  Ok(state)
}

/// Core actors own their next deadline.
pub fn next_deadline(_state: State, _now: Int) -> Result(Option(Int), Error) {
  Ok(None)
}

/// Typed subjects are always active; no raw socket activation crosses here.
pub fn activate_once(_state: State) -> Result(Nil, Error) {
  Ok(Nil)
}

/// Consume one typed event produced by public accept/read operations.
pub fn receive_active(
  state: State,
  event: NetworkEvent,
) -> Result(State, Error) {
  let state = refresh_status(state)
  use state <- result.try(synchronise_zero_rtt(state))
  case event {
    PeerStream(stream) -> receive_peer_stream(state, stream)
    StreamData(identifier, bytes, finished) ->
      case
        protocol.receive_active_stream(
          state.session,
          identifier,
          bytes,
          finished,
          qlog.monotonic_milliseconds(),
        )
      {
        Ok(protocol.StreamReceived(session)) ->
          map_session(Ok(session), "receive_stream", state)
        Ok(protocol.MessageStreamAborted(session, protocol.RequestStream, code)) ->
          map_session(Ok(session), "receive_stream", state)
          |> result.map(fn(state) {
            State(
              ..state,
              events: list.append(state.events, [
                StreamWasReset(identifier, code),
              ]),
            )
          })
        Ok(protocol.MessageStreamAborted(
          session,
          protocol.PushStream(push_id),
          code,
        )) ->
          map_session(Ok(session), "receive_stream", state)
          |> result.map(fn(state) {
            State(
              ..state,
              events: list.append(state.events, [
                PushStreamWasReset(push_id, identifier, code),
              ]),
            )
          })
        Error(error) -> map_session(Error(error), "receive_stream", state)
      }
    StreamReset(identifier, code) -> {
      use state <- result.try(
        protocol.receive_reset(state.session, identifier)
        |> map_session("receive_reset", state),
      )
      use state <- result.try(cancel_after_peer_reset(state, identifier))
      Ok(
        State(
          ..state,
          events: list.append(state.events, [StreamWasReset(identifier, code)]),
        ),
      )
    }
    DatagramReceived(bytes) ->
      protocol.receive_datagram(state.session, bytes)
      |> map_session("receive_datagram", state)
    TicketReceived(ticket) ->
      complete_pending_ticket(State(..state, pending_ticket: Some(ticket)))
    ReaderFinished -> Ok(complete_reader(state))
    CoreConnectionClosed ->
      Ok(case state.core_closed, state.active_readers {
        True, _ -> state
        False, 0 ->
          State(
            ..state,
            core_closed: True,
            events: list.append(state.events, [ConnectionTerminated]),
          )
        False, _ -> State(..state, core_closed: True)
      })
  }
}

// The public HTTP stream becomes unusable when its response is reset.
// Close its local send direction before the actor discards the opaque core handle.
// The pure receive-reset transition alone intentionally preserves half-close.
fn cancel_after_peer_reset(
  state: State,
  identifier: Int,
) -> Result(State, Error) {
  // A late RESET can acknowledge a cancellation that already retired its handle.
  // It must not try a second resource abort on that missing handle.
  use <- bool.guard(
    when: !dict.has_key(protocol.connection(state.session).streams, identifier),
    return: Ok(state),
  )
  case abort_stream(state, identifier, 0x10c) {
    Error(Http3OperationFailed(
      _,
      protocol.ResourceFailure(protocol.ResourceStreamFinished),
    )) ->
      // A peer RESET has already ended receive, and the core independently confirms send is terminal.
      // QPACK retirement can still fail visibly.
      retire_aborted_stream(state, identifier)
    outcome -> outcome
  }
}

/// Close with a validated QUIC application code.
/// The legacy reason is intentionally ignored so no application payload enters transport logs.
pub fn close(
  state: State,
  application_error_code: Int,
  _reason: String,
) -> Nil {
  let _ = close_result(state, application_error_code)
  Nil
}

/// Preserve a diagnostic flush failure at successful public close boundaries.
pub fn close_result(
  state: State,
  application_error_code: Int,
) -> Result(Nil, Error) {
  case quic_core.application_error_code(application_error_code) {
    Error(_) -> Error(InvalidInput)
    Ok(code) ->
      case core_client.close_with_code(core_connection(state), code) {
        Ok(core_client.Closed) -> Ok(Nil)
        Ok(core_client.AlreadyClosed) -> Ok(Nil)
        Error(error) -> Error(map_core_error(error))
      }
  }
}

/// Return the connection-specific core actor share needed by an adapter-owned absolute close deadline.
/// Diagnostic flush has its separately exported allowance and both shares are consumed by `close_result_until`.
pub fn close_operation_allowance_milliseconds(state: State) -> Int {
  core_client.close_operation_allowance_milliseconds(core_connection(state))
}

/// Close transport and diagnostics under the HTTP/3 caller's existing absolute monotonic deadline.
/// Only the first core closer owns admission settlement; an idempotent result never releases the reservation twice.
pub fn close_result_until(
  state: State,
  application_error_code: Int,
  deadline_milliseconds: Int,
) -> Result(Nil, Error) {
  case quic_core.application_error_code(application_error_code) {
    Error(_) -> Error(InvalidInput)
    Ok(code) ->
      case
        core_client.close_with_code_until(
          core_connection(state),
          code,
          deadline_milliseconds,
        )
      {
        Ok(core_client.Closed) -> Ok(Nil)
        Ok(core_client.AlreadyClosed) -> Ok(Nil)
        Error(error) -> Error(map_core_error(error))
      }
  }
}

/// Return whether output should be retried after core backpressure.
pub fn is_send_pressure(error: Error) -> Bool {
  case error {
    Http3OperationFailed(
      _,
      protocol.ResourceFailure(protocol.ResourceSendLimited(_)),
    ) -> True
    _ -> False
  }
}

pub fn is_stream_send_buffer_full(error: Error) -> Bool {
  is_send_pressure(error)
}

/// Return a registered application close code only when authenticated peer protocol bytes caused the failure.
/// Local transport and lifecycle failures intentionally return `None`.
pub fn peer_application_error_code(error: Error) -> Option(Int) {
  case error {
    Http3OperationFailed(_, protocol_error) ->
      protocol.peer_application_error_code(protocol_error)
    _ -> None
  }
}

/// Classify stable application-facing operation failures.
pub fn operation_failure(error: Error) -> Option(OperationFailure) {
  case error {
    Http3OperationFailed(
      _,
      protocol.ResourceFailure(protocol.ResourceDatagramsNotNegotiated),
    ) -> Some(DatagramsNotNegotiated)
    Http3OperationFailed(
      _,
      protocol.ResourceFailure(protocol.ResourceDatagramTooLarge(maximum)),
    ) -> Some(DatagramTooLarge(maximum))
    _ -> None
  }
}

/// Validate a non-empty list of DER trust anchors through the public core.
pub fn valid_ca_certificates(certificates: List(BitArray)) -> Bool {
  core_client.new_with_ca_certificates_der("localhost", 443, "h3", certificates)
  |> result.is_ok
}

fn core_configuration(config: Config) -> Result(core_client.Client, Error) {
  let configured = case config.ca_certificates {
    None -> core_client.new(config.hostname, config.port, "h3")
    Some(certificates) ->
      core_client.new_with_ca_certificates_der(
        config.hostname,
        config.port,
        "h3",
        certificates,
      )
  }
  use client <- result.try(
    configured |> result.map_error(map_client_configuration_error),
  )
  let client = case qlog_admission.core_budget(config.qlog_reservation) {
    None -> client
    Some(diagnostic_budget) ->
      core_client.with_diagnostic_budget(client, diagnostic_budget)
  }
  let client = case config.connect_trace {
    None -> client
    Some(trace) -> core_client.with_connect_trace(client, trace)
  }
  use deadlines <- result.try(core_deadlines(config))
  use client <- result.try(
    core_client.with_connect_port(client, config.connect_port)
    |> result.map_error(map_client_configuration_error),
  )
  use limits <- result.try(core_limits(config))
  let client =
    client
    |> core_client.with_address_family(config.address_family)
    |> core_client.with_deadlines(deadlines)
    |> core_client.with_limits(limits)
    |> core_client.with_version(config.quic_version)
  use client <- result.try(case config.connect_address {
    None -> Ok(client)
    Some(bytes) -> {
      use address <- result.try(
        quic_core.ip_address(bytes) |> result.replace_error(ResolutionFailed),
      )
      Ok(core_client.with_connect_address(client, address))
    }
  })
  use client <- result.try(case config.resumption_ticket {
    None -> Ok(client)
    Some(ResumptionTicket(ticket)) ->
      core_client.with_resumption_ticket(client, ticket)
      |> result.map_error(map_client_configuration_error)
  })
  use client <- result.try(case config.qlog_directory {
    "" -> Ok(client)
    directory ->
      core_client.with_qlog(client, directory)
      |> result.map_error(map_client_configuration_error)
  })
  Ok(case config.resumption_ticket {
    Some(ticket) ->
      case resumption_ticket_allows_early_data(ticket) {
        True -> core_client.with_zero_rtt(client)
        False -> client
      }
    None -> client
  })
}

fn core_deadlines(config: Config) -> Result(core_config.Deadlines, Error) {
  let deadlines = core_config.default_deadlines()
  use deadlines <- result.try(set_deadline(
    deadlines,
    core_failure.Dns,
    config.dns_timeout_milliseconds,
  ))
  use deadlines <- result.try(set_deadline(
    deadlines,
    core_failure.Connect,
    config.connect_timeout_milliseconds,
  ))
  use deadlines <- result.try(set_deadline(
    deadlines,
    core_failure.Handshake,
    config.handshake_timeout_milliseconds,
  ))
  use deadlines <- result.try(set_deadline(
    deadlines,
    core_failure.Operation,
    config.timeout_milliseconds,
  ))
  use deadlines <- result.try(set_deadline(
    deadlines,
    core_failure.Idle,
    config.idle_timeout_milliseconds,
  ))
  set_deadline(deadlines, core_failure.Total, config.timeout_milliseconds)
}

fn set_deadline(
  deadlines: core_config.Deadlines,
  phase: core_failure.TimeoutPhase,
  milliseconds: Int,
) -> Result(core_config.Deadlines, Error) {
  core_config.with_deadline(deadlines, phase, milliseconds)
  |> result.replace_error(InvalidInput)
}

fn core_limits(config: Config) -> Result(core_config.Limits, Error) {
  let limits = core_config.default_limits()
  use limits <- result.try(set_limit(
    limits,
    core_failure.Buffer,
    // The HTTP response-consumer bound is enforced by `client_worker`.
    // QUIC still needs room for one permitted HTTP frame and handshake packets;
    // coupling its transport buffer to a tiny consumer queue can otherwise make a valid 1 KiB streaming policy unable to establish a connection.
    int.max(config.stream_buffer_limit, config.frame_limit),
  ))
  use limits <- result.try(set_limit(
    limits,
    core_failure.EndpointMemory,
    config.endpoint_memory_limit,
  ))
  use limits <- result.try(set_limit(
    limits,
    core_failure.Telemetry,
    config.telemetry_limit,
  ))
  use limits <- result.try(set_limit(
    limits,
    core_failure.BidirectionalStreams,
    config.bidirectional_stream_limit,
  ))
  use limits <- result.try(set_limit(
    limits,
    core_failure.UnidirectionalStreams,
    config.unidirectional_stream_limit,
  ))
  set_limit(limits, core_failure.Datagram, config.datagram_limit)
}

fn set_limit(
  limits: core_config.Limits,
  resource: core_failure.Resource,
  maximum: Int,
) -> Result(core_config.Limits, Error) {
  core_config.with_limit(limits, resource, maximum)
  |> result.replace_error(InvalidInput)
}

fn client_http3_config(
  config: Config,
  early_data: qlog.EarlyDataStatus,
) -> http3_state.Config {
  let base = http3_state.default_config(http3_state.Client)
  let remembered_peer_settings = case config.resumption_ticket {
    Some(ticket) ->
      case resumption_ticket_allows_early_data(ticket) {
        True -> remembered_peer_settings(ticket) |> result.unwrap(None)
        False -> None
      }
    None -> None
  }
  let settings =
    http3_state.Settings(
      ..base.settings,
      qpack_max_table_capacity: config.qpack_table_limit,
      qpack_blocked_streams: config.qpack_blocked_stream_limit,
      h3_datagram: config.http_datagrams,
      grease_sample: grease.runtime_sample(qlog.monotonic_milliseconds()),
    )
  http3_state.Config(
    ..base,
    settings: settings,
    remembered_peer_settings: remembered_peer_settings,
    zero_rtt_accepted: early_data == qlog.Accepted,
    preferred_qpack_table_capacity: config.qpack_table_limit,
    maximum_transactions: config.bidirectional_stream_limit,
    maximum_datagram_payload_bytes: config.datagram_limit,
    maximum_frame_payload_bytes: config.frame_limit,
  )
}

fn core_resource() -> protocol.Resource(CoreResource) {
  core_resource_with_optional_third_critical_failure(False)
}

fn core_resource_with_third_critical_failure() -> protocol.Resource(
  CoreResource,
) {
  core_resource_with_optional_third_critical_failure(True)
}

fn core_resource_with_optional_third_critical_failure(
  fail_third_critical_stream: Bool,
) -> protocol.Resource(CoreResource) {
  protocol.Resource(
    open_bidirectional: fn(resource: CoreResource) {
      use stream <- result.try(
        core_client.open_bidirectional(resource.connection)
        |> result.map_error(map_resource_error),
      )
      let identifier =
        core_client.stream_id(stream) |> quic_core.stream_id_value
      Ok(#(
        CoreResource(
          ..resource,
          streams: dict.insert(resource.streams, identifier, stream),
        ),
        identifier,
      ))
    },
    open_unidirectional: fn(resource: CoreResource) {
      // `protocol.start` opens exactly control, QPACK encoder, and QPACK decoder streams before returning.
      // The package-local fault therefore fails after two real streams exist and exercises their core cleanup.
      use <- bool.guard(
        when: fail_third_critical_stream && dict.size(resource.streams) == 2,
        return: Error(protocol.InvalidResourceOperation),
      )
      use stream <- result.try(
        core_client.open_unidirectional(resource.connection)
        |> result.map_error(map_resource_error),
      )
      let identifier =
        core_client.stream_id(stream) |> quic_core.stream_id_value
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
        empty, True ->
          case core_client.send_and_finish(stream, bytes) {
            Ok(Nil) -> Ok(Nil)
            Error(core_client.StreamFinished)
            | Error(core_client.StreamReset(_)) ->
              case empty {
                // GOAWAY can race a just-opened request: the peer's reset is the observable rejection, while the caller's empty FIN was already semantically committed at the HTTP layer.
                True -> Ok(Nil)
                False -> Error(protocol.ResourceStreamFinished)
              }
            Error(error) -> Error(map_resource_error(error))
          }
        _, False ->
          core_client.send(stream, bytes)
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
          fn() { core_client.reset(stream, code) },
          fn() { core_client.stop_sending(stream, code) },
        ),
      )
      Ok(resource)
    },
    send_datagram: fn(resource: CoreResource, bytes: BitArray) {
      core_client.send_datagram(resource.connection, bytes)
      |> result.map(fn(_) { resource })
      |> result.map_error(map_resource_error)
    },
    maximum_datagram_size: fn(resource: CoreResource) {
      core_client.maximum_datagram_size(resource.connection)
      |> result.map_error(map_resource_error)
    },
    guaranteed_datagram_size: fn(resource: CoreResource) {
      core_client.guaranteed_datagram_size(resource.connection)
      |> result.map_error(map_resource_error)
    },
  )
}

fn receive_peer_stream(
  state: State,
  stream: core_client.Stream,
) -> Result(State, Error) {
  let identifier = core_client.stream_id(stream) |> quic_core.stream_id_value
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
    |> result.map_error(map_protocol_error("register_peer_stream")),
  )
  process.spawn_unlinked(fn() { read_stream(stream, state.network) })
  Ok(State(..state, session: session, active_readers: state.active_readers + 1))
}

fn accept_streams(
  connection: core_client.Connection,
  network: Subject(NetworkEvent),
) -> Nil {
  case core_client.accept_stream_next(connection) {
    Ok(core_client.IncomingStream(stream, _)) -> {
      process.send(network, PeerStream(stream))
      accept_streams(connection, network)
    }
    Error(_) -> {
      process.send(network, CoreConnectionClosed)
    }
  }
}

fn read_stream(
  stream: core_client.Stream,
  network: Subject(NetworkEvent),
) -> Nil {
  let identifier = core_client.stream_id(stream) |> quic_core.stream_id_value
  case core_client.receive_next(stream, maximum_stream_read_bytes) {
    Ok(core_client.Data(bytes, finished)) -> {
      process.send(network, StreamData(identifier, bytes, finished))
      case finished {
        True -> process.send(network, ReaderFinished)
        False -> read_stream(stream, network)
      }
    }
    Ok(core_client.Finished) -> {
      process.send(network, StreamData(identifier, <<>>, True))
      process.send(network, ReaderFinished)
    }
    Ok(core_client.Reset(code)) -> {
      process.send(network, StreamReset(identifier, code))
      process.send(network, ReaderFinished)
    }
    Error(core_client.StreamReset(code)) -> {
      process.send(network, StreamReset(identifier, code))
      process.send(network, ReaderFinished)
    }
    // A local HTTP cancellation closes only this stream.
    // Its blocked reader must not turn that terminal stream result into a connection-wide close.
    Error(core_client.StreamFinished)
    | Error(core_client.InvalidDirection)
    | Error(core_client.InvalidOperation) ->
      process.send(network, ReaderFinished)
    Error(_) -> process.send(network, ReaderFinished)
  }
}

fn complete_reader(state: State) -> State {
  let active_readers = int.max(0, state.active_readers - 1)
  let state = State(..state, active_readers: active_readers)
  case state.core_closed, active_readers {
    True, 0 ->
      State(..state, events: list.append(state.events, [ConnectionTerminated]))
    _, _ -> state
  }
}

fn receive_datagrams(
  connection: core_client.Connection,
  network: Subject(NetworkEvent),
) -> Nil {
  case core_client.receive_datagram_next(connection) {
    Ok(bytes) -> {
      process.send(network, DatagramReceived(bytes))
      receive_datagrams(connection, network)
    }
    Error(_) -> Nil
  }
}

fn await_ticket(
  connection: core_client.Connection,
  network: Subject(NetworkEvent),
) -> Nil {
  case core_client.resumption_ticket_next(connection) {
    Ok(ticket) -> process.send(network, TicketReceived(ticket))
    Error(_) -> Nil
  }
}

fn await_peer_settings(state: State, deadline: Int) -> Result(State, Error) {
  case
    settings_wait_decision(
      protocol.peer_settings_received(state.session),
      qlog.monotonic_milliseconds(),
      deadline,
    )
  {
    SettingsReady -> Ok(state)
    SettingsWaitExpired -> Error(HandshakeTimeout)
    WaitForSettings(remaining) -> {
      use state <- result.try(pump(state, remaining))
      await_peer_settings(state, deadline)
    }
  }
}

/// Decide a SETTINGS wait from an injected monotonic time snapshot.
@internal
pub fn settings_wait_decision(
  received: Bool,
  now_milliseconds: Int,
  deadline_milliseconds: Int,
) -> SettingsWaitDecision {
  case received, deadline_milliseconds - now_milliseconds {
    True, _ -> SettingsReady
    False, remaining if remaining <= 0 -> SettingsWaitExpired
    False, remaining -> WaitForSettings(remaining)
  }
}

fn refresh_status(state: State) -> State {
  case status_refresh_needed(state.early_data, state.resumption) {
    False -> state
    True ->
      case core_client.handshake_attempt(core_connection(state)) {
        Error(_) -> state
        Ok(qlog.HandshakeAttempt(_, _, _, early, resumption)) -> {
          let events = case state.early_data, early {
            qlog.Pending, qlog.Accepted -> [EarlyDataWasAccepted]
            qlog.Pending, qlog.Rejected -> [EarlyDataWasRejected]
            _, _ -> []
          }
          State(
            ..state,
            events: list.append(state.events, events),
            early_data: early,
            resumption: resumption,
          )
        }
      }
  }
}

/// Whether the HTTP/3 actor still needs a bounded core handshake snapshot.
@internal
pub fn status_refresh_needed(
  early_data: qlog.EarlyDataStatus,
  resumption: qlog.ResumptionStatus,
) -> Bool {
  early_data == qlog.Pending || resumption == qlog.ResumptionPending
}

fn core_connection(state: State) -> core_client.Connection {
  let CoreResource(connection, _) = protocol.connection(state.session)
  connection
}

fn find_stream(
  resource: CoreResource,
  identifier: Int,
) -> Result(core_client.Stream, Nil) {
  dict.get(resource.streams, identifier)
}

fn map_session(
  value: Result(protocol.State(CoreResource), protocol.Error),
  operation: String,
  state: State,
) -> Result(State, Error) {
  use session <- result.try(
    value |> result.map_error(map_protocol_error(operation)),
  )
  complete_pending_ticket(State(..state, session: session))
}

fn synchronise_zero_rtt(state: State) -> Result(State, Error) {
  case state.early_data {
    qlog.Accepted ->
      protocol.accept_zero_rtt(state.session)
      |> map_session("accept_zero_rtt", state)
    _ -> Ok(state)
  }
}

fn complete_pending_ticket(state: State) -> Result(State, Error) {
  case state.pending_ticket {
    None -> Ok(state)
    Some(ticket) -> {
      use peer <- result.try(
        protocol.peer_settings_snapshot(state.session)
        |> result.map_error(map_protocol_error("remember_peer_settings")),
      )
      case peer {
        None -> Ok(state)
        Some(snapshot) -> {
          use encoded <- result.try(
            settings_memory.encode(snapshot)
            |> result.replace_error(QuicTransportFailed("ticket_settings")),
          )
          use ticket <- result.try(
            core_client.with_resumption_ticket_application_context(
              ticket,
              encoded,
            )
            |> result.map_error(map_core_error),
          )
          Ok(
            State(
              ..state,
              pending_ticket: None,
              events: list.append(state.events, [
                SessionTicketStored(ResumptionTicket(ticket)),
              ]),
            ),
          )
        }
      }
    }
  }
}

fn remembered_peer_settings(
  ticket: ResumptionTicket,
) -> Result(Option(settings_memory.Snapshot), settings_memory.Error) {
  let context = core_client.resumption_ticket_application_context(ticket.ticket)
  decode_remembered_settings_context(context)
}

/// Decode the HTTP/3-owned portion of a ticket with no TLS or clock effects.
/// Empty context is the RFC initial-settings fallback; every non-empty value must be the current canonical envelope.
@internal
pub fn decode_remembered_settings_context(
  context: BitArray,
) -> Result(Option(settings_memory.Snapshot), settings_memory.Error) {
  case context {
    <<>> -> Ok(None)
    _ -> settings_memory.decode(context) |> result.map(Some)
  }
}

fn map_protocol_result(
  value: Result(value, protocol.Error),
  operation: String,
) -> Result(value, Error) {
  value |> result.map_error(map_protocol_error(operation))
}

fn map_protocol_error(operation: String) -> fn(protocol.Error) -> Error {
  fn(error) { Http3OperationFailed(operation, error) }
}

/// Abort every direction that exists from the client's point of view.
///
/// A server-initiated unidirectional push stream has only a receive direction at the client, so RESET_STREAM is not called and STOP_SENDING is sufficient to isolate it.
/// Locally initiated unidirectional streams have only a send direction.
/// Bidirectional request streams retain the two-operation contract.
@internal
pub fn abort_stream_directions(
  identifier: Int,
  reset: fn() -> Result(Nil, core_client.Error),
  stop: fn() -> Result(Nil, core_client.Error),
) -> Result(Nil, protocol.ResourceError) {
  let stream_id = quic_core.StreamId(identifier)
  case
    quic_core.stream_direction(stream_id),
    quic_core.stream_initiator(stream_id)
  {
    quic_core.UnidirectionalStream, quic_core.ServerInitiated ->
      abort_direction_outcome(stop())
    quic_core.UnidirectionalStream, quic_core.ClientInitiated ->
      abort_direction_outcome(reset())
    quic_core.BidirectionalStream, _ -> abort_directions(reset, stop)
  }
}

/// Abort both QUIC stream directions even when one direction is already done.
///
/// A normal request commonly sends FIN before its response arrives.
/// A malformed response still requires STOP_SENDING, so the reset result cannot short-circuit the independent receive-direction operation.
pub fn abort_directions(
  reset: fn() -> Result(Nil, core_client.Error),
  stop: fn() -> Result(Nil, core_client.Error),
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
  outcome: Result(Nil, core_client.Error),
) -> Result(Nil, protocol.ResourceError) {
  case outcome {
    Ok(Nil)
    | Error(core_client.StreamFinished)
    | Error(core_client.StreamReset(_)) -> Ok(Nil)
    Error(error) -> Error(map_resource_error(error))
  }
}

fn map_resource_error(error: core_client.Error) -> protocol.ResourceError {
  case error {
    core_client.StreamFinished -> protocol.ResourceStreamFinished
    core_client.Failure(core_failure.Limit(core_failure.Buffer, maximum)) ->
      protocol.ResourceSendLimited(maximum)
    core_client.Failure(core_failure.Overload(_)) ->
      protocol.ResourceSendLimited(0)
    core_client.Failure(core_failure.Limit(core_failure.Datagram, maximum)) ->
      protocol.ResourceDatagramTooLarge(maximum)
    core_client.Failure(core_failure.Closed(_, _)) -> protocol.ResourceClosed
    core_client.InvalidDirection
    | core_client.InvalidOperation
    | core_client.ConcurrentOperation
    | core_client.StreamReset(_)
    | core_client.TicketUnavailable
    | core_client.InvalidStoredTicket
    | core_client.ExpiredStoredTicket
    | core_client.StoredTicketClockRollback
    | core_client.TicketCryptoUnavailable
    | core_client.Failure(_) -> protocol.InvalidResourceOperation
  }
}

fn map_core_error(error: core_client.Error) -> Error {
  case error {
    core_client.Failure(core_failure.Resolution) -> ResolutionFailed
    core_client.Failure(core_failure.Socket(_)) as error -> core_error(error)
    core_client.Failure(core_failure.Timeout(core_failure.Dns)) -> DnsTimeout
    core_client.Failure(core_failure.Timeout(core_failure.Connect)) ->
      ConnectTimeout
    core_client.Failure(core_failure.Timeout(core_failure.Handshake)) ->
      HandshakeTimeout
    core_client.Failure(core_failure.Timeout(core_failure.Operation)) ->
      OperationTimeout
    core_client.Failure(core_failure.Timeout(core_failure.Total)) ->
      TotalTimeout
    core_client.Failure(core_failure.Timeout(core_failure.Idle)) -> PeerClosed
    core_client.Failure(core_failure.Timeout(core_failure.Drain)) ->
      OperationTimeout
    core_client.Failure(core_failure.Tls(_)) -> TlsHandshakeFailed
    core_client.Failure(core_failure.Closed(_, Some(_))) as error ->
      core_error(error)
    core_client.Failure(core_failure.Closed(_, None)) -> PeerClosed
    core_client.Failure(core_failure.Quic(_, Some(_))) as error ->
      core_error(error)
    core_client.Failure(core_failure.Quic(_, None)) ->
      QuicTransportFailed("quic")
    core_client.Failure(core_failure.Overload(_)) as error -> core_error(error)
    core_client.Failure(core_failure.Limit(_, _)) as error -> core_error(error)
    core_client.Failure(core_failure.Cancelled) -> PeerClosed
    core_client.InvalidOperation -> InvalidInput
    core_client.InvalidDirection
    | core_client.StreamFinished
    | core_client.ConcurrentOperation
    | core_client.StreamReset(_) -> QuicTransportFailed("stream")
    core_client.TicketUnavailable -> QuicTransportFailed("ticket")
    core_client.InvalidStoredTicket
    | core_client.ExpiredStoredTicket
    | core_client.StoredTicketClockRollback
    | core_client.TicketCryptoUnavailable -> QuicTransportFailed("ticket_store")
  }
}

fn core_error(error: core_client.Error) -> Error {
  case error {
    core_client.Failure(failure) -> CoreFailure(failure)
    _ -> QuicTransportFailed("core")
  }
}

fn map_client_configuration_error(
  error: core_client.ConfigurationError,
) -> Error {
  case error {
    core_client.InvalidHost | core_client.InvalidPort(_) -> InvalidInput
    core_client.InvalidApplicationProtocol -> InvalidInput
    core_client.TrustStoreUnavailable -> TrustStoreFailed
    core_client.InvalidCaCertificate -> TrustStoreFailed
    core_client.InvalidClientCertificate
    | core_client.InvalidClientPrivateKey
    | core_client.IncompatibleClientPrivateKey -> TlsHandshakeFailed
    core_client.InvalidQlogDirectory -> InvalidInput
    core_client.InvalidTicketOrigin -> TlsHandshakeFailed
    core_client.InvalidTicketStorageKey -> InvalidInput
  }
}

fn validate(config: Config) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.dns_timeout_milliseconds > 0
    && config.connect_timeout_milliseconds > 0
    && config.handshake_timeout_milliseconds > 0
    && config.timeout_milliseconds > 0
    && config.idle_timeout_milliseconds > 0
    && config.stream_buffer_limit > 0
    && config.bidirectional_stream_limit > 0
    && config.unidirectional_stream_limit >= 3
    && config.frame_limit > 0
    && config.datagram_limit > 0
    && config.qpack_table_limit > 0
    && config.qpack_blocked_stream_limit > 0
    && config.telemetry_limit > 0
    && config.maximum_pushes >= 0
    && config.maximum_pushes <= 1024
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}
