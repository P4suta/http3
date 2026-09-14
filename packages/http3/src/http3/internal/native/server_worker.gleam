//// Supervised HTTP/3 listener and per-connection actors over public QUIC.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/internal/native/connection_state as http3_state
import http3/internal/native/datagram
import http3/internal/native/header_semantics
import http3/internal/native/message_stream
import http3/internal/native/priority
import http3/internal/native/protocol
import http3/internal/native/server_connection
import http3/internal/native/terminal_registry
import http3/internal/process_label
import http3/internal/qpack/header.{type Header, Header}
import quic_core.{type AddressFamily}
import quic_core/config as core_config
import quic_core/diagnostics as qlog
import quic_core/failure as core_failure
import quic_core/server as core_server

const worker_reply_grace_milliseconds = 100

const maximum_response_data_chunk_bytes = 65_536

const maximum_terminal_handles = 1024

// During graceful drain, application completion is not transport completion:
// closing QUIC while the final response is still in flight lets the close
// packet overtake unread stream data at the peer. Poll only while draining and
// close after each successful request/push FIN is acknowledged. Connection-
// wide bytes-in-flight is deliberately not used because PMTU probes and other
// unrelated transport work may remain active throughout drain.
const drain_transport_poll_milliseconds = 10

const request_cancelled_code = 0x10c

const request_rejected_code = 0x10b

const excessive_load_code = 0x107

/// A finite caller-managed replay check retained by the public core listener.
pub opaque type ReplayGuard {
  ReplayGuard(server_connection.ReplayGuard)
}

/// Validate and retain an external atomic test-and-record callback.
pub fn new_replay_guard(
  timeout_milliseconds: Int,
  check: fn(BitArray, Int) -> Result(Bool, Nil),
) -> Result(ReplayGuard, Nil) {
  server_connection.new_replay_guard(timeout_milliseconds, check)
  |> result.map(ReplayGuard)
}

/// A parsed certificate chain and compatible signing key.
pub opaque type Credential {
  Credential(server_connection.Credential)
}

/// Stable credential-construction failures.
pub type CredentialError {
  InvalidCredentialCertificate
  InvalidCredentialPrivateKey
  IncompatibleCredentialPrivateKey
  InvalidCredentialServerName
}

/// Parse the listener's fallback certificate and key.
pub fn default_credential(
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Credential, CredentialError) {
  server_connection.default_credential(certificate_pem, private_key_pem)
  |> result.map(Credential)
  |> result.map_error(map_credential_error)
}

/// Parse one SNI-selected certificate and key.
pub fn named_credential(
  server_name: String,
  certificate_pem: BitArray,
  private_key_pem: BitArray,
) -> Result(Credential, CredentialError) {
  server_connection.named_credential(
    server_name,
    certificate_pem,
    private_key_pem,
  )
  |> result.map(Credential)
  |> result.map_error(map_credential_error)
}

/// Return the normalized SNI pattern retained by one named credential.
pub fn credential_server_name(credential: Credential) -> String {
  let Credential(credential) = credential
  server_connection.credential_server_name(credential)
}

pub fn valid_server_name(server_name: String) -> Bool {
  server_connection.valid_server_name(server_name)
}

pub fn valid_certificate(certificate_pem: BitArray) -> Bool {
  server_connection.valid_certificate(certificate_pem)
}

pub fn valid_private_key(private_key_pem: BitArray) -> Bool {
  server_connection.valid_private_key(private_key_pem)
}

fn map_credential_error(
  error: server_connection.CredentialError,
) -> CredentialError {
  case error {
    server_connection.InvalidCredentialCertificate ->
      InvalidCredentialCertificate
    server_connection.InvalidCredentialPrivateKey -> InvalidCredentialPrivateKey
    server_connection.IncompatibleCredentialPrivateKey ->
      IncompatibleCredentialPrivateKey
    server_connection.InvalidCredentialServerName -> InvalidCredentialServerName
  }
}

/// A running owner-bound listener actor.
pub opaque type Listener {
  Listener(
    commands: Subject(ListenerCommand),
    worker: Pid,
    timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
  )
}

/// One supervised HTTP/3 connection actor.
pub opaque type Connection {
  Connection(
    commands: Subject(ConnectionCommand),
    worker: Pid,
    timeout_milliseconds: Int,
  )
}

/// One accepted request routed directly to its connection actor.
pub opaque type Request {
  Request(connection: Connection, identifier: Int)
}

/// One promised server push routed directly to its connection actor.
pub opaque type Push {
  Push(connection: Connection, identifier: Int)
}

/// Primitive accepted request data.
pub type Incoming {
  Incoming(
    request: Request,
    method: String,
    path: String,
    protocol: Option(String),
    scheme: String,
    authority: String,
    headers: List(#(String, String)),
  )
}

/// Pull-based request-body events.
pub type Event {
  Data(BitArray)
  Trailers(List(#(String, String)))
  End
}

/// Idempotent accepted-request cancellation outcome.
pub type Cancellation {
  Cancelled
  AlreadyCancelled
  AlreadyCompleted
}

pub type StopResult {
  Stopped
  AlreadyStopped
}

pub type DrainResult {
  Drained
  Forced
  AlreadyDrained
}

/// Listener, connection, request, or bounded-resource failure.
pub type Error {
  InvalidInput
  StartFailed
  Timeout
  ListenerClosed
  ConnectionClosed
  StreamReset(Int)
  StreamCancelled(Int)
  ProtocolError(Int, String)
  RequestBodyTooLarge(Int)
  ResponseBodyTooLarge(Int)
  ConsumerTooSlow(Int)
  ConcurrentAccept
  ConcurrentDrain
  ConcurrentReceive
  ResponseAlreadyStarted
  ResponseNotStarted
  ResponseAlreadyFinished
  InvalidContentLength
  InvalidHeaderEncoding
  DatagramsNotNegotiated
  DatagramNotAssociated
  DatagramTooLarge(Int)
  DatagramBufferExceeded(Int)
  ConcurrentDatagramReceive
  CapsuleProtocolUnavailable
  StreamFinished
  PushCancelled
  CongestionLimited
  PathUnavailable
  QlogUnavailable
  ConcurrentSend
  PendingRequestLimitExceeded(Int)
  RequestEventQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  InvalidConnectionState
}

type ListenerCommand {
  Port(reply: Subject(Result(Int, Error)))
  ReloadCertificates(
    default: Credential,
    alternatives: List(Credential),
    reply: Subject(Result(Nil, Error)),
  )
  ReloadOperationalKeys(
    ticket_keys: List(BitArray),
    address_token_keys: List(BitArray),
    stateless_reset_keys: List(BitArray),
    reply: Subject(Result(Nil, Error)),
  )
  Accept(reply: Subject(Result(Incoming, Error)), deadline: Int)
  Stop(reply: Subject(Result(StopResult, Error)))
  GracefulStop(reply: Subject(Result(DrainResult, Error)), deadline: Int)
}

type ConnectionCommand {
  PeerEndpoint(reply: Subject(Result(#(BitArray, Int), Error)))
  Next(request_id: Int, reply: Subject(Result(Event, Error)), deadline: Int)
  CancelRequest(request_id: Int, reply: Subject(Result(Cancellation, Error)))
  SendResponse(
    request_id: Int,
    status: Int,
    headers: List(#(String, String)),
    declared_content_length: Option(Int),
    reply: Subject(Result(Nil, Error)),
  )
  Respond(
    request_id: Int,
    status: Int,
    headers: List(#(String, String)),
    body: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  SendInformational(
    request_id: Int,
    status: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  SendChunk(
    request_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  SendCapsule(
    request_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  FinishResponse(request_id: Int, reply: Subject(Result(Nil, Error)))
  FinishWithTrailers(
    request_id: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  PromisePush(
    request_id: Int,
    path: String,
    headers: List(#(String, String)),
    reply: Subject(Result(Int, Error)),
  )
  SendPushResponse(
    push_id: Int,
    status: Int,
    headers: List(#(String, String)),
    declared_content_length: Option(Int),
    reply: Subject(Result(Nil, Error)),
  )
  SendPushChunk(
    push_id: Int,
    bytes: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  FinishPush(push_id: Int, reply: Subject(Result(Nil, Error)))
  FinishPushWithTrailers(
    push_id: Int,
    headers: List(#(String, String)),
    reply: Subject(Result(Nil, Error)),
  )
  Capabilities(reply: Subject(Result(#(Bool, Bool, Bool, Bool), Error)))
  ProspectiveMaximumDatagram(
    request_id: Int,
    reply: Subject(Result(Int, Error)),
  )
  MaximumDatagram(request_id: Int, reply: Subject(Result(Int, Error)))
  GuaranteedDatagram(request_id: Int, reply: Subject(Result(Int, Error)))
  SendDatagram(
    request_id: Int,
    payload: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  NextDatagram(
    request_id: Int,
    reply: Subject(Result(BitArray, Error)),
    deadline: Int,
  )
  SetPriority(
    request_id: Int,
    urgency: Int,
    incremental: Bool,
    reply: Subject(Result(Nil, Error)),
  )
  GetPriority(request_id: Int, reply: Subject(Result(#(Int, Bool), Error)))
  EarlyData(reply: Subject(Result(server_connection.EarlyDataStatus, Error)))
  PathStats(reply: Subject(Result(qlog.PathStats, Error)))
  ConnectionStats(reply: Subject(Result(server_connection.Stats, Error)))
  TelemetryStats(reply: Subject(Result(#(Int, Int, Int), Error)))
  RequestStateStats(
    reply: Subject(
      Result(#(Int, Int, Int, Int, Int, Int, Int, Int, Int), Error),
    ),
  )
  MaximumTransmissionUnit(reply: Subject(Result(Int, Error)))
  RejectRequest(request_id: Int, code: Int, error: Error)
  BeginDrain
  StopConnection(reply: Subject(Result(Nil, Error)))
}

type ListenerNetwork {
  CoreAccepted(core_server.Connection)
  CoreListenerClosed
  PeerNotice(ConnectionNotice)
}

type ConnectionNotice {
  PeerStarted(identifier: Int, connection: Connection)
  RequestAvailable(Incoming)
  PeerDrained(identifier: Int)
  PeerStopped(identifier: Int)
}

type ListenerMessage {
  ReceivedListenerCommand(ListenerCommand)
  ReceivedListenerNetwork(ListenerNetwork)
  ListenerOwnerExited
}

type ConnectionMessage {
  ReceivedConnectionCommand(ConnectionCommand)
  ReceivedConnectionNetwork(server_connection.NetworkEvent)
  ConnectionOwnerExited
}

type AcceptWaiter {
  AcceptWaiter(reply: Subject(Result(Incoming, Error)), deadline: Int)
}

type EventWaiter {
  EventWaiter(reply: Subject(Result(Event, Error)), deadline: Int)
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Int)
}

type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
}

type ListenerDrain {
  ListenerDrain(
    reply: Subject(Result(DrainResult, Error)),
    deadline: Int,
    outstanding: Dict(Int, Nil),
  )
}

type ListenerWorker {
  ListenerWorker(
    core: core_server.Listener,
    port: Int,
    commands: Subject(ListenerCommand),
    selector: process.Selector(ListenerMessage),
    network: Subject(ListenerNetwork),
    connections: Dict(Int, Connection),
    next_connection_id: Int,
    pending: Queue(Incoming),
    accept_waiters: Queue(AcceptWaiter),
    drain: Option(ListenerDrain),
    timeout_milliseconds: Int,
    drain_timeout_milliseconds: Int,
    queue_limit: Int,
    accept_waiter_limit: Int,
    peer_config: PeerConfig,
  )
}

type RequestState {
  RequestState(
    stream_id: Int,
    method: String,
    path: String,
    protocol: Option(String),
    scheme: String,
    authority: String,
    headers: List(#(String, String)),
    capsule_candidate: Bool,
    capsule_established: Bool,
    events: Queue(Event),
    buffered_body_bytes: Int,
    received_body_bytes: Int,
    event_waiter: Option(EventWaiter),
    datagrams: Queue(BitArray),
    buffered_datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    request_finished: Bool,
    response_started: Bool,
    response_finished: Bool,
    response_body_bytes: Int,
    declared_content_length: Option(Int),
    priority: #(Int, Bool),
    failure: Option(Error),
  )
}

type RequestTerminal {
  RequestCompleted
  RequestFailed(Error)
}

type PushState {
  PushState(
    push_id: Int,
    stream_id: Int,
    response_started: Bool,
    response_finished: Bool,
    response_body_bytes: Int,
    declared_content_length: Option(Int),
    failure: Option(Error),
  )
}

type PeerConfig {
  PeerConfig(
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    http_datagrams: Bool,
    qlog_enabled: Bool,
    keepalive_milliseconds: Int,
    protocol: server_connection.Config,
  )
}

type ConnectionWorker {
  ConnectionWorker(
    identifier: Int,
    connection: server_connection.State,
    handle: Connection,
    commands: Subject(ConnectionCommand),
    selector: process.Selector(ConnectionMessage),
    notices: Subject(ListenerNetwork),
    requests: Dict(Int, RequestState),
    request_terminals: terminal_registry.Registry(RequestTerminal),
    pushes: Dict(Int, PushState),
    pending_priorities: Dict(Int, #(Int, Bool)),
    next_request_stream_id: Int,
    draining: Bool,
    drain_notified: Bool,
    closed: Bool,
    timeout_milliseconds: Int,
    request_body_limit: Int,
    response_body_limit: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    http_datagrams: Bool,
    qlog_enabled: Bool,
    keepalive_milliseconds: Int,
    next_keepalive_milliseconds: Int,
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Bind the public-core listener and start its owner-monitoring actor.
pub fn start(
  port: Int,
  bind_address: Option(BitArray),
  timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
  accept_waiter_limit: Int,
  default_credential: Credential,
  alternative_credentials: List(Credential),
  http_datagrams: Bool,
  keepalive_milliseconds: Int,
  address_family: AddressFamily,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  replay_guard: Option(ReplayGuard),
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(Listener, Error) {
  use Nil <- result.try(validate_start(
    port,
    bind_address,
    timeout_milliseconds,
    drain_timeout_milliseconds,
    idle_timeout_milliseconds,
    request_body_limit,
    response_body_limit,
    stream_buffer_limit,
    endpoint_memory_limit,
    connection_limit,
    handshake_limit,
    queue_limit,
    telemetry_limit,
    bidirectional_stream_limit,
    unidirectional_stream_limit,
    frame_limit,
    datagram_limit,
    qpack_table_limit,
    qpack_blocked_stream_limit,
    accept_waiter_limit,
    keepalive_milliseconds,
    ticket_keys,
    address_token_keys,
    stateless_reset_keys,
  ))
  let owner = process.self()
  let bootstrap = process.new_subject()
  let worker =
    process.spawn_unlinked(fn() {
      process_label.set(process_label.Listener)
      initialise_listener(
        owner,
        bootstrap,
        port,
        bind_address,
        timeout_milliseconds,
        drain_timeout_milliseconds,
        idle_timeout_milliseconds,
        request_body_limit,
        response_body_limit,
        stream_buffer_limit,
        endpoint_memory_limit,
        connection_limit,
        handshake_limit,
        queue_limit,
        telemetry_limit,
        bidirectional_stream_limit,
        unidirectional_stream_limit,
        frame_limit,
        datagram_limit,
        qpack_table_limit,
        qpack_blocked_stream_limit,
        accept_waiter_limit,
        default_credential,
        alternative_credentials,
        http_datagrams,
        keepalive_milliseconds,
        address_family,
        qlog_directory,
        allow_zero_rtt,
        replay_guard,
        ticket_keys,
        address_token_keys,
        stateless_reset_keys,
      )
    })
  await_bootstrap(
    worker,
    bootstrap,
    timeout_milliseconds + worker_reply_grace_milliseconds,
    StartFailed,
  )
}

pub fn port(listener: Listener) -> Result(Int, Error) {
  listener_call(listener, Port)
}

pub fn reload_certificates(
  listener: Listener,
  default_credential: Credential,
  alternative_credentials: List(Credential),
) -> Result(Nil, Error) {
  listener_call(listener, fn(reply) {
    ReloadCertificates(default_credential, alternative_credentials, reply)
  })
}

pub fn reload_operational_keys(
  listener: Listener,
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(Nil, Error) {
  let combined =
    list.append(
      ticket_keys,
      list.append(address_token_keys, stateless_reset_keys),
    )
  case
    ticket_keys != []
    && address_token_keys != []
    && stateless_reset_keys != []
    && valid_optional_key_ring(ticket_keys)
    && valid_optional_key_ring(address_token_keys)
    && valid_optional_key_ring(stateless_reset_keys)
    && all_keys_distinct(combined)
  {
    False -> Error(InvalidInput)
    True ->
      listener_call(listener, fn(reply) {
        ReloadOperationalKeys(
          ticket_keys,
          address_token_keys,
          stateless_reset_keys,
          reply,
        )
      })
  }
}

pub fn accept(listener: Listener) -> Result(Incoming, Error) {
  let deadline = now() + listener.timeout_milliseconds
  listener_call_with_timeout(
    listener,
    listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Accept(reply, deadline) },
  )
}

pub fn peer_endpoint(request: Request) -> Result(#(BitArray, Int), Error) {
  connection_call(request.connection, PeerEndpoint)
}

pub fn next_event(request: Request) -> Result(Event, Error) {
  let deadline = now() + request.connection.timeout_milliseconds
  connection_call_with_timeout(
    request.connection,
    request.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { Next(request.identifier, reply, deadline) },
  )
}

/// Cancel both directions of one accepted request stream idempotently.
pub fn cancel(request: Request) -> Result(Cancellation, Error) {
  connection_call(request.connection, fn(reply) {
    CancelRequest(request.identifier, reply)
  })
}

pub fn send_response(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SendResponse(
      request.identifier,
      status,
      headers,
      declared_content_length,
      reply,
    )
  })
}

pub fn respond(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    Respond(request.identifier, status, headers, body, reply)
  })
}

pub fn send_informational(
  request: Request,
  status: Int,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SendInformational(request.identifier, status, headers, reply)
  })
}

pub fn send_chunk(request: Request, bytes: BitArray) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SendChunk(request.identifier, bytes, reply)
  })
}

/// Queue Capsule Protocol bytes only after a valid Extended CONNECT response.
pub fn send_capsule(request: Request, bytes: BitArray) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SendCapsule(request.identifier, bytes, reply)
  })
}

pub fn finish_response(request: Request) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    FinishResponse(request.identifier, reply)
  })
}

pub fn send_trailers(
  request: Request,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    FinishWithTrailers(request.identifier, headers, reply)
  })
}

pub fn promise_push(
  request: Request,
  path: String,
  headers: List(#(String, String)),
) -> Result(Push, Error) {
  use identifier <- result.try(
    connection_call(request.connection, fn(reply) {
      PromisePush(request.identifier, path, headers, reply)
    }),
  )
  Ok(Push(request.connection, identifier))
}

pub fn send_push_response(
  push: Push,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
) -> Result(Nil, Error) {
  connection_call(push.connection, fn(reply) {
    SendPushResponse(
      push.identifier,
      status,
      headers,
      declared_content_length,
      reply,
    )
  })
}

pub fn send_push_chunk(push: Push, bytes: BitArray) -> Result(Nil, Error) {
  connection_call(push.connection, fn(reply) {
    SendPushChunk(push.identifier, bytes, reply)
  })
}

pub fn finish_push(push: Push) -> Result(Nil, Error) {
  connection_call(push.connection, fn(reply) {
    FinishPush(push.identifier, reply)
  })
}

pub fn send_push_trailers(
  push: Push,
  headers: List(#(String, String)),
) -> Result(Nil, Error) {
  connection_call(push.connection, fn(reply) {
    FinishPushWithTrailers(push.identifier, headers, reply)
  })
}

pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  case process.is_alive(listener.worker) {
    False -> Ok(AlreadyStopped)
    True ->
      case listener_call(listener, Stop) {
        Error(ListenerClosed) -> Ok(AlreadyStopped)
        outcome -> outcome
      }
  }
}

pub fn graceful_stop(listener: Listener) -> Result(DrainResult, Error) {
  case process.is_alive(listener.worker) {
    False -> Ok(AlreadyDrained)
    True -> {
      let deadline = now() + listener.drain_timeout_milliseconds
      case
        listener_call_with_timeout(
          listener,
          listener.drain_timeout_milliseconds + worker_reply_grace_milliseconds,
          fn(reply) { GracefulStop(reply, deadline) },
        )
      {
        Error(ListenerClosed) -> Ok(AlreadyDrained)
        outcome -> outcome
      }
    }
  }
}

pub fn capabilities(
  request: Request,
) -> Result(#(Bool, Bool, Bool, Bool), Error) {
  connection_call(request.connection, Capabilities)
}

pub fn path_stats(request: Request) -> Result(qlog.PathStats, Error) {
  connection_call(request.connection, PathStats)
}

pub fn connection_stats(
  request: Request,
) -> Result(server_connection.Stats, Error) {
  connection_call(request.connection, ConnectionStats)
}

pub fn telemetry_stats(request: Request) -> Result(#(Int, Int, Int), Error) {
  connection_call(request.connection, TelemetryStats)
}

/// Test-only payload-free snapshot of retained request and connection state.
@internal
pub fn request_state_stats(
  request: Request,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int, Int, Int), Error) {
  connection_call(request.connection, RequestStateStats)
}

pub fn maximum_transmission_unit(request: Request) -> Result(Int, Error) {
  connection_call(request.connection, MaximumTransmissionUnit)
}

pub fn maximum_datagram_size(request: Request) -> Result(Int, Error) {
  connection_call(request.connection, fn(reply) {
    MaximumDatagram(request.identifier, reply)
  })
}

pub fn guaranteed_datagram_size(request: Request) -> Result(Int, Error) {
  connection_call(request.connection, fn(reply) {
    GuaranteedDatagram(request.identifier, reply)
  })
}

pub fn prospective_guaranteed_datagram_size(
  request: Request,
) -> Result(Int, Error) {
  connection_call(request.connection, fn(reply) {
    ProspectiveMaximumDatagram(request.identifier, reply)
  })
}

pub fn send_datagram(
  request: Request,
  payload: BitArray,
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SendDatagram(request.identifier, payload, reply)
  })
}

pub fn next_datagram(request: Request) -> Result(BitArray, Error) {
  let deadline = now() + request.connection.timeout_milliseconds
  connection_call_with_timeout(
    request.connection,
    request.connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    fn(reply) { NextDatagram(request.identifier, reply, deadline) },
  )
}

pub fn set_priority(
  request: Request,
  urgency: Int,
  incremental: Bool,
) -> Result(Nil, Error) {
  connection_call(request.connection, fn(reply) {
    SetPriority(request.identifier, urgency, incremental, reply)
  })
}

pub fn get_priority(request: Request) -> Result(#(Int, Bool), Error) {
  connection_call(request.connection, fn(reply) {
    GetPriority(request.identifier, reply)
  })
}

pub fn early_data_status(
  request: Request,
) -> Result(server_connection.EarlyDataStatus, Error) {
  connection_call(request.connection, EarlyData)
}

fn initialise_listener(
  owner: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  port: Int,
  bind_address: Option(BitArray),
  timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
  accept_waiter_limit: Int,
  default_credential: Credential,
  alternative_credentials: List(Credential),
  http_datagrams: Bool,
  keepalive_milliseconds: Int,
  address_family: AddressFamily,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  replay_guard: Option(ReplayGuard),
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Nil {
  let startup = {
    use configured <- result.try(configure_core_server(
      default_credential,
      alternative_credentials,
      port,
      bind_address,
      timeout_milliseconds,
      drain_timeout_milliseconds,
      idle_timeout_milliseconds,
      stream_buffer_limit,
      endpoint_memory_limit,
      connection_limit,
      handshake_limit,
      queue_limit,
      telemetry_limit,
      bidirectional_stream_limit,
      unidirectional_stream_limit,
      frame_limit,
      datagram_limit,
      accept_waiter_limit,
      address_family,
      qlog_directory,
      allow_zero_rtt,
      replay_guard,
      ticket_keys,
      address_token_keys,
      stateless_reset_keys,
    ))
    use core <- result.try(
      core_server.start(configured) |> result.map_error(map_core_start_error),
    )
    use bound_port <- result.try(
      core_server.port(core) |> result.map_error(map_core_start_error),
    )
    Ok(#(core, bound_port))
  }
  case startup {
    Error(error) -> process.send(bootstrap, Error(error))
    Ok(#(core, bound_port)) -> {
      let commands = process.new_subject()
      let network = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedListenerCommand)
        |> process.select_map(network, ReceivedListenerNetwork)
        |> process.select_specific_monitor(owner_monitor, fn(_) {
          ListenerOwnerExited
        })
      let listener =
        Listener(
          commands,
          process.self(),
          timeout_milliseconds,
          drain_timeout_milliseconds,
        )
      let peer_config =
        PeerConfig(
          timeout_milliseconds,
          request_body_limit,
          response_body_limit,
          stream_buffer_limit,
          queue_limit,
          http_datagrams,
          qlog_directory != "",
          keepalive_milliseconds,
          server_connection.Config(
            http_datagrams,
            bidirectional_stream_limit,
            frame_limit,
            datagram_limit,
            qpack_table_limit,
            qpack_blocked_stream_limit,
          ),
        )
      process.send(bootstrap, Ok(listener))
      process.spawn_unlinked(fn() {
        process_label.set(process_label.Acceptor)
        accept_core_connections(core, network)
      })
      listener_loop(ListenerWorker(
        core,
        bound_port,
        commands,
        selector,
        network,
        dict.new(),
        0,
        queue_new(),
        queue_new(),
        None,
        timeout_milliseconds,
        drain_timeout_milliseconds,
        queue_limit,
        accept_waiter_limit,
        peer_config,
      ))
    }
  }
  Nil
}

fn configure_core_server(
  default: Credential,
  alternatives: List(Credential),
  port: Int,
  bind_address: Option(BitArray),
  timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  accept_waiter_limit: Int,
  address_family: AddressFamily,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  replay_guard: Option(ReplayGuard),
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(core_server.Server, Error) {
  let Credential(default) = default
  let alternatives =
    list.map(alternatives, fn(credential) {
      let Credential(credential) = credential
      credential
    })
  use configured <- result.try(
    server_connection.server_configuration(default, alternatives)
    |> result.replace_error(StartFailed),
  )
  use configured <- result.try(
    core_server.with_port(configured, port)
    |> result.replace_error(InvalidInput),
  )
  let configured = configured |> core_server.with_address_family(address_family)
  use configured <- result.try(case bind_address {
    None -> Ok(configured)
    Some(bytes) -> {
      use address <- result.try(
        quic_core.ip_address(bytes) |> result.replace_error(InvalidInput),
      )
      Ok(core_server.with_bind_address(configured, address))
    }
  })
  use deadlines <- result.try(core_deadlines(
    timeout_milliseconds,
    drain_timeout_milliseconds,
    idle_timeout_milliseconds,
  ))
  use limits <- result.try(core_limits(
    stream_buffer_limit,
    endpoint_memory_limit,
    connection_limit,
    handshake_limit,
    queue_limit,
    telemetry_limit,
    bidirectional_stream_limit,
    unidirectional_stream_limit,
    frame_limit,
    datagram_limit,
    accept_waiter_limit,
  ))
  let configured =
    configured
    |> core_server.with_deadlines(deadlines)
    |> core_server.with_limits(limits)
  use configured <- result.try(
    core_server.with_qlog(configured, qlog_directory)
    |> result.replace_error(StartFailed),
  )
  let configured = case allow_zero_rtt, replay_guard {
    True, Some(ReplayGuard(guard)) ->
      core_server.with_external_zero_rtt(
        configured,
        server_connection.replay_guard_handle(guard),
      )
    True, None -> core_server.with_single_node_zero_rtt(configured)
    False, _ -> configured
  }
  case ticket_keys, address_token_keys, stateless_reset_keys {
    [], [], [] -> Ok(configured)
    _, _, _ -> {
      use keys <- result.try(core_operational_keys(
        ticket_keys,
        address_token_keys,
        stateless_reset_keys,
      ))
      Ok(core_server.with_operational_keys(configured, keys))
    }
  }
}

fn core_deadlines(
  timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
) -> Result(core_config.Deadlines, Error) {
  let deadlines = core_config.default_deadlines()
  use deadlines <- result.try(set_core_deadline(
    deadlines,
    core_failure.Handshake,
    timeout_milliseconds,
  ))
  use deadlines <- result.try(set_core_deadline(
    deadlines,
    core_failure.Operation,
    timeout_milliseconds,
  ))
  use deadlines <- result.try(set_core_deadline(
    deadlines,
    core_failure.Idle,
    idle_timeout_milliseconds,
  ))
  set_core_deadline(deadlines, core_failure.Drain, drain_timeout_milliseconds)
}

fn set_core_deadline(
  deadlines: core_config.Deadlines,
  phase: core_failure.TimeoutPhase,
  milliseconds: Int,
) -> Result(core_config.Deadlines, Error) {
  core_config.with_deadline(deadlines, phase, milliseconds)
  |> result.replace_error(InvalidInput)
}

fn core_limits(
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  accept_waiter_limit: Int,
) -> Result(core_config.Limits, Error) {
  let limits = core_config.default_limits()
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Buffer,
    int.max(stream_buffer_limit, frame_limit),
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.EndpointMemory,
    endpoint_memory_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Connections,
    connection_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Handshakes,
    handshake_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Queue,
    queue_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Telemetry,
    telemetry_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.BidirectionalStreams,
    bidirectional_stream_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.UnidirectionalStreams,
    unidirectional_stream_limit,
  ))
  use limits <- result.try(set_core_limit(
    limits,
    core_failure.Datagram,
    datagram_limit,
  ))
  set_core_limit(limits, core_failure.AcceptWaiters, accept_waiter_limit)
}

fn set_core_limit(
  limits: core_config.Limits,
  resource: core_failure.Resource,
  maximum: Int,
) -> Result(core_config.Limits, Error) {
  core_config.with_limit(limits, resource, maximum)
  |> result.replace_error(InvalidInput)
}

fn core_operational_keys(
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(core_server.OperationalKeys, Error) {
  use ticket <- result.try(core_key_ring(ticket_keys))
  use address <- result.try(core_key_ring(address_token_keys))
  use reset <- result.try(core_key_ring(stateless_reset_keys))
  core_server.operational_keys(
    ticket: ticket,
    address_token: address,
    stateless_reset: reset,
  )
  |> result.replace_error(InvalidInput)
}

fn core_key_ring(keys: List(BitArray)) -> Result(core_server.KeyRing, Error) {
  case keys {
    [current] -> {
      use current <- result.try(
        core_server.operational_key(current)
        |> result.replace_error(InvalidInput),
      )
      Ok(core_server.key_ring(current))
    }
    [current, previous] -> {
      use current <- result.try(
        core_server.operational_key(current)
        |> result.replace_error(InvalidInput),
      )
      use previous <- result.try(
        core_server.operational_key(previous)
        |> result.replace_error(InvalidInput),
      )
      core_server.rotate_key_ring(core_server.key_ring(previous), current)
      |> result.replace_error(InvalidInput)
    }
    _ -> Error(InvalidInput)
  }
}

fn accept_core_connections(
  listener: core_server.Listener,
  network: Subject(ListenerNetwork),
) -> Nil {
  case core_server.accept_next(listener) {
    Ok(connection) -> {
      process.send(network, CoreAccepted(connection))
      accept_core_connections(listener, network)
    }
    Error(_) -> process.send(network, CoreListenerClosed)
  }
}

fn listener_loop(worker: ListenerWorker) -> Nil {
  let now = now()
  let worker = expire_accept_waiters(worker, now)
  case advance_listener_drain(worker, now) {
    Error(Nil) -> Nil
    Ok(worker) -> {
      let received = case listener_next_deadline(worker) {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(deadline) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, deadline - now),
          )
      }
      case received {
        Error(Nil) -> listener_loop(worker)
        Ok(ListenerOwnerExited) -> shutdown_listener(worker)
        Ok(ReceivedListenerCommand(command)) ->
          case handle_listener_command(worker, command) {
            Error(Nil) -> Nil
            Ok(worker) -> listener_loop(worker)
          }
        Ok(ReceivedListenerNetwork(event)) ->
          case handle_listener_network(worker, event) {
            Error(Nil) -> Nil
            Ok(worker) -> listener_loop(worker)
          }
      }
    }
  }
}

fn handle_listener_command(
  worker: ListenerWorker,
  command: ListenerCommand,
) -> Result(ListenerWorker, Nil) {
  case command {
    Port(reply) -> {
      process.send(reply, Ok(worker.port))
      Ok(worker)
    }
    ReloadCertificates(default, alternatives, reply) -> {
      let Credential(default) = default
      let alternatives =
        list.map(alternatives, fn(credential) {
          let Credential(credential) = credential
          credential
        })
      let outcome = {
        use configured <- result.try(
          server_connection.server_configuration(default, alternatives)
          |> result.replace_error(InvalidInput),
        )
        core_server.reload_certificates(worker.core, configured)
        |> result.map_error(map_core_runtime_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    ReloadOperationalKeys(ticket, address, reset, reply) -> {
      let outcome = {
        use keys <- result.try(core_operational_keys(ticket, address, reset))
        core_server.reload_operational_keys(worker.core, keys)
        |> result.map_error(map_core_runtime_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    Accept(reply, deadline) -> handle_listener_accept(worker, reply, deadline)
    Stop(reply) -> {
      shutdown_listener(worker)
      process.send(reply, Ok(Stopped))
      Error(Nil)
    }
    GracefulStop(reply, deadline) ->
      handle_listener_graceful_stop(worker, reply, deadline)
  }
}

fn handle_listener_accept(
  worker: ListenerWorker,
  reply: Subject(Result(Incoming, Error)),
  deadline: Int,
) -> Result(ListenerWorker, Nil) {
  case worker.drain {
    Some(_) -> {
      process.send(reply, Error(ListenerClosed))
      Ok(worker)
    }
    None ->
      case queue_pop(worker.pending) {
        Ok(#(incoming, pending)) -> {
          process.send(reply, Ok(incoming))
          Ok(ListenerWorker(..worker, pending: pending))
        }
        Error(Nil) ->
          case
            queue_count(worker.accept_waiters) >= worker.accept_waiter_limit
          {
            True -> {
              process.send(reply, Error(ConcurrentAccept))
              Ok(worker)
            }
            False ->
              Ok(
                ListenerWorker(
                  ..worker,
                  accept_waiters: queue_push(
                    worker.accept_waiters,
                    AcceptWaiter(reply, deadline),
                  ),
                ),
              )
          }
      }
  }
}

fn handle_listener_graceful_stop(
  worker: ListenerWorker,
  reply: Subject(Result(DrainResult, Error)),
  deadline: Int,
) -> Result(ListenerWorker, Nil) {
  case worker.drain {
    Some(_) -> {
      process.send(reply, Error(ConcurrentDrain))
      Ok(worker)
    }
    None -> {
      close_accept_waiters(worker.accept_waiters, ListenerClosed)
      reject_pending(worker.pending)
      let outstanding = connection_identifier_set(worker.connections)
      begin_peer_drains(dict.values(worker.connections))
      case dict.size(outstanding) {
        0 -> {
          shutdown_listener(
            ListenerWorker(
              ..worker,
              pending: queue_new(),
              accept_waiters: queue_new(),
            ),
          )
          process.send(reply, Ok(Drained))
          Error(Nil)
        }
        _ ->
          Ok(
            ListenerWorker(
              ..worker,
              pending: queue_new(),
              accept_waiters: queue_new(),
              drain: Some(ListenerDrain(reply, deadline, outstanding)),
            ),
          )
      }
    }
  }
}

fn handle_listener_network(
  worker: ListenerWorker,
  event: ListenerNetwork,
) -> Result(ListenerWorker, Nil) {
  case event {
    CoreAccepted(core) ->
      case worker.drain {
        Some(_) -> {
          close_core_connection(core)
          Ok(worker)
        }
        None -> {
          let identifier = worker.next_connection_id
          spawn_connection_actor(
            process.self(),
            identifier,
            core,
            worker.network,
            worker.peer_config,
          )
          Ok(ListenerWorker(..worker, next_connection_id: identifier + 1))
        }
      }
    CoreListenerClosed ->
      case worker.drain {
        Some(_) -> Ok(worker)
        None -> {
          shutdown_listener(worker)
          Error(Nil)
        }
      }
    PeerNotice(PeerStarted(identifier, connection)) ->
      case worker.drain {
        None ->
          Ok(
            ListenerWorker(
              ..worker,
              connections: dict.insert(
                worker.connections,
                identifier,
                connection,
              ),
            ),
          )
        Some(_) -> {
          let _ = connection_call(connection, StopConnection)
          Ok(worker)
        }
      }
    PeerNotice(RequestAvailable(incoming)) ->
      handle_available_request(worker, incoming)
    PeerNotice(PeerDrained(identifier)) ->
      handle_peer_finished(worker, identifier)
    PeerNotice(PeerStopped(identifier)) ->
      handle_peer_finished(worker, identifier)
  }
}

fn handle_available_request(
  worker: ListenerWorker,
  incoming: Incoming,
) -> Result(ListenerWorker, Nil) {
  case worker.drain {
    Some(_) -> {
      reject_incoming(incoming, request_rejected_code, ListenerClosed)
      Ok(worker)
    }
    None ->
      case queue_pop(worker.accept_waiters) {
        Ok(#(AcceptWaiter(reply, _), waiters)) -> {
          process.send(reply, Ok(incoming))
          Ok(ListenerWorker(..worker, accept_waiters: waiters))
        }
        Error(Nil) ->
          case queue_count(worker.pending) >= worker.queue_limit {
            True -> {
              reject_incoming(
                incoming,
                excessive_load_code,
                PendingRequestLimitExceeded(worker.queue_limit),
              )
              Ok(worker)
            }
            False ->
              Ok(
                ListenerWorker(
                  ..worker,
                  pending: queue_push(worker.pending, incoming),
                ),
              )
          }
      }
  }
}

fn handle_peer_finished(
  worker: ListenerWorker,
  identifier: Int,
) -> Result(ListenerWorker, Nil) {
  let connections = dict.delete(worker.connections, identifier)
  case worker.drain {
    None -> Ok(ListenerWorker(..worker, connections: connections))
    Some(ListenerDrain(reply, deadline, outstanding)) -> {
      let outstanding = dict.delete(outstanding, identifier)
      case dict.size(outstanding) {
        0 -> {
          shutdown_listener(
            ListenerWorker(..worker, connections: connections, drain: None),
          )
          process.send(reply, Ok(Drained))
          Error(Nil)
        }
        _ ->
          Ok(
            ListenerWorker(
              ..worker,
              connections: connections,
              drain: Some(ListenerDrain(reply, deadline, outstanding)),
            ),
          )
      }
    }
  }
}

fn advance_listener_drain(
  worker: ListenerWorker,
  current: Int,
) -> Result(ListenerWorker, Nil) {
  case worker.drain {
    Some(ListenerDrain(reply, deadline, _)) if current >= deadline -> {
      shutdown_listener(ListenerWorker(..worker, drain: None))
      process.send(reply, Ok(Forced))
      Error(Nil)
    }
    _ -> Ok(worker)
  }
}

fn listener_next_deadline(worker: ListenerWorker) -> Option(Int) {
  let accept_deadline = queue_accept_deadline(worker.accept_waiters, None)
  case worker.drain {
    None -> accept_deadline
    Some(ListenerDrain(_, deadline, _)) ->
      earlier_deadline(accept_deadline, Some(deadline))
  }
}

fn expire_accept_waiters(
  worker: ListenerWorker,
  current: Int,
) -> ListenerWorker {
  ListenerWorker(
    ..worker,
    accept_waiters: expire_accept_queue(worker.accept_waiters, current),
  )
}

fn expire_accept_queue(
  waiters: Queue(AcceptWaiter),
  current: Int,
) -> Queue(AcceptWaiter) {
  expire_accept_entries(waiters, current, queue_new())
}

fn expire_accept_entries(
  waiters: Queue(AcceptWaiter),
  current: Int,
  retained: Queue(AcceptWaiter),
) -> Queue(AcceptWaiter) {
  case queue_pop(waiters) {
    Error(Nil) -> retained
    Ok(#(AcceptWaiter(reply, deadline) as waiter, rest)) -> {
      let retained = case current >= deadline {
        True -> {
          process.send(reply, Error(Timeout))
          retained
        }
        False -> queue_push(retained, waiter)
      }
      expire_accept_entries(rest, current, retained)
    }
  }
}

fn shutdown_listener(worker: ListenerWorker) -> Nil {
  close_accept_waiters(worker.accept_waiters, ListenerClosed)
  stop_peer_connections(dict.values(worker.connections))
  let _ = core_server.stop(worker.core)
  Nil
}

fn close_accept_waiters(waiters: Queue(AcceptWaiter), error: Error) -> Nil {
  case queue_pop(waiters) {
    Error(Nil) -> Nil
    Ok(#(AcceptWaiter(reply, _), rest)) -> {
      process.send(reply, Error(error))
      close_accept_waiters(rest, error)
    }
  }
}

fn stop_peer_connections(connections: List(Connection)) -> Nil {
  case connections {
    [] -> Nil
    [connection, ..rest] -> {
      let _ = connection_call(connection, StopConnection)
      stop_peer_connections(rest)
    }
  }
}

fn begin_peer_drains(connections: List(Connection)) -> Nil {
  case connections {
    [] -> Nil
    [connection, ..rest] -> {
      process.send(connection.commands, BeginDrain)
      begin_peer_drains(rest)
    }
  }
}

fn reject_pending(pending: Queue(Incoming)) -> Nil {
  case queue_pop(pending) {
    Error(Nil) -> Nil
    Ok(#(incoming, rest)) -> {
      reject_incoming(incoming, request_rejected_code, ListenerClosed)
      reject_pending(rest)
    }
  }
}

fn reject_incoming(incoming: Incoming, code: Int, error: Error) -> Nil {
  let Incoming(Request(connection, identifier), _, _, _, _, _, _) = incoming
  process.send(connection.commands, RejectRequest(identifier, code, error))
}

fn connection_identifier_set(
  connections: Dict(Int, Connection),
) -> Dict(Int, Nil) {
  connection_identifier_entries(dict.keys(connections), dict.new())
}

fn connection_identifier_entries(
  identifiers: List(Int),
  set: Dict(Int, Nil),
) -> Dict(Int, Nil) {
  case identifiers {
    [] -> set
    [identifier, ..rest] ->
      connection_identifier_entries(rest, dict.insert(set, identifier, Nil))
  }
}

fn close_core_connection(connection: core_server.Connection) -> Nil {
  let _ = core_server.close(connection)
  Nil
}

fn spawn_connection_actor(
  owner: Pid,
  identifier: Int,
  core: core_server.Connection,
  notices: Subject(ListenerNetwork),
  config: PeerConfig,
) -> Nil {
  process.spawn_unlinked(fn() {
    initialise_connection(owner, identifier, core, notices, config)
  })
  Nil
}

fn initialise_connection(
  owner: Pid,
  identifier: Int,
  core: core_server.Connection,
  notices: Subject(ListenerNetwork),
  config: PeerConfig,
) -> Nil {
  process_label.set(process_label.Connection)
  let network = process.new_subject()
  case server_connection.start(identifier, core, network, config.protocol) {
    Error(_) -> {
      close_core_connection(core)
      process.send(notices, PeerNotice(PeerStopped(identifier)))
    }
    Ok(connection) -> {
      let commands = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedConnectionCommand)
        |> process.select_map(network, ReceivedConnectionNetwork)
        |> process.select_specific_monitor(owner_monitor, fn(_) {
          ConnectionOwnerExited
        })
      let handle =
        Connection(commands, process.self(), config.timeout_milliseconds)
      process.send(notices, PeerNotice(PeerStarted(identifier, handle)))
      connection_loop(
        ConnectionWorker(
          identifier,
          connection,
          handle,
          commands,
          selector,
          notices,
          dict.new(),
          terminal_registry.new(maximum_terminal_handles),
          dict.new(),
          dict.new(),
          0,
          False,
          False,
          False,
          config.timeout_milliseconds,
          config.request_body_limit,
          config.response_body_limit,
          config.stream_buffer_limit,
          config.queue_limit,
          config.http_datagrams,
          config.qlog_enabled,
          config.keepalive_milliseconds,
          case config.keepalive_milliseconds {
            0 -> 0
            interval -> now() + interval
          },
        ),
      )
    }
  }
  Nil
}

fn connection_loop(worker: ConnectionWorker) -> Nil {
  let worker = dispatch_connection_events(worker) |> retire_completed_requests
  let current = now()
  let worker = expire_connection_waiters(worker, current)
  let worker = maybe_send_keepalive(worker, current)
  case continue_connection(worker) {
    Error(Nil) -> Nil
    Ok(worker) -> {
      let current = now()
      let received = case connection_next_deadline(worker) {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(deadline) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, deadline - current),
          )
      }
      case received {
        Error(Nil) -> connection_loop(worker)
        Ok(ConnectionOwnerExited) -> shutdown_connection(worker, False)
        Ok(ReceivedConnectionCommand(command)) ->
          case handle_connection_command(worker, command) {
            Error(Nil) -> Nil
            Ok(worker) -> connection_loop(worker)
          }
        Ok(ReceivedConnectionNetwork(event)) ->
          case server_connection.receive_active(worker.connection, event) {
            Ok(connection) ->
              connection_loop(
                ConnectionWorker(..worker, connection: connection),
              )
            Error(error) -> {
              close_peer_protocol_failure(worker.connection, error)
              connection_loop(fail_all_requests(
                worker,
                map_connection_error(error),
              ))
            }
          }
      }
    }
  }
}

fn continue_connection(
  worker: ConnectionWorker,
) -> Result(ConnectionWorker, Nil) {
  case worker.closed {
    True -> {
      shutdown_connection(worker, False)
      Error(Nil)
    }
    False ->
      case
        worker.draining
        && all_connection_work_complete(worker)
        && transport_work_complete(worker)
      {
        False -> Ok(worker)
        True -> {
          let worker = case server_connection.close_drained(worker.connection) {
            Ok(connection) -> ConnectionWorker(..worker, connection: connection)
            Error(_) -> worker
          }
          shutdown_connection(worker, True)
          Error(Nil)
        }
      }
  }
}

fn shutdown_connection(worker: ConnectionWorker, drained: Bool) -> Nil {
  close_request_waiters(dict.values(worker.requests), ConnectionClosed)
  server_connection.close(worker.connection, 0x100)
  process.send(
    worker.notices,
    PeerNotice(case drained {
      True -> PeerDrained(worker.identifier)
      False -> PeerStopped(worker.identifier)
    }),
  )
  Nil
}

fn dispatch_connection_events(worker: ConnectionWorker) -> ConnectionWorker {
  let #(connection, events) = server_connection.take_events(worker.connection)
  dispatch_connection_event_entries(
    ConnectionWorker(..worker, connection: connection),
    events,
  )
}

fn dispatch_connection_event_entries(
  worker: ConnectionWorker,
  events: List(server_connection.Event),
) -> ConnectionWorker {
  case events {
    [] -> worker
    [event, ..rest] ->
      dispatch_connection_event_entries(
        dispatch_connection_event(worker, event),
        rest,
      )
  }
}

fn dispatch_connection_event(
  worker: ConnectionWorker,
  event: server_connection.Event,
) -> ConnectionWorker {
  case event {
    server_connection.Http3Event(http3_state.RequestHeaders(
      stream_id,
      validated,
    )) -> accept_request_head(worker, stream_id, validated)
    server_connection.Http3Event(http3_state.Data(_, <<>>)) -> worker
    server_connection.Http3Event(http3_state.Data(stream_id, bytes)) ->
      enqueue_body_data(worker, stream_id, bytes)
    server_connection.Http3Event(http3_state.Trailers(stream_id, validated)) ->
      case decode_trailers(validated) {
        Ok(headers) ->
          enqueue_request_event(worker, stream_id, Trailers(headers))
        Error(error) -> fail_request(worker, stream_id, error)
      }
    server_connection.Http3Event(http3_state.StreamFinished(stream_id)) ->
      mark_request_finished(worker, stream_id)
      |> enqueue_request_event(stream_id, End)
    server_connection.StreamWasReset(stream_id, code) ->
      fail_request(worker, stream_id, StreamReset(code))
    server_connection.Http3Event(http3_state.HttpDatagram(stream_id, payload)) ->
      enqueue_datagram(worker, stream_id, payload)
    server_connection.ConnectionTerminated ->
      ConnectionWorker(
        ..fail_all_requests(worker, ConnectionClosed),
        closed: True,
      )
    server_connection.Http3Event(http3_state.PriorityChanged(update)) ->
      apply_peer_priority(worker, update)
    server_connection.Http3Event(http3_state.PushCancelled(push_id)) ->
      fail_push(worker, push_id, PushCancelled)
    server_connection.Http3Event(http3_state.PushStreamCancellationRequested(
      push_id,
      stream_id,
    )) -> {
      let worker = fail_push(worker, push_id, PushCancelled)
      case
        server_connection.abort_stream(
          worker.connection,
          stream_id,
          request_cancelled_code,
        )
      {
        Ok(connection) -> ConnectionWorker(..worker, connection: connection)
        Error(_) -> worker
      }
    }
    _ -> worker
  }
}

fn accept_request_head(
  worker: ConnectionWorker,
  stream_id: Int,
  validated: header_semantics.Validated,
) -> ConnectionWorker {
  case worker.draining, decode_request(validated) {
    True, _ -> abort_request_stream(worker, stream_id, request_rejected_code)
    _, Error(_) ->
      abort_request_stream(worker, stream_id, request_cancelled_code)
    False, Ok(#(method, path, application_protocol, scheme, authority, headers))
    -> {
      let effective_priority =
        dict.get(worker.pending_priorities, stream_id)
        |> result.unwrap(#(3, False))
      let request =
        RequestState(
          stream_id,
          method,
          path,
          application_protocol,
          scheme,
          authority,
          headers,
          option.is_some(application_protocol)
            && !has_forbidden_capsule_field(headers),
          False,
          queue_new(),
          0,
          0,
          None,
          queue_new(),
          0,
          None,
          False,
          False,
          False,
          0,
          None,
          effective_priority,
          None,
        )
      let worker =
        ConnectionWorker(
          ..worker,
          requests: dict.insert(worker.requests, stream_id, request),
          next_request_stream_id: int.max(
            worker.next_request_stream_id,
            stream_id + 4,
          ),
        )
      process.send(
        worker.notices,
        PeerNotice(
          RequestAvailable(Incoming(
            Request(worker.handle, stream_id),
            method,
            path,
            application_protocol,
            scheme,
            authority,
            headers,
          )),
        ),
      )
      worker
    }
  }
}

fn enqueue_body_data(
  worker: ConnectionWorker,
  stream_id: Int,
  bytes: BitArray,
) -> ConnectionWorker {
  case dict.get(worker.requests, stream_id) {
    Error(_) -> worker
    Ok(request) -> {
      let total = request.received_body_bytes + bit_array.byte_size(bytes)
      case total > worker.request_body_limit {
        True ->
          abort_request_stream(worker, stream_id, request_cancelled_code)
          |> fail_request(
            stream_id,
            RequestBodyTooLarge(worker.request_body_limit),
          )
        False ->
          put_request(
            worker,
            RequestState(..request, received_body_bytes: total),
          )
          |> enqueue_request_event(stream_id, Data(bytes))
      }
    }
  }
}

fn enqueue_request_event(
  worker: ConnectionWorker,
  stream_id: Int,
  event: Event,
) -> ConnectionWorker {
  case dict.get(worker.requests, stream_id) {
    Error(_) -> worker
    Ok(request) ->
      case
        request.failure,
        request.event_waiter,
        queue_is_empty(request.events)
      {
        Some(_), _, _ -> worker
        None, Some(EventWaiter(reply, _)), True -> {
          process.send(reply, Ok(event))
          put_request(worker, RequestState(..request, event_waiter: None))
        }
        None, _, _ -> {
          let buffered = case event {
            Data(bytes) ->
              request.buffered_body_bytes + bit_array.byte_size(bytes)
            _ -> request.buffered_body_bytes
          }
          case
            queue_count(request.events) >= worker.queue_limit,
            buffered > worker.stream_buffer_limit
          {
            True, _ ->
              abort_request_stream(worker, stream_id, excessive_load_code)
              |> fail_request(
                stream_id,
                RequestEventQueueExceeded(worker.queue_limit),
              )
            False, True ->
              abort_request_stream(worker, stream_id, request_cancelled_code)
              |> fail_request(
                stream_id,
                ConsumerTooSlow(worker.stream_buffer_limit),
              )
            False, False ->
              put_request(
                worker,
                RequestState(
                  ..request,
                  events: queue_push(request.events, event),
                  buffered_body_bytes: buffered,
                ),
              )
          }
        }
      }
  }
}

fn enqueue_datagram(
  worker: ConnectionWorker,
  stream_id: Int,
  payload: BitArray,
) -> ConnectionWorker {
  case dict.get(worker.requests, stream_id) {
    Error(_) -> worker
    Ok(request) ->
      case request.failure, request.datagram_waiter {
        Some(_), _ -> worker
        None, Some(DatagramWaiter(reply, _)) -> {
          process.send(reply, Ok(payload))
          put_request(worker, RequestState(..request, datagram_waiter: None))
        }
        None, None -> {
          let buffered =
            request.buffered_datagram_bytes + bit_array.byte_size(payload)
          case
            queue_count(request.datagrams) >= worker.queue_limit,
            buffered > worker.stream_buffer_limit
          {
            True, _ ->
              abort_request_stream(worker, stream_id, excessive_load_code)
              |> fail_request(
                stream_id,
                DatagramQueueExceeded(worker.queue_limit),
              )
            False, True ->
              abort_request_stream(worker, stream_id, request_cancelled_code)
              |> fail_request(
                stream_id,
                DatagramBufferExceeded(worker.stream_buffer_limit),
              )
            False, False ->
              put_request(
                worker,
                RequestState(
                  ..request,
                  datagrams: queue_push(request.datagrams, payload),
                  buffered_datagram_bytes: buffered,
                ),
              )
          }
        }
      }
  }
}

fn mark_request_finished(
  worker: ConnectionWorker,
  stream_id: Int,
) -> ConnectionWorker {
  case dict.get(worker.requests, stream_id) {
    Error(_) -> worker
    Ok(request) ->
      put_request(worker, RequestState(..request, request_finished: True))
  }
}

fn apply_peer_priority(
  worker: ConnectionWorker,
  update: priority.Update,
) -> ConnectionWorker {
  case update {
    priority.PushUpdate(_, _) -> worker
    priority.RequestUpdate(stream_id, priority.Priority(urgency, incremental)) -> {
      let worker =
        ConnectionWorker(
          ..worker,
          pending_priorities: dict.insert(
            worker.pending_priorities,
            stream_id,
            #(urgency, incremental),
          ),
        )
      case dict.get(worker.requests, stream_id) {
        Error(_) -> worker
        Ok(request) ->
          put_request(
            worker,
            RequestState(..request, priority: #(urgency, incremental)),
          )
      }
    }
  }
}

fn handle_connection_command(
  worker: ConnectionWorker,
  command: ConnectionCommand,
) -> Result(ConnectionWorker, Nil) {
  case command {
    PeerEndpoint(reply) -> {
      process.send(
        reply,
        server_connection.peer_endpoint(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    Next(identifier, reply, deadline) ->
      handle_next_event(worker, identifier, reply, deadline)
    CancelRequest(identifier, reply) ->
      handle_cancel_request(worker, identifier, reply)
    SendResponse(identifier, status, headers, declared, reply) ->
      handle_send_response(worker, identifier, status, headers, declared, reply)
    Respond(identifier, status, headers, body, reply) ->
      handle_respond(worker, identifier, status, headers, body, reply)
    SendInformational(identifier, status, headers, reply) ->
      handle_send_informational(worker, identifier, status, headers, reply)
    SendChunk(identifier, bytes, reply) ->
      handle_send_chunk(worker, identifier, bytes, reply)
    SendCapsule(identifier, bytes, reply) ->
      handle_send_capsule(worker, identifier, bytes, reply)
    FinishResponse(identifier, reply) ->
      handle_finish_response(worker, identifier, reply)
    FinishWithTrailers(identifier, headers, reply) ->
      handle_finish_with_trailers(worker, identifier, headers, reply)
    PromisePush(identifier, path, headers, reply) ->
      handle_promise_push(worker, identifier, path, headers, reply)
    SendPushResponse(identifier, status, headers, declared, reply) ->
      handle_send_push_response(
        worker,
        identifier,
        status,
        headers,
        declared,
        reply,
      )
    SendPushChunk(identifier, bytes, reply) ->
      handle_send_push_chunk(worker, identifier, bytes, reply)
    FinishPush(identifier, reply) ->
      handle_finish_push(worker, identifier, reply)
    FinishPushWithTrailers(identifier, headers, reply) ->
      handle_finish_push_with_trailers(worker, identifier, headers, reply)
    Capabilities(reply) -> {
      let early = server_connection.early_data_status(worker.connection)
      process.send(
        reply,
        Ok(#(
          server_connection.datagrams_available(worker.connection),
          True,
          early != server_connection.NotAttempted,
          worker.qlog_enabled,
        )),
      )
      Ok(worker)
    }
    ProspectiveMaximumDatagram(identifier, reply) -> {
      let outcome = case dict.get(worker.requests, identifier) {
        Error(_) -> Error(request_error(worker, identifier, StreamFinished))
        Ok(request) ->
          server_connection.prospective_guaranteed_http_datagram_size(
            worker.connection,
            request.stream_id,
          )
          |> result.map_error(map_connection_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    MaximumDatagram(identifier, reply) -> {
      let outcome = case dict.get(worker.requests, identifier) {
        Error(_) -> Error(request_error(worker, identifier, StreamFinished))
        Ok(request) ->
          server_connection.maximum_http_datagram_size(
            worker.connection,
            request.stream_id,
          )
          |> result.map_error(map_connection_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    GuaranteedDatagram(identifier, reply) -> {
      let outcome = case dict.get(worker.requests, identifier) {
        Error(_) -> Error(request_error(worker, identifier, StreamFinished))
        Ok(request) ->
          server_connection.guaranteed_http_datagram_size(
            worker.connection,
            request.stream_id,
          )
          |> result.map_error(map_connection_error)
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    SendDatagram(identifier, payload, reply) ->
      handle_send_datagram(worker, identifier, payload, reply)
    NextDatagram(identifier, reply, deadline) ->
      handle_next_datagram(worker, identifier, reply, deadline)
    SetPriority(identifier, urgency, incremental, reply) ->
      handle_set_priority(worker, identifier, urgency, incremental, reply)
    GetPriority(identifier, reply) -> {
      let outcome = case dict.get(worker.requests, identifier) {
        Ok(request) -> Ok(request.priority)
        Error(_) -> Error(request_error(worker, identifier, StreamFinished))
      }
      process.send(reply, outcome)
      Ok(worker)
    }
    EarlyData(reply) -> {
      process.send(
        reply,
        Ok(server_connection.early_data_status(worker.connection)),
      )
      Ok(worker)
    }
    PathStats(reply) -> {
      process.send(
        reply,
        server_connection.path_stats(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    ConnectionStats(reply) -> {
      process.send(
        reply,
        server_connection.stats(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    TelemetryStats(reply) -> {
      process.send(
        reply,
        server_connection.telemetry_stats(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    RequestStateStats(reply) -> {
      let outcome =
        server_connection.resource_stats(worker.connection)
        |> result.map(fn(resources) {
          let #(
            core_handles,
            runtime_handles,
            transport_streams,
            protocol_inputs,
            transactions,
            push_transactions,
            blocked_streams,
          ) = resources
          #(
            dict.size(worker.requests),
            terminal_registry.size(worker.request_terminals),
            core_handles,
            runtime_handles,
            transport_streams,
            protocol_inputs,
            transactions,
            push_transactions,
            blocked_streams,
          )
        })
        |> result.map_error(map_connection_error)
      process.send(reply, outcome)
      Ok(worker)
    }
    MaximumTransmissionUnit(reply) -> {
      process.send(
        reply,
        server_connection.path_mtu(worker.connection)
          |> result.map_error(map_connection_error),
      )
      Ok(worker)
    }
    RejectRequest(identifier, code, error) ->
      Ok(
        abort_request_stream(worker, identifier, code)
        |> fail_request(identifier, error),
      )
    BeginDrain -> Ok(begin_connection_drain(worker))
    StopConnection(reply) -> {
      let _ = server_connection.close(worker.connection, 0x100)
      process.send(reply, Ok(Nil))
      process.send(worker.notices, PeerNotice(PeerStopped(worker.identifier)))
      Error(Nil)
    }
  }
}

fn handle_cancel_request(
  worker: ConnectionWorker,
  identifier: Int,
  reply: Subject(Result(Cancellation, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) -> {
      process.send(
        reply,
        Ok(request_terminal_cancellation(worker.request_terminals, identifier)),
      )
      Ok(worker)
    }
    Ok(RequestState(failure: Some(StreamCancelled(code)), ..))
      if code == request_cancelled_code
    -> {
      process.send(reply, Ok(AlreadyCancelled))
      Ok(worker)
    }
    Ok(RequestState(failure: Some(_), ..)) -> {
      process.send(reply, Ok(AlreadyCompleted))
      Ok(worker)
    }
    Ok(RequestState(request_finished: True, response_finished: True, ..)) -> {
      process.send(reply, Ok(AlreadyCompleted))
      Ok(worker)
    }
    Ok(request) ->
      case
        server_connection.abort_stream(
          worker.connection,
          request.stream_id,
          request_cancelled_code,
        )
      {
        Error(error) -> reply_error(worker, reply, map_connection_error(error))
        Ok(connection) -> {
          let worker =
            ConnectionWorker(..worker, connection: connection)
            |> fail_request(identifier, StreamCancelled(request_cancelled_code))
            |> discard_request_payloads(identifier)
          process.send(reply, Ok(Cancelled))
          Ok(worker)
        }
      }
  }
}

fn handle_next_event(
  worker: ConnectionWorker,
  identifier: Int,
  reply: Subject(Result(Event, Error)),
  deadline: Int,
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, StreamFinished),
      )
    Ok(request) ->
      case queue_pop(request.events), request.failure, request.event_waiter {
        Ok(#(event, events)), _, _ -> {
          process.send(reply, Ok(event))
          let buffered = case event {
            Data(bytes) ->
              request.buffered_body_bytes - bit_array.byte_size(bytes)
            _ -> request.buffered_body_bytes
          }
          Ok(put_request(
            worker,
            RequestState(
              ..request,
              events: events,
              buffered_body_bytes: int.max(buffered, 0),
            ),
          ))
        }
        Error(Nil), Some(error), _ -> reply_error(worker, reply, error)
        Error(Nil), None, Some(_) ->
          reply_error(worker, reply, ConcurrentReceive)
        Error(Nil), None, None ->
          Ok(put_request(
            worker,
            RequestState(
              ..request,
              event_waiter: Some(EventWaiter(reply, deadline)),
            ),
          ))
      }
  }
}

fn handle_send_response(
  worker: ConnectionWorker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyStarted),
      )
    Ok(_) if status < 200 || status > 599 ->
      reply_error(worker, reply, InvalidInput)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure,
        exceeds_response_body_limit(
          declared_content_length,
          worker.response_body_limit,
        )
      {
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None, True ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        False, False, None, False ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) ->
              case
                server_connection.send_response_headers(
                  worker.connection,
                  request.stream_id,
                  fields,
                )
              {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_request(
                    ConnectionWorker(..worker, connection: connection),
                    RequestState(
                      ..request,
                      response_started: True,
                      capsule_established: request.capsule_candidate
                        && capsule_success_status(status)
                        && declared_content_length == None
                        && !has_forbidden_capsule_field(headers),
                      declared_content_length: declared_content_length,
                    ),
                  ))
                }
              }
          }
      }
  }
}

fn handle_respond(
  worker: ConnectionWorker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyStarted),
      )
    Ok(_) if status < 200 || status > 599 ->
      reply_error(worker, reply, InvalidInput)
    Ok(request) -> {
      let size = bit_array.byte_size(body)
      case
        request.response_started,
        request.response_finished,
        request.failure,
        size > worker.response_body_limit
      {
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None, True ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        False, False, None, False ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) -> {
              let outcome = {
                use connection <- result.try(
                  server_connection.send_response_headers(
                    worker.connection,
                    request.stream_id,
                    fields,
                  ),
                )
                use connection <- result.try(send_response_bytes(
                  connection,
                  request.stream_id,
                  body,
                ))
                server_connection.finish_stream(connection, request.stream_id)
              }
              case outcome {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_request(
                    ConnectionWorker(..worker, connection: connection),
                    RequestState(
                      ..request,
                      response_started: True,
                      response_finished: True,
                      response_body_bytes: size,
                      declared_content_length: Some(size),
                    ),
                  ))
                }
              }
            }
          }
      }
    }
  }
}

fn handle_send_informational(
  worker: ConnectionWorker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyStarted),
      )
    Ok(_) if status < 100 || status >= 200 || status == 101 ->
      reply_error(worker, reply, InvalidInput)
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure
      {
        _, _, Some(error) -> reply_error(worker, reply, error)
        True, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) ->
              case
                server_connection.send_response_headers(
                  worker.connection,
                  request.stream_id,
                  fields,
                )
              {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(ConnectionWorker(..worker, connection: connection))
                }
              }
          }
      }
  }
}

fn handle_send_chunk(
  worker: ConnectionWorker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyFinished),
      )
    Ok(request) -> {
      let total = request.response_body_bytes + bit_array.byte_size(bytes)
      case
        request.response_started,
        request.response_finished,
        request.failure,
        exceeds_streaming_body_limit(
          request.declared_content_length,
          total,
          worker.response_body_limit,
        ),
        exceeds_declared_length(request.declared_content_length, total)
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _, _ -> reply_error(worker, reply, error)
        _, _, _, True, _ ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        _, _, _, _, True -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, False, False ->
          case
            send_response_bytes(worker.connection, request.stream_id, bytes)
          {
            Error(error) ->
              reply_error(worker, reply, map_connection_error(error))
            Ok(connection) -> {
              process.send(reply, Ok(Nil))
              Ok(put_request(
                ConnectionWorker(..worker, connection: connection),
                RequestState(..request, response_body_bytes: total),
              ))
            }
          }
      }
    }
  }
}

fn handle_send_capsule(
  worker: ConnectionWorker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyFinished),
      )
    Ok(RequestState(capsule_established: False, ..)) ->
      reply_error(worker, reply, CapsuleProtocolUnavailable)
    Ok(_) -> handle_send_chunk(worker, identifier, bytes, reply)
  }
}

fn handle_finish_response(
  worker: ConnectionWorker,
  identifier: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyFinished),
      )
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure,
        declared_length_matches(
          request.declared_content_length,
          request.response_body_bytes,
        )
      {
        False, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, True ->
          case
            server_connection.finish_stream(
              worker.connection,
              request.stream_id,
            )
          {
            Error(error) ->
              reply_error(worker, reply, map_connection_error(error))
            Ok(connection) -> {
              process.send(reply, Ok(Nil))
              Ok(put_request(
                ConnectionWorker(..worker, connection: connection),
                RequestState(..request, response_finished: True),
              ))
            }
          }
      }
  }
}

fn handle_finish_with_trailers(
  worker: ConnectionWorker,
  identifier: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, ResponseAlreadyFinished),
      )
    Ok(request) ->
      case
        request.response_started,
        request.response_finished,
        request.failure,
        declared_length_matches(
          request.declared_content_length,
          request.response_body_bytes,
        )
      {
        False, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, True ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) -> {
              let outcome = {
                use connection <- result.try(server_connection.send_trailers(
                  worker.connection,
                  request.stream_id,
                  fields,
                ))
                server_connection.finish_stream(connection, request.stream_id)
              }
              case outcome {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_request(
                    ConnectionWorker(..worker, connection: connection),
                    RequestState(..request, response_finished: True),
                  ))
                }
              }
            }
          }
      }
  }
}

fn handle_promise_push(
  worker: ConnectionWorker,
  request_identifier: Int,
  path: String,
  headers: List(#(String, String)),
  reply: Subject(Result(Int, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, request_identifier) {
    Error(_) -> reply_error(worker, reply, StreamFinished)
    Ok(request) ->
      case request.failure, request.scheme, request.authority, path {
        Some(error), _, _, _ -> reply_error(worker, reply, error)
        None, "", _, _ | None, _, "", _ | None, _, _, "" ->
          reply_error(worker, reply, InvalidInput)
        None, scheme, authority, path ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(regular) -> {
              let fields = [
                Header(<<":method">>, <<"GET">>, False),
                Header(<<":scheme">>, <<scheme:utf8>>, False),
                Header(<<":authority">>, <<authority:utf8>>, False),
                Header(<<":path">>, <<path:utf8>>, False),
                ..regular
              ]
              case
                server_connection.promise_push(
                  worker.connection,
                  request.stream_id,
                  fields,
                  now(),
                )
              {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(#(connection, push_id, stream_id)) -> {
                  let push =
                    PushState(push_id, stream_id, False, False, 0, None, None)
                  process.send(reply, Ok(push_id))
                  Ok(
                    ConnectionWorker(
                      ..worker,
                      connection: connection,
                      pushes: dict.insert(worker.pushes, push_id, push),
                    ),
                  )
                }
              }
            }
          }
      }
  }
}

fn handle_send_push_response(
  worker: ConnectionWorker,
  identifier: Int,
  status: Int,
  headers: List(#(String, String)),
  declared_content_length: Option(Int),
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, PushCancelled)
    Ok(_) if status < 200 || status > 599 ->
      reply_error(worker, reply, InvalidInput)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.failure,
        exceeds_response_body_limit(
          declared_content_length,
          worker.response_body_limit,
        )
      {
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        False, False, None, True ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        False, False, None, False ->
          case response_headers(status, headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) ->
              case
                server_connection.send_push_response_headers(
                  worker.connection,
                  push.stream_id,
                  fields,
                )
              {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_push(
                    ConnectionWorker(..worker, connection: connection),
                    PushState(
                      ..push,
                      response_started: True,
                      declared_content_length: declared_content_length,
                    ),
                  ))
                }
              }
          }
      }
  }
}

fn handle_send_push_chunk(
  worker: ConnectionWorker,
  identifier: Int,
  bytes: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, PushCancelled)
    Ok(push) -> {
      let total = push.response_body_bytes + bit_array.byte_size(bytes)
      case
        push.response_started,
        push.response_finished,
        push.failure,
        exceeds_streaming_body_limit(
          push.declared_content_length,
          total,
          worker.response_body_limit,
        ),
        exceeds_declared_length(push.declared_content_length, total)
      {
        False, _, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _, _ -> reply_error(worker, reply, error)
        _, _, _, True, _ ->
          reply_error(
            worker,
            reply,
            ResponseBodyTooLarge(worker.response_body_limit),
          )
        _, _, _, _, True -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, False, False ->
          case send_push_bytes(worker.connection, push.stream_id, bytes) {
            Error(error) ->
              reply_error(worker, reply, map_connection_error(error))
            Ok(connection) -> {
              process.send(reply, Ok(Nil))
              Ok(put_push(
                ConnectionWorker(..worker, connection: connection),
                PushState(..push, response_body_bytes: total),
              ))
            }
          }
      }
    }
  }
}

fn handle_finish_push(
  worker: ConnectionWorker,
  identifier: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, PushCancelled)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.failure,
        declared_length_matches(
          push.declared_content_length,
          push.response_body_bytes,
        )
      {
        False, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, True ->
          case
            server_connection.finish_push(worker.connection, push.stream_id)
          {
            Error(error) ->
              reply_error(worker, reply, map_connection_error(error))
            Ok(connection) -> {
              process.send(reply, Ok(Nil))
              Ok(put_push(
                ConnectionWorker(..worker, connection: connection),
                PushState(..push, response_finished: True),
              ))
            }
          }
      }
  }
}

fn handle_finish_push_with_trailers(
  worker: ConnectionWorker,
  identifier: Int,
  headers: List(#(String, String)),
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> reply_error(worker, reply, PushCancelled)
    Ok(push) ->
      case
        push.response_started,
        push.response_finished,
        push.failure,
        declared_length_matches(
          push.declared_content_length,
          push.response_body_bytes,
        )
      {
        False, _, _, _ -> reply_error(worker, reply, ResponseNotStarted)
        _, True, _, _ -> reply_error(worker, reply, ResponseAlreadyFinished)
        _, _, Some(error), _ -> reply_error(worker, reply, error)
        _, _, _, False -> reply_error(worker, reply, InvalidContentLength)
        True, False, None, True ->
          case encode_headers(headers) {
            Error(error) -> reply_error(worker, reply, error)
            Ok(fields) -> {
              let outcome = {
                use connection <- result.try(
                  server_connection.send_push_trailers(
                    worker.connection,
                    push.stream_id,
                    fields,
                  ),
                )
                server_connection.finish_push(connection, push.stream_id)
              }
              case outcome {
                Error(error) ->
                  reply_error(worker, reply, map_connection_error(error))
                Ok(connection) -> {
                  process.send(reply, Ok(Nil))
                  Ok(put_push(
                    ConnectionWorker(..worker, connection: connection),
                    PushState(..push, response_finished: True),
                  ))
                }
              }
            }
          }
      }
  }
}

fn handle_send_datagram(
  worker: ConnectionWorker,
  identifier: Int,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, StreamFinished),
      )
    Ok(request) ->
      case
        server_connection.send_http_datagram(
          worker.connection,
          request.stream_id,
          payload,
        )
      {
        Error(error) -> reply_error(worker, reply, map_connection_error(error))
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(ConnectionWorker(..worker, connection: connection))
        }
      }
  }
}

fn handle_next_datagram(
  worker: ConnectionWorker,
  identifier: Int,
  reply: Subject(Result(BitArray, Error)),
  deadline: Int,
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier) {
    Error(_) ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, StreamFinished),
      )
    Ok(request) ->
      case
        queue_pop(request.datagrams),
        request.failure,
        request.datagram_waiter
      {
        Ok(#(payload, datagrams)), _, _ -> {
          process.send(reply, Ok(payload))
          Ok(put_request(
            worker,
            RequestState(
              ..request,
              datagrams: datagrams,
              buffered_datagram_bytes: int.max(
                request.buffered_datagram_bytes - bit_array.byte_size(payload),
                0,
              ),
            ),
          ))
        }
        Error(Nil), Some(error), _ -> reply_error(worker, reply, error)
        Error(Nil), None, Some(_) ->
          reply_error(worker, reply, ConcurrentDatagramReceive)
        Error(Nil), None, None ->
          Ok(put_request(
            worker,
            RequestState(
              ..request,
              datagram_waiter: Some(DatagramWaiter(reply, deadline)),
            ),
          ))
      }
  }
}

fn handle_set_priority(
  worker: ConnectionWorker,
  identifier: Int,
  urgency: Int,
  incremental: Bool,
  reply: Subject(Result(Nil, Error)),
) -> Result(ConnectionWorker, Nil) {
  case dict.get(worker.requests, identifier), urgency >= 0 && urgency <= 7 {
    Error(_), _ ->
      reply_error(
        worker,
        reply,
        request_error(worker, identifier, StreamFinished),
      )
    _, False -> reply_error(worker, reply, InvalidInput)
    Ok(request), True -> {
      process.send(reply, Ok(Nil))
      Ok(put_request(
        worker,
        RequestState(..request, priority: #(urgency, incremental)),
      ))
    }
  }
}

fn begin_connection_drain(worker: ConnectionWorker) -> ConnectionWorker {
  case worker.draining {
    True -> worker
    False ->
      case server_connection.start_drain(worker.connection, now()) {
        Error(_) -> ConnectionWorker(..worker, draining: True, closed: True)
        Ok(connection) ->
          case
            server_connection.refine_drain(
              connection,
              worker.next_request_stream_id,
            )
          {
            Error(_) ->
              ConnectionWorker(..worker, connection: connection, draining: True)
            Ok(#(connection, rejected)) ->
              reject_request_streams(
                ConnectionWorker(
                  ..worker,
                  connection: connection,
                  draining: True,
                ),
                rejected,
              )
          }
      }
  }
}

fn reject_request_streams(
  worker: ConnectionWorker,
  identifiers: List(Int),
) -> ConnectionWorker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      reject_request_streams(
        abort_request_stream(worker, identifier, request_rejected_code)
          |> fail_request(identifier, ListenerClosed),
        rest,
      )
  }
}

fn all_connection_work_complete(worker: ConnectionWorker) -> Bool {
  list.all(dict.values(worker.requests), fn(request) {
    option.is_some(request.failure)
    || request.request_finished
    && request.response_finished
  })
  && list.all(dict.values(worker.pushes), fn(push) {
    option.is_some(push.failure) || push.response_finished
  })
}

fn transport_work_complete(worker: ConnectionWorker) -> Bool {
  list.all(dict.values(worker.requests), fn(request) {
    case request.failure {
      Some(_) -> True
      None ->
        server_connection.stream_send_finished(
          worker.connection,
          request.stream_id,
        )
        == Ok(True)
    }
  })
  && list.all(dict.values(worker.pushes), fn(push) {
    case push.failure {
      Some(_) -> True
      None ->
        server_connection.stream_send_finished(
          worker.connection,
          push.stream_id,
        )
        == Ok(True)
    }
  })
}

fn connection_next_deadline(worker: ConnectionWorker) -> Option(Int) {
  let deadline = request_waiter_deadlines(dict.values(worker.requests), None)
  let deadline = case worker.draining && all_connection_work_complete(worker) {
    True ->
      earlier_deadline(
        deadline,
        Some(now() + drain_transport_poll_milliseconds),
      )
    False -> deadline
  }
  case worker.next_keepalive_milliseconds > 0 {
    True -> earlier_deadline(deadline, Some(worker.next_keepalive_milliseconds))
    False -> deadline
  }
}

fn maybe_send_keepalive(
  worker: ConnectionWorker,
  current: Int,
) -> ConnectionWorker {
  case worker.keepalive_milliseconds, worker.next_keepalive_milliseconds {
    0, _ -> worker
    _, deadline if deadline > current -> worker
    interval, _ ->
      case server_connection.ping(worker.connection) {
        Error(_) -> ConnectionWorker(..worker, closed: True)
        Ok(connection) ->
          ConnectionWorker(
            ..worker,
            connection: connection,
            next_keepalive_milliseconds: current + interval,
          )
      }
  }
}

fn request_waiter_deadlines(
  requests: List(RequestState),
  earliest: Option(Int),
) -> Option(Int) {
  case requests {
    [] -> earliest
    [request, ..rest] -> {
      let earliest = case request.event_waiter {
        Some(EventWaiter(_, deadline)) ->
          earlier_deadline(earliest, Some(deadline))
        None -> earliest
      }
      let earliest = case request.datagram_waiter {
        Some(DatagramWaiter(_, deadline)) ->
          earlier_deadline(earliest, Some(deadline))
        None -> earliest
      }
      request_waiter_deadlines(rest, earliest)
    }
  }
}

fn expire_connection_waiters(
  worker: ConnectionWorker,
  current: Int,
) -> ConnectionWorker {
  expire_request_entries(worker, dict.to_list(worker.requests), current)
}

fn expire_request_entries(
  worker: ConnectionWorker,
  entries: List(#(Int, RequestState)),
  current: Int,
) -> ConnectionWorker {
  case entries {
    [] -> worker
    [#(_, request), ..rest] -> {
      let event_waiter = case request.event_waiter {
        Some(EventWaiter(reply, deadline)) if current >= deadline -> {
          process.send(reply, Error(Timeout))
          None
        }
        waiter -> waiter
      }
      let datagram_waiter = case request.datagram_waiter {
        Some(DatagramWaiter(reply, deadline)) if current >= deadline -> {
          process.send(reply, Error(Timeout))
          None
        }
        waiter -> waiter
      }
      expire_request_entries(
        put_request(
          worker,
          RequestState(
            ..request,
            event_waiter: event_waiter,
            datagram_waiter: datagram_waiter,
          ),
        ),
        rest,
        current,
      )
    }
  }
}

fn close_request_waiters(requests: List(RequestState), error: Error) -> Nil {
  case requests {
    [] -> Nil
    [request, ..rest] -> {
      case request.event_waiter {
        Some(EventWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      case request.datagram_waiter {
        Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      close_request_waiters(rest, error)
    }
  }
}

fn abort_request_stream(
  worker: ConnectionWorker,
  stream_id: Int,
  code: Int,
) -> ConnectionWorker {
  case server_connection.abort_stream(worker.connection, stream_id, code) {
    Ok(connection) -> ConnectionWorker(..worker, connection: connection)
    Error(_) -> worker
  }
}

fn fail_request(
  worker: ConnectionWorker,
  identifier: Int,
  error: Error,
) -> ConnectionWorker {
  case dict.get(worker.requests, identifier) {
    Error(_) -> worker
    Ok(RequestState(failure: Some(_), ..)) -> worker
    Ok(request) -> {
      case request.event_waiter {
        Some(EventWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      case request.datagram_waiter {
        Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      put_request(
        worker,
        RequestState(
          ..request,
          event_waiter: None,
          datagram_waiter: None,
          failure: Some(error),
        ),
      )
    }
  }
}

fn discard_request_payloads(
  worker: ConnectionWorker,
  identifier: Int,
) -> ConnectionWorker {
  case dict.get(worker.requests, identifier) {
    Error(_) -> worker
    Ok(request) ->
      put_request(
        worker,
        RequestState(
          ..request,
          events: queue_new(),
          buffered_body_bytes: 0,
          datagrams: queue_new(),
          buffered_datagram_bytes: 0,
        ),
      )
  }
}

fn fail_push(
  worker: ConnectionWorker,
  identifier: Int,
  error: Error,
) -> ConnectionWorker {
  case dict.get(worker.pushes, identifier) {
    Error(_) -> worker
    Ok(push) -> put_push(worker, PushState(..push, failure: Some(error)))
  }
}

fn fail_all_requests(
  worker: ConnectionWorker,
  error: Error,
) -> ConnectionWorker {
  let worker = fail_request_entries(worker, dict.keys(worker.requests), error)
  fail_push_entries(worker, dict.keys(worker.pushes), error)
}

fn fail_request_entries(
  worker: ConnectionWorker,
  identifiers: List(Int),
  error: Error,
) -> ConnectionWorker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_request_entries(fail_request(worker, identifier, error), rest, error)
  }
}

fn fail_push_entries(
  worker: ConnectionWorker,
  identifiers: List(Int),
  error: Error,
) -> ConnectionWorker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      fail_push_entries(fail_push(worker, identifier, error), rest, error)
  }
}

fn send_response_bytes(
  connection: server_connection.State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(server_connection.State, server_connection.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_response_data_chunk_bytes {
    True -> server_connection.send_data(connection, stream_id, bytes)
    False -> {
      use #(chunk, rest) <- result.try(split_chunk(bytes))
      use connection <- result.try(server_connection.send_data(
        connection,
        stream_id,
        chunk,
      ))
      send_response_bytes(connection, stream_id, rest)
    }
  }
}

fn send_push_bytes(
  connection: server_connection.State,
  stream_id: Int,
  bytes: BitArray,
) -> Result(server_connection.State, server_connection.Error) {
  let size = bit_array.byte_size(bytes)
  case size <= maximum_response_data_chunk_bytes {
    True -> server_connection.send_push_data(connection, stream_id, bytes)
    False -> {
      use #(chunk, rest) <- result.try(split_chunk(bytes))
      use connection <- result.try(server_connection.send_push_data(
        connection,
        stream_id,
        chunk,
      ))
      send_push_bytes(connection, stream_id, rest)
    }
  }
}

fn split_chunk(
  bytes: BitArray,
) -> Result(#(BitArray, BitArray), server_connection.Error) {
  let size = bit_array.byte_size(bytes)
  use chunk <- result.try(
    bit_array.slice(bytes, 0, maximum_response_data_chunk_bytes)
    |> result.replace_error(server_connection.InvalidInput),
  )
  use rest <- result.try(
    bit_array.slice(
      bytes,
      maximum_response_data_chunk_bytes,
      size - maximum_response_data_chunk_bytes,
    )
    |> result.replace_error(server_connection.InvalidInput),
  )
  Ok(#(chunk, rest))
}

fn put_request(
  worker: ConnectionWorker,
  request: RequestState,
) -> ConnectionWorker {
  case request_terminal(worker.connection, request) {
    None ->
      ConnectionWorker(
        ..worker,
        requests: dict.insert(worker.requests, request.stream_id, request),
      )
    Some(terminal) -> {
      let error = request_terminal_error(terminal)
      case request.event_waiter {
        Some(EventWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      case request.datagram_waiter {
        Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
        None -> Nil
      }
      let connection = case terminal {
        RequestCompleted ->
          server_connection.retire_stream(worker.connection, request.stream_id)
        RequestFailed(_) -> worker.connection
      }
      ConnectionWorker(
        ..worker,
        connection: connection,
        requests: dict.delete(worker.requests, request.stream_id),
        request_terminals: terminal_registry.insert(
          worker.request_terminals,
          request.stream_id,
          terminal,
        ),
        pending_priorities: dict.delete(
          worker.pending_priorities,
          request.stream_id,
        ),
      )
    }
  }
}

fn retire_completed_requests(worker: ConnectionWorker) -> ConnectionWorker {
  list.fold(dict.values(worker.requests), worker, fn(worker, request) {
    put_request(worker, request)
  })
}

fn request_terminal(
  connection: server_connection.State,
  request: RequestState,
) -> Option(RequestTerminal) {
  case
    queue_is_empty(request.events),
    request.failure,
    request.request_finished && request.response_finished
  {
    True, Some(error), _ -> Some(RequestFailed(error))
    True, None, True ->
      case
        server_connection.stream_send_finished(connection, request.stream_id)
      {
        Ok(True) -> Some(RequestCompleted)
        Ok(False) | Error(_) -> None
      }
    _, _, _ -> None
  }
}

fn request_terminal_error(terminal: RequestTerminal) -> Error {
  case terminal {
    RequestCompleted -> StreamFinished
    RequestFailed(error) -> error
  }
}

fn request_terminal_cancellation(
  terminals: terminal_registry.Registry(RequestTerminal),
  identifier: Int,
) -> Cancellation {
  case terminal_registry.get(terminals, identifier) {
    Ok(RequestFailed(StreamCancelled(code))) if code == request_cancelled_code ->
      AlreadyCancelled
    Ok(_) | Error(_) -> AlreadyCompleted
  }
}

fn put_push(worker: ConnectionWorker, push: PushState) -> ConnectionWorker {
  ConnectionWorker(
    ..worker,
    pushes: dict.insert(worker.pushes, push.push_id, push),
  )
}

fn request_error(
  worker: ConnectionWorker,
  identifier: Int,
  fallback: Error,
) -> Error {
  case dict.get(worker.requests, identifier) {
    Ok(RequestState(failure: Some(error), ..)) -> error
    Ok(_) -> fallback
    Error(_) ->
      terminal_registry.get(worker.request_terminals, identifier)
      |> result.map(request_terminal_error)
      |> result.unwrap(fallback)
  }
}

fn response_headers(
  status: Int,
  headers: List(#(String, String)),
) -> Result(List(Header), Error) {
  use regular <- result.try(encode_headers(headers))
  Ok([Header(<<":status">>, <<int.to_string(status):utf8>>, False), ..regular])
}

fn capsule_success_status(status: Int) -> Bool {
  status >= 200
  && status < 300
  && status != 204
  && status != 205
  && status != 206
}

fn has_forbidden_capsule_field(headers: List(#(String, String))) -> Bool {
  list.any(headers, fn(field) {
    let #(name, _) = field
    name == "content-length"
    || name == "content-type"
    || name == "transfer-encoding"
  })
}

fn encode_headers(
  headers: List(#(String, String)),
) -> Result(List(Header), Error) {
  case headers {
    [] -> Ok([])
    [#(name, value), ..rest] -> {
      use rest <- result.try(encode_headers(rest))
      Ok([Header(<<name:utf8>>, <<value:utf8>>, False), ..rest])
    }
  }
}

fn decode_request(
  validated: header_semantics.Validated,
) -> Result(
  #(String, String, Option(String), String, String, List(#(String, String))),
  Error,
) {
  let header_semantics.Validated(control, fields, _) = validated
  use request <- result.try(case control {
    header_semantics.RequestControlData(request) -> Ok(request)
    _ -> Error(ProtocolError(0x105, "invalid request control"))
  })
  let header_semantics.RequestControl(method, scheme, authority, path, protocol) =
    request
  use method <- result.try(
    bit_array.to_string(method) |> result.replace_error(InvalidHeaderEncoding),
  )
  use path <- result.try(decode_optional_text(path, ""))
  use scheme <- result.try(decode_optional_text(scheme, ""))
  use authority <- result.try(decode_optional_text(authority, ""))
  use application_protocol <- result.try(case protocol {
    None -> Ok(None)
    Some(value) ->
      bit_array.to_string(value)
      |> result.map(Some)
      |> result.replace_error(InvalidHeaderEncoding)
  })
  use fields <- result.try(decode_headers(fields))
  Ok(#(method, path, application_protocol, scheme, authority, fields))
}

fn decode_optional_text(
  value: Option(BitArray),
  fallback: String,
) -> Result(String, Error) {
  case value {
    None -> Ok(fallback)
    Some(bytes) ->
      bit_array.to_string(bytes) |> result.replace_error(InvalidHeaderEncoding)
  }
}

fn decode_trailers(
  validated: header_semantics.Validated,
) -> Result(List(#(String, String)), Error) {
  let header_semantics.Validated(_, fields, _) = validated
  decode_headers(fields)
}

fn decode_headers(
  fields: List(Header),
) -> Result(List(#(String, String)), Error) {
  case fields {
    [] -> Ok([])
    [Header(name, value, _), ..rest] -> {
      use name <- result.try(
        bit_array.to_string(name) |> result.replace_error(InvalidHeaderEncoding),
      )
      use value <- result.try(
        bit_array.to_string(value)
        |> result.replace_error(InvalidHeaderEncoding),
      )
      use rest <- result.try(decode_headers(rest))
      Ok([#(name, value), ..rest])
    }
  }
}

fn exceeds_declared_length(length: Option(Int), actual: Int) -> Bool {
  case length {
    Some(expected) -> actual > expected
    None -> False
  }
}

fn exceeds_response_body_limit(length: Option(Int), limit: Int) -> Bool {
  case length {
    Some(expected) -> expected > limit
    None -> False
  }
}

fn exceeds_streaming_body_limit(
  length: Option(Int),
  actual: Int,
  limit: Int,
) -> Bool {
  case length {
    Some(_) -> actual > limit
    None -> False
  }
}

fn declared_length_matches(length: Option(Int), actual: Int) -> Bool {
  case length {
    Some(expected) -> actual == expected
    None -> True
  }
}

fn validate_start(
  port: Int,
  bind_address: Option(BitArray),
  timeout_milliseconds: Int,
  drain_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  request_body_limit: Int,
  response_body_limit: Int,
  stream_buffer_limit: Int,
  endpoint_memory_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  frame_limit: Int,
  datagram_limit: Int,
  qpack_table_limit: Int,
  qpack_blocked_stream_limit: Int,
  accept_waiter_limit: Int,
  keepalive_milliseconds: Int,
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(Nil, Error) {
  case
    port >= 0
    && port <= 65_535
    && valid_bind_address(bind_address)
    && timeout_milliseconds > 0
    && drain_timeout_milliseconds > 0
    && idle_timeout_milliseconds > 0
    && request_body_limit > 0
    && response_body_limit > 0
    && stream_buffer_limit > 0
    && endpoint_memory_limit > 0
    && connection_limit > 0
    && handshake_limit > 0
    && queue_limit > 0
    && telemetry_limit > 0
    && bidirectional_stream_limit > 0
    && unidirectional_stream_limit > 0
    && frame_limit > 0
    && datagram_limit > 0
    && qpack_table_limit > 0
    && qpack_blocked_stream_limit > 0
    && accept_waiter_limit > 0
    && {
      keepalive_milliseconds == 0
      || { keepalive_milliseconds >= 1000 && keepalive_milliseconds <= 29_000 }
    }
    && valid_optional_key_ring(ticket_keys)
    && valid_optional_key_ring(address_token_keys)
    && valid_optional_key_ring(stateless_reset_keys)
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn valid_bind_address(address: Option(BitArray)) -> Bool {
  case address {
    None -> True
    Some(bytes) ->
      bit_array.bit_size(bytes) % 8 == 0
      && { bit_array.byte_size(bytes) == 4 || bit_array.byte_size(bytes) == 16 }
  }
}

fn valid_optional_key_ring(keys: List(BitArray)) -> Bool {
  case keys {
    [] -> True
    [current] -> valid_operational_key(current)
    [current, previous] ->
      current != previous
      && valid_operational_key(current)
      && valid_operational_key(previous)
    _ -> False
  }
}

fn valid_operational_key(key: BitArray) -> Bool {
  bit_array.bit_size(key) % 8 == 0 && bit_array.byte_size(key) == 32
}

fn all_keys_distinct(keys: List(BitArray)) -> Bool {
  case keys {
    [] -> True
    [key, ..rest] -> !list.contains(rest, key) && all_keys_distinct(rest)
  }
}

fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

fn queue_count(queue: Queue(value)) -> Int {
  queue.count
}

fn queue_is_empty(queue: Queue(value)) -> Bool {
  queue.count == 0
}

fn queue_push(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, back: [value, ..queue.back], count: queue.count + 1)
}

fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

fn queue_accept_deadline(
  waiters: Queue(AcceptWaiter),
  earliest: Option(Int),
) -> Option(Int) {
  case queue_pop(waiters) {
    Error(Nil) -> earliest
    Ok(#(AcceptWaiter(_, deadline), rest)) ->
      queue_accept_deadline(rest, earlier_deadline(earliest, Some(deadline)))
  }
}

fn earlier_deadline(first: Option(Int), second: Option(Int)) -> Option(Int) {
  case first, second {
    None, deadline | deadline, None -> deadline
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn reply_error(
  worker: ConnectionWorker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(ConnectionWorker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
}

fn await_bootstrap(
  worker: Pid,
  bootstrap: Subject(Result(value, Error)),
  timeout: Int,
  timeout_error: Error,
) -> Result(value, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(bootstrap, fn(reply) { CallReply(reply) })
    |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(CallReply(reply)) -> reply
    Ok(WorkerExited) -> Error(timeout_error)
    Error(Nil) -> {
      process.kill(worker)
      Error(timeout_error)
    }
  }
}

fn listener_call(
  listener: Listener,
  make_command: fn(Subject(Result(value, Error))) -> ListenerCommand,
) -> Result(value, Error) {
  listener_call_with_timeout(
    listener,
    listener.timeout_milliseconds + worker_reply_grace_milliseconds,
    make_command,
  )
}

fn listener_call_with_timeout(
  listener: Listener,
  timeout: Int,
  make_command: fn(Subject(Result(value, Error))) -> ListenerCommand,
) -> Result(value, Error) {
  case process.is_alive(listener.worker) {
    False -> Error(ListenerClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(listener.worker)
      process.send(listener.commands, make_command(reply))
      let outcome =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
        |> process.selector_receive(within: timeout)
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(reply)) -> reply
        Ok(WorkerExited) -> Error(ListenerClosed)
        Error(Nil) -> Error(Timeout)
      }
    }
  }
}

fn connection_call(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> ConnectionCommand,
) -> Result(value, Error) {
  connection_call_with_timeout(
    connection,
    connection.timeout_milliseconds + worker_reply_grace_milliseconds,
    make_command,
  )
}

fn connection_call_with_timeout(
  connection: Connection,
  timeout: Int,
  make_command: fn(Subject(Result(value, Error))) -> ConnectionCommand,
) -> Result(value, Error) {
  case process.is_alive(connection.worker) {
    False -> Error(ConnectionClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(connection.worker)
      process.send(connection.commands, make_command(reply))
      let outcome =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
        |> process.selector_receive(within: timeout)
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(reply)) -> reply
        Ok(WorkerExited) -> Error(ConnectionClosed)
        Error(Nil) -> Error(Timeout)
      }
    }
  }
}

fn map_core_start_error(error: core_server.Error) -> Error {
  case error {
    core_server.Failure(core_failure.Socket(_)) -> StartFailed
    core_server.Failure(core_failure.Timeout(_)) -> Timeout
    _ -> StartFailed
  }
}

fn map_core_runtime_error(error: core_server.Error) -> Error {
  case error {
    core_server.Failure(core_failure.Timeout(_)) -> Timeout
    core_server.Failure(core_failure.Closed(core_failure.Local, _)) ->
      ListenerClosed
    core_server.Failure(core_failure.Closed(_, _)) -> ConnectionClosed
    core_server.Failure(core_failure.Limit(core_failure.Datagram, maximum)) ->
      DatagramTooLarge(maximum)
    core_server.Failure(core_failure.Limit(_, _)) -> CongestionLimited
    core_server.Failure(core_failure.Overload(_)) -> CongestionLimited
    core_server.StreamFinished -> StreamFinished
    core_server.ConcurrentOperation -> ConcurrentSend
    core_server.InvalidOperation | core_server.InvalidDirection ->
      InvalidConnectionState
    core_server.Failure(_) -> ConnectionClosed
  }
}

fn map_connection_error(error: server_connection.Error) -> Error {
  case server_connection.operation_failure(error) {
    Some(server_connection.DatagramsNotNegotiated) -> DatagramsNotNegotiated
    Some(server_connection.DatagramTooLarge(maximum)) ->
      DatagramTooLarge(maximum)
    Some(server_connection.CongestionLimited) -> CongestionLimited
    None -> map_unclassified_connection_error(error)
  }
}

fn close_peer_protocol_failure(
  connection: server_connection.State,
  error: server_connection.Error,
) -> Nil {
  case server_connection.peer_application_error_code(error) {
    Some(code) -> server_connection.close(connection, code)
    None -> Nil
  }
}

fn map_unclassified_connection_error(error: server_connection.Error) -> Error {
  case error {
    server_connection.InvalidInput -> InvalidConnectionState
    server_connection.OperationTimeout -> Timeout
    server_connection.PeerClosed -> ConnectionClosed
    server_connection.CoreFailure(error) -> map_core_runtime_error(error)
    server_connection.ProtocolFailure(protocol.ResourceFailure(protocol.ResourceSendLimited(
      _,
    ))) -> CongestionLimited
    server_connection.ProtocolFailure(protocol.ResourceFailure(
      protocol.ResourceDatagramsNotNegotiated,
    )) -> DatagramsNotNegotiated
    server_connection.ProtocolFailure(protocol.ResourceFailure(protocol.ResourceDatagramTooLarge(
      maximum,
    ))) -> DatagramTooLarge(maximum)
    server_connection.ProtocolFailure(protocol.ResourceFailure(_)) ->
      ConnectionClosed
    server_connection.ProtocolFailure(protocol.Http3Failure(http3_state.DatagramFailure(datagram.UnknownAssociation(
      _,
    )))) -> DatagramNotAssociated
    server_connection.ProtocolFailure(protocol.Http3Failure(http3_state.DatagramFailure(
      datagram.UnreliableDatagramNotNegotiated,
    ))) -> DatagramsNotNegotiated
    server_connection.ProtocolFailure(protocol.Http3Failure(http3_state.MessageFailure(
      message_stream.ContentLengthExceeded(..),
    )))
    | server_connection.ProtocolFailure(protocol.Http3Failure(http3_state.MessageFailure(
        message_stream.ContentLengthMismatch(..),
      ))) -> InvalidContentLength
    server_connection.ProtocolFailure(_) ->
      ProtocolError(0x101, "HTTP/3 protocol failure")
  }
}

fn now() -> Int {
  qlog.monotonic_milliseconds()
}
