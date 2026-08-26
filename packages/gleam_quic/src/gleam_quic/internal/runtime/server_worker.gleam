//// Event-driven generic QUIC listener actor.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic.{type AddressFamily, DualStack, Ipv4, Ipv6}
import gleam_quic/internal/address_token
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/process_label
import gleam_quic/internal/qlog
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/runtime/connection as runtime_connection
import gleam_quic/internal/runtime/server_transport
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/replay_guard
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/packet
import gleam_quic/stream_id
import gleam_quic/version.{type Version}

const connection_id_bytes = 8

const maximum_packets_per_flush = 64

// Pre-validation floor for one packet's frame payload. The send path widens it
// to whatever DPLPMTUD has validated for the current path.
const maximum_frame_data_bytes = 1000

const maximum_send_chunk_bytes = 65_536

const pmtu_probe_interval_milliseconds = 50

const replay_window_milliseconds = 10_000

const replay_cache_capacity = 4096

const ticket_age_tolerance_milliseconds = 10_000

const retry_token_lifetime_milliseconds = 10_000

const new_token_lifetime_milliseconds = 86_400_000

const worker_reply_grace_milliseconds = 100

/// Running owner-bound listener.
pub opaque type Listener {
  Listener(commands: Subject(Command), worker: Pid, timeout_milliseconds: Int)
}

/// One accepted generic QUIC connection routed through its listener.
pub opaque type Connection {
  Connection(listener: Listener, identifier: BitArray)
}

/// One stream routed through its owning connection.
pub opaque type Stream {
  Stream(connection: Connection, identifier: Int)
}

/// One peer-initiated stream and its directionality.
pub type IncomingStream {
  IncomingStream(stream: Stream, bidirectional: Bool)
}

/// One bounded pull from a stream receive direction.
pub type Read {
  Data(bytes: BitArray, finished: Bool)
  Finished
  Reset(application_error_code: Int)
}

/// Idempotent listener stop outcome.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// Idempotent connection close outcome.
pub type CloseResult {
  Closed
  AlreadyClosed
}

/// Listener, connection, stream, pressure, or protocol failure.
pub type Error {
  InvalidInput
  StartFailed
  OperationTimeout
  ListenerClosed
  ConnectionClosed
  StreamClosed
  InvalidDirection
  ConcurrentSend
  ConcurrentReceive
  ConcurrentAccept
  ConcurrentDatagramReceive
  ConnectionLimitExceeded(Int)
  HandshakeLimitExceeded(Int)
  AcceptQueueExceeded(Int)
  IncomingStreamQueueExceeded(Int)
  DatagramQueueExceeded(Int)
  DatagramTooLarge(Int)
  DatagramsNotNegotiated
  CongestionLimited
  QlogUnavailable
  QuicFailure
}

type Command {
  Port(reply: Subject(Result(Int, Error)))
  AcceptConnection(reply: Subject(Result(Connection, Error)), deadline: Int)
  Open(
    connection_id: BitArray,
    direction: stream_id.Direction,
    reply: Subject(Result(Int, Error)),
  )
  AcceptStream(
    connection_id: BitArray,
    reply: Subject(Result(IncomingStream, Error)),
    deadline: Int,
  )
  Send(
    connection_id: BitArray,
    stream_id: Int,
    bytes: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  Receive(
    connection_id: BitArray,
    stream_id: Int,
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Int,
  )
  ResetStream(
    connection_id: BitArray,
    stream_id: Int,
    code: Int,
    reply: Subject(Result(Nil, Error)),
  )
  SendDatagram(
    connection_id: BitArray,
    payload: BitArray,
    reply: Subject(Result(Nil, Error)),
  )
  ReceiveDatagram(
    connection_id: BitArray,
    reply: Subject(Result(BitArray, Error)),
    deadline: Int,
  )
  MaximumDatagram(connection_id: BitArray, reply: Subject(Result(Int, Error)))
  Ping(connection_id: BitArray, reply: Subject(Result(Nil, Error)))
  SetCongestion(
    connection_id: BitArray,
    algorithm: transport.CongestionAlgorithm,
    reply: Subject(Result(Nil, Error)),
  )
  PathStats(
    connection_id: BitArray,
    reply: Subject(Result(transport.PathSnapshot, Error)),
  )
  ConnectionStats(
    connection_id: BitArray,
    reply: Subject(Result(runtime_connection.Stats, Error)),
  )
  TelemetryStats(
    connection_id: BitArray,
    reply: Subject(Result(qlog.Stats, Error)),
  )
  Phase(connection_id: BitArray, reply: Subject(Result(transport.Phase, Error)))
  ClientIdentity(
    connection_id: BitArray,
    reply: Subject(Result(Option(BitArray), Error)),
  )
  Protocol(
    connection_id: BitArray,
    reply: Subject(
      Result(
        #(
          Version,
          BitArray,
          transport.CongestionAlgorithm,
          Option(hello.CipherSuite),
          Bool,
          Bool,
          Bool,
        ),
        Error,
      ),
    ),
  )
  CloseConnection(
    connection_id: BitArray,
    reply: Subject(Result(CloseResult, Error)),
  )
  ReloadCertificates(
    certificate_chain: List(BitArray),
    signing_key: authentication.SigningKey,
    signature_scheme: extension_value.SignatureScheme,
    alternatives: List(engine.ServerCredential),
    reply: Subject(Result(Nil, Error)),
  )
  ReloadKeys(
    ticket_keys: List(BitArray),
    address_token_keys: List(BitArray),
    stateless_reset_keys: List(BitArray),
    reply: Subject(Result(Nil, Error)),
  )
  Stop(reply: Subject(Result(StopResult, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
  ReceivedNetwork(Dynamic)
  OwnerExited
}

type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
}

type ConnectionWaiter {
  ConnectionWaiter(reply: Subject(Result(Connection, Error)), deadline: Int)
}

type StreamWaiter {
  StreamWaiter(reply: Subject(Result(IncomingStream, Error)), deadline: Int)
}

type ReadWaiter {
  ReadWaiter(
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Int,
  )
}

type DatagramWaiter {
  DatagramWaiter(reply: Subject(Result(BitArray, Error)), deadline: Int)
}

type PendingSend {
  PendingSend(
    remaining: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
}

type StreamState {
  StreamState(
    read_waiter: Option(ReadWaiter),
    pending_send: Option(PendingSend),
    send_finished: Bool,
    receive_finished: Bool,
  )
}

type CandidatePath {
  CandidatePath(endpoint: udp.Endpoint, received_bytes: Int, sent_bytes: Int)
}

type PeerState {
  PeerState(
    connection: server_transport.State,
    streams: Dict(Int, StreamState),
    incoming: Queue(Int),
    stream_waiter: Option(StreamWaiter),
    datagrams: Queue(BitArray),
    datagram_bytes: Int,
    datagram_waiter: Option(DatagramWaiter),
    accepted: Bool,
    version: Version,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    token_endpoint: Option(udp.Endpoint),
    candidate_path: Option(CandidatePath),
    next_pmtu_probe_milliseconds: Int,
  )
}

type Worker {
  Worker(
    socket: udp.Socket,
    relay: udp.Relay,
    port: Int,
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    server_config: server_transport.Config,
    ticket_keys: List(BitArray),
    address_token_keys: List(BitArray),
    stateless_reset_keys: List(BitArray),
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    connections: Dict(BitArray, PeerState),
    aliases: Dict(BitArray, BitArray),
    dirty_connections: Dict(BitArray, Nil),
    pending_connections: Queue(BitArray),
    connection_waiters: Queue(ConnectionWaiter),
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    connection_limit: Int,
    handshake_limit: Int,
    accept_waiter_limit: Int,
    telemetry_limit: Int,
    qlog_directory: String,
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Start a bounded listener actor.
pub fn start(
  owner: Pid,
  port: Int,
  address_family: AddressFamily,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  accept_waiter_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  alternative_credentials: List(engine.ServerCredential),
  client_authentication: engine.ClientAuthentication,
  application_protocols: List(BitArray),
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  external_replay_guard: Option(replay_guard.Guard),
  configured_ticket_keys: List(BitArray),
  configured_address_token_keys: List(BitArray),
  configured_stateless_reset_keys: List(BitArray),
) -> Result(Listener, Error) {
  let bootstrap = process.new_subject()
  let worker =
    process.spawn_unlinked(fn() {
      process_label.set(process_label.Listener)
      initialise(
        owner,
        bootstrap,
        port,
        address_family,
        operation_timeout_milliseconds,
        idle_timeout_milliseconds,
        stream_buffer_limit,
        queue_limit,
        telemetry_limit,
        connection_limit,
        handshake_limit,
        accept_waiter_limit,
        bidirectional_stream_limit,
        unidirectional_stream_limit,
        datagram_limit,
        certificate_chain,
        signing_key,
        signature_scheme,
        alternative_credentials,
        client_authentication,
        application_protocols,
        congestion_control,
        qlog_directory,
        allow_zero_rtt,
        external_replay_guard,
        configured_ticket_keys,
        configured_address_token_keys,
        configured_stateless_reset_keys,
      )
    })
  await_bootstrap(worker, bootstrap, operation_timeout_milliseconds)
}

pub fn port(listener: Listener) -> Result(Int, Error) {
  call(listener, Port)
}

pub fn accept(listener: Listener) -> Result(Connection, Error) {
  call(listener, fn(reply) {
    AcceptConnection(
      reply,
      udp.monotonic_millisecond() + listener.timeout_milliseconds,
    )
  })
}

pub fn open_bidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Bidirectional)
}

pub fn open_unidirectional(connection: Connection) -> Result(Stream, Error) {
  open(connection, stream_id.Unidirectional)
}

fn open(
  connection: Connection,
  direction: stream_id.Direction,
) -> Result(Stream, Error) {
  call(connection.listener, fn(reply) {
    Open(connection.identifier, direction, reply)
  })
  |> result.map(fn(identifier) { Stream(connection, identifier) })
}

pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  call(connection.listener, fn(reply) {
    AcceptStream(
      connection.identifier,
      reply,
      udp.monotonic_millisecond() + connection.listener.timeout_milliseconds,
    )
  })
}

pub fn send(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, False)
}

pub fn finish(stream: Stream) -> Result(Nil, Error) {
  send_with_fin(stream, <<>>, True)
}

pub fn send_and_finish(stream: Stream, bytes: BitArray) -> Result(Nil, Error) {
  send_with_fin(stream, bytes, True)
}

fn send_with_fin(
  stream: Stream,
  bytes: BitArray,
  finish: Bool,
) -> Result(Nil, Error) {
  let Connection(listener, connection_id) = stream.connection
  call(listener, fn(reply) {
    Send(
      connection_id,
      stream.identifier,
      bytes,
      finish,
      reply,
      udp.monotonic_millisecond() + listener.timeout_milliseconds,
    )
  })
}

pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  let Connection(listener, connection_id) = stream.connection
  call(listener, fn(reply) {
    Receive(
      connection_id,
      stream.identifier,
      maximum_bytes,
      reply,
      udp.monotonic_millisecond() + listener.timeout_milliseconds,
    )
  })
}

pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  let Connection(listener, connection_id) = stream.connection
  call(listener, fn(reply) {
    ResetStream(connection_id, stream.identifier, application_error_code, reply)
  })
}

pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  call(connection.listener, fn(reply) {
    SendDatagram(connection.identifier, payload, reply)
  })
}

pub fn receive_datagram(connection: Connection) -> Result(BitArray, Error) {
  call(connection.listener, fn(reply) {
    ReceiveDatagram(
      connection.identifier,
      reply,
      udp.monotonic_millisecond() + connection.listener.timeout_milliseconds,
    )
  })
}

pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  call(connection.listener, fn(reply) {
    MaximumDatagram(connection.identifier, reply)
  })
}

pub fn ping(connection: Connection) -> Result(Nil, Error) {
  call(connection.listener, fn(reply) { Ping(connection.identifier, reply) })
}

pub fn set_congestion_control(
  connection: Connection,
  algorithm: transport.CongestionAlgorithm,
) -> Result(Nil, Error) {
  call(connection.listener, fn(reply) {
    SetCongestion(connection.identifier, algorithm, reply)
  })
}

pub fn path_stats(
  connection: Connection,
) -> Result(transport.PathSnapshot, Error) {
  call(connection.listener, fn(reply) {
    PathStats(connection.identifier, reply)
  })
}

pub fn connection_stats(
  connection: Connection,
) -> Result(runtime_connection.Stats, Error) {
  call(connection.listener, fn(reply) {
    ConnectionStats(connection.identifier, reply)
  })
}

/// Return a redacted SHA-256 fingerprint for the verified client identity.
pub fn client_identity(
  connection: Connection,
) -> Result(Option(BitArray), Error) {
  call(connection.listener, fn(reply) {
    ClientIdentity(connection.identifier, reply)
  })
}

pub fn telemetry_stats(connection: Connection) -> Result(qlog.Stats, Error) {
  call(connection.listener, fn(reply) {
    TelemetryStats(connection.identifier, reply)
  })
}

pub fn phase(connection: Connection) -> Result(transport.Phase, Error) {
  call(connection.listener, fn(reply) { Phase(connection.identifier, reply) })
}

pub fn negotiated_protocol(
  connection: Connection,
) -> Result(
  #(
    Version,
    BitArray,
    transport.CongestionAlgorithm,
    Option(hello.CipherSuite),
    Bool,
    Bool,
    Bool,
  ),
  Error,
) {
  call(connection.listener, fn(reply) { Protocol(connection.identifier, reply) })
}

pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  call(connection.listener, fn(reply) {
    CloseConnection(connection.identifier, reply)
  })
}

pub fn reload_certificates(
  listener: Listener,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  alternatives: List(engine.ServerCredential),
) -> Result(Nil, Error) {
  call(listener, fn(reply) {
    ReloadCertificates(
      certificate_chain,
      signing_key,
      signature_scheme,
      alternatives,
      reply,
    )
  })
}

pub fn reload_keys(
  listener: Listener,
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  stateless_reset_keys: List(BitArray),
) -> Result(Nil, Error) {
  call(listener, fn(reply) {
    ReloadKeys(ticket_keys, address_token_keys, stateless_reset_keys, reply)
  })
}

pub fn stop(listener: Listener) -> Result(StopResult, Error) {
  call(listener, Stop)
}

fn initialise(
  owner: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  port: Int,
  address_family: AddressFamily,
  operation_timeout_milliseconds: Int,
  idle_timeout_milliseconds: Int,
  stream_buffer_limit: Int,
  queue_limit: Int,
  telemetry_limit: Int,
  connection_limit: Int,
  handshake_limit: Int,
  accept_waiter_limit: Int,
  bidirectional_stream_limit: Int,
  unidirectional_stream_limit: Int,
  datagram_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  alternative_credentials: List(engine.ServerCredential),
  client_authentication: engine.ClientAuthentication,
  application_protocols: List(BitArray),
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  external_replay_guard: Option(replay_guard.Guard),
  configured_ticket_keys: List(BitArray),
  configured_address_token_keys: List(BitArray),
  configured_stateless_reset_keys: List(BitArray),
) -> Nil {
  let startup = {
    use socket <- result.try(
      open_listener(address_family, port) |> result.replace_error(StartFailed),
    )
    use local <- result.try(
      udp.local_endpoint(socket) |> result.replace_error(StartFailed),
    )
    let #(_, bound_port) = udp.endpoint_parts(local)
    use ticket_keys <- result.try(
      resolve_key_ring(configured_ticket_keys)
      |> result.replace_error(StartFailed),
    )
    use address_token_keys <- result.try(
      resolve_key_ring(configured_address_token_keys)
      |> result.replace_error(StartFailed),
    )
    use reset_keys <- result.try(
      resolve_key_ring(configured_stateless_reset_keys)
      |> result.replace_error(StartFailed),
    )
    use replay_cache <- result.try(
      anti_replay.new(replay_window_milliseconds, replay_cache_capacity)
      |> result.replace_error(StartFailed),
    )
    use Nil <- result.try(validate_qlog_directory(qlog_directory))
    use relay <- result.try(
      udp.start_relay(socket) |> result.replace_error(StartFailed),
    )
    Ok(#(
      socket,
      relay,
      bound_port,
      ticket_keys,
      address_token_keys,
      reset_keys,
      replay_cache,
    ))
  }
  case startup {
    Error(error) -> process.send(bootstrap, Error(error))
    Ok(#(
      socket,
      relay,
      bound_port,
      ticket_keys,
      address_token_keys,
      reset_keys,
      replay_cache,
    )) -> {
      let assert [ticket_key, ..] = ticket_keys
      let assert [reset_key, ..] = reset_keys
      let commands = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedCommand)
        |> process.select_specific_monitor(owner_monitor, fn(_) { OwnerExited })
        |> process.select_other(ReceivedNetwork)
      let server_config =
        server_transport.Config(
          certificate_chain,
          signing_key,
          signature_scheme,
          alternative_credentials,
          client_authentication,
          application_protocols,
          ticket_key,
          reset_key,
          allow_zero_rtt,
          idle_timeout_milliseconds,
          congestion_control,
          bidirectional_stream_limit,
          unidirectional_stream_limit,
          stream_buffer_limit,
          datagram_limit,
        )
      let listener =
        Listener(commands, process.self(), operation_timeout_milliseconds)
      process.send(bootstrap, Ok(listener))
      loop(Worker(
        socket,
        relay,
        bound_port,
        commands,
        selector,
        server_config,
        ticket_keys,
        address_token_keys,
        reset_keys,
        replay_cache,
        external_replay_guard,
        allow_zero_rtt,
        dict.new(),
        dict.new(),
        dict.new(),
        queue_new(),
        queue_new(),
        operation_timeout_milliseconds,
        stream_buffer_limit,
        queue_limit,
        datagram_limit,
        connection_limit,
        handshake_limit,
        accept_waiter_limit,
        telemetry_limit,
        qlog_directory,
      ))
    }
  }
}

fn loop(worker: Worker) -> Nil {
  let worker = dispatch_all_events(worker)
  let now = udp.monotonic_millisecond()
  let worker = expire_waiters(worker, now)
  let worker = retry_pending_sends(worker)
  case dict.size(worker.dirty_connections) > 0 {
    True -> drive_and_loop(worker)
    False -> wait_for_work(worker, now)
  }
}

fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case next_worker_deadline(worker, now) {
    Error(_) -> shutdown(worker, ConnectionClosed)
    Ok(deadline) -> {
      let received = case deadline {
        None -> Ok(process.selector_receive_forever(worker.selector))
        Some(value) ->
          process.selector_receive(
            worker.selector,
            within: int.max(0, value - now),
          )
      }
      case received {
        Ok(OwnerExited) -> shutdown(worker, ListenerClosed)
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(next) -> drive_and_loop(next)
          }
        Ok(ReceivedNetwork(message)) -> network_step(worker, message)
        Error(Nil) -> timer_drive_and_loop(worker)
      }
    }
  }
}

fn network_step(worker: Worker, message: Dynamic) -> Nil {
  case udp.receive_relay_batch(worker.relay, message) {
    Ok(datagrams) ->
      case udp.continue_relay(worker.relay) {
        Ok(Nil) -> drive_and_loop(route_batch(worker, datagrams))
        Error(_) -> shutdown(worker, ListenerClosed)
      }
    Error(udp.InvalidInput) -> loop(worker)
    Error(_) -> shutdown(worker, ListenerClosed)
  }
}

fn route_batch(worker: Worker, datagrams: List(udp.Datagram)) -> Worker {
  case datagrams {
    [] -> worker
    [udp.Datagram(peer, bytes, marking), ..rest] ->
      route_batch(route_datagram(worker, peer, bytes, marking), rest)
  }
}

fn route_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case datagram {
    <<first, _rest:bits>> if first >= 0x80 ->
      route_long_datagram(worker, peer, datagram, marking)
    <<_first, destination:bytes-size(connection_id_bytes), _rest:bits>> ->
      route_existing(worker, destination, peer, datagram, marking)
    _ -> worker
  }
}

fn route_long_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case packet.parse_long(datagram) {
    Error(_) -> worker
    Ok(#(parsed, _)) -> {
      let packet.LongHeader(_, protocol_version, destination, source) =
        packet_header(parsed)
      case resolve_alias(worker, destination) {
        Some(identifier) ->
          route_existing(worker, identifier, peer, datagram, marking)
        None ->
          case parsed, protocol_version {
            packet.Initial(_, token, _), version.Version1
            | packet.Initial(_, token, _), version.Version2
            ->
              route_initial(
                worker,
                peer,
                protocol_version,
                destination,
                source,
                token,
                datagram,
                marking,
              )
            packet.UnknownVersion(_, _), _ ->
              send_version_negotiation(worker, peer, destination, source)
            _, _ -> worker
          }
      }
    }
  }
}

fn route_initial(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  destination: BitArray,
  peer_connection_id: BitArray,
  token: BitArray,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case token {
    <<>> ->
      send_retry(
        worker,
        peer,
        protocol_version,
        destination,
        peer_connection_id,
      )
    _ -> {
      let #(address, port) = udp.endpoint_parts(peer)
      let now = udp.monotonic_millisecond()
      case
        open_address_token(
          worker.address_token_keys,
          token,
          address,
          port,
          now,
          new_token_lifetime_milliseconds,
        )
      {
        Ok(address_token.Token(
          address_token.Retry,
          original_destination,
          retry_source,
          issued_at,
        ))
          if retry_source == destination
          && now - issued_at <= retry_token_lifetime_milliseconds
        ->
          accept_connection(
            worker,
            peer,
            protocol_version,
            original_destination,
            Some(retry_source),
            peer_connection_id,
            Some(retry_source),
            datagram,
            marking,
          )
        Ok(address_token.Token(address_token.NewToken, <<>>, <<>>, _)) ->
          accept_connection(
            worker,
            peer,
            protocol_version,
            destination,
            None,
            peer_connection_id,
            None,
            datagram,
            marking,
          )
        _ ->
          send_retry(
            worker,
            peer,
            protocol_version,
            destination,
            peer_connection_id,
          )
      }
    }
  }
}

fn route_existing(
  worker: Worker,
  identifier: BitArray,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer_state) -> {
      let now = udp.monotonic_millisecond()
      let assert Ok(policy) = replay_policy(worker, now)
      case
        server_transport.receive_datagram(
          peer_state.connection,
          datagram,
          marking,
          now,
          policy,
        )
      {
        Error(server_transport.DriverFailure(error)) ->
          case driver.discardable_receive_error(error) {
            True -> worker
            False -> fail_connection(worker, identifier, QuicFailure)
          }
        Error(_) -> fail_connection(worker, identifier, QuicFailure)
        Ok(connection) -> {
          case peer_state.qlog_writer {
            Some(writer) ->
              qlog.datagram_received(writer, now, bit_array.byte_size(datagram))
            None -> Nil
          }
          let previous = server_transport.peer(peer_state.connection)
          case same_endpoint(previous, peer) {
            True ->
              put_peer(
                worker,
                identifier,
                PeerState(..peer_state, connection: connection),
              )
              |> update_replay_cache(connection)
              |> mark_dirty(identifier)
            False ->
              handle_candidate_path(
                worker,
                identifier,
                peer_state,
                connection,
                peer,
                bit_array.byte_size(datagram),
                now,
              )
          }
        }
      }
    }
  }
}

fn handle_candidate_path(
  worker: Worker,
  identifier: BitArray,
  peer_state: PeerState,
  connection: server_transport.State,
  peer: udp.Endpoint,
  received_bytes: Int,
  now: Int,
) -> Worker {
  case server_transport.established(connection) {
    False ->
      put_peer(
        worker,
        identifier,
        PeerState(
          ..peer_state,
          connection: server_transport.with_peer(connection, peer),
        ),
      )
      |> update_replay_cache(connection)
      |> mark_dirty(identifier)
    True ->
      case peer_state.candidate_path {
        Some(CandidatePath(endpoint, received, sent)) ->
          case same_endpoint(endpoint, peer) {
            False -> worker
            True ->
              put_peer(
                worker,
                identifier,
                PeerState(
                  ..peer_state,
                  connection: connection,
                  candidate_path: Some(CandidatePath(
                    endpoint,
                    received + received_bytes,
                    sent,
                  )),
                ),
              )
              |> update_replay_cache(connection)
              |> mark_dirty(identifier)
          }
        None ->
          case crypto.secure_random(8) {
            Error(_) -> worker
            Ok(challenge) ->
              case
                server_transport.begin_path_validation(
                  connection,
                  challenge,
                  now,
                )
              {
                Error(_) -> worker
                Ok(connection) ->
                  put_peer(
                    worker,
                    identifier,
                    PeerState(
                      ..peer_state,
                      connection: connection,
                      candidate_path: Some(CandidatePath(
                        peer,
                        received_bytes,
                        0,
                      )),
                    ),
                  )
                  |> update_replay_cache(connection)
                  |> mark_dirty(identifier)
              }
          }
      }
  }
}

fn accept_connection(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  original_destination: BitArray,
  selected_local_connection_id: Option(BitArray),
  peer_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  case
    dict.size(worker.connections) >= worker.connection_limit,
    active_handshake_count(worker) >= worker.handshake_limit,
    bit_array.byte_size(original_destination) >= 8,
    bit_array.byte_size(datagram) >= 1200
  {
    True, _, _, _ | _, True, _, _ | _, _, False, _ | _, _, _, False -> worker
    False, False, True, True ->
      case
        case selected_local_connection_id {
          Some(value) -> Ok(value)
          None -> unique_connection_id(worker, 8)
        }
      {
        Error(_) -> worker
        Ok(local_connection_id) -> {
          let now = udp.monotonic_millisecond()
          let assert Ok(policy) = replay_policy(worker, now)
          case
            server_transport.accept_initial(
              worker.server_config,
              protocol_version,
              original_destination,
              local_connection_id,
              peer_connection_id,
              retry_source_connection_id,
              peer,
              datagram,
              marking,
              now,
              policy,
            )
          {
            Error(_) -> worker
            Ok(connection) ->
              case
                open_qlog(worker.qlog_directory, worker.telemetry_limit, now)
              {
                Error(_) -> worker
                Ok(writer) -> {
                  case writer {
                    Some(value) -> {
                      qlog.connection_started(value, now)
                      qlog.datagram_received(
                        value,
                        now,
                        bit_array.byte_size(datagram),
                      )
                    }
                    None -> Nil
                  }
                  let peer_state =
                    PeerState(
                      connection,
                      dict.new(),
                      queue_new(),
                      None,
                      queue_new(),
                      0,
                      None,
                      False,
                      protocol_version,
                      worker.server_config.congestion_control,
                      writer,
                      None,
                      None,
                      now + pmtu_probe_interval_milliseconds,
                    )
                  Worker(
                    ..worker,
                    connections: dict.insert(
                      worker.connections,
                      local_connection_id,
                      peer_state,
                    ),
                    aliases: case retry_source_connection_id {
                      Some(_) -> worker.aliases
                      None ->
                        dict.insert(
                          worker.aliases,
                          original_destination,
                          local_connection_id,
                        )
                    },
                  )
                  |> update_replay_cache(connection)
                  |> mark_dirty(local_connection_id)
                }
              }
          }
        }
      }
  }
}

fn drive_and_loop(worker: Worker) -> Nil {
  worker |> tick_and_flush_dirty |> retry_pending_sends |> loop
}

fn timer_drive_and_loop(worker: Worker) -> Nil {
  worker |> tick_and_flush_all |> retry_pending_sends |> loop
}

fn tick_and_flush_dirty(worker: Worker) -> Worker {
  let identifiers = dict.keys(worker.dirty_connections)
  tick_and_flush_identifiers(
    Worker(..worker, dirty_connections: dict.new()),
    identifiers,
    udp.monotonic_millisecond(),
  )
}

fn tick_and_flush_all(worker: Worker) -> Worker {
  tick_and_flush_identifiers(
    Worker(..worker, dirty_connections: dict.new()),
    dict.keys(worker.connections),
    udp.monotonic_millisecond(),
  )
}

fn tick_and_flush_identifiers(
  worker: Worker,
  identifiers: List(BitArray),
  now: Int,
) -> Worker {
  case identifiers {
    [] -> worker
    [identifier, ..rest] ->
      case dict.get(worker.connections, identifier) {
        Error(_) -> tick_and_flush_identifiers(worker, rest, now)
        Ok(peer) ->
          case server_transport.tick(peer.connection, now) {
            Error(_) ->
              tick_and_flush_identifiers(
                fail_connection(worker, identifier, QuicFailure),
                rest,
                now,
              )
            Ok(connection) -> {
              let peer = PeerState(..peer, connection: connection)
              let worker = put_peer(worker, identifier, peer)
              let worker = maybe_queue_new_token(worker, identifier, now)
              let worker = maybe_issue_session_ticket(worker, identifier, now)
              let worker = maybe_probe(worker, identifier, now)
              let worker =
                flush_connection(
                  worker,
                  identifier,
                  now,
                  maximum_packets_per_flush,
                )
              tick_and_flush_identifiers(worker, rest, now)
            }
          }
      }
  }
}

fn maybe_queue_new_token(
  worker: Worker,
  identifier: BitArray,
  now: Int,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer) -> {
      let endpoint = server_transport.peer(peer.connection)
      let already_issued = case peer.token_endpoint {
        Some(previous) -> same_endpoint(previous, endpoint)
        None -> False
      }
      case server_transport.established(peer.connection), already_issued {
        False, _ | _, True -> worker
        True, False -> {
          let #(address, port) = udp.endpoint_parts(endpoint)
          case current_key(worker.address_token_keys) {
            Error(_) -> worker
            Ok(key) ->
              case
                address_token.seal(
                  key,
                  address_token.NewToken,
                  address,
                  port,
                  <<>>,
                  <<>>,
                  now,
                )
              {
                Error(_) -> worker
                Ok(token) ->
                  case
                    server_transport.queue_new_token(peer.connection, token)
                  {
                    Error(_) -> worker
                    Ok(connection) ->
                      put_peer(
                        worker,
                        identifier,
                        PeerState(
                          ..peer,
                          connection: connection,
                          token_endpoint: Some(endpoint),
                        ),
                      )
                  }
              }
          }
        }
      }
    }
  }
}

fn maybe_issue_session_ticket(
  worker: Worker,
  identifier: BitArray,
  now: Int,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer) ->
      case
        server_transport.issue_session_ticket_if_ready(peer.connection, now)
      {
        Error(_) -> fail_connection(worker, identifier, QuicFailure)
        Ok(connection) ->
          put_peer(
            worker,
            identifier,
            PeerState(..peer, connection: connection),
          )
      }
  }
}

fn maybe_probe(worker: Worker, identifier: BitArray, now: Int) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer) ->
      case
        peer.next_pmtu_probe_milliseconds,
        server_transport.path_validation_in_progress(peer.connection),
        server_transport.established(peer.connection)
      {
        0, _, _ | _, True, _ -> worker
        _, _, False ->
          put_peer(
            worker,
            identifier,
            PeerState(
              ..peer,
              next_pmtu_probe_milliseconds: now
                + pmtu_probe_interval_milliseconds,
            ),
          )
        deadline, _, _ if now < deadline -> worker
        _, _, True ->
          case server_transport.pmtu_discovery_complete(peer.connection) {
            True ->
              put_peer(
                worker,
                identifier,
                PeerState(..peer, next_pmtu_probe_milliseconds: 0),
              )
            False -> send_pmtu_probe(worker, identifier, peer, now)
          }
      }
  }
}

fn send_pmtu_probe(
  worker: Worker,
  identifier: BitArray,
  peer: PeerState,
  now: Int,
) -> Worker {
  case server_transport.prepare_pmtu_probe(peer.connection, now) {
    Error(_) -> worker
    Ok(None) ->
      put_peer(
        worker,
        identifier,
        PeerState(
          ..peer,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    Ok(Some(prepared)) ->
      case
        udp.send(
          worker.socket,
          candidate_send_endpoint(peer),
          server_transport.prepared_bytes(prepared),
          ecn.NotEct,
        )
      {
        Error(_) -> worker
        Ok(Nil) ->
          case server_transport.commit_datagram(prepared, ecn.NotEct, now) {
            Error(_) -> worker
            Ok(connection) ->
              put_peer(
                worker,
                identifier,
                record_candidate_send(
                  PeerState(
                    ..peer,
                    connection: connection,
                    next_pmtu_probe_milliseconds: now
                      + pmtu_probe_interval_milliseconds,
                  ),
                  bit_array.byte_size(server_transport.prepared_bytes(prepared)),
                ),
              )
          }
      }
  }
}

fn flush_connection(
  worker: Worker,
  identifier: BitArray,
  now: Int,
  remaining: Int,
) -> Worker {
  case remaining, dict.get(worker.connections, identifier) {
    0, _ | _, Error(_) -> worker
    _, Ok(peer) ->
      case
        server_transport.prepare_datagram(
          peer.connection,
          maximum_frame_data_bytes,
          now,
        )
      {
        Error(server_transport.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
          _,
        ))))
        | Error(server_transport.DriverFailure(driver.ConnectionFailure(
            transport.CongestionLimited,
          )))
        | Ok(None) -> worker
        Error(_) -> fail_connection(worker, identifier, QuicFailure)
        Ok(Some(prepared)) -> {
          let bytes = server_transport.prepared_bytes(prepared)
          let destination = candidate_send_endpoint(peer)
          case candidate_send_allowed(peer, bit_array.byte_size(bytes)) {
            False -> worker
            True ->
              case udp.send(worker.socket, destination, bytes, ecn.NotEct) {
                Error(_) -> fail_connection(worker, identifier, QuicFailure)
                Ok(Nil) ->
                  case
                    server_transport.commit_datagram(prepared, ecn.NotEct, now)
                  {
                    Error(_) -> fail_connection(worker, identifier, QuicFailure)
                    Ok(connection) -> {
                      case peer.qlog_writer {
                        Some(writer) ->
                          qlog.datagram_sent(
                            writer,
                            now,
                            bit_array.byte_size(bytes),
                          )
                        None -> Nil
                      }
                      let next =
                        record_candidate_send(
                          PeerState(..peer, connection: connection),
                          bit_array.byte_size(bytes),
                        )
                      flush_connection(
                        put_peer(worker, identifier, next),
                        identifier,
                        now,
                        remaining - 1,
                      )
                    }
                  }
              }
          }
        }
      }
  }
}

fn dispatch_all_events(worker: Worker) -> Worker {
  dispatch_connection_entries(worker, dict.to_list(worker.connections))
}

fn dispatch_connection_entries(
  worker: Worker,
  entries: List(#(BitArray, PeerState)),
) -> Worker {
  case entries {
    [] -> worker
    [#(identifier, _), ..rest] ->
      case dict.get(worker.connections, identifier) {
        Error(_) -> dispatch_connection_entries(worker, rest)
        Ok(peer) -> {
          let #(connection, events) =
            server_transport.take_events(peer.connection)
          let worker =
            put_peer(
              worker,
              identifier,
              PeerState(..peer, connection: connection),
            )
          dispatch_connection_entries(
            dispatch_events(worker, identifier, events),
            rest,
          )
        }
      }
  }
}

fn dispatch_events(
  worker: Worker,
  connection_id: BitArray,
  events: List(transport.Event),
) -> Worker {
  case events {
    [] -> worker
    [event, ..rest] ->
      dispatch_events(
        dispatch_event(worker, connection_id, event),
        connection_id,
        rest,
      )
  }
}

fn dispatch_event(
  worker: Worker,
  connection_id: BitArray,
  event: transport.Event,
) -> Worker {
  case event {
    transport.HandshakeEstablished -> enqueue_connection(worker, connection_id)
    transport.StreamOpened(identifier) ->
      register_stream(worker, connection_id, identifier)
    transport.StreamReadable(identifier) ->
      service_read_waiter(worker, connection_id, identifier)
    transport.StreamWasReset(identifier, _) ->
      service_read_waiter(worker, connection_id, identifier)
    transport.DatagramReceived(payload) ->
      enqueue_datagram(worker, connection_id, payload)
    transport.PathValidated -> commit_candidate_path(worker, connection_id)
    transport.PathValidationFailed ->
      discard_candidate_path(worker, connection_id)
    transport.PeerClosed(_, _) | transport.StatelessResetReceived ->
      fail_connection(worker, connection_id, ConnectionClosed)
    _ -> worker
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    Port(reply) -> {
      process.send(reply, Ok(worker.port))
      Ok(worker)
    }
    AcceptConnection(reply, deadline) ->
      handle_accept_connection(worker, reply, deadline)
    Open(connection_id, direction, reply) ->
      handle_open(worker, connection_id, direction, reply)
    AcceptStream(connection_id, reply, deadline) ->
      handle_accept_stream(worker, connection_id, reply, deadline)
    Send(connection_id, stream_id, bytes, finish, reply, deadline) ->
      handle_send(
        worker,
        connection_id,
        stream_id,
        bytes,
        finish,
        reply,
        deadline,
      )
    Receive(connection_id, stream_id, maximum, reply, deadline) ->
      handle_receive(worker, connection_id, stream_id, maximum, reply, deadline)
    ResetStream(connection_id, stream_id, code, reply) ->
      handle_reset(worker, connection_id, stream_id, code, reply)
    SendDatagram(connection_id, payload, reply) ->
      handle_send_datagram(worker, connection_id, payload, reply)
    ReceiveDatagram(connection_id, reply, deadline) ->
      handle_receive_datagram(worker, connection_id, reply, deadline)
    MaximumDatagram(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        server_transport.maximum_datagram_size(peer.connection)
        |> result.map_error(map_transport_error)
      })
    Ping(connection_id, reply) ->
      update_peer_reply(worker, connection_id, reply, fn(peer) {
        server_transport.ping(peer.connection)
      })
    SetCongestion(connection_id, algorithm, reply) ->
      handle_set_congestion(worker, connection_id, algorithm, reply)
    PathStats(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        Ok(server_transport.path_stats(peer.connection))
      })
    ConnectionStats(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        Ok(server_transport.stats(peer.connection))
      })
    TelemetryStats(connection_id, reply) ->
      handle_telemetry_stats(worker, connection_id, reply)
    Phase(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        Ok(server_transport.phase(peer.connection))
      })
    ClientIdentity(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        case server_transport.client_identity(peer.connection) {
          None -> Ok(None)
          Some(identity) ->
            authentication.verified_peer_fingerprint(identity)
            |> result.map(Some)
            |> result.replace_error(QuicFailure)
        }
      })
    Protocol(connection_id, reply) ->
      with_peer_reply(worker, connection_id, reply, fn(peer) {
        let protocol = case
          server_transport.application_protocol(peer.connection)
        {
          Some(value) -> value
          None -> first_protocol(worker.server_config.application_protocols)
        }
        Ok(#(
          peer.version,
          protocol,
          peer.congestion_control,
          server_transport.cipher_suite(peer.connection),
          server_transport.resumed(peer.connection),
          server_transport.early_data_attempted(peer.connection),
          server_transport.early_data_accepted(peer.connection),
        ))
      })
    CloseConnection(connection_id, reply) ->
      handle_close_connection(worker, connection_id, reply)
    ReloadCertificates(chain, key, scheme, alternatives, reply) -> {
      process.send(reply, Ok(Nil))
      Ok(
        Worker(
          ..worker,
          server_config: server_transport.Config(
            ..worker.server_config,
            certificate_chain: chain,
            signing_key: key,
            signature_scheme: scheme,
            alternative_credentials: alternatives,
          ),
        ),
      )
    }
    ReloadKeys(ticket_keys, address_token_keys, reset_keys, reply) ->
      case
        valid_key_ring(ticket_keys)
        && valid_key_ring(address_token_keys)
        && valid_key_ring(reset_keys)
      {
        False -> reply_error(worker, reply, InvalidInput)
        True -> {
          let assert [ticket_key, ..] = ticket_keys
          let assert [reset_key, ..] = reset_keys
          let connections =
            dict.map_values(worker.connections, fn(_, peer) {
              PeerState(..peer, token_endpoint: None)
            })
          process.send(reply, Ok(Nil))
          Ok(
            Worker(
              ..worker,
              ticket_keys: ticket_keys,
              address_token_keys: address_token_keys,
              stateless_reset_keys: reset_keys,
              connections: connections,
              dirty_connections: dict.map_values(connections, fn(_, _) { Nil }),
              server_config: server_transport.Config(
                ..worker.server_config,
                ticket_key: ticket_key,
                stateless_reset_key: reset_key,
              ),
            ),
          )
        }
      }
    Stop(reply) -> {
      shutdown(worker, ListenerClosed)
      process.send(reply, Ok(Stopped))
      Error(Nil)
    }
  }
}

fn handle_accept_connection(
  worker: Worker,
  reply: Subject(Result(Connection, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case queue_pop(worker.pending_connections) {
    Ok(#(identifier, rest)) -> {
      process.send(reply, Ok(connection_handle(worker, identifier)))
      Ok(mark_accepted(Worker(..worker, pending_connections: rest), identifier))
    }
    Error(Nil) ->
      case
        queue_count(worker.connection_waiters) >= worker.accept_waiter_limit
      {
        True ->
          reply_error(
            worker,
            reply,
            AcceptQueueExceeded(worker.accept_waiter_limit),
          )
        False ->
          Ok(
            Worker(
              ..worker,
              connection_waiters: queue_push(
                worker.connection_waiters,
                ConnectionWaiter(reply, deadline),
              ),
            ),
          )
      }
  }
}

fn handle_open(
  worker: Worker,
  connection_id: BitArray,
  direction: stream_id.Direction,
  reply: Subject(Result(Int, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case server_transport.open_stream(peer.connection, direction) {
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(#(connection, identifier)) -> {
          process.send(reply, Ok(identifier))
          Ok(
            put_peer(
              worker,
              connection_id,
              put_peer_stream(
                PeerState(..peer, connection: connection),
                identifier,
                new_stream_state(),
              ),
            )
            |> mark_dirty(connection_id),
          )
        }
      }
  }
}

fn handle_accept_stream(
  worker: Worker,
  connection_id: BitArray,
  reply: Subject(Result(IncomingStream, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case queue_pop(peer.incoming), peer.stream_waiter {
        Ok(#(identifier, rest)), _ -> {
          process.send(
            reply,
            incoming_stream(worker, connection_id, identifier),
          )
          Ok(put_peer(worker, connection_id, PeerState(..peer, incoming: rest)))
        }
        Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentAccept)
        Error(Nil), None ->
          Ok(put_peer(
            worker,
            connection_id,
            PeerState(
              ..peer,
              stream_waiter: Some(StreamWaiter(reply, deadline)),
            ),
          ))
      }
  }
}

fn handle_send(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    bit_array.bit_size(bytes) % 8,
    dict.get(worker.connections, connection_id),
    stream_id.can_send(identifier, stream_id.Server)
  {
    remainder, _, _ if remainder != 0 -> reply_error(worker, reply, InvalidInput)
    _, Error(_), _ -> reply_error(worker, reply, ConnectionClosed)
    _, _, False -> reply_error(worker, reply, InvalidDirection)
    _, Ok(peer), True ->
      case dict.get(peer.streams, identifier) {
        Error(_) -> reply_error(worker, reply, StreamClosed)
        Ok(stream) ->
          case stream.pending_send, stream.send_finished {
            Some(_), _ -> reply_error(worker, reply, ConcurrentSend)
            None, True -> reply_error(worker, reply, StreamClosed)
            None, False ->
              Ok(
                advance_send(
                  worker,
                  connection_id,
                  identifier,
                  PendingSend(bytes, finish, reply, deadline),
                )
                |> mark_dirty(connection_id),
              )
          }
      }
  }
}

fn advance_send(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
  pending: PendingSend,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> {
      process.send(pending.reply, Error(ConnectionClosed))
      worker
    }
    Ok(peer) ->
      case dict.get(peer.streams, identifier) {
        Error(_) -> {
          process.send(pending.reply, Error(StreamClosed))
          worker
        }
        Ok(stream) ->
          case
            server_transport.buffered_send_bytes(peer.connection, identifier)
          {
            Error(error) -> {
              process.send(pending.reply, Error(map_transport_error(error)))
              worker
            }
            Ok(buffered) -> {
              let available = worker.stream_buffer_limit - buffered
              let remaining_size = bit_array.byte_size(pending.remaining)
              case remaining_size, available {
                size, available if size > 0 && available <= 0 ->
                  put_peer(
                    worker,
                    connection_id,
                    put_peer_stream(
                      peer,
                      identifier,
                      StreamState(..stream, pending_send: Some(pending)),
                    ),
                  )
                _, _ -> {
                  let take =
                    int.min(
                      remaining_size,
                      int.min(maximum_send_chunk_bytes, int.max(available, 0)),
                    )
                  let #(chunk, rest) = take_bytes(pending.remaining, take)
                  let finish = pending.finish && rest == <<>>
                  case
                    server_transport.send(
                      peer.connection,
                      identifier,
                      chunk,
                      finish,
                    )
                  {
                    Error(error) -> {
                      process.send(
                        pending.reply,
                        Error(map_transport_error(error)),
                      )
                      worker
                    }
                    Ok(connection) ->
                      case rest {
                        <<>> -> {
                          process.send(pending.reply, Ok(Nil))
                          put_peer(
                            worker,
                            connection_id,
                            put_peer_stream(
                              PeerState(..peer, connection: connection),
                              identifier,
                              StreamState(
                                ..stream,
                                pending_send: None,
                                send_finished: stream.send_finished || finish,
                              ),
                            ),
                          )
                        }
                        _ ->
                          put_peer(
                            worker,
                            connection_id,
                            put_peer_stream(
                              PeerState(..peer, connection: connection),
                              identifier,
                              StreamState(
                                ..stream,
                                pending_send: Some(PendingSend(
                                  rest,
                                  pending.finish,
                                  pending.reply,
                                  pending.deadline,
                                )),
                              ),
                            ),
                          )
                      }
                  }
                }
              }
            }
          }
      }
  }
}

fn handle_receive(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
  maximum_bytes: Int,
  reply: Subject(Result(Read, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    maximum_bytes > 0 && maximum_bytes <= worker.stream_buffer_limit,
    dict.get(worker.connections, connection_id),
    stream_id.can_receive(identifier, stream_id.Server)
  {
    False, _, _ -> reply_error(worker, reply, InvalidInput)
    _, Error(_), _ -> reply_error(worker, reply, ConnectionClosed)
    _, _, False -> reply_error(worker, reply, InvalidDirection)
    True, Ok(peer), True ->
      case dict.get(peer.streams, identifier) {
        Error(_) -> reply_error(worker, reply, StreamClosed)
        Ok(StreamState(read_waiter: Some(_), ..)) ->
          reply_error(worker, reply, ConcurrentReceive)
        Ok(_) ->
          Ok(read_or_wait(
            worker,
            connection_id,
            identifier,
            ReadWaiter(maximum_bytes, reply, deadline),
          ))
      }
  }
}

fn read_or_wait(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
  waiter: ReadWaiter,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> {
      process.send(waiter.reply, Error(ConnectionClosed))
      worker
    }
    Ok(peer) ->
      case dict.get(peer.streams, identifier) {
        Error(_) -> {
          process.send(waiter.reply, Error(StreamClosed))
          worker
        }
        Ok(stream) ->
          case
            server_transport.read(
              peer.connection,
              identifier,
              waiter.maximum_bytes,
            )
          {
            Error(error) -> {
              process.send(waiter.reply, Error(map_transport_error(error)))
              worker
            }
            Ok(#(connection, runtime_connection.Pending)) ->
              put_peer(
                worker,
                connection_id,
                put_peer_stream(
                  PeerState(..peer, connection: connection),
                  identifier,
                  StreamState(..stream, read_waiter: Some(waiter)),
                ),
              )
            Ok(#(connection, runtime_connection.Data(bytes, finished))) -> {
              process.send(waiter.reply, Ok(Data(bytes, finished)))
              put_peer(
                worker,
                connection_id,
                put_peer_stream(
                  PeerState(..peer, connection: connection),
                  identifier,
                  StreamState(
                    ..stream,
                    read_waiter: None,
                    receive_finished: stream.receive_finished || finished,
                  ),
                ),
              )
            }
            Ok(#(connection, runtime_connection.Reset(code))) -> {
              process.send(waiter.reply, Ok(Reset(code)))
              put_peer(
                worker,
                connection_id,
                put_peer_stream(
                  PeerState(..peer, connection: connection),
                  identifier,
                  StreamState(
                    ..stream,
                    read_waiter: None,
                    receive_finished: True,
                  ),
                ),
              )
            }
            Ok(#(connection, runtime_connection.Finished)) -> {
              process.send(waiter.reply, Ok(Finished))
              put_peer(
                worker,
                connection_id,
                put_peer_stream(
                  PeerState(..peer, connection: connection),
                  identifier,
                  StreamState(
                    ..stream,
                    read_waiter: None,
                    receive_finished: True,
                  ),
                ),
              )
            }
          }
      }
  }
}

fn handle_reset(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
  code: Int,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  update_peer_reply(worker, connection_id, reply, fn(peer) {
    server_transport.reset(peer.connection, identifier, code)
  })
}

fn handle_send_datagram(
  worker: Worker,
  connection_id: BitArray,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case server_transport.maximum_datagram_size(peer.connection) {
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(maximum) -> {
          let size = bit_array.byte_size(payload)
          case size > maximum {
            True -> reply_error(worker, reply, DatagramTooLarge(maximum))
            False ->
              update_peer_reply(worker, connection_id, reply, fn(peer) {
                server_transport.send_datagram(peer.connection, payload)
              })
          }
        }
      }
  }
}

fn handle_receive_datagram(
  worker: Worker,
  connection_id: BitArray,
  reply: Subject(Result(BitArray, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case queue_pop(peer.datagrams), peer.datagram_waiter {
        Ok(#(payload, rest)), _ -> {
          process.send(reply, Ok(payload))
          Ok(put_peer(
            worker,
            connection_id,
            PeerState(
              ..peer,
              datagrams: rest,
              datagram_bytes: peer.datagram_bytes - bit_array.byte_size(payload),
            ),
          ))
        }
        Error(Nil), Some(_) ->
          reply_error(worker, reply, ConcurrentDatagramReceive)
        Error(Nil), None ->
          Ok(put_peer(
            worker,
            connection_id,
            PeerState(
              ..peer,
              datagram_waiter: Some(DatagramWaiter(reply, deadline)),
            ),
          ))
      }
  }
}

fn handle_set_congestion(
  worker: Worker,
  connection_id: BitArray,
  algorithm: transport.CongestionAlgorithm,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case server_transport.set_congestion_control(peer.connection, algorithm) {
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(
            put_peer(
              worker,
              connection_id,
              PeerState(
                ..peer,
                connection: connection,
                congestion_control: algorithm,
              ),
            )
            |> mark_dirty(connection_id),
          )
        }
      }
  }
}

fn handle_telemetry_stats(
  worker: Worker,
  connection_id: BitArray,
  reply: Subject(Result(qlog.Stats, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(PeerState(qlog_writer: None, ..)) -> {
      process.send(reply, Ok(qlog.Stats(0, 0, 0)))
      Ok(worker)
    }
    Ok(PeerState(qlog_writer: Some(writer), ..)) ->
      case qlog.stats(writer) {
        Ok(stats) -> {
          process.send(reply, Ok(stats))
          Ok(worker)
        }
        Error(_) -> reply_error(worker, reply, QlogUnavailable)
      }
  }
}

fn handle_close_connection(
  worker: Worker,
  connection_id: BitArray,
  reply: Subject(Result(CloseResult, Error)),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> {
      process.send(reply, Ok(AlreadyClosed))
      Ok(worker)
    }
    Ok(peer) ->
      case server_transport.phase(peer.connection) {
        transport.Closing | transport.Draining | transport.Closed -> {
          process.send(reply, Ok(AlreadyClosed))
          Ok(worker)
        }
        transport.Handshaking | transport.Established -> {
          process.send(reply, Ok(Closed))
          let connection =
            server_transport.close(
              peer.connection,
              0,
              "application close",
              udp.monotonic_millisecond(),
            )
          Ok(
            put_peer(
              worker,
              connection_id,
              PeerState(..peer, connection: connection),
            )
            |> mark_dirty(connection_id),
          )
        }
      }
  }
}

fn enqueue_connection(worker: Worker, identifier: BitArray) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer) if peer.accepted -> worker
    Ok(_) ->
      case queue_pop(worker.connection_waiters) {
        Ok(#(ConnectionWaiter(reply, _), rest)) -> {
          process.send(reply, Ok(connection_handle(worker, identifier)))
          mark_accepted(Worker(..worker, connection_waiters: rest), identifier)
        }
        Error(Nil) ->
          case queue_count(worker.pending_connections) >= worker.queue_limit {
            True ->
              fail_connection(
                worker,
                identifier,
                AcceptQueueExceeded(worker.queue_limit),
              )
            False ->
              Worker(
                ..worker,
                pending_connections: queue_push(
                  worker.pending_connections,
                  identifier,
                ),
              )
          }
      }
  }
}

fn register_stream(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) -> {
      let peer = case dict.has_key(peer.streams, identifier) {
        True -> peer
        False -> put_peer_stream(peer, identifier, new_stream_state())
      }
      let worker = put_peer(worker, connection_id, peer)
      case stream_id.decode(identifier) {
        Ok(stream_id.StreamId(_, stream_id.Client, _)) ->
          enqueue_incoming_stream(worker, connection_id, identifier)
        _ -> worker
      }
    }
  }
}

fn enqueue_incoming_stream(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) ->
      case peer.stream_waiter {
        Some(StreamWaiter(reply, _)) -> {
          process.send(
            reply,
            incoming_stream(worker, connection_id, identifier),
          )
          put_peer(
            worker,
            connection_id,
            PeerState(..peer, stream_waiter: None),
          )
        }
        None ->
          case queue_count(peer.incoming) >= worker.queue_limit {
            True ->
              fail_connection(
                worker,
                connection_id,
                IncomingStreamQueueExceeded(worker.queue_limit),
              )
            False ->
              put_peer(
                worker,
                connection_id,
                PeerState(
                  ..peer,
                  incoming: queue_push(peer.incoming, identifier),
                ),
              )
          }
      }
  }
}

fn service_read_waiter(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Ok(peer) ->
      case dict.get(peer.streams, identifier) {
        Ok(StreamState(read_waiter: Some(waiter), ..)) ->
          read_or_wait(worker, connection_id, identifier, waiter)
        _ -> worker
      }
    Error(_) -> worker
  }
}

fn enqueue_datagram(
  worker: Worker,
  connection_id: BitArray,
  payload: BitArray,
) -> Worker {
  case dict.get(worker.connections, connection_id) {
    Error(_) -> worker
    Ok(peer) ->
      case peer.datagram_waiter {
        Some(DatagramWaiter(reply, _)) -> {
          process.send(reply, Ok(payload))
          put_peer(
            worker,
            connection_id,
            PeerState(..peer, datagram_waiter: None),
          )
        }
        None -> {
          let size = bit_array.byte_size(payload)
          case
            queue_count(peer.datagrams) >= worker.queue_limit
            || peer.datagram_bytes + size > worker.datagram_limit
          {
            True ->
              fail_connection(
                worker,
                connection_id,
                DatagramQueueExceeded(worker.queue_limit),
              )
            False ->
              put_peer(
                worker,
                connection_id,
                PeerState(
                  ..peer,
                  datagrams: queue_push(peer.datagrams, payload),
                  datagram_bytes: peer.datagram_bytes + size,
                ),
              )
          }
        }
      }
  }
}

fn commit_candidate_path(worker: Worker, identifier: BitArray) -> Worker {
  case dict.get(worker.connections, identifier) {
    Ok(
      PeerState(candidate_path: Some(CandidatePath(endpoint, _, _)), ..) as peer,
    ) -> {
      case peer.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      put_peer(
        worker,
        identifier,
        PeerState(
          ..peer,
          connection: server_transport.with_peer(peer.connection, endpoint),
          candidate_path: None,
        ),
      )
    }
    _ -> worker
  }
}

fn discard_candidate_path(worker: Worker, identifier: BitArray) -> Worker {
  case dict.get(worker.connections, identifier) {
    Ok(peer) ->
      put_peer(worker, identifier, PeerState(..peer, candidate_path: None))
    Error(_) -> worker
  }
}

fn retry_pending_sends(worker: Worker) -> Worker {
  retry_peer_sends(worker, dict.to_list(worker.connections))
}

fn retry_peer_sends(
  worker: Worker,
  peers: List(#(BitArray, PeerState)),
) -> Worker {
  case peers {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let worker =
        retry_stream_sends(worker, connection_id, dict.to_list(peer.streams))
      retry_peer_sends(worker, rest)
    }
  }
}

fn retry_stream_sends(
  worker: Worker,
  connection_id: BitArray,
  streams: List(#(Int, StreamState)),
) -> Worker {
  case streams {
    [] -> worker
    [#(identifier, StreamState(pending_send: Some(pending), ..)), ..rest] ->
      retry_stream_sends(
        advance_send(worker, connection_id, identifier, pending),
        connection_id,
        rest,
      )
    [_, ..rest] -> retry_stream_sends(worker, connection_id, rest)
  }
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let #(waiters, expired) =
    partition_connection_waiters(
      worker.connection_waiters,
      now,
      queue_new(),
      [],
    )
  list.each(expired, fn(waiter) {
    let ConnectionWaiter(reply, _) = waiter
    process.send(reply, Error(OperationTimeout))
  })
  expire_peer_waiters(
    Worker(..worker, connection_waiters: waiters),
    dict.to_list(worker.connections),
    now,
  )
}

fn partition_connection_waiters(
  source: Queue(ConnectionWaiter),
  now: Int,
  kept: Queue(ConnectionWaiter),
  expired: List(ConnectionWaiter),
) -> #(Queue(ConnectionWaiter), List(ConnectionWaiter)) {
  case queue_pop(source) {
    Error(Nil) -> #(kept, expired)
    Ok(#(waiter, rest)) -> {
      let ConnectionWaiter(_, deadline) = waiter
      case now >= deadline {
        True ->
          partition_connection_waiters(rest, now, kept, [waiter, ..expired])
        False ->
          partition_connection_waiters(
            rest,
            now,
            queue_push(kept, waiter),
            expired,
          )
      }
    }
  }
}

fn expire_peer_waiters(
  worker: Worker,
  peers: List(#(BitArray, PeerState)),
  now: Int,
) -> Worker {
  case peers {
    [] -> worker
    [#(connection_id, peer), ..rest] -> {
      let peer = case peer.stream_waiter {
        Some(StreamWaiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          PeerState(..peer, stream_waiter: None)
        }
        _ -> peer
      }
      let peer = case peer.datagram_waiter {
        Some(DatagramWaiter(reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          PeerState(..peer, datagram_waiter: None)
        }
        _ -> peer
      }
      let peer = expire_stream_waiters(peer, dict.to_list(peer.streams), now)
      expire_peer_waiters(put_peer(worker, connection_id, peer), rest, now)
    }
  }
}

fn expire_stream_waiters(
  peer: PeerState,
  streams: List(#(Int, StreamState)),
  now: Int,
) -> PeerState {
  case streams {
    [] -> peer
    [#(identifier, stream), ..rest] -> {
      let stream = case stream.read_waiter {
        Some(ReadWaiter(_, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          StreamState(..stream, read_waiter: None)
        }
        _ -> stream
      }
      let stream = case stream.pending_send {
        Some(PendingSend(_, _, reply, deadline)) if now >= deadline -> {
          process.send(reply, Error(OperationTimeout))
          StreamState(..stream, pending_send: None)
        }
        _ -> stream
      }
      expire_stream_waiters(
        put_peer_stream(peer, identifier, stream),
        rest,
        now,
      )
    }
  }
}

fn next_worker_deadline(
  worker: Worker,
  now: Int,
) -> Result(Option(Int), Error) {
  let deadline = connection_waiter_deadline(worker.connection_waiters)
  peer_deadlines(deadline, dict.values(worker.connections), now)
}

fn peer_deadlines(
  deadline: Option(Int),
  peers: List(PeerState),
  now: Int,
) -> Result(Option(Int), Error) {
  case peers {
    [] -> Ok(deadline)
    [peer, ..rest] -> {
      use protocol <- result.try(
        server_transport.next_deadline(peer.connection, now)
        |> result.map_error(map_transport_error),
      )
      let deadline =
        deadline
        |> earlier_deadline(protocol)
        |> earlier_deadline(positive_deadline(peer.next_pmtu_probe_milliseconds))
        |> earlier_deadline(stream_waiter_deadline(peer.stream_waiter))
        |> earlier_deadline(datagram_waiter_deadline(peer.datagram_waiter))
        |> stream_deadlines(dict.values(peer.streams))
      peer_deadlines(deadline, rest, now)
    }
  }
}

fn stream_deadlines(
  deadline: Option(Int),
  streams: List(StreamState),
) -> Option(Int) {
  case streams {
    [] -> deadline
    [stream, ..rest] ->
      stream_deadlines(
        deadline
          |> earlier_deadline(read_waiter_deadline(stream.read_waiter))
          |> earlier_deadline(pending_send_deadline(stream.pending_send)),
        rest,
      )
  }
}

fn fail_connection(
  worker: Worker,
  identifier: BitArray,
  error: Error,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(peer) -> {
      fail_peer_waiters(peer, error)
      close_qlog(peer.qlog_writer)
      Worker(
        ..worker,
        connections: dict.delete(worker.connections, identifier),
        dirty_connections: dict.delete(worker.dirty_connections, identifier),
        aliases: remove_aliases(worker.aliases, identifier),
        pending_connections: queue_filter(worker.pending_connections, fn(value) {
          value != identifier
        }),
      )
    }
  }
}

fn fail_peer_waiters(peer: PeerState, error: Error) -> Nil {
  case peer.stream_waiter {
    Some(StreamWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  case peer.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> process.send(reply, Error(error))
    None -> Nil
  }
  list.each(dict.values(peer.streams), fn(stream) {
    case stream.read_waiter {
      Some(ReadWaiter(_, reply, _)) -> process.send(reply, Error(error))
      None -> Nil
    }
    case stream.pending_send {
      Some(PendingSend(_, _, reply, _)) -> process.send(reply, Error(error))
      None -> Nil
    }
  })
}

fn shutdown(worker: Worker, error: Error) -> Nil {
  list.each(dict.values(worker.connections), fn(peer) {
    fail_peer_waiters(peer, error)
    close_qlog(peer.qlog_writer)
  })
  let remaining_waiters = queue_values(worker.connection_waiters)
  list.each(remaining_waiters, fn(waiter) {
    let ConnectionWaiter(reply, _) = waiter
    process.send(reply, Error(error))
  })
  let _ = udp.stop_relay(worker.relay)
  Nil
}

fn replay_policy(
  worker: Worker,
  now: Int,
) -> Result(resumption.ServerPolicy, resumption.Error) {
  use policy <- result.try(resumption.server_policy_with_keys(
    worker.ticket_keys,
    now,
    ticket_age_tolerance_milliseconds,
    worker.replay_cache,
  ))
  Ok(case worker.allow_zero_rtt, worker.replay_guard {
    False, _ -> resumption.reject_early_data(policy)
    True, None -> policy
    True, Some(guard) -> resumption.with_external_replay_guard(policy, guard)
  })
}

fn update_replay_cache(
  worker: Worker,
  connection: server_transport.State,
) -> Worker {
  case server_transport.replay_cache(connection) {
    Some(cache) -> Worker(..worker, replay_cache: cache)
    None -> worker
  }
}

fn update_peer_reply(
  worker: Worker,
  identifier: BitArray,
  reply: Subject(Result(Nil, Error)),
  operation: fn(PeerState) ->
    Result(server_transport.State, server_transport.Error),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, identifier) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) ->
      case operation(peer) {
        Error(error) -> reply_error(worker, reply, map_transport_error(error))
        Ok(connection) -> {
          process.send(reply, Ok(Nil))
          Ok(
            put_peer(
              worker,
              identifier,
              PeerState(..peer, connection: connection),
            )
            |> mark_dirty(identifier),
          )
        }
      }
  }
}

fn with_peer_reply(
  worker: Worker,
  identifier: BitArray,
  reply: Subject(Result(value, Error)),
  operation: fn(PeerState) -> Result(value, Error),
) -> Result(Worker, Nil) {
  case dict.get(worker.connections, identifier) {
    Error(_) -> reply_error(worker, reply, ConnectionClosed)
    Ok(peer) -> {
      process.send(reply, operation(peer))
      Ok(worker)
    }
  }
}

fn reply_error(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
}

fn put_peer(worker: Worker, identifier: BitArray, peer: PeerState) -> Worker {
  Worker(
    ..worker,
    connections: dict.insert(worker.connections, identifier, peer),
  )
}

fn mark_dirty(worker: Worker, identifier: BitArray) -> Worker {
  Worker(
    ..worker,
    dirty_connections: dict.insert(worker.dirty_connections, identifier, Nil),
  )
}

fn put_peer_stream(
  peer: PeerState,
  identifier: Int,
  stream: StreamState,
) -> PeerState {
  PeerState(..peer, streams: dict.insert(peer.streams, identifier, stream))
}

fn new_stream_state() -> StreamState {
  StreamState(None, None, False, False)
}

fn connection_handle(worker: Worker, identifier: BitArray) -> Connection {
  Connection(
    Listener(
      worker.commands,
      process.self(),
      worker.operation_timeout_milliseconds,
    ),
    identifier,
  )
}

fn incoming_stream(
  worker: Worker,
  connection_id: BitArray,
  identifier: Int,
) -> Result(IncomingStream, Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(QuicFailure)
    Ok(stream_id.StreamId(_, _, direction)) ->
      Ok(IncomingStream(
        Stream(connection_handle(worker, connection_id), identifier),
        direction == stream_id.Bidirectional,
      ))
  }
}

fn mark_accepted(worker: Worker, identifier: BitArray) -> Worker {
  case dict.get(worker.connections, identifier) {
    Ok(peer) -> put_peer(worker, identifier, PeerState(..peer, accepted: True))
    Error(_) -> worker
  }
}

fn active_handshake_count(worker: Worker) -> Int {
  worker.connections
  |> dict.values
  |> list.filter(fn(peer) { !server_transport.established(peer.connection) })
  |> list.length
}

fn unique_connection_id(
  worker: Worker,
  attempts: Int,
) -> Result(BitArray, Nil) {
  case attempts {
    0 -> Error(Nil)
    _ ->
      case crypto.secure_random(connection_id_bytes) {
        Error(_) -> unique_connection_id(worker, attempts - 1)
        Ok(value) ->
          case dict.has_key(worker.connections, value) {
            True -> unique_connection_id(worker, attempts - 1)
            False -> Ok(value)
          }
      }
  }
}

fn resolve_alias(worker: Worker, destination: BitArray) -> Option(BitArray) {
  case dict.has_key(worker.connections, destination) {
    True -> Some(destination)
    False ->
      case dict.get(worker.aliases, destination) {
        Ok(identifier) -> Some(identifier)
        Error(_) -> None
      }
  }
}

fn remove_aliases(
  aliases: Dict(BitArray, BitArray),
  identifier: BitArray,
) -> Dict(BitArray, BitArray) {
  dict.filter(aliases, fn(_, value) { value != identifier })
}

fn packet_header(parsed: packet.Packet) -> packet.LongHeader {
  case parsed {
    packet.Initial(header, _, _)
    | packet.ZeroRtt(header, _)
    | packet.Handshake(header, _)
    | packet.Retry(header, _, _)
    | packet.VersionNegotiation(header, _)
    | packet.UnknownVersion(header, _) -> header
  }
}

fn send_retry(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  original_destination: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  case
    bit_array.byte_size(original_destination) >= connection_id_bytes,
    unique_connection_id(worker, 8)
  {
    False, _ | _, Error(_) -> worker
    True, Ok(retry_source) -> {
      let #(address, port) = udp.endpoint_parts(peer)
      let now = udp.monotonic_millisecond()
      case current_key(worker.address_token_keys) {
        Error(_) -> worker
        Ok(key) ->
          case
            address_token.seal(
              key,
              address_token.Retry,
              address,
              port,
              original_destination,
              retry_source,
              now,
            ),
            retry_first_byte(protocol_version)
          {
            Ok(token), Ok(first_byte) ->
              send_retry_packet(
                worker,
                peer,
                protocol_version,
                original_destination,
                peer_connection_id,
                retry_source,
                first_byte,
                token,
              )
            _, _ -> worker
          }
      }
    }
  }
}

fn send_retry_packet(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  original_destination: BitArray,
  peer_connection_id: BitArray,
  retry_source: BitArray,
  first_byte: Int,
  token: BitArray,
) -> Worker {
  let placeholder =
    packet.Retry(
      packet.LongHeader(
        first_byte,
        protocol_version,
        peer_connection_id,
        retry_source,
      ),
      token,
      <<0:128>>,
    )
  case packet.encode_long(placeholder) {
    Error(_) -> worker
    Ok(encoded) ->
      case bit_array.slice(encoded, 0, bit_array.byte_size(encoded) - 16) {
        Error(_) -> worker
        Ok(retry_without_tag) ->
          case
            retry_integrity.tag(
              protocol_version,
              original_destination,
              retry_without_tag,
            )
          {
            Error(_) -> worker
            Ok(tag) -> {
              let _ =
                udp.send(
                  worker.socket,
                  peer,
                  <<retry_without_tag:bits, tag:bits>>,
                  ecn.NotEct,
                )
              worker
            }
          }
      }
  }
}

fn retry_first_byte(protocol_version: Version) -> Result(Int, crypto.Error) {
  use random <- result.try(crypto.secure_random(1))
  let assert <<random_low_bits>> = random
  let base = case protocol_version {
    version.Version1 -> 0xf0
    version.Version2 -> 0xc0
    _ -> 0
  }
  case base {
    0 -> Error(crypto.InvalidInput)
    _ -> Ok(int.bitwise_or(base, int.bitwise_and(random_low_bits, 0x0f)))
  }
}

fn send_version_negotiation(
  worker: Worker,
  peer: udp.Endpoint,
  original_destination: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  let response =
    packet.VersionNegotiation(
      packet.LongHeader(
        0x80,
        version.Negotiation,
        peer_connection_id,
        original_destination,
      ),
      [version.Version2, version.Version1],
    )
  case packet.encode_long(response) {
    Error(_) -> worker
    Ok(bytes) -> {
      let _ = udp.send(worker.socket, peer, bytes, ecn.NotEct)
      worker
    }
  }
}

fn candidate_send_endpoint(peer: PeerState) -> udp.Endpoint {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(endpoint, _, _)), True -> endpoint
    _, _ -> server_transport.peer(peer.connection)
  }
}

fn candidate_send_allowed(peer: PeerState, bytes: Int) -> Bool {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(_, received, sent)), True -> sent + bytes <= received * 3
    _, _ -> True
  }
}

fn record_candidate_send(peer: PeerState, bytes: Int) -> PeerState {
  case
    peer.candidate_path,
    server_transport.path_validation_in_progress(peer.connection)
  {
    Some(CandidatePath(endpoint, received, sent)), True ->
      PeerState(
        ..peer,
        candidate_path: Some(CandidatePath(endpoint, received, sent + bytes)),
      )
    _, _ -> peer
  }
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn open_listener(
  address_family: AddressFamily,
  port: Int,
) -> Result(udp.Socket, udp.Error) {
  case address_family {
    DualStack -> udp.open_dual_stack(port)
    Ipv4 -> {
      use wildcard <- result.try(udp.ipv4(0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, port))
      udp.open(endpoint)
    }
    Ipv6 -> {
      use wildcard <- result.try(udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, port))
      udp.open(endpoint)
    }
  }
}

fn validate_qlog_directory(directory: String) -> Result(Nil, Error) {
  case directory {
    "" -> Ok(Nil)
    value -> qlog.validate_directory(value) |> result.replace_error(StartFailed)
  }
}

fn open_qlog(
  directory: String,
  telemetry_limit: Int,
  now: Int,
) -> Result(Option(qlog.Writer), Error) {
  case directory {
    "" -> Ok(None)
    value ->
      qlog.open(value, qlog.Server, now, telemetry_limit)
      |> result.map(Some)
      |> result.replace_error(QlogUnavailable)
  }
}

fn close_qlog(writer: Option(qlog.Writer)) -> Nil {
  case writer {
    None -> Nil
    Some(value) -> {
      qlog.connection_closed(value, udp.monotonic_millisecond())
      let _ = qlog.close(value)
      Nil
    }
  }
}

fn resolve_key_ring(keys: List(BitArray)) -> Result(List(BitArray), Nil) {
  case keys {
    [] ->
      crypto.secure_random(32)
      |> result.map(fn(key) { [key] })
      |> result.replace_error(Nil)
    _ ->
      case valid_key_ring(keys) {
        True -> Ok(keys)
        False -> Error(Nil)
      }
  }
}

fn current_key(keys: List(BitArray)) -> Result(BitArray, Nil) {
  case keys {
    [current, ..] -> Ok(current)
    [] -> Error(Nil)
  }
}

fn open_address_token(
  keys: List(BitArray),
  token: BitArray,
  address: BitArray,
  port: Int,
  now: Int,
  maximum_age: Int,
) -> Result(address_token.Token, address_token.Error) {
  case keys {
    [] -> Error(address_token.AuthenticationFailed)
    [key, ..rest] ->
      case address_token.open(key, token, address, port, now, maximum_age) {
        Ok(value) -> Ok(value)
        Error(error) ->
          case rest {
            [] -> Error(error)
            _ ->
              open_address_token(rest, token, address, port, now, maximum_age)
          }
      }
  }
}

fn valid_key_ring(keys: List(BitArray)) -> Bool {
  case keys {
    [current] -> valid_key(current)
    [current, previous] ->
      current != previous && valid_key(current) && valid_key(previous)
    _ -> False
  }
}

fn valid_key(key: BitArray) -> Bool {
  bit_array.bit_size(key) % 8 == 0 && bit_array.byte_size(key) == 32
}

fn first_protocol(protocols: List(BitArray)) -> BitArray {
  case protocols {
    [protocol, ..] -> protocol
    [] -> <<>>
  }
}

fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

fn queue_count(queue: Queue(value)) -> Int {
  queue.count
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

fn queue_filter(queue: Queue(value), keep: fn(value) -> Bool) -> Queue(value) {
  let values = list.filter(queue_values(queue), keep)
  Queue(values, [], list.length(values))
}

fn queue_values(queue: Queue(value)) -> List(value) {
  list.append(queue.front, list.reverse(queue.back))
}

fn take_bytes(bytes: BitArray, count: Int) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case count >= size {
    True -> #(bytes, <<>>)
    False -> {
      let assert Ok(chunk) = bit_array.slice(bytes, 0, count)
      let assert Ok(rest) = bit_array.slice(bytes, count, size - count)
      #(chunk, rest)
    }
  }
}

fn positive_deadline(deadline: Int) -> Option(Int) {
  case deadline > 0 {
    True -> Some(deadline)
    False -> None
  }
}

fn earlier_deadline(first: Option(Int), second: Option(Int)) -> Option(Int) {
  case first, second {
    None, value | value, None -> value
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
  }
}

fn connection_waiter_deadline(waiters: Queue(ConnectionWaiter)) -> Option(Int) {
  connection_waiter_deadline_loop(queue_values(waiters), None)
}

fn connection_waiter_deadline_loop(
  waiters: List(ConnectionWaiter),
  earliest: Option(Int),
) -> Option(Int) {
  case waiters {
    [] -> earliest
    [ConnectionWaiter(_, deadline), ..rest] ->
      connection_waiter_deadline_loop(
        rest,
        earlier_deadline(earliest, Some(deadline)),
      )
  }
}

fn stream_waiter_deadline(waiter: Option(StreamWaiter)) -> Option(Int) {
  case waiter {
    Some(StreamWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn datagram_waiter_deadline(waiter: Option(DatagramWaiter)) -> Option(Int) {
  case waiter {
    Some(DatagramWaiter(_, deadline)) -> Some(deadline)
    None -> None
  }
}

fn read_waiter_deadline(waiter: Option(ReadWaiter)) -> Option(Int) {
  case waiter {
    Some(ReadWaiter(_, _, deadline)) -> Some(deadline)
    None -> None
  }
}

fn pending_send_deadline(send: Option(PendingSend)) -> Option(Int) {
  case send {
    Some(PendingSend(_, _, _, deadline)) -> Some(deadline)
    None -> None
  }
}

fn await_bootstrap(
  worker: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  timeout: Int,
) -> Result(Listener, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(bootstrap, fn(reply) { CallReply(reply) })
    |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(CallReply(reply)) -> reply
    Ok(WorkerExited) -> Error(StartFailed)
    Error(Nil) -> {
      process.kill(worker)
      Error(OperationTimeout)
    }
  }
}

fn call(
  listener: Listener,
  make_command: fn(Subject(Result(value, Error))) -> Command,
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
        |> process.selector_receive(
          within: listener.timeout_milliseconds
          + worker_reply_grace_milliseconds,
        )
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(result)) -> result
        Ok(WorkerExited) -> Error(ListenerClosed)
        Error(Nil) -> Error(OperationTimeout)
      }
    }
  }
}

fn map_transport_error(error: server_transport.Error) -> Error {
  case error {
    server_transport.InvalidInput -> InvalidInput
    server_transport.TlsFailure(_) -> QuicFailure
    server_transport.StatelessResetFailure(_) -> QuicFailure
    server_transport.DriverFailure(error) ->
      case error {
        driver.ConnectionFailure(transport.CongestionLimited)
        | driver.ConnectionFailure(transport.PacingLimited(_)) ->
          CongestionLimited
        driver.ConnectionFailure(transport.DatagramNotNegotiated) ->
          DatagramsNotNegotiated
        driver.ConnectionFailure(transport.DatagramTooLarge(maximum)) ->
          DatagramTooLarge(maximum)
        driver.ConnectionFailure(transport.UnknownStream(_)) -> StreamClosed
        driver.ConnectionFailure(transport.ConnectionUnavailable) ->
          ConnectionClosed
        _ -> QuicFailure
      }
  }
}
