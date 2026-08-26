//// One supervised actor per accepted generic QUIC connection.
////
//// The listener actor (`server_worker`) keeps the UDP relay, connection-ID
//// routing, admission, and the accept queue. Everything about one accepted
//// connection lives here instead, in its own process: the
//// `server_transport.State`, its streams and waiters, its qlog writer, and
//// its own keepalive and PMTU deadlines. Protocol work for one connection can
//// therefore never delay another connection on the same listener.
////
//// Sends go straight to the listener-owned socket with `udp.send`, which any
//// process may call, so an outbound datagram never needs a listener hop.
////
//// The actor's life ends with its transport. Once the phase reaches `Closed`
//// -- a local close finished draining, the idle timeout expired, or the peer
//// vanished and the idle timeout expired for it -- the transport arms no
//// further deadline and owes no further output. `shutdown` runs then: the
//// listener is told the connection is `Released`, every waiter still parked
//// on it is failed with the typed closed error (`ConnectionClosed`, so its
//// owner reads a closed connection rather than a protocol failure), the qlog
//// writer is closed, and the loop returns so the process exits normally. A
//// connection that fails ends the same way, with the failure as the waiters'
//// error. The listener frees the connection ID, its aliases, and the
//// admission slot on that notice or on the monitor `Down`, whichever it sees
//// first.
////
//// Every wait in the loop is bounded, so no phase can strand the process even
//// if no timer announces it: `next_worker_deadline` always yields a deadline,
//// falling back to `maximum_park_milliseconds` when neither the transport nor
//// a waiter arms one.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/address_token
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/process_label
import gleam_quic/internal/qlog
import gleam_quic/internal/runtime/connection as runtime_connection
import gleam_quic/internal/runtime/server_transport
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/hello
import gleam_quic/internal/tls/replay_guard
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/stream_id
import gleam_quic/version.{type Version}

const maximum_packets_per_flush = 64

// Pre-validation floor for one packet's frame payload. The send path widens it
// to whatever DPLPMTUD has validated for the current path.
const maximum_frame_data_bytes = 1000

const maximum_send_chunk_bytes = 65_536

const pmtu_probe_interval_milliseconds = 50

const ticket_age_tolerance_milliseconds = 10_000

const worker_reply_grace_milliseconds = 100

// The longest this actor parks when neither the transport nor any waiter arms
// a deadline of its own. The loop then still re-examines its phase this often,
// which is what gives every wait here a fixed upper bound.
const maximum_park_milliseconds = 1000

/// One accepted generic QUIC connection, addressed by its own actor.
pub opaque type Connection {
  Connection(commands: Subject(Command), worker: Pid, timeout_milliseconds: Int)
}

/// One stream routed through its owning connection actor.
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

/// A message the listener sends to a connection actor it owns.
pub type ListenerToConnection {
  /// One inbound datagram the listener routed to this connection.
  RoutedDatagram(
    peer: udp.Endpoint,
    datagram: BitArray,
    marking: packet_space.ReceivedCodepoint,
  )
}

/// A message a connection actor sends back to its listener.
pub type ConnectionToListener {
  /// The handshake completed, so this connection can be accepted.
  Established(identifier: BitArray)
  /// One delivered batch was consumed, so the listener may refill this
  /// connection's delivery credit by exactly what the actor took off its
  /// mailbox. Without it the window never reopens and delivery stalls.
  Consumed(identifier: BitArray, datagrams: Int, bytes: Int)
  /// The connection ended, so the listener owns its identifiers again. The
  /// actor sends this immediately before it exits, so the listener frees the
  /// route, its aliases, and the admission slot without waiting for the
  /// monitor `Down` -- and frees them exactly once whichever arrives first.
  Released(identifier: BitArray, worker: Pid)
}

/// Everything one connection actor owns from the moment it is spawned.
pub type Bootstrap {
  Bootstrap(
    listener: Pid,
    notices: Subject(ConnectionToListener),
    socket: udp.Socket,
    identifier: BitArray,
    state: server_transport.State,
    protocol_version: Version,
    congestion_control: transport.CongestionAlgorithm,
    qlog_writer: Option(qlog.Writer),
    application_protocols: List(BitArray),
    ticket_keys: List(BitArray),
    address_token_key: BitArray,
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
    now: Int,
  )
}

type Command {
  /// One credited batch from the listener, plus the datagrams it had to drop
  /// for this connection since the last batch. An empty batch carries only
  /// that drop count.
  Deliver(deliveries: List(ListenerToConnection), dropped: Int)
  ReloadedKeys(ticket_keys: List(BitArray), address_token_key: BitArray)
  Terminate
  Open(direction: stream_id.Direction, reply: Subject(Result(Int, Error)))
  AcceptStream(reply: Subject(Result(IncomingStream, Error)), deadline: Int)
  Send(
    stream_id: Int,
    bytes: BitArray,
    finish: Bool,
    reply: Subject(Result(Nil, Error)),
    deadline: Int,
  )
  Receive(
    stream_id: Int,
    maximum_bytes: Int,
    reply: Subject(Result(Read, Error)),
    deadline: Int,
  )
  ResetStream(stream_id: Int, code: Int, reply: Subject(Result(Nil, Error)))
  SendDatagram(payload: BitArray, reply: Subject(Result(Nil, Error)))
  ReceiveDatagram(reply: Subject(Result(BitArray, Error)), deadline: Int)
  MaximumDatagram(reply: Subject(Result(Int, Error)))
  Ping(reply: Subject(Result(Nil, Error)))
  SetCongestion(
    algorithm: transport.CongestionAlgorithm,
    reply: Subject(Result(Nil, Error)),
  )
  PathStats(reply: Subject(Result(transport.PathSnapshot, Error)))
  ConnectionStats(
    reply: Subject(Result(#(runtime_connection.Stats, Int), Error)),
  )
  TelemetryStats(reply: Subject(Result(qlog.Stats, Error)))
  Phase(reply: Subject(Result(transport.Phase, Error)))
  ClientIdentity(reply: Subject(Result(Option(BitArray), Error)))
  Protocol(
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
  CloseConnection(reply: Subject(Result(CloseResult, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
  ListenerExited
}

type Bootstrapped {
  Bootstrapped(Connection)
  BootstrapExited
}

/// Bounded first-in first-out backlog. Both actors bound their waiter and
/// backlog queues with it, so the listener imports it from here rather than
/// keeping a second copy.
pub opaque type Queue(value) {
  Queue(front: List(value), back: List(value), count: Int)
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
    identifier: BitArray,
    notices: Subject(ConnectionToListener),
    commands: Subject(Command),
    selector: process.Selector(LoopMessage),
    peer: PeerState,
    dropped_datagrams: Int,
    dirty: Bool,
    failure: Option(Error),
    established_reported: Bool,
    application_protocols: List(BitArray),
    ticket_keys: List(BitArray),
    address_token_key: BitArray,
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    operation_timeout_milliseconds: Int,
    stream_buffer_limit: Int,
    queue_limit: Int,
    datagram_limit: Int,
  )
}

type CallOutcome(value) {
  CallReply(Result(value, Error))
  WorkerExited
}

/// Spawn and monitor-ready one connection actor for an admitted connection.
pub fn start(bootstrap: Bootstrap) -> Result(Connection, Error) {
  let ready = process.new_subject()
  let worker =
    process.spawn_unlinked(fn() {
      process_label.set(process_label.Connection)
      initialise(bootstrap, ready)
    })
  await_bootstrap(worker, ready, bootstrap.operation_timeout_milliseconds)
}

/// The connection actor process, so the listener can monitor it.
pub fn worker_pid(connection: Connection) -> Pid {
  connection.worker
}

/// Hand one credited batch of inbound datagrams to the owning connection,
/// together with the datagrams the listener had to drop for it since the last
/// batch because its delivery window was full.
pub fn deliver(
  connection: Connection,
  deliveries: List(ListenerToConnection),
  dropped: Int,
) -> Nil {
  process.send(connection.commands, Deliver(deliveries, dropped))
}

/// Install rotated ticket and address-token keys on a live connection.
pub fn reload_keys(
  connection: Connection,
  ticket_keys: List(BitArray),
  address_token_key: BitArray,
) -> Nil {
  process.send(
    connection.commands,
    ReloadedKeys(ticket_keys, address_token_key),
  )
}

/// Ask one connection actor to release its resources and exit.
pub fn terminate(connection: Connection) -> Nil {
  process.send(connection.commands, Terminate)
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
  call(connection, fn(reply) { Open(direction, reply) })
  |> result.map(fn(identifier) { Stream(connection, identifier) })
}

pub fn accept_stream(connection: Connection) -> Result(IncomingStream, Error) {
  call(connection, fn(reply) {
    AcceptStream(
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
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
  let connection = stream.connection
  call(connection, fn(reply) {
    Send(
      stream.identifier,
      bytes,
      finish,
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
}

pub fn receive(stream: Stream, maximum_bytes: Int) -> Result(Read, Error) {
  let connection = stream.connection
  call(connection, fn(reply) {
    Receive(
      stream.identifier,
      maximum_bytes,
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
}

pub fn reset(
  stream: Stream,
  application_error_code: Int,
) -> Result(Nil, Error) {
  call(stream.connection, fn(reply) {
    ResetStream(stream.identifier, application_error_code, reply)
  })
}

pub fn send_datagram(
  connection: Connection,
  payload: BitArray,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SendDatagram(payload, reply) })
}

pub fn receive_datagram(connection: Connection) -> Result(BitArray, Error) {
  call(connection, fn(reply) {
    ReceiveDatagram(
      reply,
      udp.monotonic_millisecond() + connection.timeout_milliseconds,
    )
  })
}

pub fn maximum_datagram_size(connection: Connection) -> Result(Int, Error) {
  call(connection, MaximumDatagram)
}

pub fn ping(connection: Connection) -> Result(Nil, Error) {
  call(connection, Ping)
}

pub fn set_congestion_control(
  connection: Connection,
  algorithm: transport.CongestionAlgorithm,
) -> Result(Nil, Error) {
  call(connection, fn(reply) { SetCongestion(algorithm, reply) })
}

pub fn path_stats(
  connection: Connection,
) -> Result(transport.PathSnapshot, Error) {
  call(connection, PathStats)
}

/// Snapshot the runtime counters of one connection together with the number of
/// inbound datagrams the listener dropped for it, so the public diagnostics
/// path can publish both from one call.
pub fn connection_stats(
  connection: Connection,
) -> Result(#(runtime_connection.Stats, Int), Error) {
  call(connection, ConnectionStats)
}

/// Return a redacted SHA-256 fingerprint for the verified client identity.
pub fn client_identity(
  connection: Connection,
) -> Result(Option(BitArray), Error) {
  call(connection, ClientIdentity)
}

pub fn telemetry_stats(connection: Connection) -> Result(qlog.Stats, Error) {
  call(connection, TelemetryStats)
}

pub fn phase(connection: Connection) -> Result(transport.Phase, Error) {
  call(connection, Phase)
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
  call(connection, Protocol)
}

pub fn close(connection: Connection) -> Result(CloseResult, Error) {
  call(connection, CloseConnection)
}

fn initialise(bootstrap: Bootstrap, ready: Subject(Connection)) -> Nil {
  let commands = process.new_subject()
  let listener_monitor = process.monitor(bootstrap.listener)
  let selector =
    process.new_selector()
    |> process.select_map(commands, ReceivedCommand)
    |> process.select_specific_monitor(listener_monitor, fn(_) {
      ListenerExited
    })
  let peer =
    PeerState(
      bootstrap.state,
      dict.new(),
      queue_new(),
      None,
      queue_new(),
      0,
      None,
      bootstrap.protocol_version,
      bootstrap.congestion_control,
      bootstrap.qlog_writer,
      None,
      None,
      bootstrap.now + pmtu_probe_interval_milliseconds,
    )
  process.send(
    ready,
    Connection(
      commands,
      process.self(),
      bootstrap.operation_timeout_milliseconds,
    ),
  )
  loop(Worker(
    bootstrap.socket,
    bootstrap.identifier,
    bootstrap.notices,
    commands,
    selector,
    peer,
    0,
    True,
    None,
    False,
    bootstrap.application_protocols,
    bootstrap.ticket_keys,
    bootstrap.address_token_key,
    bootstrap.replay_cache,
    bootstrap.replay_guard,
    bootstrap.allow_zero_rtt,
    bootstrap.operation_timeout_milliseconds,
    bootstrap.stream_buffer_limit,
    bootstrap.queue_limit,
    bootstrap.datagram_limit,
  ))
}

/// One turn of this actor's life: drain what arrived, expire what timed out,
/// then either end -- on a failure, or on a transport that reached `Closed` --
/// drive the work the turn made pending, or park until the next message or
/// deadline.
fn loop(worker: Worker) -> Nil {
  let worker = when_live(worker, dispatch_all_events)
  let now = udp.monotonic_millisecond()
  let worker = when_live(worker, expire_waiters(_, now))
  let worker = when_live(worker, retry_pending_sends)
  case worker.failure, transport_closed(worker), worker.dirty {
    Some(error), _, _ -> shutdown(worker, error)
    // A closed transport owes nothing further and can never reopen, so the
    // actor releases what it owns and exits rather than staying resident.
    None, True, _ -> shutdown(worker, ConnectionClosed)
    None, False, True -> drive_and_loop(worker)
    None, False, False -> wait_for_work(worker, now)
  }
}

/// Whether the transport phase reached `Closed`, after a local close drained,
/// after the idle timeout expired, or after the peer vanished.
fn transport_closed(worker: Worker) -> Bool {
  case server_transport.phase(worker.peer.connection) {
    transport.Closed -> True
    transport.Closing
    | transport.Draining
    | transport.Handshaking
    | transport.Established -> False
  }
}

fn when_live(worker: Worker, step: fn(Worker) -> Worker) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> step(worker)
  }
}

// Park until the next message or the next deadline, whichever comes first.
// The deadline is never absent, so this wait is always bounded: a phase change
// no timer announced is still noticed within one `maximum_park_milliseconds`.
// nolint: thrown_away_error -- a failed step is connection teardown here.
fn wait_for_work(worker: Worker, now: Int) -> Nil {
  case next_worker_deadline(worker, now) {
    Error(_) -> shutdown(worker, ConnectionClosed)
    Ok(deadline) -> {
      let received =
        process.selector_receive(
          worker.selector,
          within: int.max(0, deadline - now),
        )
      case received {
        Ok(ListenerExited) -> shutdown(worker, ListenerClosed)
        Ok(ReceivedCommand(command)) ->
          case handle_command(worker, command) {
            Error(Nil) -> Nil
            Ok(next) -> drive_and_loop(next)
          }
        Error(Nil) -> timer_drive_and_loop(worker)
      }
    }
  }
}

fn drive_and_loop(worker: Worker) -> Nil {
  worker
  |> when_live(flush_when_dirty)
  |> when_live(retry_pending_sends)
  |> loop
}

fn flush_when_dirty(worker: Worker) -> Worker {
  case worker.dirty {
    True -> tick_and_flush(worker)
    False -> worker
  }
}

fn timer_drive_and_loop(worker: Worker) -> Nil {
  worker |> tick_and_flush |> when_live(retry_pending_sends) |> loop
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn tick_and_flush(worker: Worker) -> Worker {
  let now = udp.monotonic_millisecond()
  let worker = Worker(..worker, dirty: False)
  case server_transport.tick(worker.peer.connection, now) {
    Error(_) -> fail_connection(worker, QuicFailure)
    Ok(connection) -> {
      let worker =
        put_peer(worker, PeerState(..worker.peer, connection: connection))
      // A connection the tick just closed sends nothing more; the loop turns
      // that phase into an orderly exit.
      case transport_closed(worker) {
        True -> worker
        False ->
          worker
          |> when_live(maybe_queue_new_token(_, now))
          |> when_live(maybe_issue_session_ticket(_, now))
          |> when_live(maybe_probe(_, now))
          |> when_live(flush_connection(_, now, maximum_packets_per_flush))
      }
    }
  }
}

/// Apply one credited batch and acknowledge it, so the listener refills this
/// connection's delivery window by exactly what left the mailbox. The drops
/// the listener reports alongside the batch are recorded first: they are
/// already gone, and QUIC recovers them like any other loss.
fn consume_deliveries(
  worker: Worker,
  deliveries: List(ListenerToConnection),
  dropped: Int,
) -> Worker {
  let #(datagrams, bytes) = delivered_cost(deliveries, 0, 0)
  let worker =
    Worker(
      ..worker,
      dropped_datagrams: worker.dropped_datagrams + int.max(0, dropped),
    )
  let worker = receive_deliveries(worker, deliveries)
  process.send(worker.notices, Consumed(worker.identifier, datagrams, bytes))
  worker
}

/// What one delivered batch cost the listener's window for this connection:
/// the datagrams it carried and their total size. The listener refills exactly
/// this much, so the two sides can never drift apart.
fn delivered_cost(
  deliveries: List(ListenerToConnection),
  datagrams: Int,
  bytes: Int,
) -> #(Int, Int) {
  case deliveries {
    [] -> #(datagrams, bytes)
    [RoutedDatagram(_, datagram, _), ..rest] ->
      delivered_cost(rest, datagrams + 1, bytes + bit_array.byte_size(datagram))
  }
}

/// Apply one routed batch, dispatching each datagram's transport events before
/// the next datagram is read. A batch is only a transport detail, so a later
/// datagram -- a peer close, say -- must never hide the events an earlier one
/// produced, such as the completed handshake this listener has to accept.
fn receive_deliveries(
  worker: Worker,
  deliveries: List(ListenerToConnection),
) -> Worker {
  case worker.failure, deliveries {
    Some(_), _ | None, [] -> worker
    None, [RoutedDatagram(peer, datagram, marking), ..rest] ->
      receive_deliveries(
        receive_one_datagram(worker, peer, datagram, marking)
          |> when_live(dispatch_all_events),
        rest,
      )
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn receive_one_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  let peer_state = worker.peer
  let now = udp.monotonic_millisecond()
  case replay_policy(worker, now) {
    Error(_) -> fail_connection(worker, QuicFailure)
    Ok(policy) ->
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
            False -> fail_connection(worker, QuicFailure)
          }
        Error(_) -> fail_connection(worker, QuicFailure)
        Ok(connection) -> {
          case peer_state.qlog_writer {
            Some(writer) ->
              qlog.datagram_received(writer, now, bit_array.byte_size(datagram))
            None -> Nil
          }
          let previous = server_transport.peer(peer_state.connection)
          case same_endpoint(previous, peer) {
            True ->
              put_peer(worker, PeerState(..peer_state, connection: connection))
              |> update_replay_cache(connection)
              |> mark_dirty
            False ->
              handle_candidate_path(
                worker,
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

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_candidate_path(
  worker: Worker,
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
        PeerState(
          ..peer_state,
          connection: server_transport.with_peer(connection, peer),
        ),
      )
      |> update_replay_cache(connection)
      |> mark_dirty
    True ->
      case peer_state.candidate_path {
        Some(CandidatePath(endpoint, received, sent)) ->
          case same_endpoint(endpoint, peer) {
            False -> worker
            True ->
              put_peer(
                worker,
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
              |> mark_dirty
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
                  |> mark_dirty
              }
          }
      }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn maybe_queue_new_token(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
  let endpoint = server_transport.peer(peer.connection)
  let already_issued = case peer.token_endpoint {
    Some(previous) -> same_endpoint(previous, endpoint)
    None -> False
  }
  case server_transport.established(peer.connection), already_issued {
    False, _ | _, True -> worker
    True, False -> {
      let #(address, port) = udp.endpoint_parts(endpoint)
      case
        address_token.seal(
          worker.address_token_key,
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
          case server_transport.queue_new_token(peer.connection, token) {
            Error(_) -> worker
            Ok(connection) ->
              put_peer(
                worker,
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

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn maybe_issue_session_ticket(worker: Worker, now: Int) -> Worker {
  case
    server_transport.issue_session_ticket_if_ready(worker.peer.connection, now)
  {
    Error(_) -> fail_connection(worker, QuicFailure)
    Ok(connection) ->
      put_peer(worker, PeerState(..worker.peer, connection: connection))
  }
}

fn maybe_probe(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
  case
    peer.next_pmtu_probe_milliseconds,
    server_transport.path_validation_in_progress(peer.connection),
    server_transport.established(peer.connection)
  {
    0, _, _ | _, True, _ -> worker
    _, _, False ->
      put_peer(
        worker,
        PeerState(
          ..peer,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    deadline, _, _ if now < deadline -> worker
    _, _, True ->
      case server_transport.pmtu_discovery_complete(peer.connection) {
        True ->
          put_peer(worker, PeerState(..peer, next_pmtu_probe_milliseconds: 0))
        False -> send_pmtu_probe(worker, peer, now)
      }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn send_pmtu_probe(worker: Worker, peer: PeerState, now: Int) -> Worker {
  case server_transport.prepare_pmtu_probe(peer.connection, now) {
    Error(_) -> worker
    Ok(None) ->
      put_peer(
        worker,
        PeerState(
          ..peer,
          next_pmtu_probe_milliseconds: now + pmtu_probe_interval_milliseconds,
        ),
      )
    Ok(Some(prepared)) ->
      case
        udp.classify_send(udp.send(
          worker.socket,
          candidate_send_endpoint(peer),
          server_transport.prepared_bytes(prepared),
          ecn.NotEct,
        ))
      {
        // Don't-Fragment is set, so a probe the local interface cannot carry
        // whole is refused rather than split. The probe is dropped
        // uncommitted and the path returns to the floor.
        udp.PathTooSmall ->
          put_peer(
            worker,
            PeerState(
              ..peer,
              connection: server_transport.report_pmtu_black_hole(
                peer.connection,
              ),
              next_pmtu_probe_milliseconds: now
                + pmtu_probe_interval_milliseconds,
            ),
          )
        udp.SocketLost -> worker
        udp.Delivered ->
          case server_transport.commit_datagram(prepared, ecn.NotEct, now) {
            Error(_) -> worker
            Ok(connection) ->
              put_peer(
                worker,
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

// nolint: thrown_away_error, deep_nesting -- teardown; moved send tree.
fn flush_connection(worker: Worker, now: Int, remaining: Int) -> Worker {
  let peer = worker.peer
  case remaining {
    0 -> worker
    _ ->
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
        Error(_) -> fail_connection(worker, QuicFailure)
        Ok(Some(prepared)) -> {
          let bytes = server_transport.prepared_bytes(prepared)
          let destination = candidate_send_endpoint(peer)
          case candidate_send_allowed(peer, bit_array.byte_size(bytes)) {
            False -> worker
            True ->
              case
                udp.classify_send(udp.send(
                  worker.socket,
                  destination,
                  bytes,
                  ecn.NotEct,
                ))
              {
                // The socket sets Don't-Fragment, so an outgoing device
                // narrower than the path DPLPMTUD confirmed refuses the
                // datagram instead of splitting it. That is a path
                // measurement, not a broken socket: the datagram is dropped
                // uncommitted, its frames are still owed and are retransmitted
                // by recovery, and the path returns to the 1200-byte floor.
                udp.PathTooSmall ->
                  put_peer(
                    worker,
                    PeerState(
                      ..peer,
                      connection: server_transport.report_pmtu_black_hole(
                        peer.connection,
                      ),
                    ),
                  )
                udp.SocketLost -> fail_connection(worker, QuicFailure)
                udp.Delivered ->
                  case
                    server_transport.commit_datagram(prepared, ecn.NotEct, now)
                  {
                    Error(_) -> fail_connection(worker, QuicFailure)
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
                        put_peer(worker, next),
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
  let #(connection, events) =
    server_transport.take_events(worker.peer.connection)
  let worker =
    put_peer(worker, PeerState(..worker.peer, connection: connection))
  dispatch_events(worker, events)
}

fn dispatch_events(worker: Worker, events: List(transport.Event)) -> Worker {
  case worker.failure, events {
    Some(_), _ | None, [] -> worker
    None, [event, ..rest] ->
      dispatch_events(dispatch_event(worker, event), rest)
  }
}

fn dispatch_event(worker: Worker, event: transport.Event) -> Worker {
  case event {
    transport.HandshakeEstablished -> report_established(worker)
    transport.StreamOpened(identifier) -> register_stream(worker, identifier)
    transport.StreamReadable(identifier) ->
      service_read_waiter(worker, identifier)
    transport.StreamWasReset(identifier, _) ->
      service_read_waiter(worker, identifier)
    transport.DatagramReceived(payload) -> enqueue_datagram(worker, payload)
    transport.PathValidated -> commit_candidate_path(worker)
    transport.PathValidationFailed -> discard_candidate_path(worker)
    transport.PeerClosed(_, _) | transport.StatelessResetReceived ->
      fail_connection(worker, ConnectionClosed)
    _ -> worker
  }
}

fn report_established(worker: Worker) -> Worker {
  case worker.established_reported {
    True -> worker
    False -> {
      process.send(worker.notices, Established(worker.identifier))
      Worker(..worker, established_reported: True)
    }
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    Deliver(deliveries, dropped) ->
      Ok(consume_deliveries(worker, deliveries, dropped))
    ReloadedKeys(ticket_keys, address_token_key) ->
      Ok(
        Worker(
          ..worker,
          ticket_keys: ticket_keys,
          address_token_key: address_token_key,
          peer: PeerState(..worker.peer, token_endpoint: None),
        )
        |> mark_dirty,
      )
    Terminate -> {
      shutdown(worker, ConnectionClosed)
      Error(Nil)
    }
    Open(direction, reply) -> handle_open(worker, direction, reply)
    AcceptStream(reply, deadline) ->
      handle_accept_stream(worker, reply, deadline)
    Send(identifier, bytes, finish, reply, deadline) ->
      handle_send(worker, identifier, bytes, finish, reply, deadline)
    Receive(identifier, maximum, reply, deadline) ->
      handle_receive(worker, identifier, maximum, reply, deadline)
    ResetStream(identifier, code, reply) ->
      update_peer_reply(worker, reply, fn(peer) {
        server_transport.reset(peer.connection, identifier, code)
      })
    SendDatagram(payload, reply) -> handle_send_datagram(worker, payload, reply)
    ReceiveDatagram(reply, deadline) ->
      handle_receive_datagram(worker, reply, deadline)
    MaximumDatagram(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        server_transport.maximum_datagram_size(peer.connection)
        |> result.map_error(map_transport_error)
      })
    Ping(reply) ->
      update_peer_reply(worker, reply, fn(peer) {
        server_transport.ping(peer.connection)
      })
    SetCongestion(algorithm, reply) ->
      handle_set_congestion(worker, algorithm, reply)
    PathStats(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.path_stats(peer.connection))
      })
    ConnectionStats(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(#(server_transport.stats(peer.connection), worker.dropped_datagrams))
      })
    TelemetryStats(reply) -> handle_telemetry_stats(worker, reply)
    Phase(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        Ok(server_transport.phase(peer.connection))
      })
    ClientIdentity(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        case server_transport.client_identity(peer.connection) {
          None -> Ok(None)
          Some(identity) ->
            authentication.verified_peer_fingerprint(identity)
            |> result.map(Some)
            |> result.replace_error(QuicFailure)
        }
      })
    Protocol(reply) ->
      with_peer_reply(worker, reply, fn(peer) {
        let protocol = case
          server_transport.application_protocol(peer.connection)
        {
          Some(value) -> value
          None -> first_protocol(worker.application_protocols)
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
    CloseConnection(reply) -> handle_close_connection(worker, reply)
  }
}

fn handle_open(
  worker: Worker,
  direction: stream_id.Direction,
  reply: Subject(Result(Int, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case server_transport.open_stream(peer.connection, direction) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(#(connection, identifier)) -> {
      process.send(reply, Ok(identifier))
      Ok(
        put_peer(
          worker,
          put_peer_stream(
            PeerState(..peer, connection: connection),
            identifier,
            new_stream_state(),
          ),
        )
        |> mark_dirty,
      )
    }
  }
}

fn handle_accept_stream(
  worker: Worker,
  reply: Subject(Result(IncomingStream, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case queue_pop(peer.incoming), peer.stream_waiter {
    Ok(#(identifier, rest)), _ -> {
      process.send(reply, incoming_stream(worker, identifier))
      Ok(put_peer(worker, PeerState(..peer, incoming: rest)))
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentAccept)
    Error(Nil), None ->
      Ok(put_peer(
        worker,
        PeerState(..peer, stream_waiter: Some(StreamWaiter(reply, deadline))),
      ))
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_send(
  worker: Worker,
  identifier: Int,
  bytes: BitArray,
  finish: Bool,
  reply: Subject(Result(Nil, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    bit_array.bit_size(bytes) % 8,
    stream_id.can_send(identifier, stream_id.Server)
  {
    remainder, _ if remainder != 0 -> reply_error(worker, reply, InvalidInput)
    _, False -> reply_error(worker, reply, InvalidDirection)
    _, True ->
      case dict.get(worker.peer.streams, identifier) {
        Error(_) -> reply_error(worker, reply, StreamClosed)
        Ok(stream) ->
          case stream.pending_send, stream.send_finished {
            Some(_), _ -> reply_error(worker, reply, ConcurrentSend)
            None, True -> reply_error(worker, reply, StreamClosed)
            None, False ->
              Ok(
                advance_send(
                  worker,
                  identifier,
                  PendingSend(bytes, finish, reply, deadline),
                )
                |> mark_dirty,
              )
          }
      }
  }
}

// nolint: thrown_away_error, deep_nesting -- teardown; moved send tree.
fn advance_send(
  worker: Worker,
  identifier: Int,
  pending: PendingSend,
) -> Worker {
  let peer = worker.peer
  case dict.get(peer.streams, identifier) {
    Error(_) -> {
      process.send(pending.reply, Error(StreamClosed))
      worker
    }
    Ok(stream) ->
      case server_transport.buffered_send_bytes(peer.connection, identifier) {
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
                  process.send(pending.reply, Error(map_transport_error(error)))
                  worker
                }
                Ok(connection) ->
                  case rest {
                    <<>> -> {
                      process.send(pending.reply, Ok(Nil))
                      put_peer(
                        worker,
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

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_receive(
  worker: Worker,
  identifier: Int,
  maximum_bytes: Int,
  reply: Subject(Result(Read, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  case
    maximum_bytes > 0 && maximum_bytes <= worker.stream_buffer_limit,
    stream_id.can_receive(identifier, stream_id.Server)
  {
    False, _ -> reply_error(worker, reply, InvalidInput)
    _, False -> reply_error(worker, reply, InvalidDirection)
    True, True ->
      case dict.get(worker.peer.streams, identifier) {
        Error(_) -> reply_error(worker, reply, StreamClosed)
        Ok(StreamState(read_waiter: Some(_), ..)) ->
          reply_error(worker, reply, ConcurrentReceive)
        Ok(_) ->
          Ok(read_or_wait(
            worker,
            identifier,
            ReadWaiter(maximum_bytes, reply, deadline),
          ))
      }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn read_or_wait(worker: Worker, identifier: Int, waiter: ReadWaiter) -> Worker {
  let peer = worker.peer
  case dict.get(peer.streams, identifier) {
    Error(_) -> {
      process.send(waiter.reply, Error(StreamClosed))
      worker
    }
    Ok(stream) ->
      case
        server_transport.read(peer.connection, identifier, waiter.maximum_bytes)
      {
        Error(error) -> {
          process.send(waiter.reply, Error(map_transport_error(error)))
          worker
        }
        Ok(#(connection, runtime_connection.Pending)) ->
          put_peer(
            worker,
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
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(..stream, read_waiter: None, receive_finished: True),
            ),
          )
        }
        Ok(#(connection, runtime_connection.Finished)) -> {
          process.send(waiter.reply, Ok(Finished))
          put_peer(
            worker,
            put_peer_stream(
              PeerState(..peer, connection: connection),
              identifier,
              StreamState(..stream, read_waiter: None, receive_finished: True),
            ),
          )
        }
      }
  }
}

fn handle_send_datagram(
  worker: Worker,
  payload: BitArray,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case server_transport.maximum_datagram_size(worker.peer.connection) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(maximum) -> {
      let size = bit_array.byte_size(payload)
      case size > maximum {
        True -> reply_error(worker, reply, DatagramTooLarge(maximum))
        False ->
          update_peer_reply(worker, reply, fn(peer) {
            server_transport.send_datagram(peer.connection, payload)
          })
      }
    }
  }
}

fn handle_receive_datagram(
  worker: Worker,
  reply: Subject(Result(BitArray, Error)),
  deadline: Int,
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case queue_pop(peer.datagrams), peer.datagram_waiter {
    Ok(#(payload, rest)), _ -> {
      process.send(reply, Ok(payload))
      Ok(put_peer(
        worker,
        PeerState(
          ..peer,
          datagrams: rest,
          datagram_bytes: peer.datagram_bytes - bit_array.byte_size(payload),
        ),
      ))
    }
    Error(Nil), Some(_) -> reply_error(worker, reply, ConcurrentDatagramReceive)
    Error(Nil), None ->
      Ok(put_peer(
        worker,
        PeerState(
          ..peer,
          datagram_waiter: Some(DatagramWaiter(reply, deadline)),
        ),
      ))
  }
}

fn handle_set_congestion(
  worker: Worker,
  algorithm: transport.CongestionAlgorithm,
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
  case server_transport.set_congestion_control(peer.connection, algorithm) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(
        put_peer(
          worker,
          PeerState(
            ..peer,
            connection: connection,
            congestion_control: algorithm,
          ),
        )
        |> mark_dirty,
      )
    }
  }
}

// nolint: thrown_away_error -- a failed step is connection teardown here.
fn handle_telemetry_stats(
  worker: Worker,
  reply: Subject(Result(qlog.Stats, Error)),
) -> Result(Worker, Nil) {
  case worker.peer.qlog_writer {
    None -> {
      process.send(reply, Ok(qlog.Stats(0, 0, 0)))
      Ok(worker)
    }
    Some(writer) ->
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
  reply: Subject(Result(CloseResult, Error)),
) -> Result(Worker, Nil) {
  let peer = worker.peer
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
        put_peer(worker, PeerState(..peer, connection: connection))
        |> mark_dirty,
      )
    }
  }
}

fn register_stream(worker: Worker, identifier: Int) -> Worker {
  let peer = worker.peer
  let peer = case dict.has_key(peer.streams, identifier) {
    True -> peer
    False -> put_peer_stream(peer, identifier, new_stream_state())
  }
  let worker = put_peer(worker, peer)
  case stream_id.decode(identifier) {
    Ok(stream_id.StreamId(_, stream_id.Client, _)) ->
      enqueue_incoming_stream(worker, identifier)
    _ -> worker
  }
}

fn enqueue_incoming_stream(worker: Worker, identifier: Int) -> Worker {
  let peer = worker.peer
  case peer.stream_waiter {
    Some(StreamWaiter(reply, _)) -> {
      process.send(reply, incoming_stream(worker, identifier))
      put_peer(worker, PeerState(..peer, stream_waiter: None))
    }
    None ->
      case queue_count(peer.incoming) >= worker.queue_limit {
        True ->
          fail_connection(
            worker,
            IncomingStreamQueueExceeded(worker.queue_limit),
          )
        False ->
          put_peer(
            worker,
            PeerState(..peer, incoming: queue_push(peer.incoming, identifier)),
          )
      }
  }
}

fn service_read_waiter(worker: Worker, identifier: Int) -> Worker {
  case dict.get(worker.peer.streams, identifier) {
    Ok(StreamState(read_waiter: Some(waiter), ..)) ->
      read_or_wait(worker, identifier, waiter)
    _ -> worker
  }
}

fn enqueue_datagram(worker: Worker, payload: BitArray) -> Worker {
  let peer = worker.peer
  case peer.datagram_waiter {
    Some(DatagramWaiter(reply, _)) -> {
      process.send(reply, Ok(payload))
      put_peer(worker, PeerState(..peer, datagram_waiter: None))
    }
    None -> {
      let size = bit_array.byte_size(payload)
      case
        queue_count(peer.datagrams) >= worker.queue_limit
        || peer.datagram_bytes + size > worker.datagram_limit
      {
        True ->
          fail_connection(worker, DatagramQueueExceeded(worker.queue_limit))
        False ->
          put_peer(
            worker,
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

fn commit_candidate_path(worker: Worker) -> Worker {
  case worker.peer {
    PeerState(candidate_path: Some(CandidatePath(endpoint, _, _)), ..) as peer -> {
      case peer.qlog_writer {
        Some(writer) -> qlog.path_updated(writer, udp.monotonic_millisecond())
        None -> Nil
      }
      put_peer(
        worker,
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

fn discard_candidate_path(worker: Worker) -> Worker {
  put_peer(worker, PeerState(..worker.peer, candidate_path: None))
}

fn retry_pending_sends(worker: Worker) -> Worker {
  retry_stream_sends(worker, dict.to_list(worker.peer.streams))
}

fn retry_stream_sends(
  worker: Worker,
  streams: List(#(Int, StreamState)),
) -> Worker {
  case streams {
    [] -> worker
    [#(identifier, StreamState(pending_send: Some(pending), ..)), ..rest] ->
      retry_stream_sends(advance_send(worker, identifier, pending), rest)
    [_, ..rest] -> retry_stream_sends(worker, rest)
  }
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let peer = worker.peer
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
  put_peer(worker, expire_stream_waiters(peer, dict.to_list(peer.streams), now))
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

/// The next moment this actor has to wake: the earliest of the transport's own
/// deadline, the PMTU probe, and every waiter's expiry. A transport that arms
/// no deadline at all still gets one here, so `Ok(None)` -- the unbounded park
/// -- is not representable and every wait in this loop stays bounded.
fn next_worker_deadline(worker: Worker, now: Int) -> Result(Int, Error) {
  let peer = worker.peer
  use protocol <- result.try(
    server_transport.next_deadline(peer.connection, now)
    |> result.map_error(map_transport_error),
  )
  Ok(
    None
    |> earlier_deadline(protocol)
    |> earlier_deadline(positive_deadline(peer.next_pmtu_probe_milliseconds))
    |> earlier_deadline(stream_waiter_deadline(peer.stream_waiter))
    |> earlier_deadline(datagram_waiter_deadline(peer.datagram_waiter))
    |> stream_deadlines(dict.values(peer.streams))
    |> option.unwrap(now + maximum_park_milliseconds),
  )
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

fn fail_connection(worker: Worker, error: Error) -> Worker {
  case worker.failure {
    Some(_) -> worker
    None -> Worker(..worker, failure: Some(error))
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

/// End this actor and release everything it owns. The listener hears
/// `Released` first, so the connection ID, its aliases, the accept-queue slot,
/// and the admission slot are freed without waiting for the monitor `Down`;
/// then every waiter still parked on this connection is failed with `error`
/// and the qlog writer is closed. Returning ends the loop, so the process
/// exits normally.
fn shutdown(worker: Worker, error: Error) -> Nil {
  process.send(worker.notices, Released(worker.identifier, process.self()))
  fail_peer_waiters(worker.peer, error)
  close_qlog(worker.peer.qlog_writer)
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
  reply: Subject(Result(Nil, Error)),
  operation: fn(PeerState) ->
    Result(server_transport.State, server_transport.Error),
) -> Result(Worker, Nil) {
  case operation(worker.peer) {
    Error(error) -> reply_error(worker, reply, map_transport_error(error))
    Ok(connection) -> {
      process.send(reply, Ok(Nil))
      Ok(
        put_peer(worker, PeerState(..worker.peer, connection: connection))
        |> mark_dirty,
      )
    }
  }
}

fn with_peer_reply(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  operation: fn(PeerState) -> Result(value, Error),
) -> Result(Worker, Nil) {
  process.send(reply, operation(worker.peer))
  Ok(worker)
}

fn reply_error(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
}

fn put_peer(worker: Worker, peer: PeerState) -> Worker {
  Worker(..worker, peer: peer)
}

fn mark_dirty(worker: Worker) -> Worker {
  Worker(..worker, dirty: True)
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

fn connection_handle(worker: Worker) -> Connection {
  Connection(
    worker.commands,
    process.self(),
    worker.operation_timeout_milliseconds,
  )
}

fn incoming_stream(
  worker: Worker,
  identifier: Int,
) -> Result(IncomingStream, Error) {
  case stream_id.decode(identifier) {
    Error(_) -> Error(QuicFailure)
    Ok(stream_id.StreamId(_, _, direction)) ->
      Ok(IncomingStream(
        Stream(connection_handle(worker), identifier),
        direction == stream_id.Bidirectional,
      ))
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

fn close_qlog(writer: Option(qlog.Writer)) -> Nil {
  case writer {
    None -> Nil
    Some(value) -> {
      qlog.connection_closed(value, udp.monotonic_millisecond())
      let _closed = qlog.close(value)
      Nil
    }
  }
}

fn first_protocol(protocols: List(BitArray)) -> BitArray {
  case protocols {
    [protocol, ..] -> protocol
    [] -> <<>>
  }
}

// The queue and deadline helpers below carry no connection state. They are
// public only because the listener actor bounds its accept queue and waiters
// with the same primitives.

/// An empty backlog.
pub fn queue_new() -> Queue(value) {
  Queue([], [], 0)
}

/// How many values a backlog holds.
pub fn queue_count(queue: Queue(value)) -> Int {
  queue.count
}

/// Append one value to a backlog.
pub fn queue_push(queue: Queue(value), value: value) -> Queue(value) {
  Queue(..queue, back: [value, ..queue.back], count: queue.count + 1)
}

/// Take the oldest value from a backlog.
pub fn queue_pop(queue: Queue(value)) -> Result(#(value, Queue(value)), Nil) {
  case queue.front, queue.back {
    [value, ..rest], _ ->
      Ok(#(value, Queue(..queue, front: rest, count: queue.count - 1)))
    [], [] -> Error(Nil)
    [], back -> queue_pop(Queue(..queue, front: list.reverse(back), back: []))
  }
}

/// Keep only the backlog values a predicate accepts.
pub fn queue_filter(
  queue: Queue(value),
  keep: fn(value) -> Bool,
) -> Queue(value) {
  let values = list.filter(queue_values(queue), keep)
  Queue(values, [], list.length(values))
}

/// Every backlog value in arrival order.
pub fn queue_values(queue: Queue(value)) -> List(value) {
  list.append(queue.front, list.reverse(queue.back))
}

fn take_bytes(bytes: BitArray, count: Int) -> #(BitArray, BitArray) {
  let size = bit_array.byte_size(bytes)
  case count >= size {
    True -> #(bytes, <<>>)
    False ->
      case
        bit_array.slice(bytes, 0, count),
        bit_array.slice(bytes, count, size - count)
      {
        Ok(chunk), Ok(rest) -> #(chunk, rest)
        _, _ -> #(bytes, <<>>)
      }
  }
}

fn positive_deadline(deadline: Int) -> Option(Int) {
  case deadline > 0 {
    True -> Some(deadline)
    False -> None
  }
}

/// The earlier of two optional deadlines.
pub fn earlier_deadline(
  first: Option(Int),
  second: Option(Int),
) -> Option(Int) {
  case first, second {
    None, value | value, None -> value
    Some(left), Some(right) if left <= right -> Some(left)
    Some(_), Some(right) -> Some(right)
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
  ready: Subject(Connection),
  timeout: Int,
) -> Result(Connection, Error) {
  let monitor = process.monitor(worker)
  let outcome =
    process.new_selector()
    |> process.select_map(ready, Bootstrapped)
    |> process.select_specific_monitor(monitor, fn(_) { BootstrapExited })
    |> process.selector_receive(within: timeout)
  process.demonitor_process(monitor)
  case outcome {
    Ok(Bootstrapped(connection)) -> Ok(connection)
    Ok(BootstrapExited) -> Error(StartFailed)
    Error(Nil) -> {
      process.kill(worker)
      Error(OperationTimeout)
    }
  }
}

fn call(
  connection: Connection,
  make_command: fn(Subject(Result(value, Error))) -> Command,
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
        |> process.selector_receive(
          within: connection.timeout_milliseconds
          + worker_reply_grace_milliseconds,
        )
      process.demonitor_process(monitor)
      case outcome {
        Ok(CallReply(result)) -> result
        Ok(WorkerExited) -> Error(ConnectionClosed)
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
