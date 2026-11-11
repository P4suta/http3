//// Event-driven generic QUIC listener actor.
////
//// The listener owns the UDP relay, connection-ID routing, the unknown-route
//// responses (Retry, Version Negotiation, address tokens), anti-replay, the
//// operational key rings, admission control, and the accept queue. Each
//// admitted connection is owned by its own supervised
//// `connection_worker` actor, which the listener spawns, monitors, and
//// forwards routed datagram batches to.
////
//// A connection actor outlives neither its transport nor this listener. When
//// one ends it sends `Released` and exits, and the listener drops its route,
//// its connection ID, every alias for it, its place in the accept queue, and
//// the admission slot it held. The monitor `Down` for the same actor runs the
//// identical release, so whichever of the two arrives first does the work and
//// the second finds no route and does nothing. Dropping the identifier and
//// its aliases in that same step is what keeps a datagram naming a released
//// connection from reaching a dead actor: it resolves to no route at all, so
//// a long header takes the unknown-route path and a short header is dropped.
////
//// The inbound path is credit bounded end to end, in four stages, so no peer
//// can grow any mailbox on it without bound:
////
////   1. relay to listener: the socket relay holds one batch of receive credit
////      and delivers nothing more until `udp.continue_relay` returns it. The
////      listener returns that credit as soon as it has decoded a batch, before
////      it routes it, so the listener itself never blocks and never queues.
////   2. listener to connection: each route carries the window in its `Entry`
////      -- `datagram_credit` datagrams and `byte_credit` bytes. A batch is
////      grouped by connection ID and each connection is sent exactly one
////      message carrying only what its remaining window admits; the rest is
////      dropped and counted for that connection alone. Every such message
////      costs the window at least one datagram, so the mailbox is bounded in
////      messages too, by the window's datagrams plus the single drop report
////      the listener sends only when nothing else is outstanding.
////   3. connection to owner: the connection actor answers each delivered
////      message with `Consumed`, reporting what it took off its mailbox, and
////      the listener refills that connection's window by exactly that much.
////      A connection whose actor stalls therefore stops being sent to rather
////      than accumulating a backlog.
////   4. owner to connection: the owner's own commands are the only other
////      source of messages for that actor, and an owner is one process issuing
////      one bounded call at a time.
////
//// Stage 2 is what makes a stalled connection structurally unable to delay
//// another: a flooded actor's mailbox is bounded by its window plus its
//// owner's commands, and the drop is protocol correct because QUIC recovers a
//// dropped datagram exactly as it recovers one the network lost.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import quic_core.{type AddressFamily, DualStack, Ipv4, Ipv6}
import quic_core/frame
import quic_core/internal/address_token
import quic_core/internal/connection_state as transport
import quic_core/internal/crypto
import quic_core/internal/ecn
import quic_core/internal/initial_crypto
import quic_core/internal/packet_space
import quic_core/internal/process_label
import quic_core/internal/qlog
import quic_core/internal/retry_integrity
import quic_core/internal/runtime/budget
import quic_core/internal/runtime/connection_worker.{
  type Connection, type Error, type Queue, AcceptQueueExceeded, InvalidInput,
  ListenerClosed, OperationTimeout, QlogUnavailable, StartFailed,
}
import quic_core/internal/runtime/qlog_budget
import quic_core/internal/runtime/server_transport
import quic_core/internal/runtime/shutdown_deadline
import quic_core/internal/stateless_reset
import quic_core/internal/tls/anti_replay
import quic_core/internal/tls/authentication
import quic_core/internal/tls/engine
import quic_core/internal/tls/extension_value
import quic_core/internal/tls/replay_guard
import quic_core/internal/tls/resumption
import quic_core/internal/udp
import quic_core/internal/version_negotiation
import quic_core/internal/wire_packet
import quic_core/packet
import quic_core/version.{type Version}

const connection_id_bytes = 8

const replay_window_milliseconds = 10_000

const replay_cache_capacity = 4096

const ticket_age_tolerance_milliseconds = 10_000

const retry_token_lifetime_milliseconds = 10_000

const new_token_lifetime_milliseconds = 86_400_000

const worker_reply_grace_milliseconds = 100

// Reserve this tail inside the configured operation deadline so fanout joiners which miss the shared boundary can be killed and observed together.
const shutdown_join_cleanup_milliseconds = 50

/// The QUIC transport error code for CONNECTION_REFUSED (RFC 9000 section 20).
const connection_refused_code = 0x02

/// The QUIC transport error code for INVALID_TOKEN (RFC 9000 section 20).
const invalid_token_code = 0x0b

/// The smallest plaintext an Initial packet may carry here, padded with
/// PADDING frames. Header protection samples 16 bytes from four bytes past the
/// packet-number field, so a bare CONNECTION_CLOSE is too short to protect.
const minimum_initial_plaintext_bytes = 32

// The listener-to-connection delivery window (stage 2 above): one connection
// may hold at most this many routed datagrams, and this many routed bytes, in
// its actor's mailbox at once, and its `Consumed` acknowledgement refills
// exactly what it took off that mailbox. Both halves bind, and the byte half
// is what bounds delivered memory: the listener sockets impose no packet-size
// cap, so a peer can spoof multi-kilobyte datagrams that the datagram half
// alone would admit 192 of.
//
// The window is sized against the relay batch, which is what keeps it safe
// for a healthy connection as well as binding on a flooding one. The relay
// hands the listener a whole batch in one message, the listener routes that
// batch in a single step, and it can route the next batch before the
// `Consumed` for the previous one is handled, so no acknowledgement can widen
// a window part way through a batch. A window narrower than two batches would
// therefore shed part of a burst a perfectly healthy connection is keeping up
// with: lost throughput for loss recovery to repair, rather than a flooding
// peer held to its share.
//
// No configured `Limits` resource fits this window. `Queue` counts accepted
// work, `Buffer` counts stream bytes, and `Datagram` bounds RFC 9221
// DATAGRAM-frame queueing inside an established connection rather than the
// UDP delivery window in front of it -- and, being application tunable, it
// must not be able to widen a denial-of-service bound. Both halves are
// therefore fixed constants, documented in the architecture notes.

/// The datagram half: three whole relay batches, 3 * 64, three times the batch
/// size `quic_core_udp_ffi:maximum_relay_batch/0` reports.
///
/// Two batches is the floor, and it is the floor the credit suite pins: the
/// listener can route a second batch before the first batch's `Consumed` is
/// handled, so a connection that is merely one acknowledgement behind has to
/// absorb two full batches back to back. The third batch is slack above that
/// floor, so an ordinary datagram of the peer's own -- an acknowledgement, a
/// probe -- arriving inside the same unrefilled window cannot eat into it.
///
/// The slack is free in memory terms: the byte half below is unchanged, and
/// the byte half is what bounds delivered memory. Widening the datagram half
/// admits more small datagrams per window, never more bytes.
const datagram_credit = 192

/// The byte half: two whole relay batches at 2 KiB a datagram, 2 * 64 * 2048.
/// 2 KiB is above the 1500-byte Ethernet MTU and well above the 1200-byte
/// floor RFC 9000 section 14 guarantees, so at the sizes a conventional path
/// actually delivers this half carries slack of its own above the two-batch
/// floor: 218 datagrams at that 1200-byte floor, 174 at the Ethernet MTU,
/// both beyond the 128 the floor requires.
///
/// What that costs, stated plainly: 256 KiB of delivered-but-unconsumed
/// memory per connection, and 256 MiB across the default 1024-connection
/// admission limit, where the narrower 64 KiB window this replaces totalled
/// 64 MiB. That aggregate is four times the 64 MiB `EndpointMemory` value
/// `config.default_limits` carries, and the two bounds are separate on
/// purpose rather than by omission. `EndpointMemory` charges what a
/// connection actor holds once it has taken a datagram off its mailbox --
/// reassembly, backlogs, send buffers, sent-packet histories -- and this
/// window bounds what is still in the mailbox, delivered to the actor but not
/// yet consumed by it. Mailbox occupancy is therefore bounded per connection
/// by this window and in aggregate by `Connections` times this window; the
/// endpoint budget does not hold that total down, and never claimed to.
/// Reaching the aggregate also takes 1024 connections flooded at once whose
/// owners have all stalled, because a connection that keeps up holds a full
/// window only momentarily.
///
/// The byte half is deliberately narrower than two batches of the largest
/// datagram the transport can carry, and the socket receive buffer is what
/// justifies the smaller bound: two batches of the largest datagram this
/// implementation will ever send -- 2 * 64 * 61_440 -- would be 7.5 MiB per
/// connection, while the listener socket's whole receive buffer is 4 MiB, so
/// a burst that large cannot even be queued for the relay. Datagrams larger
/// than 2 KiB are still delivered -- the byte half simply becomes what bounds
/// them, which is what keeps a peer spoofing 8 KiB datagrams from putting
/// 1.5 MiB in one actor's mailbox.
const byte_credit = 262_144

/// The delivery window this listener ships, as `#(datagrams, bytes)`.
/// Published so the public credit suite pins the shipped window against the
/// relay's own batch size rather than against a copy of these two numbers.
pub fn delivery_window() -> #(Int, Int) {
  #(datagram_credit, byte_credit)
}

/// Running owner-bound listener.
pub opaque type Listener {
  Listener(commands: Subject(Command), worker: Pid, timeout_milliseconds: Int)
}

/// Idempotent listener stop outcome.
pub type StopResult {
  Stopped
  AlreadyStopped
}

/// Finite, payload-free reason for the listener's Initial-token decision.
///
/// In particular, `InvalidRetryTokenRefused` is possible only after this endpoint authenticated and decoded the token as Retry.
/// Bytes that cannot be authenticated never acquire a trusted purpose and remain `UnreadableTokenRetried`, as required by RFC 9000 verified erratum 7861.
pub type InitialTokenDecision {
  MissingTokenRetried
  UnreadableTokenRetried
  InvalidNewTokenRetried
  InvalidRetryTokenRefused
  RetryTokenAccepted
  NewTokenAccepted
}

type InitialTokenRoute {
  RequireRetry
  RefuseInvalidRetry
  AcceptRetry(original_destination: BitArray, retry_source: BitArray)
  AcceptNewToken
}

type Command {
  QlogBudgetStats(reply: Subject(Result(#(Int, Int, Int), Error)))
  QlogAdmissionStats(
    reply: Subject(Result(#(Int, Int, Int, Int, Int, Int, Int), Error)),
  )
  ConnectionIdStats(reply: Subject(Result(#(Int, Int), Error)))
  Port(reply: Subject(Result(Int, Error)))
  AcceptConnection(
    reply: Subject(Result(Connection, Error)),
    deadline: Option(Int),
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
  Stop(deadline_milliseconds: Int, reply: Subject(Result(StopResult, Error)))
}

type LoopMessage {
  ReceivedCommand(Command)
  ReceivedNotice(connection_worker.ConnectionToListener)
  ReceivedQlogBudget(qlog.BudgetRequest)
  ShutdownConnectionFinished(ShutdownCompletion)
  ConnectionExited(process.Down)
  ReceivedNetwork(Dynamic)
  OwnerExited
}

type ShutdownCompletion {
  ShutdownCompletion(joiner: Pid, result: ShutdownConnectionResult)
}

type ShutdownConnectionResult {
  ShutdownDiagnosticsClosed
  ShutdownDiagnosticsFailed
  ShutdownDeadlineExpired
  ShutdownConnectionAlreadyGone
}

type ShutdownJoinerState {
  ShutdownJoinerState(
    monitor: process.Monitor,
    result: Option(ShutdownConnectionResult),
  )
}

type ConnectionWaiter {
  ConnectionWaiter(
    reply: Subject(Result(Connection, Error)),
    deadline: Option(Int),
  )
}

/// One admitted connection, the actor that owns it, and the delivery window
/// the listener still holds open for it. `datagram_credit` and `byte_credit`
/// are what the next message to this connection may carry; `dropped` counts
/// the datagrams already dropped for it that its actor has not been told
/// about yet; `outstanding` counts the messages already sent to it that it has
/// not acknowledged, which is what keeps the mailbox bounded in messages as
/// well as in datagrams and bytes.
///
///
/// This connection's share of the endpoint memory budget is not kept here. The
/// ledger in `endpoint_memory` already holds what every connection was granted
/// and which requests it could not meet, keyed by the same identifier this
/// `Dict` is keyed by, so a second copy here could only ever disagree with it.
type Entry {
  Entry(
    connection: Connection,
    established: Bool,
    datagram_credit: Int,
    byte_credit: Int,
    dropped: Int,
    outstanding: Int,
  )
}

type Worker {
  Worker(
    socket: udp.Socket,
    relay: udp.Relay,
    port: Int,
    commands: Subject(Command),
    notices: Subject(connection_worker.ConnectionToListener),
    qlog_budget_requests: Subject(qlog.BudgetRequest),
    selector: process.Selector(LoopMessage),
    server_config: server_transport.Config,
    ticket_keys: List(BitArray),
    address_token_keys: List(BitArray),
    stateless_reset_keys: List(BitArray),
    replay_cache: anti_replay.Cache,
    replay_guard: Option(replay_guard.Guard),
    allow_zero_rtt: Bool,
    connections: Dict(BitArray, Entry),
    routes: Dict(Pid, BitArray),
    aliases: Dict(BitArray, BitArray),
    endpoint_memory: budget.Budget,
    qlog_tickets: Dict(BitArray, qlog.CleanupTicket),
    handshaking: Int,
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
    qlog_reserve_attempts: Int,
    qlog_reserve_grants: Int,
    qlog_reserve_refusals: Int,
    qlog_releases: Int,
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
  bind_address: Option(BitArray),
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
  endpoint_memory_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  alternative_credentials: List(engine.ServerCredential),
  client_authentication: engine.ClientAuthentication,
  application_protocols: List(BitArray),
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  zero_rtt_application_context: BitArray,
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
        bind_address,
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
        endpoint_memory_limit,
        certificate_chain,
        signing_key,
        signature_scheme,
        alternative_credentials,
        client_authentication,
        application_protocols,
        congestion_control,
        qlog_directory,
        allow_zero_rtt,
        zero_rtt_application_context,
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
      Some(udp.monotonic_millisecond() + listener.timeout_milliseconds),
    )
  })
}

/// Wait without a polling deadline for the next authenticated connection.
/// Listener stop, listener-owner exit, or listener failure still releases the
/// caller. This exists for supervised protocol adapters which continuously
/// consume listener events; ordinary application calls should use `accept`.
pub fn accept_next(listener: Listener) -> Result(Connection, Error) {
  call_forever(listener, fn(reply) { AcceptConnection(reply, None) })
}

/// Live route occupancy, serialized with route registration and release.
pub fn connection_id_stats(listener: Listener) -> Result(#(Int, Int), Error) {
  call(listener, ConnectionIdStats)
}

/// Serialized accounting snapshot: total held bytes, diagnostic reservations,
/// and their prepaid helper slots.
/// Pending startup failures remain included.
/// nolint: unused_exports -- ordinary native UDP tests consume this internal seam.
pub fn qlog_budget_stats(
  listener: Listener,
) -> Result(#(Int, Int, Int), Error) {
  call(listener, QlogBudgetStats)
}

/// Safe, serialized qlog admission evidence.
///
/// The tuple is `#(attempts, grants, refusals, releases, held_events,
/// held_bytes, cleanup_tickets)`. All values are finite counters; no endpoint,
/// path, payload, process identity, socket or exception is exposed.
/// nolint: unused_exports -- native resource-pressure tests consume this seam.
pub fn qlog_admission_stats(
  listener: Listener,
) -> Result(#(Int, Int, Int, Int, Int, Int, Int), Error) {
  call(listener, QlogAdmissionStats)
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
  let current = udp.monotonic_millisecond()
  case
    shutdown_deadline.new(
      current,
      stop_completion_allowance_milliseconds(listener),
      shutdown_join_cleanup_milliseconds,
    )
  {
    Error(_) -> Error(InvalidInput)
    Ok(plan) ->
      stop_until(listener, shutdown_deadline.final_deadline_milliseconds(plan))
  }
}

/// Stop the listener, every connection, and diagnostics under one caller-owned absolute deadline in `quic_core/diagnostics.monotonic_milliseconds`.
pub fn stop_until(
  listener: Listener,
  deadline_milliseconds: Int,
) -> Result(StopResult, Error) {
  use _ <- result.try(validate_stop_deadline(deadline_milliseconds))
  call_stop_until(listener, deadline_milliseconds)
}

/// Additional scalar bound a protocol adapter must reserve after its own drain deadline for listener cleanup and the typed stop reply.
/// No endpoint, process, socket, or diagnostic value crosses this seam.
pub fn stop_completion_allowance_milliseconds(listener: Listener) -> Int {
  listener.timeout_milliseconds + worker_reply_grace_milliseconds
}

fn initialise(
  owner: Pid,
  bootstrap: Subject(Result(Listener, Error)),
  port: Int,
  address_family: AddressFamily,
  bind_address: Option(BitArray),
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
  endpoint_memory_limit: Int,
  certificate_chain: List(BitArray),
  signing_key: authentication.SigningKey,
  signature_scheme: extension_value.SignatureScheme,
  alternative_credentials: List(engine.ServerCredential),
  client_authentication: engine.ClientAuthentication,
  application_protocols: List(BitArray),
  congestion_control: transport.CongestionAlgorithm,
  qlog_directory: String,
  allow_zero_rtt: Bool,
  zero_rtt_application_context: BitArray,
  external_replay_guard: Option(replay_guard.Guard),
  configured_ticket_keys: List(BitArray),
  configured_address_token_keys: List(BitArray),
  configured_stateless_reset_keys: List(BitArray),
) -> Nil {
  let startup = {
    use socket <- result.try(
      open_listener(address_family, bind_address, port)
      |> result.replace_error(StartFailed),
    )
    use local <- result.try(
      udp.local_endpoint(socket) |> result.replace_error(StartFailed),
    )
    let #(_, bound_port) = udp.endpoint_parts(local)
    use #(ticket_key, ticket_keys) <- result.try(
      resolve_key_ring(configured_ticket_keys)
      |> result.replace_error(StartFailed),
    )
    use #(_, address_token_keys) <- result.try(
      resolve_key_ring(configured_address_token_keys)
      |> result.replace_error(StartFailed),
    )
    use #(reset_key, reset_keys) <- result.try(
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
      #(ticket_key, ticket_keys),
      address_token_keys,
      #(reset_key, reset_keys),
      replay_cache,
    ))
  }
  case startup {
    Error(error) -> process.send(bootstrap, Error(error))
    Ok(#(
      socket,
      relay,
      bound_port,
      #(ticket_key, ticket_keys),
      address_token_keys,
      #(reset_key, reset_keys),
      replay_cache,
    )) -> {
      let commands = process.new_subject()
      let notices = process.new_subject()
      let qlog_budget_requests = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedCommand)
        |> process.select_map(notices, ReceivedNotice)
        |> process.select_map(qlog_budget_requests, ReceivedQlogBudget)
        |> process.select_specific_monitor(owner_monitor, fn(_) { OwnerExited })
        |> process.select_monitors(ConnectionExited)
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
          zero_rtt_application_context,
          idle_timeout_milliseconds,
          congestion_control,
          bidirectional_stream_limit,
          unidirectional_stream_limit,
          stream_buffer_limit,
          datagram_limit,
          udp.dont_fragment(socket),
        )
      let listener =
        Listener(commands, process.self(), operation_timeout_milliseconds)
      process.send(bootstrap, Ok(listener))
      loop(Worker(
        socket,
        relay,
        bound_port,
        commands,
        notices,
        qlog_budget_requests,
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
        budget.new(endpoint_memory_limit),
        dict.new(),
        0,
        connection_worker.queue_new(),
        connection_worker.queue_new(),
        operation_timeout_milliseconds,
        stream_buffer_limit,
        queue_limit,
        datagram_limit,
        connection_limit,
        handshake_limit,
        accept_waiter_limit,
        telemetry_limit,
        qlog_directory,
        0,
        0,
        0,
        0,
      ))
    }
  }
}

fn loop(worker: Worker) -> Nil {
  let now = udp.monotonic_millisecond()
  wait_for_work(expire_waiters(worker, now), now)
}

fn wait_for_work(worker: Worker, now: Int) -> Nil {
  let received = case connection_waiter_deadline(worker.connection_waiters) {
    None -> Ok(process.selector_receive_forever(worker.selector))
    Some(value) ->
      process.selector_receive(worker.selector, within: int.max(0, value - now))
  }
  case received {
    Ok(OwnerExited) -> shutdown(worker, ListenerClosed)
    Ok(ReceivedCommand(command)) ->
      case handle_command(worker, command) {
        Error(Nil) -> Nil
        Ok(next) -> loop(next)
      }
    Ok(ReceivedNotice(notice)) -> loop(handle_notice(worker, notice))
    Ok(ReceivedQlogBudget(request)) ->
      loop(handle_qlog_budget_request(worker, request))
    Ok(ShutdownConnectionFinished(_)) -> loop(worker)
    Ok(ConnectionExited(down)) -> loop(release_connection(worker, down))
    Ok(ReceivedNetwork(message)) -> network_step(worker, message)
    Error(Nil) -> loop(worker)
  }
}

fn network_step(worker: Worker, message: Dynamic) -> Nil {
  case udp.receive_relay_batch(worker.relay, message) {
    Ok(datagrams) ->
      case udp.continue_relay(worker.relay) {
        Ok(Nil) -> loop(route_batch(worker, datagrams))
        Error(_) -> shutdown(worker, ListenerClosed)
      }
    Error(udp.InvalidInput) -> loop(worker)
    Error(_) -> shutdown(worker, ListenerClosed)
  }
}

fn route_batch(worker: Worker, datagrams: List(udp.Datagram)) -> Worker {
  let #(worker, routed) = route_datagrams(worker, datagrams, dict.new())
  deliver_routed(worker, dict.to_list(routed))
}

/// Send one message per connection per batch, carrying only what that
/// connection's remaining credit admits. Everything beyond the window is
/// dropped and counted for that connection alone, which is what keeps one
/// flooded connection from growing its actor's mailbox -- or delaying any
/// other connection -- without bound. QUIC is loss tolerant, so a dropped
/// datagram is recovered exactly like one the network lost.
fn deliver_routed(
  worker: Worker,
  routed: List(#(BitArray, List(connection_worker.ListenerToConnection))),
) -> Worker {
  case routed {
    [] -> worker
    [#(identifier, deliveries), ..rest] ->
      deliver_routed(
        deliver_credited(worker, identifier, list.reverse(deliveries)),
        rest,
      )
  }
}

fn deliver_credited(
  worker: Worker,
  identifier: BitArray,
  deliveries: List(connection_worker.ListenerToConnection),
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(entry) -> {
      let admission =
        take_within_credit(
          deliveries,
          entry.datagram_credit,
          entry.byte_credit,
          Admission([], 0, 0, 0),
        )
      let pending = entry.dropped + admission.dropped
      case admission.deliveries {
        // The window is shut, so this connection is sent nothing at all and
        // its drops wait for the message that reopens it.
        [] -> put_entry(worker, identifier, Entry(..entry, dropped: pending))
        admitted -> {
          connection_worker.deliver(entry.connection, admitted, pending)
          put_entry(
            worker,
            identifier,
            Entry(
              ..entry,
              datagram_credit: entry.datagram_credit - admission.datagrams,
              byte_credit: entry.byte_credit - admission.bytes,
              dropped: 0,
              outstanding: entry.outstanding + 1,
            ),
          )
        }
      }
    }
  }
}

/// One connection's share of a batch, split against its window: the datagrams
/// the window admits, what carrying them costs the window, and how many
/// datagrams were dropped because they did not fit.
type Admission {
  Admission(
    deliveries: List(connection_worker.ListenerToConnection),
    datagrams: Int,
    bytes: Int,
    dropped: Int,
  )
}

/// Split one connection's share of a batch against its remaining window. Both
/// halves of the window bind: a datagram is admitted only while it fits under
/// the datagram count and the byte total alike.
fn take_within_credit(
  deliveries: List(connection_worker.ListenerToConnection),
  remaining_datagrams: Int,
  remaining_bytes: Int,
  admission: Admission,
) -> Admission {
  case deliveries {
    [] -> Admission(..admission, deliveries: list.reverse(admission.deliveries))
    [connection_worker.RoutedDatagram(_, datagram, _) as delivery, ..rest] -> {
      let size = bit_array.byte_size(datagram)
      let next = case
        admission.datagrams + 1 <= remaining_datagrams
        && admission.bytes + size <= remaining_bytes
      {
        True ->
          Admission(
            ..admission,
            deliveries: [delivery, ..admission.deliveries],
            datagrams: admission.datagrams + 1,
            bytes: admission.bytes + size,
          )
        False -> Admission(..admission, dropped: admission.dropped + 1)
      }
      take_within_credit(rest, remaining_datagrams, remaining_bytes, next)
    }
  }
}

/// Refill one connection's window by exactly what its actor reported taking
/// off its mailbox, never above the fixed window, and release the one message
/// that acknowledgement accounts for.
///
/// A credited message already carries the drops taken for this connection, so
/// the only drops left to report are those taken while the window was shut. A
/// single empty message reports them once the actor has acknowledged
/// everything else the listener sent it: it costs the window nothing, it keeps
/// the counter converging even if no further datagram ever names this
/// connection, and sending it only when nothing else is outstanding is what
/// keeps the mailbox bounded in messages -- at most one message per datagram
/// of the window, plus that one report.
fn refill_credit(
  worker: Worker,
  identifier: BitArray,
  datagrams: Int,
  bytes: Int,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(entry) -> {
      let refilled =
        Entry(
          ..entry,
          datagram_credit: int.min(
            datagram_credit,
            entry.datagram_credit + int.max(0, datagrams),
          ),
          byte_credit: int.min(
            byte_credit,
            entry.byte_credit + int.max(0, bytes),
          ),
          outstanding: int.max(0, entry.outstanding - 1),
        )
      case
        refilled.dropped > 0
        && refilled.datagram_credit > 0
        && refilled.outstanding == 0
      {
        False -> put_entry(worker, identifier, refilled)
        True -> {
          connection_worker.deliver(refilled.connection, [], refilled.dropped)
          put_entry(
            worker,
            identifier,
            Entry(..refilled, dropped: 0, outstanding: 1),
          )
        }
      }
    }
  }
}

/// Return one connection's whole reservation after admission failed part way,
/// and offer the room straight to any connection waiting on it.
fn release_reservation(worker: Worker, identifier: BitArray) -> Worker {
  let endpoint_memory = budget.release_all(worker.endpoint_memory, identifier)
  let endpoint_memory = case dict.has_key(worker.qlog_tickets, identifier) {
    True -> endpoint_memory
    False ->
      budget.release_all(
        endpoint_memory,
        qlog_budget.reservation_key(identifier),
      )
  }
  Worker(..worker, endpoint_memory: endpoint_memory)
  |> retry_withheld_requests
}

/// Diagnostic owners have a separate key that transport growth cannot spend.
/// Failed startup tickets also occupy an admission slot: a listener cannot replace the same unconfirmed filesystem work repeatedly with fresh actors.
fn reserve_connection_memory(
  worker: Worker,
  identifier: BitArray,
) -> Result(budget.Budget, Nil) {
  use memory <- result.try(
    budget.reserve(
      worker.endpoint_memory,
      identifier,
      budget.admission_quanta() * budget.quantum(),
    )
    |> result.replace_error(Nil),
  )
  case worker.qlog_directory {
    "" -> Ok(memory)
    _ -> {
      case
        dict.size(worker.qlog_tickets) >= worker.connection_limit
        || dict.has_key(worker.qlog_tickets, identifier)
      {
        True -> Error(Nil)
        False ->
          budget.reserve(
            memory,
            qlog_budget.reservation_key(identifier),
            qlog_budget.connection_reservation_bytes(),
          )
          |> result.replace_error(Nil)
      }
    }
  }
}

/// A diagnostic DOWN only prompts inspection.
/// The receipt must also confirm all children were joined; a dead admission process alone releases nothing.
fn collect_qlog_reservations(worker: Worker) -> Worker {
  let next = reconcile_qlog_reservations(worker)
  case budget.used(next.endpoint_memory) < budget.used(worker.endpoint_memory) {
    True -> retry_withheld_requests(next)
    False -> next
  }
}

fn reconcile_qlog_reservations(worker: Worker) -> Worker {
  list.fold(dict.to_list(worker.qlog_tickets), worker, fn(current, pair) {
    let #(identifier, ticket) = pair
    case qlog.cleanup_state(ticket) {
      qlog.Pending -> current
      qlog.Released -> {
        let reservation = qlog_budget.reservation_key(identifier)
        let dynamic_bytes =
          int.max(
            0,
            budget.holding_bytes(current.endpoint_memory, reservation)
              - qlog_budget.connection_reservation_bytes(),
          )
        let released_events =
          dynamic_bytes / qlog_budget.event_reservation_bytes()
        Worker(
          ..current,
          endpoint_memory: budget.release_all(
            current.endpoint_memory,
            reservation,
          ),
          qlog_tickets: dict.delete(current.qlog_tickets, identifier),
          qlog_releases: counter_add(current.qlog_releases, released_events),
        )
      }
    }
  })
}

/// Reconcile cleanup receipts against one absolute monotonic deadline.
/// A normal writer close acknowledges admission exit before its independent guardian has necessarily published the final child-join receipt, so one immediate snapshot would turn scheduler order into a false stop failure.
fn collect_qlog_reservations_until(
  worker: Worker,
  deadline_milliseconds: Int,
) -> Worker {
  // Shutdown reconciliation must not resume ordinary transport requests.
  let next = reconcile_qlog_reservations(worker)
  case
    dict.size(next.qlog_tickets) == 0
    || udp.monotonic_millisecond() >= deadline_milliseconds
  {
    True -> next
    False -> {
      let owners = live_qlog_cleanup_owners(dict.values(next.qlog_tickets))
      case owners {
        [_, ..] -> {
          await_qlog_cleanup_owner_change(owners, deadline_milliseconds)
          collect_qlog_reservations_until(next, deadline_milliseconds)
        }
        // The final owner publishes its atomic receipt before exiting.
        // Read it once more after observing every owner down; if it is still pending,
        // no later scheduler turn can turn that unconfirmed work into success.
        [] -> reconcile_qlog_reservations(next)
      }
    }
  }
}

/// Build one unique, payload-free owner set for every pending cleanup receipt.
/// Monitoring the full set turns publication progress into an actor event and avoids scheduler-dependent polling sleeps during listener shutdown.
fn live_qlog_cleanup_owners(tickets: List(qlog.CleanupTicket)) -> List(Pid) {
  tickets
  |> list.fold(dict.new(), fn(owners, ticket) {
    case qlog.cleanup_state(ticket) {
      qlog.Released -> owners
      qlog.Pending ->
        qlog.cleanup_owners(ticket)
        |> list.fold(owners, fn(owners, owner) {
          case process.is_alive(owner) {
            True -> dict.insert(owners, owner, Nil)
            False -> owners
          }
        })
    }
  })
  |> dict.keys
}

fn await_qlog_cleanup_owner_change(
  owners: List(Pid),
  deadline_milliseconds: Int,
) -> Nil {
  let #(selector, monitors) =
    list.fold(owners, #(process.new_selector(), []), fn(state, owner) {
      let #(selector, monitors) = state
      let monitor = process.monitor(owner)
      #(process.select_specific_monitor(selector, monitor, fn(_) { owner }), [
        monitor,
        ..monitors
      ])
    })
  let _owner =
    process.selector_receive(
      selector,
      within: int.max(0, deadline_milliseconds - udp.monotonic_millisecond()),
    )
  list.each(monitors, fn(monitor) { process.demonitor_process(monitor) })
}

fn handle_qlog_budget_request(
  worker: Worker,
  request: qlog.BudgetRequest,
) -> Worker {
  case request {
    qlog.ReserveEvent(reservation, bytes, reply) -> {
      let worker =
        Worker(
          ..worker,
          qlog_reserve_attempts: counter_add(worker.qlog_reserve_attempts, 1),
        )
      case
        bytes == qlog_budget.event_reservation_bytes()
        && known_qlog_reservation(worker, reservation)
      {
        False -> {
          process.send(reply, False)
          Worker(
            ..worker,
            qlog_reserve_refusals: counter_add(worker.qlog_reserve_refusals, 1),
          )
        }
        True ->
          case budget.reserve(worker.endpoint_memory, reservation, bytes) {
            Error(_) -> {
              process.send(reply, False)
              Worker(
                ..worker,
                qlog_reserve_refusals: counter_add(
                  worker.qlog_reserve_refusals,
                  1,
                ),
              )
            }
            Ok(endpoint_memory) -> {
              process.send(reply, True)
              Worker(
                ..worker,
                endpoint_memory: endpoint_memory,
                qlog_reserve_grants: counter_add(worker.qlog_reserve_grants, 1),
              )
            }
          }
      }
    }
    qlog.ReleaseEvents(reservation, bytes, events) ->
      case
        events > 0
        && bytes == events * qlog_budget.event_reservation_bytes()
        && known_qlog_reservation(worker, reservation)
      {
        False -> worker
        True ->
          case budget.release(worker.endpoint_memory, reservation, bytes) {
            Error(_) -> worker
            Ok(endpoint_memory) ->
              Worker(
                ..worker,
                endpoint_memory: endpoint_memory,
                qlog_releases: counter_add(worker.qlog_releases, events),
              )
              |> retry_withheld_requests
          }
      }
  }
}

fn known_qlog_reservation(worker: Worker, reservation: BitArray) -> Bool {
  case qlog_budget.reservation_identifier(reservation) {
    Error(Nil) -> False
    Ok(identifier) -> dict.has_key(worker.qlog_tickets, identifier)
  }
}

fn counter_add(value: Int, increment: Int) -> Int {
  int.min(2_147_483_647, value + int.max(0, increment))
}

fn put_entry(worker: Worker, identifier: BitArray, entry: Entry) -> Worker {
  Worker(
    ..worker,
    connections: dict.insert(worker.connections, identifier, entry),
  )
}

type Routed =
  Dict(BitArray, List(connection_worker.ListenerToConnection))

fn route_datagrams(
  worker: Worker,
  datagrams: List(udp.Datagram),
  routed: Routed,
) -> #(Worker, Routed) {
  case datagrams {
    [] -> #(worker, routed)
    [udp.Datagram(peer, bytes, marking), ..rest] -> {
      let #(worker, routed) =
        route_datagram(worker, peer, bytes, marking, routed)
      route_datagrams(worker, rest, routed)
    }
  }
}

fn route_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  routed: Routed,
) -> #(Worker, Routed) {
  case datagram {
    <<first, _rest:bits>> if first >= 0x80 ->
      route_long_datagram(worker, peer, datagram, marking, routed)
    <<_first, destination:bytes-size(connection_id_bytes), _rest:bits>> ->
      case resolve_alias(worker, destination) {
        Some(identifier) -> #(
          worker,
          route_existing(worker, identifier, peer, datagram, marking, routed),
        )
        None -> #(worker, routed)
      }
    _ -> #(worker, routed)
  }
}

fn route_long_datagram(
  worker: Worker,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  routed: Routed,
) -> #(Worker, Routed) {
  case packet.parse_long(datagram) {
    Error(_) -> #(worker, routed)
    Ok(#(parsed, _)) -> {
      let packet.LongHeader(_, protocol_version, destination, source) =
        packet_header(parsed)
      case resolve_alias(worker, destination) {
        Some(identifier) -> #(
          worker,
          route_existing(worker, identifier, peer, datagram, marking, routed),
        )
        None ->
          case parsed, protocol_version {
            packet.Initial(_, token, _), version.Version1
            | packet.Initial(_, token, _), version.Version2
            -> #(
              route_initial(
                worker,
                peer,
                protocol_version,
                destination,
                source,
                token,
                datagram,
                marking,
              ),
              routed,
            )
            packet.UnknownVersion(_, _), _ -> #(
              send_version_negotiation(worker, peer, destination, source),
              routed,
            )
            _, _ -> #(worker, routed)
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
  let #(address, port) = udp.endpoint_parts(peer)
  let now = udp.monotonic_millisecond()
  let #(_, route) =
    classify_initial_token(
      worker.address_token_keys,
      token,
      protocol_version,
      address,
      port,
      destination,
      now,
    )
  case route {
    RequireRetry ->
      send_retry(
        worker,
        peer,
        protocol_version,
        destination,
        peer_connection_id,
      )
    RefuseInvalidRetry ->
      send_invalid_retry_token(
        worker,
        peer,
        protocol_version,
        destination,
        peer_connection_id,
      )
    AcceptRetry(original_destination, retry_source) ->
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
    AcceptNewToken ->
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
  }
}

/// Classify one Initial token without retaining key, token, address, or CID data in the result.
/// `now` is injected so every edge is deterministic in direct tests and production still uses the listener's monotonic clock.
pub fn initial_token_decision(
  keys: List(BitArray),
  token: BitArray,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  destination: BitArray,
  now: Int,
) -> InitialTokenDecision {
  let #(decision, _) =
    classify_initial_token(
      keys,
      token,
      protocol_version,
      address,
      port,
      destination,
      now,
    )
  decision
}

fn classify_initial_token(
  keys: List(BitArray),
  token: BitArray,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  destination: BitArray,
  now: Int,
) -> #(InitialTokenDecision, InitialTokenRoute) {
  case token {
    <<>> -> #(MissingTokenRetried, RequireRetry)
    _ ->
      case
        inspect_address_token(
          keys,
          token,
          protocol_version,
          address,
          port,
          now,
          new_token_lifetime_milliseconds,
        )
      {
        address_token.Accepted(address_token.Token(
          address_token.Retry,
          original_destination,
          retry_source,
          issued_at,
        ))
          if retry_source == destination
          && now - issued_at <= retry_token_lifetime_milliseconds
        -> #(
          RetryTokenAccepted,
          AcceptRetry(original_destination, retry_source),
        )
        address_token.Accepted(address_token.Token(address_token.Retry, _, _, _))
        | address_token.ReadableButInvalid(address_token.Retry, _) -> #(
          InvalidRetryTokenRefused,
          RefuseInvalidRetry,
        )
        address_token.Accepted(address_token.Token(
          address_token.NewToken,
          _,
          _,
          _,
        )) -> #(NewTokenAccepted, AcceptNewToken)
        address_token.ReadableButInvalid(address_token.NewToken, _) -> #(
          InvalidNewTokenRetried,
          RequireRetry,
        )
        address_token.Unreadable(_) -> #(UnreadableTokenRetried, RequireRetry)
      }
  }
}

fn route_existing(
  worker: Worker,
  identifier: BitArray,
  peer: udp.Endpoint,
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
  routed: Routed,
) -> Routed {
  case dict.has_key(worker.connections, identifier) {
    False -> routed
    True -> {
      let queued = case dict.get(routed, identifier) {
        Ok(existing) -> existing
        Error(_) -> []
      }
      dict.insert(routed, identifier, [
        connection_worker.RoutedDatagram(peer, datagram, marking),
        ..queued
      ])
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
  let worker = collect_qlog_reservations(worker)
  case
    dict.size(worker.connections) >= worker.connection_limit,
    worker.handshaking >= worker.handshake_limit,
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
        Ok(local_connection_id) ->
          // Decision D1. One handshake working set is charged to the endpoint
          // memory budget before any per-connection state is built, so a
          // connection the endpoint has no room for is refused here rather
          // than admitted into memory that has already been spent. A refusal
          // charges nothing, and every step that fails after this point
          // returns the working set with `worker` unchanged.
          case reserve_connection_memory(worker, local_connection_id) {
            Error(_) ->
              send_connection_refused(
                worker,
                peer,
                protocol_version,
                initial_destination(
                  original_destination,
                  selected_local_connection_id,
                ),
                peer_connection_id,
              )
            Ok(endpoint_memory) ->
              admit_connection(
                worker,
                Worker(..worker, endpoint_memory: endpoint_memory),
                peer,
                protocol_version,
                original_destination,
                local_connection_id,
                peer_connection_id,
                retry_source_connection_id,
                datagram,
                marking,
              )
          }
      }
  }
}

/// Build one admitted connection's transport state and spawn its actor.
///
/// Two listeners are passed deliberately: `unreserved` is the listener as it
/// was before D1 charged the handshake working set, and `reserved` is the same
/// listener holding that charge. Only the path that reaches `spawn_connection`
/// keeps the charge; every failure below returns `unreserved`, so a connection
/// that is never admitted leaves the budget exactly as it found it.
fn admit_connection(
  unreserved: Worker,
  reserved: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  original_destination: BitArray,
  local_connection_id: BitArray,
  peer_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram: BitArray,
  marking: packet_space.ReceivedCodepoint,
) -> Worker {
  let now = udp.monotonic_millisecond()
  case replay_policy(unreserved, now) {
    Error(_) -> unreserved
    Ok(policy) ->
      case
        server_transport.accept_initial(
          unreserved.server_config,
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
        Error(_) -> unreserved
        Ok(connection) ->
          spawn_connection(
            reserved,
            connection,
            protocol_version,
            original_destination,
            local_connection_id,
            retry_source_connection_id,
            bit_array.byte_size(datagram),
            now,
          )
      }
  }
}

/// The Destination Connection ID the peer's Initial packet carried, which is
/// what its Initial keys are derived from: the Retry source connection ID once
/// a Retry has been answered, and the peer's own first choice otherwise.
fn initial_destination(
  original_destination: BitArray,
  selected_local_connection_id: Option(BitArray),
) -> BitArray {
  case selected_local_connection_id {
    Some(value) -> value
    None -> original_destination
  }
}

/// Refuse one connection the endpoint has no memory for, in the packet space
/// the peer can already read.
///
/// RFC 9000 section 5.2.2 lets a server refuse a new connection with a
/// CONNECTION_CLOSE carrying CONNECTION_REFUSED (0x02), and refusing it in the
/// Initial space is what makes the refusal cheap: no handshake is run, no
/// connection state is kept, and the peer learns immediately rather than
/// waiting out its own connect deadline. The packet is built here rather than
/// through a transport state because no transport state is created for a
/// connection that is never admitted.
fn send_connection_refused(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  initial_destination_connection_id: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  send_initial_transport_close(
    worker,
    peer,
    protocol_version,
    initial_destination_connection_id,
    peer_connection_id,
    connection_refused_code,
  )
}

/// Refuse an authenticated, identifiable Retry token that cannot validate the sender.
/// The empty reason phrase keeps the Initial close payload-free.
fn send_invalid_retry_token(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  initial_destination_connection_id: BitArray,
  peer_connection_id: BitArray,
) -> Worker {
  send_initial_transport_close(
    worker,
    peer,
    protocol_version,
    initial_destination_connection_id,
    peer_connection_id,
    invalid_token_code,
  )
}

fn send_initial_transport_close(
  worker: Worker,
  peer: udp.Endpoint,
  protocol_version: Version,
  initial_destination_connection_id: BitArray,
  peer_connection_id: BitArray,
  error_code: Int,
) -> Worker {
  case
    initial_crypto.derive_initial(
      protocol_version,
      initial_destination_connection_id,
    ),
    frame.encode(frame.ConnectionCloseTransport(error_code, 0, ""))
  {
    Ok(keys), Ok(close_frame) ->
      case
        wire_packet.protect_long(
          wire_packet.Initial(<<>>),
          protocol_version,
          peer_connection_id,
          initial_destination_connection_id,
          0,
          None,
          padded_plaintext(close_frame),
          wire_packet.InitialPacketKeys(keys.server),
        )
      {
        Error(_) -> worker
        Ok(bytes) -> {
          let _sent = udp.send(worker.socket, peer, bytes, ecn.NotEct)
          worker
        }
      }
    _, _ -> worker
  }
}

/// Pad one Initial payload with PADDING frames until header protection has a
/// long enough sample to draw from.
fn padded_plaintext(plaintext: BitArray) -> BitArray {
  case bit_array.byte_size(plaintext) >= minimum_initial_plaintext_bytes {
    True -> plaintext
    False -> padded_plaintext(<<plaintext:bits, 0>>)
  }
}

fn spawn_connection(
  worker: Worker,
  connection: server_transport.State,
  protocol_version: Version,
  original_destination: BitArray,
  local_connection_id: BitArray,
  retry_source_connection_id: Option(BitArray),
  datagram_bytes: Int,
  now: Int,
) -> Worker {
  let #(worker, opened) = open_qlog(worker, local_connection_id, now)
  case opened {
    Error(_) -> release_reservation(worker, local_connection_id)
    Ok(writer) -> {
      let worker = update_replay_cache(worker, connection)
      case current_key(worker.address_token_keys) {
        Error(_) -> {
          close_qlog(writer)
          release_reservation(worker, local_connection_id)
        }
        Ok(address_token_key) ->
          case
            connection_worker.start(connection_worker.Bootstrap(
              process.self(),
              worker.notices,
              worker.socket,
              local_connection_id,
              connection,
              protocol_version,
              worker.server_config.congestion_control,
              writer,
              worker.server_config.application_protocols,
              worker.ticket_keys,
              address_token_key,
              worker.replay_cache,
              worker.replay_guard,
              worker.allow_zero_rtt,
              worker.operation_timeout_milliseconds,
              worker.stream_buffer_limit,
              worker.queue_limit,
              worker.datagram_limit,
              now,
              datagram_bytes,
            ))
          {
            Error(_) -> {
              close_qlog(writer)
              release_reservation(worker, local_connection_id)
            }
            Ok(handle) -> {
              let pid = connection_worker.worker_pid(handle)
              let _monitor = process.monitor(pid)
              Worker(
                ..worker,
                connections: dict.insert(
                  worker.connections,
                  local_connection_id,
                  Entry(handle, False, datagram_credit, byte_credit, 0, 0),
                ),
                routes: dict.insert(worker.routes, pid, local_connection_id),
                handshaking: worker.handshaking + 1,
                aliases: case retry_source_connection_id {
                  Some(_) ->
                    dict.insert(
                      worker.aliases,
                      local_connection_id,
                      local_connection_id,
                    )
                  None ->
                    dict.insert(
                      dict.insert(
                        worker.aliases,
                        local_connection_id,
                        local_connection_id,
                      ),
                      original_destination,
                      local_connection_id,
                    )
                },
              )
            }
          }
      }
    }
  }
}

fn handle_notice(
  worker: Worker,
  notice: connection_worker.ConnectionToListener,
) -> Worker {
  case notice {
    connection_worker.Established(identifier) ->
      handle_established(worker, identifier)
    connection_worker.AllocateConnectionIds(identifier, pid, count) ->
      case dict.get(worker.routes, pid) == Ok(identifier) {
        False -> worker
        True ->
          allocate_connection_ids(
            worker,
            identifier,
            int.min(3, int.max(0, count)),
            [],
          )
      }
    connection_worker.RetiredConnectionId(identifier, pid, retired, replace) ->
      case
        dict.get(worker.routes, pid) == Ok(identifier)
        && dict.get(worker.aliases, retired) == Ok(identifier)
      {
        False -> worker
        True -> {
          let worker =
            Worker(..worker, aliases: dict.delete(worker.aliases, retired))
          case replace {
            False -> worker
            True -> allocate_connection_ids(worker, identifier, 1, [])
          }
        }
      }
    connection_worker.Consumed(identifier, datagrams, bytes) ->
      refill_credit(worker, identifier, datagrams, bytes)
    connection_worker.Request(identifier, sequence, quanta) ->
      handle_request(worker, identifier, sequence, quanta)
    connection_worker.Released(identifier, pid, acknowledged) -> {
      let worker = release_reported_connection(worker, identifier, pid)
      process.send(acknowledged, Nil)
      worker
    }
  }
}

/// Decision D2, listener side. One connection actor asks for the room it is
/// about to need, and the listener answers before that room is used.
///
/// A request names the whole quanta the connection wants to hold in total, not
/// the growth it wants on top, and the answer echoes the request's sequence
/// number, so an answer that races a later request is recognised as stale by
/// the actor rather than installed over a newer one.
///
/// The arithmetic is the ledger's own: it already knows what this connection
/// was granted, it fills growth as far as the budget reaches rather than
/// refusing it whole, and it keeps a request it could not meet so that room
/// released later can be offered to it. All this function adds is the message
/// back, and the retry that a request for less than the connection holds --
/// memory coming back -- makes possible.
fn handle_request(
  worker: Worker,
  identifier: BitArray,
  sequence: Int,
  quanta: Int,
) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(entry) -> {
      let held = budget.used(worker.endpoint_memory)
      let #(endpoint_memory, answer) =
        budget.answer_request(
          worker.endpoint_memory,
          identifier,
          sequence,
          quanta,
        )
      case answer {
        budget.Met(granted) ->
          connection_worker.grant(entry.connection, sequence, granted)
        budget.Short(granted) ->
          connection_worker.refuse(entry.connection, sequence, granted)
      }
      let worker = Worker(..worker, endpoint_memory: endpoint_memory)
      case budget.used(endpoint_memory) < held {
        False -> worker
        True -> retry_withheld_requests(worker)
      }
    }
  }
}

/// Decision D3, listener side. Offer released memory to the connections whose
/// requests could not be met, oldest first.
///
/// Every path that returns memory runs this. A refused connection does not ask
/// again -- it would only be refused again, and a busy endpoint would spend
/// itself answering the same refusals -- so the listener owes it the retry,
/// and a refusal lifted only by traffic is a refusal that never lifts on a
/// steady connection. The ordering, the head-of-line fairness, and the
/// bookkeeping are the ledger's; what happens here is the message back.
fn retry_withheld_requests(worker: Worker) -> Worker {
  let #(endpoint_memory, retries) =
    budget.retry_withheld(worker.endpoint_memory)
  list.each(retries, fn(retry) {
    case dict.get(worker.connections, retry.connection) {
      Error(Nil) -> Nil
      Ok(entry) ->
        connection_worker.grant(entry.connection, retry.sequence, retry.quanta)
    }
  })
  Worker(..worker, endpoint_memory: endpoint_memory)
}

/// Free a connection the actor itself reported as ended, before its monitor
/// `Down` arrives. The identifier has to still be the one this process routes,
/// so a notice that outlived its route -- or names a connection already
/// replaced -- releases nothing.
fn release_reported_connection(
  worker: Worker,
  identifier: BitArray,
  pid: Pid,
) -> Worker {
  case dict.get(worker.routes, pid) == Ok(identifier) {
    False -> worker
    True -> release_connection_pid(worker, pid)
  }
}

/// Take one connection whose handshake completed off the handshake budget and
/// hand it to an accept waiter or the accept queue. A connection already
/// established, or already released, is left alone.
fn handle_established(worker: Worker, identifier: BitArray) -> Worker {
  case dict.get(worker.connections, identifier) {
    Error(_) -> worker
    Ok(Entry(established: True, ..)) -> worker
    Ok(entry) ->
      enqueue_connection(
        Worker(
          ..worker,
          connections: dict.insert(
            worker.connections,
            identifier,
            Entry(..entry, established: True),
          ),
          handshaking: int.max(0, worker.handshaking - 1),
          // Retire the temporary client-chosen Initial alias at establishment.
          aliases: dict.insert(
            remove_aliases(worker.aliases, identifier),
            identifier,
            identifier,
          ),
        ),
        identifier,
        entry.connection,
      )
  }
}

fn enqueue_connection(
  worker: Worker,
  identifier: BitArray,
  connection: Connection,
) -> Worker {
  case connection_worker.queue_pop(worker.connection_waiters) {
    Ok(#(ConnectionWaiter(reply, _), rest)) -> {
      process.send(reply, Ok(connection))
      Worker(..worker, connection_waiters: rest)
    }
    Error(Nil) ->
      case
        connection_worker.queue_count(worker.pending_connections)
        >= worker.queue_limit
      {
        True -> {
          connection_worker.terminate(connection)
          worker
        }
        False ->
          Worker(
            ..worker,
            pending_connections: connection_worker.queue_push(
              worker.pending_connections,
              identifier,
            ),
          )
      }
  }
}

/// Free a connection whose actor the monitor reports as gone. An actor that
/// reported `Released` first has no route left, so this finds nothing to do.
fn release_connection(worker: Worker, down: process.Down) -> Worker {
  let worker = case down {
    process.ProcessDown(_, pid, _) -> release_connection_pid(worker, pid)
    process.PortDown(_, _, _) -> worker
  }
  collect_qlog_reservations(worker)
}

/// Drop everything the listener held for one connection actor: its route, its
/// connection ID, every alias pointing at that ID, its place in the accept
/// queue, and the admission slot it occupied. Releasing a process that owns no
/// route is a no-op, which is what makes the two release paths idempotent.
fn release_connection_pid(worker: Worker, pid: Pid) -> Worker {
  case dict.get(worker.routes, pid) {
    Error(_) -> worker
    Ok(identifier) -> {
      let handshaking = case dict.get(worker.connections, identifier) {
        Ok(Entry(established: False, ..)) -> int.max(0, worker.handshaking - 1)
        _ -> worker.handshaking
      }
      Worker(
        ..worker,
        connections: dict.delete(worker.connections, identifier),
        routes: dict.delete(worker.routes, pid),
        aliases: remove_aliases(worker.aliases, identifier),
        // Decision D6: the whole reservation comes back here, on whichever of
        // the two release paths arrives first, and `release_all` makes the
        // second one free.
        endpoint_memory: budget.release_all(worker.endpoint_memory, identifier),
        handshaking: handshaking,
        pending_connections: connection_worker.queue_filter(
          worker.pending_connections,
          fn(value) { value != identifier },
        ),
      )
      // The memory this connection held is now free, so the connections whose
      // requests it was crowding out are offered it before anything else runs.
      |> retry_withheld_requests
    }
  }
}

fn handle_command(worker: Worker, command: Command) -> Result(Worker, Nil) {
  case command {
    QlogBudgetStats(reply) -> {
      let worker = collect_qlog_reservations(worker)
      let tickets = dict.size(worker.qlog_tickets)
      process.send(
        reply,
        Ok(#(
          budget.used(worker.endpoint_memory),
          tickets,
          tickets * qlog_budget.worker_slots(),
        )),
      )
      Ok(worker)
    }
    QlogAdmissionStats(reply) -> {
      let worker = collect_qlog_reservations(worker)
      process.send(
        reply,
        Ok(#(
          worker.qlog_reserve_attempts,
          worker.qlog_reserve_grants,
          worker.qlog_reserve_refusals,
          worker.qlog_releases,
          qlog_held_events(worker),
          qlog_held_bytes(worker),
          dict.size(worker.qlog_tickets),
        )),
      )
      Ok(worker)
    }
    ConnectionIdStats(reply) -> {
      process.send(
        reply,
        Ok(#(dict.size(worker.connections), dict.size(worker.aliases))),
      )
      Ok(worker)
    }
    Port(reply) -> {
      process.send(reply, Ok(worker.port))
      Ok(worker)
    }
    AcceptConnection(reply, deadline) ->
      handle_accept_connection(worker, reply, deadline)
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
      handle_reload_keys(
        worker,
        ticket_keys,
        address_token_keys,
        reset_keys,
        reply,
      )
    Stop(deadline_milliseconds, reply) ->
      handle_stop(worker, deadline_milliseconds, reply)
  }
}

fn handle_stop(
  worker: Worker,
  deadline_milliseconds: Int,
  reply: Subject(Result(StopResult, Error)),
) -> Result(Worker, Nil) {
  case
    shutdown_deadline.from_deadline(
      udp.monotonic_millisecond(),
      deadline_milliseconds,
      shutdown_join_cleanup_milliseconds,
    )
  {
    Error(shutdown_deadline.DeadlineExpired) -> {
      process.send(reply, Error(OperationTimeout))
      Ok(worker)
    }
    Error(shutdown_deadline.InvalidConfiguration)
    | Error(shutdown_deadline.DeadlineOutOfRange) -> {
      process.send(reply, Error(InvalidInput))
      Ok(worker)
    }
    Ok(shutdown_plan) -> {
      let #(shutdown_worker, diagnostics_closed, deadline_complete) =
        shutdown_result(worker, ListenerClosed, shutdown_plan)
      // All connection termination waits above have joined their qlog writers.
      // Reconcile every released ticket before deciding whether stop succeeded.
      // This also accounts for dynamic-release notices which were queued while this listener was synchronously joining its children.
      let finalized =
        collect_qlog_reservations_until(
          shutdown_worker,
          shutdown_deadline.final_deadline_milliseconds(shutdown_plan),
        )
      let diagnostics_released =
        diagnostics_closed
        && dict.size(finalized.qlog_tickets) == 0
        && list.all(dict.keys(shutdown_worker.qlog_tickets), fn(identifier) {
          budget.holding_bytes(
            finalized.endpoint_memory,
            qlog_budget.reservation_key(identifier),
          )
          == 0
        })
      let lifetime_released =
        deadline_complete
        && dict.size(finalized.connections) == 0
        && budget.used(finalized.endpoint_memory) == 0
      let confirmed = diagnostics_released && lifetime_released
      process.send(reply, case confirmed, diagnostics_released {
        True, _ -> Ok(Stopped)
        False, False -> Error(QlogUnavailable)
        False, True -> Error(OperationTimeout)
      })
      Error(Nil)
    }
  }
}

fn handle_reload_keys(
  worker: Worker,
  ticket_keys: List(BitArray),
  address_token_keys: List(BitArray),
  reset_keys: List(BitArray),
  reply: Subject(Result(Nil, Error)),
) -> Result(Worker, Nil) {
  case
    valid_key_ring(ticket_keys)
    && valid_key_ring(address_token_keys)
    && valid_key_ring(reset_keys)
  {
    False -> reply_error(worker, reply, InvalidInput)
    True ->
      case ticket_keys, address_token_keys, reset_keys {
        [ticket_key, ..], [address_token_key, ..], [reset_key, ..] -> {
          list.each(dict.values(worker.connections), fn(entry) {
            connection_worker.reload_keys(
              entry.connection,
              ticket_keys,
              address_token_key,
            )
          })
          process.send(reply, Ok(Nil))
          Ok(
            Worker(
              ..worker,
              ticket_keys: ticket_keys,
              address_token_keys: address_token_keys,
              stateless_reset_keys: reset_keys,
              server_config: server_transport.Config(
                ..worker.server_config,
                ticket_key: ticket_key,
                stateless_reset_key: reset_key,
              ),
            ),
          )
        }
        _, _, _ -> reply_error(worker, reply, InvalidInput)
      }
  }
}

fn handle_accept_connection(
  worker: Worker,
  reply: Subject(Result(Connection, Error)),
  deadline: Option(Int),
) -> Result(Worker, Nil) {
  case pop_pending(worker) {
    Ok(#(connection, worker)) -> {
      process.send(reply, Ok(connection))
      Ok(worker)
    }
    Error(Nil) ->
      case
        connection_worker.queue_count(worker.connection_waiters)
        >= worker.accept_waiter_limit
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
              connection_waiters: connection_worker.queue_push(
                worker.connection_waiters,
                ConnectionWaiter(reply, deadline),
              ),
            ),
          )
      }
  }
}

fn pop_pending(worker: Worker) -> Result(#(Connection, Worker), Nil) {
  case connection_worker.queue_pop(worker.pending_connections) {
    Error(Nil) -> Error(Nil)
    Ok(#(identifier, rest)) -> {
      let worker = Worker(..worker, pending_connections: rest)
      case dict.get(worker.connections, identifier) {
        Ok(entry) -> Ok(#(entry.connection, worker))
        Error(_) -> pop_pending(worker)
      }
    }
  }
}

fn expire_waiters(worker: Worker, now: Int) -> Worker {
  let #(waiters, expired) =
    partition_connection_waiters(
      worker.connection_waiters,
      now,
      connection_worker.queue_new(),
      [],
    )
  list.each(expired, fn(waiter) {
    let ConnectionWaiter(reply, _) = waiter
    process.send(reply, Error(OperationTimeout))
  })
  Worker(..worker, connection_waiters: waiters)
}

fn partition_connection_waiters(
  source: Queue(ConnectionWaiter),
  now: Int,
  kept: Queue(ConnectionWaiter),
  expired: List(ConnectionWaiter),
) -> #(Queue(ConnectionWaiter), List(ConnectionWaiter)) {
  case connection_worker.queue_pop(source) {
    Error(Nil) -> #(kept, expired)
    Ok(#(waiter, rest)) -> {
      let ConnectionWaiter(_, deadline) = waiter
      case deadline {
        Some(value) if now >= value ->
          partition_connection_waiters(rest, now, kept, [waiter, ..expired])
        None | Some(_) ->
          partition_connection_waiters(
            rest,
            now,
            connection_worker.queue_push(kept, waiter),
            expired,
          )
      }
    }
  }
}

fn shutdown(worker: Worker, error: Error) -> Nil {
  let shutdown_plan =
    shutdown_deadline.bounded(
      udp.monotonic_millisecond(),
      worker.operation_timeout_milliseconds,
      shutdown_join_cleanup_milliseconds,
    )
  let _shutdown = shutdown_result(worker, error, shutdown_plan)
  Nil
}

fn shutdown_result(
  worker: Worker,
  error: Error,
  shutdown_plan: shutdown_deadline.Plan,
) -> #(Worker, Bool, Bool) {
  let remaining_waiters =
    connection_worker.queue_values(worker.connection_waiters)
  list.each(remaining_waiters, fn(waiter) {
    let ConnectionWaiter(reply, _) = waiter
    process.send(reply, Error(error))
  })
  // Every joiner starts before this listener waits, and every one receives the same immutable absolute deadline.
  // Connection count therefore cannot turn one operation timeout into N sequential timeouts.
  // The listener keeps servicing qlog budget/release traffic while the typed join results and DOWN barriers converge.
  let completed = process.new_subject()
  let join_deadline_milliseconds =
    shutdown_deadline.join_deadline_milliseconds(shutdown_plan)
  let entries = dict.values(worker.connections)
  let joiners =
    start_shutdown_joiners(entries, completed, join_deadline_milliseconds)
  let targets = shutdown_targets(entries)
  let shutdown_selector =
    process.new_selector()
    |> process.select_map(worker.commands, ReceivedCommand)
    |> process.select_map(worker.notices, ReceivedNotice)
    |> process.select_map(worker.qlog_budget_requests, ReceivedQlogBudget)
    |> process.select_map(completed, ShutdownConnectionFinished)
    |> process.select_monitors(ConnectionExited)
    |> process.select_other(ReceivedNetwork)
  let #(next, diagnostics_closed, deadline_complete) =
    await_shutdown_result(
      worker,
      shutdown_selector,
      joiners,
      targets,
      True,
      True,
      shutdown_plan,
    )
  // Keep the listener-owned socket alive until every connection has observed its typed termination command.
  // The relay then consumes only what remains of the same final boundary and requires its own DOWN as socket-close proof.
  // On timeout the FFI force-kills it and never reports orderly success.
  let relay_closed = case
    udp.stop_relay_until(
      worker.relay,
      shutdown_deadline.final_deadline_milliseconds(shutdown_plan),
    )
  {
    Ok(Nil) -> True
    Error(_) -> False
  }
  #(next, diagnostics_closed, deadline_complete && relay_closed)
}

fn shutdown_targets(entries: List(Entry)) -> Dict(Pid, Nil) {
  list.fold(entries, dict.new(), fn(targets, entry) {
    dict.insert(targets, connection_worker.worker_pid(entry.connection), Nil)
  })
}

fn await_shutdown_result(
  worker: Worker,
  selector: process.Selector(LoopMessage),
  joiners: Dict(Pid, ShutdownJoinerState),
  targets: Dict(Pid, Nil),
  diagnostics_closed: Bool,
  deadline_complete: Bool,
  shutdown_plan: shutdown_deadline.Plan,
) -> #(Worker, Bool, Bool) {
  case dict.size(joiners) == 0 && dict.size(targets) == 0 {
    True -> #(worker, diagnostics_closed, deadline_complete)
    False ->
      await_shutdown_joiners(
        worker,
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
  }
}

fn await_shutdown_joiners(
  worker: Worker,
  selector: process.Selector(LoopMessage),
  joiners: Dict(Pid, ShutdownJoinerState),
  targets: Dict(Pid, Nil),
  diagnostics_closed: Bool,
  deadline_complete: Bool,
  shutdown_plan: shutdown_deadline.Plan,
) -> #(Worker, Bool, Bool) {
  let deadline_milliseconds =
    shutdown_deadline.join_deadline_milliseconds(shutdown_plan)
  let remaining =
    int.max(0, deadline_milliseconds - udp.monotonic_millisecond())
  case process.selector_receive(selector, within: remaining) {
    Ok(ShutdownConnectionFinished(completion)) ->
      await_shutdown_result(
        worker,
        selector,
        remember_shutdown_completion(joiners, completion),
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    Ok(ReceivedQlogBudget(request)) ->
      await_shutdown_result(
        handle_qlog_budget_request(worker, request),
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    Ok(ReceivedNotice(notice)) ->
      await_shutdown_result(
        handle_notice(worker, notice),
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    Ok(ConnectionExited(down)) -> {
      let #(worker, joiners, targets, diagnostics_closed, deadline_complete) =
        settle_shutdown_down(
          worker,
          joiners,
          targets,
          diagnostics_closed,
          deadline_complete,
          down,
        )
      await_shutdown_result(
        worker,
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    }
    Ok(ReceivedCommand(command)) -> {
      reject_shutdown_command(command)
      await_shutdown_result(
        worker,
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    }
    Ok(ReceivedNetwork(_)) | Ok(OwnerExited) ->
      await_shutdown_result(
        worker,
        selector,
        joiners,
        targets,
        diagnostics_closed,
        deadline_complete,
        shutdown_plan,
      )
    Error(Nil) -> {
      cancel_shutdown_joiners(joiners)
      cancel_shutdown_targets(targets)
      await_cancelled_shutdown_joiners(
        worker,
        selector,
        joiners,
        targets,
        diagnostics_closed,
        shutdown_deadline.final_deadline_milliseconds(shutdown_plan),
      )
    }
  }
}

fn start_shutdown_joiners(
  entries: List(Entry),
  completed: Subject(ShutdownCompletion),
  deadline_milliseconds: Int,
) -> Dict(Pid, ShutdownJoinerState) {
  list.fold(entries, dict.new(), fn(joiners, entry) {
    let joiner =
      process.spawn_unlinked(fn() {
        let result =
          connection_worker.terminate_and_wait_until(
            entry.connection,
            deadline_milliseconds,
          )
          |> classify_shutdown_result
        process.send(completed, ShutdownCompletion(process.self(), result))
      })
    dict.insert(
      joiners,
      joiner,
      ShutdownJoinerState(process.monitor(joiner), None),
    )
  })
}

fn classify_shutdown_result(
  outcome: Result(Nil, connection_worker.Error),
) -> ShutdownConnectionResult {
  case outcome {
    Ok(Nil) -> ShutdownDiagnosticsClosed
    Error(connection_worker.QlogUnavailable) -> ShutdownDiagnosticsFailed
    Error(connection_worker.OperationTimeout) -> ShutdownDeadlineExpired
    Error(connection_worker.ConnectionClosed)
    | Error(connection_worker.PeerClosedWithCode(_))
    | Error(connection_worker.PeerTransportFailureWithCode(_))
    | Error(connection_worker.TransportFailureWithCode(_)) ->
      ShutdownConnectionAlreadyGone
    Error(_) -> ShutdownDiagnosticsFailed
  }
}

fn remember_shutdown_completion(
  joiners: Dict(Pid, ShutdownJoinerState),
  completion: ShutdownCompletion,
) -> Dict(Pid, ShutdownJoinerState) {
  let ShutdownCompletion(joiner, result) = completion
  case dict.get(joiners, joiner) {
    Ok(state) ->
      dict.insert(
        joiners,
        joiner,
        ShutdownJoinerState(..state, result: Some(result)),
      )
    Error(_) -> joiners
  }
}

fn settle_shutdown_down(
  worker: Worker,
  joiners: Dict(Pid, ShutdownJoinerState),
  targets: Dict(Pid, Nil),
  diagnostics_closed: Bool,
  deadline_complete: Bool,
  down: process.Down,
) -> #(Worker, Dict(Pid, ShutdownJoinerState), Dict(Pid, Nil), Bool, Bool) {
  case down {
    process.ProcessDown(_, pid, _) -> {
      let targets = dict.delete(targets, pid)
      case dict.get(joiners, pid) {
        Error(_) -> #(
          release_connection(worker, down),
          joiners,
          targets,
          diagnostics_closed,
          deadline_complete,
        )
        Ok(joiner) -> {
          process.demonitor_process(joiner.monitor)
          let #(diagnostics_closed, deadline_complete) = case joiner.result {
            Some(ShutdownDiagnosticsClosed)
            | Some(ShutdownConnectionAlreadyGone) -> #(
              diagnostics_closed,
              deadline_complete,
            )
            Some(ShutdownDiagnosticsFailed) -> #(False, deadline_complete)
            Some(ShutdownDeadlineExpired) | None -> #(diagnostics_closed, False)
          }
          #(
            worker,
            dict.delete(joiners, pid),
            targets,
            diagnostics_closed,
            deadline_complete,
          )
        }
      }
    }
    process.PortDown(_, _, _) -> #(
      worker,
      joiners,
      targets,
      diagnostics_closed,
      deadline_complete,
    )
  }
}

fn cancel_shutdown_joiners(joiners: Dict(Pid, ShutdownJoinerState)) -> Nil {
  list.each(dict.keys(joiners), fn(joiner) { process.kill(joiner) })
}

fn cancel_shutdown_targets(targets: Dict(Pid, Nil)) -> Nil {
  // Kill every target in one fanout before observing any one of them.
  // This is the forced half of the same immutable plan, so connection count cannot multiply the cleanup tail.
  list.each(dict.keys(targets), fn(target) { process.kill(target) })
}

fn await_cancelled_shutdown_joiners(
  worker: Worker,
  selector: process.Selector(LoopMessage),
  joiners: Dict(Pid, ShutdownJoinerState),
  targets: Dict(Pid, Nil),
  diagnostics_closed: Bool,
  cleanup_deadline_milliseconds: Int,
) -> #(Worker, Bool, Bool) {
  case dict.size(joiners) == 0 && dict.size(targets) == 0 {
    True -> #(worker, diagnostics_closed, False)
    False -> {
      let remaining =
        int.max(0, cleanup_deadline_milliseconds - udp.monotonic_millisecond())
      case process.selector_receive(selector, within: remaining) {
        Ok(ConnectionExited(down)) -> {
          let #(worker, joiners, targets, diagnostics_closed, _) =
            settle_shutdown_down(
              worker,
              joiners,
              targets,
              diagnostics_closed,
              False,
              down,
            )
          await_cancelled_shutdown_joiners(
            worker,
            selector,
            joiners,
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        }
        Ok(ReceivedQlogBudget(request)) ->
          await_cancelled_shutdown_joiners(
            handle_qlog_budget_request(worker, request),
            selector,
            joiners,
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        Ok(ReceivedNotice(notice)) ->
          await_cancelled_shutdown_joiners(
            handle_notice(worker, notice),
            selector,
            joiners,
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        Ok(ReceivedCommand(command)) -> {
          reject_shutdown_command(command)
          await_cancelled_shutdown_joiners(
            worker,
            selector,
            joiners,
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        }
        Ok(ShutdownConnectionFinished(completion)) ->
          await_cancelled_shutdown_joiners(
            worker,
            selector,
            remember_shutdown_completion(joiners, completion),
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        Ok(ReceivedNetwork(_)) | Ok(OwnerExited) ->
          await_cancelled_shutdown_joiners(
            worker,
            selector,
            joiners,
            targets,
            diagnostics_closed,
            cleanup_deadline_milliseconds,
          )
        Error(Nil) -> {
          cancel_shutdown_joiners(joiners)
          cancel_shutdown_targets(targets)
          list.each(dict.values(joiners), fn(joiner) {
            process.demonitor_process(joiner.monitor)
          })
          #(worker, diagnostics_closed, False)
        }
      }
    }
  }
}

fn reject_shutdown_command(command: Command) -> Nil {
  case command {
    QlogBudgetStats(reply) -> process.send(reply, Error(ListenerClosed))
    QlogAdmissionStats(reply) -> process.send(reply, Error(ListenerClosed))
    ConnectionIdStats(reply) -> process.send(reply, Error(ListenerClosed))
    Port(reply) -> process.send(reply, Error(ListenerClosed))
    AcceptConnection(reply, _) -> process.send(reply, Error(ListenerClosed))
    ReloadCertificates(_, _, _, _, reply) ->
      process.send(reply, Error(ListenerClosed))
    ReloadKeys(_, _, _, reply) -> process.send(reply, Error(ListenerClosed))
    Stop(_, reply) -> process.send(reply, Error(ListenerClosed))
  }
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
  let policy = case worker.allow_zero_rtt, worker.replay_guard {
    False, _ -> resumption.reject_early_data(policy)
    True, None -> policy
    True, Some(guard) -> resumption.with_external_replay_guard(policy, guard)
  }
  resumption.with_application_context(
    policy,
    worker.server_config.zero_rtt_application_context,
  )
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

fn reply_error(
  worker: Worker,
  reply: Subject(Result(value, Error)),
  error: Error,
) -> Result(Worker, Nil) {
  process.send(reply, Error(error))
  Ok(worker)
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
          case
            dict.has_key(worker.connections, value)
            || dict.has_key(worker.aliases, value)
            || dict.has_key(worker.qlog_tickets, value)
          {
            True -> unique_connection_id(worker, attempts - 1)
            False -> Ok(value)
          }
      }
  }
}

fn resolve_alias(worker: Worker, destination: BitArray) -> Option(BitArray) {
  case dict.get(worker.aliases, destination) {
    Ok(identifier) -> Some(identifier)
    Error(_) -> None
  }
}

// The listener is the single writer for routes.
// It commits aliases before sending the command that lets the connection publish NEW_CONNECTION_ID.
fn allocate_connection_ids(
  worker: Worker,
  identifier: BitArray,
  remaining: Int,
  registered: List(#(BitArray, BitArray)),
) -> Worker {
  case remaining, dict.get(worker.connections, identifier) {
    _, Error(_) -> worker
    0, Ok(entry) -> {
      connection_worker.registered_connection_ids(
        entry.connection,
        list.reverse(registered),
      )
      worker
    }
    _, Ok(entry) -> {
      let routes =
        dict.size(
          dict.filter(worker.aliases, fn(_, owner) { owner == identifier }),
        )
      case
        routes >= 4,
        unique_connection_id(worker, 8),
        current_key(worker.stateless_reset_keys)
      {
        False, Ok(alias), Ok(key) ->
          case stateless_reset.token_for(key, alias) {
            Ok(token) ->
              allocate_connection_ids(
                Worker(
                  ..worker,
                  aliases: dict.insert(worker.aliases, alias, identifier),
                ),
                identifier,
                remaining - 1,
                [#(alias, token), ..registered],
              )
            Error(_) -> {
              connection_worker.terminate(entry.connection)
              worker
            }
          }
        _, _, _ -> {
          connection_worker.terminate(entry.connection)
          worker
        }
      }
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
              protocol_version,
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
              let _sent =
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
  let base = case protocol_version {
    version.Version1 -> 0xf0
    version.Version2 -> 0xc0
    _ -> 0
  }
  case base, random {
    0, _ -> Error(crypto.InvalidInput)
    _, <<random_low_bits>> ->
      Ok(int.bitwise_or(base, int.bitwise_and(random_low_bits, 0x0f)))
    _, _ -> Error(crypto.InvalidInput)
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
      version_negotiation.offered_versions(),
    )
  case packet.encode_long(response) {
    Error(_) -> worker
    Ok(bytes) -> {
      let _sent = udp.send(worker.socket, peer, bytes, ecn.NotEct)
      worker
    }
  }
}

fn open_listener(
  address_family: AddressFamily,
  bind_address: Option(BitArray),
  port: Int,
) -> Result(udp.Socket, udp.Error) {
  case bind_address {
    Some(bytes) -> {
      use address <- result.try(udp.address_from_bytes(bytes))
      use endpoint <- result.try(udp.endpoint(address, port))
      udp.open(endpoint)
    }
    None ->
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
}

fn validate_qlog_directory(directory: String) -> Result(Nil, Error) {
  case directory {
    "" -> Ok(Nil)
    value -> qlog.validate_path(value) |> result.replace_error(StartFailed)
  }
}

fn open_qlog(
  worker: Worker,
  identifier: BitArray,
  now: Int,
) -> #(Worker, Result(Option(qlog.Writer), Error)) {
  case worker.qlog_directory {
    "" -> #(worker, Ok(None))
    value -> {
      let #(outcome, ticket) =
        qlog.open_accounted(value, qlog.Server, now, worker.telemetry_limit)
      list.each(qlog.cleanup_owners(ticket), fn(owner) {
        let _monitor = process.monitor(owner)
        Nil
      })
      let worker =
        Worker(
          ..worker,
          qlog_tickets: dict.insert(worker.qlog_tickets, identifier, ticket),
        )
        |> collect_qlog_reservations
      case outcome {
        Error(_) -> #(worker, Error(QlogUnavailable))
        Ok(writer) ->
          case
            qlog.bind_budget(
              writer,
              worker.qlog_budget_requests,
              qlog_budget.reservation_key(identifier),
              qlog_budget.event_reservation_bytes(),
            )
          {
            Ok(Nil) -> #(worker, Ok(Some(writer)))
            Error(_) -> {
              let _closed = qlog.close(writer)
              #(worker, Error(QlogUnavailable))
            }
          }
      }
    }
  }
}

fn qlog_held_bytes(worker: Worker) -> Int {
  worker.qlog_tickets
  |> dict.keys
  |> list.fold(0, fn(total, identifier) {
    total
    + int.max(
      0,
      budget.holding_bytes(
        worker.endpoint_memory,
        qlog_budget.reservation_key(identifier),
      )
        - qlog_budget.connection_reservation_bytes(),
    )
  })
}

fn qlog_held_events(worker: Worker) -> Int {
  qlog_held_bytes(worker) / qlog_budget.event_reservation_bytes()
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

/// Resolve a key ring and its current key together.
///
/// Returning the current key beside the ring is what carries the ring's
/// non-emptiness to the caller. A ring is generated when none was configured
/// and is otherwise validated, so it always has a current key; handing that key
/// over here means no caller has to take a list head which cannot be missing.
fn resolve_key_ring(
  keys: List(BitArray),
) -> Result(#(BitArray, List(BitArray)), Nil) {
  case keys {
    [] ->
      crypto.secure_random(32)
      |> result.map(fn(key) { #(key, [key]) })
      |> result.replace_error(Nil)
    [current, ..] ->
      case valid_key_ring(keys) {
        True -> Ok(#(current, keys))
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

fn inspect_address_token(
  keys: List(BitArray),
  token: BitArray,
  protocol_version: Version,
  address: BitArray,
  port: Int,
  now: Int,
  maximum_age: Int,
) -> address_token.Inspection {
  case keys {
    [] -> address_token.Unreadable(address_token.AuthenticationFailed)
    [key, ..rest] ->
      case
        address_token.inspect(
          key,
          token,
          protocol_version,
          address,
          port,
          now,
          maximum_age,
        )
      {
        address_token.Accepted(_) as accepted -> accepted
        address_token.ReadableButInvalid(_, _) as invalid -> invalid
        address_token.Unreadable(error) ->
          case rest {
            [] -> address_token.Unreadable(error)
            _ ->
              inspect_address_token(
                rest,
                token,
                protocol_version,
                address,
                port,
                now,
                maximum_age,
              )
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

fn connection_waiter_deadline(waiters: Queue(ConnectionWaiter)) -> Option(Int) {
  connection_waiter_deadline_loop(connection_worker.queue_values(waiters), None)
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
        connection_worker.earlier_deadline(earliest, deadline),
      )
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

fn call_stop_until(
  listener: Listener,
  deadline_milliseconds: Int,
) -> Result(StopResult, Error) {
  use _ <- result.try(remaining_stop_milliseconds(deadline_milliseconds))
  case process.is_alive(listener.worker) {
    False -> Error(ListenerClosed)
    True -> {
      let reply = process.new_subject()
      let monitor = process.monitor(listener.worker)
      process.send(listener.commands, Stop(deadline_milliseconds, reply))
      let selector =
        process.new_selector()
        |> process.select_map(reply, fn(value) { CallReply(value) })
        |> process.select_specific_monitor(monitor, fn(_) { WorkerExited })
      let outcome =
        await_stop_call(selector, deadline_milliseconds, None, False)
      process.demonitor_process(monitor)
      outcome
    }
  }
}

fn await_stop_call(
  selector: process.Selector(CallOutcome(StopResult)),
  deadline_milliseconds: Int,
  reply: Option(Result(StopResult, Error)),
  worker_down: Bool,
) -> Result(StopResult, Error) {
  case reply, worker_down {
    Some(outcome), True ->
      case remaining_stop_milliseconds(deadline_milliseconds) {
        Ok(_) -> outcome
        Error(error) -> stop_timeout_result(Some(outcome), error)
      }
    _, _ ->
      case remaining_stop_milliseconds(deadline_milliseconds) {
        Error(error) -> stop_timeout_result(reply, error)
        Ok(remaining) ->
          case process.selector_receive(selector, within: remaining) {
            Ok(CallReply(outcome)) ->
              await_stop_call(
                selector,
                deadline_milliseconds,
                Some(outcome),
                worker_down,
              )
            Ok(WorkerExited) ->
              await_stop_call(selector, deadline_milliseconds, reply, True)
            Error(Nil) -> stop_timeout_result(reply, OperationTimeout)
          }
      }
  }
}

fn stop_timeout_result(
  observed: Option(Result(StopResult, Error)),
  timeout: Error,
) -> Result(StopResult, Error) {
  case observed {
    Some(Error(error)) -> Error(error)
    Some(Ok(_)) | None -> Error(timeout)
  }
}

fn validate_stop_deadline(deadline_milliseconds: Int) -> Result(Nil, Error) {
  case
    shutdown_deadline.from_deadline(
      udp.monotonic_millisecond(),
      deadline_milliseconds,
      shutdown_join_cleanup_milliseconds,
    )
  {
    Ok(_) -> Ok(Nil)
    Error(shutdown_deadline.DeadlineExpired) -> Error(OperationTimeout)
    Error(shutdown_deadline.InvalidConfiguration)
    | Error(shutdown_deadline.DeadlineOutOfRange) -> Error(InvalidInput)
  }
}

fn remaining_stop_milliseconds(
  deadline_milliseconds: Int,
) -> Result(Int, Error) {
  let current = udp.monotonic_millisecond()
  use _ <- result.try(
    case
      shutdown_deadline.from_deadline(
        current,
        deadline_milliseconds,
        shutdown_join_cleanup_milliseconds,
      )
    {
      Ok(_) -> Ok(Nil)
      Error(shutdown_deadline.DeadlineExpired) -> Error(OperationTimeout)
      Error(shutdown_deadline.InvalidConfiguration)
      | Error(shutdown_deadline.DeadlineOutOfRange) -> Error(InvalidInput)
    },
  )
  Ok(deadline_milliseconds - current)
}

fn call_forever(
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
        |> process.selector_receive_forever
      process.demonitor_process(monitor)
      case outcome {
        CallReply(result) -> result
        WorkerExited -> Error(ListenerClosed)
      }
    }
  }
}
