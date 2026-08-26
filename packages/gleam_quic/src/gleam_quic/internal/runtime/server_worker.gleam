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
import gleam_quic/internal/ecn
import gleam_quic/internal/packet_space
import gleam_quic/internal/process_label
import gleam_quic/internal/qlog
import gleam_quic/internal/retry_integrity
import gleam_quic/internal/runtime/connection_worker.{
  type Connection, type Error, type Queue, AcceptQueueExceeded, InvalidInput,
  ListenerClosed, OperationTimeout, QlogUnavailable, StartFailed,
}
import gleam_quic/internal/runtime/server_transport
import gleam_quic/internal/tls/anti_replay
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/tls/extension_value
import gleam_quic/internal/tls/replay_guard
import gleam_quic/internal/tls/resumption
import gleam_quic/internal/udp
import gleam_quic/packet
import gleam_quic/version.{type Version}

const connection_id_bytes = 8

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

/// Idempotent listener stop outcome.
pub type StopResult {
  Stopped
  AlreadyStopped
}

type Command {
  Port(reply: Subject(Result(Int, Error)))
  AcceptConnection(reply: Subject(Result(Connection, Error)), deadline: Int)
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
  ReceivedNotice(connection_worker.ConnectionToListener)
  ConnectionExited(process.Down)
  ReceivedNetwork(Dynamic)
  OwnerExited
}

type ConnectionWaiter {
  ConnectionWaiter(reply: Subject(Result(Connection, Error)), deadline: Int)
}

/// One admitted connection and the actor that owns it.
type Entry {
  Entry(connection: Connection, established: Bool)
}

type Worker {
  Worker(
    socket: udp.Socket,
    relay: udp.Relay,
    port: Int,
    commands: Subject(Command),
    notices: Subject(connection_worker.ConnectionToListener),
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
      let notices = process.new_subject()
      let owner_monitor = process.monitor(owner)
      let selector =
        process.new_selector()
        |> process.select_map(commands, ReceivedCommand)
        |> process.select_map(notices, ReceivedNotice)
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
  worker
}

fn deliver_routed(
  worker: Worker,
  routed: List(#(BitArray, List(connection_worker.ListenerToConnection))),
) -> Nil {
  case routed {
    [] -> Nil
    [#(identifier, deliveries), ..rest] -> {
      case dict.get(worker.connections, identifier) {
        Ok(entry) ->
          connection_worker.deliver(entry.connection, list.reverse(deliveries))
        Error(_) -> Nil
      }
      deliver_routed(worker, rest)
    }
  }
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
    <<_first, destination:bytes-size(connection_id_bytes), _rest:bits>> -> #(
      worker,
      route_existing(worker, destination, peer, datagram, marking, routed),
    )
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
        Ok(local_connection_id) -> {
          let now = udp.monotonic_millisecond()
          case replay_policy(worker, now) {
            Error(_) -> worker
            Ok(policy) ->
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
                  spawn_connection(
                    worker,
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
      }
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
  case open_qlog(worker.qlog_directory, worker.telemetry_limit, now) {
    Error(_) -> worker
    Ok(writer) -> {
      case writer {
        Some(value) -> {
          qlog.connection_started(value, now)
          qlog.datagram_received(value, now, datagram_bytes)
        }
        None -> Nil
      }
      let worker = update_replay_cache(worker, connection)
      case current_key(worker.address_token_keys) {
        Error(_) -> {
          close_qlog(writer)
          worker
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
            ))
          {
            Error(_) -> {
              close_qlog(writer)
              worker
            }
            Ok(handle) -> {
              let pid = connection_worker.worker_pid(handle)
              let _monitor = process.monitor(pid)
              Worker(
                ..worker,
                connections: dict.insert(
                  worker.connections,
                  local_connection_id,
                  Entry(handle, False),
                ),
                routes: dict.insert(worker.routes, pid, local_connection_id),
                handshaking: worker.handshaking + 1,
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
    connection_worker.Released(identifier, pid) ->
      release_reported_connection(worker, identifier, pid)
  }
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
  case down {
    process.ProcessDown(_, pid, _) -> release_connection_pid(worker, pid)
    process.PortDown(_, _, _) -> worker
  }
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
        handshaking: handshaking,
        pending_connections: connection_worker.queue_filter(
          worker.pending_connections,
          fn(value) { value != identifier },
        ),
      )
    }
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
    Stop(reply) -> {
      shutdown(worker, ListenerClosed)
      process.send(reply, Ok(Stopped))
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
  deadline: Int,
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
      case now >= deadline {
        True ->
          partition_connection_waiters(rest, now, kept, [waiter, ..expired])
        False ->
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
  let remaining_waiters =
    connection_worker.queue_values(worker.connection_waiters)
  list.each(remaining_waiters, fn(waiter) {
    let ConnectionWaiter(reply, _) = waiter
    process.send(reply, Error(error))
  })
  let _stopped = udp.stop_relay(worker.relay)
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
      let _sent = udp.send(worker.socket, peer, bytes, ecn.NotEct)
      worker
    }
  }
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
      let _closed = qlog.close(value)
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
        connection_worker.earlier_deadline(earliest, Some(deadline)),
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
