//// Synchronous bounded HTTP/3 client over the native QUIC runtime.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam_quic/internal/connection_state as transport
import gleam_quic/internal/crypto
import gleam_quic/internal/driver
import gleam_quic/internal/ecn
import gleam_quic/internal/http3/connection_state as http3_state
import gleam_quic/internal/http3/header_semantics
import gleam_quic/internal/http3/session
import gleam_quic/internal/qpack/header.{type Header, Header}
import gleam_quic/internal/tls/authentication
import gleam_quic/internal/tls/engine
import gleam_quic/internal/udp
import gleam_quic/transport_parameter
import gleam_quic/version.{type Version}

/// Internal alias used to normalize diagnostics without exporting internals.
pub type DriverError =
  driver.Error

/// Internal alias used to normalize diagnostics without exporting internals.
pub type SessionError =
  session.Error

const maximum_packets_per_flush = 64

const maximum_frame_data_bytes = 1000

const receive_poll_milliseconds = 10

const connection_id_bytes = 8

/// Validated inputs for one native request.
pub type Config {
  Config(
    hostname: String,
    port: Int,
    timeout_milliseconds: Int,
    maximum_response_body_bytes: Int,
    trust_store: authentication.TrustStore,
    quic_version: Version,
    keepalive_milliseconds: Int,
  )
}

/// A complete bounded HTTP response.
pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

/// Stable failures without leaking protocol-state representations.
pub type Error {
  InvalidInput
  ResolutionFailed
  SocketUnavailable
  Timeout
  TlsHandshakeFailed
  QuicTransportFailed(operation: String, error: driver.Error)
  Http3ProtocolFailed
  Http3OperationFailed(operation: String, error: session.Error)
  PeerClosed
  StreamReset(Int)
  InvalidHeaderEncoding
  ResponseBodyTooLarge(Int)
  VersionNegotiationReceived(List(Version))
  VersionNegotiationFailed
}

type Collector {
  Collector(
    status: Option(Int),
    headers: List(#(String, String)),
    body: BitArray,
    finished: Bool,
  )
}

/// Run one request on one connection and close its UDP socket before return.
pub fn send(
  config config: Config,
  fields fields: List(#(String, String)),
  body body: BitArray,
) -> Result(Response, Error) {
  case validate(config, body) {
    Error(error) -> Error(error)
    Ok(Nil) -> {
      let started = udp.monotonic_millisecond()
      let deadline = started + config.timeout_milliseconds
      use addresses <- result.try(
        udp.resolve(config.hostname, udp.Any)
        |> result.replace_error(ResolutionFailed),
      )
      use headers <- result.try(encode_headers(fields))
      try_addresses(config, addresses, headers, body, deadline, None)
    }
  }
}

fn try_addresses(
  config: Config,
  addresses: List(udp.Address),
  headers: List(Header),
  body: BitArray,
  deadline: Int,
  last_error: Option(Error),
) -> Result(Response, Error) {
  case addresses, remaining_milliseconds(deadline) {
    _, remaining if remaining <= 0 -> Error(Timeout)
    [], _ -> Error(option_error(last_error, SocketUnavailable))
    [address, ..rest], _ ->
      case request_at_address(config, address, headers, body, deadline) {
        Ok(response) -> Ok(response)
        Error(SocketUnavailable) ->
          try_addresses(
            config,
            rest,
            headers,
            body,
            deadline,
            Some(SocketUnavailable),
          )
        Error(error) -> Error(error)
      }
  }
}

fn request_at_address(
  config: Config,
  address: udp.Address,
  headers: List(Header),
  body: BitArray,
  deadline: Int,
) -> Result(Response, Error) {
  use peer <- result.try(
    udp.endpoint(address, config.port) |> result.replace_error(InvalidInput),
  )
  use socket <- result.try(
    open_for_address(address) |> result.replace_error(SocketUnavailable),
  )
  let outcome = request_on_socket(config, socket, peer, headers, body, deadline)
  let closed = udp.close(socket)
  case outcome, closed {
    Ok(response), Ok(Nil) -> Ok(response)
    Ok(_), Error(_) -> Error(SocketUnavailable)
    Error(error), _ -> Error(error)
  }
}

fn request_on_socket(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  headers: List(Header),
  body: BitArray,
  deadline: Int,
) -> Result(Response, Error) {
  request_on_socket_version(
    config,
    socket,
    peer,
    headers,
    body,
    deadline,
    config.quic_version,
    [],
  )
}

fn request_on_socket_version(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  headers: List(Header),
  body: BitArray,
  deadline: Int,
  selected_version: Version,
  attempted_versions: List(Version),
) -> Result(Response, Error) {
  use original_destination_connection_id <- result.try(random_connection_id())
  use local_connection_id <- result.try(random_connection_id())
  let transport_config = client_transport_config(selected_version)
  let tls_config =
    engine.ClientConfig(
      version: selected_version,
      hostname: config.hostname,
      application_protocols: [<<"h3">>],
      transport_parameters: client_transport_parameters(
        local_connection_id,
        selected_version,
      ),
      trust_store: config.trust_store,
      retried: False,
    )
  use tls <- result.try(
    engine.start_client(tls_config) |> result.replace_error(TlsHandshakeFailed),
  )
  use quic <- result.try(
    driver.start_client(
      transport_config,
      tls,
      original_destination_connection_id,
      local_connection_id,
      udp.monotonic_millisecond(),
    )
    |> result.map_error(fn(error) { QuicTransportFailed("start", error) }),
  )
  case handshake(quic, socket, peer, deadline) {
    Error(VersionNegotiationReceived(offered)) ->
      case
        select_compatible_version(selected_version, offered, [
          selected_version,
          ..attempted_versions
        ])
      {
        Error(_) -> Error(VersionNegotiationFailed)
        Ok(next_version) ->
          request_on_socket_version(
            config,
            socket,
            peer,
            headers,
            body,
            deadline,
            next_version,
            [selected_version, ..attempted_versions],
          )
      }
    Error(error) -> Error(error)
    Ok(quic) ->
      request_after_handshake(
        config,
        socket,
        peer,
        headers,
        body,
        deadline,
        quic,
      )
  }
}

fn request_after_handshake(
  config: Config,
  socket: udp.Socket,
  peer: udp.Endpoint,
  headers: List(Header),
  body: BitArray,
  deadline: Int,
  quic: driver.State,
) -> Result(Response, Error) {
  use http3 <- result.try(
    session.start(quic, http3_state.default_config(http3_state.Client), False)
    |> result.map_error(fn(error) { Http3OperationFailed("start", error) }),
  )
  use #(http3, stream_id) <- result.try(
    session.open_request(http3, headers, False)
    |> result.map_error(fn(error) {
      Http3OperationFailed("open_request", error)
    }),
  )
  use http3 <- result.try(case body {
    <<>> -> Ok(http3)
    _ ->
      session.send_data(http3, stream_id, body)
      |> result.map_error(fn(error) { Http3OperationFailed("send_data", error) })
  })
  use http3 <- result.try(
    session.finish_stream(http3, stream_id)
    |> result.map_error(fn(error) { Http3OperationFailed("finish", error) }),
  )
  use #(http3, response) <- result.try(collect_response(
    http3,
    socket,
    peer,
    stream_id,
    Collector(None, [], <<>>, False),
    config.maximum_response_body_bytes,
    deadline,
    config.keepalive_milliseconds,
    next_keepalive(config.keepalive_milliseconds),
  ))
  graceful_close(http3, socket, peer)
  Ok(response)
}

fn handshake(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  deadline: Int,
) -> Result(driver.State, Error) {
  case driver.phase(state), remaining_milliseconds(deadline) {
    transport.Established, _ -> Ok(state)
    transport.Closed, _ -> Error(PeerClosed)
    _, remaining if remaining <= 0 -> Error(Timeout)
    _, remaining -> {
      let now = udp.monotonic_millisecond()
      use state <- result.try(
        driver.tick(state, now)
        |> result.map_error(fn(error) { QuicTransportFailed("tick", error) }),
      )
      use state <- result.try(flush_driver(
        state,
        socket,
        peer,
        now,
        maximum_packets_per_flush,
      ))
      use state <- result.try(receive_driver(
        state,
        socket,
        peer,
        int.min(receive_poll_milliseconds, remaining),
      ))
      handshake(state, socket, peer, deadline)
    }
  }
}

fn flush_driver(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(driver.State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case driver.prepare_datagram(state, maximum_frame_data_bytes, now) {
        Error(driver.ConnectionFailure(transport.PacingLimited(_))) -> Ok(state)
        Error(driver.ConnectionFailure(transport.CongestionLimited)) ->
          Ok(state)
        Error(error) -> Error(QuicTransportFailed("prepare", error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) -> {
          use Nil <- result.try(
            udp.send(socket, peer, driver.prepared_bytes(prepared), ecn.NotEct)
            |> map_udp_send,
          )
          use state <- result.try(
            driver.commit_datagram_with_ecn(prepared, ecn.NotEct, now)
            |> result.map_error(fn(error) {
              QuicTransportFailed("commit", error)
            }),
          )
          flush_driver(state, socket, peer, now, remaining_packets - 1)
        }
      }
  }
}

fn receive_driver(
  state: driver.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  timeout: Int,
) -> Result(driver.State, Error) {
  case udp.receive(socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(udp.Closed) -> Error(SocketUnavailable)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(received_peer, bytes, marking)) ->
      case same_endpoint(received_peer, peer) {
        False -> Ok(state)
        True ->
          case
            driver.receive_datagram_with_ecn(
              state,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(state) -> Ok(state)
            Error(driver.VersionNegotiationReceived(versions)) ->
              Error(VersionNegotiationReceived(versions))
            Error(error) -> discard_or_fail_driver(state, error)
          }
      }
  }
}

fn collect_response(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
  deadline: Int,
  keepalive_milliseconds: Int,
  next_keepalive_milliseconds: Int,
) -> Result(#(session.State, Response), Error) {
  let #(state, events) = session.take_events(state)
  use collector <- result.try(apply_events(
    events,
    stream_id,
    collector,
    body_limit,
  ))
  case collector.finished, collector.status, remaining_milliseconds(deadline) {
    True, Some(status), _ ->
      Ok(#(state, Response(status, collector.headers, collector.body)))
    True, None, _ -> Error(Http3ProtocolFailed)
    _, _, remaining if remaining <= 0 -> Error(Timeout)
    _, _, remaining -> {
      let now = udp.monotonic_millisecond()
      use #(state, next_keepalive_milliseconds) <- result.try(maybe_keepalive(
        state,
        keepalive_milliseconds,
        next_keepalive_milliseconds,
        now,
      ))
      use state <- result.try(
        session.tick(state, now)
        |> result.map_error(fn(error) { Http3OperationFailed("tick", error) }),
      )
      let #(state, events) = session.take_events(state)
      use collector <- result.try(apply_events(
        events,
        stream_id,
        collector,
        body_limit,
      ))
      use state <- result.try(flush_session(
        state,
        socket,
        peer,
        now,
        maximum_packets_per_flush,
      ))
      case collector.finished {
        True ->
          collect_response(
            state,
            socket,
            peer,
            stream_id,
            collector,
            body_limit,
            deadline,
            keepalive_milliseconds,
            next_keepalive_milliseconds,
          )
        False -> {
          use state <- result.try(receive_session(
            state,
            socket,
            peer,
            int.min(receive_poll_milliseconds, remaining),
          ))
          collect_response(
            state,
            socket,
            peer,
            stream_id,
            collector,
            body_limit,
            deadline,
            keepalive_milliseconds,
            next_keepalive_milliseconds,
          )
        }
      }
    }
  }
}

fn next_keepalive(interval: Int) -> Int {
  case interval {
    0 -> 0
    _ -> udp.monotonic_millisecond() + interval
  }
}

fn maybe_keepalive(
  state: session.State,
  interval: Int,
  next: Int,
  now: Int,
) -> Result(#(session.State, Int), Error) {
  case interval > 0 && now >= next {
    False -> Ok(#(state, next))
    True ->
      session.ping(state)
      |> result.map(fn(state) { #(state, now + interval) })
      |> result.map_error(fn(error) { Http3OperationFailed("keepalive", error) })
  }
}

fn flush_session(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  now: Int,
  remaining_packets: Int,
) -> Result(session.State, Error) {
  case remaining_packets {
    0 -> Ok(state)
    _ ->
      case session.prepare_datagram(state, maximum_frame_data_bytes, now) {
        Error(session.DriverFailure(driver.ConnectionFailure(transport.PacingLimited(
          _,
        )))) -> Ok(state)
        Error(session.DriverFailure(driver.ConnectionFailure(
          transport.CongestionLimited,
        ))) -> Ok(state)
        Error(error) -> Error(Http3OperationFailed("prepare", error))
        Ok(None) -> Ok(state)
        Ok(Some(prepared)) -> {
          use Nil <- result.try(
            udp.send(socket, peer, session.prepared_bytes(prepared), ecn.NotEct)
            |> map_udp_send,
          )
          use state <- result.try(
            session.commit_datagram(prepared, ecn.NotEct, now)
            |> result.map_error(fn(error) {
              Http3OperationFailed("commit", error)
            }),
          )
          flush_session(state, socket, peer, now, remaining_packets - 1)
        }
      }
  }
}

fn receive_session(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
  timeout: Int,
) -> Result(session.State, Error) {
  case udp.receive(socket, timeout) {
    Error(udp.Timeout) -> Ok(state)
    Error(_) -> Error(SocketUnavailable)
    Ok(udp.Datagram(received_peer, bytes, marking)) ->
      case same_endpoint(received_peer, peer) {
        False -> Ok(state)
        True ->
          case
            session.receive_datagram(
              state,
              bytes,
              marking,
              udp.monotonic_millisecond(),
            )
          {
            Ok(state) -> Ok(state)
            Error(session.DriverFailure(error)) ->
              case discard_driver_error(error) {
                True -> Ok(state)
                False ->
                  Error(Http3OperationFailed(
                    "receive",
                    session.DriverFailure(error),
                  ))
              }
            Error(error) -> Error(Http3OperationFailed("receive", error))
          }
      }
  }
}

fn apply_events(
  events: List(session.Event),
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case events {
    [] -> Ok(collector)
    [event, ..rest] -> {
      use collector <- result.try(apply_event(
        event,
        stream_id,
        collector,
        body_limit,
      ))
      apply_events(rest, stream_id, collector, body_limit)
    }
  }
}

fn apply_event(
  event: session.Event,
  stream_id: Int,
  collector: Collector,
  body_limit: Int,
) -> Result(Collector, Error) {
  case event {
    session.Http3Event(http3_state.ResponseHeaders(identifier, validated))
      if identifier == stream_id
    -> {
      let header_semantics.Validated(control, fields, _) = validated
      use status <- result.try(response_status(control))
      use headers <- result.try(decode_headers(fields))
      Ok(Collector(..collector, status: Some(status), headers: headers))
    }
    session.Http3Event(http3_state.Data(identifier, bytes))
      if identifier == stream_id
    -> {
      let size =
        bit_array.byte_size(collector.body) + bit_array.byte_size(bytes)
      case size > body_limit {
        True -> Error(ResponseBodyTooLarge(body_limit))
        False ->
          Ok(Collector(..collector, body: <<collector.body:bits, bytes:bits>>))
      }
    }
    session.Http3Event(http3_state.StreamFinished(identifier))
      if identifier == stream_id
    -> Ok(Collector(..collector, finished: True))
    session.TransportEvent(transport.StreamWasReset(identifier, code))
      if identifier == stream_id
    -> Error(StreamReset(code))
    session.TransportEvent(transport.PeerClosed(_, _)) -> Error(PeerClosed)
    session.TransportEvent(transport.StatelessResetReceived) ->
      Error(PeerClosed)
    _ -> Ok(collector)
  }
}

fn response_status(control: header_semantics.Control) -> Result(Int, Error) {
  case control {
    header_semantics.ResponseControlData(status) -> Ok(status)
    _ -> Error(Http3ProtocolFailed)
  }
}

fn encode_headers(
  fields: List(#(String, String)),
) -> Result(List(Header), Error) {
  list.map(fields, fn(field) {
    let #(name, value) = field
    Header(bit_array.from_string(name), bit_array.from_string(value), False)
  })
  |> Ok
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

fn client_transport_config(selected_version: Version) -> transport.Config {
  let config = transport.default_config(transport.Client)
  transport.Config(
    ..config,
    version: selected_version,
    maximum_udp_payload_size: 1200,
    grease_quic_bit: True,
    maximum_datagram_frame_size: 0,
  )
}

fn client_transport_parameters(
  local_connection_id: BitArray,
  selected_version: Version,
) -> List(transport_parameter.Parameter) {
  [
    transport_parameter.GreaseQuicBit,
    transport_parameter.MaxIdleTimeout(30_000),
    transport_parameter.MaxUdpPayloadSize(1200),
    transport_parameter.InitialMaxData(1_048_576),
    transport_parameter.InitialMaxStreamDataBidiLocal(262_144),
    transport_parameter.InitialMaxStreamDataBidiRemote(262_144),
    transport_parameter.InitialMaxStreamDataUni(262_144),
    transport_parameter.InitialMaxStreamsBidi(100),
    transport_parameter.InitialMaxStreamsUni(100),
    transport_parameter.ActiveConnectionIdLimit(4),
    transport_parameter.InitialSourceConnectionId(local_connection_id),
    transport_parameter.VersionInformation(selected_version, [
      version.Version2,
      version.Version1,
    ]),
  ]
}

fn random_connection_id() -> Result(BitArray, Error) {
  crypto.secure_random(connection_id_bytes)
  |> result.replace_error(TlsHandshakeFailed)
}

fn open_for_address(address: udp.Address) -> Result(udp.Socket, udp.Error) {
  case bit_array.byte_size(udp.address_bytes(address)) {
    4 -> {
      use wildcard <- result.try(udp.ipv4(0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    16 -> {
      use wildcard <- result.try(udp.ipv6(0, 0, 0, 0, 0, 0, 0, 0))
      use endpoint <- result.try(udp.endpoint(wildcard, 0))
      udp.open(endpoint)
    }
    _ -> Error(udp.InvalidInput)
  }
}

fn graceful_close(
  state: session.State,
  socket: udp.Socket,
  peer: udp.Endpoint,
) -> Nil {
  let now = udp.monotonic_millisecond()
  case session.close(state, 0x100, "request complete", now) {
    // nolint: thrown_away_error -- the socket owner still closes unconditionally.
    Error(_) -> Nil
    Ok(state) -> {
      case flush_session(state, socket, peer, now, 4) {
        Ok(_) -> Nil
        // nolint: thrown_away_error -- best-effort close cannot replace a response.
        Error(_) -> Nil
      }
    }
  }
}

/// Normalize a driver failure into a non-secret stable diagnostic.
pub fn driver_error_name(error: DriverError) -> String {
  case error {
    driver.InvalidInput -> "invalid packet input"
    driver.DestinationConnectionIdMismatch -> "destination CID mismatch"
    driver.VersionNegotiationReceived(_) -> "version negotiation required"
    driver.PacketFailure(_) -> "packet protection or codec failure"
    driver.ConnectionFailure(_) -> "connection state transition failed"
  }
}

/// Normalize a session failure into a non-secret stable diagnostic.
pub fn session_error_name(error: SessionError) -> String {
  case error {
    session.ConnectionNotEstablished -> "connection is not established"
    session.InvalidPeerStream(_) -> "invalid peer stream"
    session.MissingInput(_) -> "missing stream input"
    session.PrefaceLimitExceeded -> "stream preface limit exceeded"
    session.DriverFailure(error) -> driver_error_name(error)
    session.TransportFailure(_) -> "transport state failure"
    session.Http3Failure(_) -> "HTTP/3 state failure"
    session.FrameParserFailure(_) -> "HTTP/3 frame parser failure"
    session.InstructionParserFailure(_) -> "QPACK instruction parser failure"
  }
}

fn discard_or_fail_driver(
  state: driver.State,
  error: driver.Error,
) -> Result(driver.State, Error) {
  case discard_driver_error(error) {
    True -> Ok(state)
    False -> Error(QuicTransportFailed("receive", error))
  }
}

fn discard_driver_error(error: driver.Error) -> Bool {
  case error {
    driver.InvalidInput
    | driver.DestinationConnectionIdMismatch
    | driver.PacketFailure(_)
    | driver.ConnectionFailure(transport.MissingReadKeys(_))
    | driver.ConnectionFailure(transport.MissingWriteKeys(_)) -> True
    _ -> False
  }
}

fn map_udp_send(value: Result(Nil, udp.Error)) -> Result(Nil, Error) {
  case value {
    Ok(Nil) -> Ok(Nil)
    Error(_) -> Error(SocketUnavailable)
  }
}

fn same_endpoint(left: udp.Endpoint, right: udp.Endpoint) -> Bool {
  udp.endpoint_parts(left) == udp.endpoint_parts(right)
}

fn remaining_milliseconds(deadline: Int) -> Int {
  deadline - udp.monotonic_millisecond()
}

fn option_error(value: Option(Error), fallback: Error) -> Error {
  case value {
    Some(error) -> error
    None -> fallback
  }
}

fn validate(config: Config, body: BitArray) -> Result(Nil, Error) {
  case
    config.hostname != ""
    && config.port > 0
    && config.port <= 65_535
    && config.timeout_milliseconds > 0
    && config.maximum_response_body_bytes > 0
    && {
      config.keepalive_milliseconds == 0
      || {
        config.keepalive_milliseconds >= 1000
        && config.keepalive_milliseconds <= 29_000
      }
    }
    && {
      config.quic_version == version.Version1
      || config.quic_version == version.Version2
    }
    && bit_array.bit_size(body) % 8 == 0
  {
    True -> Ok(Nil)
    False -> Error(InvalidInput)
  }
}

fn select_compatible_version(
  current: Version,
  offered: List(Version),
  attempted: List(Version),
) -> Result(Version, Nil) {
  [version.Version2, version.Version1]
  |> list.find(fn(candidate) {
    candidate != current
    && list.contains(offered, candidate)
    && !list.contains(attempted, candidate)
  })
}
