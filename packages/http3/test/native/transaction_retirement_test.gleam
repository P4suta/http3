import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import http3/internal/native/connection_state as state
import http3/internal/native/datagram
import http3/internal/native/drain
import http3/internal/native/frame
import http3/internal/native/message_stream
import http3/internal/native/protocol
import http3/internal/qpack/header.{type Header, Header}
import http3/internal/qpack/instruction

type Write {
  Write(Int, BitArray, Bool)
}

type Resource {
  Resource(
    next: Int,
    uni: Int,
    writes: List(Write),
    seen: Dict(Int, Nil),
    fail: Bool,
  )
}

fn resource() -> protocol.Resource(Resource) {
  protocol.Resource(
    open_bidirectional: fn(resource_state) {
      Ok(#(
        Resource(..resource_state, next: resource_state.next + 4),
        resource_state.next,
      ))
    },
    open_unidirectional: fn(resource_state) {
      Ok(#(
        Resource(..resource_state, uni: resource_state.uni + 4),
        resource_state.uni,
      ))
    },
    write: fn(resource_state, id, bytes, fin) {
      Ok(
        Resource(
          ..resource_state,
          writes: list.append(resource_state.writes, [Write(id, bytes, fin)]),
        ),
      )
    },
    abort: fn(resource_state, _, _) {
      case resource_state.fail {
        True -> Error(protocol.InvalidResourceOperation)
        False -> Ok(resource_state)
      }
    },
    send_datagram: fn(resource_state, _) { Ok(resource_state) },
    maximum_datagram_size: fn(_) { Ok(1200) },
    guaranteed_datagram_size: fn(_) { Ok(600) },
  )
}

fn start(role: state.Role, maximum: Int) -> protocol.State(Resource) {
  let defaults = state.default_config(role)
  let #(next, uni) = case role {
    state.Client -> #(0, 2)
    state.Server -> #(1, 3)
  }
  let assert Ok(started) =
    protocol.start(
      resource(),
      Resource(next, uni, [], dict.new(), False),
      state.Config(..defaults, maximum_transactions: maximum),
      False,
    )
  started
}

fn transfer(
  sender: protocol.State(Resource),
  receiver: protocol.State(Resource),
) -> #(protocol.State(Resource), protocol.State(Resource)) {
  let resource_state = protocol.connection(sender)
  let sender =
    protocol.with_connection(sender, Resource(..resource_state, writes: []))
  let receiver =
    list.fold(resource_state.writes, receiver, fn(receiver, write) {
      let Write(id, bytes, fin) = write
      let resource_state = protocol.connection(receiver)
      let receiver = case dict.has_key(resource_state.seen, id) {
        True -> receiver
        False -> {
          let receiver =
            protocol.with_connection(
              receiver,
              Resource(
                ..resource_state,
                seen: dict.insert(resource_state.seen, id, Nil),
              ),
            )
          let assert Ok(receiver) = protocol.register_peer_stream(receiver, id)
          receiver
        }
      }
      let assert Ok(receiver) =
        protocol.receive_stream(receiver, id, bytes, fin, 1)
      receiver
    })
  #(sender, receiver)
}

fn pair(
  client_maximum: Int,
  server_maximum: Int,
) -> #(protocol.State(Resource), protocol.State(Resource)) {
  let client = start(state.Client, client_maximum)
  let server = start(state.Server, server_maximum)
  let #(client, server) = transfer(client, server)
  let #(server, client) = transfer(server, client)
  let #(client, _) = protocol.take_events(client)
  let #(server, _) = protocol.take_events(server)
  #(client, server)
}

fn headers() -> List(Header) {
  [
    Header(<<":method">>, <<"POST">>, False),
    Header(<<":scheme">>, <<"https">>, False),
    Header(<<":authority">>, <<"localhost">>, False),
    Header(<<":path">>, <<"/cancel">>, False),
  ]
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn repeated_client_abort_releases_transaction_admission_test() -> Nil {
  let #(client, _) = pair(2, 4)
  let client =
    list.fold([0, 4], client, fn(client, expected_id) {
      let assert Ok(#(client, id)) =
        protocol.open_request(client, headers(), False)
      assert id == expected_id
      let assert Ok(client) = protocol.abort_stream(client, id, 0x10c)
      let assert Ok(client) = protocol.receive_reset(client, id)
      client
    })
  let next = protocol.open_request(client, headers(), False)
  assert result.is_ok(next)
  let #(_, transactions, _, _) = protocol.resource_counts(client)
  assert transactions == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn repeated_server_abort_releases_transaction_admission_test() -> Nil {
  let #(client, server) = pair(4, 2)
  let #(client, server) =
    list.fold([0, 4], #(client, server), fn(pair, expected_id) {
      let #(client, server) = pair
      let assert Ok(#(client, id)) =
        protocol.open_request(client, headers(), False)
      assert id == expected_id
      let #(client, server) = transfer(client, server)
      let assert Ok(server) = protocol.abort_stream(server, id, 0x10c)
      let assert Ok(server) = protocol.receive_reset(server, id)
      let #(server, _) = protocol.take_events(server)
      #(client, server)
    })
  let assert Ok(#(client, 8)) = protocol.open_request(client, headers(), False)
  let assert Ok(Write(_, bytes, False)) =
    list.find(protocol.connection(client).writes, fn(write) {
      let Write(id, _, _) = write
      id == 8
    })
  let assert Ok(server) = protocol.register_peer_stream(server, 8)
  assert result.is_ok(protocol.receive_stream(server, 8, bytes, False, 1))
  let #(_, transactions, _, _) = protocol.resource_counts(server)
  assert transactions == 0
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn abort_resource_failure_does_not_claim_protocol_retirement_test() -> Nil {
  let #(client, _) = pair(2, 2)
  let assert Ok(#(client, id)) = protocol.open_request(client, headers(), False)
  let resource_state = protocol.connection(client)
  let client =
    protocol.with_connection(client, Resource(..resource_state, fail: True))
  assert protocol.abort_stream(client, id, 0x10c)
    == Error(protocol.ResourceFailure(protocol.InvalidResourceOperation))
  let #(_, transactions, _, _) = protocol.resource_counts(client)
  assert transactions == 1
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn confirmed_terminal_resource_uses_the_same_pure_retirement_test() -> Nil {
  let #(client, _) = pair(2, 2)
  let assert Ok(#(client, id)) = protocol.open_request(client, headers(), False)
  let resource_state = protocol.connection(client)
  let client =
    protocol.with_connection(client, Resource(..resource_state, fail: True))
  let assert Ok(client) = protocol.retire_aborted_stream(client, id)
  let #(_, transactions, _, _) = protocol.resource_counts(client)
  assert transactions == 0
  assert list.any(protocol.connection(client).writes, fn(write) {
    case write {
      Write(10, bytes, False) ->
        instruction.decode_decoder(bytes)
        == Ok(#(instruction.StreamCancellation(id), <<>>))
      _ -> False
    }
  })
  let assert Ok(client) = protocol.receive_reset(client, id)
  assert result.is_ok(protocol.open_request(client, headers(), False))
}

fn pure_pair() -> #(state.State, state.State) {
  let client = state.default_config(state.Client)
  let server = state.default_config(state.Server)
  let assert Ok(client) =
    state.new(
      state.Config(
        ..client,
        settings: state.Settings(..client.settings, h3_datagram: True),
      ),
      True,
    )
  let assert Ok(server) =
    state.new(
      state.Config(
        ..server,
        settings: state.Settings(..server.settings, h3_datagram: True),
      ),
      True,
    )
  let assert Ok(#(client, _)) = state.bootstrap(client, 2, 6, 10)
  let assert Ok(#(server, _)) = state.bootstrap(server, 3, 7, 11)
  let settings =
    frame.Settings([
      frame.Setting(1, 4096),
      frame.Setting(7, 16),
      frame.Setting(8, 1),
      frame.Setting(0x33, 1),
    ])
  let assert Ok(#(client, _)) = state.receive_control_frame(client, settings)
  let assert Ok(#(server, _)) = state.receive_control_frame(server, settings)
  #(client, server)
}

fn decode(bytes: BitArray) -> frame.Frame {
  let assert Ok(#(frame, <<>>)) = frame.decode(bytes, frame.default_limits())
  frame
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_receive_reset_preserves_the_open_response_direction_test() -> Nil {
  let #(client, server) = pure_pair()
  let assert Ok(#(_, bytes)) = state.open_request(client, 0, headers(), False)
  let assert Ok(#(server, _)) =
    state.receive_request_frame(server, 0, decode(bytes))
  let assert Ok(server) = state.receive_stream_reset(server, 0)
  let response =
    state.send_response_headers(
      server,
      0,
      [Header(<<":status">>, <<"204">>, False)],
      False,
    )
  assert result.is_ok(response)
  let assert Ok(#(server, _)) = response
  assert state.resource_counts(server) == #(1, 0, 0)
  let assert Ok(server) = state.finish_send(server, 0)
  assert state.resource_counts(server) == #(0, 0, 0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_stop_send_preserves_request_bytes_until_fin_test() -> Nil {
  let #(client, server) = pure_pair()
  let assert Ok(#(_, bytes)) = state.open_request(client, 0, headers(), False)
  let assert Ok(#(server, _)) =
    state.receive_request_frame(server, 0, decode(bytes))

  let assert Ok(server) = state.observe_send_stopped(server, 0)
  assert state.resource_counts(server) == #(1, 0, 0)
  assert state.send_data(server, 0, <<1>>)
    == Error(state.MessageFailure(message_stream.FrameAfterFinished))

  let close_payload = <<136, 2, 3, 234>>
  let assert Ok(#(server, [state.Data(0, received)])) =
    state.receive_request_frame(server, 0, frame.Data(close_payload))
  assert received == close_payload
  let assert Ok(#(server, [state.StreamFinished(0)])) =
    state.receive_request_finish(server, 0)
  assert state.resource_counts(server) == #(0, 0, 0)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn local_abort_retires_scheduler_datagram_and_drain_work_test() -> Nil {
  let #(client, server) = pure_pair()
  let tunnel =
    list.append(
      list.filter(headers(), fn(field) { field.name != <<":method">> }),
      [
        Header(<<":method">>, <<"CONNECT">>, False),
        Header(<<":protocol">>, <<"connect-udp">>, False),
      ],
    )
  let assert Ok(#(_, bytes)) = state.open_request(client, 0, tunnel, False)
  let assert Ok(#(server, _)) =
    state.receive_request_frame(server, 0, decode(bytes))
  let assert Ok(#(server, _)) =
    state.send_response_headers(
      server,
      0,
      [Header(<<":status">>, <<"200">>, False)],
      False,
    )
  assert result.is_ok(state.send_datagram(server, 0, <<1>>))
  let assert Ok(server) = state.set_response_ready(server, 0, True)
  let assert Ok(#(server, _)) = state.start_drain(server, 0)
  let assert Ok(server) = state.abort_stream(server, 0)
  assert state.resource_counts(server) == #(0, 0, 0)
  assert state.next_response_stream(server) == None
  assert state.send_datagram(server, 0, <<1>>)
    == Error(state.DatagramFailure(datagram.UnknownAssociation(0)))
  assert state.drain_phase(server) == drain.ReadyToClose
  assert state.abort_stream(server, 0) == Ok(server)
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn aborting_qpack_blocked_request_releases_backlog_and_feedback_test() -> Nil {
  let #(client, server) = pure_pair()
  let assert Ok(#(client, bytes)) =
    state.open_request(client, 0, headers(), False)
  let assert Ok(#(server, _)) =
    state.receive_request_frame(server, 0, decode(bytes))
  let dynamic = Header(<<"x-indexed">>, <<"bounded">>, False)
  let assert Ok(server) = state.index_field(server, dynamic)
  let assert Ok(#(_, bytes)) =
    state.send_response_headers(
      server,
      0,
      [Header(<<":status">>, <<"200">>, False), dynamic],
      True,
    )
  let assert Ok(#(client, [state.HeadersBlocked(0, 1)])) =
    state.receive_request_frame(client, 0, decode(bytes))
  let assert Ok(#(client, [])) =
    state.receive_request_frame(client, 0, frame.Data(<<1, 2, 3>>))
  assert state.blocked_connection_bytes(client) > 0
  let assert Ok(client) = state.abort_stream(client, 0)
  assert state.resource_counts(client) == #(0, 0, 0)
  assert state.blocked_connection_bytes(client) == 0
  let assert Ok(#(client, Some(state.StreamBytes(10, feedback)))) =
    state.take_qpack_decoder_bytes(client)
  assert instruction.decode_decoder(feedback)
    == Ok(#(instruction.StreamCancellation(0), <<>>))
  let assert Ok(client) = state.abort_stream(client, 0)
  let assert Ok(#(_, None)) = state.take_qpack_decoder_bytes(client)
  Nil
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn abort_before_peer_headers_emits_cancellation_without_inventing_ack_test() -> Nil {
  let #(client, _) = pure_pair()
  let assert Ok(#(client, _)) = state.open_request(client, 0, headers(), False)
  let assert Ok(client) = state.abort_stream(client, 0)
  let assert Ok(#(_, feedback)) = state.take_qpack_decoder_bytes(client)
  assert case feedback {
    Some(state.StreamBytes(10, bytes)) ->
      instruction.decode_decoder(bytes)
      == Ok(#(instruction.StreamCancellation(0), <<>>))
    _ -> False
  }
}
