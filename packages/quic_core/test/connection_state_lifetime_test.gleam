import gleam/list
import gleam/option.{None, Some}
import quic_core/frame
import quic_core/internal/connection_id
import quic_core/internal/connection_state as connection
import quic_core/internal/packet_space
import quic_core/internal/stream_state
import quic_core/internal/tls/engine
import quic_core/internal/tls/hello
import quic_core/internal/traffic_keys
import quic_core/transport_parameter
import quic_core/version

// RFC 9000 sections 10.2.2 and 10.3.1: a reset enters silent draining;
// repeated input cannot turn the finite disposal period into a sliding timer.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn repeated_stateless_reset_keeps_the_original_deadline_test() -> Nil {
  let state = with_reset_token()
  let assert Ok(#(state, True)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(7), 10)
  assert connection.next_deadline(state, 10) == Ok(Some(110))
  let #(state, _) = connection.take_events(state)
  let assert Ok(#(state, _)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(7), 109)
  assert connection.next_deadline(state, 109) == Ok(Some(110))
  let #(state, events) = connection.take_events(state)
  assert events == []
  let assert Ok(state) = connection.tick(state, 110)
  assert connection.phase(state) == connection.Closed
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn stateless_reset_does_not_extend_local_closing_test() -> Nil {
  let state = with_reset_token()
  let assert Ok(state) = connection.close(state, 0, "", 10)
  let assert Ok(#(state, True)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(7), 109)
  assert connection.phase(state) == connection.Draining
  assert connection.next_deadline(state, 109) == Ok(Some(110))
  let silent =
    connection.prepare_packet(state, engine.OneRtt, 1200, 109)
    == Error(connection.ConnectionUnavailable)
  assert silent
}

// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_closed_connection_cannot_be_revived_by_a_reset_token_test() -> Nil {
  let state = with_reset_token()
  let assert Ok(state) = connection.close(state, 0, "", 10)
  let assert Ok(state) = connection.tick(state, 110)
  let #(state, _) = connection.take_events(state)
  let assert Ok(#(state, _)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(7), 111)
  assert connection.phase(state) == connection.Closed
  assert connection.next_deadline(state, 111) == Ok(None)
  let #(_, events) = connection.take_events(state)
  assert events == []
}

// RFC 9000 sections 3.2 and 4.4: Reset Read is terminal for receiving,
// while the unreset sending direction of a bidirectional stream remains usable.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_read_reset_cannot_be_delivered_again_test() -> Nil {
  let state = established()
  let state = receive(state, 0, [frame.ResetStream(1, 0x101, 4)])
  let assert Ok(#(state, reset)) = connection.read_stream(state, 1, 16)
  assert connection.read_reset_code(reset) == Some(0x101)
  let #(state, _) = connection.take_events(state)
  let state = receive(state, 1, [frame.ResetStream(1, 0x102, 4)])
  let #(state, events) = connection.take_events(state)
  let assert Ok(#(state, completed)) = connection.read_stream(state, 1, 16)
  assert_finished(completed)
  assert !list.any(events, is_reset_event)
  let assert Ok(state) = connection.queue_stream(state, 1, <<1, 2, 3>>, True)
  assert connection.stream_buffered_send_bytes(state, 1) == Ok(3)
}

// A successfully delivered FIN is terminal too; a delayed matching-size RESET_STREAM cannot retroactively replace that application-visible outcome.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_read_fin_cannot_be_replaced_by_a_late_reset_test() -> Nil {
  let state = receive(established(), 0, [frame.Stream(1, 0, <<42>>, True)])
  let assert Ok(#(state, data)) = connection.read_stream(state, 1, 16)
  assert connection.read_data(data) == Some(#(<<42>>, True))
  let state = receive(state, 1, [frame.ResetStream(1, 0x101, 1)])
  let assert Ok(#(_, completed)) = connection.read_stream(state, 1, 16)
  assert_finished(completed)
}

// RFC 9000 section 4.5: retaining the terminal receive state also retains its final-size check.
// Ignoring a late reset must not hide a conflicting offset.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn a_late_reset_still_validates_the_known_final_size_test() -> Nil {
  let state = receive(established(), 0, [frame.ResetStream(1, 0x101, 4)])
  let assert Ok(#(state, _)) = connection.read_stream(state, 1, 16)
  assert connection.receive_packet(
      state,
      engine.OneRtt,
      1,
      [frame.ResetStream(1, 0x102, 5)],
      packet_space.NotEct,
      2,
    )
    == Error(connection.StreamQueueFailure(stream_state.FinalSizeFailure))
}

// RFC 9000 sections 4.4/4.5: sparse offsets and the RESET_STREAM final size consume connection credit, even when the missing payload never arrived.
// Reading that reset returns the consumed credit once and releases the buffer.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn reset_final_size_reclaims_sparse_payload_and_credit_once_test() -> Nil {
  let state = established()
  let credit = connection.outstanding_receive_credit(state)
  let state = receive(state, 0, [frame.Stream(1, 12, <<1, 2, 3, 4>>, False)])
  let retained = connection.retained_bytes(state)
  let sparse_limit_enforced =
    connection.receive_packet(
      state,
      engine.OneRtt,
      1,
      [frame.Stream(5, 16, <<1>>, False)],
      packet_space.NotEct,
      2,
    )
    == Error(connection.FlowControlFailure)
  assert sparse_limit_enforced
  let state = receive(state, 1, [frame.ResetStream(1, 0x101, 32)])
  let final_size_enforced =
    connection.receive_packet(
      state,
      engine.OneRtt,
      2,
      [frame.Stream(5, 0, <<1>>, False)],
      packet_space.NotEct,
      3,
    )
    == Error(connection.FlowControlFailure)
  assert final_size_enforced
  assert connection.retained_bytes(state) == retained - 4
  let assert Ok(#(state, reset)) = connection.read_stream(state, 1, 16)
  assert connection.read_reset_code(reset) == Some(0x101)
  assert connection.outstanding_receive_credit(state) == credit
  let granted = connection.advertised_max_data(state)
  assert granted == credit + 32
  let state = receive(state, 2, [frame.ResetStream(1, 0x101, 32)])
  let assert Ok(#(state, completed)) = connection.read_stream(state, 1, 16)
  assert_finished(completed)
  assert connection.advertised_max_data(state) == granted
}

// RFC 9000 section 10.3.1: retiring a destination ID also retires its reset token.
// Reordered copies of NEW_CONNECTION_ID cannot restore its authority.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retired_peer_id_cannot_regain_reset_authority_test() -> Nil {
  let state = with_reset_token()
  let replacement = frame.NewConnectionId(1, 1, <<1:64>>, <<8:128>>)
  let state = receive(state, 0, [replacement])
  let #(state, _) = connection.take_events(state)
  let state = receive(state, 1, [replacement])
  let #(state, events) = connection.take_events(state)
  assert events == []
  assert connection.current_peer_connection_id(state) == Ok(<<1:64>>)
  let assert Ok(#(state, False)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(7), 3)
  assert connection.phase(state) == connection.Established
  let assert Ok(#(state, True)) =
    connection.handle_stateless_reset_candidate(state, reset_packet(8), 4)
  assert connection.phase(state) == connection.Draining
}

// A duplicated reset must not replace the first pending application cause or publish another wakeup while the caller has not yet read the first one.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn pending_reset_preserves_its_first_cause_without_duplicate_wakeups_test() -> Nil {
  let state = receive(established(), 0, [frame.ResetStream(1, 0x101, 4)])
  let #(state, _) = connection.take_events(state)
  let state = receive(state, 1, [frame.ResetStream(1, 0x102, 4)])
  let #(state, events) = connection.take_events(state)
  assert events == []
  let assert Ok(#(_, reset)) = connection.read_stream(state, 1, 16)
  assert connection.read_reset_code(reset) == Some(0x101)
}

// RFC 9000 sections 5.1.1/5.1.2 prohibit reusing identifiers or reset tokens.
// The bounded history enforcing that rule is retained after retirement and therefore must remain part of the endpoint's variable resident footprint.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn retired_peer_connection_id_history_remains_charged_test() -> Nil {
  let state = with_reset_token()
  let initial = connection.retained_bytes(state)
  let first = frame.NewConnectionId(1, 1, <<1:64>>, <<8:128>>)
  let state = receive(state, 0, [first])
  let one = connection.retained_bytes(state)
  assert one >= initial + 24
  let state =
    receive(state, 1, [frame.NewConnectionId(2, 2, <<2:64>>, <<9:128>>)])
  let two = connection.retained_bytes(state)
  assert two >= one + 24
  let state = receive(state, 2, [first])
  assert connection.retained_bytes(state) == two
  assert connection.current_peer_connection_id(state) == Ok(<<2:64>>)
}

// A peer cannot spend receive-window promises on its CID metadata.
// New history needs fresh room; repeated, already-known records still work under refusal.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_id_history_requires_memory_before_growth_test() -> Nil {
  let initial = with_reset_token()
  let promised = connection.outstanding_receive_credit(initial)
  let #(limited, _) = connection.apply_memory_grant(initial, promised, True)
  let first = frame.NewConnectionId(1, 1, <<1:64>>, <<8:128>>)
  let failure =
    connection.receive_packet(
      limited,
      engine.OneRtt,
      0,
      [first],
      packet_space.NotEct,
      1,
    )
  let refused =
    failure
    == Error(connection.ConnectionIdFailure(connection_id.HistoryMemoryExceeded))
  assert refused
  let #(granted, _) =
    connection.apply_memory_grant(limited, promised + 4096, False)
  let accepted = receive(granted, 0, [first])
  let #(limited, measured) =
    connection.apply_memory_grant(accepted, promised, True)
  assert measured >= 24
  let repeated = receive(limited, 1, [first])
  assert connection.retained_bytes(repeated) == measured
  let second =
    connection.receive_packet(
      repeated,
      engine.OneRtt,
      2,
      [frame.NewConnectionId(2, 2, <<2:64>>, <<9:128>>)],
      packet_space.NotEct,
      3,
    )
  let refused_again =
    second
    == Error(connection.ConnectionIdFailure(connection_id.HistoryMemoryExceeded))
  assert refused_again
}

// Metadata exhaustion is a local resource failure (RFC 9000 section 20),
// Buffered receive bytes already occupy the outstanding promise.
// A grant at the measured history boundary must fund exactly one maximum-size ID without charging those unread bytes twice or silently admitting a second ID.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_id_grant_boundary_preserves_buffered_receive_promises_test() -> Nil {
  let initial = with_reset_token()
  let first = frame.NewConnectionId(1, 1, <<1:160>>, <<8:128>>)
  let measured = receive(initial, 0, [first])
  let growth =
    connection.retained_bytes(measured) - connection.retained_bytes(initial)
  assert growth >= 36
  let buffered = receive(initial, 0, [frame.Stream(1, 0, <<0:64>>, False)])
  let promised = connection.outstanding_receive_credit(buffered)
  let #(below, _) =
    connection.apply_memory_grant(buffered, promised + growth - 1, False)
  let refused =
    connection.receive_packet(
      below,
      engine.OneRtt,
      1,
      [first],
      packet_space.NotEct,
      2,
    )
    == Error(connection.ConnectionIdFailure(connection_id.HistoryMemoryExceeded))
  assert refused
  let #(funded, _) =
    connection.apply_memory_grant(buffered, promised + growth, False)
  let funded = receive(funded, 1, [first])
  assert connection.retained_bytes(funded) == growth + 8
  let assert Ok(#(funded, data)) = connection.read_stream(funded, 1, 8)
  assert connection.read_data(data) == Some(#(<<0:64>>, False))
  assert connection.retained_bytes(funded) == growth
  let #(funded, _) =
    connection.apply_memory_grant(funded, promised + growth, False)
  let refused =
    connection.receive_packet(
      funded,
      engine.OneRtt,
      2,
      [frame.NewConnectionId(2, 2, <<2:160>>, <<9:128>>)],
      packet_space.NotEct,
      3,
    )
    == Error(connection.ConnectionIdFailure(connection_id.HistoryMemoryExceeded))
  assert refused
}

// Metadata exhaustion is a local resource failure (RFC 9000 section 20),
// distinct from an invalid peer CID or an advertised active-ID limit breach.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn peer_id_memory_refusal_emits_a_resource_close_test() -> Nil {
  let initial = with_reset_token()
  let #(limited, _) = connection.apply_memory_grant(initial, 32, True)
  let refusal =
    connection.ConnectionIdFailure(connection_id.HistoryMemoryExceeded)
  let assert Ok(closing) =
    connection.reject_authenticated_packet(limited, engine.OneRtt, refusal, 1)
  assert connection.local_transport_failure_code(closing) == Some(0x01)
  let assert Ok(connection.PacketPrepared(_, _, _, frames)) =
    connection.prepare_packet(closing, engine.OneRtt, 1200, 1)
  let resource_close =
    list.any(frames, fn(value) {
      case value {
        frame.ConnectionCloseTransport(0x01, _, "") -> True
        _ -> False
      }
    })
  assert resource_close
}

// Expanding MAX_DATA must leave the explicitly funded control allowance usable for a subsequent peer-ID update, before another endpoint grant can arrive.
// nolint: unused_exports -- gleeunit discovers public test functions by suffix.
pub fn advertised_receive_window_preserves_funded_control_headroom_test() -> Nil {
  let assert Ok(initial) =
    connection.initialize_peer_connection_id(
      established_with_window(512),
      <<0:64>>,
      <<7:128>>,
    )
  let #(funded, _) =
    connection.apply_memory_grant_with_control_headroom(
      initial,
      512,
      False,
      256,
    )
  let received = receive(funded, 0, [frame.Stream(1, 0, <<0:256>>, False)])
  let assert Ok(#(consumed, data)) = connection.read_stream(received, 1, 32)
  assert connection.read_data(data) == Some(#(<<0:256>>, False))
  assert connection.advertised_max_data(consumed) > 32
  assert connection.outstanding_receive_credit(consumed) <= 256
  let updated =
    receive(consumed, 1, [frame.NewConnectionId(1, 1, <<1:160>>, <<8:128>>)])
  assert connection.retained_bytes(updated)
    + connection.outstanding_receive_credit(updated)
    <= 512
}

fn established() -> connection.State {
  established_with_window(32)
}

fn established_with_window(window: Int) -> connection.State {
  let config =
    connection.Config(
      ..connection.default_config(connection.Client),
      initial_receive_data: 32,
      receive_data_window: window,
      draining_timeout_milliseconds: 100,
    )
  let assert Ok(state) = connection.new(config, 0)
  let assert Ok(keys) =
    traffic_keys.from_secret(version.Version1, hello.Aes128GcmSha256, <<0:256>>)
  let assert Ok(state) =
    connection.apply_tls_actions(state, [
      engine.InstallWriteKeys(engine.OneRtt, keys),
      engine.InstallReadKeys(engine.OneRtt, keys),
      engine.PeerTransportParameters([
        transport_parameter.InitialMaxData(4096),
        transport_parameter.InitialMaxStreamDataBidiLocal(1024),
        transport_parameter.InitialMaxStreamDataBidiRemote(1024),
        transport_parameter.InitialMaxStreamsBidi(4),
      ]),
      engine.HandshakeComplete,
    ])
  let #(state, _) = connection.take_events(state)
  state
}

fn with_reset_token() -> connection.State {
  let assert Ok(state) =
    connection.initialize_peer_connection_id(established(), <<0:64>>, <<7:128>>)
  state
}

fn reset_packet(token: Int) -> BitArray {
  <<1, 2, 3, 4, 5, token:128>>
}

fn receive(
  state: connection.State,
  packet_number: Int,
  frames: List(frame.Frame),
) -> connection.State {
  let assert Ok(state) =
    connection.receive_packet(
      state,
      engine.OneRtt,
      packet_number,
      frames,
      packet_space.NotEct,
      packet_number + 1,
    )
  state
}

fn is_reset_event(event: connection.Event) -> Bool {
  case event {
    connection.StreamWasReset(_, _) -> True
    _ -> False
  }
}

fn assert_finished(outcome: stream_state.ReadOutcome) -> Nil {
  let finished = connection.read_is_finished(outcome)
  assert finished
}
