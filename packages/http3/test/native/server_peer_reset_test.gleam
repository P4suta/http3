import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import http3/config
import http3/failure
import http3/internal/native/frame
import http3/internal/qpack/field_section
import http3/server
import http3_test_support
import quic_core
import quic_core/client as core_client
import quic_core/config as core_config
import quic_core/failure as core_failure

// nolint: unused_exports -- EUnit discovers this real public-core peer case.
pub fn peer_reset_reclaims_response_and_accepts_later_requests_test() -> Nil {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let limits =
    config.with_limit(config.default_limits(), failure.BidirectionalStreams, 2)
    |> known
  let configured =
    server.new(certificate, key)
    |> known
    |> server.with_address_family(config.Ipv4)
    |> server.with_limits(limits)
  let listener =
    server.with_timeout(configured, 1000) |> known |> server.start |> known
  let port = server.port(listener) |> known
  let deadlines =
    core_config.with_deadline(
      core_config.default_deadlines(),
      core_failure.Operation,
      1000,
    )
    |> known
  let connection =
    core_client.new_with_ca_certificates_der("localhost", port, "h3", [ca])
    |> known
    |> core_client.with_address_family(quic_core.Ipv4)
    |> core_client.with_deadlines(deadlines)
    |> core_client.connect
    |> known_stage(1071)
  list.each([<<0, 4, 0>>, <<2>>, <<3>>], fn(preface) {
    let control = core_client.open_unidirectional(connection) |> known
    core_client.send(control, preface) |> known
  })
  let headers = request_headers(port: port)
  let observations =
    list.try_map([0x10c, 0x123, 0x10c, 0x123], fn(code) {
      case
        reset_exchange(
          listener: listener,
          connection: connection,
          headers: headers,
          code: code,
        )
      {
        True -> Ok(Nil)
        False -> Error(Nil)
      }
    })
  let reused = case observations {
    Ok(_) -> reuse(listener: listener, connection: connection, headers: headers)
    Error(Nil) -> False
  }
  let closed = core_client.close(connection)
  let stopped = server.stop(listener)
  assert observations == Ok([Nil, Nil, Nil, Nil])
  assert reused
  assert result.is_ok(closed) && result.is_ok(stopped)
}

// nolint: unused_exports -- EUnit discovers this public wire-order test.
pub fn peer_stop_then_websocket_close_fin_retires_each_direction_once_test() -> Nil {
  run_peer_stop_then_close(False)
  run_peer_stop_then_close(True)
}

fn run_peer_stop_then_close(pre_register_waiter: Bool) -> Nil {
  let #(certificate, key, ca) = http3_test_support.server_credentials()
  let limits =
    config.with_limit(config.default_limits(), failure.Queue, 1)
    |> known_stage(101)
  let listener =
    server.new(certificate, key)
    |> known_stage(102)
    |> server.with_address_family(config.Ipv4)
    |> server.with_limits(limits)
    |> server.with_timeout(1000)
    |> known_stage(103)
    |> server.start
    |> known_stage(104)
  let port = server.port(listener) |> known_stage(105)
  let deadlines =
    core_config.with_deadline(
      core_config.default_deadlines(),
      core_failure.Operation,
      1000,
    )
    |> known_stage(106)
  let connection =
    core_client.new_with_ca_certificates_der("localhost", port, "h3", [ca])
    |> known_stage(107)
    |> core_client.with_address_family(quic_core.Ipv4)
    |> core_client.with_deadlines(deadlines)
    |> core_client.connect
    |> known
  list.each([client_control_preface(), <<2>>, <<3>>], fn(preface) {
    let control =
      core_client.open_unidirectional(connection) |> known_stage(108)
    core_client.send(control, preface) |> known_stage(109)
  })

  let stream = core_client.open_bidirectional(connection) |> known_stage(110)
  core_client.send(stream, websocket_request_headers(port))
  |> known_stage(111)
  let incoming = server.accept(listener) |> known_stage(112)
  let response_started = server.send_response(incoming, 200, []) == Ok(Nil)
  let response_observed = case core_client.receive(stream, 65_536) {
    Ok(core_client.Data(bytes, False)) -> bit_array.byte_size(bytes) > 0
    _ -> False
  }

  // STOP_SENDING is a wire-level synchronization point.
  // It closes only the server's response direction; request bytes sent after this barrier remain independently deliverable.
  let stopped = core_client.stop_sending(stream, 0x10c) == Ok(Nil)
  let completion =
    server.await_response_completion(incoming)
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x10c))))
  let mid = await_response_stopped(incoming, 100)
  let send_resources = server.send_resource_stats(incoming) |> known_stage(113)
  let response_reset = case core_client.receive(stream, 65_536) {
    Ok(core_client.Reset(code)) | Error(core_client.StreamReset(code)) ->
      code == 0x10c
    _ -> False
  }

  let waiter = case pre_register_waiter {
    False -> None
    True ->
      Some(http3_test_support.start_task(fn() { server.next_event(incoming) }))
  }
  let waiter_registered = case waiter {
    None -> True
    Some(_) -> await_event_waiter(incoming, 100).6
  }
  let close_wire = <<0x88, 0x82, 1, 2, 3, 4, 2, 0xea>>
  let close_data = frame.Data(close_wire) |> frame.encode |> known_stage(114)
  core_client.send_and_finish(stream, close_data) |> known_stage(115)
  // With no waiter, both terminal wire events must be retained even though the one configured DATA slot is occupied.
  // With a waiter, Close is handed off directly and End remains in the independent terminal slot.
  let retained =
    await_retained_terminal_events(
      incoming,
      case waiter {
        None -> 2
        Some(_) -> 1
      },
      100,
    )
  let retained_resources =
    server.terminal_delivery_stats(incoming) |> known_stage(116)
  let close_delivered = case waiter {
    None -> server.next_event(incoming) == Ok(server.Data(close_wire))
    Some(task) ->
      http3_test_support.await_task(task) == Ok(server.Data(close_wire))
  }
  let end_delivered = server.next_event(incoming) == Ok(server.End)
  let peer_terminal =
    server.next_event(incoming)
    == Error(server.Failure(failure.Closed(failure.Peer, Some(0x10c))))
  let final = await_terminal_retirement(incoming, 100)
  let final_delivery =
    server.terminal_delivery_stats(incoming) |> known_stage(117)
  let closed = core_client.close(connection)
  let listener_stopped = server.stop(listener)

  assert response_started
  assert response_observed
  assert stopped && completion && response_reset
  assert mid.0 && !mid.1 && mid.2 && mid.3 == Some(0x10c)
  assert send_resources.0 == 0 && send_resources.1 == 0
  assert waiter_registered && !retained.0
  assert retained_resources.0 == 1
  assert retained_resources.1
    == case waiter {
      None -> 2
      Some(_) -> 1
    }
  assert retained_resources.2
    == case waiter {
      None -> bit_array.byte_size(close_wire)
      Some(_) -> 0
    }
  assert close_delivered && end_delivered && peer_terminal
  assert !final.0 && final.5 == 0
  assert final_delivery.0 == 0 && final_delivery.1 == 0 && final_delivery.2 == 0
  assert result.is_ok(closed) && result.is_ok(listener_stopped)
}

fn reuse(
  listener listener: server.Listener,
  connection connection: core_client.Connection,
  headers headers: BitArray,
) -> Bool {
  let stream = core_client.open_bidirectional(connection) |> known
  core_client.send_and_finish(stream, headers) |> known
  let incoming = server.accept(listener) |> known
  let request_ended = server.next_event(incoming) == Ok(server.End)
  let response_sent = server.respond(incoming, 204, [], <<>>) == Ok(Nil)
  let response_ended = receive_finished(stream: stream, remaining: 4)
  let acknowledged = server.await_response_completion(incoming) == Ok(Nil)
  let _barrier = server.request_state_stats(incoming) |> known
  let final = server.request_state_stats(incoming) |> known
  request_ended
  && response_sent
  && response_ended
  && acknowledged
  && final.0 == 0
  && final.2 <= 6
  && final.5 <= 3
  && final.6 == 0
  && final.7 == 0
  && final.8 == 0
}

fn reset_exchange(
  listener listener: server.Listener,
  connection connection: core_client.Connection,
  headers headers: BitArray,
  code code: Int,
) -> Bool {
  let stream = core_client.open_bidirectional(connection) |> known
  core_client.send(stream, headers) |> known
  let incoming = server.accept(listener) |> known
  let sent = server.send_response(incoming, 200, []) == Ok(Nil)
  let head = case core_client.receive(stream, 65_536) {
    Ok(core_client.Data(bytes, False)) -> bit_array.byte_size(bytes) > 0
    _ -> False
  }
  // The ordinary public-core call cancels both directions.
  // The retained RESET-only peer experiment omits only its generated STOP_SENDING frame;
  // this same assertion then requires the H3 adapter's real response abort.
  let reset = core_client.reset(stream, code) == Ok(Nil)
  let received =
    server.next_event(incoming)
    == Error(server.Failure(failure.Closed(failure.Peer, Some(code))))
  let response_aborted = case core_client.receive(stream, 65_536) {
    Ok(core_client.Reset(observed))
    | Error(core_client.StreamReset(observed)) -> observed == code
    _ -> False
  }
  let barrier = server.request_state_stats(incoming) |> result.is_ok
  let reclaimed = case server.request_state_stats(incoming) {
    Ok(stats) ->
      stats.0 == 0
      && stats.2 <= 6
      && stats.5 <= 3
      && stats.6 == 0
      && stats.7 == 0
      && stats.8 == 0
    // nolint: thrown_away_error -- The observation retains only cleanup success.
    Error(_) -> False
  }
  sent && head && reset && received && response_aborted && barrier && reclaimed
}

fn receive_finished(
  stream stream: core_client.Stream,
  remaining remaining: Int,
) -> Bool {
  case remaining {
    0 -> False
    _ ->
      case core_client.receive(stream, 65_536) {
        Ok(core_client.Finished) | Ok(core_client.Data(_, True)) -> True
        Ok(core_client.Data(_, False)) ->
          receive_finished(stream: stream, remaining: remaining - 1)
        _ -> False
      }
  }
}

fn request_headers(port port: Int) -> BitArray {
  let fields =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 17),
      field_section.Indexed(True, 23),
      field_section.Indexed(True, 1),
      field_section.LiteralNameReference(
        False,
        True,
        0,
        bit_array.from_string("localhost:" <> int.to_string(port)),
      ),
    ])
    |> field_section.encode(False)
    |> known
  frame.encode(frame.Headers(fields)) |> known
}

fn client_control_preface() -> BitArray {
  let settings = frame.Settings([frame.Setting(8, 1)]) |> frame.encode |> known
  <<0, settings:bits>>
}

fn websocket_request_headers(port: Int) -> BitArray {
  let authority = bit_array.from_string("localhost:" <> int.to_string(port))
  let fields =
    field_section.Section(field_section.Prefix(0, False, 0), [
      field_section.Indexed(True, 15),
      field_section.LiteralLiteralName(False, <<":protocol">>, <<"websocket">>),
      field_section.Indexed(True, 23),
      field_section.LiteralNameReference(False, True, 0, authority),
      field_section.Indexed(True, 1),
      field_section.LiteralLiteralName(False, <<"sec-websocket-version">>, <<
        "13",
      >>),
    ])
    |> field_section.encode(False)
    |> known
  frame.encode(frame.Headers(fields)) |> known
}

fn await_response_stopped(
  incoming: server.Request,
  remaining: Int,
) -> #(Bool, Bool, Bool, Option(Int), Int, Int, Bool) {
  let snapshot = server.request_lifecycle_stats(incoming) |> known
  case snapshot.0 && snapshot.2 && snapshot.3 == Some(0x10c), remaining > 0 {
    True, _ -> snapshot
    False, True -> {
      process.sleep(5)
      await_response_stopped(incoming, remaining - 1)
    }
    False, False -> snapshot
  }
}

fn await_event_waiter(
  incoming: server.Request,
  remaining: Int,
) -> #(Bool, Bool, Bool, Option(Int), Int, Int, Bool) {
  let snapshot = server.request_lifecycle_stats(incoming) |> known
  case snapshot.6, remaining > 0 {
    True, _ -> snapshot
    False, True -> {
      process.sleep(5)
      await_event_waiter(incoming, remaining - 1)
    }
    False, False -> snapshot
  }
}

fn await_retained_terminal_events(
  incoming: server.Request,
  expected: Int,
  remaining: Int,
) -> #(Bool, Bool, Bool, Option(Int), Int, Int, Bool) {
  let snapshot = server.request_lifecycle_stats(incoming) |> known
  case !snapshot.0 && snapshot.5 == expected, remaining > 0 {
    True, _ -> snapshot
    False, True -> {
      process.sleep(5)
      await_retained_terminal_events(incoming, expected, remaining - 1)
    }
    False, False -> snapshot
  }
}

fn await_terminal_retirement(
  incoming: server.Request,
  remaining: Int,
) -> #(Bool, Bool, Bool, Option(Int), Int, Int, Bool) {
  let snapshot = server.request_lifecycle_stats(incoming) |> known
  case !snapshot.0 && snapshot.5 == 0, remaining > 0 {
    True, _ -> snapshot
    False, True -> {
      process.sleep(5)
      await_terminal_retirement(incoming, remaining - 1)
    }
    False, False -> snapshot
  }
}

// Fixtures fail with no opaque handle, credential, payload, or raw error value.
fn known(outcome: Result(value, error)) -> value {
  case outcome {
    Ok(value) -> value
    // nolint: thrown_away_error -- Fixtures deliberately redact runtime values.
    Error(_) -> http3_test_support.fail(Nil)
  }
}

fn known_stage(outcome: Result(value, error), stage: Int) -> value {
  result.lazy_unwrap(outcome, fn() { http3_test_support.fail(stage) })
}
