import gleam/bool
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import http/body
import http/context
import http/diagnostics
import http/error
import http/internal/http2/connection
import http/internal/http2/control
import http/internal/http2/header_codec
import http/internal/http2/header_semantics
import http/internal/http2/wire
import http/internal/transport
import http/resource
import http/server
import http_test_support

pub fn completed_response_cleanup_does_not_block_a_second_http2_stream_test() -> Nil {
  cleanup_isolation(
    completion: Completed,
    maximum_workers: 2,
    teardown: LateReset,
  )
}

pub fn reset_response_cleanup_does_not_block_a_second_http2_stream_test() -> Nil {
  cleanup_isolation(completion: Reset, maximum_workers: 2, teardown: LateReset)
}

pub fn suppressed_response_cleanup_does_not_block_a_second_http2_stream_test() -> Nil {
  cleanup_isolation(
    completion: Suppressed,
    maximum_workers: 2,
    teardown: LateReset,
  )
}

pub fn reset_cleanup_retains_its_admission_while_other_streams_progress_test() -> Nil {
  cleanup_isolation(completion: Reset, maximum_workers: 1, teardown: LateReset)
}

pub fn oversized_response_cleanup_does_not_block_a_second_http2_stream_test() -> Nil {
  cleanup_isolation(
    completion: Oversized,
    maximum_workers: 2,
    teardown: LateReset,
  )
}

pub fn reset_cleanup_and_executor_drain_join_the_source_once_test() -> Nil {
  cleanup_isolation(completion: Reset, maximum_workers: 2, teardown: Drain)
}

pub fn reset_cleanup_and_executor_stop_join_the_source_once_test() -> Nil {
  cleanup_isolation(completion: Reset, maximum_workers: 2, teardown: Stop)
}

type Teardown {
  LateReset
  Drain
  Stop
}

type Completion {
  Completed
  Reset
  Suppressed
  Oversized
}

fn cleanup_isolation(
  completion completion: Completion,
  maximum_workers maximum_workers: Int,
  teardown teardown: Teardown,
) -> Nil {
  let read_started = process.new_subject()
  let read_gate = process.new_subject()
  let cleanup_started = process.new_subject()
  let cleanup_finished = process.new_subject()
  let transferred = process.new_subject()
  let started = process.new_subject()
  let released = process.new_subject()
  let assert Ok(reporter) =
    diagnostics.start(
      maximum_in_flight: 16,
      sink_timeout_milliseconds: 100,
      sink: fn(record) {
        case record.event {
          diagnostics.RequestStarted(id, _) -> process.send(started, id)
          diagnostics.RequestReleased(id, _, outcome, _) ->
            process.send(released, #(id, result.map_error(outcome, error.kind)))
          _ -> Nil
        }
        Ok(Nil)
      },
    )
  let assert Ok(slow) =
    body.from_pull(
      body.pull(fn(_) {
        process.send(read_started, Nil)
        case completion {
          Reset -> process.receive_forever(read_gate)
          Completed | Suppressed | Oversized -> Nil
        }
        case completion {
          Oversized ->
            Ok(body.PullData(
              <<1>>,
              body.pull(fn(_) {
                Ok(body.PullData(
                  <<2>>,
                  body.pull(fn(_) { Ok(body.PullEnd([])) }),
                ))
              }),
            ))
          _ -> Ok(body.PullEnd([]))
        }
      }),
      None,
      None,
      fn() {
        let gate = process.new_subject()
        process.send(cleanup_started, #(process.self(), gate))
        process.receive_forever(gate)
        process.send(cleanup_finished, Nil)
      },
    )
  let slow =
    body.observe_transfer(slow, fn() { Nil }, fn(outcome) {
      process.send(transferred, result.map_error(outcome, error.kind))
    })
  let assert Ok(executor) =
    server.start(
      executor_config(maximum_workers) |> server.with_diagnostics(reporter),
      fn(incoming, _) {
        case incoming.path {
          "/cleanup" ->
            Ok(
              response.new(case completion {
                Suppressed -> 204
                Completed | Reset | Oversized -> 200
              })
              |> response.set_body(slow),
            )
          _ -> Ok(response.new(204) |> response.set_body(body.empty()))
        }
      },
    )
  let #(certificate, key, ca) = http_test_support.server_credentials()
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      listener_config(completion),
      certificate,
      key,
      "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(raw) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(socket, <<"h2":utf8>>, _)) =
    transport.upgrade_client_tls(raw, "localhost", [ca], [<<"h2":utf8>>], 1000)
  let assert Ok(state) =
    wire.new(connection.Client, connection_limits(), wire_limits())
  let assert Ok(wire.Started(state, initial)) = wire.initial_bytes(state, [])
  let assert Ok(Nil) = transport.send(socket, initial)
  let assert Ok(wire.HeadersWritten(state, 1, first)) =
    wire.send_request_headers(
      state,
      outgoing(port, "/cleanup"),
      end_stream: True,
    )
  let assert Ok(Nil) = send_frames(socket, first)
  let assert Ok(first_id) = process.receive(started, within: 1000)
  let read_begun = case completion {
    Suppressed -> process.receive(read_started, within: 0) == Error(Nil)
    Completed | Reset | Oversized ->
      process.receive(read_started, within: 1000) == Ok(Nil)
  }
  let assert Ok(#(socket, state)) =
    await_headers(
      socket:,
      state:,
      stream_id: 1,
      status: case completion {
        Suppressed -> 204
        Completed | Reset | Oversized -> 200
      },
      deadline: transport.monotonic_millisecond() + 1000,
      remaining_reads: 32,
    )
  let state = case completion {
    Reset -> {
      let assert Ok(wire.ControlWritten(state, frames)) =
        wire.reset_stream(state, stream_id: 1, error_code: 8)
      let assert Ok(Nil) = send_frames(socket, frames)
      state
    }
    Completed | Suppressed | Oversized -> state
  }
  let assert Ok(#(cleaner, cleanup_gate)) =
    process.receive(cleanup_started, within: 1000)
  let cleaner_monitor = process.monitor(cleaner)
  let assert Ok(wire.HeadersWritten(state, 3, second)) =
    wire.send_request_headers(state, outgoing(port, "/fast"), end_stream: True)
  let assert Ok(Nil) = send_frames(socket, second)
  let progress =
    await_headers(
      socket:,
      state:,
      stream_id: 3,
      status: case maximum_workers {
        1 -> 503
        _ -> 204
      },
      deadline: transport.monotonic_millisecond() + 500,
      remaining_reads: 32,
    )
  // A timeout killing the callback must not masquerade as stream isolation.
  // The peer receives its response while the first cleanup is still alive and its release gate has never been sent.
  let blocked_during_progress = process.is_alive(cleaner)
  let completed_early = process.receive(cleanup_finished, within: 0)
  let release_pending = body.await_release(slow, 0) == body.ReleasePending
  let transfer = process.receive(transferred, within: 0)
  let shutdown_reply = process.new_subject()
  let shutdown = case teardown {
    LateReset -> None
    Drain | Stop -> {
      let child =
        process.spawn_unlinked(fn() {
          let outcome = case teardown {
            Drain -> server.drain(executor)
            Stop | LateReset -> server.stop(executor)
          }
          process.send(shutdown_reply, outcome)
        })
      Some(#(child, process.monitor(child)))
    }
  }
  let shutdown_started = case teardown {
    LateReset -> True
    Drain | Stop ->
      await_shutdown(executor, transport.monotonic_millisecond() + 500)
  }
  process.send(cleanup_gate, Nil)
  let cleaner_down =
    process.new_selector()
    |> process.select_specific_monitor(cleaner_monitor, fn(_) { Nil })
    |> process.selector_receive(within: 1000)
  process.demonitor_process(cleaner_monitor)
  let release = body.await_release(slow, 1000)
  // RequestReleased is emitted only after the admitted guardian's actual DOWN.
  let guardian_released =
    await_released(released:, expected: first_id, remaining: 8)
  let late_reset = case teardown {
    LateReset -> late_reset_progress(progress, port)
    Drain | Stop -> Ok(Nil)
  }
  let shutdown_joined = case shutdown {
    None -> True
    Some(#(child, monitor)) -> {
      let outcome = process.receive(shutdown_reply, within: 1000)
      let down =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.kill(child)
      process.demonitor_process(monitor)
      outcome == Ok(Ok(Nil)) && down == Ok(Nil)
    }
  }
  let closed = transport.close(socket)
  let listener_stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  let reporter_stopped = diagnostics.stop(reporter)
  body.cancel(slow)
  assert read_begun
  assert result.map(progress, fn(_) { Nil }) == Ok(Nil)
  assert blocked_during_progress
  assert completed_early == Error(Nil)
  assert release_pending
  assert cleaner_down == Ok(Nil)
  assert closed == Ok(Nil)
  assert listener_stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  assert reporter_stopped == Ok(Nil)
  assert guardian_released
  assert late_reset == Ok(Nil)
  assert shutdown_started
  assert shutdown_joined
  assert release == body.Released(Ok(Nil))
  assert process.receive(cleanup_finished, within: 0) == Ok(Nil)
  assert process.receive(cleanup_finished, within: 0) == Error(Nil)
  assert process.receive(cleanup_started, within: 0) == Error(Nil)
  assert process.receive(transferred, within: 0) == Error(Nil)
  assert transfer
    == Ok(case completion {
      Reset -> Error(error.Cancelled)
      Oversized -> Error(error.Body(error.TooLarge(1)))
      Completed | Suppressed -> Ok(Nil)
    })
}

fn await_shutdown(executor: server.Server, deadline: Int) -> Bool {
  case server.state(executor), transport.monotonic_millisecond() < deadline {
    server.Running, True -> {
      process.sleep(1)
      await_shutdown(executor, deadline)
    }
    server.Running, False -> False
    _, _ -> True
  }
}

fn await_released(
  released released: process.Subject(
    #(diagnostics.RequestId, Result(Nil, error.ErrorKind)),
  ),
  expected expected: diagnostics.RequestId,
  remaining remaining: Int,
) -> Bool {
  use <- bool.guard(when: remaining <= 0, return: False)
  case process.receive(released, within: 1000) {
    Ok(#(id, outcome)) if id == expected -> outcome == Ok(Nil)
    Ok(_) -> await_released(released:, expected:, remaining: remaining - 1)
    Error(Nil) -> False
  }
}

fn late_reset_progress(
  progress: Result(#(transport.Socket, wire.State), Int),
  port: Int,
) -> Result(Nil, Int) {
  use pair <- result.try(progress)
  let #(socket, state) = pair
  use reset <- result.try(
    control.encode(control.ResetFrame(8), 1, 16_384) |> result.replace_error(7),
  )
  use _ <- result.try(transport.send(socket, reset) |> result.replace_error(8))
  use written <- result.try(
    wire.send_request_headers(state, outgoing(port, "/fast"), end_stream: True)
    |> result.replace_error(9),
  )
  let wire.HeadersWritten(state, stream_id, frames) = written
  use _ <- result.try(send_frames(socket, frames))
  await_headers(
    socket:,
    state:,
    stream_id:,
    status: 204,
    deadline: transport.monotonic_millisecond() + 1000,
    remaining_reads: 32,
  )
  |> result.map(fn(_) { Nil })
}

fn listener_config(completion: Completion) -> server.Http2Config {
  case completion {
    Oversized -> {
      let assert Ok(config) =
        server.with_http2_body_limits(
          server.http2_defaults(),
          maximum_body_bytes: 1,
          maximum_stream_buffer_bytes: 1,
        )
      config
    }
    _ -> server.http2_defaults()
  }
}

fn executor_config(maximum_workers: Int) -> server.Config {
  let assert Ok(limits) = resource.limits(maximum_workers:, memory_bytes: 4096)
  let assert Ok(config) =
    server.with_resource_limits(
      server.defaults(),
      limits,
      worker_memory_bytes: 64,
    )
  config
}

fn outgoing(port: Int, path: String) -> request.Request(body.Body) {
  request.new()
  |> request.set_host("localhost")
  |> request.set_port(port)
  |> request.set_path(path)
  |> request.set_body(body.empty())
}

fn await_headers(
  socket socket: transport.Socket,
  state state: wire.State,
  stream_id stream_id: Int,
  status status: Int,
  deadline deadline: Int,
  remaining_reads remaining_reads: Int,
) -> Result(#(transport.Socket, wire.State), Int) {
  let remaining = deadline - transport.monotonic_millisecond()
  use <- bool.guard(
    when: remaining <= 0 || remaining_reads <= 0,
    return: Error(1),
  )
  use received <- result.try(
    transport.read(socket, 65_536, remaining) |> result.replace_error(2),
  )
  case received {
    transport.ReadEnd(_) -> Error(3)
    transport.ReadData(bytes, socket) -> {
      use fed <- result.try(wire.feed(state, bytes) |> result.replace_error(4))
      let wire.Fed(state, actions) = fed
      use automatic <- result.try(
        wire.automatic_writes(actions, 16_384) |> result.replace_error(5),
      )
      use _ <- result.try(send_frames(socket, automatic))
      case
        list.any(actions, fn(action) { matches(action:, stream_id:, status:) })
      {
        True -> Ok(#(socket, state))
        False ->
          await_headers(
            socket:,
            state:,
            stream_id:,
            status:,
            deadline:,
            remaining_reads: remaining_reads - 1,
          )
      }
    }
  }
}

fn matches(
  action action: connection.Action,
  stream_id stream_id: Int,
  status status: Int,
) -> Bool {
  case action {
    connection.HeadersReceived(header_codec.HeaderSection(
      actual_stream,
      ended,
      header_semantics.Validated(
        header_semantics.ResponseControlData(actual_status),
        _,
        _,
      ),
      _,
    )) ->
      actual_stream == stream_id
      && actual_status == status
      && { stream_id != 3 || status == 503 || ended }
    _ -> False
  }
}

fn send_frames(
  socket: transport.Socket,
  frames: List(BitArray),
) -> Result(Nil, Int) {
  case frames {
    [] -> Ok(Nil)
    [frame, ..rest] -> {
      use _ <- result.try(
        transport.send(socket, frame) |> result.replace_error(6),
      )
      send_frames(socket, rest)
    }
  }
}

fn connection_limits() -> connection.Limits {
  connection.Limits(
    maximum_outstanding_settings: 4,
    maximum_debug_bytes: 64,
    maximum_active_streams: 16,
    header_limits: header_codec.Limits(
      maximum_block_bytes: 4096,
      maximum_header_list_bytes: 8192,
      maximum_table_capacity: 4096,
      maximum_tracked_streams: 16,
    ),
  )
}

fn wire_limits() -> wire.Limits {
  wire.Limits(
    maximum_frame_bytes: 16_384,
    maximum_feed_bytes: 65_536,
    maximum_frames_per_feed: 32,
  )
}
