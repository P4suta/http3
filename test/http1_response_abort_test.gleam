import gleam/bit_array
import gleam/bool
import gleam/erlang/process
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import http/body
import http/internal/transport
import http/server
import http_test_support

pub fn peer_close_joins_a_blocked_http1_response_pull_test() -> Nil {
  interrupted_response(PeerClose)
}

pub fn listener_stop_joins_a_blocked_http1_response_pull_test() -> Nil {
  interrupted_response(ListenerStop)
}

pub fn request_half_close_preserves_a_blocked_http1_response_test() -> Nil {
  interrupted_response(HalfClose)
}

pub fn pipelined_input_during_a_blocked_response_is_preserved_test() -> Nil {
  interrupted_response(Pipelined)
}

type Interruption {
  PeerClose
  ListenerStop
  HalfClose
  Pipelined
}

fn interrupted_response(interruption: Interruption) -> Nil {
  let entered = process.new_subject()
  let cleaned = process.new_subject()
  let stalled =
    body.pull(fn(_) {
      let gate = process.new_subject()
      process.send(entered, #(process.self(), gate))
      process.receive_forever(gate)
      Ok(body.PullEnd([]))
    })
  let outgoing =
    body.from_pull(
      body.pull(fn(_) { Ok(body.PullData(<<"response-prefix">>, stalled)) }),
      None,
      None,
      fn() { process.send(cleaned, Nil) },
    )
    |> require_ok
  let executor =
    server.start(server.defaults(), fn(request, _) {
      let source = case request.path {
        "/second" -> body.from_text("second-response")
        _ -> outgoing
      }
      Ok(response.new(200) |> response.set_body(source))
    })
    |> require_ok
  let config =
    server.with_http1_timeouts(
      server.http1_defaults() |> server.allow_http1_cleartext,
      idle_milliseconds: 5000,
      operation_milliseconds: 5000,
      tls_milliseconds: 5000,
      drain_milliseconds: 1000,
      send_milliseconds: 1000,
    )
    |> require_ok
  let #(certificate, private_key, ca) = http_test_support.server_credentials()
  let listener =
    case interruption {
      HalfClose | Pipelined ->
        server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
      _ ->
        server.listen_http1_tls(
          executor,
          <<127, 0, 0, 1>>,
          0,
          config,
          certificate,
          private_key,
          "localhost",
        )
    }
    |> require_ok
  let endpoint = server.listener_endpoint(listener)
  let socket =
    transport.connect("127.0.0.1", endpoint.port, 1000, 1000)
    |> require_ok
  let socket = case interruption {
    HalfClose | Pipelined -> socket
    _ -> {
      let transport.TlsReady(socket, _, _) =
        transport.upgrade_client_tls(
          socket,
          "localhost",
          [ca],
          [<<"http/1.1":utf8>>],
          1000,
        )
        |> require_ok
      socket
    }
  }
  let Nil =
    transport.send(socket, <<"GET /abort HTTP/1.1\r\nHost: localhost\r\n\r\n">>)
    |> require_ok
  // This second-pull barrier proves response headers and the first body chunk were written before the interruption, without a scheduling sleep.
  let #(producer, gate) = process.receive(entered, within: 1000) |> require_ok
  let monitor = process.monitor(producer)
  let stopped = case interruption {
    PeerClose -> {
      let Nil = transport.close(socket) |> require_ok
      None
    }
    ListenerStop -> {
      let task =
        http_test_support.start_task(fn() { server.stop_listener(listener) })
      Some(task)
    }
    HalfClose -> {
      let Nil = transport.shutdown_write(socket) |> require_ok
      None
    }
    Pipelined -> {
      let Nil =
        transport.send(socket, <<
          "GET /second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        >>)
        |> require_ok
      None
    }
  }
  let continued = case interruption {
    HalfClose | Pipelined -> {
      process.send(gate, Nil)
      let wire = read_until_closed(socket: socket, bytes: <<>>, budget: 16)
      case wire {
        Ok(text) ->
          string.contains(text, "response-prefix")
          && case interruption {
            Pipelined -> string.contains(text, "second-response")
            _ -> True
          }
        Error(Nil) -> False
      }
    }
    _ -> True
  }
  let exited =
    process.new_selector()
    |> process.select_specific_monitor(monitor, fn(_) { Nil })
    |> process.selector_receive(within: 500)
    |> result.is_ok
  let cancelled = process.receive(cleaned, within: 500) |> result.is_ok
  // Always release the deliberately blocked source before asserting the Red observation, so failure itself cannot leak a test process or listener.
  process.send(gate, Nil)
  let listener_stopped =
    case stopped {
      None -> server.stop_listener(listener)
      Some(task) -> http_test_support.await_task(task)
    }
    |> result.is_ok
  let closed = transport.close(socket) |> result.is_ok
  let executor_stopped = server.stop(executor) |> result.is_ok
  process.demonitor_process(monitor)
  assert exited
  assert cancelled
  assert closed
  assert listener_stopped
  assert executor_stopped
  assert continued
}

fn read_until_closed(
  socket socket: transport.Socket,
  bytes bytes: BitArray,
  budget budget: Int,
) -> Result(String, Nil) {
  use <- bool.guard(budget <= 0, Error(Nil))
  case transport.read(socket, 4096, 1000) {
    Ok(transport.ReadEnd(_)) -> bit_array.to_string(bytes)
    Ok(transport.ReadData(chunk, socket)) ->
      read_until_closed(
        socket: socket,
        bytes: <<bytes:bits, chunk:bits>>,
        budget: budget - 1,
      )
    Error(_) -> Error(Nil)
  }
}

// A failed setup never includes a native socket, process, key, or body.
// nolint: avoid_panic, thrown_away_error -- Test setup failure retains a fixed message instead of native values.
fn require_ok(value: Result(value, failure)) -> value {
  case value {
    Ok(value) -> value
    Error(_) -> panic as "response interruption fixture setup failed"
  }
}
