import gleam/bool
import gleam/erlang/process
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/option.{None, Some}
import gleam/result
import gleeunit
import http/body
import http/context
import http/error
import http/internal/http3/server as adapter
import http/server
import http3/client as http3_client
import http3/failure as http3_failure
import http3_server_test_support as server_test_support
import http_test_support
import quic_core/diagnostics

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn http3_response_worker_admission_limit_requires_finite_positive_capacity_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let assert Ok(configuration) =
    adapter.defaults(certificate, private_key, "localhost")
  assert adapter.with_response_worker_limit(configuration, 1)
    |> result.map(fn(_) { Nil })
    == Ok(Nil)
  assert adapter.with_response_worker_limit(configuration, 0)
    |> result.map(fn(_) { Nil })
    == Error(error.new(error.Resource(error.RequestWorkers)))
  assert adapter.with_response_worker_limit(configuration, 2_147_483_648)
    |> result.map(fn(_) { Nil })
    == Error(error.new(error.Resource(error.RequestWorkers)))
}

pub fn unified_server_adapts_streaming_http3_over_the_public_api_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    assert context.protocol(request_context) == context.Http3
    assert context.tls_identity(request_context)
      == context.TlsIdentity("localhost", None)
    assert context.early_data(request_context) == context.EarlyDataDisabled
    assert incoming.method == http.Post
    assert incoming.scheme == http.Https
    assert incoming.host == "localhost"
    assert incoming.path == "/unified"
    assert incoming.query == Some("transport=h3")
    let request_body_matches = case body.read_all(incoming.body, 7) {
      Ok(#(bytes, [])) -> bytes == <<"request":utf8>>
      _ -> False
    }
    assert request_body_matches
    Ok(response.Response(
      status: 201,
      headers: [#("content-type", "text/plain")],
      body: body.from_bytes_with_trailers(<<"response":utf8>>, [
        #("x-complete", "yes"),
      ]),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let outgoing =
    request.Request(
      method: http.Post,
      headers: [],
      body: <<"request":utf8>>,
      scheme: http.Https,
      host: "localhost",
      port: Some(port),
      path: "/unified",
      query: Some("transport=h3"),
    )
  let assert Ok(incoming) = http3_client.send(configuration, outgoing)

  assert incoming.status == 201
  let response_body_matches = incoming.body == <<"response":utf8>>
  assert response_body_matches
  assert response.get_header(incoming, "content-type") == Ok("text/plain")
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn unified_server_context_cancellation_resets_http3_request_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let handler = fn(_: request.Request(body.Body), request_context) {
    process.send(started, request_context)
    process.sleep(1000)
    Ok(response.Response(status: 200, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(configuration, "localhost", port)
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_path("/cancel-context")
    |> request.set_body(Nil)
  let assert Ok(stream) = http3_client.open_stream(connection, outbound)
  assert http3_client.finish(stream) == Ok(Nil)
  let assert Ok(request_context) = process.receive(started, within: 1000)

  context.cancel(request_context)

  assert http3_client.next_event(stream)
    == Error(
      http3_client.Failure(http3_failure.Closed(http3_failure.Peer, Some(0x10c))),
    )
  let _closed = http3_client.close(connection)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn unified_http3_listener_survives_an_idle_accept_deadline_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(executor) =
    server.start(server.defaults(), fn(_, _) {
      Ok(response.new(200) |> response.set_body(body.from_text("still here")))
    })
  let assert Ok(adapter) =
    server.http3_defaults(certificate, private_key, "localhost")
  let assert Ok(adapter) = server.with_http3_timeout(adapter, 1000)
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(configuration) = http3_client.with_timeout(configuration, 3000)
  // The idle period deliberately exceeds the listener's finite accept wait.
  // No peer or request is present which could satisfy that wait first.
  process.sleep(1500)
  let received =
    http3_client.send(
      configuration,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(<<>>),
    )
  let stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  let assert Ok(incoming) = received
  assert incoming.status == 200
  let response_body_matches = incoming.body == <<"still here":utf8>>
  assert response_body_matches
}

pub fn http3_head_transfer_finishes_successfully_before_disposing_source_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let finished = process.new_subject()
  let cancelled = process.new_subject()
  let read = process.new_subject()
  let handler = fn(_: request.Request(body.Body), _) {
    let assert Ok(source) =
      body.from_pull(
        body.pull(fn(_) {
          process.send(read, Nil)
          Error(error.new(error.Service))
        }),
        None,
        None,
        fn() { process.send(cancelled, Nil) },
      )
    let source =
      body.observe_transfer(source, fn() { Nil }, fn(outcome) {
        process.send(finished, outcome)
      })
    Ok(response.new(200) |> response.set_body(source))
  }
  let assert Ok(configuration) =
    adapter.defaults(certificate, private_key, "localhost")
  let assert Ok(listener) =
    adapter.listen(handler, <<127, 0, 0, 1>>, 0, configuration)
  let context.Endpoint(_, port) = adapter.endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(configuration, "localhost", port)
  let assert Ok(stream) =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_method(http.Head)
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
  let sent = http3_client.finish(stream)
  let head = http3_client.next_event(stream)
  let ended = http3_client.next_event(stream)
  let terminal = process.receive(finished, within: 1000)
  let disposed = process.receive(cancelled, within: 1000)
  let closed = http3_client.close(connection)
  let stopped = adapter.stop(listener)
  assert sent == Ok(Nil)
  assert server_test_support.default_response_head(outcome: head, status: 200)
  assert ended == Ok(http3_client.End)
  assert terminal == Ok(Ok(Nil))
  assert disposed == Ok(Nil)
  assert result.is_ok(closed)
  assert stopped == Ok(Nil)
  assert process.receive(read, within: 0) == Error(Nil)
  assert process.receive(finished, within: 0) == Error(Nil)
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

pub fn unified_http3_cancel_stalled_response_releases_its_source_test() -> Nil {
  stalled_response_cleanup(CancelContext)
}

pub fn peer_reset_releases_a_stalled_http3_response_source_test() -> Nil {
  stalled_response_cleanup(PeerReset)
}

pub fn peer_connection_close_releases_a_stalled_http3_response_source_test() -> Nil {
  stalled_response_cleanup(PeerClose)
}

pub fn unified_http3_stop_stalled_response_releases_its_source_test() -> Nil {
  stalled_response_cleanup(StopListener)
}

pub fn unified_http3_response_deadline_releases_its_source_test() -> Nil {
  stalled_response_cleanup(ExpireDeadline)
}

@external(erlang, "http_process_role_test", "http3_response_family_labelled")
fn response_family_labelled(producer: process.Pid) -> Bool

pub fn http3_response_roles_are_visible_before_a_body_callback_test() -> Nil {
  stalled_response_cleanup(ObserveRoles)
}

pub fn unified_http3_listener_owner_exit_releases_response_source_test() -> Nil {
  stalled_response_cleanup(ExitOwner)
}

pub fn unified_http3_forced_drain_reports_timeout_and_releases_its_source_test() -> Nil {
  stalled_response_cleanup(ForceDrain)
}

@external(erlang, "http_drain_test_ffi", "shorten_native_timeout")
fn shorten_native_timeout(
  configuration: server.Http3Config,
  milliseconds: Int,
) -> Result(server.Http3Config, Nil)

type ResponseTermination {
  CancelContext
  ObserveRoles
  PeerReset
  PeerClose
  StopListener
  ExpireDeadline
  ExitOwner
  ForceDrain
}

fn stalled_response_cleanup(termination: ResponseTermination) -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let cancelled = process.new_subject()
  let contexts = process.new_subject()
  let handler = fn(_: request.Request(body.Body), metadata) {
    process.send(contexts, metadata)
    let assert Ok(source) =
      body.from_pull(
        body.pull(fn(_) {
          let blocked = process.new_subject()
          process.send(started, #(blocked, process.self()))
          let _released = process.receive(blocked, within: 10_000)
          Error(error.new(error.Service))
        }),
        None,
        None,
        fn() { process.send(cancelled, Nil) },
      )
    Ok(response.new(200) |> response.set_body(source))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(certificate, private_key, "localhost")
  let adapter = case termination {
    ForceDrain -> {
      let assert Ok(adapter) = shorten_native_timeout(adapter, 1000)
      adapter
    }
    ExpireDeadline -> {
      let assert Ok(adapter) = server.with_http3_timeout(adapter, 2000)
      adapter
    }
    _ -> adapter
  }
  let #(listener, owner) = case termination {
    ExitOwner -> {
      let ready = process.new_subject()
      let pid =
        process.spawn_unlinked(fn() {
          let assert Ok(listener) =
            server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
          let keep_alive = process.new_subject()
          process.send(ready, listener)
          let _stopped = process.receive(keep_alive, within: 10_000)
          let _closed = server.stop_listener(listener)
          Nil
        })
      let assert Ok(listener) = process.receive(ready, within: 3000)
      #(listener, Some(pid))
    }
    _ -> {
      let assert Ok(listener) =
        server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
      #(listener, None)
    }
  }
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(configuration, "localhost", port)
  let assert Ok(stream) =
    http3_client.open_stream(
      connection,
      request.new()
        |> request.set_host("localhost")
        |> request.set_port(port)
        |> request.set_body(Nil),
    )
  assert http3_client.finish(stream) == Ok(Nil)
  let metadata = process.receive(contexts, within: 3000)
  let pulling = process.receive(started, within: 3000)
  let head = http3_client.next_event(stream)
  let monitor = case pulling {
    Ok(#(_, pid)) -> Some(process.monitor(pid))
    Error(Nil) -> None
  }
  let roles_visible = case termination, pulling {
    ObserveRoles, Ok(#(_, pid)) -> response_family_labelled(pid)
    _, _ -> True
  }
  let drain_result = case termination {
    ForceDrain -> Some(server.drain_listener(listener))
    _ -> None
  }
  case termination, metadata, owner {
    StopListener, _, _ -> {
      let _stopped = server.stop_listener(listener)
      Nil
    }
    CancelContext, Ok(metadata), _ | ObserveRoles, Ok(metadata), _ ->
      context.cancel(metadata)
    PeerReset, _, _ -> {
      let _cancelled = http3_client.cancel(stream)
      Nil
    }
    PeerClose, _, _ -> {
      let _closed = http3_client.close(connection)
      Nil
    }
    ExitOwner, _, Some(pid) -> process.kill(pid)
    _, _, _ -> Nil
  }
  let cleanup_milliseconds = case termination {
    PeerReset | PeerClose -> 500
    _ -> 3000
  }
  let cleaned = process.receive(cancelled, within: cleanup_milliseconds)
  let released = case monitor {
    Some(monitor) -> {
      let released =
        process.new_selector()
        |> process.select_specific_monitor(monitor, fn(_) { Nil })
        |> process.selector_receive(within: 1000)
      process.demonitor_process(monitor)
      released == Ok(Nil)
    }
    None -> False
  }
  // Release the old implementation's blocked callback before reporting Red.
  case pulling {
    Ok(#(blocked, _)) -> process.send(blocked, Nil)
    Error(Nil) -> Nil
  }
  let _closed = http3_client.close(connection)
  let stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  assert case pulling {
    Ok(_) -> True
    Error(Nil) -> False
  }
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  assert server_test_support.default_response_head(outcome: head, status: 200)
  assert cleaned == Ok(Nil)
  assert released
  assert roles_visible
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert case termination {
    ForceDrain ->
      drain_result == Some(Error(error.new(error.Timeout(error.Operation))))
    _ -> drain_result == None
  }
}

pub fn unified_http3_exiting_response_source_is_cancelled_and_isolated_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let cancelled = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/broken" -> {
        let assert Ok(source) =
          body.from_pull(
            body.pull(fn(_) {
              http_test_support.exit_now()
              Error(error.new(error.Service))
            }),
            None,
            None,
            fn() { process.send(cancelled, Nil) },
          )
        Ok(response.new(200) |> response.set_body(source))
      }
      _ -> Ok(response.new(200) |> response.set_body(body.from_text("healthy")))
    }
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(certificate, private_key, "localhost")
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(configuration) = http3_client.with_timeout(configuration, 3000)
  let outgoing =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(<<>>)
  let broken =
    http3_client.send(configuration, request.set_path(outgoing, "/broken"))
  let cleaned = process.receive(cancelled, within: 1000)
  let healthy = http3_client.send(configuration, outgoing)
  let stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  assert broken
    == Error(
      http3_client.Failure(http3_failure.Closed(http3_failure.Peer, Some(0x10c))),
    )
  assert cleaned == Ok(Nil)
  assert stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  let assert Ok(healthy) = healthy
  let healthy_body_matches = healthy.body == <<"healthy":utf8>>
  assert healthy_body_matches
  assert process.receive(cancelled, within: 0) == Error(Nil)
}

pub fn unified_http3_graceful_drain_finishes_an_active_response_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let started = process.new_subject()
  let handler = fn(_: request.Request(body.Body), _) {
    let assert Ok(source) =
      body.from_pull(
        body.pull(fn(_) {
          let release = process.new_subject()
          process.send(started, release)
          case process.receive(release, within: 3000) {
            Ok(Nil) ->
              Ok(body.PullData(
                <<"drained":utf8>>,
                body.pull(fn(_) { Ok(body.PullEnd([])) }),
              ))
            Error(Nil) -> Error(error.new(error.Timeout(error.Operation)))
          }
        }),
        None,
        None,
        fn() { Nil },
      )
    Ok(response.new(200) |> response.set_body(source))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(adapter) =
    server.http3_defaults(certificate, private_key, "localhost")
  let assert Ok(listener) =
    server.listen_http3(executor, <<127, 0, 0, 1>>, 0, adapter)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(configuration) =
    http3_client.with_ca_certificate(http3_client.new(), ca_certificate)
  let assert Ok(connection) =
    http3_client.connect(configuration, "localhost", port)
  let outbound =
    request.new()
    |> request.set_host("localhost")
    |> request.set_port(port)
    |> request.set_body(Nil)
  let assert Ok(stream) = http3_client.open_stream(connection, outbound)
  assert http3_client.finish(stream) == Ok(Nil)
  let assert Ok(release) = process.receive(started, within: 3000)
  let head = http3_client.next_event(stream)
  let draining =
    http_test_support.start_task(fn() { server.drain_listener(listener) })
  // Observe the wire-driven GOAWAY refusal before releasing the old response.
  let refused =
    await_http3_drain_refusal(
      connection: connection,
      outbound: outbound,
      deadline_milliseconds: diagnostics.monotonic_milliseconds() + 3000,
    )
  process.send(release, Nil)
  let data = http3_client.next_event(stream)
  let ended = http3_client.next_event(stream)
  let drained = http_test_support.await_task(draining)
  let _closed = http3_client.close(connection)
  let stopped = server.stop_listener(listener)
  let executor_stopped = server.stop(executor)
  // Retain every lifecycle phase as a scalar even when the first phase fails.
  assert #(
      server_test_support.default_response_head(outcome: head, status: 200),
      refused == Ok(True),
      data == Ok(http3_client.Data(<<"drained":utf8>>)),
      ended == Ok(http3_client.End),
      drained == Ok(Nil),
      stopped == Ok(Nil),
      executor_stopped == Ok(Nil),
    )
    == #(True, True, True, True, True, True, True)
}

fn await_http3_drain_refusal(
  connection connection: http3_client.Connection,
  outbound outbound: request.Request(Nil),
  deadline_milliseconds deadline_milliseconds: Int,
) -> Result(Bool, http3_client.Error) {
  use <- bool.guard(
    when: diagnostics.monotonic_milliseconds() >= deadline_milliseconds,
    return: Ok(False),
  )
  case http3_client.connection_reusable(connection) {
    Error(failure) -> Error(failure)
    Ok(True) ->
      await_http3_drain_refusal(
        connection: connection,
        outbound: outbound,
        deadline_milliseconds: deadline_milliseconds,
      )
    // The actor's payload-free GOAWAY state is the synchronization point.
    // One real open then proves the same state is enforced at the wire API.
    Ok(False) ->
      case http3_client.open_stream(connection, outbound) {
        Error(http3_client.ConnectionDraining)
        | Error(http3_client.RequestRejected) -> Ok(True)
        Error(failure) -> Error(failure)
        Ok(stream) -> {
          let _cancelled = http3_client.cancel(stream)
          Ok(False)
        }
      }
  }
}
