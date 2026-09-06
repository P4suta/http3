import gleam/bit_array
import gleam/erlang/process
import gleam/http/request.{type Request}
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string
import gleeunit
import http/body
import http/context
import http/error
import http/internal/transport
import http/server
import http_test_support

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn pipelined_requests_are_answered_in_wire_order_test() -> Nil {
  let handler = fn(request: Request(body.Body), _) {
    case request.path {
      "/first" -> process.sleep(20)
      _ -> Nil
    }
    Ok(response.Response(
      status: 200,
      headers: [#("x-path", request.path)],
      body: body.from_text(request.path),
    ))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n"
        <> "GET /second HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  let parts = string.split(text, "HTTP/1.1 200 OK")
  assert list.length(parts) == 3
  assert string.contains(text, "x-path: /first")
  assert string.contains(text, "/firstHTTP/1.1 200 OK")
  assert string.contains(text, "x-path: /second")

  stop_server(listener, executor)
}

pub fn malformed_framing_is_rejected_before_any_handler_runs_test() -> Nil {
  let called = process.new_subject()
  let handler = fn(_, _) {
    process.send(called, Nil)
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /bad HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        <> "0\r\n\r\nGET /hidden HTTP/1.1\r\nHost: example.test\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 400 Bad Request\r\n")
  assert process.receive(called, within: 20) == Error(Nil)

  stop_server(listener, executor)
}

pub fn connect_target_requires_an_explicit_valid_port_before_admission_test() -> Nil {
  let called = process.new_subject()
  let handler = fn(request: Request(body.Body), _) {
    process.send(called, request.path)
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)

  [
    "target.example",
    "target.example:",
    "target.example:0",
    "target.example:65536",
    "target.example:not-a-port",
    "user@target.example:443",
    "[2001:db8::1]",
    "[2001:db8::1]:0",
    "[2001:db8::1]:65536",
  ]
  |> list.each(fn(target) {
    let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
    let assert Ok(Nil) =
      transport.send(
        client,
        bit_array.from_string(
          "CONNECT "
          <> target
          <> " HTTP/1.1\r\n"
          <> "Host: proxy.example\r\nConnection: keep-alive\r\n\r\n",
        ),
      )
    let assert Ok(#(_, rejected)) = read_to_end(client, [])
    let assert Ok(rejected_text) = bit_array.to_string(rejected)
    assert string.starts_with(rejected_text, "HTTP/1.1 400 Bad Request\r\n")
  })
  assert process.receive(called, within: 20) == Error(Nil)

  stop_server(listener, executor)
}

pub fn rejected_connect_closes_and_never_dispatches_pipelined_bytes_test() -> Nil {
  let called = process.new_subject()
  let handler = fn(request: Request(body.Body), _) {
    process.send(called, request.path)
    Ok(response.Response(
      status: 403,
      headers: [#("connection", "keep-alive")],
      body: body.empty(),
    ))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "CONNECT target.example:443 HTTP/1.1\r\n"
        <> "Host: proxy.example\r\nConnection: keep-alive\r\n\r\n"
        <> "GET /must-not-run HTTP/1.1\r\nHost: proxy.example\r\n\r\n",
      ),
    )
  let assert Ok(#(_, rejected)) = read_to_end(client, [])
  let assert Ok(rejected_text) = bit_array.to_string(rejected)
  assert string.starts_with(rejected_text, "HTTP/1.1 403 Forbidden\r\n")
  assert string.contains(rejected_text, "Connection: close\r\n")
  assert !string.contains(rejected_text, "keep-alive")
  assert list.length(string.split(rejected_text, "HTTP/1.1")) == 2
  assert process.receive(called, within: 100) == Ok("target.example:443")
  assert process.receive(called, within: 20) == Error(Nil)

  stop_server(listener, executor)
}

pub fn expect_continue_is_sent_only_when_the_handler_pulls_the_body_test() -> Nil {
  let handler = fn(request: Request(body.Body), _) {
    process.sleep(20)
    use #(bytes, trailers) <- result.try(body.read_all(request.body, 32))
    assert trailers == []
    Ok(response.Response(status: 200, headers: [], body: body.from_bytes(bytes)))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /continue HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 5\r\nExpect: 100-continue\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Error(transport.Timeout) = transport.read(client, 4096, 5)
  // A timed-out active-once read closes a transport socket, so use a fresh
  // exchange for the positive deferred-continue assertion.
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /continue HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 5\r\nExpect: 100-continue\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(client, interim)) = read_until(client, "\r\n\r\n", 1000, [])
  assert interim == <<"HTTP/1.1 100 Continue\r\n\r\n":utf8>>
  let assert Ok(Nil) = transport.send(client, <<"hello":utf8>>)
  let assert Ok(#(_, final)) = read_to_end(client, [])
  let assert Ok(final_text) = bit_array.to_string(final)
  assert string.starts_with(final_text, "HTTP/1.1 200 OK\r\n")
  assert string.ends_with(final_text, "hello")

  stop_server(listener, executor)
}

pub fn unsupported_expectation_is_a_417_without_handler_admission_test() -> Nil {
  let called = process.new_subject()
  let handler = fn(_, _) {
    process.send(called, Nil)
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /expect HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 1\r\nExpect: something-else\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 417 Expectation Failed\r\n")
  assert process.receive(called, within: 20) == Error(Nil)

  stop_server(listener, executor)
}

pub fn stalled_connection_does_not_block_another_connection_test() -> Nil {
  let handler = fn(_, _) {
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let config =
    server.http1_defaults()
    |> server.allow_http1_cleartext
    |> server.with_http1_idle_timeout(250)
    |> result.unwrap(server.http1_defaults())
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(stalled) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(stalled, <<"GET /slow HTTP/1.1\r\n":utf8>>)

  let assert Ok(progressing) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(progressing, <<
      "GET /ok HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n":utf8,
    >>)
  let assert Ok(#(_, received)) = read_to_end(progressing, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 204 No Content\r\n")

  let assert Ok(Nil) = transport.close(stalled)
  stop_server(listener, executor)
}

pub fn http1_listener_readiness_and_phase_snapshot_are_bounded_test() -> Nil {
  let handler = fn(_, _) {
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(initial) = server.http1_listener_snapshot(listener)
  assert initial.consistent
  assert initial.state == server.Running
  assert initial.listener_ready_milliseconds >= 0
  assert initial.accepted_connections == 0
  assert initial.accept_failures == 0
  assert initial.connection_start_attempts == 0
  assert initial.started_connections == 0
  assert initial.connection_start_failures == 0
  assert initial.active_connections == 0
  assert initial.exited_connections == 0
  assert initial.parsed_request_heads == 0
  assert initial.handler_dispatches == 0
  assert initial.handler_completions == 0
  assert initial.handler_failures == 0
  assert initial.connection_failures == 0
  assert initial.last_connection_start_milliseconds == 0
  assert initial.maximum_connection_start_milliseconds == 0

  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(client, <<
      "GET /snapshot HTTP/1.1\r\nHost: example.test\r\n":utf8,
      "Connection: close\r\n\r\n":utf8,
    >>)
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 204 No Content\r\n")

  let assert Ok(completed) =
    await_http1_listener_snapshot(
      listener,
      fn(snapshot) {
        snapshot.exited_connections == 1 && snapshot.active_connections == 0
      },
      1000,
    )
  assert completed.consistent
  assert completed.state == server.Running
  assert completed.accepted_connections == 1
  assert completed.accept_failures == 0
  assert completed.connection_start_attempts == 1
  assert completed.started_connections == 1
  assert completed.connection_start_failures == 0
  assert completed.active_connections == 0
  assert completed.exited_connections == 1
  assert completed.parsed_request_heads == 1
  assert completed.handler_dispatches == 1
  assert completed.handler_completions == 1
  assert completed.handler_failures == 0
  assert completed.connection_failures == 0
  assert completed.last_connection_start_milliseconds >= 0
  assert completed.maximum_connection_start_milliseconds
    >= completed.last_connection_start_milliseconds

  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(draining) = server.http1_listener_snapshot(listener)
  assert draining.consistent
  assert draining.state == server.Draining
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(stopped) = server.http1_listener_snapshot(listener)
  assert stopped.consistent
  assert stopped.state == server.Stopped
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn http1_listener_phase_snapshot_is_atomic_under_race_test() -> Nil {
  let #(
    violations,
    accepted,
    accept_failures,
    start_attempts,
    started,
    start_failures,
    active,
    exited,
    parsed_heads,
    handler_dispatches,
    handler_completions,
    handler_failures,
    connection_failures,
    maximum_start_milliseconds,
  ) = http_test_support.http1_listener_snapshot_race(20_000)
  assert violations == 0
  assert accepted == 40_000
  assert accept_failures == 20_000
  assert start_attempts == 40_000
  assert started == 20_000
  assert start_failures == 20_000
  assert active == 0
  assert exited == 20_000
  assert parsed_heads == 40_000
  assert handler_dispatches == 40_000
  assert handler_completions == 40_000
  assert handler_failures == 20_000
  assert connection_failures == 20_000
  assert maximum_start_milliseconds == 19_999
}

pub fn http1_listener_orphaned_writer_is_finite_and_observable_test() -> Nil {
  let #(snapshot_finished, writer_finished, explicitly_inconsistent) =
    http_test_support.http1_listener_orphaned_writer_trace()
  assert snapshot_finished
  assert writer_finished
  assert explicitly_inconsistent
}

pub fn http1_listener_snapshot_rejects_other_protocols_without_handles_test() -> Nil {
  let handler = fn(_, _) {
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let config =
    server.http2_defaults() |> server.allow_http2_cleartext_prior_knowledge
  let assert Ok(listener) =
    server.listen_http2_cleartext(executor, <<127, 0, 0, 1>>, 0, config)
  let assert Error(failure) = server.http1_listener_snapshot(listener)
  assert error.kind(failure) == error.Protocol(error.Http1)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn externally_cancelled_context_closes_only_its_http1_connection_test() -> Nil {
  let captured_context = process.new_subject()
  let called = process.new_subject()
  let handler = fn(request: Request(body.Body), request_context) {
    process.send(called, request.path)
    case request.path {
      "/cancel" -> {
        process.send(captured_context, request_context)
        process.sleep(1000)
      }
      _ -> Nil
    }
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /cancel HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: keep-alive\r\n\r\n"
        <> "GET /must-not-run HTTP/1.1\r\nHost: example.test\r\n\r\n",
      ),
    )

  let captured = process.receive(captured_context, within: 5000)
  let phase_evidence = server.http1_listener_snapshot(listener)
  let assert #(Ok(request_context), Ok(dispatching)) = #(
    captured,
    phase_evidence,
  )
  assert dispatching.consistent
  assert dispatching.accepted_connections == 1
  assert dispatching.connection_start_attempts == 1
  assert dispatching.started_connections == 1
  assert dispatching.connection_start_failures == 0
  assert dispatching.active_connections == 1
  assert dispatching.parsed_request_heads == 1
  assert dispatching.handler_dispatches == 1
  assert dispatching.handler_completions == 0
  assert context.protocol(request_context) == context.Http1
  context.cancel(request_context)
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 408 Request Timeout\r\n")
  assert string.contains(text, "Connection: close\r\n")
  assert list.length(string.split(text, "HTTP/1.1")) == 2
  assert process.receive(called, within: 100) == Ok("/cancel")
  assert process.receive(called, within: 20) == Error(Nil)

  // HTTP/1.1 cannot isolate cancellation within a multiplexed connection,
  // but the listener and a fresh connection must remain healthy.
  assert_healthy_connection(port)
  assert process.receive(called, within: 100) == Ok("/healthy")

  stop_server(listener, executor)
}

pub fn tls_listener_populates_verified_protocol_context_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let observed = process.new_subject()
  let handler = fn(_, request_context) {
    process.send(observed, #(
      context.protocol(request_context),
      context.peer_endpoint(request_context),
      context.local_endpoint(request_context),
      context.tls_identity(request_context),
      context.early_data(request_context),
    ))
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http1_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(transport.TlsReady(client, <<"http/1.1":utf8>>, _)) =
    transport.upgrade_client_tls(
      client,
      "localhost",
      [ca_certificate],
      [<<"http/1.1":utf8>>],
      1000,
    )
  let assert Ok(Nil) =
    transport.send(client, <<
      "GET /secure HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n":utf8,
    >>)
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 204 No Content\r\n")
  let assert Ok(#(
    context.Http1,
    context.Endpoint(peer_host, peer_port),
    context.Endpoint(local_host, local_port),
    context.TlsIdentity("localhost", None),
    context.EarlyDataDisabled,
  )) = process.receive(observed, within: 1000)
  assert peer_host == "127.0.0.1"
  assert peer_port > 0
  assert local_host == "127.0.0.1"
  assert local_port == port

  stop_server(listener, executor)
}

pub fn request_write_half_close_still_allows_the_response_test() -> Nil {
  let handler = fn(request: Request(body.Body), _) {
    use #(bytes, _) <- result.try(body.read_all(request.body, 32))
    Ok(response.Response(status: 200, headers: [], body: body.from_bytes(bytes)))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /half-close HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 5\r\nConnection: close\r\n\r\nhello",
      ),
    )
  let assert Ok(Nil) = transport.shutdown_write(client)
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert string.ends_with(text, "hello")

  stop_server(listener, executor)
}

pub fn premature_request_eof_is_a_400_and_the_listener_recovers_test() -> Nil {
  let handler = fn(request: Request(body.Body), _) {
    use _ <- result.try(body.read_all(request.body, 32))
    Ok(response.Response(status: 204, headers: [], body: body.empty()))
  }
  let #(executor, listener, port) = cleartext_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "POST /short HTTP/1.1\r\nHost: example.test\r\n"
        <> "Content-Length: 5\r\nConnection: close\r\n\r\nabc",
      ),
    )
  let assert Ok(Nil) = transport.shutdown_write(client)
  let assert Ok(#(_, rejected)) = read_to_end(client, [])
  let assert Ok(rejected_text) = bit_array.to_string(rejected)
  assert string.starts_with(rejected_text, "HTTP/1.1 400 Bad Request\r\n")

  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /healthy HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(_, healthy)) = read_to_end(client, [])
  let assert Ok(healthy_text) = bit_array.to_string(healthy)
  assert string.starts_with(healthy_text, "HTTP/1.1 204 No Content\r\n")

  stop_server(listener, executor)
}

pub fn stalled_response_source_is_timed_out_cancelled_and_isolated_test() -> Nil {
  let cancelled = process.new_subject()
  let handler = fn(request: Request(body.Body), _) {
    case request.path {
      "/blocked" -> {
        let assert Ok(response_body) =
          body.from_pull(slow_response_body(), None, None, fn() {
            process.send(cancelled, Nil)
          })
        Ok(response.Response(status: 200, headers: [], body: response_body))
      }
      _ -> Ok(response.Response(status: 204, headers: [], body: body.empty()))
    }
  }
  let #(executor, listener, port) = short_operation_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /blocked HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert !string.contains(text, "late")
  assert process.receive(cancelled, within: 500) == Ok(Nil)
  assert_healthy_connection(port)

  stop_server(listener, executor)
}

pub fn exiting_response_source_is_cancelled_without_crashing_the_listener_test() -> Nil {
  let cancelled = process.new_subject()
  let handler = fn(request: Request(body.Body), _) {
    case request.path {
      "/exit" -> {
        let assert Ok(response_body) =
          body.from_pull(exiting_response_body(), None, None, fn() {
            process.send(cancelled, Nil)
          })
        Ok(response.Response(status: 200, headers: [], body: response_body))
      }
      _ -> Ok(response.Response(status: 204, headers: [], body: body.empty()))
    }
  }
  let #(executor, listener, port) = short_operation_server(handler)
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /exit HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 200 OK\r\n")
  assert process.receive(cancelled, within: 500) == Ok(Nil)
  assert_healthy_connection(port)

  stop_server(listener, executor)
}

fn cleartext_server(
  handler: server.Handler,
) -> #(server.Server, server.Listener, Int) {
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let config = server.http1_defaults() |> server.allow_http1_cleartext
  let assert Ok(listener) =
    server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  #(executor, listener, port)
}

fn short_operation_server(
  handler: server.Handler,
) -> #(server.Server, server.Listener, Int) {
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(config) =
    server.http1_defaults()
    |> server.allow_http1_cleartext
    |> server.with_http1_timeouts(
      idle_milliseconds: 1000,
      operation_milliseconds: 30,
      tls_milliseconds: 1000,
      drain_milliseconds: 1000,
      send_milliseconds: 1000,
    )
  let assert Ok(listener) =
    server.listen_http1(executor, <<127, 0, 0, 1>>, 0, config)
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  #(executor, listener, port)
}

fn assert_healthy_connection(port: Int) -> Nil {
  let assert Ok(client) = transport.connect("127.0.0.1", port, 1000, 1000)
  let assert Ok(Nil) =
    transport.send(
      client,
      bit_array.from_string(
        "GET /healthy HTTP/1.1\r\nHost: example.test\r\n"
        <> "Connection: close\r\n\r\n",
      ),
    )
  let assert Ok(#(_, received)) = read_to_end(client, [])
  let assert Ok(text) = bit_array.to_string(received)
  assert string.starts_with(text, "HTTP/1.1 204 No Content\r\n")
}

fn slow_response_body() -> body.Pull {
  body.pull(fn(_) {
    process.sleep(200)
    Ok(body.PullData(<<"late":utf8>>, body.pull(fn(_) { Ok(body.PullEnd([])) })))
  })
}

fn exiting_response_body() -> body.Pull {
  body.pull(fn(_) {
    http_test_support.exit_now()
    Ok(body.PullEnd([]))
  })
}

fn stop_server(listener: server.Listener, executor: server.Server) -> Nil {
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

fn await_http1_listener_snapshot(
  listener: server.Listener,
  matches: fn(server.Http1ListenerSnapshot) -> Bool,
  remaining_milliseconds: Int,
) -> Result(server.Http1ListenerSnapshot, error.Error) {
  use snapshot <- result.try(server.http1_listener_snapshot(listener))
  case matches(snapshot), remaining_milliseconds <= 0 {
    True, _ | _, True -> Ok(snapshot)
    False, False -> {
      process.sleep(2)
      await_http1_listener_snapshot(
        listener,
        matches,
        remaining_milliseconds - 2,
      )
    }
  }
}

fn read_until(
  socket: transport.Socket,
  marker: String,
  timeout: Int,
  reversed: List(BitArray),
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  use outcome <- result.try(transport.read(socket, 4096, timeout))
  case outcome {
    transport.ReadEnd(_) -> Error(transport.Closed)
    transport.ReadData(bytes, socket) -> {
      let collected = [bytes, ..reversed] |> list.reverse |> bit_array.concat
      case bit_array.to_string(collected) {
        Ok(text) ->
          case string.contains(text, marker) {
            True -> Ok(#(socket, collected))
            False -> read_until(socket, marker, timeout, [bytes, ..reversed])
          }
        _ -> read_until(socket, marker, timeout, [bytes, ..reversed])
      }
    }
  }
}

fn read_to_end(
  socket: transport.Socket,
  reversed: List(BitArray),
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  case transport.read(socket, 4096, 1000) {
    Error(failure) -> Error(failure)
    Ok(transport.ReadEnd(socket)) ->
      Ok(#(socket, reversed |> list.reverse |> bit_array.concat))
    Ok(transport.ReadData(bytes, socket)) ->
      read_to_end(socket, [bytes, ..reversed])
  }
}
