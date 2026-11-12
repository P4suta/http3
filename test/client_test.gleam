import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
import gleeunit/should
import http/body
import http/client
import http/client_store
import http/context
import http/error
import http/internal/http2/frame
import http/internal/http2/preface
import http/internal/transport
import http/server
import http3/server as h3_server
import http_test_support

type PolicyRemoval {
  CookieRemoval(client_store.Partition, String, Int)
  HstsRemoval(client_store.Partition, String, Int)
  AltSvcRemoval(client_store.Partition, String, Int)
  AltSvcUpsert(String, Int)
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn defaults_are_finite_and_plaintext_is_opt_in_test() -> Nil {
  let config = client.defaults()
  let explicit_system_roots = client.with_ca_certificates(config, [])

  assert client.timeouts(config)
    == client.Timeouts(
      dns_milliseconds: 5000,
      connect_milliseconds: 10_000,
      tls_milliseconds: 10_000,
      operation_milliseconds: 30_000,
      idle_milliseconds: 30_000,
      total_milliseconds: 30_000,
    )
  assert client.body_limits(config)
    == client.BodyLimits(
      buffered_bytes: 8_388_608,
      stream_buffer_bytes: 262_144,
      endpoint_memory_bytes: 67_108_864,
    )
  assert client.pool_limits(config)
    == client.PoolLimits(
      maximum_connections: 256,
      maximum_connections_per_origin: 8,
      idle_milliseconds: 30_000,
    )
  assert client.pooling_enabled(config)
  assert client.security(config) == client.Security(allow_plain_http: False)
  assert client.security(explicit_system_roots)
    == client.Security(allow_plain_http: False)
}

pub fn http3_pool_identity_is_collision_safe_and_network_partitioned_test() -> Nil {
  let origin = client.Origin(gleam_http.Https, "example.com", 443)
  let first =
    client.http3_pool_key(
      origin,
      client.NetworkIsolationKey(top_level_site: "a", profile: "bc"),
    )
  let repeated =
    client.http3_pool_key(
      origin,
      client.NetworkIsolationKey(top_level_site: "a", profile: "bc"),
    )
  let delimiter_collision =
    client.http3_pool_key(
      origin,
      client.NetworkIsolationKey(top_level_site: "ab", profile: "c"),
    )
  let other_origin =
    client.http3_pool_key(
      client.Origin(gleam_http.Https, "example.com", 8443),
      client.NetworkIsolationKey(top_level_site: "a", profile: "bc"),
    )
  assert first == repeated
  assert first != delimiter_collision
  assert first != other_origin
}

pub fn redirects_default_to_ten_and_can_be_bounded_or_disabled_test() -> Nil {
  let config = client.defaults()
  assert client.redirect_policy(config)
    == client.RedirectPolicy(enabled: True, maximum: 10)

  let assert Ok(bounded) = client.with_redirect_limit(config, 4)
  assert client.redirect_policy(bounded)
    == client.RedirectPolicy(enabled: True, maximum: 4)
  assert client.redirect_policy(client.without_redirects(bounded))
    == client.RedirectPolicy(enabled: False, maximum: 4)

  let assert Error(failure) = client.with_redirect_limit(config, 0)
  assert error.kind(failure) == error.Policy(error.RedirectPolicy)
}

pub fn retries_default_to_one_pre_response_attempt_and_status_is_opt_in_test() -> Nil {
  let config = client.defaults()
  assert client.retry_policy(config)
    == client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  let assert Ok(configured) =
    client.with_retry_policy(
      config,
      client.RetryPolicy(enabled: True, maximum: 2, retry_statuses: [503]),
    )
  assert client.retry_policy(configured)
    == client.RetryPolicy(enabled: True, maximum: 2, retry_statuses: [503])
  assert client.retry_policy(client.without_retries(configured))
    == client.RetryPolicy(enabled: False, maximum: 2, retry_statuses: [503])

  let assert Error(failure) =
    client.with_retry_policy(
      config,
      client.RetryPolicy(enabled: True, maximum: -1, retry_statuses: []),
    )
  assert error.kind(failure) == error.Policy(error.RetryPolicy)
}

pub fn automatic_retry_requires_safe_progress_method_body_and_budget_test() -> Nil {
  let policy =
    client.RetryPolicy(enabled: True, maximum: 2, retry_statuses: [503])
  let unstarted = client.RequestUnstarted(error.new(error.ConnectFailed))
  let rejected = client.RequestRejected
  let possibly_processed =
    client.RequestPossiblyProcessed(error.new(error.Protocol(error.Http3)))
  let response_headers = client.ResponseHeadersReceived(503)
  let partial_response =
    client.ResponseBodyPartiallyReceived(error.new(error.Protocol(error.Http3)))

  assert client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: unstarted,
  )
  assert client.automatic_retry_allowed(
    policy,
    gleam_http.Put,
    body_replayable: True,
    retries_remaining: 1,
    trigger: rejected,
  )
  assert client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: response_headers,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: possibly_processed,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: partial_response,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Post,
    body_replayable: True,
    retries_remaining: 1,
    trigger: unstarted,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: False,
    retries_remaining: 1,
    trigger: rejected,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 0,
    trigger: unstarted,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 3,
    trigger: unstarted,
  )
  assert !client.automatic_retry_allowed(
    client.RetryPolicy(enabled: False, maximum: 2, retry_statuses: [503]),
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: rejected,
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: client.ResponseHeadersReceived(500),
  )
  assert !client.automatic_retry_allowed(
    policy,
    gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: client.RequestUnstarted(
      error.new(error.Resource(error.Connections)),
    ),
  )
}

pub fn retry_failure_progress_is_conservative_without_peer_evidence_test() -> Nil {
  let connect = error.new(error.ConnectFailed)
  let operation_timeout = error.new(error.Timeout(error.Operation))
  let connection_loss = error.new(error.Protocol(error.Http3))
  let rejected = error.peer_rejected_before_processing(error.Http3)

  assert client.retry_trigger_for_failure(connect)
    == client.RequestUnstarted(connect)
  assert client.retry_trigger_for_failure(rejected) == client.RequestRejected
  assert client.retry_trigger_for_failure(operation_timeout)
    == client.RequestPossiblyProcessed(operation_timeout)
  assert client.retry_trigger_for_failure(connection_loss)
    == client.RequestPossiblyProcessed(connection_loss)
}

pub fn http3_connection_loss_without_goaway_is_possibly_processed_test() -> Nil {
  let failure = error.new(error.Protocol(error.Http3))
  let trigger = client.retry_trigger_for_failure(failure)
  let policy = client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  assert trigger == client.RequestPossiblyProcessed(failure)
  assert !client.automatic_retry_allowed(
    policy: policy,
    method: gleam_http.Get,
    body_replayable: True,
    retries_remaining: 1,
    trigger: trigger,
  )
}

pub fn failed_attempt_replay_is_constructed_only_after_source_release_test() -> Nil {
  let released = process.new_subject()
  let replay_observed = process.new_subject()
  let terminal = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let source = body.pull(fn(_) { Ok(body.PullData(<<"abc">>, terminal())) })
  let replay = fn() {
    process.send(replay_observed, process.receive(released, within: 0))
    body.pull(fn(_) { Ok(body.PullData(<<"abc">>, terminal())) })
  }
  let assert Ok(outgoing_body) =
    body.from_pull(source, Some(3), Some(replay), fn() {
      process.send(released, Nil)
    })
  let outgoing =
    request.Request(
      method: gleam_http.Put,
      headers: [],
      body: outgoing_body,
      scheme: gleam_http.Https,
      host: "example.test",
      port: None,
      path: "/retry-after-release",
      query: None,
    )
  let policy = client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  let assert Ok(Some(replayed)) =
    client.failed_attempt_retry_after_release(
      policy: policy,
      outgoing: outgoing,
      retries_remaining: 1,
      failure: error.new(error.ConnectFailed),
      within_milliseconds: 1000,
    )

  assert process.receive(replay_observed, within: 1000) == Ok(Ok(Nil))
  body.cancel(replayed.body)
  assert process.receive(released, within: 1000) == Ok(Nil)
}

pub fn failed_attempt_replay_survives_prior_terminal_source_release_test() -> Nil {
  let cancelled = process.new_subject()
  let replayed = process.new_subject()
  let terminal = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let assert Ok(outgoing_body) =
    body.from_pull(
      terminal(),
      Some(0),
      Some(fn() {
        process.send(replayed, Nil)
        terminal()
      }),
      fn() { process.send(cancelled, Nil) },
    )
  let outgoing =
    request_for(443, "/already-released", outgoing_body)
    |> request.set_scheme(gleam_http.Https)
    |> request.set_method(gleam_http.Get)
  let policy = client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  assert body.cancel_within(outgoing.body, 1000) == Ok(Nil)
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
  let assert Ok(Some(next)) =
    client.failed_attempt_retry_after_release(
      policy: policy,
      outgoing: outgoing,
      retries_remaining: 1,
      failure: error.new(error.ConnectFailed),
      within_milliseconds: 1000,
    )

  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert process.receive(replayed, within: 1000) == Ok(Nil)
  body.cancel(next.body)
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
}

// Keep the requirement-table evidence symbol while tightening "pre-response" to mean a failure proven to precede transmission.
pub fn idempotent_replayable_request_retries_one_pre_response_failure_test() -> Nil {
  failed_attempt_replay_is_constructed_only_after_source_release_test()
}

pub fn failed_attempt_release_timeout_never_constructs_replay_test() -> Nil {
  let replayed = process.new_subject()
  let blocked = process.new_subject()
  let terminal = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let assert Ok(outgoing_body) =
    body.from_pull(
      terminal(),
      Some(0),
      Some(fn() {
        process.send(replayed, Nil)
        terminal()
      }),
      fn() { process.receive_forever(blocked) },
    )
  let outgoing =
    request_for(443, "/failed-release-timeout", outgoing_body)
    |> request.set_scheme(gleam_http.Https)
    |> request.set_method(gleam_http.Get)
  let policy = client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  let assert Error(failure) =
    client.failed_attempt_retry_after_release(
      policy: policy,
      outgoing: outgoing,
      retries_remaining: 1,
      failure: error.new(error.ConnectFailed),
      within_milliseconds: 20,
    )

  assert error.kind(failure) == error.Timeout(error.Operation)
  assert process.receive(replayed, within: 0) == Error(Nil)
}

pub fn possibly_processed_failure_neither_releases_nor_replays_again_test() -> Nil {
  let cancelled = process.new_subject()
  let replayed = process.new_subject()
  let terminal = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let assert Ok(outgoing_body) =
    body.from_pull(
      terminal(),
      Some(0),
      Some(fn() {
        process.send(replayed, Nil)
        terminal()
      }),
      fn() { process.send(cancelled, Nil) },
    )
  let outgoing =
    request_for(443, "/possibly-processed", outgoing_body)
    |> request.set_scheme(gleam_http.Https)
    |> request.set_method(gleam_http.Get)
  let policy = client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [])

  assert client.failed_attempt_retry_after_release(
      policy: policy,
      outgoing: outgoing,
      retries_remaining: 1,
      failure: error.new(error.Protocol(error.Http3)),
      within_milliseconds: 1000,
    )
    == Ok(None)
  assert process.receive(cancelled, within: 0) == Error(Nil)
  assert process.receive(replayed, within: 0) == Error(Nil)
  body.cancel(outgoing.body)
  assert process.receive(cancelled, within: 1000) == Ok(Nil)
}

pub fn connection_loss_after_request_bytes_is_not_automatically_retried_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(transport.close(first))
      case transport.accept(listener, 30_000) {
        Error(_) -> Ok(False)
        Ok(second) -> {
          let _closed = transport.close(second)
          Ok(True)
        }
      }
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start
  let outgoing = request_for(port, "/retry", <<>>)

  let assert Error(failure) = client.fetch(running, outgoing)
  assert error.kind(failure) == error.Protocol(error.Http1)
  let assert Ok(Nil) = transport.stop(listener)
  let assert Ok(False) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = client.close(running)
  Nil
}

pub fn successful_exchange_does_not_construct_unused_retry_body_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use received <- result.try(read_until_text(
        socket,
        <<>>,
        "\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
      ))
      let #(socket, _) = received
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      transport.close(socket)
    })
  let replay_constructed = process.new_subject()
  let end = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let source = body.pull(fn(_) { Ok(body.PullData(<<"abc">>, end())) })
  let replay = fn() {
    process.send(replay_constructed, Nil)
    body.pull(fn(_) { Ok(body.PullData(<<"abc">>, end())) })
  }
  let assert Ok(outgoing_body) =
    body.from_pull(source, Some(3), Some(replay), fn() { Nil })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Put,
      headers: [],
      body: outgoing_body,
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/no-retry",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  assert client.response(completed).status == 200
  let assert Ok(#(<<>>, [])) = body.read_all(client.response(completed).body, 1)
  let assert Ok(Nil) = http_test_support.await_task(server_task)
  assert process.receive(replay_constructed, within: 0) == Error(Nil)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn status_503_retry_waits_for_response_release_before_replay_test() -> Nil {
  let released = process.new_subject()
  let replay_observed = process.new_subject()
  let outgoing = ordered_replay_request(released, replay_observed)
  let response_body = release_observed_body(released)
  let policy =
    client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [503])

  let assert Ok(Some(replayed)) =
    client.status_retry_after_response_release(
      policy: policy,
      status: 503,
      outgoing: outgoing,
      response_body: response_body,
      within_milliseconds: 1000,
    )

  assert process.receive(replay_observed, within: 1000) == Ok(Ok(Nil))
  body.cancel(outgoing.body)
  body.cancel(replayed.body)
}

pub fn status_retry_release_timeout_never_constructs_replay_test() -> Nil {
  let released = process.new_subject()
  let replay_observed = process.new_subject()
  let blocked = process.new_subject()
  let outgoing = ordered_replay_request(released, replay_observed)
  let assert Ok(response_body) =
    body.from_pull(
      body.pull(fn(_) { Ok(body.PullEnd([])) }),
      Some(0),
      None,
      fn() { process.receive_forever(blocked) },
    )
  let policy =
    client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [503])

  let assert Error(failure) =
    client.status_retry_after_response_release(
      policy: policy,
      status: 503,
      outgoing: outgoing,
      response_body: response_body,
      within_milliseconds: 20,
    )

  assert error.kind(failure) == error.Timeout(error.Operation)
  assert process.receive(replay_observed, within: 0) == Error(Nil)
  assert process.receive(released, within: 0) == Error(Nil)
  body.cancel(outgoing.body)
}

pub fn temporary_redirect_307_waits_for_response_release_before_replay_test() -> Nil {
  redirect_waits_for_response_release_before_replay(307)
}

pub fn permanent_redirect_308_waits_for_response_release_before_replay_test() -> Nil {
  redirect_waits_for_response_release_before_replay(308)
}

fn redirect_waits_for_response_release_before_replay(status: Int) -> Nil {
  let released = process.new_subject()
  let replay_observed = process.new_subject()
  let outgoing = ordered_replay_request(released, replay_observed)
  let response_body = release_observed_body(released)

  let assert Ok(next) =
    client.redirect_after_response_release(
      outgoing: outgoing,
      status: status,
      location: "/after-release",
      response_body: response_body,
      within_milliseconds: 1000,
    )

  assert next.method == gleam_http.Put
  assert next.path == "/after-release"
  assert process.receive(replay_observed, within: 1000) == Ok(Ok(Nil))
  body.cancel(outgoing.body)
  body.cancel(next.body)
}

fn ordered_replay_request(
  released: process.Subject(Nil),
  replay_observed: process.Subject(Result(Nil, Nil)),
) -> request.Request(body.Body) {
  let terminal = fn() { body.pull(fn(_) { Ok(body.PullEnd([])) }) }
  let initial = body.pull(fn(_) { Ok(body.PullData(<<"abc">>, terminal())) })
  let replay = fn() {
    process.send(replay_observed, process.receive(released, within: 0))
    body.pull(fn(_) { Ok(body.PullData(<<"abc">>, terminal())) })
  }
  let assert Ok(outgoing_body) =
    body.from_pull(initial, Some(3), Some(replay), fn() { Nil })
  request.Request(
    method: gleam_http.Put,
    headers: [],
    body: outgoing_body,
    scheme: gleam_http.Https,
    host: "example.test",
    port: None,
    path: "/before-release",
    query: None,
  )
}

fn release_observed_body(released: process.Subject(Nil)) -> body.Body {
  let assert Ok(response_body) =
    body.from_pull(
      body.pull(fn(_) { Ok(body.PullEnd([])) }),
      Some(0),
      None,
      fn() { process.send(released, Nil) },
    )
  response_body
}

pub fn client_follows_a_303_and_regenerates_post_as_get_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use first_request <- result.try(read_until_text(
        first,
        <<>>,
        "\r\n\r\nabc",
      ))
      let #(first, _) = first_request
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 303 See Other\r\n":utf8,
          "Location: /final\r\n":utf8,
          "Content-Length: 0\r\n":utf8,
          "Connection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use second_read <- result.try(transport.read(second, 4096, 1000))
      let assert transport.ReadData(second_request, second) = second_read
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 4\r\n":utf8,
          "Connection: close\r\n\r\ndone":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(second_request)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [
        #("authorization", "Bearer retained"),
        #("content-type", "text/plain"),
      ],
      body: body.from_text("abc"),
      scheme: gleam_http.Http,
      host: "127.0.0.1",
      port: Some(port),
      path: "/start",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  let assert Ok(#(<<"done":utf8>>, [])) =
    body.read_all(client.response(completed).body, 4)
  assert client.redirect_history(completed)
    == [
      client.RedirectHop(
        status: 303,
        from: client.Origin(gleam_http.Http, "127.0.0.1", port),
        to: client.Origin(gleam_http.Http, "127.0.0.1", port),
        protocol: client.Http1,
      ),
    ]
  let assert Ok(second_request) = http_test_support.await_task(server_task)
  let assert Ok(second_text) = bit_array.to_string(second_request)
  assert string.starts_with(second_text, "GET /final HTTP/1.1\r\n")
  assert string.contains(second_text, "authorization: Bearer retained\r\n")
  assert !string.contains(second_text, "Content-Type:")
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn configured_status_retry_replays_an_idempotent_request_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 503 Service Unavailable\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(second, 4096, 1000))
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
        >>),
      )
      transport.close(second)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_retry_policy(
      client.RetryPolicy(enabled: True, maximum: 1, retry_statuses: [503]),
    )
  let assert Ok(running) = client.start(config)

  let assert Ok(incoming) = client.fetch(running, request_for(port, "/", <<>>))
  assert incoming.status == 200
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(incoming.body, 2)
  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn pool_policy_is_validated_and_can_be_disabled_test() -> Nil {
  let limits =
    client.PoolLimits(
      maximum_connections: 12,
      maximum_connections_per_origin: 3,
      idle_milliseconds: 750,
    )
  let assert Ok(config) = client.with_pool_limits(client.defaults(), limits)
  assert client.pool_limits(config) == limits
  assert client.pooling_enabled(config)
  assert !client.pooling_enabled(client.without_pooling(config))

  let assert Error(failure) =
    client.with_pool_limits(
      config,
      client.PoolLimits(
        maximum_connections: 2,
        maximum_connections_per_origin: 3,
        idle_milliseconds: 750,
      ),
    )
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
}

pub fn body_limits_are_validated_and_replaceable_test() -> Nil {
  let limits =
    client.BodyLimits(
      buffered_bytes: 4096,
      stream_buffer_bytes: 1024,
      endpoint_memory_bytes: 8192,
    )
  let assert Ok(config) = client.with_body_limits(client.defaults(), limits)
  assert client.body_limits(config) == limits

  let assert Error(failure) =
    client.with_body_limits(
      config,
      client.BodyLimits(
        buffered_bytes: 8193,
        stream_buffer_bytes: 1024,
        endpoint_memory_bytes: 8192,
      ),
    )
  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
}

pub fn cookie_store_is_bounded_partitioned_and_disabled_by_default_test() -> Nil {
  let config = client.defaults()
  assert client.cookie_policy(config)
    == client.CookiePolicy(
      enabled: False,
      limits: client.StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
    )
  assert client.network_isolation_key(config)
    == client.NetworkIsolationKey(top_level_site: "", profile: "default")

  let assert Ok(configured) =
    client.enable_cookies(
      config,
      client.StoreLimits(maximum_entries: 8, maximum_bytes: 4096),
    )
  assert client.cookie_policy(configured)
    == client.CookiePolicy(
      enabled: True,
      limits: client.StoreLimits(maximum_entries: 8, maximum_bytes: 4096),
    )
  let assert Ok(partitioned) =
    client.with_network_isolation_key(
      configured,
      client.NetworkIsolationKey(
        top_level_site: "https://site.example",
        profile: "private",
      ),
    )
  assert client.network_isolation_key(partitioned)
    == client.NetworkIsolationKey(
      top_level_site: "https://site.example",
      profile: "private",
    )
}

pub fn typed_policy_adapter_timeout_fails_client_start_closed_test() -> Nil {
  assert client.cookie_store_adapter(client.defaults()) == None
  let assert Ok(adapter) =
    client_store.new(
      fn(_, timeout_milliseconds) {
        assert timeout_milliseconds == 10
        process.sleep(100)
        Ok([])
      },
      fn(_, _, _) { Ok(Nil) },
      fn(_, _, _) { Ok(Nil) },
      10,
    )
  let configured =
    client.defaults()
    |> client.with_cookie_store_adapter(adapter)
  let started = transport.monotonic_millisecond()
  let assert Error(failure) = client.start(configured)
  let elapsed = transport.monotonic_millisecond() - started

  assert error.kind(failure) == error.Policy(error.SecurityPolicy)
  assert elapsed < 500
}

pub fn typed_cookie_adapter_loads_partition_and_persists_mutations_test() -> Nil {
  let partition =
    client_store.Partition(
      top_level_site: "https://top.example",
      profile: "private",
    )
  let mutations = process.new_subject()
  let assert Ok(adapter) =
    client_store.new(
      fn(received_partition, timeout_milliseconds) {
        assert received_partition == partition
        assert timeout_milliseconds == 250
        Ok([
          client_store.CookieRecord(
            key: "127.0.0.1\u{0000}/\u{0000}loaded",
            name: "loaded",
            value: "yes",
            domain: "127.0.0.1",
            path: "/",
            host_only: True,
            secure: False,
            expires_in_milliseconds: 60_000,
            age_milliseconds: 0,
          ),
        ])
      },
      fn(received_partition, record, timeout_milliseconds) {
        process.send(mutations, #(
          received_partition,
          record,
          timeout_milliseconds,
        ))
        Ok(Nil)
      },
      fn(_, _, _) { Ok(Nil) },
      250,
    )
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use received <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(request_bytes, socket) = received
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          // Only the first of these outlives the session, so only the first reaches the adapter.
          // RFC 6265 section 5.3 clears the persistent flag on a cookie carrying neither Expires nor Max-Age, and removes every such cookie when the session ends.
          "Set-Cookie: stored=fresh; Path=/; Max-Age=60\r\n":utf8,
          "Set-Cookie: session=only; Path=/\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(request_bytes)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(
      maximum_entries: 8,
      maximum_bytes: 4096,
    ))
  let assert Ok(config) =
    client.with_network_isolation_key(
      config,
      client.NetworkIsolationKey(
        top_level_site: "https://top.example",
        profile: "private",
      ),
    )
  let assert Ok(running) =
    config
    |> client.with_cookie_store_adapter(adapter)
    |> client.start
  let assert Ok(_) = client.fetch(running, request_for(port, "/", <<>>))

  let assert Ok(request_bytes) = http_test_support.await_task(server_task)
  let assert Ok(request_text) = bit_array.to_string(request_bytes)
  assert string.contains(request_text, "cookie: loaded=yes\r\n")
  let assert Ok(#(received_partition, record, timeout_milliseconds)) =
    process.receive(mutations, within: 1000)
  assert received_partition == partition
  assert timeout_milliseconds == 250
  assert record.name == "stored"
  assert record.value == "fresh"
  assert record.host_only
  // The session cookie produced no adapter mutation at all, which is what leaves it unable to outlive this client.
  assert process.receive(mutations, within: 100) == Error(Nil)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn typed_cache_adapter_loads_a_bounded_complete_response_test() -> Nil {
  let partition =
    client_store.Partition(
      top_level_site: "https://top.example",
      profile: "private",
    )
  let assert Ok(adapter) =
    client_store.new(
      fn(received_partition, timeout_milliseconds) {
        assert received_partition == partition
        assert timeout_milliseconds == 250
        Ok([
          client_store.CacheRecord(
            key: "http://127.0.0.1:9/persisted",
            status: 200,
            headers: [#("content-length", "9")],
            bytes: <<"persisted":utf8>>,
            trailers: [],
            expires_in_milliseconds: 60_000,
          ),
        ])
      },
      fn(_, _, _) { Ok(Nil) },
      fn(_, _, _) { Ok(Nil) },
      250,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cache(client.StoreLimits(
      maximum_entries: 4,
      maximum_bytes: 4096,
    ))
  let assert Ok(config) =
    client.with_network_isolation_key(
      config,
      client.NetworkIsolationKey(
        top_level_site: "https://top.example",
        profile: "private",
      ),
    )
  let assert Ok(running) =
    config
    |> client.with_cache_store_adapter(adapter)
    |> client.start
  let assert Ok(incoming) =
    client.fetch(running, request_for(9, "/persisted", <<>>))
  let assert Ok(#(<<"persisted":utf8>>, [])) = body.read_all(incoming.body, 9)

  let assert Ok(Nil) = client.close(running)
  Nil
}

pub fn typed_policy_expiry_headers_invoke_exact_partition_removals_test() -> Nil {
  let partition =
    client_store.Partition(
      top_level_site: "https://top.example",
      profile: "private",
    )
  let removals = process.new_subject()
  let assert Ok(cookie_adapter) =
    client_store.new(
      fn(_, _) { Ok([]) },
      fn(_, _, _) { Ok(Nil) },
      fn(received_partition, key, timeout_milliseconds) {
        process.send(
          removals,
          CookieRemoval(received_partition, key, timeout_milliseconds),
        )
        Ok(Nil)
      },
      250,
    )
  let assert Ok(hsts_adapter) =
    client_store.new(
      fn(_, _) { Ok([]) },
      fn(_, _, _) { Ok(Nil) },
      fn(received_partition, key, timeout_milliseconds) {
        process.send(
          removals,
          HstsRemoval(received_partition, key, timeout_milliseconds),
        )
        Ok(Nil)
      },
      250,
    )
  let assert Ok(alt_svc_adapter) =
    client_store.new(
      fn(_, _) { Ok([]) },
      fn(_, _, _) { Ok(Nil) },
      fn(received_partition, key, timeout_milliseconds) {
        process.send(
          removals,
          AltSvcRemoval(received_partition, key, timeout_milliseconds),
        )
        Ok(Nil)
      },
      250,
    )
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(_, _) {
    Ok(response.Response(
      status: 200,
      headers: [
        #("set-cookie", "sid=gone; Path=/; Max-Age=0"),
        #("strict-transport-security", "max-age=0"),
        #("alt-svc", "clear"),
      ],
      body: body.empty(),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(config) =
    client.defaults()
    |> client.enable_cookies(client.StoreLimits(
      maximum_entries: 8,
      maximum_bytes: 4096,
    ))
  let assert Ok(config) =
    client.with_network_isolation_key(
      config,
      client.NetworkIsolationKey(
        top_level_site: "https://top.example",
        profile: "private",
      ),
    )
  let assert Ok(running) =
    config
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_cookie_store_adapter(cookie_adapter)
    |> client.with_hsts_store_adapter(hsts_adapter)
    |> client.with_alt_svc_store_adapter(alt_svc_adapter)
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/expire",
      query: None,
    )
  let assert Ok(_) = client.fetch(running, outgoing)
  let assert Ok(cookie_removal) = process.receive(removals, within: 1000)
  let assert Ok(hsts_removal) = process.receive(removals, within: 1000)
  let assert Ok(alt_svc_removal) = process.receive(removals, within: 1000)

  assert cookie_removal
    == CookieRemoval(partition, "localhost\u{0000}/\u{0000}sid", 250)
  assert hsts_removal == HstsRemoval(partition, "localhost", 250)
  assert alt_svc_removal
    == AltSvcRemoval(partition, "localhost:" <> int.to_string(port), 250)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn origin_misdirected_response_ignores_its_alt_svc_header_test() -> Nil {
  // RFC 7838 section 6 requires ignoring Alt-Svc on every 421 response.
  // Cache removal applies to a response from the alternative service.
  let events = process.new_subject()
  let assert Ok(alt_svc_adapter) =
    client_store.new(
      fn(_, _) { Ok([]) },
      fn(_, record: client_store.AltSvcRecord, _) {
        process.send(events, AltSvcUpsert(record.key, record.alternative_port))
        Ok(Nil)
      },
      fn(received_partition, key, timeout_milliseconds) {
        process.send(
          events,
          AltSvcRemoval(received_partition, key, timeout_milliseconds),
        )
        Ok(Nil)
      },
      250,
    )
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let statuses = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    process.send(statuses, incoming.path)
    let status = case incoming.path {
      "/learn" -> 200
      _ -> 421
    }
    Ok(response.Response(
      status: status,
      headers: [#("alt-svc", "h3=\":8443\"; ma=3600")],
      body: body.empty(),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(config) =
    client.with_network_isolation_key(
      client.defaults(),
      client.NetworkIsolationKey(
        top_level_site: "https://top.example",
        profile: "private",
      ),
    )
  let assert Ok(running) =
    config
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_alt_svc_store_adapter(alt_svc_adapter)
    |> client.with_http3_connect_gate(fn() {
      Error(error.new(error.ConnectFailed))
    })
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/learn",
      query: None,
    )
  let key = "localhost:" <> int.to_string(port)

  let assert Ok(learned) = client.fetch(running, outgoing)
  assert learned.status == 200
  assert process.receive(events, within: 1000) == Ok(AltSvcUpsert(key, 8443))

  let assert Ok(misdirected) =
    client.fetch(running, request.Request(..outgoing, path: "/moved"))
  assert misdirected.status == 421
  // The origin's 421 cannot advertise a replacement or withdraw an alternative that did not serve the response.
  assert process.receive(events, within: 250) == Error(Nil)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn a_refreshed_cookie_keeps_the_creation_time_it_had_test() -> Nil {
  // RFC 6265 section 5.3 step 11: a Set-Cookie that replaces a cookie with the same name, domain, and path keeps the creation time of the one it replaces.
  // Without that, refreshing a value moves the cookie to the end of the order section 5.4 asks for, so a server reading the first of two equally specific cookies would see a different one after every refresh.
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let respond = fn(socket, fields) {
    use _ <- result.try(transport.read(socket, 4096, 1000))
    transport.send(socket, <<
      "HTTP/1.1 200 OK\r\n":utf8,
      fields:utf8,
      "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
    >>)
  }
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(respond(
        first,
        "Set-Cookie: a=one; Path=/; Max-Age=60\r\nSet-Cookie: b=two; Path=/; Max-Age=60\r\n",
      ))
      use _ <- result.try(transport.close(first))

      // The second response refreshes the cookie that was created first.
      use second <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(respond(
        second,
        "Set-Cookie: a=refreshed; Path=/; Max-Age=60\r\n",
      ))
      use _ <- result.try(transport.close(second))

      use third <- result.try(transport.accept(listener, 1000))
      use third_read <- result.try(transport.read(third, 4096, 1000))
      let assert transport.ReadData(third_request, third) = third_read
      use _ <- result.try(
        transport.send(third, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(third))
      Ok(third_request)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(
      maximum_entries: 8,
      maximum_bytes: 4096,
    ))
  let assert Ok(running) = client.start(config)
  let assert Ok(_) = client.fetch(running, request_for(port, "/", <<>>))
  let assert Ok(_) = client.fetch(running, request_for(port, "/", <<>>))
  let assert Ok(_) = client.fetch(running, request_for(port, "/", <<>>))

  let assert Ok(third_request) = http_test_support.await_task(server_task)
  let assert Ok(third_text) = bit_array.to_string(third_request)
  // The refreshed cookie keeps its place ahead of the one set after it.
  assert string.contains(third_text, "cookie: a=refreshed; b=two\r\n")
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn a_crowded_domain_loses_its_cookies_before_another_domain_does_test() -> Nil {
  // RFC 6265 section 5.3: excess cookies go in priority order, and a cookie sharing a domain with more than a predetermined number of others goes before any other cookie.
  // The number here is half the store's entry ceiling.
  //
  // One cookie is set for the first host and then three for the second, on a store of three.
  // The first host's cookie is the oldest of the four, so it is the one a store that only counted last access would drop; what has to survive is that one, at the expense of the crowded host's oldest.
  let first = "cookie-crowd-one.test"
  let second = "cookie-crowd-two.test"
  use <- http_test_support.with_loopback_hosts([first, second])
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let exchange = fn(fields) {
    use socket <- result.try(transport.accept(listener, 1000))
    use read <- result.try(transport.read(socket, 4096, 1000))
    let assert transport.ReadData(received, socket) = read
    use _ <- result.try(
      transport.send(socket, <<
        "HTTP/1.1 200 OK\r\n":utf8,
        fields:utf8,
        "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
      >>),
    )
    use _ <- result.try(transport.close(socket))
    Ok(received)
  }
  let server_task =
    http_test_support.start_task(fn() {
      use _ <- result.try(exchange(
        "Set-Cookie: keep=me; Path=/; Max-Age=60\r\n",
      ))
      use _ <- result.try(exchange("Set-Cookie: a=1; Path=/; Max-Age=60\r\n"))
      use _ <- result.try(exchange("Set-Cookie: b=2; Path=/; Max-Age=60\r\n"))
      use _ <- result.try(exchange("Set-Cookie: c=3; Path=/; Max-Age=60\r\n"))
      exchange("")
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(
      maximum_entries: 3,
      maximum_bytes: 4096,
    ))
  let assert Ok(running) = client.start(config)
  let named = fn(host) {
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Http,
      host: host,
      port: Some(port),
      path: "/",
      query: None,
    )
  }
  let assert Ok(_) = client.fetch(running, named(first))
  let assert Ok(_) = client.fetch(running, named(second))
  let assert Ok(_) = client.fetch(running, named(second))
  let assert Ok(_) = client.fetch(running, named(second))
  let assert Ok(_) = client.fetch(running, named(first))

  let assert Ok(final_request) = http_test_support.await_task(server_task)
  let assert Ok(final_text) = bit_array.to_string(final_request)
  assert string.contains(final_text, "cookie: keep=me\r\n")
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn enabled_cookie_store_applies_a_scoped_unexpired_cookie_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Set-Cookie: sid=bounded; Path=/account; Max-Age=60; HttpOnly\r\n":utf8,
          "Content-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use second_read <- result.try(transport.read(second, 4096, 1000))
      let assert transport.ReadData(second_request, second) = second_read
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(second_request)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cookies(client.StoreLimits(
      maximum_entries: 8,
      maximum_bytes: 4096,
    ))
  let assert Ok(running) = client.start(config)
  let assert Ok(_) =
    client.fetch(running, request_for(port, "/account/set", <<>>))
  let assert Ok(_) =
    client.fetch(running, request_for(port, "/account/view", <<>>))

  let assert Ok(second_request) = http_test_support.await_task(server_task)
  let assert Ok(second_text) = bit_array.to_string(second_request)
  assert string.contains(second_text, "cookie: sid=bounded\r\n")
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn response_cache_is_finite_and_disabled_by_default_test() -> Nil {
  let config = client.defaults()
  assert client.cache_policy(config)
    == client.CachePolicy(
      enabled: False,
      limits: client.StoreLimits(
        maximum_entries: 256,
        maximum_bytes: 16_777_216,
      ),
    )
  let assert Ok(configured) =
    client.enable_cache(
      config,
      client.StoreLimits(maximum_entries: 4, maximum_bytes: 4096),
    )
  assert client.cache_policy(configured)
    == client.CachePolicy(
      enabled: True,
      limits: client.StoreLimits(maximum_entries: 4, maximum_bytes: 4096),
    )
}

pub fn enabled_cache_reuses_only_an_explicitly_fresh_get_response_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(socket, 4096, 1000))
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Cache-Control: max-age=60\r\n":utf8,
          "Content-Length: 6\r\nConnection: close\r\n\r\ncached":utf8,
        >>),
      )
      transport.close(socket)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cache(client.StoreLimits(
      maximum_entries: 4,
      maximum_bytes: 4096,
    ))
  let assert Ok(running) = client.start(config)
  let outgoing = request_for(port, "/cache", <<>>)
  let assert Ok(first) = client.fetch(running, outgoing)
  let assert Ok(#(<<"cached":utf8>>, [])) = body.read_all(first.body, 6)
  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)

  let assert Ok(second) = client.fetch(running, outgoing)
  let assert Ok(#(<<"cached":utf8>>, [])) = body.read_all(second.body, 6)
  let assert Ok(Nil) = client.close(running)
  Nil
}

pub fn an_unsafe_request_drops_the_cached_response_for_its_target_test() -> Nil {
  // RFC 9111 section 4.4: a non-error answer to an unsafe request invalidates the target URI.
  // Without that, the read after a write serves what the write replaced.
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let cacheable = fn(payload: String) {
    <<
      "HTTP/1.1 200 OK\r\n":utf8,
      "Cache-Control: max-age=60\r\n":utf8,
      "Content-Length: 5\r\nConnection: close\r\n\r\n":utf8,
      payload:utf8,
    >>
  }
  let server_task =
    http_test_support.start_task(fn() {
      // The first read, which is cached.
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(transport.send(first, cacheable("aaaaa")))
      use _ <- result.try(transport.close(first))

      // The write, whose answer invalidates that entry.
      use second <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(second, 4096, 1000))
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))

      // The read after it, which only happens if the entry went.
      use third <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(third, 4096, 1000))
      use _ <- result.try(transport.send(third, cacheable("bbbbb")))
      transport.close(third)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.enable_cache(client.StoreLimits(
      maximum_entries: 4,
      maximum_bytes: 4096,
    ))
  let assert Ok(running) = client.start(config)
  let read = request_for(port, "/thing", <<>>)

  let assert Ok(first) = client.fetch(running, read)
  let assert Ok(#(<<"aaaaa":utf8>>, [])) = body.read_all(first.body, 5)

  let write = request.Request(..read, method: gleam_http.Post)
  let assert Ok(written) = client.fetch(running, write)
  assert written.status == 204

  let assert Ok(third) = client.fetch(running, read)
  let assert Ok(#(<<"bbbbb":utf8>>, [])) = body.read_all(third.body, 5)

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn hsts_is_enabled_with_a_finite_store_and_can_be_disabled_test() -> Nil {
  let config = client.defaults()
  assert client.hsts_policy(config)
    == client.HstsPolicy(
      enabled: True,
      limits: client.StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
    )
  assert client.hsts_policy(client.without_hsts(config))
    == client.HstsPolicy(
      enabled: False,
      limits: client.StoreLimits(maximum_entries: 256, maximum_bytes: 65_536),
    )
}

pub fn verified_hsts_policy_upgrades_a_later_cleartext_uri_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let schemes = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    process.send(schemes, incoming.scheme)
    Ok(response.Response(
      status: 200,
      headers: [#("strict-transport-security", "max-age=60")],
      body: body.from_text("secure"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let secure =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/learn",
      query: None,
    )
  let cleartext =
    request.Request(..secure, scheme: gleam_http.Http, path: "/use")

  let assert Ok(first) = client.fetch(running, secure)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(first.body, 6)
  let assert Ok(second) = client.fetch(running, cleartext)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(second.body, 6)
  assert process.receive(schemes, within: 1000) == Ok(gleam_http.Https)
  assert process.receive(schemes, within: 1000) == Ok(gleam_http.Https)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn hsts_processes_only_the_first_header_field_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), _) {
    case incoming.path {
      "/learn" ->
        Ok(response.Response(
          status: 200,
          headers: [
            #("strict-transport-security", "max-age=invalid"),
            #("strict-transport-security", "max-age=60"),
          ],
          body: body.from_text("secure"),
        ))
      _ ->
        Ok(response.Response(
          status: 200,
          headers: [],
          body: body.from_text("cleartext"),
        ))
    }
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(secure_listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(cleartext_listener) =
    server.listen_http1(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults() |> server.allow_http1_cleartext,
    )
  let context.Endpoint(_, secure_port) =
    server.listener_endpoint(secure_listener)
  let context.Endpoint(_, cleartext_port) =
    server.listener_endpoint(cleartext_listener)
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let secure =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(secure_port),
      path: "/learn",
      query: None,
    )
  let cleartext =
    request.Request(
      ..secure,
      scheme: gleam_http.Http,
      port: Some(cleartext_port),
      path: "/after",
    )

  let assert Ok(first) = client.fetch(running, secure)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(first.body, 6)
  let assert Ok(second) = client.fetch(running, cleartext)
  let assert Ok(#(<<"cleartext":utf8>>, [])) = body.read_all(second.body, 9)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(secure_listener)
  let assert Ok(Nil) = server.stop_listener(secure_listener)
  let assert Ok(Nil) = server.drain_listener(cleartext_listener)
  let assert Ok(Nil) = server.stop_listener(cleartext_listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn hsts_ignores_insecure_headers_and_survives_missing_secure_headers_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let observed = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    process.send(observed, #(incoming.path, incoming.scheme))
    let headers = case incoming.path {
      "/learn" | "/insecure-learn" -> [
        #("strict-transport-security", "max-age=60"),
      ]
      _ -> []
    }
    Ok(response.Response(status: 200, headers:, body: body.from_text("ok")))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(secure_listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let assert Ok(cleartext_listener) =
    server.listen_http1(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http1_defaults() |> server.allow_http1_cleartext,
    )
  let context.Endpoint(_, secure_port) =
    server.listener_endpoint(secure_listener)
  let context.Endpoint(_, cleartext_port) =
    server.listener_endpoint(cleartext_listener)

  let assert Ok(learned_client) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let secure =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(secure_port),
      path: "/learn",
      query: None,
    )
  let assert Ok(learned) = client.fetch(learned_client, secure)
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(learned.body, 2)
  let assert Ok(missing) =
    client.fetch(learned_client, request.Request(..secure, path: "/missing"))
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(missing.body, 2)
  let assert Ok(still_upgraded) =
    client.fetch(
      learned_client,
      request.Request(..secure, scheme: gleam_http.Http, path: "/after-missing"),
    )
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(still_upgraded.body, 2)
  let assert Ok(Nil) = client.close(learned_client)

  let assert Ok(cleartext_client) =
    client.defaults() |> client.allow_plain_http |> client.start
  let cleartext =
    request.Request(
      ..secure,
      scheme: gleam_http.Http,
      port: Some(cleartext_port),
      path: "/insecure-learn",
    )
  let assert Ok(insecure) = client.fetch(cleartext_client, cleartext)
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(insecure.body, 2)
  let assert Ok(not_upgraded) =
    client.fetch(
      cleartext_client,
      request.Request(..cleartext, path: "/after-insecure"),
    )
  let assert Ok(#(<<"ok":utf8>>, [])) = body.read_all(not_upgraded.body, 2)
  let assert Ok(Nil) = client.close(cleartext_client)

  assert process.receive(observed, within: 1000)
    == Ok(#("/learn", gleam_http.Https))
  assert process.receive(observed, within: 1000)
    == Ok(#("/missing", gleam_http.Https))
  assert process.receive(observed, within: 1000)
    == Ok(#("/after-missing", gleam_http.Https))
  assert process.receive(observed, within: 1000)
    == Ok(#("/insecure-learn", gleam_http.Http))
  assert process.receive(observed, within: 1000)
    == Ok(#("/after-insecure", gleam_http.Http))

  let assert Ok(Nil) = server.drain_listener(secure_listener)
  let assert Ok(Nil) = server.stop_listener(secure_listener)
  let assert Ok(Nil) = server.drain_listener(cleartext_listener)
  let assert Ok(Nil) = server.stop_listener(cleartext_listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn hsts_upgrade_never_bypasses_tls_authentication_failure_test() -> Nil {
  let #(certificate, private_key, _) = http_test_support.server_credentials()
  let handled = process.new_subject()
  let assert Ok(executor) =
    server.start(server.defaults(), fn(_, _) {
      process.send(handled, Nil)
      Ok(response.new(200) |> response.set_body(body.empty()))
    })
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(adapter) =
    client_store.new(
      fn(_, _) {
        Ok([
          client_store.HstsRecord(
            key: "localhost",
            host: "localhost",
            include_subdomains: False,
            expires_in_milliseconds: 60_000,
          ),
        ])
      },
      fn(_, _, _) { Ok(Nil) },
      fn(_, _, _) { Ok(Nil) },
      250,
    )
  let assert Ok(running) =
    client.defaults()
    |> client.without_retries
    |> client.with_hsts_store_adapter(adapter)
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Http,
      host: "localhost",
      port: Some(port),
      path: "/must-remain-authenticated",
      query: None,
    )

  assert client.fetch(running, outgoing) |> result.map_error(error.kind)
    == Error(error.Tls)
  assert process.receive(handled, within: 50) == Error(Nil)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn protocol_discovery_is_bounded_and_can_be_disabled_test() -> Nil {
  let config = client.defaults()
  assert client.discovery_policy(config)
    == client.DiscoveryPolicy(
      enabled: True,
      alt_svc_limits: client.StoreLimits(
        maximum_entries: 256,
        maximum_bytes: 65_536,
      ),
      https_record_timeout_milliseconds: 1000,
    )
  assert client.discovery_policy(client.without_protocol_discovery(config))
    == client.DiscoveryPolicy(
      enabled: False,
      alt_svc_limits: client.StoreLimits(
        maximum_entries: 256,
        maximum_bytes: 65_536,
      ),
      https_record_timeout_milliseconds: 1000,
    )
}

pub fn https_record_discovery_cannot_extend_the_total_deadline_test() -> Nil {
  assert client.https_record_resolver_budget(1000, 10_000, 100) == 1000
  assert client.https_record_resolver_budget(1000, 10_000, 9500) == 500
  assert client.https_record_resolver_budget(1000, 10_000, 10_000) == 0
  // Resuming after the retained boundary cannot manufacture a fresh budget.
  assert client.https_record_resolver_budget(1000, 10_000, 10_250) == 0
}

pub fn alt_svc_age_expiry_is_applied_before_the_next_route_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(_: request.Request(body.Body), _request_context) {
    Ok(response.Response(
      status: 200,
      headers: [#("age", "70"), #("alt-svc", "h3=\":65534\"; ma=60")],
      body: body.from_text("tcp"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let resolver_calls = process.new_subject()
  let resolver = fn(host, origin_port, timeout_milliseconds) {
    assert host == "localhost"
    assert origin_port == port
    assert timeout_milliseconds == 1000
    process.send(resolver_calls, Nil)
    Ok([])
  }
  let assert Ok(running) =
    client.defaults()
    |> client.with_https_record_resolver(resolver)
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/aged-alt-svc",
      query: None,
    )

  let assert Ok(first) = client.exchange(running, outgoing)
  let assert Ok(#(<<"tcp":utf8>>, [])) =
    body.read_all(client.response(first).body, 3)
  let assert Ok(next_body) = body.replay(outgoing.body)
  let assert Ok(second) =
    client.exchange(
      running,
      request.Request(..outgoing, path: "/after-age", body: next_body),
    )
  let assert Ok(#(<<"tcp":utf8>>, [])) =
    body.read_all(client.response(second).body, 3)
  assert process.receive(resolver_calls, within: 1000) == Ok(Nil)
  assert process.receive(resolver_calls, within: 1000) == Ok(Nil)
  assert process.receive(resolver_calls, within: 0) == Error(Nil)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn verified_alt_svc_enables_http3_for_a_replayable_origin_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(advertised_port) = h3_server.port(udp_listener)
  let handler = fn(_: request.Request(body.Body), _request_context) {
    Ok(response.Response(
      status: 200,
      headers: [
        #("alt-svc", "h3=\":" <> int.to_string(advertised_port) <> "\"; ma=60"),
      ],
      body: body.from_text("tcp"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(tcp_configuration) =
    server.with_http2_timeouts(
      server.http2_defaults(),
      5000,
      1000,
      5000,
      5000,
      5000,
    )
  let assert Ok(tcp_listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      tcp_configuration,
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(tcp_listener)

  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      h3_server.respond(incoming, 200, [], <<"quic":utf8>>)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.without_pooling
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/discovery",
      query: None,
    )

  let assert Ok(first) = client.exchange(running, outgoing)
  assert client.selected_protocol(first) == client.Http2
  let assert Ok(#(<<"tcp":utf8>>, [])) =
    body.read_all(client.response(first).body, 3)
  // Discovery races verified connections.
  // Remove the TCP route after the authenticated advertisement instead of delaying application responses.
  let assert Ok(Nil) = server.stop_listener(tcp_listener)
  let assert Ok(next_body) = body.replay(outgoing.body)
  let assert Ok(second) =
    client.exchange(
      running,
      request.Request(..outgoing, path: "/prefer-h3", body: next_body),
    )
  assert client.selected_protocol(second) == client.Http3
  let assert Ok(#(<<"quic":utf8>>, [])) =
    body.read_all(client.response(second).body, 4)
  let assert Ok(Nil) = http_test_support.await_task(h3_task)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)
  let assert Ok(Nil) = server.drain_listener(tcp_listener)
  let assert Ok(Nil) = server.stop_listener(tcp_listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn verified_alt_svc_races_http3_against_the_tcp_route_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(advertised_port) = h3_server.port(udp_listener)
  let expected_request_body = <<"race-body":utf8>>
  let tcp_request_observed = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _request_context) {
    case incoming.path {
      "/learn-race" ->
        Ok(response.Response(
          status: 200,
          headers: [
            #(
              "alt-svc",
              "h3=\":" <> int.to_string(advertised_port) <> "\"; ma=60",
            ),
          ],
          body: body.from_text("learned"),
        ))
      _ -> {
        use #(request_body, trailers) <- result.try(body.read_all(
          incoming.body,
          bit_array.byte_size(expected_request_body),
        ))
        process.send(tcp_request_observed, #(
          bit_array.byte_size(request_body),
          request_body == expected_request_body,
          list.length(trailers),
        ))
        Ok(response.Response(
          status: 200,
          headers: [],
          body: body.from_text("tcp-winner"),
        ))
      }
    }
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(tcp_listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(tcp_listener)
  let h3_requested = process.new_subject()
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      process.send(h3_requested, Nil)
      h3_server.respond(incoming, 200, [], <<"unexpected-quic":utf8>>)
    })
  let gate_ready = process.new_subject()
  let gate_task =
    http_test_support.start_task(fn() {
      let h3_authenticated = process.new_subject()
      let tcp_waiting = process.new_subject()
      process.send(gate_ready, #(h3_authenticated, tcp_waiting))
      use _ <- result.try(process.receive(h3_authenticated, within: 5000))
      use release_tcp <- result.try(process.receive(tcp_waiting, within: 5000))
      process.send(release_tcp, Nil)
      Ok(Nil)
    })
  let #(h3_authenticated, tcp_waiting) =
    process.receive(gate_ready, within: 1000) |> should.be_ok
  let ordered_tcp_candidate = process.new_subject()
  let candidate_gate = fn(candidate, deadline) {
    let remaining = fn() {
      int.max(0, deadline - transport.monotonic_millisecond())
    }
    case candidate {
      client.Http3AuthenticatedCandidate -> {
        let never_release_h3 = process.new_subject()
        process.send(h3_authenticated, Nil)
        case process.receive(never_release_h3, within: remaining()) {
          Ok(Nil) -> Ok(Nil)
          Error(Nil) -> Error(error.new(error.Timeout(error.Total)))
        }
      }
      client.TcpAuthenticatedCandidate -> {
        let permitted = process.new_subject()
        process.send(tcp_waiting, permitted)
        use _ <- result.try(
          process.receive(permitted, within: remaining())
          |> result.replace_error(error.new(error.Timeout(error.Total))),
        )
        process.send(ordered_tcp_candidate, Nil)
        Ok(Nil)
      }
    }
  }
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 1000,
      connect_milliseconds: 2000,
      tls_milliseconds: 2000,
      operation_milliseconds: 2000,
      idle_milliseconds: 2000,
      total_milliseconds: 5000,
    )
  let assert Ok(configuration) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_https_race_candidate_gate(candidate_gate)
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(configuration)
  let base =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/learn-race",
      query: None,
    )
  let assert Ok(learned) = client.exchange(running, base)
  let assert Ok(#(<<"learned":utf8>>, [])) =
    body.read_all(client.response(learned).body, 7)
  let pulls = process.new_subject()
  let source =
    body.pull(fn(_) {
      process.send(pulls, Nil)
      Ok(body.PullData(
        expected_request_body,
        body.pull(fn(_) { Ok(body.PullEnd([])) }),
      ))
    })
  let assert Ok(non_replayable_body) =
    body.from_pull(
      source,
      Some(bit_array.byte_size(expected_request_body)),
      None,
      fn() { Nil },
    )
  assert !body.is_replayable(non_replayable_body)
  let raced =
    client.exchange(
      running,
      request.Request(
        ..base,
        method: gleam_http.Post,
        path: "/race",
        body: non_replayable_body,
      ),
    )
  let completed = case raced {
    Error(failure) -> Error(failure)
    Ok(exchange) ->
      body.read_all(client.response(exchange).body, 10)
      |> result.map(fn(contents) {
        #(
          client.selected_protocol(exchange),
          client.response(exchange).status,
          bit_array.byte_size(contents.0),
          contents.0 == <<"tcp-winner":utf8>>,
          list.length(contents.1),
        )
      })
  }
  let ordered = process.receive(ordered_tcp_candidate, within: 0)
  let tcp_request = process.receive(tcp_request_observed, within: 0)
  let first_pull = process.receive(pulls, within: 0)

  let closed = client.close(running)
  let extra_pull = process.receive(pulls, within: 0)
  let extra_tcp_request = process.receive(tcp_request_observed, within: 0)
  let extra_tcp_candidate = process.receive(ordered_tcp_candidate, within: 0)
  let h3_stopped = h3_server.stop(udp_listener)
  let _h3_outcome = http_test_support.await_task(h3_task)
  let h3_request_count = case process.receive(h3_requested, within: 0) {
    Ok(Nil) -> 1
    Error(Nil) -> 0
  }
  let tcp_drained = server.drain_listener(tcp_listener)
  let tcp_stopped = server.stop_listener(tcp_listener)
  let executor_stopped = server.stop(executor)
  let gate_done = http_test_support.await_task(gate_task)
  assert gate_done == Ok(Nil)
  assert completed == Ok(#(client.Http2, 200, 10, True, 0))
  assert ordered == Ok(Nil)
  assert tcp_request
    == Ok(#(bit_array.byte_size(expected_request_body), True, 0))
  assert first_pull == Ok(Nil)
  assert extra_pull == Error(Nil)
  assert extra_tcp_request == Error(Nil)
  assert extra_tcp_candidate == Error(Nil)
  assert h3_request_count == 0
  assert closed == Ok(Nil)
  assert h3_stopped == Ok(h3_server.Stopped)
  assert tcp_drained == Ok(Nil)
  assert tcp_stopped == Ok(Nil)
  assert executor_stopped == Ok(Nil)
  Nil
}

pub fn authenticated_http3_connect_failure_continues_with_tcp_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let http3_failed_ready = process.new_subject()
  let connect_attempts = process.new_subject()
  let server_task =
    http_test_support.start_task(fn() {
      let http3_failed = process.new_subject()
      process.send(http3_failed_ready, http3_failed)
      let assert Ok(socket) = transport.accept(listener, 1000)

      // Keep the TCP route unauthenticated until the HTTP/3 contender has reported its injected connection failure.
      // This proves fallback after failure rather than merely observing TCP win the race first.
      assert process.receive(http3_failed, within: 1000) == Ok(Nil)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
      let assert Ok(Nil) = transport.send(socket, initial)
      let assert Ok(transport.ReadData(_, socket)) =
        transport.read(socket, 65_536, 1000)
      let assert Ok(headers) =
        frame.encode(frame.Headers, 0x4, 1, <<0x88>>, 16_384)
      let assert Ok(Nil) = transport.send(socket, headers)
      let assert Ok(data) =
        frame.encode(
          frame.Data,
          0x1,
          1,
          <<"tcp-after-h3-failure":utf8>>,
          16_384,
        )
      let assert Ok(Nil) = transport.send(socket, data)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let assert Ok(http3_failed) =
    process.receive(http3_failed_ready, within: 1000)
  let resolver = fn(host, origin_port, timeout_milliseconds) {
    assert host == "localhost"
    assert origin_port == port
    assert timeout_milliseconds == 1000
    Ok([
      client.HttpsRecord(
        alpns: ["h3"],
        port: 65_534,
        authenticated: True,
        expires_in_milliseconds: 60_000,
      ),
    ])
  }
  let connect_gate = fn() {
    process.send(connect_attempts, Nil)
    process.send(http3_failed, Nil)
    Error(error.new(error.ConnectFailed))
  }
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 1000,
      tls_milliseconds: 1000,
      operation_milliseconds: 1000,
      idle_milliseconds: 1000,
      total_milliseconds: 3000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.with_https_record_resolver(resolver)
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_http3_connect_gate(connect_gate)
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/after-h3-connect-failure",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  assert client.selected_protocol(completed) == client.Http2
  let assert Ok(#(<<"tcp-after-h3-failure":utf8>>, [])) =
    body.read_all(client.response(completed).body, 20)
  assert http_test_support.await_task(server_task) == Nil
  assert process.receive(connect_attempts, within: 0) == Ok(Nil)
  assert process.receive(connect_attempts, within: 0) == Error(Nil)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn http3_failure_tcp_fallback_keeps_the_original_total_deadline_test() -> Nil {
  let invoked = process.new_subject()
  let within_deadline =
    client.run_tcp_fallback_before_total_deadline(100, 40, fn(remaining) {
      process.send(invoked, remaining)
      Ok(7)
    })
  assert within_deadline == Ok(7)
  assert process.receive(invoked, within: 0) == Ok(60)

  let expired =
    client.run_tcp_fallback_before_total_deadline(100, 100, fn(remaining) {
      process.send(invoked, remaining)
      Ok(7)
    })
  let assert Error(expired) = expired
  assert error.kind(expired) == error.Timeout(error.Total)
  assert process.receive(invoked, within: 0) == Error(Nil)
}

pub fn authenticated_https_record_can_select_http3_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(port) = h3_server.port(udp_listener)
  let observed_alt_used = process.new_subject()
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      let alt_used =
        h3_server.headers(incoming)
        |> list.find(fn(header) { string.lowercase(header.0) == "alt-used" })
        |> result.map(fn(header) { header.1 })
      process.send(observed_alt_used, alt_used)
      h3_server.respond(incoming, 200, [], <<"record":utf8>>)
    })
  let resolver = fn(host, origin_port, timeout_milliseconds) {
    assert host == "localhost"
    assert origin_port == port
    assert timeout_milliseconds == 1000
    Ok([
      client.HttpsRecord(
        alpns: ["h3"],
        port: origin_port,
        authenticated: True,
        expires_in_milliseconds: 60_000,
      ),
    ])
  }
  let assert Ok(running) =
    client.defaults()
    |> client.with_https_record_resolver(resolver)
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/https-record",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  assert client.selected_protocol(completed) == client.Http3
  let assert Ok(#(<<"record":utf8>>, [])) =
    body.read_all(client.response(completed).body, 6)
  assert process.receive(observed_alt_used, within: 1000)
    == Ok(Ok("localhost:" <> int.to_string(port)))
  let assert Ok(Nil) = http_test_support.await_task(h3_task)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)
  Nil
}

pub fn http3_421_evicts_discovery_and_ignores_replacement_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(port) = h3_server.port(udp_listener)
  let resolver_calls = process.new_subject()
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      h3_server.respond(
        incoming,
        421,
        [#("alt-svc", "h3=\":" <> int.to_string(port) <> "\"; ma=60")],
        <<>>,
      )
    })
  let resolver = fn(host, origin_port, timeout_milliseconds) {
    assert host == "localhost"
    assert origin_port == port
    assert timeout_milliseconds == 1000
    process.send(resolver_calls, Nil)
    Ok([
      client.HttpsRecord(
        alpns: ["h3"],
        port: origin_port,
        authenticated: True,
        expires_in_milliseconds: 60_000,
      ),
    ])
  }
  let assert Ok(running) =
    client.defaults()
    |> client.without_pooling
    |> client.with_https_record_resolver(resolver)
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/misdirected",
      query: None,
    )

  let assert Ok(misdirected) = client.exchange(running, outgoing)
  assert client.selected_protocol(misdirected) == client.Http3
  assert client.response(misdirected).status == 421
  let assert Ok(#(<<>>, [])) =
    body.read_all(client.response(misdirected).body, 0)
  assert process.receive(resolver_calls, within: 1000) == Ok(Nil)
  let assert Ok(Nil) = http_test_support.await_task(h3_task)
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)

  let handler = fn(_: request.Request(body.Body), _request_context) {
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_text("tcp-after-421"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(tcp_listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      port,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let next = request.Request(..outgoing, path: "/after-421", body: body.empty())
  let assert Ok(completed) = client.exchange(running, next)
  assert client.selected_protocol(completed) == client.Http2
  let assert Ok(#(<<"tcp-after-421":utf8>>, [])) =
    body.read_all(client.response(completed).body, 13)
  assert process.receive(resolver_calls, within: 1000) == Ok(Nil)
  assert process.receive(resolver_calls, within: 0) == Error(Nil)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(tcp_listener)
  let assert Ok(Nil) = server.stop_listener(tcp_listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn proxy_is_disabled_by_default_and_configuration_is_typed_test() -> Nil {
  let config = client.defaults()
  assert client.proxy_policy(config) == client.ProxyPolicy(proxy: None)
  let assert Ok(configured) =
    client.with_proxy(
      config,
      client.Proxy(
        host: "127.0.0.1",
        port: 8080,
        authorization: Some("Basic bounded"),
      ),
    )
  assert client.proxy_policy(configured)
    == client.ProxyPolicy(
      proxy: Some(client.Proxy(
        host: "127.0.0.1",
        port: 8080,
        authorization: Some("Basic bounded"),
      )),
    )
}

pub fn explicit_cleartext_proxy_receives_absolute_form_and_credentials_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, proxy_port)) = transport.local_endpoint(listener)
  let proxy_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(bytes, socket) = read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 5\r\nConnection: close\r\n\r\nproxy":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(bytes)
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_proxy(client.Proxy(
      host: "127.0.0.1",
      port: proxy_port,
      authorization: Some("Basic bounded"),
    ))
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Http,
      host: "unresolvable.invalid",
      port: Some(8081),
      path: "/through",
      query: Some("x=1"),
    )

  let assert Ok(incoming) = client.fetch(running, outgoing)
  let assert Ok(#(<<"proxy":utf8>>, [])) = body.read_all(incoming.body, 5)
  let assert Ok(bytes) = http_test_support.await_task(proxy_task)
  let assert Ok(text) = bit_array.to_string(bytes)
  assert string.starts_with(
    text,
    "GET http://unresolvable.invalid:8081/through?x=1 HTTP/1.1\r\n",
  )
  assert string.contains(text, "Proxy-Authorization: Basic bounded\r\n")
  assert string.contains(text, "Host: unresolvable.invalid:8081\r\n")
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn verified_https_uses_connect_proxy_without_leaking_credentials_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, proxy_port)) = transport.local_endpoint(listener)
  let proxy_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use connect_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(connect_bytes, socket) = connect_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 Connection Established\r\n\r\n":utf8,
        >>),
      )
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1":utf8>>],
        1000,
      ))
      let assert transport.TlsReady(socket, <<"http/1.1":utf8>>, _) = ready
      use origin_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(origin_bytes, socket) = origin_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 6\r\nConnection: close\r\n\r\nsecure":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(#(connect_bytes, origin_bytes))
    })
  let assert Ok(config) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_proxy(client.Proxy(
      host: "127.0.0.1",
      port: proxy_port,
      authorization: Some("Basic tunnel-only"),
    ))
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(9443),
      path: "/through-tls",
      query: None,
    )

  let assert Ok(incoming) = client.fetch(running, outgoing)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(incoming.body, 6)
  let assert Ok(#(connect_bytes, origin_bytes)) =
    http_test_support.await_task(proxy_task)
  let assert Ok(connect_text) = bit_array.to_string(connect_bytes)
  assert string.starts_with(connect_text, "CONNECT localhost:9443 HTTP/1.1\r\n")
  assert string.contains(connect_text, "Host: localhost:9443\r\n")
  assert string.contains(
    connect_text,
    "Proxy-Authorization: Basic tunnel-only\r\n",
  )
  let assert Ok(origin_text) = bit_array.to_string(origin_bytes)
  assert string.starts_with(origin_text, "GET /through-tls HTTP/1.1\r\n")
  assert !string.contains(origin_text, "Proxy-Authorization")
  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn client_is_reusable_then_drain_and_close_are_idempotent_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use _ <- result.try(serve_once(listener, <<"one":utf8>>))
      use _ <- result.try(serve_once(listener, <<"two":utf8>>))
      Ok(Nil)
    })
  let config = client.defaults() |> client.allow_plain_http
  let assert Ok(running) = client.start(config)

  let assert Ok(first) =
    client.exchange(running, request_for(port, "/one", body.empty()))
  assert client.selected_protocol(first) == client.Http1
  let first_response = client.response(first)
  let assert Ok(#(<<"one":utf8>>, [])) = body.read_all(first_response.body, 3)

  let second_request = request_for(port, "/two", <<>>)
  let assert Ok(second_response) = client.fetch(running, second_request)
  let assert Ok(#(<<"two":utf8>>, [])) = body.read_all(second_response.body, 3)

  assert client.drain(running) == Ok(Nil)
  assert client.drain(running) == Ok(Nil)
  let assert Error(draining_failure) = client.fetch(running, second_request)
  assert error.kind(draining_failure) == error.Cancelled
  assert client.close(running) == Ok(Nil)
  assert client.close(running) == Ok(Nil)
  let assert Error(closed_failure) = client.fetch(running, second_request)
  assert error.kind(closed_failure) == error.Cancelled

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn verified_https_negotiates_http2_through_the_public_client_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
      let assert Ok(Nil) = transport.send(socket, initial)
      let assert Ok(transport.ReadData(_, socket)) =
        transport.read(socket, 65_536, 1000)
      let assert Ok(headers) =
        frame.encode(frame.Headers, 0x4, 1, <<0x88>>, 16_384)
      let assert Ok(data) =
        frame.encode(frame.Data, 0x1, 1, <<"public-h2">>, 16_384)
      let assert Ok(Nil) = transport.send(socket, <<headers:bits, data:bits>>)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let config =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/h2",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)

  assert client.selected_protocol(completed) == client.Http2
  let assert Ok(#(<<"public-h2">>, [])) =
    body.read_all(client.response(completed).body, 16)
  assert http_test_support.await_task(server_task) == Nil
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn http2_exchange_returns_after_final_headers_before_body_data_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let final_headers_sent = process.new_subject()
  let body_gate_ready = process.new_subject()
  let body_data_started = process.new_subject()
  let fixture_deadline = transport.monotonic_millisecond() + 5000
  let server_task =
    http_test_support.start_task(fn() {
      let release_body_data = process.new_subject()
      process.send(body_gate_ready, release_body_data)
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
      let assert Ok(Nil) = transport.send(socket, initial)
      let assert Ok(transport.ReadData(_, socket)) =
        transport.read(socket, 65_536, 1000)
      let assert Ok(headers) =
        frame.encode(frame.Headers, 0x4, 1, <<0x88>>, 16_384)
      let assert Ok(Nil) = transport.send(socket, headers)
      process.send(final_headers_sent, Nil)
      let assert Ok(Nil) =
        process.receive(
          release_body_data,
          within: int.max(
            0,
            fixture_deadline - transport.monotonic_millisecond(),
          ),
        )
      process.send(body_data_started, Nil)
      let assert Ok(data) = frame.encode(frame.Data, 0x1, 1, <<"late">>, 16_384)
      let assert Ok(Nil) = transport.send(socket, data)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
  let assert Ok(release_body_data) =
    process.receive(body_gate_ready, within: 1000)
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 500,
      tls_milliseconds: 500,
      operation_milliseconds: 2500,
      idle_milliseconds: 2500,
      total_milliseconds: 3000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/stream",
      query: None,
    )
  let exchange = client.exchange(running, outgoing)
  let headers_before_exchange_return =
    process.receive(final_headers_sent, within: 0)
  let body_before_release = process.receive(body_data_started, within: 0)
  process.send(release_body_data, Nil)
  let body_after_release =
    process.receive(
      body_data_started,
      within: int.max(0, fixture_deadline - transport.monotonic_millisecond()),
    )
  let response_body = case exchange {
    Ok(completed) -> body.read_all(client.response(completed).body, 4)
    Error(failure) -> Error(failure)
  }
  assert http_test_support.await_task(server_task) == Nil
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)

  assert headers_before_exchange_return == Ok(Nil)
  assert body_before_release == Error(Nil)
  assert body_after_release == Ok(Nil)
  assert response_body == Ok(#(<<"late">>, []))
  Nil
}

pub fn http1_alpn_handoff_uses_the_authenticated_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1">>],
        1000,
      ))
      let assert transport.TlsReady(socket, <<"http/1.1">>, _) = ready
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(request_bytes, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n":utf8,
          "Connection: close\r\n\r\nfallback":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(request_bytes)
    })
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 500,
      tls_milliseconds: 500,
      operation_milliseconds: 500,
      idle_milliseconds: 500,
      total_milliseconds: 1000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/fallback",
      query: None,
    )

  let completed = client.exchange(running, outgoing)
  let received = http_test_support.await_task(server_task)

  let assert Ok(completed) = completed
  assert client.selected_protocol(completed) == client.Http1
  let assert Ok(#(<<"fallback">>, [])) =
    body.read_all(client.response(completed).body, 8)
  let assert Ok(<<"GET /fallback HTTP/1.1\r\n", _rest:bits>>) = received
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn http1_alpn_handoff_pulls_a_non_replayable_body_once_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1">>],
        1000,
      ))
      let assert transport.TlsReady(socket, <<"http/1.1">>, _) = ready
      use received <- result.try(read_until_text(
        socket,
        <<>>,
        "\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
      ))
      let #(socket, request_bytes) = received
      let correct_framing = case bit_array.to_string(request_bytes) {
        Ok(text) -> string.contains(text, "Transfer-Encoding: chunked\r\n")
        Error(_) -> False
      }
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(correct_framing)
    })
  let pulls = process.new_subject()
  let source =
    body.pull(fn(_) {
      process.send(pulls, Nil)
      Ok(body.PullData(<<"abc">>, body.pull(fn(_) { Ok(body.PullEnd([])) })))
    })
  let assert Ok(outgoing_body) =
    body.from_pull(source, Some(3), None, fn() { Nil })
  assert !body.is_replayable(outgoing_body)
  let assert Ok(config) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_timeouts(client.Timeouts(500, 500, 500, 500, 500, 1000))
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Post,
      headers: [],
      body: outgoing_body,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/fallback",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  assert client.selected_protocol(completed) == client.Http1
  assert client.response(completed).status == 204
  let server_outcome = http_test_support.await_task(server_task)
  let first_pull = process.receive(pulls, within: 0)
  let closed = client.close(running)
  let extra_pull_after_close = process.receive(pulls, within: 0)
  let listener_stopped = transport.stop(listener)

  assert server_outcome == Ok(True)
  assert first_pull == Ok(Nil)
  assert closed == Ok(Nil)
  assert extra_pull_after_close == Error(Nil)
  assert listener_stopped == Ok(Nil)
  Nil
}

pub fn http2_obeys_the_public_clients_aggregate_connection_admission_test() -> Nil {
  let #(_, _, ca_certificate) = http_test_support.server_credentials()
  let assert Ok(http1_listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, http1_port)) = transport.local_endpoint(http1_listener)
  let http1_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(http1_listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n":utf8,
        >>),
      )
      transport.read(socket, 1, 2000)
    })
  let assert Ok(h2_listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, h2_port)) = transport.local_endpoint(h2_listener)
  let h2_task =
    http_test_support.start_task(fn() {
      case transport.accept(h2_listener, 150) {
        Error(failure) -> failure != transport.Timeout
        Ok(socket) -> {
          let _closed = transport.close(socket)
          True
        }
      }
    })
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_pool_limits(client.PoolLimits(1, 1, 30_000))
  let assert Ok(running) = client.start(config)
  let assert Ok(active) =
    client.exchange(running, request_for(http1_port, "/active", body.empty()))
  let h2_request =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(h2_port),
      path: "/refused",
      query: None,
    )

  let second = client.exchange(running, h2_request)
  body.cancel(client.response(active).body)
  let assert Ok(transport.ReadEnd(_)) = http_test_support.await_task(http1_task)
  let h2_was_used = http_test_support.await_task(h2_task)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(http1_listener)
  let assert Ok(Nil) = transport.stop(h2_listener)

  let assert Error(failure) = second
  assert error.kind(failure) == error.Resource(error.Connections)
  assert !h2_was_used
}

pub fn sequential_fetches_reuse_one_http1_connection_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use first_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = first_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none":utf8,
        >>),
      )
      use second_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = second_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n":utf8,
          "Connection: close\r\n\r\ntwo":utf8,
        >>),
      )
      transport.close(socket)
    })
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 500,
      tls_milliseconds: 500,
      operation_milliseconds: 500,
      idle_milliseconds: 500,
      total_milliseconds: 1000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)

  let assert Ok(first) = client.fetch(running, request_for(port, "/one", <<>>))
  let assert Ok(#(<<"one":utf8>>, [])) = body.read_all(first.body, 3)
  let assert Ok(second) = client.fetch(running, request_for(port, "/two", <<>>))
  let assert Ok(#(<<"two":utf8>>, [])) = body.read_all(second.body, 3)

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn sequential_fetches_reuse_one_http2_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let peers = process.new_subject()
  let handler = fn(_, request_context) {
    process.send(peers, context.peer_endpoint(request_context))
    Ok(response.Response(
      status: 200,
      headers: [],
      body: body.from_text("pooled-h2"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/pooled",
      query: None,
    )

  let assert Ok(first) = client.fetch(running, outgoing)
  let assert Ok(#(<<"pooled-h2":utf8>>, [])) = body.read_all(first.body, 9)
  let assert Ok(second) = client.fetch(running, outgoing)
  let assert Ok(#(<<"pooled-h2":utf8>>, [])) = body.read_all(second.body, 9)
  let assert Ok(first_peer) = process.receive(peers, within: 1000)
  let assert Ok(second_peer) = process.receive(peers, within: 1000)
  assert first_peer == second_peer

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn http2_421_response_evicts_the_misdirected_connection_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let peers = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    process.send(peers, context.peer_endpoint(request_context))
    Ok(response.Response(
      status: case incoming.path {
        "/misdirected" -> 421
        _ -> 200
      },
      headers: [],
      body: body.empty(),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let outgoing = fn(path) {
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: path,
      query: None,
    )
  }

  let assert Ok(first) = client.fetch(running, outgoing("/misdirected"))
  assert first.status == 421
  let assert Ok(#(<<>>, [])) = body.read_all(first.body, 1)
  let assert Ok(second) = client.fetch(running, outgoing("/next"))
  assert second.status == 200
  let assert Ok(#(<<>>, [])) = body.read_all(second.body, 1)
  let assert Ok(first_peer) = process.receive(peers, within: 1000)
  let assert Ok(second_peer) = process.receive(peers, within: 1000)
  assert first_peer != second_peer

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn pooled_connection_moves_between_calling_processes_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use first_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = first_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none":utf8,
        >>),
      )
      use second_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = second_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n":utf8,
          "Connection: close\r\n\r\ntwo":utf8,
        >>),
      )
      transport.close(socket)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start

  let first_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(client.fetch(
        running,
        request_for(port, "/one", <<>>),
      ))
      body.read_all(incoming.body, 3)
    })
  let assert Ok(#(<<"one":utf8>>, [])) =
    http_test_support.await_task(first_task)
  let second_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(client.fetch(
        running,
        request_for(port, "/two", <<>>),
      ))
      body.read_all(incoming.body, 3)
    })
  let assert Ok(#(<<"two":utf8>>, [])) =
    http_test_support.await_task(second_task)

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn idle_pool_deadline_closes_the_connection_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none":utf8,
        >>),
      )
      transport.read(socket, 1, 500)
    })
  let limits = client.PoolLimits(1, 1, 20)
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_pool_limits(limits)
  let assert Ok(running) = client.start(config)

  let assert Ok(incoming) = client.fetch(running, request_for(port, "/", <<>>))
  let assert Ok(#(<<"one":utf8>>, [])) = body.read_all(incoming.body, 3)
  let assert Ok(transport.ReadEnd(_)) =
    http_test_support.await_task(server_task)

  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn aggregate_connection_limit_rejects_before_creating_a_socket_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use first_read <- result.try(transport.read(first, 4096, 1000))
      let assert transport.ReadData(_, first) = first_read
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n":utf8,
        >>),
      )

      case transport.accept(listener, 150) {
        Error(failure) -> Ok(failure == transport.Timeout)
        Ok(second) -> {
          let _closed = transport.close(second)
          Ok(False)
        }
      }
    })
  let timeouts = client.Timeouts(500, 500, 500, 500, 500, 1000)
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_pool_limits(client.PoolLimits(1, 1, 30_000))
  let assert Ok(config) = client.with_timeouts(config, timeouts)
  let assert Ok(running) = client.start(config)
  let assert Ok(active) =
    client.exchange(running, request_for(port, "/active", body.empty()))

  let assert Error(failure) =
    client.exchange(running, request_for(port, "/refused", body.empty()))
  assert error.kind(failure) == error.Resource(error.Connections)
  assert http_test_support.await_task(server_task) == Ok(True)

  body.cancel(client.response(active).body)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn close_cancels_active_response_and_releases_its_socket_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n":utf8,
        >>),
      )
      transport.read(socket, 1, 500)
    })
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 500,
      tls_milliseconds: 500,
      operation_milliseconds: 500,
      idle_milliseconds: 500,
      total_milliseconds: 1000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)
  let assert Ok(active) =
    client.exchange(running, request_for(port, "/active", body.empty()))

  assert client.close(running) == Ok(Nil)
  let assert Error(failure) = body.read(client.response(active).body, 1)
  assert error.kind(failure) == error.Cancelled
  let assert Ok(transport.ReadEnd(_)) =
    http_test_support.await_task(server_task)

  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn close_cancels_an_in_flight_http2_exchange_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let request_received = process.new_subject()
  let server_task =
    http_test_support.start_task(fn() {
      let assert Ok(socket) = transport.accept(listener, 1000)
      let assert Ok(transport.TlsReady(socket, <<"h2">>, _)) =
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
      let assert Ok(Nil) = transport.send(socket, initial)
      let assert Ok(transport.ReadData(_, socket)) =
        transport.read(socket, 65_536, 1000)
      process.send(request_received, Nil)
      await_socket_end(socket)
    })
  let timeouts =
    client.Timeouts(
      dns_milliseconds: 500,
      connect_milliseconds: 500,
      tls_milliseconds: 500,
      operation_milliseconds: 2000,
      idle_milliseconds: 2000,
      total_milliseconds: 3000,
    )
  let assert Ok(config) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_timeouts(timeouts)
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/active",
      query: None,
    )
  let exchange_task =
    http_test_support.start_task(fn() { client.exchange(running, outgoing) })
  let assert Ok(Nil) = process.receive(request_received, within: 1000)

  assert client.close(running) == Ok(Nil)

  let assert Error(failure) = http_test_support.await_task(exchange_task)
  assert error.kind(failure) == error.Cancelled
  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn fetch_buffers_and_detaches_a_replayable_body_before_returning_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n":utf8,
          "3\r\none\r\n0\r\nx-result: complete\r\n\r\n":utf8,
        >>),
      )
      transport.close(socket)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start
  let assert Ok(incoming) = client.fetch(running, request_for(port, "/", <<>>))
  assert client.close(running) == Ok(Nil)
  assert body.is_replayable(incoming.body)
  let assert Ok(#(<<"one":utf8>>, [#("x-result", "complete")])) =
    body.read_all(incoming.body, 3)

  let assert Ok(Nil) = http_test_support.await_task(server_task)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn fetch_rejects_an_oversized_buffered_body_and_closes_its_socket_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 1000))
      use request_read <- result.try(transport.read(socket, 4096, 1000))
      let assert transport.ReadData(_, socket) = request_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 8388609\r\n\r\n":utf8,
        >>),
      )
      transport.read(socket, 1, 1000)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start

  let assert Error(failure) =
    client.fetch(running, request_for(port, "/", <<>>))
  assert error.kind(failure) == error.Body(error.TooLarge(8_388_608))
  let assert Ok(transport.ReadEnd(_)) =
    http_test_support.await_task(server_task)

  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

fn request_for(
  port: Int,
  path: String,
  request_body: request_body,
) -> request.Request(request_body) {
  request.Request(
    method: gleam_http.Get,
    headers: [],
    body: request_body,
    scheme: gleam_http.Http,
    host: "127.0.0.1",
    port: Some(port),
    path: path,
    query: None,
  )
}

fn serve_once(
  listener: transport.Listener,
  response_body: BitArray,
) -> Result(Nil, transport.Error) {
  use socket <- result.try(transport.accept(listener, 1000))
  use request_read <- result.try(transport.read(socket, 4096, 1000))
  let assert transport.ReadData(_, socket) = request_read
  use _ <- result.try(
    transport.send(socket, <<
      "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n":utf8,
      response_body:bits,
    >>),
  )
  transport.close(socket)
}

fn drain_until_end(socket: transport.Socket) -> transport.Socket {
  case transport.read(socket, 65_536, 2000) {
    Ok(transport.ReadData(_, socket)) -> drain_until_end(socket)
    Ok(transport.ReadEnd(socket)) -> socket
    Error(_) -> socket
  }
}

fn await_socket_end(socket: transport.Socket) -> Result(Nil, transport.Error) {
  use read <- result.try(transport.read(socket, 65_536, 2000))
  case read {
    transport.ReadData(_, socket) -> await_socket_end(socket)
    transport.ReadEnd(_) -> Ok(Nil)
  }
}

fn read_until_text(
  socket: transport.Socket,
  buffered: BitArray,
  expected: String,
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  case bit_array.to_string(buffered) {
    Ok(text) ->
      case string.contains(text, expected) {
        True -> Ok(#(socket, buffered))
        False -> read_until_text_after_read(socket, buffered, expected)
      }
    Error(_) -> read_until_text_after_read(socket, buffered, expected)
  }
}

fn read_until_text_after_read(
  socket: transport.Socket,
  buffered: BitArray,
  expected: String,
) -> Result(#(transport.Socket, BitArray), transport.Error) {
  use read <- result.try(transport.read(socket, 4096, 1000))
  case read {
    transport.ReadData(bytes, socket) ->
      read_until_text(socket, bit_array.concat([buffered, bytes]), expected)
    transport.ReadEnd(_) -> Error(transport.Closed)
  }
}

pub fn only_the_first_strict_transport_security_field_is_processed_test() -> Nil {
  // RFC 6797 section 8.1: a response carrying more than one STS field is read for the first one only, so a second field cannot revise or withdraw what the first said.
  // Here the second would clear the policy the first sets.
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let schemes = process.new_subject()
  let handler = fn(incoming: request.Request(body.Body), _) {
    process.send(schemes, incoming.scheme)
    Ok(response.Response(
      status: 200,
      headers: [
        #("strict-transport-security", "max-age=60"),
        #("strict-transport-security", "max-age=0"),
      ],
      body: body.from_text("secure"),
    ))
  }
  let assert Ok(executor) = server.start(server.defaults(), handler)
  let assert Ok(listener) =
    server.listen_http2_tls(
      executor,
      <<127, 0, 0, 1>>,
      0,
      server.http2_defaults(),
      certificate,
      private_key,
      service_identity: "localhost",
    )
  let context.Endpoint(_, port) = server.listener_endpoint(listener)
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
  let secure =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: <<>>,
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/learn",
      query: None,
    )
  let cleartext =
    request.Request(..secure, scheme: gleam_http.Http, path: "/use")

  let assert Ok(first) = client.fetch(running, secure)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(first.body, 6)
  let assert Ok(second) = client.fetch(running, cleartext)
  let assert Ok(#(<<"secure":utf8>>, [])) = body.read_all(second.body, 6)
  // The first field is what holds: the cleartext request is upgraded rather than sent as it was written.
  assert process.receive(schemes, within: 1000) == Ok(gleam_http.Https)
  assert process.receive(schemes, within: 1000) == Ok(gleam_http.Https)

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = server.drain_listener(listener)
  let assert Ok(Nil) = server.stop_listener(listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn a_configured_proxy_holds_back_a_discovered_alternative_test() -> Nil {
  // RFC 7838 section 2.4: a client configured to use a proxy for a request does not connect directly to an alternative service for it, but routes it through that proxy.
  // Both routes answer here, and they answer differently,
  // so the body says which one was taken.
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(port) = h3_server.port(udp_listener)
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      h3_server.respond(incoming, 200, [], <<"alternative":utf8>>)
    })
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, proxy_port)) = transport.local_endpoint(listener)
  let proxy_task =
    http_test_support.start_task(fn() {
      use socket <- result.try(transport.accept(listener, 2000))
      use connect_read <- result.try(transport.read(socket, 4096, 2000))
      let assert transport.ReadData(connect_bytes, socket) = connect_read
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 Connection Established\r\n\r\n":utf8,
        >>),
      )
      use ready <- result.try(transport.upgrade_server_tls(
        socket,
        certificate,
        private_key,
        [<<"http/1.1":utf8>>],
        2000,
      ))
      let assert transport.TlsReady(socket, <<"http/1.1":utf8>>, _) = ready
      use _ <- result.try(transport.read(socket, 4096, 2000))
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 7\r\nConnection: close\r\n\r\nproxied":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(connect_bytes)
    })
  let resolver = fn(_, origin_port, _) {
    Ok([
      client.HttpsRecord(
        alpns: ["h3"],
        port: origin_port,
        authenticated: True,
        expires_in_milliseconds: 60_000,
      ),
    ])
  }
  let assert Ok(config) =
    client.defaults()
    |> client.with_https_record_resolver(resolver)
    |> client.with_ca_certificates([ca_certificate])
    |> client.with_proxy(client.Proxy(
      host: "127.0.0.1",
      port: proxy_port,
      authorization: None,
    ))
  let assert Ok(running) = client.start(config)
  let outgoing =
    request.Request(
      method: gleam_http.Get,
      headers: [],
      body: body.empty(),
      scheme: gleam_http.Https,
      host: "localhost",
      port: Some(port),
      path: "/proxied",
      query: None,
    )

  let assert Ok(completed) = client.exchange(running, outgoing)
  assert client.selected_protocol(completed) != client.Http3
  let assert Ok(#(<<"proxied":utf8>>, [])) =
    body.read_all(client.response(completed).body, 7)
  let assert Ok(connect_bytes) = http_test_support.await_task(proxy_task)
  let assert Ok(connect_text) = bit_array.to_string(connect_bytes)
  assert string.starts_with(connect_text, "CONNECT localhost:")

  let assert Ok(Nil) = client.close(running)
  // The point of the rule is that the alternative is not contacted at all, not merely that its answer is unused.
  // Stopping its listener is what ends the accept, so a task that never served a request reports a failure.
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)
  assert result.is_error(http_test_support.await_task(h3_task))
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn aggregate_connection_limit_rejects_before_sending_a_request_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use first_read <- result.try(transport.read(first, 4096, 1000))
      let assert transport.ReadData(_, first) = first_read
      use _ <- result.try(
        transport.send(first, <<
          "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n":utf8,
        >>),
      )

      let accepted = transport.accept(listener, 150)
      let _closed = transport.close(first)
      case accepted {
        Ok(second) -> {
          let _closed = transport.close(second)
          Ok(False)
        }
        Error(transport.Timeout) -> Ok(True)
        Error(failure) -> Error(failure)
      }
    })
  let timeouts = client.Timeouts(500, 500, 500, 500, 500, 1000)
  let assert Ok(config) =
    client.defaults()
    |> client.allow_plain_http
    |> client.with_pool_limits(client.PoolLimits(1, 1, 30_000))
  let assert Ok(config) = client.with_timeouts(config, timeouts)
  let assert Ok(running) = client.start(config)
  let assert Ok(active) =
    client.exchange(running, request_for(port, "/active", body.empty()))

  let assert Error(failure) =
    client.exchange(running, request_for(port, "/refused", body.empty()))
  assert error.kind(failure) == error.Resource(error.Connections)
  assert http_test_support.await_task(server_task) == Ok(True)

  body.cancel(client.response(active).body)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}
