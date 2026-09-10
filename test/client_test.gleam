import gleam/bit_array
import gleam/erlang/process
import gleam/http as gleam_http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit
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

pub fn idempotent_replayable_request_retries_one_pre_response_failure_test() -> Nil {
  let assert Ok(listener) = transport.listen(<<127, 0, 0, 1>>, 0, 8, 1000)
  let assert Ok(#(_, port)) = transport.local_endpoint(listener)
  let server_task =
    http_test_support.start_task(fn() {
      use first <- result.try(transport.accept(listener, 1000))
      use _ <- result.try(transport.read(first, 4096, 1000))
      use _ <- result.try(transport.close(first))

      use second <- result.try(transport.accept(listener, 1000))
      use second_read <- result.try(transport.read(second, 4096, 1000))
      let assert transport.ReadData(second_request, second) = second_read
      use _ <- result.try(
        transport.send(second, <<
          "HTTP/1.1 200 OK\r\n":utf8,
          "Content-Length: 7\r\n":utf8,
          "Connection: close\r\n\r\nretried":utf8,
        >>),
      )
      use _ <- result.try(transport.close(second))
      Ok(second_request)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.allow_plain_http
    |> client.start
  let outgoing = request_for(port, "/retry", <<>>)

  let assert Ok(incoming) = client.fetch(running, outgoing)
  let assert Ok(#(<<"retried":utf8>>, [])) = body.read_all(incoming.body, 7)
  let assert Ok(second_request) = http_test_support.await_task(server_task)
  let assert Ok(second_text) = bit_array.to_string(second_request)
  assert string.starts_with(second_text, "GET /retry HTTP/1.1\r\n")

  let assert Ok(Nil) = client.close(running)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
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
          "Set-Cookie: stored=fresh; Path=/; Max-Age=60\r\n":utf8,
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

pub fn verified_alt_svc_enables_http3_for_a_replayable_origin_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    let context.Endpoint(_, advertised_port) =
      context.local_endpoint(request_context)
    case incoming.path == "/prefer-h3" {
      True -> process.sleep(5000)
      False -> Nil
    }
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

  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(h3_config) = h3_server.with_port(h3_config, port)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      h3_server.respond(incoming, 200, [], <<"quic":utf8>>)
    })
  let assert Ok(running) =
    client.defaults()
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
  let assert Ok(second) =
    client.exchange(running, request.Request(..outgoing, path: "/prefer-h3"))
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
  let handler = fn(incoming: request.Request(body.Body), request_context) {
    let context.Endpoint(_, advertised_port) =
      context.local_endpoint(request_context)
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
      _ ->
        Ok(response.Response(
          status: 200,
          headers: [],
          body: body.from_text("tcp-winner"),
        ))
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
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(h3_config) = h3_server.with_port(h3_config, port)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
      process.sleep(1200)
      h3_server.respond(incoming, 200, [], <<"late-quic":utf8>>)
    })
  let assert Ok(running) =
    client.defaults()
    |> client.with_ca_certificates([ca_certificate])
    |> client.start
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
  let started = transport.monotonic_millisecond()
  let assert Ok(completed) =
    client.exchange(running, request.Request(..base, path: "/race"))
  let elapsed = transport.monotonic_millisecond() - started

  assert client.selected_protocol(completed) == client.Http2
  let assert Ok(#(<<"tcp-winner":utf8>>, [])) =
    body.read_all(client.response(completed).body, 10)
  assert elapsed < 900

  let assert Ok(Nil) = client.close(running)
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)
  let _h3_outcome = http_test_support.await_task(h3_task)
  let assert Ok(Nil) = server.drain_listener(tcp_listener)
  let assert Ok(Nil) = server.stop_listener(tcp_listener)
  let assert Ok(Nil) = server.stop(executor)
  Nil
}

pub fn authenticated_https_record_can_select_http3_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
  let assert Ok(h3_config) = h3_server.new(certificate, private_key)
  let assert Ok(udp_listener) = h3_server.start(h3_config)
  let assert Ok(port) = h3_server.port(udp_listener)
  let h3_task =
    http_test_support.start_task(fn() {
      use incoming <- result.try(h3_server.accept(udp_listener))
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
  let assert Ok(Nil) = http_test_support.await_task(h3_task)
  let assert Ok(Nil) = client.close(running)
  let assert Ok(h3_server.Stopped) = h3_server.stop(udp_listener)
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
      let assert Ok(Nil) = transport.send(socket, headers)
      process.sleep(1000)
      let assert Ok(data) = frame.encode(frame.Data, 0x1, 1, <<"late">>, 16_384)
      let assert Ok(Nil) = transport.send(socket, data)
      let socket = drain_until_end(socket)
      let assert Ok(Nil) = transport.close(socket)
      Nil
    })
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
  let started = transport.monotonic_millisecond()
  let assert Ok(completed) = client.exchange(running, outgoing)
  let exchange_milliseconds = transport.monotonic_millisecond() - started
  let assert Ok(#(<<"late">>, [])) =
    body.read_all(client.response(completed).body, 4)
  assert http_test_support.await_task(server_task) == Nil
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)

  assert exchange_milliseconds < 800
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
      use received <- result.try(read_until_text(socket, <<>>, "\r\n\r\nabc"))
      let #(socket, request_bytes) = received
      use _ <- result.try(
        transport.send(socket, <<
          "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n":utf8,
        >>),
      )
      use _ <- result.try(transport.close(socket))
      Ok(request_bytes)
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
  let assert Ok(request_bytes) = http_test_support.await_task(server_task)
  let assert Ok(request_text) = bit_array.to_string(request_bytes)
  assert string.contains(request_text, "Content-Length: 3\r\n")
  assert process.receive(pulls, within: 1000) == Ok(Nil)
  assert process.receive(pulls, within: 10) == Error(Nil)
  assert client.close(running) == Ok(Nil)
  let assert Ok(Nil) = transport.stop(listener)
  Nil
}

pub fn http2_obeys_the_public_clients_aggregate_connection_admission_test() -> Nil {
  let #(certificate, private_key, ca_certificate) =
    http_test_support.server_credentials()
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
      let assert Ok(socket) = transport.accept(h2_listener, 1000)
      case
        transport.upgrade_server_tls(
          socket,
          certificate,
          private_key,
          [<<"h2">>],
          1000,
        )
      {
        Error(_) -> False
        Ok(transport.TlsReady(socket, _, _)) -> {
          let assert Ok(initial) = preface.server_initial_bytes([], 16_384)
          let assert Ok(Nil) = transport.send(socket, initial)
          let assert Ok(transport.ReadData(_, socket)) =
            transport.read(socket, 65_536, 1000)
          let assert Ok(headers) =
            frame.encode(frame.Headers, 0x5, 1, <<0x88>>, 16_384)
          let assert Ok(Nil) = transport.send(socket, headers)
          let socket = drain_until_end(socket)
          let assert Ok(Nil) = transport.close(socket)
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

      use second <- result.try(transport.accept(listener, 1000))
      transport.read(second, 4096, 1000)
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
  let assert Ok(transport.ReadEnd(_)) =
    http_test_support.await_task(server_task)

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
      "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n":utf8,
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
