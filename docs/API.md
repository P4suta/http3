# API guide

The public API is designed around two choices: use `client.send` for one
bounded request, or use `client.connect` when connections or bodies must be
streamed. Both paths verify certificates and hostnames and have finite
defaults.

## One request

```gleam
import gleam/http/request
import http3/client

pub fn fetch() {
  let assert Ok(outbound) = request.to("https://example.com/")
  client.send(client.new(), request.set_body(outbound, <<>>))
}
```

`send` owns and closes its connection. Request and response bodies default to
8 MiB, and the default total deadline is 30 seconds.

## Reuse one connection

```gleam
import gleam/http/request
import gleam/result
import http3/client

pub fn fetch_streaming(configuration: client.Client) {
  use connection <- result.try(client.connect(configuration, "example.com", 443))
  let outbound =
    request.new()
    |> request.set_host("example.com")
    |> request.set_body(Nil)
  use stream <- result.try(client.open_stream(connection, outbound))
  use _ <- result.try(client.finish(stream))
  receive_response(stream)
}
```

Pull `Response`, `Data`, `Trailers`, and `End` with `client.next_event`.
Unconsumed data and event counts are bounded; request writes synchronously
preserve transport backpressure. Close a reusable connection explicitly when
finished. Closing and cancellation are idempotent.

## Tune finite policy once

```gleam
import http3/client
import http3/config
import http3/failure

let assert Ok(deadlines) =
  config.default_deadlines()
  |> config.with_deadline(failure.Operation, 5_000)
let assert Ok(limits) =
  config.default_limits()
  |> config.with_limit(failure.Queue, 256)
  |> config.with_limit(failure.Buffer, 1_048_576)

let configuration =
  client.new()
  |> client.with_deadlines(deadlines)
  |> client.with_limits(limits)
  |> client.with_address_family(config.DualStack)
```

There is no `unlimited` value. Invalid policy values are rejected while the
policy is constructed, so a complete `Deadlines` or `Limits` value can be
attached atomically. Connections, handshakes, streams, bodies, per-stream
buffers, operation/event queues, frame payloads, Datagrams, QPACK state,
accept waiters, and qlog telemetry reach the corresponding role-specific live
runtime paths. `EndpointMemory` is currently validated but not enforced as an
aggregate; it remains a pre-release blocker and must not be used as the host's
memory safety boundary.

## Handle failures by intent

```gleam
case client.next_event(stream) {
  Error(client.Failure(failure.Timeout(failure.Operation))) -> retry_later()
  Error(client.Failure(failure.Limit(failure.Queue, maximum))) ->
    slow_consumer(maximum)
  Error(client.Failure(failure.Tls(failure.Peer))) -> reject_peer()
  Error(client.RequestRejected) -> retry_only_if_request_is_safe()
  outcome -> handle(outcome)
}
```

Runtime failures retain a phase, resource, origin, and protocol code when one
is trustworthy. They never contain backend-formatted strings, certificate
contents, tickets, or traffic secrets.

## Server lifecycle

Construct a `server.Configuration` from complete PEM certificate/key bytes,
attach deadlines and limits, then start one owned listener. Use
`server.reload_certificates` to atomically replace the complete certificate
set for new handshakes. Existing authenticated connections keep their current
TLS state.

Use `server.graceful_stop` to send GOAWAY and drain active requests within the
configured deadline. Use `server.stop` for immediate, idempotent shutdown.
Operational key and 0-RTT setup is covered in the
[deployment guide](DEPLOYMENT.md).

For a multi-node deployment, construct one finite `server.replay_guard`
callback and attach it with `server.with_external_zero_rtt`. The callback sees
only an opaque attempt with a domain-separated fingerprint and required
retention interval. It returns `AcceptEarlyData` only after an atomic
insert-if-absent succeeds in shared storage. Rejection, error, callback exit,
or timeout automatically continues the authenticated connection at 1-RTT.

## Diagnostics

qlog is off by default. When enabled, inspect `transport.telemetry_stats` for
dropped events, write errors, and queued events. Treat trace files as
sensitive. The fixed qlog revisions are diagnostic drafts and not part of the
stable protocol guarantee. `failure.Telemetry` in the shared `Limits` value
sets the writer's maximum waiting events; one additional event may be actively
writing.
