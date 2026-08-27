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

`client.send_to(configuration, address, request)` is the bounded exact-route
variant for local health probes and controlled routing. Only the UDP dial
address is overridden: the request host still drives SNI, certificate identity
verification, and HTTP authority, so this API does not provide an insecure TLS
bypass.

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

`client.send` and other bounded helpers enforce the configured cumulative
request/response body limit. A stream opened with `client.open_stream` has no
cumulative response ceiling: each frame, the unconsumed-data queue, and every
operation remain finite, but a prompt pull consumer can remain subscribed for
an arbitrarily long transfer.

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

Bind to a specific IPv4 or IPv6 literal without DNS resolution through the
public address API:

```gleam
import http3/address
import http3/server

let assert Ok(loopback) = address.parse("127.0.0.1")
let configuration = server.with_bind_address(configuration, loopback)
let assert Ok(listener) = server.start(configuration)
```

Port zero still requests an ephemeral port. `server.scheme` and
`server.authority` expose the validated request pseudo-fields.
`server.peer_endpoint` returns only the currently validated QUIC peer path;
an unvalidated migration candidate is never exposed.

A response sent with `server.respond`, or a streaming response declaring
`Content-Length`, retains the configured cumulative response-body limit. A
response started with `server.send_response` and no `Content-Length` has no
cumulative lifetime ceiling. Individual frames, pending writes, flow control,
mailboxes, and operations remain finite, and `server.finish_response` still
terminates it explicitly.

For a multi-node deployment, construct one finite `server.replay_guard`
callback and attach it with `server.with_external_zero_rtt`. The callback sees
only an opaque attempt with a domain-separated fingerprint and required
retention interval. It returns `AcceptEarlyData` only after an atomic
insert-if-absent succeeds in shared storage. Rejection, error, callback exit,
or timeout automatically continues the authenticated connection at 1-RTT.

## WebSockets over HTTP/3

`http3/websocket` implements RFC 9220 Extended CONNECT and bounded RFC 6455
framing. The server accepts an already validated request with
`websocket.accept`; the client opens one on a reusable HTTP/3 connection with
`websocket.connect`. The handshake status is 200, not the HTTP/1.1 upgrade
status 101.

```gleam
import http3/websocket

let assert Ok(socket) = websocket.accept(websocket.new(), incoming)
let assert Ok(#(socket, websocket.TextMessage(message))) =
  websocket.receive(socket)
let assert Ok(socket) = websocket.send_text(socket, message)
```

Client frames are masked, server frames are not, fragmented messages are
reassembled within the configured message limit, text and close reasons are
UTF-8 validated, Ping receives Pong automatically, Close is echoed once, and
`websocket.cancel` aborts the underlying stream. Compression and WebSocket
extensions are deliberately not negotiated in this initial API.

## Diagnostics

qlog is off by default. When enabled, inspect `transport.telemetry_stats` for
dropped events, write errors, and queued events. Treat trace files as
sensitive. The fixed qlog revisions are diagnostic drafts and not part of the
stable protocol guarantee. `failure.Telemetry` in the shared `Limits` value
sets the writer's maximum waiting events; one additional event may be actively
writing.
