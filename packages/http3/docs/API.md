# API guide

The public API is designed around two choices: use `client.send` for one
bounded request, or use `client.connect` when connections or bodies must be
streamed. Both paths verify certificates and hostnames and have finite
defaults.

## One request

<!-- example: package=http3 id=one_request -->
```gleam
import gleam/http/request
import http3/client

pub fn fetch() {
  let assert Ok(outbound) = request.to("https://example.com/")
  client.send(client.new(), request.set_body(outbound, <<>>))
}

pub fn main() -> Nil {
  let _example = fetch
  Nil
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

<!-- example: package=http3 id=streaming_request -->
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
  client.next_event(stream)
}

pub fn main() -> Nil {
  let _example = fetch_streaming
  Nil
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

<!-- example: package=http3 id=finite_policy -->
```gleam
import http3/client
import http3/config
import http3/failure

pub fn main() -> Nil {
  let assert Ok(deadlines) =
    config.with_deadline(config.default_deadlines(), failure.Operation, 5_000)
  let assert Ok(limits) =
    config.with_limit(config.default_limits(), failure.Queue, 256)
  let assert Ok(limits) =
    config.with_limit(limits, failure.Buffer, 1_048_576)

  let _configuration =
    client.new()
    |> client.with_deadlines(deadlines)
    |> client.with_limits(limits)
    |> client.with_address_family(config.DualStack)
  Nil
}
```

There is no `unlimited` value. Invalid policy values are rejected while the
policy is constructed, so a complete `Deadlines` or `Limits` value can be
attached atomically. Connections, handshakes, streams, bodies, per-stream
buffers, operation/event queues, frame payloads, Datagrams, QPACK state,
accept waiters, and qlog telemetry reach the corresponding role-specific live
runtime paths. On a server, `EndpointMemory` is the aggregate listener budget:
connection admission and later receive, send, and mailbox growth obtain credit
before allocation. On a client it must fund the fixed connection admission
reservation before an actor or socket is created; the per-stream and queue
limits bound later growth.

For an active HTTP Datagram association,
`transport.maximum_datagram_size` reports the point-in-time payload packing
limit and `transport.guaranteed_datagram_size` reports the smaller
connection-lifetime limit. The latter is the appropriate value for a
downstream socket or mailbox ceiling that cannot be resized safely. Server
adapters can obtain that same guaranteed value before sending a successful
Extended CONNECT response with `server.request_datagram_capacity`.

## Handle failures by intent

<!-- example: package=http3 id=typed_failures -->
```gleam
import http3/client
import http3/failure

pub fn classify(stream: client.Stream) -> String {
  case client.next_event(stream) {
    Error(client.Failure(failure.Timeout(failure.Operation))) -> "retry-later"
    Error(client.Failure(failure.Limit(failure.Queue, _maximum))) ->
      "slow-consumer"
    Error(client.Failure(failure.Tls(failure.Peer))) -> "reject-peer"
    Error(client.RequestRejected) -> "retry-if-safe"
    _outcome -> "complete"
  }
}

pub fn main() -> Nil {
  let _example = classify
  Nil
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

<!-- example: package=http3 id=server_bind -->
```gleam
import http3/address
import http3/server

pub fn bind(configuration: server.Configuration) {
  let assert Ok(loopback) = address.parse("127.0.0.1")
  let configuration = server.with_bind_address(configuration, loopback)
  server.start(configuration)
}

pub fn main() -> Nil {
  let _example = bind
  Nil
}
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

<!-- example: package=http3 id=websocket_echo -->
```gleam
import http3/websocket

pub fn echo_message(incoming) {
  let assert Ok(socket) = websocket.accept(websocket.new(), incoming)
  let assert Ok(#(socket, websocket.TextMessage(message))) =
    websocket.receive(socket)
  websocket.send_text(socket, message)
}

pub fn main() -> Nil {
  let _example = echo_message
  Nil
}
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
writing. Each connection owns exactly one trace. HTTP/3 appends typed frame,
settings, and stream-role metadata through a payload-free core capability; it
cannot close or inspect the writer and cannot attach header fields, body bytes,
endpoints, certificate material, or arbitrary text. The live validation gate
requires connectivity, packet, TLS-key, recovery, HTTP/3, and QPACK families
in each client and server trace independently.
