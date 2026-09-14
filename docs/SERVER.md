# Protocol-neutral server

The common server executes the same application contract for HTTP/1.1,
HTTP/2, and HTTP/3:

<!-- example: package=http id=handler_contract -->
```gleam
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import http/body
import http/context
import http/error

pub type Handler =
  fn(Request(body.Body), context.Context) ->
    Result(Response(body.Body), error.Error)

pub fn accepts(handler: Handler) -> Handler {
  handler
}

pub fn main() -> Nil {
  let _contract = accepts
  Nil
}
```

Requests and responses use the standard `gleam_http` records. Their bodies use
the common pull-based `http/body.Body`, so a handler can stream without the
server executor collecting the representation first.

## Handler and middleware

<!-- example: package=http id=middleware_server -->
```gleam
import gleam/http/response
import gleam/result
import http/body
import http/middleware
import http/server

pub fn main() -> Nil {
  let add_server_header = fn(request, metadata, next) {
    use returned <- result.try(middleware.next(next, request, metadata))
    Ok(response.set_header(returned, "server", "example"))
  }

  let configuration =
    server.defaults()
    |> server.with_middlewares([add_server_header])

  let assert Ok(running) =
    server.start(configuration, fn(_request, _metadata) {
      Ok(response.new(204) |> response.set_body(body.empty()))
    })
  let assert Ok(Nil) = server.stop(running)
  Nil
}
```

Middleware runs in declaration order. A layer can return a response or error
without calling `middleware.next`, which short-circuits every inner layer and
the terminal handler.

## Typed request context

`http/context.Context` supplies the negotiated HTTP protocol, an optional
validated Extended CONNECT protocol token, validated peer and local endpoints,
remaining deadline, redacted TLS identity, early-data state, and shared
cancellation state. Application extensions use identity-based opaque keys:

<!-- example: package=http id=typed_context -->
```gleam
import gleam/option
import http/context

pub fn main() -> Nil {
  let assert Ok(metadata) =
    context.new(
      protocol: context.Http2,
      peer_endpoint: context.Endpoint("192.0.2.1", 443),
      local_endpoint: context.Endpoint("192.0.2.2", 8443),
      within_milliseconds: 1000,
      tls_identity: context.CleartextIdentity,
      early_data: context.EarlyDataDisabled,
    )
  let tenant_key: context.Key(String) = context.key()
  let with_tenant = context.put(metadata, tenant_key, "tenant-a")
  assert context.get(with_tenant, tenant_key) == option.Some("tenant-a")
}
```

A value can only be retrieved with the exact key that inserted it, and the key
keeps its Gleam value type. Backend handles and heterogeneous dynamic values do
not cross the public boundary.

## Admission, failures, and diagnostics

`http/resource` combines a finite request-worker count with aggregate memory
credit. Acquisition and growth happen before allocation; release is
idempotent and returns the entire live grant after completion, cancellation,
handler failure, or worker exit. The server reserves one configured grant
before spawning each handler.

Handlers run in monitored, unlinked workers. Panic and exit reasons never enter
the response or diagnostics; both become the fixed `error.Service` category.
Operation deadlines and explicit Context cancellation stop the worker and
cancel the request body.

`http/diagnostics` accepts only typed lifecycle metadata. Events contain no
host, path, query, headers, body, certificate bytes, or exception reason. A
reporter admits a finite number of sink calls and applies a finite deadline to
each; overload, callback error, panic, exit, and timeout are counted without
blocking a request worker.

## Reload, drain, and stop

`server.reload_handler` atomically replaces the middleware-wrapped handler for
later requests. Workers already admitted keep their original closure.
`server.drain` rejects later work and waits for the admitted finite set up to
the configured drain deadline. `server.stop` cancels the remaining set and is
idempotent.

## HTTP/1.1 listeners

`server.listen_http1_tls` binds an authenticated TCP/TLS listener and restricts
ALPN to `http/1.1`. It requires certificate and private-key bytes plus a
non-empty service identity. Cleartext is denied by default and can only be
enabled by applying `server.allow_http1_cleartext` before
`server.listen_http1`.

The listener has independent finite idle, operation, TLS, drain, and send
deadlines; connection/request ceilings; and request-head/body/read limits.
`server.listener_endpoint` returns only the bound typed endpoint. Use
`server.drain_listener` to stop admission and wait for existing connection
actors, then `server.stop_listener` for idempotent teardown.

`server.http1_listener_snapshot` exposes payload-free phase counters that stay
available after drain and stop. It distinguishes listener readiness, accepted
sockets, connection-owner handoff, parsed request heads, handler dispatch and
completion, connection failures, and active/exited convergence. The values
contain no endpoint or request metadata. Check `consistent` before using
cross-field invariants; `False` is a finite best-effort observation produced
when concurrent writers exhaust the snapshot retry budget.

HTTP/1.1 request bodies remain pull-based and send `100 Continue` only when the
handler first reads the body. Responses are serialized in request order.
Crashing or stalled response sources are cancelled in isolated workers and do
not terminate the listener. The client exposes an opaque byte stream for
CONNECT 2xx and Upgrade 101 only after the successful response; it rejects a
non-empty optimistic request body before opening a connection.

## HTTP/2 listeners

`server.listen_http2_tls` requires certificate and private-key bytes, a
non-empty service identity, and ALPN `h2`. Cleartext prior knowledge remains
disabled until `server.allow_http2_cleartext_prior_knowledge` is applied.
Listener and accepted-connection owners acknowledge resource receipt before a
constructor returns.

`server.http2_listener_snapshot` keeps a fixed-size, payload-free drain trace
available through Running, Draining, and Stopped. It separates the public drain
request, commands sent to live connection actors, command receipt, GOAWAY
attempt and successful write, connection exit, and drain completion. The
snapshot contains no endpoint, stream data, TLS material, PID, socket, or
backend reason; callers must check `consistent` before asserting relationships
between fields.

HTTP/3 listener integration and cross-protocol selection remain
pre-publication work; this document does not claim a production-ready network
server.
