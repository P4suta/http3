# Architecture

The repository has three dependency layers:

```text
http -> http3 -> quic_core
```

`http` owns the common body, error, client, server, policy, and HTTP/1.1 and
HTTP/2 runtime. `http3` owns HTTP/3, QPACK, Capsules, request-associated
Datagrams, and WebSocket over HTTP/3. `quic_core` owns application-independent
QUIC v1/v2, TLS 1.3, streams, transport Datagrams, and bounded diagnostics.
Each core connection also owns the lifetime of its single bounded qlog writer.
An opaque application sink lets HTTP/3 append only typed, payload-free protocol
metadata to that same trace; it cannot expose, inspect, or close the writer.
This keeps client/server events from being split across competing trace files
while preserving the transport ownership boundary.

The standard `gleam_http` request and response types cross every public HTTP
boundary. Public values never expose processes, sockets, references, backend
terms, key material, or traffic secrets. All peer-controlled queues, buffers,
waits, and allocations are finite.

The root keeps each Erlang runtime boundary narrow and task-specific. `http_body_ffi`
owns bounded positional file reads and an internal atomic cancellation flag.
`http_transport_ffi` owns finite DNS/connect, active-once TCP/TLS I/O, mandatory
TLS verification, ALPN, and socket ownership transfer. `http_client_ffi` owns
one Client's finite lifecycle and HTTP/1.1 idle pool. Its actor transfers a
checked-out socket to the calling process and takes ownership back on check-in,
so a Client can be used by different processes without a global registry.
`http_server_ffi` provides only identity tokens, resource credit, finite
diagnostic counters, monitored worker creation, an exception-redacting callback
boundary, and one event-driven cancellation broker per live Context. The broker
has no timer: it emits a one-shot tagged signal and converges after cancellation,
explicit removal, subscriber exit, or Context-owner exit. Its internal snapshot
contains only state and saturating counters. Diagnostic observations carry a
payload-free request ID and reporter-local causal sequence, so concurrent sink
completion can be reconstructed without serialising callbacks.
`http_http1_listener_ffi` and `http_http2_listener_ffi` own only their
protocol listener's saturating phase counters and finite multi-writer snapshot
protocol. The HTTP/2 snapshot additionally distinguishes drain request,
per-connection command/receipt, GOAWAY write, and drain completion. Neither
module performs network, file, parsing, or dynamic-code operations. The
complete FFI source inventory is declared once in `qualification.json`; source
discovery, Dialyzer, compiled xref, API leak checks, and the status audit all
consume that same set.
The CONNECT-UDP listener diagnostics also avoid a writer mutex: independent
atomic counters are bracketed by an active-writer count and generation. A
snapshot is marked consistent only when no writer overlaps it; after a finite
retry budget it returns the payload-free observed fields with `consistent`
false. An orphaned writer therefore poisons consistency without blocking later
counter updates or diagnostic readers.
CONNECT-UDP setup uses a separate fixed-size trace. Its DNS and socket-open
records split total phase time into bounded-worker queue and callback time,
record whether the callback began, and distinguish supervisor expiry from a
timeout value reported by the callback. All fields are booleans, counts, or
monotonic durations; the trace cannot retain adapter arguments or results.
`http_masque_udp_ffi` owns one
target-facing UDP socket per adopted actor, with finite setup and operation
deadlines, eight-command admission, active-once receive credit, a single
retained event, an independent one-slot terminal-event waiter,
requested/effective buffer observations, and owner-death cleanup. The event
waiter lets a protocol actor select socket failure without polling or another
datagram operation. A direct public-API H3 request resource composes that event
into reset plus STOP_SENDING, while a protocol-neutral Context resource reaches
the H1/H2/H3 cancellation adapters. A continuous post-success proxy-session
actor for every H1/H2/H3 tunnel remains an explicit integration step.
The setup state machine reports a fixed-size monotonic timing snapshot for DNS,
socket open, socket adoption, and failure cleanup. Socket startup/adoption and
established relay operations have independent finite deadlines, so a strict
per-command budget does not also become a cold-start admission budget. Separate
timeout bits assign an exhausted deadline to exactly the phase that observed
it, while the event sequence records production-only adoption. These
observations contain no authority, endpoint, payload, callback error, PID, or
socket value.
For the default HTTP/3 proxy, the HTTP/3 package exposes a typed guaranteed
request-Datagram capacity before the success response. `quic_core` derives it
from the authenticated peer frame limit, 1200-byte path floor, widest 1-RTT
protection, and maximum half-path ACK reservation; HTTP/3 then removes the
quarter-stream ID. The root removes CONNECT-UDP Context ID zero and caps the
target-facing UDP payload before opening the socket. ACK debt, migration, and
black-hole fallback therefore cannot invalidate the fixed tunnel contract;
the separately exposed live maximum remains available for adaptive callers.

`http_masque_packet_too_big_ffi` handles only oversized packets from the exact
connected target. It replaces the payload with a fixed-shape typed event before
the event can enter the caller mailbox, reconstructs the invoking IPv4 or IPv6
UDP packet only for the duration of a bounded ICMP build/send call, and retains
no payload in diagnostics. Raw ICMP uses a per-tunnel 10-message burst and
10-per-second token bucket, a 100 ms maximum send deadline, prohibited-address
checks, and permanent permission/unsupported caching. Its 21-counter snapshot
uses a finite-retry seqlock; a failed consistency read is explicit rather than
spinning forever. Raw-socket capability and platform-specific delivery remain
qualification concerns and never alter the primary drop decision.
The server and MASQUE protocol state machines remain in Gleam. None
of these modules parses HTTP or exposes file handles, sockets, PIDs,
references, or backend terms through the public API.

The common inbound path is:

```text
protocol adapter -> typed Context -> resource grant -> supervised Handler
                 <- standard Response(Body) <- bounded diagnostic event
```

`http/server` snapshots the current middleware-wrapped handler only after a
worker and memory lease has been granted. Reload affects later admissions;
workers already running keep their snapshot. Drain rejects later admissions
and waits only for the finite worker set. Request and response bodies remain
pull-based across this boundary, so the executor neither buffers a stream nor
breaks protocol backpressure.

The HTTP/1.1 adapter owns each accepted TCP or TLS socket in an unlinked,
listener-supervised connection actor. It parses and dispatches a finite number
of pipelined requests sequentially, preserving response order without retaining
an unbounded response queue. Request pulls are message-mediated so only the
connection actor reads the active-once socket. Response pulls run in monitored,
finite-deadline workers; timeout, callback exit, encoding failure, and socket
failure cancel the shared body cursor before the connection closes. Cleartext
listeners require an explicit opt-in, while TLS listeners require certificate,
key, service identity, and `http/1.1` ALPN configuration.

Listener construction and every accepted-socket handoff use two-sided
readiness messages: the receiver first acknowledges ownership, the caller
records the transition, and only then may the receiver enter its accept/read
loop. `http1_listener_snapshot` retains fixed-size saturating counters for
listener readiness, accept, connection start/exit, parsed heads, handler
dispatch/completion, and terminal failures. It contains no endpoint, target,
field, body, TLS material, PID, socket, or backend reason. Concurrent writers
use an active-writer/generation protocol; readers retry only 64 times and mark
a best-effort fallback `consistent = False` instead of blocking.

Package-specific implementation and qualification notes live in
[`packages/http3/docs`](../packages/http3/docs/) and
[`packages/quic_core/docs`](../packages/quic_core/docs/).
