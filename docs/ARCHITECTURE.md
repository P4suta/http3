# Architecture

Both native client paths use the core connection's existing application diagnostic sink.
HTTP/3 doesn't open a second qlog writer.
Configuration checks path syntax without filesystem work.
Core startup checks writability after validating the connection's diagnostic allowance.
Server reservations remain held until the native cleanup ticket confirms all known children have stopped.
Core and stable HTTP/3 Client copies share actor-free diagnostic admission identities across connection attempts.
The H3 identity also spans origins because each attempt creates a separate public core Client.
Unconfirmed starts retain compact byte and slot charges.
A pending cleanup starts one bounded observer for at most two owners, with no more than 64 retained tickets per identity and a seven-second absolute deadline.
A confirmed later join returns the core charge and its linked H3 scalar charge exactly once.
Refused or expired observations remain quarantined.
A successful public core close confirms diagnostic cleanup and transport actor exit under one absolute deadline.
The parent adapter clamps nested HTTP/3 closure to its remaining lifecycle budget.
Client-wide dynamic accounting outside the diagnostic slice remains open.

An HTTP/3 request that reaches its total deadline before final response headers keeps the caller inside a separate bounded cleanup-confirmation interval.
The request reaper remains the sole owner of its stream, upload, checked-out connection and request charge during that interval.
Reaper exit and a shared one-bit completion claim confirm the cleanup outcome.
Cleanup releases resources after joining every child and callback, or records a typed failure and keeps the finite charges.
If either observation is missing, the caller issues one bounded untrappable stop and records an HTTP/3 operation-cleanup failure.
The caller discards queued late replies and leaves both resources with their existing owners.
Any pool publication or request charge without prior reaper proof therefore stays quarantined.
The unified dispatcher applies its protocol-free failure fallback only after recording an HTTP/3 terminal.

The repository has three dependency layers:

```text
http -> http3 -> quic_core
```

`http` owns the common body, error, client, server, policy, and HTTP/1.1 and HTTP/2 runtime.
`http3` owns HTTP/3, QPACK, Capsules, request-associated Datagrams, and WebSocket over HTTP/3.
`quic_core` owns application-independent QUIC v1/v2, TLS 1.3, streams, transport Datagrams, and bounded diagnostics.
Each core connection also owns the lifetime of its single bounded qlog writer.
An opaque application sink lets HTTP/3 append only typed, payload-free protocol metadata to the same trace.
The sink cannot expose, inspect, or close the writer.
This keeps client/server events from being split across competing trace files while preserving the transport ownership boundary.

The standard `gleam_http` request and response types cross every public HTTP boundary.
Public values never expose processes, sockets, references, backend terms, key material, or traffic secrets.
All peer-controlled queues, buffers, waits, and allocations are finite.

Repository tooling has the same ownership rule.
A source-hash-pinned Python supervisor owns each native tool tree.
POSIX uses a new session and joined process group.
Windows creates a headless ConPTY first, attaches a suspended root process through the exact `STARTUPINFOEX` pseudoconsole attribute, assigns it to a kill-on-close Job Object, and then resumes it.
Descendants inherit the same headless console unless they explicitly detach; authored launch audits reject every nonzero creation flag.
Imported Python launch helpers also query the current console and the current Job's kill-on-close limit before spawning.
An environment value alone cannot assert ownership.
Output remains continuously drained after its retained limit, and completion requires both an empty Job and a closed, joined console session.
Process evidence contains fixed lifecycle fields and source/runtime digests; it never contains arguments, paths, process identifiers, handles, or raw failures.
Ownership is registered before the `START` transition.
An ambiguous START send is recovered through `STOP` and the normal final/exit/tree join; failure to observe that proof is a typed blocked result and preserves the isolated crash location.
A supervisor-side output-limit event is also carried as a typed classification even when the chunk crossing the limit is deliberately not forwarded to the parent.

QUIC establishment resolves IPv4 and IPv6 in independently owned callbacks.
A pure scheduler starts candidates on demand, waits at most 50 ms for an IPv6 answer after an IPv4 answer, spaces ordinary attempts by 250 ms, and preserves a 100 ms minimum when a failed attempt accelerates the next launch.
At most sixteen distinct destinations are attempted.
These observed constants remain stable throughout version 0.1.0 so tests and resource planning do not depend on an inferred release age or global IPv6 quality.
Late family results can replace unstarted tail entries and recover an earlier failed candidate.
One supervisor owns the public bootstrap actor and its eighteen helpers under the original absolute deadline.
The bootstrap joins its helpers while remaining supervised.
Only the original caller can detach an established actor, and it joins the supervisor before publishing success.
Timeout joins the entire group.
A queued successful candidate cannot cross that deadline while awaiting publication.
Socket adoption retains a close capability before ownership transfer, so cancellation between transfer and publication cannot leave an untracked socket.
After a winner is adopted, the coordinator cancels and joins its private resolver workers immediately.
The library owns no DNS cache; any continued processing and caching of a host resolver's network replies remains with that resolver.

The UDP boundary obtains a route-selected source address without sending a datagram, and reads an observed source prefix when OTP exposes its netmask.
Destination ordering applies RFC 6724's ordered rules to available attributes before family interleaving.
Missing deprecation, mobility, native-transport, or prefix information remains explicitly unknown.
Portable qualification of all RFC 6724 attributes remains open; successful loopback probes do not prove those unavailable capabilities.

The public connect trace's `NameResolution` phase measures the time until the first candidate is eligible to dial; it does not mean every DNS query succeeded.
An independent internal 64-entry scalar trace records each family's start, usable/empty answer, resolver rejection, deadline, cancellation, or unexpected worker exit.
It shares the opaque trace's lifetime and retains no hostname, address, callback error, or runtime handle.

Automatic protocol discovery accepts authenticated HTTPS records and the first supported same-host `h3` Alt-Svc alternative for an HTTPS origin.
The origin host and port remain the TLS identity, request authority, resumption identity, and application-visible URI while only the UDP destination port changes.
The finite, network-isolation-keyed store applies the RFC 7838 24-hour default, subtracts a valid response Age, and caps retained freshness at seven days.
`clear` is case-sensitive and dominates alternatives in the same response.
Unknown parameters and valid quoted pairs don't discard a supported entry.
Requests sent over the selected alternative carry `Alt-Used`, while an HTTP/3 421 removes the route and ignores any replacement advertisement in that response.
Explicit proxies disable direct HTTP/3 discovery.
The requirement inventory records unsupported discovery capabilities separately.
The automatic client excludes cross-host Alt-Svc, HTTP/2 ALTSVC frames, operating-system network-change notifications, browser origin-data clearing, and certificate-pin policy.

Automatic RFC 6265 cookie handling is an explicit opt-in.
Its in-memory store is finite by both entry count and retained bytes, belongs to one Client, and is partitioned by the configured network-isolation key.
A typed persistence adapter receives that same partition and a hard callback deadline.
Cookie hosts use the shared IDNA/IPv4/IPv6 canonicalizer.
Domain and Path matching use label and path-segment boundaries.
The client emits Secure cookies only for HTTPS.
Expires and Max-Age resolve to the store's monotonic clock.
An expired replacement removes the exact name/domain/path key.
Matching cookies are serialized once, with longer paths and earlier live creation times first, and their bounded store entries are promoted after access so capacity eviction is least-recently-used after expired entries have been removed.
Closing the Client ends the session and destroys every in-memory cookie.
When cookie handling is disabled, response Set-Cookie fields are ignored and no stored Cookie field is generated.
Caller-supplied opaque headers remain the caller's responsibility.
The library is not a browser, exposes no non-HTTP cookie API, and does not ship a continuously updated public-suffix list.
The lower 256-entry default and explicit application-selected limits intentionally favor bounded service clients over RFC 6265's advisory general-browser minima; network-isolation partitioning does not replace an application's public-suffix or third-party cookie policy.

The production OHTTP surface accepts no caller-selected request ephemeral key or response nonce.
Every request obtains fresh operating-system CSPRNG bytes.
Client and gateway response contexts each carry one shared atomic claim, so a copied value still permits exactly one authenticated response operation.
A failed authentication consumes that claim; structural and size rejection runs before it.
Byte-oriented request and response functions decode one bounded binary HTTP message and apply the same type, `Expect: 100-continue`, HTTPS, and target-authority checks as their structured counterparts.
The replay store is a shared owner process keyed by the request `enc` value.
Atomic pending reservations count toward its hard capacity, become committed immediately after AEAD authentication, and are aborted on cryptographic failure.
Caller termination and a finite pending deadline reclaim abandoned work; accepted identities remain until capacity is exhausted in the compatibility store, or until an explicitly configured retention window expires.
Store-owner termination is a typed fail-closed failure and never creates an empty replacement.
Detailed gateway opening retains a one-shot response context for authenticated malformed, Expect, and target-policy failures.
The integration admission API consumes that context to return a canonical encrypted 400, 417, or 403 response.

The private `quic_core_terminal_close_ffi` boundary stores one unsigned atomic word per accepted connection.
It preserves only the first authenticated terminal kind (peer application, peer transport, or local transport) and 62-bit code through compare-and-exchange.
Late calls can recover the cause after the connection actor releases its socket, admission, and qlog resources.
Connection handles share the word until garbage collection.
It allocates no process, table, registry, queue, or reason-text storage.

The root keeps each Erlang runtime boundary narrow and task-specific.
`http_body_ffi` owns bounded positional file reads and an internal atomic cancellation flag.
An internal result callback preserves typed cleanup timeout and cancellation failures through the Body boundary.
The public `from_pull` callback contract stays unchanged.
HTTP/3 response bodies share one scalar completion cell so cancellation can recover the cleanup result after the request coordinator exits.
Successful cancellation requires callback and controller termination.
A known failure survives an expired registry-confirmation wait, while `await_release` stays pending until the registry observes both controllers terminate.
`http_transport_ffi` owns finite DNS/connect, active-once TCP/TLS I/O, mandatory TLS verification, ALPN, and socket ownership transfer.
`http_client_ffi` owns one Client's finite lifecycle and HTTP/1.1 idle pool.
Its actor transfers a checked-out socket to the calling process and takes ownership back on check-in.
A Client can serve different processes without a global registry.
The unified client disables the HTTP/1 adapter's compatibility reconnect after a stale pool checkout.
Its single finite retry policy permits a second wire attempt only for an idempotent request with a replayable body and positive retry budget when the request is proven unstarted, the peer explicitly guarantees it was not processed, or a configured response status was received.
A connection loss without that evidence is possibly processed and never retried.
The client regenerates the body and allocates a new payload-free attempt ID only after the failed attempt has published its terminal and release.
Disabling retries therefore permits exactly one wire attempt; adapter-local and outer retries cannot compound beyond the configured maximum.
`http_server_ffi` provides only identity tokens, resource credit, finite diagnostic counters, monitored worker creation, an exception-redacting callback boundary, and one event-driven cancellation broker per live Context.
The broker emits a one-shot tagged signal without a timer.
It converges after cancellation, explicit removal, subscriber exit, or Context-owner exit.
Its internal snapshot contains only state and saturating counters.
Diagnostic observations carry a payload-free request ID and reporter-local causal sequence, so concurrent sink completion can be reconstructed without serialising callbacks.
`http_http1_listener_ffi` and `http_http2_listener_ffi` own only their protocol listener's saturating phase counters and finite multi-writer snapshot protocol.
The HTTP/2 snapshot additionally distinguishes drain request, per-connection command/receipt, GOAWAY write, and drain completion.
Neither module performs network, file, parsing, or dynamic-code operations.
The complete FFI source inventory is declared once in `qualification.json`; source discovery, Dialyzer, compiled xref, API leak checks, and the status audit all consume that same set.
The CONNECT-UDP listener diagnostics also avoid a writer mutex: independent atomic counters are bracketed by an active-writer count and generation.
A snapshot is marked consistent only when no writer overlaps it; after a finite retry budget it returns the payload-free observed fields with `consistent` false.
An orphaned writer therefore poisons consistency without blocking later counter updates or diagnostic readers.
CONNECT-UDP setup uses a separate fixed-size trace.
Its DNS and socket-open records split total phase time into bounded-worker queue and callback time.
The records distinguish callback start, supervisor expiry, and a timeout value reported by the callback.
All fields are booleans, counts, or monotonic durations; the trace cannot retain adapter arguments or results.
`http_masque_udp_ffi` owns one target-facing UDP socket per adopted actor, with finite setup and operation deadlines and eight-command admission.
Each actor has active-once receive credit, a single retained event, and an independent one-slot terminal-event waiter.
The boundary also records requested/effective buffers and handles owner-death cleanup.
The event waiter lets a protocol actor select socket failure without polling or another datagram operation.
A direct public-API H3 request resource composes that event into reset plus STOP_SENDING, while a protocol-neutral Context resource reaches the H1/H2/H3 cancellation adapters.
A continuous post-success proxy-session actor for every H1/H2/H3 tunnel remains an explicit integration step.
The setup state machine reports a fixed-size monotonic timing snapshot for DNS, socket open, socket adoption, and failure cleanup.
Socket startup/adoption and established relay operations have independent finite deadlines, so a strict per-command budget does not also become a cold-start admission budget.
Separate timeout bits assign an exhausted deadline to exactly the phase that observed it, while the event sequence records production-only adoption.
These observations contain no authority, endpoint, payload, callback error, PID, or socket value.
For the default HTTP/3 proxy, the HTTP/3 package exposes a typed guaranteed request-Datagram capacity before the success response.
`quic_core` derives it from the authenticated peer frame limit, 1200-byte path floor, widest 1-RTT protection, and maximum half-path ACK reservation; HTTP/3 then removes the quarter-stream ID.
The root removes CONNECT-UDP Context ID zero and caps the target-facing UDP payload before opening the socket.
ACK debt, migration, and black-hole fallback cannot invalidate the fixed tunnel contract.
The separately exposed live maximum remains available for adaptive callers.

`http_masque_packet_too_big_ffi` handles only oversized packets from the exact connected target.
It replaces the payload with a fixed-shape typed event before the event can enter the caller mailbox, reconstructs the invoking IPv4 or IPv6 UDP packet only for the duration of a bounded ICMP build/send call, and retains no payload in diagnostics.
Raw ICMP uses a per-tunnel 10-message burst and 10-per-second token bucket, a 100 ms maximum send deadline, prohibited-address checks, and permanent permission/unsupported caching.
Its 21-counter snapshot uses a finite-retry seqlock; a failed consistency read is explicit rather than spinning forever.
Raw-socket capability and platform-specific delivery remain qualification concerns and never alter the primary drop decision.
The server and MASQUE protocol state machines remain in Gleam.
None of the modules parses HTTP or exposes file handles, sockets, PIDs, references, or backend terms through the public API.

The common inbound path is:

```text
protocol adapter -> typed Context -> resource grant -> supervised Handler
                 <- standard Response(Body) <- bounded diagnostic event
```

`http/server` snapshots the current middleware-wrapped handler only after a worker and memory lease has been granted.
Reload affects later admissions.
Workers already running keep their snapshot.
Drain rejects later admissions and waits only for the finite worker set.
Request and response bodies remain pull-based across this boundary, so the executor neither buffers a stream nor breaks protocol backpressure.

The common server allocates one payload-free request ID and emits `RequestStarted` before resource admission.
Resource refusal ends with `RequestRefused`; cancellation, drain, and executor loss end with `RequestFailed`.
Both paths dispose the input under a fixed cleanup deadline and emit exactly one `RequestReleased`, even when no handler was created.
A single atomic dispatch token assigns acquire-to-worker cleanup to either the submitting process or the guardian.
A guardian that loses that claim reports its abandoned start before exiting, preventing its delayed DOWN from creating a duplicate release event.
Connection accept, TLS, and socket-ownership transitions stay in the bounded adapter or QUIC transport diagnostics.
The request trace begins only after an adapter has constructed a validated `Context`, so it never invents a request identity for a connection that did not produce a request head.

The HTTP/1.1 adapter owns each accepted TCP or TLS socket in an unlinked, listener-supervised connection actor.
It parses and dispatches a finite number of pipelined requests sequentially, preserving response order without retaining an unbounded response queue.
Request pulls are message-mediated so only the connection actor reads the active-once socket.
Response pulls use the same admitted source guardian as client uploads.
The guardian joins each reader, observes owner loss, and keeps its grant until source cleanup completes.
The connection selects source events, peer input, and stop commands under one absolute response deadline.
Input received during a pull is retained within the stream-buffer limit for the next pipelined request.
TLS closure cancels a stalled producer; TCP read EOF preserves the existing half-close response contract.
Listener stop closes sockets and waits for actual connection exits.
A forced termination cannot report successful graceful cleanup.
Cleartext listeners require an explicit opt-in, while TLS listeners require certificate, key, service identity, and `http/1.1` ALPN configuration.

Listener construction and every accepted-socket handoff use two-sided readiness messages: the receiver first acknowledges ownership, the caller records the transition, and only then may the receiver enter its accept/read loop.
`http1_listener_snapshot` retains fixed-size saturating counters for listener readiness, accept, connection start/exit, parsed heads, handler dispatch/completion, and terminal failures.
It contains no endpoint, target, field, body, TLS material, PID, socket, or backend reason.
Concurrent writers use an active-writer/generation protocol; readers retry only 64 times and mark a best-effort fallback `consistent = False` instead of blocking.

Package-specific implementation and qualification notes live in [`packages/http3/docs`](../packages/http3/docs/) and [`packages/quic_core/docs`](../packages/quic_core/docs/).

The private `quic_core_send_observation_ffi` boundary provides one owned, fixed-row ETS observation and one process alias per synchronous stream send.
Its four operations create the observation, record a bounded park cause, publish one typed terminal result, and await the result under the original deadline.
Publication and expiry compete for the same row.
The caller can recover a result published before expiry even when notification is delayed.
A memory-held operation keeps its memory refusal classification.
Closing the observation removes the table and alias, and caller death makes both unreachable.
The boundary contains no transport or HTTP decision logic, unbounded registry, background worker, or externally visible runtime handle.

Common response diagnostics distinguish handler completion, source EOF, and the final protocol write.
Body cursors share finite atomic completion tokens.
Reading EOF records `ResponseBodyReadFinished`; a successful final write records `RequestFinished`.
A failed final DATA, trailers, or FIN write records the typed failure even after EOF.
HEAD and other bodyless responses report the actual write outcome before disposing the suppressed source.
Observations carry an opaque request ID, reporter-local admission sequence, and monotonic timestamp; sink execution remains independently bounded.
