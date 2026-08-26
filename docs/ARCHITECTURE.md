# Architecture

## Scope and status

`http3` is an HTTP/3-only client and server for the Erlang target. HTTP/1.1,
HTTP/2, automatic fallback, and the JavaScript target are non-goals. The
current implementation uses the in-tree `gleam_quic` package as its only
production transport; aioquic and quic-go are test peers, not runtime
dependencies. The v1 decision is reopened. HTTP/3/QPACK source ownership is
physically split and the generic public QUIC API is implemented. Migrating the
root HTTP/3 workers off package-private QUIC/TLS primitives remains a release
blocker.

The package version is required tool metadata. Architecture and quality gates
do not depend on a tag, hosted release, or package publication.

## Production data flow

```text
Application
    |
http3, http3/client, http3/server, http3/transport, http3/capsule
    |  opaque Client / Connection / Stream / Listener / Request values
http3/internal request, response, event, and error adapters
    |
http3-owned HTTP/3 workers, session, Capsules, and QPACK
    |
package-private gleam_quic QUIC driver, TLS, and recovery
    |
narrow Erlang runtime FFI: UDP, crypto, X.509, qlog file I/O
    |
operating-system UDP socket
```

Protocol state moves down this diagram and typed observations move up. A raw
PID, atom, reference, socket, map, record, mailbox message, traffic secret, or
native trust-store term cannot cross the public boundary.

## Public HTTP boundary

The public client and server use `gleam/http` methods, requests, responses,
headers, and status codes. This shares an HTTP data model; it does not add an
HTTP/1.1 or HTTP/2 implementation.

`Client`, `Connection`, `Stream`, `Listener`, `Request`, `Push`,
`ResumptionTicket`, and the transport control values are opaque. Public
operations return typed configuration, HTTP, transport, lifecycle, and limit
errors. The compiler-interface audit rejects internal module names, native
handle types, and constructor bridges in the exported package interface.

The bounded helpers are intentionally collectors with explicit request and
response limits. The streaming API is the unbounded-duration alternative, not
an unbounded-memory alternative:

- request writes synchronously retain QUIC flow-control pressure;
- response and request events are pulled by the consumer;
- every unconsumed per-stream event/Datagram queue has configured byte and
  count bounds;
- concurrent receives are rejected rather than creating ambiguous waiters;
- deadlines cover the whole operation, including handshake and cleanup; and
- cancellation, close, immediate stop, and graceful stop are observable and
  idempotent.

## Native HTTP/3 runtime

The HTTP/3 workers, session, Capsules, and QPACK implementation live under
`http3/internal`. They currently call package-private QUIC transport and TLS
primitives from `gleam_quic`; the new generic public transport API must replace
that remaining dependency-boundary shortcut. The root-owned Gleam workers own
reusable connections, listeners, stream registries, pull waiters, bounded
queues, and operation deadlines. The HTTP/3 session owns:

- the local and peer control streams and SETTINGS state;
- request, response, informational, DATA, trailer, push, and GOAWAY ordering;
- graceful drain and rejection of streams beyond the advertised boundary;
- Extended CONNECT, Capsules, and HTTP Datagrams associated with a request;
- RFC 9218 priority updates and scheduling; and
- QPACK encoder and decoder streams, dynamic-table references, blocked-stream
  limits, feedback, Huffman coding, and decompression bounds.

Terminal stream state is retained in a bounded FIFO registry so late messages
can be classified without accumulating state for every historical stream.
Datagrams that arrive before their request association are bounded as strictly
as associated queues.

The public server accepts one request head at a time per `accept` call while
the underlying listener continues to multiplex connections and request
streams. Multiple certificates can be configured; the TLS server selects a
matching credential from the strict ClientHello SNI name. Graceful stop sends
the HTTP/3 drain signal, rejects later accepts, permits active requests to
finish,
then closes the listener within its deadline.

## Native QUIC runtime

`packages/gleam_quic` contains the protocol implementation. Its driver joins
the following Gleam-owned components:

- invariant, long-header, short-header, frame, transport-parameter, and packet
  codecs for QUIC v1 and v2;
- authenticated compatible version negotiation and Retry handling;
- Initial, Handshake, 0-RTT, and 1-RTT packet spaces and key lifecycle;
- connection-ID issuance, retirement, routing, and stateless-reset tokens;
- connection and stream state, out-of-order reassembly, final-size checks,
  connection and stream flow control, and round-robin stream scheduling;
- ACK generation, RTT estimation, loss detection, PTO, retransmission,
  NewReno, CUBIC, pacing, and ECN validation;
- anti-amplification, authenticated address tokens, path challenge/response,
  NAT rebinding, active migration, and connection-ID rotation;
- IPv4 and IPv6 UDP operation, QUIC DATAGRAM, path statistics, and opt-in qlog;
  and
- DPLPMTUD probes that raise the datagram size only once a probe of that size
  has been acknowledged over a socket that sets Don't-Fragment, and packets at
  every level sized from the resulting path MTU.

A 1-RTT packet takes its frame budget from the validated path MTU after
paying for the widest short header QUIC v1 allows, the AEAD tag, and any ACK
coalesced ahead of the frame. STREAM and CRYPTO data is split to what is left.
A QUIC DATAGRAM frame cannot be split, so it is sized when it is queued with
the scheduled ACK already subtracted; if the ACK has grown by the time the
packet is built, the datagram waits one packet and the ACK goes out, because
acknowledgement delay is bounded by `max_ack_delay` while an application
queue is not. An early datagram is sized against the wider 0-RTT long header
instead, and a 0-RTT packet is budgeted from the floor rather than from the
caller's request. NEW_TOKEN and CONNECTION_CLOSE carry caller-supplied payloads
and are neither splittable nor droppable, so both are bounded where they enter
the connection to fit the 1200-byte floor a black hole resets the path to.

Every packet at every level is measured against the path before it is sent, so
no datagram this endpoint builds exceeds the smaller of the validated path MTU
and the peer's advertised `max_udp_payload_size`. Initial and Handshake
packets are budgeted against the long header they ride, an Initial paying for
its address-validation token as well, and the caller's requested frame budget
is a ceiling rather than the size. That bound holds only while every level's
protection is itself smaller than the floor, so the one part of it a peer
chooses -- the address-validation token, which a client repeats in every
Initial -- is bounded where it enters the connection.
`connection_state.maximum_initial_token_bytes` is that width: the floor, minus
what protecting an Initial costs around its frames, minus the payload one
Initial keeps in reserve. It works out to 861 bytes, and that number is a
conservative internal ceiling, not a wire limit -- RFC 9000 places no upper
bound on a token, and the budget charges every Initial header field its widest
encoding (twenty-byte connection IDs and 8-byte varints throughout), so a token
somewhat past it would often still have fitted the header a given connection
writes.

A token past that width never reaches the send path. A cached NEW_TOKEN that
wide is ignored and the connection is attempted without it, because a token is
only an optimization and the server may still answer with a Retry; a NEW_TOKEN
that wide arriving on a live connection is not stored; and an authenticated
Retry carrying one ends the attempt with `driver.RetryTokenTooLarge`, since the
client can neither drop that token nor repeat it. That error is reported apart
from a connection failure precisely because the limit is local: the server
violated nothing, so neither a log nor a qlog attributes the outcome to it. The
width is checked only after the Retry integrity tag verifies, so a forged Retry
is still discarded silently and cannot end a connection.

A packet carrying nothing but an acknowledgement is measured too: a widely
scattered retained range set encodes past the floor on its own, and RFC 9000
section 13.2.4 lets the oldest ranges stay retained for a later packet while
the newest go out now. The Initial and Handshake frame-decoding budget stays at
the fixed default because Initial keys are derivable by any sender that can
observe a connection ID.

Every QUIC UDP socket asks the kernel for Don't-Fragment at open --
`IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` set to `PMTUDISC_PROBE` on Linux,
`IP_DONTFRAG`/`IPV6_DONTFRAG` on macOS and FreeBSD,
`IP_DONTFRAGMENT`/`IPV6_DONTFRAG` on Windows. A platform that refuses the
option still opens the socket; it reports Don't-Fragment inactive, and the
connection is configured so DPLPMTUD stays at the 1200-byte floor rather than
reading an acknowledged probe that the kernel could have fragmented as proof
the path carries that size (RFC 8899 section 3). Every runtime passes the
answer for the socket it actually sends on -- both core runtimes, the two
native clients, and the native server -- and `default_config` fails closed with
Don't-Fragment absent, so a connection built without that answer stays on the
floor instead of assuming a capability it has not checked.

With the option active the kernel refuses an oversized send with `EMSGSIZE`.
Every send that carries connection data routes its result through one shared
classifier, `udp.classify_send`, which is the only place the three-way decision
-- committed, path measurement, dead socket -- is made. Eleven call sites use
it: seven flush paths (the core client and server, the native client's
handshake and HTTP/3 flushes, the happy-eyeballs client's two, and the native
server's) and four probe paths (a client and a server probe in each runtime).
`EMSGSIZE` is classified as a path measurement: the datagram is dropped
uncommitted, the frames it held are still owed and are retransmitted by
recovery, and the path returns to the floor. It is never a socket failure, so
an outgoing device narrower than the path DPLPMTUD confirmed costs a round trip
rather than the connection; every other send error is fatal for the socket,
because a closed, unowned, or broken socket cannot be recovered by shrinking
the path. The remaining sends are the listener's stateless Retry and Version
Negotiation replies and the server's shutdown CONNECTION_CLOSE, which are far
below the floor and have no path state to return.

The pacer's burst and the congestion controllers' `max_datagram_size` both
follow the validated path, so one path-sized datagram always fits inside a
burst and RFC 9002's window floor of two maximum-sized datagrams stays above
the datagram the path now carries -- a loss event cannot leave the window
narrower than a single send. The pacing wake is armed for the datagram the
send path would actually build rather than for a path-sized one.

The driver uses monotonic deadlines and an active-once UDP relay. It drains
bursty handshake datagrams, retransmits after loss or corruption, validates a
new path before moving application traffic, and discards obsolete packet
protection keys according to the relevant packet-space and key-update rules.

## TLS and resumption

TLS 1.3 handshake messages, extensions, transcript coordination, key schedule,
PSK binders, QUIC transport parameters, and session-ticket contents are Gleam
code. The supported packet-protection families are AES-128-GCM,
AES-256-GCM, and ChaCha20-Poly1305 with the corresponding QUIC header
protection.

Client-side server authentication always validates the certificate path and
the DNS or IP service identity. A custom CA changes trust anchors but does not
disable either check. The normal public surface has no insecure verification
switch. Client credentials and server-side mTLS policy are not implemented.

Session tickets are opaque and encrypted. They bind the verified server name,
port, ALPN, cipher, QUIC version, and the transport parameters that affect
0-RTT. Ticket ages are bounded, the server applies a time-windowed anti-replay
cache, Retry rejects early data, and changed remembered parameters reject
early data without preventing a safe 1-RTT resumption. Until acceptance is
known, the public client permits only GET, HEAD, and OPTIONS in early data.
Rejected early requests are retransmitted after 1-RTT keys become available.

## Erlang FFI boundary

Only five production Erlang modules exist:

| Module | Responsibility |
| --- | --- |
| `http3_internal_transport_ffi` | Wrap already opaque Gleam handles for the public transport facade |
| `gleam_quic_crypto_ffi` | Runtime hashes, HMAC, secure randomness, X25519, AEAD, and header-protection primitives |
| `gleam_quic_tls_ffi` | PEM/X.509/key decoding, path and identity validation, signing, verification, and constant-time comparison |
| `gleam_quic_udp_ffi` | UDP socket ownership, address conversion, ECN ancillary data, and monotonic time |
| `gleam_quic_qlog_ffi` | Unique trace-file creation and bounded JSON event output |

These modules validate Erlang term and binary shapes, catch runtime failures,
and return closed numeric or typed errors. They do not parse or construct
QUIC, TLS, HTTP/3, or QPACK wire messages and do not own a protocol state
machine. qlog serialization formats diagnostic events that have already been
selected and bounded by Gleam; it does not inspect network packets.

## Dependency and replacement boundary

The root package depends on the path package `gleam_quic`, `gleam_http`, and
`gleam_stdlib`. The native package depends only on `gleam_erlang` and
`gleam_stdlib`. No external QUIC library, NIF, C library, or alternative
production backend is selected at runtime.

Keeping the root adapter remains useful even with one backend: it normalizes
the lower-level native errors, prevents representation leakage, and lets the
public API describe HTTP behavior rather than driver machinery. A future
transport experiment must connect below this boundary and pass the same
observable behavior suite; it cannot introduce a public raw-handle escape
hatch.

The intended `gleam_quic` public API is application-protocol independent. Raw
wire codecs are excluded from its compiler package interface. HTTP/3 session,
QPACK, Capsule, and worker ownership has moved to `http3`, and the core Hex
archive contains none of those modules. Generic endpoint/connection/stream
APIs are implemented and directly tested. Root internals have not yet migrated
to them and still reach package-private QUIC transport primitives; the
boundary audit tracks that remaining step. That audit runs as three layers
(a Semgrep rule over the already-clean files, an import scan of `src` and
`test`, and a compiled-module xref) and allowlists the remaining root
internals in the shrink-only `api/boundary.allow` until the migration
completes.

## Resource ownership and shutdown

Every live resource has one owner:

- a one-shot client owns and closes its connection;
- a reusable client worker owns its UDP socket and all request streams;
- a listener worker owns the socket, the connection-ID routing table, the
  admission counters, and the accept queue;
- one supervised connection actor per accepted connection owns that
  connection's transport state, streams, waiters, qlog writer, and keepalive
  and path-MTU deadlines;
- network and command turns drive only the connection they belong to, and each
  connection arms its own protocol timer, so a stalled connection can only
  delay itself;
- each blocked call is monitored and has a fixed deadline; and
- owner termination initiates bounded cancellation and socket cleanup.

The listener spawns each connection actor unlinked and monitors it. The actor
reports its completed handshake back to the listener, which then hands it to an
accept waiter or to the bounded accept queue.

A connection actor ends the moment its transport phase reaches `Closed` -- when
a local close finished draining, when the idle timeout expired, or when the peer
vanished and the idle timeout expired for it. A closed transport owes no further
output and arms no further deadline, so the actor releases everything it owns
instead of staying resident for the listener's lifetime: it fails every pending
waiter with the typed closed error, closes its qlog writer, tells the listener
it is released, and exits. The typed error is what its owner sees, so a waiter
on a connection that ended reads a closed connection rather than a protocol
failure.

The actor's own wait is bounded whatever the phase. Its loop parks until the
earliest of the transport deadline, the PMTU probe, and every waiter's expiry,
and when none of those arms a deadline it still parks for a bounded interval
rather than indefinitely, so a phase no timer announced is noticed within that
interval.

Releasing one connection frees its connection ID, its aliases, and its admission
count, and drops it from the accept queue. The listener performs that release on
the actor's `Released` notice and on the monitor `Down` for the same actor,
whichever arrives first; the second finds no route left for that process and
does nothing, so the release is idempotent, and a notice whose identifier is no
longer the one that process routes releases nothing. Because the identifier and
its aliases are dropped in the same step as the route, a datagram naming a
released connection ID resolves to no route at all: a long header takes the
unknown-route path and a short header is dropped, and neither reaches a dead
actor.

Each actor monitors the listener in turn, so a listener that stops takes every
connection it owned with it. Connection actors send on the listener-owned socket
directly, so no outbound datagram needs a listener hop; the listener forwards
each routed inbound batch to the owning actor. The server never issues
additional local connection IDs, so routing tracks exactly one identifier per
connection plus the pre-Retry alias.

That inbound hand-off is credit bounded per connection. The listener groups one
relay batch by connection ID and sends one message per connection per batch,
carrying only as many datagrams as that connection's remaining window admits:
192 datagrams and 256 KiB, held as a small record beside the route. Both halves
bind, and the byte half is what bounds delivered memory, because the listener
sockets impose no packet-size cap and a peer can spoof multi-kilobyte
datagrams that the datagram half alone would admit 192 of.

The window is sized against the relay batch, which is what makes it safe for a
healthy connection as well as bounding a flooding one. The relay hands the
listener a whole batch of up to 64 datagrams in one message, the listener
routes that batch in a single step, and it can route the next batch before the
consumption acknowledgement for the previous one is handled -- no
acknowledgement widens a window part way through a batch. Two whole relay
batches is therefore the floor: a connection that is merely one acknowledgement
behind has to absorb two full batches back to back without losing anything. The
datagram half ships a third batch of slack above that floor, so an ordinary
datagram of the peer's own -- an acknowledgement, a probe -- arriving inside
the same unrefilled window cannot eat into it; that slack costs no memory,
because the byte half is what bounds bytes. The byte half holds two full
batches of 2 KiB datagrams, and 2 KiB is above the Ethernet MTU and well above
the 1200-byte floor RFC 9000 section 14 guarantees, so at the sizes a
conventional path delivers it too carries slack: 218 datagrams at that floor,
174 at the Ethernet MTU, against the 128 the floor requires.

What the byte half costs is worth stating in full, because it is the number
that bounds memory: 256 KiB of delivered-but-unconsumed bytes per connection,
and 256 MiB across the default 1024-connection admission limit, where the
narrower 64 KiB window it replaces totalled 64 MiB. That aggregate is four
times the 64 MiB `EndpointMemory` value `config.default_limits` carries, and
nothing enforces it today: endpoint-wide memory accounting and admission
budgets are open work (PRE-003 and PRE-004), and this window is one of the
inputs that accounting has to charge for when it lands. Reaching the aggregate
also takes 1024 connections flooded at once whose owners have all stalled,
because a connection that keeps up holds a full window only momentarily. The
byte half is still far narrower than two batches of the largest datagram the
transport can carry: those would be 7.5 MiB per connection, while the listener
socket's whole receive buffer is 4 MiB, so a burst that large cannot even be
queued for the relay. Datagrams above 2 KiB are still delivered -- the byte
half simply becomes the half that bounds them.

No configured `Limits` resource fits that window, so both halves are fixed
constants in the listener actor. `Queue` counts accepted work, `Buffer` counts
stream bytes, and `Datagram` -- the closest-sounding candidate -- bounds RFC
9221 DATAGRAM-frame queueing inside an established connection rather than the
UDP delivery window in front of it; it is also application tunable, and a
denial-of-service bound must not be something an application can widen.

The connection actor answers each delivered message with the datagram and byte
count it consumed, and the listener refills that connection's window by exactly
that much, never above the fixed window. Because every message the listener
sends costs the window at least one datagram, the mailbox is bounded in
messages as well: at most one message per datagram of the window, plus the one
empty message that reports drops taken while the window was shut, which the
listener sends only once the actor has acknowledged everything else it was
sent. Whatever a batch carries beyond the window is dropped and counted for
that connection alone, and
`server.dropped_datagrams` publishes the count through the connection
diagnostics path. That counter is deliberately server-only: a client owns its
own socket and connection with no listener in front of it, so it has no
credited delivery path and no drops to report. Dropping is protocol correct --
QUIC recovers a dropped datagram exactly as it recovers one the network lost --
and it is what makes a stalled connection structurally unable to delay another:
its actor's mailbox is bounded by the window plus its own owner's commands, and
the relay's one-batch credit is still returned immediately after every batch, so
the listener itself never blocks and never queues.

The public suite pins both halves over real UDP. A spoofing peer that floods
one connection's ID leaves that actor's mailbox inside the window in datagrams
and in bytes, leaves one batch's admitted share in a single message rather than
one message per datagram, raises only that connection's drop counter, and --
once the flood stops -- leaves the connection able to complete a bounded round
trip. With the window removed, the same flood put 26,978 datagrams and 176 MB
in one connection actor's mailbox.

The floor is pinned in the same suite, twice. One test reads the shipped window
out of the listener and the batch size out of the relay and holds the first to
at least two of the second, so it binds the numbers production actually uses
rather than copies of them. The other is behavioural: a connection whose owner
keeps reading takes two whole relay batches sent back to back with no flow
control in the way, and `server.dropped_datagrams` stays at zero. That test
also runs a flow-controlled transfer first, which is what leaves the connection
caught up and exposes the identifier the listener routes to it; the transfer's
own drop count is read separately, but it is a sanity check on real traffic
rather than part of the floor, because a connection's receive buffer holds its
peer to well under one relay batch in flight. Raising that buffer above the
byte half would not exercise the floor either -- a peer allowed more bytes in
flight than the window admits is outrunning the delivery window by
construction, and the drops would be correct.

Known peer-controlled lengths, counts, tables, stream windows, queues,
Capsules, Datagrams, packet histories, retained keys, terminal entries,
timeouts, and amplification credit have explicit bounds, including a connection
actor's own mailbox of forwarded inbound batches, which the listener's
per-connection delivery window bounds. All role-applicable per-connection public
limits now reach those allocations; isolated accounting and enforcement of the
aggregate `EndpointMemory` budget remain release gates.
Cleanup tests require process and mailbox convergence rather than treating a
returned response as sufficient.

## Stable and experimental scope

The intended stable v1 scope is published QUIC, HTTP/3, QPACK, priority,
Extended CONNECT, Capsules, and Datagram standards. Current implementation
coverage and open requirements are tracked per row in the conformance matrix.

Internet-Drafts such as WebTransport over HTTP/3, QUIC multipath, ACK
Frequency, reliable stream reset, extended key update, receive timestamps, and
the evolving qlog schemas are not silently negotiated by this package. Draft
work belongs in an explicitly named, revision-pinned experimental package.

The implementation and evidence contract is recorded in the
[pre-release v1 gate](V1.md), [conformance matrix](CONFORMANCE.md),
[Testing](TESTING.md), and the [security review](SECURITY_REVIEW.md).
