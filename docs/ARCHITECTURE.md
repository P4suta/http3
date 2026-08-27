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
the two bounds are separate on purpose rather than by omission. The endpoint
budget below charges what a connection actor holds once it has taken a datagram
off its mailbox -- reassembly, backlogs, send buffers, sent-packet histories.
This window bounds what is still in the mailbox, delivered to the actor but not
yet consumed by it. Mailbox occupancy is therefore bounded per connection by
this window, and in aggregate by `Connections` times this window; the endpoint
budget does not hold that total down. Reaching the aggregate also takes 1024
connections flooded at once whose owners have all stalled, because a connection
that keeps up holds a full window only momentarily. The byte half is still far
narrower than two batches of the largest datagram the transport can carry:
those would be 7.5 MiB per connection, while the listener socket's whole
receive buffer is 4 MiB, so a burst that large cannot even be queued for the
relay. Datagrams above 2 KiB are still delivered -- the byte half simply
becomes the half that bounds them.

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

### Endpoint memory budget

`EndpointMemory` is one aggregate byte budget per endpoint. For a server that
endpoint is the whole listener, and the listener enforces it. For a client the
endpoint is the one connection the client owns -- and the client role does not
enforce it yet: nothing on the client path reads the value. What bounds a
client connection today is the per-connection ceilings, `Buffer`, `Queue` and
`Datagram`. Both readings, and the fact that only one of them is enforced, are
stated on `config.Limits`.

The listener owns the accumulator. The arithmetic itself is a separate pure
module, `internal/runtime/budget`, so it is exercised directly -- without a
socket, a handshake, or an actor -- and can be replaced without touching either
runtime. A budget is charged in whole 16 KiB quanta, always rounding upwards, so
it over-counts rather than under-counts and the error one connection can hide is
bounded by one quantum on the safe side. A reservation that does not fit is
refused whole and charges nothing; a release larger than a connection holds is
rejected rather than credited, because a budget that can be over-released is a
budget that silently grows; and releasing a connection twice frees its bytes
once, which is what lets the listener run the same release on the actor's
`Released` notice and on the monitor `Down` for the same actor.

The quantum is 16 KiB because the defaults have to agree with each other.
`config.default_limits` pairs a 64 MiB budget with a 1024-connection admission
limit, and admission charges three quanta -- 48 KiB, made up of a 16 KiB
handshake working set and the 32 KiB of connection-level receive credit the
server advertises in its own transport parameters. At a 64 KiB quantum a single
quantum each would already have been the whole budget, and an endpoint at its
default connection limit would have been refusing connections while every one
of them was still idle. At 16 KiB the default budget is 4096 quanta, which
funds 1024 admissions with room to spare.

Connections ask for room in 256 KiB steps rather than a quantum at a time, so
the ledger counts finely while the traffic between an actor and its listener
stays as coarse as a 64 KiB quantum made it. That step is also the receive
credit a connection has room to advertise above what it already holds, which is
why it is a window's width rather than a quantum: a step of one or two quanta
would make every window update a round trip to the listener.

#### Grant before growth

A connection is never billed for memory it has already taken. It holds a
*grant*, in whole quanta, and it may only advertise receive credit -- MAX_DATA,
MAX_STREAM_DATA, MAX_STREAMS -- and only admit an application's write into its
send buffers, inside that grant. When what it holds comes within one step of
the grant it asks the listener for the next step, asynchronously, so its hot
path never waits on the listener, and it keeps holding exactly what it holds
until the answer arrives. The peer therefore cannot make it hold more than the
grant plus the credit that was already advertised, and credit already
advertised is never retracted, because a MAX_DATA value the peer has seen is a
promise.

Every request carries a sequence number that the answer echoes, and a
connection applies only the answer to its newest outstanding request. Without
that, a `Granted` racing a later request would install a grant sized for a
footprint the connection has already grown past.

The first credit a server ever advertises is the InitialMaxData in its
handshake, and a transport parameter cannot be retracted once the peer has read
it. That value is therefore not a free promise: it is derived from the same
constant the admission charge covers, so the credit a connection opens with is
credit the budget has already funded. Every byte of credit above it is granted
before it is advertised.

The transport side of the grant is a hold on the connection receiver, stated as
an allowance over what the application has already read: the credit the peer may
have outstanding is the granted bytes less the memory the connection holds for
reasons advertising does not grow -- send buffers, sent-packet histories, crypto
reassembly. Stating it as an allowance rather than as an absolute limit is what
lets it stay true as the application reads without being restated on every read.

A held receiver keeps the ordinary half-window deadband on credit updates and
adds two triggers beneath it. One fires when there is half an update window of
room to advertise that has not been advertised yet. The other is a floor: a
peer that has spent every byte of the credit it holds is given whatever there
is room for, however little, because a hold narrower than one update window
would otherwise deadlock -- the peer runs out of credit, so the application has
nothing left to read, so half a window is never consumed and the credit is
never returned. A receiver with no hold sees none of this, so no path without
an endpoint memory grant behind it changes at all.

Both triggers are evaluated when the application reads, and a read is not the
only thing that makes room -- a grant that widens does too. Lifting a refusal
therefore drives the connection receiver directly, advertising whatever the
widened hold has made room for with nothing of the peer's to prompt it and no
read of the connection's own. Without that, a connection the hold had squeezed
down to the credit its peer had already spent would stall until its idle
timeout: the peer cannot send, so nothing arrives, so the application is never
woken to read, so a limit that only a read can raise is never raised.

#### What follows from it

- On a validated Initial the listener charges the 48 KiB admission charge
  before it builds any per-connection state. A connection that does not fit is
  refused with a CONNECTION_CLOSE carrying CONNECTION_REFUSED (0x02) in the
  Initial packet space, which RFC 9000 section 5.2.2 permits and which keeps the
  refusal cheap: no handshake is run and the peer learns immediately instead of
  waiting out its own connect deadline. Every admission step that fails after
  the charge returns the working set.
- A peer is never punished for using credit this endpoint advertised. A stream
  that arrives inside the advertised limits is always accepted, whatever the
  budget is doing; what a refusal holds back is the invitation to open more, so
  the MAX_STREAMS increase a closing stream would replenish is withheld, and
  every withheld increase is stated at once when the refusal lifts. The
  per-stream MAX_STREAM_DATA increases a refusal withholds are recorded by
  stream, so the lift restates those streams and only those: never a stream
  whose window was never held back, and never a stream this endpoint cannot
  receive on, for which RFC 9000 section 19.10 makes MAX_STREAM_DATA a
  STREAM_STATE_ERROR the peer must close the connection on. The record is
  bounded by the live stream set -- an entry is made only for a stream just read
  from, it leaves with the stream that closes, and the lift empties it. The
  connection-level limit is restated on the same lift, and from the receiver
  itself rather than from a withheld frame: the hold is a ceiling on that
  receiver rather than a queue of frames, and a ceiling that stopped a limit
  rising has to be taken off by hand.
- While refused, a Datagram frame that would take the connection past its grant
  is dropped, which RFC 9221 permits for Datagrams and which is the only place
  data is discarded. It is counted where every other inbound loss for that
  connection is counted, so an operator can see it. Stream data already inside
  an advertised window is never discarded.
- An application's write is taken into a connection's send buffers only as far
  as the grant still reaches past what that connection holds. That is checked on
  every write, not only once a refusal has landed, because a send buffer is
  memory this endpoint holds until the peer acknowledges it and billing for it
  afterwards is not a bound. A connection whose grant is being met feels no
  throttle, because the grant is kept a whole growth step ahead of what it holds
  and that step is as wide as the per-stream `Buffer` ceiling. A connection the
  endpoint has stopped funding can still finish what the grant already funds --
  a short reply, an acknowledgement -- and only what the grant does not fund is
  held back. The rest parks and ends on its own deadline as
  `Overload(EndpointMemory)` rather than as a bare operation timeout, so the
  caller can tell transient endpoint pressure from a slow peer. What decides
  that is the clamp that held the write rather than any refusal, and it is
  recorded per parked write: room left under the `Buffer` ceiling and none
  under the grant is endpoint memory, whether or not the endpoint has yet said
  no. Waiting for a refusal to say so would report the commonest case -- a
  grant met in full and already spent -- as a bare timeout. The connection
  itself is never destroyed for it, and reading, draining a backlog and
  acknowledging are untouched.
- A refusal is not sticky. A refused connection does not ask again -- it would
  only be refused again, and a busy endpoint would spend its time answering the
  same refusals -- so the endpoint keeps the request it could not meet and
  retries it, oldest first, on every path that returns memory. The retry stops
  at the first request still too large for the room available, so the queue is
  genuinely first-in-first-out and a small request cannot starve an older larger
  one. The bookkeeping lives in the ledger, keyed by connection, so it is
  bounded by the connection set itself: one connection waits on at most one
  request, a newer request replaces an older one in place, and a released
  connection takes its entry with it. Without the retry a steady connection that
  never sends another byte would stay refused forever.
- Releasing a connection returns its whole reservation, on whichever of the two
  release paths arrives first, including a connection actor that was killed
  rather than closed.

#### Sizing, and how tight the bound is

`EndpointMemory` should cover `Connections * (48 KiB + Buffer)` for the load an
endpoint expects to carry at once: the admission charge every connection pays,
plus the buffer a connection whose owner has stopped reading comes to hold. The
defaults deliberately do not satisfy that product -- 1024 connections at a
256 KiB `Buffer` would want 304 MiB against a 64 MiB default -- because refusing
to grow is the intended behaviour beyond the budget rather than a failure of it.
Connections past the budget keep the credit they were already advertised and
stop being offered more, and new connections are refused rather than admitted
into memory the endpoint does not have.

The bound is tight at admission and soft afterwards. The slack has exactly two
sources, and neither of them is the send side.

The first is advertised credit. It is never retracted, so a connection whose
grant has shrunk -- because what it holds has shrunk -- may still have
outstanding receive credit sized for the grant it held a moment ago. That is at
most one 256 KiB growth step per connection, and it closes as the peer spends
the credit and the application reads it.

The second is measurement lag. A connection walks its own footprint once per
16 KiB of traffic rather than once per datagram, so the hold it installed on its
receiver was computed from a footprint that may already be a quantum out of
date. The walk is deferred at most to the actor's next turn, so the lag is
bounded by one turn's arrivals -- itself bounded by the listener's 256 KiB
per-connection delivery window -- and the quantum is the resolution the ledger
counts in and rounds up from anyway.

The send side contributes nothing to either. An application's write is admitted
only as far as the grant reaches past what the connection holds, on every write
rather than only once a refusal has landed, and what it holds is counted
conservatively: the last measured footprint plus every byte that could have
grown it since. That is what closes the `Buffer`-sized hole a
charge-after-the-fact send side would leave, and it is what stops one turn that
advances several parked streams from admitting a whole grant to each of them.

Two costs of this design are bounded in principle and unmeasured in practice,
and the soak is where they get numbers. The footprint walk is
O(streams + in-flight packets) and runs once per 16 KiB of traffic, so a
connection with many streams pays for all of them on every quantum it moves.
And the CONNECTION_REFUSED reply is emitted per inbound Initial packet that the
budget cannot admit -- key derivation and one protected packet each time, with
no rate limit of its own beyond the `Handshakes` ceiling -- so a flood of
Initials at a full endpoint is answered one for one.

One interaction with a neighbouring bound decides what a flood meets first, and
it is worth stating plainly. A stream's receive credit is advertised against
its reassembly buffer, and the window rule can advertise more of it than that
buffer holds: the advertised limit rises by a whole window for every half
window consumed, and what caps it is `maximum_receive_stream_data` rather than
`Buffer`. A peer that fills the window it was given then exceeds the buffer,
and the connection is torn down for a frame that was inside every limit it had
been told about. That predates the endpoint budget and is not addressed here.
What follows for sizing is that `Buffer` wants to be at least as wide as the
growth step a connection rests on, so that the endpoint budget rather than one
stream's reassembly bound is what ends a flood; the public memory suite sizes
it at twice the growth step for exactly that reason.

#### What the suites pin

The pure suite pins the ledger arithmetic and the grant state machine:
rounding, whole refusal, rejected over-release, idempotent release, the
convergence property, the defaults agreeing with each other at 1024
connections, the request-before-growth rule, and the sequence-number race where
a stale answer is ignored and the newest one lands. The state-model suite pins
the two credit rules directly: under a refusal a peer stream inside the
advertised limits is still served and the advertised stream limit does not
grow until the refusal lifts; that lifting a refusal restates the per-stream
credit it withheld and nothing else, never a send-only stream and never a
stream whose update was never held back; that lifting a refusal re-advertises
the connection-level limit with no traffic and no read of the connection's own,
which is what stops a peer squeezed to zero credit from stalling to its idle
timeout; and that under the three-quantum admission grant -- the charge a
shipped listener actually applies, rather than a figure chosen for the test --
the connection holds and advertises no more than the grant however much the
peer sends.

The listener-side retry is pinned in the pure suite rather than over UDP,
because that is where it can be pinned deterministically: requests met oldest
first, a retry that stops at a head it cannot meet whole rather than stepping
over it, a connection refused twice keeping its place in the queue, and a
released connection owed nothing. Removing the retry fails those four tests
outright.

The public suite pins the observable consequences over real UDP, with a budget
sized from the endpoint's own arithmetic -- every connection a test admits but
the last resting on a growth step, and the last one left with an admission
charge and no room to grow. It pins that a further connection is refused with a
typed failure rather than a handshake that merely times out; that closing or
crashing one connection readmits the next; that a peer which stops reading gets
backpressure, where the parked send ends as `Overload(EndpointMemory)` while
the connection itself stays live, the data already inside its window still
arrives whole, and an unrelated connection completes an exchange untouched;
that a connection whose grant was met in full, with nothing refused it, still
admits a write only as far as that grant reaches, so a write far wider than the
grant and far inside the per-stream `Buffer` ceiling parks and ends as
`Overload(EndpointMemory)` rather than filling the ceiling; that a Datagram
offered to a refused connection is dropped and counted while that connection
stays live; and that a refused connection resumes once its neighbours release
the memory it was waiting on. That last test drives the subject connection
while it waits, so what it demonstrates is the recovery, not that the recovery
needed no traffic; the no-traffic property is what the pure suite pins.

One send-side test reads past the outcome of a single write, because a single
parked write cannot distinguish a grant that bounded it from a refusal that
landed while it waited. Sixteen streams are offered a quarter of the per-stream
`Buffer` ceiling each at once, and what the connection's send buffers hold is
sampled against its grant throughout. A send side that admitted a write against
the stream it is on rather than against the connection's one grant takes
sixteen ceilings' worth in the single turn that advances every parked stream;
the shipped one never takes more than the grant that funds it. The sample is a
seam on the connection actor rather than a public counter, for the same reason:
every outward consequence of overrunning the grant is a consequence the
endpoint's own refusal produces too.

Known peer-controlled lengths, counts, tables, stream windows, queues,
Capsules, Datagrams, packet histories, retained keys, terminal entries,
timeouts, and amplification credit have explicit bounds, including a connection
actor's own mailbox of forwarded inbound batches, which the listener's
per-connection delivery window bounds. All role-applicable per-connection public
limits now reach those allocations, and the aggregate `EndpointMemory` budget is
enforced listener-wide as described above -- on the server role only; the client
role does not read it yet.
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
