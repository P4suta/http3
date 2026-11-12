# PR #11 public contract changes

The packages remain at `0.1.0`.
`client.fetch`, `client.exchange`,
`Response(Body)`, and protocol-selection result types keep their interfaces.
Compiler-generated snapshots in `api/` record the public changes below.

## Streaming and ownership

HTTP/1.1 preserves trailers for byte bodies and pull sources, including sources with a declared length of zero.
A pull source can provide trailers only at EOF,
so its declared body length does not select Content-Length framing: the sender uses chunked transfer encoding without reading ahead.
Length validation still checks the declared number of body bytes.
Applications must not supply their own Content-Length or Transfer-Encoding headers on the HTTP/1.1 path.

An authenticated HTTPS connection that negotiated HTTP/1.1 is now checked out for subsequent requests before another TCP connection is reserved.
A pool with one connection can therefore perform consecutive HTTPS HTTP/1.1 exchanges.
The checked-out connection still participates in selection before request bytes or a non-replayable body are consumed.

HTTP/1.1 TLS listeners also accept clients that omit ALPN, with the same certificate and TLS policy.
An explicit incompatible ALPN remains a handshake failure.
A total deadline that expires while handing an authenticated socket to the HTTP/1.1 adapter is reported as `Timeout(Total)`.

An HTTP/3 exchange returns at the final response headers.
Read its Body in chunks, consume trailers at EOF, or cancel it explicitly.
Upload production and response reception progress independently under the exchange deadline.
Early responses stop the unused upload source and release it once.
HTTP/1.1 and HTTP/2 use the same supervised upload lifetime.
Call `body.replay` to obtain another cursor before reusing a replayable source in a separate exchange; a non-replayable source is consumed only by the selected connection.

Protocol racing authenticates connections before sending a request.
Only the winner receives request bytes.
A single available connection grant causes sequential candidate attempts.
HTTP/3 connections are pooled by origin and network-isolation key.
Closing the client joins its owned upload workers and disposes their sources before releasing their grants.

Server drain reports an interrupted accepted HTTP/3 response as a failure.
The unified adapter maps a forced native drain to `Timeout(Operation)`.
Completed responses and already-drained listeners retain successful results.

HTTP/3 listeners now reject custom URI schemes until their authority semantics are explicit.
A listener that previously accepted `web+example` can preserve the former optional-authority behavior while making the policy reviewable:

```gleam
import http3/server as http3_server

pub fn configure_custom_scheme(
  configuration: http3_server.Configuration,
) -> Result(http3_server.Configuration, http3_server.ConfigurationError) {
  configuration
  |> http3_server.with_custom_scheme_authority_policy(
    "web+example",
    http3_server.OptionalAuthority,
  )
}
```

Choose `MandatoryAuthority` or `NoAuthority` when the scheme definition requires that stronger rule.
Scheme names are ASCII-normalized, limited to 64 bytes and 32 entries, and cannot replace the mandatory `http` or `https` rules.
Under `NoAuthority`, both `:authority` and `Host` are rejected and the accepted request's `server.authority` value is the empty string.

The public deterministic OHTTP client and fixed response-nonce entry point were removed.
Use `ohttp.client`; every request now obtains fresh operating-system CSPRNG material and no production API accepts a caller-selected HPKE ephemeral key or response nonce.
Published vectors remain fixed test fixtures.
Gateway and client response contexts are one-shot across all copies and callers;
subsequent sealing or opening returns `ohttp.ContextReuseDetected`.

The byte-oriented OHTTP APIs now decode their binary HTTP input and enforce the same message, target-authority, and `Expect: 100-continue` policy as the typed APIs.
Callers that previously used them as unchecked encryption primitives must pass one complete request or response accepted by `http/bhttp`.

Gateway integrations should use `ohttp.admit_request`.
An authenticated target request yields `ForwardRequest`; malformed binary HTTP, a `100-continue` expectation, and a denied target yield a canonical encrypted 400, 417, or 403 `ProtectedResponse`.
Lower-level integrations can use `open_request_detailed` or `open_request_bytes_detailed`, then pass the retained one-shot context to `seal_protected_failure`.
The older `open_request` functions retain their result shape, but map post-decryption policy failures back to their legacy `Error` values.

`ReplayStore` is now a shared finite owner process, so every copy observes the same pending and accepted `enc` identities.
Pending authentication consumes capacity and is reclaimed on failure, expiry, or caller termination.
Accepted identities do not expire in the compatibility constructor; applications with a Date-bound or otherwise explicit replay window can use `replay_store_with_retention`.
A store never silently restarts empty; use `close_replay_store` during owner shutdown, and treat `ReplayStoreUnavailable` as a fail-closed service failure.

## Diagnostic consumers

`Observation` now has three fields: `sequence`, `monotonic_milliseconds`, and `event`.
Replace positional two-field matches with named-field access or named-field patterns.
New Event variants distinguish `HandlerFinished`,
`ResponseBodyReadFinished`, and `RequestReleased`.
`RequestFinished` describes the successful final protocol write; handler return and source EOF do not establish that outcome.
`RequestReleased.cleanup` separately reports source disposal or worker cleanup failure.

`RequestRefused` now contains `request_id`, `protocol`, and `resource`.
Match these named fields instead of the former resource-only value.
The identifier is allocated before resource admission, remains payload-free, and is distinct from every admitted request identifier.
The protocol is the protocol from the validated request context; `resource` retains the common typed refusal class.
`RequestStarted` now marks entry into the common typed server boundary before resource admission.
A refused request therefore emits `RequestStarted`, then `RequestRefused`, then `RequestReleased` after input disposal.
Cancellation,
drain, or executor loss in the acquire-to-worker interval emits `RequestStarted`, `RequestFailed`, and `RequestReleased` with the same ID.
No handler or protocol adapter needs a separate event type for this interval.

Attach an existing finite Reporter with `client.with_diagnostics`.
Client events use `ClientObserved` with an opaque request identifier and typed `ClientStage`.
An attempt's wire result, its eventual resource release, and the logical exchange result are separate stages.
DNS/connection/TLS records retain native sequence and elapsed time; `ConnectTraceFinished` exposes partial or dropped observations.
Cached responses and tunnel operations do not currently produce these network-exchange events.

`ClientPhase.ProtocolSelection` now contains the selected `http/context.Protocol`.
Selection starts and finishes only after a connection wins, before that winner consumes request bytes; TLS connections have completed authentication at this point.
Losing protocol contenders do not emit selection.
HTTP/1.1, HTTP/2, and HTTP/3 emit paired phase events for resource admission, request transmission, response reception, and resource release.
Upload and response phases may overlap because exchanges are duplex.
Cancellation is a separate paired phase, and a body-transfer failure remains a failed exchange even if response headers were already received.
Duplicate and out-of-order phase transitions are suppressed.
Each phase advances at most once from unseen to started to finished;
a finish from unseen and every repeated transition are counted without retaining event payloads.
The same finite per-attempt state machine also counts late terminal observations.

Reporter callbacks can complete in a different order from admission.
Sort observations by `sequence`; the monotonic timestamp is not wall-clock time.
The application owns the Reporter and stops it after its clients and servers.
Reporter saturation or a stopped exporter must not delay network work.

<!-- example: package=http id=diagnostic_migration -->
```gleam
import gleam/option.{type Option, None, Some}
import http/context
import http/diagnostics
import http/error

pub fn refused_resource(
  event: diagnostics.Event,
) -> Option(#(diagnostics.RequestId, context.Protocol, error.ResourceKind)) {
  case event {
    diagnostics.RequestRefused(request_id:, protocol:, resource:) ->
      Some(#(request_id, protocol, resource))
    _ -> None
  }
}

pub fn selected_protocol(
  stage: diagnostics.ClientStage,
) -> Option(context.Protocol) {
  case stage {
    diagnostics.PhaseStarted(_, diagnostics.ProtocolSelection(protocol))
    | diagnostics.PhaseFinished(
      _,
      diagnostics.ProtocolSelection(protocol),
      _,
    ) -> Some(protocol)
    _ -> None
  }
}

pub fn server_wire_result(
  observation: diagnostics.Observation,
) -> Option(Result(Nil, error.Error)) {
  case observation.event {
    diagnostics.RequestFinished(..) -> Some(Ok(Nil))
    diagnostics.RequestFailed(failure:, ..) -> Some(Error(failure))
    _ -> None
  }
}

pub fn main() -> Nil {
  let observation =
    diagnostics.Observation(
      sequence: 1,
      monotonic_milliseconds: 0,
      event: diagnostics.ServerDraining,
    )
  let assert None = server_wire_result(observation)
  let assert Some(context.Http3) =
    selected_protocol(
      diagnostics.PhaseStarted(
        1,
        diagnostics.ProtocolSelection(context.Http3),
      ),
    )
  Nil
}
```

## Endpoint, trust, and transport observations

`http3/client.connect_to` and `with_connect_address` separate the UDP destination from the authenticated origin.
The request authority, TLS SNI,
and certificate verification name remain the origin.
A connection trace is explicitly enabled through `new_connect_trace` and `with_connect_trace`, and read using `connect_snapshot`; it contains no endpoint or TLS material.

For applications with explicit trust roots, `quic_core/client` adds `new_with_ca_certificates` and `new_with_ca_certificates_der`.
These validate the supplied PEM or DER roots without first requiring an operating-system trust store.
The default constructor continues to require system trust.
HTTP/3's existing CA configuration uses the explicit-root path internally.

QUIC client and server connections expose `local_connection_id_stats`; the listener exposes `connection_id_stats`.
These bounded counts distinguish issued identifiers, active identifiers, retirement history, and listener routes without revealing identifier bytes.

RSA server credentials now require a public modulus of at least 2048 bits.
`quic_core/server.new` and `quic_core/server.with_certificate` return `server.InsufficientKeyStrength` for a decoded certificate below that RFC 9325 boundary.
Treat this as a credential replacement action; malformed certificate PEM remains `server.InvalidCertificate`, and a key that does not match the leaf remains `server.IncompatiblePrivateKey`.

`SystemUdpSocketSnapshot` adds `not_ect_configuration`.
Update positional matches or use named fields.
The existing `not_ect` policy flag, the socket option observation, and an independent packet's ECN value describe different facts.
`SystemUdpNotEctDefaultUnobserved` and `SystemUdpNotEctConfiguredUnobserved` do not prove a wire value.

## Response completion and UDP idle control

`http3/server.await_response_completion(request)` waits for acknowledgement of the response FIN or a send-direction failure without consuming request-body or Datagram events.
One waiter per request uses the configured operation deadline.
The unified server uses it to cancel a blocked response producer when the peer stops receiving, including after the request body has finished.

`quic_core/server.await_send_completion(stream, within_milliseconds)` reports `SendAcknowledged`, `SendStopped(code)`, or `SendReset(code)`.
Acknowledgement confirms transport delivery, not application processing.
A concurrent waiter is rejected; caller exit frees its registration.
Only the most recent `min(Queue, 32)` terminal outcomes are retained.
Retired information returns `StreamFinished` rather than assuming success.
Update exhaustive matches for the new public result type.

Each native QUIC connection now reserves at least 64 KiB before it is admitted.
This includes the existing working set and receive credit plus a separate 4 KiB allowance for terminal history, rounded to the accounting quantum.
Configurations with less than 64 KiB of endpoint memory cannot admit a connection.
The default 64 MiB budget still funds all 1,024 default connection reservations.
An active completion waiter separately reserves 8 KiB before creating its registration and monitor, and releases it on completion or caller exit.
Applications using smaller explicit budgets must allow for both costs.

MASQUE idle control now has an explicit `UdpIdleUnavailable` snapshot state and `IdleControlUnavailable` termination reason.
Invalid clocks and exhausted contention budgets close the session through its ordinary cleanup path.
They do not become ordinary activity, successful stop, or idle expiry.
Directional counters are sampled independently; their saturating sum defines the sampled total, rather than claiming an atomic multi-counter transaction.

An enabled idle guard's `maximum_pending_commands` is now two: one activity wake and one stop notification.
The stop notification is delivered at most once, independently of an abandoned activity wake.
Closing waits for the idle owner to exit; `UdpProxyIdleOwnerJoinTimeout` reports an unconfirmed join and allows a later close to retry.
Applications matching these public enums must handle the new variants.

## Secure-channel content compression

Code that compresses content for TLS-protected HTTP should call `compression.encode_for_secure_channel` and classify every input with `ContentProvenance`.
The call refuses `UnknownProvenance` and `MixedConfidentialAndAttackerControlled` before it examines limits,
dictionaries, or codec state.
`Identity` remains valid for every provenance because it does not compress.

`compression.encode` remains the low-level codec primitive for storage,
fixtures, and protocols that enforce equivalent policy elsewhere.
It does not claim that its input is safe to compress on a secure channel.
Each safe entry point call creates an independent codec context, so confidential and attacker-controlled inputs must be encoded in separate calls when the protocol can carry separate representations.

<!-- example: package=http id=secure_channel_compression_migration -->
```gleam
import gleam/option.{None}
import http/compression

pub fn encode_public_response(body: BitArray) {
  compression.encode_for_secure_channel(
    compression.Gzip,
    body,
    None,
    compression.defaults(),
    compression.PublicContent,
  )
}

pub fn main() -> Nil {
  Nil
}
```

## Dictionary retention budgets

`http/compression.Store` now charges each retained dictionary for its content,
both isolation-key strings, origin, pattern, identifier, and destinations.
The charge includes 96 bytes per destination and a fixed 1,024-byte allowance for record storage, binary headers, the digest, and bounded clock values.
Small explicit budgets may therefore admit fewer dictionaries or return `LimitExceeded` where earlier versions undercounted metadata.

Admission reserves this charge and evicts the oldest entries before copying the incoming content and strings.
Stored slices own their backing allocation,
so a short slice cannot retain a much larger caller-owned binary.
Stored `fetched_at`, `fresh_until`, and selection's `now` must fit signed 64-bit integers and use the same caller-supplied clock domain and units.
Out-of-range values return `InvalidDictionary`, including selection from an empty store.
A record becomes eligible at `fetched_at`; a later record cannot displace an already eligible record before its own fetch time.
The freshness deadline remains exclusive.
These helpers do not derive HTTP cache age or readability from response headers; callers remain responsible for those admission inputs.

The byte budget bounds dictionary records retained by the returned immutable store.
Applications control the lifetime of older store values and selected dictionaries they keep.
The constant empty-store structure and caller-owned inputs are outside that record budget.

## Dictionary destination support and clearing

The existing `select_dictionary` function still accepts a Fetch destination string, including the actual empty destination.
Call `select_dictionary_for_request` with `DestinationsUnsupported` when an application does not implement Fetch destinations.
In that mode, `match-dest` affects neither eligibility nor preference between matching dictionaries.
`SupportedDestination("")` preserves the empty destination's matching rules.

`clear_dictionaries` returns a new store with the same capacity limits.
Select `PartitionDictionaries(key)` to remove every origin in one isolation partition,
`ProfileDictionaries(profile)` to remove every partition in that profile, or `AllDictionaries` to clear the store.
Replace the application's authoritative store with the returned value.
Previously retained immutable stores and selected dictionaries remain usable; applications must release those references too.
Cookie deletion and private-profile lifecycle integration remain the caller's responsibility.

<!-- example: package=http id=dictionary_capability_migration -->
```gleam
import http/compression

pub fn select_without_fetch_destinations(
  store: compression.Store,
  key: compression.IsolationKey,
  now: Int,
) -> Result(compression.Dictionary, compression.Error) {
  compression.select_dictionary_for_request(
    store,
    key,
    origin: "https://example.com",
    path: "/assets/main.css",
    destination: compression.DestinationsUnsupported,
    now:,
  )
}

pub fn clear_profile(
  store: compression.Store,
  profile: String,
) -> Result(compression.Store, compression.Error) {
  compression.clear_dictionaries(
    store,
    scope: compression.ProfileDictionaries(profile),
  )
}

pub fn main() -> Nil {
  Nil
}
```

## Dictionary request URLs

Use `insert_dictionary_from_url` when registering a response fetched from a complete HTTPS URL.
Insertion validates the match pattern with that dictionary URL as its base and retains its canonical origin.
Use `select_dictionary_for_url` with the complete outgoing URL so query strings and URL canonicalization participate in matching.
Selection uses the outgoing URL as the pattern base, as specified by [RFC 9842 Section 2.2.2](https://www.rfc-editor.org/rfc/rfc9842.html#section-2.2.2).
The full fetched URL is not retained in a dictionary record.

Existing origin/path functions remain available.
`insert_dictionary` uses the origin's root URL as its validation base; `select_dictionary_for_request` combines its validated origin and path.
Inputs containing user information or a path in the origin argument now return `InvalidDictionary`.
Full URLPattern conformance remains under verification; current bounds and the pinned hostname profile are documented in [URL host canonicalization](URL_HOST_CANONICALIZATION.md).

<!-- example: package=http id=dictionary_url_migration -->
```gleam
import gleam/result
import http/compression

pub fn dictionary_for_stylesheet() -> Result(
  compression.Dictionary,
  compression.Error,
) {
  use store <- result.try(compression.store(
    maximum_entries: 8,
    maximum_bytes: 65_536,
  ))
  let key = compression.IsolationKey("https://example.com", "default")
  use directive <- result.try(compression.parse_use_as_dictionary(
    "match=\"/assets/*.css\", match-dest=(\"style\")",
  ))
  use store <- result.try(compression.insert_dictionary_from_url(
    store:,
    isolation_key: key,
    dictionary_url: "https://example.com/dictionaries/styles.css",
    directive:,
    content: <<"body { color: black; }">>,
    fresh_until: 100,
    fetched_at: 1,
  ))
  compression.select_dictionary_for_url(
    store,
    key,
    request_url: "https://EXAMPLE.com:443/assets/main.css?version=2",
    destination: compression.SupportedDestination("style"),
    now: 2,
  )
}

pub fn main() -> Nil {
  case dictionary_for_stylesheet() {
    Ok(_) -> Nil
    Error(_) -> panic as "dictionary URL example failed"
  }
}
```
