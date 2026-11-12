# HTTP/3 WebSocket handshakes

The lower `http3/websocket` API uses Extended CONNECT as described by [RFC 9220 section 3](https://www.rfc-editor.org/rfc/rfc9220.html#section-3) and [RFC 8441 section 5](https://www.rfc-editor.org/rfc/rfc8441.html#section-5).
The ordinary native regressions in `packages/http3/test/websocket_handshake_tests.erl` connect real client and server endpoints with the retained test certificate.

## Negotiation

The client supplies one `sec-websocket-version: 13` field, replacing all caller-supplied occurrences.
The server requires one supported version.
For an unsupported version it sends an empty 400 response advertising version 13, awaits transport acknowledgment, and cancels the unfinished request direction.
A failed transmission is returned as `ServerFailure`; a completed refusal returns `UnsupportedVersion`.
The supported-version advertisement follows [RFC 6455 section 4.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.4).
Every other invalid integrated mapping that is known before acceptance sends an empty 400 response through the same acknowledged, bounded cleanup path.

The client accepts successful CONNECT responses in the 2xx range, following [RFC 9114 section 4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4).
Informational responses do not select a subprotocol.
Other final statuses return `UnexpectedStatus` and cancel the failed handshake.
The 204 regression uses an empty response; other tested successful statuses carry an independent WebSocket frame.

Offered subprotocols are unique, case-sensitive HTTP tokens.
Repeated request fields are combined as a list, including the HTTP list rule that ignores empty comma members.
An explicitly present offer must contain at least one token.
The response may omit selection or contain one field selecting exactly one offered token.
These rules follow [RFC 6455 sections 4.1 and 4.2.2](https://www.rfc-editor.org/rfc/rfc6455.html#section-4.1) and its [header registration](https://www.rfc-editor.org/rfc/rfc6455.html#section-11.3.4).
Parsing has a 65,536-byte allowance across subprotocol values, charging one additional byte per field.
This is an implementation resource limit; the configured HTTP field-section limit can reject a smaller value independently.

This API rejects `sec-websocket-key`, `sec-websocket-accept`, and extensions on both handshake sides.
Rejecting the HTTP/1 nonce fields is the existing API profile: RFC 8441 says those fields are not processed, rather than mandating their rejection.
Extension negotiation remains unsupported.

## Lifetime and evidence

Handshake tests project results to fixed categories and booleans.
They retain the compiler/runtime identity, nonce-bound EUnit results, finite child-process outcomes, actual task and connection-owner termination, and stream-registry counts.
Response acknowledgment provides an explicit barrier before a refusal cancels the peer's unfinished request direction.
A separate raw-client test checks cancellation after response FIN while its own request is still open.
Both endpoints also repeat four cancellations with a two-transaction limit,
then complete a normal request on the same connection.
The observations cover application handles, core handles, parser inputs, and HTTP/3 transactions.
When a peer RESET terminates the public HTTP handle, its remaining local send direction is cancelled before retirement; the pure receive-reset transition continues to preserve the other direction.
Cancellation and QPACK cleanup failures retain their typed error.

After a valid handshake, a framing, UTF-8, message-size, or protocol-state failure emits one payload-free typed qlog code.
The adapter sends the matching Close status (1002, 1007, or 1009) and FIN, waits for bounded send completion,
and then cancels its receive direction while preserving the original typed WebSocket failure.
The client and server tests observe the Close on the peer,
the send acknowledgement, the later cancellation, and zero retained stream,
worker, grant, event, and payload ownership.
A Queue=1 wire test covers STOP_SENDING followed by Close and FIN with and without a waiting consumer;
terminal control slots are finite and independent of the one DATA slot.

The RESET-only wire control removes only the peer's generated `STOP_SENDING`.
It sends four real `RESET_STREAM` frames, including an otherwise valid `0x123` application-code discriminator, and requires the adapter to answer every one with HTTP/3 `H3_REQUEST_CANCELLED` (`0x10c`).
A bounded mutant that performs only pure transaction/QPACK retirement must fail this control.
The same connection has a two-transaction limit and must complete a later request.

The tests cover peer reset, peer connection termination, connection reuse,
version-response transmission failure, and cleanup without a peer request FIN.
Compiler-generated mutations check subprotocol membership and uniqueness,
failed-handshake cancellation, and parsing limits.
Retained diagnostic results describe the exact source and runtime executed; they do not establish that all candidate qualification gates have passed.

After admission, client handshake reads use one absolute operation deadline across informational responses, including a clock check before each pull and after each successful delivery.
Stream admission and failed-handshake cancellation have their own configured budgets.
Injected-clock regressions hold the first read until the peer has sent all response headers, so expiration tests do not depend on scheduler timing or interrupt the fixture's writes.
