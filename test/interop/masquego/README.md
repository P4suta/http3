# Independent CONNECT-UDP interoperability

`mise run interop-masque` builds the pinned `masque-go` v0.4.0 implementation with Go 1.27.0 and the checked-in module lock, then runs both client and proxy roles against this project's public APIs.
The underlying QUIC implementation is quic-go v0.60.0, as required by this MASQUE release.

Each role establishes two live CONNECT-UDP streams on one authenticated HTTP/3 connection.
Eight distinct 64-byte datagrams per flow are interleaved and checked byte for byte.
A third request to an unapproved target must receive
502. Proxy admission starts with an exact loopback target and destination
policy.
TLS verifies the fixture CA and the `localhost` certificate name;
the actual UDP connection address is separate and fixed to IPv4 loopback.

The Go proxy supplies `Capsule-Protocol: ?1` before calling the public `Proxy.Proxy` API.
In this pinned dependency pair, obtaining `HTTPStream` flushes response headers, so application headers must already be set at that boundary.
The fixture does not modify upstream source or disable verification.
See the upstream [proxy API](https://github.com/quic-go/masque-go/blob/v0.4.0/proxy.go) and [response writer](https://github.com/quic-go/quic-go/blob/v0.60.0/http3/response_writer.go).

Go peers have a 25-second internal deadline and run under the existing process group supervisor.
Native counterparts use a fixed invocation, fresh-build BEAM, verified bytecode loading, bounded process heaps and output, and observed VM exit.
Readiness exposes only two validated ephemeral port numbers in the private orchestration log.
Other native output is discarded and prevents a successful result.
Arbitrary Erlang environment flags and crash dumps are disabled.

Native terminal records bind a fresh nonce to actual completed flows,
datagrams, policy rejections, and joined workers.
Failure records preserve only a bounded phase code.
The peer audit validates both the independent executable's completion and its native counterpart's receipt, including the same source identity and run identifier.
Unknown fields, incomplete work,
late completion, stale receipts and missing cleanup cannot qualify.

This fixture covers RFC 9298 CONNECT-UDP over HTTP/3.
It does not supply an independent CONNECT-IP implementation or certify the separate RFC 9484 gates.
