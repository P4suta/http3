# Security Policy

## Project status

`http3` is unpublished. The former v1 completion decision was reopened on
2026-08-25 because known architecture, TLS, conformance, performance,
security-tooling, and distribution findings remain. The code has not had an
independent third-party security audit and is not a supported production
release.

The version in `gleam.toml` is tool metadata and does not indicate that a tag
or release exists.

| Surface | Support status |
| --- | --- |
| Current source-tree state | Security fixes are accepted |
| Earlier local states or snapshots | Not supported |
| Published releases | None |

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, or
pull request. While the repository is local and unpublished, contact the
maintainers privately through the same channel from which you received the
source. If a public repository is later created, use its private vulnerability
reporting feature.

Include the affected source revision, Erlang/OTP version, impact, reproduction
steps, and any proposed mitigation. Do not include credentials, session
tickets, traffic secrets, qlogs containing private data, or data belonging to
other people. Maintainers will acknowledge the report, assess its scope, and
coordinate remediation and disclosure through the private channel.

## Security invariants

- Client certificate-path and hostname or IP service-identity verification are
  enabled by default and cannot be disabled through the public API.
- A custom CA set replaces trust anchors without weakening path or identity
  verification.
- Server certificate and private-key material is validated before startup;
  multiple credentials are selected only through strict SNI matching.
- Raw processes, atoms, maps, references, sockets, trust-store terms, keys,
  traffic secrets, protocol messages, and mailbox formats do not cross the
  public API.
- Known packet, frame, extension, header, table, stream, queue, certificate,
  ticket, Capsule, and Datagram allocations have finite local or protocol
  bounds. The complete peer-controlled-state audit remains a release gate.
- Operations have fixed deadlines, explicit body and stream-buffer limits,
  bounded retained terminal state, and deterministic owner-driven cleanup.
- TLS authenticators, Retry integrity, PSK binders, Finished values, and
  stateless-reset tokens use authenticated or runtime constant-time checks.
- Compatible version negotiation is authenticated in the TLS transcript and
  rejects downgrade or inconsistent version information.
- Address validation and server anti-amplification apply before a path is
  trusted. Retry, address tokens, path challenges, connection IDs, migration,
  and stateless reset are authenticated and bounded.
- Session tickets are encrypted and opaque, bound to the verified origin,
  ALPN, cipher, QUIC version, and relevant transport parameters. 0-RTT is
  replay checked and limited to GET, HEAD, and OPTIONS until accepted.
- HTTP Datagrams require explicit negotiation and an Extended CONNECT request
  association. Payload, orphan, and receive queues are bounded.
- qlog is disabled by default, creates a unique trace per connection, and must
  be treated as sensitive application metadata.
- Erlang FFI is restricted to runtime UDP, time, crypto, X.509, and trace-file
  operations. QUIC, TLS, HTTP/3, and QPACK wire parsing and state machines are
  Gleam code.
- The production dependency graph contains no external QUIC implementation,
  NIF, or C library.

The current evidence, open findings, reviewed boundaries, and residual risks
are documented in the [conformance matrix](docs/CONFORMANCE.md) and
[pre-publication security review](docs/SECURITY_REVIEW.md).
