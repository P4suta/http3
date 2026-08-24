# Independent interoperability fixtures

These opt-in phase gates exercise the public library over real loopback UDP
against two independently implemented HTTP/3 stacks. Neither peer is a
production dependency. The hermetic unit and loopback suites remain in
`mise run check`; CI runs this independent gate in a separate Linux job.

## Pinned peers

| Peer | Native client evidence | Native server evidence |
| --- | --- | --- |
| aioquic 1.3.0 | v1 initial attempt to a v2-only peer, RFC 9368 compatible negotiation, certificate and hostname verification, HTTP Datagram, active migration, session ticket, actual 0-RTT request, and qlog | Bounded POST request and response with certificate and hostname verification and qlog |
| quic-go 0.61.0 | Streaming POST request and response over explicitly selected QUIC v1 and v2, with qlog | Bounded POST request and response from explicitly selected QUIC v1 and v2 clients, with qlog |

The aioquic peer records explicit observations for QUIC v2, the HTTP Datagram,
the post-migration request, and the request received before handshake
completion. Its flushed qlog must also contain a `0RTT` packet. Every native
and independent endpoint must create a non-empty qlog trace.

All client cases use the fixture CA and verify the `localhost` service
identity. No certificate-verification bypass is used.

## Running the gate

Install the pinned toolchain and create the hash-locked aioquic environment:

```sh
mise install
mise run interop-setup
```

Then run both peers, or one peer while diagnosing a failure:

```sh
mise run interop
mise run interop-aioquic
mise run interop-quicgo
```

The runner requires Bash and GNU `timeout`; the dedicated CI gate runs on
Ubuntu. Every peer operation has a fixed deadline. A trap terminates remaining
children and deletes its uniquely named temporary directory on success,
failure, or interruption. It never writes qlogs or Python bytecode into the
working tree.

Set `HTTP3_AIOQUIC_PYTHON` to use an already prepared Python interpreter. When
it is unset, the runner first looks for `build/interop-venv/bin/python` and
then falls back to `python3`.

## Updating a peer

The direct aioquic intent is pinned in `requirements.txt`; every transitive
version and distribution hash is retained in `requirements.lock`. Regenerate
the lock deliberately with:

```sh
mise run interop-lock
```

The quic-go module version is pinned in `quicgo/go.mod`, and `quicgo/go.sum`
retains module checksums. A peer update is complete only after both directions,
the applicable QUIC versions, the advanced observations, and
`mise run check` pass again. The last verified outcome is recorded in
[Testing][testing].

[testing]: ../../docs/TESTING.md
