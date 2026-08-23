# gleam_quic

`gleam_quic` is the repository's native QUIC transport core for the Erlang
target. It is an unpublished work in progress and is not yet suitable for
applications. Its current internal TLS layer completes an authenticated
client/server TLS 1.3 state-model handshake through QUIC Handshake and 1-RTT
traffic-key installation; it is not yet connected to a network transport.
The transport foundation also includes bounded recovery, NewReno, flow
control, path validation, anti-amplification, PMTU, key update, and ordered-byte
reassembly models.

Protocol parsing, state machines, recovery, congestion control, TLS 1.3
coordination, and packet protection are implemented or will be implemented in
Gleam. Small Erlang FFI modules may expose only runtime primitives such as UDP,
monotonic time, secure randomness, cryptographic operations, and X.509 path
validation.

The public completion requirements are defined in
[the repository v1 gate](../../docs/V1.md). The external `quic` package remains
only as the temporary HTTP/3 bootstrap backend while this core is built and
verified; it is not part of the intended v1 runtime.

Run this package's checks from the repository root:

```sh
mise run core-check
```
