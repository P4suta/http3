# Loopback TLS fixtures

These static Ed25519 certificates and the matching server key exist only for
the real-UDP loopback tests. The key is intentionally public test data, is not
a secret, and must never be used outside this test suite.

The private CA is named `http3 loopback test CA`. The server certificate has
the single DNS subject alternative name `localhost`; this lets the suite test
both a matching hostname and a deliberate `127.0.0.1` mismatch. The fixtures
are valid from 2026-08-23 through 2036-08-20 so pinned builds do not depend on
the machine clock being close to the generation date.
