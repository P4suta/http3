# Loopback TLS fixtures

These static Ed25519 certificates and the matching server key exist only for
the real-UDP loopback tests. The key is intentionally public test data, is not
a secret, and must never be used outside this test suite.

The private CA is named `http3 loopback test CA`. The server certificate has
the DNS subject alternative name `localhost` and IP subject alternative name
`::1`; this lets the suite exercise IPv4 by name, IPv6 by literal, and a
deliberate `127.0.0.1` mismatch. The fixtures are valid from 2026-08-24 through
2036-08-21 so pinned builds do not depend on the machine clock being close to
the generation date.

`default-server.pem` and `default-server-key.pem` are a self-signed Ed25519
fallback credential valid only for `default.invalid`. The SNI selection test
uses it as the listener default and succeeds only when the separately
configured `localhost` credential is selected.

`client.pem` and `client-key.pem` are a self-signed Ed25519 client-only
credential with `clientAuth` extended key usage. The certificate is installed
as its own explicit test trust anchor so mTLS tests do not need to retain a CA
private key. The server-only fixture is also used to prove that the client
certificate purpose check fails closed.
