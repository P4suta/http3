# QUIC core TLS fixtures

The Ed25519 fixtures mirror the HTTP/3 loopback credentials. The additional
`rsa-pss-server`, `ecdsa-p256-server`, and `ecdsa-p384-server` pairs are
self-signed, localhost-only public test credentials. Each is valid for the
live CertificateVerify matrix and is installed as its own explicit trust
anchor. None of these private keys is secret or suitable for deployment.
