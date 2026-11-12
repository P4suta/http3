# Certificate service identity

This document is the public certificate service-identity profile for the secure clients in `http`, `http3`, and `quic_core`.
It applies to HTTP/1.1,
HTTP/2, and HTTP/3.
Certificate-path validation and service-identity matching are mandatory and have no public bypass.

## Mandatory identifier profile

DNS-ID and IP-ID are mandatory to implement for every secure client path.
When the authenticated origin contains a DNS name, the client constructs one DNS-ID reference identifier.
When it contains an IP literal, the client constructs one IP-ID reference identifier and requires an exact `iPAddress` subjectAltName match.
A Common Name or any other subject RDN is never a reference identifier.

SRV-ID and URI-ID are unsupported.
The clients do not perform DNS SRV service discovery, construct an SRV-ID, construct a URI-ID, or accept a URI scheme or service name from a certificate as an identity.
ALPN selects an application protocol after authentication; it does not create another certificate identifier type.

The server APIs consume caller-supplied credentials and do not issue certificates or certificate signing requests.
A deployment must provision a subjectAltName DNS-ID or IP-ID for every origin that clients are expected to authenticate.
One certificate can be shared by HTTP/1.1, HTTP/2, and HTTP/3 when its subjectAltName entries identify each authenticated origin; sharing a certificate does not permit sharing a connection or ticket across origins.

## Origin and connection routing

The authenticated origin and the connect target have different jobs:

- The origin scheme, host, and effective port define the service identity.
  A DNS origin host supplies the DNS-ID reference and TLS SNI.
  The same origin supplies HTTP authority.
  An IP-literal origin supplies the IP-ID reference.
- DNS answers, a caller-supplied exact address, an HTTPS record, and an Alt-Svc port are connect-target routing inputs.
  They may change the socket's peer address or port, but never replace the origin reference identifier,
  TLS SNI, or HTTP authority.
- A connection pool key includes the authenticated origin.
  Stateful unified client policy additionally includes its network isolation key.
  A connection is reusable only inside those boundaries.
- A resumption ticket remains bound to the original authenticated host and port.
  Dialing an alternate address or port does not retarget a ticket, and a ticket from another origin is rejected.

For the direct `quic_core` client, the hostname and port given to its constructor are the authenticated origin boundary.
`with_connect_address` and `with_connect_port` only change the UDP destination.
For the direct `http3` and unified `http` clients, the request origin remains the authenticated boundary when discovery selects a different endpoint.

## DNS wildcards

A wildcard is permitted only in a presented certificate DNS-ID.
A reference identifier, IP-ID, Common Name, or other subject RDN is never interpreted as a wildcard.
The required matching contract accepts only a whole left-most label and only for one label.
It does not match a bare suffix or two or more labels.
Partial-label, non-left-most, multiple, and malformed wildcard forms must be ignored.

Wildcard matching is currently delegated to the two OTP certificate verifier paths.
Release qualification still requires the adversarial TCP and QUIC fixture matrix that proves all of the boundaries above.
Until that gate is recorded for the current source, wildcard certificates are outside the release-qualified subset even though this is the required public behavior.

## Internationalized DNS names

The current secure-client boundary accepts an internationalized DNS reference only in canonical ASCII A-label form.
A Unicode U-label must be converted to its canonical A-label before constructing a request or client configuration.
Supplying a U-label directly is not a supported way to authenticate the service across all three HTTP versions.

A-label comparison is required to use case-insensitive ASCII while preserving label order.
The same canonical A-label must reach DNS, TLS SNI, certificate verification, HTTP authority, the connection pool key, and resumption-ticket binding.
Repository URLPattern, cookie, or HSTS host canonicalization is not a substitute for this caller-visible TLS boundary.
Built-in U-label-to-A-label conversion before every secure-client operation remains an open release gate.

## Qualification status

The profile statements above are source-level contracts.
Provider behavior that depends on live certificates remains unqualified until the current-source TCP and QUIC matrices run under every required OTP and operating-system row.
The RFC 9525 candidate audit records those remaining rows as `Open` and is explicitly not release evidence.
