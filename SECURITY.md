# Security Policy

## Project status

`http3` is pre-alpha, unpublished, and not recommended for production use.
The current surface provides bounded and streaming HTTP/3 clients and server,
plus typed advanced transport capabilities.

The version in `gleam.toml` is tool metadata and does not indicate that a
release exists. Security support follows the current capability surface:

| Surface | Supported |
| --- | --- |
| Current client and server | Security fixes |
| Earlier local states | Not supported |

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, or
pull request. While this repository is local and unpublished, contact the
maintainers privately through the same channel from which you received the
source. Once a public repository exists, use its private vulnerability
reporting feature.

Include the affected version, Erlang/OTP version, impact, reproduction steps,
and any proposed mitigation. Avoid including secrets or data belonging to
other people. The maintainers will acknowledge the report, assess scope, and
coordinate a fix and disclosure timeline through the private reporting
channel.

## Security invariants

- Client certificate-chain and hostname verification is secure by default.
- A custom CA set changes trust anchors without disabling hostname or chain
  verification.
- The normal client surface has no certificate or hostname verification
  bypass. Any future bypass must be explicitly named and test-only.
- Backend process identifiers, atoms, maps, references, and messages do not
  cross the public API boundary.
- Untrusted protocol inputs are bounded and validated before allocation or
  dispatch.
- Client streams and server operations have fixed timeouts, explicit request
  and response body limits, bounded unconsumed stream data, and deterministic
  connection and listener cleanup.
- Server certificate and private-key material is validated before listener
  startup, and listener names come from a fixed atom pool rather than input.
- Session tickets expose no fields or serialization operation, are bound to the
  verified host and port, and restrict 0-RTT requests to GET, HEAD, and OPTIONS.
- HTTP Datagram negotiation is explicit, payload and queue sizes are bounded,
  and concurrent receivers are rejected.
- qlog is disabled by default and requires an explicit directory because trace
  files can contain connection metadata and application protocol details.
