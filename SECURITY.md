# Security Policy

## Project status

`http3` is pre-alpha, unpublished, and not recommended for production use.
The current surface can make bounded one-shot HTTP/3 client requests. It has no
connection reuse, streaming API, or server API.

The version in `gleam.toml` is tool metadata and does not indicate that a
release exists. Security support follows the current capability surface:

| Surface | Supported |
| --- | --- |
| Current bounded client | Security fixes |
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
- Each request has a fixed total timeout, explicit request and response body
  limits, and deterministic connection cleanup.
