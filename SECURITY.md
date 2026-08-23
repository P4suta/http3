# Security Policy

## Project status

`http3` is pre-alpha, unpublished, and not recommended for production use.
The bootstrap release has no client or server API and therefore cannot yet
establish an HTTP/3 connection.

| Version | Supported |
| --- | --- |
| 0.1.x | Security fixes for the bootstrap surface |
| Earlier versions | Not supported |

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
- Verification bypasses are isolated to explicit test or development APIs.
- Backend process identifiers, atoms, maps, references, and messages do not
  cross the public API boundary.
- Untrusted protocol inputs are bounded and validated before allocation or
  dispatch.
