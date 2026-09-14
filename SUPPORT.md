# Support policy

No supported release exists. The repository is unpublished, the v1 gate is
reopened, and current source is suitable only for development, testing, and
review.

The intended first-release platform range is:

- Erlang target only;
- Erlang/OTP 28 and 29; and
- Linux, macOS, and Windows after their hosted matrices pass.

The intended product scope includes HTTP/1.1, HTTP/2, HTTP/3, safe automatic
fallback, and the published MASQUE RFCs, but those surfaces are not supported
until their release gates pass. The JavaScript target, older OTP releases,
multipath QUIC, and draft protocol extensions are outside the initial scope.
WebTransport is deferred until it becomes an RFC.

Until publication, only the current source-tree revision receives fixes.
There are no compatibility, security-update, or end-of-life promises for
earlier snapshots. A future published support window must be documented before
the first tag and cannot be inferred from the `gleam.toml` metadata version.

Report suspected vulnerabilities through the private process in
[SECURITY.md](SECURITY.md). General changes should include a minimal
reproduction, expected behavior, OTP/Gleam versions, and a redacted trace or
fixed seed when relevant.
