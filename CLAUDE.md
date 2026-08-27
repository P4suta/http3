# Agent guide

`http3` is a Gleam-native HTTP/3 library for the Erlang target: QUIC v1/v2,
TLS 1.3, HTTP/3, and QPACK are implemented in this repository, with no NIF,
port driver, or external protocol backend.

Read [Architecture](docs/ARCHITECTURE.md) before changing structure,
[Testing](docs/TESTING.md) before changing behavior, and
[Conformance](docs/CONFORMANCE.md) before making a readiness claim.

## Packages and their boundary

- `packages/gleam_quic` is the application-protocol-independent QUIC/TLS core.
  Run its own suite from that directory with `gleam test`.
- The repository root is the `http3` package: HTTP/3 sessions, QPACK, Capsules,
  and the public client and server.
- The root may import only these six public core modules: `gleam_quic`,
  `gleam_quic/client`, `gleam_quic/config`, `gleam_quic/diagnostics`,
  `gleam_quic/failure`, `gleam_quic/server`.
- `api/boundary.allow` lists pre-existing package-private imports. It only
  shrinks: delete a line once its import is gone, never add one and never
  regenerate it.
- Three gates enforce this: the `boundary` verb of
  `test/http3_public_api_audit.escript`, the `http3.boundary.*` Semgrep rule in
  `.semgrep.yml`, and the boundary mode of `test/http3_ffi_xref.escript`.

## Local gates

`mise run check` is the pull-request gate and must be green at every commit.
Run whole-gate commands outside any sandbox that makes `/tmp` read-only.

```sh
mise install
mise run check
mise run security
mise run fault
mise run property
mise run fuzz
mise run interop-setup
mise run interop
```

`mise run benchmark`, `mise run load`, and `mise run soak` are performance
gates: run them only when the task asks for them.

Phase 5 tasks (`coverage`, `coverage-full`, `model`, `hostile-peer`,
`credential-matrix`, `release-sim`, `release-candidate`, `requirements-audit`,
`qlog-validate`, `examples`) are declared stubs that exit non-zero until they
are implemented. They are not part of `check`.

## Development loop

Follow Red-Green-Refactor from [Testing](docs/TESTING.md):

1. Write the smallest failing test and confirm it fails for the expected
   reason. A bug fix starts with a reproducing regression that is kept.
2. Make the smallest change that turns it green without breaking other suites.
3. Refactor with every suite green.

Every wait has a fixed upper bound; a timeout is a test failure, not a
successful cancellation. Every fixture owns and cleans up its processes,
connections, listeners, sockets, files, and temporary directories. Tests use
OS-assigned loopback ports and never depend on execution order.

Documentation-only and configuration-only changes need no invented protocol
test, but they still run the complete local check.

## Prohibitions

- Never add a way to bypass certificate-chain or service-identity
  verification on the normal client path.
- Never add an unlimited queue, buffer, or deadline value. Every
  peer-controlled allocation is bounded.
- Never expose a PID, `Subject`, socket, reference, atom, raw map, mailbox
  message, key, or traffic secret through a public value.
- No new `let assert` in `src/` (tests may use it), no `panic`, no `todo`;
  `glinter` treats them as errors.
- No unused exports and no placeholder exports.
- No new Erlang FFI module beyond those listed in
  [Architecture](docs/ARCHITECTURE.md), and no new dependency unless the task
  says so.
- Stage explicit paths. Never run `git add -A` or `git add .`: the repository
  root can hold untracked local files.
- Never tag, publish, push, or change a package version.

## Public API changes

An intentional public signature change requires `mise run api-update` followed
by a reviewed diff of `api/http3.snapshot` and `api/gleam_quic.snapshot`.
Never hand-edit a snapshot and never refresh one to silence an unexpected
difference.

## Documents to keep honest

- [Conformance](docs/CONFORMANCE.md) is the source of truth for release
  findings; it is updated only with evidence.
- `CHANGELOG.md` records behavior changes under `Unreleased`.
- [`docs/evidence/`](docs/evidence/README.md) holds one dated file per gate
  run; performance rows stay in `benchmarks/results/`.
- [Roadmap](docs/ROADMAP.md) gives the dependency order of the open work.
