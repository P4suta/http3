# Agent guide

This repository develops three Erlang-target Gleam packages: the unified
`http` package at the root, `packages/http3`, and `packages/quic_core`.

Read [Architecture](docs/ARCHITECTURE.md) before structural work and
[Testing](docs/TESTING.md) before behavior changes. Package-specific HTTP/3
qualification evidence remains under `packages/http3/docs`.

## Packages and boundary

- `http` owns common Body, Error, client/server policy, HTTP/1.1, and HTTP/2.
- `http3` owns HTTP/3, QPACK, Capsules, request Datagrams, and WebSocket over
  HTTP/3.
- `quic_core` owns application-independent QUIC v1/v2 and TLS 1.3.
- Dependencies flow only `http -> http3 -> quic_core`.
- `http3` may ultimately import only `quic_core`, `quic_core/client`,
  `quic_core/config`, `quic_core/diagnostics`, `quic_core/failure`, and
  `quic_core/server`. `api/boundary.allow` is shrink-only until it is empty.
- `scripts/package_layout_audit.escript`,
  `scripts/public_api_audit.escript`, Semgrep, and compiled xref enforce the
  physical and semantic boundaries.

## TDD loop

All phases use Red-Green-Refactor:

1. add the smallest failing executable contract or regression;
2. verify that it fails for the intended reason;
3. make the smallest bounded implementation change;
4. run the affected package and every upstream package; and
5. refactor only while all those suites remain green.

Configuration and documentation changes use executable layout, API, archive,
lint, or example gates rather than invented protocol tests.

## Local gates

`mise run check` is the pull-request gate. Network suites need permission to
bind loopback sockets.

```sh
mise run http-check
mise run http3-check
mise run core-check
mise run api
mise run security
mise run property
mise run fuzz
```

Performance gates run only when requested. Release-candidate tasks remain
failing stubs until implemented; no stub may be presented as a passing gate.

## Prohibitions

- Never expose a certificate-verification bypass on a normal client path.
- Never add an unlimited queue, buffer, allocation, or deadline.
- Never expose a PID, `Subject`, socket, reference, atom, backend term, key,
  or traffic secret through public values.
- No new `let assert` in `src`, no `panic`, and no `todo`.
- No unused or placeholder exports.
- Do not add an Erlang FFI module without documenting and auditing its narrow
  runtime responsibility.
- Never tag, publish, push, create a hosted release, or change package versions
  without a separate explicit request.

## Public API changes

Intentional signatures require `mise run api-update`, review of all three
files under `api`, and then `mise run api`. Snapshots are compiler-derived and
must never be hand-edited to hide an unexpected difference.

## User-owned changes

The worktree may contain local performance evidence and hot-path changes.
Preserve unrelated modifications and stage only explicit paths.
