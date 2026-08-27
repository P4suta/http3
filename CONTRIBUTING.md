# Contributing

Thank you for helping build `http3`. The project is pre-alpha, so changes to
the eventual public API should start from the constraints in
[Architecture](docs/ARCHITECTURE.md) and the ordered work in
[Roadmap](docs/ROADMAP.md). The
[conformance matrix](docs/CONFORMANCE.md) is the source of truth for release
findings. All behavior changes follow the workflow and gates in
[Testing](docs/TESTING.md).

## Development setup

Install [`mise`](https://mise.jdx.dev/), then install the pinned tools and run
the full local verification suite:

```sh
mise install
mise run check
```

The package supports Erlang/OTP 28 and 29. Local development uses OTP 29;
the CI definition covers the complete supported range.

## Making a change

1. Keep the public API free of backend PIDs, atoms, maps, references, and raw
   message formats.
2. Put backend conversions in `src/http3/internal/` and keep Erlang FFI modules
   small.
3. Start every behavior change with a failing test, and add a reproducing test
   before fixing a bug.
4. Update public documentation and `CHANGELOG.md` when behavior changes.
5. Review both canonical API snapshot diffs when public signatures change.
6. Never add an import of a package-private `gleam_quic` module; the
   `api/boundary.allow` allowlist only shrinks, so edit it by deleting lines
   and never by running `boundary --write-allowlist`.
7. Run `mise run check` before proposing the change.

For an intentional public API change, inspect the compiler interface and then
run `mise run api-update`. Commit both resulting snapshot changes with the API
change; never refresh snapshots merely to silence an unexpected difference.

Do not add placeholder exports. A client or server operation should be public
only after it performs the documented protocol work.

## Security changes

Do not weaken certificate-chain or hostname verification defaults. APIs that
disable verification belong in an explicitly named, test-only surface and
must not be reachable through the normal client configuration.

Report vulnerabilities according to [SECURITY.md](SECURITY.md), not in a
public change proposal.

## Licence

Contributions are accepted under the repository's dual MIT OR Apache-2.0
licence. By submitting a contribution, you agree that it may be distributed
under either licence at the recipient's option.
