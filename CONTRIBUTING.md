# Contributing

Thank you for helping build `http3`. The project is pre-alpha, so changes to
the eventual public API should start from the constraints in
[Architecture](docs/ARCHITECTURE.md) and the ordered work in
[Roadmap](docs/ROADMAP.md). All behavior changes follow the workflow and gates
in [Testing](docs/TESTING.md).

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
5. Run `mise run check` before proposing the change.

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
