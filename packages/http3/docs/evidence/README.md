# Gate evidence

This directory holds the raw record of gate runs so that
[Conformance](../CONFORMANCE.md) can cite an observation instead of a memory.
A claim without a file here is not evidence.

## Convention

One file per gate run, named `YYYY-MM-DD-<gate>.md`, where `<gate>` is the
task name without the `mise run` prefix (for example `2026-08-26-check.md`,
`2026-08-26-interop.md`, `2026-08-26-fault.md`). A second run of the same gate
on the same date gets a `-2` suffix rather than overwriting the first.

Each file records, in this order:

1. the date of the run;
2. the exact commit it was run on;
3. the Gleam, Erlang/OTP, and `mise` versions;
4. the host: operating system, kernel, CPU, and memory;
5. the exact command, including every argument; and
6. the raw summary: suite counts, pass or fail per stage, and the verbatim
   text of any failure.

Record a failed run as well as a passing one. Never edit a stored run to make
it agree with a later result; add a new dated file instead.

## Boundaries

- Performance rows stay in `benchmarks/results/`. An evidence file for
  `benchmark`, `load`, or `soak` links to those rows and does not copy them.
- Do not store secrets, private keys, packet captures, unredacted qlog, or
  peer credentials here.
- Keep files small: a summary and the failing output, not a full build log.

## Template

```markdown
# 2026-01-01 check

- Date: 2026-01-01
- Commit: 0000000000000000000000000000000000000000
- Gleam: 1.18.1
- Erlang/OTP: 29.0.5
- mise: 2026.8.10
- Host: Linux 6.8.0 x86_64, 8 cores, 32 GiB

Command:

    mise run check

Result: pass. 273 native-core tests, 228 public-package tests.
```
