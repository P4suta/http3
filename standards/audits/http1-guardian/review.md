# HTTP/1 handler guardian audit contract (v5 candidate)

This directory is the tracked authority for the HTTP/1 handler guardian gate.
Generated evidence is written below `build/root-validation/http1-handler-guardian-v5/`; generated files are never loaded as audit code or historical authority.

The source contract proves the live control flow rather than matching isolated text.
`Run()` is reachable only after the second monotonic check has returned false.
All handler-entry clauses, invoked closures, and the deliberately closed helper set are examined.
The original owner and handler monitor references must reach their live `DOWN` consumers and remain active until publication and terminal settlement.
Termination and quarantine message branches return through the same absolute-deadline dispatcher before another receive.

The v4 independent review is the deterministic v5 Red baseline.
It observed 12/12 false-green mutations and 15 release blockers.
Its exact review, audit,
process observation, outputs, and invalidation are stored below `history/` and are pinned by byte count and SHA-256 in `history/manifest.json`.
The v5 semantic phase contains 71 exact controls, the independent phase repeats the 12 external mutations, and the evidence phase contains 35 exact adversarial controls.
Their name, type, order, expected value, observed value, uniqueness, and count are fixed by `control-authority.json`.

Seven additional v5-specific mutations were also captured before the v5 checker changes.
The historical v4 checker incorrectly accepted all seven;
`history/v5-new-mutants-red.json` records those exact results and the checker and fixture identities.
The 71-control semantic phase now rejects every one of them.
Together, the three phases complete 118 controls; a missing, substituted,
duplicated, reordered, or partially completed control cannot satisfy the gate.

`launcher.py` writes an immutable Running record before loading the audit manifest.
It snapshots each bounded input once, rejects hardlinks and reparse points, executes exact staged module bytes, attempts all three phases under one absolute deadline, limits combined stdout and stderr, and records typed process results without raw output.
Each run is immutable.
`latest.json` is only a digest-bearing canonical pointer and an interrupted Running pointer becomes explicit recovery evidence on the next run.

`consumer.py` independently rejects duplicate JSON keys, unknown fields,
substituted controls, missing artifacts, stale inputs, digest drift, forbidden secret/path/PID/socket/exception values, and a forged runtime.
Candidate and terminal bytes are consumed before canonical publication.
All captured inputs and the terminal bytes are revalidated after publication.

The runtime authority resolves `python@3.12.13` through mise, reads the resolved executable and mise bytes, compares the resolved interpreter with the executing interpreter, and binds version, implementation, executable identities,
configuration, OS, architecture, launcher, and every input digest.
CPython 3.12.14 development runs are always Rejected.

The tracked manifest intentionally has `status: candidate`,
`ready_allowed: false`, and a pending configuration hash.
This makes Ready impossible until an independent v5 review succeeds and the root-owned mise and dedicated CI integration is frozen.
`integration-plan.json` records that exact pending change, including an `if: always()` evidence upload.
`.mise.toml` and CI are not changed by this candidate slice.

The eventual canonical command is:

```text
mise run http1-guardian-audit
```

The canonical run must use CPython 3.12.13.
It remains separate from supervised Erlang/Gleam behavior validation.
