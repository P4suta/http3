# RFC 9114 launcher evidence gate

`scripts/rfc9114_launcher_evidence_gate.py` is the tracked, read-only consumer for the Windows PowerShell 5.1 and PowerShell 7.6 structural mutation reports.
It validates the exact source inventory, 21 helper, gate, control,
and fix-matrix identities, all 88 mutations, canonical-to-per-run evidence links, engine identities, native and visible-process postconditions, and the independent-review state.

The current integration descriptor is deliberately `Staged` while `.mise.toml`,
CI, and the supervised runner are being changed by coordinated work.
No `evidence-lock.json` is published until those inputs are stable and both engine runs have been regenerated.
A static lock may report `StaticReady`; only a Green report from a different reviewer may change it to `Ready`.

After integration and source inputs stabilize,
`scripts/rfc9114_launcher_evidence_lock.py` creates the content-bound `StaticReady` lock.
The builder cannot create or downgrade a `Ready` lock.

The gate self-test never invokes Erlang, Gleam, or the native mutation runner:

```text
python -I -B scripts/rfc9114_launcher_evidence_gate.py --self-test
```

The invalidation chain records why the v2/v3 launcher evidence remains Rejected and cannot be substituted for the v4 evidence.
