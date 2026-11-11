<!--
SPDX-FileCopyrightText: 2026 the http contributors
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# RFC 9114 strict inventory application

This directory contains the reviewed inputs for the RFC 9114 inventory.
The candidate inventory, independent review, cited-source manifest, and every invalidated generation are tracked source.
Generation 4 adds its launcher,
applicator, closed report schema, filesystem state machines, exact application and gate-control manifests, and staged CI configuration under [`v4/`](v4/).
Generated reports and recovery evidence belong under `build/root-validation/rfc9114-v4/`.

Generation 4 is fail closed until an external source-tree anchor is frozen and independently reviewed.
`StaticReady` proves only that the complete pre-review application path and all 45 mandatory controls passed.
`AuditPending` proves that an isolated application reached the reviewed target while independent review is still missing.
Only `Ready` can represent release eligibility, and the closed report schema permits it only when the frozen anchor records an approved independent audit with its exact report hash.

The outer bootstrap verifies its externally pinned anchor, snapshots every anchored member once, and compiles and executes those exact launcher, tool, and gate bytes.
The anchor binds `.mise.toml`, CI, the audit inputs, cited sources,
the 45 application controls, the 22 gate controls, and an explicit CPython allowlist.
Each allowed runtime records OS, architecture, configured version,
normalized resolved-executable-path hash, executable-content hash, link count,
and the exact `.mise.toml` hash.
A version string alone never authorizes an executable.

An application owns an OS-released exclusive lock before exposing an attempt.
Its durable journal records each state transition.
The original, intended,
claimed, published, and concurrent bytes are stored as independent files, so an in-place write through the published target cannot mutate recovery evidence.
Same-directory staging and exclusive atomic target creation preserve any concurrent value.
The next lock owner reconciles every incomplete crash boundary idempotently without overwriting either the target or recovery bytes.

Report publication owns both the intent and report locks.
It first invalidates the canonical pointer with the new run's `Running` state, then durably writes the immutable report, the per-mode final pointer, its completion marker, and journal.
After revalidating the anchor, every member, cited source, canonical requirements bytes, and the running Python identity, it advances canonical `report.json` as the final commit.
A consumer must supply the expected run ID,
requires an exact canonical/per-mode pair, validates every completed or abandoned attempt, and revalidates the tracked source before and after reading the report.
A pre-commit failure leaves canonical `Running` and retains a typed publication-failure marker when a completed immutable report exists.

Safe fixtures retain bounded, shareable copies of transaction and publication artifacts.
Their exact sorted inventory and hashes are recorded in `fixture-summary.json`; unlisted files, aliases, stale run IDs, mixed pointers,
missing controls, schema extensions, and changed source identities are rejected.
CI must upload these artifacts with `if: always()` so a `Running` or `Rejected` outcome remains diagnosable.

Any change to the bootstrap, anchor, toolchain configuration, workflow, audit input, or cited source invalidates the frozen chain.
The maintainer must create a new external anchor, rerun the exact Red, StaticReady, gate, transaction, and recovery controls on every allowed runtime, and obtain another independent review.
Applying `standards/requirements.json` remains a separate explicit operation.
