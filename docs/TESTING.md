# Test-driven development

Every phase follows Red-Green-Refactor:

1. Add the smallest executable contract or regression and verify that it fails
   for the intended reason.
2. Make the smallest bounded implementation change that turns it green.
3. Run the affected package suite, then all upstream package suites.
4. Refactor only while those suites remain green.

Gleam `Subject` values belong to the mailbox of the process that creates them.
A fixture may pass a subject to another process for sending, but that process must not receive or select it.
Create gates inside the worker that waits on them, publish the gate through a parent-owned readiness subject, and let the parent send only the release.
`scripts/subject_ownership_audit.py` checks direct `process.spawn`, `process.spawn_unlinked`, and `start_task` boundaries across all three packages.
Its bounded self-test covers legal sending, child-local receives, shadowing, separate functions, foreign receives, and foreign selectors.
`mise run test-runner-audit` runs both the self-test and the complete source audit before starting the native runner checks.

Workers which publish a terminal result and then exit must install their monitor atomically with process creation, or use a child-owned acknowledgement that keeps the worker alive until its owner consumes the result.
The bounded `scripts/spawn_monitor_contract_audit.py` gate binds each repaired process role to its source function and rejects a return to a separate spawn followed by `monitor(pid)`.
Its self-test removes the atomic call and adds both unsafe operations, while comment and string decoys prove that only executable source satisfies the contract.

The [public protocol performance workload](PROTOCOL_PERFORMANCE.md) documents the H1/H2/H3 timing scopes, bounded runtime observation, cleanup checks, and retained execution proofs.
Its runner has adversarial controls for missing work, private failures, forged reports, stalls, output floods, and changed retained code.
`mise run performance-contract-audit` separately checks every configured performance deadline against the shared 5,400,000 ms supervisor ceiling, proves prior evidence is invalidated before preflight, and keeps the producer, aggregate verifier, and CI upload paths identical.
Its own success or typed failure reports are retained by PR CI with `if: always()`.

Run `mise exec -- escript scripts/protocol_observer_test.escript` for the isolated observer controls.
The runner launches its owned VM with an absolute deadline, bounded output and hidden Windows process creation, then requires a validated cleanup-convergence diagnostic.
`--observer-source <relative-path> --expect-pass` compiles an exact observer source in an isolated directory;
`--expect-failure` proves that a retained prior implementation is rejected.
Both modes record source, test, runner and BEAM hashes with the OTP/ERTS identity.

Qualification reports bind to the complete authored source, configuration,
test, tool, API, and documentation input set through `evidence_identity.hrl`.
The generated conformance page is an output and is excluded from its own identity.
Starting a producer invalidates its prior success; source changes during execution prevent a new success.
The final bundle rechecks the same identity and independently validates the retained peer execution records.

Requirement references must use the exact relative path in that authored inventory.
Absolute paths, path aliases and generated files outside the inventory are rejected even when they exist.
Running `escript scripts/requirements_audit.escript --self-test` exercises one valid reference and four rejected references.
The cases compare only fixed outcomes and remove their generated fixture.
This check binds a referenced file to the source identity; it does not by itself prove that the named function ran or that its assertions cover the normative requirement.

Erlang and escript references must name a parsed function declaration with the specified arity.
The auditor uses OTP's preprocessor and parser without executing or compiling the referenced code.
Comments, strings, call sites,
types, inactive branches and definitions belonging to an included file cannot stand in for that declaration.
`epp`'s include-entry and include-return file attributes are distinguished from source-authored `-file` metadata through their generated annotations, so an include cannot forge ownership and metadata in the root source cannot hide a later declaration.
A malformed source fails even after a valid function has been parsed.
Twenty controls cover these distinctions, script headers and missing files.
Six isolated mutants prove the controls detect lexical matching, ignored arity, included declarations,
partial parses, escript lexical matching and forged file origins.
Gleam references still use lexical symbol lookup; declaration and execution evidence for that language remain separate work.

Source identity version 2 length-prefixes each path and hashes each file separately.
Delimiters alone cannot distinguish arbitrary binary contents from the next path.
The identity self-test redistributes those boundary bytes between two files and requires distinct identities for both source and build artifacts.
Source enumeration is bounded and rejects symbolic links, special files, hard-linked inputs, case-colliding names, replacement during an open read, and a changed tree on the final rescan.
Access time is excluded because the verification read itself may update it; size, type, access mode,
modification/change time, link count, device and inode remain bound.
Shared reports record the observed OTP patch, ERTS version, OS and architecture without host paths or environment values.

Fresh builds capture their inputs before compilation, after the old dev profile has been removed.
Publication requires the same source, tests,
configuration and toolchain before and after compilation.
The manifest binds all dependency BEAMs, generated project Erlang, package metadata and test artifacts.
It records the actual Gleam and rebar3 file hashes; versions from the tool configuration are explicitly labelled `declared_version`.
Missing startup records, changed inputs and replaced artifacts prevent verification.
Schema 3 carries a random build nonce and the observed `prebuild_profile_state = absent` from the pre-compilation record into the final manifest.
Before removing that profile, the runner atomically creates a fixed, per-target lease directory and publishes its owner record without replacement.
`begin`, `write`, and `abort` must present that nonce and acquire an inner operation directory.
This serializes duplicate commit and abort calls;
the commit removes the owner only after the final manifest and input cleanup succeed, then removes the operation and lease directories.
Any failure in that sequence leaves the lease root present, so verification and a later build both fail closed.
A killed runner or lost host intentionally leaves a stale lease;
it may be recovered only after separately proving that its compiler process tree has ended.
No time, PID, or unverified liveness check can steal it.
Verification atomically takes the same fixed root with a distinct owner record,
so a build cannot remove or replace artifacts while they are checked.
Multi package verification acquires roots in sorted order and releases them in reverse order.
Callers which need manifest fields use the decoded report,
original bytes, and digest returned from that one bounded read; long-running consumers hold the verification lease around artifact use.
Source and artifact discovery rejects symbolic or special tree members, portable case-colliding paths and hard-linked inputs.
Portable path keys normalize separators and Unicode to NFC, then apply full Unicode casefold;
composed/decomposed names and casefold expansions therefore cannot collide only after packaging on another operating system.
Each file is opened once and its size, type, access mode, modification/change time, inode, device and link count are compared before and after the bounded read and against the final path.
Access time is intentionally ignored.
Initial and final manifests are synced to a same-volume temporary file and linked into place without replacing an existing record; interruption or a competing publisher therefore cannot expose partial JSON or silently overwrite another run.
The tree inventory is repeated before publication and verification.
Use `mise run fresh-build` followed by `mise run fresh-build-audit`; an incremental build cannot mint a fresh-build manifest.
`escript scripts/fresh_build_manifest.escript --input-self-test` runs only the filesystem boundary controls, so hardlink and symlink behavior can be diagnosed while another checkout task is still editing repository sources.
The complete `--self-test` additionally inventories the current repository and therefore fails closed during concurrent source changes.
The boundary controls hold an operation at an explicit synchronization point, prove a concurrent terminal operation cannot enter its body, exercise stale-owner ABA rejection, and prove that a failure after publication retains the blocking lease.

Exception evidence retains fixed failure classifications and at most sixteen code locations.
Exception values, stack arguments and filenames are omitted.
Secret-marker regressions exercise the shared failure formatter and the performance workload failure path.
Body cancellation also retains one shared cleanup result when the first canceller exits, and publishes release only after the source callback exits.
Callback exceptions and timeouts remain distinct from the already-recorded wire transfer result.

Dictionary retention tests measure actual record storage and referenced binary allocations without exposing dictionary bytes.
They cover isolation-key charges,
destination metadata, eviction under metadata pressure, detached binary slices,
and both signed 64-bit clock boundaries.
The five ordinary cases in `test/dictionary_memory_test.gleam` fail against the original undercounting implementation; disabling only the backing-allocation copy also fails the slice case.
The budget applies to records in the returned immutable store, while the caller controls older store values and selected records it retains.

HTTP/2 response isolation regressions hold the terminal body pull at a worker-owned synchronization point until another stream's response has arrived.
Invalid trailer names, oversized trailer sections, and short bodies with and without trailers must produce a stream reset, dispose their source once, and permit a subsequent request on the same connection.
Observations preserve only stream numbers, response statuses, reset codes and typed transport failures.
The response collector uses an absolute deadline and handles EOF without asserting on a socket value.
A separate authenticated peer sends final headers and a reset in one TLS write; attempt completion must retain HTTP/2 even when the response has not yet been returned to the caller.
Single-attempt diagnostic fixtures disable retries explicitly; the client retry policy has its own tests.

HTTP/3 pre-header deadline regressions stop the request reaper at explicit child-cleanup and source-cleanup gates.
While either gate is held, the exchange must not return, publish the checked-out connection, or release its request charge.
Confirmed cleanup releases both charges before the caller resumes.
An injected child-cleanup failure resumes the reaper but keeps both charges quarantined; its terminal and release observations must identify HTTP/3 even after the unified dispatcher applies its protocol-free fallback.
These gates anchor the ordering assertion, while the production total and cleanup deadlines remain the independent finite bounds.

Diagnostic comparisons that restore earlier source files must also rebuild from a clean profile.
Copying an older modification time can leave a later compiled artifact in an incremental build.
Such a source/artifact mismatch invalidates the comparison even when its selected tests pass.

`mise run test` and each package check use `package_suite.escript` after a fresh build.
The runtime CI matrix runs each package independently on every OS/OTP pair and retains a result even when the build or suite fails.
Reports bind the source, compiler/runtime identity, dependency artifacts, listener executable,
configured entrypoints, and actual completed EUnit cases.
Before execution the wrapper builds a complete relation from every authored `.gleam` and `.erl` test source to the exact BEAM filename, BEAM module, source and BEAM hashes,
and exported EUnit entrypoints.
Duplicate modules, missing or malformed BEAMs,
module mismatches, links, source-tree mutation and a changed post-execution inventory fail closed.
A generator is one configured entrypoint but can complete several cases; described groups retain that relationship when EUnit would otherwise flatten their output.
An empty generator, missing entrypoint, repeated ordinary test, cancellation, unknown schema field, or stale run nonce cannot qualify.
Suite, listener-completion,
campaign-build, matrix-child, and build-input JSON reject duplicate keys,
including escaped spellings and nested objects.
Filesystem-reader controls exercise both duplicate orders; choosing either value cannot manufacture a passing run.

Package-suite schema 3 also binds execution to the exact BEAM objects used by the child VM.
The parent inventories every regular, single-link BEAM under the verified `build/dev` code paths and retains the listener binary SHA-256 returned by the compiler.
Each run reserves a nonce-specific attempt and runner directory.
The listener and its complete local header closure are copied with no-replace publication into that attempt before compilation, and their bytes are rechecked against the captured source after compilation.
Units and the complete BEAM inventory are stored in a 16 MiB bounded, digest-bound invocation file so a large suite cannot exceed the Windows process command-line limit.
The short child bootstrap hashes `code:get_object_code/1`, loads those same listener bytes, reads the invocation through a finite reader, verifies its SHA-256 and canonical external-term schema, and only then starts EUnit.
After all test processes have joined, the listener compares every loaded `build/dev` module's code-server path, loaded module MD5, and object bytes with the parent's inventory.
The child report records the expected inventory digest and the loaded digest and count; the package report and runtime-matrix auditor require exact agreement with them and with the process supervisor's observed exit status.
Self-tests replace a test BEAM after inventory, restore its original file from inside the test, and still require rejection because the loaded module differs.
A second control replaces the listener after its parent-held hash and proves the bootstrap exits before report publication.
Report and runner publication uses a synced temporary file and a no-replace hard-link commit; concurrent writers,
hard-linked evidence and stale locked replacements are rejected.
Run `escript scripts/evidence_publication_self_test.escript` to exercise that publication primitive independently of compiler and network subprocesses.
Run `escript scripts/execution_beam_identity_self_test.escript` to execute the bootstrap in-process with an 800+ KiB invocation while verifying its command string stays under 4 KiB, duplicate attempt reservation fails, and a hard-link-contaminated attempt cannot be cleaned or followed by publication.
On Windows the same self-test uses the owned process supervisor to check a live owner, an exited native PID, a deliberately stale process-start identity, and a failed observation sink.
The command has a 15-second absolute deadline and a 16-KiB output limit; each native tree must report an observed exit and empty final tree.
Attempt owner receipts use schema 2 and remain private.
They bind the nonce and finite creation time to the OS PID, process-start identity, host/boot identity,
OTP runtime, architecture, and the execution-identity source digest.
Cleanup first atomically creates one fixed `.terminal-operation` directory and publishes its no-replace `owner.json` receipt, then walks and hashes the entire bounded tree without deleting anything.
It rejects links, hard links, special files, case-colliding names, case aliases of reserved names, and a changed root directory identity.
The fixed directory remains present for the whole transaction, so deleting or byte-for-byte replacing its open receipt cannot admit a second cleanup.
Windows retains the receipt handle while Unix platforms additionally compare retained device/inode identities.
Cleanup rechecks the exact attempt owner, operation directory, and operation-owner bytes around every removal, deletes ordinary files and deepest directories first, then requires an otherwise empty root before deleting the attempt owner, operation receipt, operation directory, and root in that order.
A deletion failure preserves or restores the exact owner receipts, so the attempt remains identifiable and a successful report cannot be published.

`escript scripts/package_suite.escript --recover-stale-attempt BASE NONCE SNAPSHOT` is the separate stale-attempt recovery entry point.
It accepts only a schema-2 owner whose machine, boot, PID, and process-start observations provide a strong proof of owner death or PID reuse.
Before removing any attempt entry it publishes a bounded, shareable, no-replace snapshot containing only hashes,
typed liveness proof, tree counts, finite time, and current runtime/source identity.
An occupied snapshot path, a live owner, an unverifiable host, a legacy schema-1 receipt, or a platform without a supervised strong observation provider is rejected without deletion.
The built-in Linux observer uses the machine ID, boot ID, and `/proc/PID/stat` start ticks.
On Windows,
`package_suite.escript` and `supervised_gleam.escript` install an owned provider that reads `MachineGuid`, `LastBootUpTime`, and `System.Diagnostics.Process.GetProcessById(...).StartTime` under the common process supervisor.
Domain-separated SHA-256 values are produced inside the PowerShell child; the raw machine, boot, start, and PID observations never enter shareable output.
The exact system executable is held open, hashed, and rechecked after capture.
A start failure, timeout, output saturation, malformed schema, executable change, inaccessible process, or diagnostic sink failure produces `Unavailable` and cannot authorize recovery.
macOS remains `Unavailable` until an equivalent owned strong provider is connected; heuristic PID checks never authorize deletion.

Ready package and HTTP exact reports, and ordinary Failed reports, are published only after their private attempt directory has been removed successfully.
If cleanup itself fails, no Ready report is written; HTTP exact may retain a typed Failed cleanup report alongside the contaminated attempt for investigation.
The HTTP exact schema 3 report retains the bounded child document and run nonce as well as its aggregate hashes.
Its validator reconstructs the selected unit list from that document and cross-checks all counts, sanitized failure rows, runner and inventory identities, loaded digest/count, child exit status,
and the strict process-supervisor proof.

Generated campaigns use the selected package's own dependency closure.
A three-package fixture deliberately supplies conflicting implementations of one dependency and verifies which one each child actually executes.
Synthetic runner controls preload only their own fixture code.
A retained entry marker must prove that each injected operation started; expiry during VM startup cannot count as a successful stall test.
Stall and blocked-replay controls use a five-second absolute execution budget, with separate finite process teardown.

`runtime_matrix.escript` aggregates all eighteen independent OS/OTP/package reports.
It compares the complete current compiler-discovered entrypoint set,
actual completed cases, source and native-build identities, observed runtime,
and bounded-process completion.
Missing, duplicate, replayed, failed, or stale runs produce `Blocked`.
The final audit repeats that validation from the retained reports and build manifests.
Imported documents are untrusted: only fully validated inputs are copied into `build/runtime-matrix/verified/` for sharing, while the unvalidated `inputs/` directory is never uploaded by the aggregate job.
`mise run runtime-matrix-aggregate` repeats the audit locally after the independent CI artifacts have been collected.

Every runtime worker first stages its result in a directory whose name exactly matches the uploaded artifact.
Each package uses the same two relative names,
`package-suite.json` and `fresh-build.json`; a build failure may retain only the bounded, shareable failed suite report.
The transient `fresh-build-inputs.json` is removed when a fresh build completes and is never an artifact input.
`upload-artifact` receives the single staging directory, so it strips one uniform directory root for `http`, `http3`, and `quic_core`.
The upload step runs only after staging has accepted the report and its exact file inventory, preventing a rejected stale or extra staging entry from being published.
`download-artifact` keeps its non-merged artifact directories, producing the exact layout consumed by the aggregate auditor.
The runtime-matrix self-test materializes that upload/download expansion for all eighteen jobs and rejects the former root-package layout, merged downloads, missing files, extra files,
and an unexpected stale file in a staging directory.

The shared subprocess collector accepts only positive deadlines up to 5,400,000 milliseconds, uses an 8 MiB total output limit, and retains a 64 KiB tail.
Every accepted run has one absolute deadline; arriving output never extends it.
Output exhaustion stops and reaps the owned child independently of its operation deadline.
It records whether exit was observed and distinguishes a complete output digest from a capped prefix.
One compiler-checked Erlang `open_port` call starts the source-hash-pinned Python supervisor with packet-4 framing and OTP's `hide` option.
On Windows the supervisor creates a headless pseudoconsole, binds it to a suspended root child with `STARTUPINFOEX`, passes the `HPCON` value directly with a pointer-sized attribute length, and temporarily clears all three process standard-handle slots only around `CreateProcessW`.
A `finally` block restores every slot before the child is inspected or assigned to its kill-on-close Job Object.
The supervisor starts a bounded output relay and only then resumes the child.
It retains the ConPTY input writer until the child has exited and closes it while output is still being drained.
Console-subsystem descendants inherit the pseudoconsole.
Authored Python launch helpers require an attached console plus membership in a Job whose queried limits include `KILL_ON_JOB_CLOSE`, preserve that attachment, and reject every nonzero process creation flag.
`hide` remains an additional guard on the supervisor port, rather than the descendant-console proof.
The parent registers ownership before sending `START`.
A false return or exception while sending that packet is treated as uncertain delivery: ownership stays registered, `STOP` is sent, and the parent waits for the supervisor's final frame, exit status, empty tree, and console attestation.
If that proof is not observed within the finite teardown grace period, the run is blocked and its private crash directory is retained for the residue audit.

Windows CI and local package qualification enter that boundary through `scripts/windows_headless_entry.ps1`.
The PowerShell process starts exactly one `escript.exe` with `UseShellExecute=false`, `CreateNoWindow=true`, a hidden window style, and redirected output.
That escript exposes four fixed operations: one fresh-build target, one package-suite target, one `target/windows-2025/OTP` runtime staging row, or the fixed credential self-test/fresh-build/matrix sequence.
It does not accept an executable, module,
script path, free-form argument vector, deadline, or output limit.
The bootstrap parses the documented flag order itself instead of using PowerShell's named parameter binder, so an invalid flag cannot produce an unredacted binder error before the fixed failure summary.
Every selected child then uses the same owned process supervisor described below.
CI pins OTP 28 to `28.5.0.6` and OTP 29 to `29.0.5`.
`MISE_ERLANG_VERSION` must identify OTP 28 or 29; the entry rejects a missing,
malformed, or different running OTP before starting an operation.
The outer launcher hashes the selected `escript.exe`, itself, the fixed runner, and a canonical operation configuration.
The inner VM hashes the executable under its own OTP root and the runner again, compares the identities passed by the launcher, and verifies its runtime OTP.
This binds `Get-Command escript.exe` to the requested runtime rather than trusting its leaf name.
The outer reader drains stdout and stderr concurrently, stops at one absolute deadline, and counts their combined output against a 64 KiB cap.
It retains only the bounded stdout needed for the typed inner JSON and discards stderr as it drains it.
On failure it recursively terminates the escript tree and waits for exit.
It never forwards child output.
Its only output is a fixed JSON projection without paths,
arbitrary command lines, process IDs, exceptions, or output tails.
The projection includes the source, configuration, and tool SHA-256 identities,
the fixed scope, completion count, each validated typed step result, the finite failure classification, and an allowlisted `mise` rerun command assembled only from validated selectors.

The Windows package-suite operation first runs the canonical ETF wire-format self-test, the ETF boundary-audit self-test, the package/Windows/OTP ETF matrix row, and the owner-bound console-inheritance proof as separate supervised steps.
The operation then runs the selected package suite under the same absolute deadline.
A failed audit does not suppress later independent steps;
after deadline exhaustion, every unstarted step is recorded as a typed failure.
This keeps the shared decoder controls inside the fixed entry grammar and avoids more direct `escript.exe` launch surfaces in Windows CI.
Unix rows run the same canonical fixture test,
auditor self-test, and matrix audit in independent non-Windows steps before an `always()` package suite.
All 18 package/OS/OTP rows preserve `build/evidence/etf-boundary-matrix/staging/etf-boundary-<package>-<platform>-otp<otp>/` as an artifact with the same basename.
The aggregate receives the directories without merging.
Its auditor self-test and the aggregate itself run as separate `always()` steps, so a failed self-test cannot suppress the matrix diagnosis.
The aggregate rejects missing or duplicate rows, runtime OTP mismatch, or disagreement in source, canonical-fixture, and audit-tool identity.
Each row binds the complete eleven-file decoder-and-auditor source set, including the strict JSON reader and aggregate validator.
Ready evidence requires all 32 row controls and all 576 matrix controls.
A rejected row or aggregate replaces any older Ready report with a bounded, shareable Failed report containing only typed progress counts, the failing stage, safe source/configuration/tool/runtime identity, and the fixed rerun command; exception text, output, paths, process identifiers, sockets, credentials, headers, and bodies are never retained.
The row and aggregate entry points also catch every unexpected exception before it reaches stderr and emit only a fixed failure sentence; the private exception term and stack are neither printed nor serialized.

The paired visibility step invokes `scripts/windows_console_inheritance_audit.ps1` through the same owned runner for every Windows package row on OTP 28 and 29.
Its fixture and unrelated control process use hidden `ProcessStartInfo` launches.
Four streams are drained concurrently under one combined cap and the proof's shared absolute deadline;
overflow or expiry recursively kills the trees and still requires process joins and stream EOF.
Each run invalidates its prior file and saves the bounded result as `build/test-runner/windows-console-inheritance-otp<otp>.json`.
CI uploads it as `console-inheritance-<package>-windows-2025-otp<otp>` even when a later package result fails.

The corresponding local entry tasks are:

```console
mise run windows-fresh-build -- -Target all
mise run windows-package-suite -- -Target http
mise run windows-package-suite -- -Target http3
mise run windows-package-suite -- -Target core
mise run windows-runtime-stage -- -Target http -Platform windows-2025 -Otp 29
mise run windows-credential-local
```

The caller should already be an existing terminal, CI `pwsh` step, or another headless host.
This boundary prevents the child cascade from allocating visible consoles; it cannot remove a console that the caller allocated before the script started.
Do not invoke the underlying Windows `bash`, `escript`, `mise`, or `cmd` commands directly.
The static console audit rejects those commands in a Windows-capable workflow step, alternate PowerShell process-start surfaces, a missing process-start flag, and replacement of the fixed runner dispatch.

The relay switches to discard-only mode after the output limit and continues draining until the Job is empty.
Pseudoconsole close and output EOF are joined under a finite teardown bound, avoiding the documented close-versus-undrained- output deadlock.
A successful process proof requires the pinned supervisor and Python identities, valid framing, matching reported and observed status, an empty native tree, and `native_console_isolated=true`.
The console audit parses all authored Erlang and Python launch sites and rejects unowned calls, dynamic spawns, console-detaching flags, comments or strings used as decoys, and a missing pseudoconsole attachment.
Its AST controls also reject a by-reference `HPCON`, a non-pointer-sized attribute, incomplete or non-null standard-handle clearing, restoration outside `finally`, code inserted between clearing and creation, early input-writer close, and any abnormal Windows status projected outside the fixed non-sensitive category set.
Windows qualification also observes process creation and window visibility during the complete run; its shareable result contains only fixed process names, bounded parent names, an accumulated `ever_visible` result, 100 ms monotonic buckets, counts, and source identities.
The bounded observer is `scripts/windows_process_visibility_watch.ps1`; it samples every observed process throughout its lifetime so a window shown after startup is still rejected.
Qualification uses `-RequireOwnerBinding`.
After the readiness signal, the launcher writes the fixture PID and UTC start ticks to a random token-derived private file with `CreateNew`, exclusive sharing and a durable flush.
The observer accepts one strict bounded ASCII record, opens that process, and requires both identity components and the allowlisted process name to match.
It walks at most 64 live or retained parent identities, rejects cycles and start-time inversions, and samples only that exact root and its descendants.
Concurrent Codex, Git, test, or shell processes are ignored even when they use an allowlisted executable and started after readiness.
The paired audit deliberately overlaps an unrelated hidden Python process and requires it to increase only the bounded ignored-candidate count.

PID, time, token, owner-file path and handles stay in memory and are never published.
Open handles and cached allowlisted names keep short-lived owned processes attributable after exit.
Every bound run requires complete lineage;
a visible owned target, unavailable owned visibility or lineage, an exhausted event limit, or an owned process still present at the end fails closed.
Unbound diagnostic runs retain the system-wide pre-existing-conhost baseline, but their results cannot satisfy the paired owner-bound contract.
The target inventory includes the shell and console hosts as well as Python, Gleam, escript,
erl/erlexec, beam.smp, and rebar3.
On the first visible owned target the observer stops early.
It uses the verified in-memory process identity to terminate only that executable when it is in the user-authorized tool list, waits a bounded interval, and publishes only its fixed name and whether termination completed.
It never terminates `conhost`.
An internal watcher error is projected to a fixed phase code; process exit or access races become bounded per-phase counts and make `observation_complete=false`.
Exception values, process identifiers, start times, handles, and command lines are never published.
Run the observer with `-SelfTest` before a paired proof.
This checks all fixed phase projections, the five-field failure schema, the complete target set,
bound and unbound lineage policy, strict owner-record shapes and ranges, and the rule that `conhost` is observed but never terminated, without starting a native child process.
For a paired run, supply a 32-character lowercase hexadecimal `-ReadyToken` and `-RequireOwnerBinding`.
The observer creates one exclusive token-named readiness signal, then waits a fixed ten seconds for the private owner record.
Both files are removed on success and every failure path.
A passing report requires readiness creation and cleanup, exact owner binding,
owner-record cleanup, root observation, complete owned lineage, and no owned residue.
The public JSON contains only booleans and bounded counts for that handshake.
The audit invalidates an older result before it starts and binds its report to every scanned source, `.mise.toml`, the exact OTP/ERTS environment, completed file/control counts, finite failure classifications, and a rerun command.
It retains one report per OTP version under `build/test-runner` so the Windows OTP 28 and 29 executions do not overwrite one another.
EUnit's internal output capture is also constrained: every child actor starts with a 33,554,432-word heap limit, includes referenced off-heap binaries, and is terminated at collection if it exceeds that limit.
This is a per-actor limit,
not a whole-VM resident-memory claim.
Heap-dump logging and crash dumps are disabled; inherited Erlang flag variables cannot replace these settings.
Package result artifacts omit raw stdout/stderr and their digests.
The EUnit listener retains only fixed failure classifications and safe code locations,
with at most 64 failures and an explicit dropped count.
The adversarial runner self-test includes secret values in assertions and stderr, checks generated case counts, and injects 65 consecutive failures.
Run `mise run test-runner-audit` to repeat these checks.

The supervised developer wrappers use a 600-second child deadline and a 630-second outer ownership deadline for the larger root HTTP suite.
The HTTP/3 and QUIC-core suites use 300 and 330 seconds respectively.
An ordinary nonzero test exit is reduced inside the supervised VM to at most 64 source-shaped test names, at most 64 test-module names, fixed failure categories, and finite completion/failure summaries.
The validated map crosses the outer boundary in one size-limited machine envelope; the outer VM does not reparse assertion text or a pretty-printed Erlang term.
Only exact summary lines are accepted.
`N tests, M failures` records `N` completed tests, while `P passed, F failures` records `P + F`; `F` must be positive and no larger than the completed count.
Repeated equivalent summaries are accepted, but conflicting, truncated, invalid, or free-text `tests failed` text leaves the completion state unavailable.
Output larger than the complete projection bound is sampled only for safe diagnostic categories and identifiers; its omitted middle prevents any observed summary from establishing completion counts.
Compiler output, assertion values, endpoints, process data, credentials, and raw stack frames are discarded.
The projection self-test covers plural `failures`, conflicting and spoofed summaries, private key/cookie/bearer/PID/reference/socket-shaped values, duplicate envelopes, and a 65-name saturation case without publishing those values.

When an aggregate HTTP run cannot finish, `--http-exact-test` creates a clean private source tree, hashes every source and dependency input, and temporarily replaces the one staged `gleeunit.main()` call with `Nil`.
This compiles the complete test-module closure without executing it through the aggregate entry point.
The runner restores the exact original bytes and verifies their digest before accepting any generated BEAM.
A typed listener then enumerates and runs the compiler-exported units with a 30-second limit per unit.
The focused `--http-server-exact-test` uses the same unit limit, while `--http-ohttp-exact-test` uses ten seconds.
Each report records the selected scope, unit limit, source and generated-artifact identities, completed count,
bounded failure classifications, child status, and native tree/console proof.
If the staged `gleam test` build itself fails, the runner publishes a `Failed` report before starting any unit.
That report binds source, dependency,
toolchain, compile-driver and bounded-process identities, the rerun command,
and safe typed compiler diagnostics without retaining compiler output.
Normal `--http-test`, `--http3-test`, and `--quic-test` success also requires exactly one final gleeunit summary.
The report binds the compiler-discovered test modules and units and records `completed_tests` with `skipped = 0` and `failures = 0`; a missing, duplicate, or inconsistent summary cannot qualify.
Their schema-2 failure reports retain a validated projection instead of collapsing every nonzero exit to zero completed tests.
`completion_state` is `projected` only when one normalized count pair is available;
`observed_test_failures`, `completed_tests`, and `failure_count` then carry the same bounded evidence.
Inventory remains `counts_state = unavailable` because an ordinary aggregate failure cannot prove the complete compiler-discovered unit set.
`failure_projection_bound_to_current_source` is true only when both source and runner identities remain stable.
Deadline, output-limit, process protocol, ambiguous-summary, and rejected-projection failures retain `completion_state = unavailable`.

The ordinary package wrapper and the private exact runner now use the same fail-before-test source-to-BEAM inventory contract.
A failure before a complete child record reports `counts_state = unavailable` with null counts; it cannot claim that zero tests were skipped or completed.
A successful report retains the complete inventory digest and verifies the relation again after execution.

OHTTP tests convert cryptographic results to finite integer or Boolean outcomes before assertion.
Unexpected success therefore cannot place an exporter secret,
private key, plaintext, ciphertext, authority, or process identifier in an assertion report.
Thirty-two-way barriers exercise both gateway and client one-shot response contexts and shared replay admission.
A manual monotonic-clock fixture covers pending and committed expiry without sleeping, including caller death, capacity recovery, stale leases, and store-owner death.
The deterministic HPKE sender used for RFC vectors exists only in the test Erlang module; the published OHTTP API has no caller-selected request key or response nonce.
The `Expect` corpus covers token and quoted values, quoted commas, quoted-pairs,
empty parameter members allowed by RFC 9110, invalid whitespace around `=`, and case-insensitive `100-continue` rejection.

`escript scripts/process_runner.escript --assertion-self-test` exercises 19 actual OTP assertion macro cases, two compatible command-assertion failure shapes, and seven ordinary exception/shape controls.
The command-assertion failure shapes are generated in-process from fixed private fixtures because an external command contributes nothing to their classification.
Native deadline,
output, protocol, console inheritance, and tree-reaping behavior is exercised separately through the pinned process supervisor.
The suite also includes negated assertions, exception aliases, and deferred assertions.
A normal 28-leaf suite checks classification and secret redaction; a separate 28-failure suite verifies the shared EUnit listener.
Both run in owned VMs with 15-second absolute deadlines and the same heap/output bounds.
A failed expression or command remains distinct from a failed assertion.
Only fixed tags are classified; assertion properties are discarded.
The checks also run in the complete process-runner self-test.
Each invocation retains source, compiled BEAM, OTP executable/runtime and macro-header hashes,
completion counts and observed child exits under `build/diagnostic-assertions`.
These records prove the scoped diagnostic contract, not overall qualification.
The assertion fixture opens no native process or port.
The complete runner self-test verifies parent EOF, autonomous supervisor deadline, output-limit discard-and-drain, normal descendants that outlive their root, and two-level console inheritance.
OTP 28 and 29 evidence is accepted only when child exit,
tree-empty, console-isolation, and external visibility observations all agree.

Credential qualification is derived from those verified complete platform suites.
Fourteen explicit compiler-exported test symbols cover certificate algorithms, mTLS admission and refusal, direct and retry handshakes, rotation,
resumption, replay fallback, ticket expiry, identity rejection, and failure secrecy.
Every role must have run successfully on all six OS/OTP pairs.
Source comments and a document containing only `Ready` cannot satisfy a role.

`mise run http-model` executes 10,000 independently seeded cases for each of six additional models: HTTP/1.1 framing, HTTP/2 stream halves and credit,
HPACK table accounting, connection-pool leases, cancellation subscriptions,
and executor drain.
Their oracles use byte-language boundaries, signed credit ledgers, oldest-first field queues, and independent ownership records.
A failure retains a finite invariant code, case seed, and verified shortest reproducing prefix; it never serializes a runtime handle or application data.
Use `escript scripts/http_models.escript replay <domain> <seed> <steps>` to replay a failure.
Diagnostic replay results cannot qualify as the full PR gate.

Nightly model, property, and fuzz campaigns each require all eight shards.
`mise run campaign-aggregate -- model` (or `property` / `fuzz`) checks every shard's source identity, role, seed, exact case count, required oracle checks,
and allowed fields.
Missing or invalid shards produce a bounded `Blocked` summary with replay commands; an incomplete campaign cannot qualify as a million-case run.
CI retains aggregate summaries even when a worker fails.

The live qlog runner begins its source-bound capture before opening endpoints and seals exactly two bounded trace digests after both endpoints finish.
Validation rejects traces from another source, incomplete captures, and files modified after capture.
CI uploads only the payload-free `report.json`;
trace files and runtime capture metadata remain explicit local diagnostics.

Structural changes use executable package, API, boundary, and archive audits.
Protocol behavior uses unit, state-model, property, fault-injection, and live
loopback tests. A timeout is a failure, not a successful cancellation. Every
fixture owns and releases its processes, sockets, listeners, files, and
temporary directories.

Run `mise run coverage-coordinate-audit` before long coverage campaigns.
Each compiled clause alternative needs an observable line that its siblings do not share.
In handwritten Erlang, keep alternatives on distinct physical lines;
putting several outcomes on one line prevents the auditor from distinguishing them even if every outcome has a regression test.
Coordinate failures retain only typed module, function, and line observations.
Resolve the ambiguity in the source before collecting coverage; do not remove the branch from the model.

Current test counts are discovered from public Gleam and exported zero-arity
Erlang EUnit entrypoints ending in `_test` or `_test_`, then rendered from
[`qualification.json`](../qualification.json) into the
[product conformance status](CONFORMANCE.md). The status auditor parses Erlang
forms rather than matching source text, and its synthetic discovery contract
rejects private Gleam functions, unexported Erlang functions, wrong arities,
and ordinary helpers. Counts are never maintained as handwritten documentation
values. The root suite covers common Body/Error
contracts; typed Context values; middleware order and short-circuiting;
grant-before-growth worker resources; bounded, redacted diagnostics; supervised
handler panic/exit isolation; streaming backpressure; cancellation; atomic
handler reload; graceful drain; strict HTTP/1.1 parsing and exchange behavior;
active-once TCP/TLS client and server paths; ordered finite pipelining;
deferred `100 Continue`; half-close and premature-EOF handling; isolated
stalled/exiting response sources; post-handshake CONNECT and Upgrade byte
streams; Client lifecycle, pooling, safe redirects; and the bounded HTTP/2
protocol foundation.

The stale HTTP/1 pool regression returns a zero-length response to the pool,
then closes its peer only after an explicit client-to-server synchronization point and after receiving the next request bytes.
The missing response does not prove whether that request was processed.
With retries enabled or disabled, the listener is closed after the failure to wake the pending accept without a sleep;
one failed attempt, no second connection, and no successful logical terminal are required.
Separate pure cases require a positive budget, an idempotent method, a replayable body, and either proven pre-send failure, H3_REQUEST_REJECTED,
or an explicitly configured response status.
A synchronized source fixture proves cleanup completes before its replay factory runs, while a blocked cleanup proves expiry cannot construct a replay.
The partial-response fixture proves body failure remains the sole logical failure after headers have already been returned.
All cases assert only opaque IDs, typed outcomes, counters, and causal sequence values.

Cancellation qualification is event-driven. Context tests cover one-shot and
late subscriptions, explicit removal without a tagged mailbox residue,
subscriber and Context-owner exit, payload-free lifecycle snapshots, and 250
concurrent cancel/subscribe races. Live adapter tests prove that H1 returns a
finite 408, closes the affected connection, and never dispatches its pipelined
tail; H2 resets only the affected stream while parallel and later streams on the
same TLS connection progress; H3 emits both reset directions with local
H3_REQUEST_CANCELLED provenance. The common executor contains no periodic
cancellation polling interval.

Common server admission tests suspend the executor only after the submitting process has acquired its finite worker grant and observed the queued Dispatch.
They then cancel the Context or establish the drain barrier before resuming the executor.
A separate guardian probe pauses immediately before token adoption so the caller can win the cleanup claim deterministically.
For HTTP/1.1, HTTP/2,
and HTTP/3 the evidence requires one payload-free start, one typed failure or resource refusal, one confirmed release, no handler call, and zero residual worker or memory usage.
Releasing a losing guardian must not add a late event.

HTTP/1 listener qualification records a fixed-size phase snapshot on the
context-cancellation observation boundary. A missing application Context can
therefore be attributed to listener readiness, socket acceptance, connection
actor handoff, request-head parsing, handler dispatch, or handler completion
without logging the endpoint or request. A live lifecycle test verifies
Running/Draining/Stopped retention and connection convergence. A separate
five-writer test performs 20,000 updates per writer while sampling invariants,
and an orphaned-writer fixture proves both reads and later writes remain finite
while the snapshot explicitly becomes inconsistent. The readiness protocol is
two-sided so no listener or accepted connection is reported started before its
new owner has acknowledged the transferred OTP resource.

HTTP/1 response-interruption tests wait until the second source pull has entered its own gate, then close verified TLS or stop the listener.
They require both the producer's actual exit and the source cancellation callback.
Half-close and delayed pipelining controls preserve successful responses.
The transport selector tests queue a real packet from another owned socket,
then verify that lifecycle selection leaves that packet untouched.
They also cover active-once credit, bounded reads, monitor delivery, timeout closure,
and the finite selector-size limit.
Replacing only the H1 server with its previous executable makes the TLS-close and listener-stop regressions fail.

Diagnostic qualification assigns every admitted request a payload-free opaque
ID and every accepted observation a reporter-local monotonic sequence. A test
deliberately blocks the Started sink until the corresponding Failed sink
finishes, then reconstructs causal order from sequence rather than callback
completion order. Another test races 250 emitters and rejects any missing,
duplicate, non-positive, or out-of-range sequence. The common-server test checks
that cancellation emits exactly one correlated Started/Failed pair with a
redacted `Cancelled` error. Emit/stop races run 500 times, and a blocked admitted
sink proves that stop waits for existing work while refusing every later event.

The retained HTTP/2 Red-Green cases include preface/frame fragmentation,
SETTINGS acknowledgement debt and peer limits, HPACK table-size changes,
stream and connection flow credit, RST admission release, bounded header-phase
cleanup, legacy priority observation, lossless standard-message conversion,
Content-Length/DATA agreement, bodyless response rules, explicit Extended
CONNECT opt-in, ORIGIN, RFC 9218 priority fields, RFC 9651 Structured Fields,
and finite wire-driver work limits. The retained HTTP/1.1 hostile cases include
Host authority validation, strict chunk-extension grammar, forbidden trailers,
TE/CL conflicts, duplicate lengths, bare LF, and finite head/body limits.
Network suites require permission to bind loopback sockets.

Every package-check and repository lint invocation enables glinter statistics.
The final log records the discovered file count, line count, and elapsed
milliseconds, which distinguishes a large cross-module analysis from a stopped
worker without weakening the warnings-as-errors result.

QUIC and HTTP/3 regressions keep payloads, endpoint identities, process values,
and cryptographic material out of their failure evidence. The public
application-to-qlog bridge accepts only typed HTTP/3 initiator, stream-role,
frame-kind, typed stream-ID, finite byte-count metadata, or a validated
nonnegative integer code. It has no operation for text, headers, body bytes,
transport events, writer statistics, or writer close. The supervised QUIC
connection remains the sole writer owner. Internal receive, pacing, recovery,
and lifecycle traces likewise use stable typed categories and bounded scalar
counters. qlog is explicit opt-in and creates exactly one asynchronously
written trace per connection for one-shot and reusable clients and for
servers. The live gate requires every client and server trace independently to
contain connectivity, packet, TLS-key, recovery, HTTP/3-frame, and QPACK
settings/stream-role families; an aggregate formed from one rich trace and one
transport-only trace fails. Trace files use exclusive creation with bounded
collision retries, and tests retain a qlog directory when exact cardinality or
an event assertion fails. Those files are sensitive diagnostic artifacts and
are never treated as shareable qualification evidence.

Qlog directory validation, exclusive open, and the initial JSON-SEQ header run under one five-second startup deadline, followed by at most one second to confirm child termination.
A guardian starts before filesystem work and keeps that deadline even when the calling process cannot run.
The process that opens the file remains its device writer, preserving OTP's file-owner monitor.
Startup adds no steady-state actor: a trace has admission, device-writer and guardian actors plus one OTP file device; directory validation uses only the guardian, temporary opener and probe device.
No event queue is admitted before the writer is published.
Timeout or an unconfirmed join is a failure, and a queued ready message cannot cross the original deadline.
A failed filesystem operation can leave its partial trace or empty probe file for inspection; the return value does not claim that directory entries were rolled back.

Cancellation also recovers an ownership notice queued at expiry.
Before that notice exists, a temporary observer finds the already-created file device from its monitor of the opener.
This observer uses at most 65,536 heap words and shares the same one-second cleanup deadline; it replaces the not-yet-created admission actor in the startup resource bound.
The scan accepts at most four opener watchers and one file device, and refuses unknown monitor identities.
A file-server request that has not yet opened a device cannot be synchronously cancelled through OTP's file API.
Such a startup returns failure; a later device inherits the already-dead opener and exits through OTP's owner monitor.
The failure return does not claim that this future device has already terminated.

The internal accounted-open operation returns an opaque cleanup ticket along with the ordinary writer result.
It exposes at most two process identities to the endpoint's private monitor set.
A ticket releases its reservation only after the guardian confirmed known-child cleanup and both guardian and admission have actually exited.
Snapshots never wait or enqueue fresh monitor messages.
Failure before any real device was registered or discovered remains `Pending`, even if a late device later exits; pure input rejection creates no resources.
Event admission also caps each encoded record at 512 bytes including the RFC 7464 delimiters, before queue insertion or timestamp advancement.

Native startup regressions use a scoped file-service intermediary that forwards real OTP operations while preserving the original requester PID.
They stop directory checks, file open, initial header writes and probe close separately;
the header/close barrier requires an actual queued device request.
Tests also cover owner death, successful late open after cancellation, a suspended caller,
queued readiness after expiry, and the retained opener/file monitor.
All observations are projected to booleans and fixed counts.
The intermediary restores the registered service and joins owned helpers before the case ends.

Retain an ephemeral failure directory before another run removes it with
`escript scripts/qlog_preserve.escript capture SOURCE_DIRECTORY ARTIFACT_NAME`.
The bounded collector accepts at most 256 regular `.qlog` files and validates
every JSON-SEQ header, event name, key, scalar range, empty endpoint, empty
header list, and length-only raw-data object against the strict writer schema
before making byte-identical copies under
`build/diagnostics/qlog-failures/ARTIFACT_NAME`. Its deterministic manifest
records source and artifact paths, per-trace and aggregate SHA-256 identities,
event counts and first/last times, duration percentiles, maximum event gaps,
and the receive-to-close quiet interval that exposes an otherwise hidden drain
outlier. Timestamp regressions and missing lifecycle endpoints are retained as
bounded sequence findings rather than preventing collection of the failure
that needs investigation. The manifest contains no payload, endpoint, header,
key, token, or process value; copied qlogs are payload-free but remain
explicitly non-shareable local evidence. Recheck a retained directory with
`escript scripts/qlog_preserve.escript verify ARTIFACT_NAME`.

For scheduling failures which appear only under OTP `cover`, the coverage
harness can repeat one exported zero-arity test in the same instrumented VM:

```sh
escript scripts/coverage.escript diagnose NAME SOURCE_ROOT EBIN MODULE TEST REPETITIONS
```

This mode is diagnostic and can never satisfy either coverage gate. Its schema
2 report records every attempted repetition, including the first failure, with
the typed outcome, duration, full payload-free runtime snapshot, deltas from
the initial and previous snapshots, and a bounded failure-reason tail. Timing
evidence includes nearest-rank p50/p95/p99 and a deterministic slowest
repetition for all attempts and separately after excluding the first warm-up;
a one-attempt run reports the post-warm-up distribution as `null`. Repetition
counts are bounded from 1 through 1,000 and each execution retains the same
finite four-minute watchdog. This provides a reproducible path from a rare
live failure to a focused Red case without weakening the complete-suite gate.

## Qualification campaigns

`mise run check` runs change verification on each pull request and merge group.
It checks all three packages, documentation, packaging, API boundaries, static rules, secrets, and dependency closures.
The platform jobs keep macOS, Windows, and OTP 28 and 29 coverage.

`mise run source-candidate` adds fixed-count stability repetitions, SBOM generation, and the full release qualification inventory.
It keeps property, fuzz, model, coverage, interoperability, credentials, fault, performance, and soak checks at the release boundary.
The release verification workflow runs only by manual dispatch.
It divides one million cases or transitions across eight independent shards and keeps uploaded evidence for seven days.
The informational hosted soak job is removed because its timing did not provide qualification evidence.
The source-candidate gate keeps the soak check.

`mise run property`, `mise run fuzz`, and `mise run model` run bounded deterministic campaigns.
The generated corpus entrypoints also accept explicit seeds.
A shard report records its seed, size, source digest, and result digest so repeating one failing shard does not require replaying the whole campaign.

Before either campaign runs, the harness tests its own failure locator. On a
corpus failure it reruns deterministic prefixes with binary search, records the
smallest failing generated prefix and both case indexing conventions, and
writes a bounded exception reason, bounded stack trace, source digest, and
exact replay command to `build/campaign/<mode>/failure-shard-*.json`. A failure
that does not repeat is explicitly marked non-reproducible. Prior Ready reports
for the same shard are removed before execution so stale evidence cannot mask a
new failure. The source digest includes all three package manifests, the
campaign harness and selected corpora, and every file recursively discovered
under each production `src` tree. Harness self-tests reject a missing or
non-canonical production path, so changing implementation or FFI code always
invalidates older campaign evidence.

The default property and fuzz campaigns each run 10,000 generated cases for three independently reported families: HTTP/3 wire and QPACK, QUIC core wire and TLS, and the unified HTTP MASQUE receive boundary.
The MASQUE property family checks every receive transition against an independent counter model.
Every generated property case also validates an HTTP/1 proxy request and executes a supervised, default-deny DNS/socket setup through idempotent cleanup.
Successful cases feed both a spoofed source and the exact resolved address-and-port through the target-socket transition, bind that socket to one request-stream resource, and select socket-unusable, request-stream-ended, or application-close termination from the reproducible seed.
They then verify first-reason stability, duplicate notification convergence, and that packets arriving afterwards are discarded by the inactive lifetime check before source or payload inspection.
Its fuzz family retains malformed variable-length integers, non-byte-aligned input, unknown contexts, and oversized Context ID zero payloads, and injects every retained or generated byte string as a resolver answer.
Only exact IPv4/IPv6 widths may reach the socket callback.
Drop, abort, setup, and cleanup evidence contains saturating counters and typed reasons but never retains input payloads, target names, socket values, or callback exception terms.

The focused MASQUE fault suite additionally forces resolver and socket
timeouts, worker heap exhaustion, callback panics, deliberately malformed
Erlang return terms, over-limit and mixed DNS answers, DNS rebinding policy
filters, IPv6 literals, source-address and source-port spoofing, oversized
spoofed payloads, concurrent cleanup, and cleanup retry. A live unconnected
IPv4 loopback fixture also carries the operating system's observed ephemeral
source port through the same transition and closes both fixture sockets in
`after` blocks. Bound lifetime faults additionally force request-stream close
timeouts and abnormal exits while proving socket cleanup still runs, caller
mailboxes converge, and concurrent socket/stream notifications preserve the
first causal reason. Adapter return
validation runs inside the same monitored deadline/heap boundary as the
callback. Timeout paths wait for worker termination and assert caller-mailbox
convergence; resource snapshots expose only state and saturating cleanup
counters.
The bound-session concurrent-terminal regression uses a two-sided release
barrier created by the cleanup worker, so it proves first-reason and single-run
cleanup semantics without racing a sleep against the adapter deadline. Its one
payload-free trace retains both typed notification outcomes, closing/final
state, notification count, per-resource attempt counts, and cleanup-event
cardinality; the stability matrix repeats it in isolated fresh VMs.
The lower-level socket close race uses the same owner-created barrier and
retains both close outcomes plus in-progress/final resource snapshots. Timeout
and retry behavior remains a separate five-millisecond subcase, so neither
contract depends on scheduler timing from the other.
Idle activity and idle expiry also use separate live sessions. Sixty-four
successful sends run under a five-second idle window and finish by explicit
application close; an independent no-activity session drives the real owner
deadline. Both retain one bounded payload-free trace, and an unexpected send
is converted to a redacted I/O kind plus idle/lifetime/socket states before the
test fails, never the opaque session or native socket term.
Every generated MASQUE property case, and every valid-width fuzzed resolver
answer, derives different positive socket setup and operation deadlines. The
socket-open adapter must observe only the setup value and the eventual
first-reason cleanup must observe only the operation value. This turns deadline
separation into 10,000 reproducible cases per campaign instead of relying only
on the focused unit regression.

The production CONNECT-UDP socket tests use a real IPv4 loopback echo peer.
The setup callback creates a dedicated OTP socket owner and the stable caller
must adopt it before a finite setup lease expires, so a killed setup worker
cannot orphan the port. The owner grants at most eight command slots, arms the
socket with `active, once`, retains at most one delivered packet, and admits
only one receive waiter. Tests observe those limits while two replies are in
flight, distinguish busy from timeout, verify no late caller-mailbox reply,
and prove that unknown contexts and oversized payloads never reach the OS send
counter. Additional fault rows pass a closed production-shaped handle, kill or
suspend the socket actor, flood every command grant, and let the stable owner
process exit. They prove actor/mailbox/resource convergence. An independent
one-slot terminal-event waiter can remain outstanding alongside the datagram
waiter; a production-shaped `udp_closed` event drives the same
socket-unusable/request-stream cleanup transition without another datagram
operation. Tests distinguish event timeout, duplicate-waiter busy, actor crash,
and normal application close, and verify that the two waiter credits converge
independently. The duplicate-waiter regression keeps its first waiter on a
separate five-second budget, observes registration before attempting the
duplicate, and closes the session after `Busy`; timeout behavior remains in its
own focused test. One bounded assertion records registration, queued command,
timeout and rejection counters, both typed waiter terminals, close outcome, and
the final socket state without retaining the session, socket, endpoint, or
payload. Its snapshot reports requested and effective socket-buffer sizes,
command/packet credit,
Not-ECT and Don't-Fragment capability, traffic totals, timeout totals, and
socket-failure totals, but no endpoint, payload, PID, socket term, or OS reason.
The separate setup snapshot records monotonic elapsed milliseconds and timeout
bits for DNS, socket open, socket adoption, and cleanup. DNS and socket-open
traces also record callback-start state, scheduler queue time, callback time,
and whether the bounded supervisor itself expired. Tests cover success,
adapter-reported timeout, panic, malformed return, heap exhaustion, and hard
deadline expiry without retaining adapter results. The socket-deadline test
gives its preceding DNS phase a separate 2000 ms budget so fresh-VM code loading
cannot legitimately change the phase under test; DNS expiry remains covered by
its own test. A production loopback test verifies the adoption event pair. Both
the diagnostic test and command-credit flood run thirty times in isolated fresh
BEAMs; command I/O keeps its 1 ms deadline but socket-owner cold start receives
an independent 1000 ms setup budget.
Listener diagnostics are subjected to two 20,000-update multi-writer races.
They must retain all 80,000 outcome updates while every snapshot marked
consistent preserves the cross-counter invariant. A separately injected
orphaned active-writer epoch proves that later writers still finish and that a
reader returns `consistent: False` within its finite retry budget.
An oversized exact-source target reply has a separate regression boundary: a
live loopback test proves that its bytes are counted and then discarded before
the caller mailbox, where only a typed Packet Too Big report is visible. Exact
IPv4 Fragmentation Needed and IPv6 Packet Too Big vectors pin ICMP, quoted IP,
UDP, and pseudo-header checksums; maximum-length tests pin quote truncation and
advertised MTU arithmetic. Deterministic traces cover rate-limit exhaustion and
refill across BEAM's potentially negative monotonic epoch, prohibited multicast
destinations, overflow rejection, permanent capability caching, a writer left
behind an odd seqlock, and 20,000 concurrent snapshot observations. The
snapshot invariant requires one terminal outcome per oversized packet and
always reports zero retained payload bytes.

The default-listener regression also records both HTTP/3 capacity classes: its
pre-response guarantee must equal the post-response
`guaranteed_datagram_size`, must never exceed the point-in-time maximum, and
must survive thirty isolated fresh-BEAM repetitions. A pure QUIC state-machine
test drives a validated 9000-byte path, 256 retained ACK ranges, and a
black-hole reset to 1200 bytes; the same guaranteed payload must remain
queueable and the protected ACK-plus-DATAGRAM packet must fit the collapsed
path. This is the causal guard against confusing transient ACK clearance with a
safe fixed MASQUE socket ceiling.

Unprivileged development runs normally observe the typed `PermissionDenied`
raw-socket result. That is a passing finite-failure test, not evidence that an
ICMP packet reached a peer. Successful delivery requires the separate
privileged platform/interop qualification row; the deterministic wire vectors
remain runnable without elevated privileges.
A live H3 composition holds the event waiter, injects a production-shaped
socket failure, releases both waiters, runs first-reason cleanup once, and
observes H3_REQUEST_CANCELLED at the peer. The protocol-neutral Context bridge
and independent H1/H2/H3 cancellation cases fix the remaining adapter mapping.
Continuous post-success proxy-session consumers for every H1/H2/H3 tunnel
remain a separate open qualification step; the deterministic close fixture
explicitly injects OTP's canonical
`udp_closed` message after closing the real port because external close does
not itself notify the controlling process.

`mise run hostile-peer` starts each selected test module in a fresh BEAM and
covers stalled peers, UDP/mailbox floods, actor crashes, aggregate memory,
connection/handshake admission, client endpoint memory, parser bombs, and
slow-consumer backpressure. Its families, packages, and module selection live
in the machine-readable `hostile_matrix` section of `qualification.json`.
Both the runner and status generator consume that section; the latter resolves
the current test count from source and rejects a handwritten matrix count.
The runner removes its older Ready report before starting. Each selected module
runs in its own BEAM; on the first failure the runner writes the completed
package/module/test totals plus exit status, bounded child-exit observations,
and typed EUnit failure evidence before returning nonzero. Raw output and its
digest are omitted, including on failure. A successful report is accepted
only when the independent verifier sees every configured package, module, and
test completed under the current source digest.
The QUIC credit rows distinguish application queue completion from a FIN ACK
through the public `client.send_finished` probe. Pure sender, stream, and
connection tests permit one immediate DATA_BLOCKED or STREAM_DATA_BLOCKED
advisory per unchanged limit and rearm it only when MAX_DATA or
MAX_STREAM_DATA increases. The live flooded-connection recovery case arms a
bounded actor trace before traffic, records connection/path snapshots on an
ACK timeout, and has a 100-iteration local stress reproduction for socket,
process, and listener convergence. This prevents a blocked write from becoming
the previous 64-packets-per-worker-turn busy loop while keeping loss recovery
responsible for retransmitting an emitted advisory. The aggregate-memory
backpressure case also waits on a bounded, causal refusal barrier instead of
assuming that a stopped remote flood means the listener reply has already
reached the connection actor. A missed barrier retains only five finite
accounting values -- buffered, retained, unmeasured, granted, and refused --
so a loaded-run failure identifies the stalled grant transition without
retaining application payload or a native handle.

The HTTP/2 graceful-drain regression uses a release subject created by the
response-body worker and advertises that subject to the fixture only after the
pull has started. This ownership is part of the test contract: a Gleam subject
can be received only by the process that created it. A public fixed-size phase
snapshot records listener/connection readiness, drain request,
per-connection command and receipt, GOAWAY attempt and successful write, and
final drain completion. The test waits for the write-side causal barrier before
reading the wire under a separate 10-second deadline. Its bounded wire trace
records read attempts, byte count, observed GOAWAY pairs, and a typed terminal
phase; it never prints a socket or PID. GOAWAY observation, premature drain
reply, body release, and drain completion remain one causal assertion, then
socket/listener/executor cleanup is checked separately. Five concurrent
diagnostic writers perform 20,000 updates each while readers check cross-field
invariants, and an orphaned-writer test requires finite inconsistent fallback.

`mise run stability` turns scheduling-sensitive regressions into a repeatable
gate rather than a shell-loop anecdote. Its targets and repetition counts live
in `qualification.json`; the runner validates that schema, starts the selected
zero-arity test function in a new BEAM VM for every iteration, and removes an
older Ready report before the first execution. The success report records the
exact source digest, target identity, configured count, and completed count.
On the first failure it writes `build/fault/stability.json` before returning
nonzero, including the failing iteration, exit status, original output byte
count, bounded process observations, and typed EUnit failure records. It keeps
neither raw output nor an encoded tail or guessable output digest. Failed
reports never qualify for the audit bundle. The runner self-test rejects unsafe
module/function identifiers, unknown packages, duplicate targets, zero or
excessive repetitions, and invalid output bounds, and checks tail truncation
and digest metadata. It also starts an isolated child VM that must fail for an
injected reason, verifies the captured status and marker, and proves stale
report removal without needing a package build.

For investigation without replaying the whole matrix,
`escript scripts/test_matrix.escript stability <target> [runs]` selects only a
manifest-declared target and still starts a fresh BEAM for every run. It writes
`build/fault/stability-target-<target>.json` with the current source digest and
bounded first-failure evidence. The report is explicitly marked
`DiagnosticTarget` and `shareable: false`, uses a path separate from aggregate
evidence, and cannot satisfy the full stability gate. Target names and optional
1..1000 repetition overrides are covered by the runner self-test.

The audit-bundle gate independently recomputes the matrix runner's declared
source set and rejects stale hostile-peer, stability, or credential reports.
For stability evidence it also requires schema 1, a non-empty target set,
exact configured/completed totals, and a Ready result with complete repetitions
for every target. Its self-test proves that stale digests, partial aggregate or
target counts, and non-Ready reports are rejected before bundle assembly. The
hostile-peer, stability, and aggregate credential tasks invoke that verifier
immediately after writing their report, so stale evidence cannot survive until
a later source-candidate run.

Before assembly, the audit-bundle gate also scans every candidate artifact as binary data and rejects credential-shaped JSON fields, HTTP authorization and cookie headers, private-key material, connection endpoint, authority, or address fields, `PORT=` assignments, and URLs containing user information.
Its bounded self-test covers each hostile form, malformed binary input, and safe near-misses.
Shareable evidence must replace a sensitive value with a finite typed classification, or with an already required source or artifact digest when identity binding is necessary; raw values must not appear in success or failure artifacts.

`mise run credential-matrix-local` exercises live
RSA-PSS, ECDSA P-256/P-384, Ed25519, mTLS, HRR, rotation, resumption, 0-RTT
fallback, expiry, revocation, and mismatch behavior. The aggregate credential
gate accepts only reports for Ubuntu 24.04, macOS 15, and Windows 2025 on OTP
28 and 29 with the exact current source digest.

`mise run structured-fields-oracle-setup` obtains the HTTP Working Group's
Structured Field test corpus at the exact commit and per-file SHA-256 values
recorded in `standards/structured-fields-oracle.json`. It refuses a different
origin or a modified checkout. `mise run structured-fields-oracle` then starts
from a fresh package build, exercises all 1,591 parse vectors through the
public RFC 9651 API, checks canonical serialization for every mandatory valid
case, and writes corpus and implementation digests to
`build/structured-fields-oracle/report.json`. Its six advisory vectors are
reported separately: four are accepted, while missing base64 padding and
nonzero pad bits are rejected under the documented canonical RFC 4648 policy.
The runner's self-test covers all three field shapes and malformed lock,
fixture, digest, count, and implementation-result paths before the corpus is
trusted.

Coverage reports two deliberately bounded metrics across production Gleam,
Erlang, and FFI modules. The line metric is OTP `cover` execution of physical
lines in the generated Erlang artifact. The second metric enumerates
multi-clause alternatives in the compiled BEAM debug abstract forms. An
alternative is covered only when OTP `cover` reaches an observable artifact
line that belongs to that alternative and to no sibling alternative in the
same compiled decision. A missing sibling, observable line, or
sibling-exclusive witness fails the coordinate model instead of silently
removing the alternative. The policy and JSON retain the historical key name
`branches`, but this is an observable compiled clause-alternative metric. It is
not a claim of general branch coverage: short-circuit Boolean outcomes, guard
outcomes, receive timeouts, and exception paths are not counted unless they
appear as multi-clause alternatives in those forms. No manual or generated
clause exclusion is applied.

Execution coordinates never masquerade as original Gleam line numbers. Gleam
artifact lines are attributed by compiled `{name, arity}` to Glance function
spans, including attached attributes. Erlang and FFI attribution uses exact
source lines only after the source and build artifact are proven byte-identical.
Changed-source selection uses overlap with those source spans. If any changed
range cannot be attributed, the complete module is selected conservatively and
the fallback and unattributed ranges are retained in `changed_selection`.
Untracked source likewise selects the complete module. Reports therefore show
exact generated-artifact coordinates and the corresponding source span, not a
claim of exact Gleam execution lines.

`mise run coverage-coordinate-audit` checks all three freshly built packages
without running their suites. It binds each source, generated artifact, and
compiled BEAM; validates source regions, compiled functions, clause
alternatives, and sibling-exclusive OTP `cover` witnesses; and emits one
coordinate-model digest per package. `mise run coverage-capture` runs this
audit immediately after resetting stale coverage output and before the first
expensive repeated suite, so coordinate drift fails fast.

The changed-source gate requires 100% artifact-line and compiled
clause-alternative coverage; the whole-tree gate requires 95% and 90%
respectively. Thresholds, coordinate methodology, repetition bounds,
quiescence, and the complete capture source set live in
[`coverage-policy.json`](../coverage-policy.json). Both gates write a report
before returning nonzero, so a deficit remains auditable. Each capture first
tests the coverage harness itself, then runs each package suite repeatedly in
the same instrumented VM. It performs at least ten and at most thirty
repetitions, stopping successfully only after three consecutive repetitions add
no artifact-line or clause-alternative coverage. Hitting the finite maximum
without that quiescent tail is a failure. The wider bounded window was fixed
after a ten-run capture continued to discover scheduling-dependent production
paths in its final repetition. This makes suite re-entry and cleanup part of the
gate while forming an auditable union of scheduling-sensitive paths.

Package-specific `build/coverage/*.capture.json` artifacts retain each
repetition's duration, cumulative and newly reached artifact/source
coordinates, and payload-free process, port, network-port, OTP-socket, ETS,
mailbox, run-queue, and memory observations. Test time and cleanup-settle time
are recorded separately. Before taking that repetition's coverage snapshot or
starting the next repetition, the harness waits for a bounded runtime settle:
all globally enumerated fixed `quic_core.*`, `http3.*`, and `http.*` actor labels, network
ports, and OTP sockets must return to their cold baseline, and after the first
fully settled repetition total process, port, and ETS counts must return to
that warmed baseline. Three restored, non-growing samples are required; a
nonzero stable plateau is not quiescence. The 60-second bound covers the finite
QUIC Closing/Draining lifetime and bounded qlog shutdown, and a timeout is
retained as a failed repetition rather than hidden by killing actors. Immediate
state, every 100-millisecond settle sample, per-label counts, observed peaks,
and cold/warm/final deltas remain in the JSON. Memory, run-queue, and mailbox
values remain diagnostic observations rather than allocator-sensitive
thresholds. This per-repetition barrier prevents a prior actor's terminal code
or scheduler/port load from contaminating the following repetition. Every capture is
bound to the complete production/test/fixture and harness source set, its
compiled artifacts and coordinate-model digest, OTP/ERTS version, and the
exported `.cover` digest. Reports reject stale, modified, incomplete, or
mismatched three-package captures, suppress repetitive OTP import notices, and
rank the ten modules with the largest combined artifact-line and compiled
clause-alternative deficit. The JSON report retains every module metric,
generated-artifact coordinate, source span, coordinate method, and changed
selection reason.

Changed and unattributed source ranges serialize as objects containing `first_line` and `last_line`.
Coverage self-tests pass no-change, untracked,
attributed, and conservative whole-module selections through the actual JSON encoder and decoder.
This catches a report failure that otherwise occurs only after all three package captures finish: Erlang range tuples cannot be encoded directly.
The selection algorithm and coverage thresholds are unchanged.

Both `coverage.escript report full` and `report changed` run in an owned BEAM with a 300-second absolute deadline, an 8 MiB output limit and a 256 MiB per-process heap limit including referenced binaries.
Output does not extend the deadline.
`build/coverage/report-<mode>.process.json` records the actual exit and resource-limit observations.
The selected report and shared `coverage-evidence.json` from an older attempt are removed before startup.
The known `report-<mode>.attempt.json` sidecar receives a fresh nonce first, so an earlier process record cannot validate a later invocation even when both would produce identical metric bytes.
The child writes both new documents into its private run directory, finishes cover and I/O cleanup, then writes a nonce-bound completion receipt containing their hashes.
Only after observing child exit does the parent validate that receipt and publish the captured bytes.
Completed threshold failures retain their normal schema-2 `Blocked` reports; incomplete or interrupted work cannot leave authoritative `Ready` documents.
Existing metric schemas and the 100/100 and 95/90 thresholds are unchanged.
Bundle verification requires the process and attempt records, matches their nonce and completion receipt, checks successful exit without timeout or output exhaustion, and recomputes the runner-source and both document hashes.
CI and nightly uploads include the coverage directory and the root aggregate file.

Ordinary coverage self-tests include `scripts/coverage_report_test.escript`.
Its metric producer is explicitly synthetic; it exercises the real report dispatch and child lifecycle with normal and blocked completion, ongoing output, stalled cleanup, output floods, early exit, partial documents, private failures, corrupt nonce/hash/schema receipts and missing exit observations.
These controls verify execution and publication, not measured coverage values.

Each completed package capture also writes `build/coverage/diagnostic/<package>.gaps.json` from the still-running instrumented VM.
This preserves its actual uncovered source/artifact coordinates even when another package cannot complete.
The diagnostic includes the capture,
source, coordinate-model, and exported coverage digests, plus the observed repetition count and stop reason.
It explicitly cannot satisfy a coverage gate and makes no changed-source claim.
A new capture removes its previous diagnostic before beginning.
Self-tests exercise real executed and unexecuted fixture paths;
mutations that remove gap coordinates or claim gate satisfaction must fail.

Coverage test discovery begins from each package's `test` source tree and then
inspects compiled exports for zero-arity `_test` and `_test_` entrypoints; it
therefore includes Erlang EUnit modules whose module name does not end in
`_test`. The entrypoint total is retained beside the module list, and synthetic
self-tests fix suffix and arity handling. A compact, source-bound
`coverage-evidence.json` is generated from the same validated report so the
conformance document never relies on hand-copied percentages or ephemeral
`build/` contents.

Documented Gleam examples are annotated with package and module identifiers.
`mise run examples` extracts every fence, rejects unannotated or duplicate
examples, compiles them offline against the package build, and executes each
`main` function. Current status and discovered counts are always read from the
generated [product conformance status](CONFORMANCE.md).

`mise run ffi-audit` checks every production Erlang module against the explicit FFI inventory, builds current BEAMs, and runs actual Dialyzer and compiled xref,
including the HTTP/3-to-private-core boundary.
PLT construction and type analysis run in separate owned VMs with absolute limits of 600 and 180 seconds, an 8 MiB output ceiling, and confirmed process exit.
Their compiler-graph actors have a 1 GiB heap limit including referenced binaries.
This limit is local to analysis VMs; application and test actors retain their 256 MiB limit.
On native OTP 29,
the initial 256 MiB attempts were killed during both PLT construction and PLT loading; successful analysis sampled a 390 MB actor, and PLT construction sampled 906 MB across the VM.
Sampled peaks are lower bounds, not exact maxima or a whole-VM memory limit.

`build/ffi-analysis/{plt,analyze}.json` retains source/BEAM input hashes, runtime and child compiler identity, nonce, phase bounds, sampled memory, actual exit,
and fixed type-finding locations.
Per-attempt child and execution records are kept under nonce directories.
Raw exceptions and output tails are not published.
The runner's self-tests exercise analysis-only heap scope, killed workers,
deadlines, output exhaustion, secret-bearing failures, and invalid records.
