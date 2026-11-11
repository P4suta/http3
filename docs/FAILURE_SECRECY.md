# Failure-log secrecy contract

Test failures and qualification failures are treated as untrusted data.
A failed assertion, callback, peer, compiler, or child process may contain an HTTP body, credentials, a cookie persistence key, a destination, a runtime handle, or exception arguments.
None of those values is suitable for CI logs or a shareable audit bundle.

`scripts/failure_secrecy_audit.escript` enforces three boundaries:

1. Repository scripts that catch an exception may print only the finite typed projection from `diagnostic_failure_details/3`.
   The projection keeps a stable class, a fixed failure category, and at most 16 verified module/function/arity/line frames.
   It drops reasons, frame arguments, source paths, PIDs, references, sockets, and peer-controlled values.
2. CI package tests must use the owned qualification runner.
   That runner has an absolute deadline, an output ceiling, disabled crash dumps, hidden Windows children, and confirmed child exit.
   Raw child output is available only inside the finite collector and is removed before evidence publication.
   On Windows the runner passes the direct `HPCON` value to the process attribute,
   clears all three parent standard-handle slots only around `CreateProcessW`,
   and restores every slot in `finally`.
   The child starts suspended, joins the kill-on-close Job before resume, and keeps the ConPTY input writer alive until root-process exit.
   Abnormal NTSTATUS values are reduced to a finite public category before any protocol frame is written.
   Raw ConPTY bytes still count against the output ceiling.
   After that check, the collector removes complete CSI and OSC terminal controls from successful output and from the value passed to a failure projector.
   An unterminated control consumes the bounded remainder so an OSC title path cannot escape.
   Evidence retains only `terminal_control_bytes_removed` as a finite count.
   A finite Erlang lexical scan inventories every executable `open_port` call in repository runners.
   It tracks comments, strings, quoted atoms, escaped characters, and line numbers across line boundaries, so source snippets used by mutation tests cannot be mistaken for native child launches.
   Every actual call must still prove hidden startup, an owned process tree, an absolute deadline, bounded output, and observed exit or reap.
3. Every currently present artifact that the audit bundle can publish is decoded with duplicate-key rejection and walked under finite depth, node,
   string, per-file, file-count, and total-byte limits.
   The walk rejects raw authorization and cookie headers, credentials, private keys, URL userinfo,
   user home paths, NUL-separated persistence keys, BEAM handles, output tails,
   raw bodies and payloads, exception arguments, and non-typed reasons.

The source inventory also classifies assertion sites that mention sensitive concepts.
Fixed protocol vectors and interop fixtures are counted separately from runtime-sensitive values.
These locations are review data rather than a copy of the assertion expression: the report stores only repository-relative path, line, and classification.

The Windows visibility watcher is part of this boundary.
It runs a native parent/visibility self-test before it can report success and opens each `System.Diagnostics.Process.Handle` while the enumeration result is live.
An owner-bound run receives exactly one PID and UTC start time through a random token-derived private file written with exclusive `CreateNew` and durable flush.
It verifies that live identity, walks a finite retained ancestor chain,
and observes only the exact root and descendants.
A simultaneous unrelated allowlisted process cannot enter the event, visibility, lineage, termination,
or residue sets.
The fixture supplies such an adversarial Python process.

The watcher retains the exact allowlisted name, PID, start time, and opened handle instead of querying identity fields after a short-lived process exits.
These values, the owner token and the private path never enter JSON or an error.
Both handshake files are deleted on every exit path.
An inaccessible owned handle, incomplete owned visibility or lineage, visible owned target, or unconfirmed owned residue makes the proof fail closed.
`conhost.exe` is observed but never terminated by the watcher.
Unbound system-wide observation is diagnostic only and cannot satisfy the paired audit.

Run the adversarial controls first, then the actual gate:

```text
escript scripts/failure_secrecy_audit.escript --self-test
escript scripts/failure_secrecy_audit.escript audit
```

The self-test mutates every retained-value class, duplicate JSON keys, bounds,
the two former raw exception reporters, direct CI execution, terminal-control stripping, the executable-port lexer, and the Windows ConPTY and watcher invariants above.
It also scans the current repository port inventory, rather than testing fixtures alone.
Its private marker exists only in memory and one temporary file; the file is deleted before the self-test succeeds.
Each failed mutation or current-source inventory is identified by an `audit_control_id` selected from a finite allowlist.
Its fixed failure code distinguishes a mutation that was not applied from one the audit incorrectly accepted;
arbitrary exception values collapse to `unknown`.
A current-source contract mismatch also retains only a bounded numeric `audit_check_index`.
Each content-addressed report under `build/failure-secrecy/reports/` contains no rejected value, source line, output tail, exception payload, or digest of rejected bytes.
It binds the source, audit tool, authoritative artifacts,
runtime, and crash-residue snapshot, and retains fixed audit and self-test replay commands.
