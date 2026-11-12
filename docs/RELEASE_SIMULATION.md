# Unpublished release simulation

`escript scripts/release_sim.escript` builds the three `0.1.0` Hex v3 archives,
installs their exact bytes into a temporary registry, compiles them in dependency order, and runs an empty consumer of each package.
It never publishes a package,
changes its version, creates a signed commit, or contacts a release registry.

Run `mise run fresh-build` first.
The simulation requires verified current builds of `quic_core`, `http3`, and `http`, and rechecks those builds after execution.
The final report also binds the complete authored source and settings identity.
`escript scripts/release_sim.escript --verify` rechecks the report and the retained artifacts.
`--self-test` executes compiler, consumer, archive, and hostile-evidence regressions using separate temporary output directories.

## Execution and failure evidence

Each run writes to `build/release-sim/run-<nonce>`.
Existing runs remain available for diagnosis.
Starting a run invalidates the previous aggregate report; a failed run preserves successful stages and the last active stage in `report.json`.
Success requires observed child exit, a matching invocation nonce, actual EUnit leaf completion, current input hashes, and unchanged executed BEAM bytes.

Gleam runs with `compile-package --no-beam`, so it does not launch an unowned `erlc`.
Generated Erlang then compiles in an owned VM.
Compilation uses OTP's `compile:noenv_file` with source-bound options, so `ERL_COMPILER_OPTIONS` cannot silently change the consumer's behavior.
A real macro-injection regression checks this isolation.
The compiler and its OTP inliner descendants have a maximum heap of 134,217,728 words per process,
including referenced shared binaries: 1 GiB on the supported 64-bit runtimes.
Ordinary consumer execution retains the separate 33,554,432-word limit, or 256 MiB per process.
These are process limits, not a claim that the entire VM uses at most that amount of memory.

Compilation has one absolute 120-second deadline per package.
Consumer execution has a 30-second EUnit deadline and a 35-second VM deadline.
Child output is limited to 8 MiB.
The owning runner waits for process exit and kills an unresponsive owned VM after its deadline; crash dumps are disabled.
A compiler worker result arrives with its process monitor's `DOWN`, so success includes worker termination.

Compiler failures retain only the expected module name, fixed stage and cause,
bounded error/warning counts, and completed module digests.
Compiler text, exception arguments, application values, stdout tails, and hashes of stdout are excluded from shareable reports.
An intentional lower compiler limit proves that resource failure is reported with completed work intact.

Archive paths, duplicate names, source inventory, header files, metadata, dependency versions, and both reproducibility passes are checked.
In particular, Erlang `.hrl` files such as the Brotli static tables are part of the archive and the compilation evidence.
The complete `LICENSES` directory accompanies each package, including the upstream Brotli license in `http`.
Each generated module must have exactly one accounted-for BEAM file.

Archive members use the regular-file mode `100644`, zero modification time,
and zero user and group IDs.
The explicit mode matches OTP 28's binary-member default, which that runtime cannot override; OTP 29 honors the mode option.
Both archive layers are checked when created and again by the retained-evidence verifier.
`--self-test-archive-modes` builds all three packages, and `--self-test-archive-metadata` changes mode, time, user, and group fields in each layer while rebinding checksums and both reproducibility-pass hashes.
The verifier must reject all eight changes.
Both controls also run as part of `--self-test`.

## Supply-chain document formats

The SBOM follows [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/).
Every dependency edge targets a component's `bom-ref`.
It includes the three local archives and the three external Gleam libraries actually supplied to the compiler,
with versions read from their verified OTP application metadata.
External library hashes and inventories remain in the accompanying release report; archive hashes identify the local package components.

The provenance file uses an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) with the [SLSA provenance v1 predicate](https://slsa.dev/spec/v1.2/build-provenance).
Using this document format does not claim a SLSA Build level.
The file is an unsigned local statement and has no external attestation or independently trusted builder.
The report's ephemeral Ed25519 signature verifies only the ordered archive digest payload; it neither signs this provenance statement nor establishes publisher trust.

The build type `urn:http3:release-sim:archive-consumers:v1` means the exact procedure described above.
Both `externalParameters` and `internalParameters` are empty objects: package selection, versions, compiler flags, and budgets come from the source-bound scripts.
To reproduce a statement, restore its source and compiled dependency inventories, produce verified fresh builds, and run the command above with the recorded toolchain.
Archive bytes are expected to reproduce; invocation nonces, generated BEAM paths, and the ephemeral signature are deliberately unique.

The builder identifier `urn:http3:release-sim:local-untrusted:v1` represents a tenant-controlled workstation or job, including its operator, OS, runtime, compiler,
dependency cache, and writable workspace.
It provides no independently verified trust boundary.
Its metadata `invocationId` is `release-sim:<nonce>` and identifies the retained directory.
All statement fields are generated by the local script.

`subject` contains the three archive filenames and their SHA-256 digests.
`resolvedDependencies` contains the archive-source inventory digest, complete workspace evidence identity digest, and the supplied dependency inventory digests.
Inventory digests hash the UTF-8 JSON emitted by OTP's encoder; the archive-source digest hashes package name and sorted path/digest pairs separated by NUL bytes.
`byproducts` contains the SHA-256 digest of each consumer's actual `execution.json`.
The release verifier reconstructs these fields from verified sources and execution artifacts instead of accepting document shape alone.
