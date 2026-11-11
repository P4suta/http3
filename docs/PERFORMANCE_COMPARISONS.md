# Conditions for paired performance comparisons

The comparison foundation does not issue performance qualification.
It checks observations and the compatibility of an explicitly selected pair.
Every `pair_preflight` result is `Blocked`, even when `conditions_match` is true.
The aggregate's pinned-reference and checked-in-baseline comparisons remain blocked until actual paired endpoint measurements and their controller evidence are implemented.
Matching numbers or a hand-authored host map cannot complete that evidence.

Run the independent controls and capture a host observation with the pinned Erlang runtime:

```sh
escript scripts/performance_comparison.escript --self-test
escript scripts/performance_comparison.escript --capture
escript scripts/performance_comparison.escript --verify
```

`--capture` optionally accepts `sha256:` followed by 64 lowercase hexadecimal digits.
Tags, uppercase hashes, and other strings are rejected.
That input is always labelled `declared`; this process cannot inspect the container engine from inside a container.
Omitting it records `unavailable`.
Neither case is an observed image identity.

The current result is `build/performance/comparison/current-host.json`.
`Captured` means the observation helper completed and its evidence validated;
the nested observation can still be `Incomplete`, and `qualification_status` is always `Blocked`.
Exit zero from `--capture` or `--verify` has the same limited meaning.
Starting a capture invalidates the previous result.
The selected nonce directory retains the exact three helper BEAMs and `child.json`.
The verifier checks those bytes, the nonce, current authored-source identity,
current compiled helper identity, runtime identity, no output, the absolute 30-second bound, and observed child exit.
A failed process or failed validation retains a failed record without stdout, stdout hashes, or exception values.
The child uses the shared 256 MiB per-process heap bound and 8 MiB output cap.
The controls use a separate bounded VM and retain completed EUnit case counts.

The helper is independent of the library packages and compiles its own retained code.
It therefore does not claim a package fresh-build manifest.
Future measurement receipts must additionally bind the actual endpoint package or independent peer binary, dependencies, compiler, and fresh-build evidence.

## Observed host conditions

The initial supported topology is Linux with a unified cgroup namespace whose visible root is mounted at `/sys/fs/cgroup`.
The helper verifies that membership and mount relationship before reading limits.
Another topology is incomplete;
it never silently reads a parent or sibling cgroup's settings.
These are limits of the visible namespace root.
Limits imposed by ancestors outside the namespace are not observable here and still need the external launcher's evidence.

| Observation | Source and bound |
| --- | --- |
| Kernel hash | `/proc/sys/kernel/osrelease`, at most 256 bytes |
| Allowed CPUs | `Cpus_allowed_list` in `/proc/self/status`, at most 1 MiB |
| CPU model hash | Selected allowed CPUs in `/proc/cpuinfo`, at most 1 MiB |
| Governor hash | Each allowed CPU's `scaling_governor`, at most 256 bytes per CPU |
| Effective cpuset | `cpuset.cpus.effective`, at most 32 KiB |
| CPU quota and period | `cpu.max`, at most 256 bytes |
| Memory, swap, and PID limits | Corresponding cgroup `*.max` files, at most 256 bytes each |
| Scheduler counts | Actual ordinary and dirty CPU schedulers of the observing BEAM VM |

CPU lists must be canonical, ordered, unique and nonempty.
Each has at most 4096 CPUs; a range is checked against that bound before expansion.
The allowed CPU list must fit inside the cpuset.
Limits distinguish observed `unlimited` from zero and from missing values.
Observations never substitute a default for a failed read.
Missing files, unavailable governors, unsupported platforms,
unsupported CPU descriptions, oversized probes, and inconsistent conditions produce `Incomplete`.
Windows currently reports its observed scheduler counts and explicitly unavailable Linux groups.

Only hashes of the kernel release, selected CPU model fields, and per-CPU governors enter the record.
Raw model names, release strings, governor text,
mount paths, hostnames and environment variables are omitted.
The first CPU description parser requires the Linux x86 fields `vendor_id`, `cpu family`,
`model`, `model name`, `stepping`, and `flags` for every allowed CPU.
Missing or duplicate processor records fail observation.
Dynamic `cpu MHz` is excluded from the model hash.
This static identity does not replace the existing dynamic pressure, load, frequency, thermal and sampling observations.

The scheduler counts describe this observing VM.
Capturing in a separate helper VM does not establish a measured endpoint's scheduler configuration,
nor a Go peer's `GOMAXPROCS`.
A future runner must capture inside the actual measured process or bind that process's separately observed runtime controls.

## Pair contract

`performance_comparison:validate_host/1` validates the exact complete host schema.
`compare_hosts/2` requires equality of every condition and reports only fixed field names on mismatch.
Both accept exact atom-key maps or their exact JSON equivalents; missing, mixed, extra and unknown fields fail validation.

`performance_comparison:pair_preflight/3` takes a specification, a current side,
and a reference or baseline side.
The specification explicitly binds:

- comparison kind, protocol 1/2/3, client/server role, and workload digest;
- candidate source, other source and fixed counterparty identities;
- declared image digest, pair nonce, and current side's position 1 or 2.

Each side binds the same pair, protocol, role, workload, candidate identity,
counterparty and image.
It supplies its explicitly selected source, a distinct run nonce, the required opposing position, and complete host observations from before and after execution.
All four host observations must match.
Reversing pair order must be explicit in the specification.
Replayed run nonces, mixed pairs, changed roles or workloads, and any condition drift fail compatibility.

The expected source is never inferred from whichever implementation happens to support the new benchmark API.
A checked-in baseline must be selected and reviewed explicitly, and must differ from the candidate.
If it cannot express the declared workload, that comparison remains blocked with the API gap recorded.
A failed actual endpoint execution is a failure; it is not a zero sample or a reason to choose another source.

The checked-in HTTP/3 CSVs remain historical measurements.
They lack the new paired host/controller evidence, per-request p99 samples and sampled peak memory.
They must not be converted into current comparison receipts or used as denominators for a workload they did not execute.

## Required measurement-controller integration

The next runner must retain an independently observed container-engine receipt for each actual measured process: immutable image object ID, platform-specific image identity where applicable, launch CPU/cpuset/affinity/memory/PID settings,
namespace association and outer ancestor constraints.
It must verify a declared image against the actual selected container, rather than copying the declaration into an `observed` field.
This foundation deliberately rejects that promotion.

Both sides also need owned execution receipts, exact endpoint and counterparty binary/source/lock identities, measured-runtime settings, fresh builds where applicable, actual completed workload/trial counts, bounded raw latency and resource samples, cleanup and child exit.
The controller must bind the host observations to those same measured processes and to the pair's time interval.
The schema checks here are not a signature or a proof of computation: the controller remains the trusted observer of the executions it owns.

For a client-role reference comparison, keep the pinned server constant and alternate the candidate and reference clients.
For a server-role comparison,
keep the pinned driver constant and alternate the servers.
Use the same verified TLS, request/body/trailer checks, connection reuse policy, workload and matched host conditions.
A fixture that measures both native endpoints in one VM cannot establish either independent role comparison by itself.

After those receipts exist, the auditor must recompute ratios from the same sample definitions.
The declared reference thresholds are median throughput at least 70% and p99 latency at most 150%; the baseline thresholds are throughput at least 90% and p99 latency and peak memory at most 110%. Those bounds remain unchanged.
No ratio is evaluated or reported as passing by this foundation.
