# Performance verification

The performance harness is a reproducible local verification workload, not a
production capacity claim. It uses the public `http3/client` and `http3/server`
APIs over real loopback UDP with certificate-chain and hostname verification
enabled. No backend handle or test-only verification bypass is used.

## Fixed workloads

Run the pinned toolchain and each fixed workload from the repository root:

```sh
mise install
mise run benchmark
mise run load
mise run soak
```

| Task | Warm-up | Measured trials | Connections | Requests per connection | Payload |
| --- | ---: | ---: | ---: | ---: | ---: |
| `benchmark` | 1 | 5 | 4 | 100 | 1 KiB |
| `load` | 1 | 3 | 32 | 100 | 16 KiB |
| `soak` | 1 | 1 | 8 | 10,000 | 1 KiB |

Each worker opens one TLS-verified reusable connection and sends sequential
streaming POST requests. The server reads and verifies each complete request
body, echoes it in a 200 response, and the client verifies the status and body.
The measured interval includes client connection establishment, all request
round trips, connection close, listener stop, and cleanup convergence. It
excludes compilation, fixture loading, and listener startup.

Every network and process operation has a fixed timeout. Workers have a
15-minute outer bound, individual HTTP/3 operations have a 60-second bound,
and cleanup has a 10-second bound. After a trial, the harness requires the
BEAM process count to return to or below its pre-workload value. It also records
the total queued mailbox messages across all BEAM processes before and after
the workload. A failed response, worker, shutdown, cleanup bound, or payload
comparison makes the task fail instead of emitting a successful row.

Custom exploratory workloads can use the positional interface below. The
fixed tasks above remain the comparison baseline.

```sh
mise exec -- gleam run -m http3_benchmark -- benchmark 5 4 100 1024
```

The arguments are mode, measured trials, concurrency, requests per worker, and
payload bytes. The harness bounds all inputs before allocating or starting
network work.

## Recorded local result

The 2026-08-23 run used the environment in
[`environment.txt`](results/2026-08-23-environment.txt) and retains every row
in [`local.csv`](results/2026-08-23-local.csv). Warm-up rows are excluded from
the summaries:

- The five baseline trials had a median 1,173 requests/second and a range from
  1,133 to 1,181 requests/second.
- The three 32-connection load trials had a median 1,291 requests/second and a
  range from 1,239 to 1,311 requests/second.
- The sustained measured trial completed 80,000 streams in 76.018408 seconds,
  or 1,052 requests/second. Its separate 80,000-stream warm-up took 69.870773
  seconds, so the soak task exercised 160,000 streams continuously.
- Every measured trial returned below its starting process count and recorded
  zero total mailbox messages both before and after. In the measured soak row,
  total BEAM memory changed from 40,342,576 to 40,481,088 bytes after cleanup.

These numbers describe one localhost run. CPU frequency scaling, background
system load, allocator high-water marks, scheduler placement, and a single
machine's network stack introduce uncertainty. The harness does not pin CPU
cores or governors, and the one-trial soak result has no statistical interval.
Use the raw repeated trials for comparisons; do not treat the fastest row as a
general throughput guarantee or compare it directly with a remote peer run.
