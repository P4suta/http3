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

## Recorded native-core result

The 2026-08-24 run used the repository-owned `gleam_quic` backend and the
environment in
[`2026-08-24-environment.txt`](results/2026-08-24-environment.txt). Every row
is retained in
[`2026-08-24-local.csv`](results/2026-08-24-local.csv). Warm-up rows are
excluded from the summaries:

- The five baseline trials had a median 258 requests/second and a range from
  244 to 288 requests/second.
- The three 32-connection load trials had a median 172 requests/second and a
  range from 171 to 173 requests/second.
- The sustained measured trial completed 80,000 streams in 196.909174 seconds,
  or 406 requests/second. Its separate 80,000-stream warm-up took 206.950577
  seconds, so the soak task exercised 160,000 streams continuously.
- Every row returned from 48 processes to 47 and recorded zero total mailbox
  messages before and after. In the measured soak row, total BEAM memory
  changed from 40,497,800 to 40,687,280 bytes after cleanup, an increase of
  189,480 bytes (approximately 185 KiB).

These numbers describe one localhost run on an Intel Core i7-7700K with the
`powersave` governor and without CPU affinity. CPU frequency scaling,
background load, allocator high-water marks, scheduler placement, and one
machine's network stack introduce uncertainty. The one-trial soak result has
no statistical interval. Use the raw repeated trials for comparisons; do not
treat the fastest row as a general throughput guarantee or compare it directly
with a remote peer or the former external-backend baseline.
