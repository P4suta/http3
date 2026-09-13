# 2026-09-14 windows socket policy

- Date: 2026-09-14
- Commit: 48a8b3b0a609b7c33ff54c571c9c5935ad41336f
- Gleam: 1.18.1
- Erlang/OTP: 29.0.5
- mise: 2026.8.6
- Host: Windows 11 Pro 10.0.26200 (build 26200) x86_64, AMD Ryzen 7 5800H,
  8 cores / 16 threads, 39.4 GiB

This file records a direct measurement of the Windows half of the UDP socket
policy in `packages/gleam_quic/src/gleam_quic_udp_ffi.erl`. Every earlier
Windows claim in [Architecture](../ARCHITECTURE.md) and
[Conformance](../CONFORMANCE.md) rested on the constants being right and on the
option being accepted; neither had been observed on a Windows host. The
measurements below were taken on the live network path, not on loopback, whose
MTU on this host is 4294967295 and therefore cannot exercise fragmentation at
all.

## 1. Option constants against the Windows SDK

Read from `C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared\ws2ipdef.h`:

    #define IP_DONTFRAGMENT           14 // Don't fragment IP datagrams.
    #define IPV6_DONTFRAG             14 // Don't fragment IP datagrams.

Both match `?WINDOWS_IP_DONTFRAGMENT` and `?WINDOWS_IPV6_DONTFRAG`. The header
also carries `IP_ECN` 50, `IPV6_ECN` 50, `IP_TOS` 3, and `IPV6_TCLASS` 39,
which matters for section 4.

## 2. Don't-Fragment is set, stored, and honoured

`inet:setopts/2` accepting a raw option is not proof the kernel kept it, and a
kept value is not proof the stack honours it. All three were checked.

Accepted and stored, both families:

    == IPv4: IPPROTO_IP(0) / IP_DONTFRAGMENT(14) ==
      setopts DF=1      -> ok
      getopts readback  -> {ok,1,<<1,0,0,0>>}
      setopts DF=0      -> ok / readback {ok,0,<<0,0,0,0>>}

    == IPv6: IPPROTO_IPV6(41) / IPV6_DONTFRAG(14) ==
      setopts DF=1      -> ok
      getopts readback  -> {ok,1,<<1,0,0,0>>}
      setopts DF=0      -> ok / readback {ok,0,<<0,0,0,0>>}

Honoured, measured over a real 1500-byte-MTU Wi-Fi path to the only neighbour
with a resolved ARP entry. `1500 - 20 (IPv4) - 8 (UDP) = 1472` is the largest
payload that fits unfragmented:

    dst {192,168,0,1} port 9 (discard), Wi-Fi MTU 1500, DF boundary = 1472

    payload  DF=1                   DF=0
    -------  ----                   ----
    1200     ok                     ok
    1471     ok                     ok
    1472     ok                     ok
    1473     {error,emsgsize}       ok
    1600     {error,emsgsize}       ok
    3000     {error,emsgsize}       ok

The flip is exactly at the theoretical boundary, and clearing the option
restores fragmented sends at every size. Don't-Fragment is genuinely active on
Windows, so `udp.classify_send` receives the `EMSGSIZE` it classifies as a path
measurement, and DPLPMTUD is not trusting a probe the kernel could have
fragmented.

`emsgsize` also surfaces synchronously from `gen_udp:send/4` on Windows, at the
65507-byte maximum UDP payload, independently of any interface MTU:

    send 70000 to loopback -> {error,emsgsize}
    send 65508 to loopback -> {error,emsgsize}
    send 65507 to loopback -> ok

### Not covered

The Don't-Fragment boundary was measured for IPv4 only. This host has no
reachable IPv6 neighbour, so the IPv6 result rests on the accepted-and-stored
readback above, not on an observed `EMSGSIZE`. A dual-stack Windows host on a
network with an IPv6 router is required to close that half.

## 3. Listener dual-stack, port reuse, and buffers

`open_split_dual_stack/1` binds IPv6 with `{ipv6_v6only, true}`, reads the
bound port back, and binds IPv4 to that same port. Reproduced with the exact
option list the FFI uses:

    v6 bound port           -> 56410
    v4 bind to same port    -> ok (port 56410)
    v6only readback         -> {ok,[{ipv6_v6only,true}]}

Windows `SO_REUSEADDR` is documented to let an unrelated socket bind a port
already in use and take its traffic. That does not happen through OTP 29 here.
`{reuseaddr, true}` is really applied, and the port is still not takeable --
from a second socket in the same process, and from a second OS process:

    reuseaddr readback              -> {ok,[{reuseaddr,true}]}
    same process,  reuseaddr=true   -> {error,eaddrinuse}
    other process, reuseaddr=true   -> {error,eaddrinuse}
    other process, exclusive        -> {error,eaddrinuse}

The 4 MiB socket buffer request is honoured exactly rather than silently
clamped:

    requested 4194304 bytes each
    actual -> {ok,[{recbuf,4194304},{sndbuf,4194304},{buffer,65536}]}

`buffer` is the driver's per-read buffer and stays above the 65507-byte
maximum UDP datagram, so no datagram is truncated by it.

## 4. ECN is refused, and the hardcoded `false` is correct

`runtime_supports_ecn/0` returns `false` for `{win32, _}` without asking the
socket. That is the right answer on this host: OTP 29 rejects both codepoint
options outright, even though `ws2ipdef.h` defines the underlying Windows
options.

    v4 setopts {tos,1}    -> {error,einval}
    v4 getopts tos        -> {ok,[{tos,0}]}
    v6 setopts {tclass,1} -> {error,einval}
    v6 getopts tclass     -> {ok,[]}

No change is required; this row is evidence that the existing exclusion is
justified rather than assumed.
