# Independent interoperability fixtures

These opt-in fixtures exercise the public library against an independently
implemented HTTP/3 peer. They are phase gates, not part of the hermetic unit
and loopback suite.

The advanced transport fixture requires Python and pins aioquic 1.3.0. Run the
following commands from the repository root:

```sh
python3 -m venv /tmp/http3-aioquic-1.3.0
/tmp/http3-aioquic-1.3.0/bin/pip install -r test/interop/requirements.txt
mise run build
erlc -o /tmp test/interop/http3_phase4_interop.erl
/tmp/http3-aioquic-1.3.0/bin/python test/interop/aioquic_phase4_server.py
```

The final command stays in the foreground and prints `PORT` and
`RESUMPTION_PORT`. In another terminal, create a unique qlog directory and
invoke the runner after replacing the sample ports and directory:

```sh
mktemp -d /tmp/http3-phase4-interop-qlog.XXXXXX
mise exec -- erl -noshell -pa 'build/dev/erlang/*/ebin' /tmp \
  -eval 'ok = http3_phase4_interop:run(41481, 58282, <<"/tmp/http3-phase4-interop-qlog.example">>), halt(0).'
```

The delayed second port keeps a stable origin while delaying server response
packets by 50 ms. A successful run prints `phase4 aioquic advanced interop ok`,
creates at least one qlog file, and makes the Python peer print
`OBSERVED_HTTP_DATAGRAM`, `OBSERVED_POST_MIGRATION_REQUEST`, and
`OBSERVED_0RTT_REQUEST`. Stop the peer with Ctrl-C and remove the temporary
virtual environment, BEAM file, and qlog directory when they are no longer
needed. The last verified outcome is recorded in [Testing][testing].

[testing]: ../../docs/TESTING.md
