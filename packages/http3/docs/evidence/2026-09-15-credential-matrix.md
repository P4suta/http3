# 2026-09-15 credential-matrix

- Date: 2026-09-15
- Commit: c25547d
- Gleam: 1.18.1
- Erlang/OTP: 28.5 and 29.0.5 (mise `MISE_ERLANG_VERSION` 28 and 29)
- mise: 2026.8.10 on the runners, 2026.9.7 locally
- Hosts: ubuntu-24.04, macos-15, and windows-2025 GitHub-hosted runners;
  local rows on macOS 26.6.2 (Darwin 25.6.0) arm64, 18 cores, 48 GiB

Command:

    mise run credential-matrix

run as the Nightly workflow's six `credential-matrix-local` rows followed by
`credential-matrix-aggregate`
(<https://github.com/P4suta/http3/actions/runs/34954617517>).

Result: every row Ready, and aggregate verification accepted all six.

| Platform | OTP 28 | OTP 29 |
| --- | --- | --- |
| ubuntu-24.04 | pass | pass |
| macos-15 | pass | pass |
| windows-2025 | pass | pass |

    credential local matrix (macos-15, OTP 28): 160 tests, 0 gaps
    credential local matrix (macos-15, OTP 29): 160 tests, 0 gaps

The two macOS lines above are from local runs on this host, which reproduce the
runner rows; the runner rows are the ones the aggregate consumed.

## What had been failing

The three OTP 28 rows had failed on one assertion,
`hostname_mismatch_fails_closed_with_a_typed_error_test`, which expects
`TlsAuthentication` and received `TlsHandshake`.

`tls_error_code/1` classified a refusal by looking for a certificate reason
atom anywhere in the term `ssl:connect/3` returned. Which form a release
produces is not stable. OTP 28.5 with ssl 11.6 reports a hostname mismatch as

    {tls_alert, {handshake_failure,
        "... - {bad_cert,{hostname_check_failed,{requested,\"wrong.test\"},...}}"}}

where the alert is a generic handshake failure and the certificate reason
exists only inside the rendered description, while 28.5.0.6 and 29.0.5 report
`bad_certificate` as the alert itself. One refusal was therefore reported two
ways across two builds of one release, and the weaker of the two hides that a
certificate was rejected.

The description is now read as well. It is read only for the certificate class
and never for the ALPN one, because a description carries peer-supplied names
out of the certificate that was refused: text can move a classification toward
"the certificate was refused" and never away from it. It is bounded at four
kibibytes for the same reason.

This was reproduced locally by installing OTP 28.5 and running the suite
against an unmodified tree, where the test fails exactly as the nightly
reported it.

## What this does not establish

The attestations are build artifacts of one nightly run against one source
digest, and any source edit invalidates them. Reproducing this row set means
running the nightly again, which is six machines this host does not have. The
OTP 28 release-candidate rerun that PRE-011 tracks is a different gate and is
still absent.
