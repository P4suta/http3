#!/usr/bin/env bash

set -euo pipefail

audit_temp="$(mktemp -d)"
trap 'rm -rf -- "$audit_temp"' EXIT

gleam build --warnings-as-errors

if ! dialyzer \
	--build_plt \
	--apps erts kernel stdlib crypto asn1 public_key ssl compiler \
	syntax_tools parsetools inets runtime_tools mnesia \
	--output_plt "$audit_temp/otp.plt" \
	>"$audit_temp/plt.log" 2>&1; then
	sed -n '1,240p' "$audit_temp/plt.log"
	exit 1
fi

dialyzer \
	--plt "$audit_temp/otp.plt" \
	--no_check_plt \
	--fullpath \
	build/dev/erlang/http3/ebin/http3_internal_transport_ffi.beam \
	build/dev/erlang/http3/ebin/http3_process_label_ffi.beam \
	build/dev/erlang/gleam_quic/ebin/gleam_quic_crypto_ffi.beam \
	build/dev/erlang/gleam_quic/ebin/gleam_quic_process_label_ffi.beam \
	build/dev/erlang/gleam_quic/ebin/gleam_quic_tls_ffi.beam \
	build/dev/erlang/gleam_quic/ebin/gleam_quic_udp_ffi.beam \
	build/dev/erlang/gleam_quic/ebin/gleam_quic_qlog_ffi.beam

escript test/http3_ffi_xref.escript
escript test/http3_ffi_xref.escript boundary api/boundary.allow
