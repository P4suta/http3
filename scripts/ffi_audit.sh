#!/usr/bin/env bash

set -euo pipefail

jq -e '
	.ffi_inventory.schema == 1
	and (.ffi_inventory.sources | type == "array" and length > 0)
	and all(.ffi_inventory.sources[]; type == "string" and endswith("_ffi.erl"))
' qualification.json >/dev/null

mapfile -t production_ffi_sources < <(
	jq -r '.ffi_inventory.sources[]' qualification.json
)

discovered_ffi_sources="$(
	find src packages/http3/src packages/quic_core/src \
		-type f -name '*_ffi.erl' -print | sort
)"
declared_ffi_sources="$(printf '%s\n' "${production_ffi_sources[@]}" | sort)"
manifest_ffi_sources="$(printf '%s\n' "${production_ffi_sources[@]}")"
if [[ "$manifest_ffi_sources" != "$declared_ffi_sources" ]]; then
	printf 'production FFI inventory is not sorted and unique\n' >&2
	exit 1
fi
if [[ "$discovered_ffi_sources" != "$declared_ffi_sources" ]]; then
	printf 'production FFI inventory drift\n' >&2
	diff -u \
		<(printf '%s\n' "$declared_ffi_sources") \
		<(printf '%s\n' "$discovered_ffi_sources") >&2 || true
	exit 1
fi

production_ffi_beams=()
for source in "${production_ffi_sources[@]}"; do
	module="$(basename -- "$source" .erl)"
	case "$source" in
	packages/http3/src/*)
		production_ffi_beams+=("build/dev/erlang/http3/ebin/$module.beam")
		;;
	packages/quic_core/src/*)
		production_ffi_beams+=("build/dev/erlang/quic_core/ebin/$module.beam")
		;;
	src/*)
		production_ffi_beams+=("build/dev/erlang/http/ebin/$module.beam")
		;;
	*)
		printf 'unsupported production FFI source: %s\n' "$source" >&2
		exit 1
		;;
	esac
done

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
	"${production_ffi_beams[@]}"

escript scripts/http3_ffi_xref.escript
escript scripts/http3_ffi_xref.escript boundary api/boundary.allow
