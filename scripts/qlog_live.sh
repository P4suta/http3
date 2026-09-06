#!/usr/bin/env bash

set -Eeuo pipefail

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
	pwd -P
})"
readonly repository_root
output_directory="$repository_root/build/qlog"
readonly output_directory

case "$output_directory" in
"$repository_root/build/qlog") ;;
*)
	echo "refusing unsafe qlog output directory: $output_directory" >&2
	exit 1
	;;
esac

if [[ -d "$output_directory" ]]; then
	find "$output_directory" -depth -delete
fi
mkdir -p "$output_directory"

cd -- "$repository_root/packages/http3"
HTTP3_DIAGNOSTIC_QLOG_DIR="$output_directory" \
	mise exec -- gleam run -m diagnostics/http3_diagnostic -- round-trip

trace_count="$(find "$output_directory" -maxdepth 1 -type f -name '*.qlog' -size +0c | wc -l)"
if [[ "$trace_count" -ne 2 ]]; then
	echo "live qlog fixture produced an unexpected trace count: $trace_count" >&2
	exit 1
fi

echo "live public HTTP/3 qlog fixture produced exactly $trace_count bounded traces"
