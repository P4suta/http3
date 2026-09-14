#!/usr/bin/env bash

set -Eeuo pipefail

readonly mode="${1:-aioquic}"
readonly repetitions="${HTTP3_INTEROP_REPETITIONS:-10}"

case "$mode" in
all | aioquic | quicgo) ;;
*)
	echo "usage: $0 [all|aioquic|quicgo]" >&2
	exit 2
	;;
esac

if [[ ! "$repetitions" =~ ^[0-9]+$ ]] ||
	((repetitions < 1 || repetitions > 100)); then
	echo "HTTP3_INTEROP_REPETITIONS must be an integer from 1 through 100" >&2
	exit 2
fi

package_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
	pwd -P
})"
readonly package_root
cd -- "$package_root"

readonly campaign_directory="$package_root/build/interop-campaign"
readonly failure_directory="$package_root/build/interop-failure"
mkdir -p "$campaign_directory"
report="$(mktemp "${campaign_directory%/}/.${mode}.XXXXXX")"
readonly report

cleanup() {
	if [[ -f "$report" ]]; then
		find "$report" -delete
	fi
}
trap cleanup EXIT INT TERM

printf 'profile=http3-interop-repeat-v1\nmode=%s\nrequested=%s\n' \
	"$mode" "$repetitions" >"$report"

# A campaign proves freshness once, then gives every trial its own processes,
# sockets, temporary directory, qlogs, and fixed operation deadlines.
bash ../../scripts/fresh_build.sh http3

for ((trial = 1; trial <= repetitions; trial += 1)); do
	echo "interop campaign ${mode}: trial ${trial}/${repetitions}"
	if HTTP3_INTEROP_SKIP_FRESH_BUILD=1 bash test/interop/run.sh "$mode"; then
		printf 'trial.%s=pass\n' "$trial" >>"$report"
	else
		printf 'trial.%s=fail\ncompleted=%s\nstatus=fail\n' \
			"$trial" "$trial" >>"$report"
		cp -- "$report" "$campaign_directory/${mode}.txt"
		mkdir -p "$failure_directory"
		cp -- "$report" "$failure_directory/campaign.txt"
		echo "interop campaign failed at trial ${trial}; evidence retained" >&2
		exit 1
	fi
done

printf 'completed=%s\nstatus=pass\n' "$repetitions" >>"$report"
cp -- "$report" "$campaign_directory/${mode}.txt"
echo "interop campaign passed ${repetitions}/${repetitions}: ${mode}"
