#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

set -Eeuo pipefail

repository_root="$({
	cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
	pwd -P
})"
readonly repository_root

usage() {
	echo "usage: $0 <all|http|http3|core> [...]" >&2
	exit 2
}

if (($# == 0)); then
	usage
fi

declare -a targets=()
for requested in "$@"; do
	case "${requested}" in
	all)
		targets=(core http3 http)
		break
		;;
	http | http3 | core)
		targets+=("${requested}")
		;;
	*) usage ;;
	esac
done

fresh_build() {
	local target=$1
	local package_directory

	case "${target}" in
	core) package_directory="${repository_root}/packages/quic_core" ;;
	http3) package_directory="${repository_root}/packages/http3" ;;
	http) package_directory="${repository_root}" ;;
	*) usage ;;
	esac

	(
		local lease
		local lease_active=0

		cd -- "${repository_root}"
		lease="$(escript scripts/fresh_build_manifest.escript reserve "${target}")"
		if [[ ! ${lease} =~ ^[0-9a-f]{32}$ ]]; then
			echo "fresh build returned an invalid lease token" >&2
			exit 1
		fi
		lease_active=1

		# NOTE: The EXIT trap invokes this function.
		# shellcheck disable=SC2329
		cleanup_fresh_build() {
			local exit_status=$?
			trap - EXIT
			if ((lease_active)); then
				cd -- "${repository_root}"
				if ! escript scripts/fresh_build_manifest.escript \
					abort "${target}" "${lease}" >/dev/null 2>&1; then
					echo "fresh build cleanup failed; lease retained" >&2
					exit_status=1
				fi
			fi
			exit "${exit_status}"
		}
		# NOTE: The signal traps invoke this function.
		# shellcheck disable=SC2329
		preserve_interrupted_lease() {
			local exit_status=$1
			lease_active=0
			trap - EXIT HUP INT TERM
			exit "${exit_status}"
		}
		trap cleanup_fresh_build EXIT
		trap 'preserve_interrupted_lease 129' HUP
		trap 'preserve_interrupted_lease 130' INT
		trap 'preserve_interrupted_lease 143' TERM

		escript scripts/fresh_build_manifest.escript begin "${target}" "${lease}"
		cd -- "${package_directory}"
		gleam build --warnings-as-errors
		cd -- "${repository_root}"
		escript scripts/fresh_build_manifest.escript write "${target}" "${lease}"

		lease_active=0
		trap - EXIT HUP INT TERM
	)
}

for target in "${targets[@]}"; do
	fresh_build "${target}"
done

(
	cd -- "${repository_root}"
	escript scripts/fresh_build_manifest.escript verify "${targets[@]}"
)
