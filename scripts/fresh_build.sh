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
	case "$requested" in
	all)
		targets=(core http3 http)
		break
		;;
	http | http3 | core)
		targets+=("$requested")
		;;
	*) usage ;;
	esac
done

fresh_build() {
	local target=$1
	local package_directory
	local profile_directory

	case "$target" in
	core) package_directory="$repository_root/packages/quic_core" ;;
	http3) package_directory="$repository_root/packages/http3" ;;
	http) package_directory="$repository_root" ;;
	*) usage ;;
	esac
	profile_directory="$package_directory/build/dev"

	case "$profile_directory" in
	"$repository_root/build/dev" | \
		"$repository_root/packages/http3/build/dev" | \
		"$repository_root/packages/quic_core/build/dev") ;;
	*)
		echo "refusing to clean unexpected build profile: $profile_directory" >&2
		exit 1
		;;
	esac

	if [[ -d "$profile_directory" ]]; then
		find "$profile_directory" -depth -delete
	fi
	(
		cd -- "$package_directory"
		gleam build --warnings-as-errors
	)
	(
		cd -- "$repository_root"
		escript scripts/fresh_build_manifest.escript write "$target"
	)
}

for target in "${targets[@]}"; do
	fresh_build "$target"
done

(
	cd -- "$repository_root"
	escript scripts/fresh_build_manifest.escript verify "${targets[@]}"
)
