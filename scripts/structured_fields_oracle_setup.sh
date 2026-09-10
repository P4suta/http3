#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
lock_path="$project_root/standards/structured-fields-oracle.json"
checkout_path="$project_root/build/structured-fields-oracle/upstream"
repository=$(jq -er '.repository' "$lock_path")
commit=$(jq -er '.commit' "$lock_path")

canonical_repository() {
	local value=$1
	local path

	case "$value" in
	https://github.com/*)
		path=${value#https://github.com/}
		;;
	git@github.com:*)
		path=${value#git@github.com:}
		;;
	ssh://git@github.com/*)
		path=${value#ssh://git@github.com/}
		;;
	*)
		printf '%s\n' "$value"
		return
		;;
	esac

	printf 'github.com/%s\n' "${path%.git}"
}

if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
	echo "structured-fields oracle lock has an invalid commit" >&2
	exit 1
fi

mkdir -p "$(dirname "$checkout_path")"
if [[ ! -d "$checkout_path/.git" ]]; then
	GIT_TERMINAL_PROMPT=0 git clone --filter=blob:none \
		"$repository" "$checkout_path"
fi

actual_repository=$(git -C "$checkout_path" remote get-url origin)
if [[ "$(canonical_repository "$actual_repository")" != "$(canonical_repository "$repository")" ]]; then
	echo "structured-fields oracle checkout has an unexpected origin" >&2
	exit 1
fi

# Older versions of this script cloned with --no-checkout. Recover only the
# mechanically recognizable state where every tracked path is staged deleted
# and HEAD is already the pinned commit. Any other modification remains fatal.
mapfile -t checkout_status < <(git -C "$checkout_path" status --porcelain)
if ((${#checkout_status[@]} > 0)); then
	mapfile -t tracked_paths < <(git -C "$checkout_path" ls-tree -r --name-only HEAD)
	all_tracked_paths_missing=true
	for entry in "${checkout_status[@]}"; do
		if [[ ${entry:0:3} != "D  " ]]; then
			all_tracked_paths_missing=false
			break
		fi
	done

	if [[ "$all_tracked_paths_missing" == true ]] &&
		((${#checkout_status[@]} == ${#tracked_paths[@]})) &&
		[[ "$(git -C "$checkout_path" rev-parse HEAD)" == "$commit" ]]; then
		git -c advice.detachedHead=false -C "$checkout_path" checkout --detach "$commit"
	else
		echo "structured-fields oracle checkout is modified; refusing to overwrite it" >&2
		exit 1
	fi
fi

if [[ "$(git -C "$checkout_path" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]]; then
	GIT_TERMINAL_PROMPT=0 git -C "$checkout_path" fetch --depth 1 origin "$commit"
	git -c advice.detachedHead=false -C "$checkout_path" checkout --detach "$commit"
fi

actual_commit=$(git -C "$checkout_path" rev-parse HEAD)
if [[ "$actual_commit" != "$commit" ]]; then
	echo "structured-fields oracle checkout did not reach the pinned commit" >&2
	exit 1
fi

echo "structured-fields oracle ready at $actual_commit"
