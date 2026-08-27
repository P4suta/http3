#!/bin/sh
# SPDX-FileCopyrightText: 2026 the http3 contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)

for descriptor in \
	"$root/mix.exs" \
	"$root/mix.lock" \
	"$root/packages/gleam_quic/mix.exs"; do
	if [ ! -f "$descriptor" ]; then
		echo "MixGleam package descriptor is missing: $descriptor" >&2
		exit 1
	fi
done

build_directory=$(mktemp -d "${TMPDIR:-/tmp}/http3-mix-package.XXXXXX")
stage="$build_directory/source"

cleanup() {
	if [ -d "$build_directory" ]; then
		find "$build_directory" -depth -delete
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

mkdir -p "$stage/packages/gleam_quic"
for file in gleam.toml mix.exs mix.lock; do
	cp "$root/$file" "$stage/$file"
done
cp -R "$root/src" "$stage/src"
for file in gleam.toml mix.exs; do
	cp "$root/packages/gleam_quic/$file" \
		"$stage/packages/gleam_quic/$file"
done
cp -R "$root/packages/gleam_quic/src" "$stage/packages/gleam_quic/src"

cd "$stage"
export MIX_ENV=prod

mix archive.check
mix deps.get --only prod --check-locked
mix deps.compile
mix compile --no-deps-check

for application in http3 gleam_quic; do
	application_root="_build/prod/lib/$application/ebin"
	for artifact in "$application.app" "$application.beam"; do
		if [ ! -f "$application_root/$artifact" ]; then
			echo "MixGleam package artifact is missing: $application_root/$artifact" >&2
			exit 1
		fi
	done
done

echo "MixGleam http3 and gleam_quic package artifacts are complete"
