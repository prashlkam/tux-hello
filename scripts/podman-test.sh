#!/bin/bash

# SPDX-FileCopyrightText: 2026 Tux Hello contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Build and test Tux Hello inside distro containers with podman (rootless is fine).
#
#   scripts/podman-test.sh [arch|debian|fedora|all] [--shell] [--rebuild]
#
#   --shell    open an interactive shell in the container instead of testing
#   --rebuild  rebuild the image (pull a fresh base and packages)
#
# Containers are disposable: the PAM/D-Bus changes the tests make happen inside
# them, never on the host. Cargo caches live in podman volumes
# (tuxhello-target-<distro>, tuxhello-cargo-<distro>).
set -euo pipefail

ROOT=$(realpath "$(dirname "$0")/..")
distros=()
shell=false
rebuild=false
for a in "$@"; do
	case $a in
	arch | debian | fedora) distros+=("$a") ;;
	all) distros+=(arch debian fedora) ;;
	--shell) shell=true ;;
	--rebuild) rebuild=true ;;
	*) echo "unknown argument: $a" >&2; exit 2 ;;
	esac
done
[ ${#distros[@]} -gt 0 ] || distros=(arch)

declare -A result
for d in "${distros[@]}"; do
	image=localhost/tuxhello-dev:$d
	if $rebuild || ! podman image exists "$image"; then
		echo "### building $image"
		pull=()
		$rebuild && pull=(--pull=always)
		podman build "${pull[@]}" -t "$image" -f "$ROOT/containers/Containerfile.$d" "$ROOT/containers"
	fi
	run=(podman run --rm --init
		-v "$ROOT:/src:ro,z"
		-v "tuxhello-target-$d:/target"
		-v "tuxhello-cargo-$d:/cargo-home")
	if $shell; then
		"${run[@]}" -it -w /src -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/cargo-home "$image" bash
		exit
	fi
	echo "### testing on $d"
	if "${run[@]}" "$image" /src/containers/test-in-container.sh; then
		result[$d]=PASS
	else
		result[$d]=FAIL
	fi
done

echo
status=0
for d in "${distros[@]}"; do
	echo "${result[$d]}  $d"
	[ "${result[$d]}" = PASS ] || status=1
done
exit $status
