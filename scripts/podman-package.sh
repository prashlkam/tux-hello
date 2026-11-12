#!/bin/bash
# Build and test the distribution packages with podman (rootless is fine).
#
#   scripts/podman-package.sh [arch|debian|fedora|all] [--rebuild]
#
# 1. scripts/dist.sh makes the release tarball with vendored crates (on the
#    host: it needs git, cargo and, the first time, the network).
# 2. Each container builds its package from that tarball with the network
#    switched off, installs it, logs in through PAM with it, removes it and
#    checks that PAM is back to what it was.
#
# The packages end up in dist/.
set -euo pipefail

ROOT=$(realpath "$(dirname "$0")/..")
distros=()
rebuild=false
for a in "$@"; do
	case $a in
	arch | debian | fedora) distros+=("$a") ;;
	all) distros+=(arch debian fedora) ;;
	--rebuild) rebuild=true ;;
	*) echo "unknown argument: $a" >&2; exit 2 ;;
	esac
done
[ ${#distros[@]} -gt 0 ] || distros=(arch)

echo "### release tarball"
rm -f "$ROOT"/dist/tux-hello-*.tar.xz
"$ROOT/scripts/dist.sh" "$ROOT/dist" | tail -1

declare -A result
for d in "${distros[@]}"; do
	image=localhost/tuxhello-dev:$d
	if $rebuild || ! podman image exists "$image"; then
		echo "### building $image"
		pull=()
		$rebuild && pull=(--pull=always)
		podman build "${pull[@]}" -t "$image" -f "$ROOT/containers/Containerfile.$d" "$ROOT/containers"
	fi
	echo "### packaging on $d"
	if podman run --rm --init --network=none \
		-v "$ROOT:/src:ro,z" -v "$ROOT/dist:/dist:z" \
		"$image" /src/containers/package-in-container.sh "$d"; then
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
ls -1 "$ROOT"/dist/
exit $status
