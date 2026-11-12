#!/bin/bash
# Make the release tarball: the source tree plus every crate it depends on
# (vendor/), so that distribution builds work with no network access.
#
#   scripts/dist.sh [OUTDIR]        (default: dist/)
#
# The tarball holds what git tracks plus untracked files that are not ignored,
# so it can be used to test packaging changes before they are committed.
set -euo pipefail

ROOT=$(realpath "$(dirname "$0")/..")
out=$(realpath -m "${1:-$ROOT/dist}")
ver=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml")
[ -n "$ver" ] || { echo "cannot read the version from Cargo.toml" >&2; exit 1; }
name=tux-hello-$ver

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/$name"

cd "$ROOT"
# Deleted-but-not-yet-committed files are listed by git but no longer exist.
git ls-files -co --exclude-standard -z |
	while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
	tar -c --null -T - | tar -x -C "$tmp/$name"

cd "$tmp/$name"
mkdir .cargo
cargo vendor --locked --versioned-dirs vendor >.cargo/config.toml
printf '\n[net]\noffline = true\n' >>.cargo/config.toml

# Same input, same tarball: fixed order, owner and timestamp.
mtime=$(git -C "$ROOT" log -1 --format=%cI 2>/dev/null || date -Is)
mkdir -p "$out"
tar -C "$tmp" --sort=name --owner=0 --group=0 --numeric-owner --mtime="$mtime" \
	-cf - "$name" | xz -T0 -6 >"$out/$name.tar.xz"
(cd "$out" && sha256sum "$name.tar.xz" >"$name.tar.xz.sha256")
echo "$out/$name.tar.xz"
