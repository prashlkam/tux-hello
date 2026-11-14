#!/bin/sh

# SPDX-FileCopyrightText: 2026 Tux Hello contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Called by meson: builds the Rust workspace and copies the artifacts into
# meson's build directory under their installed names.
#
# usage: cargo-build.sh <cargo> <source-root> <target-dir> <out-dir> <profile> <features>
set -eu

cargo=$1
src=$2
target_dir=$3
out_dir=$4
profile=$5
features=$6

# cargo reads .cargo/config.toml relative to the working directory. Release
# tarballs carry one that points at the vendored crates (scripts/dist.sh).
cd "$src"

set -- build --locked --manifest-path "$src/Cargo.toml" --target-dir "$target_dir" --workspace
if [ "$profile" = release ]; then
	set -- "$@" --release
fi
if [ -n "$features" ]; then
	set -- "$@" --features "$features"
fi

"$cargo" "$@"

cp -f "$target_dir/$profile/tuxhellod" "$out_dir/tuxhellod"
cp -f "$target_dir/$profile/tuxhello" "$out_dir/tuxhello"
cp -f "$target_dir/$profile/tuxhello-pam-setup" "$out_dir/tuxhello-pam-setup"
cp -f "$target_dir/$profile/libpam_tuxhello.so" "$out_dir/pam_tuxhello.so"
