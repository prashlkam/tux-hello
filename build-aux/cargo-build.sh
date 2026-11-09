#!/bin/sh
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

set -- build --manifest-path "$src/Cargo.toml" --target-dir "$target_dir" --workspace
if [ "$profile" = release ]; then
	set -- "$@" --release
fi
if [ -n "$features" ]; then
	set -- "$@" --features "$features"
fi

"$cargo" "$@"

cp -f "$target_dir/$profile/tuxhellod" "$out_dir/tuxhellod"
cp -f "$target_dir/$profile/tuxhello" "$out_dir/tuxhello"
cp -f "$target_dir/$profile/libpam_tuxhello.so" "$out_dir/pam_tuxhello.so"
