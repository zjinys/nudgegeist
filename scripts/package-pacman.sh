#!/usr/bin/env sh
set -eu
umask 022

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
out_dir="${1:-dist}"
case "$out_dir" in /*) output_dir="$out_dir";; *) output_dir="$root/$out_dir";; esac

command -v makepkg >/dev/null 2>&1 || { echo "makepkg is required" >&2; exit 1; }
mkdir -p "$output_dir"

if [ "${NUDGEGEIST_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$root" && cargo build --release --locked)
fi

target_dir="${CARGO_TARGET_DIR:-$root/target}"
bin="$target_dir/release/nudgegeist"
[ -x "$bin" ] || { echo "Release binary not found: $bin" >&2; exit 1; }

cd "$root/packaging/linux"
PKGDEST="$output_dir" makepkg -Cf
echo "Created pacman package in $output_dir"
