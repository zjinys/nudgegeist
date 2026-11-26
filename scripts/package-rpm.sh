#!/usr/bin/env sh
set -eu
umask 022

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
version="${NUDGEGEIST_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}"
out_dir="${1:-dist}"
case "$out_dir" in /*) output_dir="$out_dir";; *) output_dir="$root/$out_dir";; esac

command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild is required" >&2; exit 1; }
mkdir -p "$output_dir"

if [ "${NUDGEGEIST_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$root" && cargo build --release --locked)
fi

target_dir="${CARGO_TARGET_DIR:-$root/target}"
bin="$target_dir/release/nudgegeist"
[ -x "$bin" ] || { echo "Release binary not found: $bin" >&2; exit 1; }

top="$(mktemp -d)"
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/BUILD" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"

sed "s/@VERSION@/$version/g; s|@ROOT@|$root|g; s|@BIN@|$bin|g" \
  "$root/packaging/linux/nudgegeist.spec.in" > "$top/SPECS/nudgegeist.spec"
rpmbuild --define "_topdir $top" -bb "$top/SPECS/nudgegeist.spec" >/dev/null
find "$top/RPMS" -name '*.rpm' -exec cp {} "$output_dir/" \;
echo "Created RPM in $output_dir"
