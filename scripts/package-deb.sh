#!/usr/bin/env sh
set -eu
umask 022

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
version="${NUDGEGEIST_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}"
out_dir="${1:-dist}"
case "$out_dir" in /*) output_dir="$out_dir";; *) output_dir="$root/$out_dir";; esac

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
mkdir -p "$output_dir"

if [ "${NUDGEGEIST_SKIP_BUILD:-0}" != "1" ]; then
  (cd "$root" && cargo build --release --locked)
fi

target_dir="${CARGO_TARGET_DIR:-$root/target}"
bin="$target_dir/release/nudgegeist"
[ -x "$bin" ] || { echo "Release binary not found: $bin" >&2; exit 1; }

arch="$(dpkg --print-architecture 2>/dev/null || true)"
if [ -z "$arch" ]; then
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) arch="$(uname -m)" ;;
  esac
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

chmod 0755 "$stage"
mkdir -p \
  "$stage/DEBIAN" \
  "$stage/usr/bin" \
  "$stage/usr/share/applications" \
  "$stage/usr/share/icons/hicolor/256x256/apps" \
  "$stage/usr/share/icons/hicolor/512x512/apps"
chmod 0755 "$stage/DEBIAN"

install -m 0755 "$bin" "$stage/usr/bin/nudgegeist"
install -m 0644 "$root/packaging/linux/nudgegeist.desktop" "$stage/usr/share/applications/nudgegeist.desktop"
[ -f "$root/assets/nudgegeist-256.png" ] && \
  install -m 0644 "$root/assets/nudgegeist-256.png" "$stage/usr/share/icons/hicolor/256x256/apps/nudgegeist.png"
[ -f "$root/assets/nudgegeist.png" ] && \
  install -m 0644 "$root/assets/nudgegeist.png" "$stage/usr/share/icons/hicolor/512x512/apps/nudgegeist.png"

cat > "$stage/DEBIAN/control" <<EOF
Package: nudgegeist
Version: $version
Section: devel
Priority: optional
Architecture: $arch
Depends: libxcb1, libxkbcommon0, libxkbcommon-x11-0, libfontconfig1, libvulkan1
Maintainer: Nudgegeist contributors
Description: AI Coding Agent Watchdog and Rule Engine GUI
 Nudgegeist monitors and unblocks stalled AI coding agents through luvus
 with a configurable conservative rule engine and native GPUI desktop GUI.
EOF

out_file="$output_dir/nudgegeist_${version}_${arch}.deb"
dpkg-deb --root-owner-group --build "$stage" "$out_file" >/dev/null
echo "Created $out_file"
