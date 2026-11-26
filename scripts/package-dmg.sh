#!/bin/sh
# package-dmg.sh - Bundle Nudgegeist into a macOS .app and .dmg (run on macOS).
#
# Output: dist/Nudgegeist-<version>-<arch>.dmg
# Signing: defaults to ad-hoc (`codesign --sign -`). Set CODESIGN_IDENTITY to sign for distribution.
set -eu
umask 022

[ "$(uname -s)" = "Darwin" ] || { echo "This script must run on macOS" >&2; exit 1; }

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
version="${NUDGEGEIST_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}"
out_dir="${1:-dist}"
case "$out_dir" in /*) output_dir="$out_dir";; *) output_dir="$root/$out_dir";; esac
mkdir -p "$output_dir"

target_dir="${CARGO_TARGET_DIR:-$root/target}"
target_triple="${MACOS_TARGET:-}"
if [ -n "$target_triple" ]; then
  bin="$target_dir/$target_triple/release/nudgegeist"
  build_cmd="cargo build --release --locked --target $target_triple"
  case "$target_triple" in
    aarch64-*) arch_label="arm64" ;;
    x86_64-*) arch_label="x64" ;;
    *) arch_label="$target_triple" ;;
  esac
else
  bin="$target_dir/release/nudgegeist"
  build_cmd="cargo build --release --locked"
  case "$(uname -m)" in
    arm64) arch_label="arm64" ;;
    x86_64) arch_label="x64" ;;
    *) arch_label="$(uname -m)" ;;
  esac
fi

if [ "${NUDGEGEIST_SKIP_BUILD:-0}" != "1" ]; then
  echo "[1/4] Building Nudgegeist release binary ($arch_label) ..."
  (cd "$root" && $build_cmd)
fi
[ -x "$bin" ] || { echo "Release binary not found: $bin" >&2; exit 1; }

echo "[2/4] Assembling Nudgegeist.app ..."
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
app="$stage/Nudgegeist.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

install -m 0755 "$bin" "$app/Contents/MacOS/nudgegeist"
sed "s/@VERSION@/$version/g" "$root/packaging/macos/Info.plist.in" > "$app/Contents/Info.plist"

icon_src="$root/assets/nudgegeist.png"
if [ -f "$icon_src" ]; then
  iconset="$stage/AppIcon.iconset"
  mkdir -p "$iconset"
  for spec in "16 16x16" "32 16x16@2x" "32 32x32" "64 32x32@2x" \
              "128 128x128" "256 128x128@2x" "256 256x256" "512 256x256@2x" \
              "512 512x512" "1024 512x512@2x"; do
    set -- $spec
    sips -z "$1" "$1" "$icon_src" --out "$iconset/icon_$2.png" >/dev/null
  done
  iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"
fi

echo "[3/4] Signing (${CODESIGN_IDENTITY:-ad-hoc}) ..."
codesign --force --deep --sign "${CODESIGN_IDENTITY:--}" "$app"

echo "[4/4] Creating DMG ..."
ln -s /Applications "$stage/Applications"
out="$output_dir/Nudgegeist-${version}-${arch_label}.dmg"
rm -f "$out"
hdiutil create -volname "Nudgegeist" -srcfolder "$stage" -ov -format UDZO "$out" >/dev/null
echo "Created $out"
