#!/usr/bin/env sh
# package-appimage.sh - Package Nudgegeist into a Linux x86_64 AppImage.
set -eu
umask 022

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
version="${NUDGEGEIST_VERSION:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}"
out_dir="${1:-dist}"
case "$out_dir" in /*) output_dir="$out_dir";; *) output_dir="$root/$out_dir";; esac
mkdir -p "$output_dir"

if [ "${NUDGEGEIST_SKIP_BUILD:-0}" != "1" ]; then
  echo "[1/3] Building Nudgegeist release binary ..."
  (cd "$root" && cargo build --release --locked)
fi

target_dir="${CARGO_TARGET_DIR:-$root/target}"
bin="$target_dir/release/nudgegeist"
[ -x "$bin" ] || { echo "Release binary not found: $bin" >&2; exit 1; }

echo "[2/3] Assembling AppDir ..."
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
appdir="$stage/Nudgegeist.AppDir"
mkdir -p "$appdir/usr/bin"
install -m 0755 "$bin" "$appdir/usr/bin/nudgegeist"

cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
APPDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$APPDIR/usr/bin/nudgegeist" "$@"
EOF
chmod +x "$appdir/AppRun"

install -m 0644 "$root/packaging/linux/nudgegeist.desktop" "$appdir/nudgegeist.desktop"

icon="$root/assets/nudgegeist-256.png"
[ -f "$icon" ] || icon="$root/assets/nudgegeist.png"
[ -f "$icon" ] || { echo "Missing icon asset under assets/" >&2; exit 1; }
install -m 0644 "$icon" "$appdir/nudgegeist.png"
ln -sf nudgegeist.png "$appdir/.DirIcon"

echo "[3/3] Packaging AppImage ..."
cache="${XDG_CACHE_HOME:-$HOME/.cache}/nudgegeist"
tool="$cache/appimagetool-x86_64.AppImage"
if command -v appimagetool >/dev/null 2>&1; then
  tool="$(command -v appimagetool)"
elif [ ! -x "$tool" ]; then
  mkdir -p "$cache"
  echo "Downloading appimagetool -> $tool"
  curl -fL --retry 2 -o "$tool" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x "$tool"
fi

out="$output_dir/Nudgegeist-${version}-x86_64.AppImage"
rm -f "$out"
if [ -e /dev/fuse ]; then
  ARCH=x86_64 "$tool" "$appdir" "$out" >/dev/null
else
  ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" "$appdir" "$out" >/dev/null
fi
[ -f "$out" ] || { echo "appimagetool failed" >&2; exit 1; }
echo "Created $out"
