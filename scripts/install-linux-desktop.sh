#!/usr/bin/env sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
data_dir="${XDG_DATA_HOME:-$HOME/.local/share}"
desktop_dir="$data_dir/applications"
icon_256_dir="$data_dir/icons/hicolor/256x256/apps"
icon_512_dir="$data_dir/icons/hicolor/512x512/apps"

mkdir -p "$desktop_dir" "$icon_256_dir" "$icon_512_dir"

install -m 0644 "$root/packaging/linux/nudgegeist.desktop" "$desktop_dir/nudgegeist.desktop"
if [ -f "$root/assets/nudgegeist-256.png" ]; then
  install -m 0644 "$root/assets/nudgegeist-256.png" "$icon_256_dir/nudgegeist.png"
fi
if [ -f "$root/assets/nudgegeist.png" ]; then
  install -m 0644 "$root/assets/nudgegeist.png" "$icon_512_dir/nudgegeist.png"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$desktop_dir" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$data_dir/icons/hicolor" >/dev/null 2>&1 || true
fi
if command -v kbuildsycoca6 >/dev/null 2>&1; then
  kbuildsycoca6 >/dev/null 2>&1 || true
elif command -v kbuildsycoca5 >/dev/null 2>&1; then
  kbuildsycoca5 >/dev/null 2>&1 || true
fi

echo "Installed Nudgegeist desktop metadata in $data_dir"
