#!/usr/bin/env sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
src="$root/assets/nudgegeist.png"

[ -f "$src" ] || { echo "Missing source icon: $src" >&2; exit 1; }

if command -v magick >/dev/null 2>&1; then
  im="magick"
elif command -v convert >/dev/null 2>&1; then
  im="convert"
else
  echo "ImageMagick (magick or convert) is required" >&2
  exit 1
fi

"$im" "$src" -resize 256x256 "$root/assets/nudgegeist-256.png"
"$im" "$src" -define icon:auto-resize=256,128,64,48,32,24,16 "$root/assets/nudgegeist.ico"

echo "Generated assets/nudgegeist-256.png and assets/nudgegeist.ico"
