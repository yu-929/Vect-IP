#!/bin/bash
# Generate all app icons from the source logo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOGO_SRC="$SCRIPT_DIR/logo/图标.jpg"

if ! command -v convert &>/dev/null; then
    echo "ImageMagick not found, using pre-committed icons"
    exit 0
fi

if [ ! -f "$LOGO_SRC" ]; then
    echo "Logo not found at $LOGO_SRC, using pre-committed icons"
    exit 0
fi

OUT_DIR="/tmp/vect-icons"
mkdir -p "$OUT_DIR"

echo "==> Generating icons from $LOGO_SRC"

# Web / PWA icons (192, 512, 1024)
echo "  -> Web icons..."
convert "$LOGO_SRC" -colorspace sRGB -resize 192x192 -background white -gravity center -extent 192x192 -define png:color-type=6 "$OUT_DIR/icon-192.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 512x512 -background white -gravity center -extent 512x512 -define png:color-type=6 "$OUT_DIR/icon-512.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 1024x1024 -background white -gravity center -extent 1024x1024 -define png:color-type=6 "$OUT_DIR/icon-1024.png"

# Copy to shared web directory
cp "$OUT_DIR/icon-192.png" "$SCRIPT_DIR/web/icon-192.png"
cp "$OUT_DIR/icon-512.png" "$SCRIPT_DIR/web/icon-512.png"
cp "$OUT_DIR/icon-1024.png" "$SCRIPT_DIR/web/icon-1024.png"

# Android mipmap icons
echo "  -> Android icons..."
ANDROID_RES="$SCRIPT_DIR/android/app/src/main/res"
mkdir -p "$ANDROID_RES/mipmap-mdpi"
mkdir -p "$ANDROID_RES/mipmap-hdpi"
mkdir -p "$ANDROID_RES/mipmap-xhdpi"
mkdir -p "$ANDROID_RES/mipmap-xxhdpi"
mkdir -p "$ANDROID_RES/mipmap-xxxhdpi"
convert "$LOGO_SRC" -colorspace sRGB -resize 48x48 -background white -gravity center -extent 48x48 -define png:color-type=6 "$ANDROID_RES/mipmap-mdpi/ic_launcher.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 72x72 -background white -gravity center -extent 72x72 -define png:color-type=6 "$ANDROID_RES/mipmap-hdpi/ic_launcher.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 96x96 -background white -gravity center -extent 96x96 -define png:color-type=6 "$ANDROID_RES/mipmap-xhdpi/ic_launcher.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 144x144 -background white -gravity center -extent 144x144 -define png:color-type=6 "$ANDROID_RES/mipmap-xxhdpi/ic_launcher.png"
convert "$LOGO_SRC" -colorspace sRGB -resize 192x192 -background white -gravity center -extent 192x192 -define png:color-type=6 "$ANDROID_RES/mipmap-xxxhdpi/ic_launcher.png"

# Windows .ico (multi-size: 16,32,48,256)
echo "  -> Windows icon..."
convert "$LOGO_SRC" -resize 256x256 -define icon:auto-resize=256,48,32,16 "$SCRIPT_DIR/windows/app.ico"

echo "==> Done."