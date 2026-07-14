#!/bin/bash
# Generate iOS app icons from the source logo
# Requires: ImageMagick (convert)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$SCRIPT_DIR/VectApp/Assets.xcassets/AppIcon.appiconset"
SOURCE_ICON="$PROJECT_DIR/web/icon-1024.png"

if ! command -v convert &>/dev/null; then
    echo "ERROR: ImageMagick (convert) not found. Install with: brew install imagemagick"
    exit 1
fi

if [ ! -f "$SOURCE_ICON" ]; then
    echo "ERROR: Source icon not found at $SOURCE_ICON"
    echo "Run ../generate-icons.sh first to generate all icons."
    exit 1
fi

mkdir -p "$ASSETS_DIR"

generate_icon() {
    local size=$1
    local scale=$2
    local filename=$3
    local pixel_size=$(echo "$size * $scale" | bc | cut -d. -f1)
    convert "$SOURCE_ICON" -resize "${pixel_size}x${pixel_size}" "$ASSETS_DIR/$filename" 2>&1
    echo "  Generated $filename (${pixel_size}x${pixel_size})"
}

echo "==> Generating iOS app icons from $SOURCE_ICON"

# iPhone icons
generate_icon 20 2 "icon-20@2x.png"
generate_icon 20 3 "icon-20@3x.png"
generate_icon 29 2 "icon-29@2x.png"
generate_icon 29 3 "icon-29@3x.png"
generate_icon 40 2 "icon-40@2x.png"
generate_icon 40 3 "icon-40@3x.png"
generate_icon 60 2 "icon-60@2x.png"
generate_icon 60 3 "icon-60@3x.png"

# iPad icons
generate_icon 20 1 "icon-20.png"
generate_icon 29 1 "icon-29.png"
generate_icon 40 1 "icon-40.png"
generate_icon 76 1 "icon-76.png"
generate_icon 76 2 "icon-76@2x.png"
generate_icon 83.5 2 "icon-83.5@2x.png"

# App Store
generate_icon 1024 1 "icon-1024.png"

echo "==> Done. Icons generated in $ASSETS_DIR"