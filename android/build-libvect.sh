#!/bin/bash
# Build Android standalone executable from Go source for multiple architectures
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$SCRIPT_DIR/app/src/main/assets"
BIN_DIR="$ASSETS_DIR/bin"

# Clean previous builds
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

# Copy web assets for embedding
echo "==> Copying web assets..."
rm -rf "$SCRIPT_DIR/libvect/web"
cp -r "$PROJECT_DIR/ios/libvect/web" "$SCRIPT_DIR/libvect/web"

echo "==> Building for Android (arm64)..."
cd "$PROJECT_DIR"

export CGO_ENABLED=0
export GOOS=android

echo "  -> Building arm64..."
GOARCH=arm64 GOOS=android go build \
    -buildmode=pie \
    -ldflags="-s -w" \
    -o "$BIN_DIR/vect_server_arm64" \
    ./android/libvect/
echo "    -> $BIN_DIR/vect_server_arm64 ($(ls -lh "$BIN_DIR/vect_server_arm64" | awk '{print $5}'))"

# Copy as main binary
cp "$BIN_DIR/vect_server_arm64" "$BIN_DIR/vect_server"

# Clean up copied web assets
rm -rf "$SCRIPT_DIR/libvect/web"

echo ""
echo "Done. Built:"
echo "  $BIN_DIR/vect_server ($(ls -lh "$BIN_DIR/vect_server" | awk '{print $5}'))"