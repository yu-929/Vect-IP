#!/bin/bash
# Build Android standalone executable from Go source for multiple architectures
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ASSETS_DIR="$SCRIPT_DIR/app/src/main/assets"
BIN_DIR="$ASSETS_DIR/bin"

# Detect Go toolchain: prefer Go 1.24 to avoid Go 1.25 Android ARM64 SIGILL
if [ -x /tmp/go/bin/go ]; then
  GO=/tmp/go/bin/go
  export GOROOT=/tmp/go
  export GOCACHE=/tmp/gocache124
elif command -v go &>/dev/null; then
  GO=$(command -v go)
else
  echo "ERROR: Go is not installed. Install Go 1.24+ and try again."
  exit 1
fi

echo "Using Go: $($GO version)"

# Clean previous builds
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR"

# Copy web assets for embedding
echo "==> Copying web assets..."
rm -rf "$SCRIPT_DIR/libvect/web"
cp -r "$PROJECT_DIR/ios/libvect/web" "$SCRIPT_DIR/libvect/web"

cd "$PROJECT_DIR"

export CGO_ENABLED=0
export GOOS=android

echo "==> Building for Android..."

echo "  -> Building arm64..."
GOARCH=arm64 $GO build -buildmode=pie -ldflags="-s -w" -o "$BIN_DIR/vect_server_arm64" ./android/libvect/
echo "    -> $BIN_DIR/vect_server_arm64 ($(ls -lh "$BIN_DIR/vect_server_arm64" | awk '{print $5}'))"

# amd64 build: only if patchelf is available (for x86_64 emulators)
if command -v patchelf &>/dev/null; then
  echo "  -> Building amd64 (GOOS=linux + patchelf)..."
  GOARCH=amd64 GOOS=linux $GO build -buildmode=pie -ldflags="-s -w" -o /tmp/vect_server_amd64_linux ./android/libvect/
  patchelf --set-interpreter "/system/bin/linker64" --output "$BIN_DIR/vect_server_amd64" /tmp/vect_server_amd64_linux
  echo "    -> $BIN_DIR/vect_server_amd64 ($(ls -lh "$BIN_DIR/vect_server_amd64" | awk '{print $5}'))"
else
  echo "  -> Skipping amd64 build (patchelf not installed)"
fi

# Clean up copied web assets
rm -rf "$SCRIPT_DIR/libvect/web"

echo ""
echo "Done."