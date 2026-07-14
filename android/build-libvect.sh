#!/bin/bash
# Build Android standalone binary for multiple architectures.
# Output goes to jniLibs/ so the system PackageManager extracts it
# to the native library directory, which is always executable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

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
rm -rf "$JNILIBS_DIR"
mkdir -p "$JNILIBS_DIR/arm64-v8a"

cd "$PROJECT_DIR"

export CGO_ENABLED=0
export GOOS=android

echo "==> Building for Android..."

echo "  -> Building arm64..."
GOARCH=arm64 $GO build -buildmode=pie -ldflags="-s -w" \
  -o "$JNILIBS_DIR/arm64-v8a/libvect_server.so" \
  ./android/libvect/
echo "    -> $JNILIBS_DIR/arm64-v8a/libvect_server.so ($(ls -lh "$JNILIBS_DIR/arm64-v8a/libvect_server.so" | awk '{print $5}'))"

# amd64 build: only if patchelf is available (for x86_64 emulators)
if command -v patchelf &>/dev/null; then
  echo "  -> Building amd64 (GOOS=linux + patchelf)..."
  mkdir -p "$JNILIBS_DIR/x86_64"
  GOARCH=amd64 GOOS=linux $GO build -buildmode=pie -ldflags="-s -w" \
    -o /tmp/vect_server_amd64_linux ./android/libvect/
  patchelf --set-interpreter "/system/bin/linker64" \
    --output "$JNILIBS_DIR/x86_64/libvect_server.so" \
    /tmp/vect_server_amd64_linux
  echo "    -> $JNILIBS_DIR/x86_64/libvect_server.so ($(ls -lh "$JNILIBS_DIR/x86_64/libvect_server.so" | awk '{print $5}'))"
else
  echo "  -> Skipping amd64 build (patchelf not installed)"
fi

echo ""
echo "Done. Binaries are in $JNILIBS_DIR"