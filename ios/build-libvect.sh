#!/bin/bash
# Build iOS static library from Go source
# Requires: macOS + Xcode + Go with CGO

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_DIR="$SCRIPT_DIR/libvect"
OUTPUT_DIR="$SCRIPT_DIR/VectApp"

# Generate app icons (requires macOS)
echo "==> Generating iOS app icons..."
"$SCRIPT_DIR/generate-icons.sh"

SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(xcrun --sdk iphoneos --find clang)

export CGO_ENABLED=1
export GOOS=ios
export GOARCH=arm64
export CC="$CLANG -arch arm64 -isysroot $SDK_PATH -miphoneos-version-min=16.0"
export CGO_CFLAGS="-isysroot $SDK_PATH -arch arm64 -miphoneos-version-min=16.0"

echo "==> Compiling Go static library for iOS arm64..."

cd "$PROJECT_DIR"
go build -buildmode=c-archive \
  -tags ios \
  -o "$OUTPUT_DIR/libvect.a" \
  ./ios/libvect/

echo "==> Generated:"
ls -lh "$OUTPUT_DIR/libvect.a" "$OUTPUT_DIR/libvect.h"

echo ""
echo "Done. libvect.a and libvect.h are in $OUTPUT_DIR"
echo "Open VectApp.xcodeproj in Xcode and build."