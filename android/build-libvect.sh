#!/bin/bash
# Build Android shared library (.so) from Go source for multiple architectures
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
JNILIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"
CPP_DIR="$SCRIPT_DIR/app/src/main/cpp"

# Clean previous builds
rm -rf "$JNILIBS_DIR"/*/libvect.so "$CPP_DIR/libvect.h"
mkdir -p "$JNILIBS_DIR/arm64-v8a" "$JNILIBS_DIR/armeabi-v7a" "$JNILIBS_DIR/x86_64"

# Detect NDK
NDK_DIR=""
if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    NDK_DIR="$ANDROID_NDK_HOME"
elif [ -n "${ANDROID_NDK_ROOT:-}" ]; then
    NDK_DIR="$ANDROID_NDK_ROOT"
elif [ -d "$ANDROID_HOME/ndk" ]; then
    NDK_DIR=$(ls -d "$ANDROID_HOME/ndk/"*/ 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$NDK_DIR" ]; then
    # Try finding NDK in common locations
    for d in /usr/local/lib/android/sdk/ndk/*/ /opt/android-sdk/ndk/*/ ~/Android/Sdk/ndk/*/; do
        if [ -d "$d" ]; then
            NDK_DIR="$d"
            break
        fi
    done
fi

if [ -z "$NDK_DIR" ]; then
    echo "Error: Android NDK not found. Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT"
    exit 1
fi

echo "==> Using NDK: $NDK_DIR"

TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$TOOLCHAIN" ]; then
    TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/darwin-x86_64"
fi
if [ ! -d "$TOOLCHAIN" ]; then
    TOOLCHAIN="$NDK_DIR/toolchains/llvm/prebuilt/windows-x86_64"
fi

echo "==> Toolchain: $TOOLCHAIN"

export CGO_ENABLED=1
cd "$PROJECT_DIR"

build_arch() {
    local goarch="$1"
    local cc_name="$2"
    local out_dir="$3"
    local goarm="${4:-}"

    echo "==> Building for $goarch..."
    export GOOS=android
    export GOARCH="$goarch"
    export CC="$TOOLCHAIN/bin/${cc_name}"

    if [ -n "$goarm" ]; then
        export GOARM="$goarm"
    fi

    go build \
        -buildmode=c-shared \
        -ldflags="-s -w" \
        -o "$out_dir/libvect.so" \
        ./ios/libvect/

    echo "    -> $out_dir/libvect.so ($(ls -lh "$out_dir/libvect.so" | awk '{print $5}'))"
}

build_arch "arm64" "aarch64-linux-android21-clang" "$JNILIBS_DIR/arm64-v8a"
build_arch "arm" "armv7a-linux-androideabi21-clang" "$JNILIBS_DIR/armeabi-v7a" "7"
build_arch "amd64" "x86_64-linux-android21-clang" "$JNILIBS_DIR/x86_64"

# Copy header (same for all architectures)
cp "$JNILIBS_DIR/arm64-v8a/libvect.h" "$CPP_DIR/libvect.h"

echo ""
echo "Done. Built for:"
echo "  arm64-v8a   $(ls -lh $JNILIBS_DIR/arm64-v8a/libvect.so | awk '{print $5}')"
echo "  armeabi-v7a $(ls -lh $JNILIBS_DIR/armeabi-v7a/libvect.so | awk '{print $5}')"
echo "  x86_64      $(ls -lh $JNILIBS_DIR/x86_64/libvect.so | awk '{print $5}')"