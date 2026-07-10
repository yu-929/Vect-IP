#!/bin/bash
set -euo pipefail

REPO="yu-929/Vect-IP"
BIN="vect"
INSTALL_DIR="/usr/local/bin"
BIN_PATH="${INSTALL_DIR}/${BIN}"

detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
  esac
  case "$OS" in linux|darwin) ;; *) echo "Unsupported OS: $OS"; exit 1 ;; esac
}

get_latest_url() {
  curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep "browser_download_url.*${OS}-${ARCH}" \
    | head -1 \
    | cut -d: -f2- \
    | tr -d ' "'
}

do_install() {
  detect_platform
  echo "Fetching latest release for ${OS}/${ARCH}..."
  URL=$(get_latest_url)
  if [ -z "$URL" ]; then
    echo "Failed to find release for ${OS}/${ARCH}"
    exit 1
  fi

  TMP_DIR=$(mktemp -d)
  trap "rm -rf $TMP_DIR" EXIT

  echo "Downloading..."
  curl -#L "$URL" | tar -xz -C "$TMP_DIR"

  echo "Installing to ${BIN_PATH}..."
  install -m 755 "$TMP_DIR/${BIN}" "$BIN_PATH"

  if command -v $BIN &>/dev/null; then
    echo "Installed: $(command -v $BIN)"
    echo ""
    echo "Quick start:"
    echo "  $BIN -v --out text --cidr-file ./ipv4cidr.txt --budget 3000 --concurrency 100"
  else
    echo "Installation failed: ${BIN} not found in PATH"
    exit 1
  fi
}

do_update() {
  if [ ! -f "$BIN_PATH" ]; then
    echo "Not installed yet. Run install first or use: $0 install"
    exit 1
  fi
  echo "Updating ${BIN}..."
  do_install
}

do_uninstall() {
  if [ -f "$BIN_PATH" ]; then
    rm -f "$BIN_PATH"
    echo "Removed ${BIN_PATH}"
  else
    echo "Not installed at ${BIN_PATH}"
  fi
}

case "${1:-install}" in
  install|i)
    do_install
    ;;
  update|up|u)
    do_update
    ;;
  uninstall|remove|rm)
    do_uninstall
    ;;
  *)
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install (default)  Install or reinstall ${BIN}"
    echo "  update             Update ${BIN} to latest version"
    echo "  uninstall          Remove ${BIN}"
    echo ""
    echo "Run example:"
    echo "  $BIN -v --out text --cidr-file ./ipv4cidr.txt --budget 3000 --concurrency 100"
    exit 1
    ;;
esac