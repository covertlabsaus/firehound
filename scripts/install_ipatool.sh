#!/usr/bin/env bash
set -Eeuo pipefail

# Install ipatool on Linux/macOS using prebuilt binaries when possible.
# Fallback to `go install` if Go is available.

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  armv7l) ARCH="armv7" ;;
  *) ARCH="$ARCH_RAW" ;;
esac

INSTALL_DIR="/usr/local/bin"
if [[ ! -w "$INSTALL_DIR" ]]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  echo "Installing to $INSTALL_DIR (not writable: /usr/local/bin)"
fi

echo "Installing ipatool for ${OS}/${ARCH} into ${INSTALL_DIR}"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

download_and_place() {
  local url="$1"
  local dest="$2"
  echo "Trying $url"
  if curl -fsSL "$url" -o "$dest"; then
    chmod +x "$dest" || true
    return 0
  fi
  return 1
}

is_valid_binary() {
  local file_path="$1"
  # Prefer 'file' utility if available
  if command -v file >/dev/null 2>&1; then
    if file "$file_path" | grep -qiE 'ELF|Mach-O'; then
      return 0
    else
      return 1
    fi
  fi
  # Fallback: try executing with --version
  if "$file_path" --version >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

BIN_PATH="$INSTALL_DIR/ipatool"

# Try simple direct download first (common naming)
if [[ "$OS" == "linux" || "$OS" == "darwin" ]]; then
  if download_and_place "https://github.com/majd/ipatool/releases/latest/download/ipatool-${OS}-${ARCH}" "$BIN_PATH"; then
    if is_valid_binary "$BIN_PATH"; then
      echo "Installed: $("$BIN_PATH" --version || true)"
      exit 0
    else
      rm -f "$BIN_PATH" || true
    fi
  fi
fi

# Try GitHub API to discover asset
if command -v jq >/dev/null 2>&1; then
  echo "Discovering asset via GitHub API..."
  api_json="$tmpdir/release.json"
  if curl -fsSL "https://api.github.com/repos/majd/ipatool/releases/latest" -o "$api_json"; then
    mapfile -t all_urls < <(jq -r '.assets[].browser_download_url' "$api_json" | grep -i "$OS" | grep -i -E "$ARCH|x86_64|aarch64" || true)
    binary_urls=()
    archive_urls=()
    for u in "${all_urls[@]:-}"; do
      if [[ "$u" =~ \.(tar\.gz|tgz|zip)$ ]]; then
        archive_urls+=("$u")
      else
        binary_urls+=("$u")
      fi
    done

    # Try direct binary assets first
    for u in "${binary_urls[@]:-}"; do
      if download_and_place "$u" "$BIN_PATH"; then
        if is_valid_binary "$BIN_PATH"; then
          echo "Installed: $("$BIN_PATH" --version || true)"
          exit 0
        else
          rm -f "$BIN_PATH" || true
        fi
      fi
    done

    # Try archives next
    for u in "${archive_urls[@]:-}"; do
      echo "Downloading archive $u"
      arc="$tmpdir/ipatool.arc"
      if curl -fsSL "$u" -o "$arc"; then
        if [[ "$u" =~ \.(tar\.gz|tgz)$ ]]; then
          tar -xzf "$arc" -C "$tmpdir" || true
        else
          if command -v unzip >/dev/null 2>&1; then
            unzip -o "$arc" -d "$tmpdir" >/dev/null || true
          else
            echo "unzip not available; skipping zip archive"
            continue
          fi
        fi
        bin_candidate="$(find "$tmpdir" -type f -name ipatool -perm -u+x -print -quit)"
        if [[ -z "$bin_candidate" ]]; then
          bin_candidate="$(find "$tmpdir" -type f -name ipatool -print -quit)"
        fi
        if [[ -n "$bin_candidate" && -f "$bin_candidate" ]]; then
          mv "$bin_candidate" "$BIN_PATH" && chmod +x "$BIN_PATH"
          if is_valid_binary "$BIN_PATH"; then
            echo "Installed: $("$BIN_PATH" --version || true)"
            exit 0
          else
            rm -f "$BIN_PATH" || true
          fi
        fi
      fi
    done
  fi
fi

# Fallback: go install if available
if command -v go >/dev/null 2>&1; then
  echo "Falling back to: go install github.com/majd/ipatool/cmd/ipatool@latest"
  GOBIN="$INSTALL_DIR" go install github.com/majd/ipatool/cmd/ipatool@latest || true
  if command -v ipatool >/dev/null 2>&1 || [[ -x "$BIN_PATH" ]]; then
    echo "Success: $(ipatool --version || true)"
    exit 0
  fi
fi

echo "Failed to install ipatool automatically. Please install it manually and ensure it is in PATH."
exit 1


