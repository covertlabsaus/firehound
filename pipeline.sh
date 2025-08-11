#!/usr/bin/env bash

# Strict mode
set -Eeuo pipefail

# Colors (fallback to no color if not a TTY; allow override via FORCE_COLOR/CLICOLOR_FORCE)
if [[ -t 1 || "${FORCE_COLOR:-}" = "1" || "${CLICOLOR_FORCE:-}" = "1" ]]; then
  RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; BOLD="\033[1m"; RESET="\033[0m"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
${BOLD}Usage${RESET}: [env VARS] ./pipeline.sh [--base DIR] [--ids FILE]

Env knobs:
  IPATOOL_PASSPHRASE   Passphrase for ipatool authentication (required for fetching)
  VERBOSE              Verbose logs (default: 1)

Options:
  --base DIR           Output base dir (default: current working directory).
  --ids FILE           Optional ids file to pass to the scanner.
  -h, --help           Show this help

Quickstart:
  IPATOOL_PASSPHRASE=1 ./pipeline.sh
EOF
}

BASE="${BASE:-$PWD}"
IDS_FILE_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      BASE="$2"; shift 2 ;;
    --ids)
      IDS_FILE_ARG="--ids-file $2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    --no-color)
      RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""; shift ;;
    *)
      echo -e "${YELLOW}Warning:${RESET} Unknown arg '$1'" >&2; shift ;;
  esac
done

# Normalize BASE to absolute if possible
if [[ -d "$BASE" ]]; then
  BASE="$(cd "$BASE" && pwd)"
fi

# Export env expected by underlying scripts
export IPATOOL_PASSPHRASE="${IPATOOL_PASSPHRASE:-}"
export VERBOSE="${VERBOSE:-1}"

info() { echo -e "${BLUE}${BOLD}[*]${RESET} $*"; }
ok() { echo -e "${GREEN}${BOLD}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}${BOLD}[!]${RESET} $*"; }
fail() { echo -e "${RED}${BOLD}[x]${RESET} $*"; }

trap 'fail "Pipeline failed."' ERR

info "Base dir: $BASE"
info "Verbose: $VERBOSE"

# Dependency hints
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found in PATH"; exit 1
fi
if ! command -v ipatool >/dev/null 2>&1; then
  warn "ipatool not found in PATH. The fetch stage may fail."
fi

# --- Run the main Python application ---
info "Starting scanner application..."
# The main.py script now handles all stages internally.
# We pass the arguments to it.
python3 "${script_dir}/main.py" --base "$BASE" $IDS_FILE_ARG

# The old logic for running audit.py and summarize.py is now
# handled within the Python application. This script is now just a simple
# launcher.

ok "Pipeline complete."