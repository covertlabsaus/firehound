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
  WORKERS              Folder-level concurrency for scanning (default: 8)
  IPATOOL_PAR          Parallelism for ipatool downloads (default: 3)
  VERBOSE              Verbose logs (default: 1)
  FULL_COUNTS          Force exhaustive counting if set to 1 (default: unset/fast)
  FORCE_COLOR          Set to 1 to force ANSI colors even when output is piped

Options:
  --base DIR           Output base dir (default: current working directory). Scripts are looked up in BASE first, then in repo dir.
  --ids FILE           Optional ids file to pass to fetch.py as --ids-file FILE
  --scan-dir DIR       Skip fetch stage and re-run scan/clean on an existing scan directory
  -h, --help           Show this help

Quickstart:
  IPATOOL_PASSPHRASE=1 WORKERS=8 IPATOOL_PAR=3 ./pipeline.sh
EOF
}

BASE="${BASE:-$PWD}"
IDS="${IDS:-}"
SCAN_DIR_ARG="${SCAN_DIR:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      BASE="$2"; shift 2 ;;
    --ids)
      IDS="$2"; shift 2 ;;
    --scan-dir)
      SCAN_DIR_ARG="$2"; shift 2 ;;
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
export WORKERS="${WORKERS:-8}"
export IPATOOL_PAR="${IPATOOL_PAR:-3}"
export FULL_COUNTS="${FULL_COUNTS:-}"

info() { echo -e "${BLUE}${BOLD}[*]${RESET} $*"; }
ok() { echo -e "${GREEN}${BOLD}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}${BOLD}[!]${RESET} $*"; }
fail() { echo -e "${RED}${BOLD}[x]${RESET} $*"; }

trap 'fail "Pipeline failed. See logs above. If step 1 failed, check the temporary log captured before scan dir creation."' ERR

info "Base dir: $BASE"
info "Workers: $WORKERS | ipatool parallelism: $IPATOOL_PAR | Verbose: $VERBOSE | Full counts: ${FULL_COUNTS:-0}"

# Resolve script locations. Prefer scripts under BASE, then repo dir, then repo scripts/ subdir for robustness.
SCRIPTS_DIR="$BASE"
one_py="$SCRIPTS_DIR/fetch.py"
scan_py="$SCRIPTS_DIR/audit.py"
clean_py="$SCRIPTS_DIR/summarize.py"

if [[ ! -f "$one_py" || ! -f "$scan_py" || ! -f "$clean_py" ]]; then
  # Fallback 1: repo root alongside pipeline.sh
  if [[ -f "$script_dir/fetch.py" && -f "$script_dir/audit.py" && -f "$script_dir/summarize.py" ]]; then
    warn "Scripts not found in BASE; using repository directory for scripts instead. Outputs remain under: $BASE"
    SCRIPTS_DIR="$script_dir"
    one_py="$SCRIPTS_DIR/fetch.py"; scan_py="$SCRIPTS_DIR/audit.py"; clean_py="$SCRIPTS_DIR/summarize.py"
  # Fallback 2: repo scripts/ subdirectory
  elif [[ -f "$script_dir/scripts/fetch.py" && -f "$script_dir/scripts/audit.py" && -f "$script_dir/scripts/summarize.py" ]]; then
    warn "Scripts not found in BASE; using repository scripts/ directory instead. Outputs remain under: $BASE"
    SCRIPTS_DIR="$script_dir/scripts"
    one_py="$SCRIPTS_DIR/fetch.py"; scan_py="$SCRIPTS_DIR/audit.py"; clean_py="$SCRIPTS_DIR/summarize.py"
  else
    fail "Could not locate fetch.py, audit.py, and summarize.py in '$BASE', '$script_dir', or '$script_dir/scripts'"; exit 1
  fi
fi
info "Scripts dir: $SCRIPTS_DIR"

# Dependency hints
if ! command -v python3 >/dev/null 2>&1; then
  fail "python3 not found in PATH"; exit 1
fi
if ! command -v ipatool >/dev/null 2>&1; then
  warn "ipatool not found in PATH. Step 1 may fail if ipatool is required."
fi
if ! command -v jq >/dev/null 2>&1; then
  warn "jq not found. It's optional but helpful for inspecting JSON." 
fi

# Step 1: run fetch.py and capture its output in a temp file until we know SCAN_DIR
tmp_dir="$(mktemp -d)"
step1_log_tmp="$tmp_dir/1_fetch.log"

echo
if [[ -n "$SCAN_DIR_ARG" ]]; then
  info "Step 1/3: Resume mode (skip fetch)"
  if [[ ! -d "$SCAN_DIR_ARG" ]]; then
    fail "--scan-dir '$SCAN_DIR_ARG' does not exist or is not a directory"; exit 1
  fi
  SCAN_DIR="$(cd "$SCAN_DIR_ARG" && pwd)"
  LOG_DIR="$SCAN_DIR/logs"
  mkdir -p "$LOG_DIR"
  echo "Resume mode: fetch stage skipped by user. $(date -Is)" > "$LOG_DIR/1_fetch.log"
  rm -rf "$tmp_dir"
  ok "resume prepared"
else
  info "Step 1/3: Fetch inputs via fetch.py"

  set -o pipefail
  ids_arg=()
  if [[ -n "${IDS:-}" ]]; then
    ids_arg=(--ids-file "$IDS")
  fi

  python3 "$one_py" --base "$BASE" "${ids_arg[@]}" 2>&1 | tee "$step1_log_tmp"
  ok "fetch.py completed"

  # Determine newest scan_* directory as the SCAN_DIR
  SCAN_DIR="$(ls -td "$BASE"/scan_* 2>/dev/null | head -n 1 || true)"
  if [[ -z "$SCAN_DIR" || ! -d "$SCAN_DIR" ]]; then
    fail "No scan_* directory found in '$BASE' after fetch.py run"; echo "Bootstrap log:"; cat "$step1_log_tmp"; exit 1
  fi

  LOG_DIR="$SCAN_DIR/logs"
  mkdir -p "$LOG_DIR"
  mv "$step1_log_tmp" "$LOG_DIR/1_fetch.log"
  rm -rf "$tmp_dir"
fi

# Persist run metadata
{
  echo "timestamp=$(date -Is)"
  echo "base=$BASE"
  echo "scan_dir=$SCAN_DIR"
  echo "workers=$WORKERS"
  echo "ipatool_par=$IPATOOL_PAR"
  echo "verbose=$VERBOSE"
  echo "full_counts=${FULL_COUNTS:-0}"
  echo "ids_file=${IDS:-}"
} > "$LOG_DIR/env.txt"

echo
info "Step 2/3: Scan artifacts via audit.py"
python3 "$scan_py" "$SCAN_DIR" 2>&1 | tee "$LOG_DIR/2_scan.log"
ok "audit.py completed"

echo
info "Step 3/3: Clean results via summarize.py"
python3 "$clean_py" "$SCAN_DIR" 2>&1 | tee "$LOG_DIR/3_clean.log"
ok "summarize.py completed"

echo
ok "Pipeline complete. Logs saved under: $LOG_DIR"


