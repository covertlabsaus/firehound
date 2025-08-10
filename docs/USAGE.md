## Usage Guide (No Docker Required)

This guide explains how to run the pipeline locally without Docker or devcontainers. It covers prerequisites, installation, configuration, and step-by-step usage.

### 1) Prerequisites

- Python 3.10+
- `ipatool` installed and in your PATH
  - macOS: `brew install ipatool`
  - Linux/WSL: run `./scripts/install_ipatool.sh` or download from GitHub Releases and place `ipatool` into `/usr/local/bin` (make it executable)
  - Go-based install (any OS): `GOBIN=/usr/local/bin go install github.com/majd/ipatool/cmd/ipatool@latest`
  - Verify: `ipatool --version`
- Optional but recommended: `jq` for pretty-printing JSON (`sudo apt-get install jq` on Debian/Ubuntu)

### 2) Clone and prepare

```bash
git clone <this-repo-url>
cd scanner
chmod +x pipeline.sh
```

If your shell requires it, also make the helper script executable:
```bash
chmod +x ./scripts/install_ipatool.sh
```

### 3) Choose an output base directory

By default outputs go to the current working directory (`$PWD`). You can keep that or point to a different writable directory.

Examples:
- Use default: no action needed
- Use a local folder inside the repo: `export BASE="$(pwd)/.runs"`
- Use another path: `export BASE="/path/to/private/scanner"`

The pipeline always writes results inside a `scan_###` subfolder of `BASE`.

### 3.1) Get bundle IDs via ipatool (optional)

If you don’t have bundle identifiers yet, use the helper to search the App Store and write them into a file:

```bash
python3 search_bundles.py --query "zoom" --limit 5 --output bundles.txt
# Optional flags: --country us | --append
```

Use that file with the first stage via `--ids bundles.txt` (shown below).

### 4) Provide an Apple ID passphrase for ipatool

`ipatool` may prompt for a passphrase. Provide it via the env var `IPATOOL_PASSPHRASE` to allow non-interactive runs.

```bash
export IPATOOL_PASSPHRASE="1"   # replace with your passphrase
```

### 5) Optional inputs and knobs

- `IDS` or `--ids`: path to a file containing bundle identifiers, one per line. If omitted, a built-in list is used.
- `WORKERS` (default 8): folder-level parallelism when summarizing/cleaning.
- `IPATOOL_PAR` (default 3): concurrent ipatool downloads. Keep low to avoid rate limiting.
- `VERBOSE` (default 1): set `0` to reduce console output.
- `FULL_COUNTS` (unset by default): set to `1` to enable more exhaustive counting where supported.

### 6) Running the pipeline (recommended)

One-liner:
```bash
IPATOOL_PASSPHRASE="$IPATOOL_PASSPHRASE" WORKERS=8 IPATOOL_PAR=3 ./pipeline.sh --base "${BASE:-$PWD}" ${IDS:+--ids "$IDS"}
```

Or with `make`:
```bash
make pipeline BASE="${BASE:-$PWD}" IDS="$IDS" WORKERS=8 IPATOOL_PAR=3
```

What this does:
1. Runs `fetch.py` to download IPAs by bundle ID, extracts `Info.plist` and `GoogleService-Info.plist`, and creates a new `scan_###` folder under `BASE`.
2. Detects the newest `scan_###` folder as `SCAN_DIR`.
3. Runs `audit.py SCAN_DIR` to audit Firebase endpoints and write `*_audit.json`.
4. Runs `summarize.py SCAN_DIR` to summarize results, optionally fetch more plists based on findings, and prune non-interesting folders.

All logs are written under `SCAN_DIR/logs/`:
- `1_fetch.log`
- `2_scan.log`
- `3_clean.log`
- `env.txt` (run metadata)

### 7) Supplying bundle IDs

Create a text file with one bundle identifier per line, comments allowed with `#`:
```text
# Example
com.openai.chat
us.zoom.videomeetings
```
Then run with:
```bash
./pipeline.sh --base "$BASE" --ids ids.txt
```

### 8) Where outputs go

- `BASE/scan_###/` contains one subfolder per bundle ID that had plists extracted.
- Each folder may include `GoogleService-Info.plist`, `Info.plist`, `*_audit.json`, and `*_vuln_summary.json`.
- Some runs may also create `all_plists/` with every `.plist` from the IPA if counts indicate data presence.
- All of these are ignored by git via `.gitignore`.

### 9) Troubleshooting

- `ipatool not found`: ensure it’s installed and in PATH; try `./scripts/install_ipatool.sh` or the Go install path.
- Authentication failures: confirm `IPATOOL_PASSPHRASE` is correct. The first `fetch.py` stage prints ipatool output into `logs/1_fetch.log`.
- Permission errors on `BASE`: pick a writable path and pass it via `--base`.
- Slow runs / rate limits: reduce `IPATOOL_PAR` and/or `WORKERS`.
- Missing `*_audit.json`: check `scan.py` logs; ensure `GoogleService-Info.plist` exists in each app folder.

### 10) Advanced

- Run individual stages manually:
  - Stage 1: `python3 fetch.py --base "$BASE" --ids-file ids.txt`
  - Stage 2: `python3 audit.py "$BASE/scan_###"`
  - Stage 3: `python3 summarize.py "$BASE/scan_###"`
- Silence output: `VERBOSE=0 ./pipeline.sh ...`
- Force exhaustive counts: `FULL_COUNTS=1 ./pipeline.sh ...`

### 11) Security considerations

- This pipeline makes HTTP requests to Firebase endpoints based on discovered config in apps you download. Use responsibly and respect terms of service.
- Avoid committing credentials or run artifacts; `.gitignore` excludes common outputs and `.env` patterns.
- Consider running from a dedicated environment or container if scanning untrusted inputs.
