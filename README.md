## Scanner Pipeline Runner

A tiny wrapper to run the existing pipeline in three steps without changing the original scripts:

- Keep scripts as-is (now under `scripts/`): `scripts/fetch.py`, `scripts/audit.py`, `scripts/summarize.py`
- One command: `./pipeline.sh` (or `make pipeline`)
- Logs saved under `scan_xxx/logs/`

### Prerequisites (Beginner-friendly)

1) Install Python 3.10+.
2) Install `ipatool` (choose ONE method):
   - macOS (recommended): install Homebrew, then `brew install ipatool`.
   - Linux/WSL: run `./scripts/install_ipatool.sh`. If it fails, use the Go method below or download a release asset and place `ipatool` in `/usr/local/bin`.
   - Go method (any OS with Go): `GOBIN=/usr/local/bin go install github.com/majd/ipatool/cmd/ipatool@latest`.
   - Verify: `ipatool --version` should print a version.
3) Optional: install `jq` to make JSON output easier to inspect.

### Quickstart

```bash
IPATOOL_PASSPHRASE=1 WORKERS=8 IPATOOL_PAR=3 ./pipeline.sh  # defaults to BASE=$PWD
```

Or via Makefile:

For detailed non-Docker setup and step-by-step instructions, see `USAGE.md`. For `ipatool` install/sign-in details (what the passphrase is, 2FA, providers), see `IPATOOL_SETUP.md`.

```bash
make pipeline BASE="$PWD" IDS=ids.txt WORKERS=8 IPATOOL_PAR=3
```

### Finding bundle IDs with ipatool (new)

If you don’t already have bundle IDs, you can search the App Store via `ipatool` and write them into a file used by the first stage:

```bash
# Example: search for “zoom” and write 5 results to bundles.txt
python3 scripts/search_bundles.py --query "zoom" --limit 5 --output bundles.txt
# If your ipatool is old or missing, auto-fallback uses iTunes Search API:
python3 scripts/search_bundles.py --engine auto --query "zoom" --limit 5 --output bundles.txt

# Then run the pipeline with those IDs
./pipeline.sh --base "$PWD" --ids bundles.txt
```

Flags:
- `--country us` (optional) to target a storefront
- `--append` to add to an existing bundles file instead of overwriting
- `--engine auto|ipatool|itunes` to choose the search backend (default: auto)

### What the pipeline does

1. Runs `fetch.py --base $PWD [--ids-file ids.txt]` (scripts are resolved under `BASE` first, then the repo dir)
2. Finds the newest `$BASE/scan_*` directory
3. Runs `audit.py "$SCAN_DIR"`
4. Runs `summarize.py "$SCAN_DIR"`

Colored console output shows each step. Logs are written to `scan_xxx/logs/` as:

- `1_fetch.log`
- `2_scan.log`
- `3_clean.log`
- `env.txt` (run metadata)

### Env knobs

- `IPATOOL_PASSPHRASE`: Passphrase for ipatool (required for authenticated fetches)
- `WORKERS` (default: 8): Folder-level concurrency for scanning
- `IPATOOL_PAR` (default: 3): ipatool parallelism (keep low to avoid rate limits)
- `VERBOSE` (default: 1): Set to 0 to reduce console noise
- `FULL_COUNTS` (default: unset): If `1`, force exhaustive counting modes (when supported by scripts)

You can also pass `--base` and `--ids` to the script:

```bash
./pipeline.sh --base "$PWD" --ids ids.txt
# Resume on an existing scan directory (skip fetch):
./pipeline.sh --scan-dir "$PWD/scan_003"
```

### Docker (optional; no local installs needed)

Build:

```bash
docker build -t toolchain:latest .
```

Run (mount the workspace and set a writable BASE inside the container):

```bash
docker run --rm -it \
  -e IPATOOL_PASSPHRASE=1 -e WORKERS=8 -e IPATOOL_PAR=3 -e VERBOSE=1 \
  -e BASE=/work/private/scanner \
  -v "$PWD":/work -w /work \
  toolchain:latest ./pipeline.sh --base /work/private/scanner
```

If `ipatool` is not found, the image will attempt to install it automatically. If you prefer to bring your own, mount it:

```bash
docker run --rm -it \
  -v /path/to/ipatool:/usr/local/bin/ipatool:ro \
  -v "$PWD":/work -w /work toolchain:latest ./pipeline.sh
```

### Manual ipatool install (if not using Docker/devcontainer)

Linux/macOS quick method:

```bash
./scripts/install_ipatool.sh
# Verify
ipatool --version

If the script doesn't work for your CPU/OS, download the proper asset from `https://github.com/majd/ipatool/releases`, extract it, and put the `ipatool` binary somewhere on your PATH (e.g., `/usr/local/bin`). Then run `chmod +x` and verify with `ipatool --version`.

Tip: On Apple Silicon (arm64), ensure you download the `arm64` build.

If you have Go installed, you can also do (correct package path):
```bash
GOBIN=/usr/local/bin go install github.com/majd/ipatool/cmd/ipatool@latest
ipatool --version
```

macOS users: Homebrew is the simplest approach:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install ipatool
ipatool --version
```

Windows users: Use WSL (Ubuntu) and follow the Linux steps above, or install Go for Windows and build from source.

### Where results are saved and ignored by git

- A new folder `scan_YYYYMMDD_HHMMSS` is created under your chosen `BASE` (default: `/home/projects/private/scanner`).
- Logs are under `scan_xxx/logs/` with details of each step.
- Extracted IPA contents and generated summaries are stored inside the `scan_xxx` directory.
- These outputs are ignored by git via `.gitignore` to keep the repo clean.
```

### CI (optional)

See `.github/workflows/pipeline.yml` for a manual (dispatch-only) workflow that runs the pipeline and uploads the latest `scan_xxx` folder as an artifact. Provide `IPATOOL_PASSPHRASE` as a repository secret if needed.

### How to speed up slow HTTP-heavy steps (reference)

If/when you update the scripts, consider the following patterns to dramatically reduce latency and bandwidth:

- Early-exit counts: stop when `≥ 2` found (Storage, Firestore, RTDB)
- Reduce payload size: request partial responses with `fields=...&prettyPrint=false`
- Use count APIs: Firestore `documents:runAggregationQuery` (COUNT(*))
- Parallelize safely: folder-level concurrency and optional prefix sharding
- Avoid duplicates: cache results per `project_id`/`bucket` during a run
- Networking tweaks: `requests.Session`, gzip, keep-alive, exponential backoff

These are defaults for the public runner UX; the Python scripts can progressively adopt them without changing the wrapper.


