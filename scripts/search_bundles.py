#!/usr/bin/env python3

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import urllib.request, urllib.parse, urllib.error
from pathlib import Path
from typing import Iterable, List, Optional


VERBOSE = os.environ.get("VERBOSE", "1") != "0"
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; RED = "\033[31m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and sys.stdout.isatty())


def vprint(msg: str, color: str = "") -> None:
    if not VERBOSE:
        return
    prefix = color if (COLOR_ENABLED and color) else ""
    suffix = RESET if (COLOR_ENABLED and color) else ""
    print(f"{prefix}{msg}{suffix}" if prefix else msg)
    try:
        sys.stdout.flush()
    except Exception:
        pass


def have_command(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: List[str], timeout: int = 12) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        out = proc.stdout.decode(errors="replace")
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        return 124, "Timed out"
    except Exception as exc:
        return 1, f"Failed to run {' '.join(shlex.quote(c) for c in cmd)}: {exc}"


def parse_bundles_from_text(text: str) -> List[str]:
    bundles: list[str] = []
    # Try explicit label patterns first
    for m in re.finditer(r"(?:Bundle\s*(?:Identifier|ID)|Identifier)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)", text, re.I):
        bundles.append(m.group(1))
    # Fallback: generic reverse-DNS tokens, avoid obvious domains without third segment
    if not bundles:
        for m in re.finditer(r"\b([A-Za-z0-9][A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)\b", text):
            token = m.group(1)
            # Heuristic: skip common file extensions and URLs
            if any(token.endswith(ext) for ext in (".zip", ".ipa", ".json", ".plist")):
                continue
            bundles.append(token)
    # Deduplicate preserving order
    seen = set()
    deduped = []
    for b in bundles:
        if b not in seen:
            seen.add(b)
            deduped.append(b)
    return deduped


def parse_bundles_from_json(text: str) -> Optional[List[str]]:
    try:
        obj = json.loads(text)
    except Exception:
        return None
    candidates: list[str] = []
    items: Iterable = obj
    if isinstance(obj, dict):
        # try common keys
        for key in ("results", "apps", "data", "items"):
            if isinstance(obj.get(key), list):
                items = obj[key]
                break
    if not isinstance(items, list):
        return None
    for it in items:
        if not isinstance(it, dict):
            continue
        for key in ("bundleIdentifier", "bundleId", "bundle_id", "bundle_identifier"):
            val = it.get(key)
            if isinstance(val, str):
                candidates.append(val)
                break
    # Deduplicate preserving order
    seen = set()
    out = []
    for b in candidates:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out


def ipatool_search(term: str, limit: int, country: Optional[str], timeout: int) -> List[str]:
    if not have_command("ipatool"):
        raise SystemExit("ipatool not found in PATH. Install it first and re-try.")

    # Build a set of candidate command lines covering common ipatool variants
    cmds: list[list[str]] = []
    def add(cmd: list[str]):
        cmds.append(cmd)

    # Long flags, term positional before/after
    lf = ["--limit", str(limit)] if limit else []
    cf = (["--country", country] if country else [])
    add(["ipatool", "search", term, *lf, *cf])
    add(["ipatool", "search", *lf, *cf, term])

    # Short flags variants
    sf = (["-l", str(limit)] if limit else [])
    sc = (["-c", country] if country else [])
    add(["ipatool", "search", term, *sf, *sc])
    add(["ipatool", "search", *sf, *sc, term])

    last_out = ""
    for cmd in cmds:
        vprint(f"Running: {' '.join(shlex.quote(c) for c in cmd)}", GREY)
        rc, out = _run(cmd, timeout=timeout)
        last_out = out
        if rc != 0:
            continue
        # Try JSON parse opportunistically
        bundles = parse_bundles_from_json(out) or parse_bundles_from_text(out)
        if bundles:
            vprint(f"Found {len(bundles)} bundle id(s)", GREEN)
            return bundles
    vprint(last_out, YELLOW)
    raise SystemExit("ipatool search failed or produced no recognizable bundle IDs.")


def itunes_search(term: str, limit: int, country: Optional[str], timeout: int) -> List[str]:
    qs = {
        "term": term,
        "entity": "software",
        "limit": str(limit or 10),
    }
    if country:
        qs["country"] = country
    url = f"https://itunes.apple.com/search?{urllib.parse.urlencode(qs)}"
    req = urllib.request.Request(url, headers={"User-Agent": "bundle-search/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        vprint(f"iTunes search error: {exc}", YELLOW)
        return []
    bundles = parse_bundles_from_json(text) or []
    if bundles:
        vprint(f"Found {len(bundles)} bundle id(s) via iTunes Search API", GREEN)
    return bundles


def write_ids(ids: List[str], path: Path, append: bool) -> None:
    existing: list[str] = []
    if append and path.is_file():
        with open(path, "r", encoding="utf-8") as fp:
            for line in fp:
                s = line.strip()
                if s and not s.startswith("#"):
                    existing.append(s)
    # merge and dedupe
    seen = set(existing)
    merged = existing[:]
    for i in ids:
        if i not in seen:
            seen.add(i)
            merged.append(i)
    with open(path, "w", encoding="utf-8") as fp:
        for bid in merged:
            fp.write(bid + "\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Search the App Store via ipatool and write bundle IDs to a file.")
    p.add_argument("positionals", nargs="*", help="Optional: you can pass 'search' and the query as positionals")
    p.add_argument("--query", "-q", required=False, help="Search term (app name, developer, etc.)")
    p.add_argument("--limit", "-n", type=int, default=10, help="Max results to return (default: 10)")
    p.add_argument("--country", "-c", default=None, help="Country/storefront (e.g., us, gb, de)")
    p.add_argument("--output", "-o", default="bundles.txt", help="Output file path (default: bundles.txt)")
    p.add_argument("--append", action="store_true", help="Append results to the output file instead of overwriting")
    p.add_argument("--timeout", type=int, default=12, help="Per-attempt network timeout in seconds (default: 12)")
    p.add_argument("--engine", choices=["auto","ipatool","itunes"], default="auto", help="Search engine (default: auto)")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    term = (args.query or "").strip()
    if not term:
        # Accept positional usage:  [search] <term with spaces...>
        parts = [p for p in args.positionals if p.lower() != "search"]
        if parts:
            term = " ".join(parts).strip()
    if not term:
        raise SystemExit("Provide a query via --query/-q or as a positional argument")

    vprint(f"Searching for: {term} (limit={args.limit}, country={args.country or 'default'}, engine={args.engine})", GREY)
    bundles: List[str] = []
    if args.engine in ("auto","ipatool"):
        try:
            bundles = ipatool_search(term=term, limit=args.limit, country=args.country, timeout=args.timeout)
        except SystemExit as se:
            if args.engine == "ipatool":
                raise
            vprint(str(se), YELLOW)
        except Exception as exc:
            if args.engine == "ipatool":
                raise
            vprint(f"ipatool search failed: {exc}", YELLOW)
    if not bundles and args.engine in ("auto","itunes"):
        bundles = itunes_search(term=term, limit=args.limit, country=args.country, timeout=args.timeout)
    if not bundles:
        print("No bundle identifiers found for the given query")
        return
    out_path = Path(args.output).expanduser().resolve()
    write_ids(bundles, out_path, append=args.append)
    print(f"Wrote {len(bundles)} bundle id(s) to {out_path}")


if __name__ == "__main__":
    main()


