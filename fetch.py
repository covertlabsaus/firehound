#!/usr/bin/env python3

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import zipfile
import plistlib
from pathlib import Path
from typing import Optional, Tuple

# Verbose logging with optional ANSI colors
VERBOSE = os.environ.get("VERBOSE", "1") != "0"
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))

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

BUNDLE_IDS = [
"au.gov.ato.ATOTax",
"com.humanservices.Centrelink",
"JEC2FK53N4.com.xero.XeroTouch",
"com.itwcalculator.calculatorforipadfree",
"com.changiairport.cagapp",
"com.ninjakiwi.bloonstdbattles",
"com.txtvault.apple.atotaxcalc",
"com.globalblue.ios.Global-Blue",
"co.smartreceipts.ios",
"com.alipay.iphoneclient",
"com.fiverr.fiverr",
"com.driversnote.driversnote",
"com.guyescalculator.calculatorprofree",
"com.lamig-software.Tax-Calc-Aussie",
"au.com.etax.mobileapp",
"com.theapptower.calculator",
"com.intuit.QBOiPad",
"nz.hnry.ios",
"com.pid.turnipboy",
"com.paul.bmttax",
"com.intuit.qbse",
"com.ruizhang.TaxCalculator",
]

def have_command(command_name: str) -> bool:
    return shutil.which(command_name) is not None


def run_ipatool_download(bundle_id: str, ipa_path: Path, passphrase: str, timeout_seconds: int) -> Tuple[bool, Optional[str]]:
    """
    Runs `ipatool download` in a pseudo-tty via `script`, feeding the passphrase on stdin.
    Returns (success, combined_output_str_or_None).
    """
    cmd_str = (
        f"ipatool download --bundle-identifier {shlex.quote(bundle_id)} "
        f"--purchase --output {shlex.quote(str(ipa_path))}"
    )

    env = os.environ.copy()
    # Mirror shell snippets' behavior; also expose in env just in case
    env.setdefault("IPATOOL_PASSPHRASE", passphrase)

    if have_command("script"):
        cmd = [
            "script",
            "-q",
            "/dev/null",
            "-c",
            cmd_str,
        ]
    else:
        # Fallback to direct call (may fail if ipatool insists on a TTY)
        cmd = shlex.split(cmd_str)

    try:
        proc = subprocess.run(
            cmd,
            input=(passphrase + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
        output_text = proc.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return False, "Timed out while running ipatool"
    except Exception as exc:
        return False, f"Failed to run ipatool: {exc}"

    return ipa_path.is_file(), output_text


def find_members(zf: zipfile.ZipFile) -> Tuple[Optional[str], Optional[str]]:
    names = zf.namelist()
    info_regex = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
    google_regex = re.compile(r"^Payload/[^/]+\.app/GoogleService-Info\.plist$")
    info_path = next((n for n in names if info_regex.match(n)), None)
    google_path = next((n for n in names if google_regex.match(n)), None)
    return info_path, google_path


def extract_member_to_basename(zf: zipfile.ZipFile, member: str, out_dir: Path) -> Path:
    out_path = out_dir / Path(member).name
    with zf.open(member) as src, open(out_path, "wb") as dst:
        dst.write(src.read())
    return out_path


def convert_plist_to_xml_if_binary(plist_path: Path) -> None:
    if not plist_path.is_file():
        return
    try:
        with open(plist_path, "rb") as fp:
            header = fp.read(8)
        if header.startswith(b"bplist00"):
            with open(plist_path, "rb") as fp:
                data = plistlib.load(fp)
            with open(plist_path, "wb") as fp:
                plistlib.dump(data, fp, fmt=plistlib.FMT_XML)
    except Exception:
        # Leave file as-is on any parse error
        pass


def process_bundle_id(bundle_id: str, base_dir: Path, passphrase: str, timeout_seconds: int) -> None:
    outdir = base_dir / bundle_id
    outdir.mkdir(parents=True, exist_ok=True)
    ipa_path = outdir / f"{bundle_id}.ipa"

    vprint(f"Downloading IPA for {bundle_id}", BLUE)
    ok, output = run_ipatool_download(bundle_id, ipa_path, passphrase, timeout_seconds)
    if output:
        try:
            # Mirror shell behavior of piping through cat
            vprint(output, GREY)
        except Exception:
            pass

    if not ok:
        vprint(f"FAILED: {bundle_id}", RED)
        return

    try:
        with zipfile.ZipFile(ipa_path) as zf:
            info_member, google_member = find_members(zf)
            if info_member:
                extract_member_to_basename(zf, info_member, outdir)
            if google_member:
                extract_member_to_basename(zf, google_member, outdir)
    except Exception:
        # Ignore extraction errors and proceed to cleanup/print as in the shell script
        pass

    # Convert plists if they are binary
    convert_plist_to_xml_if_binary(outdir / "Info.plist")
    convert_plist_to_xml_if_binary(outdir / "GoogleService-Info.plist")

    # Remove IPA as in the shell snippets
    try:
        if ipa_path.exists():
            ipa_path.unlink()
    except Exception:
        pass

    vprint(f"EXTRACTED: {bundle_id} -> {outdir}", GREEN)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download IPAs and extract plists for bundle identifiers.")
    parser.add_argument(
        "--base",
        default=os.getcwd(),
        help="Base output directory (default: current working directory)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Per-download timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--ids-file",
        default=None,
        help="Optional path to a file with one bundle identifier per line. If omitted, built-in list is used.",
    )
    parser.add_argument(
        "--passphrase",
        default=os.environ.get("IPATOOL_PASSPHRASE", "1"),
        help="Passphrase to feed into ipatool (default from IPATOOL_PASSPHRASE env or '1')",
    )
    return parser.parse_args()


def load_ids(ids_file: Optional[str]) -> list:
    if not ids_file:
        return BUNDLE_IDS
    path = Path(ids_file)
    if not path.is_file():
        return BUNDLE_IDS
    ids = []
    with open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            ids.append(s)
    # Deduplicate while preserving order
    seen = set()
    unique_ids = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            unique_ids.append(i)
    return unique_ids


def create_next_scan_dir(root: Path, prefix: str = "scan_") -> Path:
    """
    Create a new subdirectory under root named like scan_### where ### increments
    based on existing siblings. Returns the created directory path.
    """
    max_n = 0
    try:
        for child in root.iterdir():
            if child.is_dir() and child.name.startswith(prefix):
                suffix = child.name[len(prefix):]
                if suffix.isdigit():
                    max_n = max(max_n, int(suffix))
    except FileNotFoundError:
        root.mkdir(parents=True, exist_ok=True)
    # attempt to create next available directory, guarding against races
    n = max_n + 1
    while True:
        candidate = root / f"{prefix}{n:03d}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            n += 1


def main() -> None:
    args = parse_args()
    base_dir = Path(args.base).expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    # Create a new numeric scan directory under the scanner root
    scan_dir = create_next_scan_dir(base_dir)
    vprint(f"Scan output directory: {scan_dir}", MAGENTA)

    # Ensure env var is set to mirror shell behavior
    os.environ.setdefault("IPATOOL_PASSPHRASE", args.passphrase)

    bundle_ids = load_ids(args.ids_file)
    for bid in bundle_ids:
        process_bundle_id(bid, scan_dir, args.passphrase, args.timeout)


if __name__ == "__main__":
    main()


