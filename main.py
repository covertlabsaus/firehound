import argparse
import os
from pathlib import Path
from datetime import datetime, timezone

from scanner.models import ScanRun, AppScan
from scanner.fetcher import Fetcher
from scanner.auditor import Auditor
from scanner.summarizer import Summarizer
from scanner.reporter import Reporter

# Default list of bundle IDs, moved from fetch.py
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

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="iOS Application Security Scanner")
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

def load_ids(ids_file: str = None) -> list:
    if not ids_file:
        return BUNDLE_IDS
    path = Path(ids_file)
    if not path.is_file():
        return BUNDLE_IDS
    with open(path, "r", encoding="utf-8") as fp:
        ids = [line.strip() for line in fp if line.strip() and not line.startswith("#")]
    # Deduplicate while preserving order
    return sorted(list(set(ids)))

def create_next_scan_dir(root: Path, prefix: str = "scan_") -> Path:
    max_n = 0
    try:
        for child in root.iterdir():
            if child.is_dir() and child.name.startswith(prefix):
                suffix = child.name[len(prefix):]
                if suffix.isdigit():
                    max_n = max(max_n, int(suffix))
    except FileNotFoundError:
        root.mkdir(parents=True, exist_ok=True)
    
    n = max_n + 1
    while True:
        candidate = root / f"{prefix}{n:03d}"
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            n += 1

def main():
    args = parse_args()
    
    base_dir = Path(args.base).expanduser().resolve()
    scan_dir = create_next_scan_dir(base_dir)
    
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    
    config = {
        "passphrase": args.passphrase,
        "timeout": args.timeout,
    }
    
    bundle_ids = load_ids(args.ids_file)
    
    app_scans = [AppScan(bundle_id=bid, scan_dir=scan_dir / bid) for bid in bundle_ids]
    
    scan_run = ScanRun(
        run_id=run_id,
        base_dir=scan_dir,
        app_scans=app_scans,
        config=config,
    )
    
    # --- Fetch Stage ---
    fetcher = Fetcher(scan_run)
    fetcher.run()
    
    # --- Audit Stage ---
    auditor = Auditor(scan_run)
    auditor.run()
    
    # --- Summarize Stage ---
    summarizer = Summarizer(scan_run)
    summarizer.run()
    
    # --- Report Stage ---
    reporter = Reporter(scan_run)
    reporter.run()
    
    # --- Print Results for now ---
    print("\n--- Scan Run Complete ---")
    for app_scan in scan_run.app_scans:
        print(f"Bundle ID: {app_scan.bundle_id}")
        print(f"  Status: {app_scan.status}")
        if app_scan.audit_result and app_scan.audit_result.rtdb.is_vulnerable:
            print(f"  RTDB Vulnerable: {app_scan.audit_result.rtdb.is_vulnerable}")
        if app_scan.error_message:
            print(f"  Error: {app_scan.error_message}")
        if app_scan.google_service_plist_path:
            print(f"  GoogleService-Info.plist: {app_scan.google_service_plist_path}")
    print("-------------------------")


if __name__ == "__main__":
    main()
