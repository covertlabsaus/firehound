#!/usr/bin/env python3
"""
Firehound Firebase Security Scanner - Main CLI
Handles IPA download, extraction, and orchestrates scanning workflow.
"""

import os, sys, json, time, plistlib, urllib.request, urllib.error, urllib.parse, argparse, re, shlex, shutil, subprocess, zipfile, getpass, logging
from collections import defaultdict
from pathlib import Path
from typing import Optional, Tuple, Iterable, List

# Import our modules
from .scanner import audit_folder, load_wordlists, set_logger, set_vprint
from .reports import FindingSummary, generate_enhanced_report, display_app_results_enhanced, display_final_scan_summary

# --- Globals ---
USER_AGENT = "f3tcher/1.1"
RESCAN = (os.environ.get("RESCAN", "0") == "1") or (os.environ.get("FORCE_RESCAN", "0") == "1")
VERBOSE = os.environ.get("VERBOSE", "1") != "0"
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))

# --- Logging Setup ---
_log_file_path = None
_logger = None

def setup_logging(base_dir: Path):
    """Setup logging to write all verbose output to a log file"""
    global _log_file_path, _logger
    
    # Create logs directory
    logs_dir = base_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped log file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    _log_file_path = logs_dir / f"firehound_scan_{timestamp}.log"
    
    # Setup logger
    _logger = logging.getLogger("firehound")
    _logger.setLevel(logging.DEBUG)
    
    # Remove any existing handlers
    _logger.handlers.clear()
    
    # File handler - captures everything
    file_handler = logging.FileHandler(_log_file_path, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # Detailed format for log file
    file_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    _logger.addHandler(file_handler)
    
    # Set logger and vprint for scanner module
    set_logger(_logger)
    set_vprint(vprint)
    
    # Log startup info
    _logger.info("=" * 80)
    _logger.info("Firehound Firebase Security Scanner - Detailed Log")
    _logger.info("=" * 80)
    _logger.info(f"Log file: {_log_file_path}")
    _logger.info(f"Working directory: {os.getcwd()}")
    _logger.info(f"Base output directory: {base_dir}")
    _logger.info(f"Environment: VERBOSE={VERBOSE}, RESCAN={RESCAN}")
    _logger.info("=" * 80)
    
    return _log_file_path

def log_detailed(message: str, level: str = "INFO"):
    """Write detailed message to log file only"""
    if _logger:
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO, 
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        _logger.log(level_map.get(level.upper(), logging.INFO), message)

# --- Utility Functions ---
def vprint(msg: str, color: str = ""):
    # Always log to file if logger is available
    if _logger:
        # Remove ANSI color codes for log file
        clean_msg = re.sub(r'\033\[[0-9;]*m', '', msg)
        log_level = "ERROR" if color == RED else "WARNING" if color == YELLOW else "INFO"
        log_detailed(clean_msg, log_level)
    
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

def _run(cmd: List[str], timeout: int = 12, env: Optional[dict] = None, input_data: Optional[bytes] = None) -> tuple[int, str]:
    cmd_str = ' '.join(shlex.quote(c) for c in cmd)
    
    # Log command execution details
    log_detailed(f"EXEC: {cmd_str}", "DEBUG")
    if env:
        # Log environment variables (but mask sensitive ones)
        safe_env = {}
        for k, v in env.items():
            if any(sensitive in k.lower() for sensitive in ['password', 'passphrase', 'token', 'key', 'secret']):
                safe_env[k] = '[MASKED]'
            else:
                safe_env[k] = v
        log_detailed(f"ENV: {safe_env}", "DEBUG")
    
    if have_command("script"):
        final_cmd = ["script", "-q", "/dev/null", "-c", cmd_str]
    else:
        final_cmd = cmd

    start_time = time.time()
    try:
        proc = subprocess.run(
            final_cmd,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env=env
        )
        out = proc.stdout.decode(errors="replace")
        duration = time.time() - start_time
        
        # Log execution result
        log_detailed(f"RESULT: exit_code={proc.returncode}, duration={duration:.2f}s", "DEBUG")
        if out.strip():
            log_detailed(f"OUTPUT: {out.strip()}", "DEBUG")
            
        return proc.returncode, out
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        log_detailed(f"TIMEOUT: command timed out after {duration:.2f}s", "ERROR")
        return 124, "Timed out"
    except Exception as exc:
        duration = time.time() - start_time
        error_msg = f"Failed to run {' '.join(shlex.quote(c) for c in final_cmd)}: {exc}"
        log_detailed(f"ERROR: {error_msg} (after {duration:.2f}s)", "ERROR")
        return 1, error_msg

def run_with_script(cmd_str: str, keychain_passphrase: str, timeout: int, env: Optional[dict] = None) -> tuple[int, str]:
    # Log the command (but mask the passphrase)
    safe_cmd = cmd_str.replace(keychain_passphrase, '[MASKED]') if keychain_passphrase in cmd_str else cmd_str
    log_detailed(f"SCRIPT_EXEC: {safe_cmd}", "DEBUG")
    
    environment = os.environ.copy()
    if env:
        environment.update(env)
        # Log safe environment variables
        safe_env = {}
        for k, v in env.items():
            if any(sensitive in k.lower() for sensitive in ['password', 'passphrase', 'token', 'key', 'secret']):
                safe_env[k] = '[MASKED]'
            else:
                safe_env[k] = v
        log_detailed(f"SCRIPT_ENV: {safe_env}", "DEBUG")
    
    if have_command("script"):
        cmd_list = ["script", "-q", "/dev/null", "-c", cmd_str]
    else:
        cmd_list = shlex.split(cmd_str)
    
    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd_list,
            input=(keychain_passphrase + "\n").encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env=environment,
        )
        duration = time.time() - start_time
        output = proc.stdout.decode(errors="replace")
        
        log_detailed(f"SCRIPT_RESULT: exit_code={proc.returncode}, duration={duration:.2f}s", "DEBUG")
        if output.strip():
            # Mask any sensitive data in output
            safe_output = output.replace(keychain_passphrase, '[MASKED]') if keychain_passphrase in output else output
            log_detailed(f"SCRIPT_OUTPUT: {safe_output.strip()}", "DEBUG")
        
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        log_detailed(f"SCRIPT_TIMEOUT: command timed out after {duration:.2f}s", "ERROR")
        return 124, "Timed out"
    except Exception as exc:
        duration = time.time() - start_time
        error_msg = f"Failed to run {' '.join(shlex.quote(c) for c in cmd_list)}: {exc}"
        log_detailed(f"SCRIPT_ERROR: {error_msg} (after {duration:.2f}s)", "ERROR")
        return 1, error_msg

# --- IPA and Plist Handling ---
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
    if not plist_path.is_file(): return
    try:
        with open(plist_path, "rb") as fp:
            header = fp.read(8)
        if header.startswith(b"bplist00"):
            with open(plist_path, "rb") as fp: data = plistlib.load(fp)
            with open(plist_path, "wb") as fp: plistlib.dump(data, fp, fmt=plistlib.FMT_XML)
    except Exception: pass

def run_ipatool_download(bundle_id: str, ipa_path: Path, keychain_passphrase: str, apple_id_password: str, timeout_seconds: int, country: Optional[str]) -> Tuple[bool, Optional[str]]:
    env = {"IPATOOL_PASSWORD": apple_id_password, "IPATOOL_PASSPHRASE": keychain_passphrase}
    # 1) Ensure we're logged in; if not, login automatically
    _, _ = _run(["ipatool", "auth", "info", "--non-interactive", "--keychain-passphrase", keychain_passphrase, "--format", "json"], env=env)
    login_cmd = f"ipatool auth login --non-interactive --keychain-passphrase {shlex.quote(keychain_passphrase)} -e {shlex.quote(os.environ.get('IPATOOL_EMAIL', ''))} -p {shlex.quote(apple_id_password)}"
    run_with_script(login_cmd, keychain_passphrase, timeout=timeout_seconds, env=env)

    # 2) Try to obtain a license explicitly
    purchase_cmd = f"ipatool purchase --bundle-identifier {shlex.quote(bundle_id)}"
    run_with_script(purchase_cmd, keychain_passphrase, timeout=timeout_seconds, env=env)

    # 3) Try download by bundle id
    dl_bundle_cmd = f"ipatool download --bundle-identifier {shlex.quote(bundle_id)} --purchase --output {shlex.quote(str(ipa_path))}"
    rc, out = run_with_script(dl_bundle_cmd, keychain_passphrase, timeout=timeout_seconds, env=env)
    if rc == 0 and ipa_path.is_file():
        return True, out

    # 4) Resolve app-id and retry by app id
    rc_s, out_s = _run(["ipatool", "search", "--non-interactive", "--keychain-passphrase", keychain_passphrase, "--format", "json", bundle_id, "--limit", "1"], timeout=timeout_seconds, env=env)
    app_id: Optional[int] = None
    if rc_s == 0:
        try:
            data = json.loads(out_s)
            apps = data.get("apps") or []
            if apps and isinstance(apps[0], dict):
                app_id = apps[0].get("id")
        except Exception:
            app_id = None
    if app_id:
        dl_id_cmd = f"ipatool download --app-id {shlex.quote(str(app_id))} --purchase --output {shlex.quote(str(ipa_path))}"
        rc2, out2 = run_with_script(dl_id_cmd, keychain_passphrase, timeout=timeout_seconds, env=env)
        if rc2 == 0 and ipa_path.is_file():
            return True, out2
        return False, out2

    return False, out

def sanitize_filename_component(name: str) -> str:
    if not name:
        return ""
    name = name.replace("/", "-").replace("\\", "-")
    name = re.sub(r"[\r\n\t]", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    name = re.sub(r"[^\w\-. ]", "-", name)
    return name or "app"

def process_bundle_id(bundle_id: str, scan_dir: Path, keychain_passphrase: str, apple_id_password: str, timeout_seconds: int, wl, country: Optional[str]) -> Optional[dict]:
    log_detailed(f"PROCESSING: Starting bundle ID {bundle_id}", "INFO")
    
    # Create temporary directory for this app
    temp_dir = scan_dir / "temp" / bundle_id
    temp_dir.mkdir(parents=True, exist_ok=True)
    ipa_path = temp_dir / f"{bundle_id}.ipa"

    vprint(f"Downloading IPA for {bundle_id}", BLUE)
    vprint("")
    
    log_detailed(f"IPA_DOWNLOAD: Starting download for {bundle_id}", "INFO")
    ok, output = run_ipatool_download(bundle_id, ipa_path, keychain_passphrase, apple_id_password, timeout_seconds, country)
    
    # Parse download results
    purchased_val = None
    err_msg = None
    if output:
        try:
            m = re.search(r"purchased=(true|false)", output)
            if m:
                purchased_val = m.group(1)
            m2 = re.search(r"error=\"([^\"]+)\"", output)
            if m2:
                err_msg = m2.group(1)
        except Exception:
            pass
    
    if ok:
        parts = ["OK", ipa_path.name]
        if purchased_val is not None:
            parts.insert(1, f"purchased={purchased_val}")
        log_detailed(f"IPA_DOWNLOAD: Success - {' | '.join(parts)}", "INFO")
        vprint("Download complete | " + " | ".join(parts), GREEN)
        vprint("")
    else:
        msg = "Download failed"
        if err_msg:
            msg += f": {err_msg}"
        log_detailed(f"IPA_DOWNLOAD: Failed - {msg}", "ERROR")
        vprint(msg, RED)
        vprint("")
        
        # Cleanup temp directory
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
        return None

    # Extract configuration files
    try:
        with zipfile.ZipFile(ipa_path) as zf:
            info_member, google_member = find_members(zf)
            if info_member: 
                extract_member_to_basename(zf, info_member, temp_dir)
            if google_member: 
                extract_member_to_basename(zf, google_member, temp_dir)
    except Exception as e:
        vprint(f"Error extracting from IPA: {e}", YELLOW)
        log_detailed(f"EXTRACTION_ERROR: {e}", "ERROR")
        return None

    # Convert binary plists to XML
    convert_plist_to_xml_if_binary(temp_dir / "Info.plist")
    convert_plist_to_xml_if_binary(temp_dir / "GoogleService-Info.plist")
    
    # Remove IPA file to save space
    try:
        if ipa_path.exists(): 
            ipa_path.unlink()
    except Exception: 
        pass
    
    vprint(f"EXTRACTED: {bundle_id} -> {temp_dir}", GREEN)
    
    # Perform security audit
    audit_result = audit_folder(temp_dir, wl, keep_plists=os.environ.get("KEEP_PLISTS", "0") == "1")
    
    if not audit_result or not audit_result.get("vulnerabilities"):
        # No findings - clean up temp directory
        try:
            shutil.rmtree(temp_dir)
            vprint(f"No findings. Removed {temp_dir}", GREY)
        except Exception as exc:
            vprint(f"Cleanup failed for {temp_dir}: {exc}", YELLOW)
        return {"bundleId": bundle_id, "appName": bundle_id, "report_path": None, "has_findings": False}

    # Get app name from Info.plist
    display_name = None
    try:
        info_plist_path = temp_dir / "Info.plist"
        if info_plist_path.is_file():
            with open(info_plist_path, "rb") as pf:
                info_obj = plistlib.load(pf)
                display_name = info_obj.get("CFBundleDisplayName") or info_obj.get("CFBundleName")
    except Exception:
        display_name = None
    
    app_name = display_name or bundle_id
    
    # Generate enhanced report
    scan_metadata = {
        "app_name": app_name,
        "duration": 0,
        "scan_time": int(time.time())
    }
    
    enhanced_report = generate_enhanced_report(
        audit_result["config"], 
        audit_result["vulnerabilities"], 
        audit_result["auth_info"], 
        scan_metadata
    )
    
    # Write report to scan directory with bundle ID as filename
    report_path = scan_dir / f"{bundle_id}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(enhanced_report, f, indent=2, ensure_ascii=False)
    
    # Enhanced terminal display
    display_app_results_enhanced(app_name, bundle_id, audit_result["summary"], audit_result["vulnerabilities"])
    vprint(f"→ Wrote enhanced report to {report_path}", GREEN)
    
    # Remove the temp directory since we've extracted what we need
    try:
        shutil.rmtree(temp_dir)
        log_detailed(f"CLEANUP: Removed temp folder {temp_dir} after extracting report", "INFO")
    except Exception as exc:
        log_detailed(f"CLEANUP_ERROR: Failed to remove {temp_dir}: {exc}", "WARNING")

    return {
        "bundleId": bundle_id, 
        "appName": app_name, 
        "report_path": str(report_path), 
        "has_findings": True, 
        "riskScore": audit_result["summary"].risk_score, 
        "riskLevel": audit_result["summary"].get_risk_level()
    }

# --- Search Functions ---
def parse_bundles_from_text(text: str) -> List[str]:
    bundles: list[str] = []
    for m in re.finditer(r"(?:Bundle\s*(?:Identifier|ID)|Identifier)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)", text, re.I):
        bundles.append(m.group(1))
    if not bundles:
        for m in re.finditer(r"\b([A-Za-z0-9][A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)\b", text):
            token = m.group(1)
            if any(token.endswith(ext) for ext in (".zip", ".ipa", ".json", ".plist")): continue
            if not re.search(r"[a-zA-Z]", token): continue
            bundles.append(token)
    seen = set()
    deduped = []
    for b in bundles:
        if b not in seen:
            seen.add(b)
            deduped.append(b)
    return deduped

def parse_bundles_from_json(text: str) -> Optional[List[str]]:
    try: obj = json.loads(text)
    except Exception: return None
    candidates: list[str] = []
    items: Iterable = obj
    if isinstance(obj, dict):
        for key in ("results", "apps", "data", "items"):
            if isinstance(obj.get(key), list):
                items = obj[key]
                break
    if not isinstance(items, list): return None
    for it in items:
        if not isinstance(it, dict):
            continue
        # Handle both iTunes and ipatool JSON shapes
        for key in ("bundleIdentifier", "bundleId", "bundleID", "bundle_id", "bundle_identifier"):
            val = it.get(key)
            if isinstance(val, str):
                candidates.append(val)
                break
    seen, out = set(), []
    for b in candidates:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out

def ipatool_search(term: str, limit: int, timeout: int, keychain_passphrase: str, apple_id_password: str, email: str) -> List[str]:
    if not have_command("ipatool"): raise SystemExit("ipatool not found in PATH. Install it first and re-try.")
    
    lf = ["--limit", str(limit)] if limit else []
    base_cmd = ["ipatool", "search", "--non-interactive", "--keychain-passphrase", keychain_passphrase, "--format", "json"]
    
    cmds_to_try = [
        [*base_cmd, term, *lf],
        [*base_cmd, *lf, term]
    ]
    
    last_out = ""
    env = os.environ.copy()
    env["IPATOOL_PASSWORD"] = apple_id_password

    for cmd in cmds_to_try:
        vprint(f"Running: {' '.join(shlex.quote(c) for c in cmd)}", GREY)
        rc, out = _run(cmd, timeout=timeout, env=env)
        last_out = out
        if rc != 0:
            continue
        
        bundles = parse_bundles_from_json(out) or parse_bundles_from_text(out)
        if bundles:
            vprint(f"Found {len(bundles)} bundle id(s)", GREEN)
            return bundles
            
    # Check if this is an authentication error
    if "failed to get item" in last_out and "keyring" in last_out:
        print(f"{RED}❌ ipatool authentication required!{RESET}")
        print(f"\n{CYAN}📋 First-time setup required:{RESET}")
        print(f"  1. {BOLD}Interactive login with 2FA:{RESET}")
        print(f"     ipatool auth login --email {email}")
        print(f"     (You'll be prompted for 2FA code)")
        print(f"  2. {BOLD}Set environment variables:{RESET}")
        print(f"     export FIREHOUND_EMAIL='{email}'")
        print(f"     export FIREHOUND_KEYCHAIN_PASSPHRASE='{keychain_passphrase}'")
        print(f"     export FIREHOUND_APPLE_ID_PASSWORD='your_password'")
        print(f"  3. {BOLD}Try again:{RESET}")
        print(f"     firehound --search {term} -l {limit}")
        print(f"\n{YELLOW}💡 Note: Step 1 only needed once per machine{RESET}")
        sys.exit(1)
    elif "not found in PATH" in last_out or "command not found" in last_out:
        print(f"{RED}❌ ipatool not found{RESET}")
        print(f"\n{CYAN}📦 Install ipatool:{RESET}")
        print(f"  macOS:   brew install majd/repo/ipatool")
        print(f"  Linux:   Download from https://github.com/majd/ipatool/releases")
        print(f"  Windows: Download .exe from GitHub releases")
        sys.exit(1)
    else:
        vprint(last_out, YELLOW)
        raise SystemExit("ipatool search failed or produced no recognizable bundle IDs.")

def check_ipatool_auth(keychain_passphrase: str, apple_id_password: str, email: str):
    if not have_command("ipatool"):
        vprint("ipatool not found in PATH. Please install it and try again.", RED)
        sys.exit(1)
    # Try to display auth info first; if it fails, we will auto-login
    env = {"IPATOOL_PASSWORD": apple_id_password}
    rc, _ = _run(["ipatool", "auth", "info", "--non-interactive", "--keychain-passphrase", keychain_passphrase, "--format", "json"], env=env)
    if rc == 0:
        return
    # Auto-login non-interactively. User may need to have a valid session/2FA on this machine.
    login_cmd = f"ipatool auth login --non-interactive --keychain-passphrase {shlex.quote(keychain_passphrase)} -e {shlex.quote(email)} -p {shlex.quote(apple_id_password)}"
    run_with_script(login_cmd, keychain_passphrase, timeout=60, env=env)
    # Best-effort verification
    _run(["ipatool", "auth", "info", "--non-interactive", "--keychain-passphrase", keychain_passphrase, "--format", "json"], env=env)

# --- Main Function ---
def main():
    parser = argparse.ArgumentParser(
        description="Firehound Firebase Security Scanner",
        epilog="""
Examples:
  %(prog)s --search "banking" --limit 3
  %(prog)s --bundle-id com.example.app
  %(prog)s --ids-file app-list.txt

Environment Variables (used as defaults):
  FIREHOUND_KEYCHAIN_PASSPHRASE  - Keychain passphrase
  FIREHOUND_APPLE_ID_PASSWORD    - Apple ID password  
  FIREHOUND_EMAIL                - Apple ID email
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--search", "-s", help="Search term for apps (e.g., 'banking apps').")
    group.add_argument("--ids-file", help="Path to a file with one bundle identifier per line.")
    group.add_argument("--bundle-id", help="A single bundle identifier to audit.")
    group.add_argument("--directory", "-d", help="Path to a directory containing a GoogleService-Info.plist to audit.")
    
    parser.add_argument("--limit", "-l", type=int, default=5, help="Max results for search (default: 5).")
    parser.add_argument("--country", "-c", default=None, help="(unused) Country/storefront hint.")
    
    # Credentials - check environment variables as fallbacks
    parser.add_argument("--keychain-passphrase", 
                       default=os.environ.get('FIREHOUND_KEYCHAIN_PASSPHRASE'),
                       help="Passphrase for the ipatool keychain. Can set FIREHOUND_KEYCHAIN_PASSPHRASE env var.")
    parser.add_argument("--apple-id-password", 
                       default=os.environ.get('FIREHOUND_APPLE_ID_PASSWORD'),
                       help="Apple ID password for ipatool. Can set FIREHOUND_APPLE_ID_PASSWORD env var.")
    parser.add_argument("--email", 
                       default=os.environ.get('FIREHOUND_EMAIL'),
                       help="Apple ID email for ipatool. Can set FIREHOUND_EMAIL env var.")
    
    parser.add_argument("--timeout", type=int, default=60, help="Network timeout in seconds (default: 60).")
    parser.add_argument("--output-dir", "-o", default=os.getcwd(), help="Base output directory.")
    
    args = parser.parse_args()

    # Validate required credentials
    missing_creds = []
    if not args.keychain_passphrase:
        missing_creds.append("--keychain-passphrase (or FIREHOUND_KEYCHAIN_PASSPHRASE)")
    if not args.apple_id_password:
        missing_creds.append("--apple-id-password (or FIREHOUND_APPLE_ID_PASSWORD)")
    if not args.email:
        missing_creds.append("--email (or FIREHOUND_EMAIL)")
    
    if missing_creds:
        print(f"{RED}❌ Missing required credentials:{RESET}")
        for cred in missing_creds:
            print(f"  • {cred}")
        print(f"\n{CYAN}💡 Quick setup:{RESET}")
        print(f"  export FIREHOUND_EMAIL='your@email.com'")
        print(f"  export FIREHOUND_KEYCHAIN_PASSPHRASE='your_passphrase'")
        print(f"  export FIREHOUND_APPLE_ID_PASSWORD='your_password'")
        print(f"\n{CYAN}Then run:{RESET} {sys.argv[0]} {' '.join([arg for arg in sys.argv[1:] if not any(arg.startswith(f'--{cred.split()[0][2:]}') for cred in ['keychain-passphrase', 'apple-id-password', 'email'])])}")
        sys.exit(1)

    # Setup base directory and create timestamped scan directory
    base_dir = Path(args.output_dir).expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Create timestamped scan directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    scan_dir = base_dir / "output" / f"scan_{timestamp}"
    scan_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize logging in the scan directory
    log_file = setup_logging(scan_dir)
    vprint(f"Scan directory: {scan_dir}", CYAN)
    vprint(f"Logging to: {log_file}", CYAN)
    vprint("")
    
    # Log command line arguments (masking sensitive ones)
    safe_args = vars(args).copy()
    for sensitive_key in ['keychain_passphrase', 'apple_id_password']:
        if sensitive_key in safe_args:
            safe_args[sensitive_key] = '[MASKED]'
    log_detailed(f"ARGS: {safe_args}", "INFO")

    check_ipatool_auth(args.keychain_passphrase, args.apple_id_password, args.email)

    wl = load_wordlists()
    bundle_ids = []
    scan_index: List[dict] = []

    if args.search:
        vprint(f"Searching for: {args.search}", BLUE)
        try:
            bundle_ids = ipatool_search(term=args.search, limit=args.limit, timeout=args.timeout, keychain_passphrase=args.keychain_passphrase, apple_id_password=args.apple_id_password, email=args.email)
        except Exception as exc:
            vprint(f"ipatool search failed: {exc}", YELLOW)
        if not bundle_ids:
            print("No bundle identifiers found.")
            return
    elif args.ids_file:
        with open(args.ids_file, "r") as f:
            bundle_ids = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.bundle_id:
        bundle_ids = [args.bundle_id]
    elif args.directory:
        log_detailed(f"AUDIT_DIRECTORY: {args.directory}", "INFO")
        audit_folder(Path(args.directory), wl)
        return
    
    log_detailed(f"SCAN_START: Processing {len(bundle_ids)} bundle IDs", "INFO")
    
    for i, bid in enumerate(bundle_ids, 1):
        log_detailed(f"SCAN_PROGRESS: Processing {i}/{len(bundle_ids)} - {bid}", "INFO")
        res = process_bundle_id(bid, scan_dir, args.keychain_passphrase, args.apple_id_password, args.timeout, wl, args.country)
        if res is None:
            log_detailed(f"SCAN_RESULT: {bid} - Failed (download error)", "ERROR")
            scan_index.append({"bundleId": bid, "appName": bid, "report_path": None, "has_findings": False, "error": "download_failed"})
        else:
            log_detailed(f"SCAN_RESULT: {bid} - {'Success' if res['has_findings'] else 'No findings'}", "INFO")
            scan_index.append(res)

    # Write scan index
    try:
        index_path = scan_dir / "scan_index.json"
        scan_summary = {
            "scannedAt": int(time.time()),
            "totalProcessed": len(bundle_ids),
            "withFindings": sum(1 for item in scan_index if item.get("has_findings", False)),
            "failed": sum(1 for item in scan_index if "error" in item),
            "items": scan_index
        }
        with open(index_path, "w", encoding="utf-8") as fp:
            json.dump(scan_summary, fp, indent=2, ensure_ascii=False)
        
        log_detailed(f"SCAN_COMPLETE: {scan_summary['withFindings']}/{scan_summary['totalProcessed']} apps with findings, {scan_summary['failed']} failed", "INFO")
        vprint(f"→ Wrote scan index to {index_path}", GREEN)
        
        # Display enhanced final summary
        display_final_scan_summary(scan_summary, scan_dir)
        
    except Exception as exc:
        log_detailed(f"INDEX_ERROR: Failed to write scan index: {exc}", "ERROR")
        vprint(f"Failed to write scan index: {exc}", YELLOW)
    
    # Final log summary
    if _log_file_path:
        log_detailed("=" * 80, "INFO")
        log_detailed("Scan completed successfully", "INFO")
        log_detailed(f"Log file saved to: {_log_file_path}", "INFO")
        log_detailed("=" * 80, "INFO")

if __name__ == "__main__":
    main()
