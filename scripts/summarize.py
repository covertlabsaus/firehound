#!/usr/bin/env python3
import os, sys, json, re, time, shutil, shlex, subprocess, zipfile, threading
from concurrent import futures
import urllib.request, urllib.parse, urllib.error

BASE_DIR = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
USER_AGENT = "f3tcher/summary/1.3"
TIMEOUT = 15

# Verbose logging with optional ANSI colors
VERBOSE = os.environ.get("VERBOSE", "1") != "0"
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))

def vprint(msg: str, color: str = ""):
    if not VERBOSE:
        return
    prefix = color if (COLOR_ENABLED and color) else ""
    suffix = RESET if (COLOR_ENABLED and color) else ""
    print(f"{prefix}{msg}{suffix}" if prefix else msg)
    try:
        sys.stdout.flush()
    except Exception:
        pass

# Concurrency controls
MAX_WORKERS = int(os.environ.get("WORKERS", "6"))
IPATOOL_PAR = int(os.environ.get("IPATOOL_PAR", "2"))
_ipatool_sem = threading.Semaphore(IPATOOL_PAR)


def convert_plist_bytes_to_xml(data: bytes) -> bytes | None:
    """Convert binary plist bytes to XML bytes; return None on failure or if already XML."""
    try:
        # Heuristic: only try to convert binary plists
        if not data.startswith(b"bplist00"):
            return None
        import plistlib
        obj = plistlib.loads(data)
        xml = plistlib.dumps(obj, fmt=plistlib.FMT_XML)
        return xml
    except Exception:
        return None

def http_json(url, method="GET", body=None, headers=None):
    vprint(f"HTTP {method} {url}", GREY)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    data = body if body is None else (body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8"))
    req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status = resp.getcode()
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace")
            vprint(f"↳ {status}", GREY)
            try:
                return status, json.loads(text), text
            except Exception:
                return status, None, text
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        text = raw.decode("utf-8", errors="replace")
        vprint(f"↳ {e.code}", GREY)
        try:
            return e.code, json.loads(text), text
        except Exception:
            return e.code, None, text
    except Exception as e:
        vprint(f"↳ ERROR {e}", RED)
        return 0, None, str(e)

def parse_vulns_from_audit(audit):
    out = {"realtime_db": [], "firestore": [], "storage": [], "cloud_functions": [], "hosting": [], "unknown": []}
    for e in audit.get("all_evidence") or []:
        if e.get("status") in (200, 201):
            svc = (e.get("service") or "Unknown").lower().replace(" ", "_")
            sev = "CRITICAL" if "CRITICAL" in (e.get("vuln") or "") else "OPEN"
            rec = {"url": e.get("url",""), "method": e.get("method","GET"), "status": e.get("status"), "severity": sev}
            (out[svc] if svc in out else out["unknown"]).append(rec)
    return out

def any_vulns(audit):
    v = parse_vulns_from_audit(audit)
    return any(len(v[k]) for k in v)

def count_rtdb(database_url):
    if not database_url: return None
    base = database_url.rstrip("/")
    status, data, _ = http_json(f"{base}/.json?shallow=true")
    if status != 200 or not isinstance(data, dict): return None
    return {"top_level_keys": len(data)}

def extract_discovered_collections(audit):
    details = ""
    fs = audit.get("firestore") or {}
    if fs.get("status") == "OPEN": details = fs.get("details","")
    if not details:
        auth = (audit.get("auth_status") or {}).get("auth_retry_results") or {}
        aa = auth.get("firestore") or {}
        if aa.get("status") == "OPEN": details = aa.get("details","")
    if not details: return []
    cols = set()
    for m in re.findall(r"/([A-Za-z0-9_\-\.]+)", details): cols.add(m)
    m = re.search(r"collections:\s*([A-Za-z0-9_\-\. ,/]+)", details, re.I)
    if m:
        for c in re.split(r"[ ,/]+", m.group(1).strip()):
            if c: cols.add(c)
    return sorted(cols)

def http_json_paginated(url_base, query_params, token_param, page_key="nextPageToken", items_key="documents"):
    total = 0
    token = ""
    while True:
        q = dict(query_params)
        if token: q[token_param] = token
        url = f"{url_base}?{urllib.parse.urlencode(q)}"
        status, data, _ = http_json(url)
        if status != 200 or not isinstance(data, dict): break
        items = data.get(items_key) or []
        total += len(items)
        token = data.get(page_key) or ""
        if not token: break
        time.sleep(0.2)
    return total

def count_firestore(project_id, api_key, collections):
    if not project_id or not api_key or not collections: return None
    counts = {}
    for coll in collections:
        base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/{urllib.parse.quote(coll, safe='')}"
        total = http_json_paginated(base, {"pageSize":"1000","key":api_key}, "pageToken", "nextPageToken", "documents")
        counts[coll] = total
    return {"collections": counts}

def count_storage(bucket):
    if not bucket: return None
    base = f"https://firebasestorage.googleapis.com/v0/b/{urllib.parse.quote(bucket, safe='')}/o"
    total = http_json_paginated(base, {"maxResults":"1000"}, "pageToken", "nextPageToken", "items")
    return {"objects": total}

def make_summary_for_file(audit_path):
    vprint(f"Summarizing: {audit_path}", BLUE)
    with open(audit_path, "r", encoding="utf-8") as f:
        audit = json.load(f)
    cfg = audit.get("config") or {}
    folder = os.path.dirname(audit_path)
    bundle_id = audit.get("bundle_id") or cfg.get("BUNDLE_ID") or os.path.basename(folder)
    project_id = audit.get("project_id") or cfg.get("PROJECT_ID") or ""
    api_key = audit.get("api_key") or cfg.get("API_KEY") or ""
    database_url = cfg.get("DATABASE_URL") or ""
    storage_bucket = cfg.get("STORAGE_BUCKET") or ""

    vuln = parse_vulns_from_audit(audit)
    counts = {}
    if (audit.get("realtime_db") or {}).get("accessible"):
        counts["realtime_db"] = count_rtdb(database_url)
    cols = extract_discovered_collections(audit)
    if (audit.get("firestore") or {}).get("status") == "OPEN" and cols:
        counts["firestore"] = count_firestore(project_id, api_key, cols)
    if (audit.get("storage") or {}).get("accessible"):
        counts["storage"] = count_storage(storage_bucket)

    cleaned = {"bundle_id": bundle_id, "project_id": project_id, "vulnerable_endpoints": vuln, "counts": counts}
    out_path = os.path.join(folder, f"{bundle_id}_vuln_summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2, ensure_ascii=False)
    vprint(f"→ wrote {out_path}", GREEN)

def counts_any_gt_one(counts: dict) -> bool:
    if not counts:
        return False
    rtdb = counts.get("realtime_db") or {}
    if isinstance(rtdb, dict) and isinstance(rtdb.get("top_level_keys"), int) and rtdb.get("top_level_keys", 0) > 1:
        return True
    fs = counts.get("firestore") or {}
    if isinstance(fs, dict):
        cols = fs.get("collections") or {}
        if any(isinstance(v, int) and v > 1 for v in cols.values()):
            return True
    st = counts.get("storage") or {}
    if isinstance(st, dict) and isinstance(st.get("objects"), int) and st.get("objects", 0) > 1:
        return True
    return False

def compute_counts_for_audit(audit: dict) -> dict:
    cfg = audit.get("config") or {}
    project_id = audit.get("project_id") or cfg.get("PROJECT_ID") or ""
    api_key = audit.get("api_key") or cfg.get("API_KEY") or ""
    database_url = cfg.get("DATABASE_URL") or ""
    storage_bucket = cfg.get("STORAGE_BUCKET") or ""
    counts = {}
    if (audit.get("realtime_db") or {}).get("accessible"):
        counts["realtime_db"] = count_rtdb(database_url)
    cols = extract_discovered_collections(audit)
    if (audit.get("firestore") or {}).get("status") == "OPEN" and cols:
        counts["firestore"] = count_firestore(project_id, api_key, cols)
    if (audit.get("storage") or {}).get("accessible"):
        counts["storage"] = count_storage(storage_bucket)
    return counts

def main():
    # Build folder -> audit files map
    folder_files = {}
    for root, _, files in os.walk(BASE_DIR):
        afs = [os.path.join(root, fn) for fn in files if fn.endswith("_audit.json")]
        if afs:
            folder_files[root] = afs

    def process_folder(folder: str, audit_files: list):
        vprint(f"\n{BOLD}Folder:{RESET} {folder}", MAGENTA)
        # Determine if folder should be kept:
        # keep only if there are vulnerabilities AND at least one count > 1
        keep = False
        for ap in audit_files:
            try:
                vprint(f"Check audit: {ap}", CYAN)
                with open(ap, "r", encoding="utf-8") as f:
                    audit = json.load(f)
                if not any_vulns(audit):
                    vprint("  no vulnerabilities", YELLOW)
                    continue
                counts = compute_counts_for_audit(audit)
                if counts_any_gt_one(counts):
                    vprint("  qualifies: vulnerabilities and count>1", GREEN)
                    keep = True
                    break
                else:
                    vprint("  has vulns but counts not >1", YELLOW)
            except Exception:
                vprint("  failed to parse audit", RED)
                continue

        if not keep:
            # Delete the entire folder if no qualifying results
            ab_base = os.path.abspath(BASE_DIR)
            ab_folder = os.path.abspath(folder)
            if ab_folder != ab_base and ab_folder.startswith(ab_base):
                shutil.rmtree(folder, ignore_errors=True)
                vprint(f"DELETED: {folder}", RED)
            return

        # Keep and produce summaries for each audit file in the folder
        trigger_extract = False
        chosen_bundle_id = None
        for ap in audit_files:
            try:
                # Summaries
                make_summary_for_file(ap)
                # Decide whether to extract all plist files later
                with open(ap, "r", encoding="utf-8") as f:
                    audit = json.load(f)
                counts = compute_counts_for_audit(audit)
                # Extract if ANY count > 0
                gt_zero = False
                rtdb = (counts.get("realtime_db") or {}).get("top_level_keys")
                if isinstance(rtdb, int) and rtdb > 0: gt_zero = True
                fs_cols = ((counts.get("firestore") or {}).get("collections") or {})
                if any(isinstance(v, int) and v > 0 for v in fs_cols.values()): gt_zero = True
                storage_objs = (counts.get("storage") or {}).get("objects")
                if isinstance(storage_objs, int) and storage_objs > 0: gt_zero = True
                if gt_zero and not trigger_extract:
                    trigger_extract = True
                    cfg = audit.get("config") or {}
                    chosen_bundle_id = audit.get("bundle_id") or cfg.get("BUNDLE_ID") or os.path.basename(folder)
                    vprint(f"  will extract all .plist from IPA for {chosen_bundle_id}", BLUE)
            except Exception as e:
                vprint(f"ERROR summarizing {ap}: {e}", RED)

        # If counts show data present (>0), download IPA and extract all .plist files
        if trigger_extract and chosen_bundle_id:
            try:
                ipa_tmp = os.path.join(folder, f"{chosen_bundle_id}__all_plists.ipa")
                # Build ipatool command and feed passphrase via PTY using 'script'
                cmd_str = (
                    f"ipatool download --bundle-identifier {shlex.quote(chosen_bundle_id)} "
                    f"--purchase --output {shlex.quote(ipa_tmp)}"
                )
                env = os.environ.copy()
                passphrase = env.get("IPATOOL_PASSPHRASE", "1")
                if shutil.which("script"):
                    cmd = ["script", "-q", "/dev/null", "-c", cmd_str]
                else:
                    cmd = shlex.split(cmd_str)
                vprint(f"Downloading IPA for {chosen_bundle_id}", BLUE)
                with _ipatool_sem:
                    proc = subprocess.run(
                        cmd,
                        input=(passphrase + "\n").encode("utf-8"),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        env=env,
                        timeout=300,
                        check=False,
                    )
                if not os.path.isfile(ipa_tmp):
                    out = proc.stdout.decode(errors="replace")
                    if out:
                        vprint(out, GREY)
                    vprint(f"FAILED to fetch IPA for {chosen_bundle_id}", RED)
                else:
                    # Extract all .plist files into subfolder 'all_plists' preserving paths
                    dest_root = os.path.join(folder, "all_plists")
                    vprint(f"Extracting .plist files to {dest_root}", BLUE)
                    try:
                        with zipfile.ZipFile(ipa_tmp) as zf:
                            for name in zf.namelist():
                                if not name.lower().endswith(".plist"):
                                    continue
                                # Skip META-INF metadata plists entirely
                                stripped = name.lstrip('/')
                                if stripped.upper().startswith('META-INF/'):
                                    continue
                                out_path = os.path.join(dest_root, name)
                                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                with zf.open(name) as src:
                                    data = src.read()
                                # Convert binary plist to XML when applicable
                                xml = convert_plist_bytes_to_xml(data)
                                to_write = xml if xml is not None else data
                                with open(out_path, "wb") as dst:
                                    dst.write(to_write)
                    except Exception as ex:
                        vprint(f"ERROR extracting plists from {ipa_tmp}: {ex}", RED)
                    # Clean up IPA
                    try:
                        os.remove(ipa_tmp)
                    except Exception:
                        pass
                    # Post-process: touch marker and count files
                    plist_count = 0
                    for root2, _, files2 in os.walk(dest_root):
                        for fn in files2:
                            if fn.lower().endswith('.plist'):
                                plist_count += 1
                    with open(os.path.join(dest_root, "EXTRACTION_OK.txt"), "w", encoding="utf-8") as fp:
                        fp.write(f"Extracted {plist_count} plist file(s)\n")
                    vprint(f"Extracted {plist_count} .plist files to {dest_root}", GREEN)
            except Exception as ex:
                vprint(f"ERROR downloading/extracting plists for {chosen_bundle_id}: {ex}", RED)

    # Process folders concurrently
    with futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        list(executor.map(lambda item: process_folder(*item), sorted(folder_files.items())))

if __name__ == "__main__":
    main()