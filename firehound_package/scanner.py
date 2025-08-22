#!/usr/bin/env python3
"""
Firehound Firebase Security Scanner - Core Testing Logic
Contains all Firebase service testing and vulnerability detection functionality.
"""

import os, sys, json, time, urllib.request, urllib.error, urllib.parse, re
from collections import defaultdict
from typing import Optional, List

# --- Globals ---
USER_AGENT = "f3tcher/1.1"
HTTP_TIMEOUT = 12
MAX_RETRIES = 2
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))

# Global logger and vprint references (set by main module)
_logger = None
_vprint = None

def set_logger(logger):
    """Set the logger instance for this module"""
    global _logger
    _logger = logger

def set_vprint(vprint_func):
    """Set the vprint function for this module"""
    global _vprint
    _vprint = vprint_func

def vprint(msg: str, color: str = ""):
    """Local vprint that uses the main module's vprint function"""
    if _vprint:
        _vprint(msg, color)

def log_detailed(message: str, level: str = "INFO"):
    """Write detailed message to log file only"""
    if _logger:
        level_map = {
            "DEBUG": 20,  # logging.DEBUG
            "INFO": 20,   # logging.INFO
            "WARNING": 30, # logging.WARNING
            "ERROR": 40,   # logging.ERROR
            "CRITICAL": 50 # logging.CRITICAL
        }
        _logger.log(level_map.get(level.upper(), 20), message)

# --- Wordlists ---
def load_wordlists():
    wl = {}
    wl["collections"] = ["users", "profiles", "posts", "messages", "items", "orders", "products", "carts", "config", "settings", "notifications", "chats", "groups", "events", "feedback", "logs", "private", "public", "admin"]
    wl["rtdb_roots"] = ["users", "public", "profiles", "data", "messages", "config", "settings", "dev", "prod", "staging", "test", "logs", "info", "private", "admin"]
    wl["functions_regions"] = ["us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4", "europe-west1", "europe-west2", "europe-west3", "europe-central2", "asia-northeast1", "asia-northeast2", "asia-east2", "asia-southeast1", "asia-southeast2", "australia-southeast1", "southamerica-east1"]
    wl["functions"] = ["api", "status", "v1"]
    return wl

# --- HTTP and Classification ---
def _infer_service_and_app(u: urllib.parse.ParseResult) -> tuple[str, str, str]:
    host = u.hostname or ""
    path = u.path or ""
    query = urllib.parse.parse_qs(u.query or "")
    if "firebasestorage" in host:
        parts = [p for p in path.split("/") if p]
        app = parts[2] if len(parts) >= 3 and parts[0] == "v0" and parts[1] == "b" else host
        # prefer maxResults > prefix > any
        if "maxResults" in query:
            variable_key = "maxResults"
        elif "prefix" in query:
            variable_key = "prefix"
        else:
            variable_key = next(iter(query.keys()), "")
        variable_val = (query.get(variable_key, [""])[0] if variable_key else "")
        return "firebasestorage", app, (f"{variable_key}={variable_val.strip('/')}" if variable_key else "")
    if "firestore" in host:
        parts = [p for p in path.split("/") if p]
        app = parts[2] if len(parts) >= 3 and parts[0].startswith("v") and parts[1] == "projects" else host
        return "firestore", app, ""  # no variable shown for firestore
    if "cloudfunctions" in host:
        sub = host.split(".cloudfunctions.net")[0]
        region_pid = sub.split("-")
        app = "-".join(region_pid[1:]) if len(region_pid) >= 2 else host
        return "cloudfunctions", app, ""
    if host.endswith(".web.app") or host.endswith(".firebaseapp.com"):
        return "hosting", host, ""
    if "firebaseio.com" in host or "firebasedatabase.app" in host:
        app = host.split(".", 1)[0]
        variable_key = next((k for k in ("auth", "shallow", "limitToFirst") if k in query), next(iter(query.keys()), ""))
        variable_val = (query.get(variable_key, [""])[0] if variable_key else "")
        return "realtime-db", app, (f"{variable_key}={variable_val}" if variable_key else "")
    return (u.hostname or ""), u.hostname or "", ""

def _format_log_line(status: int, method: str, url: str) -> str:
    u = urllib.parse.urlparse(url)
    service, app, variable = _infer_service_and_app(u)
    # Color only the status code: green for 200/201; grey otherwise
    status_str = str(status)
    status_colored = f"{GREEN}{status_str}{RESET}" if status in (200, 201) else f"{GREY}{status_str}{RESET}"
    core = [status_colored, method, service or "Unknown", app or "-"]
    line = " | ".join(core)
    if variable and service != "firestore":
        line = f"{line} | {variable}"
    return line

def http_request(url, method="GET", body=None, headers=None, log: bool = True):
    # Log detailed HTTP request info
    log_detailed(f"HTTP_REQUEST: {method} {url}", "DEBUG")
    
    headers = headers.copy() if headers else {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENT
    if "Accept" not in headers:
        headers["Accept"] = "application/json"
    
    # Log request headers (mask sensitive ones)
    safe_headers = {}
    for k, v in headers.items():
        if any(sensitive in k.lower() for sensitive in ['authorization', 'cookie', 'token', 'key']):
            safe_headers[k] = '[MASKED]'
        else:
            safe_headers[k] = v
    log_detailed(f"HTTP_HEADERS: {safe_headers}", "DEBUG")
    
    if body:
        # Log request body (truncated and sanitized)
        body_str = body if isinstance(body, str) else body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
        truncated_body = body_str[:500] + "..." if len(body_str) > 500 else body_str
        log_detailed(f"HTTP_BODY: {truncated_body}", "DEBUG")
    
    data = body if body is None else (body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8"))
    last_err = None
    
    for attempt in range(MAX_RETRIES + 1):
        start_time = time.time()
        try:
            req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                status = resp.getcode()
                raw = resp.read()
                duration = time.time() - start_time
                
                snippet = raw[:200].decode("utf-8", errors="replace") if len(raw) > 16 * 1024 else raw.decode("utf-8", errors="replace")
                
                # Log response details
                log_detailed(f"HTTP_RESPONSE: {status} in {duration:.2f}s, {len(raw)} bytes", "DEBUG")
                if snippet.strip():
                    log_detailed(f"HTTP_SNIPPET: {snippet.strip()}", "DEBUG")
                
                if log:
                    vprint(_format_log_line(status, method, url), GREY)
                evidence = ("Successful access" if status in (200, 201) else "Access denied" if status in (401, 403) else "Not found" if status == 404 else f"Status: {status}")
                svc, vuln = classify(url, status, method)
                return {"url": url, "method": method, "status": status, "snippet": snippet, "evidence": evidence, "service": svc, "vuln": vuln}
        except urllib.error.HTTPError as e:
            status = e.code
            duration = time.time() - start_time
            raw = e.read() if hasattr(e, "read") else b""
            snippet = raw[:200].decode("utf-8", errors="replace")
            
            log_detailed(f"HTTP_ERROR: {status} in {duration:.2f}s, {len(raw)} bytes", "DEBUG")
            if snippet.strip():
                log_detailed(f"HTTP_ERROR_SNIPPET: {snippet.strip()}", "DEBUG")
            
            if log:
                vprint(_format_log_line(status, method, url), GREY)
            evidence = ("Successful access" if status in (200, 201) else "Access denied" if status in (401, 403) else "Not found" if status == 404 else f"Status: {status}")
            svc, vuln = classify(url, status, method)
            return {"url": url, "method": method, "status": status, "snippet": snippet, "evidence": evidence, "service": svc, "vuln": vuln}
        except Exception as e:
            duration = time.time() - start_time
            last_err = e
            log_detailed(f"HTTP_EXCEPTION: {e} in {duration:.2f}s (attempt {attempt + 1}/{MAX_RETRIES + 1})", "WARNING")
            
            if attempt < MAX_RETRIES:
                sleep_time = 2 ** attempt
                log_detailed(f"HTTP_RETRY: waiting {sleep_time}s before retry", "DEBUG")
                time.sleep(sleep_time)
                continue
            
            log_detailed(f"HTTP_FAILED: all retries exhausted", "ERROR")
            if log:
                vprint(_format_log_line(0, method, url), RED)
            return {"url": url, "method": method, "status": 0, "snippet": "", "evidence": f"Request failed: {last_err}", "service": "Unknown", "vuln": ""}

def classify(u, status, method):
    s = u
    if "firebasedatabase.app" in s or "firebaseio.com" in s:
        if status in (200, 201): return "Realtime DB", ("CRITICAL: Public write access detected" if "_probes" in s else "OPEN: Public read access detected")
        return "Realtime DB", f"Status: {status}"
    if "firestore.googleapis" in s:
        if status in (200, 201): return "Firestore", "OPEN: Collection accessible without auth"
        return "Firestore", f"Status: {status}"
    if "firebasestorage" in s:
        if status in (200, 201): return "Storage", ("CRITICAL: Public write access detected" if "uploadType=media" in s else "OPEN: Public list access detected")
        return "Storage", f"Status: {status}"
    if "cloudfunctions.net" in s:
        if status in (200, 201): return "Cloud Functions", "OPEN: Function accessible without auth"
        return "Cloud Functions", f"Status: {status}"
    if ".web.app" in s or ".firebaseapp.com" in s:
        if status in (200, 201): return "Hosting", "OPEN: Hosting accessible"
        return "Hosting", f"Status: {status}"
    if "identitytoolkit.googleapis.com" in s:
        if status in (200, 201): return "Auth", "INFO: Anonymous signup enabled"
        return "Auth", f"Status: {status}"
    if status in (200, 201): return "Unknown", f"OPEN: {method} access detected"
    return "Unknown", f"Status: {status}"

# --- Authentication Functions ---
def get_anonymous_token(api_key):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={urllib.parse.quote(api_key)}"
    res = http_request(url, method="POST", body=json.dumps({"returnSecureToken": True}), headers={"Content-Type":"application/json"})
    if res["status"] == 200:
        try:
            data = json.loads(res["snippet"])
            return data.get("idToken")
        except Exception:
            return None
    return None

def get_email_token(api_key):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={urllib.parse.quote(api_key)}"
    email = f"probe+{int(time.time())}@example.com"
    payload = {"returnSecureToken": True, "email": email, "password": "testpassword123"}
    res = http_request(url, method="POST", body=json.dumps(payload), headers={"Content-Type":"application/json"})
    if res["status"] == 200:
        try:
            data = json.loads(res["snippet"])
            return data.get("idToken")
        except Exception:
            return None
    return None

# --- Firebase Service Testing Functions ---
def fuzz_rtdb(cfg, wl):
    ev = []
    if not cfg.get("DATABASE_URL"): return {"status":"NOT_CONFIGURED","details":"No DATABASE_URL found in configuration","accessible":False,"evidence":ev}
    db = cfg["DATABASE_URL"].rstrip("/")
    rules_url = f"{db}/.rules.json"
    rules_r = http_request(rules_url)
    ev.append(rules_r)
    if rules_r["status"] == 200: return {"status":"CRITICAL","details":"Security rules are publicly readable at /.rules.json","accessible":True,"evidence":ev}
    discovered = []
    for root in wl["rtdb_roots"]:
        url = f"{db}/{root}/.json?shallow=true&limitToFirst=1"
        r = http_request(url)
        ev.append(r)
        if r["status"] == 200: discovered.append(root)
    write_data = {"f3tcher_probe":{"timestamp": int(time.time()), "probe": True}}
    write_url = f"{db}/probes/.json"
    r = http_request(write_url, method="PATCH", body=json.dumps(write_data), headers={"Content-Type":"application/json"})
    ev.append(r)
    if r["status"] == 200:
        http_request(write_url, method="DELETE")
        details = f"Database is publicly readable AND writable; keys discovered: {', '.join(discovered)}" if discovered else "Database is publicly writable"
        return {"status":"CRITICAL","details":details,"accessible":True,"evidence":ev}
    if discovered:
        details = f"Public READ; keys discovered: {', '.join(discovered)}"
        return {"status":"OPEN","details":details,"accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Realtime Database requires authentication","accessible":False,"evidence":ev}

def fuzz_rtdb_auth(cfg, token, wl):
    ev, discovered = [], []
    if not cfg.get("DATABASE_URL"): return {"status":"NOT_CONFIGURED","details":"No DATABASE_URL found in configuration","accessible":False,"evidence":ev}
    db = cfg["DATABASE_URL"].rstrip("/")
    for root in wl["rtdb_roots"]:
        url = f"{db}/{root}/.json?shallow=true&limitToFirst=1&auth={urllib.parse.quote(token)}"
        r = http_request(url)
        ev.append(r)
        if r["status"] == 200: discovered.append(root)
    write_url = f"{db}/.json?auth={urllib.parse.quote(token)}"
    write_data = {"_probes_auth":{"rtdb_write_test": True}}
    r = http_request(write_url, method="PATCH", body=json.dumps(write_data), headers={"Content-Type":"application/json"})
    ev.append(r)
    if r["status"] == 200:
        del_url = f"{db}/_probes_auth/rtdb_write_test.json?auth={urllib.parse.quote(token)}"
        http_request(del_url, method="DELETE")
    open_count = sum(1 for e in ev if e["status"] == 200)
    write_count = sum(1 for e in ev if e["status"] == 200 and "_probes_auth" in e["url"])
    if write_count > 0: return {"status":"CRITICAL","details":f"Database accessible with any authenticated user (auth != null); keys discovered: {', '.join(discovered)}","accessible":True,"evidence":ev}
    if open_count > 0: return {"status":"OPEN","details":f"Database readable with any authenticated user (auth != null); keys discovered: {', '.join(discovered)}","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Database still requires proper authentication","accessible":False,"evidence":ev}

def is_datastore_mode(snippet):
    s = snippet.lower()
    return ("datastore mode" in s) or ("not available for firestore in datastore mode" in s)

def fuzz_firestore(cfg, wl):
    ev = []
    if not cfg.get("PROJECT_ID"): return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid, key = cfg.get("PROJECT_ID",""), urllib.parse.quote(cfg.get("API_KEY", ""))
    base_url = f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents"
    pre = http_request(f"{base_url}:runQuery?key={key}", method="POST", body='{"structuredQuery":{"limit":1}}', headers={"Content-Type":"application/json"})
    ev.append(pre)
    if pre["status"] == 400 and is_datastore_mode(pre["snippet"]): return {"status":"NOT_APPLICABLE","details":"Firestore is Datastore mode","accessible":False,"evidence":[pre]}
    write_coll = "f3tcher_probes"
    write_doc_id = f"probe-{int(time.time())}"
    write_url = f"{base_url}/{write_coll}/{write_doc_id}?key={key}"
    write_body = {"fields": {"probe": {"stringValue": "true"}, "timestamp": {"integerValue": str(int(time.time()))}}}
    write_r = http_request(write_url, method="PATCH", body=json.dumps(write_body), headers={"Content-Type":"application/json"})
    ev.append(write_r)
    if write_r["status"] == 200:
        http_request(write_url, method="DELETE")
        return {"status":"CRITICAL", "details":f"Public write access to collection '{write_coll}' allowed without auth.", "accessible":True, "evidence":ev}
    discovered = []
    for coll in wl["collections"]:
        q = {"structuredQuery":{"from":[{"collectionId":coll}],"limit":1}}
        r = http_request(f"{base_url}:runQuery?key={key}", method="POST", body=json.dumps(q), headers={"Content-Type":"application/json"})
        ev.append(r)
        if r["status"] == 200: discovered.append(coll)
    if discovered: return {"status":"OPEN","details":f"/{' ,/'.join(discovered)} readable without auth (?key=)","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Firestore requires proper authentication","accessible":False,"evidence":ev}

def fuzz_firestore_auth(cfg, token, wl):
    ev = []
    if not cfg.get("PROJECT_ID"): return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    base_url = f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents"
    headers = {"Content-Type":"application/json", "Authorization":f"Bearer {token}"}
    write_coll = "f3tcher_probes_auth"
    write_doc_id = f"probe-{int(time.time())}"
    write_url = f"{base_url}/{write_coll}/{write_doc_id}"
    write_body = {"fields": {"probe": {"stringValue": "true"}, "timestamp": {"integerValue": str(int(time.time()))}}}
    write_r = http_request(write_url, method="PATCH", body=json.dumps(write_body), headers=headers)
    ev.append(write_r)
    if write_r["status"] == 200:
        http_request(write_url, method="DELETE", headers=headers)
        return {"status":"CRITICAL", "details":f"Authenticated write access to collection '{write_coll}' allowed.", "accessible":True, "evidence":ev}
    discovered = []
    for coll in wl["collections"]:
        q = {"structuredQuery":{"from":[{"collectionId":coll}],"limit":1}}
        r = http_request(f"{base_url}:runQuery", method="POST", body=json.dumps(q), headers=headers)
        ev.append(r)
        if r["status"] == 200: discovered.append(coll)
    if discovered: return {"status":"OPEN","details":f"/{' ,/'.join(discovered)} readable with any authenticated user (auth != null)","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Firestore still requires proper authentication","accessible":False,"evidence":ev}

def fuzz_storage(cfg):
    ev = []
    if not cfg.get("STORAGE_BUCKET"): return {"status":"NOT_CONFIGURED","details":"No STORAGE_BUCKET found in configuration","accessible":False,"evidence":ev}
    b = cfg["STORAGE_BUCKET"]
    prefixes_to_check = ["", "users/", "images/", "uploads/", "public/", "private/"]
    list_results = []
    for prefix in prefixes_to_check:
        encoded_prefix = urllib.parse.quote(prefix)
        url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/&prefix={encoded_prefix}"
        res = http_request(url)
        ev.append(res)
        if res["status"] == 200: list_results.append(prefix or "root")
    write_res = None
    if list_results:
        name = urllib.parse.quote(f"probes/test-{int(time.time())}.txt", safe="")
        up = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?uploadType=media&name={name}", method="POST", body="f3tcher test file - safe to delete", headers={"Content-Type":"text/plain"})
        ev.append(up)
        write_res = up
        if up["status"] == 200:
            try:
                data = json.loads(up["snippet"])
                n = data.get("name","")
                if n:
                    del_url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o/{urllib.parse.quote(n, safe='')}"
                    http_request(del_url, method="DELETE")
            except Exception: pass
    write_successful = write_res and write_res["status"] == 200
    if write_successful:
        details = "Lists & uploads without auth (scopes: " + ', '.join(list_results) + ")"
        return {"status":"CRITICAL", "details":details, "accessible":True, "evidence":ev}
    if list_results:
        details = "Lists without auth (scopes: " + ', '.join(list_results) + ")"
        return {"status":"OPEN", "details":details, "accessible":True, "evidence":ev}
    return {"status":"CLOSED","details":"Storage requires authentication","accessible":False,"evidence":ev}

def fuzz_storage_auth(cfg, token):
    ev = []
    if not cfg.get("STORAGE_BUCKET"): return {"status":"NOT_CONFIGURED","details":"No STORAGE_BUCKET found in configuration","accessible":False,"evidence":ev}
    b = cfg["STORAGE_BUCKET"]
    headers = {"Authorization": f"Bearer {token}"}
    prefixes_to_check = ["", "users/", "images/", "uploads/", "public/", "private/"]
    list_results = []
    for prefix in prefixes_to_check:
        encoded_prefix = urllib.parse.quote(prefix)
        url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/&prefix={encoded_prefix}"
        res = http_request(url, headers=headers)
        ev.append(res)
        if res["status"] == 200: list_results.append(prefix or "root")
    write_res = None
    if list_results:
        name = urllib.parse.quote(f"probes_auth/test-{int(time.time())}.txt", safe="")
        up_headers = {"Content-Type":"text/plain", "Authorization":f"Bearer {token}"}
        up = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?uploadType=media&name={name}", method="POST", body="f3tcher auth test file - safe to delete", headers=up_headers)
        ev.append(up)
        write_res = up
        if up["status"] == 200:
            try:
                data = json.loads(up["snippet"])
                n = data.get("name","")
                if n:
                    del_url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o/{urllib.parse.quote(n, safe='')}"
                    http_request(del_url, method="DELETE", headers=headers)
            except Exception: pass
    write_successful = write_res and write_res["status"] == 200
    if write_successful:
        details = f"Storage accessible with any authenticated user (auth != null); scopes: {', '.join(list_results)}"
        return {"status":"CRITICAL", "details":details, "accessible":True, "evidence":ev}
    if list_results:
        details = f"Storage readable with any authenticated user (auth != null); scopes: {', '.join(list_results)}"
        return {"status":"OPEN", "details":details, "accessible":True, "evidence":ev}
    return {"status":"CLOSED","details":"Storage still requires proper authentication","accessible":False,"evidence":ev}

def fuzz_functions(cfg, wl):
    ev, discovered = [], []
    if not cfg.get("PROJECT_ID"): return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    for region in wl["functions_regions"]:
        for fn in wl["functions"]:
            url = f"https://{region}-{pid}.cloudfunctions.net/{fn}"
            r = http_request(url, log=False)
            ev.append(r)
            if r["status"] == 405:
                r2 = http_request(url, method="POST", body="{}", headers={"Content-Type":"application/json"}, log=False)
                ev.append(r2)
                if r2["status"] == 200: discovered.append(f"{region}->{fn} (POST)")
            if r["status"] == 200: discovered.append(f"{region}->{fn}")
    if discovered: return {"status":"OPEN","details":"Cloud Function open: " + ", ".join(discovered),"accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"No open Cloud Functions found","accessible":False,"evidence":ev}

def fuzz_hosting(cfg):
    ev = []
    if not cfg.get("PROJECT_ID"): return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    urls = [f"https://{pid}.web.app/", f"https://{pid}.firebaseapp.com/"]
    for u in urls:
        r = http_request(u)
        ev.append(r)
        if r["status"] == 200: ev.append(http_request(u + "__/firebase/init.json"))
    open_count = sum(1 for e in ev if e["status"] == 200)
    if open_count > 0: return {"status":"OPEN","details":"Firebase Hosting is accessible","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Firebase Hosting not accessible","accessible":False,"evidence":ev}

# --- Vulnerability Processing ---
def build_vulnerabilities(all_evidence: List[dict]) -> List[dict]:
    vulnerabilities: List[dict] = []
    seen = set()
    for entry in all_evidence:
        status = entry.get("status", 0)
        try:
            status = int(status)
        except Exception:
            status = 0
        service = entry.get("service", "Unknown")
        method = entry.get("method", "GET")
        url = entry.get("url", "")
        details = entry.get("vuln", entry.get("evidence", f"Status: {status}"))
        snippet = entry.get("snippet", "")

        is_open = False
        if isinstance(details, str) and (details.startswith("OPEN") or details.startswith("CRITICAL")):
            is_open = True
        if status in (200, 201):
            is_open = True or is_open
        if status == 204 and (service in ("Storage", "firebasestorage")) and method in ("DELETE", "PATCH", "PUT", "POST"):
            is_open = True
        if not is_open:
            continue
        key = (service, method, url)
        if key in seen:
            continue
        seen.add(key)
        vulnerabilities.append({
            "service": service,
            "method": method,
            "url": url,
            "details": details,
            "preview": snippet,
            "status": status,
        })
    vulnerabilities.sort(key=lambda v: (v.get("service", ""), v.get("method", ""), v.get("url", "")))
    return vulnerabilities

# --- Main Audit Function ---
def audit_folder(dir_path, wl, keep_plists: bool = False):
    """Main audit function that coordinates all Firebase service testing"""
    import plistlib
    import os
    
    plist_path = os.path.join(dir_path, "GoogleService-Info.plist")
    if not os.path.isfile(plist_path): 
        return None
        
    with open(plist_path, "rb") as f: 
        cfg = plistlib.load(f)
    if isinstance(cfg.get("CLIENT_ID"), str): 
        cfg["CLIENT_ID"] = [cfg["CLIENT_ID"]]
    
    bundle_id = cfg.get("BUNDLE_ID") or os.path.basename(dir_path.rstrip("/"))
    
    # Import here to avoid circular dependency
    from .reports import FindingSummary
    
    summary, results, all_evidence = FindingSummary(), {}, []
    
    # Test all Firebase services with colorful headers
    vprint(f"{BOLD}Fuzzing Realtime DB...{RESET}", CYAN)
    vprint("")
    rtdb = fuzz_rtdb(cfg, wl); results["rtdb"] = rtdb; all_evidence += rtdb["evidence"]; summary.add(rtdb["status"])
    vprint("")
    
    vprint(f"{BOLD}Fuzzing Firestore...{RESET}", CYAN)
    vprint("")
    fs = fuzz_firestore(cfg, wl); results["firestore"] = fs; all_evidence += fs["evidence"]; summary.add(fs["status"])
    vprint("")
    
    vprint(f"{BOLD}Fuzzing Storage...{RESET}", CYAN)
    vprint("")
    st = fuzz_storage(cfg); results["storage"] = st; all_evidence += st["evidence"]; summary.add(st["status"])
    vprint("")
    
    vprint(f"{BOLD}Fuzzing Cloud Functions...{RESET}", CYAN)
    vprint("")
    fn = fuzz_functions(cfg, wl); results["functions"] = fn; all_evidence += fn["evidence"]; summary.add(fn["status"])
    vprint("")
    
    vprint(f"{BOLD}Fuzzing Hosting...{RESET}", CYAN)
    vprint("")
    ho = fuzz_hosting(cfg); results["hosting"] = ho; all_evidence += ho["evidence"]; summary.add(ho["status"])
    vprint("")
    
    # Authentication testing
    auth = {"anonymous_enabled": False, "email_password_enabled": False, "token_obtained": False, "token_type": "", "auth_retry_results": {}}
    token = None
    if cfg.get("API_KEY"):
        vprint("")
        vprint(f"{BOLD}Attempting to get auth token...{RESET}", CYAN)
        vprint("")
        t = get_anonymous_token(cfg["API_KEY"])
        if t:
            token = t; auth["anonymous_enabled"] = True; auth["token_obtained"] = True; auth["token_type"] = "anonymous"
            vprint("↳ Anonymous token obtained.", GREEN)
        else:
            t = get_email_token(cfg["API_KEY"])
            if t:
                token = t; auth["email_password_enabled"] = True; auth["token_obtained"] = True; auth["token_type"] = "email_password"
                vprint("↳ Email/password token obtained.", GREEN)
    
    if token:
        vprint("")
        vprint(f"{BOLD}Fuzzing with authenticated user...{RESET}", CYAN)
        vprint("")
        rtdb_a = fuzz_rtdb_auth(cfg, token, wl); auth["auth_retry_results"]["rtdb"] = rtdb_a; all_evidence += rtdb_a["evidence"]; summary.add(f"auth_{rtdb_a['status']}")
        fs_a = fuzz_firestore_auth(cfg, token, wl); auth["auth_retry_results"]["firestore"] = fs_a; all_evidence += fs_a["evidence"]; summary.add(f"auth_{fs_a['status']}")
        st_a = fuzz_storage_auth(cfg, token); auth["auth_retry_results"]["storage"] = st_a; all_evidence += st_a["evidence"]; summary.add(f"auth_{st_a['status']}")
        vprint("")
    
    # Build vulnerabilities and add to summary
    vulnerabilities = build_vulnerabilities(all_evidence)
    for vuln in vulnerabilities:
        summary.add_vulnerability(vuln)
    
    return {
        "config": cfg,
        "vulnerabilities": vulnerabilities,
        "auth_info": auth,
        "summary": summary,
        "all_evidence": all_evidence
    }
