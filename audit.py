#!/usr/bin/env python3
import os, sys, json, time, plistlib, urllib.request, urllib.error, urllib.parse

BASE_DIR = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
WORDLISTS_DIR = "/home/projects/private/f3tcher/internal/wordlists"
USER_AGENT = "f3tcher/1.1"
HTTP_TIMEOUT = 12
MAX_RETRIES = 2
RESCAN = (os.environ.get("RESCAN", "0") == "1") or (os.environ.get("FORCE_RESCAN", "0") == "1")

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

def read_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception:
        return []

def load_wordlists():
    wl = {}
    wl["collections"] = read_wordlist(os.path.join(WORDLISTS_DIR, "firestore.txt")) or ["users", "profiles", "posts", "messages", "items"]
    wl["rtdb_roots"] = read_wordlist(os.path.join(WORDLISTS_DIR, "rtdb.txt")) or ["users", "public", "profiles", "data", "messages"]
    wl["functions_regions"] = read_wordlist(os.path.join(WORDLISTS_DIR, "functions_regions.txt")) or [
        "us-central1","us-east1","us-west1","europe-west1","asia-northeast1"
    ]
    wl["functions"] = read_wordlist(os.path.join(WORDLISTS_DIR, "functions.txt")) or [
        "health","healthz","status","ping","version","api","config","init","login","signup","user"
    ]
    # fast mode caps
    wl["collections"] = wl["collections"][:5]
    wl["rtdb_roots"] = wl["rtdb_roots"][:5]
    wl["functions_regions"] = wl["functions_regions"][:2]
    wl["functions"] = wl["functions"][:10]
    return wl

def http_request(url, method="GET", body=None, headers=None):
    vprint(f"HTTP {method} {url}", GREY)
    headers = headers.copy() if headers else {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENT
    if "Accept" not in headers:
        headers["Accept"] = "application/json"
    data = body if body is None else (body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8"))
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url=url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                status = resp.getcode()
                raw = resp.read()
                snippet = raw[:200].decode("utf-8", errors="replace") if len(raw) > 16 * 1024 else raw.decode("utf-8", errors="replace")
                vprint(f"↳ {status}", GREY)
                evidence = (
                    "Successful access" if status in (200, 201) else
                    "Access denied" if status in (401, 403) else
                    "Not found" if status == 404 else
                    f"Status: {status}"
                )
                svc, vuln = classify(url, status, method)
                return {"url": url, "method": method, "status": status, "snippet": snippet, "evidence": evidence, "service": svc, "vuln": vuln}
        except urllib.error.HTTPError as e:
            status = e.code
            raw = e.read() if hasattr(e, "read") else b""
            snippet = raw[:200].decode("utf-8", errors="replace")
            vprint(f"↳ {status}", GREY)
            evidence = (
                "Successful access" if status in (200, 201) else
                "Access denied" if status in (401, 403) else
                "Not found" if status == 404 else
                f"Status: {status}"
            )
            svc, vuln = classify(url, status, method)
            return {"url": url, "method": method, "status": status, "snippet": snippet, "evidence": evidence, "service": svc, "vuln": vuln}
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
                continue
            vprint(f"↳ ERROR {last_err}", RED)
            return {"url": url, "method": method, "status": 0, "snippet": "", "evidence": f"Request failed: {last_err}", "service": "Unknown", "vuln": ""}

def classify(u, status, method):
    s = u
    if "firebasedatabase.app" in s or "firebaseio.com" in s:
        if status in (200, 201):
            return "Realtime DB", ("CRITICAL: Public write access detected" if "_probes" in s else "OPEN: Public read access detected")
        return "Realtime DB", f"Status: {status}"
    if "firestore.googleapis" in s:
        if status in (200, 201):
            return "Firestore", "OPEN: Collection accessible without auth"
        return "Firestore", f"Status: {status}"
    if "firebasestorage" in s:
        if status in (200, 201):
            return "Storage", ("CRITICAL: Public write access detected" if "uploadType=media" in s else "OPEN: Public list access detected")
        return "Storage", f"Status: {status}"
    if "cloudfunctions.net" in s:
        if status in (200, 201):
            return "Cloud Functions", "OPEN: Function accessible without auth"
        return "Cloud Functions", f"Status: {status}"
    if ".web.app" in s or ".firebaseapp.com" in s:
        if status in (200, 201):
            return "Hosting", "OPEN: Hosting accessible"
        return "Hosting", f"Status: {status}"
    if "identitytoolkit.googleapis.com" in s:
        if status in (200, 201):
            return "Auth", "INFO: Anonymous signup enabled"
        return "Auth", f"Status: {status}"
    if status in (200, 201):
        return "Unknown", f"OPEN: {method} access detected"
    return "Unknown", f"Status: {status}"

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

def fuzz_rtdb(cfg, wl):
    ev = []
    details = ""
    if not cfg.get("DATABASE_URL"):
        return {"status":"NOT_CONFIGURED","details":"No DATABASE_URL found in configuration","accessible":False,"evidence":ev}
    db = cfg["DATABASE_URL"].rstrip("/")
    discovered = []
    for root in wl["rtdb_roots"]:
        url = f"{db}/{root}/.json?shallow=true&limitToFirst=1"
        r = http_request(url)
        ev.append(r)
        if r["status"] == 200:
            discovered.append(root)
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
    if not cfg.get("DATABASE_URL"):
        return {"status":"NOT_CONFIGURED","details":"No DATABASE_URL found in configuration","accessible":False,"evidence":ev}
    db = cfg["DATABASE_URL"].rstrip("/")
    for root in wl["rtdb_roots"]:
        url = f"{db}/{root}/.json?shallow=true&limitToFirst=1&auth={urllib.parse.quote(token)}"
        r = http_request(url)
        ev.append(r)
        if r["status"] == 200:
            discovered.append(root)
    write_url = f"{db}/.json?auth={urllib.parse.quote(token)}"
    write_data = {"_probes_auth":{"rtdb_write_test": True}}
    r = http_request(write_url, method="PATCH", body=json.dumps(write_data), headers={"Content-Type":"application/json"})
    ev.append(r)
    if r["status"] == 200:
        del_url = f"{db}/_probes_auth/rtdb_write_test.json?auth={urllib.parse.quote(token)}"
        http_request(del_url, method="DELETE")
    open_count = sum(1 for e in ev if e["status"] == 200)
    write_count = sum(1 for e in ev if e["status"] == 200 and "_probes_auth" in e["url"])
    if write_count > 0:
        return {"status":"CRITICAL","details":f"Database accessible with any authenticated user (auth != null); keys discovered: {', '.join(discovered)}","accessible":True,"evidence":ev}
    if open_count > 0:
        return {"status":"OPEN","details":f"Database readable with any authenticated user (auth != null); keys discovered: {', '.join(discovered)}","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Database still requires proper authentication","accessible":False,"evidence":ev}

def is_datastore_mode(snippet):
    s = snippet.lower()
    return ("datastore mode" in s) or ("not available for firestore in datastore mode" in s)

def fuzz_firestore(cfg, wl):
    ev = []
    if not cfg.get("PROJECT_ID"):
        return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid, key = cfg.get("PROJECT_ID",""), urllib.parse.quote(cfg.get("API_KEY",""))
    pre = http_request(f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents:runQuery?key={key}",
                       method="POST", body='{"structuredQuery":{"limit":1}}', headers={"Content-Type":"application/json"})
    ev.append(pre)
    if pre["status"] == 400 and is_datastore_mode(pre["snippet"]):
        return {"status":"NOT_APPLICABLE","details":"Firestore is Datastore mode","accessible":False,"evidence":[pre]}
    discovered, forbidden = [], 0
    sample = wl["collections"][:min(3, len(wl["collections"]))]
    for coll in sample:
        q = {"structuredQuery":{"from":[{"collectionId":coll}],"limit":1}}
        r = http_request(f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents:runQuery?key={key}",
                         method="POST", body=json.dumps(q), headers={"Content-Type":"application/json"})
        ev.append(r)
        if r["status"] == 200:
            discovered.append(coll)
        if r["status"] == 403:
            forbidden += 1
    if discovered:
        return {"status":"OPEN","details":f"/{' ,/'.join(discovered)} readable without auth (?key=)","accessible":True,"evidence":ev}
    # no unauth success → leave to auth phase
    return {"status":"CLOSED","details":"Firestore requires proper authentication","accessible":False,"evidence":ev}

def fuzz_firestore_auth(cfg, token, wl):
    ev = []
    if not cfg.get("PROJECT_ID"):
        return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    if not wl["collections"]:
        return {"status":"CLOSED","details":"No collections to probe","accessible":False,"evidence":ev}
    coll = wl["collections"][0]
    q = {"structuredQuery":{"from":[{"collectionId":coll}],"limit":1}}
    r = http_request(f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents:runQuery",
                     method="POST", body=json.dumps(q),
                     headers={"Content-Type":"application/json","Authorization":f"Bearer {token}"})
    ev.append(r)
    if r["status"] == 200:
        return {"status":"OPEN","details":f"/{coll} readable with any authenticated user (auth != null)","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Firestore still requires proper authentication","accessible":False,"evidence":ev}

def fuzz_storage(cfg):
    ev = []
    if not cfg.get("STORAGE_BUCKET"):
        return {"status":"NOT_CONFIGURED","details":"No STORAGE_BUCKET found in configuration","accessible":False,"evidence":ev}
    b = cfg["STORAGE_BUCKET"]
    root = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/")
    ev.append(root)
    users = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/&prefix=users%2F")
    ev.append(users)
    write_res = None
    if root["status"] == 200 or users["status"] == 200:
        name = urllib.parse.quote(f"probes/test-{int(time.time())}.txt", safe="")
        up = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?uploadType=media&name={name}",
                          method="POST", body="f3tcher test file - safe to delete",
                          headers={"Content-Type":"text/plain"})
        ev.append(up)
        write_res = up
        if up["status"] == 200:
            try:
                data = json.loads(up["snippet"])
                n = data.get("name","")
                if n:
                    del_url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o/{urllib.parse.quote(n, safe='')}"
                    http_request(del_url, method="DELETE")
            except Exception:
                pass
    open_count = sum(1 for e in ev if e["status"] == 200)
    write_count = 1 if (write_res and write_res["status"] == 200) else 0
    if write_count > 0:
        return {"status":"CRITICAL","details":"Lists & uploads without auth (scope: root/users/)","accessible":True,"evidence":ev}
    if open_count > 0:
        return {"status":"OPEN","details":"Lists without auth (scope: root/users/)","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Storage requires authentication","accessible":False,"evidence":ev}

def fuzz_storage_auth(cfg, token):
    ev = []
    if not cfg.get("STORAGE_BUCKET"):
        return {"status":"NOT_CONFIGURED","details":"No STORAGE_BUCKET found in configuration","accessible":False,"evidence":ev}
    b = cfg["STORAGE_BUCKET"]
    root = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/",
                        headers={"Authorization":f"Bearer {token}"})
    ev.append(root)
    users = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?maxResults=10&delimiter=/&prefix=users%2F",
                         headers={"Authorization":f"Bearer {token}"})
    ev.append(users)
    write_res = None
    if root["status"] == 200 or users["status"] == 200:
        name = urllib.parse.quote(f"probes_auth/test-{int(time.time())}.txt", safe="")
        up = http_request(f"https://firebasestorage.googleapis.com/v0/b/{b}/o?uploadType=media&name={name}",
                          method="POST", body="f3tcher auth test file - safe to delete",
                          headers={"Content-Type":"text/plain","Authorization":f"Bearer {token}"})
        ev.append(up)
        write_res = up
        if up["status"] == 200:
            try:
                data = json.loads(up["snippet"])
                n = data.get("name","")
                if n:
                    del_url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o/{urllib.parse.quote(n, safe='')}"
                    http_request(del_url, method="DELETE", headers={"Authorization":f"Bearer {token}"})
            except Exception:
                pass
    open_count = sum(1 for e in ev if e["status"] == 200)
    write_count = 1 if (write_res and write_res["status"] == 200) else 0
    if write_count > 0:
        return {"status":"CRITICAL","details":"Storage accessible with any authenticated user (auth != null); scope: root/users/","accessible":True,"evidence":ev}
    if open_count > 0:
        return {"status":"OPEN","details":"Storage readable with any authenticated user (auth != null); scope: root/users/","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Storage still requires proper authentication","accessible":False,"evidence":ev}

def fuzz_functions(cfg, wl):
    ev, discovered = [], []
    if not cfg.get("PROJECT_ID"):
        return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    for region in wl["functions_regions"]:
        for fn in wl["functions"]:
            url = f"https://{region}-{pid}.cloudfunctions.net/{fn}"
            r = http_request(url)
            ev.append(r)
            if r["status"] == 405:
                r2 = http_request(url, method="POST", body="{}", headers={"Content-Type":"application/json"})
                ev.append(r2)
                if r2["status"] == 200:
                    discovered.append(f"{region}->{fn} (POST)")
            if r["status"] == 200:
                discovered.append(f"{region}->{fn}")
    if discovered:
        return {"status":"OPEN","details":"Cloud Function open: " + ", ".join(discovered),"accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"No open Cloud Functions found","accessible":False,"evidence":ev}

def fuzz_hosting(cfg):
    ev = []
    if not cfg.get("PROJECT_ID"):
        return {"status":"NOT_CONFIGURED","details":"No PROJECT_ID found in configuration","accessible":False,"evidence":ev}
    pid = cfg["PROJECT_ID"]
    urls = [f"https://{pid}.web.app/", f"https://{pid}.firebaseapp.com/"]
    for u in urls:
        r = http_request(u)
        ev.append(r)
        if r["status"] == 200:
            ev.append(http_request(u + "__/firebase/init.json"))
    open_count = sum(1 for e in ev if e["status"] == 200)
    if open_count > 0:
        return {"status":"OPEN","details":"Firebase Hosting is accessible","accessible":True,"evidence":ev}
    return {"status":"CLOSED","details":"Firebase Hosting not accessible","accessible":False,"evidence":ev}

def infer_app_check(report):
    for svc in [report["realtime_db"], report["firestore"], report["storage"]]:
        if "app check" in svc.get("details","").lower():
            return {"enforced": True, "details": "App Check enforcement detected in error responses"}
    return {"enforced": False, "details": "No App Check enforcement detected"}

def calc_risk(report):
    critical = 0
    open_s = 0
    rd, fs, st = report["realtime_db"], report["firestore"], report["storage"]
    if rd["status"] == "CRITICAL": critical += 1
    elif rd.get("accessible"): open_s += 1
    if fs["status"] == "CRITICAL": critical += 1
    elif fs.get("accessible"): open_s += 1
    if st["status"] == "CRITICAL": critical += 1
    elif st.get("accessible"): open_s += 1
    details = []
    if rd["status"] == "CRITICAL": details.append("Realtime Database is publicly readable AND writable")
    elif rd.get("accessible"): details.append("Realtime Database is publicly readable")
    if fs["status"] == "CRITICAL": details.append("Firestore is publicly readable AND writable")
    elif fs.get("accessible"): details.append("Firestore is publicly accessible")
    if st["status"] == "CRITICAL": details.append("Storage bucket is publicly accessible AND writable")
    elif st.get("accessible"): details.append("Storage bucket is publicly accessible")
    if critical > 0:
        return "CRITICAL", details + [f"{critical} service(s) allow public write access"]
    if open_s == 0: return "LOW", details or ["All Firebase services are properly secured"]
    if open_s == 1: return "MEDIUM", details + ["One Firebase service is publicly accessible"]
    return "HIGH", details + ["Multiple Firebase services are publicly accessible"]

def to_json_report(cfg, results, all_evidence, auth_info, app_check, risk_level, risk_details):
    return {
        "bundle_id": cfg.get("BUNDLE_ID",""),
        "project_id": cfg.get("PROJECT_ID",""),
        "api_key": cfg.get("API_KEY",""),
        "realtime_db": results["rtdb"],
        "firestore": results["firestore"],
        "storage": results["storage"],
        "cloud_functions": results["functions"],
        "hosting": results["hosting"],
        "auth_status": auth_info,
        "app_check": app_check,
        "risk_level": risk_level,
        "risk_details": risk_details,
        "config": cfg,
        "evidence": {"critical_findings": [], "open_findings": [], "auth_findings": [], "app_check_signals": []},
        "fuzz_config": {"mode":"fast","timeout":5,"max_retries":2,"jitter":True},
        "all_evidence": all_evidence,
    }

def audit_folder(dir_path, wl):
    plist_path = os.path.join(dir_path, "GoogleService-Info.plist")
    if not os.path.isfile(plist_path):
        return
    with open(plist_path, "rb") as f:
        cfg = plistlib.load(f)
    # normalize CLIENT_ID to list
    if isinstance(cfg.get("CLIENT_ID"), str):
        cfg["CLIENT_ID"] = [cfg["CLIENT_ID"]]
    bundle_id = cfg.get("BUNDLE_ID") or os.path.basename(dir_path.rstrip("/"))
    # Skip if an audit already exists for this bundle (unless RESCAN)
    out_path = os.path.join(dir_path, f"{bundle_id}_audit.json")
    if not RESCAN and os.path.isfile(out_path):
        vprint(f"skip (audit exists): {out_path}", YELLOW)
        return

    results = {}
    all_evidence = []
    rtdb = fuzz_rtdb(cfg, wl); results["rtdb"] = rtdb; all_evidence += rtdb["evidence"]
    fs = fuzz_firestore(cfg, wl); results["firestore"] = fs; all_evidence += fs["evidence"]
    st = fuzz_storage(cfg); results["storage"] = st; all_evidence += st["evidence"]
    fn = fuzz_functions(cfg, wl); results["functions"] = fn; all_evidence += fn["evidence"]
    ho = fuzz_hosting(cfg); results["hosting"] = ho; all_evidence += ho["evidence"]
    # auth phase
    auth = {"anonymous_enabled": False, "email_password_enabled": False, "token_obtained": False, "token_type": "", "auth_retry_results": {}}
    token = None
    if cfg.get("API_KEY"):
        t = get_anonymous_token(cfg["API_KEY"])
        if t:
            token = t; auth["anonymous_enabled"] = True; auth["token_obtained"] = True; auth["token_type"] = "anonymous"
        else:
            t = get_email_token(cfg["API_KEY"])
            if t:
                token = t; auth["email_password_enabled"] = True; auth["token_obtained"] = True; auth["token_type"] = "email_password"
    if token:
        rtdb_a = fuzz_rtdb_auth(cfg, token, wl); auth["auth_retry_results"]["rtdb"] = rtdb_a; all_evidence += rtdb_a["evidence"]
        fs_a = fuzz_firestore_auth(cfg, token, wl); auth["auth_retry_results"]["firestore"] = fs_a; all_evidence += fs_a["evidence"]
        st_a = fuzz_storage_auth(cfg, token); auth["auth_retry_results"]["storage"] = st_a; all_evidence += st_a["evidence"]
    app_check = infer_app_check({"realtime_db": rtdb, "firestore": fs, "storage": st})
    risk_level, risk_details = calc_risk({"realtime_db": rtdb, "firestore": fs, "storage": st})
    report = to_json_report(cfg, results, all_evidence, auth, app_check, risk_level, risk_details)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    vprint(f"→ wrote {out_path}", GREEN)

def main():
    wl = load_wordlists()
    for name in sorted(os.listdir(BASE_DIR)):
        d = os.path.join(BASE_DIR, name)
        if not os.path.isdir(d):
            continue
        if not os.path.isfile(os.path.join(d, "GoogleService-Info.plist")):
            continue
        # Fast skip if any *_audit.json exists in the folder (unless RESCAN)
        if not RESCAN:
            try:
                if any(fn.endswith("_audit.json") for fn in os.listdir(d)):
                    vprint(f"skip (audit exists): {d}", YELLOW)
                    continue
            except Exception:
                pass
        vprint(f"\n{BOLD}Folder:{RESET} {d}", MAGENTA)
        audit_folder(d, wl)

if __name__ == "__main__":
    main()