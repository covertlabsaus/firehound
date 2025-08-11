import json
import time
import urllib.request
import urllib.error
import urllib.parse

from ..utils import vprint, GREY, RED

USER_AGENT = "f3tcher/1.1"
HTTP_TIMEOUT = 12
MAX_RETRIES = 2

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
