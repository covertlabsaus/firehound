import json
import time
import urllib.parse
from typing import Dict, Any

from .utils import http_request
from ..models import FirebaseServiceAudit

def check_vulnerabilities(config: Dict[str, Any], wordlists: Dict[str, Any]) -> FirebaseServiceAudit:
    """
    Checks for vulnerabilities in a Firebase Realtime Database.
    """
    service_audit = FirebaseServiceAudit(service_name="Realtime Database")
    
    database_url = config.get("DATABASE_URL")
    if not database_url:
        service_audit.error_message = "No DATABASE_URL found in configuration"
        return service_audit

    db_root = database_url.rstrip("/")
    
    # Unauthenticated checks
    unauth_result = _fuzz_rtdb_unauthenticated(db_root, wordlists)
    service_audit.findings.extend(unauth_result["evidence"])
    
    if unauth_result["status"] == "CRITICAL":
        service_audit.is_vulnerable = True
        # Further logic can be added here to populate more detailed findings
        
    elif unauth_result["status"] == "OPEN":
        service_audit.is_vulnerable = True

    # TODO: Add authenticated checks logic here
    
    return service_audit

def _fuzz_rtdb_unauthenticated(db_root: str, wordlists: Dict[str, Any]) -> Dict[str, Any]:
    evidence = []
    discovered = []
    
    for root in wordlists.get("rtdb_roots", []):
        url = f"{db_root}/{root}/.json?shallow=true&limitToFirst=1"
        r = http_request(url)
        evidence.append(r)
        if r["status"] == 200:
            discovered.append(root)
            
    write_data = {"f3tcher_probe": {"timestamp": int(time.time()), "probe": True}}
    write_url = f"{db_root}/probes/.json"
    r_write = http_request(write_url, method="PATCH", body=json.dumps(write_data), headers={"Content-Type": "application/json"})
    evidence.append(r_write)
    
    if r_write["status"] == 200:
        http_request(write_url, method="DELETE") # Cleanup
        details = f"Database is publicly readable AND writable; keys discovered: {', '.join(discovered)}" if discovered else "Database is publicly writable"
        return {"status": "CRITICAL", "details": details, "accessible": True, "evidence": evidence}
        
    if discovered:
        details = f"Public READ; keys discovered: {', '.join(discovered)}"
        return {"status": "OPEN", "details": details, "accessible": True, "evidence": evidence}
        
    return {"status": "CLOSED", "details": "Realtime Database requires authentication", "accessible": False, "evidence": evidence}
