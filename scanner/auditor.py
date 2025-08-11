import plistlib
from pathlib import Path
from typing import Dict, Any

from .models import ScanRun, AppScan, AuditResult
from .utils import vprint, MAGENTA, BOLD, RESET

# Import the service-specific audit functions (will be created next)
from .firebase import rtdb
# from .firebase import firestore, storage, functions, hosting, auth

class Auditor:
    def __init__(self, scan_run: ScanRun):
        self.scan_run = scan_run
        # In a future step, wordlists could be loaded here
        self.wordlists = self._load_wordlists()

    def run(self):
        vprint("Starting audit stage...", MAGENTA)
        for app_scan in self.scan_run.app_scans:
            if app_scan.status != "fetched":
                vprint(f"Skipping audit for {app_scan.bundle_id} (status: {app_scan.status})", MAGENTA)
                continue
            
            vprint(f"\n{BOLD}Auditing Folder:{RESET} {app_scan.scan_dir}", MAGENTA)
            self._audit_app(app_scan)

    def _audit_app(self, app_scan: AppScan):
        app_scan.status = "auditing"
        
        if not app_scan.google_service_plist_path or not app_scan.google_service_plist_path.is_file():
            app_scan.status = "failed"
            app_scan.error_message = "GoogleService-Info.plist not found for audit."
            return

        try:
            with open(app_scan.google_service_plist_path, "rb") as f:
                config = plistlib.load(f)
        except Exception as e:
            app_scan.status = "failed"
            app_scan.error_message = f"Failed to parse GoogleService-Info.plist: {e}"
            return
            
        app_scan.audit_result = AuditResult()
        
        # Call the audit function for RTDB
        app_scan.audit_result.rtdb = rtdb.check_vulnerabilities(config, self.wordlists)
        
        # TODO: Call the actual audit functions for each service
        # For example:
        # app_scan.audit_result.firestore = firestore.check_vulnerabilities(config, self.wordlists)
        # ... and so on for all services

        app_scan.status = "audited"
        # For now, we'll just mark it as audited. The real logic will be added next.
        vprint(f"Finished audit for {app_scan.bundle_id}", MAGENTA)


    def _load_wordlists(self) -> Dict[str, Any]:
        # This is a placeholder for the wordlist loading logic from the original audit.py
        # For now, it returns a basic set of wordlists.
        return {
            "collections": ["users", "profiles", "posts", "messages", "items"],
            "rtdb_roots": ["users", "public", "profiles", "data", "messages"],
            "functions_regions": ["us-central1", "us-east1"],
            "functions": ["health", "api", "status", "ping", "login"],
        }
