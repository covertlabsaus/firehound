from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List

@dataclass
class FirebaseServiceAudit:
    """Audit results for a single Firebase service."""
    service_name: str
    is_vulnerable: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None

@dataclass
class AuditResult:
    """Represents the full set of findings from the audit stage."""
    rtdb: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Realtime Database"))
    firestore: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Firestore"))
    storage: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Cloud Storage"))
    functions: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Cloud Functions"))
    hosting: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Hosting"))
    auth: FirebaseServiceAudit = field(default_factory=lambda: FirebaseServiceAudit("Authentication"))

@dataclass
class AppScan:
    """Represents the scan data for a single application."""
    bundle_id: str
    scan_dir: Path
    
    # Stage 1: Fetch
    ipa_path: Optional[Path] = None
    info_plist_path: Optional[Path] = None
    google_service_plist_path: Optional[Path] = None
    
    # Stage 2: Audit
    audit_result: Optional[AuditResult] = None
    
    # Stage 3: Summary
    summary: Optional[Dict[str, Any]] = None
    
    # General
    status: str = "pending"  # e.g., pending, fetched, audited, summarized, failed
    error_message: Optional[str] = None

@dataclass
class ScanRun:
    """Represents a single run of the scanner pipeline."""
    run_id: str
    base_dir: Path
    app_scans: List[AppScan] = field(default_factory=list)
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
