# Data Model Specification

## 1. Overview

A centralized data model is the cornerstone of the new architecture. It provides a "single source of truth" for the state of a scan, ensuring that data is structured, consistent, and explicit. This eliminates the ambiguity of a filesystem-based data flow and enables type-hinting for improved developer experience and code quality.

The following data classes will be defined in `scanner/models.py`. We will use Python's `dataclasses` for simplicity and clarity.

## 2. Core Data Classes

### `AppScan`

This class represents the state of a scan for a single application. It holds all the information related to one bundle ID, from initial configuration to the final summary.

```python
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List

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
    audit_result: Optional['AuditResult'] = None
    
    # Stage 3: Summary
    summary: Optional[Dict[str, Any]] = None
    
    # General
    status: str = "pending"  # e.g., pending, fetched, audited, summarized, failed
    error_message: Optional[str] = None
```

-   **`bundle_id`**: The application's bundle identifier (e.g., `com.example.app`).
-   **`scan_dir`**: The directory where the application's artifacts are stored.
-   **`ipa_path`, `info_plist_path`, etc.**: Paths to the key files extracted during the fetch stage.
-   **`audit_result`**: A nested `AuditResult` object containing the structured findings of the security audit.
-   **`summary`**: A dictionary containing the final summary data.
-   **`status`**: The current status of the scan for this app.
-   **`error_message`**: A field to store any error messages if a stage fails.

### `ScanRun`

This class is the top-level container for a single execution of the pipeline. It holds the overall configuration and a list of all the `AppScan` objects being processed.

```python
@dataclass
class ScanRun:
    """Represents a single run of the scanner pipeline."""
    run_id: str
    base_dir: Path
    app_scans: List[AppScan] = field(default_factory=list)
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
```

-   **`run_id`**: A unique identifier for the scan run (e.g., a timestamp).
-   **`base_dir`**: The root directory for the scan run's output.
-   **`app_scans`**: A list of `AppScan` objects, one for each application being scanned.
-   **`config`**: A dictionary holding the configuration for the run (e.g., `WORKERS`, `IPATOOL_PAR`).

### `AuditResult`

This class provides a structured representation of the security audit's findings, replacing the free-form JSON output of the original script.

```python
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
```

-   **`FirebaseServiceAudit`**: A generic container for the results of auditing a single service.
    -   **`service_name`**: The name of the service (e.g., "Firestore").
    -   **`is_vulnerable`**: A boolean flag indicating if any vulnerabilities were found.
    -   **`findings`**: A list of dictionaries, where each dictionary represents a specific finding (e.g., an open endpoint, a readable collection).
-   **`AuditResult`**: The main container that aggregates the audit results for all Firebase services.

## 3. Data Flow

With this data model, the pipeline's data flow becomes much clearer:

1.  The pipeline starts by creating a `ScanRun` object.
2.  For each bundle ID, an `AppScan` object is created and added to `ScanRun.app_scans`.
3.  The **fetcher** component iterates through the `app_scans`, populating the path fields (e.g., `ipa_path`).
4.  The **auditor** component takes the `app_scans`, and for each one, it performs the audit and populates the `audit_result` field with an `AuditResult` object.
5.  The **summarizer** component processes the `audit_result` for each `AppScan` and populates the `summary` field.
6.  Finally, the **reporter** component can use the completed `ScanRun` object to generate reports in various formats (JSON, HTML, etc.).
