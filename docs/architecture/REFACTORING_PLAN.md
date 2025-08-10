# Refactoring Plan

## 1. Overview

This document provides a step-by-step plan for refactoring the scanner from its current script-based architecture to the new modular, object-oriented design. The refactoring is broken down into phases to allow for incremental changes and testing at each stage.

The guiding principle is to migrate logic from the existing scripts (`fetch.py`, `audit.py`, `summarize.py`) into new classes and modules within a `scanner/` directory, orchestrated by a new `main.py` entry point.

## 2. Prerequisites

Before starting the refactoring, the following documents should be reviewed and approved:

-   `docs/architecture/IMPROVEMENTS.md`
-   `docs/architecture/DATA_MODEL.md`

## 3. Refactoring Phases

### Phase 1: Establish the New Structure (Focus: Fetch)

This phase lays the foundation of the new architecture.

1.  **Create Module Directory:**
    -   Create a new directory named `scanner/`.
    -   Add an empty `scanner/__init__.py` file to make it a Python module.

2.  **Implement the Data Model:**
    -   Create `scanner/models.py`.
    -   Implement the `ScanRun`, `AppScan`, and `AuditResult` data classes as defined in the Data Model Specification.

3.  **Create the Fetcher Component:**
    -   Create `scanner/fetcher.py`.
    -   Create a `Fetcher` class within this file.
    -   Move the core logic from the existing top-level `fetch.py` into methods within the `Fetcher` class (e.g., `fetcher.download_ipa()`, `fetcher.extract_plists()`).
    -   The `Fetcher`'s main public method (e.g., `fetcher.run()`) will take a list of `AppScan` objects and populate their path-related fields (`ipa_path`, `info_plist_path`, etc.).

4.  **Create the New Entry Point:**
    -   Create a new top-level `main.py`.
    -   This script will be responsible for initializing the `ScanRun` object and the list of `AppScan` objects.
    -   It will then instantiate the `Fetcher` and run the fetch stage.
    -   For this initial phase, it can print the state of the `ScanRun` object after the fetch is complete.

5.  **Update Orchestration:**
    -   Modify `pipeline.sh` to call `python3 main.py` instead of the individual scripts. For this phase, the calls to `audit.py` and `summarize.py` can be temporarily commented out.
    -   Remove the original `fetch.py`.

**Outcome of Phase 1:** The fetch logic is now part of the new modular structure, and the pipeline uses the new data model to track the state of the fetch stage.

### Phase 2: Migrate the Audit Logic

1.  **Create the Auditor Component:**
    -   Create `scanner/auditor.py`.
    -   Create an `Auditor` class.
    -   Create sub-modules for each Firebase service, e.g., `scanner/firebase/rtdb.py`, `scanner/firebase/firestore.py`.
    -   Move the corresponding audit logic from `audit.py` into these service-specific modules. Each module should have a function like `check_vulnerabilities()`.
    -   The `Auditor` class will orchestrate the calls to these sub-modules.

2.  **Integrate into `main.py`:**
    -   In `main.py`, after the fetch stage is complete, instantiate the `Auditor`.
    -   Pass the `ScanRun` object to the auditor's main method (e.g., `auditor.run()`).
    -   The auditor will populate the `audit_result` field of each `AppScan` object.

3.  **Cleanup:**
    -   Remove the original `audit.py`.
    -   Uncomment the audit stage call in `pipeline.sh` (which now points to `main.py`).

**Outcome of Phase 2:** The audit logic is now fully integrated into the new architecture, and the results are stored in the centralized data model.

### Phase 3: Migrate the Summarize and Report Logic

1.  **Create the Summarizer Component:**
    -   Create `scanner/summarizer.py`.
    -   Create a `Summarizer` class.
    -   Move the logic for counting and summarizing from `summarize.py` into this class.

2.  **Create the Reporter Component:**
    -   Create `scanner/reporter.py`.
    -   Create a `Reporter` class.
    -   Move the logic for writing the final JSON files into this class. This can be extended later to support other formats (e.g., HTML).

3.  **Integrate into `main.py`:**
    -   In `main.py`, after the audit stage, instantiate and run the `Summarizer` and `Reporter`.
    -   These components will populate the `summary` field of each `AppScan` and write the final output files.

4.  **Cleanup:**
    -   Remove the original `summarize.py`.
    -   The `pipeline.sh` script should now only contain the single call to `python3 main.py`.

**Outcome of Phase 3:** The entire pipeline is now running within the new modular, object-oriented architecture.

### Phase 4: Final Enhancements

1.  **Configuration:**
    -   Create a `scanner/config.py` module to handle loading configuration from environment variables and command-line arguments, populating the `ScanRun.config` dictionary.

2.  **Error Handling:**
    -   Implement the enhanced error handling strategy. Use try/except blocks in each component to catch and record errors in the `AppScan.error_message` field without halting the entire pipeline.

3.  **Logging:**
    -   Integrate Python's `logging` module to provide structured logging throughout the application.

4.  **Testing:**
    -   Create a `tests/` directory and add unit tests for the new components, especially the data model and the business logic in the auditor and summarizer.

**Outcome of Phase 4:** The new architecture is complete, robust, and ready for future development.
