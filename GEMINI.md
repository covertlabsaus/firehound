# GEMINI Project Analysis: iOS Application Scanner

## Project Overview

This project is a pipeline designed to automate the security analysis of iOS applications. It focuses on identifying misconfigurations in Google Firebase services. The pipeline consists of three main stages: fetching application data, auditing for vulnerabilities, and summarizing the results.

The core technologies used are Python for scripting the analysis logic, `ipatool` for interacting with the iOS App Store, and shell scripts for orchestrating the pipeline. The project also includes Docker support for running in a containerized environment.

## Core Concepts

### Firebase Security

The scanner's primary goal is to detect common security misconfigurations in an application's Firebase backend. It does this by analyzing the `GoogleService-Info.plist` file found in the app's bundle, which contains the Firebase project configuration. The scanner then probes the following Firebase services for vulnerabilities:

*   **Realtime Database (RTDB):** Checks for public read and write access.
*   **Cloud Firestore:** Checks for collections that can be read without authentication.
*   **Cloud Storage:** Checks for buckets that are publicly listable or writable.
*   **Cloud Functions:** Identifies publicly exposed functions.
*   **Firebase Hosting:** Checks if the hosting is accessible.
*   **Firebase Authentication:** Determines if anonymous or email/password sign-up is enabled.

### ipatool

`ipatool` is a command-line tool used to search for, download, and manage iOS applications from the App Store. This project uses `ipatool` to fetch the application's IPA file, which is then analyzed for the `GoogleService-Info.plist` file. `ipatool` requires authentication with an Apple ID, and the pipeline is designed to handle this non-interactively using a passphrase.

## Workflow

The analysis process is orchestrated by the `pipeline.sh` script and is divided into three stages:

1.  **Fetch:** The `fetch.py` script takes a list of bundle identifiers, and for each one, it uses `ipatool` to download the corresponding IPA file. It then extracts the `Info.plist` and `GoogleService-Info.plist` files from the IPA.

2.  **Audit:** The `audit.py` script parses the `GoogleService-Info.plist` file to get the Firebase project details. It then systematically probes the associated Firebase services for the vulnerabilities listed in the "Core Concepts" section. The results of the audit are saved to a JSON file.

3.  **Summarize:** The `summarize.py` script processes the audit results. It generates a summary of the vulnerabilities found and, if any data is found to be exposed, it will re-download the IPA to extract all `.plist` files for a more in-depth analysis. It also prunes any scan results that did not yield any interesting findings.

## Building and Running

The project can be run using the main `pipeline.sh` script, or via the `Makefile`.

### Prerequisites

*   Python 3.10+
*   `ipatool` (can be installed via Homebrew on macOS or a script for Linux)
*   `jq` (optional, for viewing JSON output)

### Running the Pipeline

The primary way to run the pipeline is through the `pipeline.sh` script. This script requires an `IPATOOL_PASSPHRASE` for authentication with the App Store.

```bash
# Set the passphrase for ipatool
export IPATOOL_PASSPHRASE="your-passphrase"

# Run the pipeline with default settings
./pipeline.sh
```

Alternatively, you can use the `Makefile`:

```bash
make pipeline IPATOOL_PASSPHRASE="your-passphrase"
```

### Configuration

The pipeline can be configured using environment variables and command-line arguments:

*   `IPATOOL_PASSPHRASE`: The passphrase for `ipatool`.
*   `WORKERS`: The number of concurrent workers for scanning (default: 8).
*   `IPATOOL_PAR`: The number of parallel `ipatool` downloads (default: 3).
*   `--base <DIR>`: The base directory for output (default: current directory).
*   `--ids <FILE>`: A file containing a list of bundle IDs to scan.
*   `--scan-dir <DIR>`: To resume a scan on an existing directory.

### Docker

A `Dockerfile` is provided for running the pipeline in a containerized environment.

```bash
# Build the Docker image
docker build -t toolchain:latest .

# Run the pipeline in a Docker container
docker run --rm -it \
  -e IPATOOL_PASSPHRASE="your-passphrase" \
  -v "$PWD":/work -w /work \
  toolchain:latest ./pipeline.sh
```

## Input and Output

### Input

*   **Bundle Identifiers:** The pipeline takes a list of iOS application bundle identifiers as input. This can be provided via a file (`--ids`) or from a default list within `fetch.py`.
*   **Passphrase:** The `IPATOOL_PASSPHRASE` environment variable is required for `ipatool` to authenticate with the App Store.

### Output

The pipeline generates a new directory for each run, named `scan_...`. Inside this directory, a subdirectory is created for each bundle ID that was processed. The output for each application includes:

*   `GoogleService-Info.plist`: The Firebase configuration file.
*   `Info.plist`: The application's information property list file.
*   `*_audit.json`: A detailed JSON report of the security audit.
*   `*_vuln_summary.json`: A summary of the vulnerabilities found.
*   `all_plists/`: If vulnerabilities are found and data is exposed, this directory will contain all of the `.plist` files from the IPA.
*   `logs/`: Contains logs for each stage of the pipeline.

## Development Conventions

*   **Modularity:** The pipeline is broken down into distinct, single-responsibility scripts (`fetch.py`, `audit.py`, `summarize.py`). This separation of concerns makes the codebase easier to understand, maintain, and extend.
*   **Orchestration:** A single shell script (`pipeline.sh`) orchestrates the execution of the Python scripts, providing a clear entry point and handling the flow of data between stages.
*   **Configuration:** The use of environment variables and command-line arguments for configuration makes the pipeline flexible and easy to integrate into different environments without modifying the code.
*   **Logging:** Each stage of the pipeline logs its output to a separate file in the `scan_.../logs/` directory. This, combined with verbose printing to the console, aids in debugging and monitoring the pipeline's progress.
*   **Error Handling:** The `pipeline.sh` script uses `set -Eeuo pipefail` to ensure that the script exits immediately if any command fails, preventing unexpected behavior. The Python scripts also include error handling for network requests and file operations.
*   **Concurrency:** The `summarize.py` script uses a thread pool to process multiple application folders concurrently, improving performance.