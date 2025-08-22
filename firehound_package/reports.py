#!/usr/bin/env python3
"""
Firehound Firebase Security Scanner - Reporting and Display
Contains all report generation, risk scoring, and terminal output functionality.
"""

import json, time, os, sys, re
from collections import defaultdict
from pathlib import Path

# --- Terminal Colors ---
RESET = "\033[0m"; BOLD = "\033[1m"; GREY = "\033[90m"; RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"; MAGENTA = "\033[35m"; CYAN = "\033[36m"
COLOR_ENABLED = (os.environ.get("NO_COLOR", "") == "" and (sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1" or os.environ.get("CLICOLOR_FORCE") == "1"))
VERBOSE = os.environ.get("VERBOSE", "1") != "0"

def vprint(msg: str, color: str = ""):
    """Print verbose message with color (imported from main module)"""
    if not VERBOSE:
        return
    prefix = color if (COLOR_ENABLED and color) else ""
    suffix = RESET if (COLOR_ENABLED and color) else ""
    print(f"{prefix}{msg}{suffix}" if prefix else msg)
    try:
        sys.stdout.flush()
    except Exception:
        pass

# --- Enhanced Finding Summary Class ---
class FindingSummary:
    def __init__(self):
        self.counts = defaultdict(int)
        self.vulnerabilities = []
        self.risk_score = 0

    def add(self, status):
        self.counts[status.lower()] += 1

    def add_vulnerability(self, vuln):
        self.vulnerabilities.append(vuln)
        self.risk_score = self.calculate_risk_score()

    def calculate_risk_score(self):
        """Calculate comprehensive risk score (0-100) based on vulnerability patterns"""
        if not self.vulnerabilities:
            return 0
        
        base_scores = {
            "CRITICAL": 100,
            "HIGH": 75,
            "MEDIUM": 50, 
            "LOW": 25,
            "INFO": 10
        }
        
        # Calculate base score from highest severity
        max_severity = 0
        has_write_access = False
        has_admin_access = False
        has_user_data = False
        
        for vuln in self.vulnerabilities:
            severity = self.classify_severity(vuln)
            max_severity = max(max_severity, base_scores.get(severity, 0))
            
            if "write access" in vuln.get("details", "").lower():
                has_write_access = True
            if "/admin/" in vuln.get("url", ""):
                has_admin_access = True
            if "/users/" in vuln.get("url", ""):
                has_user_data = True
        
        # Apply multipliers for dangerous combinations
        if has_admin_access and has_user_data:
            max_severity *= 1.5  # Admin + user data exposure
        elif has_write_access and len(self.vulnerabilities) > 3:
            max_severity *= 1.3  # Multiple write access points
        
        return min(100, int(max_severity))
    
    def classify_severity(self, vuln):
        """Classify individual vulnerability severity"""
        details = vuln.get("details", "").lower()
        url = vuln.get("url", "").lower()
        
        # Critical conditions
        if "write access" in details:
            return "CRITICAL"
        if "/admin/" in url and "200" in str(vuln.get("status", "")):
            return "CRITICAL"
        if "rules" in url and "public" in details:
            return "CRITICAL"
        
        # High conditions  
        if "/users/" in url and "200" in str(vuln.get("status", "")):
            return "HIGH"
        if "collection accessible" in details:
            return "HIGH"
        
        # Medium conditions
        if "list access" in details:
            return "MEDIUM"
        if "function accessible" in details:
            return "MEDIUM"
        
        # Default to low
        return "LOW"
    
    def get_risk_level(self):
        """Get human-readable risk level"""
        if self.risk_score >= 80:
            return "CRITICAL"
        elif self.risk_score >= 60:
            return "HIGH" 
        elif self.risk_score >= 40:
            return "MEDIUM"
        elif self.risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    def display(self):
        if not VERBOSE:
            return
        summary_line = " | ".join([f"{BOLD}{key.upper()}:{RESET} {self.counts[key]}" for key in sorted(self.counts.keys())])
        
        # Enhanced display with risk score
        if self.vulnerabilities:
            risk_level = self.get_risk_level()
            risk_color = RED if risk_level == "CRITICAL" else YELLOW if risk_level in ["HIGH", "MEDIUM"] else GREEN
            vprint(f"└── {summary_line} | {risk_color}RISK: {self.risk_score}/100 ({risk_level}){RESET}", MAGENTA)
        else:
            vprint(f"└── {summary_line}", MAGENTA)

    def to_dict(self):
        return {
            "counts": dict(self.counts),
            "riskScore": self.risk_score,
            "riskLevel": self.get_risk_level(),
            "totalVulnerabilities": len(self.vulnerabilities)
        }

# --- Report Generation Functions ---
def generate_enhanced_report(cfg, vulnerabilities, auth_info, scan_metadata):
    """Generate comprehensive security report with risk assessment and remediation"""
    
    # Group vulnerabilities by service
    grouped_vulns = group_vulnerabilities_by_service(vulnerabilities)
    summary = FindingSummary()
    for vuln in vulnerabilities:
        summary.add_vulnerability(vuln)
    
    report = {
        "metadata": {
            "appName": scan_metadata.get("app_name", cfg.get("BUNDLE_ID", "")),
            "bundleId": cfg.get("BUNDLE_ID", ""),
            "scanTimestamp": int(time.time()),
            "scanDuration": scan_metadata.get("duration", 0),
            "firehoundVersion": "1.0.0",
            "riskScore": summary.risk_score,
            "riskLevel": summary.get_risk_level()
        },
        
        "firebaseConfig": {
            "projectId": cfg.get("PROJECT_ID", ""),
            "apiKey": mask_api_key(cfg.get("API_KEY", "")),
            "databaseUrl": cfg.get("DATABASE_URL", ""),
            "storageBucket": cfg.get("STORAGE_BUCKET", ""),
            "clientId": cfg.get("CLIENT_ID", [])
        },
        
        "authenticationAnalysis": {
            "anonymousEnabled": auth_info.get("anonymous_enabled", False),
            "emailPasswordEnabled": auth_info.get("email_password_enabled", False),
            "tokenObtained": auth_info.get("token_obtained", False),
            "authBypassRisk": assess_auth_bypass_risk(auth_info, vulnerabilities)
        },
        
        "serviceAnalysis": {
            "realtimeDatabase": analyze_service_findings(grouped_vulns.get("Realtime DB", []), "rtdb"),
            "firestore": analyze_service_findings(grouped_vulns.get("Firestore", []), "firestore"),
            "storage": analyze_service_findings(grouped_vulns.get("Storage", []), "storage"),
            "cloudFunctions": analyze_service_findings(grouped_vulns.get("Cloud Functions", []), "functions"),
            "hosting": analyze_service_findings(grouped_vulns.get("Hosting", []), "hosting")
        },
        
        "vulnerabilities": [enhance_vulnerability_details(v) for v in vulnerabilities],
        "recommendations": generate_remediation_recommendations(vulnerabilities, cfg),
        "summary": summary.to_dict()
    }
    
    return report

def group_vulnerabilities_by_service(vulnerabilities):
    """Group vulnerabilities by Firebase service"""
    groups = defaultdict(list)
    for vuln in vulnerabilities:
        service = vuln.get("service", "Unknown")
        groups[service].append(vuln)
    return dict(groups)

def mask_api_key(api_key):
    """Mask API key for security while preserving format validation"""
    if not api_key or len(api_key) < 10:
        return api_key
    return api_key[:8] + "*" * (len(api_key) - 12) + api_key[-4:]

def assess_auth_bypass_risk(auth_info, vulnerabilities):
    """Assess risk of authentication bypass"""
    if not auth_info.get("token_obtained", False):
        return "LOW"
    
    # If we got a token AND found vulnerabilities, that's concerning
    if vulnerabilities and auth_info.get("email_password_enabled", False):
        return "HIGH"
    elif vulnerabilities and auth_info.get("anonymous_enabled", False):
        return "CRITICAL"
    
    return "MEDIUM"

def analyze_service_findings(service_vulns, service_type):
    """Analyze findings for a specific Firebase service"""
    if not service_vulns:
        return {"status": "SECURE", "vulnerabilities": 0, "riskLevel": "MINIMAL"}
    
    analysis = {
        "status": "VULNERABLE",
        "vulnerabilities": len(service_vulns),
        "riskLevel": "LOW",
        "issues": [],
        "exposedEndpoints": [],
        "dataAtRisk": []
    }
    
    critical_count = sum(1 for v in service_vulns if "CRITICAL" in v.get("details", ""))
    high_count = sum(1 for v in service_vulns if any(indicator in v.get("url", "") for indicator in ["/admin/", "/users/"]))
    
    if critical_count > 0:
        analysis["riskLevel"] = "CRITICAL"
        analysis["issues"].append(f"{critical_count} critical vulnerabilities found")
    elif high_count > 0:
        analysis["riskLevel"] = "HIGH"
        analysis["issues"].append(f"{high_count} high-impact endpoints exposed")
    else:
        analysis["riskLevel"] = "MEDIUM"
    
    # Extract specific exposed data
    for vuln in service_vulns:
        url = vuln.get("url", "")
        preview = vuln.get("preview", "")
        
        analysis["exposedEndpoints"].append(extract_endpoint_info(url))
        
        # Identify sensitive data in previews
        if preview and any(sensitive in preview.lower() for sensitive in ["user", "admin", "private", "secret"]):
            analysis["dataAtRisk"].append(extract_sensitive_data_summary(preview))
    
    return analysis

def extract_endpoint_info(url):
    """Extract meaningful endpoint information from URL"""
    if "/admin/" in url:
        return {"type": "admin", "sensitivity": "CRITICAL", "path": "/admin/"}
    elif "/users/" in url:
        return {"type": "user_data", "sensitivity": "HIGH", "path": "/users/"}
    elif "firestore" in url:
        return {"type": "database", "sensitivity": "MEDIUM", "path": "firestore_collections"}
    elif "storage" in url:
        return {"type": "file_storage", "sensitivity": "MEDIUM", "path": "storage_bucket"}
    else:
        return {"type": "unknown", "sensitivity": "LOW", "path": url}

def extract_sensitive_data_summary(preview):
    """Extract summary of sensitive data from response preview"""
    try:
        if preview.startswith("{"):
            data = json.loads(preview)
            if "superusers" in data:
                return "Admin user configuration"
            elif any(key.endswith("Id") for key in data.keys()):
                return "User identifiers"
        return "Structured data"
    except:
        return "Response data"

def enhance_vulnerability_details(vuln):
    """Add context and remediation to vulnerability entries"""
    enhanced = vuln.copy()
    
    # Add severity classification
    summary = FindingSummary()
    enhanced["severity"] = summary.classify_severity(vuln)
    
    # Add business impact description
    enhanced["businessImpact"] = describe_business_impact(vuln)
    
    # Add remediation steps
    enhanced["remediation"] = get_remediation_steps(vuln)
    
    return enhanced

def describe_business_impact(vuln):
    """Describe specific business impact of vulnerability"""
    service = vuln.get("service", "")
    details = vuln.get("details", "")
    url = vuln.get("url", "")
    
    if "Storage" in service and "write access" in details:
        return {
            "impact": "CRITICAL",
            "description": "Unrestricted file upload enables malware hosting and data pollution",
            "dataAtRisk": "Entire storage bucket integrity",
            "businessRisks": ["Brand reputation damage", "Legal liability", "Service disruption"]
        }
    elif "/admin/" in url:
        return {
            "impact": "CRITICAL", 
            "description": "Administrative data exposure enables privilege escalation",
            "dataAtRisk": "Administrative user identifiers and permissions",
            "businessRisks": ["Account takeover", "Data breach", "System compromise"]
        }
    elif "/users/" in url:
        return {
            "impact": "HIGH",
            "description": "User data exposure violates privacy expectations",
            "dataAtRisk": "User identifiers and potentially personal information", 
            "businessRisks": ["Privacy violations", "Regulatory fines", "User trust loss"]
        }
    else:
        return {
            "impact": "MEDIUM",
            "description": "Information disclosure may aid further attacks",
            "dataAtRisk": "System configuration and structure",
            "businessRisks": ["Attack surface mapping", "Social engineering"]
        }

def get_remediation_steps(vuln):
    """Generate specific remediation steps for vulnerability"""
    service = vuln.get("service", "")
    details = vuln.get("details", "")
    
    if "Storage" in service and "write access" in details:
        return {
            "priority": "IMMEDIATE",
            "timeframe": "24 hours",
            "steps": [
                "Update Firebase Storage security rules to require authentication",
                "Implement user-specific folder restrictions", 
                "Add file type and size validation",
                "Audit existing files for malicious content",
                "Enable virus scanning for uploads"
            ],
            "ruleExample": '''rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}'''
        }
    elif "Realtime DB" in service and "/admin/" in vuln.get("url", ""):
        return {
            "priority": "IMMEDIATE",
            "timeframe": "24 hours", 
            "steps": [
                "Update Realtime Database security rules to restrict admin access",
                "Implement role-based access controls",
                "Move admin functionality to Cloud Functions",
                "Audit existing admin data exposure"
            ],
            "ruleExample": '''{
  "rules": {
    "admin": {
      ".read": "auth != null && auth.token.admin === true",
      ".write": "auth != null && auth.token.admin === true"  
    }
  }
}'''
        }
    else:
        return {
            "priority": "HIGH",
            "timeframe": "1 week",
            "steps": [
                "Review and update security rules for affected service",
                "Implement proper authentication requirements",
                "Test security rules in development environment"
            ]
        }

def generate_remediation_recommendations(vulnerabilities, config):
    """Generate prioritized remediation recommendations"""
    recommendations = []
    
    # Group by service for targeted recommendations
    services_affected = set(v.get("service", "") for v in vulnerabilities)
    
    for service in services_affected:
        service_vulns = [v for v in vulnerabilities if v.get("service") == service]
        critical_vulns = [v for v in service_vulns if "CRITICAL" in v.get("details", "")]
        
        if critical_vulns:
            recommendations.append({
                "priority": "CRITICAL",
                "service": service,
                "affectedEndpoints": len(service_vulns),
                "criticalIssues": len(critical_vulns),
                "recommendation": get_service_specific_recommendation(service, critical_vulns),
                "estimatedFixTime": "4-8 hours",
                "businessJustification": "Prevents immediate data breach risk"
            })
    
    return sorted(recommendations, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["priority"], 3))

def get_service_specific_recommendation(service, vulnerabilities):
    """Get service-specific remediation recommendation"""
    if "Storage" in service:
        return "Implement comprehensive Storage security rules with user-based access controls"
    elif "Realtime DB" in service:
        return "Update Database security rules to require authentication and implement user-specific access"
    elif "Firestore" in service:
        return "Configure Firestore security rules to restrict collection access to authenticated users"
    else:
        return f"Review and secure {service} configuration"

# --- Enhanced Terminal Display Functions ---
def display_app_results_enhanced(app_name, bundle_id, summary, vulnerabilities):
    """Enhanced terminal display with clear severity indicators"""
    if not vulnerabilities:
        return
    
    # Group vulnerabilities by service
    service_groups = group_vulnerabilities_by_service(vulnerabilities)
    
    # Display app header with risk score
    risk_level = summary.get_risk_level()
    risk_color = RED if risk_level == "CRITICAL" else YELLOW if risk_level in ["HIGH", "MEDIUM"] else GREEN
    
    vprint("")
    vprint(f"{BOLD}🚨 {app_name}{RESET} ({bundle_id})", CYAN)
    vprint(f"   Risk Score: {risk_color}{summary.risk_score}/100 ({risk_level}){RESET}")
    
    # Display vulnerabilities by service
    for service, vulns in service_groups.items():
        critical_count = sum(1 for v in vulns if "CRITICAL" in v.get("details", ""))
        high_count = sum(1 for v in vulns if summary.classify_severity(v) == "HIGH")
        medium_count = sum(1 for v in vulns if summary.classify_severity(v) == "MEDIUM")
        
        if critical_count > 0:
            vprint(f"   {RED}🔥 {service}: {critical_count} CRITICAL{RESET}")
        if high_count > 0:
            vprint(f"   {YELLOW}⚠️  {service}: {high_count} HIGH{RESET}")
        if medium_count > 0:
            vprint(f"   {BLUE}ℹ️  {service}: {medium_count} MEDIUM{RESET}")
    
    # Show key exposed data
    exposed_data = extract_key_exposed_data(vulnerabilities)
    if exposed_data:
        vprint(f"   {YELLOW}📊 Exposed:{RESET} {', '.join(exposed_data)}")

def extract_key_exposed_data(vulnerabilities):
    """Extract key types of exposed data for summary display"""
    exposed = set()
    
    for vuln in vulnerabilities:
        url = vuln.get("url", "")
        preview = vuln.get("preview", "")
        
        if "/admin/" in url:
            exposed.add("Admin data")
        elif "/users/" in url:
            exposed.add("User data")
        elif "storage" in url.lower():
            exposed.add("File storage")
        elif "firestore" in url.lower():
            exposed.add("Database collections")
        
        # Check for specific sensitive data in previews
        if preview:
            if "superuser" in preview.lower():
                exposed.add("Admin privileges")
            elif any(pattern in preview.lower() for pattern in ["email", "phone", "address"]):
                exposed.add("PII data")
    
    return list(exposed)

def display_final_scan_summary(scan_index, scan_dir):
    """Display final scan summary with priorities"""
    
    vprint(f"\n{BOLD}=== FIREHOUND SCAN COMPLETE ==={RESET}", CYAN)
    
    # Summary statistics
    total_apps = len(scan_index.get("items", []))
    apps_with_findings = scan_index.get("withFindings", 0)
    failed_apps = scan_index.get("failed", 0)
    
    vprint(f"📱 Apps Scanned: {total_apps}")
    vprint(f"🔍 With Findings: {apps_with_findings}")
    vprint(f"❌ Failed: {failed_apps}")
    
    # Calculate critical apps from results
    critical_apps = 0
    high_risk_apps = []
    
    for item in scan_index.get("items", []):
        risk_score = item.get("riskScore", 0)
        if risk_score >= 80:
            critical_apps += 1
            high_risk_apps.append({
                "name": item.get("appName", item.get("bundleId", "")),
                "score": risk_score
            })
    
    if critical_apps > 0:
        vprint(f"{RED}🚨 Critical Issues: {critical_apps} apps need immediate attention{RESET}")
        
        # Show top 3 critical apps
        for app in sorted(high_risk_apps, key=lambda x: x["score"], reverse=True)[:3]:
            vprint(f"   {RED}• {app['name']}: {app['score']}/100{RESET}")
    
    # Show summary without dashboard generation
    if apps_with_findings > 0:
        vprint(f"\n{CYAN}📊 Scan analysis complete{RESET}")
        vprint(f"📁 Results saved to: {scan_dir}")
