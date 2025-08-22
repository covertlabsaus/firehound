#!/usr/bin/env python3
"""
MobSF API Integration for Firehound
Handles IPA uploads to MobSF and retrieves static analysis results
"""

import os
import time
import json
import requests
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import logging

class MobSFClient:
    """Client for MobSF REST API integration"""
    
    def __init__(self, server_url: str, api_key: str, timeout: int = 300):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': api_key,
            'User-Agent': 'Firehound-MobSF-Integration/1.0'
        })
        
    def upload_ipa(self, ipa_path: Path) -> Optional[Dict[str, Any]]:
        """Upload IPA file to MobSF and return upload response"""
        try:
            url = f"{self.server_url}/api/v1/upload"
            
            with open(ipa_path, 'rb') as f:
                files = {'file': (ipa_path.name, f, 'application/octet-stream')}
                response = self.session.post(url, files=files, timeout=60)
                
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"MobSF upload failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"MobSF upload exception: {e}")
            return None
    
    def start_scan(self, file_hash: str, scan_type: str = "ipa") -> Optional[Dict[str, Any]]:
        """Start static analysis scan for uploaded file"""
        try:
            url = f"{self.server_url}/api/v1/scan"
            data = {
                'hash': file_hash,
                'scan_type': scan_type,
                're_scan': 0
            }
            
            response = self.session.post(url, data=data, timeout=120)  # Increase timeout to 2 minutes
            
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"MobSF scan start failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"MobSF scan start exception: {e}")
            return None
    
    def get_report_pdf(self, file_hash: str) -> Optional[bytes]:
        """Download PDF report for completed scan"""
        try:
            url = f"{self.server_url}/api/v1/download_pdf"
            data = {'hash': file_hash}
            
            response = self.session.post(url, data=data, timeout=60)
            
            if response.status_code == 200:
                return response.content
            else:
                logging.error(f"MobSF PDF download failed: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"MobSF PDF download exception: {e}")
            return None
    
    def get_report_json(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get JSON report for completed scan"""
        try:
            url = f"{self.server_url}/api/v1/report_json"
            data = {'hash': file_hash}
            
            response = self.session.post(url, data=data, timeout=60)  # Increase timeout to 1 minute
            
            if response.status_code == 200:
                return response.json()
            else:
                logging.error(f"MobSF JSON report failed: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"MobSF JSON report exception: {e}")
            return None

def upload_and_scan_async_with_mobsf(ipa_path: Path, app_name: str, bundle_id: str, 
                                    server_url: str, api_key: str, timeout: int = 60) -> Optional[Dict[str, Any]]:
    """
    Async workflow: Upload IPA to MobSF, start scan, return immediately
    Returns basic scan info for tracking, or None if failed
    """
    client = MobSFClient(server_url, api_key, timeout)
    
    logging.info(f"MobSF: Starting upload for {app_name} ({bundle_id})")
    
    # Step 1: Upload IPA
    upload_result = client.upload_ipa(ipa_path)
    if not upload_result:
        return None
    
    file_hash = upload_result.get('hash')
    if not file_hash:
        logging.error("MobSF: No file hash in upload response")
        return None
    
    logging.info(f"MobSF: Upload successful, hash: {file_hash}")
    
    # Step 2: Start scan (non-blocking)
    scan_result = client.start_scan(file_hash)
    if not scan_result:
        return None
    
    logging.info("MobSF: Scan started successfully - continuing with Firebase analysis")
    
    # Return scan tracking info immediately (don't wait for completion)
    return {
        'status': 'scan_initiated',
        'file_hash': file_hash,
        'app_name': app_name,
        'bundle_id': bundle_id,
        'scan_url': f"{server_url}/recent_scans/",
        'view_url': f"{server_url}/view_source/{file_hash}/",
        'started_at': upload_result.get('timestamp', 'unknown')
    }

def upload_and_scan_with_mobsf(ipa_path: Path, app_name: str, bundle_id: str, 
                               server_url: str, api_key: str, timeout: int = 300) -> Optional[Dict[str, Any]]:
    """
    Complete workflow: Upload IPA to MobSF, scan, and return results
    Returns combined metadata and scan results, or None if failed
    """
    client = MobSFClient(server_url, api_key, timeout)
    
    logging.info(f"MobSF: Starting upload for {app_name} ({bundle_id})")
    
    # Step 1: Upload IPA
    upload_result = client.upload_ipa(ipa_path)
    if not upload_result:
        return None
    
    file_hash = upload_result.get('hash')
    if not file_hash:
        logging.error("MobSF: No file hash in upload response")
        return None
    
    logging.info(f"MobSF: Upload successful, hash: {file_hash}")
    
    # Step 2: Start scan
    scan_result = client.start_scan(file_hash)
    if not scan_result:
        return None
    
    logging.info("MobSF: Scan started successfully")
    
    # Step 3: Wait for scan completion and get results
    # MobSF scan is synchronous, so we should have results immediately
    json_report = client.get_report_json(file_hash)
    if not json_report:
        logging.error("MobSF: Failed to retrieve scan results")
        return None
    
    # Step 4: Optionally download PDF report
    pdf_report = client.get_report_pdf(file_hash)
    
    # Extract key findings for integration with Firehound report
    mobsf_summary = extract_mobsf_summary(json_report)
    
    return {
        'upload_success': True,
        'file_hash': file_hash,
        'app_name': app_name,
        'bundle_id': bundle_id,
        'summary': mobsf_summary,
        'full_report': json_report,
        'pdf_available': pdf_report is not None,
        'mobsf_server': server_url
    }

def extract_mobsf_summary(json_report: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key findings from MobSF JSON report for Firehound integration"""
    try:
        summary = {
            'security_score': json_report.get('security_score', 0),
            'total_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'info_issues': 0,
            'key_findings': []
        }
        
        # Extract issue counts
        findings = json_report.get('findings', {})
        for category, issues in findings.items():
            if isinstance(issues, list):
                summary['total_issues'] += len(issues)
                
                for issue in issues:
                    severity = issue.get('severity', '').lower()
                    if severity == 'high':
                        summary['high_issues'] += 1
                    elif severity == 'medium':
                        summary['medium_issues'] += 1
                    elif severity == 'low':
                        summary['low_issues'] += 1
                    else:
                        summary['info_issues'] += 1
                    
                    # Collect high-priority findings
                    if severity in ['high', 'medium']:
                        summary['key_findings'].append({
                            'category': category,
                            'title': issue.get('title', 'Unknown Issue'),
                            'severity': severity,
                            'description': issue.get('description', '')
                        })
        
        # Limit key findings to most important ones
        summary['key_findings'] = summary['key_findings'][:10]
        
        return summary
        
    except Exception as e:
        logging.error(f"Failed to extract MobSF summary: {e}")
        return {'error': str(e)}

def get_mobsf_config() -> Tuple[Optional[str], Optional[str]]:
    """Get MobSF server URL and API key from environment variables"""
    server_url = os.environ.get('MOBSF_SERVER_URL', 'https://scan.covertlabs.io')
    api_key = os.environ.get('MOBSF_API_KEY')
    
    return server_url, api_key

def is_mobsf_available(server_url: str, api_key: str) -> bool:
    """Check if MobSF server is available and API key is valid"""
    try:
        client = MobSFClient(server_url, api_key)
        # Try a simple API call to check connectivity
        response = client.session.get(f"{server_url}/api/v1/scans", timeout=10)
        return response.status_code in [200, 401]  # 401 means server is up but auth issue
    except Exception:
        return False
