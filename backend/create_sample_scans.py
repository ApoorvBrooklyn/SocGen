#!/usr/bin/env python3
"""
Script to create sample scan data for the Dashboard
"""
import asyncio
import json
from datetime import datetime, timedelta
from app.core.database import get_db

def create_sample_scans():
    """Create sample scan data"""
    db = get_db()
    
    # Sample scan data
    sample_scans = [
        {
            "id": "scan_001",
            "target": "192.168.1.100",
            "scanner_type": "nmap",
            "scan_type": "comprehensive",
            "status": "completed",
            "start_time": (datetime.now() - timedelta(hours=2)).isoformat(),
            "end_time": (datetime.now() - timedelta(hours=1)).isoformat(),
            "progress": 100,
            "vulnerabilities": [
                {"id": "vuln_001", "severity": "High", "title": "Open SSH Port", "description": "SSH port 22 is open"},
                {"id": "vuln_002", "severity": "Medium", "title": "Weak SSL Configuration", "description": "SSL/TLS configuration needs improvement"}
            ],
            "summary": {
                "total_vulnerabilities": 2,
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0
            }
        },
        {
            "id": "scan_002",
            "target": "10.0.0.50",
            "scanner_type": "openvas",
            "scan_type": "quick",
            "status": "running",
            "start_time": (datetime.now() - timedelta(minutes=30)).isoformat(),
            "end_time": None,
            "progress": 65,
            "vulnerabilities": [
                {"id": "vuln_003", "severity": "Critical", "title": "SQL Injection", "description": "SQL injection vulnerability detected"}
            ],
            "summary": {
                "total_vulnerabilities": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        },
        {
            "id": "scan_003",
            "target": "172.16.0.25",
            "scanner_type": "nessus",
            "scan_type": "comprehensive",
            "status": "completed",
            "start_time": (datetime.now() - timedelta(days=1)).isoformat(),
            "end_time": (datetime.now() - timedelta(hours=23)).isoformat(),
            "progress": 100,
            "vulnerabilities": [
                {"id": "vuln_004", "severity": "Low", "title": "Information Disclosure", "description": "Server version information exposed"},
                {"id": "vuln_005", "severity": "Medium", "title": "Default Credentials", "description": "Default admin credentials detected"}
            ],
            "summary": {
                "total_vulnerabilities": 2,
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 1
            }
        }
    ]
    
    # Add scans to database
    for scan in sample_scans:
        db.create("scan_results", scan)
        print(f"Created scan: {scan['id']} - {scan['target']} ({scan['status']})")
    
    print(f"Created {len(sample_scans)} sample scans")

if __name__ == "__main__":
    create_sample_scans() 