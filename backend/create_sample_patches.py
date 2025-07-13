#!/usr/bin/env python3
"""
Script to create sample patch data for the Dashboard
"""
import asyncio
import json
import time
from datetime import datetime, timedelta
from app.core.database import get_db

def create_sample_patches():
    """Create sample patch data"""
    db = get_db()
    
    # Sample patch data
    sample_patches = [
        {
            "id": "patch_001",
            "cve_id": "CVE-2025-7079",
            "os_type": "Ubuntu",
            "status": "pending",
            "recommendations": "Apply security patch for JWT token handler vulnerability",
            "patch_commands": [
                "sudo apt update",
                "sudo apt install --only-upgrade bluebell-plus",
                "sudo systemctl restart bluebell-service"
            ],
            "manual_steps": [
                "1. Update bluebell-plus package",
                "2. Restart affected services",
                "3. Verify JWT token functionality",
                "4. Test authentication flow"
            ],
            "timestamp": time.time(),
            "priority": "high",
            "estimated_downtime": "5 minutes"
        },
        {
            "id": "patch_002",
            "cve_id": "CVE-2025-7080",
            "os_type": "CentOS",
            "status": "completed",
            "recommendations": "Update SSL/TLS configuration to fix weak cipher suites",
            "patch_commands": [
                "sudo yum update openssl",
                "sudo yum update nginx",
                "sudo systemctl reload nginx"
            ],
            "manual_steps": [
                "1. Update OpenSSL package",
                "2. Configure strong cipher suites",
                "3. Test SSL/TLS connections",
                "4. Verify security headers"
            ],
            "timestamp": time.time() - 3600,  # 1 hour ago
            "priority": "medium",
            "estimated_downtime": "2 minutes",
            "deployed_at": (datetime.now() - timedelta(hours=1)).isoformat()
        },
        {
            "id": "patch_003",
            "cve_id": "CVE-2025-7081",
            "os_type": "Debian",
            "status": "in_progress",
            "recommendations": "Fix SQL injection vulnerability in web application",
            "patch_commands": [
                "sudo apt update",
                "sudo apt install --only-upgrade webapp-package",
                "sudo systemctl restart webapp"
            ],
            "manual_steps": [
                "1. Update web application package",
                "2. Apply database schema changes",
                "3. Test database queries",
                "4. Verify application functionality"
            ],
            "timestamp": time.time() - 1800,  # 30 minutes ago
            "priority": "critical",
            "estimated_downtime": "10 minutes",
            "started_at": (datetime.now() - timedelta(minutes=30)).isoformat()
        }
    ]
    
    # Add patches to database
    for patch in sample_patches:
        db.create("patch_recommendations", patch)
        print(f"Created patch: {patch['id']} - {patch['cve_id']} ({patch['status']})")
    
    print(f"Created {len(sample_patches)} sample patches")

if __name__ == "__main__":
    create_sample_patches() 