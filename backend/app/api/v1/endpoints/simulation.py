"""
Simulation API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel
from ....core.database import get_db
import random
import uuid

router = APIRouter()
db = get_db()


class SimulationRequest(BaseModel):
    count: int = 5
    severity: str = None
    target: str = None


@router.post("/cve")
async def generate_simulated_cve(request: SimulationRequest):
    """Generate simulated CVE data"""
    try:
        severities = ["Critical", "High", "Medium", "Low"]
        
        cve_data = {
            "id": f"CVE-2024-{random.randint(1000, 9999)}",
            "title": f"Simulated Vulnerability {uuid.uuid4().hex[:8]}",
            "description": "This is a simulated vulnerability for testing purposes",
            "severity": request.severity or random.choice(severities),
            "cvss_score": round(random.uniform(1.0, 10.0), 1),
            "published_date": "2024-01-15T10:30:00Z",
            "affected_products": ["Test Product 1.0", "Test Service 2.1"],
            "exploit_available": random.choice([True, False]),
            "patch_available": random.choice([True, False]),
            "source": "simulation"
        }
        
        # Store in database
        db.create("cves", cve_data)
        
        # Also store as vulnerability
        vuln_data = {
            "id": cve_data["id"],
            "title": cve_data["title"],
            "description": cve_data["description"],
            "severity": cve_data["severity"].lower(),
            "cvss_score": str(cve_data["cvss_score"]),
            "published_date": cve_data["published_date"],
            "affected_products": cve_data["affected_products"],
            "exploit_available": cve_data["exploit_available"],
            "patch_available": cve_data["patch_available"],
            "source": "simulation"
        }
        db.create("vulnerabilities", vuln_data)
        
        return cve_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def simulate_vulnerability_scan(scan_config: Dict[str, Any]):
    """Simulate vulnerability scan"""
    try:
        # Generate simulated scan results
        vulnerabilities = []
        for i in range(random.randint(1, 10)):
            vuln = {
                "id": f"VULN-{uuid.uuid4().hex[:8]}",
                "title": f"Simulated Vulnerability {i+1}",
                "severity": random.choice(["Critical", "High", "Medium", "Low"]),
                "cvss_score": round(random.uniform(1.0, 10.0), 1),
                "description": f"Simulated vulnerability description {i+1}",
                "affected_assets": [scan_config.get("target", "localhost")],
                "remediation": "Apply security patches"
            }
            vulnerabilities.append(vuln)
            
            # Store in database
            db.create("vulnerabilities", vuln)
        
        scan_result = {
            "scan_id": str(uuid.uuid4()),
            "target": scan_config.get("target", "localhost"),
            "status": "completed",
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "critical_count": len([v for v in vulnerabilities if v["severity"] == "Critical"]),
                "high_count": len([v for v in vulnerabilities if v["severity"] == "High"]),
                "medium_count": len([v for v in vulnerabilities if v["severity"] == "Medium"]),
                "low_count": len([v for v in vulnerabilities if v["severity"] == "Low"])
            }
        }
        
        return scan_result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat")
async def generate_threat_intelligence(config: Dict[str, Any]):
    """Generate simulated threat intelligence"""
    try:
        threat_data = {
            "id": str(uuid.uuid4()),
            "threat_type": config.get("threat_type", "malware"),
            "indicators": [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "domain", "value": "malicious.example.com"},
                {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"}
            ],
            "severity": random.choice(["Critical", "High", "Medium", "Low"]),
            "confidence": random.randint(60, 100),
            "description": "Simulated threat intelligence data"
        }
        
        return threat_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/exploit")
async def generate_exploit_data(config: Dict[str, Any]):
    """Generate simulated exploit data"""
    try:
        exploit_data = {
            "id": str(uuid.uuid4()),
            "cve_id": config.get("cve_id", f"CVE-2024-{random.randint(1000, 9999)}"),
            "exploit_type": random.choice(["remote", "local", "web"]),
            "complexity": random.choice(["low", "medium", "high"]),
            "availability": random.choice(["public", "private", "none"]),
            "maturity": random.choice(["proof_of_concept", "functional", "weaponized"]),
            "description": "Simulated exploit information"
        }
        
        return exploit_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/github-advisory")
async def generate_github_advisory(config: Dict[str, Any]):
    """Generate simulated GitHub security advisory"""
    try:
        advisory_data = {
            "ghsa_id": f"GHSA-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}",
            "summary": "Simulated GitHub Security Advisory",
            "description": "This is a simulated security advisory for testing purposes",
            "severity": random.choice(["Critical", "High", "Medium", "Low"]),
            "published_at": "2024-01-15T10:30:00Z",
            "updated_at": "2024-01-15T10:30:00Z",
            "references": [
                {"url": "https://github.com/example/repo/security/advisories/GHSA-xxxx-xxxx-xxxx"}
            ],
            "vulnerabilities": [
                {
                    "package": {"name": "example-package", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 1.2.3",
                    "first_patched_version": {"identifier": "1.2.3"}
                }
            ]
        }
        
        return advisory_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 