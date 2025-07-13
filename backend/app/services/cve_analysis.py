"""
CVE Analysis Service for Security Management Platform
Integrates with NVD feed and provides LLM-driven analysis
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import aiohttp
import requests
from ..core.config import settings
from ..core.database import get_db
from ..core.logging import log_vulnerability_event, get_logger
from .llm_service import get_llm_service

logger = get_logger(__name__)


class CVEAnalysisService:
    """Service for CVE analysis and management"""
    
    def __init__(self):
        self.db = get_db()
        self.llm_service = get_llm_service()
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = None
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            headers = {}
            if settings.NVD_API_KEY:
                headers["apiKey"] = settings.NVD_API_KEY
            
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self.session
    
    async def fetch_nvd_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch CVE data from NVD API"""
        try:
            session = await self.get_session()
            url = f"{self.nvd_base_url}?cveId={cve_id}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("vulnerabilities"):
                        return data["vulnerabilities"][0]["cve"]
                    
            logger.warning(f"CVE not found in NVD: {cve_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error fetching CVE from NVD: {e}")
            return None
    
    async def fetch_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """Fetch recent CVEs from NVD"""
        try:
            session = await self.get_session()
            
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            url = f"{self.nvd_base_url}?pubStartDate={start_date.strftime('%Y-%m-%dT%H:%M:%S.000')}&pubEndDate={end_date.strftime('%Y-%m-%dT%H:%M:%S.000')}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return [vuln["cve"] for vuln in data.get("vulnerabilities", [])]
                    
            logger.warning(f"Failed to fetch recent CVEs: {response.status}")
            return []
            
        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {e}")
            return []
    
    def parse_nvd_cve(self, nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse NVD CVE data into our format"""
        try:
            cve_id = nvd_data.get("id", "")
            
            # Extract basic information
            descriptions = nvd_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS scores
            cvss_score = 0.0
            severity = "Unknown"
            
            metrics = nvd_data.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "Unknown")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "Unknown")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore", 0.0)
                # Map V2 score to severity
                if cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            # Extract affected products
            affected_products = []
            configurations = nvd_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable", False):
                            cpe_uri = cpe_match.get("criteria", "")
                            if cpe_uri:
                                # Parse CPE URI to extract product info
                                parts = cpe_uri.split(":")
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 else "*"
                                    affected_products.append(f"{vendor} {product} {version}")
            
            # Extract references
            references = []
            for ref in nvd_data.get("references", []):
                references.append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source", ""),
                    "tags": ref.get("tags", [])
                })
            
            # Extract CWE information
            cwe_id = ""
            weaknesses = nvd_data.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_id = desc.get("value", "")
                        break
                if cwe_id:
                    break
            
            return {
                "id": cve_id,
                "title": f"CVE {cve_id}",
                "description": description,
                "severity": severity.title(),
                "cvss_score": cvss_score,
                "published_date": nvd_data.get("published", ""),
                "last_updated": nvd_data.get("lastModified", ""),
                "nvd_status": nvd_data.get("vulnStatus", "Unknown"),
                "cwe_id": cwe_id,
                "affected_products": affected_products,
                "references": references,
                "exploit_available": False,  # Will be determined by threat intelligence
                "patch_available": False,    # Will be determined by analysis
                "source": "NVD",
                "raw_nvd_data": nvd_data
            }
            
        except Exception as e:
            logger.error(f"Error parsing NVD CVE data: {e}")
            return {}
    
    async def analyze_cve_with_llm(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze CVE using LLM for enhanced insights"""
        try:
            # Get LLM analysis
            llm_analysis = await self.llm_service.analyze_cve(cve_data)
            
            # Update CVE data with LLM insights
            structured_analysis = llm_analysis.get("structured_analysis", {})
            
            enhanced_cve = cve_data.copy()
            enhanced_cve.update({
                "llm_summary": llm_analysis.get("llm_analysis", ""),
                "exploit_method": structured_analysis.get("exploit_method", ""),
                "business_impact": structured_analysis.get("business_impact", ""),
                "layman_explanation": structured_analysis.get("layman_explanation", ""),
                "remediation_steps": structured_analysis.get("remediation_steps", "").split("\n"),
                "confidence_score": llm_analysis.get("confidence_score", 0.0),
                "llm_analysis_timestamp": datetime.now().isoformat()
            })
            
            return enhanced_cve
            
        except Exception as e:
            logger.error(f"Error analyzing CVE with LLM: {e}")
            return cve_data
    
    async def enrich_with_threat_intelligence(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich CVE data with threat intelligence"""
        try:
            # Simulate threat intelligence enrichment
            # In a real implementation, this would query threat intelligence feeds
            
            enriched_cve = cve_data.copy()
            
            # Simulate exploit availability check
            # High severity CVEs are more likely to have exploits
            cvss_score = cve_data.get("cvss_score", 0.0)
            if cvss_score >= 7.0:
                enriched_cve["exploit_available"] = True
                enriched_cve["exploit_complexity"] = "Low" if cvss_score >= 9.0 else "Medium"
                enriched_cve["exploit_maturity"] = "Proof of Concept"
            else:
                enriched_cve["exploit_available"] = False
                enriched_cve["exploit_complexity"] = "High"
                enriched_cve["exploit_maturity"] = "Not Available"
            
            # Simulate affected assets count
            import random
            enriched_cve["affected_assets"] = random.randint(1, 100)
            
            # Add threat intelligence data
            enriched_cve["threat_intelligence"] = {
                "exploit_in_wild": cvss_score >= 8.0,
                "first_seen_exploit": datetime.now().isoformat() if cvss_score >= 8.0 else None,
                "attack_vectors": self._get_attack_vectors(cve_data),
                "targeted_sectors": ["Technology", "Finance", "Healthcare"],
                "ioc_indicators": []
            }
            
            return enriched_cve
            
        except Exception as e:
            logger.error(f"Error enriching CVE with threat intelligence: {e}")
            return cve_data
    
    def _get_attack_vectors(self, cve_data: Dict[str, Any]) -> List[str]:
        """Determine attack vectors based on CVE description"""
        description = cve_data.get("description", "").lower()
        vectors = []
        
        if "remote" in description or "network" in description:
            vectors.append("Network")
        if "local" in description:
            vectors.append("Local")
        if "web" in description or "http" in description:
            vectors.append("Web Application")
        if "email" in description or "phishing" in description:
            vectors.append("Email")
        if "physical" in description:
            vectors.append("Physical")
        
        return vectors or ["Unknown"]
    
    async def fetch_vulnerable_server_cves(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from vulnerable server and convert to CVE format"""
        try:
            session = await self.get_session()
            
            # Fetch vulnerabilities from vulnerable server
            async with session.get("http://localhost:5000/api/vulnerabilities") as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    # Convert vulnerability events to CVE format
                    cves = []
                    for vuln in vulnerabilities:
                        if vuln.get("exploit_success") and vuln.get("cve_id"):
                            cve = {
                                "id": vuln["cve_id"],
                                "title": f"{vuln['event_type']} - {vuln['description']}",
                                "description": vuln["description"],
                                "severity": vuln["severity"],
                                "cvss_score": {
                                    "Critical": 9.5,
                                    "High": 7.8,
                                    "Medium": 5.5,
                                    "Low": 2.3
                                }.get(vuln["severity"], 5.0),
                                "published_date": vuln["created_at"],
                                "last_updated": vuln["created_at"],
                                "nvd_status": "Published",  # Added required field
                                "cwe_id": self._get_cwe_id_from_event_type(vuln["event_type"]),  # Added required field
                                "exploit_available": True,
                                "patch_available": False,
                                "affected_products": ["Vulnerable Server 1.0"],
                                "source": "vulnerable-server",
                                "payload": vuln.get("payload", ""),
                                "source_ip": vuln.get("source_ip", ""),
                                "user_agent": vuln.get("user_agent", ""),
                                "affected_assets": 1,
                                "remediation_steps": [
                                    "Apply input validation",
                                    "Implement proper authentication", 
                                    "Update security configurations",
                                    "Configure web application firewall"
                                ]
                            }
                            cves.append(cve)
                    
                    return cves
                    
            # Fetch threats from vulnerable server
            async with session.get("http://localhost:5000/api/threats") as response:
                if response.status == 200:
                    data = await response.json()
                    threats = data.get("active_threats", [])
                    
                    threat_cves = []
                    for threat in threats:
                        if threat.get("is_active"):
                            cve = {
                                "id": f"CVE-2024-{threat['threat_id'][:4]}",
                                "title": f"{threat['threat_type']} Vulnerability in Vulnerable Server",
                                "description": threat["description"],
                                "severity": threat["severity"],
                                "cvss_score": {
                                    "Critical": 9.2,
                                    "High": 7.5,
                                    "Medium": 5.8,
                                    "Low": 3.1
                                }.get(threat["severity"], 5.0),
                                "published_date": threat["created_at"],
                                "last_updated": threat["last_seen"],
                                "nvd_status": "Published",  # Added required field
                                "cwe_id": self._get_cwe_id_from_threat_type(threat["threat_type"]),  # Added required field
                                "exploit_available": True,
                                "patch_available": False,
                                "affected_products": ["Vulnerable Server 1.0"],
                                "source": "vulnerable-server-threats",
                                "payload": threat.get("payload", ""),
                                "target_endpoint": threat.get("target_endpoint", ""),
                                "affected_assets": 1,
                                "threat_intelligence": {
                                    "exploit_in_wild": True,
                                    "attack_vectors": ["Network", "Application"],
                                    "detection_count": threat.get("detection_count", 1)
                                }
                            }
                            threat_cves.append(cve)
                    
                    return threat_cves
                    
            return []
            
        except Exception as e:
            logger.error(f"Error fetching vulnerable server CVEs: {e}")
            return []

    def _get_cwe_id_from_event_type(self, event_type: str) -> str:
        """Map event type to CWE ID"""
        cwe_mapping = {
            "SQL_INJECTION_ATTEMPT": "CWE-89",
            "XSS_ATTEMPT": "CWE-79", 
            "COMMAND_INJECTION_ATTEMPT": "CWE-78",
            "INFO_DISCLOSURE": "CWE-200",
            "INFO_DISCLOSURE_ATTEMPT": "CWE-200",
            "FILE_INCLUSION": "CWE-98",
            "PATH_TRAVERSAL": "CWE-22",
            "BUFFER_OVERFLOW": "CWE-120",
            "CSRF_ATTEMPT": "CWE-352",
            "AUTHENTICATION_BYPASS": "CWE-287"
        }
        return cwe_mapping.get(event_type, "CWE-20")  # Default to Input Validation
    
    def _get_cwe_id_from_threat_type(self, threat_type: str) -> str:
        """Map threat type to CWE ID"""
        cwe_mapping = {
            "SQL_INJECTION": "CWE-89",
            "XSS": "CWE-79",
            "COMMAND_INJECTION": "CWE-78", 
            "DIRECTORY_TRAVERSAL": "CWE-22",
            "FILE_UPLOAD": "CWE-434",
            "AUTHENTICATION_BYPASS": "CWE-287",
            "PRIVILEGE_ESCALATION": "CWE-269",
            "INFORMATION_DISCLOSURE": "CWE-200"
        }
        return cwe_mapping.get(threat_type, "CWE-20")  # Default to Input Validation
    
    async def get_github_advisories(self, cve_id: str) -> List[Dict[str, Any]]:
        """Fetch GitHub security advisories for CVE"""
        try:
            if not settings.GITHUB_TOKEN:
                logger.warning("GitHub token not configured")
                return []
            
            # GitHub GraphQL API query for security advisories
            query = """
            query($cve_id: String!) {
                securityAdvisories(first: 10, identifier: {type: CVE, value: $cve_id}) {
                    nodes {
                        ghsaId
                        summary
                        description
                        severity
                        publishedAt
                        updatedAt
                        references {
                            url
                        }
                        vulnerabilities(first: 10) {
                            nodes {
                                package {
                                    name
                                    ecosystem
                                }
                                vulnerableVersionRange
                                firstPatchedVersion {
                                    identifier
                                }
                            }
                        }
                    }
                }
            }
            """
            
            headers = {
                "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
                "Content-Type": "application/json"
            }
            
            session = await self.get_session()
            async with session.post(
                "https://api.github.com/graphql",
                json={"query": query, "variables": {"cve_id": cve_id}},
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
                    
            logger.warning(f"Failed to fetch GitHub advisories: {response.status}")
            return []
            
        except Exception as e:
            logger.error(f"Error fetching GitHub advisories: {e}")
            return []
    
    async def create_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new CVE record"""
        try:
            # Analyze with LLM
            enhanced_cve = await self.analyze_cve_with_llm(cve_data)
            
            # Enrich with threat intelligence
            enriched_cve = await self.enrich_with_threat_intelligence(enhanced_cve)
            
            # Get GitHub advisories
            github_advisories = await self.get_github_advisories(enriched_cve.get("id", ""))
            enriched_cve["github_references"] = github_advisories
            
            # Store in database
            created_cve = self.db.create("cves", enriched_cve)
            
            # Log the event
            log_vulnerability_event(
                cve_id=created_cve.get("id", ""),
                action="created",
                details={"severity": created_cve.get("severity"), "source": "manual"}
            )
            
            return created_cve
            
        except Exception as e:
            logger.error(f"Error creating CVE: {e}")
            raise
    
    async def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE by ID"""
        try:
            # First check local database
            cve = self.db.get_by_id("cves", cve_id)
            if cve:
                return cve
            
            # If not found locally, try to fetch from NVD
            nvd_data = await self.fetch_nvd_cve(cve_id)
            if nvd_data:
                parsed_cve = self.parse_nvd_cve(nvd_data)
                if parsed_cve:
                    # Store and return the fetched CVE
                    return await self.create_cve(parsed_cve)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting CVE {cve_id}: {e}")
            return None
    
    async def get_all_cves(self) -> List[Dict[str, Any]]:
        """Get all CVEs from database"""
        try:
            # Get CVEs from local database only
            cves = self.db.get_all("cves")
            return cves
            
        except Exception as e:
            logger.error(f"Error getting all CVEs: {e}")
            return []
    
    async def sync_recent_cves(self, days: int = 7) -> int:
        """Sync recent CVEs from NVD"""
        try:
            logger.info(f"Syncing recent CVEs from last {days} days")
            
            # Fetch recent CVEs from NVD
            recent_nvd_cves = await self.fetch_recent_cves(days)
            
            synced_count = 0
            for nvd_cve in recent_nvd_cves[:20]:  # Limit to 20 to avoid overwhelming
                try:
                    cve_id = nvd_cve.get("id", "")
                    
                    # Check if already exists
                    existing = self.db.get_by_id("cves", cve_id)
                    if existing:
                        continue
                    
                    # Parse and create CVE
                    parsed_cve = self.parse_nvd_cve(nvd_cve)
                    if parsed_cve:
                        await self.create_cve(parsed_cve)
                        synced_count += 1
                        
                        # Add small delay to avoid overwhelming the LLM
                        await asyncio.sleep(0.5)
                        
                except Exception as e:
                    logger.error(f"Error processing CVE during sync: {e}")
                    continue
            
            logger.info(f"Synced {synced_count} CVEs from NVD")
            return synced_count
            
        except Exception as e:
            logger.error(f"Error syncing recent CVEs: {e}")
            return 0
    
    async def search_cves(self, query: str) -> List[Dict[str, Any]]:
        """Search CVEs by query"""
        try:
            return self.db.search("cves", query, ["id", "title", "description", "affected_products"])
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
    
    async def get_cve_trends(self) -> Dict[str, Any]:
        """Get CVE trends and statistics"""
        try:
            all_cves = self.db.get_all("cves")
            
            # Calculate trends
            total_cves = len(all_cves)
            
            # Severity distribution
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for cve in all_cves:
                severity = cve.get("severity", "Unknown")
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Recent activity (last 30 days)
            recent_date = datetime.now() - timedelta(days=30)
            recent_cves = [
                cve for cve in all_cves
                if cve.get("created_at", "") >= recent_date.isoformat()
            ]
            
            # Top affected products
            product_counts = {}
            for cve in all_cves:
                for product in cve.get("affected_products", []):
                    product_counts[product] = product_counts.get(product, 0) + 1
            
            top_products = sorted(product_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                "total_cves": total_cves,
                "severity_distribution": severity_counts,
                "recent_activity": {
                    "last_30_days": len(recent_cves),
                    "daily_average": len(recent_cves) / 30
                },
                "top_affected_products": [{"product": p, "count": c} for p, c in top_products],
                "exploit_statistics": {
                    "with_exploits": len([cve for cve in all_cves if cve.get("exploit_available", False)]),
                    "in_wild": len([cve for cve in all_cves if cve.get("threat_intelligence", {}).get("exploit_in_wild", False)])
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting CVE trends: {e}")
            return {}
    
    async def close(self):
        """Close the service and cleanup resources"""
        if self.session and not self.session.closed:
            await self.session.close()


# Global service instance
cve_service = CVEAnalysisService()


def get_cve_service() -> CVEAnalysisService:
    """Get CVE analysis service instance"""
    return cve_service 