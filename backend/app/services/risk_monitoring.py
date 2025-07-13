"""
Risk Monitoring Service for automatic priority recalculation
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests
from ..core.database import get_db
from .llm_service import get_llm_service

logger = logging.getLogger(__name__)

class RiskMonitoringService:
    """Service for monitoring risk changes and automatically triggering recalculation"""
    
    def __init__(self):
        self.db = get_db()
        self.llm_service = get_llm_service()
        self.vulnerable_server_url = "http://localhost:5000"
        self.last_assessment_time = None
        self.last_vulnerability_count = 0
        self.last_threat_count = 0
        self.running = False
        
    async def start_monitoring(self, interval_seconds: int = 30):
        """Start continuous monitoring for risk changes"""
        self.running = True
        logger.info(f"Starting risk monitoring service with {interval_seconds}s interval")
        
        while self.running:
            try:
                await self.check_for_risk_changes()
                await asyncio.sleep(interval_seconds)
            except Exception as e:
                logger.error(f"Error in risk monitoring loop: {str(e)}")
                await asyncio.sleep(interval_seconds)
    
    def stop_monitoring(self):
        """Stop the monitoring service"""
        self.running = False
        logger.info("Risk monitoring service stopped")
    
    async def check_for_risk_changes(self) -> bool:
        """Check for significant risk changes and trigger recalculation if needed"""
        try:
            # Get current vulnerability and threat data
            current_data = await self.get_current_risk_data()
            
            if not current_data:
                return False
            
            # Check if recalculation is needed
            should_recalculate = await self.should_trigger_recalculation(current_data)
            
            if should_recalculate:
                logger.info("Triggering automatic priority recalculation due to risk changes")
                await self.trigger_priority_recalculation(current_data)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking for risk changes: {str(e)}")
            return False
    
    async def get_current_risk_data(self) -> Optional[Dict[str, Any]]:
        """Get current vulnerability and threat data"""
        try:
            # Fetch from vulnerable server
            vuln_response = requests.get(f"{self.vulnerable_server_url}/api/vulnerabilities", timeout=10)
            threats_response = requests.get(f"{self.vulnerable_server_url}/api/threats", timeout=10)
            
            vulnerabilities = []
            threats = []
            
            if vuln_response.status_code == 200:
                vuln_data = vuln_response.json()
                vulnerabilities = vuln_data.get("vulnerabilities", [])
            
            if threats_response.status_code == 200:
                threats_data = threats_response.json()
                threats = threats_data.get("active_threats", [])
            
            # Also get stored data
            stored_vulnerabilities = self.db.get_all("vulnerabilities")
            stored_threats = self.db.get_all("threats") if "threats" in self.db.collections else []
            
            return {
                "live_vulnerabilities": vulnerabilities,
                "live_threats": threats,
                "stored_vulnerabilities": stored_vulnerabilities,
                "stored_threats": stored_threats,
                "total_vulnerabilities": len(vulnerabilities) + len(stored_vulnerabilities),
                "total_threats": len(threats) + len(stored_threats),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching current risk data: {str(e)}")
            return None
    
    async def should_trigger_recalculation(self, current_data: Dict[str, Any]) -> bool:
        """Determine if priority recalculation should be triggered"""
        try:
            # Get the last assessment
            last_assessment = self.get_last_assessment()
            
            # Always recalculate if no previous assessment
            if not last_assessment:
                return True
            
            # Check time-based triggers
            if self.last_assessment_time:
                time_since_last = datetime.now() - datetime.fromisoformat(self.last_assessment_time)
                if time_since_last > timedelta(minutes=10):  # Force recalculation every 10 minutes
                    return True
            
            # Check for significant changes
            current_vuln_count = current_data["total_vulnerabilities"]
            current_threat_count = current_data["total_threats"]
            
            # Trigger if vulnerability count changed by more than 5% (more sensitive)
            if self.last_vulnerability_count > 0:
                vuln_change_ratio = abs(current_vuln_count - self.last_vulnerability_count) / self.last_vulnerability_count
                if vuln_change_ratio > 0.05:
                    logger.info(f"Vulnerability count changed significantly: {self.last_vulnerability_count} -> {current_vuln_count}")
                    return True
            
            # Also trigger on any new vulnerabilities (even 1)
            if current_vuln_count > self.last_vulnerability_count:
                logger.info(f"New vulnerabilities detected: {current_vuln_count - self.last_vulnerability_count}")
                return True
            
            # Trigger if threat count changed
            if current_threat_count != self.last_threat_count:
                logger.info(f"Threat count changed: {self.last_threat_count} -> {current_threat_count}")
                return True
            
            # Check for new critical vulnerabilities
            critical_vulns = [v for v in current_data["live_vulnerabilities"] if v.get("severity", "").lower() == "critical"]
            if critical_vulns:
                # Check if any are recent (within last hour)
                recent_critical = []
                for vuln in critical_vulns:
                    if vuln.get("created_at"):
                        try:
                            created_at = datetime.fromisoformat(vuln["created_at"].replace("Z", "+00:00"))
                            if (datetime.now() - created_at).total_seconds() < 3600:
                                recent_critical.append(vuln)
                        except:
                            pass
                
                if recent_critical:
                    logger.info(f"Found {len(recent_critical)} recent critical vulnerabilities")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error determining if recalculation should be triggered: {str(e)}")
            return False
    
    async def trigger_priority_recalculation(self, current_data: Dict[str, Any]):
        """Trigger priority recalculation and store results"""
        try:
            # Import here to avoid circular imports
            from ..api.v1.endpoints.risk_prioritization import (
                calculate_real_time_risk_score,
                calculate_vulnerability_priorities
            )
            
            # Combine all vulnerability data
            all_vulnerabilities = current_data["live_vulnerabilities"] + current_data["stored_vulnerabilities"]
            
            # Calculate risk assessment
            risk_assessment = await calculate_real_time_risk_score(
                all_vulnerabilities,
                current_data["live_threats"] + current_data["stored_threats"],
                {"status": "monitoring"}
            )
            
            # Calculate priorities
            priorities = await calculate_vulnerability_priorities(all_vulnerabilities, risk_assessment)
            
            # Store the assessment
            assessment_record = {
                "timestamp": datetime.now().isoformat(),
                "risk_assessment": risk_assessment,
                "priorities": priorities,
                "triggered_by": "automatic_monitoring",
                "trigger_reason": "risk_change_detected",
                "vulnerability_count": len(all_vulnerabilities),
                "threat_count": len(current_data["live_threats"] + current_data["stored_threats"])
            }
            
            self.db.create("risk_assessments", assessment_record)
            
            # Update monitoring state
            self.last_assessment_time = datetime.now().isoformat()
            self.last_vulnerability_count = current_data["total_vulnerabilities"]
            self.last_threat_count = current_data["total_threats"]
            
            logger.info(f"Automatic priority recalculation completed. Risk score: {risk_assessment.get('risk_score', 0)}")
            
        except Exception as e:
            logger.error(f"Error triggering priority recalculation: {str(e)}")
    
    def get_last_assessment(self) -> Optional[Dict[str, Any]]:
        """Get the most recent risk assessment"""
        try:
            assessments = self.db.get_all("risk_assessments")
            if assessments:
                # Sort by timestamp and return the most recent
                sorted_assessments = sorted(assessments, key=lambda x: x.get("timestamp", ""), reverse=True)
                return sorted_assessments[0]
            return None
        except Exception as e:
            logger.error(f"Error getting last assessment: {str(e)}")
            return None
    
    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            "running": self.running,
            "last_assessment_time": self.last_assessment_time,
            "last_vulnerability_count": self.last_vulnerability_count,
            "last_threat_count": self.last_threat_count,
            "last_assessment": self.get_last_assessment()
        }

# Global instance
risk_monitor = RiskMonitoringService()

async def start_risk_monitoring():
    """Start the risk monitoring service"""
    await risk_monitor.start_monitoring()

def stop_risk_monitoring():
    """Stop the risk monitoring service"""
    risk_monitor.stop_monitoring()

def get_risk_monitor():
    """Get the risk monitoring service instance"""
    return risk_monitor 