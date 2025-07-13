"""
Risk Prioritization API endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any
from pydantic import BaseModel
from datetime import datetime, timedelta
import requests
import asyncio
import logging
from ....services.llm_service import get_llm_service
from ....core.database import get_db
from ....services.risk_monitoring import get_risk_monitor

router = APIRouter()
llm_service = get_llm_service()
db = get_db()
logger = logging.getLogger(__name__)

# Vulnerable server URL - adjust if needed
VULNERABLE_SERVER_URL = "http://localhost:5000"


class RealTimeRiskRequest(BaseModel):
    """Request model for real-time risk calculation"""
    include_vulnerable_server: bool = True
    recalculate_threshold_minutes: int = 5


async def fetch_live_vulnerability_data():
    """Fetch live vulnerability data from vulnerable server"""
    try:
        # Fetch vulnerabilities from vulnerable server
        vuln_response = requests.get(f"{VULNERABLE_SERVER_URL}/api/vulnerabilities", timeout=10)
        threats_response = requests.get(f"{VULNERABLE_SERVER_URL}/api/threats", timeout=10)
        status_response = requests.get(f"{VULNERABLE_SERVER_URL}/api/scan_status", timeout=10)
        
        vulnerabilities = []
        threats = []
        scan_status = {}
        
        if vuln_response.status_code == 200:
            vuln_data = vuln_response.json()
            vulnerabilities = vuln_data.get("vulnerabilities", [])
        
        if threats_response.status_code == 200:
            threats_data = threats_response.json()
            threats = threats_data.get("active_threats", [])
        
        if status_response.status_code == 200:
            scan_status = status_response.json()
        
        return {
            "vulnerabilities": vulnerabilities,
            "threats": threats,
            "scan_status": scan_status,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error fetching live vulnerability data: {str(e)}")
        return {
            "vulnerabilities": [],
            "threats": [],
            "scan_status": {},
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


async def calculate_real_time_risk_score(vulnerabilities: List[Dict], threats: List[Dict], scan_status: Dict) -> Dict[str, Any]:
    """Calculate real-time risk score based on current data"""
    try:
        # Base risk calculation
        critical_vulns = len([v for v in vulnerabilities if v.get("severity", "").lower() == "critical"])
        high_vulns = len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"])
        medium_vulns = len([v for v in vulnerabilities if v.get("severity", "").lower() == "medium"])
        low_vulns = len([v for v in vulnerabilities if v.get("severity", "").lower() == "low"])
        
        # Calculate base risk score (0-100)
        base_risk = min(100, (critical_vulns * 25) + (high_vulns * 15) + (medium_vulns * 8) + (low_vulns * 3))
        
        # Active threats multiplier
        active_threats = len(threats)
        threat_multiplier = 1.0 + (active_threats * 0.2)
        
        # Recent activity multiplier (based on timestamp)
        recent_activity_multiplier = 1.0
        now = datetime.now()
        for vuln in vulnerabilities:
            if vuln.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(vuln["created_at"].replace("Z", "+00:00"))
                    if (now - created_at).total_seconds() < 3600:  # Within last hour
                        recent_activity_multiplier += 0.1
                except:
                    pass
        
        # Calculate final risk score
        final_risk = min(100, base_risk * threat_multiplier * recent_activity_multiplier)
        
        # Determine risk level
        if final_risk >= 80:
            risk_level = "critical"
        elif final_risk >= 60:
            risk_level = "high"
        elif final_risk >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": round(final_risk, 2),
            "risk_level": risk_level,
            "base_risk": base_risk,
            "threat_multiplier": threat_multiplier,
            "recent_activity_multiplier": recent_activity_multiplier,
            "vulnerability_breakdown": {
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns,
                "total": len(vulnerabilities)
            },
            "active_threats": active_threats,
            "scan_status": scan_status.get("status", "unknown"),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error calculating real-time risk score: {str(e)}")
        return {
            "risk_score": 0,
            "risk_level": "unknown",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


@router.get("/real-time")
async def get_real_time_risk_assessment():
    """Get real-time risk assessment with live vulnerability data"""
    try:
        # Fetch live vulnerability data
        live_data = await fetch_live_vulnerability_data()
        
        # Get stored vulnerabilities from database
        stored_vulnerabilities = db.get_all("vulnerabilities")
        
        # Combine live and stored data
        all_vulnerabilities = live_data["vulnerabilities"] + stored_vulnerabilities
        
        # Calculate real-time risk score
        risk_assessment = await calculate_real_time_risk_score(
            all_vulnerabilities, 
            live_data["threats"], 
            live_data["scan_status"]
        )
        
        # Priority calculation based on risk score
        priorities = await calculate_vulnerability_priorities(all_vulnerabilities, risk_assessment)
        
        # Check for recent changes (last 5 minutes)
        recent_changes = []
        current_time = datetime.now()
        
        # Check for recent vulnerabilities
        for vuln in live_data["vulnerabilities"]:
            if vuln.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(vuln["created_at"].replace("Z", "+00:00"))
                    if (current_time - created_at).total_seconds() < 300:  # 5 minutes
                        recent_changes.append({
                            "type": "vulnerability",
                            "severity": vuln.get("severity", "unknown"),
                            "description": vuln.get("description", "New vulnerability detected"),
                            "timestamp": vuln.get("created_at")
                        })
                except:
                    pass
        
        # Check for recent threats
        for threat in live_data["threats"]:
            if threat.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(threat["created_at"].replace("Z", "+00:00"))
                    if (current_time - created_at).total_seconds() < 300:  # 5 minutes
                        recent_changes.append({
                            "type": "threat",
                            "severity": threat.get("severity", "unknown"),
                            "description": threat.get("description", "New threat detected"),
                            "timestamp": threat.get("created_at")
                        })
                except:
                    pass
        
        # Store the assessment
        assessment_record = {
            "timestamp": datetime.now().isoformat(),
            "risk_assessment": risk_assessment,
            "priorities": priorities,
            "live_data_status": "error" if live_data.get("error") else "success",
            "recent_changes": recent_changes
        }
        
        db.create("risk_assessments", assessment_record)
        
        return {
            "risk_assessment": risk_assessment,
            "priorities": priorities,
            "live_data": live_data,
            "recent_changes": recent_changes,
            "total_vulnerabilities": len(all_vulnerabilities),
            "last_updated": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in real-time risk assessment: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/instant-threats")
async def get_instant_threat_updates():
    """Get instant threat updates for immediate notifications"""
    try:
        # Fetch just the latest threat data
        live_data = await fetch_live_vulnerability_data()
        
        current_time = datetime.now()
        instant_threats = []
        
        # Get threats from last 30 seconds for truly instant updates
        for threat in live_data["threats"]:
            if threat.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(threat["created_at"].replace("Z", "+00:00"))
                    if (current_time - created_at).total_seconds() < 30:  # Last 30 seconds
                        instant_threats.append({
                            "id": threat.get("id"),
                            "type": "threat",
                            "severity": threat.get("severity", "unknown"),
                            "description": threat.get("description", "New threat detected"),
                            "source_ip": threat.get("source_ip"),
                            "timestamp": threat.get("created_at"),
                            "age_seconds": (current_time - created_at).total_seconds()
                        })
                except:
                    pass
        
        # Get very recent vulnerabilities (last 30 seconds)
        for vuln in live_data["vulnerabilities"]:
            if vuln.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(vuln["created_at"].replace("Z", "+00:00"))
                    if (current_time - created_at).total_seconds() < 30:  # Last 30 seconds
                        instant_threats.append({
                            "id": vuln.get("id"),
                            "type": "vulnerability",
                            "severity": vuln.get("severity", "unknown"),
                            "description": vuln.get("description", "New vulnerability detected"),
                            "event_type": vuln.get("event_type"),
                            "timestamp": vuln.get("created_at"),
                            "age_seconds": (current_time - created_at).total_seconds()
                        })
                except:
                    pass
        
        # Sort by timestamp (newest first)
        instant_threats.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return {
            "instant_threats": instant_threats[:10],  # Limit to 10 most recent
            "count": len(instant_threats),
            "timestamp": current_time.isoformat(),
            "has_critical": any(t.get("severity") == "critical" for t in instant_threats)
        }
        
    except Exception as e:
        logger.error(f"Error getting instant threat updates: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


async def calculate_vulnerability_priorities(vulnerabilities: List[Dict], risk_assessment: Dict) -> List[Dict]:
    """Calculate vulnerability priorities based on risk assessment"""
    try:
        prioritized_vulns = []
        
        for vuln in vulnerabilities:
            # Calculate priority score
            severity = vuln.get("severity", "medium").lower()
            cvss_score = float(vuln.get("cvss_score", 0))
            
            # Base priority from severity and CVSS
            if severity == "critical":
                base_priority = 100
            elif severity == "high":
                base_priority = 80
            elif severity == "medium":
                base_priority = 60
            else:
                base_priority = 40
            
            # Adjust by CVSS score
            priority_score = base_priority + (cvss_score * 5)
            
            # Adjust by recent activity
            if vuln.get("created_at"):
                try:
                    created_at = datetime.fromisoformat(vuln["created_at"].replace("Z", "+00:00"))
                    hours_old = (datetime.now() - created_at).total_seconds() / 3600
                    if hours_old < 1:
                        priority_score += 20  # Very recent
                    elif hours_old < 6:
                        priority_score += 10  # Recent
                except:
                    pass
            
            # Determine priority level
            if priority_score >= 90:
                priority_level = "P1"
                priority_num = 1
            elif priority_score >= 70:
                priority_level = "P2"
                priority_num = 2
            elif priority_score >= 50:
                priority_level = "P3"
                priority_num = 3
            else:
                priority_level = "P4"
                priority_num = 4
            
            prioritized_vulns.append({
                "id": vuln.get("id", "unknown"),
                "title": vuln.get("title", vuln.get("description", "Unknown vulnerability")),
                "severity": severity,
                "cvss_score": cvss_score,
                "priority_score": priority_score,
                "priority_level": priority_level,
                "priority_num": priority_num,
                "created_at": vuln.get("created_at"),
                "exploit_available": vuln.get("exploit_available", False),
                "affected_assets": vuln.get("affected_assets", []),
                "business_impact": vuln.get("business_impact", "Unknown"),
                "remediation_complexity": vuln.get("remediation_complexity", "Unknown"),
                "exposure": vuln.get("exposure", "Unknown")
            })
        
        # Sort by priority score (highest first)
        prioritized_vulns.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return prioritized_vulns
        
    except Exception as e:
        logger.error(f"Error calculating vulnerability priorities: {str(e)}")
        return []


@router.post("/monitoring/start")
async def start_risk_monitoring(background_tasks: BackgroundTasks):
    """Start automatic risk monitoring"""
    try:
        risk_monitor = get_risk_monitor()
        
        if risk_monitor.running:
            return {"status": "already_running", "message": "Risk monitoring is already active"}
        
        # Start monitoring in background
        background_tasks.add_task(risk_monitor.start_monitoring, 30)  # Check every 30 seconds
        
        return {
            "status": "started",
            "message": "Risk monitoring started successfully",
            "interval_seconds": 30
        }
    except Exception as e:
        logger.error(f"Error starting risk monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/stop")
async def stop_risk_monitoring():
    """Stop automatic risk monitoring"""
    try:
        risk_monitor = get_risk_monitor()
        risk_monitor.stop_monitoring()
        
        return {
            "status": "stopped",
            "message": "Risk monitoring stopped successfully"
        }
    except Exception as e:
        logger.error(f"Error stopping risk monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/monitoring/status")
async def get_monitoring_status():
    """Get risk monitoring status"""
    try:
        risk_monitor = get_risk_monitor()
        status = await risk_monitor.get_monitoring_status()
        
        return {
            "monitoring_active": status["running"],
            "last_assessment_time": status["last_assessment_time"],
            "last_vulnerability_count": status["last_vulnerability_count"],
            "last_threat_count": status["last_threat_count"],
            "last_assessment": status["last_assessment"]
        }
    except Exception as e:
        logger.error(f"Error getting monitoring status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/monitoring/check")
async def manual_risk_check():
    """Manually trigger a risk change check"""
    try:
        risk_monitor = get_risk_monitor()
        changes_detected = await risk_monitor.check_for_risk_changes()
        
        return {
            "status": "completed",
            "changes_detected": changes_detected,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in manual risk check: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recalculate")
async def force_recalculate_priorities():
    """Force recalculation of risk priorities"""
    try:
        # Get fresh real-time assessment
        assessment = await get_real_time_risk_assessment()
        
        # Also update the monitoring service state
        risk_monitor = get_risk_monitor()
        risk_monitor.last_assessment_time = datetime.now().isoformat()
        
        return {
            "status": "recalculated",
            "timestamp": datetime.now().isoformat(),
            "assessment": assessment
        }
    except Exception as e:
        logger.error(f"Error in force recalculation: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assess")
async def assess_risk(asset_data: Dict[str, Any]):
    """Assess risk for assets"""
    try:
        # Simulate risk assessment
        risk_assessment = {
            "asset_id": asset_data.get("id"),
            "risk_score": 75,
            "priority": "P2",
            "recommendations": ["Update software", "Apply security patches"]
        }
        
        db.create("risk_assessments", risk_assessment)
        return risk_assessment
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scores")
async def get_risk_scores():
    """Get risk scores for all assets"""
    try:
        scores = db.get_all("risk_assessments")
        return scores
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/priorities")
async def update_priorities(priorities: Dict[str, Any]):
    """Update risk priorities"""
    try:
        return {"status": "updated", "priorities": priorities}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 


@router.post("/prioritize")
async def prioritize_vulnerabilities():
    """Prioritize vulnerabilities across all assets using CVSS, exploit data, and asset value"""
    try:
        # Fetch all vulnerabilities and assets
        vulnerabilities = db.get_all("vulnerabilities")
        assets = db.get_all("assets")

        # Attach asset value to vulnerabilities if possible
        asset_value_map = {a.get("id"): a.get("value", 50) for a in assets}
        for vuln in vulnerabilities:
            affected_assets = vuln.get("affected_assets", [])
            vuln["asset_value"] = max([asset_value_map.get(aid, 50) for aid in affected_assets], default=50)

        # Use LLM service to prioritize
        result = await llm_service.prioritize_vulnerabilities(vulnerabilities)

        # Optionally, store prioritization result
        db.create("risk_assessments", {
            "timestamp": result["timestamp"],
            "prioritization": result
        })

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 