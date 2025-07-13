"""
Patch Recommendations API endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
from ....services.llm_service import get_llm_service
from ....services.vulnerability_scanner import get_scanner_service
from ....core.database import get_db
import logging
import time

logger = logging.getLogger(__name__)

router = APIRouter()
llm_service = get_llm_service()
scanner_service = get_scanner_service()
db = get_db()


class PatchRecommendationRequest(BaseModel):
    cve_data: Dict[str, Any]
    os_type: str


class BatchPatchRequest(BaseModel):
    cve_ids: List[str]
    os_type: str


class PatchVerificationRequest(BaseModel):
    cve_id: str
    target_hosts: List[str]
    verification_type: str = "rescan"  # "rescan", "manual", "automated"
    expected_result: str = "vulnerability_resolved"


class PatchDeploymentRequest(BaseModel):
    cve_id: str
    patch_commands: List[str]
    target_hosts: List[str]
    deployment_method: str = "automated"  # "automated", "manual", "scheduled"
    rollback_plan: Optional[str] = None


@router.post("/recommend")
async def generate_patch_recommendations(request: PatchRecommendationRequest):
    """Generate patch recommendations for CVE"""
    try:
        recommendation = await llm_service.generate_patch_recommendation(
            request.cve_data, request.os_type
        )
        
        # Store recommendation
        db.create("patch_recommendations", recommendation)
        
        return recommendation
    except Exception as e:
        logger.error(f"LLM error generating patch recommendation: {e}")
        
        # Fallback recommendation when LLM is unavailable
        fallback_recommendation = {
            "cve_id": request.cve_data.get("id"),
            "os_type": request.os_type,
            "recommendations": f"Apply latest vendor patch for {request.cve_data.get('id', 'CVE')}. Check vendor security advisories for specific remediation steps.",
            "patch_commands": [
                f"# Update package manager for {request.os_type}",
                f"sudo apt update  # For Ubuntu/Debian",
                f"sudo yum update  # For CentOS/RHEL",
                f"# Install security updates",
                f"sudo apt upgrade  # For Ubuntu/Debian", 
                f"sudo yum upgrade  # For CentOS/RHEL",
                f"# Verify patch installation",
                f"# Test system functionality"
            ],
            "manual_steps": [
                "1. Check vendor security advisories",
                "2. Apply recommended patches",
                "3. Verify patch installation",
                "4. Test system functionality",
                "5. Monitor for any issues"
            ],
            "timestamp": time.time(),
            "llm_available": False,
            "fallback_reason": str(e)
        }
        
        # Store fallback recommendation
        db.create("patch_recommendations", fallback_recommendation)
        
        return fallback_recommendation


@router.post("/batch")
async def generate_batch_recommendations(request: BatchPatchRequest):
    """Generate patch recommendations for multiple CVEs"""
    try:
        recommendations = []
        
        for cve_id in request.cve_ids:
            # Fetch CVE data
            cve_data = db.get_by_id("cves", cve_id)
            if cve_data:
                try:
                    recommendation = await llm_service.generate_patch_recommendation(
                        cve_data, request.os_type
                    )
                    recommendations.append(recommendation)
                    
                    # Store individual recommendation
                    db.create("patch_recommendations", recommendation)
                except Exception as e:
                    logger.error(f"LLM error for CVE {cve_id}: {e}")
                    
                    # Fallback recommendation for this CVE
                    fallback_recommendation = {
                        "cve_id": cve_id,
                        "os_type": request.os_type,
                        "recommendations": f"Apply latest vendor patch for {cve_id}. Check vendor security advisories.",
                        "patch_commands": [
                            f"# Update package manager for {request.os_type}",
                            f"sudo apt update  # For Ubuntu/Debian",
                            f"sudo yum update  # For CentOS/RHEL",
                            f"# Install security updates",
                            f"sudo apt upgrade  # For Ubuntu/Debian",
                            f"sudo yum upgrade  # For CentOS/RHEL"
                        ],
                        "manual_steps": [
                            "1. Check vendor security advisories",
                            "2. Apply recommended patches",
                            "3. Verify patch installation",
                            "4. Test system functionality"
                        ],
                        "timestamp": time.time(),
                        "llm_available": False,
                        "fallback_reason": str(e)
                    }
                    
                    recommendations.append(fallback_recommendation)
                    db.create("patch_recommendations", fallback_recommendation)
        
        return {
            "total_cves": len(request.cve_ids),
            "processed": len(recommendations),
            "recommendations": recommendations
        }
    except Exception as e:
        logger.error(f"Error in batch recommendations: {e}")
        raise HTTPException(status_code=500, detail=f"Batch processing failed: {str(e)}")


@router.post("/deploy")
async def deploy_patch(request: PatchDeploymentRequest, background_tasks: BackgroundTasks):
    """Deploy patch with verification"""
    try:
        # Create deployment record
        deployment = {
            "id": f"deploy-{len(db.get_all('patch_deployments')) + 1}",
            "cve_id": request.cve_id,
            "patch_commands": request.patch_commands,
            "target_hosts": request.target_hosts,
            "deployment_method": request.deployment_method,
            "rollback_plan": request.rollback_plan,
            "status": "in_progress",
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "verification_status": "pending"
        }
        
        # Store deployment record
        db.create("patch_deployments", deployment)
        
        # Start deployment in background
        background_tasks.add_task(execute_patch_deployment, deployment["id"], request)
        
        return {
            "deployment_id": deployment["id"],
            "status": "deployment_started",
            "message": f"Patch deployment started for CVE {request.cve_id}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def execute_patch_deployment(deployment_id: str, request: PatchDeploymentRequest):
    """Execute patch deployment and verification"""
    try:
        # Simulate patch deployment
        await asyncio.sleep(5)  # Simulate deployment time
        
        # Update deployment status
        db.update("patch_deployments", deployment_id, {
            "status": "completed",
            "completed_at": datetime.now().isoformat()
        })
        
        # Start verification process
        verification_request = PatchVerificationRequest(
            cve_id=request.cve_id,
            target_hosts=request.target_hosts,
            verification_type="rescan"
        )
        
        await verify_patch_application(verification_request, deployment_id)
        
    except Exception as e:
        # Update deployment status to failed
        db.update("patch_deployments", deployment_id, {
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


@router.post("/verify")
async def verify_patch_application(request: PatchVerificationRequest, deployment_id: Optional[str] = None):
    """Verify patch application and vulnerability resolution"""
    try:
        # Get CVE data
        cve_data = db.get_by_id("cves", request.cve_id)
        if not cve_data:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        verification_results = []
        
        for host in request.target_hosts:
            if request.verification_type == "rescan":
                # Perform re-scan of the target
                scan_result = await perform_verification_scan(host, request.cve_id)
                verification_results.append(scan_result)
            elif request.verification_type == "manual":
                # Manual verification (user input)
                verification_results.append({
                    "host": host,
                    "verification_type": "manual",
                    "status": "pending_manual_verification",
                    "notes": "Requires manual verification by administrator"
                })
            else:
                # Automated verification (check specific indicators)
                verification_results.append(await perform_automated_verification(host, request.cve_id))
        
        # Create verification record
        verification_record = {
            "id": f"verify-{len(db.get_all('patch_verifications')) + 1}",
            "cve_id": request.cve_id,
            "deployment_id": deployment_id,
            "target_hosts": request.target_hosts,
            "verification_type": request.verification_type,
            "results": verification_results,
            "overall_status": determine_overall_status(verification_results),
            "verified_at": datetime.now().isoformat()
        }
        
        db.create("patch_verifications", verification_record)
        
        # Update deployment if provided
        if deployment_id:
            db.update("patch_deployments", deployment_id, {
                "verification_status": verification_record["overall_status"]
            })
        
        return verification_record
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def perform_verification_scan(host: str, cve_id: str) -> Dict[str, Any]:
    """Perform verification scan to check if vulnerability is resolved"""
    try:
        # Start a targeted scan
        scan_config = {
            "target": host,
            "scanner_type": "mock",
            "scan_type": "verification",
            "cve_id": cve_id
        }
        
        scan_result = await scanner_service.start_scan(scan_config)
        scan_id = scan_result["scan_id"]
        
        # Wait for scan to complete
        max_wait = 30  # seconds
        wait_time = 0
        while wait_time < max_wait:
            status = await scanner_service.get_scan_status(scan_id)
            if status and status.get("status") == "completed":
                break
            await asyncio.sleep(2)
            wait_time += 2
        
        # Get final scan results
        final_status = await scanner_service.get_scan_status(scan_id)
        
        # Check if the specific CVE is still present
        vulnerabilities = final_status.get("vulnerabilities", [])
        cve_still_present = any(v.get("id") == cve_id for v in vulnerabilities)
        
        return {
            "host": host,
            "verification_type": "rescan",
            "scan_id": scan_id,
            "vulnerability_resolved": not cve_still_present,
            "status": "resolved" if not cve_still_present else "still_vulnerable",
            "scan_results": final_status,
            "verification_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "host": host,
            "verification_type": "rescan",
            "status": "verification_failed",
            "error": str(e),
            "verification_time": datetime.now().isoformat()
        }


async def perform_automated_verification(host: str, cve_id: str) -> Dict[str, Any]:
    """Perform automated verification using specific indicators"""
    try:
        # Simulate automated verification checks
        # In a real implementation, this would check specific indicators like:
        # - Service version numbers
        # - Configuration file changes
        # - Registry entries
        # - File checksums
        
        import random
        # Simulate verification result
        is_resolved = random.choice([True, False])  # 50/50 chance for demo
        
        return {
            "host": host,
            "verification_type": "automated",
            "status": "resolved" if is_resolved else "still_vulnerable",
            "indicators_checked": [
                "service_version",
                "configuration_files",
                "registry_entries"
            ],
            "verification_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "host": host,
            "verification_type": "automated",
            "status": "verification_failed",
            "error": str(e),
            "verification_time": datetime.now().isoformat()
        }


def determine_overall_status(verification_results: List[Dict[str, Any]]) -> str:
    """Determine overall verification status"""
    if not verification_results:
        return "unknown"
    
    resolved_count = sum(1 for r in verification_results if r.get("status") == "resolved")
    total_count = len(verification_results)
    
    if resolved_count == total_count:
        return "all_resolved"
    elif resolved_count > 0:
        return "partially_resolved"
    else:
        return "not_resolved"


@router.get("/verifications")
async def get_patch_verifications(cve_id: Optional[str] = None):
    """Get patch verification history"""
    try:
        if cve_id:
            verifications = db.find("patch_verifications", {"cve_id": cve_id})
        else:
            verifications = db.get_all("patch_verifications")
        
        return verifications
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/deployments")
async def get_patch_deployments(cve_id: Optional[str] = None):
    """Get patch deployment history"""
    try:
        if cve_id:
            deployments = db.find("patch_deployments", {"cve_id": cve_id})
        else:
            deployments = db.get_all("patch_deployments")
        
        return deployments
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/os/{os_type}")
async def get_os_specific_recommendations(os_type: str):
    """Get all patch recommendations for a specific OS"""
    try:
        recommendations = db.find("patch_recommendations", {"os_type": os_type})
        return recommendations
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/{cve_id}")
async def get_cve_recommendations(cve_id: str):
    """Get all patch recommendations for a specific CVE"""
    try:
        recommendations = db.find("patch_recommendations", {"cve_id": cve_id})
        return recommendations
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_patch_history():
    """Get patch deployment history"""
    try:
        history = db.get_all("patch_recommendations")
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rollback")
async def rollback_patch(deployment_id: str, background_tasks: BackgroundTasks):
    """Rollback patch deployment"""
    try:
        # Get deployment record
        deployment = db.get_by_id("patch_deployments", deployment_id)
        if not deployment:
            raise HTTPException(status_code=404, detail="Deployment not found")
        
        # Create rollback record
        rollback = {
            "id": f"rollback-{len(db.get_all('patch_rollbacks')) + 1}",
            "deployment_id": deployment_id,
            "cve_id": deployment.get("cve_id"),
            "target_hosts": deployment.get("target_hosts", []),
            "rollback_plan": deployment.get("rollback_plan"),
            "status": "in_progress",
            "started_at": datetime.now().isoformat()
        }
        
        db.create("patch_rollbacks", rollback)
        
        # Execute rollback in background
        background_tasks.add_task(execute_rollback, rollback["id"], deployment)
        
        return {
            "rollback_id": rollback["id"],
            "status": "rollback_started",
            "message": f"Rollback started for deployment {deployment_id}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def execute_rollback(rollback_id: str, deployment: Dict[str, Any]):
    """Execute patch rollback"""
    try:
        # Simulate rollback process
        await asyncio.sleep(3)
        
        # Update rollback status
        db.update("patch_rollbacks", rollback_id, {
            "status": "completed",
            "completed_at": datetime.now().isoformat()
        })
        
        # Update deployment status
        db.update("patch_deployments", deployment["id"], {
            "status": "rolled_back",
            "rollback_id": rollback_id
        })
        
    except Exception as e:
        db.update("patch_rollbacks", rollback_id, {
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


# Import asyncio for async operations
import asyncio 