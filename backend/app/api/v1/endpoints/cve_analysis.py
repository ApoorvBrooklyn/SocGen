"""
CVE Analysis API endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from ....services.cve_analysis import get_cve_service
from ....core.logging import log_vulnerability_event

router = APIRouter()
cve_service = get_cve_service()


class CVEAnalysisRequest(BaseModel):
    cve_data: Dict[str, Any]
    include_llm_analysis: bool = True
    include_threat_intel: bool = True


class CVESearchRequest(BaseModel):
    query: str
    limit: int = 50


class CVEResponse(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    last_updated: str
    nvd_status: str
    cwe_id: str
    affected_products: List[str]
    exploit_available: bool
    patch_available: bool
    llm_summary: Optional[str] = None
    business_impact: Optional[str] = None
    remediation_steps: Optional[List[str]] = None
    confidence_score: Optional[float] = None


@router.get("/")
async def get_all_cves():
    """Get all CVEs"""
    try:
        cves = await cve_service.get_all_cves()
        return cves
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/raw")
async def get_all_cves_raw():
    """Get all CVEs without response model validation"""
    try:
        cves = await cve_service.get_all_cves()
        return {"count": len(cves), "cves": cves}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{cve_id}", response_model=CVEResponse)
async def get_cve(cve_id: str):
    """Get specific CVE by ID"""
    try:
        cve = await cve_service.get_cve(cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        return cve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=CVEResponse)
async def create_cve(cve_data: Dict[str, Any]):
    """Create a new CVE record"""
    try:
        created_cve = await cve_service.create_cve(cve_data)
        return created_cve
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_cve(request: CVEAnalysisRequest):
    """Analyze CVE with LLM and threat intelligence"""
    try:
        # Analyze with LLM
        llm_analysis = await cve_service.analyze_cve_with_llm(request.cve_data)
        
        # Enrich with threat intelligence if requested
        if request.include_threat_intel:
            enriched_cve = await cve_service.enrich_with_threat_intelligence(llm_analysis)
        else:
            enriched_cve = llm_analysis
        
        return {
            "analysis": enriched_cve,
            "status": "completed",
            "timestamp": enriched_cve.get("llm_analysis_timestamp")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{cve_id}/correlate")
async def correlate_cve(cve_id: str, background_tasks: BackgroundTasks):
    """Correlate CVE with threat intelligence"""
    try:
        cve = await cve_service.get_cve(cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # Get GitHub advisories
        github_advisories = await cve_service.get_github_advisories(cve_id)
        
        # Update CVE with correlation data
        correlation_data = {
            "github_references": github_advisories,
            "correlation_timestamp": cve_service.db.get_by_id("cves", cve_id).get("updated_at")
        }
        
        # Update in background
        background_tasks.add_task(
            cve_service.db.update,
            "cves",
            cve_id,
            correlation_data
        )
        
        return {
            "status": "correlation_started",
            "cve_id": cve_id,
            "github_advisories_found": len(github_advisories)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search", response_model=List[CVEResponse])
async def search_cves(request: CVESearchRequest):
    """Search CVEs by query"""
    try:
        results = await cve_service.search_cves(request.query)
        return results[:request.limit]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/trends/statistics")
async def get_cve_trends():
    """Get CVE trends and statistics"""
    try:
        trends = await cve_service.get_cve_trends()
        return trends
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync/recent")
async def sync_recent_cves(background_tasks: BackgroundTasks, days: int = 7):
    """Sync recent CVEs from NVD"""
    try:
        # Start sync in background
        background_tasks.add_task(cve_service.sync_recent_cves, days)
        
        return {
            "status": "sync_started",
            "days": days,
            "message": f"Started syncing CVEs from last {days} days"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/severity/{severity}")
async def get_cves_by_severity(severity: str):
    """Get CVEs by severity level"""
    try:
        cves = cve_service.db.find("cves", {"severity": severity.title()})
        return cves
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exploitable/list")
async def get_exploitable_cves():
    """Get CVEs with available exploits"""
    try:
        cves = cve_service.db.find("cves", {"exploit_available": True})
        return cves
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/product/{product}")
async def get_cves_by_product(product: str):
    """Get CVEs affecting a specific product"""
    try:
        all_cves = cve_service.db.get_all("cves")
        matching_cves = []
        
        for cve in all_cves:
            affected_products = cve.get("affected_products", [])
            if any(product.lower() in p.lower() for p in affected_products):
                matching_cves.append(cve)
        
        return matching_cves
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{cve_id}")
async def delete_cve(cve_id: str):
    """Delete a CVE record"""
    try:
        success = cve_service.db.delete("cves", cve_id)
        if not success:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        log_vulnerability_event(cve_id, "deleted", {"reason": "manual_deletion"})
        
        return {"status": "deleted", "cve_id": cve_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 