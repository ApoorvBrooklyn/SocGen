"""
Ticket Management API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from ....core.database import get_db
from ....core.config import settings
import aiohttp
import json

router = APIRouter()
db = get_db()


class TicketRequest(BaseModel):
    title: str
    description: str
    priority: str
    assigned_to: str = None


class GitHubTicketRequest(BaseModel):
    title: str
    description: str
    priority: str = "medium"
    labels: List[str] = []
    assignees: List[str] = []
    repository: str = "security-issues"


class VulnerabilityTicketRequest(BaseModel):
    cve_id: str
    priority: str = "medium"
    repository: str = "security-issues"
    assignees: List[str] = []


@router.get("/")
async def get_tickets():
    """Get all tickets"""
    try:
        tickets = db.get_all("tickets")
        return tickets
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def create_ticket(ticket: TicketRequest):
    """Create new ticket"""
    try:
        ticket_data = ticket.dict()
        ticket_data.update({
            "status": "open",
            "tags": [],
            "related_assets": [],
            "related_vulnerabilities": []
        })
        
        created_ticket = db.create("tickets", ticket_data)
        return created_ticket
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/github")
async def create_github_ticket(ticket: GitHubTicketRequest):
    """Create GitHub issue for security ticket"""
    try:
        if not settings.GITHUB_TOKEN:
            raise HTTPException(status_code=400, detail="GitHub token not configured")
        
        # GitHub API endpoint
        url = f"https://api.github.com/repos/{settings.GITHUB_USERNAME}/{ticket.repository}/issues"
        
        # Prepare issue data
        issue_data = {
            "title": ticket.title,
            "body": ticket.description,
            "labels": ticket.labels + ["security", "vulnerability"],
            "assignees": ticket.assignees
        }
        
        headers = {
            "Authorization": f"token {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=issue_data, headers=headers) as response:
                if response.status == 201:
                    github_issue = await response.json()
                    
                    # Store ticket in local database
                    local_ticket = {
                        "title": ticket.title,
                        "description": ticket.description,
                        "priority": ticket.priority,
                        "status": "open",
                        "github_issue_id": github_issue["id"],
                        "github_issue_number": github_issue["number"],
                        "github_url": github_issue["html_url"],
                        "repository": ticket.repository,
                        "labels": ticket.labels,
                        "assignees": ticket.assignees,
                        "created_at": github_issue["created_at"],
                        "updated_at": github_issue["updated_at"]
                    }
                    
                    created_ticket = db.create("tickets", local_ticket)
                    return {
                        "local_ticket": created_ticket,
                        "github_issue": github_issue
                    }
                else:
                    error_text = await response.text()
                    raise HTTPException(status_code=response.status, detail=f"GitHub API error: {error_text}")
                    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vulnerability")
async def create_vulnerability_ticket(request: VulnerabilityTicketRequest):
    """Create GitHub issue for vulnerability"""
    try:
        # Get CVE data
        cve_data = db.get_by_id("cves", request.cve_id)
        if not cve_data:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        # Generate ticket title and description
        title = f"Security: {cve_data.get('title', request.cve_id)}"
        
        description = f"""
## Vulnerability Details

**CVE ID:** {cve_data.get('id', 'Unknown')}
**Severity:** {cve_data.get('severity', 'Unknown')}
**CVSS Score:** {cve_data.get('cvss_score', 'Unknown')}

### Description
{cve_data.get('description', 'No description available')}

### Affected Products
{chr(10).join([f"- {product}" for product in cve_data.get('affected_products', [])])}

### Business Impact
{cve_data.get('business_impact', 'Impact assessment needed')}

### Remediation Steps
{chr(10).join([f"{i+1}. {step}" for i, step in enumerate(cve_data.get('remediation_steps', ['Remediation steps needed']))])}

### References
{chr(10).join([f"- {ref.get('url', '')}" for ref in cve_data.get('references', [])])}

---
*This ticket was automatically generated by the Security Management Platform*
        """.strip()
        
        # Determine priority based on CVSS score
        cvss_score = float(cve_data.get('cvss_score', 0))
        if cvss_score >= 9.0:
            priority = "critical"
            labels = ["security", "vulnerability", "critical", "urgent"]
        elif cvss_score >= 7.0:
            priority = "high"
            labels = ["security", "vulnerability", "high"]
        elif cvss_score >= 4.0:
            priority = "medium"
            labels = ["security", "vulnerability", "medium"]
        else:
            priority = "low"
            labels = ["security", "vulnerability", "low"]
        
        # Override priority if provided
        if request.priority != "medium":
            priority = request.priority
        
        # Create GitHub ticket
        github_request = GitHubTicketRequest(
            title=title,
            description=description,
            priority=priority,
            labels=labels,
            assignees=request.assignees,
            repository=request.repository
        )
        
        return await create_github_ticket(github_request)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch-vulnerabilities")
async def create_batch_vulnerability_tickets(cve_ids: List[str], repository: str = "security-issues"):
    """Create GitHub issues for multiple vulnerabilities"""
    try:
        results = []
        
        for cve_id in cve_ids:
            try:
                request = VulnerabilityTicketRequest(
                    cve_id=cve_id,
                    repository=repository
                )
                result = await create_vulnerability_ticket(request)
                results.append({
                    "cve_id": cve_id,
                    "status": "success",
                    "result": result
                })
            except Exception as e:
                results.append({
                    "cve_id": cve_id,
                    "status": "error",
                    "error": str(e)
                })
        
        return {
            "total_cves": len(cve_ids),
            "successful": len([r for r in results if r["status"] == "success"]),
            "failed": len([r for r in results if r["status"] == "error"]),
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/github/{issue_number}")
async def get_github_issue(issue_number: int, repository: str = "security-issues"):
    """Get GitHub issue details"""
    try:
        if not settings.GITHUB_TOKEN:
            raise HTTPException(status_code=400, detail="GitHub token not configured")
        
        url = f"https://api.github.com/repos/{settings.GITHUB_USERNAME}/{repository}/issues/{issue_number}"
        
        headers = {
            "Authorization": f"token {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise HTTPException(status_code=response.status, detail="GitHub issue not found")
                    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/github/{issue_number}")
async def update_github_issue(issue_number: int, update_data: Dict[str, Any], repository: str = "security-issues"):
    """Update GitHub issue"""
    try:
        if not settings.GITHUB_TOKEN:
            raise HTTPException(status_code=400, detail="GitHub token not configured")
        
        url = f"https://api.github.com/repos/{settings.GITHUB_USERNAME}/{repository}/issues/{issue_number}"
        
        headers = {
            "Authorization": f"token {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.patch(url, json=update_data, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise HTTPException(status_code=response.status, detail=f"GitHub API error: {error_text}")
                    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{ticket_id}")
async def get_ticket(ticket_id: str):
    """Get specific ticket"""
    try:
        ticket = db.get_by_id("tickets", ticket_id)
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")
        return ticket
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{ticket_id}")
async def update_ticket(ticket_id: str, ticket_data: Dict[str, Any]):
    """Update ticket"""
    try:
        updated_ticket = db.update("tickets", ticket_id, ticket_data)
        if not updated_ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")
        return updated_ticket
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{ticket_id}")
async def delete_ticket(ticket_id: str):
    """Delete ticket"""
    try:
        success = db.delete("tickets", ticket_id)
        if not success:
            raise HTTPException(status_code=404, detail="Ticket not found")
        return {"status": "deleted", "ticket_id": ticket_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 