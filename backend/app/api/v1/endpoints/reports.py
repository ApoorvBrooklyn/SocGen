"""
Reports API endpoints
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import json
import os
from ....services.llm_service import get_llm_service
from ....core.database import get_db
from ....core.config import settings

router = APIRouter()
llm_service = get_llm_service()
db = get_db()


class ReportRequest(BaseModel):
    report_type: str
    date_range: Dict[str, str]
    format: str = "json"
    recipients: List[str] = []
    email_subject: str = ""


class EmailReportRequest(BaseModel):
    report_type: str
    recipients: List[str]
    subject: str = "Security Report"
    include_attachments: bool = True
    date_range: Optional[Dict[str, str]] = None


class ScheduledReportRequest(BaseModel):
    report_type: str
    schedule: str  # "daily", "weekly", "monthly"
    recipients: List[str]
    time: str = "09:00"  # HH:MM format
    timezone: str = "UTC"
    enabled: bool = True


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """Generate security report"""
    try:
        # Get real data from database
        vulnerabilities = db.get_all("vulnerabilities")
        assets = db.get_all("assets")
        cves = db.get_all("cves")
        
        # Calculate statistics
        total_vulnerabilities = len(vulnerabilities)
        critical_vulnerabilities = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_vulnerabilities = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        medium_vulnerabilities = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
        low_vulnerabilities = len([v for v in vulnerabilities if v.get('severity') == 'low'])
        
        # Calculate risk score
        risk_score = min(100, (critical_vulnerabilities * 25) + (high_vulnerabilities * 15) + 
                        (medium_vulnerabilities * 8) + (low_vulnerabilities * 3))
        
        report_data = {
            "total_vulnerabilities": total_vulnerabilities,
            "critical_vulnerabilities": critical_vulnerabilities,
            "high_vulnerabilities": high_vulnerabilities,
            "medium_vulnerabilities": medium_vulnerabilities,
            "low_vulnerabilities": low_vulnerabilities,
            "risk_score": risk_score,
            "total_assets": len(assets),
            "total_cves": len(cves),
            "date_range": request.date_range,
            "generated_at": datetime.now().isoformat()
        }
        
        # Generate report content based on type
        if request.report_type == "executive":
            report_content = await generate_executive_report(report_data)
        elif request.report_type == "technical":
            report_content = await generate_technical_report(report_data, vulnerabilities, assets)
        elif request.report_type == "compliance":
            report_content = await generate_compliance_report(report_data)
        else:
            report_content = await generate_generic_report(report_data, request.report_type)
        
        # Generate LLM summary
        summary = await llm_service.generate_report_summary(report_data, request.report_type)
        
        report = {
            "id": f"report-{len(db.get_all('reports')) + 1}",
            "type": request.report_type,
            "format": request.format,
            "summary": summary,
            "content": report_content,
            "data": report_data,
            "recipients": request.recipients,
            "generated_at": datetime.now().isoformat()
        }
        
        db.create("reports", report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def generate_executive_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate executive summary report"""
    return {
        "title": "Executive Security Report",
        "summary": f"""
## Executive Summary

**Overall Risk Score:** {data['risk_score']}/100
**Total Vulnerabilities:** {data['total_vulnerabilities']}
**Critical Issues:** {data['critical_vulnerabilities']}
**High Priority Issues:** {data['high_vulnerabilities']}

### Key Findings
- {data['critical_vulnerabilities']} critical vulnerabilities require immediate attention
- {data['high_vulnerabilities']} high-priority issues need resolution within 30 days
- Overall security posture: {'Good' if data['risk_score'] < 30 else 'Moderate' if data['risk_score'] < 60 else 'Needs Improvement'}

### Recommendations
1. Prioritize critical vulnerability remediation
2. Implement security awareness training
3. Review and update security policies
4. Consider additional security controls

### Business Impact
- Potential data breach risk: {'Low' if data['risk_score'] < 30 else 'Medium' if data['risk_score'] < 60 else 'High'}
- Compliance status: {'Compliant' if data['risk_score'] < 40 else 'At Risk'}
- Recommended budget allocation for security improvements
        """.strip(),
        "charts": {
            "vulnerability_distribution": {
                "critical": data['critical_vulnerabilities'],
                "high": data['high_vulnerabilities'],
                "medium": data['medium_vulnerabilities'],
                "low": data['low_vulnerabilities']
            },
            "risk_trend": data['risk_score']
        }
    }


async def generate_technical_report(data: Dict[str, Any], vulnerabilities: List[Dict], assets: List[Dict]) -> Dict[str, Any]:
    """Generate technical detailed report"""
    # Get top vulnerabilities
    top_vulnerabilities = sorted(vulnerabilities, key=lambda x: float(x.get('cvss_score', 0)), reverse=True)[:10]
    
    # Get asset statistics
    asset_types = {}
    for asset in assets:
        asset_type = asset.get('type', 'unknown')
        asset_types[asset_type] = asset_types.get(asset_type, 0) + 1
    
    return {
        "title": "Technical Security Report",
        "summary": f"""
## Technical Security Analysis

### Vulnerability Analysis
**Total Vulnerabilities:** {data['total_vulnerabilities']}
**Average CVSS Score:** {sum(float(v.get('cvss_score', 0)) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0:.1f}

### Top Vulnerabilities
{chr(10).join([f"- {v.get('id', 'Unknown')}: CVSS {v.get('cvss_score', 'Unknown')} - {v.get('title', 'Unknown')}" for v in top_vulnerabilities])}

### Asset Inventory
**Total Assets:** {data['total_assets']}
**Asset Distribution:**
{chr(10).join([f"- {asset_type}: {count}" for asset_type, count in asset_types.items()])}

### Technical Recommendations
1. Implement automated vulnerability scanning
2. Establish patch management process
3. Configure security monitoring tools
4. Review network segmentation
5. Implement access controls
        """.strip(),
        "details": {
            "top_vulnerabilities": top_vulnerabilities,
            "asset_inventory": asset_types,
            "scan_results": data
        }
    }


async def generate_compliance_report(data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate compliance report"""
    return {
        "title": "Compliance Security Report",
        "summary": f"""
## Compliance Status Report

### Overall Compliance Score: {100 - data['risk_score']}%

### Compliance Areas
- **Vulnerability Management:** {'Compliant' if data['critical_vulnerabilities'] == 0 else 'Non-Compliant'}
- **Asset Management:** {'Compliant' if data['total_assets'] > 0 else 'Non-Compliant'}
- **Risk Assessment:** {'Compliant' if data['risk_score'] < 50 else 'Needs Review'}

### Regulatory Requirements
- **Critical Vulnerabilities:** Must be remediated within 30 days
- **High Vulnerabilities:** Must be remediated within 90 days
- **Asset Inventory:** Must be maintained and updated

### Recommendations
1. Address critical vulnerabilities immediately
2. Implement regular vulnerability assessments
3. Maintain asset inventory
4. Document remediation efforts
        """.strip(),
        "compliance_matrix": {
            "vulnerability_management": data['critical_vulnerabilities'] == 0,
            "asset_management": data['total_assets'] > 0,
            "risk_assessment": data['risk_score'] < 50
        }
    }


async def generate_generic_report(data: Dict[str, Any], report_type: str) -> Dict[str, Any]:
    """Generate generic report"""
    return {
        "title": f"{report_type.title()} Security Report",
        "summary": f"""
## {report_type.title()} Security Report

**Generated:** {data['generated_at']}
**Risk Score:** {data['risk_score']}/100
**Total Vulnerabilities:** {data['total_vulnerabilities']}
**Total Assets:** {data['total_assets']}

### Summary
This report provides a comprehensive overview of the current security posture.
        """.strip(),
        "data": data
    }


@router.post("/email")
async def send_email_report(request: EmailReportRequest, background_tasks: BackgroundTasks):
    """Send report via email"""
    try:
        # Generate report
        report_request = ReportRequest(
            report_type=request.report_type,
            date_range=request.date_range or {"start": (datetime.now() - timedelta(days=30)).isoformat(), "end": datetime.now().isoformat()},
            format="html",
            recipients=request.recipients
        )
        
        report = await generate_report(report_request)
        
        # Send email in background
        background_tasks.add_task(send_email, report, request)
        
        return {
            "status": "email_sent",
            "report_id": report["id"],
            "recipients": request.recipients
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def send_email(report: Dict[str, Any], request: EmailReportRequest):
    """Send email with report"""
    try:
        if not all([settings.SMTP_SERVER, settings.SMTP_USERNAME, settings.SMTP_PASSWORD]):
            raise Exception("SMTP configuration not complete")
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = settings.EMAIL_FROM
        msg['To'] = ', '.join(request.recipients)
        msg['Subject'] = request.subject
        
        # Create HTML body
        html_content = f"""
        <html>
        <body>
            <h1>{report['content']['title']}</h1>
            <p><strong>Generated:</strong> {report['data']['generated_at']}</p>
            <p><strong>Risk Score:</strong> {report['data']['risk_score']}/100</p>
            <p><strong>Total Vulnerabilities:</strong> {report['data']['total_vulnerabilities']}</p>
            
            <h2>Summary</h2>
            <pre>{report['content']['summary']}</pre>
            
            <hr>
            <p><em>This report was automatically generated by the Security Management Platform.</em></p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_content, 'html'))
        
        # Add JSON attachment if requested
        if request.include_attachments:
            attachment = MIMEBase('application', 'json')
            attachment.set_payload(json.dumps(report, indent=2))
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', 'attachment', filename=f"security_report_{datetime.now().strftime('%Y%m%d')}.json")
            msg.attach(attachment)
        
        # Send email
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)
            
    except Exception as e:
        print(f"Error sending email: {e}")


@router.post("/schedule")
async def schedule_report(request: ScheduledReportRequest):
    """Schedule automatic report generation"""
    try:
        schedule_data = {
            "id": f"schedule-{len(db.get_all('scheduled_reports')) + 1}",
            "report_type": request.report_type,
            "schedule": request.schedule,
            "recipients": request.recipients,
            "time": request.time,
            "timezone": request.timezone,
            "enabled": request.enabled,
            "created_at": datetime.now().isoformat(),
            "next_run": calculate_next_run(request.schedule, request.time)
        }
        
        db.create("scheduled_reports", schedule_data)
        return schedule_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def calculate_next_run(schedule: str, time: str) -> str:
    """Calculate next run time for scheduled report"""
    now = datetime.now()
    hour, minute = map(int, time.split(':'))
    
    if schedule == "daily":
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
    elif schedule == "weekly":
        # Next Monday at specified time
        days_ahead = 7 - now.weekday()
        next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=days_ahead)
    elif schedule == "monthly":
        # First day of next month
        if now.month == 12:
            next_run = now.replace(year=now.year + 1, month=1, day=1, hour=hour, minute=minute, second=0, microsecond=0)
        else:
            next_run = now.replace(month=now.month + 1, day=1, hour=hour, minute=minute, second=0, microsecond=0)
    else:
        next_run = now + timedelta(days=1)
    
    return next_run.isoformat()


@router.get("/templates")
async def get_report_templates():
    """Get available report templates"""
    try:
        templates = [
            {"id": "executive", "name": "Executive Summary", "description": "High-level overview for leadership"},
            {"id": "technical", "name": "Technical Report", "description": "Detailed technical analysis"},
            {"id": "compliance", "name": "Compliance Report", "description": "Regulatory compliance status"},
            {"id": "vulnerability", "name": "Vulnerability Report", "description": "Detailed vulnerability analysis"},
            {"id": "asset", "name": "Asset Security Report", "description": "Asset security status"}
        ]
        return templates
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_report_history():
    """Get report generation history"""
    try:
        history = db.get_all("reports")
        return history
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scheduled")
async def get_scheduled_reports():
    """Get scheduled reports"""
    try:
        scheduled = db.get_all("scheduled_reports")
        return scheduled
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/scheduled/{schedule_id}")
async def delete_scheduled_report(schedule_id: str):
    """Delete scheduled report"""
    try:
        success = db.delete("scheduled_reports", schedule_id)
        if not success:
            raise HTTPException(status_code=404, detail="Scheduled report not found")
        return {"status": "deleted", "schedule_id": schedule_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 