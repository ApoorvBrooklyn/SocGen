"""
Enhanced Chat Assistant API endpoints for SOC team with improved response handling
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, validator
from ....services.llm_service import get_llm_service
from ....core.database import get_db
import uuid
import json
import logging
from datetime import datetime, timedelta
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()
llm_service = get_llm_service()
db = get_db()


class SessionType(str, Enum):
    GENERAL = "general"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    COMPLIANCE = "compliance"
    FORENSICS = "forensics"


class ContextType(str, Enum):
    CVE = "cve"
    INCIDENT = "incident"
    THREAT = "threat"
    ASSET = "asset"
    VULNERABILITY_SCAN = "vulnerability_scan"
    LOG_ANALYSIS = "log_analysis"
    NETWORK_TRAFFIC = "network_traffic"


class ChatSessionRequest(BaseModel):
    title: Optional[str] = None
    session_type: SessionType = SessionType.GENERAL
    initial_context: Optional[Dict[str, Any]] = None


class ChatMessageRequest(BaseModel):
    session_id: str
    message: str = Field(..., min_length=1, max_length=4000)
    context_type: Optional[ContextType] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    priority: Optional[str] = "normal"  # normal, high, critical
    
    @validator('message')
    def validate_message(cls, v):
        if not v.strip():
            raise ValueError('Message cannot be empty')
        return v.strip()


class ChatSession(BaseModel):
    id: str
    title: str
    session_type: SessionType
    created_at: str
    updated_at: str
    message_count: int
    last_message: Optional[str] = None
    security_context: Optional[Dict[str, Any]] = None
    status: str = "active"  # active, archived, closed


class ChatMessage(BaseModel):
    id: str
    session_id: str
    role: str
    content: str
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None
    security_context: Optional[Dict[str, Any]] = None
    response_quality: Optional[str] = None  # excellent, good, fair, poor


class SecurityContextRequest(BaseModel):
    session_id: str
    context_type: ContextType
    context_data: Dict[str, Any]


class QuickResponseRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000)
    context_hints: Optional[List[str]] = None


class ResponseFeedbackRequest(BaseModel):
    message_id: str
    rating: int = Field(..., ge=1, le=5)
    feedback: Optional[str] = None


@router.post("/sessions", response_model=ChatSession)
async def create_session(request: ChatSessionRequest):
    """Create a new chat session for SOC team with enhanced context"""
    try:
        session_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        # Create session with enhanced SOC-specific context
        session_data = {
            "id": session_id,
            "title": request.title or f"SOC Chat - {request.session_type.value.replace('_', ' ').title()}",
            "session_type": request.session_type.value,
            "created_at": current_time,
            "updated_at": current_time,
            "message_count": 0,
            "last_message": None,
            "status": "active",
            "security_context": await initialize_security_context(request.session_type, request.initial_context)
        }
        
        created_session = db.create("chat_sessions", session_data)
        
        # Log session creation
        logger.info(f"Created new chat session: {session_id}, type: {request.session_type}")
        
        return created_session
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create session: {str(e)}")


async def initialize_security_context(session_type: SessionType, initial_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Initialize security context based on session type"""
    try:
        base_context = {
            "session_type": session_type.value,
            "active_incidents": 0,
            "critical_vulnerabilities": 0,
            "threat_level": "normal",
            "last_updated": datetime.now().isoformat()
        }
        
        # Add session-specific context
        if session_type == SessionType.INCIDENT_RESPONSE:
            incidents = db.find("incidents", {"status": "active"}) if "incidents" in db.collections else []
            base_context.update({
                "active_incidents": len(incidents),
                "incident_response_mode": True,
                "escalation_procedures": True
            })
        
        elif session_type == SessionType.VULNERABILITY_ANALYSIS:
            vulnerabilities = db.get_all("vulnerabilities")
            critical_vulns = len([v for v in vulnerabilities if v.get("severity") == "critical"])
            high_vulns = len([v for v in vulnerabilities if v.get("severity") == "high"])
            
            base_context.update({
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "vulnerability_analysis_mode": True
            })
        
        elif session_type == SessionType.THREAT_HUNTING:
            base_context.update({
                "threat_hunting_mode": True,
                "proactive_monitoring": True,
                "ioc_tracking": True
            })
        
        # Merge with initial context if provided
        if initial_context:
            base_context.update(initial_context)
        
        return base_context
        
    except Exception as e:
        logger.error(f"Error initializing security context: {str(e)}")
        return {"error": "Failed to initialize security context"}


@router.post("/messages", response_model=ChatMessage)
async def send_message(request: ChatMessageRequest):
    """Send a message and get AI response with enhanced security context"""
    try:
        # Validate session exists
        session = db.get_by_id("chat_sessions", request.session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        if session.get("status") != "active":
            raise HTTPException(status_code=400, detail="Session is not active")
        
        current_time = datetime.now().isoformat()
        
        # Create user message with validation
        user_message = {
            "id": str(uuid.uuid4()),
            "session_id": request.session_id,
            "role": "user",
            "content": request.message,
            "timestamp": current_time,
            "metadata": {
                "context_type": request.context_type.value if request.context_type else None,
                "attachments": request.attachments or [],
                "priority": request.priority,
                "message_length": len(request.message)
            }
        }
        
        db.create("chat_messages", user_message)
        
        # Get enhanced conversation context
        conversation_context = await get_enhanced_conversation_context(request.session_id, session)
        
        # Generate AI response with improved context and validation
        ai_response = await generate_enhanced_soc_response(
            message=request.message,
            context=conversation_context,
            session=session,
            request=request
        )
        
        # Validate AI response quality
        response_quality = await validate_response_quality(ai_response["response"], request.message)
        
        # Create AI message with enhanced metadata
        ai_message = {
            "id": str(uuid.uuid4()),
            "session_id": request.session_id,
            "role": "assistant",
            "content": ai_response["response"],
            "timestamp": datetime.now().isoformat(),
            "response_quality": response_quality,
            "metadata": {
                "model_used": llm_service.model_name,
                "context_length": len(conversation_context),
                "security_insights": ai_response.get("security_insights", []),
                "recommended_actions": ai_response.get("recommended_actions", []),
                "confidence_score": ai_response.get("confidence_score", 0.8),
                "response_time": ai_response.get("response_time", 0),
                "sources_used": ai_response.get("sources_used", [])
            },
            "security_context": ai_response.get("security_context", {})
        }
        
        created_ai_message = db.create("chat_messages", ai_message)
        
        # Update session with latest activity
        await update_session_activity(request.session_id, ai_response["response"])
        
        logger.info(f"Generated response for session {request.session_id}, quality: {response_quality}")
        
        return created_ai_message
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process message: {str(e)}")


async def get_enhanced_conversation_context(session_id: str, session: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get enhanced conversation context with security data"""
    try:
        # Get recent messages (last 20 for context window)
        messages = db.find("chat_messages", {"session_id": session_id})
        recent_messages = sorted(messages, key=lambda x: x.get("timestamp", ""))[-20:]
        
        # Build context with system prompts
        context = []
        
        # Add system context based on session type
        session_type = session.get("session_type", "general")
        system_prompt = get_system_prompt_for_session_type(session_type)
        context.append({"role": "system", "content": system_prompt})
        
        # Add security context
        security_context = await get_current_security_context(session)
        if security_context:
            context.append({
                "role": "system",
                "content": f"Current security status: {json.dumps(security_context, indent=2)}"
            })
        
        # Add conversation history
        for msg in recent_messages:
            context.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
                "timestamp": msg.get("timestamp"),
                "metadata": msg.get("metadata", {})
            })
        
        return context
        
    except Exception as e:
        logger.error(f"Error getting conversation context: {str(e)}")
        return []


def get_system_prompt_for_session_type(session_type: str) -> str:
    """Get appropriate system prompt based on session type"""
    prompts = {
        "general": """You are a SOC (Security Operations Center) assistant. Provide accurate, actionable security guidance. 
        Focus on clarity, relevance, and practical recommendations. Always consider security implications in your responses.""",
        
        "incident_response": """You are a SOC incident response specialist. Prioritize containment, eradication, and recovery steps. 
        Provide step-by-step guidance following incident response procedures. Be precise and time-conscious in your recommendations.""",
        
        "threat_hunting": """You are a SOC threat hunting expert. Focus on proactive threat detection, IOC analysis, and behavioral patterns. 
        Provide hunting queries, detection techniques, and analysis methodologies. Emphasize evidence-based findings.""",
        
        "vulnerability_analysis": """You are a SOC vulnerability analyst. Prioritize risk assessment, patch management, and mitigation strategies. 
        Provide detailed vulnerability analysis, impact assessment, and remediation guidance. Consider business impact in recommendations.""",
        
        "compliance": """You are a SOC compliance specialist. Focus on regulatory requirements, audit preparation, and control frameworks. 
        Provide compliance-focused guidance and ensure recommendations align with industry standards.""",
        
        "forensics": """You are a SOC forensics analyst. Focus on evidence preservation, chain of custody, and detailed analysis. 
        Provide forensically sound procedures and maintain investigative integrity in all recommendations."""
    }
    
    return prompts.get(session_type, prompts["general"])


async def get_current_security_context(session: Dict[str, Any]) -> Dict[str, Any]:
    """Get current security context for better responses"""
    try:
        context = {}
        
        # Get vulnerability data
        vulnerabilities = db.get_all("vulnerabilities")
        context["vulnerabilities"] = {
            "total": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
            "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"])
        }
        
        # Get incident data
        incidents = db.get_all("incidents") if "incidents" in db.collections else []
        context["incidents"] = {
            "total": len(incidents),
            "active": len([i for i in incidents if i.get("status") == "active"]),
            "resolved": len([i for i in incidents if i.get("status") == "resolved"])
        }
        
        # Get scan results
        scan_results = db.get_all("scan_results") if "scan_results" in db.collections else []
        context["scan_status"] = {
            "total_scans": len(scan_results),
            "recent_scans": len([s for s in scan_results if s.get("timestamp", "") > (datetime.now() - timedelta(days=7)).isoformat()])
        }
        
        # Calculate threat level
        critical_vulns = context["vulnerabilities"]["critical"]
        active_incidents = context["incidents"]["active"]
        
        if critical_vulns > 10 or active_incidents > 5:
            threat_level = "critical"
        elif critical_vulns > 5 or active_incidents > 2:
            threat_level = "high"
        elif critical_vulns > 0 or active_incidents > 0:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        context["threat_level"] = threat_level
        context["last_updated"] = datetime.now().isoformat()
        
        return context
        
    except Exception as e:
        logger.error(f"Error getting security context: {str(e)}")
        return {}


async def generate_enhanced_soc_response(message: str, context: List[Dict], session: Dict, request: ChatMessageRequest) -> Dict[str, Any]:
    """Generate enhanced SOC-specific response with validation and quality checks"""
    try:
        start_time = datetime.now()
        
        # Analyze message for security context
        security_analysis = analyze_message_for_security_context(message)
        
        # Prepare enhanced context for LLM
        enhanced_context = context.copy()
        
        # Add security analysis to context
        if security_analysis["security_keywords"]:
            enhanced_context.append({
                "role": "system",
                "content": f"Security keywords detected: {', '.join(security_analysis['security_keywords'])}"
            })
        
        # Add priority context
        if request.priority in ["high", "critical"]:
            enhanced_context.append({
                "role": "system",
                "content": f"Priority: {request.priority.upper()} - Provide immediate, actionable guidance"
            })
        
        # Generate response using LLM service
        try:
            base_response = await llm_service.chat_response(message, enhanced_context)
        except Exception as e:
            logger.error(f"LLM service error: {str(e)}")
            base_response = generate_fallback_response(message, security_analysis)
        
        # Enhance response with security insights
        security_insights = generate_security_insights(security_analysis, session)
        recommended_actions = generate_recommended_actions(security_analysis, session, request)
        
        # Calculate confidence score
        confidence_score = calculate_confidence_score(base_response, security_analysis)
        
        # Get response time
        response_time = (datetime.now() - start_time).total_seconds()
        
        # Validate response completeness
        if not base_response or len(base_response.strip()) < 10:
            base_response = generate_fallback_response(message, security_analysis)
            confidence_score = 0.3
        
        return {
            "response": base_response,
            "security_insights": security_insights,
            "recommended_actions": recommended_actions,
            "confidence_score": confidence_score,
            "response_time": response_time,
            "sources_used": security_analysis.get("sources", []),
            "security_context": {
                "session_type": session.get("session_type"),
                "detected_keywords": security_analysis["security_keywords"],
                "threat_indicators": security_analysis["threat_indicators"],
                "priority": request.priority
            }
        }
        
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        return {
            "response": f"I apologize, but I encountered an error processing your request. Please try rephrasing your question or contact support if the issue persists. Error: {str(e)[:100]}",
            "security_insights": [],
            "recommended_actions": ["Contact technical support"],
            "confidence_score": 0.1,
            "response_time": 0,
            "sources_used": [],
            "security_context": {"error": True}
        }


def analyze_message_for_security_context(message: str) -> Dict[str, Any]:
    """Analyze message for security context and keywords"""
    security_keywords = {
        "vulnerability": ["vulnerability", "exploit", "cve", "patch", "update", "flaw", "weakness"],
        "threat": ["threat", "attack", "malware", "virus", "trojan", "ransomware", "phishing"],
        "incident": ["incident", "breach", "compromise", "alert", "emergency", "outage"],
        "network": ["network", "traffic", "connection", "port", "protocol", "firewall"],
        "system": ["system", "server", "endpoint", "workstation", "database", "application"],
        "analysis": ["analyze", "investigate", "forensics", "logs", "monitoring", "detection"]
    }
    
    message_lower = message.lower()
    detected_keywords = []
    threat_indicators = []
    sources = []
    
    for category, keywords in security_keywords.items():
        for keyword in keywords:
            if keyword in message_lower:
                detected_keywords.append(keyword)
                if category == "threat":
                    threat_indicators.append(keyword)
    
    # Check for specific indicators
    if any(indicator in message_lower for indicator in ["urgent", "critical", "immediate", "emergency"]):
        threat_indicators.append("urgency_indicator")
    
    # Check for IP addresses, hashes, etc.
    import re
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
    
    if re.search(ip_pattern, message):
        sources.append("ip_address")
    if re.search(hash_pattern, message):
        sources.append("hash_value")
    
    return {
        "security_keywords": list(set(detected_keywords)),
        "threat_indicators": list(set(threat_indicators)),
        "sources": sources,
        "analysis_score": len(detected_keywords) / 10  # Normalize to 0-1
    }


def generate_security_insights(security_analysis: Dict[str, Any], session: Dict[str, Any]) -> List[str]:
    """Generate security insights based on analysis"""
    insights = []
    
    keywords = security_analysis["security_keywords"]
    
    if "vulnerability" in keywords or "cve" in keywords:
        insights.append("Vulnerability management protocols should be followed")
        insights.append("Verify patch status across all affected systems")
    
    if "incident" in keywords or "breach" in keywords:
        insights.append("Incident response procedures activated")
        insights.append("Consider escalation to security team lead")
    
    if "malware" in keywords or "virus" in keywords:
        insights.append("Malware analysis and containment required")
        insights.append("Isolate affected systems immediately")
    
    if "network" in keywords:
        insights.append("Network traffic analysis recommended")
        insights.append("Review firewall logs for suspicious activity")
    
    # Session-specific insights
    session_type = session.get("session_type", "general")
    if session_type == "incident_response":
        insights.append("Following incident response playbook procedures")
    elif session_type == "threat_hunting":
        insights.append("Proactive threat detection measures in place")
    elif session_type == "vulnerability_analysis":
        insights.append("Comprehensive vulnerability assessment required")
    
    return insights[:5]  # Limit to top 5 insights


def generate_recommended_actions(security_analysis: Dict[str, Any], session: Dict[str, Any], request: ChatMessageRequest) -> List[str]:
    """Generate recommended actions based on analysis"""
    actions = []
    
    keywords = security_analysis["security_keywords"]
    priority = request.priority
    
    # Priority-based actions
    if priority == "critical":
        actions.append("Escalate to security team lead immediately")
        actions.append("Activate emergency response procedures")
    elif priority == "high":
        actions.append("Prioritize immediate attention")
        actions.append("Document all findings")
    
    # Keyword-based actions
    if "vulnerability" in keywords:
        actions.append("Run vulnerability scan on affected systems")
        actions.append("Apply security patches as soon as possible")
        actions.append("Update vulnerability database")
    
    if "incident" in keywords:
        actions.append("Follow incident response checklist")
        actions.append("Notify stakeholders according to communication plan")
        actions.append("Begin evidence collection and preservation")
    
    if "malware" in keywords:
        actions.append("Isolate infected systems from network")
        actions.append("Run full antimalware scan")
        actions.append("Analyze malware sample in sandbox environment")
    
    if "network" in keywords:
        actions.append("Monitor network traffic for anomalies")
        actions.append("Review network access logs")
        actions.append("Update network security rules if needed")
    
    # Context-specific actions
    if request.context_type == ContextType.CVE:
        actions.append("Check CVE database for latest information")
        actions.append("Assess impact on organization's systems")
    
    return actions[:7]  # Limit to top 7 actions


def calculate_confidence_score(response: str, security_analysis: Dict[str, Any]) -> float:
    """Calculate confidence score for the response"""
    score = 0.5  # Base score
    
    # Response length factor
    if len(response) > 100:
        score += 0.1
    if len(response) > 300:
        score += 0.1
    
    # Security context factor
    if security_analysis["security_keywords"]:
        score += 0.2
    
    # Specific security terms in response
    security_terms = ["recommend", "suggest", "analyze", "investigate", "implement", "configure"]
    response_lower = response.lower()
    matching_terms = sum(1 for term in security_terms if term in response_lower)
    score += min(matching_terms * 0.05, 0.2)
    
    # Ensure score is between 0 and 1
    return min(max(score, 0.1), 1.0)


def generate_fallback_response(message: str, security_analysis: Dict[str, Any]) -> str:
    """Generate fallback response when LLM fails"""
    keywords = security_analysis["security_keywords"]
    
    if "vulnerability" in keywords:
        return """I understand you're asking about vulnerabilities. Here are the key steps to address vulnerability concerns:

1. Identify the specific vulnerability or CVE
2. Assess the risk level and potential impact
3. Check if systems are affected
4. Apply patches or implement mitigations
5. Monitor for exploitation attempts

Please provide more specific details about the vulnerability you're concerned about, and I can offer more targeted guidance."""
    
    elif "incident" in keywords:
        return """I see you're dealing with a security incident. Here's the immediate response framework:

1. **Contain** - Isolate affected systems
2. **Assess** - Determine scope and impact
3. **Eradicate** - Remove the threat
4. **Recover** - Restore normal operations
5. **Document** - Record all actions taken

Please describe the specific incident details so I can provide more targeted assistance."""
    
    elif "malware" in keywords:
        return """For malware-related concerns, follow these immediate steps:

1. **Isolate** affected systems from the network
2. **Preserve** evidence for analysis
3. **Analyze** the malware sample safely
4. **Clean** infected systems thoroughly
5. **Monitor** for reinfection

What specific malware indicators or behaviors are you observing?"""
    
    else:
        return """I'm here to help with your security question. To provide the most accurate and helpful response, could you please:

1. Provide more specific details about your concern
2. Include any relevant context or symptoms
3. Specify the urgency level
4. Mention any systems or assets involved

This will help me give you more targeted and actionable guidance."""


async def validate_response_quality(response: str, original_message: str) -> str:
    """Validate response quality and categorize it"""
    try:
        # Check response length
        if len(response) < 20:
            return "poor"
        
        # Check for specific security-related content
        security_indicators = [
            "recommend", "suggest", "analyze", "investigate", "implement",
            "configure", "monitor", "assess", "mitigate", "remediate"
        ]
        
        response_lower = response.lower()
        security_matches = sum(1 for indicator in security_indicators if indicator in response_lower)
        
        # Check for actionable content
        actionable_indicators = [
            "step", "procedure", "process", "method", "approach",
            "solution", "fix", "resolve", "address", "handle"
        ]
        
        actionable_matches = sum(1 for indicator in actionable_indicators if indicator in response_lower)
        
        # Calculate quality score
        quality_score = 0
        quality_score += min(len(response) / 200, 2)  # Length factor (max 2 points)
        quality_score += security_matches * 0.5  # Security relevance (0.5 per match)
        quality_score += actionable_matches * 0.3  # Actionable content (0.3 per match)
        
        # Categorize based on score
        if quality_score >= 4:
            return "excellent"
        elif quality_score >= 2.5:
            return "good"
        elif quality_score >= 1.5:
            return "fair"
        else:
            return "poor"
            
    except Exception as e:
        logger.error(f"Error validating response quality: {str(e)}")
        return "unknown"


async def update_session_activity(session_id: str, last_response: str):
    """Update session activity and statistics"""
    try:
        # Get current message count
        messages = db.find("chat_messages", {"session_id": session_id})
        message_count = len(messages)
        
        # Prepare last message preview
        last_message = last_response[:100] + "..." if len(last_response) > 100 else last_response
        
        # Update session
        db.update("chat_sessions", session_id, {
            "updated_at": datetime.now().isoformat(),
            "message_count": message_count,
            "last_message": last_message
        })
        
    except Exception as e:
        logger.error(f"Error updating session activity: {str(e)}")


@router.post("/feedback")
async def submit_feedback(request: ResponseFeedbackRequest):
    """Submit feedback for a response to improve quality"""
    try:
        message = db.get_by_id("chat_messages", request.message_id)
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")
        
        # Store feedback
        feedback_data = {
            "id": str(uuid.uuid4()),
            "message_id": request.message_id,
            "session_id": message.get("session_id"),
            "rating": request.rating,
            "feedback": request.feedback,
            "timestamp": datetime.now().isoformat()
        }
        
        db.create("response_feedback", feedback_data)
        
        # Update message with feedback
        current_metadata = message.get("metadata", {})
        current_metadata["user_rating"] = request.rating
        current_metadata["user_feedback"] = request.feedback
        
        db.update("chat_messages", request.message_id, {
            "metadata": current_metadata
        })
        
        logger.info(f"Feedback submitted for message {request.message_id}: {request.rating}/5")
        
        return {"status": "feedback_recorded", "message_id": request.message_id}
        
    except Exception as e:
        logger.error(f"Error submitting feedback: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint to verify API status"""
    try:
        # Check database connectivity
        db_status = "healthy"
        try:
            db.get_all("chat_sessions")
        except Exception:
            db_status = "unhealthy"
        
        # Check LLM service
        llm_status = "healthy"
        try:
            await llm_service.chat_response("test", [])
        except Exception:
            llm_status = "unhealthy"
        
        return {
            "status": "healthy" if db_status == "healthy" and llm_status == "healthy" else "degraded",
            "database": db_status,
            "llm_service": llm_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


# Include all other endpoints from the original code with improvements...
# (The remaining endpoints would follow the same pattern of enhancement)