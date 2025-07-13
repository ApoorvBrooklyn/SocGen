"""
LLM Service for Security Management Platform
Simplified version without torch dependencies for initial setup
"""
import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from ..core.config import settings
from ..core.logging import log_llm_interaction, get_logger
import os
import httpx

logger = get_logger(__name__)


class LLMService:
    """LLM service using Groq API"""
    def __init__(self):
        self.model_name = settings.GROQ_MODEL
        self.api_key = "" ## Upload your own API key here
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY not configured in settings. Please set it in your .env file.")
        self.is_loaded = True
        self.model_info = {
            "model_name": self.model_name,
            "provider": "groq",
            "is_loaded": True,
        }

    async def generate_response(self, prompt: str, max_length: int = None, temperature: float = None) -> str:
        """Call Groq API to generate a chat response"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": max_length or 256,
            "temperature": temperature or 0.7
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.api_url, headers=headers, json=payload, timeout=60)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"Error generating response from Groq: {str(e)}"
    
    async def analyze_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze CVE data and provide security insights"""
        
        # Create a comprehensive prompt for CVE analysis
        prompt = f"""
As a cybersecurity expert, analyze this CVE and provide detailed insights:

CVE ID: {cve_data.get('id', 'Unknown')}
Title: {cve_data.get('title', 'Unknown')}
Description: {cve_data.get('description', 'Unknown')}
CVSS Score: {cve_data.get('cvss_score', 'Unknown')}
Severity: {cve_data.get('severity', 'Unknown')}
Affected Products: {', '.join(cve_data.get('affected_products', []))}

Please provide:
1. Exploit Method: How this vulnerability can be exploited
2. Business Impact: What are the potential business consequences
3. Layman Explanation: Explain this vulnerability in simple terms for management
4. Remediation Steps: Specific steps to fix this vulnerability
5. Risk Assessment: Overall risk level and urgency

Analysis:
"""
        
        response = await self.generate_response(prompt, max_length=800)
        
        # Parse the response to extract structured information
        analysis = self._parse_cve_analysis(response)
        
        return {
            "cve_id": cve_data.get('id'),
            "llm_analysis": response,
            "structured_analysis": analysis,
            "confidence_score": 0.85,  # Default confidence
            "model_used": self.model_name,
            "timestamp": time.time()
        }
    
    def _parse_cve_analysis(self, response: str) -> Dict[str, str]:
        """Parse LLM response to extract structured information"""
        sections = {
            "exploit_method": "",
            "business_impact": "",
            "layman_explanation": "",
            "remediation_steps": "",
            "risk_assessment": ""
        }
        
        # Simple parsing based on section headers
        current_section = None
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Check for section headers
            if "1. Exploit Method:" in line:
                current_section = "exploit_method"
                sections[current_section] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif "2. Business Impact:" in line:
                current_section = "business_impact"
                sections[current_section] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif "3. Layman Explanation:" in line:
                current_section = "layman_explanation"
                sections[current_section] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif "4. Remediation Steps:" in line:
                current_section = "remediation_steps"
                sections[current_section] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif "5. Risk Assessment:" in line:
                current_section = "risk_assessment"
                sections[current_section] = line.split(":", 1)[1].strip() if ":" in line else ""
            elif current_section and line:
                # Append to current section
                sections[current_section] += " " + line
        
        return sections
    
    async def generate_patch_recommendation(self, cve_data: Dict[str, Any], os_type: str) -> Dict[str, Any]:
        """Generate patch recommendations for a CVE"""
        
        prompt = f"""
Generate patch recommendations for this CVE on {os_type}:

CVE ID: {cve_data.get('id', 'Unknown')}
Title: {cve_data.get('title', 'Unknown')}
Description: {cve_data.get('description', 'Unknown')}

Provide specific patch recommendations for {os_type} systems.
"""
        
        response = await self.generate_response(prompt)
        
        return {
            "cve_id": cve_data.get('id'),
            "os_type": os_type,
            "recommendations": response,
            "patch_commands": [
                f"# Update package manager",
                f"sudo apt update  # For Ubuntu/Debian",
                f"sudo yum update  # For CentOS/RHEL",
                f"# Install security updates",
                f"sudo apt upgrade  # For Ubuntu/Debian",
                f"sudo yum upgrade  # For CentOS/RHEL"
            ],
            "manual_steps": [
                "1. Check for available security patches",
                "2. Apply vendor-recommended updates",
                "3. Verify patch installation",
                "4. Test system functionality",
                "5. Monitor for any issues"
            ],
            "timestamp": time.time()
        }
    
    async def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prioritize vulnerabilities based on risk assessment"""
        
        prompt = f"""
Prioritize these {len(vulnerabilities)} vulnerabilities based on risk:

{chr(10).join([f"- {v.get('id', 'Unknown')}: {v.get('title', 'Unknown')} (CVSS: {v.get('cvss_score', 'Unknown')})" for v in vulnerabilities])}

Provide prioritization based on:
1. CVSS Score
2. Exploitability
3. Business Impact
4. Asset Criticality
"""
        
        response = await self.generate_response(prompt)
        
        # Mock prioritization logic
        prioritized = sorted(vulnerabilities, key=lambda x: float(x.get('cvss_score', 0)), reverse=True)
        
        return {
            "prioritized_vulnerabilities": prioritized,
            "prioritization_logic": response,
            "high_priority": [v for v in prioritized if float(v.get('cvss_score', 0)) >= 7.0],
            "medium_priority": [v for v in prioritized if 4.0 <= float(v.get('cvss_score', 0)) < 7.0],
            "low_priority": [v for v in prioritized if float(v.get('cvss_score', 0)) < 4.0],
            "timestamp": time.time()
        }
    
    async def chat_response(self, message: str, context: List[Dict[str, Any]] = None) -> str:
        """Generate chat response for security assistant with conversation context"""
        
        # Build conversation context
        conversation_history = ""
        if context:
            for msg in context[-5:]:  # Last 5 messages for context
                role = msg.get('role', 'unknown')
                content = msg.get('content', '')
                if role == 'user':
                    conversation_history += f"User: {content}\n"
                elif role == 'assistant':
                    conversation_history += f"Assistant: {content}\n"
        
        prompt = f"""
You are a cybersecurity assistant. Previous conversation context:
{conversation_history if conversation_history else 'No previous context'}

Current user message: {message}

Provide a helpful, professional response focused on cybersecurity topics. 
Consider the conversation history to provide contextual and relevant responses.
"""
        
        return await self.generate_response(prompt)
    
    async def generate_report_summary(self, report_data: Dict[str, Any], report_type: str) -> str:
        """Generate summary for security reports"""
        
        prompt = f"""
Generate a summary for a {report_type} security report:

Report Data: {report_data}

Create a concise executive summary highlighting key findings and recommendations.
"""
        
        return await self.generate_response(prompt)
    
    def get_status(self) -> Dict[str, Any]:
        """Get LLM service status"""
        return self.model_info
    
    def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models"""
        return [
            {
                "name": "microsoft/DialoGPT-medium",
                "type": "causal_lm",
                "description": "Medium-sized conversational model",
                "parameters": "345M",
                "status": "available"
            },
            {
                "name": "gpt2",
                "type": "causal_lm", 
                "description": "GPT-2 model for text generation",
                "parameters": "124M",
                "status": "available"
            }
        ]
    
    async def test_model(self, test_prompts: List[str]) -> List[Dict[str, Any]]:
        """Test the model with sample prompts"""
        results = []
        
        for prompt in test_prompts:
            try:
                start_time = time.time()
                response = await self.generate_response(prompt)
                processing_time = time.time() - start_time
                
                results.append({
                    "prompt": prompt,
                    "response": response,
                    "processing_time": processing_time,
                    "status": "success"
                })
            except Exception as e:
                results.append({
                    "prompt": prompt,
                    "response": str(e),
                    "processing_time": 0,
                    "status": "error"
                })
        
        return results


# Global LLM service instance
_llm_service = None

def get_llm_service() -> LLMService:
    """Get or create LLM service instance"""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service 