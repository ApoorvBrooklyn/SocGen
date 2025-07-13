"""
LLM Management API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel
from ....services.llm_service import get_llm_service

router = APIRouter()
llm_service = get_llm_service()


class LLMTestRequest(BaseModel):
    test_prompts: List[str]


class LLMResponse(BaseModel):
    prompt: str
    response: str
    success: bool


@router.get("/status")
async def get_llm_status():
    """Get LLM service status"""
    try:
        status = llm_service.get_status()
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/models")
async def get_available_models():
    """Get available LLM models"""
    try:
        models = llm_service.get_available_models()
        return models
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test", response_model=List[LLMResponse])
async def test_llm(request: LLMTestRequest):
    """Test LLM with provided prompts"""
    try:
        results = await llm_service.test_model(request.test_prompts)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_llm_config():
    """Get LLM configuration"""
    try:
        config = {
            "model_name": llm_service.model_name,
            "device": llm_service.device,
            "is_loaded": llm_service.is_loaded,
            "model_info": llm_service.model_info
        }
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_response(prompt: str, max_length: int = 512, temperature: float = 0.7):
    """Generate response using LLM"""
    try:
        response = await llm_service.generate_response(prompt, max_length, temperature)
        return {
            "prompt": prompt,
            "response": response,
            "model_used": llm_service.model_name,
            "parameters": {
                "max_length": max_length,
                "temperature": temperature
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 