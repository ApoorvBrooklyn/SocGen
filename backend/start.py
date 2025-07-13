#!/usr/bin/env python3
"""
Security Management Platform Backend Startup Script
"""

import uvicorn
import logging
from pathlib import Path
import sys

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.core.config import settings

def main():
    """Start the FastAPI server"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Security Management Platform Backend...")
    logger.info(f"Environment: {'Development' if settings.DEBUG else 'Production'}")
    logger.info(f"LLM Model: {settings.LLM_MODEL_NAME}")
    logger.info(f"LLM Device: {settings.LLM_DEVICE}")
    logger.info(f"Data Directory: {settings.DATA_DIR}")
    
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True
    )

if __name__ == "__main__":
    main() 