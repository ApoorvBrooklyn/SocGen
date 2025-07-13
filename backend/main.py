"""
Main FastAPI application for Security Management Platform
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
from datetime import datetime

from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.core.database import get_db
from app.services.llm_service import get_llm_service
from app.services.cve_analysis import get_cve_service
from app.services.vulnerability_scanner import get_scanner_service
from app.api.v1.api import api_router

# Setup logging
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Security Management Platform...")
    
    try:
        # Initialize database
        db = get_db()
        logger.info("Database initialized")
        
        # Initialize services
        llm_service = get_llm_service()
        logger.info(f"LLM service initialized: {llm_service.model_name}")
        
        cve_service = get_cve_service()
        logger.info("CVE analysis service initialized")
        
        scanner_service = get_scanner_service()
        logger.info("Vulnerability scanner service initialized")
        
        # Load initial data if needed
        cves = db.get_all("cves")
        if not cves:
            logger.info("No CVEs found, will load on first request")
        else:
            logger.info(f"Loaded {len(cves)} CVEs from database")
        
        logger.info("Security Management Platform started successfully!")
        
        yield
        
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        raise
    
    # Shutdown
    logger.info("Shutting down Security Management Platform...")
    
    try:
        # Cleanup CVE service
        await cve_service.close()
        logger.info("CVE service closed")
        
        # Cleanup LLM service
        if hasattr(llm_service, 'model') and llm_service.model:
            del llm_service.model
        if hasattr(llm_service, 'tokenizer') and llm_service.tokenizer:
            del llm_service.tokenizer
        logger.info("LLM service cleaned up")
        
        logger.info("Security Management Platform shutdown complete")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# Create FastAPI app
app = FastAPI(
    title="Security Management Platform API",
    description="Advanced security management platform with cybersecurity LLM integration",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.API_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Security Management Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database
        db = get_db()
        cve_count = len(db.get_all("cves"))
        
        # Check LLM service
        llm_service = get_llm_service()
        llm_status = "healthy" if llm_service.is_loaded else "unhealthy"
        
        # Check scanner service
        scanner_service = get_scanner_service()
        scanner_status = "healthy"  # Scanner service is always available
        
        return {
            "status": "healthy" if llm_status == "healthy" else "degraded",
            "timestamp": "2024-01-15T10:30:00Z",
            "services": {
                "llm_service": llm_status,
                "scanner": scanner_status,
                "database": "healthy"
            },
            "statistics": {
                "cves_loaded": cve_count,
                "llm_model": llm_service.model_name,
                "llm_device": getattr(llm_service, 'device', 'mock')
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": "2024-01-15T10:30:00Z"
            }
        )


@app.post("/system/reset")
async def reset_system():
    """Reset system - clear vulnerability data while preserving session data"""
    try:
        db = get_db()
        success = db.clear_vulnerability_data()
        
        if success:
            return {
                "status": "success",
                "message": "System reset completed. Vulnerability data cleared, session data preserved.",
                "timestamp": datetime.now().isoformat(),
                "cleared_collections": [
                    "cves", "vulnerabilities", "scan_results", "patch_recommendations",
                    "patch_deployments", "threat_intelligence", "risk_assessments",
                    "llm_interactions", "github_advisories", "exploit_data", "nvd_data"
                ],
                "preserved_collections": [
                    "chat_sessions", "chat_messages", "reports", "tickets"
                ]
            }
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Failed to reset system",
                    "timestamp": datetime.now().isoformat()
                }
            )
    except Exception as e:
        logger.error(f"System reset failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"System reset failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )


@app.post("/system/reset-all")
async def reset_all_data():
    """Reset all data - clear everything including session data"""
    try:
        db = get_db()
        success = db.clear_all_data()
        
        if success:
            return {
                "status": "success",
                "message": "Complete system reset completed. All data cleared.",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "message": "Failed to reset all data",
                    "timestamp": datetime.now().isoformat()
                }
            )
    except Exception as e:
        logger.error(f"Complete system reset failed: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": f"Complete system reset failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code}
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "status_code": 500}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    ) 