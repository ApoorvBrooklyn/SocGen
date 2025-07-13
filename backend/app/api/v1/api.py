"""
Main API router for Security Management Platform
"""
from fastapi import APIRouter
from .endpoints import (
    cve_analysis,
    vulnerability_scanner,
    patch_recommendations,
    chat_assistant,
    reports,
    llm_management,
    risk_prioritization,
    asset_inventory,
    ticket_management,
    simulation
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(
    cve_analysis.router,
    prefix="/cve",
    tags=["CVE Analysis"]
)

api_router.include_router(
    vulnerability_scanner.router,
    prefix="/scan",
    tags=["Vulnerability Scanner"]
)

api_router.include_router(
    patch_recommendations.router,
    prefix="/patches",
    tags=["Patch Management"]
)

api_router.include_router(
    chat_assistant.router,
    prefix="/chat",
    tags=["Chat Assistant"]
)

api_router.include_router(
    reports.router,
    prefix="/reports",
    tags=["Reports"]
)

api_router.include_router(
    llm_management.router,
    prefix="/llm",
    tags=["LLM Management"]
)

api_router.include_router(
    risk_prioritization.router,
    prefix="/risk",
    tags=["Risk Prioritization"]
)

api_router.include_router(
    asset_inventory.router,
    prefix="/assets",
    tags=["Asset Inventory"]
)

api_router.include_router(
    ticket_management.router,
    prefix="/tickets",
    tags=["Ticket Management"]
)

api_router.include_router(
    simulation.router,
    prefix="/simulation",
    tags=["Simulation"]
) 