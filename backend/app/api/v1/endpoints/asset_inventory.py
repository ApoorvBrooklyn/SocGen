"""
Asset Inventory API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel
from ....core.database import get_db

router = APIRouter()
db = get_db()


class AssetRequest(BaseModel):
    name: str
    type: str
    ip_address: str
    os_type: str


@router.get("/")
async def get_assets():
    """Get all assets"""
    try:
        assets = db.get_all("assets")
        return assets
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/")
async def add_asset(asset: AssetRequest):
    """Add new asset"""
    try:
        asset_data = asset.dict()
        asset_data.update({
            "status": "active",
            "risk_score": 50,
            "last_scan": None,
            "vulnerabilities": []
        })
        
        created_asset = db.create("assets", asset_data)
        return created_asset
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{asset_id}")
async def get_asset(asset_id: str):
    """Get specific asset"""
    try:
        asset = db.get_by_id("assets", asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{asset_id}")
async def update_asset(asset_id: str, asset_data: Dict[str, Any]):
    """Update asset"""
    try:
        updated_asset = db.update("assets", asset_id, asset_data)
        if not updated_asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return updated_asset
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str):
    """Delete asset"""
    try:
        success = db.delete("assets", asset_id)
        if not success:
            raise HTTPException(status_code=404, detail="Asset not found")
        return {"status": "deleted", "asset_id": asset_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{asset_id}/vulnerabilities")
async def get_asset_vulnerabilities(asset_id: str):
    """Get vulnerabilities for specific asset"""
    try:
        asset = db.get_by_id("assets", asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        
        return asset.get("vulnerabilities", [])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 