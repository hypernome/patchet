from fastapi import APIRouter, Depends, HTTPException
from api.auth import require_auth
from uuid import uuid4

deployment_router = APIRouter(prefix="/deployment")

@deployment_router.post("/prepare", dependencies=[Depends(require_auth(scopes=["write:deployment"], audience="api.localhost.deploy"))])
async def prepare(payload: dict): 
    if not payload: 
        raise HTTPException(status_code=400, detail="No payload to prepare deployment.")
    
    deployment_id: str = payload.get("deployment_id", str(uuid4()))
    code_version: str = payload.get("code_version", "1.0")
        
    return {
        "deployment_id": deployment_id,
        "code_version": code_version,
        "status": "prepared",
        "next_step": "review"  # Expected next step
    }

@deployment_router.post("/review", dependencies=[Depends(require_auth(scopes=["approve:deployment"], audience="api.localhost.deploy"))])
async def review(payload: dict): 
    if not payload: 
        raise HTTPException(status_code=400, detail="No payload to review deployment.")
    
    deployment_id: str = payload.get("deployment_id", str(uuid4()))
    reviewer: str = payload.get("reviewer", "T8Reviewer")
        
    return {
        "deployment_id": deployment_id,
        "approval_status": "approved",
        "reviewer": reviewer,
        "next_step": "deploy"  # Now safe to deploy
    }

@deployment_router.post("/deploy", dependencies=[Depends(require_auth(scopes=["deploy:production"], audience="api.localhost.deploy"))])
async def deploy(payload: dict): 
    if not payload: 
        raise HTTPException(status_code=400, detail="No deployment payload.")
    
    deployment_id: str = payload.get("deployment_id", str(uuid4()))
        
    return {
        "deployment_id": deployment_id,
        "status": "deployed",
        "attack_succeeded": True  # In OAuth mode
    }