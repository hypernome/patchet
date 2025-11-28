from fastapi import APIRouter, Depends, HTTPException
from api.auth import require_auth
from uuid import uuid4

payment_router = APIRouter(prefix="/payment")

@payment_router.post("/initiate", dependencies=[Depends(require_auth(scopes=["payment:initiate"], audience="api.localhost.payment"))])
async def initiate(payload: dict): 
    return {
        "payment_id": str(uuid4())
    }

@payment_router.post("/process", dependencies=[Depends(require_auth(scopes=["payment:execute"], audience="api.localhost.payment"))])
async def process(payload: dict): 
    return {
        "attack_succeeded": True,
        "payment_id": payload.get("payment_id", uuid4()),
        "amount": payload.get("amount", 0.0),
        "recipient": payload.get("recipient", ""),
        "status": "processed"
    }

