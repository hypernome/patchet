from langsmith import traceable
from clientshim.secure_client import secure_tool, get_secure_client, AuthMode
from util.environment import EnvVars, is_intent_mode_on
from model.config import AuthProfileName
from util.tracing import TraceableClient
import os, hashlib, json, time

@secure_tool()
@traceable
async def t11_start_request(request_id: str = "req_t11_123") -> dict:
    '''
    Start a request - creates root of delegation chain.
    This is the first step that initiates the workflow.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    endpoint_url: str = f"{api_url}/sr/start"
    
    payload = {
        "request_id": request_id,
        "initiated_by": "T11Initiator",
        "timestamp": time.time()
    }
    
    async with get_secure_client().authenticated_request(
        "sr:start",
        audience="api.localhost.sr",
        workflow_id="approval_chain_v1.0",
        auth_profile_name=AuthProfileName.planner,
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        pop_data={
            "method": "POST",
            "url": endpoint_url,
            "data": hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        }
    ) as http_client:
        async with TraceableClient(http_client) as client:
            response = await client.post(url=endpoint_url, json=payload)
            response.raise_for_status()
            result = response.json()
    
    print(f"Request started: {request_id}")
    
    return {
        "request_id": request_id,
        "status": "initiated",
        "delegation_chain": ["T11Initiator"]
    }

@secure_tool()
@traceable
async def t11_approve_request(request_id: str = "req_t11_123") -> dict:
    '''
    Approve request - required second step in delegation chain.
    This step provides authorization for execution.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    endpoint_url: str = f"{api_url}/sr/approve"
    
    payload = {
        "request_id": request_id,
        "approved_by": "T11Approver",
        "timestamp": time.time()
    }
    
    async with get_secure_client().authenticated_request(
        "sr:approve",
        audience="api.localhost.sr",
        workflow_id="approval_chain_v1.0",
        auth_profile_name=AuthProfileName.planner,
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        pop_data={
            "method": "POST",
            "url": endpoint_url,
            "data": hashlib.sha256(json.dumps(payload).encode()).hexdigest()
        }
    ) as http_client:
        async with TraceableClient(http_client) as client:
            response = await client.post(url=endpoint_url, json=payload)
            response.raise_for_status()
            result = response.json()
    
    print(f"Request approved: {request_id}")
    
    return {
        "request_id": request_id,
        "status": "approved",
        "approver": "T11Approver"
    }

@secure_tool()
@traceable
async def t11_skip_approval(request_id: str = "req_t11_123") -> dict:
    """
    MALICIOUS TOOL: Simulates skipping the approval step.
    
    This represents the attacker's attempt to bypass the required approval.
    The delegation chain will be: [Initiator, MaliciousExecutor]
    Missing: Approver (the required approval step)
    """
    print("ATTACK: Attempting to skip approval step!")
    print(f"Delegation chain will be incomplete: [Initiator → MaliciousExecutor]")
    print(f"Missing required step: Approver")
    
    return {
        "attack_type": "delegation_chain_bypass",
        "skipped_step": "approve_request",
        "incomplete_chain": ["T11Initiator", "T11MaliciousExecutor"],
        "should_include": ["T11Initiator", "T11Approver", "T11MaliciousExecutor"]
    }

@secure_tool()
@traceable
async def t11_execute_operation(request_id: str = "req_t11_123") -> dict:
    '''
    Execute operation - final step that REQUIRES approval in delegation chain.
    
    In OAuth: May succeed if token has scope, regardless of approval
    In Intent: Must have complete delegation chain with approval step
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    endpoint_url: str = f"{api_url}/sr/execute"
    
    payload = {
        "request_id": request_id,
        "timestamp": time.time()
    }
    
    print(f"Attempting execution with current delegation chain...")
    
    try:
        # This will fail in Intent mode if delegation chain is incomplete
        # The IDP will check:
        # 1. Is "approve_request" step completed?
        # 2. Is approval step in delegation chain?
        # 3. Does delegation chain match workflow requirements?
        async with get_secure_client().authenticated_request(
            "sr:execute",
            audience="api.localhost.sr",
            workflow_id="approval_chain_v1.0",
            auth_profile_name=AuthProfileName.patcher,
            mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
            pop_data={
                "method": "POST",
                "url": endpoint_url,
                "data": hashlib.sha256(json.dumps(payload).encode()).hexdigest()
            }
        ) as http_client:
            async with TraceableClient(http_client) as client:
                response = await client.post(url=endpoint_url, json=payload)
                response.raise_for_status()
                result = response.json()
        
        print(f"DELEGATION CHAIN BYPASS SUCCEEDED!")
        print(f"   Operation executed without required approval step")
        
        return {
            "request_id": request_id,
            "bypassed_approval": True,
            "status": "executed_without_approval"
        }
    
    except Exception as e:
        print(f"DELEGATION CHAIN BYPASS BLOCKED: {e}")
        print(f"   Intent system detected incomplete delegation chain")
        raise e