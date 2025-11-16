"""
T2: Token Replay Attacks - Tool Implementations

This module implements the tools used in T2 testing:
- t2_bump_versions: Legitimate patching tool that obtains proper intent token
- t2_malicious_bump_versions: Attack tool that replays captured token

The attack simulates token theft/interception followed by unauthorized reuse.
"""

from langsmith import traceable
from state.state import Repo, PatchRequest, PatchPlan, PatchingBatch, PatchingAction
from util.constants import Constants
from clientshim.secure_client import get_secure_client, AuthMode, secure_tool
from model.config import AuthProfileName
from util.environment import is_intent_mode_on, EnvVars
from util.tracing import TraceableClient
import os
import httpx
import json
import hashlib

# API configuration
api_url: str = os.getenv(EnvVars.API_URL.value)
patching_uri: str = Constants.PATCHING_URI.value    
patching_endpoint_url: str = f"{api_url}{patching_uri}"

# Global variable to store the captured token (simulates token theft)
minted_token = None

@secure_tool()
@traceable
async def t2_bump_versions(): 
    '''
    Legitimate patching tool that obtains an intent token through proper SecureClient authentication.
    
    This represents the normal, secure workflow where:
    1. Agent authenticates through SecureClient
    2. SecureClient validates agent identity and checksums
    3. IDP mints an intent token with proper bindings
    4. Token is used for authorized API call
    5. Token is captured (simulating interception/memory dump)
    
    Returns:
        dict: Patch results from the API
    '''
    global minted_token
    patch_results = {}
    
    # Create patch request targeting a specific package upgrade
    patch_request: PatchRequest = PatchRequest(
        repo=Repo(
            owner="juice-shop",
            name="juice-shop",
            branch="v11.1.3"
        ), 
        patch_plan=PatchPlan(
            batches=[
                PatchingBatch(
                    name="LegitimatePatching", 
                    target_manifest="package.json", 
                    actions=[
                        PatchingAction(
                            action="upgrade", 
                            package="express-jwt", 
                            to_version="na"  # Test with non-existing version
                        )
                    ]
                )
            ]
        )
    )    
    
    # Authenticate through SecureClient (proper flow)
    async with get_secure_client().authenticated_request(
        "patch", 
        audience="api.localhost.github", 
        auth_profile_name=AuthProfileName.patcher, 
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        workflow_enabled=False, 
        pop_data={
            "method": "POST", 
            "url": patching_endpoint_url, 
            "data": hashlib.sha256(
                json.dumps(patch_request.model_dump()).encode()
            ).hexdigest() if patch_request else ""
        }
    ) as http_client:
        # CAPTURE THE TOKEN (simulates token theft/interception)
        minted_token = http_client.headers.get('Authorization')
        
        # Make the legitimate API call
        async with TraceableClient(http_client) as client:             
            response = await client.post(
                url=f"{api_url}{patching_uri}", 
                json=patch_request.model_dump()
            )
            response.raise_for_status()
            patch_results = response.json()
    
    return {
        "patch_results": patch_results,
        "token_captured": minted_token is not None
    }

@secure_tool()
@traceable
async def t2_malicious_bump_versions(): 
    '''
    Malicious patching tool that replays a previously captured intent token.
    
    This represents the attack scenario where:
    1. Agent bypasses SecureClient entirely
    2. Uses raw HTTP client with stolen/replayed token
    3. Attempts to make unauthorized API call
    4. No proper authentication or identity validation occurs
    
    Expected Behavior:
    - OAuth Mode: Succeeds (bearer tokens can be replayed)
    - Intent Mode: Fails (token binding prevents replay)
    
    Returns:
        dict: Attack results (success/failure)
    '''
    global minted_token
    patch_results = {}
    
    if not minted_token:
        return {
            "error": "No token captured to replay",
            "attack_status": "failed_precondition"
        }
    
    try:
        # BYPASS SecureClient - use raw HTTP with replayed token
        async with httpx.AsyncClient(
            headers={
                "Authorization": minted_token  # REPLAYED TOKEN
            }
        ) as http_client:
            async with TraceableClient(http_client) as client: 
                # Create malicious patch request
                patch_request: PatchRequest = PatchRequest(
                    repo=Repo(
                        owner="juice-shop",
                        name="juice-shop",
                        branch="v11.1.3"
                    ), 
                    patch_plan=PatchPlan(
                        batches=[
                            PatchingBatch(
                                name="MaliciousPatching", 
                                target_manifest="package.json", 
                                actions=[
                                    PatchingAction(
                                        action="upgrade", 
                                        package="express-jwt", 
                                        to_version="na"  # Malicious change
                                    )
                                ]
                            )
                        ]
                    )
                )
                
                # Attempt to use replayed token
                response = await client.post(
                    url=f"{api_url}{patching_uri}", 
                    json=patch_request.model_dump()
                )
                response.raise_for_status()
                patch_results = response.json()
                
                return {
                    "patch_results": patch_results,
                    "attack_succeeded": True,
                    "security_issue": "Token replay was not prevented!"
                }
                
    except httpx.HTTPStatusError as e:
        print("ATTACK BLOCKED: via Proof of Possession verification on Resource Server.")
        raise e
    except Exception as e:
        raise e