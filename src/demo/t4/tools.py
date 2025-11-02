"""
T4: Runtime Code Modification - Tool Implementations

This module implements tools for testing runtime code modification detection.

Tools:
- t4_bump_versions: Legitimate implementation (baseline)

"""

import os
import hashlib
import json
from langsmith import traceable
from clientshim.secure_client import AuthMode, AuthProfileName
from util.environment import EnvVars, is_intent_mode_on
from clientshim.secure_client import get_secure_client, secure_tool
from util.tracing import TraceableClient
from util.constants import Constants
from state.state import PatchRequest, Repo, PatchPlan, PatchingBatch,PatchingAction

# API configuration


@secure_tool()
@traceable
async def t4_bump_versions(): 
    '''
    Legitimate patching tool that obtains an intent token through proper SecureClient authentication.
    
    This represents the normal, secure workflow where:
    1. Agent authenticates through SecureClient
    2. SecureClient validates agent identity and checksums
    3. IDP mints an intent token with proper bindings
    4. Token is used for authorized API call
    
    Returns:
        dict: Patch results from the API
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    patching_uri: str = Constants.PATCHING_URI.value    
    patching_endpoint_url: str = f"{api_url}{patching_uri}"
    patch_results = {}
    
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
                            to_version="na"  
                        )
                    ]
                )
            ]
        )
    )    
    
    # Authenticate through SecureClient
    try: 
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
                
            # Make the legitimate API call
            async with TraceableClient(http_client) as client:             
                response = await client.post(
                    url=f"{api_url}{patching_uri}", 
                    json=patch_request.model_dump()
                )
                response.raise_for_status()
                patch_results = response.json()
        
        return {
            "success": True,
            "attack_succeeded": True,
            "implementation": "modified",
            "checksum_status": "not_validated",
            "operation_result": patch_results,
            "security_issue": "Runtime code modification not detected"
        }
    except Exception as e: 
        print(f"RUNTIME MODIFICATION ATTACK BLOCKED: {e}")
        print("   Modified code detected by checksum validation")
        print("   Agent checksum mismatch")
        print("   Security mechanism working correctly")
        
        return {
            "success": False,
            "attack_succeeded": False,
            "implementation": "modified",
            "checksum_status": "mismatch_detected",
            "error": str(e),
            "security_validation": "Runtime modification detected and blocked"
        }

@secure_tool()
@traceable
async def t4_malicious_bump_versions(): 
    """
    Does nothing. Simulates an attack tool function.
    """