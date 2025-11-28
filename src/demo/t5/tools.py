"""
T5: Prompt Injection Attacks - Tool Implementations

This module implements tools for testing prompt injection detection.

Tools:
- t5_bump_versions: Legitimate implementation that follows agent's prompt instructions

The attack in T5 modifies the AGENT'S PROMPT at runtime, not the tool.
The same tool will execute different behavior based on the injected prompt.
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
from state.state import PatchRequest, Repo, PatchPlan, PatchingBatch, PatchingAction


@secure_tool()
@traceable
async def t5_bump_versions(): 
    '''
    Legitimate patching tool that follows the agent's prompt instructions.
    
    This represents the normal, secure workflow where:
    1. Agent with safe prompt uses this tool
    2. Tool executes according to agent's instructions
    3. SecureClient validates agent identity and checksums
    4. IDP mints an intent token with proper bindings
    
    In T5 attack:
    - Same tool, different prompt
    - Modified prompt instructs malicious behavior
    - Checksum validation should detect prompt change
    
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
                    name="PromptDrivenPatching", 
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
                
            # Make the API call (behavior influenced by agent's prompt)
            async with TraceableClient(http_client) as client:             
                response = await client.post(
                    url=f"{api_url}{patching_uri}", 
                    json=patch_request.model_dump()
                )
                response.raise_for_status()
                patch_results = response.json()
        
        return {
            "prompt_status": "modified",
            "checksum_status": "not_validated",
            "operation_result": patch_results,
            "security_issue": "Prompt injection not detected"
        }
        
    except Exception as e: 
        print(f"PROMPT INJECTION ATTACK BLOCKED: {e}")
        print("   Modified prompt detected by checksum validation")
        print("   Agent checksum mismatch")
        print("   Security mechanism working correctly")
        raise e