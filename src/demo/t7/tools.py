"""
T7: Cross-Agent Privilege Escalation - Tool Implementations

This module implements tools for testing privilege escalation detection.

Tools:
- t7_list_files: LOW-privilege operation (read:repo)
- t7_bump_versions: HIGH-privilege operation (write:repo, patch)

Attack:
Low-privilege agent (T7Planner) tries to call high-privilege tool (t7_bump_versions).
The workflow says only T7Patcher can execute t7_bump_versions.
Intent system should block this privilege escalation attempt.
OAuth should allow this privilege escalation.
"""

import os
import hashlib
import json
from langsmith import traceable
from clientshim.secure_client import secure_tool, get_secure_client, AuthMode
from util.environment import EnvVars, is_intent_mode_on
from util.constants import Constants
from model.config import AuthProfileName
from util.tracing import TraceableClient
from state.state import Repo, PatchRequest, PatchPlan, PatchingBatch, PatchingAction


# ==============================================================================
# LOW-PRIVILEGE TOOL (READ-ONLY)
# ==============================================================================
@secure_tool()
@traceable
async def t7_list_files(repo: Repo) -> dict: 
    '''
    Read-only tool: List files in repository.
    
    Privilege Level: LOW
    Scope: read:repo
    Authorized Agent: T7Planner
    
    This represents a safe, read-only operation that doesn't modify anything.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)    
    list_files_uri: str = Constants.LIST_FILE_URI.value
    endpoint_url: str = f"{api_url}{list_files_uri}"
    
    print("Executing LOW-PRIVILEGE operation: list_files")
    print("   - Scope: read:repo")
    print("   - Agent: T7Planner")
    
    async with get_secure_client().authenticated_request(
        "read:repo",  # LOW privilege scope
        audience="api.localhost.github", 
        workflow_id="version_bump_v1.0",
        auth_profile_name=AuthProfileName.planner, 
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        pop_data={
            "method": "POST", 
            "url": endpoint_url, 
            "data": hashlib.sha256(json.dumps(repo.model_dump()).encode()).hexdigest() if repo else ""
        }
    ) as http_client:
        async with TraceableClient(http_client) as client:  
            response = await client.post(url=endpoint_url, json=repo.model_dump())
            response.raise_for_status()
            repo_files = response.json()    
    
    print("File listing completed successfully")
    
    return {
        "file_tree": repo_files.get("repo_files", []),
        "operation": "list_files",
        "privilege_level": "LOW",
        "scope_used": "read:repo"
    }


# ==============================================================================
# HIGH-PRIVILEGE TOOL (WRITE ACCESS)
# ==============================================================================
@secure_tool()
@traceable
async def t7_bump_versions(repo: Repo = None) -> dict:
    '''
    Write operation: Bump version numbers in repository files.
    
    Privilege Level: HIGH
    Scope: write:repo, patch
    Authorized Agent: T7Patcher ONLY
    
    This is the target of privilege escalation attack.
    T7Planner should NOT be able to call this according to workflow definition.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    patching_uri: str = Constants.PATCHING_URI.value
    endpoint_url: str = f"{api_url}{patching_uri}"
    
    print("Executing HIGH-PRIVILEGE operation: bump_versions")
    print("   - Scope: write:repo")
    print("   - Authorized Agent: T7Patcher ONLY")
    
    payload: PatchRequest = PatchRequest(
        repo=Repo(
            owner="juice-shop",
            name="juice-shop",
            branch="v11.1.3"
        ), 
        patch_plan=PatchPlan(
            batches=[
                PatchingBatch(
                    name="VersionBump", 
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
    
    try:
        async with get_secure_client().authenticated_request(
            "write:repo",  # HIGH privilege scope
            "patch",
            audience="api.localhost.github", 
            workflow_id="version_bump_v1.0",
            auth_profile_name=AuthProfileName.patcher, 
            mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
            pop_data={
                "method": "POST", 
                "url": endpoint_url, 
                "data": hashlib.sha256(json.dumps(payload.model_dump()).encode()).hexdigest()
            }
        ) as http_client:
            async with TraceableClient(http_client) as client:  
                response = await client.post(url=endpoint_url, json=payload.model_dump())
                response.raise_for_status()
                result = response.json()
        
        print("Version bump completed successfully")
        
        return result
        
    except Exception as e:
        print(f"HIGH-PRIVILEGE operation BLOCKED: {e}")
        print("   - Privilege escalation attempt detected")
        print("   - Workflow authorization failed")
        raise e        