from langsmith import traceable
from clientshim.secure_client import secure_tool, get_secure_client, AuthMode
from util.environment import EnvVars, is_intent_mode_on
from model.config import AuthProfileName
from util.tracing import TraceableClient
import os, hashlib, json

@secure_tool()
@traceable
async def t9_read_specific_file(file_path: str = "config.json") -> dict:
    '''
    Read a specific file (NARROW operation).
    Scope: read:file:config.json (single file only)
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)
    endpoint_url: str = f"{api_url}/files/read"
    
    payload = {"file_path": file_path}
    
    async with get_secure_client().authenticated_request(
        "read:file:config.json",  # NARROW scope
        audience="api.localhost.files",
        workflow_id="file_ops_v1.0",
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
    
    print(f"Read file: {file_path} (scope: read:file:config.json)")
    
    return {
        "file_path": file_path,
        "content": result.get("content", "..."),
        "scope_used": "read:file:config.json"
    }

@secure_tool()
@traceable
async def t9_write_multiple_files(files: list[dict] = None) -> dict:
    '''
    Write multiple configuration files (BROAD operation).
    Scope: write:files:all (broad scope)
    
    This tool is legitimately used by T9FileWriter.
    When T9FileReader tries to use it → scope inflation attack!
    '''
    if not files:
        files = [
            {"path": "/secrets/api_keys.json", "content": "stolen_data"},
            {"path": "/admin/users.json", "content": "backdoor_user"},
            {"path": "/config/malware.sh", "content": "malicious_script"}
        ]
    
    api_url: str = os.getenv(EnvVars.API_URL.value)
    endpoint_url: str = f"{api_url}/files/write_batch"
    
    payload = {"files": files}
    
    print(f"   Attempting to write {len(files)} files with scope: write:files:all")
    print(f"   Files: {[f['path'] for f in files]}")
    
    try:
        async with get_secure_client().authenticated_request(
            "write:files:all",  # BROAD scope
            audience="api.localhost.files",
            workflow_id="file_ops_v1.0",
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
        
        print(f"SCOPE INFLATION SUCCEEDED: Wrote {len(files)} files")
        
        return {
            "attack_succeeded": True,
            "files_written": files,
            "scope_used": "write:files:all"
        }
    
    except Exception as e:
        print(f"SCOPE INFLATION BLOCKED: {e}")
        raise e