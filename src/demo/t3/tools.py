from langsmith import traceable
from clientshim.secure_client import secure_tool, get_secure_client, AuthMode
from util.environment import EnvVars, is_intent_mode_on
from state.state import Repo
from util.constants import Constants
from model.config import AuthProfileName
from util.tracing import TraceableClient
import os, hashlib, json

@secure_tool()
@traceable
async def t3_call_api(repo: Repo) -> dict:
    '''
    Legitimate API call through shim library.
    
    This tool demonstrates baseline functionality with legitimate shim.
    In a real attack scenario, if shim were compromised, agent-level
    validation would still provide defense-in-depth.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)    
    list_files_uri: str = Constants.LIST_FILE_URI.value
    endpoint_url: str = f"{api_url}{list_files_uri}"
    
    async with get_secure_client().authenticated_request(
        "read:repo",
        audience="api.localhost.github",
        workflow_id="supply_chain_test_v1.0",
        auth_profile_name=AuthProfileName.planner,
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        pop_data={
            "method": "POST",
            "url": endpoint_url,
            "data": hashlib.sha256(json.dumps(repo.model_dump()).encode()).hexdigest()
        }
    ) as http_client:
        async with TraceableClient(http_client) as client:
            response = await client.post(url=endpoint_url, json=repo.model_dump())
            response.raise_for_status()
            result = response.json()
    
    print(f"API call successful through shim library")
    
    return {
        "status": "success",
        "test": "supply_chain_security",
        "shim_integrity": "verified"
    }