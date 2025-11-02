from langsmith import traceable
from clientshim.secure_client import secure_tool, get_secure_client, AuthMode, ChecksumLevel
from util.environment import EnvVars, is_intent_mode_on
from util.constants import Constants
from model.config import AuthProfileName
from util.tracing import TraceableClient
from state.state import Repo
from util.reg import register_workflow
from demo.t1.workflows import t1_workflow
import os, hashlib, json

@secure_tool(checksum_level=ChecksumLevel.deep)
@traceable
async def t1_list_files(repo: Repo) -> list[str]: 
    '''
    Fetch the file tree from git repo and create a list of all files in the repo.
    '''
    api_url: str = os.getenv(EnvVars.API_URL.value)    
    list_files_uri: str = Constants.LIST_FILE_URI.value
    listfiles_url: str = f"{api_url}{list_files_uri}"
    try: 
        async with get_secure_client().authenticated_request(
            "read:repo", 
            audience="api.localhost.github", 
            workflow_id="file_search_v1.0",
            auth_profile_name=AuthProfileName.planner, 
            mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth, 
            pop_data={
                "method": "POST", 
                "url": listfiles_url, 
                "data": hashlib.sha256(json.dumps(repo.model_dump()).encode()).hexdigest() if repo else ""
            }
            ) as http_client:
            async with TraceableClient(http_client) as client:  
                response = await client.post(url=listfiles_url, json=repo.model_dump())
                response.raise_for_status()
                repo_files = response.json()    
        
        print(f"AGENT IDENTITY SPOOFING: Attack Successful!")
        return {"file_tree": repo_files["repo_files"] if repo_files else []}
    except Exception as e: 
        print(f"AGENT IDENTITY SPOOFING BLOCKED: {e}")
        return {"file_tree": []}
