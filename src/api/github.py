from fastapi import APIRouter, Depends
from state.state import Repo
from pathlib import Path
from api.auth import require_auth

github_router = APIRouter(prefix="/github")

@github_router.post("/listfiles", dependencies=[Depends(require_auth(scopes=["read:repo"], audience="api.localhost.github"))])
async def list_files(repo: Repo): 
    '''
    List files from the provided github repo.
    '''
    repo_files = []
    FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
    with open(FIXTURES_DIR / 'repo_files.txt', 'r') as file: 
        for line in file.readlines(): 
            repo_files.append(line.strip())
    
    return {"repo_files": repo_files}