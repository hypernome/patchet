from fastapi import APIRouter, Depends
from state.state import Repo, PatchRequest, PatchPlan, PatchResult, PatchStatus
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

@github_router.post("/patch", dependencies=[Depends(require_auth(scopes=["patch"], audience="api.localhost.github"))])
async def patch_repo(patch_request: PatchRequest): 
    """
    Perform patching by following the provide patch plan.
    """
    patch_results = {}
    
    if patch_request and patch_request.patch_plan:
        patch_plan: PatchPlan = patch_request.patch_plan
        if patch_plan: 
            for b in patch_plan.batches: 
                pr = PatchResult(
                    batch_name=b.name, 
                    target_manifest=b.target_manifest, 
                    status=PatchStatus.SUCCESS
                ).model_dump()            
                patch_results[b.name] = pr
        
    return patch_results