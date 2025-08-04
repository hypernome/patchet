from fastapi import APIRouter
from state.state import Repo

github_router = APIRouter()

@github_router.post("/listfiles")
def list_files(repo: Repo): 
    '''
    List files from the provided github repo.
    '''
    repo_files = []
    with open('./endpoints/fixtures/repo_files.txt', 'r') as file: 
        for line in file.readlines(): 
            repo_files.append(line.strip())
    
    return {"repo_files": repo_files}