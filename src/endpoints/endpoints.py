from fastapi import FastAPI
from .github import github_router
from .sbom import sbom_router

app = FastAPI(root_path="/")

app.include_router(github_router)
app.include_router(sbom_router)