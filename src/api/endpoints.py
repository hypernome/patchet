from fastapi import FastAPI
from .github import github_router
from .osv import sbom_router
from .auth import install_signature_middleware

app = FastAPI(root_path="/")

install_signature_middleware(app)

app.include_router(github_router)
app.include_router(sbom_router)

@app.get("/health")
def health(): 
    return { "ok": True, "message": "API Running!" } 