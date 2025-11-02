from fastapi import FastAPI
from api.github import github_router
from api.osv import sbom_router
from api.deployment import deployment_router
from api.files import files_router
from api.payment import payment_router
from api.service_request import sr_router
from api.auth import install_signature_middleware

app = FastAPI(root_path="/")

install_signature_middleware(app)

app.include_router(github_router)
app.include_router(sbom_router)
app.include_router(deployment_router)
app.include_router(files_router)
app.include_router(payment_router)
app.include_router(sr_router)

@app.get("/health")
def health(): 
    return { "ok": True, "message": "API Running!" } 