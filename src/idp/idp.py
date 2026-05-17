import os
from fastapi import FastAPI
from idp.oauth import oauth_router
from idp.intent import intent_router, lifespan
from idp.auth import install_signature_middleware

# root_path is for deployments behind a path-stripping proxy (e.g. nginx mounting
# at /idp/). For host-based routing (ALB, Caddy with idp.host { reverse_proxy }),
# leave empty. Set ROOT_PATH=/idp only if your proxy strips that prefix.
app = FastAPI(
    title="Mini IDP (OAuth2 JWT + Intent JWT)",
    root_path=os.getenv("ROOT_PATH", ""),
    lifespan=lifespan,
)

install_signature_middleware(app)

app.include_router(oauth_router)
app.include_router(intent_router)

@app.get("/health")
def health(): 
    return { "ok": True, "message": "IDP Running!" }