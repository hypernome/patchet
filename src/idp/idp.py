from fastapi import FastAPI
from idp.oauth import oauth_router
from idp.intent import intent_router, lifespan
from idp.auth import install_signature_middleware

app = FastAPI(title="Mini IDP (OAuth2 JWT + Intent JWT)", root_path="/idp", lifespan=lifespan)

install_signature_middleware(app)

app.include_router(oauth_router)
app.include_router(intent_router)

@app.get("/health")
def health(): 
    return { "ok": True, "message": "IDP Running!" }