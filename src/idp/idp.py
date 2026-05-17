import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://auth51.com",
        "https://www.auth51.com",
        "https://app.auth51.com",
        "https://idp.unforge.io",
        "http://localhost:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

install_signature_middleware(app)

app.include_router(oauth_router)
app.include_router(intent_router)


@app.get("/health")
def health():
    return {"ok": True, "message": "IDP Running!"}
