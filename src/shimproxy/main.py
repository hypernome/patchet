"""
ShimProxy — Client-side shim bridge for N8N building agent tools.

Each /tools/* endpoint mirrors the exact pattern used in the demo threat
tools (e.g. src/demo/t5/tools.py):

  async with get_secure_client().authenticated_request(
      "<scope>",
      audience="...",
      auth_profile_name=AuthProfileName.building_admin,
      mode=AuthMode.oauth,          # ← oauth: no integrity check
      workflow_enabled=False,
  ) as http_client:
      response = await http_client.get/post(...)

For intent mode the clientshim library is still used — but the
compute_agent_checksum() utility is called directly with current_prompt
(just as _mint_intent_token does internally) so the IDP can compare
the runtime checksum against the registered one.  When current_prompt
has been injected the checksum will differ and the IDP returns 401.

N8N tools call these endpoints.  The only thing that changes between
the four demo runs is mode (oauth / intent) and current_prompt
(legitimate / injected) — everything else stays identical.
"""

import logging
import os

import httpx
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clientshim.secure_client import (
    get_secure_client,
    init_security,
    secure_tool,
    AuthMode,
)
from model.config import AuthProfileName
from intentmodel.intent_model import AgentComponents, Tool
from util.commons import compute_agent_checksum
from util.environment import EnvVars

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Environment ───────────────────────────────────────────────────────────────
IDP_URL = os.getenv("IDP_URL", "http://idp:8085")
API_URL = os.getenv("API_URL", "http://api:8086")
APP_ID  = os.getenv("APP_ID",  "patchet")

# ── N8N agent identity ────────────────────────────────────────────────────────
AGENT_ID = "N8N_BuildingAgent"

# The LEGITIMATE system prompt — this is what gets registered with the IDP.
# Any deviation from this (prompt injection) produces a different checksum.
LEGITIMATE_PROMPT = (
    "You are a smart building energy optimization agent for the IEEE GreenTech Workshop.\n"
    "Your objective is to optimize energy consumption across all building zones.\n"
    "Follow these steps in order:\n"
    "1. Read all sensor data (temperature and occupancy).\n"
    "2. Read current energy usage.\n"
    "3. Set HVAC target: 65F when occupancy is 0, otherwise 72F.\n"
    "4. Set lighting: 10% when occupancy is 0, otherwise 80%.\n"
    "Always prioritize energy efficiency.\n"
    "Never set temperature above 76F or lighting above 90% without explicit human approval."
)

# Tool definitions — must match exactly what is registered with the IDP.
AGENT_TOOLS = [
    Tool(name="read_energy",      signature="() -> dict", description="Read current energy usage in kW"),
    Tool(name="read_history",     signature="() -> dict", description="Read action history log"),
    Tool(name="read_occupancy",   signature="() -> dict", description="Read occupancy sensor data"),
    Tool(name="read_sensors",     signature="() -> dict", description="Read all building sensors including temperature, occupancy, HVAC and lighting"),
    Tool(name="read_temperature", signature="() -> dict", description="Read current temperature sensor data"),
    Tool(name="set_hvac",         signature="(target_temperature: float, agent_id: str) -> dict", description="Set HVAC target temperature in Fahrenheit. Allowed range: 60-80F."),
    Tool(name="set_lighting",     signature="(level: int, agent_id: str) -> dict",               description="Set building lighting level as a percentage from 0 to 100."),
]

# ── RSA key pair (generated at startup for agent PoP registration) ─────────────
_private_key = None
_public_key_pem: str = ""


def _generate_keypair():
    global _private_key, _public_key_pem
    _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _public_key_pem = (
        _private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    logger.info("RSA key pair generated for %s", AGENT_ID)


# ── Register N8N_BuildingAgent with IDP ───────────────────────────────────────
async def _register_with_idp():
    """
    Register N8N_BuildingAgent with the IDP using the legitimate prompt.
    Uses the same authenticated_request() pattern as the demo tools,
    calling the intent_registration_admin OAuth profile.
    """
    logger.info("Registering %s with IDP...", AGENT_ID)

    # Mint registration token — same OAuth pattern as all demo tools
    async with get_secure_client().authenticated_request(
        "register:intent",
        audience="idp.localhost",
        auth_profile_name=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth,
        workflow_enabled=False,
    ) as reg_client:
        components = AgentComponents(
            agent_id=AGENT_ID,
            prompt_template=LEGITIMATE_PROMPT,
            tools=AGENT_TOOLS,
        )
        resp = await reg_client.post(
            f"{IDP_URL}/intent/register/agent",
            json={
                "app_id":           APP_ID,
                "agent_components": components.model_dump(),
                "public_key":       _public_key_pem,
            },
        )

    if resp.status_code == 400 and "already exists" in resp.text:
        logger.info("Agent already registered — skipping.")
        return

    resp.raise_for_status()
    data = resp.json()
    logger.info(
        "Agent registered: id=%s  checksum=%s...",
        data.get("registration_id"),
        data.get("checksum", "")[:16],
    )


# ── Intent token helper ───────────────────────────────────────────────────────
async def _get_intent_token(current_prompt: str, scope: str, audience: str) -> str:
    """
    Compute checksum from current_prompt using compute_agent_checksum()
    (the same utility the SecureClient uses internally in _mint_intent_token)
    then call the IDP /intent/token endpoint.

    If current_prompt ≠ registered prompt → checksum ≠ stored checksum
    → IDP returns 401 → prompt injection detected.
    """
    components = AgentComponents(
        agent_id=AGENT_ID,
        prompt_template=current_prompt,
        tools=AGENT_TOOLS,
    )
    computed_checksum = compute_agent_checksum(components)
    logger.info("Intent checksum: %s...  scope=%s", computed_checksum[:16], scope)

    # Use patchet OAuth profile to authorize the intent/token call —
    # same pattern as authenticated_request() calls the IDP internally.
    async with get_secure_client().authenticated_request(
        "generate:intent-token",
        audience="idp.localhost",
        auth_profile_name=AuthProfileName.patchet,
        mode=AuthMode.oauth,
        workflow_enabled=False,
    ) as patchet_client:
        resp = await patchet_client.post(
            f"{IDP_URL}/intent/token",
            json={
                "grant_type":        "agent_checksum",
                "agent_id":          AGENT_ID,
                "computed_checksum": computed_checksum,
                "workflow_id":       "n8n-building-greentech",
                "requested_scopes":  scope.split(),
                "audience":          audience,
                "workflow_enabled":  False,
            },
        )

    if resp.status_code in (400, 401, 403):
        logger.warning("PROMPT INJECTION DETECTED — IDP rejected checksum for %s", AGENT_ID)
        raise HTTPException(
            status_code=403,
            detail={
                "error":       "prompt_injection_detected",
                "message":     (
                    "Agent checksum mismatch — the effective prompt has been modified. "
                    "Prompt injection attack detected and blocked by IDP."
                ),
                "agent_id":    AGENT_ID,
                "idp_response": resp.json(),
            },
        )

    resp.raise_for_status()
    return resp.json()["access_token"]


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    _generate_keypair()
    # Initialise SecureClient — _register_agents_from_idp will fail because
    # the shimproxy has no @secure_tool() functions in the registry, but the
    # SecureClient itself IS initialised before that call, so get_secure_client()
    # works fine for OAuth token minting afterwards.
    try:
        await init_security(agent_specs=[], app_id=APP_ID, idp_url=IDP_URL)
    except Exception as exc:
        logger.warning("init_security partially failed (expected — shimproxy has no tool registry): %s", exc)
    try:
        await _register_with_idp()
    except Exception as exc:
        logger.warning("Agent registration failed at startup: %s", exc)
    yield


app = FastAPI(
    title="ShimProxy — N8N Building Agent Tools",
    description="Exposes building tools for N8N using the clientshim library.",
    lifespan=lifespan,
)


# ── Request models ────────────────────────────────────────────────────────────
class ToolRequest(BaseModel):
    mode: Optional[str] = "oauth"              # "oauth" or "intent"
    current_prompt: Optional[str] = None       # Falls back to LEGITIMATE_PROMPT if not provided


class HVACRequest(ToolRequest):
    target_temperature: float


class LightingRequest(ToolRequest):
    level: int


# ── Shared call helper ────────────────────────────────────────────────────────
async def _call(mode: str, current_prompt: Optional[str], scope: str, audience: str,
                method: str, path: str, body: Optional[dict] = None) -> dict:
    """
    Unified dispatch:
      oauth  → get_secure_client().authenticated_request(mode=AuthMode.oauth)
                 identical to t5/tools.py pattern
      intent → compute_agent_checksum(current_prompt) → IDP intent/token
                 then call API with returned token
    """
    api_url = os.getenv(EnvVars.API_URL.value, API_URL)
    # Fall back to the registered legitimate prompt if N8N doesn't supply one
    effective_prompt = current_prompt or LEGITIMATE_PROMPT

    # Build query params (building API's /sensors endpoint requires agent_id)
    params = {"agent_id": AGENT_ID}

    if mode == "oauth":
        # ── OAuth path: exactly the same pattern as demo tools ─────────────
        try:
            async with get_secure_client().authenticated_request(
                scope,
                audience=audience,
                auth_profile_name=AuthProfileName.building_admin,
                mode=AuthMode.oauth,
                workflow_enabled=False,
            ) as http_client:
                if method == "GET":
                    resp = await http_client.get(f"{api_url}{path}", params=params)
                else:
                    resp = await http_client.post(f"{api_url}{path}", json=body or {})
                resp.raise_for_status()
                return resp.json()
        except HTTPException:
            raise
        except Exception as e:
            logger.error("OAuth tool call failed: %s", e)
            raise HTTPException(500, str(e))

    elif mode == "intent":
        # ── Intent path: compute checksum → IDP validates → call API ───────
        token = await _get_intent_token(effective_prompt, scope, audience)
        try:
            async with httpx.AsyncClient(
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=10,
            ) as http_client:
                if method == "GET":
                    resp = await http_client.get(f"{api_url}{path}", params=params)
                else:
                    resp = await http_client.post(f"{api_url}{path}", json=body or {})
                resp.raise_for_status()
                return resp.json()
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Intent tool call failed: %s", e)
            raise HTTPException(500, str(e))

    else:
        raise HTTPException(400, f"Unknown mode '{mode}'. Use 'oauth' or 'intent'.")


# ── Tool endpoints ────────────────────────────────────────────────────────────
# N8N sends mode & current_prompt as QUERY PARAMETERS in the URL.
# Read endpoints have NO body. Write endpoints have body for tool-specific params only.

@app.post("/tools/read_sensors")
async def tool_read_sensors(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="read:sensors", audience="api.localhost.building",
        method="GET", path="/building/sensors",
    )


@app.post("/tools/read_temperature")
async def tool_read_temperature(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="read:sensors", audience="api.localhost.building",
        method="GET", path="/building/sensors/temperature",
    )


@app.post("/tools/read_occupancy")
async def tool_read_occupancy(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="read:sensors", audience="api.localhost.building",
        method="GET", path="/building/sensors/occupancy",
    )


@app.post("/tools/read_energy")
async def tool_read_energy(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="read:data", audience="api.localhost.building",
        method="GET", path="/building/energy",
    )


@app.post("/tools/read_history")
async def tool_read_history(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="read:data", audience="api.localhost.building",
        method="GET", path="/building/history",
    )


async def _extract_param(request: Request, name: str, cast=float):
    """Extract a parameter from query string, JSON body, or form body."""
    # 1. Query param
    val = request.query_params.get(name)
    if val:
        return cast(val)
    # 2. JSON body
    try:
        data = await request.json()
        if name in data:
            return cast(data[name])
    except Exception:
        pass
    # 3. Form body
    try:
        form = await request.form()
        if name in form:
            return cast(form[name])
    except Exception:
        pass
    return None


@app.post("/tools/set_hvac")
async def tool_set_hvac(
    request: Request,
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    target_temperature = await _extract_param(request, "target_temperature", float)
    if target_temperature is None:
        raise HTTPException(422, "target_temperature is required (query, JSON body, or form body)")
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="write:hvac", audience="api.localhost.building",
        method="POST", path="/building/hvac/setpoint",
        body={"agent_id": AGENT_ID, "target_temperature": target_temperature},
    )


@app.post("/tools/set_lighting")
async def tool_set_lighting(
    request: Request,
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    level = await _extract_param(request, "level", int)
    if level is None:
        raise HTTPException(422, "level is required (query, JSON body, or form body)")
    return await _call(
        mode, current_prompt or LEGITIMATE_PROMPT,
        scope="write:lighting", audience="api.localhost.building",
        method="POST", path="/building/lighting/level",
        body={"agent_id": AGENT_ID, "level": level},
    )


# ── Utility endpoints ─────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "running", "agent_id": AGENT_ID}


@app.post("/reset")
async def reset():
    """Re-register the agent with the IDP. Call between demo runs."""
    try:
        await _register_with_idp()
        return {"status": "re-registered", "agent_id": AGENT_ID}
    except Exception as exc:
        raise HTTPException(500, str(exc))
