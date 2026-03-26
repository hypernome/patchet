"""
ShimProxy — Client-side shim bridge for N8N building agent tools.

Both OAuth and Intent mode use the clientshim library's
authenticated_request() — exactly the same pattern as demo/t5/tools.py.

For intent mode to work, the shimproxy:
  1. Registers tool functions with @secure_tool() so _TOOL_REGISTRY is populated
  2. Generates RSA keys via AgentKeyManager (same as the demo agents)
  3. Registers the agent with the IDP (including public key for PoP)
  4. Calls init_security() → _register_agents_from_idp() builds a ReActAgent
     + AgentIdentity with the private key for PoP signing
  5. Each tool endpoint delegates to its @secure_tool() function which calls
     authenticated_request() — _detect_current_agent_context() walks the stack
     and finds the registered tool function + the ReActAgent in gc

N8N tools call these endpoints. The only thing that changes between
the four demo runs is mode (oauth / intent) and current_prompt
(legitimate / injected) — everything else stays identical.
"""

import hashlib
import json as json_mod
import logging
import os
from urllib.parse import unquote
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from clientshim.secure_client import (
    get_secure_client,
    init_security,
    secure_tool,
    AuthMode,
    _current_agent_context,
)
from model.config import AuthProfileName
from intentmodel.intent_model import AgentComponents, Tool
from agent.graph import prompt_tail
from util.commons import compute_agent_checksum
from util.cryptography import AgentKeyManager
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
_BASE_PROMPT = (
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


def _as_agent_prompt(prompt: str) -> str:
    """Apply the same transformation that ReActAgent.__init__ does to the prompt,
    so that the checksum computed during registration matches the runtime checksum
    that _prepare_agent computes from to_agent_components(agent)."""
    return f"\n            {prompt}{prompt_tail}\n        "


# This is what ReActAgent.__init__ will produce — used for registration AND
# for runtime checksum comparison of the legitimate prompt.
LEGITIMATE_PROMPT = _as_agent_prompt(_BASE_PROMPT)

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


# ══════════════════════════════════════════════════════════════════════════════
# 1.  @secure_tool() functions — these are the REAL tool implementations.
#     They live in _TOOL_REGISTRY so _register_agents_from_idp() can build
#     a ReActAgent.  They also appear on the call stack when
#     _detect_current_agent_context() walks up looking for registered tools.
#
#     Signatures MUST match AGENT_TOOLS exactly because
#     to_agent_components → get_core_signature inspects the real Python sig.
# ══════════════════════════════════════════════════════════════════════════════

def _decode_prompt(current_prompt: Optional[str]) -> str:
    """Undo any URL double-encoding and literal \\n from N8N,
    then apply the same ReActAgent prompt transformation so the
    checksum matches what _prepare_agent computes at runtime."""
    if not current_prompt:
        return LEGITIMATE_PROMPT
    decoded = unquote(unquote(current_prompt))
    decoded = decoded.replace("\\n", "\n")
    return _as_agent_prompt(decoded)


async def _do_api_call(scope: str, audience: str, mode: str,
                       current_prompt: Optional[str],
                       method: str, path: str,
                       body: Optional[dict] = None) -> dict:
    """
    Core dispatch — called from WITHIN each @secure_tool() function
    so that function is on the call stack when _detect_current_agent_context
    walks up.
    """
    api_url = os.getenv(EnvVars.API_URL.value, API_URL)
    params = {"agent_id": AGENT_ID}

    auth_mode = AuthMode.intent if mode == "intent" else AuthMode.oauth

    # For intent mode, set the ContextVar that _detect_current_agent_context reads
    if auth_mode == AuthMode.intent:
        _current_agent_context.set(AGENT_ID)

    auth_kwargs = dict(
        audience=audience,
        mode=auth_mode,
        workflow_enabled=False,
    )
    if auth_mode == AuthMode.oauth:
        auth_kwargs["auth_profile_name"] = AuthProfileName.building_admin

    # Build PoP data for intent+POST requests (verify_pop needs it)
    if auth_mode == AuthMode.intent and method == "POST" and body:
        auth_kwargs["pop_data"] = {
            "method": method,
            "url": f"{api_url}{path}",
            "data": hashlib.sha256(json_mod.dumps(body).encode()).hexdigest(),
        }

    async with get_secure_client().authenticated_request(
        scope, **auth_kwargs
    ) as http_client:
        if method == "GET":
            resp = await http_client.get(f"{api_url}{path}", params=params)
        else:
            resp = await http_client.post(f"{api_url}{path}", json=body or {})
        resp.raise_for_status()
        return resp.json()


@secure_tool()
async def read_sensors() -> dict:
    """Read all building sensors including temperature, occupancy, HVAC and lighting"""
    return await _do_api_call(
        scope="read:sensors", audience="api.localhost.building",
        mode=read_sensors._shim_mode, current_prompt=read_sensors._shim_prompt,
        method="GET", path="/building/sensors",
    )

@secure_tool()
async def read_temperature() -> dict:
    """Read current temperature sensor data"""
    return await _do_api_call(
        scope="read:sensors", audience="api.localhost.building",
        mode=read_temperature._shim_mode, current_prompt=read_temperature._shim_prompt,
        method="GET", path="/building/sensors/temperature",
    )

@secure_tool()
async def read_occupancy() -> dict:
    """Read occupancy sensor data"""
    return await _do_api_call(
        scope="read:sensors", audience="api.localhost.building",
        mode=read_occupancy._shim_mode, current_prompt=read_occupancy._shim_prompt,
        method="GET", path="/building/sensors/occupancy",
    )

@secure_tool()
async def read_energy() -> dict:
    """Read current energy usage in kW"""
    return await _do_api_call(
        scope="read:data", audience="api.localhost.building",
        mode=read_energy._shim_mode, current_prompt=read_energy._shim_prompt,
        method="GET", path="/building/energy",
    )

@secure_tool()
async def read_history() -> dict:
    """Read action history log"""
    return await _do_api_call(
        scope="read:data", audience="api.localhost.building",
        mode=read_history._shim_mode, current_prompt=read_history._shim_prompt,
        method="GET", path="/building/history",
    )

@secure_tool()
async def set_hvac(target_temperature: float, agent_id: str) -> dict:
    """Set HVAC target temperature in Fahrenheit. Allowed range: 60-80F."""
    return await _do_api_call(
        scope="write:hvac", audience="api.localhost.building",
        mode=set_hvac._shim_mode, current_prompt=set_hvac._shim_prompt,
        method="POST", path="/building/hvac/setpoint",
        body={"agent_id": agent_id, "target_temperature": target_temperature},
    )

@secure_tool()
async def set_lighting(level: int, agent_id: str) -> dict:
    """Set building lighting level as a percentage from 0 to 100."""
    return await _do_api_call(
        scope="write:lighting", audience="api.localhost.building",
        mode=set_lighting._shim_mode, current_prompt=set_lighting._shim_prompt,
        method="POST", path="/building/lighting/level",
        body={"agent_id": agent_id, "level": level},
    )


# ══════════════════════════════════════════════════════════════════════════════
# 2.  Key management — use AgentKeyManager so SecureClient finds the keys
# ══════════════════════════════════════════════════════════════════════════════

_key_manager = AgentKeyManager()


def _ensure_agent_keys() -> str:
    """Generate RSA key pair via AgentKeyManager, return public_key PEM."""
    os.makedirs(_key_manager.key_home_dir, exist_ok=True)
    public_key_pem = _key_manager.generate_keys_for_agent(AGENT_ID)
    logger.info("RSA key pair ready for %s", AGENT_ID)
    return public_key_pem


# ══════════════════════════════════════════════════════════════════════════════
# 3.  IDP registration
# ══════════════════════════════════════════════════════════════════════════════

async def _register_with_idp(public_key_pem: str):
    """Register N8N_BuildingAgent with the IDP including the PoP public key."""
    logger.info("Registering %s with IDP...", AGENT_ID)

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
                "public_key":       public_key_pem,
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


# ══════════════════════════════════════════════════════════════════════════════
# 4.  Lifespan — orchestrate startup in the right order
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Step A: generate keys BEFORE init_security (AgentKeyManager writes PEM
    #         files that SecureClient._prepare_agent reads later).
    public_key_pem = _ensure_agent_keys()

    # Step B: first init_security just to create the SecureClient singleton.
    #         _register_agents_from_idp may find 0 agents on first boot
    #         (agent not yet registered with IDP) — that is fine.
    try:
        await init_security(agent_specs=[], app_id=APP_ID, idp_url=IDP_URL)
    except Exception as exc:
        logger.warning("init_security first pass: %s", exc)

    # Step C: register the agent with IDP (needs SecureClient for OAuth token)
    try:
        await _register_with_idp(public_key_pem)
    except Exception as exc:
        logger.warning("Agent registration failed: %s", exc)

    # Step D: re-run _register_agents_from_idp now that the agent exists in
    #         the IDP AND tool stubs are in _TOOL_REGISTRY AND keys are
    #         available.  This builds the ReActAgent + AgentIdentity with
    #         the private key needed for PoP.
    try:
        await get_secure_client()._register_agents_from_idp()
        logger.info("Agent identity loaded — intent mode ready.")
    except Exception as exc:
        logger.warning("Loading agent identity failed: %s", exc)

    yield


app = FastAPI(
    title="ShimProxy — N8N Building Agent Tools",
    description="Exposes building tools for N8N using the clientshim library.",
    lifespan=lifespan,
)


# ══════════════════════════════════════════════════════════════════════════════
# 5.  Helper to invoke a @secure_tool from an HTTP endpoint
# ══════════════════════════════════════════════════════════════════════════════

async def _invoke_tool(tool_func, mode: str, current_prompt: Optional[str],
                       **extra_kwargs) -> dict:
    """
    Stash mode & prompt on the tool function object, then call it.
    The tool function reads them back and delegates to _do_api_call.
    This ensures the @secure_tool() function is on the call stack.
    """
    effective_prompt = _decode_prompt(current_prompt)
    tool_func._shim_mode = mode
    tool_func._shim_prompt = effective_prompt

    try:
        return await tool_func(**extra_kwargs)
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "checksum" in error_msg.lower():
            logger.warning("PROMPT INJECTION DETECTED — IDP rejected checksum for %s", AGENT_ID)
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "prompt_injection_detected",
                    "message": (
                        "Agent checksum mismatch — the effective prompt has been modified. "
                        "Prompt injection attack detected and blocked by IDP."
                    ),
                    "agent_id": AGENT_ID,
                },
            )
        logger.error("%s tool call failed: %s", mode, e)
        raise HTTPException(500, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 6.  HTTP endpoints — N8N calls these via toolHttpRequest
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/tools/read_sensors")
async def tool_read_sensors(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _invoke_tool(read_sensors, mode, current_prompt or None)


@app.post("/tools/read_temperature")
async def tool_read_temperature(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _invoke_tool(read_temperature, mode, current_prompt or None)


@app.post("/tools/read_occupancy")
async def tool_read_occupancy(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _invoke_tool(read_occupancy, mode, current_prompt or None)


@app.post("/tools/read_energy")
async def tool_read_energy(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _invoke_tool(read_energy, mode, current_prompt or None)


@app.post("/tools/read_history")
async def tool_read_history(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
):
    return await _invoke_tool(read_history, mode, current_prompt or None)


@app.post("/tools/set_hvac")
async def tool_set_hvac(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
    target_temperature: Optional[float] = Query(default=None),
):
    if target_temperature is None:
        try:
            result = await _invoke_tool(read_occupancy, mode, current_prompt or None)
            occupancy = int(result.get("occupancy", 0))
        except Exception:
            occupancy = 0
        target_temperature = 72.0 if occupancy > 0 else 65.0
        logger.info("set_hvac: no value provided, using %sF (occupancy=%d)", target_temperature, occupancy)
    return await _invoke_tool(
        set_hvac, mode, current_prompt or None,
        target_temperature=target_temperature, agent_id=AGENT_ID,
    )


@app.post("/tools/set_lighting")
async def tool_set_lighting(
    mode: str = Query(default="oauth"),
    current_prompt: str = Query(default=""),
    level: Optional[int] = Query(default=None),
):
    if level is None:
        try:
            result = await _invoke_tool(read_occupancy, mode, current_prompt or None)
            occupancy = int(result.get("occupancy", 0))
        except Exception:
            occupancy = 0
        level = 80 if occupancy > 0 else 10
        logger.info("set_lighting: no value provided, using %d%% (occupancy=%d)", level, occupancy)
    return await _invoke_tool(
        set_lighting, mode, current_prompt or None,
        level=level, agent_id=AGENT_ID,
    )


# ── Utility endpoints ─────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "running", "agent_id": AGENT_ID}


@app.post("/reset")
async def reset():
    """Re-register the agent with the IDP. Call between demo runs."""
    try:
        public_key_pem = _key_manager.agent_keys.get(AGENT_ID, {}).get("public_key_pem", "")
        await _register_with_idp(public_key_pem)
        return {"status": "re-registered", "agent_id": AGENT_ID}
    except Exception as exc:
        raise HTTPException(500, str(exc))
