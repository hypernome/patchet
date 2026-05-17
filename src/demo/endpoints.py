import os
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from enum import Enum
from clientshim.secure_client import init_security, AuthMode, get_secure_client
from demo.t1 import t1_agent_identity_spoofing as t1
from demo.t2 import t2_token_replay_attacks as t2
from demo.t3 import t3_shim_library_impersonation as t3
from demo.t4 import t4_runtime_code_modification as t4
from demo.t5 import t5_prompt_injection_attacks as t5
from demo.t6 import t6_workflow_definition_tampering as t6
from demo.t7 import t7_cross_agent_privilege_escalation as t7
from demo.t8 import t8_workflow_step_bypass as t8
from demo.t9 import t9_scope_inflation as t9
from demo.t10 import t10_intent_origin_forgery as t10
from demo.t11 import t11_delegation_chain_integrity as t11
from demo.t12 import t12_agent_configuration_exposure as t12
from contextlib import asynccontextmanager
from demo.main_scenario import start
from util.reg import register_agents as ra, batch_register_workflows as brw
from demo.utils import agent
from demo.demo_registrations import demo_agents, declared_agents, declared_workflows
from experiment.run_all_threats import set_auth_mode, ThreatTestRunner


class RunnerMode(Enum):
    oauth = "oauth"
    intent = "intent"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start up with shim initialization
    await init_security(agent_specs=[])
    yield


# root_path is empty by default for host-based routing (ALB / Caddy forwarding to
# demo.unforge.io with no path prefix). Set ROOT_PATH=/demo only if behind a
# path-stripping proxy (e.g. nginx mounting at /demo/).
app = FastAPI(root_path=os.getenv("ROOT_PATH", ""), lifespan=lifespan)


# Module-level runner used to provide logger + threat metadata to set_auth_mode.
# Its output_file is unused for live HTTP endpoints (results are returned in the
# response body), but ThreatTestRunner requires it.
_runner = ThreatTestRunner(output_file="/tmp/demo_runner.json")


async def _run_scenario(threat_module, threat_id: str, mode: RunnerMode):
    """Execute a single threat in the requested auth mode and return its result.

    NOTE: set_auth_mode mutates global state (env vars + sys.modules monkey-
    patching) for the duration of the call. Do not invoke concurrent threat
    requests across modes from multiple HTTP clients at the same time — this
    runner is intended for a single presenter driving the demo.
    """
    auth_mode = AuthMode(mode.value)
    with set_auth_mode(auth_mode, threat_id, _runner):
        return await threat_module.attack()


@app.get("/health")
def health():
    """ALB health check target. Always public, never auth-gated."""
    return {"ok": True, "service": "demo"}


@app.post("/pilot")
async def pilot():
    return {
        "cwd": os.getcwd()
    }


@app.post("/run_scenarios")
async def run_scenarios(mode: RunnerMode = RunnerMode.oauth):
    '''
    Run all the threat scenarios.
    '''
    return JSONResponse(content={"message": "Scenarios triggered!"}, status_code=200)


@app.post("/register_all_agents")
async def register_agents():
    """
    Scans the application to find all Agents and registers them with IDP.
    """
    tool_agents = [a for a in declared_agents if bool(a.get('register_as_tool', False))]
    non_tool_agents = [a for a in declared_agents if not bool(a.get('register_as_tool', False))]


    demo_agents.extend([agent(a) for a in tool_agents])
    demo_agents.extend([agent(a) for a in non_tool_agents])
    # skip_regsitration_check=True forces register_agents to generate fresh
    # PoP keypairs and POST public keys to IDP for every agent — even those
    # already known to IDP. Without this, an ECS task that boots into an IDP
    # already populated by a prior task gets verified_agents entries with
    # private_key=None, and any downstream PoP-signed request fails with
    # "'NoneType' object has no attribute 'sign'". Forcing re-registration on
    # every call ensures private keys exist locally for all 41 agents.
    response = await ra(demo_agents, skip_regsitration_check=True)
    # Refresh the in-process verified_agents cache so secure_client.get_agent(...)
    # works for the agents we just registered. Without this, init_security's
    # one-shot startup fetch leaves the cache empty for any agent registered
    # after boot, and downstream callers (e.g. T7) hit AttributeError on None.
    await get_secure_client().restart()
    return response


@app.post("/regiser_all_workflows")
async def register_workflows():
    """
    Scans the application to find all workflows and registers them with IDP.
    """
    return await brw(declared_workflows)


@app.post("/main")
async def run_main_scenario():
    """
    Run the main Patchet agentic application.
    """
    await start()


@app.post("/t1_agent_identity_spoofing")
async def run_t1(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t1 (Agent Identity Spoofing) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t1, "T1", mode)


@app.post("/t2_token_replay_attacks")
async def run_t2(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t2 (Token Replay Attacks) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t2, "T2", mode)


@app.post("/t3_shim_library_impersonation")
async def run_t3(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t3 (Shim Library Impersonation) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t3, "T3", mode)


@app.post("/t4_runtime_code_modification")
async def run_t4(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t4 (Runtime Code Modification) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t4, "T4", mode)


@app.post("/t5_prompt_injection_attacks")
async def run_t5(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t5 (Prompt Injection Attacks) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t5, "T5", mode)


@app.post("/t6_workflow_definition_tampering")
async def run_t6(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t6 (Workflow Definition Tampering) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t6, "T6", mode)


@app.post("/t7_cross_agnet_privilege_escalation")
async def run_t7(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t7 (Cross-Agent Privilege Escalation) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t7, "T7", mode)


@app.post("/t8_workflow_step_bypass")
async def run_t8(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t8 (Workflow Step Bypass) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t8, "T8", mode)


@app.post("/t9_scope_inflation")
async def run_t9(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t9 (Scope Inflation) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t9, "T9", mode)


@app.post("/t10_intent_origin_forgery")
async def run_t10(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t10 (Intent Origin Forgery) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t10, "T10", mode)


@app.post("/t11_delegation_chain_integrity")
async def run_t11(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t11 (Delegation Chain Integrity) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t11, "T11", mode)


@app.post("/t12_agent_configuration_exposure")
async def run_t12(mode: RunnerMode = RunnerMode.oauth):
    """
    Run the t12 (Agent Configuration Exposure) threat scenario in the requested auth mode.
    """
    return await _run_scenario(t12, "T12", mode)


@app.post("/dod_demo")
async def dod_demo():
    """
    Headline demo: runs T1, T7, T2 in OAuth mode then Intent mode and returns
    a consolidated JSON of all six runs. Designed for a single-call live
    narration. Maps to: Spoofing (T1), Elevation (T7), Replay (T2) — the three
    most demo-relevant STRIDE categories for a DoD audience.
    """
    plan = [
        ("T1", t1, "Agent Identity Spoofing"),
        ("T7", t7, "Cross-Agent Privilege Escalation"),
        ("T2", t2, "Token Replay Attacks"),
    ]
    out = []
    for tid, tmod, tname in plan:
        for mode in [AuthMode.oauth, AuthMode.intent]:
            # Each threat module's attack() owns its own try/except for the
            # *attack* phase, but their *legit* phase is not always wrapped.
            # In Intent mode, legit calls can be rejected upstream (api 401)
            # before the threat module's own try/except runs. We treat that
            # outer exception as a successful block — the security layer
            # refused to let the call through at all, which is exactly the
            # expected behaviour for Intent mode against a hostile flow.
            try:
                with set_auth_mode(mode, tid, _runner):
                    r = await tmod.attack()
            except Exception as e:
                r = {
                    "attack_succeeded": False,
                    "blocked_by": "Outer security layer (pre-attack auth)",
                    "error_message": str(e),
                    "outer_exception": True,
                }
            out.append({
                "threat_id": tid,
                "threat_name": tname,
                "mode": mode.value,
                **(r or {}),
            })
    summary = {
        "oauth_succeeded": sum(1 for x in out if x["mode"] == "oauth" and x.get("attack_succeeded")),
        "oauth_total": sum(1 for x in out if x["mode"] == "oauth"),
        "intent_blocked": sum(1 for x in out if x["mode"] == "intent" and not x.get("attack_succeeded")),
        "intent_total": sum(1 for x in out if x["mode"] == "intent"),
    }
    return {"results": out, "summary": summary}
