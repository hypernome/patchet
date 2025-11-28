from fastapi import FastAPI
from fastapi.responses import JSONResponse
from enum import Enum
from clientshim.secure_client import init_security
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
import os

class RunnerMode(Enum): 
    oauth = "oauth"
    intent = "intent"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start up with shim initialization
    await init_security(agent_specs=[])
    yield

app = FastAPI(root_path="/demo", lifespan=lifespan)

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
    return await ra(demo_agents)

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
async def run_t1():
    """
    Run the t1 threat scenario.
    """
    await t1.attack()

@app.post("/t2_token_replay_attacks")
async def run_t2():
    """
    Run the t2 threat scenario.
    """
    await t2.attack()

@app.post("/t3_shim_library_impersonation")
async def run_t3():
    """
    Run the t3 threat scenario.
    """
    await t3.attack()

@app.post("/t4_runtime_code_modification")
async def run_t4():
    """
    Run the t4 threat scenario.
    """
    await t4.attack()

@app.post("/t5_prompt_injection_attacks")
async def run_t5():
    """
    Run the t5 threat scenario.
    """
    await t5.attack()

@app.post("/t6_workflow_definition_tampering")
async def run_t6():
    """
    Run the t6 threat scenario.
    """
    await t6.attack()
    
@app.post("/t7_cross_agnet_privilege_escalation")
async def run_t7():
    """
    Run the t7 threat scenario.
    """
    await t7.attack()

@app.post("/t8_workflow_step_bypass")
async def run_t8():
    """
    Run the t8 threat scenario.
    """
    await t8.attack()

@app.post("/t9_scope_inflation")
async def run_t9():
    """
    Run the t9 threat scenario.
    """
    await t9.attack()

@app.post("/t10_intent_origin_forgery")
async def run_t10():
    """
    Run the t10 threat scenario.
    """
    await t10.attack()

@app.post("/t11_delegation_chain_integrity")
async def run_t11():
    """
    Run the t11 threat scenario.
    """
    await t11.attack()

@app.post("/t12_agent_configuration_exposure")
async def run_t12():
    """
    Run the t12 threat scenario.
    """
    await t12.attack()


