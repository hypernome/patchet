from fastapi import FastAPI
from fastapi.responses import JSONResponse
from enum import Enum
from agent.supervisor import Supervisor
from agent.planner import Planner, list_files
from agent.classifier import Classifier
from agent.patcher import Patcher
from clientshim.secure_client import init_security, get_secure_client, SecureClient, AuthMode
from intentmodel.intent_model import RegistrationRequest, BatchRegistrationRequest
from model.config import AuthProfileName
from util.environment import EnvVars
from contextlib import asynccontextmanager
from demo.main_scenario import start
import os

class RunnerMode(Enum): 
    oauth = "oauth"
    intent = "intent"

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_security(agent_specs=[])
    yield

app = FastAPI(root_path="/demo", lifespan=lifespan)

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
    all_agents: list = [
        Supervisor(), 
        Planner(), 
        Classifier(), 
        Patcher()
    ]
    
    request = BatchRegistrationRequest(
        registration_requests=[RegistrationRequest(
            app_id=os.getenv(EnvVars.APP_ID.value), 
            agent_components=agent.agent_components()
            ) for agent in all_agents]
        )
    
    secure_client: SecureClient = get_secure_client()
    
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/batch_register/agent"
    async with secure_client.authenticated_request(
        "register:intent", 
        audience="idp.localhost", 
        auth_profile_nane=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth
    ) as client: 
        registration_response = await client.post(
            url=url, 
            json=request.model_dump()
        )
    
    registration_response.raise_for_status()
    return registration_response.json()

@app.post("/main")
async def run_main_scenario():
    """
    Run the main Patchet agentic application.
    """
    await start()
    