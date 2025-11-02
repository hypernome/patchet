from util.cryptography import AgentKeyManager
from intentmodel.intent_model import BatchRegistrationRequest, RegistrationRequest
from util.environment import EnvVars
from util.commons import to_agent_components, compute_agent_checksum
from clientshim.secure_client import SecureClient, get_secure_client, AuthMode
from model.config import AuthProfileName
from intentmodel.intent_model import WorkflowDefinition, WorkflowDefinitionBatch
from typing import Dict
from agent.graph import ReActAgent
import os

async def register_agents(all_agents: list, skip_regsitration_check: bool = False): 
    """
    Scans the application to find all Agents and registers them with IDP.
    """
    secure_client: SecureClient = get_secure_client()
    
    request = BatchRegistrationRequest(
        registration_requests=[RegistrationRequest(
                app_id=os.getenv(EnvVars.APP_ID.value), 
                agent_components=to_agent_components(agent), 
                public_key=secure_client.agent_key_manager.generate_keys_for_agent(agent.id)
            ) for agent in all_agents if not await agent_already_registered(agent, skip_regsitration_check)]
        )    
    
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/batch_register/agent"
    async with secure_client.authenticated_request(
        "register:intent", 
        audience="idp.localhost", 
        auth_profile_name=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth
    ) as client: 
        registration_response = await client.post(
            url=url, 
            json=request.model_dump()
        )
    
    registration_response.raise_for_status()
    return registration_response.json()

async def agent_already_registered(agent: ReActAgent, skip_regsitration_check: bool = False): 
    """
    Find if this agent is already registered.
    """
    if skip_regsitration_check: 
        return False
    
    agent_id: str = agent.id
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/agents/Patchet"
    secure_client: SecureClient = get_secure_client()
    
    async with secure_client.authenticated_request(
        "read:agents", 
        audience="idp.localhost", 
        auth_profile_name=AuthProfileName.patchet, 
        mode=AuthMode.oauth
    ) as client: 
        response = await client.get(
            url=url
        )
    
    response.raise_for_status()
    
    registrations_by_app: Dict[str, list[Dict]] = response.json()
    registrations: list[Dict] = registrations_by_app.get('Patchet', [])
    for registration in registrations: 
        if registration.get('agent_id', None) == agent_id: 
            candidate_checksum: str = compute_agent_checksum(to_agent_components(agent))
            registered_checksum: str = registration.get('checksum', '')
            if candidate_checksum == registered_checksum:
                return True
    
    return False

async def deregister_workflow(workflow_id: str): 
    """
    Scans the application to find all Agents and registers them with IDP.
    """
    secure_client: SecureClient = get_secure_client()
    
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/deregister/workflow"
    async with secure_client.authenticated_request(
        "register:workflow", 
        audience="idp.localhost", 
        auth_profile_name=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth
    ) as client: 
        registration_response = await client.post(
            url=url, 
            json={
                "workflow_id": workflow_id
            }
        )
    
    registration_response.raise_for_status()
    return registration_response.json()

async def register_workflow(workflow): 
    """
    Scans the application to find all Agents and registers them with IDP.
    """
    secure_client: SecureClient = get_secure_client()
    
    request = WorkflowDefinition(**workflow)
    
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/register/workflow"
    async with secure_client.authenticated_request(
        "register:workflow", 
        audience="idp.localhost", 
        auth_profile_name=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth
    ) as client: 
        registration_response = await client.post(
            url=url, 
            json=request.model_dump()
        )
    
    registration_response.raise_for_status()
    return registration_response.json()

async def batch_register_workflows(all_workflows: list): 
    """
    Scans the application to find all workflows and registers them with IDP.
    """
    secure_client: SecureClient = get_secure_client()
    
    request = WorkflowDefinitionBatch(
        workflow_definitions=[
            WorkflowDefinition(**workflow)
            for workflow in all_workflows
        ]
    )
    
    url = f"{os.getenv(EnvVars.IDP_URL.value)}/intent/batch_register/workflow"
    async with secure_client.authenticated_request(
        "register:workflow", 
        audience="idp.localhost", 
        auth_profile_name=AuthProfileName.intent_registration_admin,
        mode=AuthMode.oauth
    ) as client: 
        registration_response = await client.post(
            url=url, 
            json=request.model_dump()
        )
    
    registration_response.raise_for_status()
    return registration_response.json()

