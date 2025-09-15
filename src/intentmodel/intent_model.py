from pydantic import BaseModel
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

# Data models
class Tool(BaseModel): 
    name: str
    signature: str
    description: str
    
class AgentComponents(BaseModel): 
    agent_id: str
    prompt_template: str
    tools: List[Tool]
    configuration: Dict = {}

class RegistrationRequest(BaseModel):
    app_id: str
    agent_components: AgentComponents

class BatchRegistrationRequest(BaseModel):
    registration_requests: list[RegistrationRequest]

class Registration(BaseModel): 
    app_id: str
    agent_id: str
    registration_id: str
    checksum: str
    prompt: str
    tools: List[Tool]
    registered_at: int
    version: str | None = None
    
class WorkflowDefinition(BaseModel):
    workflow_id: str
    steps: Dict[str, Dict]  # step_name -> {allowed_agents, next_steps}

class TokenRequest(BaseModel):
    grant_type: str  # "agent_checksum"
    agent_id: str
    computed_checksum: str
    workflow_id: str
    workflow_step: str
    requested_scopes: List[str]
    audience: str
    delegation_context: Optional[Dict] = None

