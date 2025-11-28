from pydantic import BaseModel
from typing import Optional, Dict, List, Literal
from dataclasses import dataclass, asdict
from enum import Enum

# Data models
class Tool(BaseModel): 
    name: str
    signature: str
    description: str
    source_code: str | None = None
    is_agent: bool = False
    
class AgentComponents(BaseModel): 
    agent_id: str
    prompt_template: str
    tools: List[Tool]
    configuration: Dict = {}

class RegistrationRequest(BaseModel):
    app_id: str
    agent_components: AgentComponents
    public_key: str
    

class BatchRegistrationRequest(BaseModel):
    registration_requests: list[RegistrationRequest]

class Registration(BaseModel): 
    app_id: str
    agent_id: str
    registration_id: str
    checksum: str
    prompt: str
    tools: List[Tool]
    public_key: str | None
    registered_at: int
    version: str | None = None
    
class WorkflowStep(BaseModel): 
    agent: str
    action: str
    scopes: list[str] = []
    dependencies: list[str] = []
    required: bool = False
    approval_gate: bool = False
    requires_approval: bool = False
    
class WorkflowDefinition(BaseModel):
    workflow_id: str
    workflow_type: Literal["dag"] = "dag"
    steps: Dict[str, WorkflowStep]  # step_name -> {allowed_agents, next_steps}

class WorkflowDefinitionBatch(BaseModel): 
    workflow_definitions: list[WorkflowDefinition]

class TokenRequest(BaseModel):
    grant_type: str  # "agent_checksum"
    agent_id: str
    computed_checksum: str
    workflow_id: str | None = None
    workflow_step: Dict | None = None
    requested_scopes: List[str]
    audience: str
    delegation_context: Optional[Dict] = None
    workflow_enabled: bool = True

