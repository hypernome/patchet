from pydantic import BaseModel
from typing import List, Callable, Dict, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from enum import Enum

class AgentSpec(BaseModel): 
    """
    Represents a secure agent composition that must include an agent's 
    signature (id, prompts, tools, configuration)
    """
    agent_id: str
    agent_bridge: Callable | object
    prompt: str
    tools: List[Callable]
    tools_map: Dict[str, Callable]
    configuration: Dict = {}   

@dataclass
class AgentIdentity:
    """
    Represents a verified agent identity
    """
    agent_id: str
    checksum: str
    registration_id: str
    prompt: str
    tools: List[Dict[str, str]]
    wrapped_tools: Dict[str, Any]
    configuration: Dict[str, Any]
    registered_at: float
    private_key: RSAPrivateKey | None = None

@dataclass 
class TokenResponse:
    """
    Response from IDP token endpoint
    """
    access_token: str
    token_type: str
    expires_in: int
    scope: str

class VerificationStatus(Enum):
    """
    Agent verification status
    """
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"

class WorkflowStepStatus(Enum): 
    """
    Work flow steps status.
    """
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"