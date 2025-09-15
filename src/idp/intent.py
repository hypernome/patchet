# idp/server.py
from enum import Enum
from fastapi import APIRouter, HTTPException, Form, Depends
import hashlib, jwt, time, uuid, logging, os
from typing import Dict, List, DefaultDict
from intentmodel.intent_model import (
    RegistrationRequest, 
    BatchRegistrationRequest,
    AgentComponents, 
    WorkflowDefinition, 
    TokenRequest, 
    Registration
)
from clientshim.secure_model import TokenResponse
from util.environment import EnvVars
from idp.oauth import priv_pem
from util.commons import compute_agent_checksum
from idp.auth import require_auth

logger = logging.getLogger(__name__)

intent_router = APIRouter(prefix="/intent")

# In-memory storage (We will probably use Redis/PostgreSQL in production)
registered_agents: Dict[str, list[Registration]] = DefaultDict(list)
registered_workflows: Dict[str, WorkflowDefinition] = {}
active_executions: Dict[str, Dict] = {}

class ChangeType(Enum): 
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    PATCH = "PATCH"

class IntentServer:
    def __init__(self):
        self.private_key = priv_pem
        
    async def get_registered_agents(self, app_id: str) -> List[Registration]: 
        """
        Fetch agents registered with IDP for a specific app.
        """
        
        agents_by_app = DefaultDict(list)
        
        for agent_id, registrations in registered_agents.items():
            if app_id == registrations[-1].app_id: 
                agents_by_app[app_id].append(registrations[-1])
        
        return agents_by_app
    
    async def register_agent(self, registration_request: RegistrationRequest):
        """Register a new agent with the IDP"""
        components: AgentComponents = registration_request.agent_components
        
        agent_checksum = compute_agent_checksum(components)
        registration_id = f"reg_{components.agent_id}_{int(time.time())}"
        
        # Check for duplicate checksums (impersonation attempt)
        for registrations in registered_agents.values():
            for registration in registrations:                 
                if registration.checksum == agent_checksum:
                    raise HTTPException(400, "Agent with identical checksum already exists")
        
        registration: Registration = Registration(
            app_id=registration_request.app_id, 
            agent_id=components.agent_id,
            registration_id=registration_id, 
            checksum=agent_checksum, 
            prompt=components.prompt_template, 
            tools=components.tools,
            registered_at=round(time.time() * 1000)
        )
        
        registration.version = self._compute_next_checksum_version(agent_id=components.agent_id, registration=registration)
        
        registered_agents[components.agent_id].append(registration)
        
        return {
            "agent_id": components.agent_id,
            "registration_id": registration_id,
            "checksum": agent_checksum
        }
    
    async def register_workflow(self, workflow: WorkflowDefinition):
        """Register a workflow definition"""
        for id, wf in registered_workflows.items(): 
            if id == workflow.workflow_id: 
                raise HTTPException(400, "A workflow has already been registerd with this id.")
            if wf == workflow or wf.steps == workflow.steps: 
                raise HTTPException(400, "Workflow with identical steps already exists")
        registered_workflows[workflow.workflow_id] = workflow
        return {"status": "registered", "workflow_id": workflow.workflow_id}
    
    async def mint_token(self, request: TokenRequest):
        """Mint intent token using agent checksum grant"""
        
        if request.grant_type != "agent_checksum":
            raise HTTPException(400, "Unsupported grant type")
        
        # 1. Validate agent exists and checksum matches
        if request.agent_id not in registered_agents:
            raise HTTPException(401, "Unknown agent")
        
        stored_checksum = registered_agents[request.agent_id][-1].checksum
        if request.computed_checksum != stored_checksum:
            raise HTTPException(401, "Agent checksum mismatch - code integrity violation")
        
        # 2. Validate workflow step authorization
        if not self._validate_workflow_step(request):
            raise HTTPException(403, "Agent not authorized for workflow step")
        
        # 3. Create intent token
        token = self._create_intent_token(request)
        
        token_response: TokenResponse = TokenResponse(
            access_token=token, 
            token_type="Bearer", 
            expires_in=300, # 5 minutes
            scope=request.requested_scopes
        )
        
        return token_response
    
    def _compute_next_checksum_version(self, agent_id: str, registration: Registration) -> str: 
        """
        Compute the next version for the current agent checksum being regisitered.
        """
        
        initial_version: str = "1.0.0"
        
        agent_history: List[Registration] = registered_agents.get(agent_id, [])
        
        if not agent_history: 
            return initial_version
        
        previous_registration: Registration = agent_history[-1]
        
        if not previous_registration.version: 
            return initial_version
        
        try: 
            major, minor, patch = map(int, previous_registration.version.split('.'))
        except (ValueError, AttributeError): 
            logger.warning(f"Invalid version format for {agent_id}: {previous_registration.version}")
            return initial_version
        
        change_type: ChangeType = self._detect_change_type(previous_registration, registration)
        
        if change_type == ChangeType.MAJOR: 
            return f"{major + 1}.0.0"
        elif change_type == ChangeType.MINOR: 
            return f"{major}.{minor + 1}.0"
        elif change_type == ChangeType.PATCH: 
            return f"{major}.{minor}.{patch + 1}"
        else: 
            return initial_version
    
    def _detect_change_type(self, previous_registration: Registration, registration: Registration) -> ChangeType: 
        """
        Determine what is the type of change for versioning.
        """
        
        # TODO: Replce with real implementation.
        return ChangeType.PATCH
    
    def _validate_workflow_step(self, request: TokenRequest) -> bool:
        """Validate agent is allowed to execute this workflow step"""
        workflow = registered_workflows.get(request.workflow_id)
        if not workflow:
            return False
            
        step_def = workflow.steps.get(request.workflow_step)
        if not step_def:
            return False
            
        return request.agent_id in step_def.get("allowed_agents", [])
    
    def _create_intent_token(self, request: TokenRequest) -> str:
        """Create JWT with intent claims"""
        now = int(time.time())
        
        payload = {
            "iss": os.getenv(EnvVars.ISSUER.value),
            "aud": request.audience,
            "sub": request.agent_id,
            "exp": now + 300,  # 5 minutes
            "iat": now,
            "jti": f"token_{uuid.uuid4().hex[:8]}",
            "scope": " ".join(request.requested_scopes),
            "intent": {
                "workflow_id": request.workflow_id,
                "workflow_step": request.workflow_step,
                "executed_by": request.agent_id,
                "delegation_chain": request.delegation_context.get("chain", [request.agent_id]) if request.delegation_context else [request.agent_id],
                "step_sequence_hash": self._compute_sequence_hash(request)
            },
            "agent_proof": {
                "agent_checksum": request.computed_checksum,
                "registration_id": registered_agents[request.agent_id]["registration_id"]
            }
        }
        
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    def _compute_sequence_hash(self, request: TokenRequest) -> str:
        """Compute hash of workflow execution sequence for integrity"""
        sequence = request.delegation_context.get("completed_steps", []) if request.delegation_context else []
        sequence.append(request.workflow_step)
        return hashlib.sha256("|".join(sequence).encode()).hexdigest()[:16]

idp_server = IntentServer()

@intent_router.post("/register/agent", dependencies=[Depends(require_auth(scopes=["register:intent"], audience="idp.localhost"))])
async def register_agent(registration_request: RegistrationRequest): 
    return await idp_server.register_agent(registration_request)

@intent_router.post("/batch_register/agent", dependencies=[Depends(require_auth(scopes=["register:intent"], audience="idp.localhost"))])
async def register_agent(batch_request: BatchRegistrationRequest): 
    registrations = []
    for request in batch_request.registration_requests: 
        registration = await idp_server.register_agent(request)
        registrations.append(registration)
    return registrations

@intent_router.post("/register/workflow", dependencies=[Depends(require_auth(scopes=["register:workflow"], audience="idp.localhost"))])
async def register_workflow(workflow_definition: WorkflowDefinition): 
    return await idp_server.register_workflow(workflow=workflow_definition)

@intent_router.post("/token")
async def mint_token(request: TokenRequest): 
    return await idp_server.mint_token(request)

@intent_router.get("/agents/{app_id}")
async def get_registered_agents(app_id: str): 
    return await idp_server.get_registered_agents(app_id)
