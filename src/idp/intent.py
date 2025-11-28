# idp/server.py
from enum import Enum
from fastapi import APIRouter, HTTPException, Form, Depends, FastAPI, Request
import hashlib, jwt, time, uuid, logging, os
from typing import Dict, List, DefaultDict
from intentmodel.intent_model import (
    RegistrationRequest, 
    BatchRegistrationRequest,
    WorkflowDefinitionBatch,
    AgentComponents, 
    WorkflowDefinition, 
    WorkflowStep,
    TokenRequest, 
    Registration
)
from clientshim.secure_model import TokenResponse
from util.environment import EnvVars
from idp.oauth import priv_pem, KID
from util.commons import compute_agent_checksum
from idp.auth import require_auth
from contextlib import asynccontextmanager
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from itertools import takewhile
import base64
import json

logger = logging.getLogger(__name__)

intent_router = APIRouter(prefix="/intent")

# In-memory storage (We will probably use Redis/PostgreSQL in production)
REGISTRY_FILE = "../.runtime/agent-registry.json"
WORKFLOW_REGISTRY_FILE = "../.runtime/workflow-registry.json"

registered_agents: Dict[str, list[Registration]] = DefaultDict(list)
registered_workflows: Dict[str, list[WorkflowDefinition]] = DefaultDict(list)
active_executions: Dict[str, Dict] = {}

@asynccontextmanager
async def lifespan(app: FastAPI): 
    global registered_agents, registered_workflows
    if Path(REGISTRY_FILE).exists():
        with open(REGISTRY_FILE, 'r') as registry: 
            existing_regs = json.load(registry)
            registered_agents = DefaultDict(list, {
                agent_id: [Registration(**reg) for reg in regs]
                for agent_id, regs in existing_regs.items() 
            })
        logger.info(f"Loaded {len(registered_agents)} agent registrations.")
    
    if Path(WORKFLOW_REGISTRY_FILE).exists():
        with open(WORKFLOW_REGISTRY_FILE, 'r') as workflow_registry: 
            existing_wf_regs = json.load(workflow_registry)
            registered_workflows = DefaultDict(list, {
                workflow_id: [WorkflowDefinition(**wf_reg) for wf_reg in wf_regs]
                for workflow_id, wf_regs in existing_wf_regs.items()
            })
        logger.info(f"Loaded {len(registered_workflows)} agent registrations.")
    
    yield
    
    with open(REGISTRY_FILE, "w") as registry:
        json.dump({agent_id: [reg.model_dump() for reg in regs] for agent_id, regs in registered_agents.items()}, registry, indent=2)
    logger.info(f"Saved {len(registered_agents)} agent registrations.")
    
    with open(WORKFLOW_REGISTRY_FILE, "w") as workflow_registry:
        json.dump({workflow_id: [wf_reg.model_dump() for wf_reg in wf_regs] for workflow_id, wf_regs in registered_workflows.items()}, workflow_registry, indent=2)
    logger.info(f"Saved {len(registered_workflows)} workflow registrations.")
        
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
        # TODO: Fix the app_id search.
        for agent_id, registrations in registered_agents.items():
            if app_id == registrations[-1].app_id: 
                agents_by_app[app_id].append(registrations[-1])
        
        return agents_by_app
    
    async def get_single_agent(self, app_id: str, target_agent_id: str) -> List[Registration]: 
        """
        Fetch agents registered with IDP for a specific app.
        """
        
        target_agent = None
        
        # TODO: Fix the app_id search.
        for agent_id, registrations in registered_agents.items():
            if agent_id == target_agent_id and app_id == registrations[-1].app_id: 
                return registrations[-1]
    
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
            public_key=registration_request.public_key if registration_request.public_key else None,
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
        for id, wfs in registered_workflows.items(): 
            wf = wfs[-1]
            if id == workflow.workflow_id: 
                # raise HTTPException(400, "A workflow has already been registerd with this id.")
                logger.info("A workflow has already been registerd with this id.")
                return {"status": "skipped", "workflow_id": workflow.workflow_id}
            if wf == workflow or wf.steps == workflow.steps: 
                raise HTTPException(400, "Workflow with identical steps already exists")
        registered_workflows[workflow.workflow_id].append(workflow)
        return {"status": "registered", "workflow_id": workflow.workflow_id}
    
    async def deregister_workflow(self, workflow_id: str):
        """Register a workflow definition"""
        if workflow_id in registered_workflows:
            registered_workflows.pop(workflow_id, None)
        return {"status": "deregistered", "workflow_id": workflow_id}
    
    async def mint_token(self, request: TokenRequest, has_scopes: list[str] = []):
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
        if request.workflow_enabled:
            has_scopes = list(has_scopes)
            has_scopes.extend(request.requested_scopes)
            if not self._validate_workflow_step(request, has_scopes):
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
    
    def _validate_workflow_step(self, request: TokenRequest, has_scopes: list[str]) -> bool:
        """
        Validate agent is allowed to execute this workflow step
        """
        workflow: list[WorkflowDefinition] = registered_workflows.get(request.workflow_id)
        if not workflow:
            return False
        
        active_step = request.workflow_step
        if not active_step: 
            return False        
        
        step_id: str = active_step.get('step_id', '')
        agent_id: str = active_step.get('agent_id', '')
        
        steps: Dict[str, WorkflowStep] = workflow[-1].steps
            
        step_def: WorkflowStep = steps.get(step_id, None)
        if not step_def:
            return False
            
        if agent_id != step_def.agent: 
            logger.info(f"The Step: {step_id} of the workflow {request.workflow_id} is supposed to be executed by {step_def.agent}, but was executed by {agent_id}")
            return False
        
        active_tool: str = active_step.get('tool_name', None)
        if active_tool != step_def.action: 
            return False
        
        needed_scopes: list[str] = step_def.scopes
        if needed_scopes:
            # If the step was registered with scopes.
            missing_scopes = [s for s in needed_scopes if s not in has_scopes]
            if missing_scopes: 
                return False
        
        if not request.delegation_context: 
            return False
        
        completed_steps: list = request.delegation_context.get('completed_steps', None)
        
        if not completed_steps: 
            # First step of the workflow executing API call. This is most likely a breach if we are expecting dependencies in this step.
            return not step_def.dependencies
        
        completed_step_ids: set[str] = set([s['step_id'] for s in completed_steps])
        if step_def.dependencies:
            if not set(step_def.dependencies).issubset(completed_step_ids): 
                return False
        
        chain: list = request.delegation_context.get('chain', None)
        if not chain: 
            return False
        
        required_step_ids: list[str] = [step_key for step_key in list(takewhile(lambda x: steps[x].required == True and x != step_id, steps.keys()))]
        if required_step_ids:
            all_required_are_completed: bool = set(required_step_ids).issubset(set([s['step_id'] for s in completed_steps]))
            if not all_required_are_completed: 
                return False
            
        if step_def.requires_approval:
            has_approval: bool = self._check_approval(
                request.workflow_id, 
                steps,  
                step_id, 
                completed_steps
            )
            
            if not has_approval:
                return False
        
        return True
        
    def _check_approval(
        workflow_id: str,
        steps: Dict[str, WorkflowStep], 
        active_step_id: str,
        completed_steps: list
    ): 
        # Find the last approval gate BEFORE the current step
        approval_gate_before_current = None
        
        # Iterate through steps in order until we reach current step
        for step_key in steps.keys():
            if step_key == active_step_id:
                # Reached current step, stop looking
                break
            
            if steps[step_key].approval_gate:
                # This is an approval gate before current step
                approval_gate_before_current = step_key
        
        if not approval_gate_before_current:
            # Step requires approval but no approval gate defined before it
            logger.error(
                f"Step '{active_step_id}' requires_approval=True but no approval_gate "
                f"step defined before it in workflow '{workflow_id}'"
            )
            return False
        
        # Check if that specific approval gate has been completed
        completed_step_ids = [s['step_id'] for s in completed_steps]
        
        if approval_gate_before_current not in completed_step_ids:
            # The required approval gate was not completed
            logger.warning(
                f"Step '{active_step_id}' requires approval from '{approval_gate_before_current}' "
                f"but it was not completed. Completed steps: {completed_step_ids}"
            )
            return False
    
        logger.info(
            f"Step '{active_step_id}' approval requirement satisfied by '{approval_gate_before_current}'"
        )
        
        return True    
    
    def _create_intent_token(self, request: TokenRequest) -> str:
        """Create JWT with intent claims"""
        now = int(time.time())
        
        payload = {
            "iss": os.getenv(EnvVars.ISSUER.value),
            "aud": request.audience,
            "sub": request.agent_id,
            "exp": now + 3000,  # 5 minutes
            "iat": now,
            "jti": f"token_{uuid.uuid4().hex[:8]}",
            "scope": " ".join(request.requested_scopes),
            "cnf": {
                "jwk": self._pem_string_to_jwk(registered_agents[request.agent_id][-1].public_key)
            },
            "intent": {
                "workflow_id": request.workflow_id,
                "workflow_step": request.workflow_step,
                "executed_by": request.agent_id,
                "delegation_chain": self._compute_sequence_hash(request, request.delegation_context.get("chain", [request.agent_id]) if request.delegation_context else [request.agent_id]),
                "step_sequence_hash": self._compute_sequence_hash(request, request.delegation_context.get("completed_steps", []) if request.delegation_context else [])
            },
            "agent_proof": {
                "agent_checksum": request.computed_checksum,
                "registration_id": registered_agents[request.agent_id][-1].registration_id
            }
        }
        
        return jwt.encode(payload, self.private_key, algorithm="RS256", headers={"kid": KID})
    
    def _pem_string_to_jwk(self, public_key_pem: str) -> dict:
        """Convert PEM string to JWK format"""
        
        # Load public key from PEM string
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # Extract public key components
        public_numbers = public_key.public_numbers()
        
        # Convert integers to base64url format
        def int_to_base64url(val):
            byte_length = (val.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(
                val.to_bytes(byte_length, 'big')
            ).decode('ascii').rstrip('=')
        
        # Create JWK
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256", 
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e)
        }
    
    """
    def _compute_sequence_hash(self, request: TokenRequest) -> str:
        sequence = request.delegation_context.get("completed_steps", []) if request.delegation_context else []
        if request.workflow_step:
            sequence.append(str(request.workflow_step))
        return hashlib.sha256("|".join([str(step) for step in sequence]).encode()).hexdigest()[:16]    
    """

    def _compute_sequence_hash(self, request: TokenRequest, sequence: list) -> str:
        """
        Compute hash of workflow execution sequence for integrity
        """
        sequence = [str(step) for step in sequence]
        if request.workflow_step:
            sequence.append(str(request.workflow_step))
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

@intent_router.post("/batch_register/workflow", dependencies=[Depends(require_auth(scopes=["register:workflow"], audience="idp.localhost"))])
async def register_workflow(batch_request: WorkflowDefinitionBatch): 
    workflow_registrations = []
    for request in batch_request.workflow_definitions:
        workflow_registration = await idp_server.register_workflow(workflow=request)
        workflow_registrations.append(workflow_registration)
    return workflow_registrations

@intent_router.post("/deregister/workflow", dependencies=[Depends(require_auth(scopes=["register:workflow"], audience="idp.localhost"))])
async def register_workflow(workflow_id: str): 
    return await idp_server.deregister_workflow(workflow_id=workflow_id)

@intent_router.post("/token", dependencies=[Depends(require_auth(scopes=["generate:intent-token"], audience="idp.localhost"))])
async def mint_token(request: Request, token_request: TokenRequest): 
    has_scopes: list[str] = request.state.scopes if request.state.scopes else []
    return await idp_server.mint_token(token_request, has_scopes=has_scopes)

@intent_router.get("/agents/{app_id}", dependencies=[Depends(require_auth(scopes=["read:agents"], audience="idp.localhost"))])
async def get_registered_agents(app_id: str): 
    return await idp_server.get_registered_agents(app_id)

@intent_router.get("/agents/{app_id}/{target_agent_id}", dependencies=[Depends(require_auth(scopes=["read:agents"], audience="idp.localhost"))])
async def get_registered_agents(app_id: str, target_agent_id: str): 
    return await idp_server.get_single_agent(app_id, target_agent_id)