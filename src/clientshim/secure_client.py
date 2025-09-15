"""
Agentic JWT Shim Library
"""
import logging, os, threading, httpx,uuid, time, inspect, asyncio
from contextlib import asynccontextmanager
from clientshim.env import EnvParams
from clientshim.secure_model import AgentSpec, AgentIdentity, VerificationStatus, WorkflowStepStatus, TokenResponse
from intentmodel.intent_model import AgentComponents, Tool
from typing import Dict, Any, Optional, List, Callable, AsyncGenerator
from util.commons import compute_agent_checksum
from model.config import AuthProfileName, AuthProfile, token_profiles
from enum import Enum

class AuthMode(Enum): 
    """
    Represents whether authentication mode is OAuth or Intent.
    """
    oauth = "oauth", 
    intent = "intent"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Security-related errors in the shim library"""
    pass

class ConfigurationError(Exception):
    """Configuration-related errors"""
    pass


class SecureClient: 
    """
    Shim library for security agent authentication.
    
    Provides cryptographic agent identity verification and intent-based
    token authentication for autonomous AI agents.
    """
    
    def __init__(
        self, 
        app_id: str,
        idp_url: str = os.getenv(EnvParams.IDP_URL.value),
        agent_specs: List[AgentSpec] = [],
        timeout: int = 30,
        max_retries: int = 3):
        
        self.agent_specs = agent_specs
        self.app_id = app_id
        self.idp_url = idp_url
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Bridge identifier to verified agent identity mapping
        self.bridge_to_agent: Dict[Any, AgentIdentity] = {}
        
        # Verification tracking
        self.registered_checksums: Dict[str, str] = {}  # checksum -> agent_id
        self.registered_agent_ids: set = set()
        self.verification_status: Dict[str, VerificationStatus] = {}
        
        # Token caching
        self._token_cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()
        
        # HTTP client configuration
        self._http_client: Optional[httpx.AsyncClient] = None
        
        # Workflow state tracking
        self._workflow_state = threading.local()
        
        logger.info(f"SecureClient initialized for app_id={app_id}")
    
    async def _ensure_http_client(self):
        """Ensure HTTP client is initialized"""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
            )
    
    async def _close_http_client(self):
        """Close HTTP client"""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
    
    async def __aenter__(self):
        """
        Entry for Async context manager.
        """
        await self._ensure_http_client()
        return self

    async def __aexit__(self):
        """
        Exigt for Async context manager.
        """
        await self._close_http_client()
        
    def _get_step_id_for_tool(self, agent_id: str, tool_name: str) -> str:
        """
        Map agent + tool to workflow step ID
        """
        
        # Check if we have explicit mapping
        if hasattr(self, 'tool_to_step_mapping'):
            # First try agent-specific mapping
            agent_tool_key = f"{agent_id}.{tool_name}"
            if agent_tool_key in self.tool_to_step_mapping:
                return self.tool_to_step_mapping[agent_tool_key]
            
            # Then try global tool mapping
            if tool_name in self.tool_to_step_mapping:
                return self.tool_to_step_mapping[tool_name]
        
        # Default: use tool_name as step_id
        return tool_name.lower()
    
    def _record_tool_invocation(self, agent_id: str, tool_name: str, status: WorkflowStepStatus, error: str = None):
        """
        Record tool invocation in workflow state
        """
        
        # Get current timestamp
        timestamp = time.time()
        
        # Map tool to workflow step
        step_id = self._get_step_id_for_tool(agent_id, tool_name)
        
        if status == WorkflowStepStatus.STARTED:
            # Record active step
            active_step = {
                "step_id": step_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "started_at": timestamp
            }
            self.workflow_state["active_step"] = active_step
            
            logger.debug(f"Started step: {step_id} (agent: {agent_id}, tool: {tool_name})")
            
        elif status == WorkflowStepStatus.COMPLETED:
            # Move from active to completed
            active = self.workflow_state.get("active_step")
            
            if active and active["step_id"] == step_id:
                completed_step = {
                    "step_id": step_id,
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "started_at": active["started_at"],
                    "completed_at": timestamp,
                    "duration": timestamp - active["started_at"]
                }
                
                self.workflow_state["history"].append(completed_step)
                self.workflow_state["completed_steps"].append(completed_step)
                self.workflow_state["active_step"] = None
                
                logger.debug(f"Completed step: {step_id} in {completed_step['duration']:.2f}s")
                
        elif status == WorkflowStepStatus.FAILED:
            # Record failure
            active = self.workflow_state.get("active_step")
            
            if active and active["step_id"] == step_id:
                failed_step = {
                    "step_id": step_id,
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "started_at": active["started_at"],
                    "failed_at": timestamp,
                    "error": error
                }
                
                self.workflow_state["history"].append(failed_step)
                self.workflow_state["failed_steps"] = self.workflow_state.get("failed_steps", [])
                self.workflow_state["failed_steps"].append(failed_step)
                self.workflow_state["active_step"] = None
                
                logger.error(f"Failed step: {step_id} - {error}")
    
    def _create_workflow_tracking_wrapper(self, original_func: Callable, agent_id: str, tool_name: str): 
        """
        Create a wrapper function to execute around a function or callable that corresponds to an agentic tool. 
        This wrapper function will be used to track workflow steps.
        """
        if asyncio.iscoroutinefunction(original_func): 
            async def async_tool_wrapper(*args, **kwargs): 
                # Record workflow step before tool invocation.
                self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.STARTED)
                
                # Execute the original function.
                try:
                    result = await original_func(*args, **kwargs)
                except Exception as e: 
                    self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.FAILED, error=str(e))
                    raise
                
                # Record workflow step after tool invocation.
                self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.COMPLETED)
                
                return result
            return async_tool_wrapper
        else: 
            def sync_tool_wrapper(*args, **kwargs): 
                # Record workflow step before tool invocation.
                self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.STARTED)
                
                # Execute the original function.
                try:
                    result = original_func(*args, **kwargs)
                except Exception as e: 
                    self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.FAILED, error=str(e))
                    raise
                
                # Record workflow step after tool invocation.
                self._record_tool_invocation(agent_id, tool_name, WorkflowStepStatus.COMPLETED)
                
                return result
            return sync_tool_wrapper
    
    def _wrap_agent_tools(self, agent_spec: AgentSpec):
        """
        Wrap the given agent's tools for workflow tracking.
        """
        wrapped_tools = {}
        
        for original_tool_func in agent_spec.tools:
            wrapper_func = self._create_workflow_tracking_wrapper(
                original_func=original_tool_func, 
                agent_id=agent_spec.agent_id, 
                tool_name=original_tool_func.__name__
            )
            wrapped_tools[original_tool_func.__name__] = wrapper_func
            original_tool_func = wrapper_func
            
        return wrapped_tools
    
    async def _register_agents_on_client(self, agent_specs: List[AgentSpec]): 
        logger.info(f"Starting verification and registration {len(agent_specs)} agents")
        if not agent_specs: 
            logger.info(f"There are not agents to register.")
            return
        
        # As a first step, fetch ground truth from IDP
        try:
            idp_registered_agents: Dict[str, Dict] = await self._fetch_idp_registered_agents()
        except Exception as e:
            logger.error(f"Failed to fetch IDP registered agents: {e}")
            raise
        
        # Verify that the agents provided for client registration conform with IDP.
        verification_results = []
        for agent_spec in agent_specs: 
            try: 
                self._verify_single_agent(agent_spec, idp_registered_agents)
                verification_results.append(agent_spec.agent_id, VerificationStatus.VERIFIED)
                logger.info(f"Agent '{agent_spec.agent_id}' verified successfully")
            except Exception as e: 
                verification_results.append((agent_spec.agent_id, VerificationStatus.FAILED))
                logger.error(f"Agent '{agent_spec.agent_id}' verification failed: {e}")
                raise SecurityError(f"Agent '{agent_spec.agent_id}' verification failed: {e}")
        
        # Update verification status
        for agent_id, status in verification_results:
            self.verification_status[agent_id] = status
        
        logger.info("All agents verified and registered successfully")
        
    def _verify_single_agent(
        self, 
        agent_spec: AgentSpec,
        idp_registered_agents: Dict[str, Dict]) -> None:
        """
        Verify a single agent against IDP registration.
        
        Args:
            agent_instance: Agent instance to verify
            agent_id: Claimed agent identifier
            idp_registered_agents: IDP registered agents data
            
        Raises:
            SecurityError: If verification fails
        """
        # Check if agent_id is registered with IDP
        if agent_spec.agent_id not in idp_registered_agents:
            raise SecurityError(f"Agent '{agent_spec.agent_id}' not registered with IDP")
        
        # Check for duplicate agent_id in current registration
        if agent_spec.agent_id in self.registered_agent_ids:
            raise SecurityError(f"Duplicate agent_id in registration: {agent_spec.agent_id}")
        
        # Extract and compute checksum
        
        agent_components: AgentComponents = AgentComponents(
            agent_spec.agent_id, 
            prompt_template=agent_spec.prompt, 
            tools=[
                Tool(
                    tool.__name__, 
                    str(inspect.signature(tool)), 
                    tool.__doc__) 
                for tool in agent_spec.tools], 
            configuration=agent_spec.configuration            
        )
        
        computed_checksum = compute_agent_checksum(agent_components)
        
        wrapped_tools = self._wrap_agent_tools(agent_spec)
        
        # Get expected checksum from IDP
        idp_agent_data = idp_registered_agents[agent_spec.agent_id]
        expected_checksum = idp_agent_data.get("checksum")
        
        if not expected_checksum:
            raise SecurityError(f"No checksum found for agent '{agent_spec.agent_id}' in IDP")
        
        # Verify checksums match
        if computed_checksum != expected_checksum:
            raise SecurityError(
                f"Agent '{agent_spec.agent_id}' checksum mismatch. "
                f"Expected: {expected_checksum[:16]}..., "
                f"Got: {computed_checksum[:16]}..."
            )
        
        # Check for checksum collisions
        if computed_checksum in self.registered_checksums:
            existing_agent = self.registered_checksums[computed_checksum]
            raise SecurityError(
                f"Checksum collision: agent '{agent_spec.agent_id}' has same checksum as '{existing_agent}'"
            )
        
        # Create verified agent identity
        agent_identity = AgentIdentity(
            agent_id=agent_spec.agent_id,
            checksum=computed_checksum,
            registration_id=idp_agent_data.get("registration_id", ""),
            prompt=idp_agent_data.get("prompt", ""),
            tools=idp_agent_data.get("tools", ""),
            wrapped_tools=wrapped_tools,
            configuration=agent_components.configuration,
            registered_at=time.time()
        )
        
        # Store verified mapping using agent class as bridge identifier
        bridge_identifier = agent_spec.agent_bridge if isinstance(agent_spec.agent_bridge, Callable) else agent_spec.agent_bridge.__class__
        self.bridge_to_agent[bridge_identifier] = agent_identity
        self.registered_checksums[computed_checksum] = agent_spec.agent_id
        self.registered_agent_ids.add(agent_spec.agent_id)
        
        logger.debug(f"Agent '{agent_spec.agent_id}' registered with bridge: {bridge_identifier}")

    async def _fetch_idp_registered_agents(self) -> Dict[str, Dict]:
        """
        Fetch registered agents from IDP.
        
        Returns:
            Dictionary mapping agent_id to registration details
        """
        await self._ensure_http_client()
        
        try:
            response = await self._http_client.get(
                f"{self.idp_url}/agents/{self.app_id}",
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
            agents_by_app: Dict[str, List[Dict]] = response.json()
            registered_agents: List[Dict] = agents_by_app[self.app_id]
            agents_by_agent_id: Dict[str, Dict] = {}
            for agent in registered_agents: 
                agents_by_agent_id[agent['agent_id']] = agent            
            
            logger.info(f"Fetched {len(registered_agents)} registered agents from IDP")
            
            return agents_by_agent_id
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise ConfigurationError(f"Application {self.app_id} not found in IDP")
            else:
                raise SecurityError(f"Failed to fetch registered agents: {e}")
        except Exception as e:
            raise SecurityError(f"IDP communication error: {e}")
    
    def _detect_current_agent_context(self) -> AgentIdentity:
        """
        Detect current executing agent context from call stack.
        
        Returns:
            AgentIdentity of currently executing agent
            
        Raises:
            SecurityError: If no registered agent found in execution context
        """
        # Walk up the call stack to find registered agent
        for frame_info in inspect.stack():
            frame = frame_info.frame
            
            # Look for agent instance in local variables
            if 'self' in frame.f_locals:
                obj = frame.f_locals['self']
                bridge_identifier = obj.__class__
                
                # Check if this class is registered
                if bridge_identifier in self.bridge_to_agent:
                    agent_identity = self.bridge_to_agent[bridge_identifier]
                    logger.debug(f"Detected agent context: {agent_identity.agent_id}")
                    return agent_identity
        
        # No registered agent found in call stack
        raise SecurityError(
            "No registered agent found in execution context. "
            "Ensure agent is properly registered and executing within agent method."
        )
    
    def _get_cache_key(self, *key_components) -> str:
        """
        Generate cache key for token caching
        """
        return "|".join(key_components)
    
    def _is_token_valid(self, cached_token: Dict) -> bool:
        """Check if cached token is still valid"""
        expires_at = cached_token.get("expires_at", 0)
        return time.time() < (expires_at - 30) # Refresh token 30 seconds before expiry.
    
    async def _mint_intent_token(self, 
                                workflow_id: str,
                                agent_identity: AgentIdentity,
                                *scopes: List[str], 
                                audience: str) -> TokenResponse:
        """
        Request intent token from IDP using agent checksum grant.
        
        Args:
            agent_identity: Verified agent identity
            scope: Requested OAuth scope
            audience: Token audience
            
        Returns:
            TokenResponse with access token and metadata
        """
        await self._ensure_http_client()
        
        # Prepare delegation context
        delegation_context = {
            "workflow_id": workflow_id,
            "execution_id": self.workflow_state.get("current_execution_id"),
            "chain": self.workflow_state["history"].copy(),
            "completed_steps": self.workflow_state["completed_steps"].copy()
        }
        
        # Create token request
        token_request = {
            "grant_type": "agent_checksum",
            "agent_id": agent_identity.agent_id,
            "computed_checksum": agent_identity.checksum,
            "workflow_id": workflow_id,
            "workflow_step": self.workflow_state.get('active_step', {}),
            "requested_scopes": scopes,
            "audience": audience,
            "delegation_context": delegation_context
        }
        
        try:
            response = await self._http_client.post(
                f"{self.idp_url}/oauth/token",
                json=token_request,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            
            return TokenResponse(
                access_token=token_data["access_token"],
                token_type=token_data.get("token_type", "Bearer"),
                expires_in=token_data.get("expires_in", 300),
                scope=token_data.get("scope", " ".join(scopes))
            )
            
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text if e.response else "Unknown error"
            raise SecurityError(f"Token request failed: {e.response.status_code} - {error_detail}")
        except Exception as e:
            raise SecurityError(f"Token request error: {e}")
    
    @asynccontextmanager
    async def authenticated_request(
        self, 
        *scopes,
        audience: str = None, 
        workflow_id: str = None,
        auth_profile_nane: AuthProfileName = None,
        mode: AuthMode = AuthMode.intent,
    ) -> AsyncGenerator[httpx.AsyncClient, None]:
        """
        Context manager for authenticated HTTP requests.
        
        Args:
            scope: Required OAuth scope
            audience: Target audience for token
            
        Yields:
            Authenticated HTTP client
            
        Raises:
            SecurityError: If authentication fails
        """
        try: 
            cache_key: str = None
            if mode == AuthMode.intent: 
                agent_identity: AgentIdentity = self._detect_current_agent_context()
                cache_key = self._get_cache_key(workflow_id, agent_identity.agent_id, audience, "_".join(scopes))
            else: 
                cache_key = self._get_cache_key(self.app_id, audience, "_".join(scopes))
            
            with self._cache_lock:
                cached_token = self._token_cache.get(cache_key)
                if cached_token and self._is_token_valid(cached_token):
                    access_token = cached_token["access_token"]
                    logger.debug(f"Using cached token for {agent_identity.agent_id if mode == AuthMode.intent else self.app_id}")
                else:
                    cached_token = None
            
            if not cached_token: 
                token_response: TokenResponse = await self._mint_intent_token(agent_identity, workflow_id, scopes, audience) if mode == AuthMode.intent else await self._mint_oauth_token(auth_profile_nane, scopes, audience)
                access_token = token_response.access_token
                
                # Cache the token
                with self._cache_lock:
                    self._token_cache[cache_key] = {
                        "access_token": access_token,
                        "expires_at": time.time() + token_response.expires_in,
                        "scope": token_response.scope
                    }
                
                logger.debug(f"Minted fresh token for {agent_identity.agent_id if mode == AuthMode.intent else self.app_id}")
            
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "User-Agent": f"SecureClient/{self.app_id}"
            }
            
            # Create a new client with authentication headers
            async with httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=5)
            ) as authenticated_client:
                yield authenticated_client
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise SecurityError(f"Authentication failed: {str(e)}")
            
    async def _mint_oauth_token(self, auth_profile_name: AuthProfileName, scopes, audience: str = None): 
        """
        Mint an normal oauth or enhanced intent token based on the mode input.
        """
        await self._ensure_http_client()
        
        auth_profile: AuthProfile = token_profiles[auth_profile_name]
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        token_request = {
            "grant_type": "client_credentials", 
            "client_id": auth_profile.config.client_id, 
            "client_secret": auth_profile.config.client_secret, 
            "scope": " ".join(scopes) if scopes else auth_profile.config.scope,
            "audience": audience if audience else auth_profile.config.audience 
        }
        
        token_response = await self._http_client.post(
            url=f"{self.idp_url}/oauth/token", 
            data=token_request,
            headers=headers            
        )
        
        token_response.raise_for_status()
        token = token_response.json()
        
        return TokenResponse(
            access_token=token["access_token"],
            token_type=token.get("token_type", "Bearer"),
            expires_in=token.get("expires_in", 300),
            scope=token.get("scope", " ".join(scopes))
        )
        
    
    @property
    def workflow_state(self):
        """
        Get thread-local workflow state
        """
        if not hasattr(self._workflow_state, 'data'):
            self._workflow_state.data = {
                "execution_id": f"exec_{uuid.uuid4().hex[:8]}",
                "completed_steps": [],
                "failed_steps": [],
                "history": [],
                "active_step": None,
                "started_at": time.time()
            }
        return self._workflow_state.data
    
    @workflow_state.setter
    def workflow_state(self, value):
        """
        Set thread-local workflow state
        """
        self._workflow_state.data = value

def _secure_factory(): 
    """
    Closure for secure client initialization.
    """
    _secure_client: SecureClient = None
    
    async def init_security(
        agent_specs: List[AgentSpec], 
        app_id: str = os.getenv(EnvParams.APP_ID.value),
        idp_url: str = os.getenv(EnvParams.IDP_URL.value)): 
        """
        Initialize agent security by verifying agent registrations and creating 
        and returning a SecureClient instance.
        """
        nonlocal _secure_client
        
        if not _secure_client:
            _secure_client = SecureClient(
                app_id=app_id, 
                idp_url=idp_url,
                agent_specs=agent_specs
            )
        
        if agent_specs:                
            await _secure_client._register_agents_on_client(agent_specs)
    
    def get_secure_client() -> SecureClient: 
        if not _secure_client: 
            raise RuntimeError('SecureClient is not initialized yet. Call init_security() first.')
        return _secure_client

    return init_security, get_secure_client

_init, _get = _secure_factory()
    
init_security = _init
get_secure_client = _get