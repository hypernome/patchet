"""
Agentic JWT Shim Library
"""
import hashlib, json, inspect, httpx, time, uuid, threading, asyncio
from typing import Dict, List, Optional, Any, Union, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
from intentmodel.intent_model import AgentIdentity, VerificationStatus, TokenResponse

# Configure logging
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
    Production-ready shim library for secure agent authentication.
    
    Provides cryptographic agent identity verification and intent-based
    token authentication for autonomous AI agents.
    """
    
    def __init__(self, 
                 idp_url: str,
                 app_id: str, 
                 workflow_id: str,
                 timeout: int = 30,
                 max_retries: int = 3):
        """
        Initialize the secure client.
        
        Args:
            idp_url: URL of the Identity Provider
            app_id: Application identifier  
            workflow_id: Workflow identifier
            timeout: HTTP request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.idp_url = idp_url.rstrip('/')
        self.app_id = app_id
        self.workflow_id = workflow_id
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
        self.workflow_state = {
            "current_execution_id": None,
            "completed_steps": [],
            "started_at": None
        }
        
        logger.info(f"SecureClient initialized for app_id={app_id}, workflow_id={workflow_id}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_http_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_http_client()

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

    def _extract_agent_components(self, agent_instance: Any) -> Dict[str, Any]:
        """
        Extract identity components from agent instance.
        
        This method attempts to extract prompt, tools, and configuration
        from various agent framework patterns.
        """
        components = {
            "prompt_components": {},
            "tool_signatures": [],
            "configuration": {}
        }
        
        # Extract prompt components (try common patterns)
        prompt_attrs = [
            'prompt', 'prompt_template', 'system_prompt', 'instruction',
            'planner_prompt', 'classifier_prompt', 'patcher_prompt', 'supervisor_prompt'
        ]
        
        for attr in prompt_attrs:
            if hasattr(agent_instance, attr):
                value = getattr(agent_instance, attr)
                if value and isinstance(value, str):
                    components["prompt_components"][attr] = value
        
        # Extract tool signatures
        tool_attrs = [
            'tools', 'planner_tools', 'classifier_tools', 'patcher_tools'
        ]
        
        for attr in tool_attrs:
            if hasattr(agent_instance, attr):
                tools = getattr(agent_instance, attr)
                if tools and isinstance(tools, list):
                    for tool in tools:
                        if hasattr(tool, 'name') and hasattr(tool, 'func'):
                            signature = self._get_function_signature(tool.func)
                            components["tool_signatures"].append({
                                "name": tool.name,
                                "signature": signature,
                                "description": getattr(tool, 'description', '')
                            })
        
        # Extract configuration
        config_attrs = ['config', 'configuration', 'settings']
        for attr in config_attrs:
            if hasattr(agent_instance, attr):
                config = getattr(agent_instance, attr)
                if config and isinstance(config, dict):
                    components["configuration"].update(config)
        
        # Add agent class information
        components["configuration"]["agent_class"] = agent_instance.__class__.__name__
        components["configuration"]["agent_module"] = agent_instance.__class__.__module__
        
        return components

    def _get_function_signature(self, func: Callable) -> str:
        """Get normalized function signature for checksum computation"""
        try:
            sig = inspect.signature(func)
            return f"{func.__name__}{sig}"
        except Exception as e:
            logger.warning(f"Failed to get signature for {func}: {e}")
            return f"{func.__name__}()"

    def _compute_agent_checksum(self, components: Dict[str, Any]) -> str:
        """
        Compute deterministic checksum for agent identity components.
        
        Args:
            components: Agent identity components
            
        Returns:
            SHA-256 checksum as hex string
        """
        # Normalize components for consistent hashing
        normalized = {
            "prompt_components": dict(sorted(components.get("prompt_components", {}).items())),
            "tool_signatures": sorted(
                components.get("tool_signatures", []),
                key=lambda x: x.get("name", "")
            ),
            "configuration": dict(sorted(components.get("configuration", {}).items()))
        }
        
        # Create deterministic JSON representation
        content = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
        
        # Compute SHA-256 checksum
        checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        logger.debug(f"Computed checksum: {checksum[:16]}... for components")
        return checksum

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
            
            registered_agents = response.json()
            logger.info(f"Fetched {len(registered_agents)} registered agents from IDP")
            
            return registered_agents
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise ConfigurationError(f"Application {self.app_id} not found in IDP")
            else:
                raise SecurityError(f"Failed to fetch registered agents: {e}")
        except Exception as e:
            raise SecurityError(f"IDP communication error: {e}")

    async def verify_and_register_agents(self, agents_to_register: List[tuple]) -> None:
        """
        Verify and register agents with startup-time validation.
        
        Args:
            agents_to_register: List of (agent_instance, agent_id) tuples
            
        Raises:
            SecurityError: If any agent fails verification
            ConfigurationError: If configuration is invalid
        """
        logger.info(f"Starting verification and registration of {len(agents_to_register)} agents")
        
        # Fetch ground truth from IDP
        try:
            idp_registered_agents = await self._fetch_idp_registered_agents()
        except Exception as e:
            logger.error(f"Failed to fetch IDP registered agents: {e}")
            raise
        
        # Verify each agent
        verification_results = []
        
        for agent_instance, agent_id in agents_to_register:
            try:
                await self._verify_single_agent(
                    agent_instance, 
                    agent_id, 
                    idp_registered_agents
                )
                verification_results.append((agent_id, VerificationStatus.VERIFIED))
                logger.info(f"Agent '{agent_id}' verified successfully")
                
            except Exception as e:
                verification_results.append((agent_id, VerificationStatus.FAILED))
                logger.error(f"Agent '{agent_id}' verification failed: {e}")
                raise SecurityError(f"Agent '{agent_id}' verification failed: {e}")
        
        # Update verification status
        for agent_id, status in verification_results:
            self.verification_status[agent_id] = status
            
        logger.info("All agents verified and registered successfully")

    async def _verify_single_agent(self, 
                                 agent_instance: Any,
                                 agent_id: str, 
                                 idp_registered_agents: Dict) -> None:
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
        if agent_id not in idp_registered_agents:
            raise SecurityError(f"Agent '{agent_id}' not registered with IDP")
        
        # Check for duplicate agent_id in current registration
        if agent_id in self.registered_agent_ids:
            raise SecurityError(f"Duplicate agent_id in registration: {agent_id}")
        
        # Extract and compute checksum
        components = self._extract_agent_components(agent_instance)
        computed_checksum = self._compute_agent_checksum(components)
        
        # Get expected checksum from IDP
        idp_agent_data = idp_registered_agents[agent_id]
        expected_checksum = idp_agent_data.get("checksum")
        
        if not expected_checksum:
            raise SecurityError(f"No checksum found for agent '{agent_id}' in IDP")
        
        # Verify checksums match
        if computed_checksum != expected_checksum:
            raise SecurityError(
                f"Agent '{agent_id}' checksum mismatch. "
                f"Expected: {expected_checksum[:16]}..., "
                f"Got: {computed_checksum[:16]}..."
            )
        
        # Check for checksum collisions
        if computed_checksum in self.registered_checksums:
            existing_agent = self.registered_checksums[computed_checksum]
            raise SecurityError(
                f"Checksum collision: agent '{agent_id}' has same checksum as '{existing_agent}'"
            )
        
        # Create verified agent identity
        agent_identity = AgentIdentity(
            agent_id=agent_id,
            checksum=computed_checksum,
            registration_id=idp_agent_data.get("registration_id", ""),
            prompt_components=components.get("prompt_components", {}),
            tool_signatures=components.get("tool_signatures", []),
            configuration=components.get("configuration", {}),
            registered_at=time.time()
        )
        
        # Store verified mapping using agent class as bridge identifier
        bridge_identifier = agent_instance.__class__
        self.bridge_to_agent[bridge_identifier] = agent_identity
        self.registered_checksums[computed_checksum] = agent_id
        self.registered_agent_ids.add(agent_id)
        
        logger.debug(f"Agent '{agent_id}' registered with bridge: {bridge_identifier}")

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

    async def _mint_intent_token(self, 
                                agent_identity: AgentIdentity,
                                scope: str, 
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
            "chain": [agent_identity.agent_id],
            "completed_steps": self.workflow_state["completed_steps"].copy(),
            "execution_id": self.workflow_state.get("current_execution_id"),
            "workflow_id": self.workflow_id
        }
        
        # Create token request
        token_request = {
            "grant_type": "agent_checksum",
            "agent_id": agent_identity.agent_id,
            "computed_checksum": agent_identity.checksum,
            "workflow_id": self.workflow_id,
            "workflow_step": self._infer_workflow_step(),
            "requested_scope": scope,
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
                scope=token_data.get("scope", scope)
            )
            
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text if e.response else "Unknown error"
            raise SecurityError(f"Token request failed: {e.response.status_code} - {error_detail}")
        except Exception as e:
            raise SecurityError(f"Token request error: {e}")

    def _infer_workflow_step(self) -> str:
        """
        Infer current workflow step from call stack.
        
        Returns:
            Workflow step identifier
        """
        # Method name to workflow step mapping
        STEP_MAPPING = {
            "list_files": "file-listing",
            "generate_sbom_with_vulns": "sbom-generation",
            "triage_vulns": "vulnerability-analysis",
            "bump_versions": "patching",
            "create_patch_plan": "patch-planning",
            "search_patterns_in_file_tree": "ecosystem-classification",
            "transform_identified_ecosystems": "ecosystem-classification",
            "regenerate_sbom": "sbom-regeneration"
        }
        
        # Look for method name in call stack
        for frame_info in inspect.stack():
            method_name = frame_info.function
            if method_name in STEP_MAPPING:
                return STEP_MAPPING[method_name]
        
        return "unknown"

    def _get_cache_key(self, agent_id: str, scope: str, audience: str) -> str:
        """Generate cache key for token caching"""
        return f"{agent_id}:{scope}:{audience}:{self.workflow_id}"

    def _is_token_valid(self, cached_token: Dict) -> bool:
        """Check if cached token is still valid"""
        expires_at = cached_token.get("expires_at", 0)
        return time.time() < (expires_at - 30)  # 30 second buffer

    @asynccontextmanager
    async def authenticated_request(self, scope: str, audience: str):
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
            # 1. Detect current agent context
            agent_identity = self._detect_current_agent_context()
            
            # 2. Check token cache
            cache_key = self._get_cache_key(agent_identity.agent_id, scope, audience)
            
            with self._cache_lock:
                cached_token = self._token_cache.get(cache_key)
                if cached_token and self._is_token_valid(cached_token):
                    access_token = cached_token["access_token"]
                    logger.debug(f"Using cached token for {agent_identity.agent_id}")
                else:
                    cached_token = None
            
            # 3. Get fresh token if needed
            if not cached_token:
                token_response = await self._mint_intent_token(agent_identity, scope, audience)
                access_token = token_response.access_token
                
                # Cache the token
                with self._cache_lock:
                    self._token_cache[cache_key] = {
                        "access_token": access_token,
                        "expires_at": time.time() + token_response.expires_in,
                        "scope": token_response.scope
                    }
                
                logger.debug(f"Minted fresh token for {agent_identity.agent_id}")
            
            # 4. Create authenticated HTTP client
            await self._ensure_http_client()
            
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
                
            # 5. Record step completion
            self._record_step_completion(agent_identity.agent_id)
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise SecurityError(f"Authentication failed: {str(e)}")

    def _record_step_completion(self, agent_id: str):
        """Record workflow step completion"""
        step = self._infer_workflow_step()
        
        if not self.workflow_state["current_execution_id"]:
            self.workflow_state["current_execution_id"] = f"exec_{uuid.uuid4().hex[:8]}"
            self.workflow_state["started_at"] = time.time()
        
        completion_record = {
            "step": step,
            "agent": agent_id,
            "timestamp": time.time()
        }
        
        self.workflow_state["completed_steps"].append(completion_record)
        logger.debug(f"Recorded step completion: {step} by {agent_id}")

    def start_workflow(self, initiated_by: str):
        """
        Start a new workflow execution.
        
        Args:
            initiated_by: Agent ID that initiated the workflow
        """
        self.workflow_state = {
            "current_execution_id": f"exec_{uuid.uuid4().hex[:8]}",
            "completed_steps": [],
            "started_at": time.time(),
            "initiated_by": initiated_by
        }
        logger.info(f"Started workflow {self.workflow_id} initiated by {initiated_by}")

    def get_workflow_state(self) -> Dict:
        """Get current workflow state"""
        return self.workflow_state.copy()

    def get_verification_status(self) -> Dict[str, str]:
        """Get verification status for all agents"""
        return {agent_id: status.value for agent_id, status in self.verification_status.items()}

    def get_registered_agents(self) -> List[str]:
        """Get list of successfully registered agent IDs"""
        return list(self.registered_agent_ids)

    async def close(self):
        """Clean up resources"""
        await self._close_http_client()
        with self._cache_lock:
            self._token_cache.clear()
        logger.info("SecureClient closed")

# Global singleton instance
_global_secure_client: Optional[SecureClient] = None

def initialize_secure_client(idp_url: str, 
                           app_id: str, 
                           workflow_id: str,
                           **kwargs) -> SecureClient:
    """
    Initialize the global secure client instance.
    
    Args:
        idp_url: URL of the Identity Provider
        app_id: Application identifier
        workflow_id: Workflow identifier
        **kwargs: Additional SecureClient arguments
        
    Returns:
        SecureClient instance
    """
    global _global_secure_client
    _global_secure_client = SecureClient(idp_url, app_id, workflow_id, **kwargs)
    logger.info(f"Global SecureClient initialized for {app_id}")
    return _global_secure_client

def get_secure_client() -> SecureClient:
    """
    Get the global secure client instance.
    
    Returns:
        SecureClient instance
        
    Raises:
        ConfigurationError: If client not initialized
    """
    if _global_secure_client is None:
        raise ConfigurationError(
            "Secure client not initialized. Call initialize_secure_client() first."
        )
    return _global_secure_client

# Convenience decorator for agent classes
def secure_agent(agent_id: str, **metadata):
    """
    Decorator to mark agent classes for registration.
    
    Args:
        agent_id: Agent identifier
        **metadata: Additional metadata for the agent
        
    Returns:
        Decorated class with security metadata
    """
    def decorator(cls):
        cls._secure_agent_id = agent_id
        cls._secure_metadata = metadata
        return cls
    return decorator

# Export public API
__all__ = [
    'SecureClient',
    'SecurityError', 
    'ConfigurationError',
    'AgentIdentity',
    'TokenResponse',
    'VerificationStatus',
    'initialize_secure_client',
    'get_secure_client',
    'secure_agent'
]