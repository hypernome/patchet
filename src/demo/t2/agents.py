"""
T2: Token Replay Attacks - Agent Definitions

This module defines the agents used in T2 testing:
- GenuinePlanner: Legitimate agent that obtains a valid intent token
- MaliciousPlanner: Attack agent that replays the captured token
- Supervisor: Orchestrates the attack sequence

Threat: T2 - Token Replay Attacks (Spoofing)
OWASP: A02:2021 - Cryptographic Failures
Description: Intercepted intent tokens are replayed by unauthorized agents
Attack: Network interception or memory dumps expose valid tokens that are replayed before expiration
"""

from demo.demo_registrations import declared_agents
import demo.t2.tools

# Global variable to capture the minted token (simulates token theft/interception)
minted_token = None

# ==============================================================================
# GENUINE PLANNER AGENT
# ==============================================================================
# This agent legitimately obtains an intent token through proper SecureClient flow
t2_genuine_planner = {
    "name": "T2GenuinePlanner",
    "prompt": """
    You are a Genuine Planner agent for automated SBOM patching system.
    
    Your job:
    1. Call 't2_bump_versions' tool to apply patches using legitimate authentication
    2. This tool will obtain a proper intent token through SecureClient
    3. Once 't2_bump_versions' completes successfully, call 'Done' tool
    
    You represent the legitimate use case where an agent properly authenticates
    and obtains authorization tokens through the correct security protocols.
    """,
    "tools": [
        {"name": "t2_bump_versions"}
    ],
    "register_as_tool": True
}

# ==============================================================================
# MALICIOUS PLANNER AGENT  
# ==============================================================================
# This agent attempts to replay the captured token without proper authentication
t2_malicious_planner = {
    "name": "T2MaliciousPlanner",
    "prompt": """
    You are a Malicious Planner agent attempting token replay attack.
    
    Your job:
    1. Call 't2_malicious_bump_versions' tool to apply patches using replayed token
    2. This tool will bypass SecureClient and use the captured token directly
    3. Once 't2_malicious_bump_versions' completes, call 'Done' tool
    
    You represent the attack scenario where an unauthorized agent attempts to
    reuse a stolen/intercepted token without proper authentication.
    
    Expected Outcome:
    - OAuth Mode: Attack succeeds (bearer tokens can be replayed)
    - Intent Mode: Attack blocked (token binding prevents replay)
    """,
    "tools": [
        {"name": "t2_malicious_bump_versions"}
    ],
    "register_as_tool": True
}

# ==============================================================================
# SUPERVISOR AGENT
# ==============================================================================
# Orchestrates the attack sequence: legitimate token minting followed by replay attempt
t2_supervisor = {
    "name": "T2Supervisor",
    "prompt": """
    You are the Supervisor agent orchestrating the T2 Token Replay Attack test.
    
    Execute the following sequence:
    1. Run 'T2GenuinePlanner' - this mints a legitimate intent token
    2. Run 'T2MaliciousPlanner' - this attempts to replay the captured token
    3. Call 'Done' when both steps complete
    
    This test validates that the system can detect and prevent token replay attacks.
    """,
    "tools": [
        {
            "name": "T2GenuinePlanner", 
            "from_agent": "T2GenuinePlanner"
        },
        {
            "name": "T2MaliciousPlanner",
            "from_agent": "T2MaliciousPlanner"
        }
    ],
    "register_as_tool": False  # Supervisor is the entry point
}

# Register all T2 agents
declared_agents.extend([
    t2_genuine_planner,
    t2_malicious_planner,
    t2_supervisor
])