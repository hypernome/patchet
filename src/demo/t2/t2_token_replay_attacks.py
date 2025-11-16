from demo.initial_state import initial_state
from demo.t2.agents import t2_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t2.workflows import t2_workflow
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T2: Token Replay Attacks
    
    THREAT DESCRIPTION:
    T2 tests the system's ability to detect and prevent TOKEN REPLAY attacks
    where an intercepted or stolen intent token is reused by an unauthorized
    agent without proper authentication or cryptographic proof of possession.
    
    ATTACK SCENARIO:
    Phase 1: Legitimate agent obtains intent token
    Phase 2: Token is captured (simulating network interception/memory dump)
    Phase 3: Malicious agent replays captured token without authentication
    
    The attack tests whether tokens are cryptographically bound to the
    requesting agent and whether the system validates:
    1. Agent identity (checksum binding)
    2. Proof-of-Possession (PoP) keys
    3. Execution context
    4. Delegation chain integrity
    
    ATTACK FLOW:
    1. Supervisor calls T2GenuinePlanner
       → Authenticates via SecureClient
       → IDP mints intent token with bindings:
          * Agent checksum (identity)
          * PoP public key (possession)
          * Execution context (workflow)
          * Delegation chain (audit)
       → Token captured in global variable (simulating theft)
    
    2. Supervisor calls T2MaliciousPlanner
       → BYPASSES SecureClient authentication
       → Uses raw HTTP client with replayed token
       → No checksum computation
       → No PoP key verification
       → Attempts API call with stolen token
    
    3. Resource Server validates token
       → Checks token signature and expiry
       → Validates agent checksum binding
       → Validates PoP key possession
       → Validates execution context
    
    EXPECTED BEHAVIOR:
    
    OAuth Mode: Attack succeeds (Vulnerability!)
    - OAuth checks: "Is token signature valid?" → YES
    - OAuth checks: "Is token expired?" → NO
    - OAuth checks: "Does token have required scope?" → YES
    - OAuth DOES NOT check: Token binding to agent
    - OAuth DOES NOT check: PoP key verification
    - OAuth DOES NOT check: Execution context
    - Attack succeeds: Token replay accepted, unauthorized operation executed
    
    Intent Mode: Attack blocked (Protection Working!)
    - Intent checks: Token signature valid? → YES
    - Intent checks: Token expired? → NO
    - Intent checks: Required scope? → YES
    - Intent checks: Agent checksum matches? → NO (different agent!)
    - Intent checks: PoP key proof provided? → NO (can't prove possession!)
    - Intent checks: Execution context matches? → NO (different context!)
    - Security Error: "Token binding validation failed"
    - Attack blocked: Token replay rejected, operation denied
    
    KEY VALIDATIONS TESTED:
    1. Token Binding: Token cryptographically bound to agent identity
    2. PoP Verification: Proof-of-possession required for token use
    3. Checksum Validation: Agent identity must match token binding
    4. Context Validation: Execution context must match token issuance
    
    REAL-WORLD ANALOGY:
    Like credit card fraud - stealing a credit card number (bearer token)
    vs. stealing a card with chip+PIN (bound token). The chip validates
    the physical card possession, just like PoP validates agent identity.
    
    OWASP MAPPING:
    - A02:2021 - Cryptographic Failures
    - Category: Spoofing (impersonating legitimate agent)
    
    REAL-WORLD PRECEDENT:
    - 2014 Heartbleed (CVE-2014-0160): Memory disclosure leading to token theft
    - OAuth bearer tokens can be replayed if intercepted
    
    MITIGATIONS TESTED:
    - A1: Agent Checksum Verification (identity binding)
    - A3: Bridge Identifier Binding (agent-token cryptographic link)
    - A4: Client Credentials Prerequisite (authentication required)
    - A7: Intent Token Structure (includes binding information)
    """
    result = ThreatTestResult()
    print("=" * 70)
    print("T2: TOKEN REPLAY ATTACKS")
    print("=" * 70)
    print("Scenario: Replay stolen intent token without authentication")
    print("")
    print("Phase 1: Legitimate agent obtains token")
    print("Phase 2: Token captured (simulating theft)")
    print("Phase 3: Malicious agent replays token")
    print("")
    print("Expected: OAuth allows replay, Intent blocks replay")
    print("=" * 70)
    print("")
    
    # Start workflow execution
    secure_client = get_secure_client()
    # secure_client.start_workflow_execution("t2-token-replay-v1.0")
    
    # Get supervisor agent
    t2_supervisor_agent: ReActAgent = secure_client.get_agent(
        t2_supervisor.get('name', '')
    )
    
    # Trigger the attack
    print("Starting attack: Supervisor will execute token capture and replay...")
    print("")
    with measure_detection_time() as timer: 
      try: 
         attack_result = await t2_supervisor_agent.ainvoke(initial_state)
         tool_output = attack_result.get('tool_outputs', None)
         result.attack_succeeded(
            message="ATTACK SUCCEEDED: Token replay was NOT detected, Unauthorized operation executed with stolen token.", 
            elapsed_time_ms=timer.elapsed_ms()  
         )
         result.add_detail("tool_result", tool_output)
      except Exception as e: 
         result.attack_blocked(
            blocked_by=get_anchors("A6"), 
            elapsed_time_ms=timer.elapsed_ms(),
            error_message=str(e)
         )
    
    print("=" * 70)
    
    return result.to_dict()