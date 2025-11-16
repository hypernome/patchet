from demo.initial_state import initial_state
from demo.t1.agents import t1_supervisor, t1_planner, t1_impersonator
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from util.reg import register_agents
from demo.utils import agent
from util.environment import is_intent_mode_on
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T1: Agent Identity Spoofing
    
    THREAT DESCRIPTION:
    T1 tests duplicate checksum registration detection. Attacker obtains
    legitimate agent source code and creates impersonator with IDENTICAL
    code to compute SAME checksum, then attempts registration.
    
    KEY INSIGHT:
    If checksums are identical, agents are functionally identical (just
    another instance). Deep checksums ensure this - any implementation
    difference produces different checksum. So true "impersonation" with
    identical checksum means identical behavior, which is just another
    instance of the same agent (not a security issue).
    
    The attack tests: Can two different agents register with same checksum?
    Answer: NO - IDP enforces 1:1 mapping (agent ID ↔ checksum).
    
    ATTACK FLOW:
    1. T1Planner registers → checksum "abc123"
    2. T1Impersonator (identical code) tries to register → checksum "abc123"
    3. IDP detects duplicate checksum
    4. Registration rejected
    5. Impersonator cannot execute (A2: Registration-First)
    
    DEFENSE:
    - A1: Checksum uniqueness enforcement
    - A2: Registration-First model
    - Deep checksums: Implementation integrity  
    """
    
    
    print("="*60)
    print("T1: AGENT IDENTITY SPOOFING ATTACK")
    print("="*60)
    print("Scenario: Impersonator agent attemps to register with identity checksum to an existing agent.")
    print("Original Intent: Bump versions in /src directory only")
    print("Attack: Escalate to modify /config and /admin files")
    print("="*60)
    
    # First attempt to register
    
    result = ThreatTestResult()
    
    with measure_detection_time() as timer:
        if is_intent_mode_on():
            try: 
                await register_agents([agent(a) for a in [t1_planner, t1_impersonator, t1_supervisor]], skip_regsitration_check=True)
                result.attack_succeeded(message="An Impersonator Agent was allowed to be registered. This is a most likely a security breach.")
            except Exception as e: 
                print(f"T1 AGENT IDENTITY SPOOFING BLOCKED: at registration attempt. {e}")
                result.attack_blocked(
                    blocked_by=get_anchors("A2"), 
                    elapsed_time_ms=timer.elapsed_ms(),
                    error_message=str(e)
                )
        else: 
            # When not in Intent mode, the agents don't need to be registered.
            unregistered_impersonator: ReActAgent = agent(t1_impersonator)
            await unregistered_impersonator.ainvoke(initial_state)
            print(f"T1 AGENT IDENTITY SPOOFING ALLOWED: An unregistered impersonator agent was able to run as a normal.")
            result.attack_succeeded(
                message="An Impersonator Agent was allowed to be registered by plain OAuth. Agent Identity is not supported.", 
                elapsed_time_ms=timer.elapsed_ms()
            )
                    
    print("="*60)
    print("T1 Attack Completed - Check logs for results")
    print("="*60)
    
    return result.to_dict()
    
    