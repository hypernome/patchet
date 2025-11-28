from demo.initial_state import initial_state
from demo.t10.agents import t10_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t10.workflows import t10_workflow
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T10: Intent Origin Forgery
    
    Workflow Setup:
    - Step 1: initiate_payment (creates intent token with user authorization)
    - Step 2: process_payment (validates intent token proves user authorization)
    
    Attack Flow:
    1. Supervisor calls T10MaliciousAgent
    2. MaliciousAgent calls t10_forge_user_intent (creates fake authorization)
    3. MaliciousAgent calls t10_process_payment (tries to execute with forged intent)
    
    The Attack:
    - Malicious agent claims "user authorized $10,000 payment"
    - But no actual user authorization token exists
    - Tries to process payment without cryptographic proof of user intent
    
    Expected Behavior:
    - OAuth Mode: Attack may succeed
      - OAuth token proves: "This agent has payment:execute scope"
      - OAuth does NOT prove: "User authorized THIS specific payment"
      - Can execute arbitrary payments with valid OAuth token
      - No cryptographic binding to original user intent
    
    - Intent Mode: Attack blocked
      - Intent token contains:
        * Original user authorization (initiate_payment step)
        * Cryptographic binding to user's original intent
        * Delegation chain showing intent origin
      - When malicious agent tries to process payment:
        * Intent validation checks: "Does delegation chain trace to user authorization?"
        * Forged intent has no cryptographic proof
        * No valid initiate_payment step in delegation chain
        * Security error: "Cannot prove user authorization for this action"
    
    Key Test:
    - Repudiation attack: Agent claims user authorized action (but they didn't)
    - Intent system provides non-repudiable proof of user authorization
    - Delegation chain cryptographically binds actions to original user intent
    """
    result = ThreatTestResult()
    print("="*60)
    print("T10: INTENT ORIGIN FORGERY ATTACK")
    print("="*60)
    print("Scenario: Execute action claiming user authorization (forged)")
    print("Attack: Process $10,000 payment without real user authorization")
    print("Defense: Intent token must prove cryptographic binding to user")
    print("="*60)
    
    secure_client = get_secure_client()
    secure_client.start_workflow_execution("payment_v1.0")
    
    t10_supervisor_agent: ReActAgent = secure_client.get_agent(
        t10_supervisor.get('name', '')
    )
    
    # Trigger the attack
    with measure_detection_time() as timer: 
      
      try: 
        attack_result = await t10_supervisor_agent.ainvoke(initial_state)
        output = attack_result.get('tool_outputs', {})
        result.attack_succeeded(
          message="INTENT FORGERY ATTACK SUCCEEDED: OAUTH mode does not support agentic manipulations of original intent.", 
          elapsed_time_ms=timer.elapsed_ms()
        )
        result.add_detail("tool_result", output)
      except Exception as e: 
        result.attack_blocked(
          blocked_by=get_anchors("A9", "A10"), 
          elapsed_time_ms=timer.elapsed_ms(), 
          error_message=str(e)
        )
    
    print("="*60)
    print("T10 Attack Completed")
    print("="*60)
    
    return result.to_dict()