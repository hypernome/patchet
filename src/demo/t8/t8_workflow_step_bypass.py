from demo.initial_state import initial_state
from demo.t8.agents import t8_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t8.workflows import t8_workflow
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T8: Workflow Step Bypass
    
    Attack Flow:
    1. Supervisor calls Planner (prepares deployment)
    2. Workflow REQUIRES Reviewer approval (step 2)
    3. Malicious Deployer skips Reviewer and tries to deploy directly
    4. Attempts to forge approval without actual review
    
    Expected Behavior:
    - OAuth Mode: Attack succeeds
      - Deployer has deploy:production scope
      - No workflow step validation
      - Bypasses required approval gate
    
    - Intent Mode: Attack blocked
      - Intent token validates workflow step sequence
      - Detects missing "review_deployment" step
      - Delegation chain shows approval gate was skipped
      - Security error: "Required workflow step not completed"
    
    Key Test:
    - Workflow requires: prepare → review → deploy
    - Attack attempts: prepare → deploy (skip review)
    - Intent system validates step dependencies
    """
    result = ThreatTestResult()
    print("="*60)
    print("T8: WORKFLOW STEP BYPASS ATTACK")
    print("="*60)
    print("Scenario: Skip required security review before deployment")
    print("Required Flow: Planner → Reviewer → Deployer")
    print("Attack Flow: Planner → [SKIP REVIEWER] → Deployer")
    print("="*60)
    
    t8_supervisor_agent: ReActAgent = get_secure_client().get_agent(
        t8_supervisor.get('name', '')
    )
    
    # Trigger the attack
    
    with measure_detection_time() as timer: 
      try: 
        attack_result = await t8_supervisor_agent.ainvoke(initial_state)
        output = attack_result.get('tool_outputs', {})
        result.attack_succeeded(
          message="ATTACK SUCCEEDED: Plain OAuth execution. Agentic workflow attack could not be prevented.", 
          elapsed_time_ms=timer.elapsed_ms()
        )
        result.add_detail("tool_result", output)
      except Exception as e: 
        result.attack_blocked(
          blocked_by=get_anchors("A8", "A10"), 
          elapsed_time_ms=timer.elapsed_ms(), 
          error_message=str(e)
        )
    
    print("="*60)
    print("T8 Attack Completed")
    print("="*60)
    
    return result.to_dict()