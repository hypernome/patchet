from demo.initial_state import initial_state
from demo.t8.agents import t8_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t8.workflows import t8_workflow

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
    result = await t8_supervisor_agent.ainvoke(initial_state)
    
    output = result.get('tool_outputs', {})
    
    
    print("="*60)
    print("T8 Attack Completed")
    print(f"Deployment Status: {output.get('status', 'unknown')}")
    print(f"Attack Succeeded: {output.get('attack_succeeded', False)}")
    print("="*60)
    
    return result