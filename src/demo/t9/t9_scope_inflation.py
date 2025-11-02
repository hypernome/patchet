from demo.initial_state import initial_state
from demo.t9.agents import t9_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t9.workflows import t9_workflow

async def attack():
    """
    Run scenario for threat T9: Scope Inflation
    
    Workflow Setup:
    - Step 1: read_specific_file (agent: T9FileReader, scope: read:file:config.json)
    - Step 2: write_multiple_files (agent: T9FileWriter, scope: write:files:all)
    
    Attack Flow:
    1. Supervisor calls T9FileReader
    2. T9FileReader executes t9_read_specific_file (legitimate, Step 1)
    3. T9FileReader then calls t9_write_multiple_files (ATTACK - tries Step 2's action)
    4. t9_write_multiple_files requests broad scope: write:files:all
    
    The Attack:
    - T9FileReader is executing in Step 1 context (narrow scope)
    - But tries to execute Step 2's action (broad scope)
    - Workflow step validation should detect this mismatch
    
    Expected Behavior:
    - OAuth Mode: Attack succeeds
      - OAuth validates: "Does workflow have write:files:all?" → YES
      - No step-level validation
      - Writes unauthorized files
    
    - Intent Mode: Attack blocked
      - Current executing step: read_specific_file (scopes: ["read:file:config.json"])
      - Requested scope: write:files:all
      - Validation: write:files:all ∉ ["read:file:config.json"] → BLOCKED
      - Security error: "Requested scope not allowed in current workflow step"
    
    Key Test:
    - Agent registered for narrow-scope step tries to use broad-scope action
    - Intent system enforces: agent can only use scopes from its current step
    """
    
    print("="*60)
    print("T9: SCOPE INFLATION ATTACK")
    print("="*60)
    print("Scenario: Agent uses action from different workflow step")
    print("Agent Context: T9FileReader (Step 1, narrow scope)")
    print("Action Attempted: t9_write_multiple_files (Step 2, broad scope)")
    print("="*60)
    
    secure_client = get_secure_client()
    secure_client.start_workflow_execution("file_ops_v1.0")
    
    t9_supervisor_agent: ReActAgent = secure_client.get_agent(
        t9_supervisor.get('name', '')
    )
    
    # Trigger the attack
    result = await t9_supervisor_agent.ainvoke(initial_state)
    output = result.get('tool_outputs', {})
    
    print("="*60)
    print("T9 Attack Completed")
    print(f"Attack Succeeded: {output.get('attack_succeeded', False)}")
    if result.get('files_written'):
        print(f"Unauthorized Files Written: {len(output['files_written'])}")
    print("="*60)
    
    return output