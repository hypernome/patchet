from demo.initial_state import initial_state
from demo.t11.agents import t11_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t11.workflows import t11_workflow
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T11: Delegation Chain Integrity Validation
    
    THREAT DESCRIPTION:
    T11 tests the system's ability to detect INCOMPLETE delegation chains
    where required workflow steps (particularly approval steps) are skipped.
    
    ATTACK SCENARIO:
    Legitimate Workflow: Initiator - Approver - Executor
    Attack Workflow: Initiator - MaliciousExecutor (skips Approver)
    
    The delegation chain is computed by runtime introspection in SecureClient,
    so the attacker cannot directly manipulate the chain data. However, the
    attack tests whether the IDP properly validates that:
    1. All REQUIRED steps are completed
    2. APPROVAL steps are present when required
    3. Delegation chain matches workflow dependencies
    
    ATTACK FLOW:
    1. Supervisor calls T11Initiator
       - Creates delegation chain: [Initiator]
       - Completes step: "start_request"
    
    2. Supervisor calls T11MaliciousExecutor (skips T11Approver!)
       - Delegation chain: [Initiator, MaliciousExecutor]
       - Missing: "approve_request" step
    
    3. MaliciousExecutor calls t11_execute_operation
       - Requests token for "execute_operation" step
       - IDP validates delegation chain and completed steps
    
    EXPECTED BEHAVIOR:
    
    OAuth Mode: Attack may succeed
    - OAuth checks: "Does token have request:execute scope?" - YES
    - OAuth doesn't validate workflow step dependencies
    - OAuth doesn't check for required approval steps
    - Attack succeeds: Operation executes without approval
    
    Intent Mode: Attack blocked
    - IDP validates delegation context against workflow definition
    - Checks: "Is approve_request in completed_steps?" - NO
    - Checks: "Is approval gate completed?" - NO
    - Checks: "Does delegation chain match dependencies?" - NO
    - Security Error: "Required approval step missing from delegation chain"
    - Attack blocked: Cannot mint token for execute_operation
    
    KEY VALIDATIONS TESTED:
    1. Required Step Validation: All required=True steps must be completed
    2. Approval Gate Validation: Steps with requires_approval=True need approval gate
    3. Dependency Validation: Dependencies must be satisfied before execution
    4. Chain Integrity: Delegation chain must be complete and properly sequenced
    
    REAL-WORLD ANALOGY:
    Like a multi-signature approval system where someone tries to execute
    a transaction after getting 1 of 2 required signatures. The system
    must detect that the approval chain is incomplete.
    
    OWASP MAPPING:
    - A02:2021 - Cryptographic Failures (incomplete proof of authorization)
    - Category: Repudiation (can't prove proper approval was obtained)
    
    MITIGATIONS TESTED:
    - A8: Workflow Validation (ensures steps follow defined workflow)
    - A9: Cryptographic Delegation Chains (immutable audit trail)
    - A10: Workflow Execution Logging (tracks all step transitions)
    """
    result = ThreatTestResult()
    print("=" * 70)
    print("T11: DELEGATION CHAIN INTEGRITY VALIDATION")
    print("=" * 70)
    print("Scenario: Execute operation with incomplete delegation chain")
    print("")
    print("Required workflow: Initiator - Approver - Executor")
    print("Attack workflow:   Initiator - [SKIP APPROVER] - MaliciousExecutor")
    print("")
    print("Expected delegation chain: [Initiator, Approver, MaliciousExecutor]")
    print("Actual delegation chain:   [Initiator, MaliciousExecutor]")
    print("")
    print("Missing required step: approve_request (approval gate)")
    print("=" * 70)
    print("")
    
    # Start workflow execution
    secure_client = get_secure_client()
    secure_client.start_workflow_execution("approval_chain_v1.0")
    
    # Get supervisor agent
    t11_supervisor_agent: ReActAgent = secure_client.get_agent(
        t11_supervisor.get('name', '')
    )
    
    # Trigger the attack
    print("Starting attack: Supervisor will skip Approver step...")
    print("")
    
    with measure_detection_time() as timer: 
        try: 
            attack_result = await t11_supervisor_agent.ainvoke(initial_state)
            output = attack_result.get("tool_outputs", {})
            result.attack_succeeded(
                message="ATTACK SUCCEEDED: Operation executed without required approval. System failed to validate workflow dependencies.", 
                elapsed_time_ms=timer.elapsed_ms()   
            )
            result.add_detail("tool_result", output)
        except Exception as e: 
            result.attack_blocked(
                blocked_by=get_anchors("A9", "A6"), 
                elapsed_time_ms=timer.elapsed_ms(), 
                error_message=str(e)
            )
    
    print("")
    print("=" * 70)
    print("T11 ATTACK COMPLETED")
    print("=" * 70)
       
    return result.to_dict()