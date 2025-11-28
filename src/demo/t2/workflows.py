"""
T2: Token Replay Attacks - Workflow Definition

This module defines the workflow configuration for T2 testing.

Workflow Structure:
- Uses proper WorkflowDefinition and WorkflowStep Pydantic models
- Two-phase workflow: legitimate token acquisition → replay attack
- Tests token binding and PoP verification

Attack Flow:
1. Genuine agent obtains legitimate token (legitimate step)
2. Token is captured (simulating theft/interception)
3. Malicious agent attempts to replay the token (attack step)
4. System should detect and block the replay attempt
"""

from demo.demo_registrations import declared_workflows

t2_workflow = {
    "workflow_id": "t2-token-replay-v1.0",
    "workflow_type": "dag",
    "steps": {
        # Supervisor init step
        "init": {
            "agent": "T2Supervisor",
            "action": "T2GenuinePlanner",
            "scopes": [],
            "dependencies": ["t2_bump_versions"],
            "required": False,
            "approval_gate": False,
            "requires_approval": False
        },
        
        # Phase 1: Legitimate token acquisition
        "t2_bump_versions": {
            "agent": "T2GenuinePlanner",
            "action": "t2_bump_versions",
            "scopes": ["repo:write", "sbom:patch"],
            "dependencies": [],  # First step, no dependencies
            "required": True,    # Required for legitimate workflow
            "approval_gate": False,
            "requires_approval": False
        },
        
        # Phase 2: Attack - Token replay attempt
        # This step simulates an attacker replaying the captured token
        "t2_malicious_bump_versions": {
            "agent": "T2MaliciousPlanner",
            "action": "t2_malicious_bump_versions",
            "scopes": ["repo:write", "sbom:patch"],
            "dependencies": ["genuine_patch"],  # Must come after genuine step
            "required": False,   # This is the attack, not required for legitimate flow
            "approval_gate": False,
            "requires_approval": False
        }
    }
}

# Register T2 workflow
declared_workflows.append(t2_workflow)


# ==============================================================================
# WORKFLOW STRUCTURE DOCUMENTATION
# ==============================================================================
"""
T2 Workflow Explanation:
-----------------------
Step "init":
  - Supervisor step that orchestrates the workflow
  - Depends on "genuine_patch" completing first
  - Not required (optional orchestration step)

Step "genuine_patch":
  - First step in the workflow
  - Legitimate agent obtains intent token through proper SecureClient flow
  - Required: True (must complete for legitimate workflow)
  - No dependencies (starting point)
  - Scopes: repo:write, sbom:patch
  
Step "malicious_replay":
  - Attack step simulating token replay
  - Depends on "genuine_patch" (token must be captured first)
  - Required: False (this is the attack, not part of legitimate flow)
  - Attempts to reuse captured token without proper authentication
  - Scopes: repo:write, sbom:patch (same as genuine, attempting to impersonate)

IDP Validation:
--------------
When an agent requests an intent token, the IDP validates:
1. Agent is authorized for the workflow step (agent == step_def.agent)
2. Action matches the step definition (active_tool == step_def.action)
3. Agent has required scopes (step_def.scopes ⊆ has_scopes)
4. All dependencies have been completed (delegation_context.completed_steps)
5. Required steps in sequence have been completed
6. If step requires_approval, an approval_gate step must have completed

Security Properties:
-------------------
1. **Step Sequence Enforcement**: Dependencies ensure proper ordering
2. **Agent Authorization**: Only designated agents can execute steps
3. **Scope Validation**: Each step validates required scopes
4. **Required Steps**: Mandatory steps cannot be bypassed
5. **Approval Gates**: Critical operations require approval steps
6. **Delegation Chain**: Tracks complete execution history

Expected Outcomes:
-----------------
OAuth Mode:
  - genuine_patch: ✅ Succeeds (bearer token obtained)
  - malicious_replay: ❌ Succeeds (token can be replayed - VULNERABILITY!)
  - Result: Demonstrates OAuth's inability to prevent token replay

Intent Mode:
  - genuine_patch: ✅ Succeeds (intent token obtained with binding)
  - malicious_replay: ✅ Blocked (token binding validation fails)
  - Result: Demonstrates intent system's token replay protection
"""


# ==============================================================================
# WORKFLOW SECURITY PROPERTIES
# ==============================================================================
"""
Security Properties Tested by T2:

1. Token Binding (Intent Mode):
   - Intent tokens are cryptographically bound to the agent that obtained them
   - Binding includes agent checksum, execution context, and PoP key
   - Replaying a token from different agent/context fails validation

2. OAuth Vulnerability (OAuth Mode):
   - Bearer tokens have no binding to the requesting agent
   - Any agent with possession of token can use it
   - Token replay attacks succeed in OAuth mode

3. Detection Mechanisms:
   - Agent identity verification through checksums
   - Execution context validation
   - Proof-of-Possession (PoP) key verification
   - Delegation chain integrity checks

Key Test Assertions:
- Genuine agent successfully obtains and uses token ✓
- Token is successfully captured (simulating interception) ✓
- Malicious replay attempt is detected and blocked (Intent Mode) ✓
- Malicious replay attempt succeeds (OAuth Mode) - demonstrates vulnerability ✓
"""