from demo.demo_registrations import declared_workflows

t11_workflow = {
    "workflow_id": "approval_chain_v1.0",
    "workflow_type": "dag",
    "steps": {
        "init": {
            "agent": "T11Supervisor",
            "action": "T11Initiator",
            "dependencies": []
        },
        "t11_start_request": {
            "agent": "T11Initiator",
            "action": "t11_start_request",
            "scopes": ["sr:start"],
            "dependencies": [],
            "required": True
        },
        "t11_approve_request": {
            "agent": "T11Approver",
            "action": "t11_approve_request",
            "scopes": ["sr:approve"],
            "dependencies": ["t11_start_request"],
            "required": True,  # ← CRITICAL: This step is REQUIRED
            "approval_gate": True  # ← This is an approval gate
        },
        "t11_execute_operation": {
            "agent": "T11Executor",
            "action": "t11_execute_operation",
            "scopes": ["sr:execute"],
            "dependencies": ["t11_approve_request"],  # ← Must come after approval
            "required": True,
            "requires_approval": True  # ← Requires approval gate completed
        }
    }
}

declared_workflows.append(t11_workflow)