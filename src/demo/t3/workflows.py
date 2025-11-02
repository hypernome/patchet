from demo.demo_registrations import declared_workflows

t3_workflow = {
    "workflow_id": "supply_chain_test_v1.0",
    "workflow_type": "dag",
    "description": "T3: Shim Library Supply Chain Security Test",
    "steps": {
        "t3_call_api": {
            "agent": "T3LegitimateAgent",
            "action": "t3_call_api",
            "scopes": ["read:repo"],
            "required": True
        }
    }
}

declared_workflows.append(t3_workflow)