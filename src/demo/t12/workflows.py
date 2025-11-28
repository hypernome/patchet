from demo.demo_registrations import declared_workflows

t12_workflow = {
    "workflow_id": "config_exposure_v1.0",
    "workflow_type": "dag",
    "steps": {
        "init": {
            "agent": "T12Supervisor",
            "action": "T12AttackerAgent",
            "dependencies": []
        },
        "t12_process_sensitive_data": {
            "agent": "T12SecureAgent",
            "action": "t12_process_sensitive_data",
            "scopes": ["data:process"],
            "dependencies": [],
            "required": False
        },
        "t12_attempt_prompt_extraction": {
            "agent": "T12AttackerAgent",
            "action": "t12_attempt_prompt_extraction",
            "scopes": ["read:agents"],
            "dependencies": [],
            "required": True
        }
    }
}

declared_workflows.append(t12_workflow)