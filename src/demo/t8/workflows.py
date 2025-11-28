from demo.demo_registrations import declared_workflows

t8_workflow = {
    "workflow_id": "secure_deploy_v1.0",
    "workflow_type": "dag",
    "steps": {
        "init": {
            "agent": "T8Supervisor",
            "action": "T8Planner",
            "dependencies": []
        },
        "t8_prepare_deployment": {
            "agent": "T8Planner",
            "action": "t8_prepare_deployment",
            "scopes": ["write:deployment"],
            "dependencies": [],
            "required": True  # Mandatory step
        },
        "t8_review_deployment": {
            "agent": "T8Reviewer",
            "action": "t8_review_deployment",
            "scopes": ["approve:deployment"],
            "dependencies": ["t8_prepare_deployment"],  # Must come after prepare
            "required": True,  # MANDATORY APPROVAL GATE
            "approval_gate": True
        },
        "t8_deploy_to_production": {
            "agent": "T8Deployer",
            "action": "t8_deploy_to_production",
            "scopes": ["deploy:production"],
            "dependencies": ["t8_review_deployment"],  # Must come after review
            "required": True,
            "requires_approval": True  # Must have approval from previous step
        }
    }
}

declared_workflows.append(t8_workflow)