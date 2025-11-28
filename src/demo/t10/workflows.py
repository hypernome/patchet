from demo.demo_registrations import declared_workflows

t10_workflow = {
    "workflow_id": "payment_v1.0",
    "workflow_type": "dag",
    "steps": {
        "init": {
            "agent": "T10Supervisor",
            "action": "T10UserAgent",
            "dependencies": []
        },
        "t10_initiate_payment": {
            "agent": "T10UserAgent",
            "action": "t10_initiate_payment",
            "scopes": ["payment:initiate"],
            "dependencies": [],
            "required": True,
            "requires_user_authorization": True  # Must have real user intent
        },
        "t10_process_payment": {
            "agent": "T10PaymentProcessor",
            "action": "t10_process_payment",
            "scopes": ["payment:execute"],
            "dependencies": ["initiate_payment"],  # Must come after initiation
            "required": True,
            "requires_user_authorization": True  # Must trace back to user intent
        }
    }
}

declared_workflows.append(t10_workflow)