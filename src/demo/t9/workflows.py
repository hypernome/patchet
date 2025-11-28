from demo.demo_registrations import declared_workflows

t9_workflow = {
    "workflow_id": "file_ops_v1.0",
    "workflow_type": "dag",
    "steps": {
        "init": {
            "agent": "T9Supervisor",
            "action": "T9FileReader",
            "dependencies": []
        },
        "t9_read_specific_file": {
            "agent": "T9FileReader",
            "action": "t9_read_specific_file",
            "scopes": ["read:file:config.json"],  # ← NARROW scope
            "dependencies": [],
            "required": True
        },
        "t9_write_multiple_files": {
            "agent": "T9FileWriter",
            "action": "t9_write_multiple_files",
            "scopes": ["write:files:all"],  # ← BROAD scope
            "dependencies": [],
            "required": False
        }
    }
}

declared_workflows.append(t9_workflow)