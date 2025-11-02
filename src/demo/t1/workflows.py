from demo.demo_registrations import declared_workflows

t1_workflow = {
    "workflow_id": "t1_file_search_v1.0",
    "workflow_type": "dag",
    "steps": {
        "t1_list_files": {
            "agent": "T1Planner",
            "action": "t1_list_files", 
            "dependencies": []
        }        
    }
}

declared_workflows.append(t1_workflow)
