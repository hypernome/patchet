"""
T7: Cross-Agent Privilege Escalation - Workflow Definition

This module defines the workflow configuration for T7 testing.

- t7_list_files: Tool that mints token for list files API
- t7_bump_versions: Tool that mints token for bump versions API

Workflow enforces: t7_list_files MUST complete before t7_bump_versions can execute.
"""

from demo.demo_registrations import declared_workflows

t7_workflow = {
    "workflow_id": "version_bump_v1.0",
    "workflow_type": "dag",
    "steps": {
        # Init step: Supervisor starts workflow
        "init": {
            "agent": "T7Supervisor",
            "action": "T7Planner",           # Supervisor calls Planner
            "scopes": [],
            "dependencies": ["list_files"],
            "required": False,
            "approval_gate": False,
            "requires_approval": False
        },
        
        # Step 1: LOW-PRIVILEGE API CALL
        # Tool: t7_list_files (mints token for list files API)
        "t7_list_files": {
            "agent": "T7Planner",              # Only Planner can call this
            "action": "t7_list_files",         # The actual API-calling tool
            "scopes": ["read:repo"],           # LOW privilege scope
            "dependencies": [],                # First step, no dependencies
            "required": True,
            "approval_gate": False,
            "requires_approval": False
        },
        
        # Step 2: HIGH-PRIVILEGE API CALL
        # Tool: t7_bump_versions (mints token for bump versions API)
        "t7_bump_versions": {
            "agent": "T7Patcher",              # Only Patcher can call this
            "action": "t7_bump_versions",      # The actual API-calling tool
            "scopes": ["write:repo"],          # HIGH privilege scope
            "dependencies": ["t7_list_files"],    # MUST complete list_files first
            "required": True,
            "approval_gate": False,
            "requires_approval": False
        }
    }
}

# Register T7 workflow
declared_workflows.append(t7_workflow)
