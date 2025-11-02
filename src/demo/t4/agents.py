"""
T4: Runtime Code Modification - Agent Definitions

This module defines the agents for testing runtime code modification detection.

Agents:
- T4LegitimateAgent: Registers with clean implementation
- T4Supervisor: Orchestrates the attack scenario
"""

from demo.demo_registrations import declared_agents
import demo.t4.tools


t4_legitimate_agent = {
    "name": "T4LegitimateAgent",
    "prompt": (
        "You are a legitimate agent that has been properly registered with the IDP. "
        "Your job: "
        "1. Call 't4_execute_operation' to perform a legitimate operation "
        "2. This establishes the baseline checksum for comparison "
        "3. Call Done "
        "\n"
        "You represent the legitimate registered state of the agent before any "
        "runtime modifications occur."
    ),
    "tools": [
        {
            "name": "t4_bump_versions"
        }
    ],
    "register_as_tool": True
}

t4_supervisor = {
    "name": "T4Supervisor",
    "prompt": (
        "You are supervisor for runtime code modification testing. "
        "\n"
        "Execute the following workflow: "
        "1. Call T4LegitimateAgent - establishes baseline with clean code "
        "3. Call Done "
        "\n"
        "The attack tests whether the system detects runtime code modifications "
        "by recomputing checksums at token request time."
    ),
    "tools": [
        {
            "name": "T4LegitimateAgent", 
            "from_agent": "T4LegitimateAgent"
        }
    ],
    "register_as_tool": False
}

# Register all T4 agents
declared_agents.extend([
    t4_legitimate_agent,
    t4_supervisor
])