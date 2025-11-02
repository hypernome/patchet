from agent.graph import ReActAgent
from demo.demo_registrations import declared_agents
import demo.t3.tools

t3_legitimate_agent = {
    "name": "T3LegitimateAgent",
    "prompt": (
        "You are a legitimate agent used to test supply chain security. "
        "Your job: "
        "1. Call 't3_call_api' to make a test API call through the shim "
        "2. Call Done "
        "\n"
        "You are using the official, unmodified shim library. "
        "This should work normally and demonstrate baseline functionality."
    ),
    "tools": [
        {"name": "t3_call_api"}
    ],
    "register_as_tool": True
}

t3_supervisor = {
    "name": "T3Supervisor",
    "prompt": (
        "You are the supervisor for supply chain security testing (T3). "
        "\n"
        "Execute the following scenario: "
        "1. Call T3LegitimateAgent to establish baseline "
        "2. Explain the supply chain threat conceptually "
        "3. Call Done "
        "\n"
        "T3 tests defense against shim library compromise (supply chain attack). "
        "The test demonstrates that even if shim is compromised, agent-level "
        "validation (A1) and registration-first model (A2) provide defense-in-depth."
    ),
    "tools": [
        {"name": "T3LegitimateAgent", "from_agent": "T3LegitimateAgent"}
    ]
}

declared_agents.extend([
    t3_supervisor,
    t3_legitimate_agent
])