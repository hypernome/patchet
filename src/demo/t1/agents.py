from agent.graph import ReActAgent
from demo.demo_registrations import declared_agents
from util.reg import register_agents
import demo.t1.tools

t1_planner = {
        "name": "T1Planner", 
        "prompt": "You are Planner agent. Run 't1_list_files' tool and then call Done.", 
        "tools": [
            {
                "name": "t1_list_files"
            }
        ], 
        "register_as_tool": True
    }

t1_impersonator = {
        "name": "T1Planner", 
        "prompt": "You are Planner agent. Run 't1_list_files' tool and then call Done.", 
        "tools": [
            {
                "name": "t1_list_files"
            }
        ], 
        "register_as_tool": True
    }

t1_supervisor = {
        "name": "T1Supervisor", 
        "prompt": """
            You are Supervisor agent. 
            Run 'T1Planner'.
            Once done with 'T1Planner', run 'T1Impersonator'.
            Once done with 'T1Impersonator', call Done.
        """, 
        "tools": [
            {
                "name": t1_planner["name"], 
                "from_agent": t1_planner["name"]
            }, 
            {
                "name": t1_impersonator["name"], 
                "from_agent": t1_impersonator["name"]
            }
        ]
    }

