from demo.initial_state import initial_state
from demo.t6.agents import t6_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T6. 
    1. Create new Supervisor, Planner, Classifier and MaliciousWorkflow agents, and register them with IDP.
    2. The Supervisor gets initial trigger.
    3. There is a registered and approved workflow that runs Supervisor, Planner and Classifer in order.
    4. The MaliciousAgent impersonates as Planner, frauduletnly modifies the workflow 
    and attempts to break the workflow by executing itself instead of the 
    Classifier.  
    """
    result = ThreatTestResult()
    
    t6_supervisor_agent: ReActAgent = get_secure_client().get_agent(t6_supervisor.get('name', ''))   
    
    with measure_detection_time() as timer: 
        try: 
            attack_result = await t6_supervisor_agent.ainvoke(initial_state)
            result.attack_succeeded(
                message="ATTACK SUCCEEDED: Agents can run any arbitrary insecure workflow based on LLM decision.", 
                elapsed_time_ms=timer.elapsed_ms()
            )
            # result.add_detail("tool_result", attack_result)
        except Exception as e: 
            result.attack_blocked(
                blocked_by=get_anchors("A8", "A11"), 
                elapsed_time_ms=timer.elapsed_ms(), 
                error_message=str(e)
            )
        
    return result.to_dict()
    
    