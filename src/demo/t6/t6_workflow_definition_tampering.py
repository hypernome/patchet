from demo.initial_state import initial_state
from demo.t6.agents import t6_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent


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
    
    t6_supervisor_agent: ReActAgent = get_secure_client().get_agent(t6_supervisor.get('name', ''))   
    await t6_supervisor_agent.ainvoke(initial_state)
    
    
    
    
    