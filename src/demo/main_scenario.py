from agent.graph import ReActAgent
from demo.initial_state import initial_state
from clientshim.secure_client import get_secure_client

async def start(): 
    """
    Start the Supervisor agent.
    """
    
    secure_client = get_secure_client()
    
    supervisor_graph: ReActAgent = secure_client.get_agent("Supervisor")
    await supervisor_graph.ainvoke(initial_state)