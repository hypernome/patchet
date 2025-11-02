from agent.graph import ReActAgent, ToolSpec
from clientshim.secure_client import get_secure_client, tool_from_registry, register_as_tool as rat

def agent(spec: dict): 
    """
    Construct demo agent.
    """
    secure_client = get_secure_client()
    agent_id: str = spec.get("name", None)
    prompt: str = spec.get('prompt', "")
    tools: list[dict] = spec.get('tools', [])
    register_as_tool: bool = bool(spec.get('register_as_tool', False))
    
    tool_specs = []
    
    for tool in tools: 
        tool_name: str = tool.get('name', '')
        from_agent: str = tool.get('from_agent', None)
        
        tool_func = tool_from_registry(tool_name)
        wrapper_func = secure_client._create_workflow_tracking_wrapper(
            original_func=tool_func, 
            agent_id=agent_id, 
            tool_name=tool_name
        )
        tool_specs.append(ToolSpec(
            original_func=tool_func, 
            func=wrapper_func, 
            name=tool_name, 
            description=tool_func.__doc__, 
            is_agent=True if from_agent else False
        ))
    
    react_agent = ReActAgent(
        id=agent_id, 
        prompt=prompt, 
        tool_specs=tool_specs, 
        limit=10
    )
    
    if register_as_tool:
        rat(agent_id, react_agent.ainvoke)
    
    return react_agent.build(recompile=True)