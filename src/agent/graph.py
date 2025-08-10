from langchain.chat_models import init_chat_model
from langchain.tools import Tool, StructuredTool
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, START, END
from langsmith import traceable
from typing import Callable, Literal
from enum import Enum
from state.state import PatchetState, serialize_state, serialize_state_flags
import json, uuid, asyncio, inspect, tiktoken
from tiktoken import Encoding
from state.state import CURRENT_STATE

class InternalTools: 
    '''
    Defines tools internal to the ReActAgent meant to be part of the tool list always.
    '''
    
    @traceable
    def Done(): 
        '''
        Call this tool when the current state (PatchetState) and/or inputs show that the objective of this agent are completed.
        '''
    
    @traceable
    def Yield():
        '''
        Call this tool when the current state (PatchetState) and/or inputs show that the you cannot proceed further and for now the 
        control should be handed over to the calling Parent workflow.
        ''' 
    
    

class Decision(Enum): 
        '''
        Enum that represents a check to decide breaking the agent loop.
        '''
        CONTINUE = "CONTINUE"
        STOP = "STOP"

class ReActAgent: 
    '''
    Basic langgraph sub-graph based ReAct agent implementation.
    '''
        
    def __init__(self, prompt: str = "<Tools>{tools_prompt}</Tools> \n<Input>{input}</Input>", tools: list[Tool] = [], 
                 llm_name: str = "openai:gpt-4.1", conditionally_continue: Callable[[PatchetState], bool]  = None, 
                 limit: int = -1, state_overrides: dict = {}, field_exclusion_func: Callable[[PatchetState], list[str]] = None, 
                 state_serializer_func: Callable[[PatchetState, list[str]], str] = serialize_state):
        self.prompt = f"""
            {prompt if prompt else ""}\n\n<CurrentState>\n{{current_state}}\n</CurrentState>\n\n<StateFlags>\n{{state_flags}}\n</StateFlags>\n\n{{tools_prompt}} \n\n<Input>\n{{user_input}}\n</Input>\n
        """
        self.tools = tools.extend([StructuredTool.from_function(InternalTools.Yield), StructuredTool.from_function(InternalTools.Done)])
        
        self.tool_aware_llm = init_chat_model(llm_name, temperature=0.0).bind_tools(tools)        
        self.conditionally_continue = conditionally_continue
        if tools: 
            self.tools_by_name = {tool.name: tool for tool in tools}
            self.tools_prompt = "".join(
                [f"{index + 1}. {tool.name}({tool.args_schema}) - {tool.description}\n" for index, tool in enumerate(tools)]
            )
        self.agent = None
        self.state_overrides = state_overrides
        self.field_exclusion_func = field_exclusion_func
        self.state_serializer_func = state_serializer_func
    
    @traceable
    async def consult_llm(self, state:  PatchetState) -> PatchetState: 
        '''
        This method represents the Agent internal node that is responsible for generating 
        LLM thought for taking decisions for tool calling or exiting.
        '''
        
        history = []
        for message in state.messages: 
            if isinstance(message, AIMessage): 
                history.append(message)
            else:
                history.append({"role": message["role"], "content": f"{message["content"]}", "tool_call_id": message["tool_call_id"]})
        
        llm_advice = await self.tool_aware_llm.ainvoke(
            [
                {"role": "system", "content": self.prompt.format(
                    current_state=self.state_serializer_func(state, exclusions=self.field_exclusion_func(state) if self.field_exclusion_func else state.default_exclusion_list()),
                    state_flags=serialize_state_flags(state),
                    tools_prompt=f"<Tools>\n{self.tools_prompt}\n</Tools>" if self.tools_prompt else "",
                    user_input=state.input
                )}
            ] 
            + history
        )
        
        state.messages.append(llm_advice)
        return state
    
    @traceable
    async def run_tool(self, state: PatchetState) -> PatchetState: 
        '''
        This method represents the Agent internal node that is responsible for running tools 
        after a tool calling decision from LLM. It runs the relevant tools, collects outputs 
        as oversvations, and passes the observations to the Agent's state for further potential 
        iterations.
        '''
        if state.messages: 
            ai_message = state.messages[-1]
            if ai_message and isinstance(ai_message, AIMessage):
                for tool_call in ai_message.tool_calls: 
                    tool = self.tools_by_name[tool_call["name"]]
                    args = tool_call["args"]
                    if isinstance(args, str): 
                        args = json.loads(args)
                    is_tool_an_agent: bool = inspect.ismethod(tool.func) and isinstance(tool.func.__self__, ReActAgent)            
                    parent_messages = state.messages.copy() if is_tool_an_agent else None
                    args = {'state': state.model_dump(exclude=set(['messages']))} if is_tool_an_agent else args
                    token = CURRENT_STATE.set(state)
                    try:
                        observation = await tool.ainvoke(args)
                        if asyncio.iscoroutine(observation) or asyncio.iscoroutinefunction(observation): 
                            observation = await observation
                        self.transfer_to_state(observation, state, parent_messages)
                        tool_call_id = tool_call["id"]
                        state.messages.append({"role": "tool", "content": f"{self.safe_content(observation, tool_call_id)}", "tool_call_id": tool_call_id})        
                    finally: 
                        CURRENT_STATE.reset(token)
                    
        return state
    
    @traceable
    def should_continue(self, state: PatchetState) -> Literal[Decision.CONTINUE, Decision.STOP]:
        '''
        This method represents the Agent internal loop termination check based on a 'conditional' constructor argument 
        or falling back to default implementation if it is not provided.
        1. The default implementation is based on whether the LLM returns back with further tool calls or not. 
        2. There is also an iteration limit that can be used to break the loop after certain fixed number of interations.
        3. A negative value for the constructor parameter 'limit' is interpreted as unlimited interations until LLM stops making tool calls.
        ''' 
        
        if self.conditionally_continue:
            if self.conditionally_continue(state): 
                return Decision.CONTINUE
            else: 
                return Decision.STOP
        else: 
            last_message = state.messages[-1] if state.messages else None
            if not last_message: 
                return Decision.CONTINUE
            if isinstance(last_message, AIMessage) and last_message.tool_calls:                 
                for tool_call in last_message.tool_calls: 
                    if tool_call["name"] in [InternalTools.Done.__name__, InternalTools.Yield.__name__]: 
                        state.messages.append({"role": "tool", "content": '', "tool_call_id": tool_call["id"]})
                        return Decision.STOP
                    else: 
                        return Decision.CONTINUE
            else: 
                return Decision.STOP
    
    @traceable
    def wind_up(self, state: PatchetState) -> PatchetState: 
        '''
        Winds up the agent processing before returning to the caller and right after a Yield / Done tool call.
        '''
        state.messages = []
        if self.state_overrides and isinstance(self.state_overrides, dict): 
            for field, value in self.state_overrides.items(): 
                setattr(state, field, value)
        return state
    
    @traceable
    def build(self, name="", recompile: bool = False): 
        '''
        Build the agent graph.
        '''
        if not recompile and self.agent is not None: 
            return self
        
        graph = StateGraph(PatchetState)
        
        if not name: 
            name = "Anonymous"
        self.name = f"{name}_graph"
        self.id = uuid.uuid4()
        
        graph.add_node(self.consult_llm.__name__, self.consult_llm)
        graph.add_node(self.run_tool.__name__, self.run_tool)
        graph.add_node(self.wind_up.__name__, self.wind_up)
        graph.add_edge(START, self.consult_llm.__name__)
        graph.add_conditional_edges(self.consult_llm.__name__, self.should_continue, { Decision.CONTINUE: self.run_tool.__name__, Decision.STOP: self.wind_up.__name__ })
        graph.add_edge(self.run_tool.__name__, self.consult_llm.__name__)
        graph.add_edge(self.wind_up.__name__, END)
        
        self.agent = graph.compile()
        
        return self
    
    def safe_content(self, observation: any, tool_call_id: str, max_tokens: int = 500) -> str: 
        '''
        Check on the length of the observation before appending it to messages for next potential LLM call.
        '''
        if not observation: 
            return ''
        
        encoding: Encoding = None
        
        try:
            encoding = tiktoken.get_encoding('cl100k_base')
        except: 
            encoding = tiktoken.get_encoding('o200k_base')
        
        obs = str(observation)
        
        if not encoding: 
            return obs
        
        tokens = encoding.encode(obs)
        if len(tokens) > max_tokens: 
            return f"<{tool_call_id}> output is too long. Please extract it from the GlobalState."
        return obs

    @traceable
    def transfer_to_state(self, observation: any, state: PatchetState, parent_messages: list): 
        '''
        If observation is a dict and contains a any keys common with the state, then patch the state 
        with value from observation. Ignore otherwise.
        '''
        if isinstance(observation, dict): 
            if parent_messages: 
                observation['messages'] = parent_messages
            for field in observation: 
                if field in PatchetState.model_fields: 
                    setattr(state, field, observation[field])
    
    @traceable   
    async def ainvoke(self, state: PatchetState): 
        '''
        Async invocation for this graph.
        '''
        if self.agent: 
          return await self.agent.ainvoke(state) 
    
    @traceable   
    def invoke(self, state: PatchetState): 
        '''
        Async invocation for this graph.
        '''
        if self.agent: 
          return self.agent.invoke(state)


class StrcturedAgent: 
    '''
    Basic Structured agent implementation.
    '''
        
    def __init__(self, structure_on, prompt: str = "<Input>{input}</Input>",  
                 llm_name: str = "openai:gpt-4.1"):
        self.prompt = f"""
            {prompt if prompt else ""}\n\n<Input>\n{{input}}\n</Input>\n
        """
        self.structured_llm = init_chat_model(llm_name, temperature=0.0).with_structured_output(structure_on)
        
    async def structure_single_output(self, input: str): 
        structured_output = await self.structured_llm.ainvoke(
            [
                {"role": "system", "content": self.prompt.format(
                    input=input                    
                )}
            ] 
        )
        return structured_output