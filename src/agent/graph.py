from langchain.chat_models import init_chat_model
from langchain.tools import Tool, StructuredTool
from langchain_core.messages import AIMessage
from langgraph.graph import StateGraph, START, END
from langsmith import traceable
from typing import Callable, Literal
from enum import Enum
from state.state import PatchetState, serialize_state
import json, uuid, asyncio, inspect

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
                 limit: int = -1):
        self.prompt = f"""
            {prompt if prompt else ""}\n\n
            <GlobalState/>\n{{current_state}}\n<GlobalState>\n\n
            {{tools_prompt}} \n\n
            <Input>\n{{user_input}}\n</Input>\n
        """
        self.tools = tools.extend([StructuredTool.from_function(InternalTools.Yield), StructuredTool.from_function(InternalTools.Done)])
        
        init_chat_model(llm_name, temperature=0.0).with_structured_output(PatchetState)
        
        self.tool_aware_llm = init_chat_model(llm_name, temperature=0.0).bind_tools(tools)        
        self.conditionally_continue = conditionally_continue
        if tools: 
            self.tools_by_name = {tool.name: tool for tool in tools}
            self.tools_prompt = "".join(
                [f"{index + 1}. {tool.name}({tool.args_schema}) - {tool.description}\n" for index, tool in enumerate(tools)]
            )
        self.agent = None            
    
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
                    current_state=serialize_state(state, exclusions=["messages", "input"]),
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
                    parent_messages = state.messages.copy() if inspect.ismethod(tool.func) and isinstance(tool.func.__self__, ReActAgent) else None
                    observation = await tool.ainvoke(args)
                    if asyncio.iscoroutine(observation) or asyncio.iscoroutinefunction(observation): 
                        observation = await observation
                    self.transfer_to_state(observation, state, parent_messages)
                    state.messages.append({"role": "tool", "content": f"{observation}", "tool_call_id": tool_call["id"]})        
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
    
        
 