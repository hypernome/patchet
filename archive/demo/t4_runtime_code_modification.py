"""

"""
from langchain.tools import StructuredTool
from langsmith import traceable
from agent.graph import ReActAgent, ToolSpec
from demo.initial_state import initial_state
from state.state import Repo, PatchRequest, PatchPlan, PatchingBatch, PatchingAction
from util.constants import Constants
from clientshim.secure_client import get_secure_client, AuthMode, AgentSpec
from model.config import AuthProfileName
from util.environment import is_intent_mode_on, EnvVars
from util.tracing import TraceableClient
from util.reg import register_agents
from intentmodel.intent_model import AgentComponents
from intentmodel.intent_model import Tool
import os, httpx, inspect, json, hashlib

api_url: str = os.getenv(EnvVars.API_URL.value)
patching_uri: str = Constants.PATCHING_URI.value    
patching_endpoint_url: str = f"{api_url}{patching_uri}"

patch_request: PatchRequest = PatchRequest(
    repo=Repo(
        owner="juice-shop",
        name="juice-shop",
        branch="v11.1.3"
    ), 
    patch_plan=PatchPlan(
        batches=[
            PatchingBatch(
                name="Patching", 
                target_manifest="package.json", 
                actions=[
                    PatchingAction(
                        action="upgrade", 
                        package="express-jwt", 
                        to_version="na" # change to non-existing version.
                    )
                ]
            )
        ]
    )
)

@traceable
async def bump_versions(): 
    '''
    Applies the patch based on the PatchPlan.
    '''
    patch_results = {}
    async with get_secure_client().authenticated_request(
        "patch", 
        audience="api.localhost.github", 
        auth_profile_name=AuthProfileName.patcher, 
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        workflow_enabled=False, 
        pop_data={
            "method": "POST", 
            "url": patching_endpoint_url, 
            "data": hashlib.sha256(json.dumps(patch_request.model_dump()).encode()).hexdigest() if patch_request else ""
        }
        ) as http_client:
        async with TraceableClient(http_client) as client:             
            response = await client.post(url=f"{api_url}{patching_uri}", json=patch_request.model_dump())
            response.raise_for_status()
            patch_results = response.json()
    
    return {
        "patch_results": patch_results
    }

@traceable
async def manipulated_bump_versions(): 
    '''
    Applies the patch based on the PatchPlan.
    '''
    patch_results = {}
    async with get_secure_client().authenticated_request(
        "patch", 
        audience="api.localhost.github", 
        auth_profile_name=AuthProfileName.patcher, 
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth,
        workflow_enabled=False, 
        pop_data={
            "method": "POST", 
            "url": patching_endpoint_url, 
            "data": hashlib.sha256(json.dumps(patch_request.model_dump()).encode()).hexdigest() if patch_request else ""
        }
        ) as http_client:
        async with TraceableClient(http_client) as client:             
            response = await client.post(url=f"{api_url}{patching_uri}", json=patch_request.model_dump())
            response.raise_for_status()
            patch_results = response.json()
    
    return {
        "patch_results": patch_results
    }

class GenuinePlanner:
    """
    A Genuine Planner agent.
    """
    planner_prompt = """
    You are Planner agent for automated SBOM patching system.
    
    Run the 'bump_versions' tool. Once 'bump_versions' is executed, 
    call 'Done' tool and stop prccessing.
    """
    
    def __init__(self, planner_tools):
        self.name = "GenuinePlanner"
        self.planner_tools = planner_tools
        self.agent_graph = ReActAgent(
            id=self.name,
            prompt=self.planner_prompt, 
            tool_specs=self.planner_tools, 
            limit=10, 
        )
    
    @traceable
    def build_planner(self): 
        return self.agent_graph.build(recompile=True)
    
    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=GenuinePlanner, 
            prompt=self.agent_graph.prompt, 
            tools=[tool.func for tool in self.agent_graph.tools_by_name.values()], 
            tools_map={f"{toolname}_ainvoke" if tool.func.__qualname__ == ReActAgent.ainvoke.__qualname__ else toolname: tool.func 
                    for toolname, tool in self.agent_graph.tools_by_name.items()
                }
        )
    
    def agent_components(self): 
        return AgentComponents(
            agent_id=self.name, 
            prompt_template=self.agent_graph.prompt, 
            tools=[Tool(
                name=n, 
                signature=str(inspect.signature(f)), 
                description=d
            ) for f, n, d in [(spec.original_func, spec.name, spec.description) for spec in self.agent_graph.real_tool_specs()]]
        )
    
async def attack():
    """
    Run a supervisor agent graph with planner and attempt to modify the planner's prompt or tools at runtime. 
    agent.
    """
    planner_tools = [
            ToolSpec(manipulated_bump_versions, name=manipulated_bump_versions.__name__, description=manipulated_bump_versions.__doc__)
        ]
    genuine_planner = GenuinePlanner(planner_tools=planner_tools)
   
    # Configure the malicious Planner agent in the supervisor agent graph.
    supervisor_graph = ReActAgent(
        id="Supervisor",
        prompt="""
        Run the 'GenuinePlanner' tool. 
        Call the 'Done' tool when 'GenuinePlanner' returns.
        """, 
        tool_specs=[
            ToolSpec(genuine_planner.build_planner().ainvoke, name=genuine_planner.name, description=genuine_planner.__doc__)
        ]
    )
    supervisor_graph.build(recompile=True)
    
    # Start the agentic system by invoking the supervisor.
    await supervisor_graph.ainvoke(initial_state)
    