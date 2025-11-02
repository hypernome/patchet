from state.state import Repo, RepoEvent, PatchetState, PatchPlan, PatchRequest, PatchResult, PatchStatus, CURRENT_STATE
from util.constants import Constants
from langsmith import traceable
from langchain.tools import StructuredTool
from agent.graph import ReActAgent, BootstrapTool, ToolSpec
from clientshim.secure_model import AgentSpec
from intentmodel.intent_model import AgentComponents, Tool
from clientshim.secure_client import get_secure_client, AuthMode, secure_tool
from model.config import AuthProfileName
from util.tracing import TraceableClient
from util.environment import EnvVars, is_intent_mode_on
import inspect, os

api_url: str = os.getenv(EnvVars.API_URL.value)

@traceable
@secure_tool()
async def bump_versions(): 
    '''
    Applies the patch based on the PatchPlan.
    '''
    state: PatchetState = CURRENT_STATE.get(Constants.CURRENT_STATE.value)
    repo_event: RepoEvent = state.trigger.change_event
    patch_plan: PatchPlan = state.patch_plan
    patch_results = {}
    
    patching_uri: str = Constants.PATCHING_URI.value
    async with get_secure_client().authenticated_request(
        "patch", 
        audience="api.localhost.github", 
        auth_profile_name=AuthProfileName.patcher, 
        mode=AuthMode.intent if is_intent_mode_on() else AuthMode.oauth
        ) as http_client:
        async with TraceableClient(http_client) as client: 
            patch_request: PatchRequest = PatchRequest(
                repo=repo_event.repo, 
                patch_plan=patch_plan
            )
            response = await client.post(url=f"{api_url}{patching_uri}", json=patch_request.model_dump())
            response.raise_for_status()
            patch_results = response.json()
    
    return {
        "patch_results": patch_results
    }
    
@secure_tool()
def regenerate_sbom():
    '''
    Regenerates the final sbom after all the patching is completed.
    '''

class Patcher: 
    '''
    Handles the actual patching. Starts with the 'patch_plan' field for the current state. 
    This agent's objective is to execute the patch plan represented by the patch_plan field in 
    the PatchetState. It using ecossytem and manifest type specific tools, if required.
    
    This agent makes use of the following tools - 
    1. bump_versions
    2. local_verify
    3. push_as_feature
    4. remote_verify
    5. raise_pr
    6. merge_pr
    7. regenerate_sbom
    '''
    
    patcher_prompt = '''
        You are the **Patcher**. Your job is to finalize patching for the current repository by
        observing the outcome of a deterministic bootstrap step and then taking exactly one of two paths:
        (1) finish the run by regenerating the final SBOM, or (2) yield control if upgrades failed.

        ## Ground rules
        - Use **only** the tools listed in the <Tools> section that follows this message.
        - The bootstrap tool **bump_versions** has already been executed before your first turn.
        Treat its observation as authoritative. **Never call `bump_versions` yourself.**
        - Call at most **one tool per turn**. After any tool call, you will think again and either
        call the next tool or terminate with `Done` / `Yield`.
        - Do not invent tools or arguments; if a tool takes no arguments, call it with '{{}}'.

        ## Inputs you will see
        The host supplies:
        - `<CurrentState>`: includes `patch_plan` and (after bootstrap) `patch_results` as a list of objects
        like `{{ "batch_name": "...", "target_manifest": "...", "status": "SUCCESS" | "FAIL" | "ERROR" }}`.
        - `<StateFlags>`: derived booleans indicating whether a patch plan exists, whether patching is complete, etc.
        - Prior tool output messages (e.g., the bootstrap result) appear in the conversation history.

        ## Deterministic decision policy (follow exactly)
        1) **No plan → Yield**  
        If `patch_plan` is missing, empty, or has zero `batches`, call `Yield` with a brief reason.

        2) **No bootstrap result → Yield**  
        If `patch_results` is absent or empty after the bootstrap, call `Yield` with reason `"no_patch_results"`.

        3) **Any failure → Yield**  
        If any item in `patch_results` has `status` other than `"SUCCESS"`, summarize the failing batch
        names in your thought (briefly), then call `Yield`. (Do **not** attempt remediation here.)

        4) **All succeeded → Regenerate SBOM → Done**  
        If **every** `patch_results[*].status == "SUCCESS"`:
        - If you have **not** already called `regenerate_sbom` in this run, call `regenerate_sbom` with `{{}}`.
        - On your next turn, call `Done`.

        5) **Idempotency**  
        If you detect that `regenerate_sbom` has **already been called** earlier in this run (from prior tool messages),
        skip calling it again and immediately call `Done`.

        ## Output discipline
        - Keep thoughts concise (one short sentence). Focus on the rule that triggered your decision.
        - Never edit state directly; only tool observations update state.
        - Never call tools that are not listed in <Tools>. Never call `bump_versions`.

        Proceed.
    '''
    
    def __init__(self):
        self.name = "Patcher"
        self.tool_funcs = [bump_versions, regenerate_sbom]
        self.agent_graph = ReActAgent(
            id=self.name,
            prompt=self.patcher_prompt, 
            tool_specs=[ToolSpec(func) for func in self.tool_funcs], 
            limit=10, 
            bootstrap_tool=BootstrapTool(StructuredTool.from_function(bump_versions), {})
        )
    
    @traceable
    def build_patcher(self): 
        return self.agent_graph.build(recompile=True)
    
    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=Patcher, 
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