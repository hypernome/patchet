from pydantic import BaseModel
from typing import Literal
import yaml

class Repo(BaseModel): 
    '''
    Object that encapsulates general information about a github repo.
    '''
    owner: str
    name: str
    branch: str

class ChangeEvent(BaseModel): 
    '''
    Event representing a change that can potentially lead to a new workflow for sbom generation and patching.
    '''
    id: str
    
class RepoEvent(ChangeEvent): 
    '''
    Event representing the specific repo either updated or impacted by a cve update.
    '''
    repo: Repo
    commit: str
    package: str | None

class CveEvent(ChangeEvent): 
    '''
    ChangeEvent representing either a new CVE or a change in existing CVE.
    '''
    cve_id: str
    
class ManualEvent(ChangeEvent): 
    '''
    ChangeEvent produced when a manual trigger takes place, either from a user or programmatically.
    '''
    user_cmd: str

class Trigger(BaseModel): 
    '''
    Object that represents the immutable trigger information that starts the execution at anyone of the entrypoints.
    '''
    type: Literal["push", "cve", "manual"]
    impacted_repo_ids: list[str]
    change_event: ChangeEvent | RepoEvent | CveEvent | ManualEvent

class Ecosystem(BaseModel): 
    '''
    Object that reprents ecosystem information and metadata about the current git repo. For example, 
    its type (maven, npm, etc.)
    '''
    @staticmethod
    def create(name: str, manifest_globs: list[str]): 
        es = Ecosystem(name=name, manifest_globs=manifest_globs)
        return es
    
    name: str
    manifest_globs: list[str]

class AgentIteration(BaseModel): 
    '''
    Reprsents an iteration in Agentic loop.
    '''
    iteration_count: int = 0
    llm_call: dict
    tool_calls: list[dict]
    last_run_tool: str

class AgentExecution(BaseModel): 
    '''
    Represents execution trace of an agent.
    '''
    iterations: list[AgentIteration]

class PatchetState(BaseModel): 
    '''
    Overall global state available to all the agents. To be used to pass application wide messages.
    '''
    messages: list = []
    input: str | None = None
    trigger: Trigger
    next_agent: str
    agent_trail: list[AgentExecution] = []
    file_tree: list[str] = []
    ecosystems: list[Ecosystem] = []
    sbom: dict = {}
    vulns: dict[str, dict] = {}
    results: dict[str, dict] = {}

def serialize_state(state: PatchetState, exclusions: list[str] = []): 
    state_dict = state.model_dump(exclude=set(exclusions))
    return yaml.safe_dump(state_dict, sort_keys=False, default_flow_style=False)
    
    