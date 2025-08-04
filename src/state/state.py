from pydantic import BaseModel
from typing import Literal
from contextvars import ContextVar
from util.constants import Constants
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
    def create(name: str, manifest_info: dict[str, list[str]]): 
        es = Ecosystem(name=name, manifest_globs=manifest_info['manifest_globs'], manifest_paths=manifest_info['manifest_paths'])
        return es
    
    name: str
    manifest_globs: list[str]
    manifest_paths: list[str] = []

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

class VulnAnalysisSpec(BaseModel): 
    '''
    Represents the result of vulnerablity analysis done on list of vulnerbilities
    found under scope.
    '''
    cve_id: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    manifest: str   # e.g.: path/to/pom.xml or package.json
    lockfile: str   # e.g. path/to/generated/effective/pom.xml or package-lock.json
    ecosystem: Ecosystem # e.g. Maven, Npm etc.
    direct_dep: str
    fixed_in: str
    is_transitive: bool

class SbomTarget(BaseModel): 
    '''
    Represents the target repository and associated manifests required for generating 
    an SBOM.
    '''
    repo: Repo = None
    ecosystems: list[Ecosystem] = []
    start: int = 0
    stop: int = None
    
    @staticmethod
    def create(repo: Repo, ecosystems: list[Ecosystem], start: int = 500, stop: int = 1499): 
        sbom_target = SbomTarget()
        sbom_target.repo = repo
        sbom_target.ecosystems = ecosystems
        sbom_target.start = start
        sbom_target.stop = stop
        return sbom_target

class PatchetState(BaseModel): 
    '''
    Overall global state available to all the agents. To be used to pass application wide messages.
    '''
    messages: list = []
    input: str | None = None
    trigger: Trigger
    agent_trail: list[AgentExecution] = []
    file_tree: list[str] = []
    ecosystems: list[Ecosystem] = []    
    sbom_ref: str | None = None
    vulns: list[dict] = []
    vuln_analysis: VulnAnalysisSpec | None = None
    results: dict[str, dict] = {}
    
    def default_exclusion_list(self): 
        return ["messages", "input", "file_tree"]

class StateFlags(BaseModel): 
    '''
    Represents the flags that indicate current state of the data in the PatchetState instance.
    '''
    file_tree_computed: bool = False
    ecosystems_detected: bool = False
    sbom_generated: bool = False
    vulns_fetched: bool = False
    vuln_analysis_done: bool = False
    vulns_patched: bool = False
    
    @staticmethod
    def create(state: PatchetState): 
        state_flags = StateFlags()
        state_flags.file_tree_computed = True if state.file_tree else False
        state_flags.ecosystems_detected = True if state.ecosystems else False
        state_flags.sbom_generated = True if state.sbom_ref else False
        state_flags.vulns_fetched = True if state.vulns else False
        state_flags.vuln_analysis_done = True if state.vuln_analysis else False
        state_flags.vulns_patched = True if state.results else False        
        return state_flags
    
def serialize_state(state: PatchetState, exclusions: list[str] = []) -> str: 
    state_dict = state.model_dump(exclude=set(exclusions))
    return yaml.safe_dump(state_dict, sort_keys=False, default_flow_style=False)

def serialize_state_flags(state: PatchetState) -> str: 
    state_flags: StateFlags = StateFlags.create(state)
    state_flags_dict = state_flags.model_dump()
    return yaml.safe_dump(state_flags_dict, sort_keys=False, default_flow_style=False)
    
CURRENT_STATE: ContextVar[PatchetState] = ContextVar(Constants.CURRENT_STATE.value)    