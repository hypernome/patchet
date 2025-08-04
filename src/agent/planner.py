from state.state import Repo, Ecosystem, VulnAnalysisSpec, SbomTarget
from model.types import SBOMQuery
from langchain.tools import StructuredTool
from langsmith import traceable
from agent.graph import ReActAgent
from endpoints.github import list_files as lf
from endpoints.sbom import generate_sbom_and_vulns

@traceable
def list_files(repo: Repo) -> list[str]: 
    '''
    Fetch the file tree from git repo and create a list of all files in the repo.
    '''
    repo_files = lf(repo)
    return {"file_tree": repo_files["repo_files"] if repo_files else []}

@traceable
async def generate_sbom_with_vulns(repo: Repo, ecosystems: list[Ecosystem]) -> dict: 
    '''
    Takes the repo and all the globs representing a manifest file in git repo and generates 
    a consolidated SBOM at the repo level. Also responsible for saving this SBOM and setting 
    the necessary state to indicate the SBOM generation result. Overall this tool is responsible 
    for the following tasks - 
    1. Use the provided repo and ecosystem to generate an SBOM.
    2. Save the SBOM and generate a reference.
    3. Update the indicator field 'sbom_generated' to True if the SBOM was generated successfully and to False if it failed.
    4. Obtain the reference to the saved SBOM and update the field 'sbom_ref' with that reference.
    5. Extract package urls ('purl') from each of the component library packages from SBOM. 
    6. Use these extracted purls to query osv.dev database and find vulnerabilities for each of them.
    7. Generate a list of mappings between purl and its vulnerabilities and populate the 'vulns' field of the state with it.    
    '''
    target: SbomTarget = SbomTarget.create(repo, ecosystems, start=500, stop=1499)
    vulns = await generate_sbom_and_vulns(target, is_mocked=True)
    
    return {
        "sbom_generated": True,
        "sbom_ref": "./endpoints/fixtures/sbom.json",
        "vulns": vulns
    }

@traceable
def search_sbom_index(sbom_query: SBOMQuery) -> dict: 
    '''
    Search the SBOM Index by a CVE affected package and find out if the repo has 
    already been patched for packges impacted by this CVE.
    '''
    return {
        "results": {
            sbom_query.package: {
                "present": True,
                "current_version": "5.2.0.RELEASE",
                "patched": False,
                "patched_version_available": "5.2.9.RELEASE"
            }
        }
    }

def triage_vulns(file_list: list[str], sbom: dict, vulns: list[str]) -> VulnAnalysisSpec:
    '''
    This tool is used to triage vulnerabilities present in the provided list of vulnerabilities. For 
    each of these vulnerabilities it produces an analysis spec that sums up the details about the 
    following: 
    1. Vulnerability CVE id.
    2. Severity
    3. Applicable manifest file path with applicable ecosystem. 
    4. Applicable lock file.
    '''

class Planner: 
    '''
    Handles planning for patching (tools: list_files, generate_sbom, etc). This agent uses the following tools: 
    - list_files
    - generate_sbom_with_vulns
    - search_sbom_index
    - triage_vulns
    '''
    
    planner_prompt = '''
    You are the Planner agent for an automated SBOM patching system.

    At each step, choose the most appropriate tool to advance the process toward generating a vulnerability-free SBOM for the target repository.
    - Use file listing tools to enumerate repository files. This tool should be used only if the flags, 'file_tree_computed' and 'ecosystems_detected' in the 'StateFlags' state object are currently False.
    - There are two types of state objects, 'PatchetState' and 'StateFlags'. The 'StateFlags' object is the only one included in prompts and should be used to make decisions.
    - The 'StateFlags' state object has the following flags: 
        - file_tree_computed
        - ecosystems_detected
        - sbom_generated
        - vulns_fetched
        - vuln_analysis_done
        - vulns_patched
    - In case the 'file_tree_computed' flag False but 'ecosystems_detected' flag is True, assume that file listing is not required anymore for the next steps. The only function of 'file_tree' was to provide input to compute 'ecosystems' field.
    - You do not have the ability to compute manifests, therefore Yield if there are no manifests available after listing tool has enumerated repository files, so that other agents can compute manifest and return control back to you.
    - If both file_tree and ecosystems have been computed already, and other values like 'sbom_ref', 'vulns' etc are not available then proceed with relevant tools.
    - Generate SBOMs using identified manifests, if available. Whether manifests are available or not can be found out by looking at the 'ecosystems_detected' flag in the 'StateFlags' state object.
    - Resolve vulnerabilities for all the packages included in the generated SBOM
    - SBOM generation along with vulnerability resolution can be done by using a single tool 'generate_sbom_with_vulns'.
    - Successful SBOM generation is indicated by the True value in the 'sbom_generated' flag. 
    - Similarly, successful vulnerability resolution is indicated by the presense of non-empty vulns list in the 'vulns' field.
    - If 'sbom_generated' field is True and the 'vulns' field is still empty, it means that no vulnerabilities were found and the current SBOM is the final one.
    - The 'sbom_ref' field contains path to the generated SBOM. This path could be a file system path, a url or an arbitrary reference. This 'sbom_ref' field needs to be interpreted only in context of the 'sbom_generated' field.
    - If additional information (e.g., repository ecosystem) is required, or you cannot proceed further, call the `Yield` tool to return control to the Supervisor agent.
    - If the current state has sufficient data to indicate that the objective is over, then call the Done tool.
    - Definition of Done: When file_tree, ecosystems, sbom and vulns all have values in the current state, the objective has been achieved.
    
    Your objective is to patch all vulnerable dependencies in the repository until the SBOM is free of critical or high vulnerabilities.

    You can only call one tool per step, and should wait for the result before proceeding. If the workflow is complete, call the `Done` tool.

    You **must not make assumptions**—base your tool selection strictly on the state provided.
    '''    
    
    def __init__(self):
        self.name = "Planner"
        self.planner_tools = [
            StructuredTool.from_function(list_files), 
            StructuredTool.from_function(generate_sbom_with_vulns), 
            StructuredTool.from_function(search_sbom_index)
        ]
        self.agent_graph = ReActAgent(self.planner_prompt, self.planner_tools, limit=10)
    
    @traceable
    def build_planner(self): 
        return self.agent_graph.build(recompile=True)
    
    





    