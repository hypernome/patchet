from state.state import Repo
from model.types import SBOMQuery
from langchain.tools import StructuredTool
from langsmith import traceable
from agent.graph import ReActAgent

@traceable
def list_files(repo: Repo) -> list[str]: 
    '''ss
    Fetch the file tree from git repo and create a list of all files in the repo.
    '''
    return {
        "file_tree": [
            "README.md",
            "pom.xml",
            "src/main/java/com/example/App.java",
            "src/main/resources/application.properties"
        ]
    }

@traceable
def generate_sbom_from_manifests(globs: list[str]) -> dict: 
    '''
    Takes all the globs representing a manifest file in git repo and generates 
    a consolidated SBOM at the repo level.
    '''
    sbom = {
        "dependencies": [
            {
                "name": "org.springframework:spring-core",
                "version": "5.2.0.RELEASE",
                "purl": "pkg:maven/org.springframework/spring-core@5.2.0.RELEASE"
            },
            {
                "name": "org.slf4j:slf4j-api",
                "version": "1.7.30",
                "purl": "pkg:maven/org.slf4j/slf4j-api@1.7.30"
            }
        ]
    }
    return {"sbom": sbom}

@traceable
def query_cve(sbom: dict) -> dict[str, dict]: 
    """
    Given the current sbom (software bill of materials), call this tool to fetch vulnerabilities for each purl.
    Required argument:
        sbom: The **FULL** current sbom dictionary as stored in the global state or historical tool message. 
        Always provide the latest value.
    """
    vulns = {
        "pkg:maven/org.springframework/spring-core@5.2.0.RELEASE": {
            "cve_id": "CVE-2020-5421",
            "description": "Spring Core vulnerability allowing remote code execution.",
            "severity": "CRITICAL",
            "patched_versions": ["5.2.9.RELEASE", "5.3.0.RELEASE"]
        },
        "pkg:maven/org.slf4j/slf4j-api@1.7.30": {
            "cve_id": None,  # No known CVE for this version
            "description": None,
            "severity": None,
            "patched_versions": []
        }
    }
    return {"vulns": vulns}

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

class Planner: 
    '''
    Handles SBOM planning and patching (tools: list_files, generate_sbom, etc)
    '''
    
    planner_prompt = '''
    You are the Planner agent for an automated SBOM patching system.

    At each step, choose the most appropriate tool to advance the process toward generating a vulnerability-free SBOM for the target repository.
    - Use file listing tools to enumerate repository files. This tool should be used only if the current state does not already have value for file_tree.
    - You do not have the ability to compute manifests, therefore Yield if there are no manifests available after listing tool has enumerated repository files, so that other agents can compute manifest and return control back to you.
    - If both file_tree and ecosystems values are available in the current state, and other values like 'sbom', 'vulns' etc are not available then proceed with relevant tools.
    - Generate SBOMs using identified manifests, if available. Whether manifests are available or not can be found out by looking at the 'ecosystems' in the current state.
    - Generated SBOM is availble in the 'sbom' value in the current state.
    - Use generated SBOM to find vulnerabilities via the query_cve tool to identify CVEs affecting dependencies.
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
            StructuredTool.from_function(generate_sbom_from_manifests), 
            StructuredTool.from_function(query_cve), 
            StructuredTool.from_function(search_sbom_index)
        ]
        self.agent_graph = ReActAgent(self.planner_prompt, self.planner_tools, limit=10)
    
    @traceable
    def build_planner(self): 
        return self.agent_graph.build(recompile=True)
    
    





    