from state.state import Repo, Ecosystem
from clientshim.secure_model import AgentSpec
from clientshim.secure_client import init_agent_security, get_secure_client

# ------------------------------- Supervisor -----------------------------
class Supervisor:
    """
    Supervisor agent to orchestrate the agentic flow.
    """
    
    def __init__(self):
        self.agent_id: str = "supervisor"
        self.prompt: str = "Supervisor agent's goal is to orchestrate all the other agents."
        self.tools = []

# ------------------------------- Planner -----------------------------
class Planner:
    """
    Planner agent to plan the vulnerability, sbom generation and patching.
    """
    
    def __init__(self):
        self.agent_id: str = "planner"
        self.prompt: str = "Planner agent's goal is to create a executable plan for patching vulneabilities."
        self.tools = [list_files, generate_sbom_with_vulns, triage_vulns, create_patch_plan]
    
    def agentspec(self):
        return AgentSpec(
            agent_id=self.agent_id, 
            agent_bridge=self, 
            prompt=self.prompt, 
            tools=self.tools
        )

async def list_files(repo: Repo) -> list[str]: 
    '''
    Fetch the file tree from git repo and create a list of all files in the repo.
    '''

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

async def triage_vulns() -> dict:
    '''
    This tool is used to triage vulnerabilities present in the provided list of vulnerabilities. For 
    each of these vulnerabilities it produces an analysis spec that sums up the details about the 
    following: 
    1. Vulnerability CVE id.
    2. Severity
    3. Applicable manifest file path with applicable ecosystem. 
    4. Applicable lock file.
    
    This tool does not take any arguments and should be invoked the moment 'vulns_fetched' flag become True.
    '''

async def create_patch_plan(): 
    '''
    This tool creates the patch plan. Which is the terminal goal for this Planner agent.
    '''

# ------------------------------- Classifier -----------------------------
class Classifier:
    """
    Classifer agent to identify ecosystems.
    """
    
    def __init__(self):
        self.agent_id: str = "classifier"
        self.prompt: str = "Classifer agent's goals is to identify and classify applicable ecosystems."
        self.tools = [search_patterns_in_file_tree, transform_identified_ecosystems, retrieve_official_osv_ecosystems]

    def agentspec(self):
        return AgentSpec(
            agent_id=self.agent_id, 
            agent_bridge=self, 
            prompt=self.prompt, 
            tools=self.tools
        )

def search_patterns_in_file_tree(ecosystems: list[Ecosystem]): 
    '''
    This tool looks at each of the provided ecosystems. It takes the list of manifest_globs for each and attempts to find the actual 
    file path in the file_tree for each of those manifest_globs.
    Once done it populates the actual paths in the manifest_paths field and returns. 
    '''

def transform_identified_ecosystems(ecosystems: dict[str, dict[str, list[str]]]) -> dict[str, list[Ecosystem]]: 
    '''
    This tool is to be called after one or more ecosystems for the given file_tree has already be identified and 
    the associated manifest glob patterns have been deduced along with the actual manifest paths, if computed. 
    The incoming arguments should contain this information. This tool simply takes the incoming data and sets it 
    in the 'ecosystems' field of the 'state'. 
    The argument to this tool is a dictionary that contains a key for each identified ecosystem. The value should be 
    another dict that contains two keys 'manifest_globs' and 'manifest_paths'. 'manifest_globs' represents a list of 
    glob patterns for each possible manifest of that ecosystem. 'manifest_paths' represents a list of actual manifest 
    file paths in the 'file_tree'. Below is a sample dictionary that the argument into this tool should look like: 
    
    .. code-block:: python:
        {
            "ecosystems": {
                "npm": {
                    "manifest_globs": [
                        "*/package.json", 
                        "**/package.json"
                    ], 
                    "manifest_paths": [
                        "./package.json", 
                        "./server/package.json"
                    ]
                }, 
                "Maven": {
                    "manifest_globs": [
                        "*/pom.xml", 
                        "**/pom.xml"
                    ], 
                    "manifest_paths": [
                        "./pom.xml", 
                        "./child/pom.xml"
                    ]
                }
            }
        }
    
    This is a representative sample not actual data. Make sure that the argument contains only one key 'ecosystems' as shown above.
    
    The objective, for each ecosystem is to find out the actual 'manifest_paths' from the file_tree. But if the file_tree does not have enough 
    or full information then you need to come up with a list of standard 'manifest_globs' for each of the identified ecosystems, in this case 
    actual 'manifest_paths' are not mandatory.
    
    Pass this type of argument directly into this tool.
    '''
   
def retrieve_official_osv_ecosystems(): 
    
    '''
    This tools returns back the official list of osv.dev supported ecosystems.
    '''
    return {
        "osv_official_ecosystems": [
            "AlmaLinux",
            "Alpine",
            "Android",
            "Bitnami",
            "CRAN",
            "Chainguard",
            "Debian",
            "GHC",
            "GIT",
            "GSD",
            "GitHub Actions",
            "Go",
            "Hackage",
            "Hex",
            "Linux",
            "Mageia",
            "Maven",
            "MinimOS",
            "NuGet",
            "OSS-Fuzz",
            "Packagist",
            "Pub",
            "PyPI",
            "Red Hat",
            "Rocky Linux",
            "RubyGems",
            "SUSE",
            "SwiftURL",
            "UVI",
            "Ubuntu",
            "Wolfi",
            "crates.io",
            "npm",
            "openSUSE"
        ]
    }

# ------------------------------- Patcher -----------------------------
class Patcher:
    """
    Pathcer agent to perform patching.
    """
    
    def __init__(self):
        self.agent_id: str = "patcher"
        self.prompt: str = "Patcher agent's goal is to execute the plan created by planner and perform actual vulnerability patching."
        self.tools = [bump_versions, regenerate_sbom]
    
    def agentspec(self):
        return AgentSpec(
            agent_id=self.agent_id, 
            agent_bridge=Patcher, 
            prompt=self.prompt, 
            tools=self.tools
        )
                
def bump_versions(): 
    '''
    Applies the patch based on the PatchPlan.
    '''

def regenerate_sbom():
    '''
    Regenerates the final sbom after all the patching is completed.
    '''        

# ------------------------------------------------------------------- #

if __name__ == "__main__": 
    agent_specs = [Planner().agentspec(), Classifier().agentspec(), Patcher().agentspec()]
    init_agent_security(agent_specs, workflow_id="vulnerability-patching-v1.2")
    get_secure_client()

        
        