from agent.graph import ReActAgent
from state.state import PatchetState, Ecosystem
from langchain.tools import StructuredTool
from langsmith import traceable

@traceable
def transform_identified_ecosystems(ecosystems: dict[str, list[str]]): 
    '''
    This tool is to be called after one or more ecosystems for the given file_tree has already be identified and 
    the associated manifest glob patterns have been deduced. The incoming arguments should contain this information 
    This tool simply transforms this information in a different form required for processing. 
    The argument to this tool is a dictionary of str to list[str], every key should be an identified ecosystem name 
    taken from the list of the official osv.dev ecosystems and the value should be a list of identified manifests 
    decuded with the help of file_tree field of the PatchetState. For example a typical ecosystems argument to this tool 
    will look like: 
    
    { 
        "ecosystems": {
            'Maven': ['pom.xml', 'gradle.build']
        }
    }
    Pass this type of dictionary directly into this tool. The top-level key should always be "ecosystems", The value should 
    be dictionary with some ecosystem such as 'Maven' as key and a list of strings one for each manifest for that key as value.
    '''
    ess = []
    if ecosystems: 
        for ecosystem in ecosystems: 
            es = Ecosystem.create(ecosystem, ecosystems[ecosystem])
            ess.append(es)
    return {
        "ecosystems": ess
    }

@traceable
def retrieve_official_osv_ecosystems(): 
    
    '''
    This tools returns back the official list of osv.dev supported ecosystems.
    '''
    return {
        "osv_official_ecosystems": [
            "AlmaLinux"
            "Alpine"
            "Android"
            "Bitnami"
            "CRAN"
            "Chainguard"
            "Debian"
            "GHC"
            "GIT"
            "GSD"
            "GitHub Actions"
            "Go"
            "Hackage"
            "Hex"
            "Linux"
            "Mageia"
            "Maven"
            "MinimOS"
            "NuGet"
            "OSS-Fuzz"
            "Packagist"
            "Pub"
            "PyPI"
            "Red Hat"
            "Rocky Linux"
            "RubyGems"
            "SUSE"
            "SwiftURL"
            "UVI"
            "Ubuntu"
            "Wolfi"
            "crates.io"
            "npm"
            "openSUSE"
        ]
    }

class Classifier: 
    '''
    Represents a classifer agent that classifies the ecosystem(s) the current execution is dealing with. 
    Ecosystem is in context of the type of git repo and the type of dependency manifests that it supports, 
    For example: If a repo is Java based it will typically have maven or gradle ecosystem and based on that it 
    will use pom.xml or gradle.build etc.
    '''
    
    classifier_prompt = '''
    You are the Classifier agent responsible for inferring the software ecosystem and relevant manifest files for a given repository.

    - Use your tools to analyze the provided repository file tree and determine the primary package ecosystem (e.g., npm, PyPI, Maven, etc.).
    - Call the 'retrieve_official_osv_ecosystems' tool to fetch all the osv.dev supported ecosystem names.
    - Once you have the ecosystem names, Identify which of these ecosystems apply to the current file_tree.
    - Also identify all manifest files relevant for dependency analysis.
    - Create a list of the glob patterns for each of these manifest files for downloading them.
    - Once classification is complete, call the 'transform_identified_ecosystems' tool to update the state. 
    - Call the `Done` tool to return control to the Supervisor agent if all work is completed.
    - If insufficient data is available, call the `Yield` tool.

    You should only call one tool at a time, and always wait for results before continuing.

    **Do not attempt to patch vulnerabilities or analyze SBOMs; your sole purpose is ecosystem and manifest inference.**
    '''
    
    def __init__(self):
        self.name = "Classifier"
        self.classifier_tools = [
            StructuredTool.from_function(transform_identified_ecosystems), 
            StructuredTool.from_function(retrieve_official_osv_ecosystems)
        ]
        self.classifier = ReActAgent(
            prompt=self.classifier_prompt, 
            tools=self.classifier_tools, 
            conditionally_continue=self.classify
        )
    
    @traceable
    def classify(self, state: PatchetState) -> bool: 
        '''
        Looks for the presence of ecosystems in the state, if not present then look for the presense of file_tree, 
        If both not present then quit. If file_tree is present and ecosystems is not present only then execute the 
        classification process and populate ecosystems.
        '''
        return not state.ecosystems or state.ecosystems is None
    
    @traceable
    def build_classifier(self): 
        '''
        Build and return the compiled classifier agent.
        '''
        return self.classifier.build(recompile=True)
            