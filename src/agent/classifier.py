from agent.graph import ReActAgent
from state.state import PatchetState, Ecosystem
from langchain.tools import StructuredTool
from langsmith import traceable
from pathlib import PurePosixPath as P
from collections import defaultdict
from state.state import CURRENT_STATE
from util.constants import Constants
from clientshim.secure_model import AgentSpec
from intentmodel.intent_model import AgentComponents, Tool
import random, yaml, fnmatch, inspect

@traceable
def search_patterns_in_file_tree(ecosystems: list[Ecosystem]): 
    '''
    This tool looks at each of the provided ecosystems. It takes the list of manifest_globs for each and attempts to find the actual 
    file path in the file_tree for each of those manifest_globs.
    Once done it populates the actual paths in the manifest_paths field and returns. 
    '''
    state: PatchetState = CURRENT_STATE.get(Constants.CURRENT_STATE.value)
    
    for es in ecosystems: 
        if es.manifest_paths: 
            continue
        es.manifiest_paths = []
        es.manifest_paths.extend([fnmatch.filter(state.file_tree, pattern) for pattern in es.manifest_globs])
        
    return { "ecosystems": ecosystems }

@traceable
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

def stratified_sample(paths, per_dir=5, total_cap=200):
    by_dir = defaultdict(list)
    for p in paths:
        by_dir[P(p).parts[:2]].append(p)
    sample = []
    for group in by_dir.values():
        sample.extend(group[:per_dir])
    if len(sample) > total_cap:
        sample = random.sample(sample, total_cap)
    return sample
    
def exclude_for_classifier(state: PatchetState) -> list[str]: 
    state_field_exclusions: list[str] = ["messages", "input"]
    if state.file_tree and len(state.file_tree) > 250 and not stratified_sample(state.file_tree):         
        state_field_exclusions.append("file_tree")
    return state_field_exclusions

def serialize_state_for_classifier(state: PatchetState, exclusions: list[str] = []) -> str:
    shallow_state = state.model_copy()
    sampled_file_tree = stratified_sample(state.file_tree)
    if sampled_file_tree: 
        shallow_state.file_tree = sampled_file_tree
    state_dict = shallow_state.model_dump(exclude=set(exclusions))
    return yaml.safe_dump(state_dict, sort_keys=False, default_flow_style=False)

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
    - Also identify all actual manifest file paths from the given file_tree for the indentfied ecosystem.
    - If the file_tree is not present or if you cannot find any such actual manifest file paths from the file_tree, then generate the glob patterns that can be used to find the paths and call the tool 'search_patterns_in_file_tree' supplying the globs.
    - Once classification is complete, call the 'transform_identified_ecosystems' tool to update the state. 
    - Call the `Done` tool to return control to the Supervisor agent if all work is completed.
    - If insufficient data is available, call the `Yield` tool.

    You should only call one tool at a time, and always wait for results before continuing.

    **Do not attempt to patch vulnerabilities or analyze SBOMs; your sole purpose is ecosystem and manifest inference.**
    '''
    
    def __init__(self):
        self.name = "Classifier"
        self.classifier_tools = [
            StructuredTool.from_function(search_patterns_in_file_tree),
            StructuredTool.from_function(transform_identified_ecosystems), 
            StructuredTool.from_function(retrieve_official_osv_ecosystems)
        ]
        self.classifier = ReActAgent(
            prompt=self.classifier_prompt, 
            tools=self.classifier_tools, 
            conditionally_continue=self.classify, 
            field_exclusion_func=exclude_for_classifier, 
            state_serializer_func=serialize_state_for_classifier
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
    
    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=Classifier, 
            prompt=self.classifier.prompt, 
            tools=[tool.func for tool in self.classifier.tools_by_name.values()]
        )
    
    def agent_components(self): 
        return AgentComponents(
            agent_id=self.name, 
            prompt_template=self.classifier.prompt, 
            tools=[Tool(
                name=tool.func.__name__, 
                signature=str(inspect.signature(tool.func)), 
                description=tool.func.__doc__
            ) for tool in self.classifier.tools_by_name.values()]
        )      