from state.state import Repo, Ecosystem, VulnAnalysisRequest, VulnAnalysisSpec, SbomTarget, PatchetState, PackageUpgrade, PatchPlan, CURRENT_STATE
from model.types import SBOMQuery
from langchain.tools import StructuredTool
from langsmith import traceable
from agent.graph import ReActAgent, StrcturedAgent
from api.github import list_files as lf
from api.osv import generate_sbom_and_vulns, generate_vuln_analysis, triage_vulns as tv
from util.constants import Constants
from util.environment import EnvVars
from model.config import AuthProfileName
from clientshim.secure_model import AgentSpec
from clientshim.secure_client import get_secure_client, SecureClient, AuthMode
from intentmodel.intent_model import AgentComponents, Tool
from util.tracing import TraceableClient
import os, inspect

api_url: str = os.getenv(EnvVars.API_URL.value)
_intent_auth_mode: bool = bool(os.getenv(EnvVars.INTENT_AUTH_MODE.value, "False").lower() == 'true')

@traceable
async def list_files(repo: Repo) -> list[str]: 
    '''
    Fetch the file tree from git repo and create a list of all files in the repo.
    '''
    
    list_files_uri: str = Constants.LIST_FILE_URI.value
    async with get_secure_client().authenticated_request(
        "read:repo", 
        audience="api.localhost.github", 
        auth_profile_nane=AuthProfileName.planner, 
        mode=AuthMode.intent if _intent_auth_mode else AuthMode.oauth
        ) as client: 
        response = await client.post(url=f"{api_url}{list_files_uri}", json=repo.model_dump())
        response.raise_for_status()
        repo_files = response.json()    
    
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
    async with get_secure_client().authenticated_request(
        "read:sbom", 
        "write:sbom", 
        audience="api.localhost.osv", 
        auth_profile_nane=AuthProfileName.planner, 
        mode=AuthMode.intent if _intent_auth_mode else AuthMode.oauth
        ) as client:        
        response = await client.post(url=f"{api_url}{Constants.VULNS_URI.value}", params={ "is_mocked": True }, json=target.model_dump())
        response.raise_for_status()
        vulns = response.json()
    
    return {
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

@traceable
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
    state: PatchetState = CURRENT_STATE.get(Constants.CURRENT_STATE.value)
    analysis_request: VulnAnalysisRequest = VulnAnalysisRequest(vulns=state.vulns, ecosystems=state.ecosystems)
    
    async with get_secure_client().authenticated_request(
        "plan", 
        audience="api.localhost.osv", 
        auth_profile_nane=AuthProfileName.planner, 
        mode=AuthMode.intent if _intent_auth_mode else AuthMode.oauth
        ) as client:
        response = await client.post(url=f"{api_url}{Constants.VULNS_ANALYSIS_URI.value}", params={ "is_mocked": True }, json=analysis_request.model_dump())
        response.raise_for_status()
        response_data = response.json()
        vuln_analysis: list[VulnAnalysisSpec] = [VulnAnalysisSpec.model_validate(item) for item in response_data]
    
    # vuln_analysis: list[VulnAnalysisSpec] = await generate_vuln_analysis(VulnAnalysisRequest(vulns=state.vulns, ecosystems=state.ecosystems), is_mocked=True)
    packageUpgrades: list[PackageUpgrade] = await tv(vuln_analysis)
        
    return {
        "vuln_analysis": packageUpgrades
    }
    
@traceable
def derive_dep_graph(): 
    '''
    This tool derives the dependency graph required for planning the batches to perform patching.
    '''
    
    """
    TODO: 
    1. Delegate to ecosystem specific commands for generating a depdency graph.
    2. Use thin parsers to convert ecosystem sepcific dep graph into UDIR format.
        - Sample UDIR: 
        {
            "nodes":[
                {"id":"nA","name":"react","version":"16.14.0",
                "kinds":["direct"], "attrs":{"ecosystem":"npm","isNative":false}},
                {"id":"nB","name":"react-dom","version":"16.14.0","kinds":["transitive"]}
            ],
            "edges":[
                {"from":"nRoot","to":"nA","type":"depends","range":"^16"},
                {"from":"nA","to":"nB","type":"peer","range":"^16"}
            ],
            "targets":[{"node":"nA","toVersion":"18.3.1"}],
            "policies":{"allowDevChanges":false,"targetNode":">=18"}
        }
    3. Persist this UDIR representing the entire dep graph into a persistent store PostGres + Redis with BFS sql.
    """
    
@traceable
async def create_patch_plan(): 
    '''
    This tool creates the patch plan. Which is the terminal goal for this Planner agent.
    '''
    
    """
    TODO: 
    1. Take input from dependency graph's persisted UDIR.
    2. Fetch only relevant slices of the UDIR required for current patching.
    3. Generate batches of patch plans. Using the following: 
        - resolve(udirslice) → returns constraint conflicts if the proposed versions wouldn't install (you can shell out to native tools or use a dry-run semver solver).
	    - subgraph(query) → returns exactly the nodes/edges requested (pagination/filtering). The LLM asks for what it needs; you don't “curate.”
    4. Generate structured output patch plan.
        - Sample structured output: 
        {
            "batches":[
                {
                    "name":"react18-cluster",
                    "target_manifest": "package.json",
                    "actions":[
                        {"action":"upgrade","name":"react","to":"18.3.1"},
                        {"action":"upgrade","name":"react-dom","to":"18.3.1"},
                        {"action":"widenPeer","name":"xyz-lib","peer":"react","range":"^18"}
                    ],
                    "prechecks":["list peers of react with major<18"],
                    "validateWith":["resolve"],
                    "fallbacks":[{"action":"pin","name":"xyz-lib","to":"3.9.4"}],
                    "rationale":"Co-upgrade peer cluster to avoid split majors."
                }
            ]
        }
    """
    
    state: PatchetState = CURRENT_STATE.get(Constants.CURRENT_STATE.value)
    if not state.vuln_analysis: 
        return {}
    
    structured_agent = StrcturedAgent(
        PatchPlan, 
        prompt="""
            # You are the Patch Planner
            Given the JSON list inside `<Input>…</Input>`, produce a minimal, safe, deterministic patch plan using only information present in the input (no outside knowledge, no web lookups, no tool calls).

            ## Objective
            Create an ordered list of batches that upgrades every listed package to its `target_version`. Be conservative and purely name/field-driven.

            ## Global rules
            - Use only the data provided in `<Input>…</Input>`.
            - Include every input item exactly once (no omissions, no duplicates).
            - `to_version` must equal the item's `target_version`.
            - Use only “upgrade” actions (no rollback/revert).
            - Never mix different manifests in the same batch.
            - Never mix different ecosystems in the same batch.
            - Be fully deterministic: same input → same batches, names, and ordering.

            ## Batching algorithm (apply in order)
            1. **Partition by `manifest`.** Build completely separate sequences per manifest (e.g., `package.json`, `pom.xml`).  
            Overall batch ordering across manifests: ASCII ascending by manifest.
            2. **Within each manifest, stratify by `severity`** in this strict order:  
            CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN → anything else.
            3. **Within each severity stratum, form “families” using string-only heuristics (no external knowledge):**
            - **npm scope handling:** For family detection, drop the `@scope/` prefix from names (keep the scoped name unchanged in actions).
            - **Base-token family:** Split the (de-scoped) name on `-` and `.`; the first token is the tentative family key.  
                Examples: `lodash-es`, `lodash-amd`, `lodash.defaultsdeep` → family `lodash`.  
                `pug`, `pug-code-gen` → family `pug`.
            - **JWT cluster rule (string-only):** If a name equals or contains tokens among `jwt`, `jsonwebtoken`, `jws`, or a hyphenated form like `express-jwt`, use family `jwt`.
            - **Maven coordinates:** Treat the full `groupId:artifactId` string as the package identity. Do not group different coordinates together; each unique coordinate forms its own family (i.e., typically singletons), even if artifactIds look similar.
            - If no clear family emerges, treat as a **singleton**.
            4. **Batch sizing:** Prefer up to 5 actions per batch. If a family exceeds 5 items, split into batches with numeric suffixes preserving alphabetical action order.
            5. **Ordering:**
            - **Batches inside a manifest:** order by severity (as above), then by **family key** (lowercased ASCII ascending), then by **batch index** (for splits).
            - **Actions inside a batch:** sort alphabetically by the exact `package` string (ASCII ascending).

            ## Naming
            - **Batch name format (all lowercase, hyphen-separated tokens):**  
            `{{manifest}}:{{severity_lower}}:{{family_or_singleton}}:{{index}}`  
            Examples:  
            - `package.json:critical:lodash:1`  
            - `package.json:high:jwt:1`  
            - `pom.xml:high:singleton-org.webjars.npm:http-cache-semantics:1`
            - For singletons, use `singleton-<package>` as the family token (keep the package string as-is, lowercased for the token).

            ## Field setting guidance
            - `target_manifest` = the exact `manifest` value for all actions in that batch.
            - Each action's `package` = the exact `package` string from input (do not normalize).
            - Each action's `to_version` = the exact `target_version` from input.

            ## Edge cases
            - If the same `package` string appears multiple times in the same manifest (rare), keep one action using the highest severity among those entries and the highest `target_version` by semver comparison; if versions are incomparable, choose the lexicographically greatest. (Remain deterministic.)
            - If the same `package` appears under different manifests, plan it separately in each manifest's sequence.
            - If any `severity` is missing or unrecognized, treat it as UNKNOWN.

            **Input appears below between `<Input>` tags. Parse it as JSON and follow these rules exactly.**
        """
    )
    patch_plan: PatchPlan = await structured_agent.structure_single_output([x.model_dump() for x in state.vuln_analysis])
    return {
        "patch_plan": patch_plan
    }

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
        - patch_planned
        - vulns_patched
    - In case the 'file_tree_computed' flag False but 'ecosystems_detected' flag is True, assume that file listing is not required anymore for the next steps. The only function of 'file_tree' was to provide input to compute 'ecosystems' field.
    - You do not have the ability to compute manifests, therefore Yield if there are no manifests available after listing tool has enumerated repository files, so that other agents can compute manifest and return control back to you.
    - If both file_tree and ecosystems have been computed already, and other values like 'sbom_ref', 'vulns' etc are not available then proceed with relevant tools.
    - Generate SBOMs using identified manifests, if available. Whether manifests are available or not can be found out by looking at the 'ecosystems_detected' flag in the 'StateFlags' state object.
    - Resolve vulnerabilities for all the packages included in the generated SBOM
    - SBOM generation along with vulnerability resolution can be done by using a single tool 'generate_sbom_with_vulns'.
    - Successful SBOM generation is indicated by the True value in the 'sbom_generated' flag. 
    - Similarly, successful vulnerability resolution is indicated by the True value in 'vulns_fetched' flag.
    - If 'sbom_generated' flag is True and the 'vulns_fetched' field is still False, it means that no vulnerabilities were found and the current SBOM is the final one.
    - The 'sbom_ref' field contains path to the generated SBOM. This path could be a file system path, a url or an arbitrary reference. This 'sbom_ref' field needs to be interpreted only in context of the 'sbom_generated' field.
    - If additional information (e.g., repository ecosystem) is required, or you cannot proceed further, call the `Yield` tool to return control to the Supervisor agent.
    - If the current state has sufficient data to indicate that the objective is over, then call the Done tool.
    - Definition of Done: Below is how the state of the 'StateFlags' object would look like when all your objectives are achieved: 
        file_tree_computed: true
        ecosystems_detected: true
        sbom_generated: true
        vulns_fetched: true
        vuln_analysis_done: true
        patch_planned: true
        vulns_patched: false
    
    Your objective is to plan the patching of all vulnerable dependencies in the repository until the SBOM.

    You can only call one tool per step, and should wait for the result before proceeding. If the workflow is complete, call the `Done` tool.

    You **must not make assumptions**—base your tool selection strictly on the state provided.
    '''    
    
    def __init__(self):
        self.name = "Planner"
        self.planner_tools = [
            StructuredTool.from_function(list_files), 
            StructuredTool.from_function(generate_sbom_with_vulns), 
            StructuredTool.from_function(triage_vulns),
            StructuredTool.from_function(create_patch_plan)
        ]
        self.agent_graph = ReActAgent(
            self.planner_prompt, 
            self.planner_tools, 
            limit=10, 
        )
    
    @traceable
    def build_planner(self): 
        return self.agent_graph.build(recompile=True)

    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=Planner, 
            prompt=self.agent_graph.prompt, 
            tools=[tool.func for tool in self.agent_graph.tools_by_name.values()]
        )
    
    def agent_components(self): 
        return AgentComponents(
            agent_id=self.name, 
            prompt_template=self.agent_graph.prompt, 
            tools=[Tool(
                name=tool.func.__name__, 
                signature=str(inspect.signature(tool.func)), 
                description=tool.func.__doc__
            ) for tool in self.agent_graph.tools_by_name.values()]
        )





    