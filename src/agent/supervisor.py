from langchain.tools import StructuredTool, Tool
from agent.planner import Planner
from agent.classifier import Classifier
from agent.patcher import Patcher
from agent.graph import ReActAgent
from clientshim.secure_model import AgentSpec
from intentmodel.intent_model import AgentComponents, Tool
import inspect

class Supervisor: 
    '''
    Main supervisor graph that coordinates agentic decisions and routing.
    '''
    
    supervisor_prompt = """
    You are the **Supervisor** agent that coordinates two tools:

    • **Planner**   - computes file-tree, SBOM, vuln list, analysis, patches  
    • **Classifier** - detects repository ecosystems / manifest paths

    ───────────────────  STATE  ───────────────────
    You see **only** the compact `StateFlags` object (booleans):

    file_tree_computed
    ecosystems_detected
    sbom_generated
    vulns_fetched
    vuln_analysis_done 
    patch_planned 
    patch_completed # (final flag set by Planner when patching done)

    Agent-completion rules
    ----------------------
    Planner is *finished* ⇢ **all four** of  
        file_tree_computed, sbom_generated, vulns_fetched, vuln_analysis_done, patch_planned  
        are True.

    Classifier is *finished* ⇢ ecosystems_detected is True.

    Global completion ⇢ every flag above is True - then call **Done** and stop.

    ───────────────────  DECISION TREE  ───────────────────
    1. If **global completion** ➜ `Done`
    2. Else if **Planner not finished** ➜ call **Planner**
    3. Else if **Classifier not finished** ➜ call **Classifier**
    4. Else (both finished, but some final flag still False) ➜ **Yield**

    **Important: Yield is ONLY valid in step 4.  
    Never Yield while at least one agent is unfinished.**

    Only one tool call per cycle.
    
    Call Planner while patch_planned == False.
	•	Once patch_planned == True, hand off to Patcher, if Patcher is available or call Done if its not available.
	•	Never call Planner again after patch_planned is True

    ───────────────────  EXAMPLE SEQUENCE  ───────────────────
    • start (all False)           → Planner  
    • file_tree_computed=True     → Classifier  
    • ecosystems_detected=True    → Planner  
    • sbom_generated=True         → Planner  
    • vulns_fetched=True          → Planner  
    • vuln_analysis_done=True     → Planner
    - patch_planned=True          → Patcher
    - patch_completed=True        → Done

    Always reevaluate flags each cycle; ignore any memory of earlier messages.
    """
    
    def __init__(self):
        self.name = "Supervisor"
        self.planner = Planner()
        self.classifier = Classifier()
        self.patcher = Patcher()
        
        self.supervisor_graph = ReActAgent(self.supervisor_prompt, tools=[
            StructuredTool.from_function(self.planner.build_planner().ainvoke, name=self.planner.name, description=self.planner.__doc__),
            StructuredTool.from_function(self.classifier.build_classifier().ainvoke, name=self.classifier.name, description=self.classifier.__doc__),
            StructuredTool.from_function(self.patcher.build_patcher().ainvoke, name=self.patcher.name, description=self.patcher.__doc__)
        ])        
    
    def build(self):
        return self.supervisor_graph.build(recompile=True)
    
    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=Supervisor, 
            prompt=self.supervisor_graph.prompt, 
            tools=[tool.func for tool in self.supervisor_graph.tools_by_name.values()]
        )
    
    def agent_components(self): 
        return AgentComponents(
            agent_id=self.name, 
            prompt_template=self.supervisor_graph.prompt, 
            tools=[Tool(
                name=tool.func.__name__, 
                signature=str(inspect.signature(tool.func)), 
                description=tool.func.__doc__ 
            ) for tool in self.supervisor_graph.tools_by_name.values()]
        ) 
    