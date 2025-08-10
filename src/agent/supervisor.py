from langchain.tools import StructuredTool
from agent.planner import Planner
from agent.classifier import Classifier
from agent.graph import ReActAgent
from state.state import PatchetState

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
    patch_planned # (final flag set by Planner when patching done)

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
    - patch_planned=True          → Done

    Always reevaluate flags each cycle; ignore any memory of earlier messages.
    """
    
    def __init__(self):
        self.planner = Planner()
        self.classifier = Classifier()
        
        # Planner tool
        async def planner_tool(state: PatchetState): 
            return await self.planner.build_planner().ainvoke(state)
        
        # Classifier tool
        async def classifier_tool(state: PatchetState): 
            return await self.classifier.build_classifier().ainvoke(state)
        
        async def patcher_tool(state: PatchetState): 
            pass
        
        self.suprevisor_graph = ReActAgent(self.supervisor_prompt, tools=[
            StructuredTool.from_function(self.planner.build_planner().ainvoke, name=self.planner.name, description=self.planner.__doc__),
            StructuredTool.from_function(self.classifier.build_classifier().ainvoke, name=self.classifier.name, description=self.classifier.__doc__)
        ])        
    
    def build(self):
        return self.suprevisor_graph.build(recompile=True)
            
    